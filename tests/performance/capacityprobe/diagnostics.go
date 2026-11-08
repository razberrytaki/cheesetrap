package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	diagnosticSlots     = 5
	diagnosticLogLimit  = 8 << 20
	diagnosticHeapLimit = 16 << 20
)

var errDiagnostics = errors.New("probe_diagnostics_failed")

// Diagnostics are opt-in probe observations. Sampling and profiles add overhead;
// runs with this flag are not throughput/latency acceptance measurements.
type probeDiagnostics struct {
	ctx       context.Context
	cancel    context.CancelFunc
	root      *os.Root
	log       *os.File
	mu        sync.Mutex
	written   int
	err       error
	closed    bool
	done      chan struct{}
	profiles  chan heapRequest
	profileMu sync.Mutex
	sequence  uint64
	closeOnce sync.Once
}

type heapRequest struct {
	At     time.Time `json:"requested_at"`
	Reason string    `json:"reason"`
}

type diagnosticMemory struct {
	HeapAlloc     uint64  `json:"heap_alloc"`
	HeapSys       uint64  `json:"heap_sys"`
	HeapInuse     uint64  `json:"heap_inuse"`
	HeapIdle      uint64  `json:"heap_idle"`
	HeapReleased  uint64  `json:"heap_released"`
	HeapObjects   uint64  `json:"heap_objects"`
	TotalAlloc    uint64  `json:"total_alloc"`
	Sys           uint64  `json:"sys"`
	StackInuse    uint64  `json:"stack_inuse"`
	GCSys         uint64  `json:"gc_sys"`
	NextGC        uint64  `json:"next_gc"`
	LastGC        uint64  `json:"last_gc_unix_ns"`
	NumGC         uint32  `json:"num_gc"`
	NumForcedGC   uint32  `json:"num_forced_gc"`
	PauseTotalNs  uint64  `json:"pause_total_ns"`
	GCCPUFraction float64 `json:"gc_cpu_fraction"`
	Mallocs       uint64  `json:"mallocs"`
	Frees         uint64  `json:"frees"`
	Goroutines    int     `json:"goroutines"`
}

type diagnosticRecord struct {
	At         time.Time        `json:"at"`
	Kind       string           `json:"kind"`
	Query      string           `json:"query,omitempty"`
	Failed     bool             `json:"failed,omitempty"`
	DurationMS float64          `json:"duration_ms,omitempty"`
	Memory     diagnosticMemory `json:"memory"`
}

func diagnosticDirectory(path string) error {
	if path == "" {
		return nil
	}
	st, err := os.Lstat(path)
	if !filepath.IsAbs(path) || err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("probe_diagnostics_directory_invalid")
	}
	return nil
}

func startDiagnostics(parent context.Context, path string) (*probeDiagnostics, error) {
	if path == "" {
		return nil, nil
	}
	if err := diagnosticDirectory(path); err != nil {
		return nil, err
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errDiagnostics
	}
	// Refuse to replace earlier diagnostics or a pre-existing link/file.
	names := []string{"memory.jsonl", "heap.tmp", "metadata.tmp"}
	for slot := 0; slot < diagnosticSlots; slot++ {
		names = append(names, fmt.Sprintf("heap-%d.pprof", slot), fmt.Sprintf("heap-%d.json", slot))
	}
	for _, name := range names {
		if _, err = root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			root.Close()
			return nil, errDiagnostics
		}
	}
	log, err := root.OpenFile("memory.jsonl", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		root.Close()
		return nil, errDiagnostics
	}
	ctx, cancel := context.WithCancel(parent)
	d := &probeDiagnostics{ctx: ctx, cancel: cancel, root: root, log: log, done: make(chan struct{}), profiles: make(chan heapRequest, 1)}
	d.record("start", "", false, 0)
	// Keep profile serialization off both query callbacks and the 100ms sampler.
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); d.sampleLoop() }()
	go func() { defer workers.Done(); d.profileLoop() }()
	go func() { workers.Wait(); close(d.done) }()
	return d, nil
}

func diagnosticMemStats() diagnosticMemory {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return diagnosticMemory{HeapAlloc: m.HeapAlloc, HeapSys: m.HeapSys, HeapInuse: m.HeapInuse, HeapIdle: m.HeapIdle, HeapReleased: m.HeapReleased, HeapObjects: m.HeapObjects, TotalAlloc: m.TotalAlloc, Sys: m.Sys, StackInuse: m.StackInuse, GCSys: m.GCSys, NextGC: m.NextGC, LastGC: m.LastGC, NumGC: m.NumGC, NumForcedGC: m.NumForcedGC, PauseTotalNs: m.PauseTotalNs, GCCPUFraction: m.GCCPUFraction, Mallocs: m.Mallocs, Frees: m.Frees, Goroutines: runtime.NumGoroutine()}
}

func (d *probeDiagnostics) record(kind, query string, failed bool, duration time.Duration) {
	if d == nil || d.ctx.Err() != nil {
		return
	}
	record := diagnosticRecord{At: time.Now().UTC(), Kind: kind, Query: query, Failed: failed, DurationMS: float64(duration) / float64(time.Millisecond), Memory: diagnosticMemStats()}
	data, err := json.Marshal(record)
	if err != nil {
		d.fail()
		return
	}
	data = append(data, '\n')
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		return
	}
	if d.written+len(data) > diagnosticLogLimit {
		d.err = errDiagnostics
		d.cancel()
		return
	}
	n, err := d.log.Write(data)
	d.written += n
	if err != nil || n != len(data) {
		d.err = errDiagnostics
		d.cancel()
	}
}

func (d *probeDiagnostics) fail() { d.mu.Lock(); d.err = errDiagnostics; d.mu.Unlock(); d.cancel() }
func (d *probeDiagnostics) sampleLoop() {
	sample := time.NewTicker(100 * time.Millisecond)
	defer sample.Stop()
	profile := time.NewTicker(time.Second)
	defer profile.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-sample.C:
			d.record("sample", "", false, 0)
		case <-profile.C:
			d.requestHeap("interval")
		}
	}
}
func (d *probeDiagnostics) requestHeap(reason string) {
	if d == nil || d.ctx.Err() != nil {
		return
	}
	select {
	case d.profiles <- heapRequest{At: time.Now().UTC(), Reason: reason}:
	default:
	}
}
func (d *probeDiagnostics) profileLoop() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case request := <-d.profiles:
			if d.ctx.Err() != nil {
				return
			}
			if err := d.writeHeap(request); err != nil {
				d.fail()
				return
			}
		}
	}
}

type cappedDiagnosticWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *cappedDiagnosticWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errDiagnostics
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

// A metadata SHA256 detects an interrupted replacement between the two atomic
// renames. Only these five slots and two fixed temporary files are ever used.
func (d *probeDiagnostics) writeHeap(request heapRequest) error {
	d.profileMu.Lock()
	defer d.profileMu.Unlock()
	if d.ctx.Err() != nil {
		return nil
	}
	at := time.Now().UTC()
	f, err := d.root.OpenFile("heap.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errDiagnostics
	}
	defer d.root.Remove("heap.tmp")
	digest := sha256.New()
	writer := &cappedDiagnosticWriter{writer: io.MultiWriter(f, digest), remaining: diagnosticHeapLimit}
	err = pprof.WriteHeapProfile(writer) // Deliberately no runtime.GC or GC tuning.
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errDiagnostics
	}
	slot := d.sequence % diagnosticSlots
	name := fmt.Sprintf("heap-%d.pprof", slot)
	metadata := struct {
		heapRequest
		Sequence    uint64    `json:"sequence"`
		StartedAt   time.Time `json:"started_at"`
		CompletedAt time.Time `json:"completed_at"`
		File        string    `json:"file"`
		SHA256      string    `json:"sha256"`
	}{request, d.sequence, at, time.Now().UTC(), name, hex.EncodeToString(digest.Sum(nil))}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return errDiagnostics
	}
	meta, err := d.root.OpenFile("metadata.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errDiagnostics
	}
	defer d.root.Remove("metadata.tmp")
	_, writeErr := meta.Write(append(raw, '\n'))
	closeErr = meta.Close()
	if writeErr != nil || closeErr != nil {
		return errDiagnostics
	}
	if err = d.root.Rename("heap.tmp", name); err != nil {
		return errDiagnostics
	}
	if err = d.root.Rename("metadata.tmp", fmt.Sprintf("heap-%d.json", slot)); err != nil {
		return errDiagnostics
	}
	d.sequence++
	return nil
}

func (d *probeDiagnostics) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.cancel()
		<-d.done
		d.mu.Lock()
		defer d.mu.Unlock()
		d.closed = true
		if err := d.log.Close(); err != nil {
			d.err = errDiagnostics
		}
		if err := d.root.Close(); err != nil {
			d.err = errDiagnostics
		}
	})
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

type diagnosticQueryKey struct{}
type diagnosticQuery struct {
	name    string
	started time.Time
}

// Only exact generated first-line declarations can produce a named label.
// Unknown SQL, arguments, command tags, and driver errors are never serialized.
func diagnosticQueryLabel(sql string) string {
	line, _, _ := strings.Cut(sql, "\n")
	declaration, ok := strings.CutPrefix(line, "-- name: ")
	if !ok {
		return "Other"
	}
	name, kind, ok := strings.Cut(declaration, " ")
	if !ok {
		return "Other"
	}
	switch kind {
	case ":one", ":many", ":exec", ":execrows":
	default:
		return "Other"
	}
	switch name {
	case "LockReportDrafts", "NextDraftWindow", "NextDraftSource", "ListReportSourceDetections", "ListReportCandidateEvidence", "ReportEvidenceGaps", "CompleteReportWindow", "RecordReportCandidate", "CreateReport", "AppendReportRevision", "AdvanceReportRevision", "LockReport", "CurrentReportRevision", "ReportRevisionClock", "CopyReportEvidenceBatch":
		return name
	default:
		return "Other"
	}
}
func (d *probeDiagnostics) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if d.ctx.Err() != nil {
		return ctx
	}
	label := diagnosticQueryLabel(data.SQL)
	d.record("query_start", label, false, 0)
	if label == "AppendReportRevision" {
		d.requestHeap("AppendReportRevision_start")
	}
	return context.WithValue(ctx, diagnosticQueryKey{}, diagnosticQuery{name: label, started: time.Now()})
}
func (d *probeDiagnostics) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	query, ok := ctx.Value(diagnosticQueryKey{}).(diagnosticQuery)
	if !ok {
		return
	}
	d.record("query_end", query.name, data.Err != nil, time.Since(query.started))
	if query.name == "CopyReportEvidenceBatch" {
		d.requestHeap("CopyReportEvidenceBatch_end")
	}
}
