package main

import (
	"compress/gzip"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestDiagnosticsOptInAcceptsExistingAbsoluteDirectory(t *testing.T) {
	dir := t.TempDir()
	args := []string{"--action", "draft", "--isolated-fixture", "--worker-url-file", "/tmp/worker-url", "--window-id", "10000000-0000-4000-8000-000000000001"}
	c, err := parse(args)
	if err != nil || c.DiagnosticsDir != "" {
		t.Fatal("default diagnostics unexpectedly enabled", err)
	}
	d, err := startDiagnostics(context.Background(), "")
	if err != nil || d != nil {
		t.Fatal("disabled diagnostics created state", err)
	}
	c, err = parse(append(args, "--diagnostics-dir", dir))
	if err != nil || c.DiagnosticsDir != dir {
		t.Fatal("explicit diagnostics directory rejected", err)
	}
}

func TestDiagnosticsRejectInvalidOrPreviouslyUsedDestination(t *testing.T) {
	parent := t.TempDir()
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", filepath.Join(parent, "missing"), file, link} {
		if _, err := startDiagnostics(context.Background(), path); err == nil {
			t.Fatalf("invalid diagnostic destination accepted: %s", path)
		}
	}
	prior := filepath.Join(parent, "memory.jsonl")
	if err := os.WriteFile(prior, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := startDiagnostics(context.Background(), parent); !errors.Is(err, errDiagnostics) {
		t.Fatal("existing diagnostic output accepted", err)
	}
	raw, err := os.ReadFile(prior)
	if err != nil || string(raw) != "keep" {
		t.Fatal("earlier diagnostic output replaced", err)
	}
}

func TestDiagnosticQueryLabelsAndRecordsRedactSecrets(t *testing.T) {
	for _, test := range []struct{ sql, want string }{
		{"-- name: ListReportSourceDetections :many\nSELECT 'SECRET'", "ListReportSourceDetections"},
		{"-- name: CopyReportEvidenceBatch :exec\nSELECT 'SECRET'", "CopyReportEvidenceBatch"},
		{"-- name: AppendReportRevision :one\nSELECT 'SECRET'", "AppendReportRevision"},
		{"SELECT 'SECRET'", "Other"},
		{"-- name: SECRET :one\nSELECT 1", "Other"},
		{"-- name: AppendReportRevision :one SECRET\nSELECT 1", "Other"},
		{"SELECT 1\n-- name: AppendReportRevision :one", "Other"},
	} {
		if got := diagnosticQueryLabel(test.sql); got != test.want {
			t.Fatalf("query label %q want %q", got, test.want)
		}
	}
	dir := t.TempDir()
	d, err := startDiagnostics(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 4 {
				ctx := d.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "-- name: ListReportSourceDetections :many\nSELECT 'SECRET_SQL'", Args: []any{"SECRET_ARGUMENT"}})
				d.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: errors.New("SECRET_DSN postgres://password@example.invalid")})
			}
		}()
	}
	workers.Wait()
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "memory.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "postgres://") || strings.Contains(string(raw), "SELECT") {
		t.Fatal("diagnostics disclosed SQL, parameters, or driver details")
	}
	starts, ends := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var record diagnosticRecord
		if err = json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Kind == "query_start" {
			starts++
		}
		if record.Kind == "query_end" {
			ends++
			if !record.Failed || record.Query != "ListReportSourceDetections" {
				t.Fatal("redacted end status missing")
			}
		}
		if record.Memory.HeapAlloc == 0 || record.At.IsZero() {
			t.Fatal("query memory observation missing")
		}
	}
	if starts != 16 || ends != 16 {
		t.Fatal("concurrent query boundaries lost", starts, ends)
	}
}

func TestDiagnosticHeapRotationPreservesFiveRealProfiles(t *testing.T) {
	dir := t.TempDir()
	d, err := startDiagnostics(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 7 {
		if err = d.writeHeap(heapRequest{At: time.Now().UTC(), Reason: "interval"}); err != nil {
			t.Fatal(err)
		}
	}
	runtime.ReadMemStats(&after)
	if after.NumForcedGC != before.NumForcedGC {
		t.Fatal("heap observation forced GC")
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1+2*diagnosticSlots {
		t.Fatalf("profile rotation left %d files", len(entries))
	}
	sequences := map[uint64]bool{}
	for slot := 0; slot < diagnosticSlots; slot++ {
		raw, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("heap-%d.json", slot)))
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Sequence uint64    `json:"sequence"`
			At       time.Time `json:"started_at"`
			File     string    `json:"file"`
			SHA256   string    `json:"sha256"`
		}
		if err = json.Unmarshal(raw, &meta); err != nil {
			t.Fatal(err)
		}
		if meta.Sequence%diagnosticSlots != uint64(slot) || meta.At.IsZero() {
			t.Fatal("rotation metadata invalid")
		}
		sequences[meta.Sequence] = true
		profile, err := os.ReadFile(filepath.Join(dir, meta.File))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(profile)
		if hex.EncodeToString(digest[:]) != meta.SHA256 {
			t.Fatal("profile and atomic metadata do not match")
		}
		f, err := os.Open(filepath.Join(dir, meta.File))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal("heap output is not a real pprof profile", err)
		}
		decoded, err := io.ReadAll(reader)
		reader.Close()
		f.Close()
		if err != nil || len(decoded) == 0 {
			t.Fatal("heap profile empty", err)
		}
	}
	var latest uint64
	for seq := range sequences {
		if seq > latest {
			latest = seq
		}
	}
	if latest < 6 {
		t.Fatal("profiles did not rotate")
	}
	for n := uint64(0); n < diagnosticSlots; n++ {
		if !sequences[latest-n] {
			t.Fatal("rotation lost one of the last five profiles")
		}
	}
}

func TestDiagnosticsSampleAndStopWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	d, err := startDiagnostics(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	samples := 0
	for samples < 2 {
		select {
		case <-deadline.C:
			t.Fatal("100ms memory sampler did not run")
		case <-poll.C:
		}
		raw, err := os.ReadFile(filepath.Join(dir, "memory.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		samples = strings.Count(string(raw), `"kind":"sample"`)
	}
	cancel()
	select {
	case <-d.done:
	case <-time.After(3 * time.Second):
		t.Fatal("diagnostic goroutines survived cancellation")
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "memory.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	queryCtx := d.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "-- name: AppendReportRevision :one"})
	d.TraceQueryEnd(queryCtx, nil, pgx.TraceQueryEndData{})
	if err = d.Close(); err != nil {
		t.Fatal("second close failed", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "memory.jsonl"))
	if err != nil || string(after) != string(before) {
		t.Fatal("diagnostics wrote after shutdown", err)
	}
}

func TestDiagnosticProfileRequestsNeverWaitForWriter(t *testing.T) {
	d := &probeDiagnostics{ctx: context.Background(), profiles: make(chan heapRequest, 1)}
	done := make(chan struct{})
	go func() {
		for range 100 {
			d.requestHeap("interval")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("profile requests blocked behind writer")
	}
	if len(d.profiles) != 1 {
		t.Fatal("profile requests accumulated without bound")
	}
}

func TestDiagnosticLogAndProfileWritersAreBounded(t *testing.T) {
	dir := t.TempDir()
	d, err := startDiagnostics(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.written = diagnosticLogLimit - 1
	d.mu.Unlock()
	d.record("sample", "", false, 0)
	if err = d.Close(); !errors.Is(err, errDiagnostics) {
		t.Fatal("log cap did not stop diagnostics", err)
	}
	var out strings.Builder
	writer := &cappedDiagnosticWriter{writer: &out, remaining: 3}
	if _, err = writer.Write([]byte("abcd")); !errors.Is(err, errDiagnostics) || out.Len() != 0 {
		t.Fatal("oversized profile write escaped cap", err)
	}
}
