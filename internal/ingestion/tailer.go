package ingestion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
	"unicode/utf8"
)

var (
	ErrTailerClosed = errors.New("tailer is closed")
	errUnsafeFile   = errors.New("source is not a regular non-symlink file")
)

// TailerConfig describes one active engine log. ArchivePaths are only bounded
// candidates for restoring known Resume generations after a rename during
// downtime. They do not request historical archive discovery or ingestion;
// that policy belongs to the caller. All paths and parent directories are
// trusted local collector configuration, not engine-record fields.
//
// Zero budgets use defaults: 8 held files, 128 records, 1 MiB input per Poll,
// and 32 recent diagnostics. Hard maxima are 64/1024/16 MiB/1024 respectively.
// Fingerprint probes additionally read at most 4096 bytes per verification.
// No source files are modified. Only Linux and Darwin support file tailing.
type TailerConfig struct {
	Path           string
	ArchivePaths   []string
	Resume         []ResumePoint
	MaxOpenFiles   int
	MaxRecords     int
	MaxBytes       int
	MaxDiagnostics int
}

// TailerRecord has exclusive EndOffset (including LF), exact StartOffset, and a
// SHA-256 of original bytes excluding LF. Identical records at different offsets
// are different evidence. Problem is a static code; damaged records have no
// payload. Bytes is the explicit sensitive-data boundary for the pure adapters.
// JSON and formatted diagnostic output never contain the original payload.
type TailerRecord struct {
	GenerationID string `json:"generation_id"`
	StartOffset  int64  `json:"start_offset"`
	EndOffset    int64  `json:"end_offset"`
	ByteCount    int64  `json:"byte_count"`
	RawHash      string `json:"raw_hash"`
	Problem      string `json:"problem,omitempty"`
	raw          []byte
}

func (r TailerRecord) Bytes() []byte    { return bytes.Clone(r.raw) }
func (r TailerRecord) String() string   { b, _ := json.Marshal(r); return string(b) }
func (r TailerRecord) GoString() string { return r.String() }

type GenerationStatus struct {
	Generation FileGeneration `json:"generation"`
	ReadOffset int64          `json:"read_offset"`
	// RecordOffset is the next complete-line boundary, not a committed checkpoint.
	RecordOffset int64 `json:"record_offset"`
	PendingBytes int64 `json:"pending_bytes"`
	Detached     bool  `json:"detached"`
}
type TailerDiagnostic struct {
	Code         string    `json:"code"`
	GenerationID string    `json:"generation_id,omitempty"`
	Offset       int64     `json:"offset"`
	Bytes        int64     `json:"bytes"`
	At           time.Time `json:"at"`
}

// TailerStatus describes this process's observations. CollectionGap is sticky;
// a caller must not clear evidence of loss just because a path reappears.
// LastCollectionTime is the last emitted complete record (including damaged
// records), never a claim of DB commit time. Counters and recent diagnostics are
// process-local. Persist any status needed across restart in the caller.
type TailerStatus struct {
	CollectionGap      bool               `json:"collection_gap"`
	GapCount           uint64             `json:"gap_count"`
	Truncations        uint64             `json:"truncations"`
	MalformedRecords   uint64             `json:"malformed_records"`
	OversizedRecords   uint64             `json:"oversized_records"`
	LastCollectionTime *time.Time         `json:"last_collection_time"`
	Generations        []GenerationStatus `json:"generations"`
	Diagnostics        []TailerDiagnostic `json:"diagnostics"`
}
type TailerBatch struct {
	// GapCountFloor is supplied by the leased collector, not the tailer. A
	// monotonic floor makes replay of a committed batch idempotent.
	GapCountFloor int64 `json:"-"`
	// ObservationStartedAt is supplied by the collector from the database clock
	// immediately BEFORE Poll. Tailer itself leaves it zero. It is a conservative
	// lower bound for loss discovered on the next poll, persisted with this batch.
	ObservationStartedAt time.Time `json:"observation_started_at,omitempty"`

	Records []TailerRecord `json:"records"`
	// Generations contains a value snapshot for every emitted generation ID,
	// updated through its last record in this batch. It is bounded by Records
	// and independent of Status.Generations, which describes currently held
	// generations and may already have replaced an emitted generation.
	// Retain these snapshots with uncommitted records for later persistence.
	Generations []FileGeneration `json:"generations"`
	BytesRead   int64            `json:"bytes_read"`
	Status      TailerStatus     `json:"status"`
}

func (b *TailerBatch) appendRecord(record TailerRecord, generation FileGeneration) {
	b.Records = append(b.Records, record)
	for i := range b.Generations {
		if b.Generations[i].ID == generation.ID {
			b.Generations[i] = generation
			return
		}
	}
	b.Generations = append(b.Generations, generation)
}

type tailGeneration struct {
	metadata                            FileGeneration
	file                                *os.File
	detached                            bool
	readOffset, recordOffset, lineBytes int64
	partial                             []byte
	digest                              hash.Hash
}

// Tailer is a serial, deterministic polling reader. Its methods must not run
// concurrently. It has no goroutine, timer or watcher. EOF never retires an old
// descriptor: external rename does not make Cowrie reopen. When capacity is
// exhausted new files are deferred with a gap instead of evicting old writers.
// The caller must retain uncommitted batches or restart from committed resume
// points. Close releases resources; it does not acknowledge any bytes.
type Tailer struct {
	cfg         TailerConfig
	generations []*tailGeneration
	resume      []ResumePoint
	status      TailerStatus
	next        int
	closed      bool
	now         func() time.Time
	identity    func(os.FileInfo) (fileIdentity, error)
	openSource  func(string) (*os.File, os.FileInfo, error)
}

func NewTailer(cfg TailerConfig) (*Tailer, error) {
	for _, budget := range []struct {
		value                 *int
		defaultValue, maximum int
	}{{&cfg.MaxOpenFiles, 8, 64}, {&cfg.MaxRecords, 128, 1024}, {&cfg.MaxBytes, 1024 * 1024, 16 * 1024 * 1024}, {&cfg.MaxDiagnostics, 32, 1024}} {
		if *budget.value == 0 {
			*budget.value = budget.defaultValue
		}
		if *budget.value < 1 || *budget.value > budget.maximum {
			return nil, errors.New("invalid tailer budget")
		}
	}
	if !filepath.IsAbs(cfg.Path) || len(cfg.ArchivePaths) > 64 || len(cfg.Resume) > cfg.MaxOpenFiles {
		return nil, errors.New("invalid tailer paths or resume count")
	}
	for _, path := range cfg.ArchivePaths {
		if !filepath.IsAbs(path) {
			return nil, errors.New("invalid tailer archive path")
		}
	}
	ids := map[string]bool{}
	for _, p := range cfg.Resume {
		if !validResume(p) || !filepath.IsAbs(p.Generation.Path) || ids[p.Generation.ID] {
			return nil, errors.New("invalid tailer resume metadata")
		}
		ids[p.Generation.ID] = true
	}
	cfg.ArchivePaths = slices.Clone(cfg.ArchivePaths)
	cfg.Resume = slices.Clone(cfg.Resume)
	return &Tailer{cfg: cfg, resume: slices.Clone(cfg.Resume), now: time.Now, identity: identifyFile, openSource: openLog}, nil
}

func (t *Tailer) Poll(ctx context.Context) (TailerBatch, error) {
	if t.closed {
		return TailerBatch{}, ErrTailerClosed
	}
	if err := ctx.Err(); err != nil {
		return TailerBatch{}, err
	}
	if err := t.restore(ctx); err != nil {
		return TailerBatch{Status: t.Status()}, err
	}
	if len(t.resume) > 0 {
		// A generic verification I/O error is retryable. Keep its saved UUID
		// pending instead of admitting the same source as a new generation.
		return TailerBatch{Status: t.Status()}, nil
	}
	if err := ctx.Err(); err != nil {
		return TailerBatch{Status: t.Status()}, err
	}
	t.reconcileActive()
	batch := TailerBatch{}
	count := len(t.generations)
	start := t.next
	for step := 0; step < count; step++ {
		if err := ctx.Err(); err != nil {
			batch.Status = t.Status()
			return batch, err
		}
		index := (start + step) % count
		g := t.generations[index]
		t.next = (index + 1) % count
		if !t.inspect(g) {
			continue
		}
		if err := t.read(ctx, g, &batch); err != nil {
			batch.Status = t.Status()
			return batch, err
		}
		if len(batch.Records) >= t.cfg.MaxRecords || batch.BytesRead >= int64(t.cfg.MaxBytes) {
			break
		}
	}
	batch.Status = t.Status()
	return batch, nil
}

func (t *Tailer) restore(ctx context.Context) error {
	for len(t.resume) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		saved := t.resume[0]
		candidates := append([]string{saved.Generation.Path, t.cfg.Path}, t.cfg.ArchivePaths...)
		restored := false
		retryable := false
		for _, path := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			f, info, err := t.openSource(path)
			if err != nil {
				// Missing/unsafe candidates cannot identify the saved file.
				// Other open or fstat failures leave that identity unresolved.
				retryable = retryable || (!errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) && !errors.Is(err, errUnsafeFile))
				continue
			}
			id, err := t.identity(info)
			if err != nil {
				f.Close()
				retryable = true
				continue
			}
			sameIdentity := id.Device == saved.Generation.Device && id.Inode == saved.Generation.Inode
			shrank := sameIdentity && info.Size() < saved.Generation.ObservedSize
			matches := shrank
			if sameIdentity && !shrank {
				matches, err = fingerprintMatches(f, saved.Generation)
				if matches && err == nil {
					matches, err = resumeBoundary(f, info.Size(), saved.ByteOffset)
				}
				if err != nil && !isShortRead(err) {
					f.Close()
					retryable = true
					continue
				}
				if !matches {
					// A verified identity with an invalid prefix/boundary is not
					// made safe by retrying another name for that same inode.
					f.Close()
					retryable = false
					break
				}
			}
			if matches {
				for _, g := range t.generations {
					held, e := g.file.Stat()
					if e != nil {
						retryable = true
						matches = false
						break
					}
					same := os.SameFile(held, info)
					if same {
						// The candidate stat preceded the held-descriptor stat.
						t.observeSize(g, info)
					}
					t.observeSize(g, held)
					if same {
						matches = false
						break
					}
				}
			}
			if matches {
				g := &tailGeneration{metadata: saved.Generation, file: f, readOffset: saved.ByteOffset, recordOffset: saved.ByteOffset, digest: sha256.New(), detached: true}
				g.metadata.Path = path
				if !t.observeSize(g, info) && g.metadata.ID == saved.Generation.ID {
					f.Close()
					retryable = true
					continue
				}
				t.generations = append(t.generations, g)
				restored = true
				break
			}
			f.Close()
		}
		if !restored {
			if retryable {
				t.note("read_error", saved.Generation.ID, saved.ByteOffset, 0, true)
				return nil
			}
			t.note("resume_unavailable", saved.Generation.ID, saved.ByteOffset, 0, true)
		}
		t.resume = t.resume[1:]
	}
	return nil
}

func (t *Tailer) reconcileActive() {
	for _, g := range t.generations {
		g.detached = true
	}
	info, err := os.Lstat(t.cfg.Path)
	if err != nil {
		t.sourceError(err)
		return
	}
	if !info.Mode().IsRegular() {
		t.sourceError(errUnsafeFile)
		return
	}
	id, err := t.identity(info)
	if err != nil {
		t.sourceError(err)
		return
	}
	reused := false
	for _, g := range t.generations {
		held, e := g.file.Stat()
		if e != nil {
			continue
		}
		same := os.SameFile(info, held)
		if same {
			// Apply observations in time order: an earlier smaller Lstat must
			// survive a regrowth already visible to the later descriptor stat.
			t.observeSize(g, info)
		}
		t.observeSize(g, held)
		if same {
			g.detached = false
			g.metadata.Path = t.cfg.Path
			return
		}
		if g.metadata.Device == id.Device && g.metadata.Inode == id.Inode {
			reused = true
		}
	}
	if len(t.generations) >= t.cfg.MaxOpenFiles {
		t.note("capacity_exceeded", "", 0, 0, true)
		return
	}
	f, opened, err := t.openSource(t.cfg.Path)
	if err != nil {
		t.sourceError(err)
		return
	}
	if !os.SameFile(info, opened) {
		f.Close()
		t.note("source_changed", "", 0, 0, true)
		return
	}
	// Preserve the earlier path observation before applying open's later stat.
	// Using only opened would erase a decrease seen during first/replacement open.
	metadata, err := newGeneration(f, info, id, t.cfg.Path, t.now().UTC())
	if metadata.ID == "" {
		f.Close()
		t.sourceError(err)
		return
	}
	g := &tailGeneration{metadata: metadata, file: f, digest: sha256.New()}
	t.observeSize(g, opened)
	if err != nil && g.metadata.ID == metadata.ID {
		if isShortRead(err) {
			t.resetAfterShortRead(g)
		} else {
			t.note("read_error", g.metadata.ID, 0, 0, true)
		}
	}
	if reused {
		t.note("identity_reused", "", 0, 0, true)
	}
	t.generations = append(t.generations, g)
}
func (t *Tailer) sourceError(err error) {
	code := "source_unavailable"
	if errors.Is(err, os.ErrNotExist) {
		code = "active_missing"
	}
	if errors.Is(err, errUnsafeFile) {
		code = "unsafe_file"
	}
	t.note(code, "", 0, 0, true)
}

// observeSize handles a decrease immediately, independently of the record
// budget. Merely retaining a maximum loses an observed shrink if the file
// regrows before its deferred read. Resetting here also makes snapshots carry
// the new generation before any record from that generation is emitted.
func (t *Tailer) observeSize(g *tailGeneration, info os.FileInfo) bool {
	if info.Size() < g.metadata.ObservedSize || info.Size() < g.readOffset {
		return t.resetGeneration(g, info)
	}
	g.metadata.ObservedSize = max(g.metadata.ObservedSize, info.Size())
	return true
}

func (t *Tailer) resetGeneration(g *tailGeneration, info os.FileInfo) bool {
	old := g.metadata.ID
	t.status.Truncations++
	t.note("file_truncated", old, g.recordOffset, max(g.lineBytes, g.metadata.ObservedSize-info.Size()), true)
	id, err := t.identity(info)
	if err != nil {
		return false
	}
	metadata, err := newGeneration(g.file, info, id, g.metadata.Path, t.now().UTC())
	if metadata.ID == "" {
		return false
	}
	g.metadata = metadata
	g.readOffset = 0
	g.recordOffset = 0
	g.lineBytes = 0
	g.partial = nil
	g.digest.Reset()
	if err != nil {
		t.note("read_error", g.metadata.ID, 0, 0, true)
		return false
	}
	return true
}

// A short read confirms loss independently of the next stat size. Use the
// current stat for the fresh metadata, but reset even if regrowth already made
// its size look healthy. Ordinary I/O failures do not call this function.
func (t *Tailer) resetAfterShortRead(g *tailGeneration) {
	info, err := g.file.Stat()
	if err != nil {
		t.note("read_error", g.metadata.ID, g.readOffset, 0, true)
		return
	}
	t.resetGeneration(g, info)
}

func (t *Tailer) inspect(g *tailGeneration) bool {
	info, err := g.file.Stat()
	if err != nil {
		t.note("read_error", g.metadata.ID, g.readOffset, 0, true)
		return false
	}
	if !t.observeSize(g, info) {
		return false
	}
	matches, err := fingerprintMatches(g.file, g.metadata)
	if err != nil {
		if isShortRead(err) {
			t.resetAfterShortRead(g)
		} else {
			t.note("read_error", g.metadata.ID, g.readOffset, 0, true)
		}
		return false
	}
	if !matches && !t.resetGeneration(g, info) {
		return false
	}
	return t.extendFingerprint(g, info)
}

// Extend a short fingerprint only after its old prefix has been verified.
func (t *Tailer) extendFingerprint(g *tailGeneration, info os.FileInfo) bool {
	n := int(min(info.Size(), int64(fingerprintLimit)))
	if n > g.metadata.FingerprintBytes {
		fingerprint, err := fingerprintAt(g.file, n)
		if err != nil {
			if isShortRead(err) {
				t.resetAfterShortRead(g)
			} else {
				t.note("read_error", g.metadata.ID, g.readOffset, 0, true)
			}
			return false
		}
		g.metadata.FingerprintBytes = n
		g.metadata.FingerprintSHA256 = fingerprint
	}
	return true
}

func (t *Tailer) read(ctx context.Context, g *tailGeneration, batch *TailerBatch) error {
	var buffer [8192]byte
	for batch.BytesRead < int64(t.cfg.MaxBytes) && len(batch.Records) < t.cfg.MaxRecords {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := int64(t.cfg.MaxBytes) - batch.BytesRead
		n, err := g.file.ReadAt(buffer[:min(int64(len(buffer)), remaining)], g.readOffset)
		batch.BytesRead += int64(n)
		if isShortRead(err) && g.readOffset+int64(n) < g.metadata.ObservedSize {
			// EOF proves a smaller extent even if the file regrows before stat.
			// Discard this ambiguous buffer before hashing/parsing or advancing
			// offsets; the next Poll rereads the fresh generation from zero.
			t.resetAfterShortRead(g)
			return nil
		}
		// An append can happen after stat. Preserve the full read-ahead extent,
		// including bytes beyond the last record admitted to this batch.
		g.metadata.ObservedSize = max(g.metadata.ObservedSize, g.readOffset+int64(n))
		data := buffer[:n]
		for len(data) > 0 && len(batch.Records) < t.cfg.MaxRecords {
			newline := bytes.IndexByte(data, '\n')
			length := len(data)
			if newline >= 0 {
				length = newline
			}
			piece := data[:length]
			g.digest.Write(piece)
			g.lineBytes += int64(length)
			g.readOffset += int64(length)
			if g.lineBytes <= RecordLimit {
				g.partial = append(g.partial, piece...)
			} else {
				g.partial = nil
			}
			if newline < 0 {
				break
			}
			g.readOffset++
			batch.appendRecord(t.complete(g), g.metadata)
			data = data[length+1:]
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.note("read_error", g.metadata.ID, g.readOffset, 0, true)
			}
			return nil
		}
		if n == 0 {
			return nil
		}
	}
	return nil
}
func (t *Tailer) complete(g *tailGeneration) TailerRecord {
	r := TailerRecord{GenerationID: g.metadata.ID, StartOffset: g.recordOffset, EndOffset: g.readOffset, ByteCount: g.lineBytes, RawHash: hex.EncodeToString(g.digest.Sum(nil))}
	trimmed := bytes.TrimSpace(g.partial)
	if g.lineBytes > RecordLimit {
		r.Problem = "record_too_large"
		t.status.OversizedRecords++
	} else if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(g.partial) || !json.Valid(g.partial) {
		r.Problem = "invalid_json"
		t.status.MalformedRecords++
	} else {
		r.raw = g.partial
	}
	if r.Problem != "" {
		t.note(r.Problem, g.metadata.ID, g.recordOffset, g.lineBytes, false)
	}
	now := t.now().UTC()
	t.status.LastCollectionTime = &now
	g.recordOffset = g.readOffset
	g.lineBytes = 0
	g.partial = nil
	g.digest.Reset()
	return r
}

func (t *Tailer) note(code, id string, offset, size int64, gap bool) {
	if gap {
		t.status.CollectionGap = true
	}
	diagnostics := t.status.Diagnostics
	if len(diagnostics) > 0 {
		last := diagnostics[len(diagnostics)-1]
		if last.Code == code && last.GenerationID == id && last.Offset == offset && last.Bytes == size {
			return
		}
	}
	if gap {
		t.status.GapCount++
	}
	next := TailerDiagnostic{Code: code, GenerationID: id, Offset: offset, Bytes: size, At: t.now().UTC()}
	if len(diagnostics) == t.cfg.MaxDiagnostics {
		copy(diagnostics, diagnostics[1:])
		diagnostics[len(diagnostics)-1] = next
	} else {
		diagnostics = append(diagnostics, next)
	}
	t.status.Diagnostics = diagnostics
}

func (t *Tailer) Status() TailerStatus {
	status := t.status
	status.Diagnostics = slices.Clone(t.status.Diagnostics)
	if status.LastCollectionTime != nil {
		at := *status.LastCollectionTime
		status.LastCollectionTime = &at
	}
	status.Generations = make([]GenerationStatus, 0, len(t.generations))
	for _, g := range t.generations {
		status.Generations = append(status.Generations, GenerationStatus{Generation: g.metadata, ReadOffset: g.readOffset, RecordOffset: g.recordOffset, PendingBytes: g.lineBytes, Detached: g.detached})
	}
	return status
}

// Retire explicitly closes a detached generation. It never infers writer exit
// from EOF. The caller should first establish its engine/retention policy and
// commit every returned record. Even a drained file may receive late writes, so
// retirement always records a potential collection gap. Diagnostic Bytes gives
// the currently pending plus unread bytes, and Offset the complete-line boundary.
// Partial final lines are discarded only by this explicit operation (or Close).
// An active file cannot be retired. There is no automatic eviction or timeout.
func (t *Tailer) Retire(id string) error {
	if t.closed {
		return ErrTailerClosed
	}
	for i, g := range t.generations {
		if g.metadata.ID != id {
			continue
		}
		if !g.detached {
			return errors.New("cannot retire active generation; poll after rotation")
		}
		info, err := g.file.Stat()
		if err != nil {
			return errors.New("cannot inspect generation for retirement")
		}
		if !t.observeSize(g, info) {
			return errors.New("cannot reset truncated generation for retirement")
		}
		pending := g.lineBytes + max(int64(0), info.Size()-g.readOffset)
		if err := g.file.Close(); err != nil {
			return errors.New("cannot close retired generation")
		}
		t.note("generation_retired", id, g.recordOffset, pending, true)
		t.generations = slices.Delete(t.generations, i, i+1)
		t.next = 0
		return nil
	}
	return errors.New("unknown file generation")
}
func (t *Tailer) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	var err error
	for _, g := range t.generations {
		if e := g.file.Close(); e != nil {
			err = fmt.Errorf("close file generation: %w", e)
		}
	}
	t.generations = nil
	return err
}
