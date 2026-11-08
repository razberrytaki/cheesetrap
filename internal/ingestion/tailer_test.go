//go:build darwin || linux

package ingestion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeLog(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func appendLog(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
func newTestTailer(t *testing.T, cfg TailerConfig) *Tailer {
	t.Helper()
	tail, err := NewTailer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tail.Close(); err != nil {
			t.Error(err)
		}
	})
	return tail
}
func pollLog(t *testing.T, tail *Tailer) TailerBatch {
	t.Helper()
	b, err := tail.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func countRecords(t *testing.T, b TailerBatch, n int) {
	t.Helper()
	if len(b.Records) != n {
		t.Fatalf("got %d records, want %d; status=%+v", len(b.Records), n, b.Status)
	}
}
func hasDiagnostic(s TailerStatus, code string) bool {
	for _, d := range s.Diagnostics {
		if d.Code == code {
			return true
		}
	}
	return false
}
func TestTailerPartialAndIdenticalRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cowrie.json")
	raw := encoded(t, baseCowrie())
	writeLog(t, path, raw[:20])
	tail := newTestTailer(t, TailerConfig{Path: path})
	now := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	tail.now = func() time.Time { return now }
	first := pollLog(t, tail)
	countRecords(t, first, 0)
	if first.Status.LastCollectionTime != nil || first.Status.Generations[0].RecordOffset != 0 {
		t.Fatal("partial line advanced collection/checkpoint boundary")
	}
	appendLog(t, path, append(append(append([]byte{}, raw[20:]...), '\n'), append(raw, '\n')...))
	second := pollLog(t, tail)
	countRecords(t, second, 2)
	a, b := second.Records[0], second.Records[1]
	if a.StartOffset != 0 || a.EndOffset != int64(len(raw)+1) || b.StartOffset != a.EndOffset || a.GenerationID != b.GenerationID || a.RawHash != digest(raw) || a.RawHash != b.RawHash || !bytes.Equal(a.Bytes(), raw) {
		t.Fatal("exact bytes/offset identity lost")
	}
	if a.Problem != "" || second.Status.CollectionGap || second.Status.LastCollectionTime == nil || !second.Status.LastCollectionTime.Equal(now) {
		t.Fatal("unexpected record/status")
	}
	mutated := a.Bytes()
	mutated[0] = '!'
	if !bytes.Equal(a.Bytes(), raw) {
		t.Fatal("caller mutated retained payload")
	}
	countRecords(t, pollLog(t, tail), 0)
	encodedBatch := string(encoded(t, second))
	for _, output := range []string{encodedBatch, fmt.Sprint(a), fmt.Sprintf("%+v", a), fmt.Sprintf("%#v", a), fmt.Sprintf("%#v", second), fmt.Sprint(second), fmt.Sprintf("%+v", second)} {
		if strings.Contains(output, "cowrie-secret") || strings.Contains(output, "username") {
			t.Fatal("record diagnostics expose source payload")
		}
	}
}
func TestTailerRenameAndLateWrites(t *testing.T) {
	for _, engine := range []string{"cowrie daily rename reopen", "web external rename reopen", "cowrie external rename no reopen"} {
		t.Run(engine, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			first, second, late := []byte("{\"n\":1}\n"), []byte("{\"n\":2}\n"), []byte("{\"n\":3}\n")
			writeLog(t, path, first)
			tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			initial := pollLog(t, tail)
			countRecords(t, initial, 1)
			original := initial.Records[0].GenerationID
			archive := path + ".2026-10-17"
			appendLog(t, path, second)
			if err := os.Rename(path, archive); err != nil {
				t.Fatal(err)
			}
			if engine != "cowrie external rename no reopen" {
				writeLog(t, path, first)
			}
			drained := pollLog(t, tail)
			countRecords(t, drained, 1)
			if drained.Records[0].GenerationID != original || drained.Records[0].StartOffset != int64(len(first)) {
				t.Fatal("old file not drained")
			}
			next := pollLog(t, tail)
			if engine != "cowrie external rename no reopen" {
				countRecords(t, next, 1)
				if next.Records[0].GenerationID == original {
					t.Fatal("replacement reused generation")
				}
			} else {
				countRecords(t, next, 0)
				if !hasDiagnostic(next.Status, "active_missing") {
					t.Fatal("missing active path not visible")
				}
			}
			// Multiple observed EOFs are not evidence that the old writer has closed.
			countRecords(t, pollLog(t, tail), 0)
			appendLog(t, archive, late)
			got := pollLog(t, tail)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID != original || got.Records[0].StartOffset != int64(len(first)+len(second)) {
				t.Fatal("late old-inode write lost")
			}
		})
	}
}
func TestTailerArchiveDateCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cowrie.json")
	writeLog(t, path, []byte("{\"n\":1}\n"))
	writeLog(t, path+".2026-10-17", []byte("{\"archived\":true}\n"))
	tail := newTestTailer(t, TailerConfig{Path: path})
	a := pollLog(t, tail)
	countRecords(t, a, 1)
	// Cowrie declines a daily rotation when its date archive exists and appends.
	appendLog(t, path, []byte("{\"n\":2}\n"))
	b := pollLog(t, tail)
	countRecords(t, b, 1)
	if b.Records[0].GenerationID != a.Records[0].GenerationID || b.Status.CollectionGap {
		t.Fatal("filename date determined identity")
	}
}
func TestTailerTruncationAndReplacement(t *testing.T) {
	for _, mode := range []string{"observed truncate", "regrown changed prefix", "injected inode reuse"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			original := []byte("{\"old\":123456789}\n{\"partial\":")
			writeLog(t, path, original)
			tail := newTestTailer(t, TailerConfig{Path: path})
			if mode == "injected inode reuse" {
				tail.identity = func(os.FileInfo) (fileIdentity, error) { return fileIdentity{Device: 7, Inode: 8}, nil }
			}
			a := pollLog(t, tail)
			countRecords(t, a, 1)
			fresh := []byte("{\"new\":1}\n")
			if mode == "regrown changed prefix" {
				fresh = []byte("{\"new\":123456789012345678901234567890123456789}\n")
			}
			if mode == "injected inode reuse" {
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
			}
			writeLog(t, path, fresh)
			b := pollLog(t, tail)
			countRecords(t, b, 1)
			if b.Records[0].GenerationID == a.Records[0].GenerationID || b.Records[0].StartOffset != 0 || !bytes.Equal(b.Records[0].Bytes(), bytes.TrimSuffix(fresh, []byte("\n"))) || !b.Status.CollectionGap {
				t.Fatal("replacement mixed with previous generation")
			}
			if mode != "injected inode reuse" && b.Status.Truncations != 1 {
				t.Fatal("truncation counter missing")
			}
		})
	}
}
func TestTailerDamagedLinesAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	bad := []byte("{\"password\":\"secret-malformed\"")
	oversized := bytes.Repeat([]byte("s"), RecordLimit+17)
	valid := []byte("{\"ok\":true}")
	data := bytes.Join([][]byte{bad, oversized, valid}, []byte("\n"))
	data = append(data, '\n')
	writeLog(t, path, data)
	tail := newTestTailer(t, TailerConfig{Path: path, MaxBytes: 8192, MaxRecords: 2, MaxDiagnostics: 2})
	var records []TailerRecord
	for i := 0; i < 100 && len(records) < 3; i++ {
		batch := pollLog(t, tail)
		if batch.BytesRead > 8192 || len(batch.Records) > 2 || len(batch.Status.Diagnostics) > 2 {
			t.Fatal("poll budget exceeded")
		}
		for _, g := range tail.generations {
			if len(g.partial) > RecordLimit {
				t.Fatal("oversized line grew buffer")
			}
		}
		records = append(records, batch.Records...)
	}
	if len(records) != 3 {
		t.Fatalf("recovery stopped: %d", len(records))
	}
	for i, want := range []string{"invalid_json", "record_too_large", ""} {
		if records[i].Problem != want {
			t.Fatalf("record %d problem=%q", i, records[i].Problem)
		}
	}
	if records[0].Bytes() != nil || records[1].Bytes() != nil || records[0].RawHash != digest(bad) || records[1].RawHash != digest(oversized) || records[1].ByteCount != int64(len(oversized)) || records[2].StartOffset != int64(len(bad)+len(oversized)+2) {
		t.Fatal("quarantine metadata/raw isolation wrong")
	}
	status := tail.Status()
	if status.MalformedRecords != 1 || status.OversizedRecords != 1 {
		t.Fatal("damaged counters missing")
	}
	if strings.Contains(string(encoded(t, records)), "secret-malformed") {
		t.Fatal("bad record credential leak")
	}
}
func TestTailerRecordBoundaryLimitAndCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	exact := append([]byte("{\"x\":\""), bytes.Repeat([]byte("x"), RecordLimit-8)...)
	exact = append(exact, []byte("\"}")...)
	if len(exact) != RecordLimit {
		t.Fatal("bad test boundary")
	}
	crlf := []byte("{\"ok\":1}\r")
	writeLog(t, path, append(append(append(append([]byte{}, exact...), '\n'), crlf...), '\n'))
	tail := newTestTailer(t, TailerConfig{Path: path})
	got := pollLog(t, tail)
	countRecords(t, got, 2)
	if got.Records[0].Problem != "" || got.Records[0].RawHash != digest(exact) || got.Records[1].RawHash != digest(crlf) || !bytes.Equal(got.Records[1].Bytes(), crlf) {
		t.Fatal("limit/newline changed source bytes")
	}
}
func TestTailerDeletionAndUnsafeFiles(t *testing.T) {
	t.Run("deleted before first read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.json")
		writeLog(t, path, []byte("{}\n"))
		tail := newTestTailer(t, TailerConfig{Path: path})
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		got := pollLog(t, tail)
		countRecords(t, got, 0)
		if !got.Status.CollectionGap || !hasDiagnostic(got.Status, "active_missing") || got.Status.LastCollectionTime != nil {
			t.Fatal("unopened missing file reported healthy")
		}
	})
	for _, kind := range []string{"symlink", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			switch kind {
			case "symlink":
				target := path + ".target"
				writeLog(t, target, []byte("{}\n"))
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			tail := newTestTailer(t, TailerConfig{Path: path})
			got := pollLog(t, tail)
			countRecords(t, got, 0)
			if !got.Status.CollectionGap || !hasDiagnostic(got.Status, "unsafe_file") {
				t.Fatal("unsafe source not rejected")
			}
		})
	}
	t.Run("unlink held descriptor still drains", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.json")
		writeLog(t, path, []byte("{}\n{}\n"))
		tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
		a := pollLog(t, tail)
		countRecords(t, a, 1)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		b := pollLog(t, tail)
		countRecords(t, b, 1)
		if b.Records[0].GenerationID != a.Records[0].GenerationID {
			t.Fatal("unlink lost pinned generation")
		}
	})
}
func TestTailerResumeCommittedBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	line := []byte("{\"n\":1}\n")
	writeLog(t, path, append(append(append([]byte{}, line...), line...), []byte("{\"partial\":")...))
	tail := newTestTailer(t, TailerConfig{Path: path})
	a := pollLog(t, tail)
	countRecords(t, a, 2)
	generation := a.Status.Generations[0].Generation
	if err := tail.Close(); err != nil {
		t.Fatal(err)
	}
	// Persist only the caller's committed first line, not the tailer's read offset.
	saved := ResumePoint{Generation: generation, ByteOffset: int64(len(line))}
	var restored ResumePoint
	if err := json.Unmarshal(encoded(t, saved), &restored); err != nil {
		t.Fatal(err)
	}
	archive := path + ".2026-10-17"
	if err := os.Rename(path, archive); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, []byte("{\"new\":2}\n"))
	restarted := newTestTailer(t, TailerConfig{Path: path, ArchivePaths: []string{archive}, Resume: []ResumePoint{restored}})
	b := pollLog(t, restarted)
	countRecords(t, b, 2)
	if b.Records[0].GenerationID != generation.ID || b.Records[0].StartOffset != int64(len(line)) || b.Records[1].GenerationID == generation.ID || b.Status.CollectionGap {
		t.Fatal("restart did not replay uncommitted line with original identity")
	}
	appendLog(t, archive, []byte("true}\n"))
	c := pollLog(t, restarted)
	countRecords(t, c, 1)
	if c.Records[0].GenerationID != generation.ID || c.Records[0].StartOffset != 2*int64(len(line)) {
		t.Fatal("restart lost partial record")
	}
}
func TestTailerResumeMissingChangedAndInvalidBoundary(t *testing.T) {
	for _, kind := range []string{"missing", "changed fingerprint", "past EOF", "mid-record"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, []byte("{\"n\":1}\n"))
			tail := newTestTailer(t, TailerConfig{Path: path})
			first := pollLog(t, tail)
			countRecords(t, first, 1)
			saved := ResumePoint{Generation: first.Status.Generations[0].Generation, ByteOffset: first.Records[0].EndOffset}
			if err := tail.Close(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "changed fingerprint":
				writeLog(t, path, []byte("{\"n\":2}\n"))
			case "past EOF":
				saved.ByteOffset += 9
			case "mid-record":
				saved.ByteOffset = 3
			}
			resumed := newTestTailer(t, TailerConfig{Path: path, Resume: []ResumePoint{saved}})
			got := pollLog(t, resumed)
			if !got.Status.CollectionGap || !hasDiagnostic(got.Status, "resume_unavailable") {
				t.Fatal("invalid resume silently accepted")
			}
			if kind != "missing" {
				countRecords(t, got, 1)
				if got.Records[0].GenerationID == saved.Generation.ID || got.Records[0].StartOffset != 0 {
					t.Fatal("invalid resume retained generation")
				}
			}
		})
	}
}
func TestTailerCapacityRetirementAndFairness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, []byte("{}\n"))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxOpenFiles: 2, MaxRecords: 1, MaxDiagnostics: 2})
	a := pollLog(t, tail)
	countRecords(t, a, 1)
	firstID := a.Records[0].GenerationID
	if err := tail.Retire(firstID); err == nil {
		t.Fatal("retired active generation")
	}
	if err := os.Rename(path, path+".one"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, []byte("{}\n"))
	b := pollLog(t, tail)
	countRecords(t, b, 1)
	appendLog(t, path+".one", bytes.Repeat([]byte("{}\n"), 10))
	appendLog(t, path, []byte("{}\n"))
	one := pollLog(t, tail)
	two := pollLog(t, tail)
	countRecords(t, one, 1)
	countRecords(t, two, 1)
	if one.Records[0].GenerationID == two.Records[0].GenerationID {
		t.Fatal("busy older file starves newer generation")
	}
	if err := os.Rename(path, path+".two"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, []byte("{\"three\":3}\n"))
	full := pollLog(t, tail)
	if len(full.Status.Generations) != 2 || !full.Status.CollectionGap || !hasDiagnostic(full.Status, "capacity_exceeded") {
		t.Fatal("descriptor cap silently evicted a file")
	}
	if err := tail.Retire(firstID); err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(tail.Status(), "generation_retired") {
		t.Fatal("explicit retirement risk hidden")
	}
	found := false
	for i := 0; i < 4; i++ {
		next := pollLog(t, tail)
		for _, r := range next.Records {
			if bytes.Equal(r.Bytes(), []byte("{\"three\":3}")) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("capacity recovery failed")
	}
	if err := tail.Retire("missing"); err == nil {
		t.Fatal("unknown retirement accepted")
	}
}
func TestTailerCancellationCloseAndConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, []byte("{}\n"))
	tail := newTestTailer(t, TailerConfig{Path: path})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tail.Poll(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if len(tail.Status().Generations) != 0 {
		t.Fatal("cancelled poll opened source")
	}
	if err := tail.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := tail.Poll(context.Background()); !errors.Is(err, ErrTailerClosed) {
		t.Fatal("closed tailer read")
	}
	for _, cfg := range []TailerConfig{{}, {Path: path, MaxRecords: -1}, {Path: path, MaxBytes: -1}, {Path: path, MaxOpenFiles: 65}, {Path: path, MaxDiagnostics: 1025}, {Path: path, Resume: []ResumePoint{{ByteOffset: -1}}}} {
		if bad, err := NewTailer(cfg); err == nil {
			bad.Close()
			t.Fatal("invalid config accepted")
		}
	}
}
func TestTailerEngineFixtures(t *testing.T) {
	var manifest fixtureManifest
	data, err := os.ReadFile("../../testdata/engines/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range manifest.Engines {
		t.Run(fixture.Engine, func(t *testing.T) {
			raw, err := os.ReadFile("../../testdata/engines/" + fixture.Fixture)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, raw)
			tail := newTestTailer(t, TailerConfig{Path: path})
			var records []TailerRecord
			for i := 0; i < 100 && len(records) < fixture.RowCount; i++ {
				records = append(records, pollLog(t, tail).Records...)
			}
			if len(records) != fixture.RowCount {
				t.Fatalf("fixture records=%d want=%d", len(records), fixture.RowCount)
			}
			for i, r := range records {
				if r.RawHash != fixture.Rows[i].Hash || r.StartOffset != fixture.Rows[i].Offset || r.Problem != "" {
					t.Fatalf("fixture line %d hash/offset changed", i+1)
				}
				service := "ssh"
				if fixture.Engine == "web" {
					var source struct {
						Protocol string `json:"protocol"`
					}
					if err = json.Unmarshal(r.Bytes(), &source); err != nil {
						t.Fatal(err)
					}
					service = source.Protocol
				}
				c := contextFor(service)
				c.Cursor.FileGenerationID = r.GenerationID
				c.Cursor.ByteOffset = r.StartOffset
				fn := DecodeCowrie
				if fixture.Engine == "web" {
					fn = DecodeWeb
				}
				event, err := fn(r.Bytes(), c)
				if err != nil {
					t.Fatal(err)
				}
				if event.RawHash != r.RawHash || event.EventID != nil || event.IngestedAt != nil || event.IngestionSeq != nil {
					t.Fatal("tailer altered adapter precommit contract")
				}
			}
		})
	}
}

func TestTailerOversizedPartialAndJSONErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	partial := bytes.Repeat([]byte("s"), RecordLimit+1)
	writeLog(t, path, partial)
	tail := newTestTailer(t, TailerConfig{Path: path, MaxBytes: 16 * 1024})
	for range 20 {
		batch := pollLog(t, tail)
		countRecords(t, batch, 0)
	}
	status := tail.Status()
	if status.Generations[0].PendingBytes != int64(len(partial)) || status.Generations[0].RecordOffset != 0 || status.LastCollectionTime != nil || len(tail.generations[0].partial) != 0 {
		t.Fatal("unterminated oversized record was retained or emitted")
	}
	invalidUTF8 := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	suffix := append([]byte("\n"), invalidUTF8...)
	suffix = append(suffix, []byte("\n[]\n\n{}\n")...)
	appendLog(t, path, suffix)
	got := pollLog(t, tail)
	countRecords(t, got, 5)
	for i, want := range []string{"record_too_large", "invalid_json", "invalid_json", "invalid_json", ""} {
		if got.Records[i].Problem != want {
			t.Fatalf("record %d=%q want=%q", i, got.Records[i].Problem, want)
		}
	}
	if got.Records[0].RawHash != digest(partial) || got.Status.OversizedRecords != 1 || got.Status.MalformedRecords != 3 {
		t.Fatal("partial discard state or counters lost")
	}
}

func TestTailerResumeShortFingerprintAfterAppend(t *testing.T) {
	for _, initial := range []string{"", "{}\n"} {
		t.Run(fmt.Sprintf("initial_bytes_%d", len(initial)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, []byte(initial))
			tail := newTestTailer(t, TailerConfig{Path: path})
			first := pollLog(t, tail)
			saved := ResumePoint{Generation: first.Status.Generations[0].Generation, ByteOffset: int64(len(initial))}
			if err := tail.Close(); err != nil {
				t.Fatal(err)
			}
			appendLog(t, path, []byte("{\"appended\":true}\n"))
			resumed := newTestTailer(t, TailerConfig{Path: path, Resume: []ResumePoint{saved}})
			got := pollLog(t, resumed)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID != saved.Generation.ID || got.Records[0].StartOffset != saved.ByteOffset || got.Status.CollectionGap {
				t.Fatal("legitimate append invalidated fixed-length resume fingerprint")
			}
		})
	}
}

func TestTailerRetirementAndStatusBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, []byte("{}\n{\"password\":\"pending-secret"))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxOpenFiles: 2, MaxDiagnostics: 2})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	saved := tail.Status()
	saved.Generations[0].Generation.ID = "changed"
	saved.LastCollectionTime.Add(time.Hour)
	originalTime := *tail.Status().LastCollectionTime
	*saved.LastCollectionTime = time.Time{}
	if *tail.Status().LastCollectionTime != originalTime || tail.Status().Generations[0].Generation.ID == "changed" {
		t.Fatal("snapshot aliases internal state")
	}
	for i := range 8 {
		current := tail.Status().Generations[0]
		if err := os.Rename(path, fmt.Sprintf("%s.%d", path, i)); err != nil {
			t.Fatal(err)
		}
		writeLog(t, path, []byte("{}\n"))
		pollLog(t, tail)
		if err := tail.Retire(current.Generation.ID); err != nil {
			t.Fatal(err)
		}
		status := tail.Status()
		if len(status.Generations) != 1 || len(status.Diagnostics) > 2 || len(tail.generations) != 1 {
			t.Fatal("retired states grew without bounds")
		}
		last := status.Diagnostics[len(status.Diagnostics)-1]
		if last.Code != "generation_retired" || last.GenerationID != current.Generation.ID || i == 0 && last.Bytes != current.PendingBytes {
			t.Fatal("retirement omitted pending source bytes")
		}
		if strings.Contains(string(encoded(t, status)), "pending-secret") {
			t.Fatal("retirement leaked discarded partial")
		}
	}
	held := tail.generations[0].file
	if err := tail.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := held.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("Close left descriptor open")
	}
}

func TestTailerObservedUnreadTruncation(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart_%t", restart), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
			tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			first := pollLog(t, tail)
			countRecords(t, first, 1)
			saved := ResumePoint{Generation: first.Status.Generations[0].Generation, ByteOffset: first.Records[0].EndOffset}
			if restart {
				if err := tail.Close(); err != nil {
					t.Fatal(err)
				}
				var decoded ResumePoint
				if err := json.Unmarshal(encoded(t, saved), &decoded); err != nil {
					t.Fatal(err)
				}
				tail = newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1, Resume: []ResumePoint{decoded}})
			}
			// The first 4096 bytes and every consumed byte survive. The known unread
			// suffix still disappeared, so neither fingerprint nor cursor is sufficient.
			if err := os.Truncate(path, 8192); err != nil {
				t.Fatal(err)
			}
			got := pollLog(t, tail)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID == first.Records[0].GenerationID || got.Records[0].StartOffset != 0 || got.Status.Truncations != 1 || !got.Status.CollectionGap || !hasDiagnostic(got.Status, "file_truncated") {
				t.Fatalf("observed unread shrink was not a new generation and gap: record=%+v status=%+v", got.Records[0], got.Status)
			}
		})
	}
}

func TestTailerReadAheadExtendsSizeWitness(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart_%t", restart), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, bytes.Repeat([]byte("{}\n"), 1366)) // 4098 bytes
			tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			first := pollLog(t, tail)
			countRecords(t, first, 1)
			g := tail.generations[0]
			if !tail.inspect(g) {
				t.Fatal("could not inspect original file")
			}
			// A real append after stat, before ReadAt. Exercise that boundary directly,
			// without a timing race or replacing the filesystem with a fake reader.
			appendLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
			batch := TailerBatch{}
			if err := tail.read(context.Background(), g, &batch); err != nil {
				t.Fatal(err)
			}
			countRecords(t, batch, 1)
			if batch.BytesRead != 8192 || batch.Records[0].EndOffset != 6 || tail.Status().CollectionGap {
				t.Fatal("ordinary append changed identity or read budget")
			}
			saved := ResumePoint{Generation: tail.Status().Generations[0].Generation, ByteOffset: batch.Records[0].EndOffset}
			if restart {
				if err := tail.Close(); err != nil {
					t.Fatal(err)
				}
				var decoded ResumePoint
				if err := json.Unmarshal(encoded(t, saved), &decoded); err != nil {
					t.Fatal(err)
				}
				tail = newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1, Resume: []ResumePoint{decoded}})
			}
			// ReadAt observed through offset 8195 despite returning one record. A shrink
			// to 8193 exceeds the earlier stat size and cursor but loses observed bytes.
			if err := os.Truncate(path, 8193); err != nil {
				t.Fatal(err)
			}
			got := pollLog(t, tail)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID == first.Records[0].GenerationID || got.Records[0].StartOffset != 0 || got.Status.Truncations != 1 || !got.Status.CollectionGap {
				t.Fatal("read-ahead extent was not retained for truncation detection")
			}
		})
	}
}

func TestTailerTruncatedArchiveResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	saved := ResumePoint{Generation: first.Status.Generations[0].Generation, ByteOffset: first.Records[0].EndOffset}
	if err := tail.Close(); err != nil {
		t.Fatal(err)
	}
	archive := path + ".archive"
	if err := os.Rename(path, archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(archive, 8192); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, []byte("{\"active\":true}\n"))
	resumed := newTestTailer(t, TailerConfig{Path: path, ArchivePaths: []string{archive}, MaxRecords: 1, Resume: []ResumePoint{saved}})
	got := pollLog(t, resumed)
	countRecords(t, got, 1)
	if got.Records[0].GenerationID == saved.Generation.ID || got.Records[0].StartOffset != 0 || got.Status.Generations[0].Generation.Path != archive || !got.Status.CollectionGap || got.Status.Truncations != 1 {
		t.Fatal("truncated archive reused its old generation or lost its gap")
	}
	next := pollLog(t, resumed)
	countRecords(t, next, 1)
	if !bytes.Equal(next.Records[0].Bytes(), []byte("{\"active\":true}")) || !next.Status.CollectionGap {
		t.Fatal("archive recovery hid active source or cleared gap")
	}
}

func TestTailerDeferredInspectionRetainsObservedSize(t *testing.T) {
	t.Run("reconcile active while old file fills batch", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.json")
		writeLog(t, path, []byte("{}\n"))
		tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
		pollLog(t, tail)
		archive := path + ".old"
		if err := os.Rename(path, archive); err != nil {
			t.Fatal(err)
		}
		writeLog(t, path, []byte("{}\n"))
		active := pollLog(t, tail)
		countRecords(t, active, 1)
		appendLog(t, archive, bytes.Repeat([]byte("{}\n"), 10))
		appendLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
		deferred := pollLog(t, tail)
		countRecords(t, deferred, 1)
		if deferred.Records[0].GenerationID == active.Records[0].GenerationID {
			t.Fatal("test did not defer active inspection")
		}
		if err := os.Truncate(path, 8192); err != nil {
			t.Fatal(err)
		}
		got := pollLog(t, tail)
		countRecords(t, got, 1)
		if got.Records[0].GenerationID == active.Records[0].GenerationID || got.Status.Truncations != 1 || !got.Status.CollectionGap {
			t.Fatal("reconciliation forgot the observed active size")
		}
	})
	t.Run("restore observes growth before later inspection", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.json")
		writeLog(t, path, []byte("{}\n"))
		tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
		first := pollLog(t, tail)
		countRecords(t, first, 1)
		saved := ResumePoint{Generation: first.Status.Generations[0].Generation, ByteOffset: first.Records[0].EndOffset}
		if err := tail.Close(); err != nil {
			t.Fatal(err)
		}
		appendLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
		resumed := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1, Resume: []ResumePoint{saved}})
		if err := resumed.restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, 8192); err != nil {
			t.Fatal(err)
		}
		got := pollLog(t, resumed)
		countRecords(t, got, 1)
		if got.Records[0].GenerationID == saved.Generation.ID || got.Status.Truncations != 1 || !got.Status.CollectionGap {
			t.Fatal("restore forgot growth observed before inspection")
		}
	})
}

func TestTailerObservedShrinkSurvivesDeferredReadAndRegrowth(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart_%t", restart), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, bytes.Repeat([]byte("{}\n"), 12))
			tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			pollLog(t, tail)
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			content := bytes.Repeat([]byte("{}\n"), 4096)
			writeLog(t, path, content)
			pollLog(t, tail)
			active := pollLog(t, tail)
			countRecords(t, active, 1)
			if active.Records[0].StartOffset != 0 {
				t.Fatal("test did not read the active generation")
			}
			if err := os.Truncate(path, 8192); err != nil {
				t.Fatal(err)
			}
			deferred := pollLog(t, tail)
			countRecords(t, deferred, 1)
			if deferred.Records[0].GenerationID == active.Records[0].GenerationID {
				t.Fatal("active read was not deferred")
			}
			var snapshot GenerationStatus
			for _, g := range deferred.Status.Generations {
				if !g.Detached {
					snapshot = g
				}
			}
			if snapshot.Generation.ID == active.Records[0].GenerationID || snapshot.RecordOffset != 0 || deferred.Status.Truncations != 1 || !deferred.Status.CollectionGap {
				t.Fatal("observed decrease was deferred with the read budget")
			}
			if restart {
				saved := ResumePoint{Generation: snapshot.Generation, ByteOffset: snapshot.RecordOffset}
				var decoded ResumePoint
				if err := json.Unmarshal(encoded(t, saved), &decoded); err != nil {
					t.Fatal(err)
				}
				if err := tail.Close(); err != nil {
					t.Fatal(err)
				}
				tail = newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1, Resume: []ResumePoint{decoded}})
			}
			writeLog(t, path, content)
			got := pollLog(t, tail)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID != snapshot.Generation.ID || got.Records[0].StartOffset != 0 {
				t.Fatal("regrowth or restart forgot the already observed generation change")
			}
			// The caller persists process-local gap status separately from resume data.
			if !restart && (got.Status.Truncations != 1 || !got.Status.CollectionGap) {
				t.Fatal("regrowth cleared the observed gap")
			}
		})
	}
}

func TestTailerRestoreDuplicateCheckPreservesObservedShrink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.json")
	other := filepath.Join(directory, "other.json")
	content := bytes.Repeat([]byte("{}\n"), 4096)
	writeLog(t, path, content)
	writeLog(t, other, []byte("{}\n"))
	source := newTestTailer(t, TailerConfig{Path: other})
	otherBatch := pollLog(t, source)
	saved := ResumePoint{Generation: otherBatch.Status.Generations[0].Generation}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	if err := os.Truncate(path, 8192); err != nil {
		t.Fatal(err)
	}
	// A pending restore can run after an earlier generation has already opened,
	// as when cancellation separates the bounded candidate checks.
	tail.resume = []ResumePoint{saved}
	if err := tail.restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := tail.Status()
	if status.Generations[0].Generation.ID == first.Records[0].GenerationID || status.Truncations != 1 || !status.CollectionGap {
		t.Fatal("restore duplicate-check stat forgot a held-file decrease")
	}
	writeLog(t, path, content)
	got := pollLog(t, tail)
	countRecords(t, got, 1)
	if got.Records[0].GenerationID != status.Generations[0].Generation.ID || got.Records[0].StartOffset != 0 {
		t.Fatal("regrowth lost duplicate-check generation reset")
	}
}

func TestTailerRetireReportsObservedShrink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	archive := path + ".old"
	if err := os.Rename(path, archive); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, []byte("{}\n"))
	pollLog(t, tail)
	if err := os.Truncate(archive, 8192); err != nil {
		t.Fatal(err)
	}
	if err := tail.Retire(first.Records[0].GenerationID); err != nil {
		t.Fatal(err)
	}
	if status := tail.Status(); status.Truncations != 1 || !hasDiagnostic(status, "file_truncated") || !hasDiagnostic(status, "generation_retired") {
		t.Fatal("retirement omitted an observed truncation")
	}
}

func TestTailerObservedShrinkSurvivesFingerprintReadRace(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart_%t", restart), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			content := bytes.Repeat([]byte("{}\n"), 4096)
			writeLog(t, path, content)
			tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			first := pollLog(t, tail)
			countRecords(t, first, 1)
			if err := os.Truncate(path, 8192); err != nil {
				t.Fatal(err)
			}
			smaller, err := tail.generations[0].file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			// The real file shrinks again after stat but before the reset's prefix read.
			// No fake filesystem, sleeps, or timing-dependent goroutines are needed.
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
			if tail.observeSize(tail.generations[0], smaller) {
				t.Fatal("fingerprint read unexpectedly succeeded")
			}
			status := tail.Status()
			generation := status.Generations[0].Generation
			if generation.ID == first.Records[0].GenerationID || status.Generations[0].RecordOffset != 0 || status.Truncations != 1 || !status.CollectionGap {
				t.Fatal("failed fingerprint read revived the old generation")
			}
			if restart {
				var saved ResumePoint
				if err := json.Unmarshal(encoded(t, ResumePoint{Generation: generation}), &saved); err != nil {
					t.Fatal(err)
				}
				if err := tail.Close(); err != nil {
					t.Fatal(err)
				}
				tail = newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1, Resume: []ResumePoint{saved}})
			}
			writeLog(t, path, content)
			got := pollLog(t, tail)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID != generation.ID || got.Records[0].StartOffset != 0 {
				t.Fatal("regrowth reused identity from before the observed truncation")
			}
		})
	}
}

func TestTailerAdmissionObservesLstatToOpenChanges(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		for _, change := range []string{"shrink", "shrink below fingerprint", "append"} {
			t.Run(fmt.Sprintf("replacement_%t/%s", replacement, change), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "events.json")
				tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
				if replacement {
					writeLog(t, path, []byte("{}\n"))
					pollLog(t, tail)
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
				}
				writeLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
				changed := false
				tail.identity = func(info os.FileInfo) (fileIdentity, error) {
					id, err := identifyFile(info)
					if !changed {
						changed = true
						if info.Size() != 12288 {
							t.Fatalf("initial Lstat size=%d", info.Size())
						}
						switch change {
						case "shrink":
							if err := os.Truncate(path, 8192); err != nil {
								t.Fatal(err)
							}
						case "shrink below fingerprint":
							if err := os.Truncate(path, 3); err != nil {
								t.Fatal(err)
							}
						case "append":
							appendLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
						}
					}
					return id, err
				}
				got := pollLog(t, tail)
				countRecords(t, got, 1)
				if change == "append" {
					if got.Status.CollectionGap || got.Status.Truncations != 0 {
						t.Fatal("normal append between Lstat and open caused a false gap")
					}
				} else if !got.Status.CollectionGap || got.Status.Truncations != 1 || !hasDiagnostic(got.Status, "file_truncated") {
					t.Fatal("new admission discarded its earlier larger Lstat observation")
				}
			})
		}
	}
}

func TestTailerPayloadEOFObservesShrinkBeforeParsing(t *testing.T) {
	for _, size := range []int64{8192, 0} {
		t.Run(fmt.Sprintf("truncate_to_%d", size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			content := bytes.Repeat([]byte("{}\n"), 4096)
			writeLog(t, path, content)
			tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			first := pollLog(t, tail)
			countRecords(t, first, 1)
			g := tail.generations[0]
			if !tail.inspect(g) {
				t.Fatal("could not inspect original file")
			}
			if err := os.Truncate(path, size); err != nil {
				t.Fatal(err)
			}
			ambiguous := TailerBatch{}
			if err := tail.read(context.Background(), g, &ambiguous); err != nil {
				t.Fatal(err)
			}
			countRecords(t, ambiguous, 0)
			status := tail.Status()
			fresh := status.Generations[0]
			if fresh.Generation.ID == first.Records[0].GenerationID || fresh.RecordOffset != 0 || status.Truncations != 1 || !status.CollectionGap {
				t.Fatal("EOF-proven shrink was forgotten before regrowth")
			}
			if ambiguous.BytesRead != max(int64(0), size-3) {
				t.Fatal("discarded bytes escaped the input budget")
			}
			writeLog(t, path, content)
			got := pollLog(t, tail)
			countRecords(t, got, 1)
			if got.Records[0].GenerationID != fresh.Generation.ID || got.Records[0].StartOffset != 0 {
				t.Fatal("ambiguous EOF bytes were labeled with the old generation")
			}
		})
	}
	t.Run("normal append short read EOF", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.json")
		writeLog(t, path, bytes.Repeat([]byte("{}\n"), 1707))
		tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
		first := pollLog(t, tail)
		countRecords(t, first, 1)
		g := tail.generations[0]
		if !tail.inspect(g) {
			t.Fatal("could not inspect original file")
		}
		appendLog(t, path, []byte("{}\n{}\n"))
		got := TailerBatch{}
		if err := tail.read(context.Background(), g, &got); err != nil {
			t.Fatal(err)
		}
		countRecords(t, got, 1)
		if got.Records[0].GenerationID != first.Records[0].GenerationID || got.Records[0].StartOffset != 3 || tail.Status().CollectionGap || tail.Status().Truncations != 0 {
			t.Fatal("normal append plus EOF changed the generation")
		}
	})
}

func TestTailerResumeFailureCannotBeUndoneByCandidateRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	original := bytes.Repeat([]byte("{}\n"), 4096)
	writeLog(t, path, original)
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	saved := ResumePoint{Generation: first.Status.Generations[0].Generation, ByteOffset: first.Records[0].EndOffset}
	if err := tail.Close(); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(original)
	changed[0] = ' '
	writeLog(t, path, changed)
	resumed := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1, Resume: []ResumePoint{saved}})
	calls := 0
	resumed.identity = func(info os.FileInfo) (fileIdentity, error) {
		id, err := identifyFile(info)
		calls++
		if calls == 2 {
			writeLog(t, path, original)
		}
		return id, err
	}
	got := pollLog(t, resumed)
	countRecords(t, got, 1)
	if got.Records[0].GenerationID == saved.Generation.ID || got.Records[0].StartOffset != 0 || !got.Status.CollectionGap {
		t.Fatal("later candidate retry erased an observed resume fingerprint failure")
	}
}

func TestTailerFingerprintExtensionEOFResetsGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, []byte("{}\n"))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	content := bytes.Repeat([]byte("{}\n"), 4096)
	writeLog(t, path, content)
	g := tail.generations[0]
	info, err := g.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	matched, matchErr := fingerprintMatches(g.file, g.metadata)
	if !tail.observeSize(g, info) || !matched || matchErr != nil {
		t.Fatal("ordinary append failed the existing prefix check")
	}
	// A real shrink after the old prefix check, before extending that prefix.
	if err := os.Truncate(path, 3); err != nil {
		t.Fatal(err)
	}
	if tail.extendFingerprint(g, info) {
		t.Fatal("short prefix read unexpectedly succeeded")
	}
	status := tail.Status()
	fresh := status.Generations[0]
	if fresh.Generation.ID == first.Records[0].GenerationID || fresh.RecordOffset != 0 || status.Truncations != 1 || !status.CollectionGap {
		t.Fatal("prefix-extension EOF left the old generation active")
	}
	writeLog(t, path, content)
	got := pollLog(t, tail)
	countRecords(t, got, 1)
	if got.Records[0].GenerationID != fresh.Generation.ID || got.Records[0].StartOffset != 0 {
		t.Fatal("prefix-extension failure was erased by later regrowth")
	}
}

func TestTailerFingerprintIOFailureDoesNotRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	writeLog(t, path, []byte("{}\n"))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	first := pollLog(t, tail)
	countRecords(t, first, 1)
	appendLog(t, path, bytes.Repeat([]byte("{}\n"), 4096))
	g := tail.generations[0]
	info, err := g.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !tail.observeSize(g, info) {
		t.Fatal("append observation failed")
	}
	if err := g.file.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if tail.extendFingerprint(g, info) {
			t.Fatal("closed descriptor unexpectedly readable")
		}
		status := tail.Status()
		if status.Generations[0].Generation.ID != first.Records[0].GenerationID || status.Truncations != 0 || !hasDiagnostic(status, "read_error") {
			t.Fatal("ordinary I/O failure was treated as a confirmed source rewrite")
		}
	}
	// Close is still invoked to leave the test helper's cleanup idempotent.
	if err := tail.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("expected the already closed descriptor error")
	}
}

func TestTailerResumeTemporaryOpenFailure(t *testing.T) {
	for _, inject := range []bool{false, true} {
		t.Run(fmt.Sprintf("inject_permission_errno_%t", inject), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			writeLog(t, path, []byte("{\"n\":1}\n{\"n\":2}\n"))
			first := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
			initial := pollLog(t, first)
			saved := ResumePoint{Generation: initial.Status.Generations[0].Generation, ByteOffset: initial.Records[0].EndOffset}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(path, 0600) })
			resumed := newTestTailer(t, TailerConfig{Path: path, Resume: []ResumePoint{saved}})
			if inject || os.Geteuid() == 0 {
				// Root may bypass chmod. Inject only the permission errno while all
				// source creation, resume metadata, and recovered reads stay real.
				resumed.openSource = func(string) (*os.File, os.FileInfo, error) {
					return nil, nil, unix.EACCES
				}
			}
			for range 2 {
				unavailable := pollLog(t, resumed)
				countRecords(t, unavailable, 0)
				if len(resumed.resume) != 1 || len(unavailable.Status.Generations) != 0 || hasDiagnostic(unavailable.Status, "resume_unavailable") || !hasDiagnostic(unavailable.Status, "read_error") {
					t.Fatal("temporary open failure discarded the committed resume point or admitted a fresh generation")
				}
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			resumed.openSource = openLog
			recovered := pollLog(t, resumed)
			countRecords(t, recovered, 1)
			if recovered.Records[0].GenerationID != saved.Generation.ID || recovered.Records[0].StartOffset != saved.ByteOffset || len(resumed.resume) != 0 {
				t.Fatal("permission recovery replayed committed records under a fresh identity")
			}

		})
	}
}

func TestTailerBatchRetainsEmittedGenerationMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	line := append([]byte("{\"v\":\""), bytes.Repeat([]byte("x"), 8183)...)
	line = append(line, []byte("\"}\n")...)
	if len(line) != 8192 {
		t.Fatalf("line bytes = %d", len(line))
	}
	writeLog(t, path, append(bytes.Clone(line), line...))
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 2})
	calls := 0
	tail.now = func() time.Time {
		calls++
		if calls == 2 {
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
		}
		return time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	}
	batch := pollLog(t, tail)
	countRecords(t, batch, 1)
	if !batch.Status.CollectionGap || batch.Status.Truncations != 1 || batch.Status.Generations[0].Generation.ID == batch.Records[0].GenerationID {
		t.Fatal("fixture did not reset the live generation after emitting its first record")
	}
	var returned struct {
		Generations []FileGeneration `json:"generations"`
	}
	if err := json.Unmarshal(encoded(t, batch), &returned); err != nil {
		t.Fatal(err)
	}
	if len(returned.Generations) != 1 || returned.Generations[0].ID != batch.Records[0].GenerationID {
		t.Fatal("returned record lost its generation metadata when the live generation reset")
	}
	metadata := returned.Generations[0]
	if metadata.Path != path || metadata.ObservedSize != 2*int64(len(line)) || !validResume(ResumePoint{Generation: metadata, ByteOffset: batch.Records[0].EndOffset}) {
		t.Fatal("emitted generation snapshot cannot support caller-controlled commit/resume")
	}
}

func TestTailerResumeOtherCandidateAfterOpenFailure(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocked, "events.json")
	archive := filepath.Join(dir, "archive.json")
	writeLog(t, path, []byte("{\"n\":1}\n{\"n\":2}\n"))
	if err := os.Link(path, archive); err != nil {
		t.Fatal(err)
	}
	first := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 1})
	initial := pollLog(t, first)
	saved := ResumePoint{Generation: initial.Status.Generations[0].Generation, ByteOffset: initial.Records[0].EndOffset}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(blocked, 0700) })
	resumed := newTestTailer(t, TailerConfig{Path: path, ArchivePaths: []string{archive}, Resume: []ResumePoint{saved}})
	if os.Geteuid() == 0 {
		resumed.openSource = func(candidate string) (*os.File, os.FileInfo, error) {
			if candidate == path {
				return nil, nil, unix.EACCES
			}
			return openLog(candidate)
		}
	}
	got := pollLog(t, resumed)
	countRecords(t, got, 1)
	if got.Records[0].GenerationID != saved.Generation.ID || got.Records[0].StartOffset != saved.ByteOffset || len(resumed.resume) != 0 || hasDiagnostic(got.Status, "resume_unavailable") {
		t.Fatal("an inaccessible candidate blocked restoration from an accessible archive")
	}
}

func TestTailerBatchSnapshotsAreBoundedAndIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	line := append([]byte("{\"v\":\""), bytes.Repeat([]byte("x"), 8183)...)
	line = append(line, []byte("\"}\n")...)
	writeLog(t, path, line)
	tail := newTestTailer(t, TailerConfig{Path: path, MaxRecords: 2})
	calls := 0
	tail.now = func() time.Time {
		calls++
		if calls == 2 {
			appendLog(t, path, line)
		}
		return time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	}
	batch := pollLog(t, tail)
	countRecords(t, batch, 2)
	if len(batch.Generations) != 1 || batch.Records[0].GenerationID != batch.Records[1].GenerationID || batch.Generations[0].ID != batch.Records[0].GenerationID || batch.Generations[0].ObservedSize < batch.Records[1].EndOffset {
		t.Fatal("per-batch metadata was duplicated or did not include the last emitted extent")
	}
	before := bytes.Clone(encoded(t, batch))
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	next := pollLog(t, tail)
	countRecords(t, next, 0)
	if len(next.Generations) != 0 || !bytes.Equal(before, encoded(t, batch)) {
		t.Fatal("live state reset mutated an earlier batch snapshot or added metadata without records")
	}
	batch.Generations[0].Path = "caller-mutated"
	if tail.Status().Generations[0].Generation.Path != path {
		t.Fatal("caller mutation of a batch snapshot changed the live generation")
	}
}
