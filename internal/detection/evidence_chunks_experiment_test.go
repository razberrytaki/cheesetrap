//go:build experiment

package detection

// Pure-memory experiment. No production schema, evaluator, or storage changes.
import (
	"cheesetrap/internal/domain"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

type experimentChunkStore struct {
	width                                   uint64
	chunks                                  map[string][]string
	memberships, references, roots, logical int64
}

func newExperimentChunkStore(width uint64) *experimentChunkStore {
	return &experimentChunkStore{width: width, chunks: map[string][]string{}}
}
func (s *experimentChunkStore) roundTrip(t *testing.T, ids []string, seqs map[string]uint64) []string {
	t.Helper()
	buckets := map[uint64][]string{}
	for _, id := range ids {
		seq, ok := seqs[id]
		if !ok || seq == 0 {
			t.Fatal("missing committed evidence sequence")
		}
		bucket := (seq - 1) / s.width
		buckets[bucket] = append(buckets[bucket], id)
	}
	refs := []string{}
	for bucket, members := range buckets {
		slices.Sort(members)
		if len(slices.Compact(slices.Clone(members))) != len(members) {
			t.Fatal("duplicate evidence ID")
		}
		raw, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		key := fmt.Sprintf("%d:%d:%x", s.width, bucket, hash)
		if existing, ok := s.chunks[key]; ok {
			if !slices.Equal(existing, members) {
				t.Fatal("content hash collision")
			}
		} else {
			s.chunks[key] = slices.Clone(members)
			s.memberships += int64(len(members))
		}
		refs = append(refs, key)
	}
	s.references += int64(len(refs))
	s.roots++
	s.logical += int64(len(ids))
	decoded := []string{}
	for _, ref := range refs {
		decoded = append(decoded, s.chunks[ref]...)
	}
	slices.Sort(decoded)
	return decoded
}
func experimentVerify(t *testing.T, r Result, stores []*experimentChunkStore, seqs map[string]uint64) {
	t.Helper()
	for _, s := range stores {
		got := s.roundTrip(t, r.EvidenceIDs, seqs)
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		if !slices.Equal(got, r.EvidenceIDs) || len(got) != r.Explanation.Count || hex.EncodeToString(hash[:]) != r.EvidenceHash {
			t.Fatalf("width=%d changed exact IDs/hash/count for %s seq=%d", s.width, r.RuleID, r.ProcessingIngestionSeq)
		}
	}
}
func experimentSequences(events []domain.Event) map[string]uint64 {
	out := map[string]uint64{}
	for _, e := range events {
		out[*e.EventID] = *e.IngestionSeq
	}
	return out
}
func TestEvidenceChunksExperimentEdges(t *testing.T) {
	for _, kind := range []string{"ssh", "web", "exploit"} {
		g := fixtureGroup{Count: 24, Step: 30, Test: true}
		switch kind {
		case "web":
			g.Kind = "web"
			g.Paths = SuspiciousPaths()
		case "exploit":
			g.Kind = "web"
			g.Paths = []string{"/../etc/passwd"}
		}
		late := g
		late.Count = 1
		late.Start = 300
		late.Step = 0
		events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{g, {Count: 1, Kind: "normal", Start: 600}, late}})
		for i := range events {
			if events[i].Service == "http" && i%2 == 0 {
				events[i].Service = "https"
			}
		}
		stores := []*experimentChunkStore{newExperimentChunkStore(64), newExperimentChunkStore(128), newExperimentChunkStore(256)}
		seqs := experimentSequences(events)
		matched := 0
		for i, e := range events {
			results, err := Evaluate(e, events[:i])
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range results {
				experimentVerify(t, r, stores, seqs)
				matched++
			}
		}
		if matched == 0 {
			t.Fatal("fixture emitted no results")
		}
	}
	s := newExperimentChunkStore(64)
	seqs := map[string]uint64{"a": 1, "b": 2, "c": 3}
	if got := s.roundTrip(t, []string{"a", "c"}, seqs); !slices.Equal(got, []string{"a", "c"}) {
		t.Fatal("included nonmember")
	}
	before := s.memberships
	s.roundTrip(t, []string{"a", "c"}, seqs)
	if s.memberships != before {
		t.Fatal("identical chunk did not share")
	}
	s.roundTrip(t, []string{"a", "b"}, seqs)
	if s.memberships == before {
		t.Fatal("different subset reused chunk")
	}
}
func TestEvidenceChunksExperimentSustained(t *testing.T) {
	seconds := 300
	if raw := os.Getenv("CHEESETRAP_CHUNK_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1800 {
			t.Fatal("seconds must be 1..1800")
		}
		seconds = n
	}
	events := make([]domain.Event, 0, seconds*20)
	base := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	paths := append([]string{"/synthetic"}, SuspiciousPaths()...)
	// Calibration observed five normalized rows per SSH attempt. This models two
	// login failures, eight nonmatches, five HTTP and five HTTPS per second.
	// The deterministic normalized ordering is not an actual engine trace.
	for sec := 0; sec < seconds; sec++ {
		for slot := 0; slot < 20; slot++ {
			seq := uint64(len(events) + 1)
			sum := sha256.Sum256([]byte(fmt.Sprintf("chunk-experiment-%d", seq)))
			id := fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
			at := base.Add(time.Duration(seq-1) * 50 * time.Millisecond)
			ingested := at.Add(time.Millisecond)
			e := domain.Event{EventID: &id, IngestionSeq: &seq, ObservedAt: &at, IngestedAt: &ingested, SourceIP: "127.0.0.1", DestinationIP: "192.0.2.1", DestinationPort: 22, Engine: "cowrie", Service: "ssh", EventType: "cowrie.session.connect", IsTest: true}
			if slot == 0 || slot == 5 {
				e.EventType = "cowrie.login.failed"
			}
			if slot >= 10 {
				method := "GET"
				path := paths[(sec*5+(slot-10)%5)%len(paths)]
				e.Engine = "web"
				e.EventType = "web.request"
				e.Service = "http"
				e.DestinationPort = 80
				if slot >= 15 {
					e.Service = "https"
					e.DestinationPort = 443
				}
				e.Attributes.Method = &method
				e.Attributes.URI = &path
			}
			events = append(events, e)
		}
	}
	stores := []*experimentChunkStore{newExperimentChunkStore(64), newExperimentChunkStore(128), newExperimentChunkStore(256)}
	seqs := experimentSequences(events)
	started := time.Now()
	rules := map[string]int{}
	for i, e := range events {
		results, err := Evaluate(e, events[:i])
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			experimentVerify(t, r, stores, seqs)
			rules[r.RuleID]++
		}
	}
	type metric struct {
		Width               uint64  `json:"bucket_width"`
		Logical             int64   `json:"logical_memberships"`
		Physical            int64   `json:"physical_memberships"`
		References          int64   `json:"result_chunk_references"`
		Chunks              int     `json:"chunks"`
		Results             int64   `json:"results"`
		MembershipReduction float64 `json:"membership_reduction_fraction"`
		CombinedReduction   float64 `json:"membership_plus_reference_reduction_fraction"`
	}
	metrics := []metric{}
	for _, s := range stores {
		if s.logical == 0 {
			t.Fatal("no evidence")
		}
		metrics = append(metrics, metric{s.width, s.logical, s.memberships, s.references, len(s.chunks), s.roots, 1 - float64(s.memberships)/float64(s.logical), 1 - float64(s.memberships+s.references)/float64(s.logical)})
	}
	report := map[string]any{"schema": 1, "kind": "pure_memory_exact_membership_experiment_not_database_benchmark", "seconds": seconds, "normalized_events": len(events), "eps": 20, "rules": rules, "elapsed_seconds": time.Since(started).Seconds(), "metrics": metrics, "limitations": []string{"Synthetic deterministic order, not actual engine trace", "No PostgreSQL integration, FK/privilege, report, retention, WAL, disk-byte or throughput validation", "Header rows/index bytes excluded from combined reduction"}}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
	if out := os.Getenv("CHEESETRAP_CHUNK_OUTPUT"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
