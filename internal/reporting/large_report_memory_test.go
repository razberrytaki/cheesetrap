package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/domain"
)

// This synthetic diagnostic uses the observed large-report cardinalities. It
// carries full rule explanations and evidence metadata, not only identifiers.
func largeReportMemoryFixture() domain.ReportRevision {
	at := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	r := domain.ReportRevision{ReportID: "10000000-0000-4000-8000-000000000001", Body: "body", Subject: "subject", HoldReasons: []string{"contact_missing"}, Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1", WindowID: "20000000-0000-4000-8000-000000000001", WindowStart: at, WindowEnd: at.Add(time.Hour), ObservedStart: at, ObservedEnd: at.Add(time.Hour), Registry: []byte(`{"address":"1.1.1.1","lookup_succeeded":false,"held_reason":"contact_lookup_failed"}`)}}
	r.Snapshot.Evidence = make([]domain.ReportEvidence, 18600)
	for i := range r.Snapshot.Evidence {
		r.Snapshot.Evidence[i] = domain.ReportEvidence{EventID: fmt.Sprintf("30000000-0000-4000-8000-%012d", i), IngestionSeq: int64(i + 1), SensorID: "40000000-0000-4000-8000-000000000001", Engine: "web", ObservedAt: at, IngestedAt: at, SourceIP: "1.1.1.1", SourcePort: 12345, DestinationIP: "8.8.8.8", DestinationPort: 8080, Service: "http", EventType: "web.request", Method: "GET", URI: "/.env", RawHash: strings.Repeat("a", 64), QualityFlags: []string{}, FieldCompleteness: map[string]string{"method": "present", "uri": "present", "body": "present", "headers": "present"}, Truncation: map[string]domain.Truncation{"uri": {Limit: 4096, Observed: 5, Retained: 5}, "body": {Limit: 8192}, "headers": {Limit: 8192}}}
	}
	r.Snapshot.Rules = make([]domain.ReportRule, 18572)
	config := detection.DefaultConfig()
	for i := range r.Snapshot.Rules {
		explanation, _ := json.Marshal(detection.Explanation{SettingsVersion: "1", RuleConfig: &config, RuleVersion: "1", Count: 3570, Threshold: 20, DistinctPathThreshold: 5, Paths: detection.SuspiciousPaths(), RequiredFields: []string{"source_ip", "observed_at", "event_type", "attributes.method", "attributes.uri"}, ObservedStart: at, ObservedEnd: at.Add(time.Hour), WindowStart: at, WindowEnd: at.Add(time.Hour), HoldReasons: []string{}})
		r.Snapshot.Rules[i] = domain.ReportRule{SettingsVersion: "1", DetectionID: fmt.Sprintf("50000000-0000-4000-8000-%012d", i), RuleID: "WEB-REPEAT", RuleVersion: "1", ContextCount: 3570, AttachedCount: 3570, EvidenceHash: strings.Repeat("b", 64), EvidenceEligible: true, AutoApprovalAllowed: true, Explanation: explanation}
	}
	return r
}

func BenchmarkLargeReportContentDigest(b *testing.B) {
	r := largeReportMemoryFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ContentDigest(r); err != nil {
			b.Fatal(err)
		}
	}
}

// Run explicitly for allocation/peak diagnostics; ordinary tests do not pay
// for sampling or write heap artifacts. No runtime memory tuning is applied.
func BenchmarkLargeReportMemoryDiagnostic(t *testing.B) {
	directory := os.Getenv("CHEESETRAP_REPORT_MEMORY_DIAGNOSTICS")
	if directory == "" {
		t.Skip("explicit local memory diagnostic")
	}
	continuous := os.Getenv("CHEESETRAP_REPORT_MEMORY_CONTINUOUS") == "1"
	r := largeReportMemoryFixture()
	for _, phase := range []struct {
		name string
		run  func()
	}{
		{"prepare_explanations", func() {
			for _, rule := range r.Snapshot.Rules {
				var e detection.Explanation
				if err := json.Unmarshal(rule.Explanation, &e); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"render", func() {
			var err error
			r.Subject, r.Body, err = Render(r)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"evidence_marshal", func() {
			data, err := json.Marshal(r.Snapshot.Evidence)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("evidence bytes=%d", len(data))
			runtime.KeepAlive(data)
		}},
		{"content_digest", func() {
			digest, err := ContentDigest(r)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("digest=%s", digest)
		}},
		{"snapshot_marshal", func() {
			data, err := marshalReportSnapshot(r.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("snapshot bytes=%d", len(data))
			runtime.KeepAlive(data)
		}},
	} {
		if !continuous {
			runtime.GC()
		}
		var start runtime.MemStats
		runtime.ReadMemStats(&start)
		stop := make(chan struct{})
		done := make(chan runtime.MemStats)
		go func() {
			peak := start
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					done <- peak
					return
				case <-tick.C:
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					if m.HeapAlloc > peak.HeapAlloc {
						peak = m
					}
				}
			}
		}()
		began := time.Now()
		phase.run()
		close(stop)
		peak := <-done
		var end runtime.MemStats
		runtime.ReadMemStats(&end)
		t.Logf("phase=%s elapsed=%s start_heap=%d peak_heap=%d heap_sys=%d heap_inuse=%d heap_released=%d sys_minus_released=%d allocated=%d gc=%d", phase.name, time.Since(began), start.HeapAlloc, peak.HeapAlloc, peak.HeapSys, peak.HeapInuse, peak.HeapReleased, peak.Sys-peak.HeapReleased, end.TotalAlloc-start.TotalAlloc, end.NumGC-start.NumGC)
	}
	runtime.KeepAlive(r)
	profile := "/large-report-allocs-optimized-isolated.pprof"
	if continuous {
		profile = "/large-report-allocs-optimized-continuous.pprof"
	}
	profile = strings.TrimSuffix(profile, ".pprof") + "-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".pprof"
	t.Logf("allocation profile=%s", profile)
	f, err := os.Create(directory + profile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
		t.Fatal(err)
	}
}
