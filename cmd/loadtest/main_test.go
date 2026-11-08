package main

import (
	"bytes"
	"cheesetrap/internal/ingestion"
	"cheesetrap/internal/loadtest"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestNoOperationalDefault(t *testing.T) {
	var out bytes.Buffer
	if execute(nil, &out) == nil {
		t.Fatal("missing config accepted")
	}
	if out.Len() != 0 {
		t.Fatal("unexpected report")
	}
}

func TestCollectorTestGuardBeforeTraffic(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(404) }))
	defer server.Close()
	sourcesPath := filepath.Join(dir, "sources.json")
	sources := []ingestion.Source{{SensorID: "10000000-0000-4000-8000-000000000707", Name: "load-test", Engine: "web", Path: "web.json", IsTest: false, Endpoints: []ingestion.Endpoint{{Service: "http", ObservedIP: "172.30.91.11", ObservedPort: 8080, PublicIP: "192.0.2.10", PublicPort: 8080}}}}
	write := func(path string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(sourcesPath, sources)
	c := loadtest.Config{IsolatedTest: true, ExternalEnrichmentDisabled: true, CollectorLogDir: logs, CollectorSourcesFile: sourcesPath, HTTPURL: server.URL, Concurrency: 1, Timeout: "1s"}
	configPath := filepath.Join(dir, "config.json")
	write(configPath, c)
	scenariosPath := filepath.Join(dir, "scenarios.json")
	os.WriteFile(scenariosPath, []byte(`{"schema_version":1,"scenarios":[{"name":"smoke","duration":"20ms","http_requests_per_second":50}]}`), 0600)
	args := []string{"-config", configPath, "-scenarios", scenariosPath, "-scenario", "smoke"}
	var out bytes.Buffer
	if e := execute(args, &out); e == nil || e.Error() != "all_collector_sources_must_be_test" {
		t.Fatalf("unexpected guard error: %v", e)
	}
	if requests.Load() != 0 {
		t.Fatal("traffic before guard")
	}
	sources[0].IsTest = true
	write(sourcesPath, sources)
	if e := execute(args, &out); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 1 {
		t.Fatal("expected real HTTP request")
	}
	var report loadtest.Report
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	if report.NormalizedEventsPerSecond != nil {
		t.Fatal("normalized count fabricated")
	}
}
