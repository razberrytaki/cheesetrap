package ingestion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testSource() Source {
	return Source{SensorID: "10000000-0000-4000-8000-000000000104", Name: "test-sensor", Engine: "cowrie", Path: "cowrie.json", Endpoints: []Endpoint{{Service: "ssh", ObservedIP: "192.0.2.2", ObservedPort: 2222, PublicIP: "192.0.2.1", PublicPort: 22}}}
}
func TestCollectorSources(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	conf := filepath.Join(t.TempDir(), "sources.json")
	write := func(s []Source) {
		t.Helper()
		data, _ := json.Marshal(s)
		if os.WriteFile(conf, data, 0600) != nil {
			t.Fatal("write fixture")
		}
	}
	write([]Source{testSource()})
	got, err := LoadSources(root, conf)
	if err != nil || len(got) != 1 || got[0].Path != filepath.Join(root, "cowrie.json") {
		t.Fatal("trusted source manifest was not loaded")
	}
	for _, tc := range []struct {
		name   string
		change func(*Source)
	}{
		{"absolute_path", func(s *Source) { s.Path = "/elsewhere" }},
		{"parent_path", func(s *Source) { s.Path = "../elsewhere" }},
		{"unclean_path", func(s *Source) { s.Path = "foo/../bar" }},
		{"bad_uuid", func(s *Source) { s.SensorID = "engine-controlled" }},
		{"unsupported_engine", func(s *Source) { s.Engine = "unknown" }},
		{"endpoint_protocol", func(s *Source) { s.Endpoints[0].Service = "https" }},
		{"duplicate_endpoint", func(s *Source) { s.Endpoints = append(s.Endpoints, s.Endpoints[0]) }},
		{"archive_escape", func(s *Source) { s.ArchivePaths = []string{"../secret"} }},
		{"port", func(s *Source) { s.Endpoints[0].ObservedPort = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSource()
			tc.change(&s)
			write([]Source{s})
			if _, err := LoadSources(root, conf); err != ErrSources {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	write([]Source{testSource(), testSource()})
	if _, err := LoadSources(root, conf); err != ErrSources {
		t.Fatal("duplicate sensor/path accepted")
	}
	inside := filepath.Join(root, "sources.json")
	data, _ := json.Marshal([]Source{testSource()})
	_ = os.WriteFile(inside, data, 0600)
	if _, err := LoadSources(root, inside); err != ErrSources {
		t.Fatal("engine-writable manifest accepted")
	}
	_ = os.WriteFile(conf, append(data, []byte(" {}")...), 0600)
	if _, err := LoadSources(root, conf); err != ErrSources {
		t.Fatal("trailing manifest data accepted")
	}
}

func TestCollectorWebRoutingUsesObservedSocket(t *testing.T) {
	source := testSource()
	source.Engine = "web"
	source.Endpoints = []Endpoint{{Service: "http", ObservedIP: "192.0.2.2", ObservedPort: 8080, PublicIP: "192.0.2.1", PublicPort: 80}, {Service: "https", ObservedIP: "192.0.2.2", ObservedPort: 8443, PublicIP: "192.0.2.1", PublicPort: 443}}
	record := TailerRecord{GenerationID: "20000000-0000-4000-8000-000000000104", raw: []byte(`{"event_type":"web.request","protocol":"https","destination_ip":"192.0.2.2","destination_port":8080}`)}
	if _, err := decodeSource(source, record, false); err == nil {
		t.Fatal("forged protocol selected trusted HTTPS mapping for HTTP socket")
	}
	record.raw = []byte(`{"event_type":"web.request","protocol":"https","destination_ip":"192.0.2.2","destination_port":8443,"is_test":true,"sensor_id":"forged"}`)
	got, err := decodeSource(source, record, false)
	if err != nil || got.Service != "https" || got.DestinationPort != 443 || got.IsTest || got.SensorID != source.SensorID {
		t.Fatal("verified HTTPS mapping or trusted source identity failed")
	}
	record.raw = []byte(`{"event_type":"web.request","protocol":"https"}`)
	if _, err := decodeSource(source, record, false); err == nil {
		t.Fatal("missing socket accepted for routing")
	}
}
