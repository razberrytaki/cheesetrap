package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

func annotateBaseline(report *Report, run Run, raw []byte) {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 4096), RecordLimit+1)
	for line := 1; scan.Scan(); line++ {
		var v struct {
			Type            int            `json:"logtype"`
			At              string         `json:"utc_time"`
			Peer            string         `json:"src_host"`
			Port            int            `json:"src_port"`
			Destination     string         `json:"dst_host"`
			DestinationPort int            `json:"dst_port"`
			Data            map[string]any `json:"logdata"`
		}
		if json.Unmarshal(scan.Bytes(), &v) != nil || v.Type != 3000 {
			continue
		}
		at, e := time.Parse("2006-01-02 15:04:05.999999", v.At)
		if e != nil {
			continue
		}
		for i := range report.Results {
			r := &report.Results[i]
			if !strings.HasSuffix(r.CaseID, "-login-control") || v.Data["PATH"] != "/index.html" || v.Peer != run.ExpectedIP || v.Port < 1 || v.Destination != r.Mapping.ContainerIP || v.DestinationPort != r.Mapping.ContainerPort || at.Before(r.Attempt.StartedAt.Add(-2*time.Second)) || at.After(r.Attempt.EndedAt.Add(2*time.Second)) {
				continue
			}
			r.Evidence = &Reference{File: "raw/opencanary.log", Line: line, SHA256: Hash(scan.Bytes())}
			r.PeerIP = v.Peer
			r.PeerPort = v.Port
			for field, source := range map[string]string{"timestamp": "utc_time", "peer_ip": "src_host", "peer_port": "src_port", "destination": "dst_host/dst_port joined to raw/inspect.json"} {
				r.Fields[field] = Field{Status: "present", Source: source}
			}
			r.Fields["uri"] = Field{Status: "missing", Source: "logdata.PATH", Reason: "default log has path only; full URI/query is absent"}
			r.Fields["headers"] = Field{Status: "missing", Source: "logdata.HOSTNAME/USERAGENT", Reason: "default log has selected header summaries, not retained request headers"}
			r.Reason = "default login-page log proves peer/destination but lacks full request evidence"
		}
	}
}
