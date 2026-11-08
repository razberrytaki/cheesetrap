//go:build integration

package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/ingestion"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

const memoryFixtureCount = 12000
const memoryTestImage = "postgres:17.11-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826"

type memoryContacts struct{}

func (memoryContacts) Lookup(_ context.Context, ip string) (enrichment.Result, error) {
	return enrichment.Result{SchemaVersion: 1, Address: ip, HeldReason: "contact_lookup_failed", Candidates: []enrichment.Contact{}}, nil
}

// A separate Linux process has a real 256 MiB cgroup limit. GOMEMLIMIT alone
// is a soft target and cannot establish that the former OOM boundary is fixed.
func TestSecurityMemoryChild(t *testing.T) {
	mode := os.Getenv("SECURITY_MEMORY_CHILD")
	if mode == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := store.NewPool(ctx, os.Getenv("SECURITY_MEMORY_DB"))
	if err != nil {
		t.Fatal("child database unavailable")
	}
	defer pool.Close()
	if mode == "detection" {
		p, err := detection.ProcessBatch(ctx, pool, 1)
		if err != nil || p.Processed != 1 {
			t.Fatal("bounded detection", p, err)
		}
	} else if mode == "wide-rules" {
		var id string
		if err := pool.QueryRow(ctx, `SELECT report_id::text FROM cheesetrap.reports WHERE source_ip='9.9.9.9'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		subject := "wide rule proof"
		r, err := ChangeRevision(ctx, pool, id, 1, RevisionChanges{Subject: &subject})
		if err != nil {
			t.Fatal("bounded wide-rule revision", err)
		}
		if e, rules := r.Snapshot.Counts(); e != 1 || rules != 32 {
			t.Fatal("wide rule proof lost entries", e, rules)
		}
		r, err = LoadRevision(ctx, pool, id)
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		err = r.Snapshot.EachRule(func(rule domain.ReportRule) error {
			var explanation detection.Explanation
			if err := json.Unmarshal(rule.Explanation, &explanation); err != nil {
				return err
			}
			if len(explanation.Paths) != (ingestion.URILimit-len("/etc/passwd"))/3 {
				return fmt.Errorf("wide explanation lost paths")
			}
			seen++
			return nil
		})
		if err != nil || seen != 32 {
			t.Fatal("wide proof traversal", seen, err)
		}
	} else if mode == "revision" {
		var id string
		if err := pool.QueryRow(ctx, `SELECT report_id::text FROM cheesetrap.reports`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		subject := "large retained proof"
		r, err := ChangeRevision(ctx, pool, id, 1, RevisionChanges{Subject: &subject})
		if err != nil {
			t.Fatal("bounded revision", err)
		}
		evidence, rules := r.Snapshot.Counts()
		if evidence != memoryFixtureCount || rules != memoryFixtureCount {
			t.Fatal("revision lost proof", evidence, rules)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		r, err = RevisionTx(ctx, tx, id)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		s := NewDraftService(pool)
		s.contacts = memoryContacts{}
		p, err := s.Next(ctx)
		if err != nil || !p.Processed {
			t.Fatal("bounded draft", p, err)
		}
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	t.Logf("mode=%s completed heap=%.2f MiB", mode, float64(stats.HeapAlloc)/(1<<20))
}

func TestSecurityAggregateMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_MEMORY_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	run := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "memory.test")
	build := exec.CommandContext(ctx, "go", "test", "-tags=integration", "-c", "-o", binaryPath, "./internal/reporting")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Linux child build: %v\n%s", err, output)
	}
	// The runner's private umask creates mode 0700; the container runs as a
	// different UID. Grant access only to this read-only test executable.
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		t.Fatalf("Linux child executable permissions: %v", err)
	}
	child := func(mode string) {
		t.Helper()
		u, err := url.Parse(os.Getenv("CHEESETRAP_TEST_MEMORY_WORKER_URL"))
		if err != nil {
			t.Fatal("test database URL")
		}
		u.Host = "127.0.0.1:5432"
		name := fmt.Sprintf("cheesetrap-memory-%s-%d", mode, time.Now().UnixNano())
		defer func() {
			mounts, _ := exec.Command("docker", "inspect", "--format", `{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}`, name).Output()
			exec.Command("docker", "rm", "-f", "-v", name).Run()
			for _, volume := range strings.Fields(string(mounts)) {
				if exec.Command("docker", "volume", "inspect", volume).Run() == nil {
					t.Errorf("%s child left volume %s", mode, volume)
				}
			}
		}()
		cmd := exec.CommandContext(ctx, "docker", "run", "--name", name, "--network", "container:"+os.Getenv("CHEESETRAP_TEST_CONTAINER"), "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "128", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "10001:10001", "-v", binaryPath+":/memory.test:ro,Z", "-e", "SECURITY_MEMORY_DB", "-e", "SECURITY_MEMORY_CHILD="+mode, "-e", "GOMEMLIMIT=192MiB", "--entrypoint", "/memory.test", memoryTestImage, "-test.run=^TestSecurityMemoryChild$", "-test.v")
		cmd.Env = append(os.Environ(), "SECURITY_MEMORY_DB="+u.String())
		output, runErr := cmd.CombinedOutput()
		state, inspectErr := exec.Command("docker", "inspect", "--format", "{{.State.OOMKilled}} {{.State.ExitCode}}", name).CombinedOutput()
		t.Logf("%s: %s; cgroup=%s", mode, strings.TrimSpace(string(output)), strings.TrimSpace(string(state)))
		if runErr != nil || inspectErr != nil || strings.TrimSpace(string(state)) != "false 0" {
			t.Fatal("bounded worker did not complete", runErr, inspectErr)
		}
	}
	at := time.Now().UTC().Add(-time.Hour)
	raw, _ := json.Marshal(map[string]any{"timestamp": at.Format(time.RFC3339Nano), "event_type": "web.request", "protocol": "http", "peer_ip": "1.1.1.1", "peer_port": 12345, "destination_ip": "8.8.8.8", "destination_port": 8080, "method": "GET", "uri": "/", "headers": []domain.Header{{Name: "content-type", Value: "text/plain"}, {Name: "x-pad", Value: strings.Repeat("b", 8192)}}, "body": strings.Repeat("a", 16384), "parse_error": ""})
	e, err := ingestion.DecodeWeb(raw, ingestion.Context{SensorID: "memory", Service: "http", ObservedIP: "8.8.8.8", ObservedPort: 8080, PublicIP: "8.8.8.8", PublicPort: 8080, Cursor: domain.SourceCursor{FileGenerationID: "memory"}, ReferenceTime: at})
	if err != nil || e.Attributes.Body == nil || len(*e.Attributes.Body) != 16384 || e.Attributes.Headers == nil || len((*e.Attributes.Headers)[1].Value) != 8192 {
		t.Fatal("fixture did not retain original attack payload")
	}
	attrs, _ := json.Marshal(e.Attributes)
	t.Logf("normalized payload=%d bytes; aggregate > %.2f MiB", len(attrs), float64(len(attrs)*memoryFixtureCount)/(1<<20))
	run(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES('10000000-0000-4000-8000-000000000999','memory','web','8.8.8.8',8080)`)
	run(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000999','10000000-0000-4000-8000-000000000999','/fixture',1,1)`)
	run(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,source_port,destination_ip,destination_port,service,event_type,attributes,raw_hash)
SELECT '10000000-0000-4000-8000-000000000999','20000000-0000-4000-8000-000000000999',n,n,1,'web',$1,$1,'1.1.1.1',12345,'8.8.8.8',8080,'http','web.request',jsonb_set($2::jsonb,'{uri}',to_jsonb((ARRAY['/.env','/.git/config','/wp-login.php','/wp-admin','/phpmyadmin'])[1+n%5])),repeat('a',64) FROM generate_series(1,$3::integer+1)n`, at, attrs, memoryFixtureCount)
	run(`INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version,settings_version) SELECT ingestion_seq,event_id,'1',1 FROM cheesetrap.events WHERE ingestion_seq<=$1`, memoryFixtureCount)
	run(`UPDATE cheesetrap.processing_cursors SET ingested_seq=$1,detected_seq=$2`, memoryFixtureCount+1, memoryFixtureCount)
	child("detection")
	var count int
	var scheme string
	if err = owner.QueryRow(ctx, `SELECT evidence_count,evidence_hash_scheme FROM cheesetrap.detection_results`).Scan(&count, &scheme); err != nil || count != memoryFixtureCount+1 || scheme != "sha256-chain-v2" {
		t.Fatal("full context proof missing", count, scheme, err)
	}
	// Same-cardinality compact control and immutable replay preserve every ID.
	run(`UPDATE cheesetrap.events SET attributes=attributes-'body'-'headers'`)
	run(`UPDATE cheesetrap.processing_cursors SET detected_seq=$1`, memoryFixtureCount)
	child("detection")
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_results`).Scan(&count); err != nil || count != 1 {
		t.Fatal("replay duplicated proof", err)
	}
	// Separate valid single-event exploit roots exercise full draft cardinality,
	// including legacy membership and large input payloads in the same window.
	run(`TRUNCATE cheesetrap.detection_evidence,cheesetrap.detection_evidence_chunks,cheesetrap.evidence_chunk_members,cheesetrap.evidence_chunks,cheesetrap.detection_results`)
	run(`UPDATE cheesetrap.events SET attributes=jsonb_set($1::jsonb,'{uri}','"/../../etc/passwd"'::jsonb),observed_at=$2::timestamptz+ingestion_seq*interval '7 seconds',ingested_at=$2::timestamptz+ingestion_seq*interval '7 seconds'`, attrs, at.Add(-24*time.Hour))
	run(`INSERT INTO cheesetrap.detection_results(rule_id,rule_version,signature_id,signature_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation)
SELECT 'WEB-EXPLOIT','1','path-traversal-etc-passwd','1',event_id,ingestion_seq,source_ip,observed_at-interval '10 minutes',observed_at,cheesetrap.evidence_set_hash(ARRAY[event_id]),1,true,false,'{}' FROM cheesetrap.events WHERE ingestion_seq<=$1`, memoryFixtureCount)
	run(`INSERT INTO cheesetrap.detection_evidence(detection_id,event_id) SELECT detection_id,processing_event_id FROM cheesetrap.detection_results`)
	run(`INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES($1,$2,1,'ready',$3,$2,$2)`, at.Add(-24*time.Hour), at, memoryFixtureCount+1)
	child("draft")
	var rules int
	var size int
	if err = owner.QueryRow(ctx, `SELECT evidence_count,rule_count,octet_length(v.snapshot::text) FROM cheesetrap.report_proofs p JOIN cheesetrap.report_revisions v USING(report_id) WHERE sealed`).Scan(&count, &rules, &size); err != nil || count != memoryFixtureCount || rules != memoryFixtureCount || size > 4096 {
		t.Fatal("draft lost evidence or retained aggregate JSON", count, rules, size, err)
	}
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.report_evidence`).Scan(&count); err != nil || count != memoryFixtureCount {
		t.Fatal("ownership copies incomplete", count, err)
	}
	t.Logf("complete draft: evidence=%d rules=%d signed snapshot=%d bytes", count, rules, size)
	child("revision")
	seedWideRuleProof(t, ctx, owner, at)
	child("wide-rules")
}

// WEB-EXPLOIT retains distinct matching paths in each explanation. Every path
// length allowed by the real normalizer can coexist in one observed-time window.
// A row-count page alone is insufficient when 32 such explanations are read.
func seedWideRuleProof(t *testing.T, ctx context.Context, owner *pgxpool.Pool, at time.Time) {
	t.Helper()
	var events []domain.Event
	for n := 1; ; n++ {
		uri := "/" + strings.Repeat("../", n) + "etc/passwd"
		if len(uri) > ingestion.URILimit {
			break
		}
		raw, _ := json.Marshal(map[string]any{"timestamp": at.Format(time.RFC3339Nano), "event_type": "web.request", "protocol": "http", "peer_ip": "9.9.9.9", "peer_port": 12345, "destination_ip": "8.8.8.8", "destination_port": 8080, "method": "GET", "uri": uri, "parse_error": ""})
		e, err := ingestion.DecodeWeb(raw, ingestion.Context{SensorID: "wide-rules", Service: "http", ObservedIP: "8.8.8.8", ObservedPort: 8080, PublicIP: "8.8.8.8", PublicPort: 8080, Cursor: domain.SourceCursor{FileGenerationID: "wide-rules"}, ReferenceTime: at})
		if err != nil || e.Attributes.URI == nil || *e.Attributes.URI != uri {
			t.Fatal("wide path rejected by normalizer", err)
		}
		id, seq := fmt.Sprintf("c0000000-0000-4000-8000-%012d", n), uint64(n)
		e.EventID, e.IngestionSeq, e.IngestedAt = &id, &seq, &at
		events = append(events, e)
	}
	results, err := detection.Evaluate(events[len(events)-1], events[:len(events)-1])
	if err != nil || len(results) != 1 || len(results[0].Explanation.Paths) != len(events) {
		t.Fatal("wide rule evaluator", err)
	}
	explanation, err := json.Marshal(results[0].Explanation)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("normalized distinct paths=%d; one rule explanation=%d bytes; 32-part payload=%.2f MiB", len(events), len(explanation), float64(32*len(explanation))/(1<<20))
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var id, window string
	if err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) SELECT window_id,'9.9.9.9' FROM cheesetrap.report_windows LIMIT 1 RETURNING report_id::text,window_id::text`).Scan(&id, &window); err != nil {
		t.Fatal(err)
	}
	w, err := newProofWriter(ctx, db.New(tx), id)
	if err != nil {
		t.Fatal(err)
	}
	rule := domain.ReportRule{RuleID: "WEB-EXPLOIT", RuleVersion: "1", EvidenceEligible: true, Explanation: explanation, ContextCount: len(events)}
	for n := 0; n < 32; n++ {
		rule.DetectionID = fmt.Sprintf("d0000000-0000-4000-8000-%012d", n+1)
		if err = w.part("rules", []domain.ReportRule{rule}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.part("evidence", []domain.ReportEvidence{{EventID: *events[0].EventID, ObservedAt: at, DestinationIP: "8.8.8.8", DestinationPort: 8080}}, 1); err != nil {
		t.Fatal(err)
	}
	registry, _ := json.Marshal(enrichment.Result{SchemaVersion: 1, Address: "9.9.9.9", HeldReason: "contact_lookup_failed", Candidates: []enrichment.Contact{}})
	r := domain.ReportRevision{ReportID: id, Version: 1, Subject: "wide rule proof", Body: "synthetic proof", State: "held", HoldReasons: []string{"contact_lookup_failed"}, Snapshot: domain.ReportSnapshot{WindowID: window, SourceIP: "9.9.9.9", ObservedStart: at, ObservedEnd: at, Registry: registry}}
	if err = w.seal(&r.Snapshot); err != nil {
		t.Fatal(err)
	}
	if err = appendRevision(ctx, db.New(tx), &r, 0); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
