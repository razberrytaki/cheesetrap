package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store"
	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
)

type ReportDraft struct {
	ReportID          string    `json:"report_id"`
	Version           string    `json:"version"`
	CurrentRevisionID string    `json:"current_revision_id"`
	SourceIP          string    `json:"source_ip"`
	State             string    `json:"state"`
	CreatedAt         time.Time `json:"created_at"`
	Subject           string    `json:"subject"`
	Recipient         string    `json:"recipient"`
	HoldReasons       []string  `json:"hold_reasons"`
	EvidenceCount     string    `json:"evidence_count"`
	RuleCount         string    `json:"rule_count"`
}
type RevisionView struct {
	ReportID          string          `json:"report_id"`
	RevisionID        string          `json:"revision_id"`
	Version           string          `json:"version"`
	Subject           string          `json:"subject"`
	Body              string          `json:"body"`
	Recipient         string          `json:"recipient"`
	ReplyTo           string          `json:"reply_to"`
	State             string          `json:"state"`
	HoldReasons       []string        `json:"hold_reasons"`
	BodyEdited        bool            `json:"body_edited"`
	ContentDigest     string          `json:"content_digest"`
	CreatedAt         time.Time       `json:"created_at"`
	SourceIP          string          `json:"source_ip"`
	WindowID          string          `json:"window_id"`
	WindowStart       string          `json:"window_start"`
	WindowEnd         string          `json:"window_end"`
	ObservedStart     string          `json:"observed_start"`
	ObservedEnd       string          `json:"observed_end"`
	DelayedCollection bool            `json:"delayed_collection"`
	Registry          json.RawMessage `json:"registry"`
	RegistryTruncated bool            `json:"registry_truncated"`
	EvidenceCount     string          `json:"evidence_count"`
	RuleCount         string          `json:"rule_count"`
}
type RefreshView struct {
	RequestID         string     `json:"request_id"`
	ExpectedVersion   string     `json:"expected_version"`
	CurrentRevisionID string     `json:"current_revision_id"`
	Status            string     `json:"status"`
	ResultRevisionID  *string    `json:"result_revision_id"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at"`
}
type reportListInput struct {
	Limit    int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Cursor   string `query:"cursor" maxLength:"512"`
	SourceIP string `query:"source_ip" maxLength:"64"`
	State    string `query:"state" enum:"needs_review,held,rejected,archived"`
}
type reportListOutput struct {
	Body struct {
		Items      []ReportDraft `json:"items"`
		NextCursor string        `json:"next_cursor"`
	}
}
type reportDetailOutput struct {
	Body struct {
		ReportDraft
		Revision      RevisionView `json:"revision"`
		LatestRefresh *RefreshView `json:"latest_refresh"`
	}
}
type RevisionInput struct {
	ID         string `path:"id" format:"uuid"`
	RevisionID string `path:"revision_id" format:"uuid"`
}
type revisionOutput struct{ Body RevisionView }
type revisionListInput struct {
	ID     string `path:"id" format:"uuid"`
	Limit  int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Cursor string `query:"cursor" maxLength:"512"`
}
type revisionSummary struct {
	RevisionID    string    `json:"revision_id"`
	Version       string    `json:"version"`
	State         string    `json:"state"`
	Recipient     string    `json:"recipient"`
	ContentDigest string    `json:"content_digest"`
	CreatedAt     time.Time `json:"created_at"`
}
type revisionListOutput struct {
	Body struct {
		Items      []revisionSummary `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
}
type revisionPageInput struct {
	RevisionInput
	Limit  int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Cursor string `query:"cursor" maxLength:"512"`
}
type EvidenceView struct {
	domain.ReportEvidence
	IngestionSeq   string `json:"ingestion_seq" doc:"Lossless ingestion bigint"`
	EntryTruncated bool   `json:"entry_truncated"`
}

type RuleView struct {
	EvidenceHashScheme string          `json:"evidence_hash_scheme,omitempty"`
	SettingsVersion    string          `json:"settings_version,omitempty"`
	DetectionID        string          `json:"detection_id"`
	RuleID             string          `json:"rule_id"`
	RuleVersion        string          `json:"rule_version"`
	SignatureID        string          `json:"signature_id,omitempty"`
	SignatureVersion   string          `json:"signature_version,omitempty"`
	ContextCount       int             `json:"context_count"`
	AttachedCount      int             `json:"attached_count"`
	EvidenceHash       string          `json:"evidence_hash"`
	EvidenceEligible   bool            `json:"evidence_eligible"`
	Explanation        json.RawMessage `json:"explanation"`
	EntryTruncated     bool            `json:"entry_truncated"`
}
type evidencePageOutput struct {
	Body struct {
		Items      []EvidenceView `json:"items"`
		Total      string         `json:"total"`
		NextCursor string         `json:"next_cursor"`
	}
}
type rulePageOutput struct {
	Body struct {
		Items      []RuleView `json:"items"`
		Total      string     `json:"total"`
		NextCursor string     `json:"next_cursor"`
	}
}
type revisionPageOutput struct {
	Body struct {
		Items      []json.RawMessage `json:"items"`
		Total      string            `json:"total"`
		NextCursor string            `json:"next_cursor"`
	}
}
type ipInput struct {
	DetectionLimit  int    `query:"detection_limit" default:"50" minimum:"1" maximum:"200"`
	DetectionCursor string `query:"detection_cursor" maxLength:"512"`
	IP              string `path:"ip" maxLength:"64"`
	Limit           int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Cursor          string `query:"cursor" maxLength:"512"`
}
type ipOutput struct {
	Body struct {
		Registry            json.RawMessage `json:"registry"`
		RegistryTruncated   bool            `json:"registry_truncated"`
		RegistryExpiresAt   *time.Time      `json:"registry_expires_at"`
		RegistryExpired     bool            `json:"registry_expired"`
		Detections          []DetectionView `json:"detections"`
		NextDetectionCursor string          `json:"next_detection_cursor"`

		Address       string        `json:"address"`
		Reports       []ReportDraft `json:"reports"`
		NextCursor    string        `json:"next_cursor"`
		LatestRefresh *RefreshView  `json:"latest_refresh"`
	}
}

func (s *server) reviewOperation(id, method, path string) huma.Operation {
	security := map[string][]string{"session": {}}
	middlewares := huma.Middlewares{s.requireSession}
	if method != "GET" {
		security["csrf"] = []string{}
	}
	switch id {
	case "reports-select-contact":
		middlewares = append(middlewares, completeProofCommand)
	}
	return huma.Operation{OperationID: id, Method: method, Path: path, Middlewares: middlewares, Errors: []int{400, 401, 403, 404, 409, 422, 503}, Security: []map[string][]string{security}}
}
func pageCursor(raw, scope string) (snapshot, before int64, err error) {
	snapshot = math.MaxInt64
	before = math.MaxInt64
	if raw == "" {
		return
	}
	var c cursor
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil || json.Unmarshal(b, &c) != nil || c.Version != 1 || c.Filters != scope {
		return 0, 0, apiError(400)
	}
	snapshot, e = strconv.ParseInt(c.Snapshot, 10, 64)
	if e != nil || snapshot < 1 {
		return 0, 0, apiError(400)
	}
	before, e = strconv.ParseInt(c.Before, 10, 64)
	if e != nil || before < 1 || before > snapshot {
		return 0, 0, apiError(400)
	}
	return
}
func encodePage(snapshot, before int64, scope string) string {
	b, _ := json.Marshal(cursor{Version: 1, Snapshot: strconv.FormatInt(snapshot, 10), Before: strconv.FormatInt(before, 10), Filters: scope})
	return base64.RawURLEncoding.EncodeToString(b)
}
func pageScope(parts ...string) string {
	b, _ := json.Marshal(parts)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

const reportColumns = `r.report_id::text,r.version::text,r.current_revision_id::text,host(r.source_ip),` + store.ReportStateSQL + `,r.created_at,v.subject,v.recipient,v.hold_reasons,CASE WHEN v.snapshot ? 'proof' THEN v.snapshot->'proof'->>'evidence_count' ELSE jsonb_array_length(v.snapshot->'evidence')::text END,CASE WHEN v.snapshot ? 'proof' THEN v.snapshot->'proof'->>'rule_count' ELSE jsonb_array_length(v.snapshot->'rules')::text END`

func scanReport(row pgx.Row, r *ReportDraft, tail ...any) error {
	args := []any{&r.ReportID, &r.Version, &r.CurrentRevisionID, &r.SourceIP, &r.State, &r.CreatedAt, &r.Subject, &r.Recipient, &r.HoldReasons, &r.EvidenceCount, &r.RuleCount}
	return row.Scan(append(args, tail...)...)
}
func (s *server) listReports(ctx context.Context, in *reportListInput) (*reportListOutput, error) {
	if in.SourceIP != "" {
		ip, ok := enrichment.PublicAddress(in.SourceIP)
		if !ok {
			return nil, apiError(400)
		}
		in.SourceIP = ip.String()
	}
	scope := pageScope("reports", in.SourceIP, in.State)
	snapshot, before, err := pageCursor(in.Cursor, scope)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+reportColumns+`,r.review_seq FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id WHERE r.review_seq<=$1 AND r.review_seq<$2 AND ($3='' OR host(r.source_ip)=$3) AND ($4='' OR (`+store.ReportStateSQL+`)=$4) ORDER BY r.review_seq DESC LIMIT $5`, snapshot, before, in.SourceIP, in.State, in.Limit+1)
	if err != nil {
		return nil, apiError(503)
	}
	defer rows.Close()
	out := &reportListOutput{}
	out.Body.Items = []ReportDraft{}
	var last int64
	for rows.Next() {
		var r ReportDraft
		var seq int64
		if err = scanReport(rows, &r, &seq); err != nil {
			return nil, apiError(503)
		}
		if len(out.Body.Items) == in.Limit {
			out.Body.NextCursor = encodePage(snapshot, last, scope)
			break
		}
		if len(out.Body.Items) == 0 && in.Cursor == "" {
			snapshot = seq
		}
		out.Body.Items = append(out.Body.Items, r)
		last = seq
	}
	if rows.Err() != nil {
		return nil, apiError(503)
	}
	return out, nil
}
func (s *server) readRevision(ctx context.Context, id, revision string) (RevisionView, error) {
	var v RevisionView
	err := s.pool.QueryRow(ctx, `SELECT report_id::text,revision_id::text,version::text,subject,body,recipient,reply_to,state,hold_reasons,body_edited,content_digest,created_at,
 snapshot->>'source_ip',snapshot->>'window_id',snapshot->>'window_start',snapshot->>'window_end',snapshot->>'observed_start',snapshot->>'observed_end',coalesce((snapshot->>'delayed_collection')::boolean,false),
 CASE WHEN octet_length((snapshot->'registry')::text)<=65536 THEN snapshot->'registry' ELSE '{}'::jsonb END,coalesce(octet_length((snapshot->'registry')::text)>65536,false),CASE WHEN snapshot ? 'proof' THEN snapshot->'proof'->>'evidence_count' ELSE jsonb_array_length(snapshot->'evidence')::text END,CASE WHEN snapshot ? 'proof' THEN snapshot->'proof'->>'rule_count' ELSE jsonb_array_length(snapshot->'rules')::text END
 FROM cheesetrap.report_revisions WHERE report_id=$1 AND revision_id=$2`, id, revision).Scan(&v.ReportID, &v.RevisionID, &v.Version, &v.Subject, &v.Body, &v.Recipient, &v.ReplyTo, &v.State, &v.HoldReasons, &v.BodyEdited, &v.ContentDigest, &v.CreatedAt, &v.SourceIP, &v.WindowID, &v.WindowStart, &v.WindowEnd, &v.ObservedStart, &v.ObservedEnd, &v.DelayedCollection, &v.Registry, &v.RegistryTruncated, &v.EvidenceCount, &v.RuleCount)
	return v, err
}
func (s *server) latestRefresh(ctx context.Context, report, ip string) (*RefreshView, error) {
	var v RefreshView
	err := s.pool.QueryRow(ctx, `SELECT f.request_id::text,f.expected_version::text,f.revision_id::text,f.status,f.result_revision_id::text,f.created_at,f.completed_at FROM cheesetrap.contact_refresh_requests f JOIN cheesetrap.reports r USING(report_id) WHERE ($1='' OR f.report_id::text=$1) AND ($2='' OR host(r.source_ip)=$2) ORDER BY f.created_at DESC,f.request_id DESC LIMIT 1`, report, ip).Scan(&v.RequestID, &v.ExpectedVersion, &v.CurrentRevisionID, &v.Status, &v.ResultRevisionID, &v.CreatedAt, &v.CompletedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &v, err
}
func (s *server) registerReports(a huma.API) {
	huma.Register(a, s.reviewOperation("reports-list", "GET", "/api/v1/reports"), s.listReports)
	huma.Register(a, s.reviewOperation("reports-get", "GET", "/api/v1/reports/{id}"), func(ctx context.Context, in *eventInput) (*reportDetailOutput, error) {
		out := &reportDetailOutput{}
		err := scanReport(s.pool.QueryRow(ctx, `SELECT `+reportColumns+` FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id WHERE r.report_id=$1`, in.ID), &out.Body.ReportDraft)
		if err != nil {
			return nil, reviewError(err)
		}
		out.Body.Revision, err = s.readRevision(ctx, in.ID, out.Body.CurrentRevisionID)
		if err != nil {
			return nil, reviewError(err)
		}
		out.Body.LatestRefresh, err = s.latestRefresh(ctx, in.ID, "")
		if err != nil {
			return nil, apiError(503)
		}
		return out, nil
	})
	huma.Register(a, s.reviewOperation("report-revisions-list", "GET", "/api/v1/reports/{id}/revisions"), func(ctx context.Context, in *revisionListInput) (*revisionListOutput, error) {
		scope := pageScope("revisions", in.ID)
		snapshot, before, err := pageCursor(in.Cursor, scope)
		if err != nil {
			return nil, err
		}
		var exists bool
		if err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.reports WHERE report_id=$1)`, in.ID).Scan(&exists); err != nil {
			return nil, apiError(503)
		}
		if !exists {
			return nil, apiError(404)
		}
		rows, err := s.pool.Query(ctx, `SELECT revision_id::text,version::text,state,recipient,content_digest,created_at FROM cheesetrap.report_revisions WHERE report_id=$1 AND version<=$2 AND version<$3 ORDER BY version DESC LIMIT $4`, in.ID, snapshot, before, in.Limit+1)
		if err != nil {
			return nil, apiError(503)
		}
		defer rows.Close()
		out := &revisionListOutput{}
		out.Body.Items = []revisionSummary{}
		var last int64
		for rows.Next() {
			var v revisionSummary
			if err = rows.Scan(&v.RevisionID, &v.Version, &v.State, &v.Recipient, &v.ContentDigest, &v.CreatedAt); err != nil {
				return nil, apiError(503)
			}
			if len(out.Body.Items) == in.Limit {
				out.Body.NextCursor = encodePage(snapshot, last, scope)
				break
			}
			last, _ = strconv.ParseInt(v.Version, 10, 64)
			if len(out.Body.Items) == 0 && in.Cursor == "" {
				snapshot = last
			}
			out.Body.Items = append(out.Body.Items, v)
		}
		if rows.Err() != nil {
			return nil, apiError(503)
		}
		return out, nil
	})
	huma.Register(a, s.reviewOperation("report-revisions-get", "GET", "/api/v1/reports/{id}/revisions/{revision_id}"), func(ctx context.Context, in *RevisionInput) (*revisionOutput, error) {
		v, err := s.readRevision(ctx, in.ID, in.RevisionID)
		if err != nil {
			return nil, reviewError(err)
		}
		return &revisionOutput{Body: v}, nil
	})
	huma.Register(a, s.reviewOperation("report-revision-evidence", "GET", "/api/v1/reports/{id}/revisions/{revision_id}/evidence"), func(ctx context.Context, in *revisionPageInput) (*evidencePageOutput, error) {
		page, err := s.revisionPage(ctx, in, "evidence")
		if err != nil {
			return nil, err
		}
		out := &evidencePageOutput{}
		out.Body.Items = []EvidenceView{}
		out.Body.Total = page.Body.Total
		out.Body.NextCursor = page.Body.NextCursor
		for _, data := range page.Body.Items {
			var v EvidenceView
			if json.Unmarshal(data, &v) != nil {
				return nil, apiError(503)
			}
			out.Body.Items = append(out.Body.Items, v)
		}
		return out, nil
	})
	huma.Register(a, s.reviewOperation("report-revision-rules", "GET", "/api/v1/reports/{id}/revisions/{revision_id}/rules"), func(ctx context.Context, in *revisionPageInput) (*rulePageOutput, error) {
		page, err := s.revisionPage(ctx, in, "rules")
		if err != nil {
			return nil, err
		}
		out := &rulePageOutput{}
		out.Body.Items = []RuleView{}
		out.Body.Total = page.Body.Total
		out.Body.NextCursor = page.Body.NextCursor
		for _, data := range page.Body.Items {
			var v RuleView
			if json.Unmarshal(data, &v) != nil {
				return nil, apiError(503)
			}
			out.Body.Items = append(out.Body.Items, v)
		}
		return out, nil
	})
	huma.Register(a, s.reviewOperation("ips-get", "GET", "/api/v1/ips/{ip}"), func(ctx context.Context, in *ipInput) (*ipOutput, error) {
		ip, ok := enrichment.PublicAddress(in.IP)
		if !ok {
			return nil, apiError(400)
		}
		reports, err := s.listReports(ctx, &reportListInput{Limit: in.Limit, Cursor: in.Cursor, SourceIP: ip.String()})
		if err != nil {
			return nil, err
		}
		out := &ipOutput{}
		out.Body.Address = ip.String()
		out.Body.Reports = reports.Body.Items
		out.Body.NextCursor = reports.Body.NextCursor
		out.Body.Registry = []byte("null")
		err = s.pool.QueryRow(ctx, `SELECT CASE WHEN octet_length(result::text)<=65536 THEN result ELSE '{}'::jsonb END,coalesce(octet_length(result::text)>65536,false),expires_at,expires_at<=clock_timestamp() FROM cheesetrap.enrichment_cache WHERE address=$1 AND result IS NOT NULL`, ip).Scan(&out.Body.Registry, &out.Body.RegistryTruncated, &out.Body.RegistryExpiresAt, &out.Body.RegistryExpired)
		if err != nil && err != pgx.ErrNoRows {
			return nil, apiError(503)
		}
		out.Body.Detections, out.Body.NextDetectionCursor, err = s.ipDetections(ctx, ip.String(), in.DetectionLimit, in.DetectionCursor)
		if err != nil {
			return nil, err
		}
		out.Body.LatestRefresh, err = s.latestRefresh(ctx, "", ip.String())
		if err != nil {
			return nil, apiError(503)
		}
		return out, nil
	})
}
func (s *server) revisionPage(ctx context.Context, in *revisionPageInput, field string) (*revisionPageOutput, error) {
	scope := pageScope(field, in.ID, in.RevisionID)
	var count int64
	var proof bool
	if err := s.pool.QueryRow(ctx, `SELECT snapshot ? 'proof',CASE WHEN snapshot ? 'proof' THEN (snapshot->'proof'->>(CASE WHEN $3='evidence' THEN 'evidence_count' ELSE 'rule_count' END))::bigint ELSE jsonb_array_length(snapshot->$3)::bigint END FROM cheesetrap.report_revisions WHERE report_id=$1 AND revision_id=$2`, in.ID, in.RevisionID, field).Scan(&proof, &count); err != nil {
		return nil, reviewError(err)
	}
	start := int64(0)
	if in.Cursor != "" {
		snapshot, before, err := pageCursor(in.Cursor, scope)
		if err != nil || snapshot != count || before < 1 || before >= count {
			return nil, apiError(400)
		}
		start = before
	}
	// generate_series is bounded before extracting any JSON entries. Oversized
	// individual entries are explicitly omitted, never silently truncated JSON.
	query := `SELECT CASE WHEN octet_length(entry::text)>65536 THEN jsonb_build_object('entry_truncated',true,'event_id',entry->>'event_id','detection_id',entry->>'detection_id') ELSE entry END FROM cheesetrap.report_revisions v CROSS JOIN LATERAL generate_series($4::integer,least($4::integer+$5::integer-1,jsonb_array_length(v.snapshot->$3)-1)) n CROSS JOIN LATERAL (SELECT CASE WHEN $3='evidence' THEN (v.snapshot->$3->n)||jsonb_build_object('ingestion_seq',v.snapshot->$3->n->>'ingestion_seq') ELSE (v.snapshot->$3->n) END entry) x WHERE v.report_id=$1 AND v.revision_id=$2`
	if proof {
		query = `SELECT CASE WHEN octet_length(entry::text)>65536 THEN jsonb_build_object('entry_truncated',true,'event_id',entry->>'event_id','detection_id',entry->>'detection_id') ELSE entry END
FROM cheesetrap.report_proof_parts p CROSS JOIN LATERAL jsonb_array_elements(convert_from(p.payload,'UTF8')::jsonb) WITH ORDINALITY x(raw,n)
CROSS JOIN LATERAL (SELECT CASE WHEN $3='evidence' THEN raw||jsonb_build_object('ingestion_seq',raw->>'ingestion_seq') ELSE raw END entry) y
WHERE p.report_id=$1 AND $2::uuid IS NOT NULL AND p.kind=$3 AND p.first_item BETWEEN greatest(0,$4::bigint-31) AND $4::bigint+$5::integer-1
AND p.first_item+n-1 >= $4::bigint AND p.first_item+n-1 < $4::bigint+$5::integer ORDER BY p.first_item,n LIMIT $5`
	}
	rows, err := s.pool.Query(ctx, query, in.ID, in.RevisionID, field, start, in.Limit)
	if err != nil {
		return nil, apiError(503)
	}
	defer rows.Close()
	out := &revisionPageOutput{}
	out.Body.Items = []json.RawMessage{}
	out.Body.Total = strconv.FormatInt(count, 10)
	for rows.Next() {
		var b json.RawMessage
		if err = rows.Scan(&b); err != nil {
			return nil, apiError(503)
		}
		out.Body.Items = append(out.Body.Items, b)
	}
	if rows.Err() != nil {
		return nil, apiError(503)
	}
	next := start + int64(len(out.Body.Items))
	if next < count {
		out.Body.NextCursor = encodePage(count, next, scope)
	}
	return out, nil
}
