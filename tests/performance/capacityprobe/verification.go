package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"cheesetrap/internal/domain"
	"github.com/jackc/pgx/v5"
)

// Preserve json.Marshal(slice) bytes, including nil versus empty and element
// order, without retaining a second complete evidence array.
func evidenceSHA256(evidence []domain.ReportEvidence) (string, error) {
	h := sha256.New()
	if evidence == nil {
		h.Write([]byte("null"))
	} else {
		h.Write([]byte("["))
		for i, e := range evidence {
			encoded, err := json.Marshal(e)
			if err != nil {
				return "", err
			}
			if i > 0 {
				h.Write([]byte(","))
			}
			h.Write(encoded)
		}
		h.Write([]byte("]"))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type verificationQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Both comparisons pin the immutable revision read and hashed by the caller.
// The existence and cardinality checks prevent an empty/missing relation from
// passing vacuously, and exact JSONB equality retains every persisted field.
func verifyRevisionCopies(ctx context.Context, q verificationQuery, reportID, revisionID string, count int) error {
	var valid bool
	err := q.QueryRow(ctx, `WITH revision AS MATERIALIZED (
 SELECT snapshot FROM cheesetrap.report_revisions WHERE report_id=$1 AND revision_id=$2
 ), expected AS MATERIALIZED (
 SELECT value s FROM revision CROSS JOIN LATERAL jsonb_array_elements(snapshot->'evidence')
 ), actual AS MATERIALIZED (
 SELECT snapshot s FROM cheesetrap.report_evidence WHERE report_id=$1
 ) SELECT (SELECT count(*) FROM revision)=1
 AND coalesce((SELECT jsonb_typeof(snapshot->'evidence')='array' FROM revision),false)
 AND (SELECT count(*) FROM expected)=$3
 AND (SELECT count(DISTINCT s->>'event_id') FROM expected)=$3
 AND (SELECT count(*) FROM actual)=$3
 AND NOT EXISTS(SELECT 1 FROM expected x FULL JOIN actual a ON x.s->>'event_id'=a.s->>'event_id' WHERE x.s IS DISTINCT FROM a.s)`, reportID, revisionID, count).Scan(&valid)
	if err != nil || !valid {
		return errors.New("probe_report_copy_mismatch")
	}
	return nil
}

func verifyRevisionRules(ctx context.Context, q verificationQuery, reportID, revisionID string, count int) error {
	var valid bool
	err := q.QueryRow(ctx, `WITH revision AS MATERIALIZED (
 SELECT snapshot FROM cheesetrap.report_revisions WHERE report_id=$1 AND revision_id=$2
 ), expected AS MATERIALIZED (
 SELECT value x FROM revision CROSS JOIN LATERAL jsonb_array_elements(snapshot->'rules')
 ) SELECT (SELECT count(*) FROM revision)=1
 AND coalesce((SELECT jsonb_typeof(snapshot->'rules')='array' FROM revision),false)
 AND (SELECT count(*) FROM expected)=$3
 AND (SELECT count(DISTINCT x->>'detection_id') FROM expected)=$3
 AND NOT EXISTS(SELECT 1 FROM expected LEFT JOIN cheesetrap.detection_results d ON d.detection_id=(x->>'detection_id')::uuid
 WHERE d.detection_id IS NULL OR d.evidence_hash IS DISTINCT FROM x->>'evidence_hash'
 OR d.evidence_count IS DISTINCT FROM (x->>'context_count')::bigint
 OR d.rule_id IS DISTINCT FROM x->>'rule_id' OR d.rule_version IS DISTINCT FROM x->>'rule_version'
 OR d.explanation IS DISTINCT FROM x->'explanation' OR d.settings_version::text IS DISTINCT FROM x->>'settings_version'
 OR coalesce(d.signature_id,'') IS DISTINCT FROM coalesce(x->>'signature_id','')
 OR coalesce(d.signature_version,'') IS DISTINCT FROM coalesce(x->>'signature_version','')
 OR d.evidence_eligible IS DISTINCT FROM (x->>'evidence_eligible')::boolean
 OR d.auto_approval_allowed IS DISTINCT FROM (x->>'auto_approval_allowed')::boolean
 OR (x->>'attached_count')::bigint NOT BETWEEN 0 AND d.evidence_count)`, reportID, revisionID, count).Scan(&valid)
	if err != nil || !valid {
		return errors.New("probe_report_rule_mismatch")
	}
	return nil
}

func currentRevisionMetadata(ctx context.Context, q verificationQuery, id string) (int64, string, error) {
	var version int64
	var body string
	err := q.QueryRow(ctx, `SELECT v.version,v.body FROM cheesetrap.report_revisions v JOIN cheesetrap.reports r ON r.report_id=v.report_id AND r.current_revision_id=v.revision_id WHERE r.report_id=$1`, id).Scan(&version, &body)
	return version, body, err
}
