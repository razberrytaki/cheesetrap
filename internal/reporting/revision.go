package reporting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"sort"
	"unicode"
	"unicode/utf8"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrRevisionInput = errors.New("report_revision_invalid")
var ErrRevisionConflict = errors.New("report_revision_conflict")
var ErrRevisionFailed = errors.New("report_revision_failed")

type RevisionChanges struct{ Recipient, Subject, Body *string }

func uuid(s string) pgtype.UUID { var id pgtype.UUID; _ = id.Scan(s); return id }
func revisionError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrRevisionFailed
}

func LoadRevision(ctx context.Context, pool *pgxpool.Pool, id string) (domain.ReportRevision, error) {
	if pool == nil || !uuid(id).Valid {
		return domain.ReportRevision{}, ErrRevisionInput
	}
	return readCurrentRevision(ctx, db.New(pool), id)
}
func readRevision(row db.CheesetrapReportRevision) (domain.ReportRevision, error) {
	r := domain.ReportRevision{ReportID: row.ReportID.String(), RevisionID: row.RevisionID.String(), Version: row.Version, Recipient: row.Recipient, ReplyTo: row.ReplyTo, Subject: row.Subject, Body: row.Body, HoldReasons: row.HoldReasons, State: row.State, AutoApprovalAllowed: row.AutoApprovalAllowed, BodyEdited: row.BodyEdited, ContentDigest: row.ContentDigest}
	if json.Unmarshal(row.Snapshot, &r.Snapshot) != nil {
		return r, ErrRevisionFailed
	}
	return r, nil
}

// ChangeRevision appends an immutable revision. Recipient edits
// select from the persisted, fresh registry evidence only. Expected version
// protects concurrent reviewers from overwriting each other's revision pointer.
func ChangeRevision(ctx context.Context, pool *pgxpool.Pool, id string, expected int64, c RevisionChanges) (domain.ReportRevision, error) {
	var empty domain.ReportRevision
	if pool == nil || !uuid(id).Valid || expected < 1 {
		return empty, ErrRevisionInput
	}
	if c.Subject != nil && !ValidHeader(*c.Subject) || c.Body != nil && !ValidBody(*c.Body) {
		return empty, ErrRevisionInput
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return empty, revisionError(ctx)
	}
	defer tx.Rollback(context.Background())
	r, err := ChangeRevisionTx(ctx, tx, id, expected, "", c, nil)
	if err != nil {
		return empty, err
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, revisionError(ctx)
	}
	return r, nil
}

// ChangeRevisionTx joins the caller's audit/idempotency transaction. The report
// lock fences the entire command; refreshed registry data has already been
// obtained outside this transaction. A terminal report never accepts content.
func ChangeRevisionTx(ctx context.Context, tx pgx.Tx, id string, expected int64, current string, c RevisionChanges, registry *enrichment.Result) (domain.ReportRevision, error) {
	var empty domain.ReportRevision
	if tx == nil || !uuid(id).Valid || expected < 1 || (current != "" && !uuid(current).Valid) || c.Subject != nil && !ValidHeader(*c.Subject) || c.Body != nil && !ValidBody(*c.Body) {
		return empty, ErrRevisionInput
	}
	if _, err := tx.Exec(ctx, `SET LOCAL work_mem='4MB'; SET LOCAL jit=off; SET LOCAL statement_timeout=0`); err != nil {
		return empty, revisionError(ctx)
	}
	q := db.New(tx)
	report, err := q.LockReport(ctx, uuid(id))
	if err != nil {
		return empty, revisionError(ctx)
	}
	if report.Version != expected || (report.State != "held" && report.State != "needs_review") || (current != "" && report.CurrentRevisionID.String() != current) {
		return empty, ErrRevisionConflict
	}
	r, err := readCurrentRevision(ctx, q, id)
	if err != nil {
		return empty, err
	}
	r.Version = expected + 1
	r.RevisionID = ""
	if registry != nil {
		r.Snapshot.Registry, err = json.Marshal(registry)
		if err != nil {
			return empty, ErrRevisionFailed
		}
		r.Recipient = ""
	}
	if err = prepareRevision(ctx, q, &r, c.Recipient); err != nil {
		return empty, err
	}
	if c.Body == nil && !r.BodyEdited {
		_, r.Body, err = Render(r)
		if err != nil {
			return empty, err
		}
	}
	if c.Subject != nil {
		r.Subject = *c.Subject
	}
	if c.Body != nil {
		r.Body = *c.Body
		r.BodyEdited = true
	}
	if err = appendRevision(ctx, q, &r, expected); err != nil {
		return empty, err
	}
	return r, nil
}

// ValidBody permits nonempty UTF-8 up to 1 MiB with LF and tab controls.
func ValidBody(s string) bool {
	if len(s) == 0 || len(s) > 1024*1024 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

func SetReplyTo(ctx context.Context, pool *pgxpool.Pool, address string) error {
	normalized, ok := enrichment.Mailbox(address)
	if !ok || pool == nil {
		return ErrRevisionInput
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return revisionError(ctx)
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	if err = q.SetReportReplyTo(ctx, normalized); err != nil {
		return revisionError(ctx)
	}
	if err = q.AppendAudit(ctx, db.AppendAuditParams{Action: "reporting_reply_to_changed", Details: []byte(`{}`)}); err != nil {
		return revisionError(ctx)
	}
	if err = tx.Commit(ctx); err != nil {
		return revisionError(ctx)
	}
	return nil
}
func appendRevision(ctx context.Context, q *db.Queries, r *domain.ReportRevision, expected int64) error {
	if !ValidHeader(r.Subject) || !ValidBody(r.Body) {
		return ErrRevisionInput
	}
	if err := normalizeLegacyProof(ctx, q, r); err != nil {
		return ErrRevisionFailed
	}
	digest, err := ContentDigest(*r)
	if err != nil {
		return ErrRevisionFailed
	}
	r.ContentDigest = digest
	snapshot, err := marshalReportSnapshot(r.Snapshot)
	if err != nil {
		return ErrRevisionFailed
	}
	id, err := q.AppendReportRevision(ctx, db.AppendReportRevisionParams{ReportID: uuid(r.ReportID), Version: r.Version, Snapshot: snapshot, Subject: r.Subject, Body: r.Body, Recipient: r.Recipient, ReplyTo: r.ReplyTo, HoldReasons: r.HoldReasons, State: r.State, AutoApprovalAllowed: r.AutoApprovalAllowed, BodyEdited: r.BodyEdited, ContentDigest: digest})
	if err != nil {
		return revisionError(ctx)
	}
	n, err := q.AdvanceReportRevision(ctx, db.AdvanceReportRevisionParams{ReportID: uuid(r.ReportID), CurrentRevisionID: id, State: r.State, Version: expected})
	if err != nil {
		return revisionError(ctx)
	}
	if n != 1 {
		return ErrRevisionConflict
	}
	r.RevisionID = id.String()
	return nil
}

// ContentDigest canonicalizes the entire payload, including nested JSONB maps.
// UseNumber preserves integer evidence beyond JavaScript/float64 precision.
// Revision UUID, version and insertion time do not change signed content.
func ContentDigest(r domain.ReportRevision) (string, error) {
	// Discover the signed fields through their existing JSON representation, but
	// leave the large arrays out of this small scaffold. Each array element gets
	// the same canonicalization independently while it is written into the hash.
	snapshot := r.Snapshot
	snapshot.Evidence, snapshot.Rules = nil, nil
	payload := struct {
		ReportID                          string                `json:"report_id"`
		Snapshot                          domain.ReportSnapshot `json:"snapshot"`
		Recipient, ReplyTo, Subject, Body string
		HoldReasons                       []string
		AutoApprovalAllowed               bool
	}{r.ReportID, snapshot, r.Recipient, r.ReplyTo, r.Subject, r.Body, r.HoldReasons, r.AutoApprovalAllowed}
	canonical, err := digestCanonicalValue(payload)
	if err != nil {
		return "", ErrRevisionInput
	}
	fields := canonical.(map[string]any)["snapshot"].(map[string]any)
	if r.Snapshot.Proof == nil && r.Snapshot.Contents != nil {
		fields["evidence"], fields["rules"] = digestContents{r.Snapshot.Contents, true}, digestContents{r.Snapshot.Contents, false}
	} else {
		fields["evidence"], fields["rules"] = r.Snapshot.Evidence, r.Snapshot.Rules
	}
	sum := sha256.New()
	if err := writeDigestValue(sum, canonical); err != nil {
		return "", ErrRevisionInput
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// Preserve the original two-stage conversion even for individual objects:
// RawMessage maps, duplicate keys, number lexemes and invalid UTF-8 strings
// must all behave exactly like the former whole-payload decoder.
func digestCanonicalValue(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var canonical any
	if err := decoder.Decode(&canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

func writeDigestValue(sum hash.Hash, value any) error {
	switch value := value.(type) {
	case digestContents:
		return value.write(sum)
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		sum.Write([]byte{'{'})
		for i, key := range keys {
			if i > 0 {
				sum.Write([]byte{','})
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return err
			}
			sum.Write(encoded)
			sum.Write([]byte{':'})
			if err := writeDigestValue(sum, value[key]); err != nil {
				return err
			}
		}
		sum.Write([]byte{'}'})
	case []domain.ReportEvidence:
		return writeDigestArray(sum, value)
	case []domain.ReportRule:
		return writeDigestArray(sum, value)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		sum.Write(encoded)
	}
	return nil
}

func writeDigestArray[T any](sum hash.Hash, values []T) error {
	if values == nil {
		sum.Write([]byte("null"))
		return nil
	}
	sum.Write([]byte{'['})
	for i, value := range values {
		if i > 0 {
			sum.Write([]byte{','})
		}
		canonical, err := digestCanonicalValue(value)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return err
		}
		sum.Write(encoded)
	}
	sum.Write([]byte{']'})
	return nil
}

type digestContents struct {
	source   domain.ReportContents
	evidence bool
}

func (d digestContents) write(sum hash.Hash) error {
	e, r := d.source.NullArrays()
	if (d.evidence && e) || (!d.evidence && r) {
		sum.Write([]byte("null"))
		return nil
	}
	sum.Write([]byte{'['})
	first := true
	item := func(value any) error {
		canonical, err := digestCanonicalValue(value)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return err
		}
		if !first {
			sum.Write([]byte{','})
		}
		first = false
		sum.Write(encoded)
		return nil
	}
	var err error
	if d.evidence {
		err = d.source.EachEvidence(func(e domain.ReportEvidence) error { return item(e) })
	} else {
		err = d.source.EachRule(func(r domain.ReportRule) error { return item(r) })
	}
	if err != nil {
		return err
	}
	sum.Write([]byte{']'})
	return nil
}
