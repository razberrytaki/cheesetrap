package reporting

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DraftProgress struct {
	Processed bool
	More      bool
}

// DraftService reuses the production resolver/cache policy across River jobs.
// There is deliberately no public endpoint or transport override.
type DraftService struct {
	pool     *pgxpool.Pool
	contacts interface {
		Lookup(context.Context, string) (enrichment.Result, error)
	}
}

// NewDraftService prepares immutable report drafts and contact information.
func NewDraftService(pool *pgxpool.Pool) *DraftService {
	s := &DraftService{pool: pool, contacts: enrichment.NewService(pool)}
	return s
}
func DraftNext(ctx context.Context, pool *pgxpool.Pool) (DraftProgress, error) {
	return NewDraftService(pool).Next(ctx)
}

// Next handles one IP or one empty window per call. The preflight read and
// registry lookup hold no transaction. The draft lock then rechecks chronology
// and source membership before claiming events and atomically publishing copies.
func (s *DraftService) Next(ctx context.Context) (DraftProgress, error) {
	if s == nil || s.pool == nil {
		return DraftProgress{}, ErrRevisionFailed
	}
	q := db.New(s.pool)
	w, err := q.NextDraftWindow(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return DraftProgress{}, nil
	}
	if err != nil {
		return DraftProgress{}, revisionError(ctx)
	}
	if w.State != "ready" {
		return DraftProgress{More: w.State == "sealed"}, nil
	}
	source, err := q.NextDraftSource(ctx, w.WindowID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DraftProgress{}, revisionError(ctx)
	}
	var registry enrichment.Result
	if source != "" {
		registry, err = s.contacts.Lookup(ctx, source)
		if ctx.Err() != nil {
			return DraftProgress{}, ctx.Err()
		}
		if err != nil {
			registry = enrichment.Result{SchemaVersion: 1, Address: source, HeldReason: "contact_lookup_failed", Candidates: []enrichment.Contact{}}
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DraftProgress{}, revisionError(ctx)
	}
	defer tx.Rollback(context.Background())
	q = db.New(tx)
	if _, err = tx.Exec(ctx, `SET LOCAL work_mem='4MB'; SET LOCAL jit=off; SET LOCAL statement_timeout=0`); err != nil {
		return DraftProgress{}, revisionError(ctx)
	}
	if _, err = q.LockReportDrafts(ctx); err != nil {
		return DraftProgress{}, revisionError(ctx)
	}
	current, err := q.NextDraftWindow(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return DraftProgress{}, nil
	}
	if err != nil {
		return DraftProgress{}, revisionError(ctx)
	}
	if current.WindowID != w.WindowID || current.State != "ready" {
		return DraftProgress{More: true}, nil
	}
	next, err := q.NextDraftSource(ctx, w.WindowID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DraftProgress{}, revisionError(ctx)
	}
	if next != source {
		return DraftProgress{More: true}, nil
	}
	if source == "" {
		if err = q.CompleteReportWindow(ctx, w.WindowID); err != nil {
			return DraftProgress{}, revisionError(ctx)
		}
	} else {
		candidate := db.RecordReportCandidateParams{WindowID: w.WindowID, SourceIp: netip.MustParseAddr(source), Outcome: "already_assigned"}
		hasEvidence, err := q.HasReportCandidateEvidence(ctx, db.ListReportCandidateEvidenceParams{WindowID: w.WindowID, SourceIp: candidate.SourceIp})
		if err != nil {
			return DraftProgress{}, revisionError(ctx)
		}
		if hasEvidence {
			report, err := q.CreateReport(ctx, db.CreateReportParams{WindowID: w.WindowID, SourceIp: candidate.SourceIp})
			if err != nil {
				return DraftProgress{}, revisionError(ctx)
			}
			snapshot, err := collectProof(ctx, q, w, source, report.ReportID.String())
			if err != nil || snapshot.Proof == nil {
				return DraftProgress{}, revisionError(ctx)
			}
			snapshot.Registry, err = json.Marshal(registry)
			if err != nil {
				return DraftProgress{}, revisionError(ctx)
			}
			r := domain.ReportRevision{ReportID: report.ReportID.String(), Version: 1, Snapshot: snapshot}
			if err = prepareRevision(ctx, q, &r, nil); err != nil {
				return DraftProgress{}, err
			}
			r.Subject, r.Body, err = Render(r)
			if err != nil {
				return DraftProgress{}, err
			}
			if err = appendRevision(ctx, q, &r, 0); err != nil {
				return DraftProgress{}, err
			}
			candidate.Outcome = "created"
			candidate.ReportID = report.ReportID
		}
		if err = q.RecordReportCandidate(ctx, candidate); err != nil {
			return DraftProgress{}, revisionError(ctx)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return DraftProgress{}, revisionError(ctx)
	}
	return DraftProgress{Processed: true, More: true}, nil
}

// Copy in bounded statements inside the existing draft transaction. This keeps
// the JSON encoder and pgx parameter buffers small; any later failure still
// rolls back the report, every prior batch, and its revision/candidate together.
func copyReportEvidence(ctx context.Context, q *db.Queries, reportID pgtype.UUID, evidence []domain.ReportEvidence) error {
	const batchSize = 1000
	for start := 0; start < len(evidence); start += batchSize {
		data, err := json.Marshal(evidence[start:min(start+batchSize, len(evidence))])
		if err != nil {
			return err
		}
		if err := q.CopyReportEvidenceBatch(ctx, db.CopyReportEvidenceBatchParams{ReportID: reportID, Snapshots: data}); err != nil {
			return err
		}
	}
	return nil
}
