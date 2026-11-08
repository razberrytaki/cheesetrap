package detection

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrProcessing = errors.New("detection_processing_failed")

// ErrRetiredResult identifies a replay whose immutable proof is being retired.
// ProcessBatch also preserves ErrProcessing for existing worker retry handling.
var ErrRetiredResult = errors.New("detection_result_retired")
var ErrBatchLimit = errors.New("detection_batch_limit_invalid")
var ErrBatchBudget = errors.New("detection_batch_budget_invalid")

type Progress struct {
	Processed   int
	DetectedSeq uint64
	HasMore     bool
}

// ProcessBatch locks the collector's cursor first, then completes consecutive
// events, including nonmatches. Results, evidence links, completions and the
// cursor commit together. A caller may safely retry after an uncertain commit.
// No network or filesystem I/O other than this database occurs in the lock.
func ProcessBatch(ctx context.Context, pool *pgxpool.Pool, limit int) (Progress, error) {
	return processBatch(ctx, pool, limit, 0)
}

// ProcessBatchWithBudget cooperatively yields the cursor after a complete event
// when the lock-held budget expires. Every committed prefix is atomic. A single
// event can exceed the budget; no evidence or partially completed event is cut.
// HasMore tells the caller to schedule another pass even after a short prefix.
func ProcessBatchWithBudget(ctx context.Context, pool *pgxpool.Pool, limit int, budget time.Duration) (Progress, error) {
	if budget <= 0 {
		return Progress{}, ErrBatchBudget
	}
	return processBatch(ctx, pool, limit, budget)
}

func processBatch(ctx context.Context, pool *pgxpool.Pool, limit int, budget time.Duration) (Progress, error) {
	return processBatchWithContextLimits(ctx, pool, limit, budget, defaultContextCacheLimits())
}

func processBatchWithContextLimits(ctx context.Context, pool *pgxpool.Pool, limit int, budget time.Duration, cacheLimits contextCacheLimits) (Progress, error) {
	if limit < 1 || limit > 1000 {
		return Progress{}, ErrBatchLimit
	}
	if err := ctx.Err(); err != nil {
		return Progress{}, err
	}
	if pool == nil {
		return Progress{}, ErrProcessing
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Progress{}, ErrProcessing
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	// Sorts and window frames spill to disk instead of growing with hostile
	// context cardinality. This is scoped to this atomic processing transaction.
	if _, err = tx.Exec(ctx, `SET LOCAL work_mem='4MB'; SET LOCAL jit=off; SET LOCAL statement_timeout=0`); err != nil {
		return Progress{}, ErrProcessing
	}
	cursors, err := q.LockProcessingCursors(ctx)
	if err != nil {
		return Progress{}, ErrProcessing
	}
	lockAcquiredAt := time.Now()
	batchRows, err := tx.Query(ctx, `SELECT * FROM cheesetrap.processing_events WHERE ingestion_seq>$1 AND ingestion_seq<=$2 ORDER BY ingestion_seq LIMIT $3`, cursors.DetectedSeq, cursors.IngestedSeq, limit)
	if err != nil {
		return Progress{}, ErrProcessing
	}
	rows, err := pgx.CollectRows(batchRows, pgx.RowToStructByName[db.CheesetrapEvent])
	if err != nil {
		return Progress{}, ErrProcessing
	}
	expected := min(int64(limit), cursors.IngestedSeq-cursors.DetectedSeq)
	if int64(len(rows)) != expected {
		return Progress{}, ErrProcessing
	}
	gaps := map[pgtype.UUID]bool{}
	convert := func(row db.CheesetrapEvent) (domain.Event, error) {
		e, err := domainEvent(row)
		if err != nil {
			return e, err
		}
		gap, known := gaps[row.SensorID]
		if !known {
			gap, err = q.DetectionSensorHasGap(ctx, row.SensorID)
			if err != nil {
				return e, err
			}
			gaps[row.SensorID] = gap
		}
		if gap && !slices.Contains(e.QualityFlags, "collection_gap") {
			e.QualityFlags = append(e.QualityFlags, "collection_gap")
		}
		return e, nil
	}
	next := cursors.DetectedSeq
	for _, row := range rows {
		if row.IngestionSeq != next+1 {
			return Progress{}, ErrProcessing
		}
		trigger, err := convert(row)
		if err != nil {
			return Progress{}, ErrProcessing
		}
		version, err := q.RuleConfigAt(ctx, row.IngestionSeq)
		if err != nil {
			return Progress{}, ErrProcessing
		}
		var config Config
		if json.Unmarshal(version.Config, &config) != nil || !config.Valid() {
			return Progress{}, ErrProcessing
		}
		if err := evaluateStream(ctx, tx, trigger, config, version.SettingsVersion, convert); err != nil {
			if errors.Is(err, ErrRetiredResult) {
				return Progress{}, errors.Join(ErrProcessing, ErrRetiredResult)
			}
			return Progress{}, ErrProcessing
		}
		if err := q.CompleteDetectionEvent(ctx, db.CompleteDetectionEventParams{IngestionSeq: row.IngestionSeq, EventID: row.EventID, RuleSetVersion: RuleVersion, SettingsVersion: version.SettingsVersion}); err != nil {
			return Progress{}, ErrProcessing
		}
		next = row.IngestionSeq
		if budget > 0 && time.Since(lockAcquiredAt) >= budget {
			break
		}
	}
	if next != cursors.DetectedSeq {
		n, err := q.AdvanceContinuousDetectedCursor(ctx, db.AdvanceContinuousDetectedCursorParams{NextSeq: next, PreviousSeq: cursors.DetectedSeq})
		if err != nil || n != 1 {
			return Progress{}, ErrProcessing
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Progress{}, ErrProcessing
	}
	return Progress{Processed: int(next - cursors.DetectedSeq), DetectedSeq: uint64(next), HasMore: next < cursors.IngestedSeq}, nil
}
func timestamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func domainEvent(row db.CheesetrapEvent) (domain.Event, error) {
	seq := uint64(row.IngestionSeq)
	id := row.EventID.String()
	ingested := row.IngestedAt.Time
	e := domain.Event{EventID: &id, IngestionSeq: &seq, IngestedAt: &ingested, SensorID: row.SensorID.String(), Engine: row.Engine, Service: row.Service, EventType: row.EventType, QualityFlags: slices.Clone(row.QualityFlags), IsTest: row.IsTest}
	if row.ObservedAt.Valid {
		at := row.ObservedAt.Time
		e.ObservedAt = &at
	}
	if row.SourceIp != nil {
		e.SourceIP = row.SourceIp.Unmap().String()
	}
	if row.DestinationIp != nil {
		e.DestinationIP = row.DestinationIp.Unmap().String()
	}
	if row.SourcePort != nil {
		e.SourcePort = int(*row.SourcePort)
	}
	if row.DestinationPort != nil {
		e.DestinationPort = int(*row.DestinationPort)
	}
	if err := json.Unmarshal(row.Attributes, &e.Attributes); err != nil {
		return e, ErrProcessing
	}
	return e, nil
}
func saveResult(ctx context.Context, q *db.Queries, triggerID pgtype.UUID, r Result) error {
	explanation, err := json.Marshal(r.Explanation)
	if err != nil {
		return err
	}
	id, err := q.InsertChunkDetectionResult(ctx, db.InsertChunkDetectionResultParams{RuleID: r.RuleID, RuleVersion: r.RuleVersion, SignatureID: r.SignatureID, SignatureVersion: r.SignatureVersion, ProcessingEventID: triggerID, ProcessingIngestionSeq: int64(r.ProcessingIngestionSeq), SourceIp: netip.MustParseAddr(r.SourceIP), WindowStart: timestamp(r.Explanation.WindowStart), WindowEnd: timestamp(r.Explanation.WindowEnd), EvidenceHash: r.EvidenceHash, EvidenceCount: int32(len(r.EvidenceIDs)), EvidenceEligible: r.EvidenceEligible, AutoApprovalAllowed: r.AutoApprovalAllowed, Explanation: explanation, SettingsVersion: r.SettingsVersion})
	if errors.Is(err, pgx.ErrNoRows) {
		stored, lookupErr := q.GetStoredDetectionIdentity(ctx, db.GetStoredDetectionIdentityParams{RuleID: r.RuleID, RuleVersion: r.RuleVersion, SignatureID: r.SignatureID, SignatureVersion: r.SignatureVersion, ProcessingEventID: triggerID, EvidenceHash: r.EvidenceHash})
		if lookupErr != nil {
			return lookupErr
		}
		if stored.EvidenceState == "retiring" {
			return ErrRetiredResult
		}
		if stored.EvidenceState != "active" {
			return ErrProcessing
		}
		id, err = stored.DetectionID, nil
	}
	if err != nil {
		return err
	}
	evidenceIDs := make([]pgtype.UUID, 0, len(r.EvidenceIDs))
	for _, event := range r.EvidenceIDs {
		var evidenceID pgtype.UUID
		if err := evidenceID.Scan(event); err != nil {
			return err
		}
		evidenceIDs = append(evidenceIDs, evidenceID)
	}
	// Provisional internal candidate; Task 4 measurements choose the final width.
	// The storage function validates exact IDs/hash/count and preserves the
	// existing representation on replay, including historical legacy roots.
	const candidateBucketWidth = 128
	return q.StoreDetectionChunks(ctx, db.StoreDetectionChunksParams{DetectionID: id, BucketWidth: candidateBucketWidth, EventIds: evidenceIDs})
}
