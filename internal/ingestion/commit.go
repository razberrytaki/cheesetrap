package ingestion

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrCommit = errors.New("collector_commit_failed")
	ErrBatch  = errors.New("collector_batch_conflict")
)

type transactionStarter interface {
	Begin(context.Context) (pgx.Tx, error)
}
type preparedRecord struct {
	record TailerRecord
	event  *db.InsertEventParams
	reason string
}

// CommitBatch atomically persists sanitized evidence, complete-line checkpoints,
// generation witnesses and the cursor. The cursor lock is the common collector /
// future window-sealing serialization point and is held through COMMIT. All
// decoding and JSON preparation happens before the transaction; only DB I/O is
// performed while it is open. On any failure retain the entire batch for replay.
func CommitBatch(ctx context.Context, conn transactionStarter, source Source, batch TailerBatch) error {
	if batch.GapCountFloor < 0 || !validSource(source) || len(batch.Records) > 1024 || len(batch.Generations) > 1024 || len(batch.Status.Generations) > 64 {
		return ErrBatch
	}
	records := make([]preparedRecord, 0, len(batch.Records))
	for _, r := range batch.Records {
		if !validUUID(r.GenerationID) || r.StartOffset < 0 || r.EndOffset <= r.StartOffset || r.ByteCount != r.EndOffset-r.StartOffset-1 || !validHash(r.RawHash) {
			return ErrBatch
		}
		prepared := preparedRecord{record: r, reason: r.Problem}
		if r.Problem != "" && r.Problem != "invalid_json" && r.Problem != "record_too_large" {
			return ErrBatch
		}
		if r.Problem == "" {
			e, err := decodeSource(source, r, batch.Status.CollectionGap)
			if err != nil {
				prepared.reason = "adapter_rejected"
			} else {
				attributes, err := json.Marshal(e.Attributes)
				if err != nil {
					return ErrBatch
				}
				p := db.InsertEventParams{SensorID: uuid(source.SensorID), FileGenerationID: uuid(r.GenerationID), ByteOffset: r.StartOffset, ByteEndOffset: valuePtr(r.EndOffset), SchemaVersion: int32(e.SchemaVersion), Engine: e.Engine, ObservedAt: timestampPtr(e.ObservedAt), SourceIp: ipPtr(e.SourceIP), SourcePort: portPtr(e.SourcePort), DestinationIp: ipPtr(e.DestinationIP), DestinationPort: portPtr(e.DestinationPort), Service: e.Service, EventType: e.EventType, Attributes: attributes, RawHash: r.RawHash, QualityFlags: e.QualityFlags, IsTest: e.IsTest}
				if e.SessionID != "" {
					p.SessionID = valuePtr(e.SessionID)
				}
				prepared.event = &p
			}
		}
		records = append(records, prepared)
	}
	// Each generation's records must form a forward chain. Stable sorting permits
	// batches interleaved by the tailer's fair scheduler without accepting holes.
	slices.SortStableFunc(records, func(a, b preparedRecord) int {
		if n := strings.Compare(a.record.GenerationID, b.record.GenerationID); n != 0 {
			return n
		}
		if a.record.StartOffset < b.record.StartOffset {
			return -1
		}
		if a.record.StartOffset > b.record.StartOffset {
			return 1
		}
		return 0
	})
	witnesses := append([]FileGeneration(nil), batch.Generations...)
	for _, g := range batch.Status.Generations {
		witnesses = append(witnesses, g.Generation)
	}
	known := map[string]bool{}
	for _, g := range witnesses {
		if !validResume(ResumePoint{Generation: g}) || !filepath.IsAbs(g.Path) {
			return ErrBatch
		}
		known[g.ID] = true
	}
	for _, r := range records {
		if !known[r.record.GenerationID] {
			return ErrBatch
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return commitError(ctx)
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	cursor, err := q.LockProcessingCursors(ctx)
	if err != nil {
		return commitError(ctx)
	}
	initialObservation := pgtype.Timestamptz{}
	if !batch.ObservationStartedAt.IsZero() {
		initialObservation = timestamp(batch.ObservationStartedAt)
	}
	sensor, err := q.EnsureCollectorSensor(ctx, db.EnsureCollectorSensorParams{SensorID: uuid(source.SensorID), Name: source.Name, Engine: source.Engine, InitialObservation: initialObservation})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrBatch
		}
		return commitError(ctx)
	}
	for _, g := range witnesses {
		_, err := q.SaveGenerationWitness(ctx, db.SaveGenerationWitnessParams{FileGenerationID: uuid(g.ID), SensorID: uuid(source.SensorID), Path: g.Path, Device: numeric(g.Device), Inode: numeric(g.Inode), CreatedAt: timestamp(g.CreatedAt), ObservedSize: g.ObservedSize, FingerprintBytes: int32(g.FingerprintBytes), FingerprintSha256: g.FingerprintSHA256})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrBatch
			}
			return commitError(ctx)
		}
	}
	checkpoints := map[string]int64{}
	for id := range known {
		cp, err := q.GetCheckpoint(ctx, db.GetCheckpointParams{SensorID: uuid(source.SensorID), FileGenerationID: uuid(id)})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return commitError(ctx)
		}
		checkpoints[id] = cp.ByteOffset
	}
	fresh := make([]preparedRecord, 0, len(records))
	for _, r := range records {
		row := r.record
		evidence, err := q.FindCommittedEvidence(ctx, db.FindCommittedEvidenceParams{SensorID: uuid(source.SensorID), FileGenerationID: uuid(row.GenerationID), ByteOffset: row.StartOffset})
		if err != nil {
			return commitError(ctx)
		}
		if len(evidence) > 0 {
			// Old records without the durable end boundary cannot safely prove a replay.
			if len(evidence) != 1 || evidence[0].RawHash != row.RawHash || evidence[0].ByteEndOffset == nil || *evidence[0].ByteEndOffset != row.EndOffset || row.EndOffset > checkpoints[row.GenerationID] {
				return ErrBatch
			}
			continue
		}
		if row.StartOffset != checkpoints[row.GenerationID] {
			return ErrBatch
		}
		checkpoints[row.GenerationID] = row.EndOffset
		fresh = append(fresh, r)
	}
	// clock_timestamp is sampled AFTER lock acquisition and replay detection.
	// now()/transaction_timestamp() would backdate a batch waiting on the lock.
	// The query also clamps to sealed_before so clock rollback cannot reopen
	// membership of an already sealed reporting interval.
	at, err := q.CommitClock(ctx)
	if err != nil {
		return commitError(ctx)
	}
	seq := cursor.IngestedSeq
	for _, r := range fresh {
		if r.event != nil {
			if seq == math.MaxInt64 {
				return ErrBatch
			}
			seq++
			r.event.IngestionSeq = seq
			r.event.IngestedAt = at
			if _, err := q.InsertEvent(ctx, *r.event); err != nil {
				return commitError(ctx)
			}
		} else {
			row := r.record
			if err := q.InsertRejection(ctx, db.InsertRejectionParams{SensorID: uuid(source.SensorID), FileGenerationID: uuid(row.GenerationID), ByteOffset: row.StartOffset, ByteEndOffset: row.EndOffset, ByteCount: row.ByteCount, RawHash: row.RawHash, Reason: r.reason}); err != nil {
				return commitError(ctx)
			}
		}
	}
	for id, offset := range checkpoints {
		if err := q.SetCheckpoint(ctx, db.SetCheckpointParams{SensorID: uuid(source.SensorID), FileGenerationID: uuid(id), ByteOffset: offset}); err != nil {
			return commitError(ctx)
		}
	}
	if batch.Status.CollectionGap {
		since := sensor.LastObservationAt.Time
		if err := q.MarkCollectionGap(ctx, db.MarkCollectionGapParams{SensorID: uuid(source.SensorID), Column2: timestamp(since)}); err != nil {
			return commitError(ctx)
		}
		if batch.GapCountFloor > 0 {
			if _, err := tx.Exec(ctx, `UPDATE cheesetrap.ingestion_gaps SET gap_count=greatest(gap_count,$2) WHERE sensor_id=$1`, source.SensorID, batch.GapCountFloor); err != nil {
				return commitError(ctx)
			}
		}
		for _, d := range batch.Status.Diagnostics {
			if (d.Code == "file_truncated" || d.Code == "resume_unavailable") && validUUID(d.GenerationID) {
				if err := q.CloseSensorGeneration(ctx, db.CloseSensorGenerationParams{SensorID: uuid(source.SensorID), FileGenerationID: uuid(d.GenerationID)}); err != nil {
					return commitError(ctx)
				}
			}
		}
	}
	observation := sensor.LastObservationAt
	if !batch.ObservationStartedAt.IsZero() {
		if batch.ObservationStartedAt.After(at.Time) {
			return ErrBatch
		}
		observation = timestamp(batch.ObservationStartedAt)
	}
	if err := q.UpdateCollectorState(ctx, db.UpdateCollectorStateParams{SensorID: uuid(source.SensorID), Column2: observation}); err != nil {
		return commitError(ctx)
	}
	if len(records) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE cheesetrap.sensors SET last_engine_log_at=greatest(last_engine_log_at,$2::timestamptz) WHERE sensor_id=$1`, source.SensorID, at); err != nil {
			return commitError(ctx)
		}
	}
	if n, err := q.AdvanceIngestedCursor(ctx, seq); err != nil || n != 1 {
		return commitError(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		return commitError(ctx)
	}
	return nil
}

func decodeSource(s Source, r TailerRecord, gap bool) (domain.Event, error) {
	raw := r.Bytes()
	var endpoint Endpoint
	if s.Engine == "cowrie" {
		endpoint = s.Endpoints[0]
	} else {
		// Routing requires a matching configured observed socket, never protocol alone.
		var wire struct {
			IP   string `json:"destination_ip"`
			Port int    `json:"destination_port"`
		}
		if err := readRecord(raw, &wire); err != nil {
			return domain.Event{}, err
		}
		ip, err := address(wire.IP)
		if err != nil {
			return domain.Event{}, errEndpoint
		}
		for _, e := range s.Endpoints {
			configured, _ := address(e.ObservedIP)
			if configured == ip && e.ObservedPort == wire.Port {
				endpoint = e
				break
			}
		}
		if endpoint.Service == "" {
			return domain.Event{}, errEndpoint
		}
	}
	c := Context{SensorID: s.SensorID, Service: endpoint.Service, ObservedIP: endpoint.ObservedIP, ObservedPort: endpoint.ObservedPort, PublicIP: endpoint.PublicIP, PublicPort: endpoint.PublicPort, Cursor: domain.SourceCursor{FileGenerationID: r.GenerationID, ByteOffset: r.StartOffset}, IsTest: s.IsTest, ReferenceTime: time.Now().UTC(), CollectionGap: gap}
	if s.Engine == "cowrie" {
		return DecodeCowrie(raw, c)
	}
	return DecodeWeb(raw, c)
}
func commitError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrCommit
}
func uuid(s string) pgtype.UUID { var v pgtype.UUID; _ = v.Scan(s); return v }
func numeric(n uint64) pgtype.Numeric {
	return pgtype.Numeric{Int: new(big.Int).SetUint64(n), Valid: true}
}
func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
}
func timestampPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return timestamp(*t)
}
func valuePtr[T any](v T) *T { return &v }
func portPtr(p int) *int32 {
	if p == 0 {
		return nil
	}
	return valuePtr(int32(p))
}
func ipPtr(s string) *netip.Addr {
	if s == "" {
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &a
}
func validHash(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
