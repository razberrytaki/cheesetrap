package detection

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const evidencePageSize = 128

// The evaluator's predicates still run in Go. Only matched, projected rows go
// into database staging, whose sorts and window frames can spill to disk. No
// cardinality limit drops context, and no aggregate array crosses either side
// of the database boundary.
func evaluateStream(ctx context.Context, tx pgx.Tx, trigger domain.Event, config Config, version int64, convert func(db.CheesetrapEvent) (domain.Event, error)) error {
	ip, valid := sourceIP(trigger)
	if !valid || trigger.ObservedAt == nil || !triggerNeedsContext(config, trigger) {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cheesetrap.detection_work`); err != nil {
		return err
	}
	active := []rule{}
	for _, r := range rules(config) {
		if _, ok := r.match(trigger); ok {
			active = append(active, r)
		}
	}
	stage := func(events []domain.Event) error {
		values := [][]any{}
		for _, e := range events {
			for _, r := range active {
				if p, ok := r.match(e); ok {
					values = append(values, []any{r.id, *e.EventID, int64(*e.IngestionSeq), *e.ObservedAt, p, holdReasons(e)})
				}
			}
		}
		if len(values) == 0 {
			return nil
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"cheesetrap", "detection_work"}, []string{"rule_id", "event_id", "ingestion_seq", "observed_at", "path", "holds"}, pgx.CopyFromRows(values))
		return err
	}
	if err := stage([]domain.Event{trigger}); err != nil {
		return err
	}
	var after int64
	for {
		rows, err := tx.Query(ctx, `SELECT e.* FROM cheesetrap.processing_events e
JOIN cheesetrap.detection_completions c ON c.event_id=e.event_id AND c.ingestion_seq=e.ingestion_seq
WHERE e.source_ip=$1 AND e.event_type=$2 AND e.ingestion_seq>$3 AND e.ingestion_seq<$4
AND e.observed_at >= $5 AND e.observed_at <= $6 ORDER BY e.ingestion_seq LIMIT 128`, ip, trigger.EventType, after, int64(*trigger.IngestionSeq), trigger.ObservedAt.Add(-Window), trigger.ObservedAt.Add(Window))
		if err != nil {
			return err
		}
		page, err := pgx.CollectRows(rows, pgx.RowToStructByName[db.CheesetrapEvent])
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		events := make([]domain.Event, 0, len(page))
		for _, row := range page {
			e, err := convert(row)
			if err != nil {
				return err
			}
			events = append(events, e)
			after = row.IngestionSeq
		}
		if err := stage(events); err != nil {
			return err
		}
	}
	for _, r := range active {
		// RANGE includes every tied timestamp, just like EvaluateConfigured.
		// There are exactly five code-versioned repeat paths; summing their
		// nonempty window counts implements distinct-path cardinality without
		// an unbounded Go set or an array aggregate in PostgreSQL.
		var end time.Time
		err := tx.QueryRow(ctx, `SELECT observed_at FROM (
SELECT observed_at,count(*) OVER w AS n,
((count(*) FILTER(WHERE path='/.env') OVER w>0)::int+
 (count(*) FILTER(WHERE path='/.git/config') OVER w>0)::int+
 (count(*) FILTER(WHERE path='/wp-login.php') OVER w>0)::int+
 (count(*) FILTER(WHERE path='/wp-admin') OVER w>0)::int+
 (count(*) FILTER(WHERE path='/phpmyadmin') OVER w>0)::int) AS paths
FROM cheesetrap.detection_work WHERE rule_id=$1
WINDOW w AS (ORDER BY observed_at RANGE BETWEEN interval '10 minutes' PRECEDING AND CURRENT ROW)
) ranked WHERE observed_at >= $2 AND n >= $3 AND paths >= $4 ORDER BY observed_at LIMIT 1`, r.id, *trigger.ObservedAt, r.threshold, r.paths).Scan(&end)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if err := saveStreamResult(ctx, tx, trigger, config, version, r, end); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `DELETE FROM cheesetrap.detection_work`)
	return err
}

func saveStreamResult(ctx context.Context, tx pgx.Tx, trigger domain.Event, config Config, version int64, r rule, end time.Time) error {
	start := end.Add(-Window)
	explanation := Explanation{RuleVersion: RuleVersion, Threshold: r.threshold, DistinctPathThreshold: r.paths, RequiredFields: slices.Clone(r.required), WindowStart: start, WindowEnd: end, Paths: []string{}, HoldReasons: []string{}}
	if version > 0 {
		explanation.SettingsVersion = strconv.FormatInt(version, 10)
		explanation.RuleConfig = &config
	}
	if err := tx.QueryRow(ctx, `SELECT count(*),min(observed_at),max(observed_at) FROM cheesetrap.detection_work WHERE rule_id=$1 AND observed_at BETWEEN $2 AND $3`, r.id, start, end).Scan(&explanation.Count, &explanation.ObservedStart, &explanation.ObservedEnd); err != nil {
		return err
	}
	for _, field := range []string{"path", "hold"} {
		query := `SELECT DISTINCT path FROM cheesetrap.detection_work WHERE rule_id=$1 AND observed_at BETWEEN $2 AND $3 AND path<>'' ORDER BY path`
		if field == "hold" {
			query = `SELECT DISTINCT unnest(holds) AS hold FROM cheesetrap.detection_work WHERE rule_id=$1 AND observed_at BETWEEN $2 AND $3 ORDER BY hold`
		}
		rows, err := tx.Query(ctx, query, r.id, start, end)
		if err != nil {
			return err
		}
		values, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		// Keep explanation ordering identical to the Go evaluator regardless
		// of the database's locale/collation.
		slices.Sort(values)
		if field == "path" {
			explanation.Paths = values
		} else {
			explanation.HoldReasons = values
		}
	}
	// Hash old bytes as well to recognize historical immutable replay roots.
	legacy := sha256.New()
	legacy.Write([]byte{'['})
	chain := sha256.Sum256([]byte("cheesetrap:evidence:sha256-chain-v2"))
	rows, err := tx.Query(ctx, `SELECT event_id FROM cheesetrap.detection_work WHERE rule_id=$1 AND observed_at BETWEEN $2 AND $3 ORDER BY event_id`, r.id, start, end)
	if err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		var id pgtype.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if n > 0 {
			legacy.Write([]byte{','})
		}
		legacy.Write([]byte(`"` + id.String() + `"`))
		var b [48]byte
		copy(b[:32], chain[:])
		copy(b[32:], id.Bytes[:])
		chain = sha256.Sum256(b[:])
		n++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	legacy.Write([]byte{']'})
	var final [40]byte
	copy(final[:32], chain[:])
	binary.BigEndian.PutUint64(final[32:], uint64(n))
	chain = sha256.Sum256(final[:])
	digest := hex.EncodeToString(chain[:])
	oldDigest := hex.EncodeToString(legacy.Sum(nil))
	var id pgtype.UUID
	var state string
	err = tx.QueryRow(ctx, `SELECT detection_id,evidence_state FROM cheesetrap.detection_results WHERE rule_id=$1 AND rule_version=$2 AND signature_id=$3 AND signature_version=$4 AND processing_event_id=$5 AND evidence_hash IN ($6,$7)`, r.id, RuleVersion, r.signature.ID, r.signature.Version, *trigger.EventID, digest, oldDigest).Scan(&id, &state)
	if err == nil {
		if state == "retiring" {
			return ErrRetiredResult
		}
		if state != "active" {
			return ErrProcessing
		}
		// Compare actual sets even on a matching hash; legacy and chunk proofs
		// remain untouched. Relational EXCEPT can spill under work_mem.
		var same bool
		err = tx.QueryRow(ctx, `WITH expected AS (SELECT event_id FROM cheesetrap.detection_work WHERE rule_id=$1 AND observed_at BETWEEN $2 AND $3), stored AS (
SELECT event_id FROM cheesetrap.detection_evidence WHERE detection_id=$4 UNION ALL
SELECT m.event_id FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunk_members m USING(chunk_id) WHERE d.detection_id=$4)
SELECT NOT EXISTS((SELECT * FROM expected EXCEPT ALL SELECT * FROM stored) UNION ALL (SELECT * FROM stored EXCEPT ALL SELECT * FROM expected))`, r.id, start, end, id).Scan(&same)
		if err != nil {
			return err
		}
		if !same {
			return ErrProcessing
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	data, err := json.Marshal(explanation)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.detection_results(rule_id,rule_version,signature_id,signature_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,settings_version,evidence_representation,evidence_hash_scheme)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'chunks-v1','sha256-chain-v2') RETURNING detection_id`, r.id, RuleVersion, r.signature.ID, r.signature.Version, *trigger.EventID, int64(*trigger.IngestionSeq), trigger.SourceIP, start, end, digest, n, len(explanation.HoldReasons) == 0, r.signature.ID == "" || r.signature.AutoApprovalAllowed, data, version).Scan(&id)
	if err != nil {
		return err
	}
	// Build bounded buckets on the server and insert every reference in one
	// statement. The immediate attachment guard scans the complete root once.
	_, err = tx.Exec(ctx, `SELECT cheesetrap.attach_detection_work($1,$2,$3,$4)`, id, r.id, start, end)
	return err
}
