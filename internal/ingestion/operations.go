package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"os"
	"path/filepath"
)

func readRetentionReceipt(root string) (map[string]int64, error) {
	p := filepath.Join(root, ".retention-loss.json")
	st, e := os.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		return map[string]int64{}, nil
	}
	if e != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return nil, ErrSources
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, ErrSources
	}
	defer f.Close()
	var v struct {
		Version int              `json:"version"`
		Sensors map[string]int64 `json:"sensors"`
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Version != 1 || v.Sensors == nil {
		return nil, ErrSources
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrSources
	}
	for k, n := range v.Sensors {
		if !validUUID(k) || n < 0 {
			return nil, ErrSources
		}
	}
	return v.Sensors, nil
}
func notePersistentGap(ctx context.Context, conn *pgx.Conn, sensor string, amount int64) error {
	_, err := conn.Exec(ctx, `INSERT INTO cheesetrap.ingestion_gaps(sensor_id,started_at,observed_through,gap_count) SELECT sensor_id,least(last_observation_at,clock_timestamp()),clock_timestamp(),$2 FROM cheesetrap.sensors WHERE sensor_id=$1 ON CONFLICT(sensor_id) DO UPDATE SET gap_count=ingestion_gaps.gap_count+EXCLUDED.gap_count,observed_through=EXCLUDED.observed_through`, sensor, amount)
	if err != nil {
		return commitError(ctx)
	}
	_, err = conn.Exec(ctx, `UPDATE cheesetrap.sensors SET state='degraded' WHERE sensor_id=$1`, sensor)
	if err != nil {
		return commitError(ctx)
	}
	return nil
}
func applyRetentionReceipt(ctx context.Context, conn *pgx.Conn, sensor string, count int64) (bool, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return false, commitError(ctx)
	}
	defer tx.Rollback(context.Background())
	var previous int64
	if err = tx.QueryRow(ctx, `SELECT raw_loss_count FROM cheesetrap.sensors WHERE sensor_id=$1 FOR UPDATE`, sensor).Scan(&previous); err != nil {
		return false, commitError(ctx)
	}
	if count <= previous {
		return false, nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.ingestion_gaps(sensor_id,started_at,observed_through,gap_count) SELECT sensor_id,least(last_observation_at,clock_timestamp()),clock_timestamp(),$2 FROM cheesetrap.sensors WHERE sensor_id=$1 ON CONFLICT(sensor_id) DO UPDATE SET gap_count=ingestion_gaps.gap_count+EXCLUDED.gap_count,observed_through=EXCLUDED.observed_through`, sensor, count-previous)
	if err != nil {
		return false, commitError(ctx)
	}
	_, err = tx.Exec(ctx, `UPDATE cheesetrap.sensors SET state='degraded',raw_loss_count=$2 WHERE sensor_id=$1`, sensor, count)
	if err != nil {
		return false, commitError(ctx)
	}
	if tx.Commit(ctx) != nil {
		return false, commitError(ctx)
	}
	return true, nil
}
