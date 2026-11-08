// Package observability exposes durable operational facts separately from sensor traffic.
package observability

import (
	"cheesetrap/internal/policy"
	"cheesetrap/internal/retention"
	"cheesetrap/internal/store"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"strconv"
	"time"
)

var ErrStatus = errors.New("operations_status_failed")

type SensorStatus struct {
	Name              string     `json:"name"`
	CollectorState    string     `json:"collector_state"`
	LastEngineLogAt   *time.Time `json:"last_engine_log_at"`
	LastObservationAt *time.Time `json:"last_observation_at"`
	GapCount          string     `json:"gap_count"`
}
type Status struct {
	StorageState          string            `json:"storage_state"`
	DiskUsedPercent       *float64          `json:"disk_used_percent"`
	StorageSampledAt      *time.Time        `json:"storage_sampled_at"`
	StorageBacklog        bool              `json:"storage_backlog"`
	ProtectedEvents       string            `json:"protected_events"`
	DetectionLagSeconds   *float64          `json:"detection_lag_seconds"`
	CollectionLagSeconds  *float64          `json:"collection_lag_seconds"`
	OldestQueueAgeSeconds *float64          `json:"oldest_queue_age_seconds"`
	LookupFailures        string            `json:"lookup_failures"`
	ReportStates          map[string]string `json:"report_states"`
	Sensors               []SensorStatus    `json:"sensors"`
	Retention             retention.Policy  `json:"retention"`
}

func CapacityState(total, used uint64, sampled, now time.Time) string {
	if total == 0 || used > total || sampled.IsZero() || sampled.After(now.Add(time.Minute)) {
		return "unavailable"
	}
	if now.Sub(sampled) > 2*time.Minute {
		return "stale"
	}
	percent := float64(used) / float64(total) * 100
	if percent >= 90 {
		return "restricted"
	}
	if percent >= 80 {
		return "warning"
	}
	return "normal"
}
func Read(ctx context.Context, pool *pgxpool.Pool, now time.Time) (Status, error) {
	s := Status{StorageState: "unavailable", Sensors: []SensorStatus{}, ReportStates: map[string]string{}, Retention: retention.DefaultPolicy()}
	if pool == nil {
		return s, ErrStatus
	}
	operational, err := policy.Read(ctx, pool)
	if err != nil {
		return s, ErrStatus
	}
	s.Retention = operational.Retention
	rows, err := pool.Query(ctx, `SELECT name,state,last_engine_log_at,last_observation_at,COALESCE(g.gap_count,0)::text FROM cheesetrap.sensors s LEFT JOIN cheesetrap.ingestion_gaps g USING(sensor_id) ORDER BY name`)
	if err != nil {
		return s, ErrStatus
	}
	for rows.Next() {
		var v SensorStatus
		if err = rows.Scan(&v.Name, &v.CollectorState, &v.LastEngineLogAt, &v.LastObservationAt, &v.GapCount); err != nil {
			rows.Close()
			return s, ErrStatus
		}
		s.Sensors = append(s.Sensors, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return s, ErrStatus
	}
	var available bool
	if err = pool.QueryRow(ctx, `SELECT max(used_percent),min(sampled_at),COALESCE(bool_and(available),false) FROM cheesetrap.storage_status`).Scan(&s.DiskUsedPercent, &s.StorageSampledAt, &available); err != nil {
		return s, ErrStatus
	}
	if available && s.DiskUsedPercent != nil && s.StorageSampledAt != nil {
		s.StorageState = CapacityState(100000, uint64(*s.DiskUsedPercent*1000), *s.StorageSampledAt, now)
	}
	if err = pool.QueryRow(ctx, `SELECT protected_events::text FROM cheesetrap.retention_status WHERE singleton`).Scan(&s.ProtectedEvents); err != nil {
		return s, ErrStatus
	}
	s.StorageBacklog = s.ProtectedEvents != "0"
	if err = pool.QueryRow(ctx, `SELECT CASE WHEN count(*)=0 THEN NULL ELSE greatest(0,extract(epoch FROM ($1::timestamptz-min(ingested_at))))::float8 END FROM cheesetrap.events WHERE ingestion_seq>(SELECT detected_seq FROM cheesetrap.processing_cursors WHERE singleton)`, now).Scan(&s.DetectionLagSeconds); err != nil {
		return s, ErrStatus
	}
	if err = pool.QueryRow(ctx, `SELECT CASE WHEN count(*)=0 THEN NULL ELSE greatest(0,extract(epoch FROM ($1::timestamptz-min(last_observation_at))))::float8 END FROM cheesetrap.sensors WHERE state<>'disabled'`, now).Scan(&s.CollectionLagSeconds); err != nil {
		return s, ErrStatus
	}
	if err = pool.QueryRow(ctx, `SELECT CASE WHEN count(*)=0 THEN NULL ELSE greatest(0,extract(epoch FROM ($1::timestamptz-min(scheduled_at))))::float8 END FROM cheesetrap_river.river_job WHERE queue IN ('drafts','detection','windows','contacts','retention') AND state IN ('available','pending','retryable','scheduled') AND scheduled_at<=$1`, now).Scan(&s.OldestQueueAgeSeconds); err != nil {
		return s, ErrStatus
	}
	if err = pool.QueryRow(ctx, `SELECT count(*)::text FROM cheesetrap.enrichment_cache WHERE result->>'lookup_succeeded'='false'`).Scan(&s.LookupFailures); err != nil {
		return s, ErrStatus
	}
	for _, v := range []struct {
		sql  string
		dest map[string]string
	}{{`SELECT ` + store.ReportStateSQL + `,count(*) FROM cheesetrap.reports r GROUP BY 1`, s.ReportStates}} {
		rows, err = pool.Query(ctx, v.sql)
		if err != nil {
			return s, ErrStatus
		}
		for rows.Next() {
			var k string
			var n int64
			if rows.Scan(&k, &n) != nil {
				rows.Close()
				return s, ErrStatus
			}
			v.dest[k] = strconv.FormatInt(n, 10)
		}
		rows.Close()
		if rows.Err() != nil {
			return s, ErrStatus
		}
	}
	return s, nil
}
