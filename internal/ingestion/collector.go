package ingestion

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"slices"
	"time"

	"cheesetrap/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"cheesetrap/internal/observability"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
)

var ErrCollectorOwned = errors.New("collector_already_running")

// RunCollector owns a single-server session lease on the very connection used
// for every commit. A lost connection terminates this run: a replacement process
// must acquire the lease and restore committed state before opening any source.
// It retains pending batches across ordinary transaction failures and never
// polls ahead of their durable checkpoint. Detached EOF writers are not evicted.
func RunCollector(ctx context.Context, databaseURL, logRoot, sourcesFile string) error {
	return runCollector(ctx, databaseURL, logRoot, sourcesFile, nil)
}
func runCollector(ctx context.Context, databaseURL, logRoot, sourcesFile string, probe observability.Probe) error {
	sources, err := LoadSources(logRoot, sourcesFile)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(logRoot)
	if err != nil {
		return ErrSources
	}
	pool, err := store.NewPool(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	leased, err := pool.Acquire(ctx)
	if err != nil {
		return commitError(ctx)
	}
	conn := leased.Hijack()
	var owned bool
	defer func() {
		// A healthy session acknowledges the unlock before shutdown. Cancellation
		// can instead make pgx close asynchronously; Close alone does not wait for
		// that cleanup. Keep this detached from the canceled run, but bounded.
		clean, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if owned && !conn.IsClosed() {
			_, _ = conn.Exec(clean, "SELECT pg_advisory_unlock(1667781748,1)")
		}
		_ = conn.Close(clean)
		select {
		case <-conn.PgConn().CleanupDone():
		case <-clean.Done():
			// A failed connection can outlive this bound on the server. The next
			// collector must still acquire the lease before reading any source.
		}
	}()
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(1667781748,1)").Scan(&owned); err != nil {
		return commitError(ctx)
	}
	if !owned {
		return ErrCollectorOwned
	}
	readers := make([]collectorReader, 0, len(sources))
	defer func() {
		for _, r := range readers {
			_ = r.tail.Close()
		}
	}()
	q := db.New(conn)
	for _, s := range sources {
		// Identity conflicts are checked before opening any engine file.
		if _, err := q.EnsureCollectorSensor(ctx, db.EnsureCollectorSensorParams{SensorID: uuid(s.SensorID), Name: s.Name, Engine: s.Engine}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrBatch
			}
			return commitError(ctx)
		}
		resume, err := loadResume(ctx, q, s.SensorID, root)
		if err != nil {
			return err
		}
		tail, err := NewTailer(TailerConfig{Path: s.Path, ArchivePaths: s.ArchivePaths, Resume: resume, MaxOpenFiles: 64, MaxDiagnostics: 1024})
		if err != nil {
			return ErrBatch
		}
		r := collectorReader{source: s, tail: tail}
		readers = append(readers, r)
	}
	storagePaused := false
	for {
		receipt, e := readRetentionReceipt(root)
		if e != nil {
			return e
		}
		for i := range readers {
			changed, e := applyRetentionReceipt(ctx, conn, readers[i].source.SensorID, receipt[readers[i].source.SensorID])
			if e != nil {
				return e
			}
			if changed {
				readers[i].noteGap(domain.GapRetentionCleanup)
			}
		}
		paths := observability.ConfiguredPaths()
		if len(paths) == 0 {
			paths = []string{root}
		}
		restricted, e := observability.SampleWithProbe(ctx, pool, "collector", paths, probe)
		if e != nil {
			return e
		}
		if restricted {
			if !storagePaused {
				for i := range readers {
					if e := notePersistentGap(ctx, conn, readers[i].source.SensorID, domain.GapStorageRestricted, 1); e != nil {
						return e
					}
					readers[i].noteGap(domain.GapStorageRestricted)
				}
			}
			storagePaused = true
			if e := waitCollector(ctx, time.Second); e != nil {
				return e
			}
			continue
		}
		storagePaused = false
		for i := range readers {
			r := &readers[i]
			observed, err := q.CommitClock(ctx)
			if err != nil {
				return commitError(ctx)
			}
			batch, err := r.tail.Poll(ctx)
			batch.ObservationStartedAt = observed.Time
			if err != nil {
				return err
			}
			if batch.Status.GapCount > r.gaps {
				var persisted int64
				if err := conn.QueryRow(ctx, `SELECT COALESCE((SELECT gap_count FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1),0)`, r.source.SensorID).Scan(&persisted); err != nil {
					return commitError(ctx)
				}
				delta := batch.Status.GapCount - r.gaps
				if delta > uint64(math.MaxInt64-persisted) {
					return ErrBatch
				}
				batch.GapCountFloor = persisted + int64(delta)
				r.noteGap(domain.GapSourceChange)
			}
			delay := 250 * time.Millisecond
			for {
				batch.Status.CollectionGap = r.gap
				batch.GapCauses = r.causes
				err := CommitBatch(ctx, conn, r.source, batch)
				if err == nil {
					r.gaps = batch.Status.GapCount
					r.gap = false
					r.causes = nil
					break
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if conn.IsClosed() || !errors.Is(err, ErrCommit) {
					return err
				}
				r.noteGap(domain.GapSourceChange)
				if err := waitCollector(ctx, delay); err != nil {
					return err
				}
				delay = min(5*time.Second, delay*2)
			}
		}
		if err := waitCollector(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
}

type collectorReader struct {
	source Source
	tail   *Tailer
	gap    bool
	gaps   uint64
	causes []domain.GapCause
}

func (r *collectorReader) noteGap(cause domain.GapCause) {
	r.gap = true
	if !slices.Contains(r.causes, cause) {
		r.causes = append(r.causes, cause)
	}
}

func waitCollector(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func loadResume(ctx context.Context, q *db.Queries, sensor, root string) ([]ResumePoint, error) {
	rows, err := q.ListCollectorResume(ctx, uuid(sensor))
	if err != nil {
		return nil, commitError(ctx)
	}
	if len(rows) > 64 {
		return nil, ErrBatch
	}
	points := make([]ResumePoint, 0, len(rows))
	for _, r := range rows {
		device, ok := numericUint64(r.Device)
		inode, inoOK := numericUint64(r.Inode)
		id := fmt.Sprintf("%x-%x-%x-%x-%x", r.FileGenerationID.Bytes[:4], r.FileGenerationID.Bytes[4:6], r.FileGenerationID.Bytes[6:8], r.FileGenerationID.Bytes[8:10], r.FileGenerationID.Bytes[10:])
		p := ResumePoint{Generation: FileGeneration{ID: id, Path: r.Path, Device: device, Inode: inode, CreatedAt: r.CreatedAt.Time, ObservedSize: r.ObservedSize, FingerprintBytes: int(r.FingerprintBytes), FingerprintSHA256: r.FingerprintSha256}, ByteOffset: r.ByteOffset}
		// Pre-M1-04 checkpoint rows have no witness and must not masquerade as an
		// observed empty file. Never guess a prefix or end boundary during upgrade.
		if !ok || !inoOK || !validResume(p) || !within(root, r.Path) || p.ByteOffset > p.Generation.ObservedSize {
			return nil, ErrBatch
		}
		points = append(points, p)
	}
	return points, nil
}
func numericUint64(n pgtype.Numeric) (uint64, bool) {
	if !n.Valid || n.NaN || n.InfinityModifier != pgtype.Finite || n.Int == nil {
		return 0, false
	}
	value := new(big.Int).Set(n.Int)
	if n.Exp > 0 {
		value.Mul(value, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n.Exp)), nil))
	} else if n.Exp < 0 {
		factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-n.Exp)), nil)
		remainder := new(big.Int)
		value.QuoRem(value, factor, remainder)
		if remainder.Sign() != 0 {
			return 0, false
		}
	}
	return value.Uint64(), value.IsUint64()
}
