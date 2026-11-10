package observability

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"time"
)

// Usage includes space reserved from the application user, which cannot safely
// be consumed even if the filesystem still reports free blocks.
func Usage(total, available uint64) (float64, bool) {
	if total == 0 || available > total {
		return 0, false
	}
	return float64(total-available) / float64(total) * 100, true
}

type Probe func(string) (uint64, uint64, error)

func filesystemProbe(path string) (uint64, uint64, error) {
	var st unix.Statfs_t
	err := unix.Statfs(path, &st)
	return st.Blocks, st.Bavail, err
}

type Storage struct {
	Paths                []string
	DatabaseQuotaBytes   uint64
	DatabaseQuotaInvalid bool
}

func ConfiguredStorage() Storage {
	var s Storage
	if v := os.Getenv("CHEESETRAP_STORAGE_PATHS"); v != "" {
		s.Paths = strings.Split(v, ":")
	}
	if v, configured := os.LookupEnv("CHEESETRAP_DATABASE_QUOTA_GIB"); configured {
		gib, err := strconv.ParseUint(v, 10, 64)
		s.DatabaseQuotaInvalid = err != nil || gib == 0 || gib > ^uint64(0)/(1<<30)
		if !s.DatabaseQuotaInvalid {
			s.DatabaseQuotaBytes = gib * (1 << 30)
		}
	}
	return s
}

func (s Storage) measure(ctx context.Context, probe Probe, databaseSize func(context.Context) (int64, error)) (float64, bool) {
	if s.DatabaseQuotaInvalid {
		return 0, false
	}
	var worst float64
	for _, path := range s.Paths {
		total, free, err := probe(path)
		if path == "" || err != nil {
			return 0, false
		}
		p, ok := Usage(total, free)
		if !ok {
			return 0, false
		}
		worst = max(worst, p)
	}
	if s.DatabaseQuotaBytes > 0 {
		size, err := databaseSize(ctx)
		if err != nil || size < 0 {
			return 0, false
		}
		worst = max(worst, min(100, float64(size)/float64(s.DatabaseQuotaBytes)*100))
	}
	return worst, true
}

func Sample(ctx context.Context, pool *pgxpool.Pool, component string, storage Storage) (bool, error) {
	return SampleWithProbe(ctx, pool, component, storage, nil)
}
func SampleWithProbe(ctx context.Context, pool *pgxpool.Pool, component string, storage Storage, probe Probe) (bool, error) {
	if probe == nil {
		probe = filesystemProbe
	}
	if len(storage.Paths) == 0 && storage.DatabaseQuotaBytes == 0 && !storage.DatabaseQuotaInvalid {
		return false, nil
	}
	worst, available := storage.measure(ctx, probe, func(ctx context.Context) (int64, error) {
		var size int64
		err := pool.QueryRow(ctx, "SELECT pg_database_size(current_database())").Scan(&size)
		return size, err
	})
	var percent *float64
	if available {
		percent = &worst
	}
	_, err := pool.Exec(ctx, `INSERT INTO cheesetrap.storage_status(component,used_percent,available,sampled_at) VALUES($1,$2,$3,$4) ON CONFLICT(component) DO UPDATE SET used_percent=EXCLUDED.used_percent,available=EXCLUDED.available,sampled_at=EXCLUDED.sampled_at`, component, percent, available, time.Now().UTC())
	if err != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		return true, ErrStatus
	}
	return !available || worst >= 90, nil
}
