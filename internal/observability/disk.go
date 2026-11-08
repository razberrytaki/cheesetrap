package observability

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"os"
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

// Sample measures configured actual storage mounts, never the container layer.
// Standalone deployments opt in with CHEESETRAP_STORAGE_PATHS; Compose sets it.
// Failed configured probes fail closed and are persisted as unavailable.
type Probe func(string) (uint64, uint64, error)

func filesystemProbe(path string) (uint64, uint64, error) {
	var st unix.Statfs_t
	err := unix.Statfs(path, &st)
	return st.Blocks, st.Bavail, err
}
func Sample(ctx context.Context, pool *pgxpool.Pool, component string, paths []string) (bool, error) {
	return SampleWithProbe(ctx, pool, component, paths, nil)
}
func SampleWithProbe(ctx context.Context, pool *pgxpool.Pool, component string, paths []string, probe Probe) (bool, error) {
	if probe == nil {
		probe = filesystemProbe
	}
	if len(paths) == 0 {
		return false, nil
	}
	var worst float64
	available := true
	for _, path := range paths {
		total, free, err := probe(path)
		if path == "" || err != nil {
			available = false
			break
		}
		p, ok := Usage(total, free)
		if !ok {
			available = false
			break
		}
		if p > worst {
			worst = p
		}
	}
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
func ConfiguredPaths() []string {
	v := os.Getenv("CHEESETRAP_STORAGE_PATHS")
	if v == "" {
		return nil
	}
	return strings.Split(v, ":")
}
