//go:build integration

package observability

import (
	"context"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/store"
)

func TestStorageSampleRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, component := range []string{"collector", "worker"} {
		t.Run(component, func(t *testing.T) {
			key := "CHEESETRAP_TEST_COLLECTOR_URL"
			if component == "worker" {
				key = "CHEESETRAP_TEST_WORKER_URL"
			}
			pool, err := store.NewPool(ctx, os.Getenv(key))
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			var size int64
			if err := pool.QueryRow(ctx, "SELECT pg_database_size(current_database())").Scan(&size); err != nil || size <= 0 {
				t.Fatalf("database size unavailable: %v", err)
			}
			for _, tc := range []struct {
				storage               Storage
				restricted, available bool
				percent               float64
			}{
				{Storage{DatabaseQuotaBytes: 1}, true, true, 100},
				{Storage{Paths: []string{"logs"}, DatabaseQuotaBytes: 1 << 40}, false, true, 60},
				{Storage{DatabaseQuotaInvalid: true}, true, false, 0},
			} {
				restricted, err := SampleWithProbe(ctx, pool, component, tc.storage, func(string) (uint64, uint64, error) { return 100, 40, nil })
				if err != nil || restricted != tc.restricted {
					t.Fatalf("restricted=%v err=%v", restricted, err)
				}
				var available bool
				var percent *float64
				if err := pool.QueryRow(ctx, "SELECT used_percent,available FROM cheesetrap.storage_status WHERE component=$1", component).Scan(&percent, &available); err != nil {
					t.Fatal(err)
				}
				if available != tc.available || (tc.available && (percent == nil || *percent != tc.percent)) || (!tc.available && percent != nil) {
					t.Fatalf("unexpected persisted sample: %v %v", percent, available)
				}
			}
		})
	}
}
