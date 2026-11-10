package observability

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestStorageSources(t *testing.T) {
	for _, tc := range []struct {
		name      string
		storage   Storage
		size      int64
		queryErr  error
		want      float64
		available bool
	}{
		{"quota", Storage{DatabaseQuotaBytes: 100}, 80, nil, 80, true},
		{"clamp", Storage{DatabaseQuotaBytes: 100}, 150, nil, 100, true},
		{"database_worst", Storage{Paths: []string{"logs"}, DatabaseQuotaBytes: 100}, 95, nil, 95, true},
		{"filesystem_worst", Storage{Paths: []string{"logs"}, DatabaseQuotaBytes: 100}, 20, nil, 60, true},
		{"invalid_quota", Storage{DatabaseQuotaInvalid: true}, 0, nil, 0, false},
		{"query_failure", Storage{DatabaseQuotaBytes: 100}, 0, errors.New("unavailable"), 0, false},
		{"path_failure", Storage{Paths: []string{""}, DatabaseQuotaBytes: 100}, 20, nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, available := tc.storage.measure(context.Background(), func(string) (uint64, uint64, error) { return 100, 40, nil }, func(context.Context) (int64, error) { return tc.size, tc.queryErr })
			if got != tc.want || available != tc.available {
				t.Fatalf("usage=%v available=%v, want %v %v", got, available, tc.want, tc.available)
			}
		})
	}
}

func TestConfiguredStorageQuota(t *testing.T) {
	t.Setenv("CHEESETRAP_STORAGE_PATHS", "/logs:/db")
	for _, value := range []string{"", "1", "1000000", "0", "-1", "1.5", "invalid", "18446744073709551615", " 1", "+1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("CHEESETRAP_DATABASE_QUOTA_GIB", value)
			got := ConfiguredStorage()
			valid := value == "1" || value == "1000000"
			if len(got.Paths) != 2 || got.DatabaseQuotaInvalid != !valid {
				t.Fatalf("invalid configuration parse: %+v", got)
			}
			if value == "1" && got.DatabaseQuotaBytes != 1<<30 {
				t.Fatalf("not GiB: %d", got.DatabaseQuotaBytes)
			}
		})
	}
}

func TestStorageUnconfigured(t *testing.T) {
	t.Setenv("CHEESETRAP_STORAGE_PATHS", "")
	t.Setenv("CHEESETRAP_DATABASE_QUOTA_GIB", "1")
	if err := os.Unsetenv("CHEESETRAP_DATABASE_QUOTA_GIB"); err != nil {
		t.Fatal(err)
	}
	storage := ConfiguredStorage()
	restricted, err := Sample(context.Background(), nil, "worker", storage)
	if err != nil || restricted {
		t.Fatalf("unconfigured storage restricted=%v err=%v", restricted, err)
	}
}
