package observability

import (
	"testing"
	"time"
)

func TestCapacityThresholds(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		used uint64
		want string
	}{{79, "normal"}, {80, "warning"}, {89, "warning"}, {90, "restricted"}, {100, "restricted"}} {
		got := CapacityState(100, tc.used, now, now)
		if got != tc.want {
			t.Fatalf("%d: %s", tc.used, got)
		}
	}
	if CapacityState(0, 0, now, now) != "unavailable" {
		t.Fatal("zero capacity")
	}
	if CapacityState(100, 40, now.Add(-3*time.Minute), now) != "stale" {
		t.Fatal("stale sample")
	}
	if CapacityState(100, 101, now, now) != "unavailable" {
		t.Fatal("invalid capacity")
	}
	if CapacityState(100, 40, now, now) != "normal" {
		t.Fatal("recovery")
	}
}
func TestDiskGateVirtualCapacity(t *testing.T) {
	for _, v := range []struct {
		total, available uint64
		restrict         bool
	}{{100, 21, false}, {100, 20, false}, {100, 10, true}, {100, 0, true}, {0, 0, true}, {100, 101, true}} {
		percent, ok := Usage(v.total, v.available)
		if (!ok || percent >= 90) != v.restrict {
			t.Fatalf("capacity %v", v)
		}
	}
}
