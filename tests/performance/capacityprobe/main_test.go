package main

import (
	"context"
	"errors"
	"testing"

	"cheesetrap/internal/retention"
)

func TestIsolationGuardRejectsAnyUnsafeRow(t *testing.T) {
	for _, tc := range []struct {
		marker         string
		events, copies int64
	}{
		{"", 0, 0}, {"isolated-v2", 0, 0}, {"isolated-v1", 1, 0}, {"isolated-v1", 0, 1},
	} {
		if checkGuard(tc.marker, tc.events, tc.copies) == nil {
			t.Fatalf("unsafe fixture accepted: %+v", tc)
		}
	}
	if err := checkGuard("isolated-v1", 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupStopsOnNoProgressAndPreservesErrors(t *testing.T) {
	calls := 0
	got, err := cleanupPasses(context.Background(), 10, func(context.Context) (retention.Progress, error) {
		calls++
		if calls == 1 {
			return retention.Progress{Deleted: 2}, nil
		}
		return retention.Progress{}, nil
	})
	if err != nil || calls != 2 || len(got) != 2 {
		t.Fatalf("did not stop at zero: %d %v", calls, err)
	}
	calls = 0
	got, err = cleanupPasses(context.Background(), 10, func(context.Context) (retention.Progress, error) {
		calls++
		return retention.Progress{}, retention.ErrBusy
	})
	if !errors.Is(err, retention.ErrBusy) || calls != 1 || len(got) != 1 {
		t.Fatalf("busy hidden/retried: %d %v", calls, err)
	}
}

func TestCleanupHonorsBoundAndCancellation(t *testing.T) {
	calls := 0
	got, err := cleanupPasses(context.Background(), 3, func(context.Context) (retention.Progress, error) { calls++; return retention.Progress{Deleted: 1}, nil })
	if err != nil || calls != 3 || len(got) != 3 {
		t.Fatalf("bound ignored: %d %v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = cleanupPasses(ctx, 3, func(context.Context) (retention.Progress, error) {
		t.Fatal("called after cancellation")
		return retention.Progress{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestConfigRejectsImplicitAuthorizationAndUnboundedRuns(t *testing.T) {
	base := config{Action: "cleanup", Isolated: true, WorkerFile: "/tmp/worker-url", Calls: 100}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.Isolated = false }, func(c *config) { c.Calls = 0 }, func(c *config) { c.Calls = 20001 },
		func(c *config) { c.Action = "sql" }, func(c *config) { c.WorkerFile = "relative" },
		func(c *config) { c.Action = "draft"; c.Window = "bad-uuid" },
		func(c *config) { c.Action = "revise"; c.Report = "10000000-0000-4000-8000-000000000001" },
	} {
		c := base
		mutate(&c)
		if c.validate() == nil {
			t.Fatalf("bad config accepted: %+v", c)
		}
	}
}

func TestProtectedCopyFingerprintIncludesEmptyReportsAndAllowsTerminalRemoval(t *testing.T) {
	before := snapshot{ProtectedReports: map[string]bool{"held": true, "expired": false}, Copies: map[string]copyFingerprint{"held": {Rows: 2, SHA256: "unchanged"}, "expired": {Rows: 5, SHA256: "old"}}}
	after := snapshot{Copies: map[string]copyFingerprint{"held": {Rows: 2, SHA256: "unchanged"}}}
	if !protectedUnchanged(before, after) {
		t.Fatal("valid expired removal rejected")
	}
	after.Copies["held"] = copyFingerprint{Rows: 2, SHA256: "changed"}
	if protectedUnchanged(before, after) {
		t.Fatal("same-count immutable change missed")
	}
	delete(after.Copies, "held")
	if protectedUnchanged(before, after) {
		t.Fatal("protected report removal missed")
	}
}

func TestSafeErrorsNeverIncludeDriverOrSecretDetails(t *testing.T) {
	err := errors.New("connection failed postgres://worker:SECRET@example.invalid/private")
	if got := safeError(err); got != "probe_failed" {
		t.Fatal("unexpected error disclosure", got)
	}
	c, err := parse([]string{"--action", "cleanup", "--isolated-fixture", "--worker-url-file", "/tmp/worker-url"})
	if err != nil || c.Calls != 100 {
		t.Fatal("explicit guarded invocation rejected", err)
	}
	if _, err := parse([]string{"--sql", "SECRET"}); err == nil || safeError(err) != "probe_arguments_invalid" {
		t.Fatal("arbitrary SQL accepted")
	}
}

func TestVerifyRequiresExplicitReportAndDoesNotRequireAPI(t *testing.T) {
	c := config{Action: "verify", Isolated: true, WorkerFile: "/tmp/worker-url", Calls: 100}
	if c.validate() == nil {
		t.Fatal("verify accepted no target")
	}
	c.Report = "10000000-0000-4000-8000-000000000001"
	if err := c.validate(); err != nil {
		t.Fatal("read-only verify required API", err)
	}
}

func TestProvenanceNeverClaimsMissingBaseRowsWereVerified(t *testing.T) {
	for _, tc := range []struct {
		available int64
		total     int
		want      string
	}{{0, 100, "unavailable"}, {50, 100, "partial"}, {100, 100, "verified"}, {0, 0, "unavailable"}} {
		if got := provenanceStatus(tc.available, tc.total); got != tc.want {
			t.Fatalf("available=%d total=%d got=%s", tc.available, tc.total, got)
		}
	}
}
