package jobs

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"cheesetrap/internal/retention"
	"github.com/riverqueue/river"
)

func TestRetentionPassDrainAndYield(t *testing.T) {
	passes, yields, samples := 0, 0, 0
	err := runRetentionPasses(context.Background(), time.Now, func(context.Context) error { samples++; return nil }, func(context.Context) (retention.Progress, error) {
		if passes != yields {
			t.Fatal("next transaction admitted before yielding")
		}
		passes++
		if passes < 4 {
			return retention.Progress{Deleted: 1000}, nil
		}
		return retention.Progress{}, nil
	}, func(context.Context) error { yields++; return nil })
	if err != nil || passes != 4 || yields != 3 || samples != 1 {
		t.Fatalf("drain passes=%d yields=%d error=%v", passes, yields, err)
	}
}

func TestRetentionPassHorizon(t *testing.T) {
	for _, yieldDelay := range []bool{false, true} {
		t.Run(map[bool]string{false: "pass_budget", true: "yield_budget"}[yieldDelay], func(t *testing.T) {
			now := time.Unix(0, 0)
			passes, yields := 0, 0
			err := runRetentionPasses(context.Background(), func() time.Time { return now }, retentionSampleOK, func(context.Context) (retention.Progress, error) {
				passes++
				now = now.Add(7 * time.Second)
				return retention.Progress{Deleted: 1000}, nil
			}, func(context.Context) error {
				yields++
				if yieldDelay {
					now = now.Add(20 * time.Second)
				}
				return nil
			})
			var snooze *river.JobSnoozeError
			if !errors.As(err, &snooze) || snooze.Duration != time.Second {
				t.Fatal("budget must snooze", err)
			}
			expected := 3
			if yieldDelay {
				expected = 1
			}
			if passes != expected {
				t.Fatalf("passes=%d want%d", passes, expected)
			}
		})
	}
}

func TestRetentionPassCancellationAndErrors(t *testing.T) {
	for _, mode := range []string{"before", "pass_cancel", "yield_cancel", "busy_cancel", "real_error", "sql_timeout", "yield_error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			passes, yields := 0, 0
			sentinel := errors.New("database connection lost")
			if mode == "before" {
				cancel()
			}
			err := runRetentionPasses(ctx, time.Now, retentionSampleOK, func(context.Context) (retention.Progress, error) {
				passes++
				switch mode {
				case "pass_cancel":
					cancel()
				case "busy_cancel":
					cancel()
					return retention.Progress{}, retention.ErrBusy
				case "real_error":
					return retention.Progress{}, sentinel
				case "sql_timeout":
					return retention.Progress{}, context.DeadlineExceeded
				}
				return retention.Progress{Deleted: 1}, nil
			}, func(context.Context) error {
				yields++
				if mode == "yield_error" {
					return sentinel
				}
				cancel()
				return ctx.Err()
			})
			var snooze *river.JobSnoozeError
			switch mode {
			case "real_error", "yield_error":
				if !errors.Is(err, sentinel) || errors.As(err, &snooze) {
					t.Fatal("real error lost", err)
				}
			case "sql_timeout":
				if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &snooze) {
					t.Fatal("SQL timeout became snooze", err)
				}
			default:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			}
			expected := 1
			if mode == "before" {
				expected = 0
			}
			if passes != expected {
				t.Fatalf("unexpected passes %d", passes)
			}
			if (mode == "before" || mode == "pass_cancel" || mode == "busy_cancel") && yields != 0 {
				t.Fatal("yield after cancellation")
			}
		})
	}
}

func TestRetentionYieldCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := yieldRetention(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("yield ignored cancellation", err)
	}
}

func retentionSampleOK(context.Context) error { return nil }

func TestRetentionSampleConsumesHorizon(t *testing.T) {
	now := time.Unix(0, 0)
	samples, passes := 0, 0
	err := runRetentionPasses(context.Background(), func() time.Time { return now }, func(context.Context) error { samples++; now = now.Add(20 * time.Second); return nil }, func(context.Context) (retention.Progress, error) { passes++; return retention.Progress{}, nil }, retentionSampleOK)
	var snooze *river.JobSnoozeError
	if !errors.As(err, &snooze) || snooze.Duration != time.Second || samples != 1 || passes != 0 {
		t.Fatalf("sample outside budget: samples=%d passes=%d error=%v", samples, passes, err)
	}
}

func TestRetentionBusyRetriesThenDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		samples := 0
		var attempts []time.Duration
		err := runRetentionPasses(context.Background(), time.Now, func(context.Context) error {
			samples++
			return nil
		}, func(context.Context) (retention.Progress, error) {
			attempts = append(attempts, time.Since(started))
			switch len(attempts) {
			case 1:
				return retention.Progress{}, retention.ErrBusy
			case 2:
				return retention.Progress{Deleted: 1000}, nil
			default:
				return retention.Progress{}, nil
			}
		}, yieldRetention)
		if err != nil || samples != 1 || len(attempts) != 3 {
			t.Fatalf("busy must retry and drain within one invocation: attempts=%v samples=%d err=%v", attempts, samples, err)
		}
		// synctest advances the real timers deterministically. This verifies
		// admission backoff and the existing post-commit fairness yield together.
		if attempts[0] != 0 || attempts[1] != 50*time.Millisecond || attempts[2] != 60*time.Millisecond {
			t.Fatalf("retry must wait50ms and successful pass must yield10ms: %v", attempts)
		}
	})
}

func TestRetentionBusyRetriesUntilOriginalHorizon(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		samples, attempts := 0, 0
		err := runRetentionPasses(context.Background(), time.Now, func(context.Context) error {
			samples++
			time.Sleep(2 * time.Second)
			return nil
		}, func(context.Context) (retention.Progress, error) {
			attempts++
			if attempts > 360 {
				t.Fatal("busy retry spun without waiting or reset the original horizon")
			}
			return retention.Progress{}, retention.ErrBusy
		}, func(context.Context) error {
			t.Fatal("busy admission used the successful-pass yield")
			return nil
		})
		var snooze *river.JobSnoozeError
		if !errors.As(err, &snooze) || snooze.Duration != time.Second || samples != 1 || attempts != 360 || time.Since(started) != 20*time.Second {
			t.Fatalf("busy retries must use remaining original budget: samples=%d attempts=%d elapsed=%s err=%v", samples, attempts, time.Since(started), err)
		}
	})
}

func TestRetentionBusyWaitCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		attempts := 0
		go func() {
			result <- runRetentionPasses(ctx, time.Now, retentionSampleOK, func(context.Context) (retention.Progress, error) {
				attempts++
				return retention.Progress{}, retention.ErrBusy
			}, yieldRetention)
		}()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("busy invocation returned instead of waiting for admission: %v", err)
		default:
		}
		time.Sleep(25 * time.Millisecond)
		cancel()
		synctest.Wait()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) || attempts != 1 {
				t.Fatalf("cancelled busy wait retried or hid cancellation: attempts=%d err=%v", attempts, err)
			}
		default:
			t.Fatal("busy wait did not return promptly after cancellation")
		}
	})
}

func TestRetentionBusyRetryPreservesRealErrors(t *testing.T) {
	for _, failure := range []error{retention.ErrCleanup, context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				attempts := 0
				err := runRetentionPasses(context.Background(), time.Now, retentionSampleOK, func(context.Context) (retention.Progress, error) {
					attempts++
					if attempts == 1 {
						return retention.Progress{}, retention.ErrBusy
					}
					return retention.Progress{}, failure
				}, yieldRetention)
				if !errors.Is(err, failure) || attempts != 2 || time.Since(started) != 50*time.Millisecond {
					t.Fatalf("real failure after busy admission was changed: attempts=%d elapsed=%s err=%v", attempts, time.Since(started), err)
				}
			})
		})
	}
}
