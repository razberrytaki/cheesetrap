package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"cheesetrap/internal/detection"
	"github.com/riverqueue/river"
)

func TestDetectionPassHorizon(t *testing.T) {
	for _, gateDelay := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed_pass_exceeds_horizon", true: "gate_consumes_remaining_horizon"}[gateDelay], func(t *testing.T) {
			now := time.Unix(0, 0)
			passes, gates := 0, 0
			err := runDetectionPasses(context.Background(), func() time.Time { return now }, func(context.Context) error {
				gates++
				if gateDelay && gates == 2 {
					now = now.Add(20 * time.Second)
				}
				return nil
			}, func(context.Context) (detection.Progress, error) {
				passes++
				now = now.Add(7 * time.Second)
				return detection.Progress{HasMore: true}, nil
			})
			var snooze *river.JobSnoozeError
			if !errors.As(err, &snooze) || snooze.Duration != time.Second {
				t.Fatalf("backlog should snooze at horizon: %v", err)
			}
			expected := 3
			if gateDelay {
				expected = 1
			}
			if passes != expected {
				t.Fatalf("started pass after horizon: got %d want %d", passes, expected)
			}
		})
	}
}

func TestDetectionPassChecksEveryBoundary(t *testing.T) {
	for _, mode := range []string{"drain", "cancel", "storage", "processing_error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			passes, gates := 0, 0
			sentinel := errors.New("injected failure")
			err := runDetectionPasses(ctx, time.Now, func(context.Context) error {
				gates++
				if mode == "storage" && gates == 2 {
					return sentinel
				}
				return nil
			}, func(context.Context) (detection.Progress, error) {
				passes++
				if mode == "cancel" {
					cancel()
				}
				if mode == "processing_error" {
					return detection.Progress{}, sentinel
				}
				return detection.Progress{HasMore: passes < 3}, nil
			})
			switch mode {
			case "drain":
				if err != nil || passes != 3 || gates != 3 {
					t.Fatalf("did not drain: %d %d %v", passes, gates, err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) || passes != 1 || gates != 1 {
					t.Fatalf("continued after cancellation: %d %d %v", passes, gates, err)
				}
			case "storage":
				if !errors.Is(err, sentinel) || passes != 1 || gates != 2 {
					t.Fatalf("storage gate not repeated: %d %d %v", passes, gates, err)
				}
			case "processing_error":
				if !errors.Is(err, sentinel) || passes != 1 {
					t.Fatalf("processing error lost: %d %v", passes, err)
				}
			}
		})
	}
}
