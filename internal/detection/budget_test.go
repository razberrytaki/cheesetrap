package detection

import (
	"context"
	"testing"
	"time"
)

func TestDetectionBudgetValidation(t *testing.T) {
	for _, budget := range []time.Duration{0, -time.Second} {
		if _, err := ProcessBatchWithBudget(context.Background(), nil, 1000, budget); err != ErrBatchBudget {
			t.Fatalf("invalid budget accepted: %v", err)
		}
	}
}
