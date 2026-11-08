package api

import (
	"cheesetrap/internal/policy"
	"encoding/json"
	"testing"
)

func TestLegacySettingsReplayDefaults(t *testing.T) {
	var got Settings
	if err := json.Unmarshal([]byte(`{"version":"2","reply_to":"ops@example.org","period_days":7}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Retention != policy.Defaults().Retention {
		t.Fatal("old idempotency response lost defaults", got)
	}
}
