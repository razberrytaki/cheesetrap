package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDraftOnlyContract(t *testing.T) {
	raw, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	var schema struct{ Paths map[string]json.RawMessage }
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for path := range schema.Paths {
		for _, removed := range []string{"deliveries", "smtp-test", "/approve", "/cancel", "/retry", "close-unconfirmed"} {
			if strings.Contains(path, removed) {
				t.Errorf("sending operation remains: %s", path)
			}
		}
	}
	for _, field := range []string{"automatic_mode", "delivery_limits", "smtp_test_recipient", "latest_smtp_test", "delivery_uncertain", "has_delivery_attempts", "auto_approval_allowed"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Errorf("sending field remains: %s", field)
		}
	}
}
