package config

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestAPIOriginSharedContract(t *testing.T) {
	data, err := os.ReadFile("../../testdata/api-origins.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Input, Canonical string }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Input, func(t *testing.T) {
			values := validEnv()
			values["CHEESETRAP_API_ORIGIN"] = tc.Input
			cfg, err := Parse([]string{"api"}, env(values))
			if tc.Canonical == "" {
				if !errors.Is(err, ErrAPIOriginInvalid) {
					t.Fatalf("invalid origin accepted: %v", err)
				}
				return
			}
			if err != nil || cfg.APIOrigin != tc.Canonical {
				t.Fatalf("origin=%q error=%v want=%q", cfg.APIOrigin, err, tc.Canonical)
			}
			if cfg.APIListen != "127.0.0.1:8080" {
				t.Fatal("origin changed the loopback listener")
			}
		})
	}
}

func TestHTTPSOriginDoesNotPermitExternalListener(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", "100.64.0.1:8080", "192.0.2.1:8080"} {
		values := validEnv()
		values["CHEESETRAP_API_ORIGIN"] = "https://dashboard.example.com"
		values["CHEESETRAP_API_LISTEN"] = address
		if _, err := Parse([]string{"api"}, env(values)); !errors.Is(err, ErrAPIListenInvalid) {
			t.Fatal("HTTPS relaxed bind restrictions")
		}
	}
}
