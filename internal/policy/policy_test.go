package policy

import "testing"

func TestLegacyDefaultsAndValidation(t *testing.T) {
	p, err := Decode([]byte(`{"reply_to":""}`))
	if err != nil || p != Defaults() {
		t.Fatalf("legacy defaults: %+v %v", p, err)
	}
	for _, raw := range []string{
		`{"retention":{"raw_bytes":"01"}}`, `{"retention":{"event_days":0}}`,
		`{"retention":null}`, `{"retention":{"raw_days":null}}`,
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	p, err = Decode([]byte(`{"delivery_limits":{"daily":200,"recipient_daily":50},"retention":{"raw_days":2,"event_days":60,"history_days":360,"job_days":3,"raw_bytes":"2147483648"}}`))
	if err != nil || p.Retention.EventDays != 60 {
		t.Fatalf("custom: %+v %v", p, err)
	}
}
