package ingestion

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionReceipt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".retention-loss.json")
	if v, e := readRetentionReceipt(dir); e != nil || len(v) != 0 {
		t.Fatal(v, e)
	}
	for _, raw := range []string{`{"version":2,"sensors":{}}`, `{"version":1,"sensors":{"bad":-1}}`, `{"version":1,"sensors":{"10000000-0000-4000-8000-000000000701":-1}}`} {
		os.WriteFile(p, []byte(raw), 0600)
		if _, e := readRetentionReceipt(dir); e == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
	os.WriteFile(p, []byte(`{"version":1,"sensors":{"10000000-0000-4000-8000-000000000701":3}}`), 0600)
	if v, e := readRetentionReceipt(dir); e != nil || v["10000000-0000-4000-8000-000000000701"] != 3 {
		t.Fatal(v, e)
	}
}
