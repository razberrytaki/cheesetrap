package auth

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func readAdminForTest(ctx context.Context, f *os.File) (string, string, error) {
	return ReadAdminInput(ctx, f, io.Discard)
}
func TestAdminInputBoundedAndCancellable(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{{"admin\ncorrect horse battery staple\n", true}, {"admin\ncorrect horse battery staple", true}, {"\ncorrect horse battery staple\n", false}, {"admin\nshort\n", false}, {"admin\ncorrect horse battery staple\nextra", false}, {"admin\n" + strings.Repeat("x", 1025), false}} {
		f, err := os.CreateTemp(t.TempDir(), "input")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(f, tc.value)
		_, _ = f.Seek(0, 0)
		user, password, err := readAdminForTest(context.Background(), f)
		_ = f.Close()
		if tc.valid {
			if err != nil || user != "admin" || password != "correct horse battery staple" {
				t.Fatal("valid protected input rejected")
			}
		} else if err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err = readAdminForTest(ctx, r)
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("blocked input did not cancel")
	}
}
