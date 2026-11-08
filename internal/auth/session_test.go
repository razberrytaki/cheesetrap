package auth

import (
	"context"
	"strings"
	"testing"
)

// Small adapters keep password assertions readable.
func hashForTest(password string) (string, error) {
	return HashPassword(context.Background(), password)
}
func verifyForTest(hash, password string) bool {
	ok, _ := VerifyPassword(context.Background(), hash, password)
	return ok
}
func TestPasswordHashAndVerify(t *testing.T) {
	const password = "correct horse battery staple"
	hash, err := hashForTest(password)
	if err != nil || !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=1$") || strings.Contains(hash, password) {
		t.Fatal("password is not an encoded Argon2id hash")
	}
	other, err := hashForTest(password)
	if err != nil || hash == other {
		t.Fatal("password salts must be random")
	}
	if !verifyForTest(hash, password) || verifyForTest(hash, "wrong") {
		t.Fatal("password verification mismatch")
	}
}
func TestPasswordRejectsUnboundedOrMalformedHash(t *testing.T) {
	for _, hash := range []string{"", "plaintext", "$argon2id$v=19$m=999999999,t=99,p=255$c2FsdA$aGFzaA", strings.Repeat("x", 1025)} {
		if verifyForTest(hash, "wrong") {
			t.Fatal("malformed hash accepted")
		}
	}
	for _, password := range []string{"", "short", strings.Repeat("a", 1025)} {
		if _, err := hashForTest(password); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
}

func TestHashConcurrencyBoundAndCancellation(t *testing.T) {
	hashSlots <- struct{}{}
	hashSlots <- struct{}{}
	defer func() { <-hashSlots; <-hashSlots }()
	if _, err := HashPassword(context.Background(), "correct horse battery staple"); err != ErrUnavailable {
		t.Fatal("saturated KDF must fail without allocating another hash")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HashPassword(ctx, "correct horse battery staple"); err != ErrUnavailable {
		t.Fatal("cancelled hash accepted")
	}
}
