// Package auth owns local administrator credentials and revocable sessions.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

var ErrCredentials = errors.New("invalid_credentials")
var ErrUnavailable = errors.New("authentication_unavailable")
var ErrInput = errors.New("invalid_admin_input")
var hashSlots = make(chan struct{}, 2)

const hashPrefix = "$argon2id$v=19$m=65536,t=3,p=1$"

// A valid fixed-work dummy hash prevents an unknown username from skipping KDF
// work. Its key need not correspond to a real credential.
const dummyHash = hashPrefix + "MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func derive(ctx context.Context, password string, salt []byte) ([]byte, error) {
	select {
	case hashSlots <- struct{}{}:
		defer func() { <-hashSlots }()
	case <-ctx.Done():
		return nil, ErrUnavailable
	default:
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32), nil
}
func HashPassword(ctx context.Context, password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", ErrInput
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", ErrUnavailable
	}
	key, err := derive(ctx, password, salt)
	if err != nil {
		return "", err
	}
	return hashPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// VerifyPassword accepts exactly our bounded parameters, before allocating any
// KDF memory. Invalid stored hashes still consume ordinary dummy-hash work.
func VerifyPassword(ctx context.Context, encoded, password string) (bool, error) {
	valid := len(encoded) <= 256 && strings.HasPrefix(encoded, hashPrefix) && len(password) <= 1024
	salt, key := []byte(nil), []byte(nil)
	if valid {
		parts := strings.Split(strings.TrimPrefix(encoded, hashPrefix), "$")
		if len(parts) == 2 {
			salt, _ = base64.RawStdEncoding.DecodeString(parts[0])
			key, _ = base64.RawStdEncoding.DecodeString(parts[1])
		}
		valid = len(salt) == 16 && len(key) == 32
	}
	if !valid {
		parts := strings.Split(strings.TrimPrefix(dummyHash, hashPrefix), "$")
		salt, _ = base64.RawStdEncoding.DecodeString(parts[0])
		key, _ = base64.RawStdEncoding.DecodeString(parts[1])
		password = "invalid"
	}
	actual, err := derive(ctx, password, salt)
	if err != nil {
		return false, err
	}
	return valid && subtle.ConstantTimeCompare(actual, key) == 1, nil
}
func ValidUsername(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
