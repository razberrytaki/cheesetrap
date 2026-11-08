package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const SessionLifetime = 12 * time.Hour
const SessionIdle = time.Hour

// Identity contains no credentials or session token.
type Identity struct {
	AdminID  string `json:"admin_id"`
	Username string `json:"username"`
}
type Session struct {
	Identity  Identity
	Token     string
	ExpiresAt time.Time
}
type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }
func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("random_source_unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func ValidToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == token
}
func (s *Service) CreateAdmin(ctx context.Context, username, password string) error {
	if !ValidUsername(username) {
		return ErrInput
	}
	hash, err := HashPassword(ctx, password)
	if err != nil {
		return err
	}
	if s.pool == nil {
		return ErrUnavailable
	}
	_, err = db.New(s.pool).CreateAdmin(ctx, db.CreateAdminParams{Username: username, PasswordHash: hash})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) Login(ctx context.Context, username, password, previousToken string) (Session, error) {
	if s.pool == nil {
		return Session{}, ErrUnavailable
	}
	q := db.New(s.pool)
	admin, err := q.GetAdminForLogin(ctx, username)
	known := err == nil
	hash := dummyHash
	if known {
		hash = admin.PasswordHash
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrUnavailable
	}
	ok, err := VerifyPassword(ctx, hash, password)
	if err != nil {
		return Session{}, err
	}
	if !known || !ok || !ValidUsername(username) {
		return Session{}, ErrCredentials
	}
	token := RandomToken()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Session{}, ErrUnavailable
	}
	defer tx.Rollback(ctx)
	q = db.New(tx)
	if ValidToken(previousToken) {
		if q.DeleteSession(ctx, TokenHash(previousToken)) != nil {
			return Session{}, ErrUnavailable
		}
	}
	created, err := q.CreateLoginSession(ctx, db.CreateLoginSessionParams{TokenHash: TokenHash(token), AdminID: admin.AdminID})
	if err != nil {
		return Session{}, ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return Session{}, ErrUnavailable
	}
	return Session{Identity: Identity{AdminID: uuidString(admin.AdminID), Username: admin.Username}, Token: token, ExpiresAt: created.Time}, nil
}
func (s *Service) Authenticate(ctx context.Context, token string) (Identity, error) {
	if !ValidToken(token) {
		return Identity{}, ErrCredentials
	}
	if s.pool == nil {
		return Identity{}, ErrUnavailable
	}
	row, err := db.New(s.pool).AuthenticateSession(ctx, TokenHash(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrCredentials
	}
	if err != nil {
		return Identity{}, ErrUnavailable
	}
	return Identity{AdminID: uuidString(row.AdminID), Username: row.Username}, nil
}
func (s *Service) Logout(ctx context.Context, token string) error {
	if !ValidToken(token) {
		return nil
	}
	if s.pool == nil || db.New(s.pool).DeleteSession(ctx, TokenHash(token)) != nil {
		return ErrUnavailable
	}
	return nil
}
func uuidString(id pgtype.UUID) string { return id.String() }
