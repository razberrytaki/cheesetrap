//go:build integration

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/auth"
	"cheesetrap/internal/domain"
	"cheesetrap/internal/observability"
	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

func handlerForPool(pool *pgxpool.Pool) http.Handler { return NewHandler(pool, testOrigin) }
func apiFixture(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool, http.Handler) {
	t.Helper()
	ctx := context.Background()
	pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_API_URL"))
	if err != nil {
		t.Fatal("isolated api database required")
	}
	t.Cleanup(pool.Close)
	migration, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_MIGRATION_URL"))
	if err != nil {
		t.Fatal("isolated migration database required")
	}
	t.Cleanup(migration.Close)
	if _, err := migration.Exec(ctx, "DELETE FROM cheesetrap.sessions; DELETE FROM cheesetrap.admins"); err != nil {
		t.Fatal("admin fixture cleanup failed")
	}
	salt := []byte("0123456789abcdef")
	hash := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(argon2.IDKey([]byte("correct horse battery staple"), salt, 3, 65536, 1, 32)))
	if _, err := pool.Exec(ctx, "INSERT INTO cheesetrap.admins(username,password_hash) VALUES('admin',$1)", hash); err != nil {
		t.Fatal("admin fixture failed")
	}
	t.Cleanup(func() {
		_, _ = migration.Exec(context.Background(), "DELETE FROM cheesetrap.sessions; DELETE FROM cheesetrap.admins")
	})
	return pool, migration, handlerForPool(pool)
}
func csrf(t *testing.T, h http.Handler) (string, []*http.Cookie) {
	t.Helper()
	w := request(h, "GET", "/api/v1/auth/csrf", "", nil)
	if w.Code != 200 {
		t.Fatalf("bootstrap status=%d", w.Code)
	}
	var b struct {
		Token string `json:"csrf_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &b) != nil || b.Token == "" {
		t.Fatal("csrf body invalid")
	}
	return b.Token, w.Result().Cookies()
}
func login(t *testing.T, h http.Handler) (string, []*http.Cookie) {
	t.Helper()
	token, cookies := csrf(t, h)
	w := request(h, "POST", "/api/v1/auth/login", `{"username":"admin","password":"correct horse battery staple"}`, map[string]string{"Origin": testOrigin, "X-CSRF-Token": token, "Content-Type": "application/json"}, cookies...)
	if w.Code != 200 {
		t.Fatalf("login status=%d", w.Code)
	}
	var b struct {
		Token string `json:"csrf_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &b) != nil || b.Token == "" || b.Token == token {
		t.Fatal("login must rotate csrf")
	}
	cookies = w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("login must set session and csrf cookies")
	}
	for _, c := range cookies {
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Domain != "" || c.Secure {
			t.Fatal("unsafe session cookie")
		}
	}
	return b.Token, cookies
}
func TestAuthSessions(t *testing.T) {
	pool, migration, h := apiFixture(t)
	ctx := context.Background()
	t.Run("credentials_and_session_hash_only", func(t *testing.T) {
		token, cookies := csrf(t, h)
		for _, credentials := range []string{`{"username":"admin","password":"wrong-password"}`, `{"username":"missing","password":"wrong-password"}`} {
			w := request(h, "POST", "/api/v1/auth/login", credentials, map[string]string{"Origin": testOrigin, "X-CSRF-Token": token, "Content-Type": "application/json"}, cookies...)
			if w.Code != 401 {
				t.Fatalf("credential status=%d", w.Code)
			}
			assertError(t, w, "wrong-password")
		}
		_, cookies = login(t, h)
		w := request(h, "GET", "/api/v1/auth/me", "", nil, cookies...)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"username":"admin"`) {
			t.Fatalf("me status=%d", w.Code)
		}
		var hash string
		var lifetime time.Duration
		var seconds float64
		if pool.QueryRow(ctx, "SELECT token_hash, extract(epoch from(expires_at-created_at)) FROM cheesetrap.sessions").Scan(&hash, &seconds) != nil {
			t.Fatal("session missing")
		}
		lifetime = time.Duration(seconds) * time.Second
		if len(hash) != 64 || lifetime > 12*time.Hour || lifetime < 12*time.Hour-time.Second {
			t.Fatal("invalid session hash or lifetime")
		}
		for _, c := range cookies {
			if c.Value == hash {
				t.Fatal("stored plaintext token")
			}
		}
	})

	t.Run("login_replaces_session_and_csrf", func(t *testing.T) {
		_, _ = migration.Exec(ctx, "DELETE FROM cheesetrap.sessions")
		token, cookies := login(t, h)
		w := request(h, "POST", "/api/v1/auth/login", `{"username":"admin","password":"correct horse battery staple"}`, map[string]string{"Origin": testOrigin, "X-CSRF-Token": token, "Content-Type": "application/json"}, cookies...)
		if w.Code != 200 {
			t.Fatal("replacement login failed")
		}
		if request(h, "GET", "/api/v1/auth/me", "", nil, cookies...).Code != 401 {
			t.Fatal("replaced session still valid")
		}
		if request(h, "GET", "/api/v1/auth/me", "", nil, w.Result().Cookies()...).Code != 200 {
			t.Fatal("replacement session invalid")
		}
	})
	t.Run("idle_expiry_absolute_expiry_and_logout", func(t *testing.T) {
		for _, expiry := range []string{"idle", "absolute", "logout"} {
			_, _ = migration.Exec(ctx, "DELETE FROM cheesetrap.sessions")
			token, cookies := login(t, h)
			if expiry == "idle" {
				if _, err := migration.Exec(ctx, "UPDATE cheesetrap.sessions SET created_at=clock_timestamp()-interval '2 hours',last_seen_at=clock_timestamp()-interval '61 minutes'"); err != nil {
					t.Fatal("idle fixture failed")
				}
			}
			if expiry == "absolute" {
				if _, err := migration.Exec(ctx, "UPDATE cheesetrap.sessions SET created_at=clock_timestamp()-interval '13 hours',last_seen_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour'"); err != nil {
					t.Fatal("absolute fixture failed")
				}
			}
			if expiry == "logout" {
				w := request(h, "POST", "/api/v1/auth/logout", "", map[string]string{"Origin": testOrigin, "X-CSRF-Token": token}, cookies...)
				if w.Code != 200 {
					t.Fatalf("logout status=%d", w.Code)
				}
			}
			for range 2 {
				w := request(h, "GET", "/api/v1/auth/me", "", nil, cookies...)
				if w.Code != 401 {
					t.Fatalf("%s session status=%d", expiry, w.Code)
				}
			}
		}
	})
	t.Run("authentication_touches_and_never_revives_deleted_session", func(t *testing.T) {
		_, _ = migration.Exec(ctx, "DELETE FROM cheesetrap.sessions")
		token, cookies := login(t, h)
		if _, err := migration.Exec(ctx, "UPDATE cheesetrap.sessions SET created_at=clock_timestamp()-interval '30 minutes',last_seen_at=clock_timestamp()-interval '10 minutes'"); err != nil {
			t.Fatal("touch fixture failed")
		}
		if request(h, "GET", "/api/v1/auth/me", "", nil, cookies...).Code != 200 {
			t.Fatal("valid idle session failed")
		}
		var fresh bool
		if pool.QueryRow(ctx, "SELECT last_seen_at>clock_timestamp()-interval '1 minute' FROM cheesetrap.sessions").Scan(&fresh) != nil || !fresh {
			t.Fatal("authentication did not touch session")
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 10 {
				request(h, "GET", "/api/v1/auth/me", "", nil, cookies...)
			}
		}()
		if request(h, "POST", "/api/v1/auth/logout", "", map[string]string{"Origin": testOrigin, "X-CSRF-Token": token}, cookies...).Code != 200 {
			t.Fatal("concurrent logout failed")
		}
		<-done
		if request(h, "GET", "/api/v1/auth/me", "", nil, cookies...).Code != 401 {
			t.Fatal("logout resurrected")
		}
	})
}
func TestEventsPaginationAndFilters(t *testing.T) {
	_, migration, h := apiFixture(t)
	ctx := context.Background()
	sensor := "10000000-0000-4000-8000-000000000501"
	generation := "20000000-0000-4000-8000-000000000501"
	_, err := migration.Exec(ctx, "INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES($1,'api-fixture','cowrie');", sensor)
	if err != nil {
		t.Fatal("sensor fixture failed")
	}
	if _, err := migration.Exec(ctx, "INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES($1,$2,'/test/api',1,1)", generation, sensor); err != nil {
		t.Fatal("generation fixture failed")
	}
	t.Cleanup(func() {
		_, _ = migration.Exec(context.Background(), "DELETE FROM cheesetrap.events WHERE sensor_id=$1", sensor)
		_, _ = migration.Exec(context.Background(), "DELETE FROM cheesetrap.file_generations WHERE sensor_id=$1", sensor)
		_, _ = migration.Exec(context.Background(), "DELETE FROM cheesetrap.sensors WHERE sensor_id=$1", sensor)
	})
	insert := func(seq int64, offset int, isTest bool) {
		t.Helper()
		_, err := migration.Exec(ctx, `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,source_ip,service,event_type,attributes,raw_hash,is_test) VALUES($1,$2,$3,$4,1,'cowrie','192.0.2.205','ssh','api-fixture.test','{"command":"<script>alert(1)</script>","password":"[REDACTED]"}',repeat('a',64),$5)`, sensor, generation, offset, seq, isTest)
		if err != nil {
			t.Fatal("event fixture failed")
		}
	}
	for i := range 3 {
		insert(9223372036854775804+int64(i), i, i == 0)
	}
	_, cookies := login(t, h)
	overview := request(h, "GET", "/api/v1/overview", "", nil, cookies...)
	if overview.Code != 200 || !strings.Contains(overview.Body.String(), "sensors_unknown") {
		t.Fatal("overview missing sensor operation state")
	}
	t.Run("dated_gap_overview_and_status", func(t *testing.T) {
		check := func(want string, cause domain.GapCause) {
			t.Helper()
			response := request(h, "GET", "/api/v1/overview", "", nil, cookies...)
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if string(body["sensors_recent_gaps"]) != `"`+want+`"` {
				t.Fatalf("recent sensor count %s, want %s", body["sensors_recent_gaps"], want)
			}
			var status observability.Status
			if err := json.Unmarshal(body["operations"], &status); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, s := range status.Sensors {
				if s.Name != "api-fixture" {
					continue
				}
				found = true
				if cause == "" {
					if s.LastGap != nil {
						t.Fatal("sensor without incidents has last_gap")
					}
				} else if s.LastGap == nil || len(s.LastGap.Causes) != 1 || s.LastGap.Causes[0] != cause || s.LastGap.ObservedThrough.Before(s.LastGap.StartedAt) {
					t.Fatalf("latest incident lost its range or cause: %+v", s.LastGap)
				}
			}
			if !found {
				t.Fatal("fixture sensor missing from overview")
			}

		}
		check("0", "")
		if _, err := migration.Exec(ctx, `INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes) VALUES($1,clock_timestamp()-interval '3 days',clock_timestamp()-interval '2 days',ARRAY['legacy'])`, sensor); err != nil {
			t.Fatal(err)
		}
		check("0", domain.GapLegacy)
		if _, err := migration.Exec(ctx, `INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes) SELECT $1,clock_timestamp()-interval '1 hour',clock_timestamp(),ARRAY['source_change'] FROM generate_series(1,2)`, sensor); err != nil {
			t.Fatal(err)
		}
		check("1", domain.GapSourceChange)
	})
	get := func(path string) *httptest.ResponseRecorder { return request(h, "GET", path, "", nil, cookies...) }
	w := get("/api/v1/events?event_type=api-fixture.test&detection_result=pending&limit=2")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"detection_result":"pending"`) {
		t.Fatalf("pending result missing: %d %s", w.Code, w.Body.String())
	}
	w = get("/api/v1/events?event_type=api-fixture.test&limit=2")
	if w.Code != 200 {
		t.Fatalf("events status=%d", w.Code)
	}
	var page struct {
		Items []struct {
			ID       string `json:"event_id"`
			Sequence string `json:"ingestion_seq"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 2 || page.Next == "" || page.Items[0].Sequence != "9223372036854775806" {
		t.Fatal("unstable or lossy first page")
	}
	insert(9223372036854775807, 3, false)
	w = get("/api/v1/events?event_type=api-fixture.test&limit=2&cursor=" + page.Next)
	if w.Code != 200 {
		t.Fatal("cursor rejected")
	}
	var second = page
	if json.Unmarshal(w.Body.Bytes(), &second) != nil || len(second.Items) != 1 || second.Items[0].Sequence != "9223372036854775804" || second.Next != "" {
		t.Fatal("cursor skipped/duplicated or included later insertion")
	}
	w = get("/api/v1/events/" + page.Items[0].ID)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `\u003cscript\u003e`) || strings.Contains(w.Body.String(), "raw_log") {
		t.Fatal("event detail unsafe or missing")
	}
	w = get("/api/v1/events?event_type=api-fixture.test&source_ip=192.0.2.205&service=ssh&is_test=true")
	var filtered struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(w.Body.Bytes(), &filtered) != nil || len(filtered.Items) != 1 {
		t.Fatal("event filters ignored")
	}

	w = get("/api/v1/events?event_type=api-fixture.test&is_test=true&since=2000-01-01T00:00:00Z&until=2001-01-01T00:00:00Z")
	if json.Unmarshal(w.Body.Bytes(), &filtered) != nil || len(filtered.Items) != 0 {
		t.Fatal("event time window ignored")
	}
	w = get("/api/v1/events?event_type=api-fixture.test&source_ip=192.0.2.206")
	if json.Unmarshal(w.Body.Bytes(), &filtered) != nil || len(filtered.Items) != 0 {
		t.Fatal("source IP filter ignored")
	}
	// Oversized normalized evidence is omitted before it leaves PostgreSQL.
	if _, err := migration.Exec(ctx, "UPDATE cheesetrap.events SET attributes=jsonb_build_object('command',repeat('x',17000)) WHERE event_id=$1", page.Items[0].ID); err != nil {
		t.Fatal("oversize evidence fixture failed")
	}
	w = get("/api/v1/events/" + page.Items[0].ID)
	if w.Code != 200 || len(w.Body.Bytes()) > 4096 || !strings.Contains(w.Body.String(), `"attributes_truncated":true`) {
		t.Fatal("unbounded event evidence response")
	}
	for _, path := range []string{"/api/v1/events?limit=201", "/api/v1/events?limit=0", "/api/v1/events?cursor=bad", "/api/v1/events?source_ip=invalid", "/api/v1/events?since=invalid", "/api/v1/events/not-a-uuid"} {
		w = get(path)
		if w.Code != 400 && w.Code != 422 {
			t.Errorf("invalid query accepted: status=%d", w.Code)
		}
		assertError(t, w, "")
	}
}

// The local password limit is measured before JSON encoding. Each accepted
// control byte can expand to a six-byte escape in a legitimate HTTP request.
func TestAuthEscapedPassword(t *testing.T) {
	pool, migration, h := apiFixture(t)
	ctx := context.Background()
	if _, err := migration.Exec(ctx, "DELETE FROM cheesetrap.sessions; DELETE FROM cheesetrap.admins"); err != nil {
		t.Fatal("admin fixture cleanup failed")
	}
	password := strings.Repeat("\x01", 1024)
	input, err := os.CreateTemp(t.TempDir(), "admin-input")
	if err != nil {
		t.Fatal("protected input creation failed")
	}
	defer input.Close()
	if _, err := io.WriteString(input, "admin\n"+password+"\n"); err != nil {
		t.Fatal("protected input write failed")
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal("protected input rewind failed")
	}
	username, accepted, err := auth.ReadAdminInput(ctx, input, io.Discard)
	if err != nil || accepted != password {
		t.Fatal("maximum-size local password rejected")
	}
	if err := auth.NewService(pool).CreateAdmin(ctx, username, accepted); err != nil {
		t.Fatal("local administrator creation failed")
	}
	body, err := json.Marshal(map[string]string{"username": username, "password": accepted})
	if err != nil || len(body) <= 4096 || len(body) > 8192 {
		t.Fatal("fixture did not exercise bounded JSON expansion")
	}
	token, cookies := csrf(t, h)
	w := request(h, "POST", "/api/v1/auth/login", string(body), map[string]string{"Origin": testOrigin, "X-CSRF-Token": token, "Content-Type": "application/json"}, cookies...)
	if w.Code != 200 {
		t.Fatalf("accepted maximum-size password login status=%d, want 200", w.Code)
	}
	if request(h, "GET", "/api/v1/auth/me", "", nil, w.Result().Cookies()...).Code != 200 {
		t.Fatal("escaped password did not establish a usable session")
	}
}
