//go:build integration

package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestContactCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER", "API", "COLLECTOR"} {
		raw := os.Getenv("CHEESETRAP_TEST_ENRICHMENT_" + role + "_URL")
		if raw == "" {
			t.Fatal("isolated enrichment runner credentials required")
		}
		pool, err := store.NewPool(ctx, raw)
		if err != nil {
			t.Fatal("enrichment database unavailable")
		}
		defer pool.Close()
		pools[role] = pool
	}
	owner, worker := pools["MIGRATION"], pools["WORKER"]
	var count int
	if err := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.enrichment_cache").Scan(&count); err != nil {
		t.Fatal("enrichment cache schema absent")
	}
	if count != 0 {
		t.Fatal("enrichment database must start empty")
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal("cache fixture SQL failed")
		}
	}
	result := func(ip, email string) Result {
		r := held(ip, "")
		r.Method = "rdap"
		r.SourceURL = "https://rdap.db.ripe.net/ip/" + ip
		r.NetworkStart = "8.8.8.0"
		r.NetworkEnd = "8.8.8.255"
		var contacts []Contact
		if email != "" {
			contacts = []Contact{{Email: email, Role: "abuse", Method: r.Method, SourceURL: r.SourceURL, NetworkStart: r.NetworkStart, NetworkEnd: r.NetworkEnd}}
		}
		finalizeContacts(&r, contacts, false)
		return r
	}
	checkEmail := func(r Result, email string) {
		t.Helper()
		if len(r.Candidates) != 1 || r.Candidates[0].Email != email {
			t.Fatalf("wrong cached contact: %+v", r)
		}
	}
	lookup := func(s *Service, ip string) Result {
		t.Helper()
		r, err := s.Lookup(ctx, ip)
		if err != nil {
			t.Fatalf("lookup failed: %v", err)
		}
		return r
	}
	t.Run("expiry_failure_ambiguity_and_changed_contact", func(t *testing.T) {
		for n, kind := range []string{"success", "missing", "ambiguous", "failure", "rate_limit"} {
			t.Run(kind, func(t *testing.T) {
				ip := fmt.Sprintf("8.8.8.%d", n+1)
				var calls atomic.Int32
				s := NewService(worker)
				s.lookup = func(_ context.Context, ip string) (Result, error) {
					calls.Add(1)
					r := result(ip, "one@example.net")
					switch kind {
					case "missing":
						r = result(ip, "")
					case "ambiguous":
						c := r.Candidates[0]
						c.Email = "two@example.net"
						finalizeContacts(&r, append(r.Candidates, c), false)
					case "failure":
						r = held(ip, "registry_unavailable")
					case "rate_limit":
						r = held(ip, "rate_limited")
						r.RetryAfter = r.QueriedAt.Add(2 * time.Hour)
						r.ExpiresAt = r.RetryAfter
					}
					return r, nil
				}
				first := lookup(s, ip)
				ttl := 24 * time.Hour
				if kind == "failure" {
					ttl = time.Hour
				}
				if kind == "rate_limit" {
					ttl = 2 * time.Hour
				}
				if kind == "rate_limit" && !first.ExpiresAt.Equal(first.RetryAfter) {
					t.Fatal("Retry-After not preserved exactly")
				}
				if (kind != "rate_limit" && first.ExpiresAt.Sub(first.QueriedAt) != ttl) || (kind == "rate_limit" && (first.ExpiresAt.Sub(first.QueriedAt) < ttl || first.ExpiresAt.Sub(first.QueriedAt) > ttl+time.Second)) {
					t.Fatalf("wrong TTL %s", first.ExpiresAt.Sub(first.QueriedAt))
				}
				other := NewService(worker)
				other.lookup = func(context.Context, string) (Result, error) {
					t.Error("cache hit performed network lookup")
					return Result{}, errors.New("unexpected lookup")
				}
				cached := lookup(other, "::ffff:"+ip)
				a, _ := json.Marshal(first)
				b, _ := json.Marshal(cached)
				if string(a) != string(b) || calls.Load() != 1 {
					t.Fatal("result or provenance changed on canonical cache hit")
				}
				var stored []byte
				var expires time.Time
				if err := owner.QueryRow(ctx, "SELECT result,expires_at FROM cheesetrap.enrichment_cache WHERE address=$1", ip).Scan(&stored, &expires); err != nil {
					t.Fatal(err)
				}
				var persisted Result
				if json.Unmarshal(stored, &persisted) != nil || persisted.SchemaVersion != 1 || !expires.Equal(first.ExpiresAt.Truncate(time.Microsecond)) {
					t.Fatal("versioned result/expiry not persisted")
				}
				exec("UPDATE cheesetrap.enrichment_cache SET queried_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 second' WHERE address=$1", ip)
				other.lookup = func(_ context.Context, ip string) (Result, error) {
					calls.Add(1)
					return result(ip, "changed@example.net"), nil
				}
				refreshed := lookup(other, ip)
				checkEmail(refreshed, "changed@example.net")
				if calls.Load() != 2 {
					t.Fatal("expired entry was not refreshed once")
				}
				checkEmail(lookup(s, ip), "changed@example.net")
			})
		}
	})
	t.Run("service_instances_coalesce_without_transaction_during_IO", func(t *testing.T) {
		ip := "8.8.8.20"
		started := make(chan struct{})
		release := make(chan struct{})
		var calls atomic.Int32
		hook := func(_ context.Context, ip string) (Result, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			<-release
			return result(ip, "shared@example.net"), nil
		}
		first := NewService(worker)
		first.lookup = hook
		results := make(chan Result, 16)
		errs := make(chan error, 16)
		go func() { r, e := first.Lookup(ctx, ip); results <- r; errs <- e }()
		<-started
		var wg sync.WaitGroup
		for range 15 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := NewService(worker)
				s.lookup = hook
				r, e := s.Lookup(ctx, ip)
				results <- r
				errs <- e
			}()
		}
		// A row lock held across registry I/O would block this independent writer.
		updateCtx, stop := context.WithTimeout(ctx, time.Second)
		_, err := owner.Exec(updateCtx, "UPDATE cheesetrap.enrichment_cache SET address=address WHERE address=$1", ip)
		stop()
		close(release)
		wg.Wait()
		if err != nil {
			t.Fatal("database transaction/row lock held during network I/O")
		}
		for range 16 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
			checkEmail(<-results, "shared@example.net")
		}
		if calls.Load() != 1 {
			t.Fatalf("concurrent service lookups=%d", calls.Load())
		}
	})
	t.Run("cancelled_leader_releases_claim", func(t *testing.T) {
		ip := "8.8.8.21"
		started := make(chan struct{})
		s := NewService(worker)
		s.lookup = func(c context.Context, _ string) (Result, error) {
			close(started)
			<-c.Done()
			return Result{}, c.Err()
		}
		c, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { _, err := s.Lookup(c, ip); done <- err }()
		<-started
		stop()
		if !errors.Is(<-done, context.Canceled) {
			t.Fatal("leader cancellation not propagated")
		}
		next := NewService(worker)
		next.lookup = func(_ context.Context, ip string) (Result, error) { return result(ip, "recovered@example.net"), nil }
		recoveryCtx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		r, err := next.Lookup(recoveryCtx, ip)
		if err != nil {
			t.Fatal("cancelled leader did not release claim")
		}
		checkEmail(r, "recovered@example.net")
	})
	t.Run("stale_owner_cannot_overwrite_new_result", func(t *testing.T) {
		ip := "8.8.8.22"
		started := make(chan struct{})
		release := make(chan struct{})
		old := NewService(worker)
		old.lookup = func(_ context.Context, ip string) (Result, error) {
			close(started)
			<-release
			return result(ip, "stale@example.net"), nil
		}
		done := make(chan Result, 1)
		errs := make(chan error, 1)
		go func() { r, e := old.Lookup(ctx, ip); done <- r; errs <- e }()
		<-started
		exec("UPDATE cheesetrap.enrichment_cache SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE address=$1", ip)
		next := NewService(worker)
		next.lookup = func(_ context.Context, ip string) (Result, error) { return result(ip, "new@example.net"), nil }
		fresh := lookup(next, ip)
		close(release)
		checkEmail(fresh, "new@example.net")
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		checkEmail(<-done, "new@example.net")
		checkEmail(lookup(next, ip), "new@example.net")
	})
	t.Run("abandoned_claim_expires", func(t *testing.T) {
		ip := "8.8.8.23"
		exec("INSERT INTO cheesetrap.enrichment_cache(address,lease_token,lease_expires_at) VALUES($1,gen_random_uuid(),clock_timestamp()+interval '50 milliseconds')", ip)
		s := NewService(worker)
		s.lookup = func(_ context.Context, ip string) (Result, error) { return result(ip, "recovered@example.net"), nil }
		checkEmail(lookup(s, ip), "recovered@example.net")
	})
	t.Run("completion_failure_is_atomic_and_recoverable", func(t *testing.T) {
		ip := "8.8.8.24"
		s := NewService(worker)
		s.lookup = func(_ context.Context, ip string) (Result, error) { return result(ip, "original@example.net"), nil }
		lookup(s, ip)
		exec("UPDATE cheesetrap.enrichment_cache SET queried_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 second' WHERE address=$1", ip)
		exec(`CREATE FUNCTION cheesetrap.test_cache_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result IS DISTINCT FROM OLD.result THEN RAISE EXCEPTION 'injected write failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_cache_failure BEFORE UPDATE ON cheesetrap.enrichment_cache FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_cache_failure()`)
		defer owner.Exec(context.Background(), "DROP TRIGGER IF EXISTS test_cache_failure ON cheesetrap.enrichment_cache; DROP FUNCTION IF EXISTS cheesetrap.test_cache_failure()")
		s.lookup = func(_ context.Context, ip string) (Result, error) { return result(ip, "changed@example.net"), nil }
		if _, err := s.Lookup(ctx, ip); err == nil {
			t.Fatal("completion failure hidden")
		}
		var email string
		var released bool
		if err := owner.QueryRow(ctx, "SELECT result->'candidates'->0->>'email',lease_token IS NULL FROM cheesetrap.enrichment_cache WHERE address=$1", ip).Scan(&email, &released); err != nil || email != "original@example.net" || !released {
			t.Fatal("failed completion damaged previous result or stranded claim")
		}
		exec("DROP TRIGGER test_cache_failure ON cheesetrap.enrichment_cache; DROP FUNCTION cheesetrap.test_cache_failure()")
		checkEmail(lookup(s, ip), "changed@example.net")
	})
	t.Run("lease_wait_obeys_caller_budget", func(t *testing.T) {
		ip := "8.8.8.25"
		exec("INSERT INTO cheesetrap.enrichment_cache(address,lease_token,lease_expires_at) VALUES($1,gen_random_uuid(),clock_timestamp()+interval '1 minute')", ip)
		s := NewService(worker)
		s.lookup = func(context.Context, string) (Result, error) {
			t.Error("unexpired claim bypassed")
			return Result{}, nil
		}
		short, stop := context.WithTimeout(ctx, 60*time.Millisecond)
		defer stop()
		if _, err := s.Lookup(short, ip); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("claim wait ignored caller cancellation: %v", err)
		}
	})
	t.Run("roles_and_address_constraints", func(t *testing.T) {
		for _, role := range []string{"API", "WORKER"} {
			if _, err := pools[role].Exec(ctx, "SELECT address,result FROM cheesetrap.enrichment_cache"); err != nil {
				t.Fatal("authorized cache read denied")
			}
		}
		for _, tc := range []struct{ role, sql string }{
			{"COLLECTOR", "SELECT * FROM cheesetrap.enrichment_cache"},
			{"API", "UPDATE cheesetrap.enrichment_cache SET result=NULL"},
			{"API", "INSERT INTO cheesetrap.enrichment_cache(address) VALUES('8.8.4.4')"},
			{"WORKER", "DELETE FROM cheesetrap.enrichment_cache"},
			{"WORKER", "TRUNCATE cheesetrap.enrichment_cache"},
		} {
			if _, err := pools[tc.role].Exec(ctx, tc.sql); err == nil {
				t.Fatalf("forbidden %s cache operation allowed", tc.role)
			}
		}
		for i, body := range []string{`{}`, `{"schema_version":null}`, `{"schema_version":"1"}`, `{"schema_version":2}`, `[]`} {
			if _, err := worker.Exec(ctx, "INSERT INTO cheesetrap.enrichment_cache(address,result,queried_at,expires_at) VALUES($1,$2,clock_timestamp(),clock_timestamp()+interval '1 hour')", fmt.Sprintf("8.8.4.%d", i+1), body); err == nil {
				t.Errorf("invalid result schema accepted: %s", body)
			}
		}
		for _, ip := range []string{"8.8.8.0/24", "::ffff:8.8.4.4"} {
			if _, err := worker.Exec(ctx, "INSERT INTO cheesetrap.enrichment_cache(address) VALUES($1)", ip); err == nil {
				t.Fatal("noncanonical cache key accepted")
			}
		}
	})
}

func TestContactManualRefresh(t *testing.T) {
	ctx := context.Background()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_ENRICHMENT_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_ENRICHMENT_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	const ip = "8.8.4.4"
	defer owner.Exec(ctx, `DELETE FROM cheesetrap.enrichment_cache WHERE address=$1`, ip)
	svc := NewService(worker)
	var calls atomic.Int32
	svc.lookup = func(ctx context.Context, address string) (Result, error) {
		calls.Add(1)
		return Result{SchemaVersion: 1, Address: address, LookupSucceeded: true}, nil
	}
	r, err := svc.Lookup(ctx, ip)
	if err != nil || calls.Load() != 1 {
		t.Fatal("initial fixture failed", err)
	}
	var requested time.Time
	if err = owner.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&requested); err != nil {
		t.Fatal(err)
	}
	type refresher interface {
		Refresh(context.Context, string, time.Time) (Result, error)
	}
	fresh, ok := any(svc).(refresher)
	if !ok {
		t.Fatal("manual refresh cannot bypass a still-fresh positive cache")
	}
	r, err = fresh.Refresh(ctx, ip, requested)
	if err != nil || calls.Load() != 2 || r.QueriedAt.Before(requested) {
		t.Fatal("manual refresh reused stale positive cache", err, calls.Load())
	}
	_, err = fresh.Refresh(ctx, ip, requested)
	if err != nil || calls.Load() != 2 {
		t.Fatal("same request repeated external lookup", err)
	}
	negative := held(ip, "rate_limited")
	negative.QueriedAt = time.Now().Add(-time.Minute)
	negative.RetryAfter = time.Now().Add(2 * time.Hour)
	negative.ExpiresAt = negative.RetryAfter
	data, _ := json.Marshal(negative)
	if _, err = owner.Exec(ctx, `UPDATE cheesetrap.enrichment_cache SET result=$1,queried_at=$2,expires_at=$3 WHERE address=$4`, data, negative.QueriedAt, negative.ExpiresAt, ip); err != nil {
		t.Fatal(err)
	}
	r, err = fresh.Refresh(ctx, ip, time.Now())
	if err != nil || calls.Load() != 2 || r.HeldReason != "rate_limited" {
		t.Fatal("manual refresh bypassed negative Retry-After", err)
	}
}
