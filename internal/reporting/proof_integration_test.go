//go:build integration

package reporting

import (
	"cheesetrap/internal/domain"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestReportProofRetentionBounded(t *testing.T) {
	ctx := context.Background()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_PROOF_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_PROOF_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	r, _, err := SeedRevisionTx(ctx, tx, func(r *domain.ReportRevision) {
		e, rule := r.Snapshot.Evidence[0], r.Snapshot.Rules[0]
		r.Snapshot.Evidence = nil
		r.Snapshot.Rules = nil
		for i := 0; i < 7; i++ {
			e.EventID = fmt.Sprintf("80000000-0000-4000-8000-%012d", i+1)
			r.Snapshot.Evidence = append(r.Snapshot.Evidence, e)
			r.Snapshot.Rules = append(r.Snapshot.Rules, rule)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	q := db.New(tx)
	if err = copyReportEvidence(ctx, q, uuid(r.ReportID), r.Snapshot.Evidence); err != nil {
		t.Fatal(err)
	}
	r, err = readCurrentRevision(ctx, q, r.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	r.Version = 2
	if err = appendRevision(ctx, q, &r, 1); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.report_proof_parts WHERE report_id=$1`, r.ReportID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	cleanup := func() {
		t.Helper()
		if _, err := worker.Exec(ctx, `SELECT cheesetrap.retention_cleanup($1,2)`, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	cleanup()
	if count() != 14 {
		t.Fatal("active proof was retired")
	}
	age, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer age.Rollback(ctx)
	if _, err = age.Exec(ctx, `ALTER TABLE cheesetrap.reports DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if _, err = age.Exec(ctx, `UPDATE cheesetrap.reports SET state='rejected',last_changed_at=clock_timestamp()-interval '181 days' WHERE report_id=$1`, r.ReportID); err != nil {
		t.Fatal(err)
	}
	if _, err = age.Exec(ctx, `ALTER TABLE cheesetrap.reports ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if err = age.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := count()
	for i := 0; i < 20; i++ {
		cleanup()
		after := count()
		if before-after > 2 {
			t.Fatal("unbounded proof retirement", before, after)
		}
		before = after
		var exists bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.reports WHERE report_id=$1)`, r.ReportID).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			if after != 0 {
				t.Fatal("report removed before proof")
			}
			return
		}
	}
	t.Fatal("terminal report did not drain")
}

func TestReportProofRoundTrip(t *testing.T) {
	ctx := context.Background()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_PROOF_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	r, _, err := SeedRevisionTx(ctx, tx, nil)
	if err != nil {
		t.Fatal("seed", err)
	}
	q := db.New(tx)
	loaded, err := readCurrentRevision(ctx, q, r.ReportID)
	if err != nil {
		t.Fatal("read", err)
	}
	digest, err := ContentDigest(loaded)
	if err != nil || digest != r.ContentDigest {
		t.Fatalf("legacy digest %s want %s: %v", digest, r.ContentDigest, err)
	}
	if err = normalizeLegacyProof(ctx, q, &loaded); err != nil {
		t.Fatal("normalize", err)
	}
	loaded.Version = 2
	if err = appendRevision(ctx, q, &loaded, 1); err != nil {
		t.Fatal("append", err)
	}
	loaded, err = readCurrentRevision(ctx, q, r.ReportID)
	if err != nil {
		t.Fatal("read normalized", err)
	}
	digest, err = ContentDigest(loaded)
	if err != nil || digest != loaded.ContentDigest {
		t.Fatal("normalized digest", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"API", "WORKER"} {
		t.Run(role, func(t *testing.T) {
			seed, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			r, _, err := SeedRevisionTx(ctx, seed, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = seed.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_PROOF_"+role+"_URL"))
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			q := db.New(tx)
			r, err = readCurrentRevision(ctx, q, r.ReportID)
			if err != nil {
				t.Fatal(err)
			}
			if err = normalizeLegacyProof(ctx, q, &r); err != nil {
				t.Fatal("runtime normalize", err)
			}
			r.Version = 2
			if err = appendRevision(ctx, q, &r, 1); err != nil {
				t.Fatal("runtime append", err)
			}
			bad, err := tx.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = bad.Exec(ctx, `INSERT INTO cheesetrap.report_proof_parts(report_id,kind,ordinal,first_item,item_count,payload) VALUES($1,'evidence',1,1,1,convert_to('[{}]','UTF8'))`, r.ReportID); err == nil {
				t.Fatal("sealed proof accepted appended evidence")
			}
			if err = bad.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			loaded, err := readCurrentRevision(ctx, q, r.ReportID)
			if err != nil {
				t.Fatal(err)
			}
			if e, r := loaded.Snapshot.Counts(); e != 1 || r != 1 {
				t.Fatal("manifest count", e, r)
			}
			if digest, err := ContentDigest(loaded); err != nil || digest != loaded.ContentDigest {
				t.Fatal("runtime digest", err)
			}
		})
	}
}
