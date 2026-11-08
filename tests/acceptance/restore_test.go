//go:build integration

package acceptance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"
)

func TestRestoreDrafts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	owner, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RESTORE_MIGRATION_URL"))
	must(e)
	defer owner.Close()
	worker, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RESTORE_WORKER_URL"))
	must(e)
	defer worker.Close()
	tx, e := owner.Begin(ctx)
	must(e)
	defer tx.Rollback(ctx)
	r, _, e := reporting.SeedRevisionTx(ctx, tx, nil)
	must(e)
	// Include sealed parts in the physical backup, alongside retained legacy
	// revisions and the mixed detection graph seeded below.
	r, e = reporting.ChangeRevisionTx(ctx, tx, r.ReportID, r.Version, r.RevisionID, reporting.RevisionChanges{}, nil)
	must(e)
	must(tx.Commit(ctx))
	// Docker Desktop shares the checkout, but an independently mounted TMPDIR
	// may not be visible to its VM. Keep this bind-mounted fixture in our
	// ignored private evidence directory and remove only the directory we own.
	fixtureBase, e := filepath.Abs(filepath.Join("..", "..", ".local", "restore"))
	must(e)
	must(os.MkdirAll(fixtureBase, 0700))
	root, e := os.MkdirTemp(fixtureBase, "restore-fixture-")
	must(e)
	t.Cleanup(func() {
		if e := os.RemoveAll(root); e != nil {
			t.Errorf("remove owned restore fixture: %v", e)
		}
	})
	config := filepath.Join(root, "install")
	must(os.MkdirAll(filepath.Join(config, "secrets"), 0700))
	must(os.WriteFile(filepath.Join(config, "install.json"), []byte(`{"installation":"test"}`), 0600))
	must(os.MkdirAll(filepath.Join(config, "config", "web"), 0700))
	must(os.WriteFile(filepath.Join(config, "config", "web", "key.pem"), []byte("canary-secret-never-in-backup"), 0600))
	must(os.WriteFile(filepath.Join(config, "config", "web", "opencanary.conf"), []byte(`{"device.node_id":"test-engine"}`), 0600))
	backup := filepath.Join(root, "backup")
	restored := filepath.Join(root, "restored")
	script := func(name string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "../../scripts/"+name, args...)
		out, e := cmd.CombinedOutput()
		return string(out), e
	}
	evidenceBefore := seedRestoreEvidence(t, ctx, owner, worker, r.ReportID)
	out, e := script("backup.sh", "--container", os.Getenv("CHEESETRAP_TEST_CONTAINER"), "--database", "cheesetrap_restore_test", "--install-root", config, "--output", backup, "--app-version", "7649eb8")
	if e != nil {
		t.Fatalf("backup failed: %s", out)
	}
	name := "cheesetrap-restore-" + strings.ReplaceAll(r.ReportID, "-", "")
	defer exec.Command("docker", "rm", "-f", "-v", name).Run()
	out, e = script("restore-check.sh", "--backup", backup, "--target", name, "--output", restored)
	if e != nil {
		t.Fatalf("restore failed: %s", out)
	}
	url, e := os.ReadFile(filepath.Join(restored, "worker-url"))
	must(e)
	restoredWorker, e := store.NewPool(ctx, strings.TrimSpace(string(url)))
	must(e)
	defer restoredWorker.Close()
	ownerURL, e := os.ReadFile(filepath.Join(restored, "migration-url"))
	must(e)
	restoredOwner, e := store.NewPool(ctx, strings.TrimSpace(string(ownerURL)))
	must(e)
	defer restoredOwner.Close()
	restoredRevision, e := reporting.LoadRevision(ctx, restoredOwner, r.ReportID)
	must(e)
	evidenceCount, ruleCount := restoredRevision.Snapshot.Counts()
	digest, e := reporting.ContentDigest(restoredRevision)
	must(e)
	if restoredRevision.Snapshot.Proof == nil || evidenceCount != 1 || ruleCount != 1 || digest != r.ContentDigest {
		t.Fatal("restored proof manifest or digest changed")
	}
	seen := 0
	must(restoredRevision.Snapshot.EachEvidence(func(_ domain.ReportEvidence) error { seen++; return nil }))
	must(restoredRevision.Snapshot.EachRule(func(_ domain.ReportRule) error { seen++; return nil }))
	if seen != 2 {
		t.Fatal("restored proof parts missing", seen)
	}
	verifyRestoredEvidence(t, ctx, restoredOwner, restoredWorker, evidenceBefore)
	if _, e = restoredWorker.Exec(ctx, `REINDEX TABLE cheesetrap_river.river_job`); e == nil {
		t.Fatal("worker can REINDEX")
	}
	_, e = restoredOwner.Exec(ctx, `REINDEX TABLE CONCURRENTLY cheesetrap_river.river_job`)
	must(e)
	engine, e := os.ReadFile(filepath.Join(restored, "config", "config", "web", "opencanary.conf"))
	must(e)
	if string(engine) != `{"device.node_id":"test-engine"}` {
		t.Fatal("engine config changed")
	}
	// Existing target must remain untouched even with a fresh output path.
	if _, e = script("restore-check.sh", "--backup", backup, "--target", name, "--output", filepath.Join(root, "again")); e == nil {
		t.Fatal("existing restore target accepted")
	}
	if _, e = script("restore-check.sh", "--backup", backup, "--target", "production", "--output", filepath.Join(root, "prod")); e == nil {
		t.Fatal("production target accepted")
	}
	must(filepath.Walk(backup, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if strings.Contains(string(data), "canary-secret-never-in-backup") {
			t.Errorf("secret copied to %s", filepath.Base(path))
		}
		return nil
	}))
	t.Log("draft proof and evidence restored; existing and production targets refused; secrets excluded")
}
