//go:build integration

package reporting

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store"
)

func TestTemplateRefreshPreservesProof(t *testing.T) {
	ctx := context.Background()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_APPROVAL_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	old, _, err := SeedRevisionTx(ctx, tx, func(r *domain.ReportRevision) {
		r.Body = "Historical excerpt: cowrie.login.failed; SSH-REPEAT v1 settings=v1"
		r.Snapshot.Evidence[0].EventID = "11111111-1111-4111-8111-111111111111"
		r.Snapshot.Evidence[0].Engine = "cowrie"
		r.Snapshot.Evidence[0].Service = "ssh"
		r.Snapshot.Evidence[0].EventType = "cowrie.login.failed"
		r.Snapshot.Rules[0].RuleID = "SSH-REPEAT"
	})
	if err != nil {
		t.Fatal(err)
	}
	var version int64
	if err = tx.QueryRow(ctx, "SELECT version FROM cheesetrap.reports WHERE report_id=$1", old.ReportID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	revised, err := ChangeRevisionTx(ctx, tx, old.ReportID, version, old.RevisionID, RevisionChanges{Recipient: &old.Recipient}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if revised.RevisionID == old.RevisionID || revised.ContentDigest == old.ContentDigest || revised.BodyEdited || !strings.Contains(revised.Body, "SSH authentication failed") || strings.Contains(revised.Body, "cowrie") {
		t.Fatal("template was not regenerated into a new draft revision")
	}
	// The fixture starts with legacy inline arrays. Revision creation may move
	// those arrays to sealed proof parts; compare their complete content.
	var evidence []domain.ReportEvidence
	var rules []domain.ReportRule
	if err = revised.Snapshot.EachEvidence(func(e domain.ReportEvidence) error { evidence = append(evidence, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if err = revised.Snapshot.EachRule(func(r domain.ReportRule) error { rules = append(rules, r); return nil }); err != nil {
		t.Fatal(err)
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	var sameProof bool
	if err = tx.QueryRow(ctx, `SELECT
	(a.snapshot-'evidence'-'rules'-'proof')=(b.snapshot-'evidence'-'rules'-'proof')
	AND a.snapshot->'evidence'=$3::jsonb AND a.snapshot->'rules'=$4::jsonb
	AND a.recipient=b.recipient AND a.reply_to=b.reply_to
	FROM cheesetrap.report_revisions a,cheesetrap.report_revisions b
	WHERE a.revision_id=$1 AND b.revision_id=$2`, old.RevisionID, revised.RevisionID, evidenceJSON, rulesJSON).Scan(&sameProof); err != nil || !sameProof {
		t.Fatal("persisted evidence, rules, registry, or recipient changed", err)
	}
	var oldBody, oldDigest string
	if err = tx.QueryRow(ctx, "SELECT body,content_digest FROM cheesetrap.report_revisions WHERE revision_id=$1", old.RevisionID).Scan(&oldBody, &oldDigest); err != nil {
		t.Fatal(err)
	}
	if oldBody != old.Body || oldDigest != old.ContentDigest {
		t.Fatal("historical revision changed")
	}

	if _, err = ChangeRevisionTx(ctx, tx, old.ReportID, version, old.RevisionID, RevisionChanges{}, nil); !errors.Is(err, ErrRevisionConflict) {
		t.Fatal("stale refresh overwrote the new revision", err)
	}
	// A reviewer-authored body must survive a later template-based contact refresh.
	manual := "Operator-authored statement."
	edited, err := ChangeRevisionTx(ctx, tx, old.ReportID, revised.Version, revised.RevisionID, RevisionChanges{Body: &manual}, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ChangeRevisionTx(ctx, tx, old.ReportID, edited.Version, edited.RevisionID, RevisionChanges{Recipient: &edited.Recipient}, nil)
	if err != nil || again.Body != manual || !again.BodyEdited {
		t.Fatal("manual wording overwritten", err)
	}
}
