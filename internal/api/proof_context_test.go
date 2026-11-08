package api

import (
	"context"
	"testing"
	"time"
)

func TestProofContextKeepsClientCancellation(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	values, stop := context.WithCancel(context.WithValue(parent, identityKey, "actor"))
	stop() // Expiry of the short API budget must not cancel an authenticated proof.
	ctx := proofCommandContext{Context: parent, values: values}
	if ctx.Err() != nil || ctx.Value(identityKey) != "actor" {
		t.Fatal("proof context lost request")
	}
	if got, _ := ctx.Deadline(); !got.Equal(func() time.Time { d, _ := parent.Deadline(); return d }()) {
		t.Fatal("client deadline lost")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("client disconnect ignored")
	}
}
