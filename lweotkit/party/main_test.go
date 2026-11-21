package main

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// The adapter round trip: what the receiver recovers is exactly the sender's pad at each chosen index.
func TestLweImplRoundTrip(t *testing.T) {
	choices := []int{0, 1, 1, 0, 1}
	var impl lweImpl
	rn, points, rhos, st, err := impl.Receive(choices)
	if err != nil {
		t.Fatal(err)
	}
	cts, pads, err := impl.SendRandom(rn, points, rhos)
	if err != nil {
		t.Fatal(err)
	}
	got, err := impl.RecoverRandom(st, cts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(choices) || len(pads) != len(choices) {
		t.Fatalf("lengths: recovered %d, pads %d, choices %d", len(got), len(pads), len(choices))
	}
	for i, c := range choices {
		if !bytes.Equal(got[i], pads[i][c]) {
			t.Fatalf("transfer %d: recovered pad is not the sender's pad %d", i, c)
		}
		if bytes.Equal(got[i], pads[i][1-c]) {
			t.Fatalf("transfer %d: recovered pad equals the other pad", i)
		}
	}
}

func TestLweImplRejectsForeignState(t *testing.T) {
	if _, err := (lweImpl{}).RecoverRandom("not a receiver state", nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("want os.ErrInvalid, got %v", err)
	}
}

func TestLweImplPropagatesErrors(t *testing.T) {
	_, _, _, st, err := (lweImpl{}).Receive([]int{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (lweImpl{}).RecoverRandom(st, nil); err == nil {
		t.Fatal("a ciphertext count that does not match the transfers must fail")
	}
	if _, _, err := (lweImpl{}).SendRandom(nil, nil, nil); err == nil {
		t.Fatal("a malformed receiver message must fail")
	}
}

// run reaches the shared command: keygen without a directory is a usage error (status 2).
func TestRunUsage(t *testing.T) {
	if got := run([]string{"pca-mpc-party", "keygen"}); got != 2 {
		t.Fatalf("status %d, want 2", got)
	}
}
