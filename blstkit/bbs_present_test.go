package blstkit

import "testing"

func TestBbsPresentCredentialRoundTrip(t *testing.T) {
	sk, pk, err := BbsGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := BbsSkToBytes(sk); err != nil {
		t.Fatal(err)
	} else if back, err := BbsSkFromBytes(b); err != nil || back.Cmp(sk) != 0 {
		t.Fatalf("secret scalar round trip: %v", err)
	}
	cap := map[string]any{"issuer": "iss-key", "holder": "sub-key", "caveats": []any{map[string]any{"type": "expires", "at": 5}}}
	cred, err := BbsIssueCapabilityCredential(cap, sk, pk, []byte("hdr"))
	if err != nil {
		t.Fatal(err)
	}
	if !BbsVerifyCredential(cred) {
		t.Fatal("a fresh credential must verify")
	}
	ph := []byte("action-digest")
	pres, err := BbsPresentCredential(cred, []string{"iss", "cav:0:expires"}, ph)
	if err != nil {
		t.Fatal(err)
	}
	if !BbsVerifyPresentation(pres, nil) {
		t.Fatal("the presentation must verify as it stands")
	}
	if !BbsVerifyPresentation(pres, &BbsPresentOptions{PublicKey: pk, PresentationHeader: ph}) {
		t.Fatal("the presentation must verify under the pinned key and header")
	}
	if BbsVerifyPresentation(pres, &BbsPresentOptions{PresentationHeader: []byte("another")}) {
		t.Fatal("a presentation bound to another header must not verify")
	}
	if _, err := BbsPresentCredential(cred, []string{"nope"}, nil); err == nil {
		t.Fatal("an unknown attribute must be refused")
	}
	if _, err := BbsSkFromBytes(make([]byte, 32)); err == nil {
		t.Fatal("a zero scalar must be refused")
	}
}
