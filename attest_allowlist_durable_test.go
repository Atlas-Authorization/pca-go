package pca

import (
	"strings"
	"testing"
)

func TestVerifyAllowlistDurableKeepsTheHighWaterMark(t *testing.T) {
	ed, _ := KeyPairFromSeedB64u(b64.EncodeToString(fill(32, 2)))
	mk := func(version int64, label string) map[string]any {
		body := map[string]any{"version": version, "issuedAt": int64(10), "notBefore": int64(10), "expiresAt": int64(1000), "entries": []any{
			map[string]any{"kind": "tdx-mrtd", "value": strings.Repeat("ab", 48), "label": label},
		}}
		man, err := SignAllowlistManifest(body, "op", "ed25519", ed, nil)
		if err != nil {
			t.Fatal(err)
		}
		return man
	}
	opts := VerifyAllowlistOptions{IssuerKeys: map[string]AllowlistIssuerKey{"op": {Alg: "ed25519", EdPub: ed.Public}}, NowMs: 100}
	kv := CreateMemoryDurableKv()
	if r := VerifyAllowlistDurable(mk(3, "a"), opts, kv); !r.OK || r.Version != 3 {
		t.Fatalf("first: %+v", r)
	}
	if r := VerifyAllowlistDurable(mk(3, "a"), opts, kv); !r.OK {
		t.Fatalf("the same manifest again: %+v", r)
	}
	if r := VerifyAllowlistDurable(mk(3, "b"), opts, kv); r.OK || r.Code != "conflict" {
		t.Fatalf("same version, other body: %+v", r)
	}
	if r := VerifyAllowlistDurable(mk(5, "a"), opts, kv); !r.OK {
		t.Fatalf("newer: %+v", r)
	}
	if r := VerifyAllowlistDurable(mk(4, "a"), opts, kv); r.OK || r.Code != "rollback" {
		t.Fatalf("older than the mark: %+v", r)
	}
	if err := kv.Set("allowlist/op", map[string]any{"version": "5"}); err != nil {
		t.Fatal(err)
	}
	if r := VerifyAllowlistDurable(mk(6, "a"), opts, kv); r.OK || r.Code != "malformed" {
		t.Fatalf("corrupt mark: %+v", r)
	}
	if r := VerifyAllowlistDurable(map[string]any{"issuer": 1}, opts, kv); r.OK || r.Code != "malformed" {
		t.Fatalf("no issuer: %+v", r)
	}
}

func TestDurableMaaKeyStateStoreIsMonotone(t *testing.T) {
	kv := CreateMemoryDurableKv()
	s := DurableMaaKeyStateStore(kv)
	iss := "https://x.attest.azure.net"
	rec := MaaAnchorRecord{Spki: strings.Repeat("a", 64), Kind: "self-signed", NotBeforeMs: 1, NotAfterMs: 9, FirstSeenMs: 2}
	if err := s.Set(iss, MaaKeyState{V: 1, Issuer: iss, FetchedAtMs: 20, Anchors: []MaaAnchorRecord{rec}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(iss, MaaKeyState{V: 1, Issuer: iss, FetchedAtMs: 10, Anchors: nil}); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.Get(iss)
	st := parseMaaKeyState(v, iss)
	if err != nil || !ok || st == nil || st.FetchedAtMs != 20 || len(st.Anchors) != 1 {
		t.Fatalf("a stale writer moved the state back: %v %v %+v", ok, err, st)
	}
	if _, ok, _ := s.Get("other"); ok {
		t.Fatal("unknown issuer")
	}
}
