package pca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

// Mutation-kill tests for threshold.go (scoped run after R6-02/03/04) and the lenient depth safety cap.

func b64n(n int) string { return b64.EncodeToString(bytes.Repeat([]byte{7}, n)) }

func edKey(label string) (ed25519.PrivateKey, string) {
	s := sha256.Sum256([]byte(label))
	k := ed25519.NewKeyFromSeed(s[:])
	return k, b64.EncodeToString(k.Public().(ed25519.PublicKey))
}

// signedShare builds a valid ed25519 share for `role` over an ed25519-only signer set (t = 1).
func signedShare(t *testing.T, role string, tm []byte) (map[string]any, ed25519.PrivateKey) {
	t.Helper()
	ka, pa := edKey("mut-agent")
	_, pg := edKey("mut-guardian")
	_, pp := edKey("mut-principal")
	set := []any{
		map[string]any{"role": "agent", "publicKey": pa},
		map[string]any{"role": "guardian", "publicKey": pg},
		map[string]any{"role": "principal", "publicKey": pp},
	}
	ssh, ok := SignerSetHash(set)
	if !ok {
		t.Fatal("signer set hash")
	}
	var msg bytes.Buffer
	msg.WriteString(shareDomainPrefix + role + "\x00")
	msg.Write(sha(tm))
	msg.Write(ssh)
	msg.WriteByte(1)
	e := map[string]any{
		"role": role, "t": json.Number("1"), "signer_set": set, "threshold_message": b64.EncodeToString(tm),
		"share": map[string]any{"role": role, "publicKey": pa, "sig": b64.EncodeToString(ed25519.Sign(ka, msg.Bytes()))},
	}
	if !VerifyThresholdShare(e) {
		t.Fatal("baseline share does not verify")
	}
	return e, ka
}

func TestMutShareRoleMustEqualRole(t *testing.T) {
	e, _ := signedShare(t, "agent", []byte("m"))
	e["share"].(map[string]any)["role"] = "guardian" // the signature is still valid for role "agent"
	if VerifyThresholdShare(e) {
		t.Fatal("share.role != role accepted")
	}
}

func TestMutThresholdMessageMustBeAString(t *testing.T) {
	e, _ := signedShare(t, "agent", []byte{}) // signed over the EMPTY threshold message
	for _, bad := range []any{5, nil, []any{}, true} {
		e["threshold_message"] = bad // a non-string must not read as ""
		if VerifyThresholdShare(e) {
			t.Fatalf("non-string threshold_message %v accepted", bad)
		}
	}
	e["threshold_message"] = ""
	if !VerifyThresholdShare(e) {
		t.Fatal("empty-string threshold_message (what was signed) refused")
	}
}

func TestMutThresholdT(t *testing.T) {
	for _, c := range []struct {
		v  any
		ok bool
		b  byte
	}{
		{json.Number("1"), true, 1}, {json.Number("3"), true, 3}, {json.Number("1.5"), false, 0}, {json.Number("1e0"), false, 0},
		{json.Number("4"), false, 0}, {2.0, true, 2}, {0.0, false, 0}, {3, true, 3}, {int64(2), true, 2}, {int64(9), false, 0},
		{"1", false, 0}, {nil, false, 0}, {true, false, 0},
	} {
		b, ok := thresholdT(c.v)
		if ok != c.ok || (ok && b != c.b) {
			t.Fatalf("thresholdT(%#v) = %d,%v want %d,%v", c.v, b, ok, c.b, c.ok)
		}
	}
}

func TestMutValidateSignerSetEveryRefusal(t *testing.T) {
	_, pa := edKey("mut-agent")
	_, pg := edKey("mut-guardian")
	ok := func(set []any) bool { _, v := validateSignerSet(set); return v }
	a := func(extra map[string]any) map[string]any {
		m := map[string]any{"role": "agent", "publicKey": pa}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if !ok([]any{a(nil), map[string]any{"role": "guardian", "publicKey": pg}}) {
		t.Fatal("valid set refused")
	}
	for name, set := range map[string][]any{
		"non-object":        {5},
		"role-number":       {map[string]any{"role": 5, "publicKey": pa}},
		"role-unknown":      {map[string]any{"role": "Agent", "publicKey": pa}},
		"pk-number":         {map[string]any{"role": "agent", "publicKey": 5}},
		"pk-short":          {map[string]any{"role": "agent", "publicKey": b64n(31)}},
		"pq-number":         {a(map[string]any{"pq_pk": 5})},
		"pq-null":           {a(map[string]any{"pq_pk": nil})},
		"pq-bad-length":     {a(map[string]any{"pq_pk": b64n(1951)})},
		"pq-noncanonical":   {a(map[string]any{"pq_pk": "AB"})},
		"two-keys-one-role": {a(nil), map[string]any{"role": "agent", "publicKey": pg}},
		"conflicting-pq":    {a(map[string]any{"pq_pk": b64n(1952)}), a(map[string]any{"pq_pk": b64n(2592)})},
		"one-key-two-roles": {a(nil), map[string]any{"role": "guardian", "publicKey": pa}},
	} {
		if reg, v := validateSignerSet(set); v || reg != nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// every registered PQ key length (any suite) validates; its neighbours do not
	for _, n := range []int{1952, 2592, 32, 64, 897, 1793, 97484} {
		if !ok([]any{a(map[string]any{"pq_pk": b64n(n)})}) {
			t.Fatalf("pq_pk of %d bytes refused", n)
		}
		for _, m := range []int{n - 1, n + 1} {
			if pqPkLengths[m] {
				continue
			}
			if ok([]any{a(map[string]any{"pq_pk": b64n(m)})}) {
				t.Fatalf("pq_pk of %d bytes accepted", m)
			}
		}
	}
	// identical duplicate accepted; registration kept
	reg, v := validateSignerSet([]any{a(map[string]any{"pq_pk": b64n(32)}), a(map[string]any{"pq_pk": b64n(32)})})
	if !v || !reg["agent"].hasPq || reg["agent"].pq != b64n(32) {
		t.Fatalf("identical duplicate: %v %v", reg, v)
	}
}

func TestMutSignerSetHashRefusalsAndOrder(t *testing.T) {
	for name, set := range map[string][]any{
		"non-object":  {5},
		"role-number": {map[string]any{"role": 5, "publicKey": "k"}},
		"pk-number":   {map[string]any{"role": "agent", "publicKey": 5}},
		"lone-surrogate-role": {map[string]any{"role": "\xed\xa0\x80", "publicKey": "k"}},
	} {
		if h, ok := SignerSetHash(set); ok || h != nil {
			t.Fatalf("%s: hashed", name)
		}
	}
	hashOf := func(rows ...map[string]any) string {
		arr := make([]any, len(rows))
		for i, r := range rows {
			arr[i] = r
		}
		c, err := Canonicalize(arr)
		if err != nil {
			t.Fatal(err)
		}
		return b64.EncodeToString(sha(append([]byte(signersetDomain), c...)))
	}
	got := func(set []any) string {
		h, ok := SignerSetHash(set)
		if !ok {
			t.Fatal("hash refused")
		}
		return b64.EncodeToString(h)
	}
	// same role: ordered by publicKey; different roles: by role; equal (role, key): input order kept (stable)
	r1 := map[string]any{"role": "agent", "publicKey": "b"}
	r2 := map[string]any{"role": "agent", "publicKey": "a"}
	if got([]any{r1, r2}) != hashOf(r2, r1) {
		t.Fatal("same role not ordered by publicKey")
	}
	g := map[string]any{"role": "guardian", "publicKey": "a"}
	if got([]any{g, r1}) != hashOf(r1, g) {
		t.Fatal("roles not ordered")
	}
	p1 := map[string]any{"role": "agent", "publicKey": "k", "pq_pk": "x"}
	p2 := map[string]any{"role": "agent", "publicKey": "k", "pq_pk": "y"}
	if got([]any{p2, p1}) != hashOf(p2, p1) || got([]any{p1, p2}) != hashOf(p1, p2) {
		t.Fatal("equal (role, key) rows reordered")
	}
}

// The lenient fixture loader's safety cap is exactly 131072 (1 << 17), for arrays and objects alike.
func TestMutLenientDepthExactCap(t *testing.T) {
	for _, c := range []struct {
		n  int
		ok bool
	}{{131072, true}, {131073, false}} {
		arr := strings.Repeat("[", c.n) + strings.Repeat("]", c.n)
		if _, err := ParseJSONLenient([]byte(arr)); (err == nil) != c.ok {
			t.Fatalf("array depth %d: %v", c.n, err)
		}
		obj := strings.Repeat(`{"a":`, c.n-1) + "{}" + strings.Repeat("}", c.n-1)
		if _, err := ParseJSONLenient([]byte(obj)); (err == nil) != c.ok {
			t.Fatalf("object depth %d: %v", c.n, err)
		}
	}
}
