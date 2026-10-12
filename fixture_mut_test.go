package pca

// Self-contained signing fixture for mutation-kill tests: builds capability chains, Merkle plans and signed PCActns
// from fresh Ed25519 keys, following the normative wire (cap body digest, SIG_DOMAIN message, RFC-6962 plan).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
)

type fxKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func newKey(t *testing.T) fxKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fxKey{pub, priv, b64.EncodeToString(pub)}
}

func jnum(n int64) json.Number { return json.Number(fmt.Sprint(n)) }

// mkCap builds and signs a capability. parent=="" means root.
func mkCap(t *testing.T, issuer fxKey, holder string, caveats []any, parent string, extra map[string]any) map[string]any {
	t.Helper()
	c := map[string]any{"issuer": issuer.id, "holder": holder, "caveats": caveats}
	if parent != "" {
		c["parent"] = parent
	}
	for k, v := range extra {
		c[k] = v
	}
	body, ok := signableHopBody(c)
	if !ok {
		t.Fatal("body")
	}
	d, err := HashCanonical(body)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := capSigMessage(d)
	c["id"], c["body_digest"] = d, d
	c["sig"] = b64.EncodeToString(ed25519.Sign(issuer.priv, msg))
	return c
}

// mkChain makes an n-hop chain root->...->leaf and returns the keys (keys[i] is the holder of hop i-1 / issuer of hop i).
func mkChain(t *testing.T, n int, caveatsPerHop func(i int) []any) ([]any, []fxKey) {
	t.Helper()
	keys := make([]fxKey, n+1)
	for i := range keys {
		keys[i] = newKey(t)
	}
	var chain []any
	parent := ""
	for i := 0; i < n; i++ {
		var cv []any
		if caveatsPerHop != nil {
			cv = caveatsPerHop(i)
		}
		if cv == nil {
			cv = []any{}
		}
		c := mkCap(t, keys[i], keys[i+1].id, cv, parent, nil)
		chain = append(chain, c)
		h, _ := CapHash(c)
		parent = h
	}
	return chain, keys
}

func deep(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := StrictParse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func deepM(t *testing.T, v map[string]any) map[string]any { return deep(t, v).(map[string]any) }

// treeProof returns the RFC-6962 audit path (leaf -> root) computed independently of pathShape.
func treeProof(hs [][]byte, m int) ([]string, [][]byte) {
	n := len(hs)
	if n == 1 {
		return nil, nil
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	if m < k {
		s, h := treeProof(hs[:k], m)
		return append(s, "R"), append(h, rootOf(hs[k:]))
	}
	s, h := treeProof(hs[k:], m-k)
	return append(s, "L"), append(h, rootOf(hs[:k]))
}

func rootOf(hs [][]byte) []byte {
	if len(hs) == 1 {
		return hs[0]
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	return nodeHash(rootOf(hs[:k]), rootOf(hs[k:]))
}

func leafHashes(t *testing.T, leaves []any) [][]byte {
	hs := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := leafHash(l)
		if err != nil {
			t.Fatal(err)
		}
		hs[i] = h
	}
	return hs
}

func proofMap(sides []string, hashes [][]byte, idx, size int) map[string]any {
	path := make([]any, len(sides))
	for i := range sides {
		path[i] = map[string]any{"side": sides[i], "hash": b64.EncodeToString(hashes[i])}
	}
	return map[string]any{"index": jnum(int64(idx)), "size": jnum(int64(size)), "path": path}
}

type fx struct {
	t      *testing.T
	chain  []any
	keys   []fxKey
	grant  map[string]any
	p      map[string]any
	now    int64
	aud    string
	hasCnd bool
}

// newFx builds a valid 3-hop PCActn (audience "rs-1", now = iat+1000).
func newFx(t *testing.T) *fx {
	chain, keys := mkChain(t, 3, func(i int) []any {
		out := []any{}
		for j := 0; j <= i; j++ {
			out = append(out, map[string]any{"type": "c", "n": jnum(int64(j))})
		}
		return out
	})
	f := &fx{t: t, chain: chain, keys: keys, aud: "rs-1", now: 1_700_000_001_000}
	f.grant = chain[0].(map[string]any)
	action := map[string]any{"verb": "pay", "resource": "acct:1", "params_digest": b64.EncodeToString(sha([]byte("p"))), "reversibility_class": "reversible"}
	cond := b64.EncodeToString(sha([]byte("cond")))
	f.hasCnd = true
	leaves := make([]any, 5)
	for i := range leaves {
		l, _ := planLeaf(fmt.Sprintf("n%d", i), action, cond)
		leaves[i] = l
	}
	hs := leafHashes(t, leaves)
	sides, sib := treeProof(hs, 2)
	root, _ := MerkleRoot(leaves)
	f.p = map[string]any{
		"ver": jnum(2), "action": action, "grant_ref": f.grant["id"], "cap_chain": chain,
		"plan":        map[string]any{"root": root, "node_id": "n2", "conditions_digest": cond, "inclusion_proof": proofMap(sides, sib, 2, 5)},
		"attestation": map[string]any{"epoch": jnum(1), "quote_digest": "q", "model_id": "m", "measurement": "x", "operator": "o"},
		"provenance":  map[string]any{"causal_hash": "h", "taint_level": jnum(0), "trusted_refs": []any{"r"}},
		"freshness":   map[string]any{"beacon_ref": "b", "accumulator_witness": "w", "epoch": jnum(1)},
		"counter":     jnum(0), "risk_claim": map[string]any{"r": json.Number("0.5"), "inputs": map[string]any{}},
		"aud": f.aud, "iat": jnum(1_700_000_000_000), "exp": jnum(1_700_000_600_000),
	}
	f.resign()
	return f
}

// resign recomputes the leaf signature under the final hop's holder key.
func (f *fx) resign() {
	f.t.Helper()
	msg, err := ThresholdMessage(f.p)
	if err != nil {
		f.t.Fatal(err)
	}
	f.p["sig"] = b64.EncodeToString(ed25519.Sign(f.keys[len(f.keys)-1].priv, msg))
}

// norm round-trips through strict JSON so numbers are json.Number as the verifier sees them.
func (f *fx) norm() map[string]any { return deepM(f.t, f.p) }

func (f *fx) verify(allowed []string) Verdict {
	f.t.Helper()
	v, err := VerifyPCActnCorePolicy(f.norm(), f.grant, f.now, f.aud, allowed)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}
