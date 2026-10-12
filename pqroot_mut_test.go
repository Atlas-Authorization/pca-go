package pca

// Mutation-kill tests for the PQ key choke point (resolvePqVerifyKey), root PQ authority (pqPins / trustedRoot,
// R4-01) and real ML-DSA-65 / hybrid hops and leaves.

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type pqKey struct {
	pk  *mldsa65.PublicKey
	sk  *mldsa65.PrivateKey
	b64 string
}

func newPq(t *testing.T) pqKey {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pk.MarshalBinary()
	return pqKey{pk, sk, b64.EncodeToString(b)}
}

func (k pqKey) sign(t *testing.T, msg []byte) string {
	t.Helper()
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.sk, msg, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(sig)
}

// mkPqCap builds a capability signed under alg ("ml-dsa-65" or "hybrid-ed25519-ml-dsa-65").
func mkPqCap(t *testing.T, alg string, issuer fxKey, pq pqKey, holder string, caveats []any, parent string, extra map[string]any) map[string]any {
	t.Helper()
	c := map[string]any{"issuer": issuer.id, "holder": holder, "caveats": caveats, "alg": alg, "pq_pk": pq.b64}
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
	d, _ := HashCanonical(body)
	msg, _ := capSigMessage(d)
	c["id"], c["body_digest"] = d, d
	if alg == "ml-dsa-65" {
		c["sig"] = pq.sign(t, msg)
	} else {
		c["sig"] = b64.EncodeToString(ed25519.Sign(issuer.priv, msg))
		c["pq_sig"] = pq.sign(t, msg)
	}
	return c
}

func TestMutResolvePqVerifyKey(t *testing.T) {
	pk := "PKSTR"
	commit := holderPqCommitment(pk)
	// suites without a PQ key: zero key, true, regardless of authority
	for _, c := range []struct {
		alg     any
		present bool
	}{{nil, false}, {"ed25519", true}, {"unknown", true}, {5, true}} {
		k, ok := resolvePqVerifyKey(c.alg, c.present, pk, pqAuthority{})
		if !ok || k.pk != nil {
			t.Fatalf("%v: %v %v", c.alg, k, ok)
		}
	}
	type tc struct {
		name string
		pk   any
		auth pqAuthority
		ok   bool
	}
	for _, alg := range []string{"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"} {
		for _, c := range []tc{
			{"non-string artifact pk", 5, pqAuthority{holderPq: commit, hasHolderPq: true}, false},
			{"nil artifact pk", nil, pqAuthority{trustedPk: pk, hasTrusted: true}, false},
			{"trusted equal", pk, pqAuthority{trustedPk: pk, hasTrusted: true}, true},
			{"trusted differs", pk, pqAuthority{trustedPk: "other", hasTrusted: true}, false},
			{"trusted wins over a matching holder_pq", "other", pqAuthority{trustedPk: pk, hasTrusted: true, holderPq: holderPqCommitment("other"), hasHolderPq: true}, false},
			{"holder_pq bound", pk, pqAuthority{holderPq: commit, hasHolderPq: true}, true},
			{"holder_pq mismatch", pk, pqAuthority{holderPq: holderPqCommitment("x"), hasHolderPq: true}, false},
			{"holder_pq absent", pk, pqAuthority{}, false},
			{"holder_pq flag unset but value present", pk, pqAuthority{holderPq: commit}, false},
			{"holder_pq flag set but nil", pk, pqAuthority{hasHolderPq: true}, false},
			{"holder_pq non-string", pk, pqAuthority{holderPq: 5, hasHolderPq: true}, false},
		} {
			k, ok := resolvePqVerifyKey(alg, true, c.pk, c.auth)
			if ok != c.ok {
				t.Fatalf("%s/%s: ok=%v", alg, c.name, ok)
			}
			if ok && k.pk != pk {
				t.Fatalf("%s/%s: key %v", alg, c.name, k)
			}
			if !ok && k.pk != nil {
				t.Fatalf("%s/%s: failure must return the zero key", alg, c.name)
			}
		}
	}
	if k := callerVouchedPqKey("z"); k.pk != "z" {
		t.Fatal("callerVouchedPqKey")
	}
}

func TestMutRootPqAuthority(t *testing.T) {
	iss := newKey(t)
	pq := newPq(t)
	holder := newKey(t)
	root := mkPqCap(t, "ml-dsa-65", iss, pq, holder.id, []any{}, "", nil)
	root = deepM(t, root)
	other := newPq(t)

	if a, ok := rootPqAuthority(root, iss.id, nil, nil); ok || a.hasTrusted {
		t.Fatal("no authority")
	}
	if a, ok := rootPqAuthority(root, iss.id, map[string]string{iss.id: pq.b64}, nil); !ok || !a.hasTrusted || a.trustedPk != pq.b64 {
		t.Fatalf("own pin: %+v %v", a, ok)
	}
	if _, ok := rootPqAuthority(root, iss.id, map[string]string{iss.id: other.b64}, nil); ok {
		t.Fatal("differing pin must refuse")
	}
	if _, ok := rootPqAuthority(root, iss.id, map[string]string{holder.id: pq.b64}, nil); ok {
		t.Fatal("pin for another issuer")
	}
	if _, ok := rootPqAuthority(root, iss.id, map[string]string{}, nil); ok {
		t.Fatal("empty pins")
	}
	if a, ok := rootPqAuthority(root, iss.id, nil, root); !ok || !a.hasTrusted || a.trustedPk != pq.b64 {
		t.Fatalf("stored grant: %+v %v", a, ok)
	}
	diff := deepM(t, root)
	diff["caveats"] = []any{map[string]any{"type": "x"}}
	if _, ok := rootPqAuthority(root, iss.id, nil, diff); ok {
		t.Fatal("different stored grant")
	}
	// a differing stored grant does not hide a correct pin, and a correct stored grant beats a wrong pin
	if _, ok := rootPqAuthority(root, iss.id, map[string]string{iss.id: pq.b64}, diff); !ok {
		t.Fatal("pin should still apply")
	}
	if _, ok := rootPqAuthority(root, iss.id, map[string]string{iss.id: other.b64}, root); !ok {
		t.Fatal("stored grant beats wrong pin")
	}
	bad := deepM(t, root)
	bad["caveats"] = []any{map[string]any{"type": "\xed\xa0\x80"}}
	if _, ok := rootPqAuthority(root, iss.id, nil, bad); ok {
		t.Fatal("unhashable stored grant")
	}
	if _, ok := rootPqAuthority(bad, iss.id, nil, bad); ok {
		t.Fatal("unhashable root")
	}
	nb := deepM(t, root)
	nb["pq_pk"] = 5
	if _, ok := rootPqAuthority(nb, iss.id, map[string]string{iss.id: pq.b64}, nb); ok {
		t.Fatal("non-string root pq_pk")
	}
	delete(nb, "pq_pk")
	if _, ok := rootPqAuthority(nb, iss.id, map[string]string{iss.id: ""}, nil); ok {
		t.Fatal("absent pq_pk")
	}
}

func TestMutPqRootChains(t *testing.T) {
	iss, h1, h2 := newKey(t), newKey(t), newKey(t)
	pq := newPq(t)
	other := newPq(t)
	for _, alg := range []string{"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"} {
		root := deepM(t, mkPqCap(t, alg, iss, pq, h1.id, []any{}, "", nil))
		rh, _ := CapHash(root)
		child := mkCap(t, h1, h2.id, []any{}, rh, nil)
		chain := []any{root, deep(t, child)}
		refuse := "hop 0: root suite '" + alg + "' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"
		if why, ok := VerifyChain(chain, iss.id, true); ok || why != refuse {
			t.Fatalf("%s no authority: %q", alg, why)
		}
		if why, ok := VerifyChainPolicy(chain, iss.id, true, nil, map[string]string{iss.id: pq.b64}, nil); !ok {
			t.Fatalf("%s pinned: %q", alg, why)
		}
		if why, ok := VerifyChainPolicy(chain, iss.id, true, nil, nil, root); !ok {
			t.Fatalf("%s trusted: %q", alg, why)
		}
		if why, ok := VerifyChainPolicy(chain, iss.id, true, nil, map[string]string{iss.id: other.b64}, nil); ok || why != refuse {
			t.Fatalf("%s wrong pin: %q", alg, why)
		}
		if why, ok := VerifyChainPolicy(chain, iss.id, true, nil, map[string]string{h1.id: pq.b64}, nil); ok || why != refuse {
			t.Fatalf("%s pin for someone else: %q", alg, why)
		}
		// the suite policy is evaluated BEFORE the PQ authority
		why, ok := VerifyChainPolicy(chain, iss.id, true, []string{"ed25519"}, nil, nil)
		if ok || !strings.HasPrefix(why, "hop 0: signature suite '"+alg+"' is not allowed") {
			t.Fatalf("%s policy first: %q", alg, why)
		}
		// authority OK but the signature itself is checked: forge the signature with a different PQ key but the pinned pk
		forged := deepM(t, mkPqCap(t, alg, iss, other, h1.id, []any{}, "", map[string]any{"pq_pk": pq.b64}))
		fc := []any{forged}
		if why, ok := VerifyChainPolicy(fc, iss.id, true, nil, map[string]string{iss.id: pq.b64}, nil); ok || why != "hop 0: bad signature (not signed by expected key)" {
			t.Fatalf("%s forged pq sig: %q %v", alg, why, ok)
		}
		// hop 1 using the PQ suite, bound via the parent's holder_pq
		pq1 := newPq(t)
		root2 := deepM(t, mkCap(t, iss, h1.id, []any{}, "", map[string]any{"holder_pq": holderPqCommitment(pq1.b64)}))
		rh2, _ := CapHash(root2)
		c1 := deepM(t, mkPqCap(t, alg, h1, pq1, h2.id, []any{}, rh2, nil))
		if why, ok := VerifyChain([]any{root2, c1}, iss.id, true); !ok {
			t.Fatalf("%s bound hop: %q", alg, why)
		}
		// a different pq key in the hop (not the committed one) is the F-2 refusal
		c1bad := deepM(t, mkPqCap(t, alg, h1, other, h2.id, []any{}, rh2, nil))
		if why, ok := VerifyChain([]any{root2, c1bad}, iss.id, true); ok || why != "hop 1: pq_pk does not match the signer's committed holder_pq (F-2)" {
			t.Fatalf("%s F-2: %q", alg, why)
		}
		// root without holder_pq commitment
		root3 := deepM(t, mkCap(t, iss, h1.id, []any{}, "", nil))
		rh3, _ := CapHash(root3)
		c1nc := deepM(t, mkPqCap(t, alg, h1, pq1, h2.id, []any{}, rh3, nil))
		if why, ok := VerifyChain([]any{root3, c1nc}, iss.id, true); ok || why != "hop 1: pq_pk does not match the signer's committed holder_pq (F-2)" {
			t.Fatalf("%s uncommitted: %q", alg, why)
		}
	}
}

func TestMutPqLeaf(t *testing.T) {
	for _, alg := range []string{"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"} {
		f := newFx(t)
		pq := newPq(t)
		// rebuild the chain so the LEAF capability commits to the PQ key
		k := f.keys
		root := mkCap(t, k[0], k[1].id, []any{}, "", nil)
		rh, _ := CapHash(root)
		mid := mkCap(t, k[1], k[2].id, []any{}, rh, nil)
		mh, _ := CapHash(mid)
		leaf := mkCap(t, k[2], k[3].id, []any{}, mh, map[string]any{"holder_pq": holderPqCommitment(pq.b64)})
		f.chain = []any{root, mid, leaf}
		f.grant = root
		f.p["cap_chain"], f.p["grant_ref"] = f.chain, root["id"]
		f.p["alg"], f.p["pq_pk"] = alg, pq.b64
		sign := func() {
			delete(f.p, "pq_sig")
			if alg == "ml-dsa-65" {
				f.p["sig"] = b64.EncodeToString(make([]byte, 3309)) // placeholder of the right size; replaced below
			}
			msg, err := ThresholdMessage(f.p)
			if err != nil {
				t.Fatal(err)
			}
			if alg == "ml-dsa-65" {
				f.p["sig"] = pq.sign(t, msg)
			} else {
				f.p["sig"] = b64.EncodeToString(ed25519.Sign(k[3].priv, msg))
				f.p["pq_sig"] = pq.sign(t, msg)
			}
		}
		sign()
		v := f.verify(nil)
		if !v.Allow || !v.Checks["leaf_signature"] {
			t.Fatalf("%s valid pq leaf: %+v", alg, v)
		}
		if v := f.verify([]string{alg}); v.Allow {
			t.Fatalf("%s: policy lists only the leaf suite, but the ed25519 hops are refused", alg)
		}
		if v := f.verify([]string{"ed25519", alg}); !v.Allow {
			t.Fatalf("%s policy with both: %+v", alg, v)
		}
		if v := f.verify([]string{"ed25519"}); v.Allow || v.Checks["leaf_signature"] || v.Reason != "leaf_signature: signature suite not allowed or pq_pk not bound to the leaf holder_pq" {
			t.Fatalf("%s leaf suite not allowed: %+v", alg, v)
		}
		// unbound pq key (a different key, validly self-signed) is refused
		other := newPq(t)
		f.p["pq_pk"] = other.b64
		pq2 := pq
		pq = other
		sign()
		pq = pq2
		v = f.verify(nil)
		if v.Allow || v.Checks["leaf_signature"] || v.Reason != "leaf_signature: signature suite not allowed or pq_pk not bound to the leaf holder_pq" {
			t.Fatalf("%s unbound key: %+v", alg, v)
		}
		// bound key, bad PQ signature
		f.p["pq_pk"] = pq.b64
		sign()
		var sg []byte
		if alg == "ml-dsa-65" {
			sg, _ = b64.DecodeString(f.p["sig"].(string))
		} else {
			sg, _ = b64.DecodeString(f.p["pq_sig"].(string))
		}
		sg[10] ^= 1
		if alg == "ml-dsa-65" {
			f.p["sig"] = b64.EncodeToString(sg)
		} else {
			f.p["pq_sig"] = b64.EncodeToString(sg)
		}
		if v = f.verify(nil); v.Allow || v.Checks["leaf_signature"] || v.Reason != "leaf_signature: signature does not verify under the leaf holder key" {
			t.Fatalf("%s tampered pq sig: %+v", alg, v)
		}
		// leaf cap that commits nothing
		f.chain[2] = mkCap(t, k[2], k[3].id, []any{}, mh, nil)
		f.p["cap_chain"] = f.chain
		sign()
		if v = f.verify(nil); v.Allow || v.Checks["leaf_signature"] {
			t.Fatalf("%s uncommitted leaf: %+v", alg, v)
		}
	}
}
