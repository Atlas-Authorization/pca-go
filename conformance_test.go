package pca

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

const dir = "conformance/"

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(dir + name)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func num(v any) int64 { i, _ := safeInt(v); return i }

// supportedSuites are the signature suites this Go verifier implements for a GENUINE crypto verdict — on the
// leaf signature (requires:"pq"), on non-leaf capability-chain hops (requires:"pq-nonleaf"), the threshold
// share binding, and the PQ transparency artifacts. These are the three CROSS-IMPL suites every conformant
// verifier must agree on: classical Ed25519, pure lattice ML-DSA-65 (FIPS-204, via cloudflare/circl), and the
// hybrid Ed25519 + ML-DSA-65. The other 7 registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids,
// and the SUF-CMA nested hybrid) are NOT wired in Go, so vectors needing a real signature verdict under them
// are skipped EXPLICITLY — never silently passed.
var supportedSuites = map[string]bool{
	"ed25519":                  true,
	"ml-dsa-65":                true,
	"hybrid-ed25519-ml-dsa-65": true,
}

func algOf(o map[string]any) string {
	if s, ok := o["alg"].(string); ok {
		return s
	}
	return "ed25519"
}

// unsupportedSuite returns the concrete suite a vector exercises that Go does NOT implement, if any: the leaf
// `alg` for requires:"pq", or the first non-ed25519 capability-hop `alg` for requires:"pq-nonleaf". Returns
// ("", false) for core vectors and for vectors that stay entirely within supportedSuites.
func unsupportedSuite(v map[string]any) (string, bool) {
	p, ok := v["pcactn"].(map[string]any)
	if !ok {
		return "", false // raw-json (wire) vectors and core vectors carry no PQ suite
	}
	switch v["requires"] {
	case "pq":
		if a := algOf(p); !supportedSuites[a] {
			return a, true
		}
	case "pq-nonleaf":
		if chain, ok := p["cap_chain"].([]any); ok {
			for _, hv := range chain {
				if hop, ok := hv.(map[string]any); ok {
					if a := algOf(hop); !supportedSuites[a] {
						return a, true
					}
				}
			}
		}
	}
	return "", false
}

// terminalWireFalse reports whether the expected verdict is a terminal {wire:false} — a wire failure is
// suite-AGNOSTIC (unknown `alg`, or a `pq_sig` whose size the suite cannot admit, is rejected at the wire
// stage regardless of whether we implement the suite), so these negatives still RUN and pass even for an
// unimplemented suite. Everything else under an unsupported suite needs a genuine signature outcome.
func terminalWireFalse(checks map[string]any) bool {
	if len(checks) != 1 {
		return false
	}
	w, ok := checks["wire"].(bool)
	return ok && !w
}

func TestVectors(t *testing.T) {
	doc := load(t, "vectors.json")
	if num(doc["format"]) != 2 || num(doc["ver"]) != 2 {
		t.Fatal("not a format-2 vector file")
	}
	vs := doc["vectors"].([]any)
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	pass := 0
	skippedBySuite := map[string]int{}
	for _, x := range vs {
		v := x.(map[string]any)
		name := v["name"].(string)
		exp := v["expect"].(map[string]any)
		ec := exp["checks"].(map[string]any)
		// SUITE-AWARE skip: only skip a vector whose expected verdict needs a real crypto verdict under a
		// suite Go does not implement. A terminal {wire:false} negative is run regardless.
		if suite, bad := unsupportedSuite(v); bad && !terminalWireFalse(ec) {
			skippedBySuite[suite]++
			continue
		}
		t.Run(name, func(t *testing.T) {
			ctx := v["context"].(map[string]any)
			var got Verdict
			var err error
			if raw, ok := v["pcactn_json"].(string); ok {
				p, perr := ParsePCActn(raw)
				if perr != nil {
					got = WireFailure(perr.Error())
				} else {
					got, err = VerifyPCActnCore(p, v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string))
				}
			} else {
				got, err = VerifyPCActnCore(v["pcactn"].(map[string]any), v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string))
			}
			if err != nil {
				t.Fatal(err)
			}
			ok := true
			if got.Allow != exp["allow"].(bool) {
				ok = false
				t.Errorf("allow = %v, want %v (%s)", got.Allow, exp["allow"], got.Reason)
			}
			if len(ec) != len(got.Checks) {
				ok = false
				t.Errorf("checks %v, want %v", got.Checks, ec)
			}
			for k, w := range ec {
				if g, has := got.Checks[k]; !has || g != w.(bool) {
					ok = false
					t.Errorf("check %s = %v, want %v (%s)", k, g, w, got.Reason)
				}
			}
			if ok {
				pass++
			}
		})
	}
	skipped := 0
	for _, n := range skippedBySuite {
		skipped += n
	}
	t.Logf("format-2 PCActn vectors passing: %d/%d (ran %d, skipped %d)", pass, len(vs), len(vs)-skipped, skipped)
	for _, s := range sortedKeys(skippedBySuite) {
		t.Logf("  skipped %d vector(s) requiring unimplemented suite %q", skippedBySuite[s], s)
	}
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---- v2.1 agent-leaf threshold-share binding (GAP 2) ---------------------------------

const (
	shareDomainPrefix = "atlas-pca/share/"
	signersetDomain   = "atlas-pca/signerset/v1\x00"
)

// signerSetHash = sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role, publicKey)[{publicKey, role}])).
// FAIL-CLOSED: (_, false) on any malformed entry, never panics.
func signerSetHash(signerSet []any) ([]byte, bool) {
	type ent struct{ role, pk string }
	ents := make([]ent, 0, len(signerSet))
	for _, e := range signerSet {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		role, ok := o["role"].(string)
		if !ok {
			return nil, false
		}
		pk, ok := o["publicKey"].(string)
		if !ok {
			return nil, false
		}
		ents = append(ents, ent{role, pk})
	}
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].role != ents[j].role {
			return ents[i].role < ents[j].role
		}
		return ents[i].pk < ents[j].pk
	})
	arr := make([]any, len(ents))
	for i, e := range ents {
		arr[i] = map[string]any{"publicKey": e.pk, "role": e.role}
	}
	canon, err := Canonicalize(arr)
	if err != nil {
		return nil, false
	}
	return sha(append([]byte(signersetDomain), canon...)), true
}

// verifyThresholdShare verifies a single `primitives.threshold_share[]` entry under the v2.1 agent-leaf share
// binding. RECOMPUTES the bound message from scratch (does not trust the stored `share_message`):
//
//	"atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash(signer_set) || t(1 byte)
//
// and confirms `share.sig` verifies over it under `share.publicKey` (routed through the SAME suite seam as the
// leaf, so a PQ/hybrid share would use `share.pq_pk`/`share.pq_sig`). FAIL-CLOSED: false on any malformed
// input, never panics. The PRE-v2.1 bare agent share (a `sig` over the bare threshold message) and a
// cross-signer-set replay (a share bound to a DIFFERENT signer set) therefore both fail — the clean break the
// v2.1 binding mandates.
func verifyThresholdShare(entry map[string]any) bool {
	role, ok := entry["role"].(string)
	if !ok {
		return false
	}
	ti, ok := safeInt(entry["t"])
	if !ok || ti < 0 || ti > 255 {
		return false
	}
	signerSet, ok := entry["signer_set"].([]any)
	if !ok {
		return false
	}
	tmStr, ok := entry["threshold_message"].(string)
	if !ok {
		return false
	}
	tm, ok := DecodeB64uStrict(tmStr, -1)
	if !ok {
		return false
	}
	ssh, ok := signerSetHash(signerSet)
	if !ok {
		return false
	}
	share, ok := entry["share"].(map[string]any)
	if !ok {
		return false
	}
	pk, ok := share["publicKey"].(string)
	if !ok {
		return false
	}
	// Bound share message: domain(role) || sha256(thresholdMessage) || signerSetHash || t.
	msg := make([]byte, 0, len(shareDomainPrefix)+len(role)+1+32+len(ssh)+1)
	msg = append(msg, shareDomainPrefix...)
	msg = append(msg, role...)
	msg = append(msg, 0)
	msg = append(msg, sha(tm)...)
	msg = append(msg, ssh...)
	msg = append(msg, byte(ti))
	algV, algPresent := share["alg"]
	return verifyLeafSuite(algV, algPresent, pk, share["pq_pk"], msg, share["sig"], share["pq_sig"])
}

func TestThresholdShares(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	shares, ok := prim["threshold_share"].([]any)
	if !ok || len(shares) == 0 {
		t.Fatal("no threshold_share primitives")
	}
	accepted, rejected := 0, 0
	bareRejected, wrongSetRejected := false, false
	for _, sv := range shares {
		s := sv.(map[string]any)
		name, _ := s["name"].(string)
		if name == "" {
			name, _ = s["role"].(string)
		}
		want := true
		if w, ok := s["valid"].(bool); ok {
			want = w
		}
		got := verifyThresholdShare(s)
		if got != want {
			t.Errorf("%s: share verified = %v, want valid = %v", name, got, want)
		}
		if want {
			accepted++
		} else {
			rejected++
		}
		if name == "agent-bare-rejected" && !got {
			bareRejected = true
		}
		if name == "agent-bound-wrong-set" && !got {
			wrongSetRejected = true
		}
	}
	if !bareRejected {
		t.Error("v2.1 binding: the pre-v2.1 bare agent share (agent-bare-rejected) MUST be rejected")
	}
	if !wrongSetRejected {
		t.Error("v2.1 binding: a cross-signer-set agent share replay (agent-bound-wrong-set) MUST be rejected")
	}
	t.Logf("threshold shares: %d valid accepted, %d invalid rejected (incl. v2.1 bare-agent-share + cross-signer-set replay)", accepted, rejected)
}

// ---- PQ transparency / authority artifacts (shared agility seam) ----------------------

// TestPQArtifact exercises the representative post-quantum signatures for the non-leaf transparency/authority
// surfaces. They route through the SAME suite seam as the leaf, so an implemented suite yields a genuine
// verdict and an unimplemented one is skipped explicitly.
func TestPQArtifact(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	arts, ok := prim["pq_artifact"].([]any)
	if !ok || len(arts) == 0 {
		t.Fatal("no pq_artifact primitives")
	}
	ran, skipped := 0, 0
	skippedBySuite := map[string]int{}
	for _, av := range arts {
		a := av.(map[string]any)
		alg, _ := a["alg"].(string)
		artifact, _ := a["artifact"].(string)
		if !supportedSuites[alg] {
			skipped++
			skippedBySuite[alg]++
			continue
		}
		msgStr, _ := a["message"].(string)
		msg, ok := DecodeB64uStrict(msgStr, -1)
		if !ok {
			t.Errorf("%s/%s: message not canonical base64url", artifact, alg)
			continue
		}
		edPub, _ := a["ed_pub"].(string)
		got := verifyLeafSuite(alg, true, edPub, a["pq_pk"], msg, a["sig"], a["pq_sig"])
		want, _ := a["valid"].(bool)
		if got != want {
			t.Errorf("%s/%s: verified = %v, want %v", artifact, alg, got, want)
		}
		ran++
	}
	t.Logf("pq artifacts: ran %d, skipped %d", ran, skipped)
	for _, s := range sortedKeys(skippedBySuite) {
		t.Logf("  skipped %d pq artifact(s) under unimplemented suite %q", skippedBySuite[s], s)
	}
}

func TestPrimitives(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	for _, x := range prim["canonical"].([]any) {
		c := x.(map[string]any)
		s, err := Canonicalize(c["value"])
		if err != nil || s != c["expect"].(string) {
			t.Errorf("canonical mismatch: %q vs %q (%v)", s, c["expect"], err)
		}
		h, _ := HashCanonical(c["value"])
		if h != c["hash"].(string) {
			t.Errorf("hash mismatch for %s", s)
		}
	}
	for _, x := range prim["json_parse"].([]any) {
		c := x.(map[string]any)
		in := c["input"].(string)
		v, err := StrictParse(in)
		if c["accept"].(bool) {
			if err != nil {
				t.Errorf("json_parse %q: rejected: %v", in, err)
				continue
			}
			if want, ok := c["canonical"].(string); ok {
				if got, cerr := Canonicalize(v); cerr != nil || got != want {
					t.Errorf("json_parse %q: canonical %q want %q (%v)", in, got, want, cerr)
				}
			}
		} else if err == nil {
			t.Errorf("json_parse %q: accepted, must reject", in)
		}
	}
	for _, x := range prim["b64u"].([]any) {
		c := x.(map[string]any)
		in := c["input"].(string)
		n := -1
		if l, ok := c["len"]; ok {
			n = int(num(l))
		}
		_, ok := DecodeB64uStrict(in, n)
		if ok != c["valid"].(bool) {
			t.Errorf("b64u %q len %d: valid=%v want %v", in, n, ok, c["valid"])
		}
	}
	for _, x := range prim["merkle"].([]any) {
		m := x.(map[string]any)
		leaves := m["leaves"].([]any)
		root, err := MerkleRoot(leaves)
		if err != nil || root != m["root"].(string) {
			t.Errorf("merkle root mismatch: %s vs %s", root, m["root"])
		}
		for i, p := range m["proofs"].([]any) {
			if !VerifyInclusion(root, p.(map[string]any), leaves[i]) {
				t.Errorf("proof %d does not verify", i)
			}
		}
	}
	e, _ := ParamsDigest(nil)
	if e != prim["params_digest_empty"].(string) {
		t.Error("empty params digest mismatch")
	}
}

// A forged (R=identity, S=0) signature must not verify under an identity / order-2 key.
func TestSmallOrderForgery(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 1
	order2 := make([]byte, 32)
	order2[0] = 0xec
	for i := 1; i < 31; i++ {
		order2[i] = 0xff
	}
	order2[31] = 0x7f
	sig := make([]byte, 64)
	copy(sig, identity)
	for _, pk := range [][]byte{identity, order2} {
		if VerifyStrict(pk, []byte("m"), sig) {
			t.Errorf("small-order key %x accepted a forged signature", pk)
		}
	}
}

var _ = json.Number("")
