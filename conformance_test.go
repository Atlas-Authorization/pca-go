package pca

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
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

// supportedSuites is this verifier's capability manifest (SupportedSuites(): every registered suite Go implements,
// see packages/pca/conformance/SUITES.md). A vector that needs a suite outside it is not skipped: the verifier must
// refuse it with the distinct reason unsupported_suite (asserted in TestVectors).
var supportedSuites = func() map[string]bool {
	m := map[string]bool{}
	for _, a := range SupportedSuites() {
		m[a] = true
	}
	return m
}()

func algOf(o map[string]any) string {
	if s, ok := o["alg"].(string); ok {
		return s
	}
	return "ed25519"
}

// unsupportedSuite returns the concrete suite a vector exercises that Go does NOT implement, if any: the leaf
// `alg` for requires:"pq", the first non-ed25519 capability-hop `alg` for requires:"pq-nonleaf", or the suite a
// requires:"<alg>" vector names directly (0.4.1 share vectors). Returns
// ("", false) for core vectors and for vectors that stay entirely within supportedSuites.
func unsupportedSuite(v map[string]any) (string, bool) {
	p, ok := v["pcactn"].(map[string]any)
	if !ok {
		return "", false // raw-json (wire) vectors and core vectors carry no PQ suite
	}
	switch v["requires"] {
	case nil, "":
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
	default:
		// 0.4.1: `requires` may name a concrete suite directly (e.g. a threshold share under ml-dsa-87 or
		// slh-dsa-sha2-128f, which wire now validates per suite). Skip it when Go does not implement that suite.
		if s, ok := v["requires"].(string); ok && !supportedSuites[s] {
			return s, true
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
			// Suite capability rule: a registered suite this verifier does not implement fails closed with
			// unsupported_suite (counted, never silently passed).
			skippedBySuite[suite]++
			t.Run(name+"/unsupported_suite", func(t *testing.T) {
				ctx := v["context"].(map[string]any)
				got, err := VerifyPCActnCore(v["pcactn"].(map[string]any), v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string))
				if err != nil {
					t.Fatal(err)
				}
				if got.Allow || !strings.Contains(got.Reason, UnsupportedSuite) {
					t.Errorf("suite %q: allow=%v reason=%q, want a refusal with %s", suite, got.Allow, got.Reason, UnsupportedSuite)
				}
			})
			continue
		}
		// Intent Layer v2 (README "suite capability"): a vector whose artifacts need a suite this build does not
		// implement must FAIL with unsupported_suite (never skipped, never accepted).
		requiredSuite, needsSuite := v["requires_suite"].(string)
		mustRefuse := needsSuite && !suiteSupported(requiredSuite, true)
		t.Run(name, func(t *testing.T) {
			ctx := v["context"].(map[string]any)
			var got Verdict
			var err error
			var allowed []string
			if as, has := ctx["allowed_suites"].([]any); has {
				allowed = make([]string, 0, len(as))
				for _, a := range as {
					allowed = append(allowed, a.(string))
				}
			}
			// Intent Layer M2: `intent-*` vectors may carry context.intent_policy (lenient; misconfig fails closed).
			// context.intent_policy_json (raw JSON text, keeps 950000.0 / 1e6 / -0.0) wins over context.intent_policy.
			// Intent Layer v2: context.intent_v2 is the verifier state of the schema-* / session-* / acc-* / layers-*
			// vectors (absent = none).
			opts := VerifyOptions{AllowedSuites: allowed, Intent: IntentPolicyFromJSON(ctx["intent_policy"]), IntentV2: IntentV2ContextFromJSON(ctx["intent_v2"])}
			if text, ok := ctx["intent_policy_json"].(string); ok {
				ip, perr := IntentPolicyFromJSONText(text)
				if perr != nil {
					t.Fatalf("intent_policy_json: %v", perr)
				}
				opts.Intent = ip
			}
			if raw, ok := v["pcactn_json"].(string); ok {
				p, perr := ParsePCActn(raw)
				if perr != nil {
					got = WireFailure(perr.Error())
				} else {
					got, err = VerifyPCActnCoreWith(p, v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string), opts)
				}
			} else {
				got, err = VerifyPCActnCoreWith(v["pcactn"].(map[string]any), v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string), opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mustRefuse {
				if got.Allow || !strings.Contains(got.Reason, UnsupportedSuite) {
					t.Errorf("requires_suite %q: allow=%v reason=%q, want a refusal with %s", requiredSuite, got.Allow, got.Reason, UnsupportedSuite)
				}
				return
			}
			if rc, ok := exp["reason_contains"].(string); ok && !strings.Contains(got.Reason, rc) {
				t.Errorf("reason %q does not contain %q", got.Reason, rc)
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

// ---- v2.1 agent-leaf threshold-share binding (GAP 2): library VerifyThresholdShare (threshold.go) ----

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
		got := VerifyThresholdShare(s)
		// Suite capability: an entry whose `requires` suite Go lacks is not compared; it must be refused.
		if req, ok := s["requires"].(string); ok && !supportedSuites[req] {
			if got {
				t.Errorf("%s: share under unsupported suite %s verified (want fail closed)", name, req)
			}
			continue
		}
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
		got := verifyLeafSuite(alg, true, edPub, callerVouchedPqKey(a["pq_pk"]), msg, a["sig"], a["pq_sig"])
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

// TestChainPin runs the R4-01 shared vectors (primitives.chain_pin[]) against the standalone VerifyChainPolicy.
func TestChainPin(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	vecs, _ := prim["chain_pin"].([]any)
	if len(vecs) < 25 {
		t.Fatalf("chain_pin vectors: %d < 25", len(vecs))
	}
	ran, skipped := 0, 0
	for _, vv := range vecs {
		v := vv.(map[string]any)
		name, _ := v["name"].(string)
		chain, _ := v["chain"].([]any)
		expect, _ := v["expect"].(map[string]any)
		wantOK, _ := expect["ok"].(bool)
		wantReason, _ := expect["reason"].(string)
		pinReason := strings.HasPrefix(wantReason, "hop 0: root suite")
		needsCrypto := wantOK || !pinReason
		unsupported := false
		for _, c := range chain {
			if cm, ok := c.(map[string]any); ok {
				if a := algOf(cm); a != "ed25519" && !supportedSuites[a] {
					unsupported = true
				}
			}
		}
		if unsupported && needsCrypto {
			skipped++
			t.Logf("skip %s: suite not implemented", name)
			continue
		}
		issuer, haveIssuer := v["expected_root_issuer"].(string)
		var allowed []string
		if al, ok := v["allowed_suites"].([]any); ok {
			allowed = []string{}
			for _, a := range al {
				allowed = append(allowed, a.(string))
			}
		}
		var pins map[string]string
		if pm, ok := v["pq_pins"].(map[string]any); ok {
			pins = map[string]string{}
			for k, x := range pm {
				pins[k], _ = x.(string)
			}
		}
		trusted, _ := v["trusted_root"].(map[string]any)
		why, ok := VerifyChainPolicy(chain, issuer, haveIssuer, allowed, pins, trusted)
		if ok != wantOK {
			t.Errorf("%s: ok = %v (%s), want %v", name, ok, why, wantOK)
		}
		if pinReason && why != wantReason {
			t.Errorf("%s: reason %q, want %q", name, why, wantReason)
		}
		ran++
	}
	t.Logf("chain_pin: ran %d, skipped %d", ran, skipped)
	if ran+skipped != len(vecs) {
		t.Fatal("count mismatch")
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
