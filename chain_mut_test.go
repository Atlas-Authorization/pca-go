package pca

// Mutation-kill tests for capability-chain and VerifyPCActnCore logic using a self-signed fixture.

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

func cloneChain(t *testing.T, chain []any) []any { return deep(t, chain).([]any) }

func TestMutChainValid(t *testing.T) {
	chain, keys := mkChain(t, 3, nil)
	if why, ok := VerifyChain(chain, keys[0].id, true); !ok || why != "" {
		t.Fatalf("valid: %q", why)
	}
	if why, ok := VerifyChain(chain, "anything-else", false); !ok || why != "" {
		t.Fatalf("no issuer pin: %q", why)
	}
	if why, ok := VerifyChain(chain, "", true); ok || why != "hop 0: root issuer is not the expected principal" {
		t.Fatalf("pin mismatch: %q %v", why, ok)
	}
	if why, ok := VerifyChain(chain, keys[1].id, true); ok || why != "hop 0: root issuer is not the expected principal" {
		t.Fatalf("pin mismatch2: %q %v", why, ok)
	}
	// 16 hops valid, 17 too long, 0 empty
	c16, k16 := mkChain(t, 16, nil)
	if why, ok := VerifyChain(c16, k16[0].id, true); !ok {
		t.Fatalf("16 hops: %q", why)
	}
	c17, _ := mkChain(t, 17, nil)
	if why, ok := VerifyChain(c17, "", false); ok || why != "chain too long" {
		t.Fatalf("17 hops: %q", why)
	}
	for _, c := range [][]any{nil, {}} {
		if why, ok := VerifyChain(c, "", false); ok || why != "empty chain" {
			t.Fatalf("empty: %q", why)
		}
	}
}

func TestMutChainMalformedHops(t *testing.T) {
	chain, _ := mkChain(t, 3, func(i int) []any { return []any{map[string]any{"type": "c"}} })
	mods := map[string]func(c map[string]any){
		"id nonstring":     func(c map[string]any) { c["id"] = 1 },
		"issuer nonstring": func(c map[string]any) { c["issuer"] = nil },
		"holder missing":   func(c map[string]any) { delete(c, "holder") },
		"digest nonstring": func(c map[string]any) { c["body_digest"] = []any{} },
		"sig nonstring":    func(c map[string]any) { c["sig"] = 5 },
		"parent nonstring": func(c map[string]any) { c["parent"] = 5 },
		"holder_pq nonstr": func(c map[string]any) { c["holder_pq"] = 5 },
		"caveats missing":  func(c map[string]any) { delete(c, "caveats") },
		"caveats nonarray": func(c map[string]any) { c["caveats"] = "x" },
		"caveat nonobject": func(c map[string]any) { c["caveats"] = []any{"x"} },
		"caveat notype":    func(c map[string]any) { c["caveats"] = []any{map[string]any{}} },
		"caveat type int":  func(c map[string]any) { c["caveats"] = []any{map[string]any{"type": 1}} },
	}
	for name, mod := range mods {
		for hop := 0; hop < 3; hop++ {
			ch := cloneChain(t, chain)
			mod(ch[hop].(map[string]any))
			// hop 0 with a parent string would instead trip "root must not have a parent" only if well-typed; these are all ill-typed
			if name == "parent nonstring" && hop == 0 {
				ch[0].(map[string]any)["parent"] = 5
			}
			want := fmt.Sprintf("hop %d: malformed capability", hop)
			if why, ok := VerifyChain(ch, "", false); ok || why != want {
				t.Fatalf("%s hop %d: %q %v", name, hop, why, ok)
			}
		}
	}
	ch := cloneChain(t, chain)
	ch[1] = "not-an-object"
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 1: malformed capability" {
		t.Fatalf("non-object hop: %q", why)
	}
	// well-typed with optional fields present is accepted by wellTypedCap
	m := chain[0].(map[string]any)
	if _, ok := wellTypedCap(m); !ok {
		t.Fatal("well-typed")
	}
	if _, ok := wellTypedCap(5); ok {
		t.Fatal("non-map")
	}
}

func TestMutChainLinkErrors(t *testing.T) {
	chain, keys := mkChain(t, 3, nil)
	// root has a parent
	ch := cloneChain(t, chain)
	ch[0].(map[string]any)["parent"] = "x"
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 0: root must not have a parent" {
		t.Fatalf("root parent: %q", why)
	}
	// broken parent link at hop 1 and hop 2 (reason carries the index)
	for _, hop := range []int{1, 2} {
		ch = cloneChain(t, chain)
		ch[hop].(map[string]any)["parent"] = b64.EncodeToString(sha([]byte("other")))
		if why, ok := VerifyChain(ch, "", false); ok || why != fmt.Sprintf("hop %d: broken parent link", hop) {
			t.Fatalf("parent link hop %d: %q", hop, why)
		}
	}
	// issuer of hop 1 is not the parent's holder (parent link intact)
	ch = cloneChain(t, chain)
	ch[1].(map[string]any)["issuer"] = keys[2].id
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 1: issuer is not the parent's bound holder" {
		t.Fatalf("issuer: %q", why)
	}
	// digest mismatch (body tampered, id/digest kept), at root and at a child
	ch = cloneChain(t, chain)
	ch[0].(map[string]any)["caveats"] = []any{map[string]any{"type": "x"}}
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 0: body digest mismatch" {
		t.Fatalf("root digest: %q", why)
	}
	// id != body_digest
	ch = cloneChain(t, chain)
	ch[0].(map[string]any)["id"] = b64.EncodeToString(sha([]byte("z")))
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 0: body digest mismatch" {
		t.Fatalf("id mismatch: %q", why)
	}
	// bad signature at root and child
	for _, hop := range []int{0, 1, 2} {
		ch = cloneChain(t, chain)
		sg, _ := b64.DecodeString(ch[hop].(map[string]any)["sig"].(string))
		sg[0] ^= 1
		ch[hop].(map[string]any)["sig"] = b64.EncodeToString(sg)
		if why, ok := VerifyChain(ch, "", false); ok || why != fmt.Sprintf("hop %d: bad signature (not signed by expected key)", hop) {
			t.Fatalf("sig hop %d: %q", hop, why)
		}
	}
	// signed by the wrong key (a key that is not the parent's holder), link intact
	wrong := newKey(t)
	ch = cloneChain(t, chain)
	c2 := mkCap(t, wrong, keys[3].id, []any{}, ch[1].(map[string]any)["id"].(string), nil)
	c2["issuer"] = keys[2].id // claim the right issuer
	ch[2] = deep(t, c2)
	if why, ok := VerifyChain(ch, "", false); ok {
		t.Fatalf("wrong signer accepted: %q", why)
	}
	// unknown alg -> fail-closed with the alg in the reason; non-string alg
	ch = cloneChain(t, chain)
	ch[0].(map[string]any)["alg"] = "rot13"
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 0: unknown signature alg 'rot13'" {
		t.Fatalf("alg: %q", why)
	}
	// malformed body (lone surrogate in a caveat)
	ch = cloneChain(t, chain)
	ch[0].(map[string]any)["caveats"] = []any{map[string]any{"type": "\xed\xa0\x80"}}
	if why, ok := VerifyChain(ch, "", false); ok || why != "hop 0: malformed body" {
		t.Fatalf("malformed body: %q", why)
	}
}

func TestMutChainCaveatMonotonicity(t *testing.T) {
	cA, cB, cC := map[string]any{"type": "a"}, map[string]any{"type": "b"}, map[string]any{"type": "c"}
	build := func(parentCav, childCav []any) ([]any, string) {
		k0, k1, k2 := newKey(t), newKey(t), newKey(t)
		root := mkCap(t, k0, k1.id, parentCav, "", nil)
		h, _ := CapHash(root)
		child := mkCap(t, k1, k2.id, childCav, h, nil)
		return []any{root, child}, k0.id
	}
	for _, c := range []struct {
		name          string
		parent, child []any
		want          string
	}{
		{"same", []any{cA, cB}, []any{cA, cB}, ""},
		{"narrowed", []any{cA}, []any{cA, cB}, ""},
		{"dropped", []any{cA, cB}, []any{cA}, "hop 1: drops parent caveat(s)"},
		{"dropped all", []any{cA}, []any{}, "hop 1: drops parent caveat(s)"},
		{"reordered", []any{cA, cB}, []any{cB, cA, cC}, "hop 1: caveat 0 altered or reordered"},
		{"altered second", []any{cA, cB}, []any{cA, cC}, "hop 1: caveat 1 altered or reordered"},
		{"altered content", []any{map[string]any{"type": "a", "v": jnum(1)}}, []any{map[string]any{"type": "a", "v": jnum(2)}}, "hop 1: caveat 0 altered or reordered"},
	} {
		ch, iss := build(c.parent, c.child)
		ch = cloneChain(t, ch)
		why, ok := VerifyChain(ch, iss, true)
		if (c.want == "") != ok || why != c.want {
			t.Fatalf("%s: %q %v", c.name, why, ok)
		}
	}
}

func TestMutChainSuitePolicy(t *testing.T) {
	chain, keys := mkChain(t, 2, nil)
	why, ok := VerifyChainPolicy(chain, keys[0].id, true, []string{}, nil, nil)
	if ok || why != "hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy" {
		t.Fatalf("empty policy root: %q", why)
	}
	if why, ok = VerifyChainPolicy(chain, keys[0].id, true, []string{"ml-dsa-65"}, nil, nil); ok || !strings.HasPrefix(why, "hop 0: signature suite 'ed25519' is not allowed") {
		t.Fatalf("other policy: %q", why)
	}
	if why, ok = VerifyChainPolicy(chain, keys[0].id, true, []string{"ml-dsa-65", "ed25519"}, nil, nil); !ok {
		t.Fatalf("listed: %q", why)
	}
	if why, ok = VerifyChainPolicy(chain, keys[0].id, true, nil, nil, nil); !ok {
		t.Fatalf("nil policy: %q", why)
	}
	// explicit alg:"ed25519" counts as ed25519 and, in a non-ed25519-only policy, a hop with alg ml-dsa-65 is refused at hop 1
	k0, k1, k2 := newKey(t), newKey(t), newKey(t)
	root := mkCap(t, k0, k1.id, []any{}, "", nil)
	h, _ := CapHash(root)
	child := mkCap(t, k1, k2.id, []any{}, h, map[string]any{"alg": "ml-dsa-65", "pq_pk": "x"})
	ch := cloneChain(t, []any{root, child})
	why, ok = VerifyChainPolicy(ch, k0.id, true, []string{"ed25519"}, nil, nil)
	if ok || why != "hop 1: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy" {
		t.Fatalf("hop1 policy: %q", why)
	}
	// without a policy the pq hop is refused because the signer committed no holder_pq (F-2)
	why, ok = VerifyChainPolicy(ch, k0.id, true, nil, nil, nil)
	if ok || why != "hop 1: pq_pk does not match the signer's committed holder_pq (F-2)" {
		t.Fatalf("F-2: %q", why)
	}
}

// pqBindingOK is the holder_pq binding predicate, expressed through the single resolvePqVerifyKey choke point.
func pqBindingOK(alg any, present bool, pqPk any, committed any, has bool) bool {
	_, ok := resolvePqVerifyKey(alg, present, pqPk, pqAuthority{holderPq: committed, hasHolderPq: has})
	return ok
}

func TestMutPqBindingAndSuiteHelpers(t *testing.T) {
	good := holderPqCommitment("PK")
	if !pqBindingOK("ml-dsa-65", true, "PK", good, true) || !pqBindingOK("hybrid-ed25519-ml-dsa-65", true, "PK", good, true) {
		t.Fatal("bound")
	}
	if pqBindingOK("ml-dsa-65", true, "PK", good, false) || pqBindingOK("ml-dsa-65", true, "PK", nil, true) ||
		pqBindingOK("ml-dsa-65", true, "PK2", good, true) || pqBindingOK("ml-dsa-65", true, 5, good, true) || pqBindingOK("ml-dsa-65", true, "PK", 5, true) {
		t.Fatal("unbound accepted")
	}
	if !pqBindingOK("ed25519", true, nil, nil, false) || !pqBindingOK("", false, nil, nil, false) {
		t.Fatal("ed25519 needs no binding")
	}
	if !pqBindingOK("zzz", true, nil, nil, false) { // unknown alg: handled elsewhere (fail-closed upstream)
		t.Fatal("unknown alg passes this helper")
	}
	if !suiteAllowed(nil, false, nil) || !suiteAllowed("x", true, nil) || suiteAllowed(nil, false, []string{}) ||
		!suiteAllowed(nil, false, []string{"ed25519"}) || suiteAllowed("ml-dsa-65", true, []string{"ed25519"}) || suiteAllowed(5, true, []string{"ed25519"}) {
		t.Fatal("suiteAllowed")
	}
	if algName(nil, false) != "ed25519" || algName("a", true) != "a" || algName(5, true) != "\x00non-string" {
		t.Fatal("algName")
	}
	if _, err := capSigMessage("!!"); err == nil {
		t.Fatal("capSigMessage err")
	}
	m, err := capSigMessage("AAAA")
	if err != nil || string(m) != capDomain+"\x00\x00\x00" {
		t.Fatalf("capSigMessage %q %v", m, err)
	}
}

func TestMutCoreAllPass(t *testing.T) {
	f := newFx(t)
	v := f.verify(nil)
	if !v.Allow || v.Reason != "" {
		t.Fatalf("valid fixture: %+v", v)
	}
	for _, c := range []string{"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"} {
		if !v.Checks[c] {
			t.Fatalf("check %s", c)
		}
	}
	if len(v.Checks) != 9 {
		t.Fatalf("checks: %v", v.Checks)
	}
	if v2, _ := VerifyPCActnCore(f.norm(), f.grant, f.now, f.aud); !v2.Allow {
		t.Fatal("VerifyPCActnCore wrapper")
	}
	if v.Checks["x"] {
		t.Fatal("phantom check")
	}
	// policy allowing exactly ed25519
	if v := f.verify([]string{"ed25519"}); !v.Allow {
		t.Fatal("ed25519 policy")
	}
	v = f.verify([]string{})
	if v.Allow || v.Checks["chain"] || v.Checks["leaf_signature"] || !strings.HasPrefix(v.Reason, "chain: hop 0: signature suite 'ed25519' is not allowed") {
		t.Fatalf("empty policy: %+v", v)
	}
	if v.Checks["leaf_signature"] {
		t.Fatal("leaf must fail when suite not allowed")
	}
}

func TestMutCoreSingleFailures(t *testing.T) {
	type tc struct {
		name   string
		mod    func(f *fx)
		failed []string
		reason string
	}
	cases := []tc{
		{"version", func(f *fx) { f.p["ver"] = jnum(3) }, []string{"version"}, "version: unsupported ver"},
		{"audience", func(f *fx) { f.p["aud"] = "rs-2" }, []string{"audience"}, "audience: aud does not match this resource server / instance"},
		{"exp==iat", func(f *fx) { f.p["exp"] = f.p["iat"] }, []string{"validity"}, "validity: exp must be greater than iat"},
		{"exp<iat", func(f *fx) { f.p["exp"] = jnum(1_699_999_999_999) }, []string{"validity"}, "validity: exp must be greater than iat"},
		{"lifetime max", func(f *fx) { f.p["exp"] = jnum(1_700_000_000_000 + 3_600_000); f.now = 1_700_000_000_000 + 3_600_000 }, nil, ""},
		{"lifetime too long", func(f *fx) { f.p["exp"] = jnum(1_700_000_000_000 + 3_600_001); f.now = 1_700_000_000_000 + 3_600_001 }, []string{"validity"}, "validity: lifetime too long"},
		{"iat skew edge ok", func(f *fx) { f.now = 1_700_000_000_000 - 60_000 }, nil, ""},
		{"iat future", func(f *fx) { f.now = 1_700_000_000_000 - 60_001 }, []string{"validity"}, "validity: iat is in the future (clock skew)"},
		{"expired edge ok", func(f *fx) { f.now = 1_700_000_600_000 }, nil, ""},
		{"expired", func(f *fx) { f.now = 1_700_000_600_001 }, []string{"validity"}, "validity: the PCActn has expired"},
		{"counter zero ok", func(f *fx) { f.p["counter"] = jnum(0) }, nil, ""},
		{"counter one ok", func(f *fx) { f.p["counter"] = jnum(1) }, nil, ""},
		{"counter negative", func(f *fx) { f.p["counter"] = jnum(-1) }, []string{"counter_format"}, "counter_format: missing or not a non-negative safe integer"},
		{"grant_ref other", func(f *fx) { f.p["grant_ref"] = b64.EncodeToString(sha([]byte("zz"))) }, []string{"grant_ref_bound"}, "grant_ref_bound: grant_ref is not the id of the root capability in cap_chain"},
		{"plan node", func(f *fx) { f.p["plan"].(map[string]any)["node_id"] = "n3" }, []string{"plan_inclusion"}, "plan_inclusion: action is not a node of the committed plan"},
		{"plan cond differs", func(f *fx) {
			f.p["plan"].(map[string]any)["conditions_digest"] = b64.EncodeToString(sha([]byte("other")))
		}, []string{"plan_inclusion"}, "plan_inclusion: action is not a node of the committed plan"},
		{"plan cond absent", func(f *fx) { delete(f.p["plan"].(map[string]any), "conditions_digest") }, []string{"plan_inclusion"}, "plan_inclusion: action is not a node of the committed plan"},
		{"action verb", func(f *fx) { f.p["action"].(map[string]any)["verb"] = "burn" }, []string{"plan_inclusion"}, "plan_inclusion: action is not a node of the committed plan"},
		{"leaf sig key", func(f *fx) { f.keys[len(f.keys)-1] = newKey(t) }, []string{"leaf_signature"}, "leaf_signature: signature does not verify under the leaf holder key"},
	}
	for _, c := range cases {
		f := newFx(t)
		c.mod(f)
		if c.name != "leaf sig key" {
			f.resign()
		} else {
			f.resign() // signed by a key that is not the chain's leaf holder
		}
		v := f.verify(nil)
		wantAllow := len(c.failed) == 0
		if v.Allow != wantAllow || v.Reason != c.reason {
			t.Fatalf("%s: allow=%v reason=%q", c.name, v.Allow, v.Reason)
		}
		fails := map[string]bool{}
		for _, n := range c.failed {
			fails[n] = true
		}
		for _, n := range []string{"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"} {
			if v.Checks[n] == fails[n] {
				t.Fatalf("%s: check %s = %v", c.name, n, v.Checks[n])
			}
		}
	}
}

func TestMutCoreFirstReasonWins(t *testing.T) {
	f := newFx(t)
	f.p["aud"] = "rs-2"
	f.now = 1_700_000_600_001 // also expired
	f.p["counter"] = jnum(-5)
	f.resign()
	v := f.verify(nil)
	if v.Allow || v.Reason != "audience: aud does not match this resource server / instance" || v.Checks["validity"] || v.Checks["counter_format"] {
		t.Fatalf("%+v", v)
	}
}

func TestMutCoreChainFailures(t *testing.T) {
	// chain root is not the grant
	f := newFx(t)
	other, _ := mkChain(t, 1, nil)
	f.grant = other[0].(map[string]any)
	v := f.verify(nil)
	if v.Allow || v.Checks["chain"] || v.Reason != "chain: chain root is not the grant" {
		t.Fatalf("root!=grant: %+v", v)
	}
	// nil grant: CapHash(nil) differs
	f = newFx(t)
	f.grant = nil
	v = f.verify(nil)
	if v.Allow || v.Reason != "chain: chain root is not the grant" {
		t.Fatalf("nil grant: %+v", v)
	}
	// chain verification failure surfaces the chain reason (tampered mid hop) and fails closed
	f = newFx(t)
	f.p["cap_chain"].([]any)[1].(map[string]any)["caveats"] = []any{}
	f.resign()
	v = f.verify(nil)
	if v.Allow || v.Checks["chain"] || v.Reason != "chain: hop 1: body digest mismatch" {
		t.Fatalf("tampered: %+v", v)
	}
	// empty chain
	f = newFx(t)
	f.p["cap_chain"] = []any{}
	f.resign()
	v = f.verify(nil)
	if v.Allow || v.Checks["chain"] || v.Checks["leaf_signature"] || v.Checks["grant_ref_bound"] || v.Reason != "chain: empty chain" {
		t.Fatalf("empty chain: %+v", v)
	}
	// too long (17 hops): only the chain check (and what depends on it) fails
	c17, k17 := mkChain(t, 17, nil)
	f = newFx(t)
	f.chain, f.keys, f.grant = c17, k17, c17[0].(map[string]any)
	f.p["cap_chain"], f.p["grant_ref"] = c17, f.grant["id"]
	f.resign()
	v = f.verify(nil)
	if v.Allow || v.Checks["chain"] || v.Reason != "chain: chain too long" || !v.Checks["leaf_signature"] || !v.Checks["grant_ref_bound"] {
		t.Fatalf("17 hops: %+v", v)
	}
	// caveat cap: single-hop chain whose root has 257 caveats; everything else valid -> the chain check alone must deny
	cv := make([]any, 257)
	for i := range cv {
		cv[i] = map[string]any{"type": "n"}
	}
	c1, k1 := mkChain(t, 1, func(int) []any { return cv })
	f = newFx(t)
	f.chain, f.keys, f.grant = c1, k1, c1[0].(map[string]any)
	f.p["cap_chain"], f.p["grant_ref"] = c1, f.grant["id"]
	f.resign()
	v = f.verify(nil)
	if v.Allow || v.Checks["chain"] || v.Reason != "chain: "+CaveatLimitReason || !v.Checks["leaf_signature"] {
		t.Fatalf("caveat cap: %+v", v)
	}
}

func TestMutCoreChainReasonPrecedesGrantMismatch(t *testing.T) {
	// a too-long / over-capped chain is reported as such even when its root also differs from the stored grant
	c17, k17 := mkChain(t, 17, nil)
	f := newFx(t)
	f.chain, f.keys = c17, k17
	f.p["cap_chain"], f.p["grant_ref"] = c17, c17[0].(map[string]any)["id"]
	f.resign()
	if v := f.verify(nil); v.Allow || v.Reason != "chain: chain too long" {
		t.Fatalf("17 hops, other grant: %+v", v)
	}
	cv := make([]any, 257)
	for i := range cv {
		cv[i] = map[string]any{"type": "n"}
	}
	c1, k1 := mkChain(t, 1, func(int) []any { return cv })
	f = newFx(t)
	f.chain, f.keys = c1, k1
	f.p["cap_chain"], f.p["grant_ref"] = c1, c1[0].(map[string]any)["id"]
	f.resign()
	if v := f.verify(nil); v.Allow || v.Reason != "chain: "+CaveatLimitReason {
		t.Fatalf("caveat cap, other grant: %+v", v)
	}
}

func TestMutParsePCActnErrors(t *testing.T) {
	_, err := ParsePCActn("x")
	if err == nil || err.Error() != "strict JSON: unexpected token (at offset 0)" {
		t.Fatalf("%v", err)
	}
	if _, err = ParsePCActn(""); err == nil || err.Error() != "strict JSON: unexpected end of input (at offset 0)" {
		t.Fatalf("%v", err)
	}
}

func TestMutCoreWireFailure(t *testing.T) {
	f := newFx(t)
	delete(f.p, "counter")
	v, err := VerifyPCActnCore(f.norm(), f.grant, f.now, f.aud)
	if err != nil || v.Allow || v.Reason != "wire: missing field 'counter'" || len(v.Checks) != 1 || v.Checks["wire"] {
		t.Fatalf("%+v %v", v, err)
	}
	if w := WireFailure("x"); w.Allow || w.Reason != "wire: x" || w.Checks["wire"] || len(w.Checks) != 1 {
		t.Fatal("WireFailure")
	}
	if r := ValidateWireV2(nil); r != "PCActn is not an object" {
		t.Fatal(r)
	}
}

func TestMutLeafSignaturePaths(t *testing.T) {
	f := newFx(t)
	// not ed25519-allowed leaf alg declared but unknown -> wire failure (unknown alg)
	f.p["alg"] = "nope"
	v := f.verify(nil)
	if v.Allow || v.Reason != "wire: unknown signature alg 'nope'" {
		t.Fatalf("%+v", v)
	}
	// ml-dsa-65 declared without the holder commitment: wire needs pq_pk; policy forbids -> leaf fails
	f = newFx(t)
	f.p["sig"] = b64.EncodeToString(make([]byte, 64))
	v = f.verify(nil)
	if v.Allow || v.Checks["leaf_signature"] || v.Reason != "leaf_signature: signature does not verify under the leaf holder key" {
		t.Fatalf("bad leaf: %+v", v)
	}
	// holder is the signer, not the issuer of the leaf
	f = newFx(t)
	msg, _ := ThresholdMessage(f.p)
	f.p["sig"] = b64.EncodeToString(ed25519.Sign(f.keys[len(f.keys)-2].priv, msg))
	if v = f.verify(nil); v.Allow || v.Checks["leaf_signature"] {
		t.Fatal("signed by previous key")
	}
}
