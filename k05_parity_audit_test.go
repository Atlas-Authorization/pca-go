package pca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Parity audit items. References: packages/pca/src/server/verify.ts:527-533 (bond), capability.ts:174-193 (budget_alloc),
// pcactn.ts:835-841 (zk), require-pca.ts:292 (allowedSuites), pca-grants/src/blueprint.ts (runtime_pins), pca-need.ts:69 (scope
// whitespace), passport.ts:309-329 (throwing hooks), attest-intel-collateral.ts:241-260, attest-amd-snp.ts:83,108,
// attest-nvidia-ocsp.ts:195,269,297.

// ---- A: bond_ref

const bondRefused = "bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)"

func TestParityBondRefUnsupported(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	bond := func(counter int64) map[string]any {
		return g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, counter, map[string]any{"bond_ref": "b1"})
	}
	in := g01DynIn(g)
	r := Authorize(bond(1), in)
	if r.Allow || r.Status != 403 || r.Decision != "deny" || r.Checks["bond"] != "unsupported" || r.Reason != bondRefused || !g01Has(r.Reasons, bondRefused) {
		t.Fatalf("refused: %+v", r)
	}
	// the refused proof did not spend its counter
	in.AllowUnsupported = []string{"other"}
	if r := Authorize(bond(1), in); r.Allow {
		t.Fatalf("another check listed: %+v", r)
	}
	in.AllowUnsupported = []string{"bond"}
	r = Authorize(bond(1), in)
	if !r.Allow || r.Checks["bond"] != "unsupported" || len(r.Reasons) != 0 {
		t.Fatalf("listed: %+v", r)
	}
	// without a bond_ref there is no bond check
	if r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 2, nil), g01DynIn(g)); !r.Allow {
		t.Fatalf("control: %+v", r)
	} else if _, has := r.Checks["bond"]; has {
		t.Fatalf("control carries bond: %+v", r.Checks)
	}
	// after every other reason: the first failure stays the decisive one
	in = g01DynIn(g)
	in.Operation = &Operation{Verb: "g01.other", Resource: "acct/1", Params: g01Params()}
	r = Authorize(bond(3), in)
	if r.Allow || r.Reason == bondRefused || r.Reasons[len(r.Reasons)-1] != bondRefused {
		t.Fatalf("order: %+v", r)
	}
}

// A required check's failure is never overwritten (require-pca.ts, "a required provenance_flow stays refused").
func TestParityRequiredFailureStays(t *testing.T) {
	const absent = "%s: required check is absent (default-deny: not enforced by this resource server)"
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	chain := []map[string]any{g}
	in := g01DynIn(g)
	if r := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), in); !r.Allow || r.Checks["provenance_flow"] == "fail" {
		t.Fatalf("control: %+v", r)
	}
	in = g01DynIn(g)
	in.Require = []string{"provenance_flow"}
	r := Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), in)
	if r.Allow || r.Decision != "deny" || r.Checks["provenance_flow"] != "fail" || !g01Has(r.Reasons, fmt.Sprintf(absent, "provenance_flow")) {
		t.Fatalf("require provenance_flow: %+v", r)
	}
	bond := g01Act(t, g, chain, k.agent, "", g01Now, 1, map[string]any{"bond_ref": "b1"})
	in = g01DynIn(g)
	in.Require, in.AllowUnsupported = []string{"bond"}, []string{"bond"}
	r = Authorize(bond, in)
	if r.Allow || r.Decision != "deny" || r.Checks["bond"] != "fail" || !g01Has(r.Reasons, fmt.Sprintf(absent, "bond")) {
		t.Fatalf("require bond, listed: %+v", r)
	}
	in.AllowUnsupported = nil
	r = Authorize(bond, in)
	if r.Allow || r.Checks["bond"] != "fail" || !g01Has(r.Reasons, bondRefused) {
		t.Fatalf("require bond, not listed: %+v", r)
	}
	in = g01DynIn(g)
	in.Require = []string{"bond"}
	if r = Authorize(g01Act(t, g, chain, k.agent, "", g01Now, 1, nil), in); r.Allow || r.Checks["bond"] != "fail" {
		t.Fatalf("require bond, no bond_ref: %+v", r)
	}
}

// With another escalate-class failure, a valid answer admits the action, unless a required check failed.
func TestParityRequiredFailureIsNotEscalated(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	a := signAnswer(t, sk, pub, grant, pcactn, nil, nil)
	if r := Authorize(pcactn, in(NewMemoryStateStore(), nil, nil)); r.Allow || r.Decision != "escalate" {
		t.Fatalf("control, no answer: %+v", r)
	}
	if r := Authorize(pcactn, in(NewMemoryStateStore(), a, []string{pub})); !r.Allow {
		t.Fatalf("control, answered: %+v", r)
	}
	i := in(NewMemoryStateStore(), nil, nil)
	i.Require = []string{"provenance_flow"}
	if r := Authorize(pcactn, i); r.Allow || r.Decision != "deny" || r.Escalation != nil || r.Checks["provenance_flow"] != "fail" {
		t.Fatalf("required, no answer: %+v", r)
	}
	i = in(NewMemoryStateStore(), a, []string{pub})
	i.Require = []string{"provenance_flow"}
	if r := Authorize(pcactn, i); r.Allow || r.Decision != "deny" || r.Checks["provenance_flow"] != "fail" {
		t.Fatalf("required, answered: %+v", r)
	}
}

// ---- B: budget_alloc

func TestParityBudgetAllocMonotone(t *testing.T) {
	bud := func(v any) map[string]any { return map[string]any{"type": "budget_alloc", "limit": v} }
	root, mid := newKey(t), newKey(t)
	build := func(parent any, extra ...any) []any {
		c0 := mkCap(t, root, mid.id, []any{parent}, "", nil)
		h, _ := CapHash(c0)
		c1 := mkCap(t, mid, "holder", append([]any{parent}, extra...), h, nil)
		return []any{c0, c1}
	}
	widen := "budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)"
	notNum := "budget_alloc caveat 1: limit must be a finite number >= 0"
	for _, c := range []struct {
		name  string
		chain []any
		want  string
	}{
		{"narrow", build(bud(json.Number("10")), bud(json.Number("5"))), ""},
		{"equal", build(bud(json.Number("10")), bud(json.Number("10"))), ""},
		{"zero", build(bud(json.Number("0")), bud(json.Number("0"))), ""},
		{"widen", build(bud(json.Number("10")), bud(json.Number("100"))), widen},
		{"fraction", build(bud(json.Number("1.5")), bud(json.Number("2.5"))), "budget_alloc caveat 1: allocation 2.5 widens the parent's carried allocation 1.5 (monotone: a child can only allocate <= its parent)"},
		{"another type between", build(bud(json.Number("10")), map[string]any{"type": "note"}, bud(json.Number("11"))), "budget_alloc caveat 2: allocation 11 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)"},
		{"negative", build(bud(json.Number("10")), bud(json.Number("-1"))), notNum},
		{"string", build(bud(json.Number("10")), bud("5")), notNum},
		{"missing", build(bud(json.Number("10")), map[string]any{"type": "budget_alloc"}), notNum},
		{"first negative", build(bud(json.Number("-1"))), "budget_alloc caveat 0: limit must be a finite number >= 0"},
	} {
		why, ok := VerifyChainPolicy(c.chain, root.id, true, nil, nil, nil)
		if why != c.want || ok != (c.want == "") {
			t.Errorf("%s: %q %v, want %q", c.name, why, ok, c.want)
		}
	}
}

// ---- C: zk_compliance at the core

func TestParityZkFailsAtTheCore(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	if v, _ := VerifyPCActnCoreWith(p, g, g01Now, g01Aud, VerifyOptions{InsecureSkipPlanRootCheck: true}); !v.Allow {
		t.Fatalf("control: %+v", v)
	}
	zk := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, map[string]any{"zk_compliance": map[string]any{"proof": "x"}})
	want := "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof"
	v, _ := VerifyPCActnCoreWith(zk, g, g01Now, g01Aud, VerifyOptions{InsecureSkipPlanRootCheck: true})
	if v.Allow || v.Reason != want || v.Checks["zk_compliance"] {
		t.Fatalf("core: %+v", v)
	}
	if v, _ := VerifyPCActnCoreWith(zk, g, g01Now, g01Aud, VerifyOptions{InsecureSkipPlanRootCheck: true, zkInAuthorize: true}); !v.Allow {
		t.Fatalf("Authorize decides it after revocation: %+v", v)
	}
	r := Authorize(zk, g01DynIn(g))
	if r.Allow || r.Checks["zk_compliance"] != "fail" || !g01Has(r.Reasons, want) {
		t.Fatalf("authorize: %+v", r)
	}
	// and the signature-only guard
	opts := RequirePCAOptions{InsecureSkipPlanRootCheck: true, Audience: g01Aud, Now: func() int64 { return g01Now }, SignatureOnly: true,
		ResolveGrant: func(string) (map[string]any, error) { return g, nil }}
	if got := serve(t, opts, p); got.code != 204 || got.calls != 1 {
		t.Fatalf("signature-only control: %+v", got)
	}
	if got := serve(t, opts, zk); got.code != 403 || got.calls != 0 {
		t.Fatalf("signature-only zk: %+v", got)
	}
}

// ---- D: allowedSuites on the guard

func TestParityGuardForwardsAllowedSuites(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	p := g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil)
	opts := RequirePCAOptions{InsecureSkipPlanRootCheck: true, Audience: g01Aud, Now: func() int64 { return g01Now }, SignatureOnly: true, AllowedSuites: []string{"ed25519"},
		ResolveGrant: func(string) (map[string]any, error) { return g, nil }}
	if got := serve(t, opts, p); got.code != 204 {
		t.Fatalf("listed: %+v", got)
	}
	opts.AllowedSuites = []string{}
	if got := serve(t, opts, p); got.code != 403 || got.calls != 0 {
		t.Fatalf("not listed: %+v", got)
	}
}

// ---- F: blueprint runtime_pins

func parityBlueprint(t *testing.T, op fxKey, key, status string, mut func(b map[string]any)) map[string]any {
	t.Helper()
	b := map[string]any{"v": jnum(1), "id": "bp1", "key": key, "ceiling": []any{}, "epoch": jnum(1), "status": status, "issued_at": jnum(1), "operator": op.id,
		"runtime_pins": []any{map[string]any{"model_id": "m"}}}
	if mut != nil {
		mut(b)
	}
	b["sig"] = signDomain(t, op, agentBlueprintDomain, b)
	return deepM(t, b)
}

func TestParityBlueprintRuntimePins(t *testing.T) {
	op := newKey(t)
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	check := func(b map[string]any) BlueprintDecision {
		reg := NewBlueprintRegistry([]string{op.id}, MemoryBlueprintKv())
		if code, _ := reg.Accept(b); code != "" {
			t.Fatalf("accept: %q", code)
		}
		return CheckBlueprints(chain, reg, jnum(2), "any", nil)
	}
	if d := check(parityBlueprint(t, op, "K", "active", nil)); d.Decision != "deny" || d.Code != "admission_required" || d.Blueprint != "bp1" {
		t.Fatalf("pinned: %+v", d)
	}
	if d := check(parityBlueprint(t, op, "K", "disabled", nil)); d.Code != "blueprint_disabled" {
		t.Fatalf("group kill: %+v", d)
	}
	if d := check(parityBlueprint(t, op, "K", "active", func(b map[string]any) {
		b["max_depth"] = jnum(1)
		chain = append(chain, map[string]any{"issuer": "inst", "holder": "x"})
	})); d.Code != "too_deep" {
		t.Fatalf("too_deep first: %+v", d)
	}
	chain = chain[:2]
	if d := check(parityBlueprint(t, op, "K", "active", func(b map[string]any) { delete(b, "runtime_pins") })); d.Decision != "allow" {
		t.Fatalf("control: %+v", d)
	}
	// the pins are signed
	forged := parityBlueprint(t, op, "K", "active", func(b map[string]any) { delete(b, "runtime_pins") })
	forged["runtime_pins"] = []any{map[string]any{"model_id": "m"}}
	if VerifyBlueprint(forged) {
		t.Fatal("pins added after signing verified")
	}
	pins := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"operator": "o"}
		}
		return out
	}
	for _, c := range []struct {
		name string
		pins any
		ok   bool
	}{
		{"every key", []any{map[string]any{"runtime_measurement": "a", "model_id": "b", "weights_digest": "c", "operator": "d", "spiffe_id": "e"}}, true},
		{"16", pins(16), true}, {"17", pins(17), false}, {"empty list", []any{}, false}, {"not a list", "x", false},
		{"empty pin", []any{map[string]any{}}, false}, {"unknown key", []any{map[string]any{"x": "y"}}, false},
		{"not a string", []any{map[string]any{"model_id": jnum(1)}}, false}, {"pin not an object", []any{"x"}, false},
		{"good then bad", []any{map[string]any{"model_id": "m"}, map[string]any{"x": "y"}}, false},
		{"256", []any{map[string]any{"model_id": strings.Repeat("m", 256)}}, true}, {"257", []any{map[string]any{"model_id": strings.Repeat("m", 257)}}, false},
	} {
		b := parityBlueprint(t, op, "K", "active", func(b map[string]any) { b["runtime_pins"] = c.pins })
		if got := VerifyBlueprint(b); got != c.ok {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// ---- G: registries under concurrent calls (the map access is what the runtime or -race catches)

func TestParityRegistriesConcurrent(t *testing.T) {
	op := newKey(t)
	lreg := NewLeaseRegistry(LeasePolicy{Authorities: []string{op.id}}, MemoryLeaseKv())
	breg := NewBlueprintRegistry([]string{op.id}, MemoryBlueprintKv())
	const n = 64
	leases, bps := make([]map[string]any, n), make([]map[string]any, n)
	for i := range leases {
		l := g04Lease()
		l["lease_id"] = fmt.Sprintf("L%d", i)
		leases[i] = g04SignLease(t, op, l)
		bps[i] = parityBlueprint(t, op, fmt.Sprintf("K%d", i), "active", func(b map[string]any) { delete(b, "runtime_pins") })
	}
	revRec := g04Rev()
	revRec["value"] = "none"
	rev := g04SignRev(t, op, revRec)
	var wg sync.WaitGroup
	chain := []any{map[string]any{"issuer": "root", "holder": "K0"}, map[string]any{"issuer": "K0", "holder": "inst"}}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r := lreg.Accept(leases[i], nil); !r.Ok {
				t.Errorf("lease %d: %+v", i, r)
			}
			lreg.Get("L0")
			lreg.Revoke(rev)
			CheckLease(leases[i], lreg, jnum(150))
			if code, _ := breg.Accept(bps[i]); code != "" {
				t.Errorf("blueprint %d: %q", i, code)
			}
			breg.Epoch()
			CheckBlueprints(chain, breg, jnum(2), "any", nil)
		}(i)
	}
	wg.Wait()
	for i := range leases {
		if lreg.Get(fmt.Sprintf("L%d", i)) == nil {
			t.Errorf("lost lease %d", i)
		}
	}
	if breg.Epoch() != 1 {
		t.Errorf("epoch %d", breg.Epoch())
	}
}

// ---- H: scope whitespace is JavaScript's \s

func TestParityScopeWhitespaceIsJS(t *testing.T) {
	for _, c := range []struct{ scope, want string }{
		{"a\ufeffb", "bad_field"}, {"a b", "bad_field"}, {"a\u00a0b", "bad_field"}, {"a\u2028b", "bad_field"},
		{"a\u0085b", ""}, // Go's unicode.IsSpace has NEL, \s does not
		{"cart:pay", ""},
	} {
		if got := ValidateA2ANeed(g07xNeed(func(m map[string]any) { m["scopes"] = []any{c.scope} })); got != c.want {
			t.Errorf("%q: %q, want %q", c.scope, got, c.want)
		}
	}
}

// ---- K: a panicking passport hook denies

func TestParityPassportHookPanics(t *testing.T) {
	sp, iss := g05Passport(t, false, nil)
	o := g05PassOpts(iss, g05Iat)
	o.Revoked = func(string, string, string) (bool, error) { panic("boom") }
	g05Want(t, "revocation panics", VerifyPassport(sp, o), "revocation_unavailable")
	o.Revoked = func(string, string, string) (bool, error) { return true, nil }
	g05Want(t, "revoked", VerifyPassport(sp, o), "revoked")
	o.Revoked = func(string, string, string) (bool, error) { return false, fmt.Errorf("down") }
	g05Want(t, "revocation errors", VerifyPassport(sp, o), "revocation_unavailable")

	hw, iss2 := g05Passport(t, true, map[string]any{"document": map[string]any{"nonce": "n"}, "at": g05Iat})
	o = g05PassOpts(iss2, g05Iat)
	o.Attest = func(map[string]any, PassportBinding) (PassportAttestation, error) { panic("boom") }
	g05Want(t, "attest panics", VerifyPassport(hw, o), "hardware_attestation_failed")
}

// ---- L: the Intel body comes from the signed bytes

func parityDup(t *testing.T, text, name string) string {
	t.Helper()
	raw, ok := rawJSONObject(text, name)
	if !ok {
		t.Fatalf("no %s", name)
	}
	forged := strings.ReplaceAll(raw, "UpToDate", "Revoked")
	if forged == raw {
		t.Fatalf("%s has no UpToDate", name)
	}
	out := strings.Replace(text, `,"signature":`, `,"`+name+`":`+forged+`,"signature":`, 1)
	if out == text {
		t.Fatalf("%s: no signature member", name)
	}
	return out
}

func TestParityIntelCollateralSignedBody(t *testing.T) {
	doc := loadAttestVectors(t)
	blobs, _ := doc["blobs"].(map[string]any)
	ran := 0
	for _, r := range doc["attestation_vectors"].([]any) {
		hr, err := hydrateBlobs(r, blobs)
		if err != nil {
			t.Fatal(err)
		}
		row := hr.(map[string]any)
		exp, _ := row["expect"].(map[string]any)
		ev, _ := row["evidence"].(map[string]any)
		col, _ := ev["collateral"].(map[string]any)
		info, _ := col["tcbInfoJson"].(string)
		qe, _ := col["qeIdentityJson"].(string)
		if exp["ok"] != true || !strings.Contains(info, "UpToDate") || !strings.Contains(qe, "UpToDate") {
			continue
		}
		honest := normJSON(t, runAttestationRow(t, row))
		for _, f := range []struct{ member, name, text string }{{"tcbInfoJson", "tcbInfo", info}, {"qeIdentityJson", "enclaveIdentity", qe}} {
			col[f.member] = parityDup(t, f.text, f.name)
			if got := normJSON(t, runAttestationRow(t, row)); !reflect.DeepEqual(got, honest) {
				t.Errorf("%v, duplicate %s: %v, honest %v", row["id"], f.name, got, honest)
			}
			col[f.member] = f.text
		}
		if ran++; ran == 3 {
			return
		}
	}
	if ran == 0 {
		t.Fatal("no vector carries collateral")
	}
}

func TestParitySignedBodyUnit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"status":"UpToDate"}`
	h := sha256.Sum256([]byte(raw))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	text := `{"tcbInfo":` + raw + `,"tcbInfo":{"status":"Forged"},"signature":"` + hex.EncodeToString(sig) + `"}`
	body, why := verifySignedJSON(text, "tcbInfo", certKey{pub: &key.PublicKey})
	if why != "" || body["status"] != "UpToDate" {
		t.Fatalf("%v %q", body, why)
	}
	// a later non-object duplicate does not matter either
	text = strings.Replace(text, `{"status":"Forged"}`, `1`, 1)
	if body, why := verifySignedJSON(text, "tcbInfo", certKey{pub: &key.PublicKey}); why != "" || body["status"] != "UpToDate" {
		t.Fatalf("%v %q", body, why)
	}
}

// ---- M: the AMD ARK pin comes only from family

func TestParityAmdPinNotFromConfig(t *testing.T) {
	cfg := map[string]any{"family": "milan", "binding": "report-data", "trustAnchorArkSpkiSha384": "attacker",
		"policy": map[string]any{"measurements": []any{"aa"}}}
	amdConformancePin = false
	defer func() { amdConformancePin = true }()
	v, err := newAmdVerifier(cfg)
	if err != nil || v.pin != amdARKSpkiSHA384["milan"] {
		t.Fatalf("production: %v %v", v, err)
	}
	amdConformancePin = true
	if v, err = newAmdVerifier(cfg); err != nil || v.pin != "attacker" {
		t.Fatalf("harness: %v %v", v, err)
	}
	cfg["trustAnchorArkSpkiSha384"] = jnum(1)
	if v, err = newAmdVerifier(cfg); err != nil || v.pin != amdARKSpkiSHA384["milan"] {
		t.Fatalf("not a string: %v %v", v, err)
	}
}

// ---- N, O: a malformed list or floor never means none

func parityCfg(t *testing.T, s string) map[string]any {
	t.Helper()
	v, err := jsonLenient([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func TestParityMalformedListsRefused(t *testing.T) {
	m96 := `"` + zeros96 + `"`
	amd := func(extra string) string {
		return `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]` + extra + `}}`
	}
	dcap := func(extra string) string {
		return `{"binding":"report-data","policy":{"mrtds":[` + m96 + `]` + extra + `}}`
	}
	maa := func(extra string) string {
		return `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["aa"]` + extra + `}}`
	}
	for _, c := range []struct{ vendor, cfg, want string }{
		{"amd-sev-snp", amd(`,"hostData":["aa",1]`), "createAmdSnpVerifier: policy.hostData must be an array of strings"},
		{"amd-sev-snp", amd(`,"chipIds":[1]`), "createAmdSnpVerifier: policy.chipIds must be an array of strings"},
		{"amd-sev-snp", amd(`,"hostData":"aa"`), "createAmdSnpVerifier: policy.hostData must be an array of strings"},
		{"amd-sev-snp", amd(`,"hostData":null,"chipIds":[]`), ""},
		{"intel-tdx-dcap", dcap(`,"fmspcs":["aa",1]`), "createIntelDcapVerifier: policy.fmspcs must be an array of strings"},
		{"intel-tdx-dcap", dcap(`,"rtmrs":[1]`), "createIntelDcapVerifier: policy.rtmrs must be an array of strings"},
		{"intel-tdx-dcap", dcap(`,"collateral":{"acceptStatuses":"UpToDate"}`), "createIntelDcapVerifier: collateral policy.acceptStatuses must be a list"},
		{"intel-tdx-dcap", dcap(`,"collateral":{"minTcbEvaluationDataNumber":"abc"}`), "createIntelDcapVerifier: collateral policy.minTcbEvaluationDataNumber must be a number"},
		{"intel-tdx-dcap", dcap(`,"collateral":{"minTcbEvaluationDataNumber":true}`), "createIntelDcapVerifier: collateral policy.minTcbEvaluationDataNumber must be a number"},
		{"azure-maa", maa(`,"sevSnpHostData":["aa",1]`), "createAzureMaaVerifier: policy.sevSnpHostData must be an array of strings"},
		{"azure-maa", maa(`,"tdxRtmrs":[1]`), "createAzureMaaVerifier: policy.tdxRtmrs must be an array of strings"},
		{"azure-maa", maa(`,"tdxMrtds":[1]`), "createAzureMaaVerifier: policy.tdxMrtds must be an array of strings"},
		{"azure-maa", maa(`,"tdxAllowedTcbStatuses":"UpToDate"`), "createAzureMaaVerifier: policy.tdxAllowedTcbStatuses must be a list"},
	} {
		_, err := VerifierFromConfig(c.vendor, parityCfg(t, c.cfg))
		if got := fmt.Sprint(err); (c.want == "" && err != nil) || (c.want != "" && got != c.want) {
			t.Errorf("%s: %v, want %q", c.cfg, err, c.want)
		}
	}
	// a status list stays as given: a non-string entry matches nothing and does not restore the default
	d, err := newDcapVerifier(parityCfg(t, dcap(`,"collateral":{"acceptStatuses":["SWHardeningNeeded",1],"minTcbEvaluationDataNumber":"16"}`)))
	if err != nil || !d.collateralPol.hasAccept || !reflect.DeepEqual(d.collateralPol.acceptStatuses, []string{"SWHardeningNeeded"}) {
		t.Fatalf("%+v %v", d, err)
	}
	// the reference's `<` converts a string floor with Number()
	if !d.collateralPol.hasMinEval || d.collateralPol.minEval != 16 {
		t.Fatalf("string floor dropped: %+v", d.collateralPol)
	}
	d, err = newDcapVerifier(parityCfg(t, dcap(`,"collateral":{"minTcbEvaluationDataNumber":17}`)))
	if err != nil || d.collateralPol.hasAccept || d.collateralPol.minEval != 17 {
		t.Fatalf("%+v %v", d, err)
	}
	m, err := newMaaVerifier(parityCfg(t, maa(`,"tdxAllowedTcbStatuses":["UpToDate",1]`)))
	if err != nil || !m.policy.hasTdxStatuses || !reflect.DeepEqual(m.policy.tdxStatuses, []string{"UpToDate"}) {
		t.Fatalf("%+v %v", m, err)
	}
}

// ---- P: OCSP

func TestParityOcspRefusals(t *testing.T) {
	f := g02newFx(t)
	resp := f.responder(t, nil, f.inter, f.interK)
	respA := g02att(t, resp.Raw)
	withCerts := func(certs []byte) []byte {
		return f.mod(t, func(r *g02rsp) { r.rid, r.certs, r.signer = g02byName(respA), certs, f.respK })
	}
	for _, c := range []struct {
		name string
		der  []byte
		want string
	}{
		{"embedded certificate that does not parse", withCerts(derTLV(0xa0, derTLV(0x30, derTLV(0x30, []byte{0x01, 0x01, 0x00})))), "OCSP response rejected: "},
		{"good then one that does not parse", withCerts(derTLV(0xa0, derTLV(0x30, resp.Raw, derTLV(0x30)))), "OCSP response rejected: "},
		{"certs wrapper of two members", withCerts(derTLV(0xa0, derTLV(0x30, resp.Raw), derTLV(0x30))), "OCSP response rejected: malformed certs"},
	} {
		got := verifyNvidiaOcspResponse(c.der, f.leafA, f.interA, f.chain, f.nowMs)
		if got.ok || !strings.HasPrefix(got.reason, c.want) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	this := g02now.Add(-time.Hour)
	utc := derTLV(0xa0, derTLV(0x17, []byte("260601000000Z")))
	if got := verifyNvidiaOcspResponse(f.fresh(t, this, this, utc), f.leafA, f.interA, f.chain, f.nowMs); got != g02no("OCSP response rejected: malformed nextUpdate") {
		t.Errorf("UTCTime nextUpdate: %+v", got)
	}
	two := derTLV(0xa0, g02gt(g02now), g02gt(g02now))
	if got := verifyNvidiaOcspResponse(f.fresh(t, this, this, two), f.leafA, f.interA, f.chain, f.nowMs); got != g02no("OCSP response rejected: malformed nextUpdate") {
		t.Errorf("two nextUpdate members: %+v", got)
	}

	// PKCS#1 under an rsa-pss key: the same key verifies as an rsaEncryption key only
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tbs := []byte("tbs")
	d := sha256.Sum256(tbs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	const sha256RSA = "1.2.840.113549.1.1.11"
	if !ocspSigOK(sha256RSA, tbs, sig, certKey{pub: &rk.PublicKey, typ: "rsa"}) {
		t.Error("rsa key")
	}
	if ocspSigOK(sha256RSA, tbs, sig, certKey{pub: &rk.PublicKey, typ: "rsa-pss"}) {
		t.Error("rsa-pss key")
	}
}

// NVIDIA OCSP SingleResponse strictness: the pkijs schema refuses these (attest-nvidia-ocsp.ts).
func TestParityOcspSingleResponseStrict(t *testing.T) {
	f := g02newFx(t)
	at := g02now.Add(-time.Hour)
	past, ahead := derTLV(0xa0, g02gt(g02now.Add(-time.Minute))), derTLV(0xa0, g02gt(g02now.Add(time.Hour)))
	ext := derTLV(0xa1, derTLV(0x30))
	malformedStatus := g02no("malformed certStatus")
	malformedSingle := g02rej("malformed SingleResponse")
	// a SingleResponse of another certificate is parsed as well
	other := func(tail ...[]byte) []byte {
		return f.mod(t, func(r *g02rsp) {
			r.singles = [][]byte{
				g02single(g02certID(t, f.interA, big.NewInt(99)), g02good, g02gt(at), tail...),
				g02single(g02certID(t, f.interA, f.leaf.SerialNumber), g02good, g02gt(at)),
			}
		})
	}
	for _, c := range []struct {
		name string
		der  []byte
		want ocspResult
	}{
		{"constructed [0] status", f.withStatus(t, derTLV(0xa0)), malformedStatus},
		{"constructed [2] status", f.withStatus(t, derTLV(0xa2)), malformedStatus},
		{"primitive [1] status", f.withStatus(t, []byte{0x81, 0x00}), malformedStatus},
		{"constructed [3] status", f.withStatus(t, derTLV(0xa3)), g02no("unrecognised certStatus")},
		{"nextUpdate and extensions", f.fresh(t, at, at, ahead, ext), g02ok("good")},
		{"extensions alone", f.fresh(t, at, at, ext), g02ok("good")},
		{"past nextUpdate and extensions", f.fresh(t, at, at, past, ext), g02no("response is stale (past nextUpdate)")},
		{"past nextUpdate under an unknown tag", f.fresh(t, at, at, derTLV(0xa2, g02gt(g02now.Add(-time.Minute)))), malformedSingle},
		{"extensions before nextUpdate", f.fresh(t, at, at, ext, past), malformedSingle},
		{"two nextUpdates", f.fresh(t, at, at, ahead, past), malformedSingle},
		{"two extensions", f.fresh(t, at, at, ext, ext), malformedSingle},
		{"an element after the extensions", f.fresh(t, at, at, ahead, ext, derTLV(0xa2)), malformedSingle},
		{"other certificate, control", other(ahead, ext), g02ok("good")},
		{"other certificate, unknown tag", other(derTLV(0xa2)), malformedSingle},
		{"other certificate, malformed nextUpdate", other(derTLV(0xa0)), g02rej("malformed nextUpdate")},
	} {
		if got := verifyNvidiaOcspResponse(c.der, f.leafA, f.interA, f.chain, f.nowMs); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// certCheckIssued rows: a certificate is built with exact extension bytes (x509.ParseCertificate would refuse several).
func TestParityCertCheckIssued(t *testing.T) {
	oid := func(s ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(s) }
	aki, ski, san := oid(2, 5, 29, 35), oid(2, 5, 29, 14), oid(2, 5, 29, 17)
	ext := func(id asn1.ObjectIdentifier, v []byte) func(*x509.Certificate) {
		return func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: id, Value: v})
		}
	}
	key := g02key(t)
	skid := []byte{1, 2, 3}
	rootT := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "up"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: skid}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	up := g02att(t, rootDER)
	parent := &x509.Certificate{Subject: rootT.Subject}
	child := func(muts ...func(*x509.Certificate)) *attCert {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "child"}}
		for _, m := range muts {
			m(tmpl)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return g02att(t, der)
	}
	keyid := func(b ...byte) []byte { return derTLV(0x80, b) }
	serial := func(b ...byte) []byte { return derTLV(0x82, b) }
	dirName := derTLV(0xa1, derTLV(0xa4, up.RawIssuer))
	otherName := derTLV(0xa1, derTLV(0xa4, derTLV(0x30)))
	for _, c := range []struct {
		name string
		c    *attCert
		up   *attCert
		want bool
	}{
		{"no AKI", child(), up, true},
		{"same key id", child(ext(aki, derTLV(0x30, keyid(1, 2, 3)))), up, true},
		{"other key id", child(ext(aki, derTLV(0x30, keyid(1, 2, 4)))), up, false},
		{"serial", child(ext(aki, derTLV(0x30, serial(7)))), up, true},
		{"other serial", child(ext(aki, derTLV(0x30, serial(8)))), up, false},
		{"directoryName", child(ext(aki, derTLV(0x30, dirName))), up, true},
		{"other directoryName", child(ext(aki, derTLV(0x30, otherName))), up, false},
		{"second directoryName not read", child(ext(aki, derTLV(0x30, derTLV(0xa1, derTLV(0xa4, up.RawIssuer), derTLV(0xa4, derTLV(0x30)))))), up, true},
		{"non-directory name", child(ext(aki, derTLV(0x30, derTLV(0xa1, derTLV(0x82, []byte("x")))))), up, true},
		{"all three", child(ext(aki, derTLV(0x30, keyid(1, 2, 3), dirName, serial(7)))), up, true},
		{"out of order", child(ext(aki, derTLV(0x30, serial(7), keyid(1, 2, 3)))), up, false},
		{"repeated", child(ext(aki, derTLV(0x30, keyid(1, 2, 3), keyid(1, 2, 3)))), up, false},
		{"unknown member", child(ext(aki, derTLV(0x30, derTLV(0x83, []byte{1})))), up, false},
		{"AKI not a SEQUENCE", child(ext(aki, derTLV(0x04, []byte{1}))), up, false},
		{"AKI trailing bytes", child(ext(aki, append(derTLV(0x30, keyid(1, 2, 3)), 0))), up, false},
		{"AKI members overrun", child(ext(aki, []byte{0x30, 2, 0x80, 5})), up, false},
		{"bad generalNames", child(ext(aki, []byte{0x30, 4, 0xa1, 2, 0x82, 5})), up, false},
		{"good SAN", child(ext(san, derTLV(0x30, derTLV(0x82, []byte("x"))))), up, true},
		{"SAN entry that is no GeneralName", child(ext(san, derTLV(0x30, derTLV(0x04, []byte("x"))))), up, false},
		{"SAN not a SEQUENCE", child(ext(san, derTLV(0x04, nil))), up, false},
		{"SAN trailing bytes", child(ext(san, append(derTLV(0x30), 0))), up, false},
		{"SAN overrun", child(ext(san, []byte{0x30, 2, 0x82, 5})), up, false},
	} {
		if got := certCheckIssued(c.c, c.up); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}

	// the issuer's own members
	mk := func(mut func(*x509.Certificate)) *attCert {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "up"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
		mut(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return g02att(t, der)
	}
	plain := child()
	if certCheckIssued(plain, mk(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature })) {
		t.Error("issuer keyUsage without keyCertSign")
	}
	if !certCheckIssued(plain, mk(func(c *x509.Certificate) { c.KeyUsage = 0 })) {
		t.Error("issuer without keyUsage")
	}
	if certCheckIssued(plain, mk(func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "stranger"} })) {
		t.Error("name link")
	}
	noSKI, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "up"}, KeyUsage: x509.KeyUsageCertSign},
		&x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "up"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if !certCheckIssued(child(ext(aki, derTLV(0x30, keyid(9)))), g02att(t, noSKI)) {
		t.Error("an issuer without a subject key id cannot disagree on the key id")
	}
	if certCheckIssued(plain, mk(ext(san, derTLV(0x30, derTLV(0x04, []byte("x")))))) {
		t.Error("issuer SAN that does not decode")
	}
	if certCheckIssued(child(ext(aki, derTLV(0x30, keyid(1, 2, 3)))), mk(ext(ski, derTLV(0x03, []byte{0, 1})))) {
		t.Error("issuer SKI that is not an OCTET STRING")
	}
	if certCheckIssued(child(ext(aki, derTLV(0x30, keyid(1, 2, 3)))), mk(ext(ski, append(derTLV(0x04, []byte{1, 2, 3}), 0)))) {
		t.Error("issuer SKI trailing bytes")
	}
}

// ---- Q: exact PSS salt, outer and tbs signature algorithms

// parityPSSParams is RSASSA-PSS-params over SHA-256 with an explicit salt length.
func parityPSSParams(salt byte) []byte {
	sha := derTLV(0x30, g02oid("2.16.840.1.101.3.4.2.1"))
	mgf := derTLV(0x30, g02oid("1.2.840.113549.1.1.8"), sha)
	return derTLV(0x30, derTLV(0xa0, sha), derTLV(0xa1, mgf), derTLV(0xa2, derTLV(0x02, []byte{salt})))
}

// paritySignNoSalt is EMSA-PSS with an empty salt (RFC 8017 section 9.1.1), which crypto/rsa cannot produce.
func paritySignNoSalt(k *rsa.PrivateKey, digest []byte) []byte {
	emLen := (k.N.BitLen() - 1 + 7) / 8
	hh := sha256.New()
	hh.Write(make([]byte, 8))
	hh.Write(digest)
	h := hh.Sum(nil)
	db := make([]byte, emLen-len(h)-1)
	db[len(db)-1] = 1
	var counter [4]byte
	for off := 0; off < len(db); counter[3]++ {
		m := sha256.New()
		m.Write(h)
		m.Write(counter[:])
		for _, b := range m.Sum(nil) {
			if off < len(db) {
				db[off] ^= b
				off++
			}
		}
	}
	db[0] &= 0xff >> (8*emLen - (k.N.BitLen() - 1))
	em := append(append(db, h...), 0xbc)
	return new(big.Int).Exp(new(big.Int).SetBytes(em), k.D, k.N).FillBytes(make([]byte, k.Size()))
}

func TestParityPSSSaltIsExact(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tbs := []byte("tbs")
	d := sha256.Sum256(tbs)
	salted, err := rsa.SignPSS(rand.Reader, rk, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	noSalt := paritySignNoSalt(rk, d[:])
	k := certKey{pub: &rk.PublicKey, typ: "rsa"}
	for _, c := range []struct {
		name string
		salt byte
		sig  []byte
		want bool
	}{
		{"salt 0, no salt", 0, noSalt, true},
		{"salt 0, a 32-byte salt", 0, salted, false},
		{"salt 32, a 32-byte salt", 32, salted, true},
		{"salt 32, no salt", 32, noSalt, false},
	} {
		child := &attCert{SigOID: "1.2.840.113549.1.1.10", SigParams: parityPSSParams(c.salt), RawTBS: tbs, Signature: c.sig}
		if got := certSigOK(child, k); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestParityOuterAndTbsSigAlgMustMatch(t *testing.T) {
	key := g02key(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	good := g02att(t, der)
	if !certSigOKBy(good, good) {
		t.Fatal("control")
	}
	// the same certificate with an unsigned NULL added to the outer algorithm: same OID, same signature
	var c struct{ TBS, Alg, Sig asn1.RawValue }
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		t.Fatal(err)
	}
	alg := derTLV(0x30, c.Alg.Bytes, []byte{0x05, 0x00})
	bad := derTLV(0x30, c.TBS.FullBytes, alg, c.Sig.FullBytes)
	if !bytes.Equal(good.Signature, g02att(t, bad).Signature) {
		t.Fatal("fixture")
	}
	if certSigOKBy(g02att(t, bad), good) {
		t.Fatal("outer algorithm differing from the tbs one verified")
	}
}
