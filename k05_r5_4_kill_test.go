package pca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// r5n4: reason texts, early exits and guards for action_schema.go, actions.go, decision.go, strictjson.go, k3.go,
// intent_artifacts.go, attest_nvidia.go, blueprint.go and runtime_claim.go (the reference texts are TS packages/pca/src).

func r5n4PV(d map[string]any, x any) string {
	c, r := paramValueViolationReason(d, x)
	return c + "|" + r
}

func TestR5N4ValueDomains(t *testing.T) {
	obj := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	abc := []any{"a", "b", "c"}
	for _, c := range []struct {
		name string
		d    map[string]any
		x    any
		want string
	}{
		{"string ok", obj("type", "string"), "a", "|"},
		{"string not string", obj("type", "string"), 5, "bad_type|expected a string"},
		{"string too long", obj("type", "string", "max_len", 3), "abcd", "out_of_domain|longer than 3 UTF-8 bytes"},
		{"string not in values", obj("type", "string", "values", abc), "z", "out_of_domain|not one of the declared values"},
		{"string in values", obj("type", "string", "values", abc), "b", "|"},
		{"string bad format", obj("type", "string", "format", "email"), "nope", "out_of_domain|not a valid email"},
		{"string good format", obj("type", "string", "format", "email"), "a@b.co", "|"},
		{"datetime ok", obj("type", "datetime"), "2020-01-01T00:00:00Z", "|"},
		{"datetime not string", obj("type", "datetime"), 5, "bad_type|expected an RFC 3339 UTC string"},
		{"datetime bad", obj("type", "datetime"), "2020-02-30T00:00:00Z", "out_of_domain|not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z"},
		{"duration not int", obj("type", "duration"), "x", "bad_type|expected a safe integer (milliseconds)"},
		{"duration ok", obj("type", "duration", "min", 1, "max", 9), 5, "|"},
		{"duration below", obj("type", "duration", "min", 5), 4, "out_of_domain|below min 5"},
		{"duration above", obj("type", "duration", "max", 9), 10, "out_of_domain|above max 9"},
		{"integer not int", obj("type", "integer"), "x", "bad_type|expected a safe integer"},
		{"integer ok", obj("type", "integer", "min", 5, "max", 9), 7, "|"},
		{"integer at min", obj("type", "integer", "min", 5, "max", 9), 5, "|"},
		{"integer at max", obj("type", "integer", "min", 5, "max", 9), 9, "|"},
		{"integer below", obj("type", "integer", "min", 5, "max", 9), 4, "out_of_domain|below min 5"},
		{"integer above", obj("type", "integer", "min", 5, "max", 9), 10, "out_of_domain|above max 9"},
		{"boolean ok", obj("type", "boolean"), true, "|"},
		{"boolean not", obj("type", "boolean"), 1, "bad_type|expected a boolean"},
		{"date ok", obj("type", "date"), "2020-02-28", "|"},
		{"date not string", obj("type", "date"), 1, "bad_type|expected a YYYY-MM-DD string"},
		{"date bad", obj("type", "date"), "2020-02-30", "out_of_domain|not a calendar date YYYY-MM-DD"},
		{"set ok", obj("type", "set", "values", abc), []any{"a", "b"}, "|"},
		{"set not array", obj("type", "set", "values", abc), "a", "bad_type|expected an array of strings"},
		{"set non-string member", obj("type", "set", "values", abc), []any{1}, "bad_type|expected an array of strings"},
		{"set duplicate", obj("type", "set", "values", abc), []any{"a", "a"}, "out_of_domain|set members must be distinct"},
		{"set undeclared member", obj("type", "set", "values", abc), []any{"z"}, "out_of_domain|set member not among the declared values"},
		{"set too small", obj("type", "set", "values", abc, "min_items", 2), []any{"a"}, "out_of_domain|set size outside the declared bounds"},
		{"set too big", obj("type", "set", "values", abc, "max_items", 1), []any{"a", "b"}, "out_of_domain|set size outside the declared bounds"},
		{"array ok strings", obj("type", "array"), []any{"a"}, "|"},
		{"array ok ints", obj("type", "array", "items", "integer", "min", 0, "max", 5), []any{0, 5}, "|"},
		{"array not array", obj("type", "array"), "a", "bad_type|expected an array"},
		{"array item below", obj("type", "array", "items", "integer", "min", 0, "max", 5), []any{-1}, "out_of_domain|array item outside min/max"},
		{"array item above", obj("type", "array", "items", "integer", "min", 0, "max", 5), []any{6}, "out_of_domain|array item outside min/max"},
		{"array too short", obj("type", "array", "min_items", 2), []any{"a"}, "out_of_domain|array length outside the declared bounds"},
		{"array too long", obj("type", "array", "max_items", 1), []any{"a", "b"}, "out_of_domain|array length outside the declared bounds"},
		{"unknown type", obj("type", "zzz"), "a", "bad_type|unknown declared type"},
	} {
		if got := r5n4PV(c.d, c.x); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if c, r := formatViolation(map[string]any{}, "x"); c != "" || r != "" {
		t.Errorf("no format: %q %q", c, r)
	}
}

func TestR5N4ConformReasons(t *testing.T) {
	doc := map[string]any{"verbs": []any{map[string]any{"verb": "v", "params": map[string]any{
		"action.params.x": map[string]any{"type": "string"}}}}}
	res, why := conformActionReason(doc, "v", "not an object")
	if res.Code != "params_not_object" || why != "params must be a JSON object" {
		t.Errorf("params not object: %+v %q", res, why)
	}
	res, why = conformActionReason(doc, "v", map[string]any{})
	if res.Code != "missing_param" || res.Path != "action.params.x" || why != "required parameter 'action.params.x' is missing" {
		t.Errorf("missing: %+v %q", res, why)
	}
	res, why = conformActionReason(doc, "v", map[string]any{"x": "s"})
	if !res.OK || res.Code != "" || why != "" {
		t.Errorf("ok: %+v %q", res, why)
	}
	res, why = conformActionReason(doc, "v", map[string]any{"x": 5})
	if res.Code != "bad_type" || why != "'action.params.x': expected a string" {
		t.Errorf("violation: %+v %q", res, why)
	}
}

func TestR5N4ShapeMessages(t *testing.T) {
	if got := paramDeclError("action.params.x", "not an object", nil, false); got != "action.params.x: declaration must be an object" {
		t.Errorf("declaration: %q", got)
	}
	g08Eq(t, "traits_digest", actionSchemaShapeError(g08DocV2("traits_digest", "x"), false), "traits_digest must be a canonical base64url SHA-256 digest")
	g08Eq(t, "traits_digest ok", actionSchemaShapeError(g08DocV2("traits_digest", g08B32), false), "")
	g08Eq(t, "sig not an object", actionSchemaShapeError(g08DocV2("sig", "x"), true), "sig must be an object")
}

func TestR5N4ActionsHelpers(t *testing.T) {
	for _, c := range []struct {
		s, class string
		want     bool
	}{
		{"123", "digits", true}, {"12a", "digits", false},
		{"0af", "hex", true}, {"0g", "hex", false},
		{"aZ9", "alnum", true}, {"a-", "alnum", false},
		{"a-_9", "slug", true}, {"A", "slug", false},
		{"0af-", "uuid", true}, {"g", "uuid", false},
	} {
		if got := inIDClass(c.s, c.class); got != c.want {
			t.Errorf("inIDClass(%q, %q) = %v", c.s, c.class, got)
		}
	}
	orig := []any{map[string]any{"k": "v"}, "s"}
	cp := deepCopy(orig).([]any)
	cp[1] = "changed"
	cp[0].(map[string]any)["k"] = "changed"
	if orig[1] != "s" || orig[0].(map[string]any)["k"] != "v" {
		t.Errorf("deepCopy of an array shares its elements: %v", orig)
	}
	if got := defJSONProfileError(make(chan int), 0); got != "only JSON values are allowed" {
		t.Errorf("profile: %q", got)
	}
	// normalizeParam owns its values slice
	p := map[string]any{"values": []any{"a", "b"}}
	out := normalizeParam(p)
	out["values"].([]any)[0] = "z"
	if p["values"].([]any)[0] != "a" {
		t.Error("normalizeParam aliases the values slice")
	}
	// normalizeDef keeps only by / map / default of a reversibility map, as a copy
	rm := map[string]any{"by": "p", "map": map[string]any{"x": "reversible"}, "extra": "junk"}
	d := map[string]any{"resource": map[string]any{"type": "t", "id": "*", "scope": "own"}, "params": map[string]any{}, "reversibility": rm}
	nrev := normalizeDef(d)["reversibility"].(map[string]any)
	if _, has := nrev["extra"]; has || nrev["by"] != "p" {
		t.Errorf("reversibility members: %v", nrev)
	}
	nrev["map"].(map[string]any)["x"] = "q"
	if rm["map"].(map[string]any)["x"] != "reversible" {
		t.Error("normalizeDef aliases the reversibility map")
	}
	root, err := packRoot(nil)
	if root != "" || err == nil || !strings.HasPrefix(err.Error(), "empty_pack") {
		t.Errorf("empty pack: %q %v", root, err)
	}
	root, err = packRoot([]string{"a", "a"})
	if root != "" || err == nil || !strings.HasPrefix(err.Error(), "duplicate_def") {
		t.Errorf("duplicate pack: %q %v", root, err)
	}
}

func TestR5N4DecisionHelpers(t *testing.T) {
	if got := SignalCeiling("x"); got != "deny" {
		t.Errorf("SignalCeiling: %q", got)
	}
	if got := DecisionOf(map[string]any{"allow": false}); got != "deny" {
		t.Errorf("no checks: %q", got)
	}
	if got := DecisionOf(map[string]any{"checks": 5}); got != "deny" {
		t.Errorf("checks not an object: %q", got)
	}
	if got := DecisionOf(map[string]any{"checks": map[string]any{"c": "fail"}, "reasons": []any{"c: escalate: x"}}); got != "escalate" {
		t.Errorf("escalate: %q", got)
	}

	// decideFault injects a fault into both fail-closed catches
	old := decideFault
	decideFault = func() { panic("late") }
	res := DecideTighten(map[string]any{})
	ok, why := DecideUnits(map[string]any{})
	decideFault = old
	if res.Outcome != "deny" || res.Reason != "evaluation error (fail closed): late" || res.Offending == nil || len(res.Offending) != 0 {
		t.Errorf("DecideTighten fault: %+v", res)
	}
	if ok || why != "evaluation error (fail closed): late" {
		t.Errorf("DecideUnits fault: %v %q", ok, why)
	}

	// a non-string single_source entry is skipped, never read as ""
	pred := map[string]any{"where": []any{map[string]any{"field": "env.world."}}}
	r2 := DecideTighten(map[string]any{"single_source": []any{5, "a"}, "predicates": []any{[]any{pred}}})
	if r2.Outcome != "ok" || len(r2.Offending) != 0 {
		t.Errorf("single_source: %+v", r2)
	}
	r3 := DecideTighten(map[string]any{})
	if r3.Outcome != "ok" || r3.Offending == nil || len(r3.Offending) != 0 {
		t.Errorf("no predicates: %+v", r3)
	}

	// collectPredicatePaths skips an out-of-scope predicate, not the rest of the list
	found := map[string]bool{}
	p1 := map[string]any{"verb": "o", "where": []any{map[string]any{"field": "action.params.a"}}}
	p2 := map[string]any{"verb": "v", "where": []any{map[string]any{"field": "action.params.b"}}}
	collectPredicatePaths([]any{"not a list", []any{p1, p2}}, func(p any) bool { return p.(map[string]any)["verb"] == "v" }, found)
	if found["action.params.a"] || !found["action.params.b"] {
		t.Errorf("scoped paths: %v", found)
	}

	// DecideUnits: an undeclared tag is skipped, the next one is still judged
	in := map[string]any{
		"units": map[string]any{
			"action.params.a": map[string]any{"kind": "x"},
			"action.params.b": map[string]any{"kind": "money"},
		},
		"verb":         "v",
		"schema_units": map[string]any{"u": map[string]any{"kind": "count"}},
		"verb_params":  map[string]any{"action.params.b": map[string]any{"unit": "u"}},
	}
	ok, why = DecideUnits(in)
	if ok || why != "'action.params.b' is declared as count by the action schema but the policy term is tagged money (unit confusion)" {
		t.Errorf("unit confusion: %v %q", ok, why)
	}
	ok, why = DecideUnits(map[string]any{"units": map[string]any{}, "verb": "v", "verb_params": map[string]any{}})
	if !ok || why != "" {
		t.Errorf("valid units: %v %q", ok, why)
	}

	// FoldV2Reasons: a passing or reasonless check does not end the fold
	got := FoldV2Reasons(nil, []V2CheckResult{
		{Name: "a", OK: true},
		{Name: "c", OK: false},
		{Name: "b", OK: false, Reason: "r", HasReason: true},
	})
	if len(got) != 1 || got[0] != "b: r" {
		t.Errorf("fold: %v", got)
	}
}

func TestR5N4StrictJSONStrErrors(t *testing.T) {
	for _, c := range []struct{ in, msg string }{
		{`"abc`, "unterminated string"},
		{`"\`, "unterminated string"},
		{"\"a\x01\"", "raw control character in string"},
		{`"\uZZZZ"`, `bad \u escape`},
		{`"\ud800"`, "lone surrogate in string"},
		{`"\udc00"`, "lone surrogate in string"},
		{`"\q"`, "unknown escape"},
	} {
		p := &jparser{s: c.in, strict: true}
		s, err := p.str()
		if s != "" || err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%q: %q %v, want %q", c.in, s, err, c.msg)
		}
	}
	if got := numberLexemeError("a.5"); got != "non-finite number" {
		t.Errorf("unparseable decimal: %q", got)
	}
	if got := numberLexemeError("1.5"); got != "" {
		t.Errorf("1.5: %q", got)
	}
}

func TestR5N4K3(t *testing.T) {
	if d, ok := AuthorityDigest("x"); d != "" || ok {
		t.Errorf("non-object authority: %q %v", d, ok)
	}
	if d, ok := AuthorityDigest(map[string]any{"verbs": []any{"a"}}); d != "" || ok {
		t.Errorf("no resources: %q %v", d, ok)
	}
	if d, ok := AuthorityDigest(map[string]any{"verbs": []any{"a"}, "resources": []any{"r"}}); d == "" || !ok {
		t.Errorf("good authority: %q %v", d, ok)
	}

	// a bundle that signs fine but whose digest wrapper is one level too deep is malformed, never accepted
	k := newKey(t)
	opts := BundleVerifyOptions{Signers: []string{k.id}, Threshold: 1, VerifierVersion: "1.0"}
	found := false
	for n := 1; n <= 40 && !found; n++ {
		x := any([]any{})
		for i := 1; i < n; i++ {
			x = []any{x}
		}
		b := g13k3Bundle()
		b["x"] = x
		if _, err := canonBytes(withoutKeys(b, "sigs")); err != nil {
			break
		}
		if _, ok := BundleDigest(b); ok {
			continue
		}
		found = true
		if v := VerifyBundle(g13k3SignBundle(t, b, []fxKey{k}), opts); v.OK || v.Code != "malformed" || v.Reason != "bundle is not canonicalizable" {
			t.Errorf("deep bundle: %+v", v)
		}
	}
	if !found {
		t.Fatal("no bundle depth separates the body from its digest wrapper")
	}

	// a grant whose authority is not an object cannot be merged
	p := newKey(t)
	approved := []any{}
	nr := map[string]any{"id": "n1", "grant_id": "g1", "status": "pending", "needs": []any{}}
	sig := signDomain(t, p, needApproveDomain, map[string]any{"need": "n1", "grant": "g1", "rev": jnum(1), "approved": approved})
	g := map[string]any{"principal": p.id, "rev": jnum(1), "authority": "not an object"}
	var v NeedVerdict
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		v = VerifyNeedApproval(nr, g, approved, sig, true)
	}()
	if v.OK || v.Code != "bad_request" {
		t.Errorf("bad authority: %+v", v)
	}
}

func TestR5N4IntentArtifacts(t *testing.T) {
	const dom = "r5n4/dom\x00"
	pq := newWBPQKey(t)
	art := signArtPQ(t, pq, dom, map[string]any{"x": jnum(1)})
	if !verifyArtifactSig(dom, art, "holder", pq.pk) {
		t.Fatal("pure PQ artifact under a pinned pq key refused")
	}
	for _, bad := range []any{nil, 5} {
		if verifyArtifactSig(dom, art, bad, pq.pk) {
			t.Errorf("artifact verified under pinned signer %v", bad)
		}
	}
	noSig := map[string]any{"x": jnum(1), "alg": art["alg"], "pq_pk": art["pq_pk"], "sig": nil}
	if verifyArtifactSig(dom, noSig, "holder", pq.pk) {
		t.Error("artifact without a sig verified")
	}

	dv := map[string]any{"sig": map[string]any{"kid": "k"}}
	first := []any{map[string]any{"kid": "k", "alg": "ed25519"}, map[string]any{"kid": "k", "alg": "zzz"}}
	if got := actionSchemaSuiteReason(dv, first); got != "" {
		t.Errorf("first key wins: %q", got)
	}
	if got := actionSchemaSuiteReason(dv, []any{map[string]any{"kid": "k", "alg": "zzz"}}); got != UnsupportedSuite {
		t.Errorf("unsupported key alg: %q", got)
	}
	r := map[string]any{}
	if got := receiptSuiteReason(r, []any{map[string]any{"keys": []any{map[string]any{"alg": "zzz"}}}}); got != UnsupportedSuite {
		t.Errorf("unsupported entry alg: %q", got)
	}
	if got := receiptSuiteReason(r, []any{map[string]any{"keys": []any{map[string]any{"alg": "ed25519"}}}}); got != "" {
		t.Errorf("supported entry alg: %q", got)
	}
}

func TestR5N4NvidiaHostAssertedOpaque(t *testing.T) {
	r := newG10nvRig(t)
	now := int64(1_800_000_000_000)
	raw, err := attestationBindingBytes(*testBinding)
	if err != nil {
		t.Fatal(err)
	}
	nonce := sha256Sum(raw)
	d1 := []byte{1, 1, 1}
	v, err := VerifierFromConfig("nvidia-gpu-spdm", map[string]any{"rootSpkiSha256": []any{g10nvPin(r.root)},
		"policy": map[string]any{"measurements": map[string]any{"1": hex.EncodeToString(d1)}}})
	if err != nil {
		t.Fatal(err)
	}
	b := r.signed(t, g10nvRaw(nonce, 1, g10nvBlock(1, g10nvDMTF(d1)), nil))
	res := v.Verify(map[string]any{"evidence": base64.StdEncoding.EncodeToString(b), "certChainPem": g10nvPEM(r.leaf, r.root)}, testBinding, now)
	if !res.OK {
		t.Fatalf("report: %+v", res)
	}
	if _, has := res.HostAsserted["driver_version"]; has {
		t.Error("driver_version asserted without an opaque driver TLV")
	}
	if _, has := res.HostAsserted["vbios_version"]; has {
		t.Error("vbios_version asserted without an opaque vbios TLV")
	}

	// a CA whose BasicConstraints reads cA TRUE and then fails to parse is no CA
	key := g10nvP384(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "bad basic constraints"}, NotBefore: r.nb, NotAfter: r.na,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x05, 0x01, 0x01, 0xff, 0x05, 0x00}}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if info, rerr := readCertRoleInfo(der); rerr == nil || !info.hasBasicConstraints || !info.ca {
		t.Fatalf("fixture: %+v %v", info, rerr)
	}
	if certIsCA(&attCert{Raw: der}) {
		t.Error("a certificate with unreadable BasicConstraints is a CA")
	}
}

func TestR5N4BlueprintExpiry(t *testing.T) {
	op := newKey(t)
	reg := NewBlueprintRegistry([]string{op.id}, MemoryBlueprintKv())
	b := parityBlueprint(t, op, "K", "active", func(b map[string]any) {
		delete(b, "runtime_pins")
		b["expires_at"] = jnum(1000)
	})
	if code, _ := reg.Accept(b); code != "" {
		t.Fatalf("accept: %q", code)
	}
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	if d := CheckBlueprints(chain, reg, jnum(999), "any", nil); d.Decision != "allow" {
		t.Errorf("before expiry: %+v", d)
	}
	if d := CheckBlueprints(chain, reg, jnum(1000), "any", nil); d.Decision != "deny" || d.Code != "blueprint_expired" {
		t.Errorf("at expiry: %+v", d)
	}
}

func TestR5N4RuntimeClaimRefusesAnExtraMember(t *testing.T) {
	k := newKey(t)
	pinned := []string{k.id}
	if got := VerifiedRuntimeClass(g07rcClaim(t, k, nil), pinned, "pd", []string{"ed"}, json.Number("150")); got != "os_confined" {
		t.Fatalf("baseline: %q", got)
	}
	extra := g07rcClaim(t, k, func(m map[string]any) { m["extra"] = json.Number("1") })
	if got := VerifiedRuntimeClass(extra, pinned, "pd", []string{"ed"}, json.Number("150")); got != "none" {
		t.Errorf("signed claim with an extra member: %q", got)
	}
	if got := VerifiedRuntimeClass("x", pinned, "pd", []string{"ed"}, json.Number("150")); got != "none" {
		t.Errorf("non-object claim: %q", got)
	}
}
