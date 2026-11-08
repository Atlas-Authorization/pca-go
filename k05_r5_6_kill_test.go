package pca

// r5n6: survivor kills for attest_cert.go, pca.go, lease.go, tool_schema.go, actions_confirm.go, approval.go, keyorder.go,
// revocation_nonmembership.go, policyclasses.go and attest_v8json.go. Every expected value below is the reference behaviour (the
// OpenSSL message the certificate engine imitates, or the TypeScript result of the same input), not what a mutant happens to do.

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// r5n6Guard reports a panic that escapes f (a deferred recover that went missing) as a failure of the test.
func r5n6Guard(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("%s: panic escaped: %v", what, x)
		}
	}()
	f()
}

// ───────────────────────────────────────────────────────────── attest_cert.go

func TestR5N6_ParseCertDERBrokenChildLists(t *testing.T) {
	for name, mut := range map[string]func(c *g03cert){
		"validity":  func(c *g03cert) { c.validity = derTLV(0x30, []byte{0x17, 0x05}) },
		"spki":      func(c *g03cert) { c.spki = derTLV(0x30, []byte{0x30, 0x05}) },
		"extension": func(c *g03cert) { c.tail = g03exts(derTLV(0x30, []byte{0x06, 0x05})) },
	} {
		c := g03base()
		mut(&c)
		got, err := parseCertDER(c.der())
		if got != nil || err == nil || err.Error() != osslNested {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
}

func TestR5N6_KeyOfCertUnreadableRSAKey(t *testing.T) {
	for name, oid := range map[string][]byte{"rsa": g03oidRsaEnc, "rsa-pss": g03oidRsaPss} {
		spki := derTLV(0x30, derTLV(0x30, oid, []byte{0x05, 0x00}), derTLV(0x03, []byte{0x00, 0x01, 0x02}))
		r5n6Guard(t, name, func() {
			k, err := keyOfCert(&attCert{RawSPKI: spki})
			if err == nil || err.Error() != g03unsupp || k.pub != nil {
				t.Errorf("%s: %+v %v", name, k, err)
			}
		})
	}
}

func TestR5N6_AlgIDRefusals(t *testing.T) {
	alg := func(b []byte) (string, []byte, error) {
		e, err := readCertElem(b, 0, len(b), 0x30)
		if err != nil {
			t.Fatal(err)
		}
		return algID(b, e)
	}
	if o, p, err := alg(derTLV(0x30, []byte{0x06, 0x05})); err == nil || err.Error() != osslNested || o != "" || p != nil {
		t.Errorf("overrunning member: %q %v %v", o, p, err)
	}
	defer func(old func([]byte, derTlv) (string, error)) { certOIDText = old }(certOIDText)
	certOIDText = func([]byte, derTlv) (string, error) { return "", errors.New("r5n6 oid") }
	if o, p, err := alg(derTLV(0x30, g03oidSha256, []byte{0x05, 0x00})); err == nil || err.Error() != osslObject || o != "" || p != nil {
		t.Errorf("an OID that cannot be rendered: %q %v %v", o, p, err)
	}
}

func TestR5N6_AkidMatches(t *testing.T) {
	ext := func(v []byte) *attCert { return &attCert{exts: []lenientExt{{oid: "2.5.29.35", value: v}}} }
	up := func(ski []byte) *attCert {
		u := &attCert{Serial: []byte{5}, RawIssuer: []byte("iss")}
		if ski != nil {
			u.exts = []lenientExt{{oid: "2.5.29.14", value: ski}}
		}
		return u
	}
	keyid := func(s string) []byte { return derTLV(0x80, []byte(s)) }
	serial := derTLV(0x82, []byte{5})
	seq := func(parts ...[]byte) []byte { return derTLV(0x30, parts...) }
	for _, c := range []struct {
		name string
		c    *attCert
		up   *attCert
		want bool
	}{
		{"no extension", &attCert{}, up(nil), true},
		{"not a SEQUENCE", ext([]byte{0x31, 0x00}), up(nil), false},
		{"trailing byte", ext(append(seq(), 0)), up(nil), false},
		{"overrunning member", ext([]byte{0x30, 0x02, 0x80, 0x05}), up(nil), false},
		{"key id, issuer without key id", ext(seq(keyid("k"))), up(nil), true},
		{"key id equal", ext(seq(keyid("k"))), up(derTLV(0x04, []byte("k"))), true},
		{"key id differs", ext(seq(keyid("k"))), up(derTLV(0x04, []byte("j"))), false},
		{"empty key id, empty issuer key id", ext(seq(keyid(""))), up([]byte{}), false},
		{"issuer key id with a trailing byte", ext(seq(keyid("k"))), up(append(derTLV(0x04, []byte("k")), 0)), false},
		{"issuer key id of the wrong tag", ext(seq(keyid("k"))), up([]byte{0x31, 0x00}), false},
		{"names overrun", ext(seq(derTLV(0xa1, []byte{0x02, 0x05}))), up(nil), false},
		{"directoryName equal", ext(seq(derTLV(0xa1, derTLV(0xa4, []byte("iss"))))), up(nil), true},
		{"directoryName differs", ext(seq(derTLV(0xa1, derTLV(0xa4, []byte("xxx"))))), up(nil), false},
		{"only the first directoryName", ext(seq(derTLV(0xa1, derTLV(0xa4, []byte("iss")), derTLV(0xa4, []byte("xxx"))))), up(nil), true},
		{"serial equal", ext(seq(serial)), up(nil), true},
		{"serial differs", ext(seq(derTLV(0x82, []byte{6}))), up(nil), false},
		{"unknown member", ext(seq(derTLV(0x83, []byte{1}))), up(nil), false},
		{"repeated member", ext(seq(serial, serial)), up(nil), false},
		{"serial before key id", ext(seq(serial, keyid("k"))), up(nil), false},
		{"key id then serial", ext(seq(keyid("k"), serial)), up(nil), true},
	} {
		if got := certAkidMatches(c.c, c.up); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// An issuer whose DER the strict reader refuses (a trailing byte) never issues, however well its other members agree.
func TestR5N6_CertCheckIssuedUnreadableIssuer(t *testing.T) {
	key := g02key(t)
	upT := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "up"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	upDER, err := x509.CreateCertificate(rand.Reader, upT, upT, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	childT := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "child"}}
	childDER, err := x509.CreateCertificate(rand.Reader, childT, upT, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	up, child := g02att(t, upDER), g02att(t, childDER)
	if !certCheckIssued(child, up) {
		t.Fatal("control: a plain issuer does not issue")
	}
	bad := *up
	bad.Raw = append(append([]byte{}, up.Raw...), 0)
	if certCheckIssued(child, &bad) {
		t.Error("an issuer whose DER has a trailing byte issued")
	}
}

// ───────────────────────────────────────────────────────────── pca.go

func TestR5N6_HashAndMerkleErrors(t *testing.T) {
	bad := make(chan int)
	if h, err := HashCanonical(bad); h != "" || err == nil {
		t.Errorf("HashCanonical: %q %v", h, err)
	}
	if r, err := MerkleRoot([]any{bad}); r != "" || err == nil {
		t.Errorf("MerkleRoot: %q %v", r, err)
	}
	// a leaf that cannot be hashed has no hash to compare: the empty root must not be matched by an empty hash
	proof := map[string]any{"path": []any{}, "index": json.Number("0"), "size": json.Number("1")}
	if VerifyInclusion("", proof, bad) {
		t.Error("an unhashable leaf verified against the empty root")
	}
}

func TestR5N6_SignableHopBodyPqPk(t *testing.T) {
	hop := func(pq any) map[string]any {
		c := map[string]any{"issuer": "i", "holder": "h", "caveats": []any{}, "parent": "p", "alg": "ml-dsa-65"}
		if pq != nil {
			c["pq_pk"] = pq
		}
		return c
	}
	for name, pq := range map[string]any{"absent": nil, "not a string": json.Number("5")} {
		body, ok := signableHopBody(hop(pq))
		if !ok {
			t.Fatalf("%s: suite refused", name)
		}
		if _, has := body["pq_pk"]; has {
			t.Errorf("%s: pq_pk bound into the body", name)
		}
		if body["alg"] != "ml-dsa-65" {
			t.Errorf("%s: alg %v", name, body["alg"])
		}
	}
	if body, _ := signableHopBody(hop("KEY")); body["pq_pk"] != "KEY" {
		t.Errorf("a string pq_pk is bound: %v", body["pq_pk"])
	}
}

func TestR5N6_RootPqAuthorityNeedsAPin(t *testing.T) {
	root := map[string]any{"issuer": "i", "pq_pk": ""}
	if _, ok := rootPqAuthority(root, "i", nil, nil); ok {
		t.Error("no pin and no stored grant gave an authority")
	}
	if _, ok := rootPqAuthority(root, "i", map[string]string{"other": ""}, nil); ok {
		t.Error("a pin for another issuer gave an authority")
	}
	if a, ok := rootPqAuthority(root, "i", map[string]string{"i": ""}, nil); !ok || !a.hasTrusted {
		t.Errorf("an own pin that agrees: %+v %v", a, ok)
	}
	if _, ok := rootPqAuthority(root, "i", map[string]string{"i": "x"}, nil); ok {
		t.Error("an own pin that differs gave an authority")
	}
}

func TestR5N6_WireAndChainFaultsAreVerdicts(t *testing.T) {
	oldW, oldC := wireFault, chainFault
	defer func() { wireFault, chainFault = oldW, oldC }()
	wired, chained := false, false
	wireFault = func() { wired = true; panic("r5n6 wire") }
	chainFault = func() { chained = true; panic("r5n6 chain") }
	r5n6Guard(t, "ValidateWireV2", func() {
		if got := ValidateWireV2(nil); got != "malformed: r5n6 wire" || !wired {
			t.Errorf("ValidateWireV2: %q (fault ran: %v)", got, wired)
		}
	})
	r5n6Guard(t, "VerifyChainPolicy", func() {
		why, ok := VerifyChainPolicy(nil, "", false, nil, nil, nil)
		if ok || why != "malformed capability chain: r5n6 chain" || !chained {
			t.Errorf("VerifyChainPolicy: %q %v (fault ran: %v)", why, ok, chained)
		}
	})
}

// ───────────────────────────────────────────────────────────── lease.go

func TestR5N6_LeaseWellFormedNumbersAreIntegers(t *testing.T) {
	for _, c := range []struct{ key, val string }{
		{"seq", "1.5"}, {"issued_at", "100.5"}, {"renewed_at", "100.5"}, {"expires_at", "200.5"}, {"max_ttl", "1000.5"},
	} {
		l := g04Lease()
		l[c.key] = json.Number(c.val)
		if m, ok := leaseWellFormed(l); ok || m != nil {
			t.Errorf("%s = %s accepted", c.key, c.val)
		}
	}
}

func TestR5N6_LeasePickKeepsOnlyPresentKeys(t *testing.T) {
	got := leasePick(map[string]any{"a": 1, "c": 3}, []string{"a", "b", "c"})
	if _, has := got["b"]; has || len(got) != 2 || got["a"] != 1 || got["c"] != 3 {
		t.Errorf("leasePick: %v", got)
	}
}

// ───────────────────────────────────────────────────────────── tool_schema.go

func TestR5N6_CheckSchemaValueEdges(t *testing.T) {
	n := 0
	if got := checkSchemaValue(map[string]any{"type": "weird"}, "x", "p", 1, &n); got != "p: unknown type" {
		t.Errorf("unknown type: %q", got)
	}
	// maxItems above the absolute cap is cut to the cap
	arr := make([]any, AbsoluteMaxArrayItems+1)
	for i := range arr {
		arr[i] = true
	}
	spec := map[string]any{"type": "array", "maxItems": jnum(AbsoluteMaxArrayItems + 10), "items": map[string]any{"type": "boolean"}}
	n = 0
	if got := checkSchemaValue(spec, arr, "p", 1, &n); got != "p: exceeds maxItems" {
		t.Errorf("array over the absolute cap: %q", got)
	}
}

func TestR5N6_SchemaEqNonScalar(t *testing.T) {
	if schemaEq(nil, "") || schemaEq([]any{}, "") || schemaEq(map[string]any{}, "") {
		t.Error("a non-scalar equals the empty string")
	}
	if !schemaEq("a", "a") || schemaEq("a", "b") || schemaEq("a", nil) {
		t.Error("string comparison")
	}
}

func TestR5N6_EvaluateAgentCaveatsFailedNames(t *testing.T) {
	ok, failed := EvaluateAgentCaveats([]any{}, nil, nil, nil)
	if !ok || failed == nil || len(failed) != 0 {
		t.Errorf("no caveats: %v %#v", ok, failed)
	}
	ok, failed = EvaluateAgentCaveats([]any{map[string]any{"type": json.Number("5")}, "x", map[string]any{"type": "nope"}}, nil, nil, nil)
	if ok || !reflect.DeepEqual(failed, []string{"<malformed>", "<malformed>", "nope"}) {
		t.Errorf("malformed names: %v %v", ok, failed)
	}
}

func TestR5N6_EvaluatorFaultsFailClosed(t *testing.T) {
	oldT, oldC, oldS := toolSchemaFault, agentCaveatsFault, agentStockCaveats
	defer func() { toolSchemaFault, agentCaveatsFault, agentStockCaveats = oldT, oldC, oldS }()
	var ranT, ranC, ranS bool
	toolSchemaFault = func() { ranT = true; panic("r5n6 tool schema") }
	agentCaveatsFault = func() { ranC = true; panic("r5n6 caveats") }
	agentStockCaveats = func(any, map[string]any) (bool, []string) { ranS = true; panic("r5n6 stock") }
	r5n6Guard(t, "EvaluateToolSchema", func() {
		if ok, reason := EvaluateToolSchema(nil, nil); ok || reason != "evaluation error (fail closed)" || !ranT {
			t.Errorf("EvaluateToolSchema: %v %q (fault ran: %v)", ok, reason, ranT)
		}
	})
	r5n6Guard(t, "evaluateAgentCaveats", func() {
		ok, failed := EvaluateAgentCaveats([]any{}, nil, nil, nil)
		if ok || !reflect.DeepEqual(failed, []string{"<evaluation error>"}) || !ranC {
			t.Errorf("EvaluateAgentCaveats: %v %v (fault ran: %v)", ok, failed, ranC)
		}
	})
	r5n6Guard(t, "agentCaveatSatisfied", func() {
		if agentCaveatSatisfied(map[string]any{"type": "max_spend"}, nil, nil, nil, &regexBudget{}) || !ranS {
			t.Errorf("agentCaveatSatisfied accepted a caveat whose evaluator faulted (fault ran: %v)", ranS)
		}
	})
}

// ───────────────────────────────────────────────────────────── actions_confirm.go

func TestR5N6_ConfirmationFaultAndRegistryDigest(t *testing.T) {
	s := g06acNew(t)
	att := func() map[string]any { return s.attest(t, "w", []any{}, nil) }
	if got := confirmationError(att(), "w", nil, coreRegistry, s.pins, g06yes); got != "" {
		t.Fatalf("control: %q", got)
	}
	// a fault inside the confirmation (here the caller's trait check) is "malformed confirmation", never a confirmation
	r5n6Guard(t, "confirmationError", func() {
		got := confirmationError(att(), "w", nil, coreRegistry, s.pins, func([]string) bool { panic("r5n6 final") })
		if got != "malformed confirmation" {
			t.Errorf("faulting trait check: %q", got)
		}
	})
	// a registry that has no digest (a lone surrogate cannot be canonicalised) confirms nothing
	badReg := Registry{"x": TraitDef{ID: "x", Card: "\xed\xa0\x80"}}
	if got := confirmationError(att(), "w", nil, badReg, s.pins, g06yes); got != "the trait registry has no digest" {
		t.Errorf("registry without a digest: %q", got)
	}
	// a verb whose facts cannot be digested
	if got := verbConfirmationError(map[string]any{"x": "\xed\xa0\x80"}, coreRegistry, map[string]any{}); got != "malformed confirmation" {
		t.Errorf("verb facts without a digest: %q", got)
	}
}

// ───────────────────────────────────────────────────────────── approval.go

func TestR5N6_ApprovalRefusalsReturnNoValue(t *testing.T) {
	if d, err := ApprovalRenderDigest("not a render"); d != "" || err == nil {
		t.Errorf("ApprovalRenderDigest: %q %v", d, err)
	}
	if c, err := ApprovalChallenge("x", "y"); c != "" || err == nil {
		t.Errorf("ApprovalChallenge: %q %v", c, err)
	}
	if w, err := BindingWords("x"); w != "" || err == nil {
		t.Errorf("BindingWords: %q %v", w, err)
	}
	if s, err := MinorToDecimal(-1, 2); s != "" || err == nil {
		t.Errorf("MinorToDecimal: %q %v", s, err)
	}
}

// A currency that is neither a literal nor a {from} reference is unresolved, even when a parameter happens to carry the name a
// missing reference would print.
func TestR5N6_RenderApprovalCurrencyWithoutLiteralOrReference(t *testing.T) {
	def := map[string]any{"resource": map[string]any{"scope": "s"}, "params": map[string]any{
		"amt":   map[string]any{"type": "integer", "unit": map[string]any{"kind": "money", "exp": jnum(2), "ccy": jnum(5)}},
		"<nil>": map[string]any{"type": "string"},
	}}
	r, err := RenderApproval(def, map[string]any{"amt": jnum(5), "<nil>": "USD"}, true)
	if r != nil || err == nil || !strings.HasPrefix(err.Error(), "render_unresolved_currency") {
		t.Errorf("%v %v", r, err)
	}
}

// ───────────────────────────────────────────────────────────── keyorder.go

func TestR5N6_KeyOrderStaleEntryAndFault(t *testing.T) {
	m := map[string]any{"a": 1, "b": 2}
	recordKeyOrder(m, []string{"b", "a"})
	if got := jsKeys(m); !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Fatalf("control: %v", got)
	}
	// same member count, different members: the recorded order no longer describes the map
	delete(m, "b")
	m["c"] = 3
	if got := jsKeys(m); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Errorf("stale entry used: %v", got)
	}
	runtime.KeepAlive(m)

	old := keyOrderFault
	defer func() { keyOrderFault = old }()
	ran := false
	keyOrderFault = func() { ran = true; panic("r5n6 key order") }
	m2 := map[string]any{"c": 1, "d": 2}
	r5n6Guard(t, "recordKeyOrder", func() { recordKeyOrder(m2, []string{"d", "c"}) })
	if !ran {
		t.Error("the fault seam did not run")
	}
	if _, ok := g14koEntry(m2); ok {
		t.Error("an entry survived the fault")
	}
	runtime.KeepAlive(m2)
}

// ───────────────────────────────────────────────────────────── revocation_nonmembership.go, policyclasses.go

func TestR5N6_RevLeafOKUnhashableID(t *testing.T) {
	root, ok := bindRevRoot(1, "")
	if !ok {
		t.Fatal("bindRevRoot")
	}
	proof := map[string]any{"index": jnum(0), "size": jnum(1), "path": []any{}}
	if revLeafOK(root, 1, "\xed\xa0\x80", proof) {
		t.Error("an id that cannot be hashed matched the root of an empty hash")
	}
}

func TestR5N6_ClassVerdictsMemberNotAnObject(t *testing.T) {
	if got := ClassVerdictsError([]any{"x"}); got != "policy_classes[0] must be an object" {
		t.Errorf("%q", got)
	}
}
