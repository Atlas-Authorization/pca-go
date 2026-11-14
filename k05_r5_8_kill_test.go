package pca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

// r5n8: kills for executor.go, attest_jws.go, attest_der.go, assurance.go, attest_intel.go, attest_nvidia_rim.go, workflow.go,
// saferegex.go and intent_v2.go. Each test pins the behaviour the Go port already shares with the TypeScript reference (reasons
// and results are the ones the shared vectors and differential oracles use); no limit or text is invented here.

// ---- executor.go:69 ------------------------------------------------------------------------------------------------------

func TestR5N8ExecutorRecheckRevocationUnknown(t *testing.T) {
	grant := map[string]any{"id": "g"}
	for name, f := range map[string]func(_, _ map[string]any) (bool, error){
		"error": func(_, _ map[string]any) (bool, error) { return false, errors.New("revocation store down") },
		"panic": func(_, _ map[string]any) (bool, error) { panic("boom") },
	} {
		in := AuthorizeInput{Risk: InsecureCalmRisk, ResolveGrant: func(string) (map[string]any, error) { return grant, nil }, IsRevoked: f}
		rc, err := NewExecutor(ExecutorOptions{Authorize: in}).recheck(func() int64 { return 1 })(g10exHandle(nil))
		if err != nil || rc.OK || rc.Reason != "revocation could not be checked" {
			t.Errorf("%s: %+v %v", name, rc, err)
		}
	}
}

// ---- attest_jws.go:93,96,167,169,171 --------------------------------------------------------------------------------------

func r5n8Seg(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestR5N8ParseJWTHeaderMembers(t *testing.T) {
	tok := func(hdr string) string { return r5n8Seg(hdr) + "." + r5n8Seg(`{}`) + ".AA" }
	p, err := parseJWT(tok(`{"alg":"ES256","kid":5,"x5c":"abc"}`), "p")
	if err != nil {
		t.Fatal(err)
	}
	if p.hasKid || p.kid != "" || p.hasX5c || p.x5c != nil {
		t.Errorf("a non-string kid and a non-list x5c are absent: %+v", p)
	}
	p, err = parseJWT(tok(`{"alg":"ES256","kid":"k1","x5c":["a","b"]}`), "p")
	if err != nil {
		t.Fatal(err)
	}
	if !p.hasKid || p.kid != "k1" || !p.hasX5c || !reflect.DeepEqual(p.x5c, []string{"a", "b"}) {
		t.Errorf("a string kid and a string list x5c are read: %+v", p)
	}
}

func TestR5N8JWKECKeyCurves(t *testing.T) {
	for _, c := range []struct {
		crv   string
		curve elliptic.Curve
		size  int
	}{{"P-256", elliptic.P256(), 32}, {"P-384", elliptic.P384(), 48}, {"P-521", elliptic.P521(), 66}} {
		k, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x := base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, c.size)))
		y := base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, c.size)))
		ck, err := jwkECKey(c.crv, x, y)
		if err != nil {
			t.Fatalf("%s: %v", c.crv, err)
		}
		pub, ok := ck.pub.(*ecdsa.PublicKey)
		if !ok || pub.Curve.Params().Name != c.crv || ck.typ != "ec" {
			t.Errorf("%s: %+v", c.crv, ck)
		}
	}
	const want = "error:1E08010C:DECODER routines::unsupported"
	if _, err := jwkECKey("P-192", "AA", "AA"); err == nil || err.Error() != want {
		t.Errorf("an unknown curve: %v", err)
	}
	if _, err := jwkRSAKey("", "AQAB"); err == nil || err.Error() != want {
		t.Errorf("an empty modulus: %v", err)
	}
	if _, err := jwkRSAKey("AQAB", "AQ"); err == nil || err.Error() != want {
		t.Errorf("exponent 1: %v", err)
	}
}

// ---- attest_der.go:233,241,252,416,432,435 --------------------------------------------------------------------------------

func TestR5N8OidToDottedErrorsReturnNoText(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		tag  byte
		want string
	}{
		{"wrong tag", []byte{0x2a}, 0x04, "extension OID is malformed"},
		{"empty", []byte{}, 0x06, "extension OID is malformed"},
		{"non-minimal arc", []byte{0x80, 0x01}, 0x06, "extension OID has a non-minimal arc"},
		{"truncated", []byte{0x81}, 0x06, "extension OID is truncated"},
	} {
		got, err := oidToDotted(c.b, derTlv{tag: c.tag, start: 0, end: len(c.b)})
		if got != "" || err == nil || err.Error() != c.want {
			t.Errorf("%s: %q %v, want an error %q and no text", c.name, got, err, c.want)
		}
	}
}

func TestR5N8UnrecognisedCriticalExtensionNone(t *testing.T) {
	for name, cert := range map[string][]byte{
		"non-critical unknown":           g09dRoleCert(g09dExt(g09dRaw(0x2a), false, nil)),
		"critical but recognised":        g09dRoleCert(g09dExt(g09dRaw(0x55, 0x1d, 0x13), true, nil)),
		"critical key usage (2.5.29.15)": g09dRoleCert(g09dExt(g09dRaw(0x55, 0x1d, 0x0f), true, nil)),
	} {
		if oid, found, err := unrecognisedCriticalExtension(cert, nil); oid != "" || found || err != nil {
			t.Errorf("%s: %q %v %v", name, oid, found, err)
		}
	}
}

// ---- assurance.go ---------------------------------------------------------------------------------------------------------

func TestR5N8AssuranceReportSetKeepsPosition(t *testing.T) {
	var r AssuranceReport
	r.Set("x", CheckAssurance{Outcome: "pass"})
	r.Set("y", CheckAssurance{Outcome: "pass"})
	r.Set("x", CheckAssurance{Outcome: "fail"})
	if got := r.Names(); !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Fatalf("Names %v", got)
	}
	if c, ok := r.Get("x"); !ok || c.Outcome != "fail" {
		t.Fatalf("replaced entry %+v", c)
	}
}

func TestR5N8AssuranceReportFromMapMembers(t *testing.T) {
	m := map[string]any{
		"a": map[string]any{"outcome": "pass", "vendor": "v1", "ceremony": "c1", "suites": []any{"s1", "s2"}, "t": float64(2)},
		"b": map[string]any{"outcome": "pass"},
	}
	r := AssuranceReportFromMap(m)
	a, _ := r.Get("a")
	if a.Vendor != "v1" || a.Ceremony != "c1" || !reflect.DeepEqual(a.Suites, []string{"s1", "s2"}) || a.T == nil || *a.T != 2 {
		t.Errorf("a: %+v", a)
	}
	b, _ := r.Get("b")
	if b.Vendor != "" || b.Ceremony != "" || b.Suites != nil || b.T != nil {
		t.Errorf("b: members that are absent stay absent: %+v", b)
	}
}

func TestR5N8AwaitingAuditSchemes(t *testing.T) {
	for s, want := range map[string]bool{"frost": true, "frost_dkg": true, "mpc": true, "": false, "frost2": false, "shamir": false, "FROST": false} {
		if got := isAwaitingAuditScheme(s); got != want {
			t.Errorf("isAwaitingAuditScheme(%q) = %v", s, got)
		}
	}
}

func TestR5N8UnmetAssurance(t *testing.T) {
	one := func(name string, c CheckAssurance) AssuranceReport {
		var r AssuranceReport
		r.Set(name, c)
		return r
	}
	// an unregistered requirement is never met by any evidence
	if got := UnmetAssurance(one("attestation", CheckAssurance{Outcome: "pass", Level: "multi_root"}), AssuranceRequirement{Attestation: "bogus"}); got != "assurance: bogus attestation required but the evidence is multi_root" {
		t.Errorf("unknown attestation requirement: %q", got)
	}
	if got := UnmetAssurance(one("zk_compliance", CheckAssurance{Outcome: "pass", Level: "groth16"}), AssuranceRequirement{Zk: "bogus"}); got != "assurance: zk compliance (bogus) required but the evidence is groth16" {
		t.Errorf("unknown zk requirement: %q", got)
	}
	// attested_vm_hardware refuses a prover key that is not bound to hardware, whatever the rank
	const unbound = "assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence"
	for _, lvl := range []string{"attested_vm", "unknown", ""} {
		if got := UnmetAssurance(one("zk_compliance", CheckAssurance{Outcome: "pass", Level: lvl}), AssuranceRequirement{Zk: "attested_vm_hardware"}); got != unbound {
			t.Errorf("level %q is not bound to hardware: %q", lvl, got)
		}
	}
	for _, lvl := range []string{"attested_vm_hw", "stark", "groth16"} {
		if got := UnmetAssurance(one("zk_compliance", CheckAssurance{Outcome: "pass", Level: lvl}), AssuranceRequirement{Zk: "attested_vm_hardware"}); got != "" {
			t.Errorf("level %q meets attested_vm_hardware: %q", lvl, got)
		}
	}
	// an entry that is not a passing awaiting-audit one does not stop the scan for the ones after it
	var r AssuranceReport
	r.Set("a", CheckAssurance{Outcome: "fail"})
	r.Set("b", CheckAssurance{Outcome: "pass"})
	r.Set("c", CheckAssurance{Outcome: "pass", AwaitingAudit: true})
	if got := UnmetAssurance(r, AssuranceRequirement{}); got != "assurance: c rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it" {
		t.Errorf("scan: %q", got)
	}
}

// ---- attest_intel.go:305,435 ----------------------------------------------------------------------------------------------

// The leaf is the FIRST certificate that issues no other: with a chain and an orphan after it, the chain is the path walked and
// the orphan is what the connectivity check names.
func TestR5N8PckChainFirstLeafWins(t *testing.T) {
	rk := g08Key(t)
	rt := g08CATmpl("r5n8 root", 1)
	root := g08MakeCert(t, rt, rt, &rk.PublicKey, rk)
	lk := g08Key(t)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "r5n8 leaf"}, NotBefore: g08nb, NotAfter: g08na}
	leaf := g08MakeCert(t, lt, rt, &lk.PublicKey, rk)
	ork := g08Key(t)
	ot := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "r5n8 orphan"}, NotBefore: g08nb, NotAfter: g08na}
	orphan := g08MakeCert(t, ot, g08CATmpl("r5n8 absent issuer", 3), &ork.PublicKey, g08Key(t))
	r := verifyIntelPckChain(g08PEM(leaf.Raw, root.Raw, orphan.Raw), g08Pin(root), g08now)
	if r.ok || r.reason != "PCK chain is not a single connected path (orphan/duplicate certificates)" {
		t.Fatalf("%+v", r)
	}
}

func TestR5N8TdxQuoteAttestationKeyOffCurve(t *testing.T) {
	f := g08NewTdx(t)
	bad := make([]byte, 64)
	for i := range bad {
		bad[i] = 1
	}
	q := f.quote(t, func(qe []byte) { copy(qe[dcapQeRdataOff:], sha256Sum(bad)) })
	off := dcapHeaderLen + dcapTdReportLen + 4 + 64
	copy(q[off:off+64], bad)
	var r tdxResult
	func() {
		defer func() {
			if v := recover(); v != nil {
				t.Errorf("panicked instead of refusing: %v", v)
			}
		}()
		r = verifyGenuineTdxQuote(q, f.pin, g08now, nil, false)
	}()
	if r.ok || r.reason != "attestation public key is not a valid P-256 point" {
		t.Fatalf("%+v", r)
	}
}

// ---- attest_nvidia_rim.go -------------------------------------------------------------------------------------------------

func TestR5N8RimDuplicateMeasurementIndex(t *testing.T) {
	r := g12NewRig(t)
	xml := r.sign(t, `<Meta product="GH100" colloquialVersion="1"/><Payload>`+g12Res+g12Res+`</Payload>`)
	if rim, why := verifyNvidiaRim(xml, r.pins, g12Now); rim != nil || why != "RIM: duplicate Measurement index 0" {
		t.Fatalf("%+v %q", rim, why)
	}
}

func TestR5N8FirmwarePolicyCheck(t *testing.T) {
	if got := (&firmwarePolicy{}).check(&nvidiaRimIDs{driverVersion: "535.86", vbiosVersion: "zz"}); got != "VBIOS version 'zz' in the GPU report is not parseable" {
		t.Errorf("unparseable VBIOS: %q", got)
	}
	p, err := compileFirmwarePolicy(map[string]any{"denyDriverVersions": []any{"535.86"}, "denyVbiosVersions": []any{"96.00.1A"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ drv, vb, want string }{
		{"535.86", "96.00.1B", "driver 535.86 is on the deny list"},
		{"535.87", "96.00.1A", "VBIOS 96.00.1A is on the deny list"},
		{"535.87", "96.00.1B", ""},
		{"535.86", "96.00.1A", "driver 535.86 is on the deny list"},
	} {
		if got := p.check(&nvidiaRimIDs{driverVersion: c.drv, vbiosVersion: c.vb}); got != c.want {
			t.Errorf("driver %s VBIOS %s: %q, want %q", c.drv, c.vb, got, c.want)
		}
	}
}

func TestR5N8NvidiaHookConstruction(t *testing.T) {
	h, err := newNvidiaHook(map[string]any{"rimRootSpkiSha256": []any{"aa"}})
	if err != nil || h.firmware != nil {
		t.Fatalf("no firmware policy configured: %+v %v", h, err)
	}
	bound := &nvidiaHook{bundle: &nvidiaBundle{driverRim: "x"}}
	if cp := bound.withBundle(nil); cp.bundle != nil || bound.bundle == nil {
		t.Fatalf("withBundle(nil) must drop the bundle on the copy only: %+v %+v", cp, bound)
	}
}

func TestR5N8NvidiaHookChipFamilyMismatch(t *testing.T) {
	r := g12NewRig(t)
	chain := r.chain(t)
	o := g12Opaque()
	o[nvOpaqueChipInfo] = []byte("GB100")
	rep := &spdmReport{opaque: o}
	want := fmt.Sprintf("device leaf subject '%s' is not a GB100 device certificate (chip family mismatch)", subjectLine(chain[0]))
	if got := (&nvidiaHook{rimPins: r.pins}).run(rep, chain, g12Now); got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

func TestR5N8ChainRevocationKeyErrors(t *testing.T) {
	r := g12NewRig(t)
	chain := r.chain(t)
	bad := &attCert{RawSPKI: []byte{1}}
	if _, err := keyOfCert(bad); err == nil {
		t.Fatal("fixture: the key of the bad certificate must not parse")
	}
	clean := r.crl(t, r.root, r.rootKey)
	safe := func(f func() string) (s string) {
		defer func() {
			if v := recover(); v != nil {
				s = fmt.Sprint("panic: ", v)
			}
		}()
		return f()
	}
	// a certificate whose key cannot be read is skipped, never tried with an empty key
	if got := safe(func() string { return checkNvidiaChainRevocation([]*attCert{bad}, [][]byte{clean}, g12Now, nil) }); got != "CRL #0 rejected: no chain certificate verifies it" {
		t.Errorf("only an unreadable key: %q", got)
	}
	// and the search goes on past it
	if got := safe(func() string {
		return checkNvidiaChainRevocation([]*attCert{bad, chain[0], chain[1]}, [][]byte{clean}, g12Now, nil)
	}); got != "" {
		t.Errorf("unreadable key first: %q", got)
	}
	// the FIRST certificate that verifies the CRL is its issuer, even if a later one is the same key again
	revoked := r.crl(t, r.root, r.rootKey, r.leaf.SerialNumber)
	want := "chain certificate '" + subjectLine(chain[0]) + "' is revoked"
	if got := safe(func() string {
		return checkNvidiaChainRevocation([]*attCert{chain[0], chain[1], chain[1]}, [][]byte{revoked}, g12Now, nil)
	}); got != want {
		t.Errorf("duplicate issuer: %q, want %q", got, want)
	}
}

// ---- workflow.go ----------------------------------------------------------------------------------------------------------

func TestR5N8WorkflowVerifyBodyChecksSigEncoding(t *testing.T) {
	old := k5Signed
	defer func() { k5Signed = old }()
	k5Signed = func(string, string, map[string]any, any) bool { return true }
	body := map[string]any{"a": jnum(1)}
	if !k5VerifyBody("d", body, "signer", strings.Repeat("A", 86)) {
		t.Fatal("a canonical 64-byte signature is passed to the verifier")
	}
	for _, bad := range []string{"AAAA", strings.Repeat("A", 87), strings.Repeat("A", 85), strings.Repeat("A", 85) + "B", strings.Repeat("A", 85) + "+"} {
		if k5VerifyBody("d", body, "signer", bad) {
			t.Errorf("%d characters %q... must not reach the verifier", len(bad), bad[:4])
		}
	}
}

func TestR5N8WorkflowReceiptChain(t *testing.T) {
	rs := newKey(t)
	empty := map[string]any{}
	// two receipts for one step: the second is refused although the chain and signatures are sound
	ab := g09wBody(rs.id, []any{g09wStep("a"), g09wStep("b", "a")}, []any{})
	ra := g09wRcpt(t, rs, ab, "a", 0, nil, empty, empty, 1100, "ok")
	ra2 := g09wRcpt(t, rs, ab, "a", 1, g09wRef(ra), empty, empty, 1100, "ok")
	if got := k5ReceiptError(ab, rs.id, []any{ra, ra2}, 1500); got != 1 {
		t.Errorf("duplicate step receipt: %d, want 1", got)
	}
	// every dependency of a receipted step is checked, not only the ones up to the first that already has a receipt
	abc := g09wBody(rs.id, []any{g09wStep("a"), g09wStep("b"), g09wStep("c", "a", "b")}, []any{})
	rA := g09wRcpt(t, rs, abc, "a", 0, nil, empty, empty, 1100, "ok")
	rC := g09wRcpt(t, rs, abc, "c", 1, g09wRef(rA), empty, empty, 1100, "ok")
	if got := k5ReceiptError(abc, rs.id, []any{rA, rC}, 1500); got != 1 {
		t.Errorf("a later dependency without a receipt: %d, want 1", got)
	}
	rB := g09wRcpt(t, rs, abc, "b", 1, g09wRef(rA), empty, empty, 1100, "ok")
	rC2 := g09wRcpt(t, rs, abc, "c", 2, g09wRef(rB), empty, empty, 1100, "ok")
	if got := k5ReceiptError(abc, rs.id, []any{rA, rB, rC2}, 1500); got != -1 {
		t.Errorf("a sound chain: %d, want -1", got)
	}
}

func TestR5N8WorkflowAdmitEdges(t *testing.T) {
	pr, rs := newKey(t), newKey(t)
	empty := map[string]any{}
	in := func(sw map[string]any, receipts []any, req map[string]any) AdmitInput {
		return AdmitInput{Workflow: sw, Principal: pr.id, RsSigner: rs.id, Receipts: receipts, Now: 1500, Request: req}
	}
	steps := func() []any { return []any{g09wStep("a"), g09wStep("b", "a")} }

	// lt and gt hold strictly: the value must be below / above the produced number
	for _, c := range []struct {
		op    string
		val   int64
		allow bool
	}{{"lt", 3, true}, {"lt", 5, false}, {"lt", 7, false}, {"gt", 7, true}, {"gt", 5, false}, {"gt", 3, false}, {"le", 5, true}, {"ge", 5, true}, {"le", 6, false}, {"ge", 4, false}} {
		body := g09wBody(pr.id, steps(), []any{g09wEdge("a", "o", "b", "p", c.op, nil)})
		r := g09wRcpt(t, rs, body, "a", 0, nil, empty, map[string]any{"o": g09wOut(jnum(5))}, 1100, "ok")
		res := AdmitStep(in(g09wSign(t, pr, body), []any{r}, g09wReq("b", map[string]any{"p": jnum(c.val)})))
		if c.allow {
			g09wIs(t, fmt.Sprintf("%s %d", c.op, c.val), res, "allow", "", "b", -1)
		} else {
			g09wIs(t, fmt.Sprintf("%s %d", c.op, c.val), res, "deny", "edge_relation", "b", 0)
		}
	}

	// the edge's deny_labels refuse exactly the labels listed, not every label the source carries
	for _, c := range []struct {
		labels []string
		allow  bool
	}{{[]string{"secret"}, false}, {[]string{"public"}, true}, {nil, true}, {[]string{"public", "secret"}, false}} {
		e := g09wEdge("a", "o", "b", "p", "le", nil)
		e["deny_labels"] = g09wAnys("secret")
		body := g09wBody(pr.id, steps(), []any{e})
		r := g09wRcpt(t, rs, body, "a", 0, nil, empty, map[string]any{"o": g09wOut(jnum(5), c.labels...)}, 1100, "ok")
		res := AdmitStep(in(g09wSign(t, pr, body), []any{r}, g09wReq("b", map[string]any{"p": jnum(5)})))
		if c.allow {
			g09wIs(t, fmt.Sprint("labels ", c.labels), res, "allow", "", "b", -1)
		} else {
			g09wIs(t, fmt.Sprint("labels ", c.labels), res, "deny", "taint_flow", "b", 0)
		}
	}

	// every missing dependency is looked at: a non-promise edge from the second one still escalates
	cd := g09wBody(pr.id, []any{g09wStep("a"), g09wStep("b"), g09wStep("c", "a", "b")},
		[]any{g09wEdge("a", "o", "c", "p", "eq", "pr"), g09wEdge("b", "o", "c", "q", "eq", nil)})
	both := map[string]any{"p": jnum(1), "q": jnum(1)}
	g09wIs(t, "second dependency unconstrained", AdmitStep(in(g09wSign(t, pr, cd), []any{}, g09wReq("c", both))), "escalate", "pipeline_unconstrained", "c", -1)

	// every edge whose source has no receipt yet is pending, in order
	pe := g09wBody(pr.id, steps(), []any{g09wEdge("a", "o1", "b", "p", "eq", "pr"), g09wEdge("a", "o2", "b", "q", "eq", "pr")})
	g09wIs(t, "two pending edges", AdmitStep(in(g09wSign(t, pr, pe), []any{}, g09wReq("b", both))), "allow", "", "b", -1, 0, 1)
}

// ---- saferegex.go ---------------------------------------------------------------------------------------------------------

func r5n8Panics(f func()) (v any) {
	defer func() { v = recover() }()
	f()
	return nil
}

// A brace that is not a quantifier and a class that never closes are refused by the parser itself, not by a later accident.
func TestR5N8RegexParserRefuses(t *testing.T) {
	p := &reParser{s: utf16Units("a{x}")}
	if v := r5n8Panics(func() { p.quantified() }); v != (regexRefuse{}) {
		t.Errorf("a{x}: %v", v)
	}
	p = &reParser{s: utf16Units("[ab")}
	if v := r5n8Panics(func() { p.cls() }); v != (regexRefuse{}) {
		t.Errorf("[ab: %v", v)
	}
}

// ---- intent_v2.go ---------------------------------------------------------------------------------------------------------

func TestR5N8IntentV2ContextShapes(t *testing.T) {
	if c := IntentV2ContextFromJSON([]any{}); c == nil || !c.malformed {
		t.Fatalf("an array is a malformed context: %+v", c)
	}
	if got := intentV2ContextError(IntentV2ContextFromJSON("x")); got != "the v2 verifier context must be an object" {
		t.Errorf("string context: %q", got)
	}
	if got := intentV2ContextError(IntentV2ContextFromJSON(map[string]any{"policy": map[string]any{"schema": map[string]any{}}})); got != "" {
		t.Errorf("policy.schema without closed_world: %q", got)
	}
	if got := intentV2ContextError(IntentV2ContextFromJSON(map[string]any{"policy": map[string]any{"schema": map[string]any{"closed_world": jnum(1)}}})); got != "policy.schema.closed_world must be a boolean" {
		t.Errorf("closed_world 1: %q", got)
	}
	for _, c := range []struct {
		name string
		fn   func(*IntentV2Context) string
		ctx  map[string]any
		want string
	}{
		{"schema string", schemaCtxError, map[string]any{"schema": "x"}, "the schema context must be {docs: [...], keys: [...]}"},
		{"schema without members", schemaCtxError, map[string]any{"schema": map[string]any{}}, "the schema context must be {docs: [...], keys: [...]}"},
		{"schema ok", schemaCtxError, map[string]any{"schema": map[string]any{"docs": []any{}, "keys": []any{}}}, ""},
		{"session string", sessionCtxError, map[string]any{"session": "x"}, "the session context must be an object"},
		{"session ok", sessionCtxError, map[string]any{"session": map[string]any{}}, ""},
		{"acc string", accCtxError, map[string]any{"acc": "x"}, "the accumulator context must be an object"},
		{"acc ok", accCtxError, map[string]any{"acc": map[string]any{}}, ""},
	} {
		if got := c.fn(IntentV2ContextFromJSON(c.ctx)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func r5n8Decide(t *testing.T, f *v2fx) v2Decision {
	t.Helper()
	b, err := json.Marshal(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := IntentV2ContextFromJSONText(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return decideIntentV2(f.p2(), deepM(t, f.grant), ctx, float64(f.now))
}

func r5n8Check(d v2Decision, name string) (v2Check, bool) {
	for _, c := range d.checks {
		if c.name == name {
			return c, true
		}
	}
	return v2Check{}, false
}

// A wallet-held accumulator is not a site-local one: it ends nothing, the accumulators after it are still checked.
func TestR5N8AccumulatorsAfterAWalletHeldOne(t *testing.T) {
	f := newV2Fx(t)
	wallet := map[string]any{"id": "w1", "agg": "count", "sel": map[string]any{"event": "question"}, "win": map[string]any{"kind": "task"}, "key": nil,
		"holder": map[string]any{"kind": "wallet"}}
	f.S["accumulators"] = []any{wallet, tripAcc()}
	f.signRoot()
	f.rebind()
	f.setClaim(38_900)
	expectV2(t, "right claim", f.verify(), v2Base)
	f.setClaim(38_899)
	expectV2(t, "off-by-one claim", f.verify(), minus(v2Base, "accumulators"), "accumulators")
}

func TestR5N8MonitorStateReachesTheEnv(t *testing.T) {
	f := newV2Fx(t)
	f.S["monitors"] = []any{map[string]any{"id": "m", "kind": "requires_prior", "p": map[string]any{"verb": "air.book"}, "q": map[string]any{"verb": "hotel.book"}}}
	f.signRoot()
	f.rebind()
	f.ctx["acc"].(map[string]any)["monitors"] = map[string]any{"m": "unmet"}
	d := r5n8Decide(t, f)
	if c, ok := r5n8Check(d, "accumulators"); !ok || !c.ok {
		t.Fatalf("accumulators: %+v", c)
	}
	mon, _ := d.env["mon"].(map[string]any)
	m, _ := mon["m"].(map[string]any)
	if m["state"] != "unmet" {
		t.Fatalf("env.mon = %v", d.env["mon"])
	}
}

// r5n8ClosedWorld is the fixture's G_0 action decided against its schema alone (closed world, no session).
func r5n8ClosedWorld(t *testing.T, f *v2fx, params map[string]any, grant map[string]any) v2Decision {
	t.Helper()
	p := f.p2()
	delete(p, "intent_session")
	pd, ok := hashCanonicalV(params)
	if !ok {
		t.Fatal("params digest")
	}
	p["action"].(map[string]any)["params_digest"] = pd
	ctxMap := map[string]any{}
	for k, v := range f.ctx {
		ctxMap[k] = v
	}
	ctxMap["policy"] = map[string]any{"schema": map[string]any{"closed_world": true}}
	ctxMap["params"] = params
	return decideIntentV2(p, grant, IntentV2ContextFromJSON(ctxMap), float64(v2Now))
}

func TestR5N8SchemaCheckPublishesTheCanonProjection(t *testing.T) {
	f := newV2Fx(t)
	d := r5n8ClosedWorld(t, f, f.params, deepM(t, f.grant))
	if len(d.checks) != 1 || d.checks[0].name != "schema" || !d.checks[0].ok {
		t.Fatalf("checks: %+v", d.checks)
	}
	canon, _ := d.env["canon"].(map[string]any)
	if canon == nil || canon["refundable"] != "false" {
		t.Fatalf("env.canon = %v", d.env["canon"])
	}
	if _, has := canon["add_ons"]; !has {
		t.Fatalf("env.canon lacks the set parameter: %v", canon)
	}
	// a projection that cannot be built fails the check (fail closed); canonProjection itself always succeeds on params that
	// hashed canonical, so the branch is reached through the seam
	old := v2CanonProjection
	defer func() { v2CanonProjection = old }()
	v2CanonProjection = func(any, string, map[string]any) (map[string]any, bool) { return nil, false }
	d = r5n8ClosedWorld(t, f, f.params, deepM(t, f.grant))
	if len(d.checks) != 1 || d.checks[0].ok || d.checks[0].why != "schema error (fail closed): canonical projection" {
		t.Fatalf("failed projection: %+v", d.checks)
	}
}

// A schema document without a units table has an empty one: policy unit tags for parameters it does not declare pass.
func TestR5N8UnitsRuleOverASchemaWithoutUnits(t *testing.T) {
	f := newV2Fx(t)
	delete(f.schema, "units")
	delete(f.schema["verbs"].([]any)[0].(map[string]any)["params"].(map[string]any), "action.params.total")
	f.signSchema()
	params := map[string]any{"offer_id": "OF-1", "add_ons": []any{"none"}, "refundable": false}
	env := map[string]any{"type": envelopeCaveat, "goal_commit": "g", "predicates": []any{}, "caveats": []any{}, "agent_binding": map[string]any{},
		"risk_policy": DefaultRiskPolicy(), "units": map[string]any{"action.params.zz": map[string]any{"kind": "money"}}}
	grant := deepM(t, map[string]any{"id": "G", "issuer": "I", "caveats": []any{env}})
	if ReadEnvelope(grant) == nil {
		t.Fatal("fixture envelope refused")
	}
	d := r5n8ClosedWorld(t, f, params, grant)
	var got []string
	for _, c := range d.checks {
		got = append(got, fmt.Sprintf("%s:%v:%s", c.name, c.ok, c.why))
	}
	if want := []string{"schema:true:", "units:true:"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("checks %q, want %q", got, want)
	}
}

// DecideTighten always names a reason when it does not answer ok, and an ok answer carries none; modelRules is exact either way.
func TestR5N8TightenOutcomeReasons(t *testing.T) {
	old := v2DecideTighten
	defer func() { v2DecideTighten = old }()
	ctx := IntentV2ContextFromJSON(map[string]any{"policy": map[string]any{"model_polarity": "legacy"}})
	for _, c := range []struct {
		name   string
		res    TightenResult
		want   string
		legacy bool
	}{
		{"ok with a leftover reason", TightenResult{Outcome: "ok", Reason: "leftover"}, "", false},
		{"refusal without a reason", TightenResult{Outcome: "deny"}, "refused", false},
		{"refusal with a reason", TightenResult{Outcome: "deny", Reason: "because"}, "because", false},
		{"legacy mode is reported", TightenResult{Outcome: "ok", Legacy: true}, "", true},
	} {
		res := c.res
		v2DecideTighten = func(map[string]any) TightenResult { return res }
		out := &v2Decision{env: map[string]any{}}
		var got string
		ran := false
		run := func(name string, f func() string) bool {
			if name == "tighten" {
				ran, got = true, f()
			}
			return true
		}
		modelRules(out, map[string]any{}, map[string]any{}, ctx, run, map[string]any{"verb": "air.book"})
		if !ran || got != c.want || out.legacy != c.legacy {
			t.Errorf("%s: ran=%v reason=%q legacy=%v, want %q / %v", c.name, ran, got, out.legacy, c.want, c.legacy)
		}
	}
}
