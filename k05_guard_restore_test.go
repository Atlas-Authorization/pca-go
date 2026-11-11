package pca

// Guards restored after the k05 kill program deleted them as redundant: each refuses its input itself, never through a later
// throw, cast or callee. The seams they read are identity in production; these tests swap them so each guard is the only
// thing that can refuse.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

// grLE is x as 48 little-endian bytes (an SNP report signature component).
func grLE(x *big.Int) []byte {
	be := x.FillBytes(make([]byte, 48))
	for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return be
}

func grAlwaysECDSA(*ecdsa.PublicKey, []byte, *big.Int, *big.Int) bool { return true }

// hardware-sevsnp.ts verifySevSnpReportSignature rejects r or s outside [1, n-1]; the Go port refuses them itself.
func TestGrSnpSignatureRangeGuard(t *testing.T) {
	defer func(old func(*ecdsa.PublicKey, []byte, *big.Int, *big.Int) bool) { snpEcdsaVerify = old }(snpEcdsaVerify)
	snpEcdsaVerify = grAlwaysECDSA
	n := elliptic.P384().Params().N
	one, zero := big.NewInt(1), big.NewInt(0)
	nm1 := new(big.Int).Sub(n, one)
	for _, c := range []struct {
		name string
		r, s *big.Int
		want bool
	}{{"r = s = 1", one, one, true}, {"r = s = n-1", nm1, nm1, true}, {"r = 0", zero, one, false}, {"s = 0", one, zero, false},
		{"r = n", n, one, false}, {"s = n", one, n, false}} {
		rep := &snpReport{signed: []byte("gr"), sigR: grLE(c.r), sigS: grLE(c.s)}
		if got := verifySnpReportSignature(rep, nil); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// hardware-sevsnp.ts extractVcekPublicKey: the VCEK point is read with ecPointFromKey, which throws (fail closed).
func TestGrAmdVcekPointGuard(t *testing.T) {
	defer func(old func(certKey, string) ([]byte, error)) { amdVcekPoint = old }(amdVcekPoint)
	f := g13amdNew(t)
	if r, pub, tbs := f.chain(f.vcekDer, g13amdNow, nil); r != "" || pub == nil || tbs == nil {
		t.Fatalf("genuine chain: %q", r)
	}
	amdVcekPoint = func(certKey, string) ([]byte, error) { return nil, errors.New("gr point") }
	if r, pub, tbs := f.chain(f.vcekDer, g13amdNow, nil); r != "AMD chain verification error: gr point" || pub != nil || tbs != nil {
		t.Fatalf("unreadable point: %q", r)
	}
}

// hardware-sevsnp.ts: `if (!chain.ok || !chain.vcek || !chain.vcekTbs) return { ok: false, reason: `cert chain invalid: ...` }`.
func TestGrAmdChainResultGuard(t *testing.T) {
	defer func(old func([]byte, string, string, int64, any) (string, *ecdsa.PublicKey, []byte)) {
		amdCertChain = old
	}(amdCertChain)
	f := g13amdNew(t)
	meas := make([]byte, 48)
	for i := range meas {
		meas[i] = 0x3c
	}
	v := &amdVerifier{pin: f.pin, binding: "report-data", policy: snpPolicy{measurements: []string{toHexLower(meas)}, requireEcdsaP384: true}}
	raw := g13amdReport(t, f.vcekKey, meas)
	for name, res := range map[string]struct {
		key *ecdsa.PublicKey
		tbs []byte
	}{"no key": {nil, []byte{0x30}}, "no tbs": {&f.vcekKey.PublicKey, nil}} {
		res := res
		amdCertChain = func([]byte, string, string, int64, any) (string, *ecdsa.PublicKey, []byte) {
			return "", res.key, res.tbs
		}
		if why, rep := v.verifyReport(raw, f.vcekDer, f.askPEM+f.arkPEM, g13amdNow, nil); why != "cert chain invalid: " || rep != nil {
			t.Fatalf("%s: %q", name, why)
		}
	}
}

// grCertDER is a fresh self-signed P-256 certificate with a BasicConstraints extension (no key is kept).
func grCertDER(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "gr"}, NotBefore: time.Unix(0, 0),
		NotAfter: time.Unix(1<<31, 0), BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// An OID oidToDotted cannot render is refused where it is read (algorithm identifier, extension), with OpenSSL's text.
func TestGrCertOIDTextGuards(t *testing.T) {
	defer func(old func([]byte, derTlv) (string, error)) { certOIDText = old }(certOIDText)
	der := grCertDER(t)
	if _, err := parseCertDER(der); err != nil {
		t.Fatalf("genuine certificate: %v", err)
	}
	certOIDText = func([]byte, derTlv) (string, error) { return "", errors.New("gr oid") }
	if _, err := parseCertDER(der); err == nil || err.Error() != osslObject {
		t.Fatalf("algorithm identifier: %v", err)
	}
	certOIDText = func(b []byte, e derTlv) (string, error) {
		s, err := oidToDotted(b, e)
		if s == "2.5.29.19" {
			return "", errors.New("gr oid")
		}
		return s, err
	}
	if _, err := parseCertDER(der); err == nil || err.Error() != osslObject {
		t.Fatalf("extension: %v", err)
	}
}

// An empty raw signature is refused before the signature library sees it.
func TestGrRawECDSAEmptySignatureGuard(t *testing.T) {
	defer func(old func(*ecdsa.PublicKey, []byte, *big.Int, *big.Int) bool) { rawECDSAVerify = old }(rawECDSAVerify)
	rawECDSAVerify = grAlwaysECDSA
	if verifyRawECDSA(nil, nil, nil) || verifyRawECDSA(nil, nil, []byte{}) {
		t.Fatal("empty signature accepted")
	}
	if !verifyRawECDSA(nil, nil, []byte{1, 1}) || verifyRawECDSA(nil, nil, []byte{1}) {
		t.Fatal("the seam is not reached for a well-formed signature")
	}
}

// attest-intel-collateral.ts: `if (typeof body !== 'object' || body === null || Array.isArray(body)) return { error: `${name} is not an object` }`.
func TestGrSignedJSONObjectGuard(t *testing.T) {
	defer func(old func([]byte) (any, error)) { signedJSONBody = old }(signedJSONBody)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"a":1}`
	r, s, err := ecdsa.Sign(rand.Reader, k, sha256Sum([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	sig := hex.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
	text := `{"tcbInfo":` + raw + `,"signature":"` + sig + `"}`
	key := certKey{pub: &k.PublicKey, typ: "ec", curve: "prime256v1"}
	if body, why := verifySignedJSON(text, "tcbInfo", key); why != "" || body == nil {
		t.Fatalf("genuine: %q", why)
	}
	for _, parsed := range []any{nil, []any{}, "x"} {
		parsed := parsed
		signedJSONBody = func([]byte) (any, error) { return parsed, nil }
		if body, why := verifySignedJSON(text, "tcbInfo", key); why != "tcbInfo is not an object" || body != nil {
			t.Fatalf("%v: %q", parsed, why)
		}
	}
}

// The core verifier never returns an error today; one is still a refusal (authorize.ts: `authorize error (fail closed)`).
func TestGrAuthorizeCoreErrorGuard(t *testing.T) {
	defer func(old func(map[string]any, map[string]any, int64, string, VerifyOptions) (Verdict, error)) {
		authorizeCoreVerify = old
	}(authorizeCoreVerify)
	in, _, p := g01Fix(t)
	authorizeCoreVerify = func(pc, g map[string]any, now int64, aud string, o VerifyOptions) (Verdict, error) {
		v, _ := VerifyPCActnCoreWith(pc, g, now, aud, o)
		return v, errors.New("gr core")
	}
	g01Refused(t, Authorize(p, in), 403, "authorize", "authorize: error (fail closed): gr core")
}

func TestGrAuthorizeParamsDigestGuard(t *testing.T) {
	defer func(old func(any) (string, error)) { authorizeParamsDigest = old }(authorizeParamsDigest)
	in, _, p := g01Fix(t)
	authorizeParamsDigest = func(any) (string, error) { return "", errors.New("gr digest") }
	g01Refused(t, Authorize(p, in), 403, "authorize", "authorize: error (fail closed): gr digest")
}

// An answer whose binding digests cannot be computed is never verified (no "escalation:" verdict), and never lifts a failure.
func TestGrAuthorizeEscalationDigestGuard(t *testing.T) {
	defer func(a func(map[string]any) (string, error), b func(map[string]any) (string, error), c func(*int64) (string, error)) {
		authorizeEscPolicyDigest, authorizeEscActionDigest, authorizeEscHistoryHead = a, b, c
	}(authorizeEscPolicyDigest, authorizeEscActionDigest, authorizeEscHistoryHead)
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	run := func() AuthorizeResult {
		return Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	}
	if r := run(); !r.Allow || !g01Has(r.Reasons, "escalation: answered allow by principal "+pub[:8]) {
		t.Fatalf("answered: %q", r.Reasons)
	}
	boom := errors.New("gr digest")
	for name, set := range map[string]func(){
		"policy":  func() { authorizeEscPolicyDigest = func(map[string]any) (string, error) { return "x", boom } },
		"action":  func() { authorizeEscActionDigest = func(map[string]any) (string, error) { return "x", boom } },
		"history": func() { authorizeEscHistoryHead = func(*int64) (string, error) { return "x", boom } },
	} {
		authorizeEscPolicyDigest, authorizeEscActionDigest, authorizeEscHistoryHead = EscalationPolicyDigest, EscalationActionDigest, EscalationHistoryHead
		set()
		if r := run(); r.Allow || g01HasPrefix(r.Reasons, "escalation:") {
			t.Fatalf("%s digest failed: allow=%v %q", name, r.Allow, r.Reasons)
		}
	}
}

// A nil plan node is refused by planRoot itself, not left to planLeaf's missing id.
func TestGrPlanRootNilNodeGuard(t *testing.T) {
	defer func(old func(any, map[string]any, string) (map[string]any, error)) { planRootLeaf = old }(planRootLeaf)
	planRootLeaf = func(any, map[string]any, string) (map[string]any, error) { return map[string]any{"gr": "leaf"}, nil }
	if root, ok := planRoot([]map[string]any{{"id": "n1"}}); !ok || root == "" {
		t.Fatal("the seam is not reached for a node")
	}
	if root, ok := planRoot([]map[string]any{{"id": "n1"}, nil}); ok || root != "" {
		t.Fatalf("nil node: %q %v", root, ok)
	}
}

// Run answers a lone replay failure from the record only with an operation and a PCActn in hand.
func TestGrExecutorLoneReplayGuard(t *testing.T) {
	defer func(old func(any, AuthorizeInput) AuthorizeResult) { executorAuthorize = old }(executorAuthorize)
	ex, _, op, _ := executorFixture(t, -1)
	want, err := ParamsDigest(paramsAny(op.Params))
	if err != nil {
		t.Fatal(err)
	}
	pc := map[string]any{"gr": "pcactn"}
	var nilPC map[string]any
	for _, v := range []map[string]any{pc, nilPC} {
		id, err := HashCanonical(v)
		if err != nil {
			continue // no record can sit under it
		}
		rec := OperationRecord{ID: id, State: OpCommitted, Verb: op.Verb, Resource: op.Resource, ParamsDigest: want, StartedAt: 1, FinishedAt: 1, Result: "gr"}
		if _, _, err := ex.o.Operations.Create(rec); err != nil {
			t.Fatal(err)
		}
	}
	replay := func(p map[string]any) {
		executorAuthorize = func(any, AuthorizeInput) AuthorizeResult {
			return AuthorizeResult{Status: 403, Checks: map[string]string{"replay": "fail"}, PCActn: p}
		}
	}
	never := func(ExecutionHandle) (any, error) { t.Fatal("executed"); return nil, nil }
	replay(pc)
	if o := ex.Run(pc, op, never); o.Status == "denied" {
		t.Fatalf("a lone replay with its record: %+v", o)
	}
	if o := ex.Run(pc, nil, never); o.Status != "denied" {
		t.Fatalf("no operation: %+v", o)
	}
	replay(nilPC)
	if o := ex.Run(pc, op, never); o.Status != "denied" {
		t.Fatalf("no PCActn: %+v", o)
	}
}

// ledger.ts verifyCheckpointChain: `if (!cp.proof) return { ok: false, at: i, reason: 'proof_missing' }`.
func TestGrCheckpointMissingProofGuard(t *testing.T) {
	defer func(old func(any, any, any, string, map[string]any, ...map[string]string) bool) {
		checkpointHeadConsistency = old
	}(checkpointHeadConsistency)
	checkpointHeadConsistency = func(any, any, any, string, map[string]any, ...map[string]string) bool { return true }
	g := g05Key(t, 0x6b)
	h3, h4 := g05Head(t, g, 3, g05Root(3), "q"), g05Head(t, g, 4, g05Root(4), g05Root(3))
	if v := VerifyCheckpointChain([]any{map[string]any{"sth": h3}, map[string]any{"sth": h4, "proof": "gr"}}, g.Public, nil); v != (CheckpointVerdict{true, 0}) {
		t.Fatalf("the seam is not reached: %+v", v)
	}
	for _, second := range []map[string]any{{"sth": h4}, {"sth": h4, "proof": nil}, {"sth": h4, "proof": false}} {
		if v := VerifyCheckpointChain([]any{map[string]any{"sth": h3}, second}, g.Public, nil); v != (CheckpointVerdict{false, 1}) {
			t.Fatalf("%v: %+v", second, v)
		}
	}
}

// k5VerifyBody refuses a non-string signer or signature itself, not through extSigned.
func TestGrWorkflowSignerTypeGuard(t *testing.T) {
	defer func(old func(string, string, map[string]any, any) bool) { k5Signed = old }(k5Signed)
	k5Signed = func(string, string, map[string]any, any) bool { return true }
	sig := b64.EncodeToString(make([]byte, 64))
	if !k5VerifyBody("gr", map[string]any{}, "s", sig) {
		t.Fatal("the seam is not reached")
	}
	if k5VerifyBody("gr", map[string]any{}, 5, sig) || k5VerifyBody("gr", map[string]any{}, nil, sig) || k5VerifyBody("gr", map[string]any{}, "s", 5) {
		t.Fatal("a non-string signer or signature verified")
	}
}

// A plan context whose PlanAuthorized is set while its status is not executable never makes the arguments trusted:
// plan_state fails and the provenance gate still runs as for an unplanned request (no principal_plan).
func TestGrPrincipalPlanNeedsExecutableGuard(t *testing.T) {
	old := authorizePlanContext
	t.Cleanup(func() { authorizePlanContext = old })
	authorizePlanContext = func(*PlanRegistry, string, string, int64) *PlanContext {
		return &PlanContext{PlanAuthorized: true, Status: PlanStatus{State: PlanDraft, Reason: "plan is draft"}}
	}
	in, pcactn, _ := provGateInput(t)
	in.Plans, in.ArgProvenance = NewPlanRegistry(PlanRegistryOptions{}), nil // no bundle: untrusted unless the principal planned it
	r := Authorize(pcactn, in)
	if r.Allow || r.Checks["plan_state"] != "fail" || r.Checks["provenance_flow"] != "fail" {
		t.Fatalf("a non-executable plan made the arguments trusted: %+v", r)
	}
	authorizePlanContext = func(*PlanRegistry, string, string, int64) *PlanContext {
		return &PlanContext{PlanAuthorized: true, Status: PlanStatus{State: PlanAuthorized, Executable: true}}
	}
	in, pcactn, _ = provGateInput(t)
	in.Plans, in.ArgProvenance = NewPlanRegistry(PlanRegistryOptions{}), nil // no bundle: untrusted unless the principal planned it
	if r := Authorize(pcactn, in); r.Checks["provenance_flow"] != "pass" {
		t.Fatalf("an executable principal plan: provenance_flow %q (%+v)", r.Checks["provenance_flow"], r)
	}
}
