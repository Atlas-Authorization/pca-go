package pca

import (
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
)

const attTestNonce = "0123456789abcdef0123456789abcdef"

func attTestSetup(t *testing.T) (*DevAttestor, map[string]any, ExpectedAttestationBinding, map[string]any) {
	t.Helper()
	att, err := CreateDevAttestor(fill(32, 5), nil)
	if err != nil {
		t.Fatal(err)
	}
	h, g, ep := att.PublicKey, "grant-1", int64(0)
	doc, err := att.Attest(AttestationClaims{ModelID: "m", WeightsDigest: "w", RuntimeMeasurement: "7", Operator: "op", Nonce: attTestNonce,
		IssuedAt: 1000, ExpiresAt: 2000, HolderPub: &h, GrantRef: &g, Epoch: &ep})
	if err != nil {
		t.Fatal(err)
	}
	exp := ExpectedAttestationBinding{HolderPub: h, GrantRef: g, Epoch: 0, Nonce: attTestNonce}
	ctx := map[string]any{"pcactn": map[string]any{"grant_ref": g, "attestation": map[string]any{"epoch": 0, "quote_digest": attTestNonce}}}
	return att, doc, exp, ctx
}

func nanF() float64 { var z float64; return z / z }

func TestAttestationDevAttestorVerifyAndFailClosed(t *testing.T) {
	att, doc, exp, ctx := attTestSetup(t)
	in := VerifyAttestationInput{Document: doc, Ctx: ctx, Expected: exp, NowMs: 1500, TrustedAttestorKeys: []string{att.PublicKey}}
	if v := VerifyAttestation(in); !v.OK || !v.Bound || v.Identity == nil || v.Identity.ModelID != "m" {
		t.Fatalf("a good document must verify: %+v", v)
	}
	cases := map[string]func(*VerifyAttestationInput){
		"attestor key is not trusted":             func(i *VerifyAttestationInput) { i.TrustedAttestorKeys = nil },
		"attestation expired":                     func(i *VerifyAttestationInput) { i.NowMs = 3000 },
		"attestation not yet valid":               func(i *VerifyAttestationInput) { i.NowMs = 10 },
		"no attestation document for this action": func(i *VerifyAttestationInput) { i.Document = nil },
		"attestation nonce does not bind": func(i *VerifyAttestationInput) {
			i.Ctx = map[string]any{"pcactn": map[string]any{"grant_ref": "grant-1", "attestation": map[string]any{"epoch": 0, "quote_digest": "x"}}}
		},
		"PCActn grant_ref differs from expected": func(i *VerifyAttestationInput) { i.Expected.GrantRef = "other" },
		"verifier clock is not a finite time":    func(i *VerifyAttestationInput) { i.NowMs = nanF() },
		"attestation signature does not verify":  func(i *VerifyAttestationInput) { d := copyMap(doc); d["model_id"] = "evil"; i.Document = d },
		"attestation binding mismatch":           func(i *VerifyAttestationInput) { i.Expected.HolderPub = "someone-else" },
	}
	for want, mut := range cases {
		c := in
		mut(&c)
		if v := VerifyAttestation(c); v.OK || v.Bound || !strings.Contains(v.Reason, want) {
			t.Fatalf("%q: got %+v", want, v)
		}
	}
	d, _ := AttestationDigest(doc)
	if len(d) != 43 {
		t.Fatalf("digest %q", d)
	}
	if !NonceBinds(doc, ctx) || NonceBinds(doc, map[string]any{}) {
		t.Fatal("NonceBinds")
	}
	if AttestationRegistry([]map[string]any{doc})(ctx)["nonce"] != attTestNonce {
		t.Fatal("registry")
	}
}

func TestAttestationHookConsumesNonceOnce(t *testing.T) {
	att, doc, exp, ctx := attTestSetup(t)
	store, err := NewMemoryNonceStore(10, MemoryNonceStoreOptions{Now: func() int64 { return 1500 }})
	if err != nil {
		t.Fatal(err)
	}
	h := CreateAttestationVerifier(AttestationVerifierOpts{NonceStore: store, TrustedAttestorKeys: []string{att.PublicKey},
		ResolveDocument: AttestationRegistry([]map[string]any{doc}), ExpectedBinding: func(map[string]any) *ExpectedAttestationBinding { return &exp },
		Now: func() int64 { return 1500 }})
	if r := h.Verify(ctx); !r.OK || !r.Bound || !r.Enforced {
		t.Fatalf("first use: %+v", r)
	}
	if r := h.Verify(ctx); r.OK || r.Bound || !strings.Contains(r.Reason, "already consumed") {
		t.Fatalf("replay must be refused: %+v", r)
	}
	if h.Assurance().Level != "software" {
		t.Fatal("software mode label")
	}
	weak := exp
	weak.Nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h2 := CreateAttestationVerifier(AttestationVerifierOpts{ExpectedBinding: func(map[string]any) *ExpectedAttestationBinding { return &weak }})
	if r := h2.Verify(ctx); r.OK || !strings.Contains(r.Reason, "128 bits") {
		t.Fatalf("low entropy nonce: %+v", r)
	}
	if r := CreateAttestationVerifier(AttestationVerifierOpts{}).Verify(ctx); r.OK || !strings.Contains(r.Reason, "no server-issued") {
		t.Fatalf("no expected binding: %+v", r)
	}
}

func TestAttestationNonceStoreAndEntropy(t *testing.T) {
	now := int64(0)
	s, _ := NewMemoryNonceStore(2, MemoryNonceStoreOptions{RetentionMs: 100, Now: func() int64 { return now }})
	if !s.Consume("a") || s.Consume("a") || !s.Consume("b") || s.Consume("c") {
		t.Fatal("single use, and a store full of live nonces refuses")
	}
	now = 150
	if !s.Consume("c") || !s.Consume("a") {
		t.Fatal("aged out entries make room")
	}
	if _, err := NewMemoryNonceStore(0, MemoryNonceStoreOptions{}); err == nil {
		t.Fatal("max < 1")
	}
	if !NonceEntropyOk(attTestNonce, 0) || NonceEntropyOk("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0) || NonceEntropyOk("short", 0) || NonceEntropyOk(5, 0) || NonceEntropyOk("not base64 !!!!!!!!!!!!!!!!", 0) {
		t.Fatal("NonceEntropyOk")
	}
}

func TestAttestationMatchAgentBinding(t *testing.T) {
	sp := "sp"
	id := MeasuredIdentity{ModelID: "m", WeightsDigest: "w", RuntimeMeasurement: "7", Operator: "op", SystemPromptDigest: &sp}
	ok := []map[string]any{{}, {"model_allowlist": []any{"m"}}, {"operator": "op"}, {"min_measurement": "7"}, {"min_measurement": map[string]any{"svn": 7}},
		{"weights_allowlist": []any{"w"}}, {"system_prompt_allowlist": []any{"sp"}}}
	for i, b := range ok {
		if r := MatchAgentBinding(id, b); r != "" {
			t.Fatalf("case %d: %s", i, r)
		}
	}
	bad := map[string]map[string]any{
		"not in model_allowlist":   {"model_allowlist": []any{"x"}},
		"malformed":                {"min_measurement": map[string]any{"svn": "5"}},
		"does not match required":  {"min_measurement": "8"},
		"below required min svn":   {"min_measurement": map[string]any{"svn": 9}},
		"not the bound operator":   {"operator": "other"},
		"not hardware-measured":    {"require_measured_weights": true},
		"not in weights_allowlist": {"weights_allowlist": []any{"x"}},
		"tool_manifest_allowlist":  {"tool_manifest_allowlist": []any{"t"}},
	}
	for want, b := range bad {
		if r := MatchAgentBinding(id, b); !strings.Contains(r, want) {
			t.Fatalf("%q: got %q", want, r)
		}
	}
}

func TestAttestationMultiRoot(t *testing.T) {
	root := func(id string, res HardwareResult, req bool) MultiRootAttestationRoot {
		return MultiRootAttestationRoot{ID: id, Required: req, Verifier: AttestationHardwareFunc(func(_, _ map[string]any, _ int64, _ ExpectedAttestationBinding) HardwareResult { return res })}
	}
	good := func(model string) HardwareResult {
		return HardwareResult{OK: true, Bound: true, Measured: MeasuredIdentity{ModelID: model, RuntimeMeasurement: "r", Operator: "o"}.Map()}
	}
	run := func(threshold int, rs ...MultiRootAttestationRoot) HardwareResult {
		v, err := CreateMultiRootVerifier(rs, threshold)
		if err != nil {
			t.Fatal(err)
		}
		return v.VerifyHardware(nil, nil, 0, ExpectedAttestationBinding{})
	}
	if r := run(2, root("a", good("m"), false), root("b", good("m"), false)); !r.OK || !r.Bound || r.Measured["model_id"] != "m" {
		t.Fatalf("two agreeing roots: %+v", r)
	}
	if r := run(2, root("a", good("m"), false), root("b", good("n"), false)); r.OK || !strings.Contains(r.Reason, "identity conflict") {
		t.Fatalf("conflict: %+v", r)
	}
	if r := run(2, root("a", good("m"), false), root("b", HardwareResult{Reason: "boom"}, false)); r.OK || !strings.Contains(r.Reason, "below threshold (1/2") {
		t.Fatalf("below threshold: %+v", r)
	}
	if r := run(1, root("a", good("m"), false), root("b", HardwareResult{Reason: "boom"}, true)); r.OK || !strings.Contains(r.Reason, "required attestation root 'b' failed: boom") {
		t.Fatalf("required root: %+v", r)
	}
	for _, c := range []struct {
		rs []MultiRootAttestationRoot
		th int
	}{{nil, 1}, {[]MultiRootAttestationRoot{root("a", good("m"), false)}, 2}, {[]MultiRootAttestationRoot{root("a", good("m"), false), root("a", good("m"), false)}, 1}, {[]MultiRootAttestationRoot{root("", good("m"), false)}, 1}} {
		if _, err := CreateMultiRootVerifier(c.rs, c.th); err == nil {
			t.Fatal("construction must refuse")
		}
	}
}

func TestPassportExtrasAndX509Validity(t *testing.T) {
	p := map[string]any{"id": "x", "model_id": "m", "operator": "op", "hardware_rooted": true, "weights_digest": "w", "weights_measured": true, "runtime_measurement": "7"}
	if ok, r := MatchesBinding(p, map[string]any{"model_allowlist": []any{"m"}, "require_hardware": true, "min_measurement": map[string]any{"svn": 5}}); !ok {
		t.Fatalf("match: %v", r)
	}
	if ok, r := MatchesBinding(p, map[string]any{"tool_manifest_allowlist": []any{"t"}, "operator": "x"}); ok || len(r) != 2 {
		t.Fatalf("mismatch: %v", r)
	}
	if got := TrustScore(p, []string{"op"}); math.Abs(got-0.8) > 1e-9 {
		t.Fatalf("trust score %v", got)
	}
	if PassportAssurance(false, nil).Level != "software" || PassportAssurance(true, nil).Level != "unknown" {
		t.Fatal("PassportAssurance")
	}
	if b := PassportEvidenceBinding("id", "sub", "n"); b.GrantRef != "passport:id" || b.HolderPub != "sub" {
		t.Fatal("PassportEvidenceBinding")
	}
	if ms, ok := ParseOpenSslTime("Jan  1 00:00:00 2030 GMT"); !ok || ms != 1893456000000 {
		t.Fatalf("openssl time %d %v", ms, ok)
	}
	if _, ok := ParseOpenSslTime("Feb 30 00:00:00 2030 GMT"); ok {
		t.Fatal("roll-over must be refused")
	}
	if _, ok := ParseOpenSslTime("Bad time value"); ok {
		t.Fatal("garbage")
	}
	if ms, ok := ParseDerTime(0x17, "300101000000Z"); !ok || ms != 1893456000000 {
		t.Fatalf("der time %d %v", ms, ok)
	}
	lk := X509ValidityLike{ValidFrom: "Jan  1 00:00:00 2030 GMT", ValidTo: "Jan  1 00:00:00 2031 GMT"}
	if !X509ValidAt(lk, 1893456000000+1, 0) || X509ValidAt(lk, 1893456000000-1, 0) || X509ValidAt(X509ValidityLike{ValidFrom: "x", ValidTo: "y"}, 0, 0) {
		t.Fatal("X509ValidAt")
	}
}

func TestSevSnpPublicSurface(t *testing.T) {
	raw := make([]byte, snpReportLen)
	raw[0] = 3
	raw[snpOffSigAlgo] = 1
	rep, err := ParseSevSnpReport(raw)
	if err != nil || rep.Version != 3 || rep.SignatureAlgo != SevSnpSigAlgoEcdsaP384Sha384 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	if _, err := ParseSevSnpReport(raw[:10]); err == nil {
		t.Fatal("short report")
	}
	if r := CheckSevSnpPolicy(rep, SevSnpPolicy{}); r != "" {
		t.Fatalf("default policy: %s", r)
	}
	rep.Policy = SevSnpPolicyDebugBit
	rep.r.policy = SevSnpPolicyDebugBit
	if r := CheckSevSnpPolicy(rep, SevSnpPolicy{}); !strings.Contains(r, "DEBUG") {
		t.Fatalf("debug bit: %s", r)
	}
	if r := CheckSevSnpPolicy(rep, SevSnpPolicy{AllowDebug: true, MinLaunchTcb: big.NewInt(1)}); !strings.Contains(r, "launch_tcb") {
		t.Fatalf("tcb floor: %s", r)
	}
	if _, err := SevSnpSignatureToCompact(make([]byte, 72), make([]byte, 72)); err == nil {
		t.Fatal("zero r must be refused")
	}
	if _, err := EcdsaP384PublicKey([]byte{1, 2, 3}); err == nil {
		t.Fatal("a malformed point must be refused")
	}
	if len(SplitPemCertificates("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\nx\n-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----")) != 2 {
		t.Fatal("SplitPemCertificates")
	}
	var url string
	body, err := FetchVcekFromKds([]byte{0xab, 0xcd}, 0x07_00_00_00_00_00_02_01, KdsOptions{Fetch: func(u string) (int, []byte, error) { url = u; return 200, []byte("der"), nil }})
	if err != nil || string(body) != "der" || url != "https://kdsintf.amd.com/vcek/v1/Milan/abcd?blSPL=1&teeSPL=2&snpSPL=0&ucodeSPL=7" {
		t.Fatalf("kds: %v %q", err, url)
	}
	if _, err := FetchVcekFromKds(nil, 0, KdsOptions{Fetch: func(string) (int, []byte, error) { return 404, nil, nil }}); err == nil {
		t.Fatal("non-2xx")
	}
	if _, err := FetchVcekFromKds(nil, 0, KdsOptions{Fetch: func(string) (int, []byte, error) { return 0, nil, errors.New("down") }}); err == nil {
		t.Fatal("transport error")
	}
	if id := MakeDefaultDeriveIdentity(true)(rep); id.WeightsMeasured || id.WeightsDigest == "" {
		t.Fatalf("default identity: %+v", id)
	}
}
