package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Fail-closed tables: every row is "missing / invalid X => exact result", per vendor, plus unit tests of the strict DER rules.
// None of them needs the conformance vector file: the inputs are built here (generated certificates, signed tokens, byte edits).

func cfgOf(t *testing.T, text string) map[string]any {
	t.Helper()
	v, err := ParseJSONLenient([]byte(text))
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return v.(map[string]any)
}

var testBinding = &AttestationBinding{HolderPub: "holder-key", GrantRef: "passport:abc", Epoch: 0, Nonce: "nonce-1"}

var zeros96 = strings.Repeat("a", 96)

func TestAttestationBindingKnownAnswer(t *testing.T) {
	got, err := attestationBindingBytes(AttestationBinding{HolderPub: "h", GrantRef: "g", Epoch: 3, Nonce: "n"})
	if err != nil {
		t.Fatal(err)
	}
	if hx := hex.EncodeToString(got); hx != "a96a474bee436996d639ac056ef40b906991ac6732d192214c9ff400ee7f60597bea43c2cef340b5439bd38ddc63fbf24dd1b2da311650a7e9a8e0bdbc8e16c3" {
		t.Fatalf("binding %s", hx)
	}
	got, _ = attestationBindingBytes(*testBinding)
	if hx := hex.EncodeToString(got); hx != "9ea99cfad60fa258d6dd4e6000b34a2ef855ab18b681a6f203dc99bbf8f4dbc2f8c957981a8b26975420e2e621fa53ef7c135d64a620f47bcba6a12966d8feff" {
		t.Fatalf("binding %s", hx)
	}
	for _, c := range []struct {
		b    AttestationBinding
		want string
	}{
		{AttestationBinding{GrantRef: "g", Nonce: "n"}, "binding: holderPub required"},
		{AttestationBinding{HolderPub: "h", Nonce: "n"}, "binding: grantRef required"},
		{AttestationBinding{HolderPub: "h", GrantRef: "g"}, "binding: nonce required"},
		{AttestationBinding{HolderPub: "h", GrantRef: "g", Nonce: "n", Epoch: -1}, "binding: epoch must be a non-negative safe integer"},
		{AttestationBinding{HolderPub: "h", GrantRef: "g", Nonce: "n", Epoch: 1.5}, "binding: epoch must be a non-negative safe integer"},
		{AttestationBinding{HolderPub: "h", GrantRef: "g", Nonce: "n", Epoch: 9007199254740992}, "binding: epoch must be a non-negative safe integer"},
	} {
		if _, err := attestationBindingBytes(c.b); err == nil || err.Error() != c.want {
			t.Errorf("binding %+v: %v, want %q", c.b, err, c.want)
		}
	}
}

func TestAttestConstructRefusals(t *testing.T) {
	m96 := `"` + zeros96 + `"`
	rows := []struct{ vendor, cfg, want string }{
		{"amd-sev-snp", `{"family":"rome","binding":"report-data","policy":{"measurements":["aa"]}}`, "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"},
		{"amd-sev-snp", `{"family":"milan","binding":"x","policy":{"measurements":["aa"]}}`, "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"},
		{"amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":[]}}`, "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"},
		{"amd-sev-snp", `{"family":"milan","binding":"report-data"}`, "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"},
		{"amd-sev-snp", `{"family":"rome","binding":"report-data","policy":{"measurements":["aa"],"minReportedTcb":"abc"}}`, "Cannot convert abc to a BigInt"},
		{"intel-tdx-dcap", `{"binding":"x","policy":{"mrtds":[` + m96 + `]}}`, "createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'"},
		{"intel-tdx-dcap", `{"binding":"report-data","policy":{}}`, "createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)"},
		{"intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":["abc"]}}`, "createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)"},
		{"intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":[` + m96 + `],"mrSeams":[]}}`, "createIntelDcapVerifier: policy.mrSeams, if given, must be a NON-EMPTY list"},
		{"intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":[` + m96 + `],"mrSignerSeams":["zz"]}}`, "createIntelDcapVerifier: every mrSignerSeams entry must be 96 hex chars (48 bytes)"},
		{"azure-maa", `{}`, "createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs"},
		{"azure-maa", `{"trustedIssuers":[""]}`, "createAzureMaaVerifier: every trusted issuer must be a non-empty URL string"},
		{"azure-maa", `{"trustedIssuers":["https://i"]}`, "createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted"},
		{"azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]}}`, "createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)"},
		{"azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["aa"],"sevSnpMinTcb":{"bogus":1}}}`, "createAzureMaaVerifier: policy.sevSnpMinTcb.bogus is not a known field (bootloader | snp | microcode | tee)"},
		{"azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["aa"],"sevSnpMinTcb":{"snp":-1}}}`, "createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer"},
		{"gcp-confidential-space", `{}`, "createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs"},
		{"gcp-confidential-space", `{"trustedIssuers":["https://i"]}`, "createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted"},
		{"gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{}}`, "createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)"},
		{"gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"],"allowedTeeTypes":[]}}`, "createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty"},
		{"nvidia-gpu-spdm", `{}`, "createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)"},
		{"nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"]}`, "createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"},
		{"nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"],"policy":{"measurements":{"256":"aa"}}}`, "createNvidiaSpdmVerifier: measurement index out of range"},
		{"nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"],"collateral":{}}`, "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root"},
		{"nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"],"collateral":{"rimRootSpkiSha256":["aa"],"firmware":{"minDriverVersion":"x"}}}`, "nvidiaCollateralHook: malformed minDriverVersion 'x'"},
	}
	for _, r := range rows {
		_, err := VerifierFromConfig(r.vendor, cfgOf(t, r.cfg))
		if err == nil || err.Error() != r.want {
			t.Errorf("%s %s:\n got  %v\n want %q", r.vendor, r.cfg, err, r.want)
		}
	}
	if _, err := VerifierFromConfig("no-such-vendor", map[string]any{}); err == nil {
		t.Error("an unknown vendor must be refused")
	}
	// the constructors accept a complete configuration
	for _, r := range []struct{ vendor, cfg string }{
		{"amd-sev-snp", `{"family":"genoa","binding":"azure-runtime-data","policy":{"measurements":["aa"],"minReportedTcb":"18446744073709551615"}}`},
		{"intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":[` + m96 + `],"mrSeams":[` + m96 + `]}}`},
		{"azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"],"sevSnpMinTcb":{"snp":3}}}`},
		{"gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`},
		{"nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"],"collateral":{"rimRootSpkiSha256":["aa"]}}`},
	} {
		if _, err := VerifierFromConfig(r.vendor, cfgOf(t, r.cfg)); err != nil {
			t.Errorf("%s: %v", r.vendor, err)
		}
	}
}

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func unsignedJWT(header, payload string) string { return b64u(header) + "." + b64u(payload) + ".AA" }

func TestAttestFailClosedNoEvidenceAndBadEvidence(t *testing.T) {
	zeroQuote := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	badQuote := make([]byte, 700)
	badQuote[0], badQuote[2], badQuote[4] = 4, 2, 0x81
	badQuote[632], badQuote[633] = 0xff, 0xff // signature data length 65535
	snp1184 := make([]byte, 1184)
	snp1184Reserved := make([]byte, 1184)
	snp1184Reserved[900] = 1

	cases := []struct {
		name, vendor, cfg string
		ev                map[string]any
		expected          *AttestationBinding
		want              string
		prefix            bool
	}{
		{"amd nil evidence", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, nil, testBinding, "no AMD SEV-SNP evidence for this action", false},
		{"amd empty evidence", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, map[string]any{}, testBinding, "no AMD SEV-SNP evidence for this action", false},
		{"amd no binding", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, map[string]any{"report": "AA==", "vcekDer": "AA==", "askArkPem": "x"}, nil, "no expected attestation binding supplied", false},
		{"amd short report", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, map[string]any{"report": "AA==", "vcekDer": "AA==", "askArkPem": "x"}, testBinding, "SEV-SNP report invalid: report parse failed: parseSevSnpReport: report too short (1 < 816)", false},
		{"amd non-canonical length", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, map[string]any{"report": zeroQuote(1000), "vcekDer": "AA==", "askArkPem": "x"}, testBinding, "SEV-SNP report invalid: report length 1000 is not the canonical 1184", false},
		{"amd reserved bytes", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, map[string]any{"report": base64.StdEncoding.EncodeToString(snp1184Reserved), "vcekDer": "AA==", "askArkPem": "x"}, testBinding, "SEV-SNP report invalid: report signature block has non-zero reserved bytes", false},
		{"amd garbage VCEK", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}`, map[string]any{"report": base64.StdEncoding.EncodeToString(snp1184), "vcekDer": "AA==", "askArkPem": "x"}, testBinding, "SEV-SNP report invalid: cert chain invalid: AMD chain verification error: ", true},
		{"amd negative skew", "amd-sev-snp", `{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]},"clockSkewMs":-1}`, map[string]any{"report": base64.StdEncoding.EncodeToString(snp1184), "vcekDer": "AA==", "askArkPem": "x"}, testBinding, "SEV-SNP report invalid: cert chain invalid: clockSkewMs must be a non-negative number", false},
		{"amd azure mode needs runtime data", "amd-sev-snp", `{"family":"milan","binding":"azure-runtime-data","policy":{"measurements":["aa"]}}`, nil, testBinding, "no AMD SEV-SNP evidence for this action", false},

		{"dcap nil evidence", "intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":["` + zeros96 + `"]}}`, nil, testBinding, "no Intel DCAP quote for this action", false},
		{"dcap no binding", "intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":["` + zeros96 + `"]}}`, map[string]any{"quote": "AA=="}, nil, "no expected attestation binding supplied", false},
		{"dcap short quote", "intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":["` + zeros96 + `"]}}`, map[string]any{"quote": "AA=="}, testBinding, "DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length", false},
		{"dcap version 0", "intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":["` + zeros96 + `"]}}`, map[string]any{"quote": zeroQuote(700)}, testBinding, "DCAP quote invalid: quote parse failed: parseDcapQuote: unsupported quote version 0 (expected 4)", false},
		{"dcap signature data overruns", "intel-tdx-dcap", `{"binding":"report-data","policy":{"mrtds":["` + zeros96 + `"]}}`, map[string]any{"quote": base64.StdEncoding.EncodeToString(badQuote)}, testBinding, "DCAP quote invalid: quote parse failed: parseDcapQuote: signature data (65535) overruns the quote", false},

		{"maa nil evidence", "azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}`, nil, testBinding, "no Azure MAA token for this action", false},
		{"maa not a JWS", "azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}`, map[string]any{"token": "x"}, testBinding, "MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts", false},
		{"maa non-canonical header", "azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}`, map[string]any{"token": "a.b.c"}, testBinding, "MAA token parse failed: parseMaaJwt: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)", false},
		{"maa alg none", "azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}`, map[string]any{"token": unsignedJWT(`{"alg":"none"}`, `{}`)}, testBinding, "unsupported JWS alg 'none' (MAA uses ES256 / RS256)", false},
		{"maa no signing chain", "azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}`, map[string]any{"token": unsignedJWT(`{"alg":"ES256"}`, `{}`)}, testBinding, "no signing x5c available (no JWKS and no header x5c)", false},
		{"maa kid matches nothing", "azure-maa", `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}`, map[string]any{"token": unsignedJWT(`{"alg":"ES256","kid":"zz"}`, `{}`), "jwks": map[string]any{"keys": []any{map[string]any{"kid": "other", "x5c": []any{"AA=="}}}}}, testBinding, "no JWKS key matches the token kid 'zz' (untrusted signer)", false},

		{"gcp nil evidence", "gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`, nil, testBinding, "no GCP Confidential Space token for this action", false},
		{"gcp alg none", "gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`, map[string]any{"token": unsignedJWT(`{"alg":"none"}`, `{}`)}, testBinding, "unsupported JWS alg 'none' (Confidential Space uses RS256)", false},
		{"gcp no kid, no key", "gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`, map[string]any{"token": unsignedJWT(`{"alg":"ES256"}`, `{}`)}, testBinding, "Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available", false},
		{"gcp unknown kid", "gcp-confidential-space", `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}`, map[string]any{"token": unsignedJWT(`{"alg":"ES256","kid":"zz"}`, `{}`)}, testBinding, "Confidential Space signing key invalid: no JWKS key matches the token kid 'zz' (untrusted signer)", false},

		{"nvidia nil evidence", "nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"],"policy":{"measurements":{"1":"aa"}}}`, nil, testBinding, "no NVIDIA GPU evidence for this action", false},
		{"nvidia empty chain", "nvidia-gpu-spdm", `{"rootSpkiSha256":["aa"],"policy":{"measurements":{"1":"aa"}}}`, map[string]any{"evidence": "AA==", "certChainPem": ""}, testBinding, "device chain unparseable: parsePemChain: no certificates found", false},
	}
	for _, c := range cases {
		ver, err := VerifierFromConfig(c.vendor, cfgOf(t, c.cfg))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		r := ver.Verify(c.ev, c.expected, 1_800_000_000_000)
		if r.OK || r.Bound || r.Measured != nil || r.HostAsserted != nil {
			t.Errorf("%s: must be a plain denial, got %+v", c.name, r)
			continue
		}
		if c.prefix {
			if !strings.HasPrefix(r.Reason, c.want) {
				t.Errorf("%s: reason %q does not start with %q", c.name, r.Reason, c.want)
			}
		} else if r.Reason != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, r.Reason, c.want)
		}
	}
}

// ───────────────────────────────────────────────────────────── signed tokens (Google Confidential Space)

const gcpIssuer = "https://confidentialcomputing.googleapis.com"
const tokNow = int64(1_800_000_000_000)

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := b64u(header) + "." + b64u(payload)
	h := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func bindingB64(t *testing.T, b *AttestationBinding) string {
	t.Helper()
	raw, err := attestationBindingBytes(*b)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func jwkOf(key *ecdsa.PrivateKey, kid string) map[string]any {
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return map[string]any{"kid": kid, "kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}
}

func TestGcpConfidentialSpaceSignedTokens(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nowSec := tokNow / 1000
	claims := func(mut func(m map[string]any)) string {
		m := map[string]any{
			"iss": gcpIssuer, "exp": nowSec + 3600, "iat": nowSec - 60, "nbf": nowSec - 60,
			"swname": "CONFIDENTIAL_SPACE", "swversion": []any{"240500"}, "hwmodel": "GCP_AMD_SEV", "dbgstat": "disabled-since-boot",
			"eat_nonce": []any{bindingB64(t, testBinding)},
			"submods":   map[string]any{"confidential_space": map[string]any{"support_attributes": []any{}}, "container": map[string]any{"image_digest": "sha256:ABC", "image_reference": "r/i@sha256:abc"}},
		}
		if mut != nil {
			mut(m)
		}
		return mustJSON(t, m)
	}
	hdr := `{"alg":"ES256","kid":"k1"}`
	cfg := func(policy string) map[string]any {
		c := cfgOf(t, `{"trustedIssuers":["`+gcpIssuer+`"],"trustAnchors":{},"policy":`+policy+`}`)
		c["trustAnchors"] = map[string]any{"trustedJwks": map[string]any{"keys": []any{jwkOf(key, "k1")}}}
		return c
	}
	run := func(config map[string]any, token string, b *AttestationBinding, now int64) HardwareResult {
		ver, err := VerifierFromConfig("gcp-confidential-space", config)
		if err != nil {
			t.Fatal(err)
		}
		return ver.Verify(map[string]any{"token": token}, b, now)
	}
	good := signES256(t, key, hdr, claims(nil))
	r := run(cfg(`{"imageDigests":["sha256:abc"]}`), good, testBinding, tokNow)
	if !r.OK || !r.Bound || r.Measured["runtime_measurement"] != "sha256:ABC" || r.Measured["weights_measured"] != false {
		t.Fatalf("baseline: %+v", r)
	}
	wantHost := map[string]string{"attestation_type": "sev-snp", "hwmodel": "GCP_AMD_SEV", "image_digest": "sha256:ABC", "image_reference": "r/i@sha256:abc"}
	for k, v := range wantHost {
		if r.HostAsserted[k] != v {
			t.Errorf("hostAsserted[%s] = %q, want %q", k, r.HostAsserted[k], v)
		}
	}
	relay := *testBinding
	relay.Nonce = "nonce-2"
	rows := []struct {
		name   string
		config map[string]any
		token  string
		b      *AttestationBinding
		now    int64
		want   string
	}{
		{"relayed nonce", cfg(`{"imageDigests":["sha256:abc"]}`), good, &relay, tokNow, "eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)"},
		{"image not allowed", cfg(`{"imageDigests":["sha256:other"]}`), good, testBinding, tokNow, "workload image_digest not in policy allowlist"},
		{"expired token", cfg(`{"imageDigests":["sha256:abc"]}`), good, testBinding, tokNow + 4_000_000, "Confidential Space token expired"},
		{"not yet valid", cfg(`{"imageDigests":["sha256:abc"]}`), good, testBinding, tokNow - 600_000, "Confidential Space token not yet valid (nbf)"},
		{"another signer", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, other, hdr, claims(nil)), testBinding, tokNow, "JWS ES256 signature does not verify under the Confidential Space signing key"},
		{"issuer not configured", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, key, hdr, claims(func(m map[string]any) { m["iss"] = "https://other" })), testBinding, tokNow, "token iss 'https://other' is not a configured trusted Google attestation issuer"},
		{"debug build", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, key, hdr, claims(func(m map[string]any) { m["dbgstat"] = "enabled" })), testBinding, tokNow, "token dbgstat 'enabled' is not 'disabled-since-boot' (debug build — no confidentiality)"},
		{"wrong software", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, key, hdr, claims(func(m map[string]any) { m["swname"] = "OTHER" })), testBinding, tokNow, "unexpected swname 'OTHER' (expected 'CONFIDENTIAL_SPACE')"},
		{"tee type pinned away", cfg(`{"imageDigests":["sha256:abc"],"allowedTeeTypes":["tdx"]}`), good, testBinding, tokNow, "attestation type 'sev-snp' (hwmodel 'GCP_AMD_SEV') is not in the policy allowlist"},
		{"unknown hardware model", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, key, hdr, claims(func(m map[string]any) { m["hwmodel"] = "SOMETHING" })), testBinding, tokNow, "unrecognized hwmodel 'SOMETHING' (not a known AMD SEV-SNP / Intel TDX model)"},
		{"no nonce claim", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, key, hdr, claims(func(m map[string]any) { delete(m, "eat_nonce") })), testBinding, tokNow, "token carries no eat_nonce claim to bind the PCA challenge"},
		{"no exp", cfg(`{"imageDigests":["sha256:abc"]}`), signES256(t, key, hdr, claims(func(m map[string]any) { delete(m, "exp") })), testBinding, tokNow, "token has no exp (cannot bound validity — fail closed)"},
		{"swversion not allowed", cfg(`{"imageDigests":["sha256:abc"],"allowedSwVersions":["1"]}`), good, testBinding, tokNow, "swversion not in policy allowlist"},
		{"binding not constructible", cfg(`{"imageDigests":["sha256:abc"]}`), good, &AttestationBinding{GrantRef: "g", Nonce: "n"}, tokNow, "binding not constructible: binding: holderPub required"},
		{"no expected binding", cfg(`{"imageDigests":["sha256:abc"]}`), good, nil, tokNow, "no expected attestation binding supplied"},
	}
	for _, c := range rows {
		got := run(c.config, c.token, c.b, c.now)
		if got.OK || got.Reason != c.want {
			t.Errorf("%s:\n got  %+v\n want %q", c.name, got, c.want)
		}
	}
	// the nonce hash option binds H(binding)
	hashed := func(m map[string]any) {
		raw, _ := attestationBindingBytes(*testBinding)
		h := sha256.Sum256(raw)
		m["eat_nonce"] = base64.StdEncoding.EncodeToString(h[:])
	}
	r = run(cfg(`{"imageDigests":["sha256:abc"],"nonceHash":"sha256"}`), signES256(t, key, hdr, claims(hashed)), testBinding, tokNow)
	if !r.OK {
		t.Fatalf("sha256 nonce: %+v", r)
	}
}

// ───────────────────────────────────────────────────────────── signed tokens (Azure MAA) under a generated signing certificate

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, cn string, from, to time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to,
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAzureMaaSignedTokens(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := selfSigned(t, key, "maa-test", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pinHex := hex.EncodeToString(pin[:])
	jwks := map[string]any{"keys": []any{map[string]any{"kid": "k1", "kty": "EC", "x5c": []any{base64.StdEncoding.EncodeToString(cert.Raw)}}}}
	nowSec := tokNow / 1000
	rawBinding, _ := attestationBindingBytes(*testBinding)
	mrtd := zeros96
	claims := func(mut func(m map[string]any)) string {
		m := map[string]any{
			"iss": "https://maa.test", "exp": nowSec + 3600, "iat": nowSec - 60, "nbf": nowSec - 60,
			"x-ms-isolation-tee": map[string]any{
				"x-ms-attestation-type": "tdxvm", "tdx_mrtd": strings.ToUpper(mrtd), "tdx_report_data": hex.EncodeToString(rawBinding), "attester_tcb_status": "UpToDate", "tdx_rtmr0": "bb",
			},
		}
		if mut != nil {
			mut(m)
		}
		return mustJSON(t, m)
	}
	tee := func(m map[string]any) map[string]any { return m["x-ms-isolation-tee"].(map[string]any) }
	cfg := func(pins string, policy string) map[string]any {
		return cfgOf(t, `{"trustedIssuers":["https://maa.test"],"trustAnchors":{"rootSpkiSha256":[`+pins+`]},"policy":`+policy+`}`)
	}
	run := func(config map[string]any, token string, b *AttestationBinding, now int64) HardwareResult {
		ver, err := VerifierFromConfig("azure-maa", config)
		if err != nil {
			t.Fatal(err)
		}
		return ver.Verify(map[string]any{"token": token, "jwks": jwks}, b, now)
	}
	hdr := `{"alg":"ES256","kid":"k1"}`
	good := signES256(t, key, hdr, claims(nil))
	okCfg := cfg(`"`+pinHex+`"`, `{"tdxMrtds":["`+mrtd+`"]}`)
	r := run(okCfg, good, testBinding, tokNow)
	if !r.OK || !r.Bound || r.Measured["runtime_measurement"] != mrtd || r.HostAsserted["attestation_type"] != "tdxvm" || r.HostAsserted["tcb_status"] != "UpToDate" || r.HostAsserted["rtmr0"] != "bb" {
		t.Fatalf("baseline: %+v", r)
	}
	relay := *testBinding
	relay.GrantRef = "passport:other"
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rows := []struct {
		name   string
		config map[string]any
		token  string
		b      *AttestationBinding
		now    int64
		want   string
	}{
		{"another trust pin", cfg(`"`+strings.Repeat("00", 32)+`"`, `{"tdxMrtds":["`+mrtd+`"]}`), good, testBinding, tokNow, "MAA signing chain invalid: x5c chain does not anchor in a configured MAA trust root"},
		{"signing cert expired", okCfg, good, testBinding, time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), "MAA signing chain invalid: x5c certificate at index 0 is outside its validity window"},
		{"relayed binding", okCfg, good, &relay, tokNow, "report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)"},
		{"another signer", okCfg, signES256(t, other, hdr, claims(nil)), testBinding, tokNow, "JWS ES256 signature does not verify under the MAA signing key"},
		{"measurement not allowed", cfg(`"`+pinHex+`"`, `{"tdxMrtds":["`+strings.Repeat("bb", 48)+`"]}`), good, testBinding, tokNow, "TDX MRTD not in policy allowlist"},
		{"debug guest", okCfg, signES256(t, key, hdr, claims(func(m map[string]any) { tee(m)["tdx_td_attributes_debug"] = true })), testBinding, tokNow, "TDX guest is debuggable (no confidentiality)"},
		{"tcb status not accepted", okCfg, signES256(t, key, hdr, claims(func(m map[string]any) { tee(m)["attester_tcb_status"] = "OutOfDate" })), testBinding, tokNow, "TDX platform TCB status 'OutOfDate' is not accepted by policy"},
		{"rtmr0 not allowed", cfg(`"`+pinHex+`"`, `{"tdxMrtds":["`+mrtd+`"],"tdxRtmrs":["cc"]}`), good, testBinding, tokNow, "TDX RTMR0 not in policy allowlist"},
		{"token expired", okCfg, good, testBinding, tokNow + 4_000_000, "MAA token expired"},
		{"issuer not configured", okCfg, signES256(t, key, hdr, claims(func(m map[string]any) { m["iss"] = "https://x" })), testBinding, tokNow, "token iss 'https://x' is not a configured trusted MAA instance"},
		{"isolation type unknown", okCfg, signES256(t, key, hdr, claims(func(m map[string]any) { tee(m)["x-ms-attestation-type"] = "vbs" })), testBinding, tokNow, "unexpected x-ms-attestation-type 'vbs' (expected sevsnpvm | tdxvm)"},
		{"sevsnp token with only a TDX allowlist", okCfg, signES256(t, key, hdr, claims(func(m map[string]any) {
			tee(m)["x-ms-attestation-type"] = "sevsnpvm"
			tee(m)["x-ms-sevsnpvm-reportdata"] = hex.EncodeToString(rawBinding)
		})), testBinding, tokNow, "sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)"},
		{"no report-data claim", okCfg, signES256(t, key, hdr, claims(func(m map[string]any) { delete(tee(m), "tdx_report_data") })), testBinding, tokNow, "token carries no report-data claim to bind the PCA challenge"},
	}
	for _, c := range rows {
		got := run(c.config, c.token, c.b, c.now)
		if got.OK || got.Reason != c.want {
			t.Errorf("%s:\n got  %+v\n want %q", c.name, got, c.want)
		}
	}
	// the SEV-SNP side: a launch-measurement allowlist, an SVN floor, and the reported SVNs surfaced
	sev := func(mut func(m map[string]any)) string {
		return signES256(t, key, hdr, claims(func(m map[string]any) {
			m["x-ms-isolation-tee"] = map[string]any{
				"x-ms-attestation-type": "sevsnpvm", "x-ms-sevsnpvm-reportdata": hex.EncodeToString(rawBinding), "x-ms-sevsnpvm-launchmeasurement": strings.ToUpper(mrtd),
				"x-ms-sevsnpvm-is-debuggable": false, "x-ms-sevsnpvm-snpfw-svn": 5, "x-ms-sevsnpvm-hostdata": "ABCD",
			}
			if mut != nil {
				mut(m)
			}
		}))
	}
	sevCfg := cfg(`"`+pinHex+`"`, `{"sevSnpMeasurements":["`+mrtd+`"],"sevSnpMinTcb":{"snp":5}}`)
	r = run(sevCfg, sev(nil), testBinding, tokNow)
	if !r.OK || r.HostAsserted["snpfw_svn"] != "5" || r.HostAsserted["host_data"] != "abcd" || r.Measured["runtime_measurement"] != mrtd {
		t.Fatalf("sev-snp baseline: %+v", r)
	}
	low := run(cfg(`"`+pinHex+`"`, `{"sevSnpMeasurements":["`+mrtd+`"],"sevSnpMinTcb":{"snp":6}}`), sev(nil), testBinding, tokNow)
	if low.OK || low.Reason != "SEV-SNP snp SVN 5 is below the policy minimum 6" {
		t.Errorf("svn floor: %+v", low)
	}
	missing := run(cfg(`"`+pinHex+`"`, `{"sevSnpMeasurements":["`+mrtd+`"],"sevSnpMinTcb":{"tee":1}}`), sev(nil), testBinding, tokNow)
	if missing.OK || missing.Reason != "SEV-SNP tee SVN claim 'x-ms-sevsnpvm-tee-svn' is missing or not a non-negative integer (policy requires a minimum)" {
		t.Errorf("svn missing: %+v", missing)
	}
}

// ───────────────────────────────────────────────────────────── strict DER

func derTLV(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	out := []byte{tag}
	switch {
	case len(body) < 0x80:
		out = append(out, byte(len(body)))
	case len(body) < 0x100:
		out = append(out, 0x81, byte(len(body)))
	default:
		out = append(out, 0x82, byte(len(body)>>8), byte(len(body)))
	}
	return append(out, body...)
}

func TestStrictDERLengths(t *testing.T) {
	rows := []struct {
		name string
		in   []byte
		want string
	}{
		{"multi-byte tag", []byte{0x1f, 0x01, 0x00}, "DER: multi-byte tags are not supported"},
		{"indefinite length", []byte{0x30, 0x80, 0x00, 0x00}, "DER: unsupported length form"},
		{"four length octets", []byte{0x30, 0x84, 0, 0, 0, 1, 0}, "DER: unsupported length form"},
		{"long form below 128", []byte{0x04, 0x81, 0x05, 1, 2, 3, 4, 5}, "DER: non-minimal length (long form below 128)"},
		{"leading zero length", []byte{0x04, 0x82, 0x00, 0x90}, "DER: non-minimal length (leading zero)"},
		{"truncated length", []byte{0x04, 0x82, 0x01}, "DER: truncated length"},
		{"overrun", []byte{0x04, 0x05, 1}, "DER: element overruns its parent"},
		{"truncated header", []byte{0x04}, "DER: truncated header"},
	}
	for _, r := range rows {
		if _, err := readTlvStrict(r.in, 0, len(r.in)); err == nil || err.Error() != r.want {
			t.Errorf("%s: %v, want %q", r.name, err, r.want)
		}
	}
	if tl, err := readTlvStrict([]byte{0x04, 0x81, 0x80}, 0, 3); err == nil {
		t.Errorf("a long form carrying 128 over a 1-byte body must overrun: %+v", tl)
	}
	body := make([]byte, 200)
	if tl, err := readTlvStrict(append([]byte{0x04, 0x81, 200}, body...), 0, 203); err != nil || tl.start != 3 || tl.end != 203 {
		t.Errorf("a minimal long form must parse: %+v %v", tl, err)
	}
}

func TestStrictExtensionTable(t *testing.T) {
	bcOID := []byte{0x06, 0x03, 0x55, 0x1d, 0x13}
	ext := func(critical []byte, value []byte, trailing ...byte) []byte {
		parts := [][]byte{bcOID}
		if critical != nil {
			parts = append(parts, critical)
		}
		parts = append(parts, derTLV(0x04, value))
		if len(trailing) > 0 {
			parts = append(parts, trailing)
		}
		return derTLV(0x30, parts...)
	}
	tbs := func(exts ...[]byte) []byte {
		block := derTLV(0xa3, derTLV(0x30, exts...))
		return derTLV(0x30, derTLV(0x02, []byte{1}), block)
	}
	trueDER := []byte{0x01, 0x01, 0xff}
	val := []byte{0x30, 0x00}

	tbl, err := parseTbsExtensions(tbs(ext(trueDER, val)))
	if err != nil || len(tbl.oids) != 1 || tbl.oids[0] != "2.5.29.19" || !tbl.m["2.5.29.19"].critical || hex.EncodeToString(tbl.m["2.5.29.19"].value) != "3000" {
		t.Fatalf("ok table: %+v %v", tbl, err)
	}
	rows := []struct {
		name string
		in   []byte
		want string
	}{
		{"critical not 0xff", tbs(ext([]byte{0x01, 0x01, 0x01}, val)), "extension 2.5.29.19 has a non-DER critical flag"},
		{"explicit FALSE", tbs(ext([]byte{0x01, 0x01, 0x00}, val)), "extension 2.5.29.19 has a non-DER critical flag"},
		{"duplicate", tbs(ext(trueDER, val), ext(nil, val)), "duplicate extension 2.5.29.19"},
		{"empty block", tbs(), "empty Extensions SEQUENCE"},
		{"trailing bytes in extension", tbs(ext(trueDER, val, 0x00)), "extension 2.5.29.19 has trailing bytes"},
		{"trailing bytes after tbs", append(tbs(ext(trueDER, val)), 0x00), "trailing bytes after tbsCertificate"},
		{"two extension blocks", derTLV(0x30, derTLV(0xa3, derTLV(0x30, ext(nil, val))), derTLV(0xa3, derTLV(0x30, ext(nil, val)))), "duplicate [3] extensions block"},
		{"block not last", derTLV(0x30, derTLV(0xa3, derTLV(0x30, ext(nil, val))), derTLV(0x02, []byte{1})), "extensions block is not the last TBS element"},
		{"non-minimal OID arc", derTLV(0x30, derTLV(0xa3, derTLV(0x30, derTLV(0x30, []byte{0x06, 0x03, 0x80, 0x1d, 0x13}, derTLV(0x04, val))))), "extension OID has a non-minimal arc"},
		{"truncated OID", derTLV(0x30, derTLV(0xa3, derTLV(0x30, derTLV(0x30, []byte{0x06, 0x02, 0x55, 0x9d}, derTLV(0x04, val))))), "extension OID is truncated"},
		{"value not an OCTET STRING", derTLV(0x30, derTLV(0xa3, derTLV(0x30, derTLV(0x30, bcOID, derTLV(0x02, []byte{1}))))), "extension 2.5.29.19 value is not an OCTET STRING"},
	}
	for _, r := range rows {
		if _, err := parseTbsExtensions(r.in); err == nil || err.Error() != r.want {
			t.Errorf("%s: %v, want %q", r.name, err, r.want)
		}
	}
}

func TestStrictDerTime(t *testing.T) {
	rows := []struct {
		tag  int
		text string
		ms   int64
		ok   bool
	}{
		{0x17, "250101000000Z", 1735689600000, true},
		{0x17, "251231235959Z", 1767225599000, true},
		{0x17, "500101000000Z", -631152000000, true},
		{0x17, "490101000000Z", 2493072000000, true},
		{0x18, "20250101000000Z", 1735689600000, true},
		{0x17, "250230000000Z", 0, false},
		{0x17, "250101000060Z", 0, false},
		{0x17, "251301000000Z", 0, false},
		{0x17, "250101240000Z", 0, false},
		{0x17, "2501010000Z", 0, false},
		{0x17, "250101000000+0100", 0, false},
		{0x17, "25010100000AZ", 0, false},
		{0x18, "20250101000000.5Z", 0, false},
		{0x18, "250101000000Z", 0, false},
		{0x16, "250101000000Z", 0, false},
	}
	for _, r := range rows {
		got := parseDerTime(r.tag, r.text)
		if got.ok != r.ok || (r.ok && got.ms != r.ms) {
			t.Errorf("%#x %q: %+v, want ok=%v ms=%d", r.tag, r.text, got, r.ok, r.ms)
		}
	}
}

func TestChainRolesAndExtensionsOfGeneratedCertificates(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	nb, na := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(tmpl *x509.Certificate, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		tmpl.NotBefore, tmpl.NotAfter = nb, na
		if tmpl.SerialNumber == nil {
			tmpl.SerialNumber = big.NewInt(1)
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	rk, ik, lk := newKey(), newKey(), newKey()
	root := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "root"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, nil, &rk.PublicKey, rk)
	rootPath0 := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "root0"}, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, nil, &rk.PublicKey, rk)
	inter := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "inter"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, root, &ik.PublicKey, rk)
	leaf := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, BasicConstraintsValid: true, IsCA: false, KeyUsage: x509.KeyUsageDigitalSignature}, inter, &lk.PublicKey, ik)
	caLeaf := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "caleaf"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, inter, &lk.PublicKey, ik)
	noBC := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "nobc"}}, nil, &ik.PublicKey, ik)
	notCA := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "notca"}, BasicConstraintsValid: true, IsCA: false}, nil, &ik.PublicKey, ik)
	noCertSign := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "nocs"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature}, nil, &ik.PublicKey, ik)
	critical := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "crit"}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}}, inter, &lk.PublicKey, ik)

	raw := func(cs ...*x509.Certificate) [][]byte {
		var out [][]byte
		for _, c := range cs {
			out = append(out, c.Raw)
		}
		return out
	}
	rows := []struct {
		name  string
		chain [][]byte
		want  string
	}{
		{"leaf, intermediate, root", raw(leaf, inter, root), ""},
		{"a bare root", raw(root), ""},
		{"leaf that is a CA", raw(caLeaf, inter, root), "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"},
		{"issuer without BasicConstraints", raw(leaf, noBC), "issuer certificate at depth 1 has no BasicConstraints (not a CA)"},
		{"issuer that is not a CA", raw(leaf, notCA), "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)"},
		{"issuer without keyCertSign", raw(leaf, noCertSign), "issuer certificate at depth 1 keyUsage lacks keyCertSign"},
		{"path length exceeded", raw(leaf, inter, rootPath0), "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"},
	}
	for _, r := range rows {
		if got := checkChainRoles(r.chain); got != r.want {
			t.Errorf("%s: %q, want %q", r.name, got, r.want)
		}
	}
	if got := checkChainRoles([][]byte{{0x30, 0x00}}); got != "" && !strings.HasPrefix(got, "certificate extension parse failed: ") {
		t.Errorf("garbage: %q", got)
	}
	if got := checkChainRoles([][]byte{leaf.Raw, {0x30, 0x03, 1, 2, 3}}); !strings.HasPrefix(got, "certificate extension parse failed: ") {
		t.Errorf("a malformed issuer must fail with the parse reason: %q", got)
	}

	if oid, found, err := unrecognisedCriticalExtension(critical.Raw, nil); err != nil || !found || oid != "1.2.3.4" {
		t.Errorf("critical: %q %v %v", oid, found, err)
	}
	if _, found, err := unrecognisedCriticalExtension(critical.Raw, map[string]bool{"1.2.3.4": true, "2.5.29.19": true, "2.5.29.15": true}); err != nil || found {
		t.Errorf("recognised critical extension must pass: %v %v", found, err)
	}
	if _, found, err := unrecognisedCriticalExtension(leaf.Raw, nil); err != nil || found {
		t.Errorf("a leaf with BasicConstraints and keyUsage only: %v %v", found, err)
	}

	info, err := readCertRoleInfo(rootPath0.Raw)
	if err != nil || !info.hasBasicConstraints || !info.ca || info.pathLen != 0 || !info.hasKeyUsage || !info.keyCertSign {
		t.Errorf("role info: %+v %v", info, err)
	}
	if _, err := readCertRoleInfo(append(append([]byte{}, leaf.Raw...), 0)); err == nil || err.Error() != "trailing bytes after the certificate" {
		t.Errorf("trailing bytes after the certificate: %v", err)
	}

	from, to := derValidity(leaf.Raw)
	if !from.ok || !to.ok || from.ms != nb.UnixMilli() || to.ms != na.UnixMilli() {
		t.Errorf("validity: %+v %+v", from, to)
	}
	if !derValidAt(leaf.Raw, nb.UnixMilli(), 0) || !derValidAt(leaf.Raw, na.UnixMilli(), 0) || derValidAt(leaf.Raw, nb.UnixMilli()-1, 0) || derValidAt(leaf.Raw, na.UnixMilli()+1, 0) {
		t.Error("the validity window is inclusive at both ends")
	}
	if !derValidAt(leaf.Raw, nb.UnixMilli()-5, 5) || !derValidAt(leaf.Raw, na.UnixMilli()+5, 5) || derValidAt(leaf.Raw, na.UnixMilli()+6, 5) {
		t.Error("the skew widens both ends")
	}
	if derValidAt([]byte{0x30, 0x00}, 0, 0) {
		t.Error("an unparseable certificate is never valid")
	}
	// the chain signature primitives
	att := func(c *x509.Certificate) *attCert {
		a, err := parseCertDER(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if !certSigOKBy(att(leaf), att(inter)) || certSigOKBy(att(leaf), att(root)) || !certSigOKBy(att(root), att(root)) || !certSigOKBy(att(inter), att(root)) {
		t.Error("certificate signatures")
	}
	if !certIsCA(att(inter)) || certIsCA(att(leaf)) || certIsCA(att(noBC)) || certIsCA(att(noCertSign)) {
		t.Error("certIsCA")
	}
	// a certificate crypto/x509 refuses but the reference's engine reads: trailing bytes after it, a non-minimal outer length
	padded := append(append([]byte{}, leaf.Raw...), 0x00)
	if c, err := parseCertDER(padded); err != nil || len(c.Raw) != len(leaf.Raw) {
		t.Errorf("trailing bytes after a DER certificate are ignored: %v", err)
	}
	if _, err := readCertRoleInfo(padded); err == nil {
		t.Error("the strict reader must still refuse them")
	}
	if c, err := parseCertDER(leaf.Raw); err != nil || c.Serial[len(c.Serial)-1] != 1 || certSerialHex(c) != "1" {
		t.Errorf("serial %v %v", c, err)
	}
	if _, err := certFromPEM("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(padded) + "\n-----END CERTIFICATE-----"); err == nil {
		t.Error("a byte after the certificate inside a PEM block is an error")
	}
	if c, err := certFromPEM("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(leaf.Raw) + "\n-----END CERTIFICATE-----"); err != nil || certSelfIssued(c) {
		t.Errorf("pem: %v", err)
	}
	if k, err := keyOfCert(att(leaf)); err != nil || k.typ != "ec" || k.curve != "prime256v1" {
		t.Errorf("key: %+v %v", k, err)
	}
	// the name rendering used for subjects
	if got := nameText(leaf.RawSubject); got != "CN=leaf" {
		t.Errorf("name text %q", got)
	}
	if got := fmt.Sprint(nameText(mk(&x509.Certificate{Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"NVIDIA"}, CommonName: "GH100, A01"}}, nil, &lk.PublicKey, lk).RawSubject)); got != "C=US\nO=NVIDIA\nCN=GH100\\, A01" {
		t.Errorf("multi-attribute subject %q", got)
	}
}

func TestVbiosVersionFormat(t *testing.T) {
	if got := formatVbiosVersion([]byte{0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa}); got != "96.00.9f.00.04" {
		t.Errorf("vbios version %q", got)
	}
}

func TestNodeBase64(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"AAEC", "000102"}, {"AAE=", "0001"}, {"AA==", "00"}, {"AA", "00"}, {"A A\nE C", "000102"}, {"-_8=", "fbff"}, {"+/8=", "fbff"}, {"AA==AAEC", "00"}, {"", ""},
	} {
		if got := hex.EncodeToString(nodeB64(c.in)); got != c.want {
			t.Errorf("%q: %s, want %s", c.in, got, c.want)
		}
	}
}
