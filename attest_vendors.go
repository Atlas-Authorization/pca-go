package pca

// The vendor attestation facades under their reference names: the suite and pin constants, the PEM / SEC1 helpers, the Intel TDX
// quote and report parsers, the PCK chain, the CRL and signed-JSON checks, the Azure runtime-data binding, the MAA and Confidential
// Space token parsers, the x5c chain checks, the hardware-model mapper and the JWKS fetchers over an injected transport. Each is a
// thin layer over the vendor verifiers (attest_intel.go, attest_intel_collateral.go, attest_maa.go, attest_gcp.go); the genuine-quote
// and collateral verifiers are VerifyGenuineTdxQuoteBound and VerifyIntelTdxCollateral (attest_public_surface.go).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// The suite names and the Confidential Space defaults.
const (
	IntelDcapSuite     = "intel-tdx-dcap-ecdsa-p256"
	AzureMaaSuite      = "azure-maa-jwt"
	GcpCsSuite         = "gcp-confidential-space-jwt"
	GcpCsDefaultIssuer = "https://confidentialcomputing.googleapis.com"
	AmdSnpSuite        = "amd-sev-snp-ecdsa-p384"
)

// AzureMaaSuites and GcpCsSuites are the JWS algorithms of the MAA and Confidential Space verifiers.
var (
	AzureMaaSuites = []string{"ES256", "RS256"}
	GcpCsSuites    = []string{"RS256", "ES256"}
)

// VendorConstants are the suite names, the Intel SGX root pin, the AMD ARK pins and the default accepted TCB statuses.
func VendorConstants() map[string]any {
	ark := map[string]any{}
	for k, v := range amdARKSpkiSHA384 {
		ark[k] = v
	}
	statuses := make([]any, len(defaultAcceptedStatuses))
	for i, s := range defaultAcceptedStatuses {
		statuses[i] = s
	}
	return map[string]any{
		"INTEL_DCAP_SUITE": IntelDcapSuite, "AZURE_MAA_SUITE": AzureMaaSuite, "AZURE_MAA_SUITES": strsAny(AzureMaaSuites),
		"GCP_CS_SUITE": GcpCsSuite, "GCP_CS_SUITES": strsAny(GcpCsSuites), "GCP_CS_DEFAULT_ISSUER": GcpCsDefaultIssuer,
		"INTEL_SGX_ROOT_CA_SPKI_SHA256": intelSGXRootCASpkiSHA256, "AMD_SNP_SUITE": AmdSnpSuite, "AMD_ARK_SPKI_SHA384": ark,
		"DEFAULT_ACCEPTED_STATUSES": statuses,
	}
}

func strsAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// ToHex is the lowercase hex of b.
func ToHex(b []byte) string { return toHexLower(b) }

// PemToDer is the DER of the first certificate block of a PEM text (the base64 body, whitespace removed).
func PemToDer(pemText string) ([]byte, error) {
	m := pemCertBodyRe.FindStringSubmatch(pemText)
	if m == nil || m[1] == "" {
		return nil, errors.New("pemToDer: no certificate found")
	}
	return nodeB64(strings.Map(func(r rune) rune {
		if isJSSpace(r) {
			return -1
		}
		return r
	}, m[1])), nil
}

// EcdsaP256PublicKey is the uncompressed SEC1 point (65 bytes) of a P-256 public key given compressed (33) or uncompressed (65); an
// off-curve point is an error.
func EcdsaP256PublicKey(sec1 []byte) ([]byte, error) {
	var pub *ecdsa.PublicKey
	switch {
	case len(sec1) == 65 && sec1[0] == 0x04:
		if p, ok := pointToKey(elliptic.P256(), sec1); ok {
			pub = p
		}
	case len(sec1) == 33 && (sec1[0] == 0x02 || sec1[0] == 0x03):
		if x, y := elliptic.UnmarshalCompressed(elliptic.P256(), sec1); x != nil {
			pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		}
	default:
		return nil, fmt.Errorf("invalid Point, expected length of 33, or uncompressed 65, got %d", len(sec1))
	}
	if pub == nil {
		return nil, errors.New("bad point: not on the P-256 curve")
	}
	return ecPointOfKey(keyInfoOf(pub, nil), "P-256")
}

// DcapTdReport is the TD report body of a DCAP v4 quote (the first 584 bytes).
type DcapTdReport struct {
	TeeTcbSvn, MrSeam, MrSignerSeam, TdAttributes, MrTd, MrConfigId []byte
	Rtmr0, Rtmr1, Rtmr2, Rtmr3, ReportData, Raw                     []byte
}

// ParseDcapTdReport reads the TD report fields of a body of at least 584 bytes.
func ParseDcapTdReport(body []byte) (*DcapTdReport, error) {
	if len(body) < dcapTdReportLen {
		return nil, fmt.Errorf("parseDcapTdReport: body too short (%d < %d)", len(body), dcapTdReportLen)
	}
	at := func(off, n int) []byte { return append([]byte{}, body[off:off+n]...) }
	return &DcapTdReport{TeeTcbSvn: at(0, 16), MrSeam: at(16, 48), MrSignerSeam: at(64, 48), TdAttributes: at(120, 8), MrTd: at(136, 48),
		MrConfigId: at(184, 48), Rtmr0: at(328, 48), Rtmr1: at(376, 48), Rtmr2: at(424, 48), Rtmr3: at(472, 48), ReportData: at(520, 64),
		Raw: at(0, dcapTdReportLen)}, nil
}

// NewTdxQuotePolicy builds the measurement policy of a genuine TDX quote check. An empty mrtds / fmspcs / rtmrs list is not gated; a
// non-nil mrSeams / mrSignerSeams list is always gated (an empty one refuses every quote). Entries are compared lowercase.
func NewTdxQuotePolicy(mrtds, fmspcs, rtmrs, mrSeams, mrSignerSeams []string, allowDebug bool) *TdxQuotePolicy {
	return &tdxQuotePolicy{mrtds: lowerAll(mrtds), fmspcs: lowerAll(fmspcs), rtmrs: lowerAll(rtmrs), mrSeams: lowerAll(mrSeams), mrSignerSeams: lowerAll(mrSignerSeams),
		hasMrSeams: mrSeams != nil, hasMrSigner: mrSignerSeams != nil, allowDebug: allowDebug}
}

// NewIntelCollateral is the Intel PCS collateral bundle: the signed TCB info and QE identity documents, their issuer chains (PEM) and
// the PCK and Root CA CRLs (DER).
func NewIntelCollateral(tcbInfoJSON, tcbInfoIssuerChainPem, qeIdentityJSON, qeIdentityIssuerChainPem string, pckCrlDer, rootCrlDer []byte) *IntelCollateral {
	return &intelCollateral{tcbInfoJSON: tcbInfoJSON, tcbInfoChain: tcbInfoIssuerChainPem, qeIdentityJSON: qeIdentityJSON, qeIdentityChain: qeIdentityIssuerChainPem,
		pckCrl: pckCrlDer, rootCrl: rootCrlDer}
}

// PckChainX509Result is the outcome of VerifyIntelPckChainX509.
type PckChainX509Result struct {
	Ok     bool
	Reason string
	// Failure is "validity" when a certificate is outside its validity window.
	Failure string
	LeafDer []byte
	// LeafPoint is the PCK leaf's uncompressed P-256 point.
	LeafPoint []byte
	Depth     int
}

// VerifyIntelPckChainX509 verifies a PEM PCK chain to the pinned Intel SGX Root CA at nowMs (an empty pin is the built-in root).
func VerifyIntelPckChainX509(pckChainPem, pin string, nowMs int64) PckChainX509Result {
	if pin == "" {
		pin = intelSGXRootCASpkiSHA256
	}
	r := verifyIntelPckChain(pckChainPem, pin, nowMs)
	if !r.ok {
		out := PckChainX509Result{Reason: r.reason}
		if r.validity {
			out.Failure = "validity"
		}
		return out
	}
	pt, _ := ecPointOfKey(keyInfoOf(r.leafKey, nil), "P-256")
	return PckChainX509Result{Ok: true, LeafDer: append([]byte{}, r.leaf.Raw...), LeafPoint: pt, Depth: r.depth}
}

func spkiKey(spkiDer []byte) (certKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spkiDer)
	if err != nil {
		return certKey{}, err
	}
	return keyInfoOf(pub, spkiDer), nil
}

// VerifyCrlSpki verifies a DER CRL under the issuer public key (its SubjectPublicKeyInfo DER) at nowMs: the revoked serials (lowercase
// hex, no leading zeros, sorted) or the failure reason.
func VerifyCrlSpki(crlDer, issuerSpkiDer []byte, nowMs int64) ([]string, string) {
	k, err := spkiKey(issuerSpkiDer)
	if err != nil {
		return nil, "CRL issuer key unreadable: " + errMsg(err)
	}
	set, why := verifyCRL(crlDer, k, nowMs)
	if why != "" {
		return nil, why
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, ""
}

// VerifySignedJsonSpki verifies an Intel PCS signed document under the signer public key (SubjectPublicKeyInfo DER): the body under
// name, or the failure text.
func VerifySignedJsonSpki(text, name string, signerSpkiDer []byte) (map[string]any, string) {
	k, err := spkiKey(signerSpkiDer)
	if err != nil {
		return nil, "signer key unreadable: " + errMsg(err)
	}
	return verifySignedJSON(text, name, k)
}

// DecodeIssuerChainHeader decodes a PCS issuer-chain HTTP header value (URL-encoded PEM) like decodeURIComponent: a plus stays a
// plus, and a malformed escape or an escaped byte sequence that is not UTF-8 is an error.
func DecodeIssuerChainHeader(value string) (string, error) {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			out = append(out, value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", errors.New("URI malformed")
		}
		hi, ok1 := hexNibble(value[i+1])
		lo, ok2 := hexNibble(value[i+2])
		if !ok1 || !ok2 {
			return "", errors.New("URI malformed")
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	if !utf8.Valid(out) {
		return "", errors.New("URI malformed")
	}
	return string(out), nil
}

// CheckAzureRuntimeDataBinding is the failure reason of the Azure runtime-data binding of a quote's report_data, or "" when it binds.
func CheckAzureRuntimeDataBinding(reportData, runtimeData []byte, expected AttestationBinding) string {
	return checkAzureRuntimeDataBinding(reportData, runtimeData, &expected)
}

// JwsHeader is the header of a parsed compact JWS (only the members a vendor token verifier reads, each present only when it has the
// right JSON type).
type JwsHeader struct {
	Alg           string
	Kid, Jku, Typ *string
	X5c           []string // non-nil when the header carries an x5c array of strings (possibly empty)
}

// ParsedJwt is a compact JWS split into its header, payload and signing input; nothing is verified.
type ParsedJwt struct {
	Header       JwsHeader
	Payload      map[string]any
	SigningInput []byte
	Signature    []byte
}

func parseVendorJwt(token, name string) (*ParsedJwt, error) {
	t, err := parseJWT(token, name)
	if err != nil {
		return nil, err
	}
	h := JwsHeader{Alg: t.alg}
	if t.hasKid {
		h.Kid = &t.kid
	}
	if t.hasJku {
		h.Jku = &t.jku
	}
	if t.hasTyp {
		h.Typ = &t.typ
	}
	if t.hasX5c {
		h.X5c = append([]string{}, t.x5c...)
	}
	return &ParsedJwt{Header: h, Payload: t.payload, SigningInput: t.signingInput, Signature: t.signature}, nil
}

// ParseMaaJwt splits an Azure MAA token (verifying nothing); a structural violation is an error.
func ParseMaaJwt(token string) (*ParsedJwt, error) { return parseVendorJwt(token, "parseMaaJwt") }

// ParseGcpCsJwt splits a Confidential Space token (verifying nothing); a structural violation is an error.
func ParseGcpCsJwt(token string) (*ParsedJwt, error) { return parseVendorJwt(token, "parseGcpCsJwt") }

// X5cChainResult is the outcome of VerifyX5cChain.
type X5cChainResult struct {
	Ok     bool
	Reason string
	// LeafDer and LeafSpkiSha256 describe the leaf certificate (Ok only).
	LeafDer        []byte
	LeafSpkiSha256 string
}

// VerifyX5cChain verifies an MAA x5c chain (base64 DER entries, leaf first; an entry that is not a string is refused) to a configured
// anchor: a root certificate (PEM) or an SPKI SHA-256 pin. clockSkewMs below zero or not finite is zero.
func VerifyX5cChain(x5c []any, rootCertsPem, rootSpkiSha256 []string, nowMs int64, clockSkewMs float64) X5cChainResult {
	skew := 0.0
	if !math.IsNaN(clockSkewMs) && !math.IsInf(clockSkewMs, 0) {
		skew = math.Max(0, clockSkewMs)
	}
	leaf, why := maaAnchors{rootCertsPem: rootCertsPem, rootSpki: rootSpkiSha256}.verifyX5cChain(x5c, nowMs, skew)
	if leaf == nil {
		return X5cChainResult{Reason: why}
	}
	k, err := keyOfCert(leaf)
	if err != nil {
		return X5cChainResult{Reason: "x5c chain verification error (fail closed): " + errMsg(err)}
	}
	return X5cChainResult{Ok: true, LeafDer: append([]byte{}, leaf.Raw...), LeafSpkiSha256: k.spkiSHA256()}
}

// VerifyJwkX5cChain verifies a Confidential Space JWK x5c chain to a configured SPKI pin of any chain certificate or a root
// (certificate or bare public key, PEM) at nowMs: "" when it anchors, else the failure reason.
func VerifyJwkX5cChain(x5c []any, trustedKeySpki, rootCertsPem []string, nowMs int64, skewMs float64) string {
	v := &gcpVerifier{spkiPins: map[string]bool{}, rootCertsPem: rootCertsPem, skew: skewMs}
	for _, s := range trustedKeySpki {
		v.spkiPins[strings.ToLower(s)] = true
	}
	return v.verifyJwkX5cChain(x5c, nowMs)
}

// TeeTypeOfHwModel maps a Confidential Space hwmodel to "sev-snp" or "tdx" ("" when unrecognised).
func TeeTypeOfHwModel(hwmodel string) string { return gcpTeeType(hwmodel) }

// VendorFetchResponse is a transport answer: the HTTP status and the body (JSON text).
type VendorFetchResponse struct {
	Status int
	Body   []byte
}

// VendorFetch is the injected transport of the JWKS fetchers; it is called with the URL only.
type VendorFetch func(url string) (VendorFetchResponse, error)

// GcpJwk is one Confidential Space signing key (each member present only when it is a string; X5c when it is an array of strings).
type GcpJwk struct {
	Kid, Kty, Alg, Use, N, E, Crv, X, Y *string
	X5c                                 []string
}

func vendorJSON(f VendorFetch, url, failure string) (any, error) {
	res, err := f(url)
	if err != nil {
		return nil, err
	}
	if res.Status < 200 || res.Status > 299 {
		return nil, fmt.Errorf("%s: HTTP %d for %s", failure, res.Status, url)
	}
	return ParseJSONLenient(res.Body)
}

func vendorKeys(body any, what string) ([]map[string]any, error) {
	obj, _ := body.(map[string]any)
	raw, ok := obj["keys"].([]any)
	if !ok {
		return nil, errors.New(what + ": response has no keys array")
	}
	var out []map[string]any
	for _, k := range raw {
		if m, isObj := k.(map[string]any); isObj {
			out = append(out, m)
		}
	}
	return out, nil
}

func mapStrPtr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok {
		return &s
	}
	return nil
}

func x5cOf(m map[string]any) []string {
	if l, ok := asStrList(m["x5c"]); ok {
		return l
	}
	return nil
}

// FetchMaaJwks reads the MAA signing keys from <issuer><certsPath> (certsPath "/certs" when nil; trailing slashes of the issuer are
// dropped) over the injected transport: kid, kty, alg and x5c only. A non-2xx answer, a body that is not JSON and a body without a
// keys array are errors.
func FetchMaaJwks(issuer string, fetch VendorFetch, certsPath *string) (*MaaJwks, error) {
	path := "/certs"
	if certsPath != nil {
		path = *certsPath
	}
	body, err := vendorJSON(fetch, strings.TrimRight(issuer, "/")+path, "MAA JWKS fetch failed")
	if err != nil {
		return nil, err
	}
	keys, err := vendorKeys(body, "MAA JWKS fetch")
	if err != nil {
		return nil, err
	}
	out := &MaaJwks{Keys: []MaaJwk{}}
	for _, k := range keys {
		out.Keys = append(out.Keys, MaaJwk{Kid: mapStrPtr(k, "kid"), Kty: mapStrPtr(k, "kty"), Alg: mapStrPtr(k, "alg"), X5c: x5cOf(k)})
	}
	return out, nil
}

// FetchGcpConfidentialSpaceJwks reads the Confidential Space signing keys from jwksUri, or when it is empty from the jwks_uri of the
// issuer's OpenID configuration, over the injected transport.
func FetchGcpConfidentialSpaceJwks(issuer string, fetch VendorFetch, jwksUri string) ([]GcpJwk, error) {
	if jwksUri == "" {
		confURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
		conf, err := vendorJSON(fetch, confURL, "Confidential Space OpenID config fetch failed")
		if err != nil {
			return nil, err
		}
		cm, _ := conf.(map[string]any)
		uri, _ := cm["jwks_uri"].(string)
		if uri == "" {
			return nil, errors.New("Confidential Space OpenID config carries no jwks_uri")
		}
		jwksUri = uri
	}
	body, err := vendorJSON(fetch, jwksUri, "Confidential Space JWKS fetch failed")
	if err != nil {
		return nil, err
	}
	keys, err := vendorKeys(body, "Confidential Space JWKS fetch")
	if err != nil {
		return nil, err
	}
	out := []GcpJwk{}
	for _, k := range keys {
		out = append(out, GcpJwk{Kid: mapStrPtr(k, "kid"), Kty: mapStrPtr(k, "kty"), Alg: mapStrPtr(k, "alg"), Use: mapStrPtr(k, "use"), N: mapStrPtr(k, "n"), E: mapStrPtr(k, "e"),
			Crv: mapStrPtr(k, "crv"), X: mapStrPtr(k, "x"), Y: mapStrPtr(k, "y"), X5c: x5cOf(k)})
	}
	return out, nil
}
