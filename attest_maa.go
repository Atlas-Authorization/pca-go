package pca

// Microsoft Azure Attestation (MAA): the signed MAA JWT of an Azure confidential VM (SEV-SNP "sevsnpvm" or TDX "tdxvm"),
// verified under the token-signing x5c chain anchored in a configured MAA root, with the PCA challenge bound through the
// report-data or runtime user-data claim. Same checks, order and reason text as the reference verifier. Classical (ES256 /
// RS256); no network I/O. The key-rotation trust store of the reference (fetching and persisting JWKS) is not part of the
// verifier: anchors are configured explicitly.

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

type maaAnchors struct {
	rootCertsPem []string
	rootSpki     []string
}

type maaPolicy struct {
	sevSnp, tdx       []string
	sevHost, tdxRtmrs []string
	minTcb            map[string]float64
	allowDebug        bool
	runtimeUserData   bool
	tdxStatuses       []string
	hasTdxStatuses    bool
	reportDataHash    string
	hasSev, hasTdx    bool
}

type maaVerifier struct {
	issuers map[string]bool
	anchors maaAnchors
	policy  maaPolicy
	skew    float64
}

var maaTcbClaims = []struct{ name, claim, hostKey string }{
	{"bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"},
	{"snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"},
	{"microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"},
	{"tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"},
}

func listLen(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case string:
		return len(t)
	}
	return 0
}

func skewOf(cfg map[string]any) float64 {
	if f, ok := asFinite(cfg["clockSkewMs"]); ok {
		return math.Max(0, f)
	}
	return 0
}

func newMaaVerifier(cfg map[string]any) (*maaVerifier, error) {
	const p = "createAzureMaaVerifier: "
	issArr, ok := cfg["trustedIssuers"].([]any)
	if !ok || len(issArr) == 0 {
		return nil, errors.New(p + "trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")
	}
	v := &maaVerifier{issuers: map[string]bool{}}
	for _, x := range issArr {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, errors.New(p + "every trusted issuer must be a non-empty URL string")
		}
		v.issuers[s] = true
	}
	anch, _ := cfg["trustAnchors"].(map[string]any)
	if listLen(anch["rootCertsPem"])+listLen(anch["rootSpkiSha256"]) == 0 {
		return nil, errors.New(p + "trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted")
	}
	v.anchors.rootCertsPem, _ = asStrList(anch["rootCertsPem"])
	v.anchors.rootSpki, _ = asStrList(anch["rootSpkiSha256"])
	pol, isPol := cfg["policy"].(map[string]any)
	var sev, tdx []string
	if isPol {
		sev, _ = asStrList(pol["sevSnpMeasurements"])
		tdx, _ = asStrList(pol["tdxMrtds"])
	}
	v.policy.hasSev, v.policy.hasTdx = len(sev) > 0, len(tdx) > 0
	if !isPol || (!v.policy.hasSev && !v.policy.hasTdx) {
		return nil, errors.New(p + "policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)")
	}
	v.policy.sevSnp, v.policy.tdx = lowerAll(sev), lowerAll(tdx)
	if raw, present := pol["sevSnpMinTcb"]; present {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New(p + "policy.sevSnpMinTcb must be an object")
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		v.policy.minTcb = map[string]float64{}
		for _, k := range keys {
			known := false
			for _, c := range maaTcbClaims {
				if c.name == k {
					known = true
				}
			}
			if !known {
				return nil, fmt.Errorf("%spolicy.sevSnpMinTcb.%s is not a known field (bootloader | snp | microcode | tee)", p, k)
			}
			f, ok := asFinite(m[k])
			if !ok || f != math.Trunc(f) || f < 0 {
				return nil, fmt.Errorf("%spolicy.sevSnpMinTcb.%s must be a non-negative integer", p, k)
			}
			v.policy.minTcb[k] = f
		}
	}
	if l, ok := asStrList(pol["sevSnpHostData"]); ok {
		v.policy.sevHost = lowerAll(l)
	}
	if l, ok := asStrList(pol["tdxRtmrs"]); ok {
		v.policy.tdxRtmrs = lowerAll(l)
	}
	v.policy.allowDebug = pol["allowDebug"] == true
	v.policy.runtimeUserData = pol["runtimeUserDataBinding"] == true
	if l, ok := asStrList(pol["tdxAllowedTcbStatuses"]); ok {
		v.policy.tdxStatuses, v.policy.hasTdxStatuses = l, true
	}
	v.policy.reportDataHash, _ = pol["reportDataHash"].(string)
	v.skew = skewOf(cfg)
	return v, nil
}

// ───────────────────────────────────────────────────────────── x5c chain

// verifyX5cChain verifies an x5c chain (base64 DER, leaf first) to a configured trust anchor. The leaf, or the failure reason.
func (a maaAnchors) verifyX5cChain(x5c []any, nowMs int64, skew float64) (*attCert, string) {
	thrown := func(err error) (*attCert, string) {
		return nil, "x5c chain verification error (fail closed): " + errMsg(err)
	}
	if len(x5c) == 0 {
		return nil, "empty x5c certificate chain"
	}
	certs := make([]*attCert, 0, len(x5c))
	for i, e := range x5c {
		b64, ok := e.(string)
		if !ok || b64 == "" {
			return nil, fmt.Sprintf("empty x5c entry at index %d", i)
		}
		c, err := parseCertDER(nodeB64(b64))
		if err != nil {
			return nil, fmt.Sprintf("malformed x5c certificate at index %d: %s", i, errMsg(err))
		}
		if !derValidAtF(c.Raw, nowMs, skew) {
			return nil, fmt.Sprintf("x5c certificate at index %d is outside its validity window", i)
		}
		certs = append(certs, c)
	}
	fingerprints := map[string]bool{}
	for _, fp := range a.rootSpki {
		if fp != "" {
			fingerprints[strings.ToLower(fp)] = true
		}
	}
	var roots []*attCert
	for _, pem := range a.rootCertsPem {
		c, err := certFromPEM(pem)
		if err != nil {
			return thrown(err)
		}
		k, err := keyOfCert(c)
		if err != nil {
			return thrown(err)
		}
		roots = append(roots, c)
		fingerprints[k.spkiSHA256()] = true
	}
	if len(fingerprints) == 0 && len(roots) == 0 {
		return nil, "no MAA trust anchor configured (fail closed)"
	}
	anchorIdx := -1
	for j, c := range certs {
		k, err := keyOfCert(c)
		if err != nil {
			return thrown(err)
		}
		if fingerprints[k.spkiSHA256()] {
			anchorIdx = j
			break
		}
	}
	if anchorIdx >= 0 {
		for i := 0; i < anchorIdx; i++ {
			if !certSigOKBy(certs[i], certs[i+1]) {
				return nil, fmt.Sprintf("x5c link %d is not signed by the certificate above it", i)
			}
		}
		return certs[0], ""
	}
	for i := 0; i < len(certs)-1; i++ {
		if !certSigOKBy(certs[i], certs[i+1]) {
			return nil, fmt.Sprintf("x5c link %d is not signed by the certificate above it", i)
		}
	}
	top := certs[len(certs)-1]
	for _, r := range roots {
		if certSigOKBy(top, r) {
			return certs[0], ""
		}
	}
	return nil, "x5c chain does not anchor in a configured MAA trust root"
}

// resolveSigningX5c: the JWKS entry matched by kid, else the header's own x5c.
func resolveSigningX5c(tok *jwtParsed, jwks any) ([]any, string) {
	var keys []any
	if m, ok := jwks.(map[string]any); ok {
		keys, _ = m["keys"].([]any)
	}
	chainOf := func(k any) []any {
		rec, _ := k.(map[string]any)
		c, _ := rec["x5c"].([]any)
		return c
	}
	if len(keys) > 0 {
		if !tok.hasKid || tok.kid == "" {
			if len(keys) != 1 {
				return nil, "token has no kid and the JWKS publishes multiple keys (ambiguous)"
			}
			if c := chainOf(keys[0]); len(c) > 0 {
				return c, ""
			}
			return nil, "JWKS key carries no x5c chain"
		}
		for _, k := range keys {
			rec, _ := k.(map[string]any)
			if kid, ok := rec["kid"].(string); ok && kid == tok.kid {
				if c := chainOf(k); len(c) > 0 {
					return c, ""
				}
				return nil, fmt.Sprintf("JWKS key '%s' carries no x5c chain", tok.kid)
			}
		}
		return nil, fmt.Sprintf("no JWKS key matches the token kid '%s' (untrusted signer)", tok.kid)
	}
	if tok.hasX5c && len(tok.x5c) > 0 {
		out := make([]any, len(tok.x5c))
		for i, s := range tok.x5c {
			out[i] = s
		}
		return out, ""
	}
	return nil, "no signing x5c available (no JWKS and no header x5c)"
}

func (v *maaVerifier) jwsSignature(tok *jwtParsed, leaf *attCert) string {
	k, err := keyOfCert(leaf)
	if err != nil {
		return "x5c chain verification error (fail closed): " + errMsg(err)
	}
	kty, crv := jwkKtyCrv(k)
	switch tok.alg {
	case "ES256":
		if kty != "EC" || crv != "P-256" {
			return fmt.Sprintf("ES256 token but signing key is %s/%s (not EC P-256)", kty, crv)
		}
		if len(tok.signature) != 64 {
			return fmt.Sprintf("ES256 signature is %d bytes (expected 64: r‖s)", len(tok.signature))
		}
		if !jwsES256OK(tok.signature, tok.signingInput, k) {
			return "JWS ES256 signature does not verify under the MAA signing key"
		}
		return ""
	case "RS256":
		if kty != "RSA" {
			return fmt.Sprintf("RS256 token but signing key is %s (not RSA)", kty)
		}
		if !jwsRS256OK(tok.signature, tok.signingInput, k) {
			return "JWS RS256 signature does not verify under the MAA signing key"
		}
		return ""
	}
	return fmt.Sprintf("unsupported JWS alg '%s' (MAA uses ES256 / RS256)", tok.alg)
}

func firstString(rec map[string]any, keys []string) (string, bool) {
	for _, k := range keys {
		if s, ok := rec[k].(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

func transformBinding(binding []byte, mode string) []byte {
	switch mode {
	case "sha256":
		return sha256Sum(binding)
	case "sha512":
		return sha512Sum(binding)
	}
	return binding
}

func (v *maaVerifier) verify(ev map[string]any, expected *AttestationBinding, nowMs int64) HardwareResult {
	token, ok := ev["token"].(string)
	if ev == nil || !ok || token == "" {
		return hwFail("no Azure MAA token for this action")
	}
	tok, err := parseJWT(token, "parseMaaJwt")
	if err != nil {
		return hwFail("MAA token parse failed: " + err.Error())
	}
	if tok.alg != "ES256" && tok.alg != "RS256" {
		return hwFail(fmt.Sprintf("unsupported JWS alg '%s' (MAA uses ES256 / RS256)", tok.alg))
	}
	x5c, why := resolveSigningX5c(tok, ev["jwks"])
	if x5c == nil {
		return hwFail(why)
	}
	leaf, why := v.anchors.verifyX5cChain(x5c, nowMs, v.skew)
	if leaf == nil {
		return hwFail("MAA signing chain invalid: " + why)
	}
	if sigErr := v.jwsSignature(tok, leaf); sigErr != "" {
		return hwFail(sigErr)
	}

	payload := tok.payload
	iss, issIsStr := payload["iss"].(string)
	if iss == "" || !v.issuers[iss] {
		shown := iss
		if !issIsStr {
			shown = "undefined"
		}
		return hwFail(fmt.Sprintf("token iss '%s' is not a configured trusted MAA instance", shown))
	}
	nowSec := math.Floor(float64(nowMs) / 1000)
	skewSec := math.Ceil(v.skew / 1000)
	exp, hasExp := asFinite(payload["exp"])
	iat, hasIat := asFinite(payload["iat"])
	nbf, hasNbf := asFinite(payload["nbf"])
	if !hasExp {
		return hwFail("token has no exp (cannot bound validity — fail closed)")
	}
	if nowSec-skewSec > exp {
		return hwFail("MAA token expired")
	}
	if hasNbf && nowSec+skewSec < nbf {
		return hwFail("MAA token not yet valid (nbf)")
	}
	if hasIat && nowSec+skewSec < iat {
		return hwFail("MAA token issued in the future (iat)")
	}

	teeClaims := payload
	if iso, ok := payload["x-ms-isolation-tee"].(map[string]any); ok {
		teeClaims = iso
	}
	isolation, hasIso := teeClaims["x-ms-attestation-type"].(string)
	if !hasIso {
		isolation, hasIso = payload["x-ms-attestation-type"].(string)
	}
	if !hasIso || (isolation != "sevsnpvm" && isolation != "tdxvm") {
		shown := "undefined"
		if hasIso {
			shown = isolation
		}
		return hwFail(fmt.Sprintf("unexpected x-ms-attestation-type '%s' (expected sevsnpvm | tdxvm)", shown))
	}

	if expected == nil {
		return hwFail("no expected attestation binding supplied")
	}
	if v.policy.runtimeUserData {
		raw, err := attestationBindingBytes(*expected)
		if err != nil {
			return hwFail("binding not constructible: " + err.Error())
		}
		runtime, ok := payload["x-ms-runtime"].(map[string]any)
		if !ok {
			return hwFail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
		}
		ud, _ := runtime["user-data"].(string)
		if ud == "" {
			return hwFail("x-ms-runtime carries no user-data to bind the PCA challenge")
		}
		got := decodeClaimBytes(ud)
		if got == nil || !timingSafeEq(got, raw) {
			return hwFail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
		}
	} else {
		raw, err := attestationBindingBytes(*expected)
		if err != nil {
			return hwFail("binding not constructible: " + err.Error())
		}
		bindingBytes := transformBinding(raw, v.policy.reportDataHash)
		keys := []string{"tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata"}
		if isolation == "sevsnpvm" {
			keys = []string{"x-ms-sevsnpvm-reportdata"}
		}
		claim, ok := firstString(teeClaims, keys)
		if !ok {
			return hwFail("token carries no report-data claim to bind the PCA challenge")
		}
		got := decodeClaimBytes(claim)
		if got == nil {
			return hwFail("report-data claim is not decodable (hex/base64)")
		}
		if !timingSafeEq(got, bindingBytes) {
			return hwFail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
		}
	}

	if isolation == "sevsnpvm" {
		return v.sevSnpResult(teeClaims)
	}
	return v.tdxResult(teeClaims)
}

func jsStringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return "undefined"
	}
	return fmt.Sprint(v)
}

func (v *maaVerifier) sevSnpResult(tee map[string]any) HardwareResult {
	if !v.policy.hasSev {
		return hwFail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)")
	}
	measurement, ok := firstString(tee, []string{"x-ms-sevsnpvm-launchmeasurement"})
	if !ok {
		return hwFail("sevsnpvm token carries no launch-measurement claim")
	}
	mHex := strings.ToLower(measurement)
	if !containsStr(v.policy.sevSnp, mHex) {
		return hwFail("SEV-SNP launch measurement not in policy allowlist")
	}
	if dbg, ok := tee["x-ms-sevsnpvm-is-debuggable"].(bool); ok && dbg && !v.policy.allowDebug {
		return hwFail("SEV-SNP guest is debuggable (no confidentiality)")
	}
	hostData, hasHost := firstString(tee, []string{"x-ms-sevsnpvm-hostdata"})
	if len(v.policy.sevHost) > 0 {
		if !hasHost || !containsStr(v.policy.sevHost, strings.ToLower(hostData)) {
			return hwFail("SEV-SNP host-data not in policy allowlist")
		}
	}
	reported := map[string]string{}
	for _, c := range maaTcbClaims {
		f, isNum := asFinite(tee[c.claim])
		isSvn := isNum && f == math.Trunc(f) && f >= 0
		if isSvn {
			reported[c.hostKey] = jsNumString(f)
		}
		floor, has := v.policy.minTcb[c.name]
		if !has {
			continue
		}
		if !isSvn {
			return hwFail(fmt.Sprintf("SEV-SNP %s SVN claim '%s' is missing or not a non-negative integer (policy requires a minimum)", c.name, c.claim))
		}
		if f < floor {
			return hwFail(fmt.Sprintf("SEV-SNP %s SVN %s is below the policy minimum %s", c.name, jsNumString(f), jsNumString(floor)))
		}
	}
	host := map[string]string{"attestation_type": "sevsnpvm"}
	for k, val := range reported {
		host[k] = val
	}
	if hasHost {
		host["host_data"] = strings.ToLower(hostData)
	}
	return HardwareResult{OK: true, Bound: true, Measured: newMeasured(mHex, ""), HostAsserted: host}
}

func (v *maaVerifier) tdxResult(tee map[string]any) HardwareResult {
	if !v.policy.hasTdx {
		return hwFail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)")
	}
	mrtd, ok := firstString(tee, []string{"tdx_mrtd", "x-ms-tdx-mrtd"})
	if !ok {
		return hwFail("tdxvm token carries no MRTD claim")
	}
	mrtdHex := strings.ToLower(mrtd)
	if !containsStr(v.policy.tdx, mrtdHex) {
		return hwFail("TDX MRTD not in policy allowlist")
	}
	tdDebug, _ := tee["tdx_td_attributes_debug"].(bool)
	dbgstat, hasDbg := tee["dbgstat"].(string)
	if !v.policy.allowDebug && (tdDebug || (hasDbg && dbgstat != "disabled")) {
		return hwFail("TDX guest is debuggable (no confidentiality)")
	}
	tcbStatus, hasStatus := tee["attester_tcb_status"].(string)
	if hasStatus {
		accepted := defaultAcceptedStatuses
		if v.policy.hasTdxStatuses {
			accepted = v.policy.tdxStatuses
		}
		if !containsStr(accepted, tcbStatus) {
			return hwFail(fmt.Sprintf("TDX platform TCB status '%s' is not accepted by policy", tcbStatus))
		}
	}
	rtmr0, hasRtmr := firstString(tee, []string{"tdx_rtmr0", "x-ms-tdx-rtmr0"})
	if len(v.policy.tdxRtmrs) > 0 {
		if !hasRtmr || !containsStr(v.policy.tdxRtmrs, strings.ToLower(rtmr0)) {
			return hwFail("TDX RTMR0 not in policy allowlist")
		}
	}
	host := map[string]string{"attestation_type": "tdxvm"}
	if hasStatus && tcbStatus != "" {
		host["tcb_status"] = tcbStatus
	}
	if hasRtmr {
		host["rtmr0"] = strings.ToLower(rtmr0)
	}
	return HardwareResult{OK: true, Bound: true, Measured: newMeasured(mrtdHex, ""), HostAsserted: host}
}
