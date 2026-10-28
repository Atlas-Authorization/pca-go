package pca

// Google Cloud Confidential Space: the attestation token (RS256, ES256 defensively) verified under a signing key anchored
// in the configured trust anchors (a pinned JWKS, SPKI pins or an x5c chain to a configured root), with iss / time window,
// the Confidential Space claims, the eat_nonce binding and the workload image-digest allowlist. Same checks, order and
// reason text as the reference verifier. Classical; no network I/O.

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"strings"
)

type gcpVerifier struct {
	issuers       map[string]bool
	trustedKeys   []map[string]any
	spkiPins      map[string]bool
	rootCertsPem  []string
	images        map[string]bool
	teeTypes      map[string]bool
	hasTeeTypes   bool
	swName        string
	swVersions    map[string]bool
	hasSwVersions bool
	allowDebug    bool
	nonceHash     string
	skew          float64
}

func newGcpVerifier(cfg map[string]any) (*gcpVerifier, error) {
	const p = "createGcpConfidentialSpaceVerifier: "
	issArr, ok := cfg["trustedIssuers"].([]any)
	if !ok || len(issArr) == 0 {
		return nil, errors.New(p + "trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs")
	}
	v := &gcpVerifier{issuers: map[string]bool{}, spkiPins: map[string]bool{}, images: map[string]bool{}}
	for _, x := range issArr {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, errors.New(p + "every trusted issuer must be a non-empty URL string")
		}
		v.issuers[s] = true
	}
	anch, _ := cfg["trustAnchors"].(map[string]any)
	if tj, ok := anch["trustedJwks"].(map[string]any); ok {
		if keys, ok := tj["keys"].([]any); ok {
			for _, k := range keys {
				rec, _ := k.(map[string]any)
				v.trustedKeys = append(v.trustedKeys, rec)
			}
		}
	}
	spki := listLen(anch["trustedKeySpki"])
	for _, s := range anyStrings(anch["trustedKeySpki"]) {
		v.spkiPins[strings.ToLower(s)] = true
	}
	v.rootCertsPem, _ = asStrList(anch["rootCertsPem"])
	if len(v.trustedKeys)+spki+listLen(anch["rootCertsPem"]) == 0 {
		return nil, errors.New(p + "trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted")
	}
	pol, _ := cfg["policy"].(map[string]any)
	digests, ok := asStrList(pol["imageDigests"])
	if !ok || len(digests) == 0 {
		return nil, errors.New(p + "policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")
	}
	if raw, present := pol["allowedTeeTypes"]; present {
		if arr, isArr := raw.([]any); isArr {
			if len(arr) == 0 {
				return nil, errors.New(p + "policy.allowedTeeTypes, when present, must be non-empty")
			}
			v.hasTeeTypes = true
			v.teeTypes = map[string]bool{}
			for _, x := range arr {
				if s, ok := x.(string); ok {
					v.teeTypes[s] = true
				}
			}
		}
	}
	v.skew = skewOf(cfg)
	for _, d := range digests {
		v.images[strings.ToLower(d)] = true
	}
	v.swName = "CONFIDENTIAL_SPACE"
	if s, ok := pol["expectedSwName"].(string); ok {
		v.swName = s
	}
	if arr, ok := pol["allowedSwVersions"].([]any); ok {
		v.hasSwVersions = true
		v.swVersions = map[string]bool{}
		for _, x := range arr {
			if s, ok := x.(string); ok {
				v.swVersions[s] = true
			}
		}
	}
	v.allowDebug = pol["allowDebug"] == true
	v.nonceHash, _ = pol["nonceHash"].(string)
	return v, nil
}

// anyStrings is the string members of a JSON array (nil when v is not an array).
func anyStrings(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// jwkKey builds a public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain). The reason on failure.
func jwkKey(jwk map[string]any) (certKey, string) {
	n, nok := jwk["n"].(string)
	e, eok := jwk["e"].(string)
	if nok && eok {
		k, err := jwkRSAKey(n, e)
		if err != nil {
			return certKey{}, "JWKS key is not a usable public key: " + errMsg(err)
		}
		return k, ""
	}
	crv, cok := jwk["crv"].(string)
	x, xok := jwk["x"].(string)
	y, yok := jwk["y"].(string)
	if jwk["kty"] == "EC" && cok && xok && yok {
		k, err := jwkECKey(crv, x, y)
		if err != nil {
			return certKey{}, "JWKS key is not a usable public key: " + errMsg(err)
		}
		return k, ""
	}
	if x5c, ok := jwk["x5c"].([]any); ok && len(x5c) > 0 {
		if s, ok := x5c[0].(string); ok {
			c, err := parseCertDER(nodeB64(s))
			if err != nil {
				return certKey{}, "JWKS key is not a usable public key: " + errMsg(err)
			}
			k, err := keyOfCert(c)
			if err != nil {
				return certKey{}, "JWKS key is not a usable public key: " + errMsg(err)
			}
			return k, ""
		}
	}
	return certKey{}, "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate"
}

// verifyJwkX5cChain verifies a JWK x5c chain to a configured SPKI pin or root certificate; "" when it anchors.
func (v *gcpVerifier) verifyJwkX5cChain(x5c []any, nowMs int64) string {
	if len(x5c) == 0 {
		return "empty x5c certificate chain"
	}
	certs := make([]*attCert, 0, len(x5c))
	for i, e := range x5c {
		b64, ok := e.(string)
		if !ok || b64 == "" {
			return fmt.Sprintf("empty x5c entry at index %d", i)
		}
		c, err := parseCertDER(nodeB64(b64))
		if err != nil {
			return fmt.Sprintf("malformed x5c certificate at index %d: %s", i, errMsg(err))
		}
		if !derValidAtF(c.Raw, nowMs, v.skew) {
			return fmt.Sprintf("x5c certificate at index %d is outside its validity window", i)
		}
		certs = append(certs, c)
	}
	for i := 0; i < len(certs)-1; i++ {
		if !certSigOKBy(certs[i], certs[i+1]) {
			return fmt.Sprintf("x5c link %d is not signed by the certificate above it", i)
		}
	}
	for _, c := range certs {
		if k, err := keyOfCert(c); err == nil && v.spkiPins[k.spkiSHA256()] {
			return ""
		}
	}
	top := certs[len(certs)-1]
	for _, pemText := range v.rootCertsPem {
		if rk, ok := rootKeyFromPEM(pemText); ok && certSigOK(top, rk) {
			return ""
		}
	}
	return "x5c chain does not anchor in a configured GCP trust root"
}

// rootKeyFromPEM reads a trust root given as a certificate or as a bare public key.
func rootKeyFromPEM(pemText string) (certKey, bool) {
	if c, err := certFromPEM(pemText); err == nil {
		if k, err := keyOfCert(c); err == nil {
			return k, true
		}
	}
	if blk, _ := pem.Decode([]byte(pemText)); blk != nil {
		if pub, err := x509.ParsePKIXPublicKey(blk.Bytes); err == nil {
			return keyInfoOf(pub, blk.Bytes), true
		}
	}
	return certKey{}, false
}

// pickJwk is the key the token was signed under: by kid if present, else the sole key.
func pickJwk(tok *jwtParsed, keys []map[string]any) map[string]any {
	if tok.hasKid && tok.kid != "" {
		for _, k := range keys {
			if kid, ok := k["kid"].(string); ok && kid == tok.kid {
				return k
			}
		}
		return nil
	}
	if len(keys) == 1 {
		return keys[0]
	}
	return nil
}

func mapList(v any) []map[string]any {
	arr, _ := v.([]any)
	var out []map[string]any
	for _, x := range arr {
		rec, _ := x.(map[string]any)
		out = append(out, rec)
	}
	return out
}

// signingKey resolves the token's signing key and confirms it is anchored. The key, or the failure reason.
func (v *gcpVerifier) signingKey(tok *jwtParsed, evidenceJwks any, nowMs int64) (certKey, string) {
	var evKeys []map[string]any
	if m, ok := evidenceJwks.(map[string]any); ok {
		evKeys = mapList(m["keys"])
	}
	jwk := pickFrom(evKeys, tok)
	fromTrusted := false
	if jwk == nil {
		jwk = pickFrom(v.trustedKeys, tok)
		fromTrusted = jwk != nil
	}
	hasKid := tok.hasKid && tok.kid != ""
	if jwk == nil && tok.hasX5c && len(tok.x5c) > 0 {
		x5c := make([]any, len(tok.x5c))
		for i, s := range tok.x5c {
			x5c[i] = s
		}
		jwk = map[string]any{"x5c": x5c}
	}
	if jwk == nil {
		if hasKid {
			return certKey{}, fmt.Sprintf("no JWKS key matches the token kid '%s' (untrusted signer)", tok.kid)
		}
		return certKey{}, "no kid on the token and no unambiguous single signing key available"
	}
	key, why := jwkKey(jwk)
	if why != "" {
		return certKey{}, why
	}
	spki := key.spkiSHA256()
	if fromTrusted || v.spkiPins[spki] {
		return key, ""
	}
	for _, tk := range v.trustedKeys {
		if tb, w := jwkKey(tk); w == "" && tb.spkiSHA256() == spki {
			return key, ""
		}
	}
	if x5c, ok := jwk["x5c"].([]any); ok && len(x5c) > 0 && (len(v.rootCertsPem) > 0 || len(v.spkiPins) > 0) {
		if chainErr := v.verifyJwkX5cChain(x5c, nowMs); chainErr == "" {
			return key, ""
		} else {
			return certKey{}, "signing key not trusted: " + chainErr
		}
	}
	return certKey{}, "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"
}

func pickFrom(keys []map[string]any, tok *jwtParsed) map[string]any { return pickJwk(tok, keys) }

func (v *gcpVerifier) jwsSignature(tok *jwtParsed, k certKey) string {
	kty, crv := jwkKtyCrv(k)
	switch tok.alg {
	case "RS256":
		if kty != "RSA" {
			return fmt.Sprintf("RS256 token but signing key is %s (not RSA)", kty)
		}
		if !jwsRS256OK(tok.signature, tok.signingInput, k) {
			return "JWS RS256 signature does not verify under the Confidential Space signing key"
		}
		return ""
	case "ES256":
		if kty != "EC" || crv != "P-256" {
			return fmt.Sprintf("ES256 token but signing key is %s/%s (not EC P-256)", kty, crv)
		}
		if len(tok.signature) != 64 {
			return fmt.Sprintf("ES256 signature is %d bytes (expected 64: r‖s)", len(tok.signature))
		}
		if !jwsES256OK(tok.signature, tok.signingInput, k) {
			return "JWS ES256 signature does not verify under the Confidential Space signing key"
		}
		return ""
	}
	return fmt.Sprintf("unsupported JWS alg '%s' (Confidential Space uses RS256)", tok.alg)
}

// gcpTeeType maps a Confidential Space hwmodel to its isolation family ("" when unrecognised).
func gcpTeeType(hwmodel string) string {
	switch hwmodel {
	case "GCP_AMD_SEV", "GCP_AMD_SEV_SNP", "GCP_AMD_SEV_ES":
		return "sev-snp"
	case "GCP_INTEL_TDX":
		return "tdx"
	}
	up := strings.ToUpper(hwmodel)
	if strings.HasPrefix(up, "GCP_AMD_SEV") {
		return "sev-snp"
	}
	if strings.HasPrefix(up, "GCP_INTEL_TDX") {
		return "tdx"
	}
	return ""
}

func nonceCandidates(v any) []string {
	if s, ok := v.(string); ok {
		if s != "" {
			return []string{s}
		}
		return nil
	}
	arr, ok := asStrList(v)
	if !ok {
		return nil
	}
	var out []string
	for _, s := range arr {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (v *gcpVerifier) verify(ev map[string]any, expected *AttestationBinding, nowMs int64) HardwareResult {
	token, ok := ev["token"].(string)
	if ev == nil || !ok || token == "" {
		return hwFail("no GCP Confidential Space token for this action")
	}
	tok, err := parseJWT(token, "parseGcpCsJwt")
	if err != nil {
		return hwFail("Confidential Space token parse failed: " + err.Error())
	}
	if tok.alg != "RS256" && tok.alg != "ES256" {
		return hwFail(fmt.Sprintf("unsupported JWS alg '%s' (Confidential Space uses RS256)", tok.alg))
	}
	key, why := v.signingKey(tok, ev["jwks"], nowMs)
	if why != "" {
		return hwFail("Confidential Space signing key invalid: " + why)
	}
	if sigErr := v.jwsSignature(tok, key); sigErr != "" {
		return hwFail(sigErr)
	}

	payload := tok.payload
	iss, issIsStr := payload["iss"].(string)
	if iss == "" || !v.issuers[iss] {
		shown := iss
		if !issIsStr {
			shown = "undefined"
		}
		return hwFail(fmt.Sprintf("token iss '%s' is not a configured trusted Google attestation issuer", shown))
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
		return hwFail("Confidential Space token expired")
	}
	if hasNbf && nowSec+skewSec < nbf {
		return hwFail("Confidential Space token not yet valid (nbf)")
	}
	if hasIat && nowSec+skewSec < iat {
		return hwFail("Confidential Space token issued in the future (iat)")
	}

	submods, _ := payload["submods"].(map[string]any)
	if _, ok := submods["confidential_space"].(map[string]any); !ok {
		return hwFail("token carries no submods.confidential_space (not a Confidential Space token)")
	}
	swname, hasSw := payload["swname"].(string)
	if !hasSw || swname != v.swName {
		shown := swname
		if !hasSw {
			shown = "undefined"
		}
		return hwFail(fmt.Sprintf("unexpected swname '%s' (expected '%s')", shown, v.swName))
	}
	if v.hasSwVersions {
		versions, isList := asStrList(payload["swversion"])
		if !isList {
			if s, ok := payload["swversion"].(string); ok && s != "" {
				versions = []string{s}
			}
		}
		found := false
		for _, x := range versions {
			if v.swVersions[x] {
				found = true
			}
		}
		if !found {
			return hwFail("swversion not in policy allowlist")
		}
	}
	hwmodel, _ := payload["hwmodel"].(string)
	if hwmodel == "" {
		return hwFail("token carries no hwmodel claim")
	}
	teeType := gcpTeeType(hwmodel)
	if teeType == "" {
		return hwFail(fmt.Sprintf("unrecognized hwmodel '%s' (not a known AMD SEV-SNP / Intel TDX model)", hwmodel))
	}
	if v.hasTeeTypes && !v.teeTypes[teeType] {
		return hwFail(fmt.Sprintf("attestation type '%s' (hwmodel '%s') is not in the policy allowlist", teeType, hwmodel))
	}
	dbgstat, hasDbg := payload["dbgstat"].(string)
	if !v.allowDebug && (!hasDbg || dbgstat != "disabled-since-boot") {
		shown := dbgstat
		if !hasDbg {
			shown = "undefined"
		}
		return hwFail(fmt.Sprintf("token dbgstat '%s' is not 'disabled-since-boot' (debug build — no confidentiality)", shown))
	}
	if expected == nil {
		return hwFail("no expected attestation binding supplied")
	}
	raw, err := attestationBindingBytes(*expected)
	if err != nil {
		return hwFail("binding not constructible: " + err.Error())
	}
	bindingBytes := transformBinding(raw, v.nonceHash)
	candidates := nonceCandidates(payload["eat_nonce"])
	if len(candidates) == 0 {
		return hwFail("token carries no eat_nonce claim to bind the PCA challenge")
	}
	bound := false
	for _, c := range candidates {
		if b := decodeClaimBytes(c); b != nil && timingSafeEq(b, bindingBytes) {
			bound = true
			break
		}
	}
	if !bound {
		return hwFail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)")
	}
	container, _ := submods["container"].(map[string]any)
	imageDigest, hasImage := firstString(container, []string{"image_digest"})
	if !hasImage {
		return hwFail("token carries no submods.container.image_digest to measure the workload")
	}
	if !v.images[strings.ToLower(imageDigest)] {
		return hwFail("workload image_digest not in policy allowlist")
	}
	host := map[string]string{"attestation_type": teeType, "hwmodel": hwmodel, "image_digest": imageDigest}
	if ref, ok := firstString(container, []string{"image_reference"}); ok {
		host["image_reference"] = ref
	}
	return HardwareResult{OK: true, Bound: true, Measured: newMeasured(imageDigest, ""), HostAsserted: host}
}
