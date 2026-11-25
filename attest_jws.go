package pca

// Compact-JWS plumbing shared by the Azure MAA and Google Confidential Space verifiers: the canonical base64url gate, the
// parsed token and the signature checks (ES256 and RS256) under a certificate or JWK key.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"encoding/base64"
)

var b64uPattern = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// jwkMarshalSPKI is x509.MarshalPKIXPublicKey; a var only so a test can reach the fail-closed branch it never takes for a JWK key.
var jwkMarshalSPKI = x509.MarshalPKIXPublicKey

// decodeCanonicalBase64url decodes one strictly canonical unpadded base64url segment (one spelling per value).
func decodeCanonicalBase64url(seg string) ([]byte, error) {
	if !b64uPattern.MatchString(seg) {
		return nil, errors.New("non-canonical compact JWS: bad-character")
	}
	if len(seg)%4 == 1 {
		return nil, errors.New("non-canonical compact JWS: non-canonical-base64url (impossible length)")
	}
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != seg {
		return nil, errors.New("non-canonical compact JWS: non-canonical-base64url")
	}
	return b, nil
}

type jwtParsed struct {
	alg          string
	kid          string
	hasKid       bool
	x5c          []string
	hasX5c       bool
	jku, typ     string
	hasJku       bool
	hasTyp       bool
	payload      map[string]any
	signingInput []byte
	signature    []byte
}

// parseJWT parses a compact JWS into header fields, payload and signing input; it verifies nothing. prefix is the
// reference parser's name (it leads every message).
// errInvalidJSONSegment is the refusal of a header or payload that is not JSON or repeats a member.
var errInvalidJSONSegment = errors.New("invalid JSON")

// nodeUTF8String is Buffer#toString('utf8'): the WHATWG decoder, which replaces each maximal ill-formed subsequence with one U+FFFD.
func nodeUTF8String(b []byte) string {
	var sb strings.Builder
	var cp rune
	needed, seen := 0, 0
	lower, upper := byte(0x80), byte(0xBF)
	for i := 0; i < len(b); {
		c := b[i]
		if needed == 0 {
			i++
			switch {
			case c <= 0x7F:
				sb.WriteByte(c)
			case c >= 0xC2 && c <= 0xDF:
				needed, cp = 1, rune(c&0x1F)
			case c >= 0xE0 && c <= 0xEF:
				if c == 0xE0 {
					lower = 0xA0
				}
				if c == 0xED {
					upper = 0x9F
				}
				needed, cp = 2, rune(c&0x0F)
			case c >= 0xF0 && c <= 0xF4:
				if c == 0xF0 {
					lower = 0x90
				}
				if c == 0xF4 {
					upper = 0x8F
				}
				needed, cp = 3, rune(c&0x07)
			default:
				sb.WriteRune('\uFFFD')
			}
			continue
		}
		if c < lower || c > upper { // the sequence ends here: one replacement, and this byte is read again
			cp, needed, seen, lower, upper = 0, 0, 0, 0x80, 0xBF
			sb.WriteRune('\uFFFD')
			continue
		}
		lower, upper = 0x80, 0xBF
		cp = cp<<6 | rune(c&0x3F)
		seen++
		i++
		if seen == needed {
			sb.WriteRune(cp)
			cp, needed, seen = 0, 0, 0
		}
	}
	if needed != 0 {
		sb.WriteRune('\uFFFD')
	}
	return sb.String()
}

func parseJWT(token, prefix string) (*jwtParsed, error) {
	if token == "" {
		return nil, fmt.Errorf("%s: empty token", prefix)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%s: a compact JWS has exactly three dot-separated parts", prefix)
	}
	h, p, s := parts[0], parts[1], parts[2]
	if h == "" || p == "" || s == "" {
		return nil, fmt.Errorf("%s: empty JWS segment", prefix)
	}
	var headerObj, payloadObj any
	// both segments are decoded and size-checked first, then parsed with the duplicate-only check (a genuine vendor token is not canonical
	// JSON: 8.0, 1e3 and -0 are read as written): a repeated member (JSON.parse keeps the last while the signer saw the first) or any
	// parse failure is refused as "invalid JSON"
	hb, err := decodeCanonicalBase64url(h)
	var pb []byte
	if err == nil {
		pb, err = decodeCanonicalBase64url(p)
	}
	if err == nil && (len(hb) > maxLenientJSONBytes || len(pb) > maxLenientJSONBytes) {
		err = errJSONTooLarge
	}
	if err == nil {
		// Buffer#toString('utf8') substitutes U+FFFD for an invalid sequence, so the reference parses (and reads) the substituted text
		if headerObj, err = ParseNoDuplicates(nodeUTF8String(hb)); err == nil {
			payloadObj, err = ParseNoDuplicates(nodeUTF8String(pb))
		}
		if err != nil {
			err = errInvalidJSONSegment
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: malformed JSON segment: %s", prefix, err.Error())
	}
	hdr, ok := headerObj.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: header is not a JSON object", prefix)
	}
	payload, ok := payloadObj.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: payload is not a JSON object", prefix)
	}
	alg, _ := hdr["alg"].(string)
	if alg == "" {
		return nil, fmt.Errorf("%s: header has no alg", prefix)
	}
	// the native is stricter than the reference here: bytes that are not UTF-8 never make a parsed token (the signature covers the
	// bytes, the claims were read from a substituted text); the reference's refusals above, which come first, keep their own reasons
	if !utf8.Valid(hb) || !utf8.Valid(pb) {
		return nil, fmt.Errorf("%s: malformed JSON segment: %s", prefix, errInvalidJSONSegment.Error())
	}
	out := &jwtParsed{alg: alg, payload: payload, signingInput: []byte(h + "." + p)}
	if kid, ok := hdr["kid"].(string); ok {
		out.kid, out.hasKid = kid, true
	}
	if v, ok := hdr["jku"].(string); ok {
		out.jku, out.hasJku = v, true
	}
	if v, ok := hdr["typ"].(string); ok {
		out.typ, out.hasTyp = v, true
	}
	if l, ok := asStrList(hdr["x5c"]); ok {
		out.x5c, out.hasX5c = l, true
	}
	sig, err := decodeCanonicalBase64url(s)
	if err != nil {
		return nil, fmt.Errorf("%s: malformed signature segment: %s", prefix, err.Error())
	}
	out.signature = sig
	return out, nil
}

// jwkKtyCrv is the kty / crv of a key's JWK export ("undefined" for a key type without a curve).
func jwkKtyCrv(k certKey) (string, string) {
	switch p := k.pub.(type) {
	case *ecdsa.PublicKey:
		return "EC", p.Curve.Params().Name
	case *rsa.PublicKey:
		return "RSA", "undefined"
	}
	if k.typ == "ed25519" {
		return "OKP", "Ed25519"
	}
	return k.typ, "undefined"
}

// jwsES256OK verifies a raw r||s ES256 signature over the signing input under a P-256 key.
func jwsES256OK(sig, input []byte, k certKey) bool {
	pk, ok := k.pub.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() || len(sig) != 64 {
		return false
	}
	return verifyRawECDSA(pk, sha256Sum(input), sig)
}

// jwsRS256OK verifies an RSASSA-PKCS1-v1_5 / SHA-256 signature under an RSA key.
func jwsRS256OK(sig, input []byte, k certKey) bool {
	pk, ok := k.pub.(*rsa.PublicKey)
	if !ok || !rsaKeyOK(pk) {
		return false
	}
	if k.typ == "rsa-pss" { // an rsa-pss key signs only with PSS, never PKCS#1 v1.5
		return false
	}
	return rsa.VerifyPKCS1v15(pk, crypto.SHA256, sha256Sum(input), sig) == nil
}

// jwkRSAKey builds a public RSA key from base64url n / e.
func jwkRSAKey(n, e string) (certKey, error) {
	nb, eb := nodeB64(n), nodeB64(e)
	if len(nb) == 0 || len(eb) == 0 {
		return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	ev := new(big.Int).SetBytes(eb)
	if !ev.IsInt64() || ev.Int64() < 3 || ev.Int64() > 1<<31-1 {
		return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(ev.Int64())}
	if !rsaKeyOK(pub) { // before the key is built or used: an unusable key is not a key
		return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	der, err := jwkMarshalSPKI(pub)
	if err != nil {
		return certKey{}, err
	}
	return keyInfoOf(pub, der), nil
}

// jwkECKey builds a public EC key from crv / x / y (on-curve points only).
func jwkECKey(crv, x, y string) (certKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	xb, yb := nodeB64(x), nodeB64(y)
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	der, err := jwkMarshalSPKI(pub)
	if err != nil {
		return certKey{}, err
	}
	return keyInfoOf(pub, der), nil
}
