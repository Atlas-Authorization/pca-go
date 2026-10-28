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

	"encoding/base64"
)

var b64uPattern = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

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
	payload      map[string]any
	signingInput []byte
	signature    []byte
}

// parseJWT parses a compact JWS into header fields, payload and signing input; it verifies nothing. prefix is the
// reference parser's name (it leads every message).
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
	hb, err := decodeCanonicalBase64url(h)
	if err == nil {
		headerObj, err = jsonLenient(hb)
	}
	if err == nil {
		var pb []byte
		if pb, err = decodeCanonicalBase64url(p); err == nil {
			payloadObj, err = jsonLenient(pb)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: malformed JSON segment: %s", prefix, jsonSegmentError(h, p, err))
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
	out := &jwtParsed{alg: alg, payload: payload, signingInput: []byte(h + "." + p)}
	if kid, ok := hdr["kid"].(string); ok {
		out.kid, out.hasKid = kid, true
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
	if !ok {
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
	der, err := x509.MarshalPKIXPublicKey(pub)
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
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return certKey{}, err
	}
	return keyInfoOf(pub, der), nil
}

// jsonSegmentError is the message to report for a header or payload segment that did not decode or parse: the canonical-form
// message of the base64url gate, else the engine's JSON.parse wording of the segment that failed.
func jsonSegmentError(h, p string, err error) string {
	if strings.HasPrefix(err.Error(), "non-canonical compact JWS") {
		return err.Error()
	}
	for _, seg := range []string{h, p} {
		b, derr := decodeCanonicalBase64url(seg)
		if derr != nil {
			return derr.Error()
		}
		if _, jerr := jsonLenient(b); jerr != nil {
			if msg := v8JSONError(string(b)); msg != "" {
				return msg
			}
			return jerr.Error()
		}
	}
	return err.Error()
}
