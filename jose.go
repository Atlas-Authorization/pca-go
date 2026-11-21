package pca

// The JOSE layer the protocol bridges share: the canonical compact-JWS gate (one accepted spelling per token, the reference
// assertCanonicalCompactJws), public JWK import, RFC 7638 thumbprints, compact JWS signing (EdDSA, deterministic) and a JWT
// verifier with the reference library's (jose) acceptance rules: crit / b64, the algorithm allowlist, key / algorithm
// compatibility, the signature, then typ, required claims, audience and the iat / nbf / exp checks.

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/ed448"
)

// DefaultMaxJWSBytes is the canonical gate's default size cap.
const DefaultMaxJWSBytes = 64 * 1024

// CanonicalJWS is a token that passed the canonical gate.
type CanonicalJWS struct {
	Segments []string
	Header   map[string]any
	Payload  map[string]any // nil unless the payload was parsed as JSON
}

func jwsJSONSegment(b []byte) (any, error) {
	if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		return nil, errors.New("non-canonical compact JWS: bom")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("non-canonical compact JWS: bad-utf8")
	}
	v, err := StrictParse(string(b))
	if err != nil {
		return nil, fmt.Errorf("non-canonical compact JWS: bad-json (%v)", err)
	}
	return v, nil
}

// AssertCanonicalCompactJWS is the canonical-spelling gate run before any JOSE library: a string of at most maxBytes (0 = the
// default) with `parts` (3 or 5) non-empty canonical base64url segments, a strict-JSON object header and (jsonPayload) payload.
func AssertCanonicalCompactJWS(token any, parts, maxBytes int, jsonPayload bool) (*CanonicalJWS, error) {
	if parts == 0 {
		parts = 3
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxJWSBytes
	}
	s, ok := token.(string)
	if !ok {
		return nil, errors.New("non-canonical compact JWS: not-a-string")
	}
	if utf16Len(s) > maxBytes {
		return nil, errors.New("non-canonical compact JWS: too-long")
	}
	segs := strings.Split(s, ".")
	if len(segs) != parts {
		return nil, fmt.Errorf("non-canonical compact JWS: bad-segment-count (%d != %d)", len(segs), parts)
	}
	raw := make([][]byte, len(segs))
	for i, seg := range segs {
		if seg == "" {
			if parts == 5 && i == 1 {
				continue
			}
			return nil, fmt.Errorf("non-canonical compact JWS: empty-segment (segment %d)", i)
		}
		b, err := decodeCanonicalBase64url(seg)
		if err != nil {
			return nil, err
		}
		raw[i] = b
	}
	h, err := jwsJSONSegment(raw[0])
	if err != nil {
		return nil, err
	}
	hm, ok := h.(map[string]any)
	if !ok {
		return nil, errors.New("non-canonical compact JWS: not-an-object")
	}
	out := &CanonicalJWS{Segments: segs, Header: hm}
	if parts == 3 && jsonPayload {
		p, err := jwsJSONSegment(raw[1])
		if err != nil {
			return nil, err
		}
		pm, ok := p.(map[string]any)
		if !ok {
			return nil, errors.New("non-canonical compact JWS: not-an-object")
		}
		out.Payload = pm
	}
	return out, nil
}

// JOSEKey is an imported public key: kty "OKP" (Ed25519 / Ed448), "EC" (P-256 / P-384 / P-521) or "RSA".
type JOSEKey struct {
	Kty, Crv string
	Ed25519  ed25519.PublicKey
	Ed448    ed448.PublicKey
	EC       *ecdsa.PublicKey
	RSA      *rsa.PublicKey
	HMAC     []byte // kty "oct": an HS256 / HS384 / HS512 secret
}

func jwkB64(jwk map[string]any, k string) ([]byte, error) {
	s, ok := jwk[k].(string)
	if !ok {
		return nil, fmt.Errorf("JWK %q missing or not a string", k)
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

var jwkPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth", "r", "t"}

// ImportPublicJWK imports a public JWK (a private member is refused: this is the verification side).
func ImportPublicJWK(jwk map[string]any) (*JOSEKey, error) {
	if jwk == nil {
		return nil, errors.New("JWK must be an object")
	}
	for _, m := range jwkPrivateMembers {
		if _, has := jwk[m]; has {
			return nil, errors.New("JWK carries private key material")
		}
	}
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	switch kty {
	case "OKP":
		x, err := jwkB64(jwk, "x")
		if err != nil {
			return nil, err
		}
		switch {
		case crv == "Ed25519" && len(x) == ed25519.PublicKeySize:
			return &JOSEKey{Kty: kty, Crv: crv, Ed25519: ed25519.PublicKey(x)}, nil
		case crv == "Ed448" && len(x) == ed448.PublicKeySize:
			return &JOSEKey{Kty: kty, Crv: crv, Ed448: ed448.PublicKey(x)}, nil
		}
		return nil, errors.New("unsupported or malformed OKP JWK")
	case "EC":
		var c elliptic.Curve
		var dh ecdh.Curve
		switch crv {
		case "P-256":
			c, dh = elliptic.P256(), ecdh.P256()
		case "P-384":
			c, dh = elliptic.P384(), ecdh.P384()
		case "P-521":
			c, dh = elliptic.P521(), ecdh.P521()
		default:
			return nil, errors.New("unsupported EC curve")
		}
		x, err1 := jwkB64(jwk, "x")
		y, err2 := jwkB64(jwk, "y")
		n := (c.Params().BitSize + 7) / 8
		if err1 != nil || err2 != nil || len(x) != n || len(y) != n {
			return nil, errors.New("malformed EC JWK")
		}
		pt := append(append([]byte{4}, x...), y...)
		if _, err := dh.NewPublicKey(pt); err != nil { // on-curve, not the identity
			return nil, errors.New("EC JWK point is not on the curve")
		}
		return &JOSEKey{Kty: kty, Crv: crv, EC: &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}}, nil
	case "RSA":
		nb, err1 := jwkB64(jwk, "n")
		eb, err2 := jwkB64(jwk, "e")
		if err1 != nil || err2 != nil || len(nb) == 0 || len(eb) == 0 || len(eb) > 4 {
			return nil, errors.New("malformed RSA JWK")
		}
		e := new(big.Int).SetBytes(eb)
		if e.Int64() < 3 || e.Int64()%2 == 0 {
			return nil, errors.New("malformed RSA JWK exponent")
		}
		return &JOSEKey{Kty: kty, RSA: &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}}, nil
	}
	return nil, errors.New("unsupported JWK kty")
}

func joseHash(alg string) (crypto.Hash, func() hash.Hash) {
	switch alg[len(alg)-3:] {
	case "384":
		return crypto.SHA384, sha512.New384
	case "512":
		return crypto.SHA512, sha512.New
	}
	return crypto.SHA256, sha256.New
}

// joseKeyFits is the reference library's key / algorithm compatibility check (RSA moduli of at least 2048 bits).
func joseKeyFits(alg string, k *JOSEKey) bool {
	switch alg {
	case "EdDSA":
		return k.Kty == "OKP" && (k.Crv == "Ed25519" || k.Crv == "Ed448")
	case "ES256":
		return k.Kty == "EC" && k.Crv == "P-256"
	case "ES384":
		return k.Kty == "EC" && k.Crv == "P-384"
	case "ES512":
		return k.Kty == "EC" && k.Crv == "P-521"
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return k.Kty == "RSA" && (k.RSA == nil || k.RSA.N.BitLen() >= 2048) // a nil RSA / EC key (unusable material) verifies nothing
	case "HS256", "HS384", "HS512":
		return k.HMAC != nil
	}
	return false
}

// JOSEVerify checks a JWS signature over input under k for alg.
func JOSEVerify(alg string, k *JOSEKey, input, sig []byte) bool {
	if k == nil || !joseKeyFits(alg, k) {
		return false
	}
	switch {
	case alg == "EdDSA" && k.Ed25519 != nil:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.Ed25519, input, sig)
	case alg == "EdDSA":
		return k.Ed448 != nil && len(sig) == ed448.SignatureSize && ed448.Verify(k.Ed448, input, sig, "")
	}
	h, newH := joseHash(alg)
	d := newH()
	d.Write(input)
	sum := d.Sum(nil)
	switch alg[:2] {
	case "ES":
		if k.EC == nil {
			return false
		}
		n := (k.EC.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return false
		}
		return ecdsa.Verify(k.EC, sum, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
	case "RS", "PS":
		if k.RSA == nil {
			return false
		}
	}
	switch alg[:2] {
	case "RS":
		return rsa.VerifyPKCS1v15(k.RSA, h, sum, sig) == nil
	case "PS":
		return rsa.VerifyPSS(k.RSA, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case "HS":
		m := hmac.New(newH, k.HMAC)
		m.Write(input)
		return hmac.Equal(m.Sum(nil), sig)
	}
	return false
}

// JWKThumbprint is the RFC 7638 thumbprint (digest "sha256" | "sha384" | "sha512") over the required members only.
func JWKThumbprint(jwk any, digest string) (string, error) {
	m, ok := jwk.(map[string]any)
	if !ok {
		return "", errors.New("JWK must be an object")
	}
	var req []string
	switch m["kty"] {
	case "OKP":
		req = []string{"crv", "kty", "x"}
	case "EC":
		req = []string{"crv", "kty", "x", "y"}
	case "RSA":
		req = []string{"e", "kty", "n"}
	case "oct":
		req = []string{"k", "kty"}
	default:
		return "", errors.New(`"kty" (Key Type) Parameter missing or unsupported`)
	}
	parts := make([]string, len(req))
	for i, k := range req {
		s, ok := m[k].(string)
		if !ok || s == "" {
			return "", fmt.Errorf("%q Parameter missing or invalid", k)
		}
		v, _ := canonicalLenient(s)
		parts[i] = `"` + k + `":` + v
	}
	var h hash.Hash
	switch digest {
	case "", "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return "", errors.New("digest must be sha256, sha384 or sha512")
	}
	h.Write([]byte("{" + strings.Join(parts, ",") + "}"))
	return b64.EncodeToString(h.Sum(nil)), nil
}

// rawJSON is JSON text placed verbatim by jsonObject.
type rawJSON string

// jsonObject renders JSON.stringify of an object built in insertion order from key, value pairs (a rawJSON value is
// inserted as is; other values are rendered canonically, which equals JSON.stringify for scalars and arrays of scalars).
func jsonObject(kv ...any) (rawJSON, error) {
	var sb strings.Builder
	sb.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			sb.WriteByte(',')
		}
		k, _ := canonicalLenient(kv[i].(string))
		sb.WriteString(k + ":")
		if r, ok := kv[i+1].(rawJSON); ok {
			sb.WriteString(string(r))
			continue
		}
		v, ok := canonicalLenient(kv[i+1])
		if !ok {
			return "", fmt.Errorf("not serializable: %T", kv[i+1])
		}
		sb.WriteString(v)
	}
	sb.WriteByte('}')
	return rawJSON(sb.String()), nil
}

// SignCompactEdDSA signs header.payload (both JSON text) with an Ed25519 seed.
func SignCompactEdDSA(header, payload rawJSON, seed []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", errors.New("an Ed25519 secret key must be 32 bytes")
	}
	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(input))
	return input + "." + b64.EncodeToString(sig), nil
}

// JWTVerifyOptions are the reference library's jwtVerify options. NowSec nil = the wall clock.
type JWTVerifyOptions struct {
	Algorithms     []string
	Typ            string
	RequiredClaims []string
	Issuer         []string // nil = no issuer check; otherwise "iss" is required and must be one of these
	Audience       []string // nil = no audience check; otherwise "aud" is required and must name one of these
	AudienceAny    bool     // with Audience set: "aud" is required but its value is not checked (the reference's empty-string audience)
	MaxTokenAge    float64  // seconds; 0 = no age check
	ClockTolerance float64
	NowSec         *float64
}

// JOSEError is a JWTVerify failure classified as the reference library classifies it: Kind "invalid" (a malformed or refused
// token), "key" (no usable key for the algorithm), "signature", "claim" (a claim check, Claim names it) or "expired" (exp, or
// iat past MaxTokenAge).
type JOSEError struct{ Kind, Claim, Msg string }

func (e *JOSEError) Error() string { return e.Msg }

func normalizeTyp(s string) string { return strings.TrimPrefix(strings.ToLower(s), "application/") }

// JWTVerify verifies a compact JWT (which must already have passed AssertCanonicalCompactJWS) under the key that keyFor returns
// for its protected header, and validates its claims set. It returns the protected header and the claims.
func JWTVerify(token string, keyFor func(header map[string]any) (*JOSEKey, error), o JWTVerifyOptions, nowWall float64) (map[string]any, map[string]any, error) {
	fail := func(m string) (map[string]any, map[string]any, error) {
		return nil, nil, &JOSEError{Kind: "invalid", Msg: m}
	}
	failK := func(kind, claim, m string) (map[string]any, map[string]any, error) {
		return nil, nil, &JOSEError{Kind: kind, Claim: claim, Msg: m}
	}
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return fail("Invalid Compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return fail("Invalid Compact JWS")
	}
	hv, err := ParseJSONLenient(hb)
	h, ok := hv.(map[string]any)
	if err != nil || !ok {
		return fail("JWS Protected Header must be an object")
	}
	h = normalizeJSON(h).(map[string]any)
	unencoded := false // b64: false is refused, but only after the signature check (as the reference does)
	if c, has := h["crit"]; has {
		l, ok := c.([]any)
		if !ok || len(l) == 0 {
			return fail(`"crit" (Critical) Header Parameter must be an array of non-empty strings`)
		}
		for _, x := range l {
			s, ok := x.(string)
			if !ok || s == "" {
				return fail(`"crit" (Critical) Header Parameter must be an array of non-empty strings`)
			}
			if s != "b64" {
				return fail("Extension Header Parameter not recognized")
			}
			b, has := h["b64"]
			if !has {
				return fail("Extension Header Parameter missing")
			}
			bb, ok := b.(bool)
			if !ok {
				return fail(`The "b64" (base64url-encode payload) Header Parameter must be a boolean`)
			}
			unencoded = !bb
		}
	}
	alg, _ := h["alg"].(string)
	if alg == "" {
		return fail(`JWS "alg" (Algorithm) Header Parameter missing or invalid`)
	}
	allowed := false
	for _, a := range o.Algorithms {
		allowed = allowed || a == alg
	}
	if !allowed {
		return fail(`"alg" (Algorithm) Header Parameter value not allowed`)
	}
	k, err := keyFor(h)
	if err != nil {
		return nil, nil, err
	}
	if k == nil || !joseKeyFits(alg, k) {
		return failK("key", "", "key is not usable with the token's alg")
	}
	sig, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil || !JOSEVerify(alg, k, []byte(segs[0]+"."+segs[1]), sig) {
		return failK("signature", "", "signature verification failed")
	}
	if unencoded {
		return fail("JWTs MUST NOT use unencoded payload")
	}
	pb, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return fail("Invalid Compact JWS")
	}
	if o.Typ != "" {
		t, ok := h["typ"].(string)
		if !ok || normalizeTyp(t) != normalizeTyp(o.Typ) {
			return failK("claim", "typ", `unexpected "typ" JWT header value`)
		}
	}
	pv, err := ParseJSONLenient(pb)
	p, ok := pv.(map[string]any)
	if err != nil || !ok || !utf8.Valid(pb) {
		return fail("JWT Claims Set must be a top-level JSON object")
	}
	p = normalizeJSON(p).(map[string]any)
	// presence: iss, aud, iat (with an age check), then the required claims, each once, in that order
	req := []string{}
	if o.Issuer != nil {
		req = append(req, "iss")
	}
	if o.Audience != nil {
		req = append(req, "aud")
	}
	if o.MaxTokenAge != 0 {
		req = append(req, "iat")
	}
	for i := len(o.RequiredClaims) - 1; i >= 0; i-- {
		req = append(req, o.RequiredClaims[i])
	}
	seen := map[string]bool{}
	for _, c := range req {
		if seen[c] {
			continue
		}
		seen[c] = true
		if _, has := p[c]; !has {
			return failK("claim", c, `missing required "`+c+`" claim`)
		}
	}
	if o.Issuer != nil {
		okIss := false
		for _, a := range o.Issuer {
			okIss = okIss || p["iss"] == a
		}
		if !okIss {
			return failK("claim", "iss", `unexpected "iss" claim value`)
		}
	}
	if o.Audience != nil && !o.AudienceAny {
		in := func(s any) bool {
			for _, a := range o.Audience {
				if s == a {
					return true
				}
			}
			return false
		}
		okAud := false
		switch a := p["aud"].(type) {
		case string:
			okAud = in(a)
		case []any:
			for _, x := range a {
				okAud = okAud || in(x)
			}
		}
		if !okAud {
			return failK("claim", "aud", `unexpected "aud" claim value`)
		}
	}
	now := math.Floor(nowWall)
	if o.NowSec != nil {
		now = math.Floor(*o.NowSec)
	}
	tol := o.ClockTolerance
	iat, iatOK := jsNum(p["iat"])
	if _, has := p["iat"]; (has || o.MaxTokenAge != 0) && !iatOK {
		return failK("claim", "iat", `"iat" claim must be a number`)
	}
	if v, has := p["nbf"]; has {
		f, ok := jsNum(v)
		if !ok {
			return failK("claim", "nbf", `"nbf" claim must be a number`)
		}
		if f > now+tol {
			return failK("claim", "nbf", `"nbf" claim timestamp check failed`)
		}
	}
	if v, has := p["exp"]; has {
		f, ok := jsNum(v)
		if !ok {
			return failK("claim", "exp", `"exp" claim must be a number`)
		}
		if f <= now-tol {
			return failK("expired", "exp", `"exp" claim timestamp check failed`)
		}
	}
	if o.MaxTokenAge != 0 {
		age := now - iat
		if age-tol > o.MaxTokenAge {
			return failK("expired", "iat", `"iat" claim timestamp check failed (too far in the past)`)
		}
		if age < 0-tol {
			return failK("claim", "iat", `"iat" claim timestamp check failed (it should be in the past)`)
		}
	}
	return h, p, nil
}
