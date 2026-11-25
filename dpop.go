package pca

// Sender-constrained proof of possession: RFC 9449 DPoP proofs over the HTTP method + target URI (the holder's public key in
// the `jwk` header, its RFC 7638 thumbprint the `jkt`), RFC 8705 mTLS `x5t#S256` confirmation, and the binding of a PCActn's
// leaf holder key (an Ed25519 OKP JWK with x = holder) to a DPoP proof. Replay stores and stateless server nonces included.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// DPoP constants (RFC 9449).
const (
	DpopJwtTyp             = "dpop+jwt"
	DpopDefaultMaxAgeSec   = 300
	DpopClockSkewSec       = 5
	DpopMaxProofBytes      = 8192
	DpopInMemoryMaxEntries = 100_000
)

// DpopAllowedAlgs are the JWS algorithms a DPoP proof may use: asymmetric only.
var DpopAllowedAlgs = []string{"EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256"}

func dpopErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func dpopNowSec() float64 { return math.Floor(float64(time.Now().UnixMilli()) / 1000) }

// JtiSeenSet is a replay set of jti values.
type JtiSeenSet interface {
	Has(jti string) bool
	Add(jti string)
}

// DpopReplayStore is a durable, atomic jti replay store: of N concurrent AddIfAbsent calls with one key exactly one returns
// true. The key is `<jkt>.<jti>`; an entry may be dropped once nowSec >= expiresAtSec.
type DpopReplayStore interface {
	AddIfAbsent(key string, expiresAtSec, nowSec float64) (bool, error)
}

// InMemoryDpopReplayStore is a bounded single-process store: when full of live entries a new key is an error (the verifier
// then refuses) rather than evicting a live entry.
type InMemoryDpopReplayStore struct {
	mu   sync.Mutex
	max  int
	seen map[string]float64
}

// NewInMemoryDpopReplayStore makes a store holding at most maxEntries live entries (DpopInMemoryMaxEntries is the usual size).
func NewInMemoryDpopReplayStore(maxEntries int) (*InMemoryDpopReplayStore, error) {
	if maxEntries < 1 {
		return nil, dpopErr("misconfigured", "maxEntries must be a positive integer")
	}
	return &InMemoryDpopReplayStore{max: maxEntries, seen: map[string]float64{}}, nil
}

func (s *InMemoryDpopReplayStore) AddIfAbsent(key string, expiresAtSec, nowSec float64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, has := s.seen[key]
	if has && !(finite(nowSec) && nowSec >= held) {
		return false, nil
	}
	if !has && len(s.seen) >= s.max {
		for k, exp := range s.seen {
			if finite(nowSec) && nowSec >= exp {
				delete(s.seen, k)
			}
		}
		if len(s.seen) >= s.max {
			return false, errors.New("replay store is full")
		}
	}
	s.seen[key] = expiresAtSec
	return true, nil
}

// RunDpopReplayStoreConformance returns the failed checks of a DpopReplayStore (empty = conformant); make returns a fresh
// empty store. A store error aborts the run.
func RunDpopReplayStoreConformance(make func() DpopReplayStore) ([]string, error) {
	failures := []string{}
	var runErr error
	add := func(s DpopReplayStore, k string, exp, now float64) bool {
		ok, err := s.AddIfAbsent(k, exp, now)
		if err != nil && runErr == nil {
			runErr = err
		}
		return ok && err == nil
	}
	check := func(ok bool, name string) {
		if !ok {
			failures = append(failures, name)
		}
	}
	s := make()
	check(add(s, "a", 200, 100), "first sight of a key returns true")
	check(!add(s, "a", 200, 101), "second sight of the same key returns false")
	check(add(s, "b", 200, 101), "a different key is independent")
	check(!add(s, "a", 200, 199), "still seen one second before expiry")
	t := make()
	add(t, "c", 200, 100)
	check(add(t, "c", 400, 200), "an expired entry may be added again (nowSec >= expiresAtSec)")
	u := make()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := u.AddIfAbsent("race", 200, 100)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && runErr == nil {
				runErr = err
			}
			if ok && err == nil {
				wins++
			}
		}()
	}
	wg.Wait()
	check(wins == 1, fmt.Sprintf("16 concurrent adds of one key: exactly one wins (got %d)", wins))
	if runErr != nil {
		return nil, runErr
	}
	return failures, nil
}

// DpopNonceIssuer issues and checks stateless server nonces: an 8-byte timestamp MACed with a server secret.
type DpopNonceIssuer struct {
	secret []byte
	ttl    float64
}

// NewDpopNonceIssuer: secret of at least 32 bytes; ttlSec nil = 300.
func NewDpopNonceIssuer(secret []byte, ttlSec *float64) (*DpopNonceIssuer, error) {
	if len(secret) < 32 {
		return nil, dpopErr("misconfigured", "nonce secret must be at least 32 bytes")
	}
	ttl := 300.0
	if ttlSec != nil {
		ttl = *ttlSec
	}
	if math.IsNaN(ttl) || math.IsInf(ttl, 0) || ttl <= 0 {
		return nil, dpopErr("misconfigured", "nonce ttlSec must be positive")
	}
	return &DpopNonceIssuer{secret: append([]byte(nil), secret...), ttl: ttl}, nil
}

func (n *DpopNonceIssuer) mac(ts []byte) []byte {
	m := hmac.New(sha256.New, n.secret)
	m.Write([]byte("dpop-nonce\x00"))
	m.Write(ts)
	return m.Sum(nil)[:16]
}

// Issue mints a nonce for nowSec (nil = now), which must be a non-negative integer below 2^64.
func (n *DpopNonceIssuer) Issue(nowSec *float64) (string, error) {
	now := dpopNowSec()
	if nowSec != nil {
		now = *nowSec
	}
	if now != math.Trunc(now) || math.IsInf(now, 0) {
		return "", fmt.Errorf("the number %s cannot be converted to a BigInt because it is not an integer", jsNumberString(now))
	}
	if now < 0 || now >= 1<<64 {
		return "", errors.New("nonce timestamp out of range")
	}
	ts := binary.BigEndian.AppendUint64(nil, uint64(now))
	return base64.RawURLEncoding.EncodeToString(append(ts, n.mac(ts)...)), nil
}

// Check is true only for a nonce this issuer minted that is at most ttlSec old and not more than the skew in the future.
func (n *DpopNonceIssuer) Check(nonce any, nowSec *float64) bool {
	s, ok := nonce.(string)
	if !ok {
		return false
	}
	now := dpopNowSec()
	if nowSec != nil {
		now = *nowSec
	}
	raw := nodeBase64Lenient(s)
	if len(raw) != 24 || base64.RawURLEncoding.EncodeToString(raw) != s {
		return false
	}
	if subtle.ConstantTimeCompare(raw[8:], n.mac(raw[:8])) != 1 {
		return false
	}
	issued := float64(binary.BigEndian.Uint64(raw[:8]))
	return finite(now) && issued <= now+DpopClockSkewSec && now-issued <= n.ttl
}

// DpopAlgForJwk is the JWS alg for a key from its kty / crv (RSA signs PS256).
func DpopAlgForJwk(jwk map[string]any) (string, error) {
	crv := jwk["crv"]
	switch jwk["kty"] {
	case "OKP":
		if crv == "Ed25519" || crv == "Ed448" {
			return "EdDSA", nil
		}
		return "", dpopErr("unsupported_key", fmt.Sprintf("unsupported OKP curve '%s' for DPoP", jsMemberString(jwk, "crv")))
	case "EC":
		switch crv {
		case "P-256":
			return "ES256", nil
		case "P-384":
			return "ES384", nil
		case "P-521":
			return "ES512", nil
		}
		return "", dpopErr("unsupported_key", fmt.Sprintf("unsupported EC curve '%s' for DPoP", jsMemberString(jwk, "crv")))
	case "RSA":
		return "PS256", nil
	}
	return "", dpopErr("unsupported_key", fmt.Sprintf("unsupported key type '%s' for DPoP", jsMemberString(jwk, "kty")))
}

// DpopAlgMatchesJwk: the allow-listed alg belongs to the key type of jwk. Unknown algs never match.
func DpopAlgMatchesJwk(alg string, jwk map[string]any) bool {
	kty, crv := jwk["kty"], jwk["crv"]
	switch alg {
	case "EdDSA":
		return kty == "OKP" && (crv == "Ed25519" || crv == "Ed448")
	case "ES256":
		return kty == "EC" && crv == "P-256"
	case "ES384":
		return kty == "EC" && crv == "P-384"
	case "ES512":
		return kty == "EC" && crv == "P-521"
	case "PS256", "RS256":
		return kty == "RSA"
	}
	return false
}

// NormalizeHtu is the HTTP target URI with query and fragment removed (RFC 9449 section 4.3), as the WHATWG parser
// serializes it.
func NormalizeHtu(url string) (string, error) {
	u, err := whatwgParse(url)
	if err != nil {
		return "", err
	}
	return u.scheme + "://" + u.host + u.pathname, nil
}

// AthFor is the DPoP access-token hash: base64url(SHA-256(UTF-8 of the token)).
func AthFor(accessToken string) string {
	s := sha256.Sum256([]byte(wellFormedUTF8(accessToken)))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// CreateDpopProofInput: PrivateKey is the holder's private JWK; PublicJwk (projected to its public members) is embedded and
// drives the alg; Iat nil = now, Jti nil = a random UUID.
type CreateDpopProofInput struct {
	Method, URL string
	PrivateKey  map[string]any
	PublicJwk   map[string]any
	Nonce, Ath  *string
	Iat         *float64
	Jti         *string
}

// dpopPublicJwk projects a JWK to its public members, in the reference's member order.
func dpopPublicJwk(jwk map[string]any) rawJSON {
	var kv []any
	for _, k := range []string{"kty", "crv", "x", "y", "n", "e"} {
		if v, has := jwk[k]; has {
			kv = append(kv, k, v)
		}
	}
	o, err := jsonObject(kv...)
	if err != nil {
		return "{}"
	}
	return o
}

func dpopUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := fmt.Sprintf("%x", b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// CreateDpopProof builds and signs a DPoP proof JWT (typ dpop+jwt, embedded public jwk, htm / htu / iat / jti claims).
func CreateDpopProof(in CreateDpopProofInput) (string, error) {
	pubKV := map[string]any{}
	for _, k := range []string{"kty", "crv", "x", "y", "n", "e"} {
		if v, has := in.PublicJwk[k]; has {
			pubKV[k] = v
		}
	}
	alg, err := DpopAlgForJwk(pubKV)
	if err != nil {
		return "", err
	}
	iat := dpopNowSec()
	if in.Iat != nil {
		iat = *in.Iat
	}
	htu, err := NormalizeHtu(in.URL)
	if err != nil {
		return "", err
	}
	jti := dpopUUID()
	if in.Jti != nil {
		jti = *in.Jti
	}
	kv := []any{"htm", cases.Upper(language.Und).String(in.Method), "htu", htu, "iat", jsNumber(iat), "jti", jti}
	if in.Nonce != nil {
		kv = append(kv, "nonce", *in.Nonce)
	}
	if in.Ath != nil {
		kv = append(kv, "ath", *in.Ath)
	}
	payload, err := jsonObject(kv...)
	if err != nil {
		return "", err
	}
	header, err := jsonObject("typ", DpopJwtTyp, "alg", alg, "jwk", dpopPublicJwk(in.PublicJwk))
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	sig, err := dpopSign(alg, in.PrivateKey, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

func dpopJwkBytes(jwk map[string]any, k string) ([]byte, error) {
	s, ok := jwk[k].(string)
	if !ok || s == "" {
		return nil, fmt.Errorf("private JWK member %q missing", k)
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// dpopSign signs with a private JWK whose key type must fit alg.
func dpopSign(alg string, jwk map[string]any, input []byte) ([]byte, error) {
	if _, has := jwk["d"]; !has {
		return nil, errors.New("JSON Web Key for this operation be a private JWK")
	}
	d, err := dpopJwkBytes(jwk, "d")
	if err != nil {
		return nil, err
	}
	switch alg {
	case "EdDSA":
		switch {
		case jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && len(d) == ed25519.SeedSize:
			return ed25519.Sign(ed25519.NewKeyFromSeed(d), input), nil
		case jwk["kty"] == "OKP" && jwk["crv"] == "Ed448" && len(d) == ed448.SeedSize:
			return ed448.Sign(ed448.NewKeyFromSeed(d), input, ""), nil
		}
		return nil, errors.New("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448")
	case "ES256", "ES384", "ES512":
		curve, h := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg],
			map[string]crypto.Hash{"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512}[alg]
		if jwk["kty"] != "EC" || jwk["crv"] != map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg] {
			return nil, errors.New("Invalid key for this operation, its asymmetricKeyType must be ec")
		}
		priv, err := ecdsa.ParseRawPrivateKey(curve, d)
		if err != nil {
			return nil, err
		}
		hh := h.New()
		hh.Write(input)
		r, s, err := ecdsa.Sign(rand.Reader, priv, hh.Sum(nil))
		if err != nil {
			return nil, err
		}
		n := (curve.Params().BitSize + 7) / 8
		return append(r.FillBytes(make([]byte, n)), s.FillBytes(make([]byte, n))...), nil
	case "PS256":
		if jwk["kty"] != "RSA" {
			return nil, errors.New("Invalid key for this operation, its asymmetricKeyType must be rsa")
		}
		var ints [5]*big.Int
		for i, k := range []string{"n", "e", "p", "q"} {
			b, err := dpopJwkBytes(jwk, k)
			if err != nil {
				return nil, err
			}
			ints[i] = new(big.Int).SetBytes(b)
		}
		if !ints[1].IsInt64() || ints[1].Int64() > math.MaxInt32 {
			return nil, errors.New("unsupported RSA exponent")
		}
		priv := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: ints[0], E: int(ints[1].Int64())}, D: new(big.Int).SetBytes(d), Primes: []*big.Int{ints[2], ints[3]}}
		if priv.N.BitLen() < 2048 {
			return nil, errors.New("PS256 requires key modulusLength to be 2048 bits or larger")
		}
		if err := priv.Validate(); err != nil {
			return nil, err
		}
		priv.Precompute()
		sum := sha256.Sum256(input)
		return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return nil, errors.New("unsupported DPoP alg")
}

// VerifyDpopProofOptions: MaxAgeSec nil = DpopDefaultMaxAgeSec. Without ReplayStore or SeenJti the verification is refused
// unless RequireReplayStore is explicitly false. NowSec nil = now.
type VerifyDpopProofOptions struct {
	Method, URL        string
	MaxAgeSec          *float64
	ExpectedJkt        *string
	SeenJti            JtiSeenSet
	ReplayStore        DpopReplayStore
	RequireReplayStore *bool
	NonceIssuer        *DpopNonceIssuer
	NowSec             *float64
	ExpectedNonce      *string
	AccessToken        *string
}

// DpopVerifyResult is the verified claims, the embedded public JWK and its RFC 7638 thumbprint.
type DpopVerifyResult struct {
	Claims map[string]any `json:"claims"`
	Jwk    map[string]any `json:"jwk"`
	Jkt    string         `json:"jkt"`
}

var dpopPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

// VerifyDpopProof verifies a DPoP proof: canonical spelling, typ, a public embedded jwk whose type fits alg, the signature,
// htm / htu against the request, iat freshness, the optional jkt / nonce / ath bindings and jti replay. Every failure is a
// *CodedError naming the check.
func VerifyDpopProof(proof string, o VerifyDpopProofOptions) (*DpopVerifyResult, error) {
	// A NaN or infinite max age would disable the stale check (now-iat > NaN is never true): refuse it.
	if o.MaxAgeSec != nil && (math.IsNaN(*o.MaxAgeSec) || math.IsInf(*o.MaxAgeSec, 0) || *o.MaxAgeSec < 0) {
		return nil, dpopErr("max_age", "maxAgeSec must be a finite, non-negative number of seconds")
	}
	if (o.RequireReplayStore == nil || *o.RequireReplayStore) && o.ReplayStore == nil && o.SeenJti == nil {
		return nil, dpopErr("replay_store_required", "no replay store configured; replay cannot be detected")
	}
	if jsLen(proof) > DpopMaxProofBytes {
		return nil, dpopErr("oversize", fmt.Sprintf("proof is not a string or exceeds %d bytes", DpopMaxProofBytes))
	}
	cj, err := AssertCanonicalCompactJWS(proof, 3, 0, true)
	if err != nil {
		return nil, dpopErr("malformed", "not a JWS: "+err.Error())
	}
	header := cj.Header
	if header["typ"] != DpopJwtTyp {
		return nil, dpopErr("typ", fmt.Sprintf("header typ must be '%s', got '%s'", DpopJwtTyp, jsMemberString(header, "typ")))
	}
	hj, has := header["jwk"]
	if !has {
		return nil, dpopErr("no_jwk", "proof header has no embedded jwk")
	}
	if hj == nil {
		return nil, errors.New("proof header jwk is null")
	}
	jm, isObj := hj.(map[string]any)
	for _, m := range dpopPrivateMembers {
		if _, has := jm[m]; isObj && has {
			return nil, dpopErr("private_jwk", "proof header jwk contains private key material")
		}
	}
	if alg, ok := header["alg"].(string); ok && dpopAllowed(alg) && !(isObj && DpopAlgMatchesJwk(alg, jm)) {
		return nil, dpopErr("alg_jwk_mismatch", fmt.Sprintf("alg '%s' does not match the embedded jwk key type", alg))
	}
	keyFor := func(map[string]any) (*JOSEKey, error) {
		if !isObj {
			return nil, &JOSEError{Kind: "invalid", Msg: `"jwk" (JSON Web Key) Header Parameter must be a JSON object`}
		}
		return ImportPublicJWK(jm)
	}
	_, payload, err := JWTVerify(proof, keyFor, JWTVerifyOptions{Algorithms: DpopAllowedAlgs, Typ: DpopJwtTyp}, float64(time.Now().Unix()))
	if err != nil {
		return nil, dpopErr("signature", "DPoP signature did not verify: "+err.Error())
	}
	htm, ok := payload["htm"].(string)
	if !ok {
		return nil, dpopErr("htm", "htm is missing or not a string")
	}
	htu, ok := payload["htu"].(string)
	if !ok {
		return nil, dpopErr("htu", "htu is missing or not a string")
	}
	iat, ok := jsNum(payload["iat"])
	if !ok || math.IsNaN(iat) || math.IsInf(iat, 0) {
		return nil, dpopErr("iat", "iat is missing or not a number")
	}
	jti, _ := payload["jti"].(string)
	if jti == "" {
		return nil, dpopErr("jti", "jti is missing or empty")
	}
	if htm != cases.Upper(language.Und).String(o.Method) {
		return nil, dpopErr("htm", fmt.Sprintf("htm '%s' does not match request method", htm))
	}
	want, err := NormalizeHtu(o.URL)
	if err != nil {
		return nil, err
	}
	if htu != want {
		return nil, dpopErr("htu", fmt.Sprintf("htu '%s' does not match request URL", htu))
	}
	now := dpopNowSec()
	if o.NowSec != nil {
		now = *o.NowSec
	}
	if math.IsNaN(now) || math.IsInf(now, 0) {
		return nil, dpopErr("now", "nowSec must be a finite number")
	}
	maxAge := float64(DpopDefaultMaxAgeSec)
	if o.MaxAgeSec != nil {
		maxAge = *o.MaxAgeSec
	}
	if iat > now+DpopClockSkewSec {
		return nil, dpopErr("iat_future", "iat is in the future")
	}
	if now-iat > maxAge {
		return nil, dpopErr("iat_stale", fmt.Sprintf("proof is older than %ss", jsNumberString(maxAge)))
	}
	jkt, err := JWKThumbprint(jm, "sha256")
	if err != nil {
		return nil, err
	}
	if o.ExpectedJkt != nil && jkt != *o.ExpectedJkt {
		return nil, dpopErr("jkt", "embedded key thumbprint does not match expected jkt")
	}
	if o.ExpectedNonce != nil {
		if n, ok := payload["nonce"].(string); !ok || n != *o.ExpectedNonce {
			return nil, dpopErr("nonce", "proof nonce is missing or does not match the expected nonce")
		}
	}
	if o.NonceIssuer != nil && !o.NonceIssuer.Check(payload["nonce"], &now) {
		return nil, dpopErr("nonce", "proof nonce is missing, forged or expired")
	}
	if o.AccessToken != nil {
		if a, ok := payload["ath"].(string); !ok || a != AthFor(*o.AccessToken) {
			return nil, dpopErr("ath", "proof ath is missing or does not match the access token")
		}
	}
	if o.SeenJti != nil {
		if o.SeenJti.Has(jti) {
			return nil, dpopErr("jti_replay", fmt.Sprintf("jti '%s' has already been seen", jti))
		}
		o.SeenJti.Add(jti)
	}
	if o.ReplayStore != nil {
		fresh, err := o.ReplayStore.AddIfAbsent(jkt+"."+jti, iat+maxAge+DpopClockSkewSec, now)
		if err != nil {
			return nil, dpopErr("replay_store_error", "replay store failed: "+err.Error())
		}
		if !fresh {
			return nil, dpopErr("jti_replay", fmt.Sprintf("jti '%s' has already been seen", jti))
		}
	}
	return &DpopVerifyResult{Claims: payload, Jwk: jm, Jkt: jkt}, nil
}

func dpopAllowed(alg string) bool {
	for _, a := range DpopAllowedAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

// ---- RFC 8705 mTLS ----

var pemCertBlock = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----`)
var nonBase64 = regexp.MustCompile(`[^A-Za-z0-9+/=]`)

// MtlsCnf is the RFC 8705 confirmation {"x5t#S256": b64u(sha256(DER))} for a certificate given as DER bytes or a PEM string
// (the bytes are hashed as given; see MtlsThumbprint for a certificate that must parse).
func MtlsCnf(cert any) (map[string]any, error) {
	var der []byte
	switch c := cert.(type) {
	case []byte:
		der = c
	case string:
		body := c
		if m := pemCertBlock.FindStringSubmatch(c); m != nil {
			body = m[1]
		}
		der = nodeBase64Lenient(nonBase64.ReplaceAllString(body, ""))
	default:
		return nil, errors.New("certificate must be DER bytes or a PEM string")
	}
	s := sha256.Sum256(der)
	return map[string]any{"x5t#S256": base64.RawURLEncoding.EncodeToString(s[:])}, nil
}

// mtlsCertDER returns the DER of the first certificate in DER bytes or PEM text (bytes after the certificate are ignored).
func mtlsCertDER(data []byte) ([]byte, bool) {
	first := func(b []byte) ([]byte, bool) {
		s := cryptobyte.String(b)
		var el cryptobyte.String
		if !s.ReadASN1Element(&el, cbasn1.SEQUENCE) {
			return nil, false
		}
		if _, err := x509.ParseCertificate(el); err != nil {
			return nil, false
		}
		return el, true
	}
	if der, ok := first(data); ok {
		return der, true
	}
	for rest := data; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			return nil, false
		}
		if blk.Type == "CERTIFICATE" || blk.Type == "X509 CERTIFICATE" || blk.Type == "TRUSTED CERTIFICATE" {
			return first(blk.Bytes)
		}
	}
}

// MtlsThumbprint is the RFC 8705 thumbprint base64url(SHA-256(DER)) of a certificate that parses as X.509 (code "cert"
// otherwise).
func MtlsThumbprint(cert any) (string, error) {
	var data []byte
	switch c := cert.(type) {
	case []byte:
		data = c
	case string:
		data = []byte(c)
	default:
		return "", dpopErr("cert", "not an X.509 certificate: unsupported input")
	}
	der, ok := mtlsCertDER(data)
	if !ok {
		return "", dpopErr("cert", "not an X.509 certificate")
	}
	s := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(s[:]), nil
}

// AssertMtlsBound checks that the presented client certificate hashes to the cnf's x5t#S256 (codes cert, x5t_missing, x5t).
// It does not validate the TLS handshake or chain.
func AssertMtlsBound(cert any, cnf any) (map[string]any, error) {
	m, _ := cnf.(map[string]any)
	want, _ := m["x5t#S256"].(string)
	if want == "" {
		return nil, dpopErr("x5t_missing", "cnf has no 'x5t#S256' thumbprint")
	}
	got, err := MtlsThumbprint(cert)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return nil, dpopErr("x5t", "client certificate thumbprint does not match cnf x5t#S256")
	}
	return map[string]any{"x5t#S256": got}, nil
}

// ---- PCActn <-> DPoP ----

// LeafHolderJwk is the OKP / Ed25519 JWK of the PCActn's bound holder key, the leaf of its capability chain
// (cap_chain[last].holder). Code "no_leaf" for an empty chain.
func LeafHolderJwk(p map[string]any) (map[string]any, error) {
	var leaf any
	found := false
	switch c := p["cap_chain"].(type) {
	case []any:
		if len(c) > 0 {
			leaf, found = c[len(c)-1], true
		}
	case string:
		if u := utf16Units(c); len(u) > 0 {
			leaf, found = string(rune(u[len(u)-1])), true
		}
	case map[string]any: // an array-like object: chain[chain.length - 1]
		leaf, found = c[jsNumberString(jsToNumber(c["length"])-1)]
	case nil:
		return nil, errors.New("PCActn has no capability chain")
	}
	if !found {
		return nil, dpopErr("no_leaf", "PCActn capability chain is empty; no bound holder key")
	}
	if leaf == nil {
		return nil, errors.New("PCActn leaf hop is null")
	}
	out := map[string]any{"kty": "OKP", "crv": "Ed25519"}
	if h, ok := leaf.(map[string]any); ok {
		if x, has := h["holder"]; has {
			out["x"] = x
		}
	}
	return out, nil
}

// BindPcaToDpop is the `cnf: {jkt}` confirmation of a PCActn's bound holder key.
func BindPcaToDpop(p map[string]any) (map[string]any, error) {
	j, err := LeafHolderJwk(p)
	if err != nil {
		return nil, err
	}
	jkt, err := JWKThumbprint(j, "sha256")
	if err != nil {
		return nil, err
	}
	return map[string]any{"jkt": jkt}, nil
}

// AssertPcaDpop verifies a DPoP proof with the expected jkt fixed to the PCActn's leaf-holder thumbprint (o.ExpectedJkt is
// replaced).
func AssertPcaDpop(p map[string]any, proof string, o VerifyDpopProofOptions) (*DpopVerifyResult, error) {
	b, err := BindPcaToDpop(p)
	if err != nil {
		return nil, err
	}
	jkt := b["jkt"].(string)
	o.ExpectedJkt = &jkt
	return VerifyDpopProof(proof, o)
}
