package pca

// OpenID Connect for rooting a grant in an authenticated human: provider discovery, a caching JWKS resolver that fails closed on
// stale or unreachable keys, ID-token verification (the canonical compact-JWS gate, then the JOSE checks, then the OIDC claim
// rules: nonce, azp, at_hash / c_hash) and the mapping of verified claims to a principal and an oidc_subject caveat.

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	DefaultMaxDiscoveryBytes = 1024 * 1024
	DefaultJwksTimeoutMs     = 5000
	OidcSubjectCaveat        = "oidc_subject"
	oidcWellKnown            = "/.well-known/openid-configuration"
)

// DefaultIDTokenAlgs are the asymmetric algorithms accepted when VerifyIdTokenOptions.Algorithms is nil (HS* must be opted into).
var DefaultIDTokenAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// OidcVerificationError codes: config, invalid_token, signature, issuer, audience, expired, issued_at, not_before, nonce, azp,
// at_hash, c_hash, keys, claims. Every ID-token verification failure is a *CodedError with one of them.
func oidcErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// ---- fetching ---------------------------------------------------------------------------------------------------------------

// OidcFetchRequest is one GET the discovery / JWKS code makes (Accept: application/json).
type OidcFetchRequest struct {
	URL       string
	TimeoutMs float64
	MaxBytes  int64 // the caller refuses a larger body; a fetcher may stop reading after MaxBytes+1 bytes
}

// OidcFetchResponse is the reply: Status, lower-cased Headers and the Body text.
type OidcFetchResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

// OidcFetch performs a request (nil = net/http).
type OidcFetch func(OidcFetchRequest) (*OidcFetchResponse, error)

func oidcHTTPFetch(r OidcFetchRequest) (*OidcFetchResponse, error) {
	c := &http.Client{}
	if r.TimeoutMs > 0 {
		c.Timeout = time.Duration(r.TimeoutMs * float64(time.Millisecond))
	}
	req, err := http.NewRequest(http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, r.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	h := map[string]string{}
	for k := range res.Header {
		h[strings.ToLower(k)] = res.Header.Get(k)
	}
	return &OidcFetchResponse{Status: res.StatusCode, Headers: h, Body: string(b)}, nil
}

func (f OidcFetch) do(r OidcFetchRequest) (*OidcFetchResponse, error) {
	if f == nil {
		return oidcHTTPFetch(r)
	}
	res, err := f(r)
	if err == nil && res == nil {
		err = errors.New("fetch returned no response")
	}
	return res, err
}

// ---- discovery --------------------------------------------------------------------------------------------------------------

// DiscoverOidcOptions: Fetch (nil = net/http), MaxBytes (nil or not a finite number = DefaultMaxDiscoveryBytes), RequireHttps
// (nil = true; only false allows a non-https issuer / jwks_uri).
type DiscoverOidcOptions struct {
	Fetch        OidcFetch
	MaxBytes     *float64
	RequireHttps *bool
}

// OidcDiscoveryURL is issuer + "/.well-known/openid-configuration" (one trailing slash on the issuer is dropped).
func OidcDiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + oidcWellKnown
}

func oidcIsHTTPS(u string) bool {
	p, ok := parseJSURL(u)
	return ok && p.scheme == "https"
}

// DiscoverOidc fetches and validates the provider metadata of issuer: a JSON object with non-empty string issuer (exactly the
// requested one) and jwks_uri; every member is kept.
func DiscoverOidc(issuer string, o DiscoverOidcOptions) (map[string]any, error) {
	if issuer == "" {
		return nil, errors.New("discoverOidc: issuer must be a non-empty string")
	}
	requireHttps := o.RequireHttps == nil || *o.RequireHttps
	if requireHttps && !oidcIsHTTPS(issuer) {
		return nil, fmt.Errorf("discoverOidc: issuer '%s' is not an https URL", issuer)
	}
	url := OidcDiscoveryURL(issuer)
	maxBytes := float64(DefaultMaxDiscoveryBytes)
	if o.MaxBytes != nil && !math.IsNaN(*o.MaxBytes) && !math.IsInf(*o.MaxBytes, 0) {
		maxBytes = *o.MaxBytes
	}
	res, err := o.Fetch.do(OidcFetchRequest{URL: url, MaxBytes: int64(math.Max(0, maxBytes))})
	if err != nil {
		return nil, fmt.Errorf("discoverOidc: fetch of %s failed: %w", url, err)
	}
	if res.Status < 200 || res.Status > 299 {
		return nil, fmt.Errorf("discoverOidc: %s returned HTTP %d", url, res.Status)
	}
	if cl, has := res.Headers["content-length"]; has {
		if d := jsStringToNumber(cl); !math.IsNaN(d) && !math.IsInf(d, 0) && d > maxBytes {
			return nil, fmt.Errorf("discoverOidc: %s response exceeds %v bytes", url, maxBytes)
		}
	}
	if float64(len(res.Body)) > maxBytes {
		return nil, fmt.Errorf("discoverOidc: %s response exceeds %v bytes", url, maxBytes)
	}
	body, err := ParseJSONLenient([]byte(res.Body))
	if err != nil {
		return nil, fmt.Errorf("discoverOidc: %s did not return valid JSON", url)
	}
	rec, ok := normalizeJSON(body).(map[string]any)
	if !ok {
		return nil, errors.New("discoverOidc: metadata is not a JSON object")
	}
	if s, ok := rec["issuer"].(string); !ok || s == "" {
		return nil, errors.New(`discoverOidc: metadata is missing a string "issuer"`)
	}
	if s, ok := rec["jwks_uri"].(string); !ok || s == "" {
		return nil, errors.New(`discoverOidc: metadata is missing a string "jwks_uri"`)
	}
	if rec["issuer"] != issuer {
		return nil, fmt.Errorf("discoverOidc: metadata issuer '%s' does not match requested '%s'", rec["issuer"], issuer)
	}
	if requireHttps && !oidcIsHTTPS(rec["jwks_uri"].(string)) {
		return nil, fmt.Errorf("discoverOidc: jwks_uri '%s' is not an https URL", rec["jwks_uri"])
	}
	return rec, nil
}

// ---- keys -------------------------------------------------------------------------------------------------------------------

// OidcKeyResolver returns the verification key for a token's protected header.
type OidcKeyResolver func(header map[string]any) (*JOSEKey, error)

// oidcImportJWK imports a JWK for alg as the reference library does: the JWK must be a public JWK (no private member) whose
// alg member, when present, is alg; a key passed directly must also allow verification (use "sig", key_ops with "verify") when
// it says. Key material that is malformed imports as an unusable key that verifies nothing (a signature failure, never an
// acceptance), except an OKP member of a key set, which is refused.
func oidcImportJWK(v any, alg string, direct bool) (*JOSEKey, error) {
	jwk, ok := v.(map[string]any)
	kty, tok := jwk["kty"].(string)
	if !ok || !tok {
		return nil, &JOSEError{Kind: "key", Msg: "key is not a JWK"}
	}
	for _, m := range jwkPrivateMembers {
		if _, has := jwk[m]; has && kty != "oct" { // an oct JWK is the shared secret itself
			return nil, &JOSEError{Kind: "key", Msg: "a private JWK cannot verify"}
		}
	}
	if a, has := jwk["alg"]; has && a != alg {
		return nil, &JOSEError{Kind: "key", Msg: "the JWK alg member does not match the token alg"}
	}
	if direct {
		if u, ok := jwk["use"].(string); ok && u != "sig" {
			return nil, &JOSEError{Kind: "key", Msg: "the JWK is not for signatures"}
		}
		if ops, ok := jwk["key_ops"].([]any); ok {
			has := false
			for _, op := range ops {
				has = has || op == "verify"
			}
			if !has {
				return nil, &JOSEError{Kind: "key", Msg: "the JWK key_ops do not allow verify"}
			}
		}
	}
	switch kty {
	case "oct":
		k, err := jwkB64(jwk, "k")
		if err != nil {
			return nil, &JOSEError{Kind: "key", Msg: "malformed oct JWK"}
		}
		return &JOSEKey{Kty: kty, HMAC: k}, nil
	case "EC", "RSA":
		crv, _ := jwk["crv"].(string)
		if kty == "EC" && crv != "P-256" && crv != "P-384" && crv != "P-521" {
			return nil, &JOSEError{Kind: "key", Msg: "unsupported EC curve"}
		}
		if k, err := ImportPublicJWK(jwk); err == nil {
			return k, nil
		}
		return &JOSEKey{Kty: kty, Crv: crv}, nil
	}
	k, err := ImportPublicJWK(jwk)
	if err != nil {
		if crv, _ := jwk["crv"].(string); direct && kty == "OKP" {
			return &JOSEKey{Kty: kty, Crv: crv}, nil
		}
		return nil, &JOSEError{Kind: "key", Msg: err.Error()}
	}
	return k, nil
}

func oidcKtyOfAlg(alg any) string {
	s, _ := alg.(string)
	if len(s) < 2 {
		return ""
	}
	switch s[:2] {
	case "RS", "PS":
		return "RSA"
	case "ES":
		return "EC"
	case "Ed":
		return "OKP"
	}
	return ""
}

// NewLocalJWKSet is a resolver over a JWK Set ({"keys": [JWK objects]}): the one key whose kty fits the token alg and whose kid
// (when the header has a string kid), alg, use ("sig"), key_ops ("verify") and curve fit; none or several is a refusal.
func NewLocalJWKSet(jwks any) (OidcKeyResolver, error) {
	set, ok := normalizeJSON(jwks).(map[string]any)
	keys, kok := set["keys"].([]any)
	if !ok || !kok {
		return nil, errors.New("JSON Web Key Set malformed")
	}
	members := make([]map[string]any, len(keys))
	for i, k := range keys {
		m, ok := k.(map[string]any)
		if !ok {
			return nil, errors.New("JSON Web Key Set malformed")
		}
		members[i] = m
	}
	return func(header map[string]any) (*JOSEKey, error) {
		alg, _ := header["alg"].(string)
		kty := oidcKtyOfAlg(header["alg"])
		if kty == "" {
			return nil, &JOSEError{Kind: "invalid", Msg: `Unsupported "alg" value for a JSON Web Key Set`}
		}
		kid, hasKid := header["kid"].(string)
		var found []map[string]any
		for _, j := range members {
			c := j["kty"] == kty
			if c && hasKid {
				c = j["kid"] == kid
			}
			if a, ok := j["alg"].(string); c && ok {
				c = a == alg
			}
			if u, ok := j["use"].(string); c && ok {
				c = u == "sig"
			}
			if ops, ok := j["key_ops"].([]any); c && ok {
				has := false
				for _, op := range ops {
					has = has || op == "verify"
				}
				c = has
			}
			if c && alg == "EdDSA" {
				c = j["crv"] == "Ed25519" || j["crv"] == "Ed448"
			}
			if c {
				switch alg {
				case "ES256":
					c = j["crv"] == "P-256"
				case "ES256K":
					c = j["crv"] == "secp256k1"
				case "ES384":
					c = j["crv"] == "P-384"
				case "ES512":
					c = j["crv"] == "P-521"
				}
			}
			if c {
				found = append(found, j)
			}
		}
		switch len(found) {
		case 0:
			return nil, &JOSEError{Kind: "invalid", Msg: "no applicable key found in the JSON Web Key Set"}
		case 1:
			return oidcImportJWK(found[0], alg, false)
		}
		return nil, &JOSEError{Kind: "invalid", Msg: "multiple matching keys found in the JSON Web Key Set"}
	}, nil
}

// OidcJwksOptions configure CreateOidcJwks. Unset numbers take their defaults: CacheMaxAgeSec 600, CooldownSec 30, MaxBytes
// 1 MiB, TimeoutMs DefaultJwksTimeoutMs; a set one must be finite and >= 0. RequireHttps nil = true. Now is the clock in epoch ms
// (nil = the wall clock).
type OidcJwksOptions struct {
	JwksURI                                          string
	Fetch                                            OidcFetch
	CacheMaxAgeSec, CooldownSec, MaxBytes, TimeoutMs *float64
	RequireHttps                                     *bool
	Now                                              func() float64
}

var httpsPrefix = regexp.MustCompile(`(?i)^https://`)

// CreateOidcJwks is a caching JWKS resolver that fails closed: a key set is used for at most CacheMaxAgeSec, after which it is
// refetched and, if that fails, verification is refused (code "keys"; a stale set is never used). An unknown kid refetches at
// most once per CooldownSec.
func CreateOidcJwks(o OidcJwksOptions) (OidcKeyResolver, error) {
	if o.JwksURI == "" {
		return nil, errors.New("createOidcJwks: jwksUri is required")
	}
	if (o.RequireHttps == nil || *o.RequireHttps) && !httpsPrefix.MatchString(o.JwksURI) {
		return nil, errors.New("createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)")
	}
	num := func(name string, v *float64, def float64) (float64, error) {
		if v == nil {
			return def, nil
		}
		if math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 {
			return 0, fmt.Errorf("createOidcJwks: %s must be a finite number >= 0", name)
		}
		return *v, nil
	}
	maxAge, err := num("cacheMaxAgeSec", o.CacheMaxAgeSec, 600)
	if err != nil {
		return nil, err
	}
	cooldown, err := num("cooldownSec", o.CooldownSec, 30)
	if err != nil {
		return nil, err
	}
	maxBytes, err := num("maxBytes", o.MaxBytes, 1024*1024)
	if err != nil {
		return nil, err
	}
	timeout, err := num("timeoutMs", o.TimeoutMs, DefaultJwksTimeoutMs)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	maxAgeMs, cooldownMs := maxAge*1000, cooldown*1000
	keysErr := func() error {
		return oidcErr("keys", "could not fetch the issuer signing keys from "+o.JwksURI)
	}
	type cached struct {
		at      float64
		resolve OidcKeyResolver
		kids    map[string]bool
	}
	var (
		mu        sync.Mutex
		cache     *cached
		lastFetch = math.Inf(-1)
	)
	refetch := func() error {
		lastFetch = now()
		if timeout != math.Trunc(timeout) || timeout > math.MaxUint32 {
			return keysErr() // the reference's request timer takes whole milliseconds only
		}
		res, err := o.Fetch.do(OidcFetchRequest{URL: o.JwksURI, TimeoutMs: timeout, MaxBytes: int64(maxBytes)})
		if err != nil || res.Status < 200 || res.Status > 299 || float64(len(res.Body)) > maxBytes {
			return keysErr()
		}
		v, err := ParseJSONLenient([]byte(res.Body))
		if err != nil {
			return keysErr()
		}
		resolve, err := NewLocalJWKSet(v)
		if err != nil {
			return keysErr()
		}
		kids := map[string]bool{}
		for _, k := range normalizeJSON(v).(map[string]any)["keys"].([]any) {
			if s, ok := k.(map[string]any)["kid"].(string); ok {
				kids[s] = true
			}
		}
		cache = &cached{at: now(), resolve: resolve, kids: kids}
		return nil
	}
	return func(header map[string]any) (*JOSEKey, error) {
		mu.Lock()
		defer mu.Unlock()
		t := now()
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil, oidcErr("keys", "the clock returned a non-finite time")
		}
		if cache == nil || t-cache.at >= maxAgeMs {
			cache = nil // never serve a stale set, even if the refetch fails
			if err := refetch(); err != nil {
				return nil, err
			}
		} else if kid, ok := header["kid"].(string); ok && !cache.kids[kid] && t-lastFetch >= cooldownMs {
			if err := refetch(); err != nil {
				return nil, err
			}
		}
		return cache.resolve(header)
	}, nil
}

// CreateOidcJwksFromIssuer discovers the issuer's jwks_uri (https unless RequireHttps is false) and builds the resolver.
func CreateOidcJwksFromIssuer(issuer string, o OidcJwksOptions) (OidcKeyResolver, error) {
	meta, err := DiscoverOidc(issuer, DiscoverOidcOptions{Fetch: o.Fetch, RequireHttps: o.RequireHttps})
	if err != nil {
		return nil, err
	}
	o.JwksURI = meta["jwks_uri"].(string)
	return CreateOidcJwks(o)
}

// ExportPublicJWK is the public JWK (kty, crv, x, y, n, e) of an imported key.
func ExportPublicJWK(k *JOSEKey) map[string]any {
	enc := base64.RawURLEncoding.EncodeToString
	switch {
	case k.Ed25519 != nil:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": enc(k.Ed25519)}
	case k.Ed448 != nil:
		return map[string]any{"kty": "OKP", "crv": "Ed448", "x": enc(k.Ed448)}
	case k.EC != nil:
		n := (k.EC.Curve.Params().BitSize + 7) / 8
		return map[string]any{"kty": "EC", "crv": k.Crv, "x": enc(k.EC.X.FillBytes(make([]byte, n))), "y": enc(k.EC.Y.FillBytes(make([]byte, n)))}
	case k.RSA != nil:
		return map[string]any{"kty": "RSA", "n": enc(k.RSA.N.Bytes()), "e": enc(big.NewInt(int64(k.RSA.E)).Bytes())}
	}
	return map[string]any{"kty": k.Kty}
}

// ---- ID-token verification ----------------------------------------------------------------------------------------------------

// VerifyIdTokenOptions. Exactly one of Audience (a single client id; "" = "aud" required but unchecked) and Audiences (non-nil:
// "aud" must name one of them) is set. Key is a *JOSEKey, a JWK (map), an HMAC secret ([]byte) or an OidcKeyResolver; without it,
// JwksURI (or Discover, through the issuer's discovery document) builds a CreateOidcJwks resolver. Algorithms nil =
// DefaultIDTokenAlgs. A nil pointer is an absent option.
type VerifyIdTokenOptions struct {
	Issuer                            string
	Audience                          *string
	Audiences                         []string
	Nonce, AuthorizedParty            *string
	AccessToken, Code                 *string
	ClockToleranceSec, MaxTokenAgeSec *float64
	Algorithms                        []string
	Key                               any
	JwksURI                           *string
	Discover                          bool
	Fetch                             OidcFetch
	RequireHttps                      *bool
	NowSec                            *float64
}

func oidcMapJoseError(err error) error {
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce
	}
	var je *JOSEError
	if !errors.As(err, &je) {
		return oidcErr("invalid_token", "id token verification failed")
	}
	switch je.Kind {
	case "expired":
		if je.Claim == "iat" {
			return oidcErr("issued_at", "id token is older than the maximum accepted age")
		}
		return oidcErr("expired", "id token has expired")
	case "claim":
		code := map[string]string{"iss": "issuer", "aud": "audience", "iat": "issued_at", "nbf": "not_before"}[je.Claim]
		if code == "" {
			code = "claims"
		}
		return oidcErr(code, je.Msg)
	case "signature":
		return oidcErr("signature", "id token signature verification failed")
	}
	return oidcErr("invalid_token", je.Msg)
}

func oidcKeyFor(o VerifyIdTokenOptions) (func(map[string]any) (*JOSEKey, error), error) {
	switch k := o.Key.(type) {
	case *JOSEKey:
		return func(map[string]any) (*JOSEKey, error) { return k, nil }, nil
	case []byte:
		return func(map[string]any) (*JOSEKey, error) { return &JOSEKey{Kty: "oct", HMAC: k}, nil }, nil
	case map[string]any:
		return func(h map[string]any) (*JOSEKey, error) { a, _ := h["alg"].(string); return oidcImportJWK(k, a, true) }, nil
	case OidcKeyResolver:
		return k, nil
	case func(map[string]any) (*JOSEKey, error):
		return k, nil
	case nil:
	default:
		return func(map[string]any) (*JOSEKey, error) { return nil, &JOSEError{Kind: "key", Msg: "unsupported key"} }, nil
	}
	var uri string
	switch {
	case o.JwksURI != nil:
		uri = *o.JwksURI
	case o.Discover:
		meta, err := DiscoverOidc(o.Issuer, DiscoverOidcOptions{RequireHttps: o.RequireHttps, Fetch: o.Fetch})
		if err != nil {
			return nil, err
		}
		uri = meta["jwks_uri"].(string)
	default:
		return nil, oidcErr("config", "verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)")
	}
	r, err := CreateOidcJwks(OidcJwksOptions{JwksURI: uri, RequireHttps: o.RequireHttps})
	if err != nil {
		return nil, oidcErr("config", "verifyIdToken: "+err.Error())
	}
	return r, nil
}

// oidcHalfHash is base64url(left half of SHA-n(value)) with the value encoded one byte per UTF-16 code unit (its low byte),
// as the reference hashes it.
func oidcHalfHash(value, alg string) (string, bool) {
	bits := ""
	if alg == "EdDSA" {
		bits = "512"
	} else if len(alg) >= 3 {
		if t := alg[len(alg)-3:]; t == "256" || t == "384" || t == "512" {
			bits = t
		}
	}
	units := utf16.Encode([]rune(value))
	b := make([]byte, len(units))
	for i, u := range units {
		b[i] = byte(u)
	}
	var d []byte
	switch bits {
	case "256":
		s := sha256.Sum256(b)
		d = s[:]
	case "384":
		s := sha512.Sum384(b)
		d = s[:]
	case "512":
		s := sha512.Sum512(b)
		d = s[:]
	default:
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(d[:len(d)/2]), true
}

func oidcStr(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && s != ""
}

// VerifyIdToken verifies an OIDC ID token and returns its projected claims: iss, sub, aud, iat, exp, plus nonce, azp, at_hash,
// c_hash, auth_time, email, email_verified, name, preferred_username, given_name, family_name, picture and cnf when present with
// the right type. Every failure is a *CodedError.
func VerifyIdToken(idToken string, o VerifyIdTokenOptions) (map[string]any, error) {
	if idToken == "" {
		return nil, oidcErr("invalid_token", "verifyIdToken: idToken must be a non-empty string")
	}
	if o.Issuer == "" {
		return nil, oidcErr("config", "verifyIdToken: opts.issuer is required")
	}
	if o.Audience == nil && o.Audiences == nil {
		return nil, oidcErr("config", "verifyIdToken: opts.audience is required")
	}
	// a non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check (an infinite one is the unbounded limit)
	if o.ClockToleranceSec != nil && !(finite(*o.ClockToleranceSec) && *o.ClockToleranceSec >= 0) {
		return nil, oidcErr("config", "verifyIdToken: clockToleranceSec must be a finite number >= 0")
	}
	if o.MaxTokenAgeSec != nil && !(*o.MaxTokenAgeSec >= 0) {
		return nil, oidcErr("config", "verifyIdToken: maxTokenAgeSec must be a number >= 0")
	}
	if _, err := AssertCanonicalCompactJWS(idToken, 3, 0, true); err != nil {
		return nil, oidcErr("invalid_token", err.Error())
	}
	keyFor, err := oidcKeyFor(o)
	if err != nil {
		return nil, err
	}
	vo := JWTVerifyOptions{Issuer: []string{o.Issuer}, Algorithms: o.Algorithms, NowSec: o.NowSec}
	if vo.Algorithms == nil {
		vo.Algorithms = DefaultIDTokenAlgs
	}
	if o.Audience != nil {
		vo.Audience, vo.AudienceAny = []string{*o.Audience}, *o.Audience == ""
	} else {
		vo.Audience = o.Audiences
	}
	if o.ClockToleranceSec != nil {
		vo.ClockTolerance = *o.ClockToleranceSec
	}
	if o.MaxTokenAgeSec != nil {
		vo.MaxTokenAge = *o.MaxTokenAgeSec
	}
	h, p, err := JWTVerify(idToken, keyFor, vo, float64(time.Now().Unix()))
	if err != nil {
		return nil, oidcMapJoseError(err)
	}
	claims, err := oidcProjectClaims(p, o)
	if err != nil {
		return nil, err
	}
	alg, _ := h["alg"].(string)
	for _, c := range []struct {
		name  string
		value *string
	}{{"at_hash", o.AccessToken}, {"c_hash", o.Code}} {
		if c.value == nil {
			continue
		}
		actual, has := claims[c.name]
		if !has {
			return nil, oidcErr(c.name, "id token is missing the expected "+c.name)
		}
		want, ok := oidcHalfHash(*c.value, alg)
		if !ok {
			return nil, oidcErr(c.name, fmt.Sprintf("cannot compute %s for alg %s", c.name, alg))
		}
		if actual != want {
			return nil, oidcErr(c.name, "id token "+c.name+" does not match the supplied value")
		}
	}
	return claims, nil
}

func oidcProjectClaims(p map[string]any, o VerifyIdTokenOptions) (map[string]any, error) {
	iss, ok := oidcStr(p["iss"])
	if !ok {
		return nil, oidcErr("issuer", `id token is missing the "iss" claim`)
	}
	sub, ok := oidcStr(p["sub"])
	if !ok {
		return nil, oidcErr("claims", `id token is missing the "sub" claim`)
	}
	aud, has := p["aud"]
	if !has {
		return nil, oidcErr("audience", `id token is missing the "aud" claim`)
	}
	if _, ok := jsNum(p["iat"]); !ok {
		return nil, oidcErr("issued_at", `id token is missing a numeric "iat" claim`)
	}
	if _, ok := jsNum(p["exp"]); !ok {
		return nil, oidcErr("expired", `id token is missing a numeric "exp" claim`)
	}
	out := map[string]any{"iss": iss, "sub": sub, "aud": aud, "iat": p["iat"], "exp": p["exp"]}
	for _, k := range []string{"nonce", "azp", "at_hash", "c_hash", "email", "name", "preferred_username", "given_name", "family_name", "picture"} {
		if s, ok := oidcStr(p[k]); ok {
			out[k] = s
		}
	}
	if o.Nonce != nil && out["nonce"] != *o.Nonce {
		if _, has := out["nonce"]; !has {
			return nil, oidcErr("nonce", "id token is missing the expected nonce")
		}
		return nil, oidcErr("nonce", "id token nonce does not match the expected value")
	}
	expectedAzp := o.AuthorizedParty
	if expectedAzp == nil && o.Audience != nil {
		expectedAzp = o.Audience
	}
	azp, hasAzp := out["azp"]
	if l, isList := aud.([]any); isList && len(l) > 1 && !hasAzp {
		return nil, oidcErr("azp", "id token has multiple audiences but no azp (authorized party)")
	}
	if hasAzp && expectedAzp != nil && azp != *expectedAzp {
		return nil, oidcErr("azp", "id token azp does not match the authorized party")
	}
	if c, ok := p["cnf"].(map[string]any); ok {
		out["cnf"] = c
	}
	if b, ok := p["email_verified"].(bool); ok {
		out["email_verified"] = b
	}
	if _, ok := jsNum(p["auth_time"]); ok {
		out["auth_time"] = p["auth_time"]
	}
	return out, nil
}

// ---- principal --------------------------------------------------------------------------------------------------------------

func oidcCanonicalEd25519(s string) bool {
	_, ok := DecodeB64uStrict(s, 32)
	return ok && s != ""
}

// OidcPrincipal maps verified claims to a principal: iss, sub, principalId ("iss#sub"), subjectCaveat ({type: oidc_subject, iss,
// sub}), claims, and principalPublic (the cnf-bound Ed25519 key, or principalPublic, which must equal it when both are present),
// email, emailVerified, name, preferredUsername and authTime when the claims carry them.
func OidcPrincipal(claims map[string]any, principalPublic *string) (map[string]any, error) {
	iss, ok := oidcStr(claims["iss"])
	if !ok {
		return nil, errors.New("oidcPrincipal: claims.iss is required")
	}
	sub, ok := oidcStr(claims["sub"])
	if !ok {
		return nil, errors.New("oidcPrincipal: claims.sub is required")
	}
	var fromToken *string
	if cnf, has := claims["cnf"]; has {
		if cnf == nil {
			return nil, errors.New("oidcPrincipal: claims.cnf is null")
		}
		if c, ok := cnf.(map[string]any); ok {
			if jwk, ok := c["jwk"].(map[string]any); ok && jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" {
				if x, ok := jwk["x"].(string); ok && oidcCanonicalEd25519(x) {
					fromToken = &x
				}
			}
		}
	}
	pub := fromToken
	if principalPublic != nil {
		if !oidcCanonicalEd25519(*principalPublic) {
			return nil, errors.New("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key")
		}
		if fromToken != nil && *fromToken != *principalPublic {
			return nil, errors.New("oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token")
		}
		pub = principalPublic
	}
	out := map[string]any{
		"iss": iss, "sub": sub, "principalId": iss + "#" + sub,
		"subjectCaveat": map[string]any{"type": OidcSubjectCaveat, "iss": iss, "sub": sub}, "claims": claims,
	}
	if pub != nil {
		out["principalPublic"] = *pub
	}
	for from, to := range map[string]string{"email": "email", "email_verified": "emailVerified", "name": "name", "preferred_username": "preferredUsername", "auth_time": "authTime"} {
		if v, has := claims[from]; has {
			out[to] = v
		}
	}
	return out, nil
}

// IsOidcSubjectCaveat reports whether cv is {type: "oidc_subject", iss: non-empty string, sub: non-empty string}.
func IsOidcSubjectCaveat(cv any) bool {
	m, ok := cv.(map[string]any)
	_, iok := oidcStr(m["iss"])
	_, sok := oidcStr(m["sub"])
	return ok && m["type"] == OidcSubjectCaveat && iok && sok
}
