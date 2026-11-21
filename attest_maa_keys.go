package pca

// Rotation-safe key trust for Azure MAA token-signing keys (the reference attestMaaKeys): it derives the SPKI pins a MAA verifier
// trusts from a freshly fetched `<issuer>/certs` JWKS under an explicit rotation policy, persists the accepted set and fails closed
// when the policy is violated. Network I/O happens only inside GetTrustAnchors / FetchMaaCerts, only for https issuers named in
// the policy, through an injected transport. Self-signed instance certs need subject CN equal to the issuer URL, a genuine self
// signature, a live validity window (+skew), an age within MaxKeyAgeMs and RSA 2048..8192 or EC P-256/384/521; Microsoft-chained
// keys count only under a pinned chain root (and a pinned intermediate when configured). The accepted set changes only by rotation
// (at most MaxNewKeysPerFetch unseen keys per fetch, one key in common with the previous unexpired set), unless an operator-signed
// manifest approves the new keys. A transport failure serves the last accepted set for at most MaxStaleMs; a policy violation never
// falls back to stale data. See the reference header for what is not guaranteed (the built-in pins are release-signed, not a
// Microsoft root, for self-signed instance keys).

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maaHour          = int64(3_600_000)
	maaDay           = 24 * maaHour
	maaMaxJwksKeys   = 32
	maaMaxX5c        = 8
	maaMaxX5cB64     = 131_072
	maaMaxSafeInt    = int64(1)<<53 - 1
	maaDefaultBodyMb = int64(1_048_576)
)

var (
	maaIssuerURL = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	maaHex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	maaSoleCnRe  = regexp.MustCompile(`^CN=(.*)$`)
	maaEcCurves  = map[string]bool{"prime256v1": true, "secp384r1": true, "secp521r1": true}
)

// MaaKeyPolicy is the rotation policy. Pointer fields are optional (nil is the documented default); a nil slice is "not set".
type MaaKeyPolicy struct {
	// TrustedIssuers are the pinned MAA instance issuer URLs (exact match, https, no path or trailing slash).
	TrustedIssuers []string
	// TtlMs reuses a fetched set for this long (default 1 h).
	TtlMs *int64
	// MaxStaleMs serves the last accepted set on transport failure for at most this long after its fetch (default 24 h).
	MaxStaleMs *int64
	// MaxNewKeysPerFetch caps keys not in the previous set per fetch (default 2).
	MaxNewKeysPerFetch *int
	// MaxInitialKeys caps the very first (trust-on-first-use or re-pinned) set (default 8).
	MaxInitialKeys *int
	// MaxKeyAgeMs rejects self-signed certs whose notBefore is older than this (default 400 days).
	MaxKeyAgeMs *int64
	// RequireOverlap demands one key in common with the previous unexpired set (default true).
	RequireOverlap *bool
	// AllowTrustOnFirstUse is the explicit opt-in to trust-on-first-use when there is no built-in pin, initial pin or state.
	AllowTrustOnFirstUse bool
	// InitialPins are out-of-band SPKI SHA-256 pins per issuer, the baseline when no state is stored.
	InitialPins map[string][]string
	// ChainRootSpkiSha256 are the pinned roots under which Microsoft-chained keys are accepted (nil: the built-in pins').
	ChainRootSpkiSha256 []string
	// ChainIntermediateSpkiSha256 is an intermediate every accepted chained key must pass through (nil: the built-in pins').
	ChainIntermediateSpkiSha256 []string
	// DisableBuiltinPins turns the release-signed built-in pins off; BuiltinPinsSource substitutes another signed source.
	DisableBuiltinPins bool
	BuiltinPinsSource  *BuiltinMaaPinsSource
	// ChainLeafCn restricts a chained leaf's subject CN (nil: the built-in leaf CN).
	ChainLeafCn []string
	// ClockSkewMs is the tolerance for certificate validity (default 60 s).
	ClockSkewMs *int64
	// FetchTimeoutMs is the fetch timeout (default 10 s); MaxBodyBytes the response limit (default 1 MiB).
	FetchTimeoutMs, MaxBodyBytes *int64
}

func (p *MaaKeyPolicy) skew() int64 {
	if p.ClockSkewMs != nil {
		return *p.ClockSkewMs
	}
	return 60_000
}

func (p *MaaKeyPolicy) clone() MaaKeyPolicy {
	c := *p
	c.TrustedIssuers = append([]string(nil), p.TrustedIssuers...)
	if p.InitialPins != nil {
		c.InitialPins = map[string][]string{}
		for k, v := range p.InitialPins {
			c.InitialPins[k] = append([]string(nil), v...)
		}
	}
	if p.ChainRootSpkiSha256 != nil {
		c.ChainRootSpkiSha256 = append([]string{}, p.ChainRootSpkiSha256...)
	}
	if p.ChainIntermediateSpkiSha256 != nil {
		c.ChainIntermediateSpkiSha256 = append([]string{}, p.ChainIntermediateSpkiSha256...)
	}
	if p.ChainLeafCn != nil {
		c.ChainLeafCn = append([]string{}, p.ChainLeafCn...)
	}
	return c
}

// MaaAnchorRecord is one accepted anchor. Kind is self-signed, chained-root or chained-intermediate.
type MaaAnchorRecord struct {
	Spki        string `json:"spki"`
	Kind        string `json:"kind"`
	NotBeforeMs int64  `json:"notBeforeMs"`
	NotAfterMs  int64  `json:"notAfterMs"`
	FirstSeenMs int64  `json:"firstSeenMs"`
}

// MaaKeyState is the persisted accepted set of one issuer (V is always 1).
type MaaKeyState struct {
	V           int               `json:"v"`
	Issuer      string            `json:"issuer"`
	FetchedAtMs int64             `json:"fetchedAtMs"`
	Anchors     []MaaAnchorRecord `json:"anchors"`
}

// MaaKeyStateStore is the caller-supplied persistence. Get returns the stored value undecoded (a decoded JSON value, or a
// MaaKeyState) so that GetTrustAnchors can validate it and fail closed (corrupt-state) on anything malformed.
type MaaKeyStateStore interface {
	Get(issuer string) (value any, ok bool, err error)
	Set(issuer string, state MaaKeyState) error
}

// MemoryMaaKeyStateStore is the in-memory MaaKeyStateStore (tests, single process).
type MemoryMaaKeyStateStore struct{ m map[string]string }

// CreateMemoryMaaKeyStateStore returns an empty in-memory store.
func CreateMemoryMaaKeyStateStore() *MemoryMaaKeyStateStore {
	return &MemoryMaaKeyStateStore{m: map[string]string{}}
}

// Get implements MaaKeyStateStore (the value is a decoded copy).
func (s *MemoryMaaKeyStateStore) Get(issuer string) (any, bool, error) {
	t, ok := s.m[issuer]
	if !ok {
		return nil, false, nil
	}
	v, perr := ParseJSONLenient([]byte(t))
	return v, true, perr
}

// Set implements MaaKeyStateStore (the state is stored as its JSON).
func (s *MemoryMaaKeyStateStore) Set(issuer string, state MaaKeyState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	s.m[issuer] = string(b)
	return nil
}

// Snapshot returns the stored states by issuer.
func (s *MemoryMaaKeyStateStore) Snapshot() map[string]MaaKeyState {
	out := map[string]MaaKeyState{}
	for k, t := range s.m {
		var st MaaKeyState
		if json.Unmarshal([]byte(t), &st) == nil {
			out[k] = st
		}
	}
	return out
}

// MaaKeyErrorCode is the failure class of a MaaTrustResult.
type MaaKeyErrorCode string

// The failure classes of GetTrustAnchors.
const (
	MaaUntrustedIssuer    MaaKeyErrorCode = "untrusted-issuer"
	MaaCorruptState       MaaKeyErrorCode = "corrupt-state"
	MaaClockRegression    MaaKeyErrorCode = "clock-regression"
	MaaFetchFailed        MaaKeyErrorCode = "fetch-failed"
	MaaStaleExceeded      MaaKeyErrorCode = "stale-exceeded"
	MaaNoValidKeys        MaaKeyErrorCode = "no-valid-keys"
	MaaNoBaseline         MaaKeyErrorCode = "no-baseline"
	MaaTooManyNewKeys     MaaKeyErrorCode = "too-many-new-keys"
	MaaNoOverlap          MaaKeyErrorCode = "no-overlap"
	MaaRepinInvalid       MaaKeyErrorCode = "repin-invalid"
	MaaBuiltinPinsInvalid MaaKeyErrorCode = "builtin-pins-invalid"
)

// MaaRejectedKey is a JWKS entry that was not accepted, with the reason.
type MaaRejectedKey struct{ Kid, Reason string }

// MaaTrustResult is the outcome of GetTrustAnchors. On Ok, RootSpkiSha256 is ready for the MAA verifier's trust anchors.
type MaaTrustResult struct {
	Ok     bool
	Code   MaaKeyErrorCode
	Reason string
	// RootSpkiSha256 is the sorted, de-duplicated anchor SPKI SHA-256 set.
	RootSpkiSha256 []string
	// Source is cache, fetched or stale-cache.
	Source  string
	Anchors []MaaAnchorRecord
	// NewKeys are the keys not in the previous set; RemovedKeys the previous ones absent now.
	NewKeys, RemovedKeys []string
	Rejected             []MaaRejectedKey
}

// MaaJwk is one JWKS entry (only the members the key trust reads).
type MaaJwk struct {
	Kid, Kty, Alg *string
	X5c           []string
}

// MaaJwks is a MAA signing-certificate set.
type MaaJwks struct{ Keys []MaaJwk }

// MaaFetchResponse is what a MaaFetch returns for a GET: the status, the final URL ("" when unknown), the declared content length
// (-1 when unknown) and the body.
type MaaFetchResponse struct {
	Status        int
	URL           string
	ContentLength int64
	Body          []byte
}

// MaaFetch is the injected transport. It must not follow redirects, must give up after timeoutMs and must not read more than
// maxBytes+1 bytes of the body.
type MaaFetch func(url string, timeoutMs, maxBytes int64) (MaaFetchResponse, error)

// DefaultMaaFetch is a net/http MaaFetch (redirects are an error).
func DefaultMaaFetch(url string, timeoutMs, maxBytes int64) (MaaFetchResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return MaaFetchResponse{}, err
	}
	req.Header.Set("accept", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return MaaFetchResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return MaaFetchResponse{}, errors.New("redirect refused")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return MaaFetchResponse{}, err
	}
	return MaaFetchResponse{Status: res.StatusCode, URL: res.Request.URL.String(), ContentLength: res.ContentLength, Body: body}, nil
}

// FetchMaaCertsOptions configure FetchMaaCerts. Fetch is required (DefaultMaaFetch is the net/http one); zero TimeoutMs / MaxBytes
// mean 10 s and 1 MiB.
type FetchMaaCertsOptions struct {
	Fetch               MaaFetch
	TimeoutMs, MaxBytes int64
}

// FetchMaaCerts fetches `<issuer>/certs` with https only, no redirects, a timeout and a size limit. Any problem is an error.
func FetchMaaCerts(issuer string, o FetchMaaCertsOptions) (*MaaJwks, error) {
	if o.Fetch == nil {
		return nil, errors.New("fetchMaaCerts: a fetch implementation must be injected")
	}
	if !maaIssuerURL.MatchString(issuer) {
		return nil, errors.New("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)")
	}
	timeoutMs, maxBytes := o.TimeoutMs, o.MaxBytes
	if timeoutMs == 0 {
		timeoutMs = 10_000
	}
	if maxBytes == 0 {
		maxBytes = maaDefaultBodyMb
	}
	url := issuer + "/certs"
	type outcome struct {
		res MaaFetchResponse
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- outcome{err: fmt.Errorf("%v", r)}
			}
		}()
		r, err := o.Fetch(url, timeoutMs, maxBytes)
		ch <- outcome{r, err}
	}()
	var out outcome
	select {
	case out = <-ch:
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return nil, fmt.Errorf("MAA certs fetch timed out after %d ms", timeoutMs)
	}
	if out.err != nil {
		return nil, out.err
	}
	res := out.res
	if res.Status < 200 || res.Status > 299 {
		return nil, fmt.Errorf("MAA certs fetch failed: HTTP %d", res.Status)
	}
	if res.URL != "" && res.URL != url {
		return nil, errors.New("MAA certs fetch: response URL differs from the request (redirect)")
	}
	if res.ContentLength > maxBytes {
		return nil, errors.New("MAA certs response exceeds the size limit")
	}
	if int64(len(res.Body)) > maxBytes {
		return nil, errors.New("MAA certs response exceeds the size limit")
	}
	body := res.Body
	if !utf8.Valid(body) {
		return nil, errors.New("MAA certs response is not valid UTF-8 JSON")
	}
	body = []byte(strings.TrimPrefix(string(body), "\ufeff")) // TextDecoder drops a BOM
	parsed, perr := ParseJSONLenient(body)
	if perr != nil {
		return nil, errors.New("MAA certs response is not valid UTF-8 JSON")
	}
	return parseMaaJwks(parsed)
}

func parseMaaJwks(x any) (*MaaJwks, error) {
	obj, ok := x.(map[string]any)
	var raw []any
	if ok {
		raw, ok = obj["keys"].([]any)
	}
	if !ok {
		return nil, errors.New("MAA certs: response has no keys array")
	}
	if len(raw) > maaMaxJwksKeys {
		return nil, errors.New("MAA certs: too many keys")
	}
	out := &MaaJwks{}
	for _, k := range raw {
		r, isObj := k.(map[string]any)
		if !isObj {
			return nil, errors.New("MAA certs: malformed key entry")
		}
		x5c, isArr := r["x5c"].([]any)
		if !isArr || len(x5c) == 0 || len(x5c) > maaMaxX5c {
			return nil, errors.New("MAA certs: key without a well-formed x5c")
		}
		jk := MaaJwk{}
		for _, c := range x5c {
			s, isStr := c.(string)
			if !isStr || len(s) == 0 || utf16Len(s) > maaMaxX5cB64 {
				return nil, errors.New("MAA certs: key without a well-formed x5c")
			}
			jk.X5c = append(jk.X5c, s)
		}
		str := func(name string) *string {
			if s, isStr := r[name].(string); isStr {
				return &s
			}
			return nil
		}
		jk.Kid, jk.Kty, jk.Alg = str("kid"), str("kty"), str("alg")
		out.Keys = append(out.Keys, jk)
	}
	return out, nil
}

// ───────────────────────────── JWKS evaluation ─────────────────────────────

func maaSpkiOf(c *attCert) string {
	h := sha256.Sum256(c.RawSPKI)
	return hex.EncodeToString(h[:])
}

func maaSoleCn(subject string) (string, bool) {
	var lines []string
	for _, l := range strings.Split(subject, "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		return "", false
	}
	m := maaSoleCnRe.FindStringSubmatch(lines[0])
	if m == nil {
		return "", false
	}
	return m[1], true
}

func maaLeafCn(subject string) (string, bool) {
	for _, l := range strings.Split(subject, "\n") {
		if strings.HasPrefix(l, "CN=") {
			return l[3:], true
		}
	}
	return "", false
}

// maaKeyStrengthError is "" when the key is allowed; an unreadable key is an error.
func maaKeyStrengthError(c *attCert) (string, error) {
	k, err := keyOfCert(c)
	if err != nil {
		return "", err
	}
	switch k.typ {
	case "rsa":
		bits := 0
		if pk, ok := k.pub.(*rsa.PublicKey); ok && pk.N != nil {
			bits = pk.N.BitLen()
		}
		if !(bits >= 2048 && bits <= 8192) {
			return fmt.Sprintf("RSA key size %d outside 2048..8192", bits), nil
		}
		if pk, ok := k.pub.(*rsa.PublicKey); !ok || !rsaKeyOK(pk) {
			return "RSA public exponent must be odd, at least 3 and at most 32 bits", nil
		}
		return "", nil
	case "ec":
		if maaEcCurves[k.curve] {
			return "", nil
		}
		return fmt.Sprintf("EC curve '%s' not allowed", k.curve), nil
	}
	return fmt.Sprintf("key type '%s' not allowed", k.typ), nil
}

// maaSafeVerify is rsaKeyOk(key) && cert.verify(key); a key that cannot be read fails.
func maaSafeVerify(c, signer *attCert) bool {
	k, err := keyOfCert(signer)
	if err != nil {
		return false
	}
	if pk, isRsa := k.pub.(*rsa.PublicKey); isRsa && !rsaKeyOK(pk) {
		return false
	}
	return certSigOK(c, k)
}

// MaaJwksEvaluation is the pure validation of a JWKS: the accepted anchors (FirstSeenMs is 0) and the rejected entries.
type MaaJwksEvaluation struct {
	Accepted []MaaAnchorRecord
	Rejected []MaaRejectedKey
}

func lowerSet(in []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range in {
		m[strings.ToLower(s)] = true
	}
	return m
}

// EvaluateMaaJwks validates every key of a JWKS against the policy at nowMs. It never panics.
func EvaluateMaaJwks(jwks *MaaJwks, issuer string, policy *MaaKeyPolicy, nowMs int64) MaaJwksEvaluation {
	skew := policy.skew()
	maxAge := 400 * maaDay
	if policy.MaxKeyAgeMs != nil {
		maxAge = *policy.MaxKeyAgeMs
	}
	roots, inters := lowerSet(policy.ChainRootSpkiSha256), lowerSet(policy.ChainIntermediateSpkiSha256)
	var order []string
	accepted := map[string]MaaAnchorRecord{}
	ev := MaaJwksEvaluation{}
	if jwks == nil {
		return ev
	}
	for i, key := range jwks.Keys {
		kid := fmt.Sprintf("#%d", i)
		if key.Kid != nil {
			kid = *key.Kid
		}
		no := func(reason string) { ev.Rejected = append(ev.Rejected, MaaRejectedKey{kid, reason}) }
		rec, err := func() (rec *MaaAnchorRecord, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("%v", r)
				}
			}()
			return maaEvaluateKey(key, issuer, policy, nowMs, skew, maxAge, roots, inters, accepted)
		}()
		if err != nil {
			no(err.Error())
			continue
		}
		if rec == nil {
			continue
		}
		if _, seen := accepted[rec.Spki]; !seen {
			order = append(order, rec.Spki)
		}
		accepted[rec.Spki] = *rec
	}
	for _, s := range order {
		ev.Accepted = append(ev.Accepted, accepted[s])
	}
	return ev
}

func maaEvaluateKey(key MaaJwk, issuer string, policy *MaaKeyPolicy, nowMs, skew, maxAge int64, roots, inters map[string]bool, accepted map[string]MaaAnchorRecord) (*MaaAnchorRecord, error) {
	if len(key.X5c) == 0 {
		return nil, errors.New("no x5c")
	}
	certs := make([]*attCert, len(key.X5c))
	for i, b := range key.X5c {
		c, err := parseCertDER(nodeB64(b))
		if err != nil {
			return nil, err
		}
		certs[i] = c
	}
	leaf := certs[0]
	for j, c := range certs {
		from, to := derValidity(c.Raw)
		if !from.ok || !to.ok {
			return nil, fmt.Errorf("cert %d: unparsable validity", j)
		}
		if nowMs+skew < from.ms {
			return nil, fmt.Errorf("cert %d: not yet valid", j)
		}
		if nowMs-skew > to.ms {
			return nil, fmt.Errorf("cert %d: expired", j)
		}
	}
	lvFrom, lvTo := derValidity(leaf.Raw)
	strength, err := maaKeyStrengthError(leaf)
	if err != nil {
		return nil, err
	}
	if strength != "" {
		return nil, errors.New(strength)
	}
	leafSubject, leafIssuer := nameText(leaf.RawSubject), nameText(leaf.RawIssuer)
	if len(certs) == 1 {
		if nowMs-lvFrom.ms > maxAge {
			return nil, errors.New("key older than maxKeyAgeMs")
		}
		cn, ok := maaSoleCn(leafSubject)
		if !ok {
			return nil, errors.New("subject is not a single CN")
		}
		if strings.Contains(cn, "*") {
			return nil, errors.New("wildcard CN rejected")
		}
		if cn != issuer {
			return nil, errors.New("subject CN does not equal the issuer URL")
		}
		if leafIssuer != leafSubject || !maaSafeVerify(leaf, leaf) {
			return nil, errors.New("not a genuine self-signed cert")
		}
		spki := maaSpkiOf(leaf)
		return &MaaAnchorRecord{Spki: spki, Kind: "self-signed", NotBeforeMs: lvFrom.ms, NotAfterMs: lvTo.ms}, nil
	}
	// Chained key: only under an explicitly pinned root (and, when configured, a pinned intermediate).
	if len(roots) == 0 {
		return nil, errors.New("chained key ignored (no chainRootSpkiSha256 configured)")
	}
	for j := 0; j < len(certs)-1; j++ {
		if !maaSafeVerify(certs[j], certs[j+1]) {
			return nil, fmt.Errorf("chain link %d is not signed by the next cert", j)
		}
	}
	if profile := strictChainError(certs); profile != "" {
		return nil, fmt.Errorf("chain profile: %s", profile)
	}
	top := certs[len(certs)-1]
	if nameText(top.RawIssuer) != nameText(top.RawSubject) || !maaSafeVerify(top, top) {
		return nil, errors.New("chain does not end in a self-signed root")
	}
	rootSpki := maaSpkiOf(top)
	if !roots[rootSpki] {
		return nil, errors.New("chain root is not pinned")
	}
	if policy.ChainLeafCn != nil {
		cn, ok := maaLeafCn(leafSubject)
		if !ok {
			cn = "\x00"
		}
		if !containsStr(policy.ChainLeafCn, cn) {
			return nil, errors.New("chained leaf CN not allowed")
		}
	}
	t2From, t2To := derValidity(top.Raw)
	if !t2From.ok || !t2To.ok {
		return nil, errors.New("chain root: unparsable validity")
	}
	anchorSpki, anchorKind, anchorFrom, anchorTo := rootSpki, "chained-root", t2From.ms, t2To.ms
	if len(inters) > 0 {
		// The pinned intermediate must sit strictly between leaf and root; it (not the shared root) becomes the anchor.
		var mid *attCert
		for _, c := range certs[1 : len(certs)-1] {
			if inters[maaSpkiOf(c)] {
				mid = c
				break
			}
		}
		if mid == nil {
			return nil, errors.New("chain does not pass through a pinned intermediate")
		}
		mf, mt := derValidity(mid.Raw)
		anchorSpki, anchorKind, anchorFrom, anchorTo = maaSpkiOf(mid), "chained-intermediate", mf.ms, mt.ms
	}
	rec := &MaaAnchorRecord{Spki: anchorSpki, Kind: anchorKind, NotBeforeMs: anchorFrom, NotAfterMs: anchorTo}
	if prev, ok := accepted[anchorSpki]; ok {
		rec.NotBeforeMs = minI64(prev.NotBeforeMs, anchorFrom)
		rec.NotAfterMs = minI64(anchorTo, maxI64(prev.NotAfterMs, lvTo.ms))
	} else {
		rec.NotAfterMs = minI64(anchorTo, maxI64(0, lvTo.ms))
	}
	return rec, nil
}

func minI64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ───────────────────────────── trust store ─────────────────────────────

// MaaRepin is an operator-signed re-pin: an allowlist manifest carrying maa-signing-spki entries labelled with the issuer URL.
// Verify are its verification options (issuer keys, minimum version, last seen ...); NowMs is supplied by GetTrustAnchors.
type MaaRepin struct {
	Manifest any
	Verify   VerifyAllowlistOptions
}

// MaaKeyTrustOptions configure NewMaaKeyTrust.
type MaaKeyTrustOptions struct {
	Policy MaaKeyPolicy
	Store  MaaKeyStateStore
	Fetch  MaaFetch
}

// MaaKeyTrust derives the trust anchors of a MAA issuer under the rotation policy.
type MaaKeyTrust struct {
	policy MaaKeyPolicy
	store  MaaKeyStateStore
	fetch  MaaFetch
}

func maaSafeInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		s := string(n)
		if strings.HasPrefix(s, "-") && strings.Trim(s, "-0.eE+") == "" {
			return 0, false // -0
		}
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return maaFloatSafe(f)
	case float64:
		if n == 0 && math.Signbit(n) {
			return 0, false
		}
		return maaFloatSafe(n)
	case int:
		return maaSafeI64(int64(n))
	case int64:
		return maaSafeI64(n)
	case string:
		// numbers as JS lexemes (ParseJSONLenient)
		_, err := json.Number(n).Float64()
		if err != nil || strings.TrimSpace(n) != n || n == "" {
			return 0, false
		}
		return maaSafeInt(json.Number(n))
	}
	return 0, false
}

func maaFloatSafe(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > float64(maaMaxSafeInt) {
		return 0, false
	}
	return int64(f), true
}

func maaSafeI64(n int64) (int64, bool) { return n, n >= -maaMaxSafeInt && n <= maaMaxSafeInt }

// parseMaaKeyState validates a stored value; nil when it is not a well-formed state for issuer.
func parseMaaKeyState(x any, issuer string) *MaaKeyState {
	if st, ok := x.(MaaKeyState); ok {
		x = maaStateAsAny(st)
	}
	s, ok := x.(map[string]any)
	if !ok {
		return nil
	}
	if v, ok := maaSafeInt(s["v"]); !ok || v != 1 {
		return nil
	}
	if iss, ok := s["issuer"].(string); !ok || iss != issuer {
		return nil
	}
	fetched, ok := maaSafeInt(s["fetchedAtMs"])
	if !ok {
		return nil
	}
	arr, ok := s["anchors"].([]any)
	if !ok {
		return nil
	}
	out := &MaaKeyState{V: 1, Issuer: issuer, FetchedAtMs: fetched, Anchors: []MaaAnchorRecord{}}
	for _, a := range arr {
		r, ok := a.(map[string]any)
		if !ok {
			return nil
		}
		spki, ok := r["spki"].(string)
		if !ok || !maaHex64.MatchString(spki) {
			return nil
		}
		kind, ok := r["kind"].(string)
		if !ok || (kind != "self-signed" && kind != "chained-root" && kind != "chained-intermediate") {
			return nil
		}
		nb, ok1 := maaSafeInt(r["notBeforeMs"])
		na, ok2 := maaSafeInt(r["notAfterMs"])
		fs, ok3 := maaSafeInt(r["firstSeenMs"])
		if !ok1 || !ok2 || !ok3 {
			return nil
		}
		out.Anchors = append(out.Anchors, MaaAnchorRecord{Spki: spki, Kind: kind, NotBeforeMs: nb, NotAfterMs: na, FirstSeenMs: fs})
	}
	return out
}

func maaStateAsAny(st MaaKeyState) map[string]any {
	anchors := make([]any, 0, len(st.Anchors))
	for _, a := range st.Anchors {
		anchors = append(anchors, map[string]any{"spki": a.Spki, "kind": a.Kind, "notBeforeMs": a.NotBeforeMs, "notAfterMs": a.NotAfterMs, "firstSeenMs": a.FirstSeenMs})
	}
	return map[string]any{"v": st.V, "issuer": st.Issuer, "fetchedAtMs": st.FetchedAtMs, "anchors": anchors}
}

// NewMaaKeyTrust builds the key trust. The policy is copied: later edits by the caller do not change what this trust enforces.
func NewMaaKeyTrust(o MaaKeyTrustOptions) (*MaaKeyTrust, error) {
	if o.Fetch == nil {
		return nil, errors.New("createMaaKeyTrust: fetch must be injected")
	}
	if o.Store == nil {
		return nil, errors.New("createMaaKeyTrust: a store is required")
	}
	p := o.Policy.clone()
	if len(p.TrustedIssuers) == 0 {
		return nil, errors.New("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs")
	}
	for _, i := range p.TrustedIssuers {
		if !maaIssuerURL.MatchString(i) {
			return nil, errors.New("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs")
		}
	}
	return &MaaKeyTrust{policy: p, store: o.Store, fetch: o.Fetch}, nil
}

type maaOrderedSet struct {
	list []string
	m    map[string]bool
}

func newMaaOrderedSet() *maaOrderedSet { return &maaOrderedSet{m: map[string]bool{}} }

func (s *maaOrderedSet) add(v string) {
	if !s.m[v] {
		s.m[v] = true
		s.list = append(s.list, v)
	}
}

func maaLive(a []MaaAnchorRecord, nowMs, skew int64) []MaaAnchorRecord {
	var out []MaaAnchorRecord
	for _, r := range a {
		if nowMs-skew <= r.NotAfterMs && nowMs+skew >= r.NotBeforeMs {
			out = append(out, r)
		}
	}
	return out
}

func maaFail(code MaaKeyErrorCode, reason string) MaaTrustResult {
	return MaaTrustResult{Code: code, Reason: reason}
}

func maaBuild(source string, anchors []MaaAnchorRecord, newKeys, removed []string, rejected []MaaRejectedKey) MaaTrustResult {
	seen := map[string]bool{}
	var spkis []string
	for _, a := range anchors {
		if !seen[a.Spki] {
			seen[a.Spki] = true
			spkis = append(spkis, a.Spki)
		}
	}
	if len(spkis) == 0 {
		return maaFail(MaaNoValidKeys, "no unexpired, un-revoked signing keys remain")
	}
	sort.Strings(spkis)
	return MaaTrustResult{Ok: true, RootSpkiSha256: spkis, Source: source, Anchors: anchors, NewKeys: newKeys, RemovedKeys: removed, Rejected: rejected}
}

// GetTrustAnchors returns the anchors a MAA verifier should trust for issuer at nowMs (an integer clock reading), consulting the
// store and, when its cache is stale, the issuer's /certs. repin (optional) approves or revokes keys.
func (t *MaaKeyTrust) GetTrustAnchors(issuer string, nowMs int64, repin *MaaRepin) (res MaaTrustResult) {
	defer func() {
		if r := recover(); r != nil {
			res = maaFail(MaaFetchFailed, fmt.Sprint(r))
		}
	}()
	res, err := t.getTrustAnchors(issuer, nowMs, repin)
	if err != nil {
		return maaFail(MaaFetchFailed, err.Error())
	}
	return res
}

func (t *MaaKeyTrust) getTrustAnchors(issuer string, nowMs int64, repin *MaaRepin) (MaaTrustResult, error) {
	policy := &t.policy
	trusted := false
	for _, i := range policy.TrustedIssuers {
		trusted = trusted || i == issuer
	}
	if !trusted {
		return maaFail(MaaUntrustedIssuer, "issuer is not in policy.trustedIssuers"), nil
	}
	if _, ok := maaSafeI64(nowMs); !ok {
		return maaFail(MaaClockRegression, "nowMs must be an integer"), nil
	}
	ttl, maxStale, maxNew, maxInitial, skew, requireOverlap := maaHour, maaDay, 2, 8, policy.skew(), true
	if policy.TtlMs != nil {
		ttl = *policy.TtlMs
	}
	if policy.MaxStaleMs != nil {
		maxStale = *policy.MaxStaleMs
	}
	if policy.MaxNewKeysPerFetch != nil {
		maxNew = *policy.MaxNewKeysPerFetch
	}
	if policy.MaxInitialKeys != nil {
		maxInitial = *policy.MaxInitialKeys
	}
	if policy.RequireOverlap != nil {
		requireOverlap = *policy.RequireOverlap
	}

	// Operator approvals / revocations (re-pin manifest).
	approved, denied := map[string]bool{}, map[string]bool{}
	if repin != nil {
		vo := repin.Verify
		vo.NowMs = nowMs
		v := VerifyAllowlistManifest(repin.Manifest, vo)
		if !v.OK {
			return maaFail(MaaRepinInvalid, v.Code+": "+v.Reason), nil
		}
		p, err := ProjectAllowlist(v, nowMs)
		if err != nil {
			return MaaTrustResult{}, err
		}
		for _, s := range p.MaaSigningSpkis[issuer] {
			approved[s] = true
		}
		for _, r := range p.Revoked {
			if r.Kind == "maa-signing-spki" && r.Label == issuer {
				denied[r.Value] = true
			}
		}
	}
	// Built-in release-signed pins (default on): the offline root of the first accepted set.
	eff := t.policy
	var builtinBaseline []string
	var builtinReason string
	hasBuiltinReason := false
	if !policy.DisableBuiltinPins {
		b, err := LoadBuiltinMaaPins(nowMs, policy.BuiltinPinsSource)
		if err == nil {
			builtinBaseline = append(builtinBaseline, b.MaaSigningSpkis[issuer]...)
			for _, r := range b.RevokedSigningSpkis[issuer] {
				denied[r] = true
			}
			if eff.ChainRootSpkiSha256 == nil {
				eff.ChainRootSpkiSha256 = b.MaaChainRootSpkis
			}
			if eff.ChainIntermediateSpkiSha256 == nil {
				eff.ChainIntermediateSpkiSha256 = b.MaaChainIntermediateSpkis
			}
			if eff.ChainLeafCn == nil {
				eff.ChainLeafCn = append([]string{}, BuiltinChainLeafCn...)
			}
			// The pinned Microsoft intermediate only counts for issuers the release actually pinned (no leak to others).
			if len(builtinBaseline) > 0 {
				builtinBaseline = append(builtinBaseline, b.MaaChainIntermediateSpkis...)
			}
		} else {
			builtinReason, hasBuiltinReason = err.Error(), true
		}
	}
	allow := func(a []MaaAnchorRecord) []MaaAnchorRecord {
		var out []MaaAnchorRecord
		for _, r := range a {
			if !denied[r.Spki] {
				out = append(out, r)
			}
		}
		return out
	}

	rawState, has, err := t.store.Get(issuer)
	if err != nil {
		return MaaTrustResult{}, err
	}
	var state *MaaKeyState
	if has {
		state = parseMaaKeyState(rawState, issuer)
		if state == nil {
			return maaFail(MaaCorruptState, "persisted MAA key state failed validation"), nil
		}
		if nowMs < state.FetchedAtMs-skew {
			return maaFail(MaaClockRegression, "clock is behind the last persisted fetch time"), nil
		}
	}

	// 1. Fresh cache.
	if state != nil && nowMs-state.FetchedAtMs < ttl && nowMs >= state.FetchedAtMs {
		if a := allow(maaLive(state.Anchors, nowMs, skew)); len(a) > 0 {
			return maaBuild("cache", a, nil, nil, nil), nil
		}
	}

	// 2. Refresh.
	fo := FetchMaaCertsOptions{Fetch: t.fetch}
	if policy.FetchTimeoutMs != nil {
		fo.TimeoutMs = *policy.FetchTimeoutMs
	}
	if policy.MaxBodyBytes != nil {
		fo.MaxBytes = *policy.MaxBodyBytes
	}
	jwks, ferr := FetchMaaCerts(issuer, fo)
	if ferr != nil {
		why := ferr.Error()
		if state == nil {
			return maaFail(MaaFetchFailed, why+"; no cached key set"), nil
		}
		if nowMs-state.FetchedAtMs > maxStale {
			return maaFail(MaaStaleExceeded, why+"; cached set is older than maxStaleMs"), nil
		}
		a := allow(maaLive(state.Anchors, nowMs, skew))
		if len(a) == 0 {
			return maaFail(MaaStaleExceeded, why+"; every cached key has expired or been revoked"), nil
		}
		return maaBuild("stale-cache", a, nil, nil, nil), nil
	}

	ev := EvaluateMaaJwks(jwks, issuer, &eff, nowMs)
	accepted := allow(ev.Accepted)
	if len(accepted) == 0 {
		var parts []string
		for _, r := range ev.Rejected {
			parts = append(parts, r.Kid+": "+r.Reason)
		}
		detail := strings.Join(parts, "; ")
		if detail == "" {
			detail = "empty JWKS"
		}
		return maaFail(MaaNoValidKeys, "no JWKS key passed validation ("+detail+")"), nil
	}

	// 3. Rotation policy.
	baseline := newMaaOrderedSet()
	if state != nil {
		for _, a := range maaLive(state.Anchors, nowMs, skew) {
			baseline.add(a.Spki)
		}
	} else {
		for _, p := range policy.InitialPins[issuer] {
			baseline.add(strings.ToLower(p))
		}
		for _, p := range builtinBaseline {
			baseline.add(p)
		}
	}
	for _, p := range builtinBaseline {
		approved[p] = true
	}
	acceptedSet := map[string]bool{}
	for _, a := range accepted {
		acceptedSet[a.Spki] = true
	}
	approvedHere, unapprovedNew, overlapBase := 0, 0, false
	for s := range acceptedSet {
		if approved[s] {
			approvedHere++
		}
		if !baseline.m[s] && !approved[s] {
			unapprovedNew++
		}
		if baseline.m[s] {
			overlapBase = true
		}
	}
	if len(baseline.list) == 0 {
		if approvedHere == 0 && !policy.AllowTrustOnFirstUse {
			if hasBuiltinReason {
				return maaFail(MaaBuiltinPinsInvalid, fmt.Sprintf("built-in pins unusable (%s); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use", builtinReason)), nil
			}
			return maaFail(MaaNoBaseline, "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use"), nil
		}
		if len(acceptedSet) > maxInitial && approvedHere < len(acceptedSet) {
			return maaFail(MaaTooManyNewKeys, fmt.Sprintf("initial set of %d keys exceeds maxInitialKeys", len(acceptedSet))), nil
		}
	} else {
		if unapprovedNew > maxNew {
			return maaFail(MaaTooManyNewKeys, fmt.Sprintf("%d new keys exceed maxNewKeysPerFetch=%d", unapprovedNew, maxNew)), nil
		}
		if requireOverlap && !(overlapBase || approvedHere > 0) {
			return maaFail(MaaNoOverlap, "the new key set shares no key with the previous set and is not covered by a signed re-pin"), nil
		}
	}

	// 4. Persist (monotone fetchedAtMs) and return.
	firstSeen := map[string]int64{}
	fetchedAt := nowMs
	if state != nil {
		for _, a := range state.Anchors {
			firstSeen[a.Spki] = a.FirstSeenMs
		}
		fetchedAt = maxI64(state.FetchedAtMs, nowMs)
	}
	records := make([]MaaAnchorRecord, len(accepted))
	for i, a := range accepted {
		a.FirstSeenMs = nowMs
		if fs, ok := firstSeen[a.Spki]; ok {
			a.FirstSeenMs = fs
		}
		records[i] = a
	}
	if err := t.store.Set(issuer, MaaKeyState{V: 1, Issuer: issuer, FetchedAtMs: fetchedAt, Anchors: records}); err != nil {
		return MaaTrustResult{}, err
	}
	var newKeys, removed []string
	for _, r := range records {
		if !baseline.m[r.Spki] {
			newKeys = append(newKeys, r.Spki)
		}
	}
	for _, s := range baseline.list {
		if !acceptedSet[s] {
			removed = append(removed, s)
		}
	}
	return maaBuild("fetched", records, newKeys, removed, ev.Rejected), nil
}

// ───────────────────────────── multi-vantage corroboration ─────────────────────────────

// MaaVantageObservation is one independent observation of `<issuer>/certs` from a named network vantage point. The label is counted
// once per distinct value.
type MaaVantageObservation struct {
	Vantage string
	Issuer  string
	Jwks    *MaaJwks
}

// MaaCorroborationResult is the outcome of CorroborateMaaKeySets. Code is malformed, insufficient-vantages, vantage-disagreement
// or no-valid-keys on failure.
type MaaCorroborationResult struct {
	Ok       bool
	Code     string
	Reason   string
	Issuer   string
	Spkis    []string
	Vantages []string
	K        int
}

// CorroborateMaaKeySets accepts a first-use key set only if at least k (>= 2) distinct vantage points observed the same issuer and
// every observation validates to the identical SPKI set. Independence of the vantages is the caller's claim. policy (optional)
// supplies the evaluation policy.
func CorroborateMaaKeySets(sets []MaaVantageObservation, k int, issuer string, nowMs int64, policy *MaaKeyPolicy) (res MaaCorroborationResult) {
	bad := func(code, reason string) MaaCorroborationResult {
		return MaaCorroborationResult{Code: code, Reason: reason}
	}
	defer func() {
		if r := recover(); r != nil {
			res = bad("malformed", fmt.Sprint(r))
		}
	}()
	if k < 2 {
		return bad("malformed", "k must be an integer >= 2")
	}
	if !maaIssuerURL.MatchString(issuer) {
		return bad("malformed", "issuer/nowMs invalid")
	}
	if _, ok := maaSafeI64(nowMs); !ok {
		return bad("malformed", "issuer/nowMs invalid")
	}
	pol := MaaKeyPolicy{TrustedIssuers: []string{issuer}}
	if policy != nil {
		pol = policy.clone()
	}
	byVantage := map[string]string{}
	var order []string
	for _, o := range sets {
		if o.Vantage == "" || utf16Len(o.Vantage) > 100 {
			return bad("malformed", "vantage label must be a non-empty string")
		}
		if o.Issuer != issuer {
			return bad("malformed", fmt.Sprintf("observation from '%s' is for a different issuer", o.Vantage))
		}
		ev := EvaluateMaaJwks(o.Jwks, issuer, &pol, nowMs)
		if len(ev.Accepted) == 0 {
			var rs []string
			for _, r := range ev.Rejected {
				rs = append(rs, r.Reason)
			}
			detail := strings.Join(rs, "; ")
			if detail == "" {
				detail = "empty"
			}
			return bad("no-valid-keys", fmt.Sprintf("vantage '%s' observed no valid key (%s)", o.Vantage, detail))
		}
		spkis := make([]string, len(ev.Accepted))
		for i, a := range ev.Accepted {
			spkis[i] = a.Spki
		}
		sort.Strings(spkis)
		fp := strings.Join(spkis, ",")
		if prior, seen := byVantage[o.Vantage]; seen {
			if prior != fp {
				return bad("vantage-disagreement", fmt.Sprintf("vantage '%s' supplied two different key sets", o.Vantage))
			}
		} else {
			order = append(order, o.Vantage)
		}
		byVantage[o.Vantage] = fp
	}
	if len(byVantage) < k {
		return bad("insufficient-vantages", fmt.Sprintf("%d distinct vantage(s) < k=%d", len(byVantage), k))
	}
	distinct := map[string]bool{}
	for _, f := range byVantage {
		distinct[f] = true
	}
	if len(distinct) != 1 {
		var parts []string
		for _, v := range order {
			var short []string
			for _, x := range strings.Split(byVantage[v], ",") {
				if len(x) > 8 {
					x = x[:8]
				}
				short = append(short, x)
			}
			parts = append(parts, v+"="+strings.Join(short, "+"))
		}
		return bad("vantage-disagreement", "vantages disagree: "+strings.Join(parts, " | "))
	}
	vantages := append([]string(nil), order...)
	sort.Strings(vantages)
	return MaaCorroborationResult{Ok: true, Issuer: issuer, Spkis: strings.Split(byVantage[order[0]], ","), Vantages: vantages, K: k}
}
