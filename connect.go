package pca

// An OUTBOUND connection/token vault for PCA agents: it holds an agent's third-party OAuth tokens and refreshes them, releasing a
// fresh, least-privilege access token only when a verified Proof-Carrying Action proves authority over the provider and scopes.
// Covers `oauth_scope` caveats, token refresh, the proxy-mode request extractor, signed release receipts, the
// envelope-encrypted store (AES-256-GCM) and the TokenVault. Injected transports are plain funcs. Not safe for concurrent use
// without a store that locks.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// ---- the oauth_scope caveat ----------------------------------------------------------------------------------------------------

// OAuthScopeCaveatType is the caveat `type` the vault reads.
const OAuthScopeCaveatType = "oauth_scope"

func connDedup(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func connStrList(v any) ([]string, bool) {
	switch l := v.(type) {
	case []string:
		return append([]string{}, l...), true
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func connAnyList(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// OAuthScopeCaveat is an `oauth_scope` caveat granting scopes on provider; duplicate scopes are collapsed.
func OAuthScopeCaveat(provider string, scopes []string) map[string]any {
	return map[string]any{"type": OAuthScopeCaveatType, "provider": provider, "scopes": connAnyList(connDedup(scopes))}
}

// IsOAuthScopeCaveat reports whether cv is a well-formed `oauth_scope` caveat.
func IsOAuthScopeCaveat(cv any) bool {
	m, ok := cv.(map[string]any)
	if !ok {
		return false
	}
	t, hasT := m["type"]
	_, hasP := m["provider"]
	sc, hasS := m["scopes"]
	if !hasT || !hasP || !hasS {
		return false
	}
	_, provOK := m["provider"].(string)
	l, isList := sc.([]any)
	if !isList || !provOK || t != OAuthScopeCaveatType {
		return false
	}
	for _, x := range l {
		if _, ok := x.(string); !ok {
			return false
		}
	}
	return true
}

// GrantedOAuthScopes is the INTERSECTION of every `oauth_scope` caveat naming provider in the chain's leaf; granted is false when
// the chain grants nothing for it (so the vault can tell "not covered" from "covered but too narrow"). Run the chain verifier
// first. A null leaf is an error (the reference throws).
func GrantedOAuthScopes(chain any, provider string) (scopes []string, granted bool, err error) {
	l, ok := chain.([]any)
	if !ok || len(l) == 0 {
		return nil, false, nil
	}
	if l[len(l)-1] == nil {
		return nil, false, errors.New("Cannot read properties of null")
	}
	leaf, ok := l[len(l)-1].(map[string]any)
	if !ok {
		return nil, false, nil
	}
	cavs, ok := leaf["caveats"].([]any)
	if !ok {
		return nil, false, nil
	}
	var eff []string
	have := false
	for _, cv := range cavs {
		if !IsOAuthScopeCaveat(cv) || cv.(map[string]any)["provider"] != provider {
			continue
		}
		here, _ := connStrList(cv.(map[string]any)["scopes"])
		hs := map[string]bool{}
		for _, s := range here {
			hs[s] = true
		}
		if !have {
			eff, have = connDedup(here), true
			continue
		}
		next := []string{}
		for _, s := range eff {
			if hs[s] {
				next = append(next, s)
			}
		}
		eff = next
	}
	if !have {
		return nil, false, nil
	}
	return eff, true, nil
}

// ---- errors --------------------------------------------------------------------------------------------------------------------

// VaultError is every typed refusal of the vault; branch on Code.
type VaultError struct {
	Name, Code, Message string
	Status              *float64 // RefreshFailed: the provider's HTTP status
	Missing             []string // ScopeExceeded
	Checks              map[string]bool
}

func (e *VaultError) Error() string { return e.Message }

// Unwrap exposes the code to errors.As(*CodedError).
func (e *VaultError) Unwrap() error { return &CodedError{Code: e.Code, Msg: e.Message} }

func vaultErr(name, code, msg string) *VaultError {
	return &VaultError{Name: name, Code: code, Message: msg}
}

func newNotAuthorized(msg string, checks map[string]bool) *VaultError {
	e := vaultErr("NotAuthorizedError", "not_authorized", msg)
	e.Checks = checks
	return e
}

func newScopeExceeded(provider string, missing []string) *VaultError {
	e := vaultErr("ScopeExceededError", "scope_exceeded",
		fmt.Sprintf("requested scopes exceed the capability's grant for '%s': not granted [%s]", provider, strings.Join(missing, ", ")))
	e.Missing = append([]string{}, missing...)
	return e
}

func newRefreshFailed(provider, detail string, status *float64) *VaultError {
	e := vaultErr("RefreshFailedError", "refresh_failed", fmt.Sprintf("refresh for '%s' failed: %s", provider, detail))
	e.Status = status
	return e
}

func newStoreError(msg string) *VaultError { return vaultErr("StoreError", "store_error", msg) }

func connMismatch(m string) error {
	return vaultErr("RequestMismatchError", "request_mismatch", "outbound request refused: "+m)
}

func newUnknownAction(verb string) *VaultError {
	return vaultErr("UnknownActionError", "unknown_action", fmt.Sprintf("no pinned action definition for verb '%s': refusing to release a credential", verb))
}

// ---- stored connections --------------------------------------------------------------------------------------------------------

// ConnectionAuthority binds which capability may use a connection.
type ConnectionAuthority struct {
	Provider  string   `json:"provider"`
	Principal string   `json:"principal"`
	Scopes    []string `json:"scopes"`
	Audience  *string  `json:"audience,omitempty"`
}

// Connection is one stored third-party connection of an agent.
type Connection struct {
	AgentID      string              `json:"agentId"`
	Provider     string              `json:"provider"`
	ConnectionID string              `json:"connectionId"`
	AccessToken  string              `json:"accessToken"`
	RefreshToken *string             `json:"refreshToken,omitempty"`
	ExpiresAt    float64             `json:"expiresAt"`
	Scopes       []string            `json:"scopes"`
	Authority    ConnectionAuthority `json:"authority"`
	CreatedAt    float64             `json:"createdAt"`
	LastUsedAt   *float64            `json:"lastUsedAt,omitempty"`
	UseCount     float64             `json:"useCount"`
}

// ConnectionKey identifies a connection.
type ConnectionKey struct{ AgentID, Provider, ConnectionID string }

// ConnectionStore holds connections; Get returns (nil, nil) when absent.
type ConnectionStore interface {
	Get(key ConnectionKey) (*Connection, error)
	Set(c *Connection) error
	Delete(key ConnectionKey) error
}

// CloneConnection is a deep copy (callers cannot mutate vault state through it).
func CloneConnection(c *Connection) *Connection {
	o := *c
	o.Scopes = append([]string{}, c.Scopes...)
	o.Authority.Scopes = append([]string{}, c.Authority.Scopes...)
	if c.RefreshToken != nil {
		s := *c.RefreshToken
		o.RefreshToken = &s
	}
	if c.LastUsedAt != nil {
		f := *c.LastUsedAt
		o.LastUsedAt = &f
	}
	if c.Authority.Audience != nil {
		s := *c.Authority.Audience
		o.Authority.Audience = &s
	}
	return &o
}

func connKeyString(k ConnectionKey) string {
	return k.AgentID + "\x00" + k.Provider + "\x00" + k.ConnectionID
}

// InMemoryConnectionStore is a process-local store; records are cloned in and out.
type InMemoryConnectionStore struct{ m map[string]*Connection }

// NewInMemoryConnectionStore returns an empty store.
func NewInMemoryConnectionStore() *InMemoryConnectionStore {
	return &InMemoryConnectionStore{m: map[string]*Connection{}}
}

// Get returns a clone of the record, or nil.
func (s *InMemoryConnectionStore) Get(k ConnectionKey) (*Connection, error) {
	if c := s.m[connKeyString(k)]; c != nil {
		return CloneConnection(c), nil
	}
	return nil, nil
}

// Set stores a clone.
func (s *InMemoryConnectionStore) Set(c *Connection) error {
	s.m[connKeyString(ConnectionKey{c.AgentID, c.Provider, c.ConnectionID})] = CloneConnection(c)
	return nil
}

// Delete removes the record.
func (s *InMemoryConnectionStore) Delete(k ConnectionKey) error {
	delete(s.m, connKeyString(k))
	return nil
}

// ---- the proxy-mode request extractor -------------------------------------------------------------------------------------------

var (
	connSpecialSchemes = map[string]bool{"ftp": true, "http": true, "https": true, "ws": true, "wss": true}
	connPlaceholder    = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)
)

func connPctEncode(s, extra string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7E || strings.IndexByte(extra, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func connHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// connPctDecodeBytes decodes valid %XX escapes and leaves a malformed one literal.
func connPctDecodeBytes(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && connHexVal(s[i+1]) >= 0 && connHexVal(s[i+2]) >= 0 {
			out = append(out, byte(connHexVal(s[i+1])<<4|connHexVal(s[i+2])))
			i += 2
		} else {
			out = append(out, s[i])
		}
	}
	return out
}

// connPctDecodeLoose is the form-urlencoded component decode: '+' is a space and invalid UTF-8 becomes U+FFFD.
// shortcut: one U+FFFD per invalid byte (the WHATWG decoder emits one per maximal subpart); matters only to a hostile truncated sequence, which then fails to equal a pinned value.
func connPctDecodeLoose(s string) string {
	b := connPctDecodeBytes(strings.ReplaceAll(s, "+", " "))
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n <= 1 {
			sb.WriteRune(utf8.RuneError)
			n = 1
		} else {
			sb.WriteRune(r)
		}
		b = b[n:]
	}
	return sb.String()
}

type connPair struct{ k, v string }

func connFormPairs(s string) []connPair {
	var out []connPair
	for _, seq := range strings.Split(s, "&") {
		if seq == "" {
			continue
		}
		k, v, _ := strings.Cut(seq, "=")
		out = append(out, connPair{connPctDecodeLoose(k), connPctDecodeLoose(v)})
	}
	return out
}

func connDecodeURIComponent(s string) (string, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) || connHexVal(s[i+1]) < 0 || connHexVal(s[i+2]) < 0 {
			return "", errors.New("URI malformed")
		}
		out = append(out, byte(connHexVal(s[i+1])<<4|connHexVal(s[i+2])))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", errors.New("URI malformed")
	}
	return string(out), nil
}

// connURL is the part of the WHATWG URL parse the extractor reads, for special schemes.
type connURL struct {
	scheme, origin, pathname, hash, search, query string
	username, password                            string
}

func connParseURL(text string) (connURL, error) {
	p, err := whatwgParse(text)
	if err != nil || !connSpecialSchemes[p.scheme] {
		return connURL{}, errInvalidURL
	}
	s := strings.TrimFunc(text, func(r rune) bool { return r <= 0x20 })
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)
	rest := strings.TrimLeft(s[strings.IndexByte(s, ':')+1:], `/\`)
	end := strings.IndexAny(rest, `/\?#`)
	if end < 0 {
		end = len(rest)
	}
	auth := rest[:end]
	u := connURL{scheme: p.scheme, pathname: p.pathname, origin: p.scheme + "://" + p.host}
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		u.username, u.password, _ = strings.Cut(auth[:i], ":")
	}
	rest = rest[end:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		if frag := rest[i+1:]; frag != "" {
			u.hash = "#" + connPctEncode(frag, "\"<>`")
		}
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		u.query = connPctEncode(rest[i+1:], "\"#<>'")
		if u.query != "" {
			u.search = "?" + u.query
		}
	}
	return u, nil
}

// connEntries is Object.entries of a JSON value, in JS key order.
func connEntries(v any) ([][2]any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make([][2]any, 0, len(t))
		for _, k := range jsKeys(t) {
			out = append(out, [2]any{k, t[k]})
		}
		return out, nil
	case []any:
		out := make([][2]any, len(t))
		for i, x := range t {
			out[i] = [2]any{strconv.Itoa(i), x}
		}
		return out, nil
	case string:
		var out [][2]any
		i := 0
		for _, r := range t {
			out = append(out, [2]any{strconv.Itoa(i), string(r)})
			i++
		}
		return out, nil
	case nil:
		return nil, errors.New("Cannot convert undefined or null to object")
	}
	return nil, nil
}

func connJSTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
			return true
		}
		return r >= 0x2000 && r <= 0x200A
	})
}

// HttpExtractor builds the extractor of one operation: it maps an outbound request back to the action's parameters and refuses
// anything the pinned spec does not carry (an extra query key, body member, header or redirect target). spec is
// {method, url, query?, body? ("json"|"form"), fixed?}; a malformed spec is an error here (the reference throws a TypeError).
func HttpExtractor(spec map[string]any) (func(req map[string]any) (map[string]any, error), error) {
	specURL, ok1 := spec["url"].(string)
	method, ok2 := spec["method"].(string)
	if !ok1 || !ok2 {
		return nil, errors.New("httpExtractor: url and method must be strings")
	}
	u, err := connParseURL(connPlaceholder.ReplaceAllString(specURL, "x"))
	if err != nil {
		return nil, errors.New("Invalid URL")
	}
	if u.scheme != "https" || u.search != "" || u.hash != "" || u.username != "" || u.password != "" {
		return nil, errors.New("httpExtractor: url must be https without query, fragment or userinfo")
	}
	if method != strings.ToUpper(method) {
		return nil, errors.New("httpExtractor: method must be upper case")
	}
	units := utf16.Encode([]rune(specURL))
	cut := len(u.origin)
	if cut > len(units) {
		cut = len(units)
	}
	template := string(utf16.Decode(units[cut:]))
	var names []string
	var pat strings.Builder
	pat.WriteString("^(?:")
	last := 0
	for _, loc := range connPlaceholder.FindAllStringSubmatchIndex(template, -1) {
		pat.WriteString(regexp.QuoteMeta(template[last:loc[0]]))
		names = append(names, template[loc[2]:loc[3]])
		pat.WriteString("([A-Za-z0-9._~%-]+)")
		last = loc[1]
	}
	pat.WriteString(regexp.QuoteMeta(template[last:]))
	pat.WriteString(")$")
	rx, err := regexp.Compile(pat.String())
	if err != nil {
		return nil, err
	}
	allowedQuery := map[string]bool{}
	if q, ok := spec["query"].([]any); ok {
		for _, x := range q {
			if s, ok := x.(string); ok {
				allowedQuery[s] = true
			}
		}
	}
	bodyKind, hasBody := spec["body"].(string)
	ctype := ""
	switch bodyKind {
	case "json":
		ctype = "application/json"
	case "form":
		ctype = "application/x-www-form-urlencoded"
	}
	fixedSpec, _ := spec["fixed"].(map[string]any)

	return func(req map[string]any) (map[string]any, error) {
		if m, isStr := req["method"].(string); !isStr || m != method {
			return nil, connMismatch(fmt.Sprintf("method %s is not %s", jsMemberString(req, "method"), method))
		}
		r, err := connParseURL(wtfToUTF8(jsMemberString(req, "url"))) // the URL parser encodes a lone surrogate as U+FFFD
		if _, isStr := req["url"].(string); !isStr || err != nil {
			return nil, connMismatch("the url does not parse")
		}
		if r.origin != u.origin || r.username != "" || r.password != "" || r.hash != "" {
			return nil, connMismatch("the url is not on the pinned origin")
		}
		m := rx.FindStringSubmatch(r.pathname)
		if m == nil {
			return nil, connMismatch("the path does not match the pinned template")
		}
		params := map[string]any{}
		put := func(k string, v any) error {
			if _, dup := params[k]; dup {
				return connMismatch(fmt.Sprintf("parameter '%s' is carried twice", k))
			}
			params[k] = v
			return nil
		}
		for i, n := range names {
			v, err := connDecodeURIComponent(m[i+1])
			if err != nil {
				return nil, connMismatch("a path segment is not valid percent-encoding")
			}
			if err := put(n, v); err != nil {
				return nil, err
			}
		}
		seen := map[string]bool{}
		for _, kv := range connFormPairs(r.query) {
			if !allowedQuery[kv.k] {
				return nil, connMismatch(fmt.Sprintf("query key '%s' is not allowed", kv.k))
			}
			if seen[kv.k] {
				return nil, connMismatch(fmt.Sprintf("query key '%s' is repeated", kv.k))
			}
			seen[kv.k] = true
			if err := put(kv.k, kv.v); err != nil {
				return nil, err
			}
		}
		var ct any
		hasCT := false
		if hv, present := req["headers"]; present && hv != nil {
			ents, err := connEntries(hv)
			if err != nil {
				return nil, err
			}
			for _, e := range ents {
				if strings.ToLower(e[0].(string)) == "content-type" {
					ct, hasCT = e[1], true
					break
				}
			}
		}
		body, hasBodyMember := req["body"]
		if !hasBody {
			if hasBodyMember && body != "" {
				return nil, connMismatch("this operation carries no body")
			}
			return params, nil
		}
		bs, isStr := body.(string)
		if !isStr || len(bs) == 0 {
			return nil, connMismatch("the body is missing")
		}
		cts, ctStr := ct.(string)
		if !hasCT || !ctStr || strings.ToLower(connJSTrim(strings.SplitN(cts, ";", 2)[0])) != ctype {
			return nil, connMismatch("content-type must be " + ctype)
		}
		fixed := map[string]any{}
		for k, v := range fixedSpec {
			fixed[k] = v
		}
		if bodyKind == "json" {
			parsed, err := StrictParse(bs)
			if err != nil {
				return nil, connMismatch("the body is not strict JSON")
			}
			obj, ok := parsed.(map[string]any)
			if !ok {
				return nil, connMismatch("the body must be a JSON object")
			}
			for _, k := range jsKeys(obj) {
				v := obj[k]
				if fv, isFixed := fixed[k]; isFixed {
					a, e1 := HashCanonical(v)
					b, e2 := HashCanonical(fv)
					if e1 != nil || e2 != nil || a != b {
						return nil, connMismatch(fmt.Sprintf("fixed member '%s' has another value", k))
					}
					delete(fixed, k)
				} else if err := put(k, v); err != nil {
					return nil, err
				}
			}
		} else {
			keys := map[string]bool{}
			form := strings.TrimPrefix(bs, "?")
			for _, kv := range connFormPairs(form) {
				if keys[kv.k] {
					return nil, connMismatch(fmt.Sprintf("form key '%s' is repeated", kv.k))
				}
				keys[kv.k] = true
				if fv, isFixed := fixed[kv.k]; isFixed {
					if fs, ok := fv.(string); !ok || fs != kv.v {
						return nil, connMismatch(fmt.Sprintf("fixed member '%s' has another value", kv.k))
					}
					delete(fixed, kv.k)
				} else if err := put(kv.k, kv.v); err != nil {
					return nil, err
				}
			}
		}
		if len(fixed) > 0 {
			var left []string
			for _, k := range jsKeys(fixedSpec) {
				if _, ok := fixed[k]; ok {
					left = append(left, k)
				}
			}
			return nil, connMismatch(fmt.Sprintf("fixed member(s) %s missing", strings.Join(left, ", ")))
		}
		return params, nil
	}, nil
}

// DefaultProxyHeaders are the request headers an agent may set in proxy mode.
var DefaultProxyHeaders = []string{"content-type", "accept", "idempotency-key"}

// CheckProxyHeaders returns the lower-cased headers the agent may set (the vault sets Authorization itself); anything else, a
// repeat, or a value with CR / LF / NUL is refused. headers is nil or a JSON object.
func CheckProxyHeaders(headers any, allow []string) (map[string]string, error) {
	out := map[string]string{}
	if headers == nil {
		return out, nil
	}
	ents, err := connEntries(headers)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		k := e[0].(string)
		n := strings.ToLower(k)
		okAllowed := false
		for _, a := range allow {
			okAllowed = okAllowed || a == n
		}
		if !okAllowed {
			return nil, connMismatch(fmt.Sprintf("header '%s' is not allowed", k))
		}
		if _, dup := out[n]; dup {
			return nil, connMismatch(fmt.Sprintf("header '%s' is repeated", k))
		}
		v, ok := e[1].(string)
		if !ok || strings.ContainsAny(v, "\r\n\x00") {
			return nil, connMismatch(fmt.Sprintf("header '%s' has an invalid value", k))
		}
		out[n] = v
	}
	return out, nil
}

// ---- release receipts ------------------------------------------------------------------------------------------------------------

// ReleaseReceiptDomain is the signing domain of a release receipt.
const ReleaseReceiptDomain = "atlas-pca/connect-release-receipt/v1\x00"

// OutboundRequestDigest binds a proxied request (method, url, the headers the agent set, body or null).
func OutboundRequestDigest(method, url string, headers map[string]string, body *string) (string, error) {
	h := map[string]any{}
	for k, v := range headers {
		h[k] = v
	}
	var b any
	if body != nil {
		b = *body
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/connect-request/v1", "method": method, "url": url, "headers": h, "body": b})
}

// SignReleaseReceipt is the receipt body plus an Ed25519 signature of the vault key (a 32-byte seed) over domain || canonical(body).
func SignReleaseReceipt(body map[string]any, seed []byte) (map[string]any, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return SignArtifact(ReleaseReceiptDomain, body, kp, nil)
}

// VerifyReleaseReceipt is true iff the receipt is signed by the pinned vault key.
func VerifyReleaseReceipt(r any, vaultPK any) bool {
	m, ok := r.(map[string]any)
	return ok && verifyArtifactSig(ReleaseReceiptDomain, m, vaultPK, nil)
}

// ReceiptActionDigest is the digest the receipt carries for the action it served.
func ReceiptActionDigest(p map[string]any) (string, error) { return EscalationActionDigest(p) }

// ---- token refresh -------------------------------------------------------------------------------------------------------------

// ProviderConfig is a provider's token-endpoint configuration.
type ProviderConfig struct {
	TokenEndpoint, ClientID string
	ClientSecret            *string
	ExtraParams             [][2]string // in order
	SupportsScopeNarrowing  bool
}

// ConnectResponse is a transport response: JSON/Text may fail (an unparseable or unreadable body).
type ConnectResponse struct {
	OK     bool
	Status float64
	JSON   func() (any, error)
	Text   func() (string, error)
}

// ConnectFetch is the injected transport for the token endpoint.
type ConnectFetch func(url string, init map[string]any) (*ConnectResponse, error)

// RefreshResult is the fields to apply to a refreshed connection.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    float64
	Scopes       []string
}

func connEncodeComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func connRedact(text string, secrets []string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[redacted]")
		}
	}
	return text
}

func connIsJSWS(r rune) bool { return connJSTrim(string(r)) == "" }

type connTokenResponse struct {
	accessToken, refreshToken string
	hasExpires                bool
	expiresInSecs             float64
	scopes                    []string
	hasScopes                 bool
}

func connParseTokenResponse(body any, provider string) (*connTokenResponse, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, newRefreshFailed(provider, "token endpoint returned a non-object body", nil)
	}
	at, _ := m["access_token"].(string)
	if at == "" {
		return nil, newRefreshFailed(provider, "token endpoint response has no access_token", nil)
	}
	out := &connTokenResponse{accessToken: at}
	if ex, ok := jsNum(m["expires_in"]); ok && !math.IsNaN(ex) && !math.IsInf(ex, 0) && ex > 0 {
		out.hasExpires, out.expiresInSecs = true, ex
	}
	if rt, _ := m["refresh_token"].(string); rt != "" {
		out.refreshToken = rt
	}
	if sc, ok := m["scope"].(string); ok {
		if t := connJSTrim(sc); t != "" {
			out.hasScopes = true
			out.scopes = strings.FieldsFunc(t, connIsJSWS)
		}
	}
	return out, nil
}

func connJWTExpiryMs(token string) (float64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, false
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		return 0, false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return 0, false
	}
	exp, ok := obj["exp"]
	if !ok {
		return 0, false
	}
	f, ok := jsNum(exp)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f * 1000, true
}

// connU16Prefix is the first n UTF-16 units of s.
// shortcut: a cut inside a surrogate pair drops the half pair (Go strings cannot hold a lone surrogate); only error detail text is affected.
func connU16Prefix(s string, n int) string {
	u := utf16.Encode([]rune(s))
	if len(u) <= n {
		return s
	}
	u = u[:n]
	if len(u) > 0 && u[len(u)-1] >= 0xD800 && u[len(u)-1] <= 0xDBFF {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

// RefreshConnection refreshes connection's access token at its provider's token endpoint. It returns the fields to apply to the
// connection; any transport or parse failure is a RefreshFailed error, and no secret reaches an error.
func RefreshConnection(connection *Connection, config *ProviderConfig, refreshToken string, requested []string, fetch ConnectFetch, now, defaultTokenLifetimeMs float64) (*RefreshResult, error) {
	provider := connection.Provider
	secrets := []string{refreshToken, connection.AccessToken}
	if config != nil {
		if config.ClientSecret != nil {
			secrets = append(secrets, *config.ClientSecret)
		}
		for _, kv := range config.ExtraParams {
			secrets = append(secrets, kv[1])
		}
	}
	if config == nil {
		return nil, newRefreshFailed(provider, "no provider token-endpoint config", nil)
	}
	if fetch == nil {
		return nil, newRefreshFailed(provider, "no fetch transport configured", nil)
	}
	params := [][2]string{{"grant_type", "refresh_token"}, {"refresh_token", refreshToken}, {"client_id", config.ClientID}}
	set := func(k, v string) {
		for i := range params {
			if params[i][0] == k {
				params[i][1] = v
				return
			}
		}
		params = append(params, [2]string{k, v})
	}
	if config.ClientSecret != nil {
		set("client_secret", *config.ClientSecret)
	}
	for _, kv := range config.ExtraParams {
		set(kv[0], kv[1])
	}
	narrowing := config.SupportsScopeNarrowing
	if narrowing && len(requested) > 0 {
		set("scope", strings.Join(requested, " "))
	}
	pairs := make([]string, len(params))
	for i, kv := range params {
		pairs[i] = connEncodeComponent(kv[0]) + "=" + connEncodeComponent(kv[1])
	}
	res, err := fetch(config.TokenEndpoint, map[string]any{
		"method":  "POST",
		"headers": map[string]any{"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
		"body":    strings.Join(pairs, "&"),
	})
	if err != nil {
		return nil, newRefreshFailed(provider, "transport error: "+connRedact(err.Error(), secrets), nil)
	}
	if !res.OK {
		detail := "<unreadable body>"
		if txt, terr := res.Text(); terr == nil {
			detail = connRedact(connU16Prefix(txt, 256), secrets)
		}
		st := res.Status
		return nil, newRefreshFailed(provider, fmt.Sprintf("token endpoint %s: %s", jsNumberString(st), detail), &st)
	}
	j, err := res.JSON()
	if err != nil {
		return nil, newRefreshFailed(provider, "unparseable JSON body", nil)
	}
	parsed, err := connParseTokenResponse(j, provider)
	if err != nil {
		return nil, err
	}
	var expiresAt float64
	if parsed.hasExpires {
		expiresAt = now + parsed.expiresInSecs*1000
	} else if jwt, ok := connJWTExpiryMs(parsed.accessToken); ok {
		expiresAt = jwt
	} else {
		expiresAt = now + defaultTokenLifetimeMs
	}
	var scopes []string
	switch {
	case parsed.hasScopes:
		scopes = parsed.scopes
	case narrowing && len(requested) > 0:
		scopes = append([]string{}, requested...)
	default:
		scopes = append([]string{}, connection.Scopes...)
	}
	rt := refreshToken
	if parsed.refreshToken != "" {
		rt = parsed.refreshToken
	}
	return &RefreshResult{AccessToken: parsed.accessToken, RefreshToken: rt, ExpiresAt: expiresAt, Scopes: scopes}, nil
}

// ---- envelope encryption of stored tokens ------------------------------------------------------------------------------------------

const connEnvelopePrefix = "pca1"

func connSeal(key, aad, plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, g.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return g.Seal(iv, iv, plain, aad), nil // iv || ciphertext || 16-byte tag
}

func connOpen(key, aad, sealed []byte) ([]byte, error) {
	if len(sealed) < 12+16 {
		return nil, errors.New("short ciphertext")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, sealed[:12], sealed[12:], aad)
}

// KeyWrapper wraps and unwraps a data key (production keys belong behind a KMS implementing this).
type KeyWrapper interface {
	Wrap(dek, aad []byte) (keyID string, wrapped []byte, err error)
	Unwrap(keyID string, wrapped, aad []byte) ([]byte, error)
}

// LocalKeyWrapper is a key ring held in process memory.
type LocalKeyWrapper struct {
	keys   map[string][]byte
	active string
}

// NewLocalKeyWrapper builds a ring from 32-byte keys; activeID must be in it.
func NewLocalKeyWrapper(keys map[string][]byte, activeID string) (*LocalKeyWrapper, error) {
	w := &LocalKeyWrapper{keys: map[string][]byte{}}
	for id, k := range keys {
		if err := w.AddKey(id, k); err != nil {
			return nil, err
		}
	}
	if _, ok := w.keys[activeID]; !ok {
		return nil, errors.New("LocalKeyWrapper: the active key id is not in the key ring")
	}
	w.active = activeID
	return w, nil
}

// AddKey adds (or replaces) a ring key.
func (w *LocalKeyWrapper) AddKey(id string, key []byte) error {
	if id == "" {
		return errors.New("LocalKeyWrapper: key id must not be empty")
	}
	if len(key) != 32 {
		return errors.New("LocalKeyWrapper: keys must be 32 bytes")
	}
	w.keys[id] = append([]byte{}, key...)
	return nil
}

// SetActive picks the key new records are wrapped under.
func (w *LocalKeyWrapper) SetActive(id string) error {
	if _, ok := w.keys[id]; !ok {
		return errors.New("LocalKeyWrapper: the active key id is not in the key ring")
	}
	w.active = id
	return nil
}

// RemoveKey drops a non-active ring key.
func (w *LocalKeyWrapper) RemoveKey(id string) error {
	if id == w.active {
		return errors.New("LocalKeyWrapper: cannot remove the active key")
	}
	delete(w.keys, id)
	return nil
}

// Destroy zeroes and forgets every key.
func (w *LocalKeyWrapper) Destroy() {
	for _, k := range w.keys {
		clear(k)
	}
	w.keys = map[string][]byte{}
}

// Wrap seals dek under the active key.
func (w *LocalKeyWrapper) Wrap(dek, aad []byte) (string, []byte, error) {
	k, ok := w.keys[w.active]
	if !ok {
		return "", nil, errors.New("no active key")
	}
	s, err := connSeal(k, aad, dek)
	return w.active, s, err
}

// Unwrap opens a wrapped data key.
func (w *LocalKeyWrapper) Unwrap(keyID string, wrapped, aad []byte) ([]byte, error) {
	k, ok := w.keys[keyID]
	if !ok {
		return nil, errors.New("unknown key id")
	}
	return connOpen(k, aad, wrapped)
}

func connAAD(k ConnectionKey, field string) []byte {
	var parts = []string{"pca-connect/v1", field, k.AgentID, k.Provider, k.ConnectionID}
	enc := make([]string, len(parts))
	for i, p := range parts {
		enc[i] = fmt.Sprintf("%d:%s", len(p), wellFormedUTF8(p))
	}
	return []byte(strings.Join(enc, "|"))
}

func connEncryptField(w KeyWrapper, k ConnectionKey, field, plain string) (string, error) {
	aad := connAAD(k, field)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	id, wrapped, err := w.Wrap(dek, aad)
	if err != nil {
		return "", err
	}
	sealed, err := connSeal(dek, aad, []byte(wellFormedUTF8(plain)))
	if err != nil {
		return "", err
	}
	return strings.Join([]string{connEnvelopePrefix, b64.EncodeToString([]byte(wellFormedUTF8(id))), b64.EncodeToString(wrapped), b64.EncodeToString(sealed)}, "."), nil
}

var connB64Chars = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

func connUnb64u(s string) ([]byte, error) {
	if !connB64Chars.MatchString(s) {
		return nil, errors.New("bad encoding")
	}
	return b64.DecodeString(s)
}

func connDecryptField(w KeyWrapper, k ConnectionKey, field, value string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != connEnvelopePrefix {
		return "", errors.New("not an envelope")
	}
	aad := connAAD(k, field)
	id, err := connUnb64u(parts[1])
	if err != nil || !utf8.Valid(id) {
		return "", errors.New("bad key id")
	}
	wrapped, err := connUnb64u(parts[2])
	if err != nil {
		return "", err
	}
	sealed, err := connUnb64u(parts[3])
	if err != nil {
		return "", err
	}
	dek, err := w.Unwrap(string(id), wrapped, aad)
	if err != nil {
		return "", err
	}
	plain, err := connOpen(dek, aad, sealed)
	if err != nil || !utf8.Valid(plain) {
		return "", errors.New("decrypt failed")
	}
	return string(plain), nil
}

// EncryptedConnectionStore wraps a store so accessToken and refreshToken are encrypted before they reach it. It fails closed: a
// stored token that is not an envelope, fails authentication, or was sealed under an unknown key makes Get return a StoreError
// (no detail).
type EncryptedConnectionStore struct {
	inner   ConnectionStore
	wrapper KeyWrapper
}

// NewEncryptedConnectionStore wraps inner.
func NewEncryptedConnectionStore(inner ConnectionStore, w KeyWrapper) *EncryptedConnectionStore {
	return &EncryptedConnectionStore{inner: inner, wrapper: w}
}

// Encrypted marks the store as encrypting (TokenVault strict mode requires it).
func (s *EncryptedConnectionStore) Encrypted() bool { return true }

// Get decrypts a stored record.
func (s *EncryptedConnectionStore) Get(key ConnectionKey) (*Connection, error) {
	raw, err := s.inner.Get(key)
	if err != nil || raw == nil {
		return nil, err
	}
	bad := newStoreError("a stored token could not be decrypted")
	k := ConnectionKey{raw.AgentID, raw.Provider, raw.ConnectionID}
	if k != key {
		return nil, bad
	}
	out := CloneConnection(raw)
	if out.AccessToken, err = connDecryptField(s.wrapper, k, "access", raw.AccessToken); err != nil {
		return nil, bad
	}
	if raw.RefreshToken != nil {
		rt, err := connDecryptField(s.wrapper, k, "refresh", *raw.RefreshToken)
		if err != nil {
			return nil, bad
		}
		out.RefreshToken = &rt
	}
	return out, nil
}

// Set encrypts the tokens and stores the record.
func (s *EncryptedConnectionStore) Set(c *Connection) error {
	k := ConnectionKey{c.AgentID, c.Provider, c.ConnectionID}
	sealed := CloneConnection(c)
	bad := newStoreError("a token could not be encrypted; nothing was stored")
	var err error
	if sealed.AccessToken, err = connEncryptField(s.wrapper, k, "access", c.AccessToken); err != nil {
		return bad
	}
	if c.RefreshToken != nil {
		rt, err := connEncryptField(s.wrapper, k, "refresh", *c.RefreshToken)
		if err != nil {
			return bad
		}
		sealed.RefreshToken = &rt
	}
	return s.inner.Set(sealed)
}

// Delete removes the record.
func (s *EncryptedConnectionStore) Delete(key ConnectionKey) error { return s.inner.Delete(key) }

// Reencrypt re-seals one record under the wrapper's active key (run after rotating the key ring).
func (s *EncryptedConnectionStore) Reencrypt(key ConnectionKey) (bool, error) {
	c, err := s.Get(key)
	if err != nil || c == nil {
		return false, err
	}
	return true, s.Set(c)
}

// ---- the vault -------------------------------------------------------------------------------------------------------------------

// ConnectAction is the pinned definition of one verb, as the vault's actions lookup returns it.
type ConnectAction struct {
	Verb             string
	DefDigest        string
	Confirmed        bool
	UpstreamProvider string
	ScopesMin        []string // nil: the action declares none
	Extract          func(req map[string]any) (map[string]any, error)
}

// ReceiptOptions turns on signed release receipts: SecretKey is the 32-byte Ed25519 seed; Sink (optional) receives each receipt
// and a failure of it is ignored (a failing sink must not turn a made call into an error the caller retries).
type ReceiptOptions struct {
	SecretKey []byte
	Sink      func(receipt map[string]any) error
}

// TokenVaultOptions configure a TokenVault.
type TokenVaultOptions struct {
	Store                     ConnectionStore
	Providers                 map[string]*ProviderConfig
	Fetch                     ConnectFetch
	Now                       func() float64
	Audience                  string
	PqPins                    map[string]string
	AuthorizedPlanRoots       []string // nil = unset (a non-nil empty list enforces and refuses every root)
	InsecureSkipPlanRootCheck bool
	ExpiryLeewayMs            *float64
	DefaultConnectionID       string
	RequireActionBinding      *bool
	ResourceFor               func(provider, connectionID string) string
	UseVerb                   *string // nil = "use_connection"
	NoUseVerb                 bool    // skip the verb check
	DefaultTokenLifetimeMs    *float64
	Replay                    PcactnReplayStore
	IsRevoked                 func(pcactn map[string]any) (bool, error)
	Strict                    *bool // nil = strict
	Actions                   func(verb string) *ConnectAction
	InsecureBearerRelease     bool
	ProxyFetch                func(req map[string]any) (map[string]any, error)
	ProxyHeaders              []string
	MaxProxyResponseBytes     *float64
	Receipts                  *ReceiptOptions
}

// TokenVault holds an agent's third-party OAuth tokens and releases a fresh access token only for a verified PCActn.
type TokenVault struct {
	o                TokenVaultOptions
	proxyHeaders     []string
	maxProxy, leeway float64
	defaultLifetime  float64
	defaultCID       string
	requireBinding   bool
	useVerb          string
	resourceFor      func(provider, cid string) string
	now              func() float64
}

// NewTokenVault validates the options. In strict mode (the default) the store must be encrypting and Replay, IsRevoked and
// Audience must be set.
func NewTokenVault(o TokenVaultOptions) (*TokenVault, error) {
	if o.Strict == nil || *o.Strict {
		var missing []string
		enc, _ := o.Store.(interface{ Encrypted() bool })
		if enc == nil || !enc.Encrypted() {
			missing = append(missing, "an encrypting store")
		}
		if o.Replay == nil {
			missing = append(missing, "replay")
		}
		if o.IsRevoked == nil {
			missing = append(missing, "isRevoked")
		}
		if o.Audience == "" {
			missing = append(missing, "audience")
		}
		if len(missing) > 0 {
			return nil, errors.New("TokenVault strict mode requires " + strings.Join(missing, ", "))
		}
	} else if o.Store == nil {
		return nil, errors.New("TokenVault requires a store")
	}
	v := &TokenVault{o: o, maxProxy: 4 * 1024 * 1024, leeway: 30_000, defaultLifetime: 300_000, defaultCID: "default", requireBinding: true, useVerb: "use_connection"}
	v.proxyHeaders = DefaultProxyHeaders
	if o.ProxyHeaders != nil {
		v.proxyHeaders = make([]string, len(o.ProxyHeaders))
		for i, h := range o.ProxyHeaders {
			v.proxyHeaders[i] = strings.ToLower(h)
		}
	}
	if o.MaxProxyResponseBytes != nil {
		v.maxProxy = *o.MaxProxyResponseBytes
	}
	if o.ExpiryLeewayMs != nil {
		v.leeway = *o.ExpiryLeewayMs
	}
	if o.DefaultTokenLifetimeMs != nil {
		v.defaultLifetime = *o.DefaultTokenLifetimeMs
	}
	if o.DefaultConnectionID != "" {
		v.defaultCID = o.DefaultConnectionID
	}
	if o.RequireActionBinding != nil {
		v.requireBinding = *o.RequireActionBinding
	}
	if o.UseVerb != nil {
		v.useVerb = *o.UseVerb
	}
	v.resourceFor = o.ResourceFor
	if v.resourceFor == nil {
		v.resourceFor = func(provider, _ string) string { return "oauth:" + provider }
	}
	v.now = o.Now
	if v.now == nil {
		v.now = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	return v, nil
}

func (v *TokenVault) cid(p *string) string {
	if p == nil {
		return v.defaultCID
	}
	return *p
}

// PutConnectionOptions are the arguments of PutConnection. RefreshToken nil = none; AuthorityScopes nil = Scopes.
type PutConnectionOptions struct {
	AgentID, Provider, AccessToken string
	ConnectionID                   *string // nil = the vault default
	RefreshToken                   *string
	ExpiresAt                      float64
	Scopes                         []string
	AuthorityPrincipal             string
	AuthorityScopes                []string
	AuthorityAudience              *string
}

// PutConnection stores (or replaces) an agent's connection; the authority descriptor binds which capability may use it.
func (v *TokenVault) PutConnection(o PutConnectionOptions) (*Connection, error) {
	cid := v.cid(o.ConnectionID)
	for _, f := range [][2]string{{"agentId", o.AgentID}, {"provider", o.Provider}, {"connectionId", cid}, {"accessToken", o.AccessToken}, {"principal", o.AuthorityPrincipal}} {
		if f[1] == "" {
			return nil, fmt.Errorf("putConnection: %s must be a non-empty string", f[0])
		}
	}
	if math.IsNaN(o.ExpiresAt) || math.IsInf(o.ExpiresAt, 0) {
		return nil, errors.New("putConnection: expiresAt must be a finite number")
	}
	if o.RefreshToken != nil && *o.RefreshToken == "" {
		return nil, errors.New("putConnection: refreshToken must be a non-empty string when given")
	}
	aScopes := o.AuthorityScopes
	if aScopes == nil {
		aScopes = o.Scopes
	}
	c := &Connection{AgentID: o.AgentID, Provider: o.Provider, ConnectionID: cid, AccessToken: o.AccessToken, ExpiresAt: o.ExpiresAt,
		Scopes: append([]string{}, o.Scopes...), CreatedAt: v.now(),
		Authority: ConnectionAuthority{Provider: o.Provider, Principal: o.AuthorityPrincipal, Scopes: append([]string{}, aScopes...), Audience: o.AuthorityAudience}}
	if o.RefreshToken != nil {
		rt := *o.RefreshToken
		c.RefreshToken = &rt
	}
	if err := v.storeSet(c); err != nil {
		return nil, err
	}
	return c, nil
}

// GetTokenResult is a released bearer token.
type GetTokenResult struct {
	Provider, ConnectionID, AccessToken string
	Scopes                              []string
	ExpiresAt                           float64
	Refreshed                           bool
}

// GetConnectionToken returns a FRESH access token iff pcactn verifies against the connection's bound principal and the chain's
// grant covers the requested provider and scopes (scopes nil = the connection's authority, or the action's minimum). Disabled
// unless the vault was built with InsecureBearerRelease (prefer ProxyCall).
func (v *TokenVault) GetConnectionToken(pcactn map[string]any, provider string, connectionID *string, scopes []string) (*GetTokenResult, error) {
	if !v.o.InsecureBearerRelease {
		return nil, vaultErr("BearerReleaseDisabledError", "bearer_release_disabled",
			"this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)")
	}
	a, err := v.authorize(pcactn, provider, connectionID, scopes, false, nil)
	if err != nil {
		return nil, err
	}
	token, refreshed, err := v.freshToken(a)
	if err != nil {
		return nil, err
	}
	done, err := v.recordUse(a, token)
	if err != nil {
		return nil, err
	}
	if _, err := v.issueReceipt(pcactn, a, "bearer", nil, nil, "released", done.Scopes); err != nil {
		return nil, err
	}
	exp := done.ExpiresAt
	if a.action != nil {
		if e, ok := jsNum(pcactn["exp"]); ok && !math.IsNaN(e) && !math.IsInf(e, 0) {
			exp = math.Min(exp, e)
		}
	}
	return &GetTokenResult{Provider: a.provider, ConnectionID: a.connectionID, AccessToken: done.AccessToken, Scopes: append([]string{}, done.Scopes...), ExpiresAt: exp, Refreshed: refreshed}, nil
}

// ProxyCall is proxy mode: the vault makes the outbound call itself (the agent never holds the credential). The request must
// re-derive exactly the params the PCActn signed; the action is spent first; redirects are not followed; a receipt links release
// to effect. It returns {response: {status, headers, body}, receipt?}.
func (v *TokenVault) ProxyCall(pcactn, request map[string]any, provider string, connectionID *string) (map[string]any, error) {
	return v.ProxyCallScopes(pcactn, request, provider, connectionID, nil)
}

// ProxyCallScopes is ProxyCall asking for explicit scopes (nil: the action's minimum): scopes beyond the action's minimum or the
// capability's grant are refused with a ScopeExceededError.
func (v *TokenVault) ProxyCallScopes(pcactn, request map[string]any, provider string, connectionID *string, scopes []string) (map[string]any, error) {
	if v.o.Actions == nil {
		return nil, errors.New("proxyCall requires the vault to be constructed with `actions`")
	}
	if v.o.ProxyFetch == nil {
		return nil, errors.New("proxyCall requires the vault to be constructed with `proxyFetch`")
	}
	var hdrs any
	if h, ok := request["headers"]; ok {
		hdrs = h
	}
	sendHeaders, err := CheckProxyHeaders(hdrs, v.proxyHeaders)
	if err != nil {
		return nil, err
	}
	a, err := v.authorize(pcactn, provider, connectionID, scopes, true, request)
	if err != nil {
		return nil, err
	}
	token, _, err := v.freshToken(a)
	if err != nil {
		return nil, err
	}
	done, err := v.recordUse(a, token)
	if err != nil {
		return nil, err
	}
	headers := map[string]any{}
	for k, val := range sendHeaders {
		headers[k] = val
	}
	headers["authorization"] = "Bearer " + done.AccessToken
	method, _ := request["method"].(string)
	url, _ := request["url"].(string)
	var bodyPtr *string
	body, hasBody := request["body"]
	if s, ok := body.(string); ok {
		bodyPtr = &s
	}
	reqDigest, err := OutboundRequestDigest(method, url, sendHeaders, bodyPtr)
	if err != nil {
		return nil, err
	}
	call := map[string]any{"method": request["method"], "url": request["url"], "headers": headers, "redirect": "manual"}
	if hasBody {
		call["body"] = body
	}
	response, perr := v.o.ProxyFetch(call)
	if perr != nil {
		if _, err := v.issueReceipt(pcactn, a, "proxy", &reqDigest, nil, "failed", done.Scopes); err != nil {
			return nil, err
		}
		return nil, vaultErr("ProxyFailedError", "proxy_failed", "the outbound call failed before a response")
	}
	rbody, bodyIsStr := response["body"].(string)
	size := math.Inf(1)
	if bodyIsStr {
		size = float64(len(rbody))
	}
	var status any
	if st, ok := jsNum(response["status"]); ok && !math.IsNaN(st) && !math.IsInf(st, 0) && st == math.Trunc(st) && math.Abs(st) <= replayMaxSafe {
		status = response["status"]
	}
	receipt, err := v.issueReceipt(pcactn, a, "proxy", &reqDigest, status, "executed", done.Scopes)
	if err != nil {
		return nil, err
	}
	if !(finite(size) && size <= v.maxProxy) { // an unmeasurable body is never within the limit; an infinite limit is the unbounded one
		return nil, vaultErr("ProxyFailedError", "proxy_failed", "the response is larger than maxProxyResponseBytes (the call was made and the action is spent)")
	}
	tok := done.AccessToken
	rh := map[string]any{}
	if hm, ok := response["headers"].(map[string]any); ok {
		for _, k := range jsKeys(hm) {
			if strings.ToLower(k) != "set-cookie" {
				rh[k] = strings.ReplaceAll(jsValueString(hm[k]), tok, "[redacted]")
			}
		}
	}
	out := map[string]any{"response": map[string]any{"status": response["status"], "headers": rh, "body": strings.ReplaceAll(rbody, tok, "[redacted]")}}
	if receipt != nil {
		out["receipt"] = receipt
	}
	return out, nil
}

type connAuthorized struct {
	agentID, provider, connectionID string
	connection                      *Connection
	requested                       []string
	now                             float64
	action                          *ConnectAction
}

func (v *TokenVault) authorize(pcactn map[string]any, provider string, connectionID *string, scopes []string, needAction bool, request map[string]any) (*connAuthorized, error) {
	cid := v.cid(connectionID)
	chain, ok := pcactn["cap_chain"].([]any)
	if !ok || len(chain) == 0 {
		return nil, newNotAuthorized("PCActn has no capability chain", nil)
	}
	leafV, rootV := chain[len(chain)-1], chain[0]
	if leafV == nil || rootV == nil {
		return nil, newNotAuthorized("PCActn capability chain is malformed", nil)
	}
	// a leaf that is not an object has no holder: JavaScript reads `undefined` and the lookup finds no connection for it
	agentID := "undefined"
	if leaf, isObj := leafV.(map[string]any); isObj {
		agentID = jsMemberString(leaf, "holder")
	}
	root, _ := rootV.(map[string]any)
	connection, err := v.storeGet(ConnectionKey{agentID, provider, cid})
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, vaultErr("UnknownConnectionError", "unknown_connection", fmt.Sprintf("no connection for agent '%s' provider '%s' id '%s'", agentID, provider, cid))
	}
	if root == nil {
		return nil, newNotAuthorized("PCActn capability chain is malformed", nil)
	}
	if issuer, _ := root["issuer"].(string); issuer != connection.Authority.Principal {
		return nil, newNotAuthorized("capability chain is not rooted at the connection's bound principal", nil)
	}
	now := v.now()
	audience := v.o.Audience
	if connection.Authority.Audience != nil {
		audience = *connection.Authority.Audience
	}
	if audience == "" { // no audience pinned: accept the action's own signed aud
		audience, _ = pcactn["aud"].(string)
	}
	vd, err := VerifyPCActnCoreWith(pcactn, root, int64(now), audience, VerifyOptions{
		AuthorizedPlanRoots: v.o.AuthorizedPlanRoots, InsecureSkipPlanRootCheck: v.o.InsecureSkipPlanRootCheck, PQPins: v.o.PqPins})
	if err != nil {
		return nil, newNotAuthorized("PCActn verification failed: "+err.Error(), nil)
	}
	if !vd.Allow {
		reason := vd.Reason
		if reason == "" {
			reason = "rejected"
		}
		return nil, newNotAuthorized("PCActn verification failed: "+reason, vd.Checks)
	}
	if v.o.IsRevoked != nil {
		revoked, rerr := v.o.IsRevoked(pcactn)
		if rerr != nil {
			return nil, newNotAuthorized("revocation source unavailable", nil)
		}
		if revoked {
			return nil, newNotAuthorized("the capability chain is revoked", nil)
		}
	}
	act, _ := pcactn["action"].(map[string]any)
	if act == nil {
		return nil, errors.New("PCActn has no action")
	}
	verb, _ := act["verb"].(string)
	var action *ConnectAction
	if v.o.Actions != nil {
		action = v.o.Actions(verb)
		if action == nil || action.Verb != verb {
			return nil, newUnknownAction(jsMemberString(act, "verb"))
		}
		if !action.Confirmed {
			return nil, vaultErr("UnconfirmedActionError", "unconfirmed_action",
				fmt.Sprintf("the definition of '%s' has no valid signed confirmation: refusing to release a credential", verb))
		}
		if action.UpstreamProvider != provider {
			return nil, newNotAuthorized(fmt.Sprintf("the action '%s' is not for provider '%s'", verb, provider), nil)
		}
		if len(action.ScopesMin) == 0 {
			return nil, newNotAuthorized(fmt.Sprintf("the action '%s' declares no upstream scopes (nothing to release)", verb), nil)
		}
	} else if needAction {
		return nil, newUnknownAction(jsMemberString(act, "verb"))
	} else if v.requireBinding {
		expected := v.resourceFor(provider, cid)
		if res, _ := act["resource"].(string); res != expected {
			return nil, newNotAuthorized(fmt.Sprintf("PCActn action resource '%s' is not for this connection (expected '%s')", jsMemberString(act, "resource"), expected), nil)
		}
		if !v.o.NoUseVerb && verb != v.useVerb {
			return nil, newNotAuthorized(fmt.Sprintf("PCActn action verb '%s' is not a connection-use verb (expected '%s')", jsMemberString(act, "verb"), v.useVerb), nil)
		}
	}
	granted, hasGrant, gerr := GrantedOAuthScopes(chain, provider)
	if gerr != nil {
		return nil, gerr
	}
	if !hasGrant {
		return nil, newNotAuthorized(fmt.Sprintf("capability grants no authority for provider '%s'", provider), nil)
	}
	in := func(xs []string, s string) bool {
		for _, x := range xs {
			if x == s {
				return true
			}
		}
		return false
	}
	var requested []string
	if action != nil {
		mn := action.ScopesMin
		requested = scopes
		if requested == nil {
			requested = mn
		}
		var beyond []string
		for _, s := range requested {
			if !in(mn, s) {
				beyond = append(beyond, s)
			}
		}
		if len(beyond) > 0 {
			return nil, newScopeExceeded(provider, beyond)
		}
		var unheld []string
		for _, s := range mn {
			if !in(connection.Scopes, s) || !in(connection.Authority.Scopes, s) {
				unheld = append(unheld, s)
			}
		}
		if len(unheld) > 0 {
			return nil, newScopeExceeded(provider, unheld)
		}
		if !needAction {
			var extra []string
			for _, s := range connection.Scopes {
				if !in(mn, s) {
					extra = append(extra, s)
				}
			}
			if len(extra) > 0 {
				return nil, newScopeExceeded(provider, extra)
			}
		}
		var ungranted []string
		for _, s := range mn {
			if !in(granted, s) {
				ungranted = append(ungranted, s)
			}
		}
		if len(ungranted) > 0 {
			return nil, newScopeExceeded(provider, ungranted)
		}
	} else {
		requested = scopes
		if requested == nil {
			requested = connection.Authority.Scopes
		}
	}
	var missing []string
	for _, s := range requested {
		if !in(granted, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return nil, newScopeExceeded(provider, missing)
	}
	if needAction && action != nil {
		if request == nil || action.Extract == nil {
			return nil, connMismatch2("the action has no request extractor: proxy mode cannot bind the outbound request")
		}
		params, xerr := action.Extract(request)
		if xerr != nil {
			var ve *VaultError
			if errors.As(xerr, &ve) && ve.Code == "request_mismatch" {
				return nil, xerr
			}
			return nil, connMismatch2("the outbound request could not be mapped to the action parameters")
		}
		d, derr := ParamsDigest(params)
		if derr != nil {
			return nil, connMismatch2("the outbound request parameters are not canonical")
		}
		if want, _ := act["params_digest"].(string); d != want {
			return nil, connMismatch2("the outbound request does not carry the parameters the PCActn signed")
		}
	}
	if v.o.Replay != nil {
		aud, _ := pcactn["aud"].(string)
		if verdict := GuardPcactnReplay(v.o.Replay, pcactn, aud, now, nil, true, nil); !verdict.OK {
			return nil, newNotAuthorized("replay guard refused the action: "+verdict.Reason, nil)
		}
	}
	return &connAuthorized{agentID: agentID, provider: provider, connectionID: cid, connection: connection, requested: append([]string{}, requested...), now: now, action: action}, nil
}

// connMismatch2 is a request-mismatch refusal with its message verbatim (no "outbound request refused" prefix).
func connMismatch2(msg string) error {
	return vaultErr("RequestMismatchError", "request_mismatch", msg)
}

func (v *TokenVault) freshToken(a *connAuthorized) (*Connection, bool, error) {
	conn := a.connection
	if !finite(conn.ExpiresAt) || !finite(a.now) || !finite(v.leeway) || conn.ExpiresAt-a.now <= v.leeway {
		if conn.RefreshToken == nil {
			return nil, false, vaultErr("ExpiredNoRefreshError", "expired_no_refresh",
				fmt.Sprintf("connection '%s/%s' token is expired and has no refresh token", a.provider, a.connectionID))
		}
		up, err := RefreshConnection(conn, v.o.Providers[a.provider], *conn.RefreshToken, a.requested, v.o.Fetch, a.now, v.defaultLifetime)
		if err != nil {
			return nil, false, err
		}
		t := CloneConnection(conn)
		t.AccessToken, t.ExpiresAt, t.Scopes = up.AccessToken, up.ExpiresAt, up.Scopes
		rt := up.RefreshToken
		t.RefreshToken = &rt
		return t, true, nil
	}
	return conn, false, nil
}

func (v *TokenVault) recordUse(a *connAuthorized, token *Connection) (*Connection, error) {
	t := CloneConnection(token)
	t.LastUsedAt = &a.now
	t.UseCount = token.UseCount + 1
	if err := v.storeSet(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (v *TokenVault) issueReceipt(pcactn map[string]any, a *connAuthorized, mode string, requestDigest *string, httpStatus any, outcome string, scopes []string) (map[string]any, error) {
	if v.o.Receipts == nil {
		return nil, nil
	}
	ad, err := ReceiptActionDigest(pcactn)
	if err != nil {
		return nil, err
	}
	sorted := append([]string{}, scopes...)
	sort.SliceStable(sorted, func(i, j int) bool { return utf16Less(sorted[i], sorted[j]) })
	var rd any
	if requestDigest != nil {
		rd = *requestDigest
	}
	receipt, err := SignReleaseReceipt(map[string]any{"v": json.Number("1"), "kind": "pca-release-receipt", "action_digest": ad, "provider": a.provider,
		"connection_id": a.connectionID, "mode": mode, "scopes_released": connAnyList(sorted), "request_digest": rd, "http_status": httpStatus,
		"outcome": outcome, "ts": jsNumber(a.now)}, v.o.Receipts.SecretKey)
	if err != nil {
		return nil, err
	}
	if v.o.Receipts.Sink != nil {
		_ = v.o.Receipts.Sink(receipt)
	}
	return receipt, nil
}

// DeleteConnection removes a stored connection.
func (v *TokenVault) DeleteConnection(agentID, provider string, connectionID *string) error {
	if err := v.o.Store.Delete(ConnectionKey{agentID, provider, v.cid(connectionID)}); err != nil {
		var ve *VaultError
		if errors.As(err, &ve) {
			return err
		}
		return newStoreError("the connection store failed") // the store's own error text can quote a record
	}
	return nil
}

func (v *TokenVault) storeGet(k ConnectionKey) (*Connection, error) {
	c, err := v.o.Store.Get(k)
	if err != nil {
		var ve *VaultError
		if errors.As(err, &ve) {
			return nil, err
		}
		return nil, newStoreError("the connection store failed")
	}
	return c, nil
}

func (v *TokenVault) storeSet(c *Connection) error {
	if err := v.o.Store.Set(c); err != nil {
		var ve *VaultError
		if errors.As(err, &ve) {
			return err
		}
		return newStoreError("the connection store failed")
	}
	return nil
}
