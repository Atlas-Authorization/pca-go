package pca

// A declarative catalog of outbound OAuth connectors for the token vault: manifest validation and digests, the provider
// registry, the authorize URL with PKCE and URL variables, access-token placement, authorization-code exchange and refresh into
// the vault, and the manifest-to-vault-provider mapping. Manifests and option bags are JSON-like maps with the reference's
// member names (the seeded manifests are in BuiltinManifests). Injected transports are plain funcs (ConnectFetch); the vault is
// a TokenVault. Not safe for concurrent registration.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ConnectorError is every typed refusal of the catalog; Name is "ConnectorError", "ManifestValidationError" or
// "UnknownProviderError" (Issues carries the validation problems).
type ConnectorError struct {
	Name, Message string
	Issues        []string
}

func (e *ConnectorError) Error() string { return e.Message }

func connectorErr(format string, a ...any) error {
	return &ConnectorError{Name: "ConnectorError", Message: fmt.Sprintf(format, a...)}
}

// RESERVED request members the builders own (a manifest or caller may not set them).
var (
	// ReservedAuthorizeParams are the authorize-request members the URL builder owns.
	ReservedAuthorizeParams = setOf("response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method")
	// ReservedTokenParams are the token-request members the exchange builder owns.
	ReservedTokenParams = setOf("grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token")
)

var (
	connIDRx         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	connHeaderNameRx = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	connQueryNameRx  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	connLabelRx      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	connVerifierRx   = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	connRawHostRx    = regexp.MustCompile(`^\{\w+\}(:\d+)?$`)
	connForbidden    = setOf("host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie")
)

func connIsWSOrComma(r rune) bool { return r == ',' || connIsJSWS(r) }

func connHasWSOrComma(s string) bool { return strings.IndexFunc(s, connIsWSOrComma) >= 0 }

func connProp(o any, k string) (any, bool) {
	m, ok := o.(map[string]any)
	if !ok {
		return nil, false
	}
	v, has := m[k]
	return v, has
}

func connNonEmpty(v any) bool { s, ok := v.(string); return ok && s != "" }

func connIsStrArray(v any) bool { _, ok := v.([]any); return ok && connStrListOK(v) }

func connStrListOK(v any) bool { _, ok := connStrList(v); return ok }

func connIsStrRecord(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, x := range m {
		if _, ok := x.(string); !ok {
			return false
		}
	}
	return true
}

// connCopyMap copies m and keeps its key order.
func connCopyMap(m map[string]any) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = v
	}
	recordKeyOrder(o, jsKeys(m))
	return o
}

func connIsHTTPSURL(v any) bool {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "https://") {
		return false
	}
	u, err := connParseURL(connPlaceholder.ReplaceAllString(s, "x"))
	if err != nil || u.scheme != "https" || u.username != "" || u.password != "" || u.hash != "" {
		return false
	}
	raw := s[len("https://"):]
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	return !connRawHostRx.MatchString(raw)
}

func connURLVars(url string) []string {
	var out []string
	for _, m := range connPlaceholder.FindAllStringSubmatch(url, -1) {
		out = append(out, m[1])
	}
	return out
}

func connInList(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func connOneOf(items ...string) string { return strings.Join(items, " | ") }

// ValidateManifest returns the frozen manifest, or every problem of the input (no partial acceptance).
func ValidateManifest(inp any) (manifest map[string]any, issues []string) {
	in, ok := inp.(map[string]any)
	if !ok {
		return nil, []string{"manifest must be an object"}
	}
	str := func(k string) (any, bool) { v, has := in[k]; return v, has }
	mid, _ := str("id")
	if !connNonEmpty(mid) {
		issues = append(issues, "id must be a non-empty string")
	} else if !connIDRx.MatchString(mid.(string)) {
		issues = append(issues, fmt.Sprintf("id '%s' must be lowercase and match %s", mid, "^[a-z0-9][a-z0-9._-]*$"))
	}
	if v, _ := str("displayName"); !connNonEmpty(v) {
		issues = append(issues, "displayName must be a non-empty string")
	}
	authorizeURL, _ := str("authorizeUrl")
	if !connIsHTTPSURL(authorizeURL) {
		issues = append(issues, "authorizeUrl must be an https:// URL")
	}
	tokenURL, _ := str("tokenUrl")
	if !connIsHTTPSURL(tokenURL) {
		issues = append(issues, "tokenUrl must be an https:// URL")
	}
	scopesAvailable, _ := str("scopesAvailable")
	if !connIsStrArray(scopesAvailable) {
		issues = append(issues, "scopesAvailable must be an array of strings")
	}
	defaultScopes, _ := str("defaultScopes")
	if !connIsStrArray(defaultScopes) {
		issues = append(issues, "defaultScopes must be an array of strings")
	}
	for _, p := range []struct {
		name string
		lst  any
	}{{"scopesAvailable", scopesAvailable}, {"defaultScopes", defaultScopes}} {
		if !connIsStrArray(p.lst) {
			continue
		}
		l, _ := connStrList(p.lst)
		for _, s := range l {
			if s == "" || connHasWSOrComma(s) {
				issues = append(issues, p.name+" entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)")
				break
			}
		}
		if len(connDedup(l)) != len(l) {
			issues = append(issues, p.name+" must not contain duplicates")
		}
	}
	if connIsStrArray(scopesAvailable) && connIsStrArray(defaultScopes) {
		avail, _ := connStrList(scopesAvailable)
		def, _ := connStrList(defaultScopes)
		if len(avail) > 0 {
			var missing []string
			for _, s := range def {
				if !connInList(avail, s) {
					missing = append(missing, s)
				}
			}
			if len(missing) > 0 {
				issues = append(issues, fmt.Sprintf("defaultScopes must be a subset of scopesAvailable (unknown: %s)", strings.Join(missing, ", ")))
			}
		}
	}
	refreshV, _ := str("refresh")
	if refresh, ok := refreshV.(map[string]any); !ok {
		issues = append(issues, "refresh must be an object")
	} else {
		if mode, ok := refresh["mode"].(string); !ok || (mode != "refresh_token" && mode != "none") {
			issues = append(issues, "refresh.mode must be one of "+connOneOf("refresh_token", "none"))
		}
		if te, has := refresh["tokenEndpoint"]; has && !connIsHTTPSURL(te) {
			issues = append(issues, "refresh.tokenEndpoint, when present, must be an https:// URL")
		}
		if sn, has := refresh["supportsScopeNarrowing"]; has {
			if _, isBool := sn.(bool); !isBool {
				issues = append(issues, "refresh.supportsScopeNarrowing must be a boolean")
			}
		}
		if ep, has := refresh["extraParams"]; has && !connIsStrRecord(ep) {
			issues = append(issues, "refresh.extraParams must be a string→string map")
		} else if has {
			em := ep.(map[string]any)
			for _, k := range jsKeys(em) {
				if ReservedTokenParams[k] {
					issues = append(issues, fmt.Sprintf("refresh.extraParams may not set '%s': the request builder owns it", k))
				}
			}
		}
	}
	placement, _ := str("tokenPlacement")
	if p, ok := placement.(string); !ok || (p != "bearer" && p != "header" && p != "query") {
		issues = append(issues, "tokenPlacement must be one of "+connOneOf("bearer", "header", "query"))
	} else if hn, _ := str("headerName"); p == "header" && !connNonEmpty(hn) {
		issues = append(issues, "tokenPlacement 'header' requires a non-empty headerName")
	} else if qp, _ := str("queryParam"); p == "query" && !connNonEmpty(qp) {
		issues = append(issues, "tokenPlacement 'query' requires a non-empty queryParam")
	}
	if hn, ok := in["headerName"].(string); ok && (!connHeaderNameRx.MatchString(hn) || connForbidden[strings.ToLower(hn)]) {
		issues = append(issues, fmt.Sprintf("headerName '%s' must be an HTTP token and not a protocol header", hn))
	}
	if qp, ok := in["queryParam"].(string); ok && !connQueryNameRx.MatchString(qp) {
		issues = append(issues, fmt.Sprintf("queryParam '%s' must be a plain parameter name", qp))
	}
	if sep, ok := in["scopeSeparator"].(string); ok && sep == "" {
		issues = append(issues, "scopeSeparator must not be empty")
	}
	if pk, has := in["pkce"]; has {
		if _, isBool := pk.(bool); !isBool {
			issues = append(issues, "pkce must be a boolean")
		}
	}
	if sep, has := in["scopeSeparator"]; has {
		if _, isStr := sep.(string); !isStr {
			issues = append(issues, "scopeSeparator must be a string")
		}
	}
	if ap, has := in["authParams"]; has && !connIsStrRecord(ap) {
		issues = append(issues, "authParams must be a string→string map")
	} else if has {
		am := ap.(map[string]any)
		for _, k := range jsKeys(am) {
			if ReservedAuthorizeParams[k] {
				issues = append(issues, fmt.Sprintf("authParams may not set '%s': the request builder owns it", k))
			}
		}
	}
	if ca, has := in["clientAuth"]; has {
		if s, isStr := ca.(string); !isStr || (s != "post" && s != "basic") {
			issues = append(issues, "clientAuth must be one of "+connOneOf("post", "basic"))
		}
	}
	requiredVars, hasRV := in["requiredVars"]
	if hasRV && !connIsStrArray(requiredVars) {
		issues = append(issues, "requiredVars must be an array of strings")
	}
	if connIsHTTPSURL(authorizeURL) && connIsHTTPSURL(tokenURL) {
		var declared []string
		if connIsStrArray(requiredVars) {
			declared, _ = connStrList(requiredVars)
		}
		declared = connDedup(declared)
		used := connDedup(append(connURLVars(authorizeURL.(string)), connURLVars(tokenURL.(string))...))
		for _, v := range used {
			if !connInList(declared, v) {
				issues = append(issues, fmt.Sprintf("url uses '{%s}' but requiredVars does not declare it", v))
			}
		}
		for _, v := range declared {
			if !connInList(used, v) {
				issues = append(issues, fmt.Sprintf("requiredVars declares '%s' but no URL uses '{%s}'", v, v))
			}
		}
	}
	if du, has := in["docsUrl"]; has {
		if _, isStr := du.(string); !isStr {
			issues = append(issues, "docsUrl must be a string")
		}
	}
	if len(issues) > 0 {
		return nil, issues
	}
	return connFreezeManifest(in), nil
}

func connFreezeManifest(in map[string]any) map[string]any {
	strOr := func(k string) any {
		if s, ok := in[k].(string); ok {
			return s
		}
		return ""
	}
	listOr := func(k string) any {
		if l, ok := connStrList(in[k]); ok && connIsStrArray(in[k]) {
			return connAnyList(l)
		}
		return []any{}
	}
	rr, _ := in["refresh"].(map[string]any)
	refresh := map[string]any{"mode": "refresh_token"}
	if rr["mode"] == "none" {
		refresh["mode"] = "none"
	}
	if te, ok := rr["tokenEndpoint"].(string); ok {
		refresh["tokenEndpoint"] = te
	}
	if sn, ok := rr["supportsScopeNarrowing"].(bool); ok {
		refresh["supportsScopeNarrowing"] = sn
	}
	if connIsStrRecord(rr["extraParams"]) {
		refresh["extraParams"] = connCopyMap(rr["extraParams"].(map[string]any))
	}
	tp := "bearer"
	if in["tokenPlacement"] == "header" || in["tokenPlacement"] == "query" {
		tp = in["tokenPlacement"].(string)
	}
	m := map[string]any{"id": strOr("id"), "displayName": strOr("displayName"), "authorizeUrl": strOr("authorizeUrl"), "tokenUrl": strOr("tokenUrl"),
		"scopesAvailable": listOr("scopesAvailable"), "defaultScopes": listOr("defaultScopes"), "refresh": refresh, "tokenPlacement": tp}
	if pk, ok := in["pkce"].(bool); ok {
		m["pkce"] = pk
	}
	if sep, ok := in["scopeSeparator"].(string); ok {
		m["scopeSeparator"] = sep
	}
	if connIsStrRecord(in["authParams"]) {
		m["authParams"] = connCopyMap(in["authParams"].(map[string]any))
	}
	if in["clientAuth"] == "post" || in["clientAuth"] == "basic" {
		m["clientAuth"] = in["clientAuth"]
	}
	for _, k := range []string{"headerName", "queryParam", "docsUrl"} {
		if s, ok := in[k].(string); ok {
			m[k] = s
		}
	}
	if connIsStrArray(in["requiredVars"]) {
		l, _ := connStrList(in["requiredVars"])
		m["requiredVars"] = connAnyList(l)
	}
	return m
}

// AssertManifest returns the frozen manifest or a ManifestValidationError carrying every issue.
func AssertManifest(inp any) (map[string]any, error) {
	m, issues := ValidateManifest(inp)
	if issues != nil {
		return nil, &ConnectorError{Name: "ManifestValidationError", Message: "invalid provider manifest: " + strings.Join(issues, "; "), Issues: issues}
	}
	return m, nil
}

// ManifestDigest is the content address of a validated manifest: a pinned digest detects a swapped endpoint.
func ManifestDigest(manifest map[string]any) (string, error) { return HashCanonical(manifest) }

// ---- registry --------------------------------------------------------------------------------------------------------------------

// RegisterOptions of ProviderRegistry.Register: ExpectedDigest pins the manifest ("" with HasExpectedDigest pins the empty digest);
// Replace allows overwriting an id deliberately.
type RegisterOptions struct {
	ExpectedDigest    string
	HasExpectedDigest bool
	Replace           bool
}

// ProviderRegistry is a set of validated provider manifests by id.
type ProviderRegistry struct{ byID map[string]map[string]any }

// NewProviderRegistry returns an empty registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{byID: map[string]map[string]any{}}
}

// Register validates and registers a manifest.
func (r *ProviderRegistry) Register(manifest any, opts RegisterOptions) (map[string]any, error) {
	valid, err := AssertManifest(manifest)
	if err != nil {
		return nil, err
	}
	id := valid["id"].(string)
	if opts.HasExpectedDigest {
		d, err := ManifestDigest(valid)
		if err != nil {
			return nil, err
		}
		if d != opts.ExpectedDigest {
			return nil, connectorErr("manifest '%s' does not match the pinned digest", id)
		}
	}
	if _, dup := r.byID[id]; dup && !opts.Replace {
		return nil, connectorErr("provider '%s' is already registered; pass { replace: true } to replace it deliberately", id)
	}
	r.byID[id] = valid
	return valid, nil
}

// Get returns the manifest or nil.
func (r *ProviderRegistry) Get(id string) map[string]any { return r.byID[id] }

// Require returns the manifest or an UnknownProviderError.
func (r *ProviderRegistry) Require(id string) (map[string]any, error) {
	if m := r.byID[id]; m != nil {
		return m, nil
	}
	return nil, &ConnectorError{Name: "UnknownProviderError", Message: fmt.Sprintf("no connector registered for provider '%s'", id)}
}

// Has reports whether id is registered.
func (r *ProviderRegistry) Has(id string) bool { _, ok := r.byID[id]; return ok }

// List returns the manifests in id order (UTF-16 code unit order).
func (r *ProviderRegistry) List() []map[string]any {
	out := make([]map[string]any, 0, len(r.byID))
	for _, m := range r.byID {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return utf16Less(out[i]["id"].(string), out[j]["id"].(string)) })
	return out
}

// IDs returns the registered ids in order.
func (r *ProviderRegistry) IDs() []string {
	l := r.List()
	out := make([]string, len(l))
	for i, m := range l {
		out[i] = m["id"].(string)
	}
	return out
}

// CreateDefaultRegistry returns a registry holding the built-in catalog.
func CreateDefaultRegistry() *ProviderRegistry {
	r := NewProviderRegistry()
	for _, m := range BuiltinManifests() {
		if _, err := r.Register(m, RegisterOptions{}); err != nil {
			panic("pca: the built-in connector catalog is invalid: " + err.Error())
		}
	}
	return r
}

var connDefaultRegistry = CreateDefaultRegistry()

// DefaultProviderRegistry is the process-wide registry (built-ins plus RegisterProvider calls).
func DefaultProviderRegistry() *ProviderRegistry { return connDefaultRegistry }

// RegisterProvider registers a manifest in the process-wide registry.
func RegisterProvider(manifest any, opts RegisterOptions) (map[string]any, error) {
	return connDefaultRegistry.Register(manifest, opts)
}

// CatalogDigest is one digest over the whole catalog (id and manifest digest, in id order); nil = the default registry.
func CatalogDigest(r *ProviderRegistry) (string, error) {
	if r == nil {
		r = connDefaultRegistry
	}
	rows := []any{}
	for _, m := range r.List() {
		d, err := ManifestDigest(m)
		if err != nil {
			return "", err
		}
		rows = append(rows, []any{m["id"], d})
	}
	return HashCanonical(rows)
}

// ---- authorize URL, PKCE, URL variables and token placement ------------------------------------------------------------------------

const connMinStateChars = 16

func connRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// PkceChallenge is the PKCE challenge of a verifier: S256 (base64url of its SHA-256), or the verifier itself for "plain".
func PkceChallenge(verifier, method string) string {
	if method == "plain" {
		return verifier
	}
	h := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(h[:])
}

// SubstituteVars fills `{name}` placeholders from vars; each value must be a single DNS label so a value can never change the
// host. A nil vars has no variables (every placeholder is missing).
func SubstituteVars(url string, vars map[string]any) (string, error) {
	var first error
	out := connPlaceholder.ReplaceAllStringFunc(url, func(m string) string {
		if first != nil {
			return m
		}
		name := m[1 : len(m)-1]
		v, has := vars[name]
		if !has {
			first = connectorErr("missing URL variable '{%s}'", name)
			return m
		}
		s, ok := v.(string)
		if !ok || !connLabelRx.MatchString(s) {
			first = connectorErr("URL variable '{%s}' must be a single DNS label (letters, digits and hyphens)", name)
			return m
		}
		return s
	})
	if first != nil {
		return "", first
	}
	return out, nil
}

func connEnc(v any) string {
	if s, ok := v.(string); ok {
		return connEncodeComponent(s)
	}
	return connEncodeComponent(jsValueString(v))
}

func connEncodeForm(params [][2]any) string {
	parts := make([]string, len(params))
	for i, kv := range params {
		parts[i] = connEnc(kv[0]) + "=" + connEnc(kv[1])
	}
	return strings.Join(parts, "&")
}

type connURLInfo struct{ protocol, username, password, hostname, hash string }

var connSchemeRx = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.\-]*):`)

// connInfoOf is the protocol, credentials, hostname and hash of an absolute URL (WHATWG parse; an error when it does not parse).
func connInfoOf(text string) (connURLInfo, error) {
	s := strings.TrimFunc(text, func(r rune) bool { return r <= 0x20 })
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)
	m := connSchemeRx.FindStringSubmatch(s)
	if m == nil {
		return connURLInfo{}, errInvalidURL
	}
	scheme := strings.ToLower(m[1])
	if u, err := connParseURL(s); err == nil {
		p, _ := whatwgParse(s)
		host := p.host
		if strings.HasPrefix(host, "[") {
			if i := strings.Index(host, "]"); i >= 0 {
				host = host[:i+1]
			}
		} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		return connURLInfo{scheme + ":", u.username, u.password, host, u.hash}, nil
	} else if connSpecialSchemes[scheme] {
		return connURLInfo{}, err
	}
	rest := s[len(m[0]):]
	frag := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		frag = rest[i+1:]
	}
	info := connURLInfo{protocol: scheme + ":"}
	if strings.HasPrefix(rest, "//") {
		auth := rest[2:]
		if i := strings.IndexAny(auth, "/?#"); i >= 0 {
			auth = auth[:i]
		}
		if i := strings.LastIndexByte(auth, '@'); i >= 0 {
			info.username, info.password, _ = strings.Cut(auth[:i], ":")
			auth = auth[i+1:]
		}
		info.hostname, _, _ = strings.Cut(auth, ":")
	}
	if frag != "" {
		info.hash = "#" + frag
	}
	return info, nil
}

func connCheckRedirectURI(uri any, present bool) error {
	text := "undefined"
	if present {
		text = jsValueString(uri)
	}
	u, err := connInfoOf(text)
	if err != nil {
		return connectorErr("buildAuthorizeUrl: redirectUri must be an absolute URL")
	}
	if u.hash != "" {
		return connectorErr("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)")
	}
	if u.username != "" || u.password != "" {
		return connectorErr("buildAuthorizeUrl: redirectUri must not carry credentials")
	}
	local := u.hostname == "localhost" || u.hostname == "127.0.0.1" || u.hostname == "[::1]"
	if u.protocol != "https:" && !(u.protocol == "http:" && local) {
		return connectorErr("buildAuthorizeUrl: redirectUri must be https (http only for localhost)")
	}
	return nil
}

func connSeparator(manifest map[string]any) string {
	if s, ok := manifest["scopeSeparator"].(string); ok {
		return s
	}
	return " "
}

func connCheckScopes(manifest map[string]any, scopes any, allowUnlisted bool) error {
	l, ok := scopes.([]any)
	if !ok {
		return connectorErr("buildAuthorizeUrl: scopes must be a list")
	}
	seen := map[string]bool{}
	sep := connSeparator(manifest)
	avail, _ := connStrList(manifest["scopesAvailable"])
	for _, x := range l {
		s, isStr := x.(string)
		if !isStr || s == "" || connHasWSOrComma(s) || strings.Contains(s, sep) {
			return connectorErr("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator")
		}
		if seen[s] {
			return connectorErr("buildAuthorizeUrl: scope '%s' is listed twice", s)
		}
		seen[s] = true
		if !allowUnlisted && len(avail) > 0 && !connInList(avail, s) {
			return connectorErr("buildAuthorizeUrl: scope '%s' is not offered by provider '%s'", s, manifest["id"])
		}
	}
	return nil
}

// connOrderedPairs reads a JSON object as ordered pairs (nil and absent: none); anything else is an error.
func connOrderedPairs(v any) ([][2]any, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		out := make([][2]any, 0, len(t))
		for _, k := range jsKeys(t) {
			out = append(out, [2]any{k, t[k]})
		}
		return out, nil
	case bool, float64, int, int64, json.Number: // Object.entries of a boolean or a number has no entries
		return nil, nil
	case string: // Object.entries of a string: one entry per UTF-16 unit
		var out [][2]any
		for i, u := range utf16Units(t) {
			unit := string(rune(u))
			if u >= 0xD800 && u <= 0xDFFF { // each half of a pair is its own (lone surrogate) string
				unit = string([]byte{0xED, byte(0xA0 | u>>6&0x1F), byte(0x80 | u&0x3F)})
			}
			out = append(out, [2]any{strconv.Itoa(i), unit})
		}
		return out, nil
	case []any:
		var out [][2]any
		for i, x := range t {
			out = append(out, [2]any{strconv.Itoa(i), x})
		}
		return out, nil
	}
	return nil, errors.New("extraParams must be an object")
}

// AuthorizeURL is the result of BuildAuthorizeUrl: the URL, the state, and the PKCE verifier / challenge / method when used.
type AuthorizeURL struct {
	URL, State string
	Pkce       map[string]any // nil when PKCE is off
}

// BuildAuthorizeUrl builds the authorization URL (RFC 6749 3.1, RFC 7636) for a registered provider. options carries clientId,
// redirectUri, scopes, state, pkce (false, true or {verifier, method}), vars, extraParams, allowUnlistedScopes and
// allowPlainPkce; registry nil = the default registry. A random state / PKCE verifier is generated when none is given.
func BuildAuthorizeUrl(providerID string, options map[string]any, registry *ProviderRegistry) (*AuthorizeURL, error) {
	if registry == nil {
		registry = connDefaultRegistry
	}
	manifest, err := registry.Require(providerID)
	if err != nil {
		return nil, err
	}
	scopes := options["scopes"]
	if scopes == nil {
		scopes = manifest["defaultScopes"]
	}
	separator := connSeparator(manifest)
	stateV := options["state"]
	if stateV == nil {
		if stateV, err = connRandomToken(); err != nil {
			return nil, err
		}
	}
	clientID, _ := options["clientId"].(string)
	if clientID == "" {
		return nil, connectorErr("buildAuthorizeUrl: clientId must be a non-empty string")
	}
	redirect, hasRedirect := options["redirectUri"]
	if err := connCheckRedirectURI(redirect, hasRedirect); err != nil {
		return nil, err
	}
	state, isStr := stateV.(string)
	if !isStr || jsLen(state) < connMinStateChars {
		return nil, connectorErr("buildAuthorizeUrl: state must be at least %d characters (omit it to get a random one)", connMinStateChars)
	}
	if err := connCheckScopes(manifest, scopes, options["allowUnlistedScopes"] == true); err != nil {
		return nil, err
	}
	extra, err := connOrderedPairs(options["extraParams"])
	if err != nil {
		return nil, err
	}
	for _, kv := range extra {
		if ReservedAuthorizeParams[kv[0].(string)] {
			return nil, connectorErr("buildAuthorizeUrl: extraParams may not set '%s'", kv[0])
		}
	}
	params := [][2]any{{"response_type", "code"}, {"client_id", clientID}, {"redirect_uri", redirect}}
	scopeList, _ := connStrList(scopes)
	if len(scopeList) > 0 {
		params = append(params, [2]any{"scope", strings.Join(scopeList, separator)})
	}
	params = append(params, [2]any{"state", state})
	pk, hasPk := options["pkce"]
	want := false
	switch {
	case pk == false:
		want = false
	case hasPk:
		want = true
	default:
		want = manifest["pkce"] == true
	}
	var pkce map[string]any
	if want {
		var verifier any
		method := any("S256")
		if pm, ok := pk.(map[string]any); ok {
			verifier = pm["verifier"]
			if m := pm["method"]; m != nil {
				method = m
			}
		} else if hasPk && pk == nil {
			return nil, errors.New("Cannot read properties of null")
		} else {
			if verifier, err = connRandomToken(); err != nil {
				return nil, err
			}
		}
		vs := "undefined"
		if verifier != nil {
			vs = jsValueString(verifier)
		}
		if !connVerifierRx.MatchString(vs) {
			return nil, connectorErr("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)")
		}
		if method != "S256" && !(method == "plain" && options["allowPlainPkce"] == true) {
			return nil, connectorErr("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')")
		}
		verifierStr, ok := verifier.(string)
		if !ok {
			return nil, errors.New("the PKCE verifier must be a string")
		}
		challenge := PkceChallenge(verifierStr, method.(string))
		params = append(params, [2]any{"code_challenge", challenge}, [2]any{"code_challenge_method", method})
		pkce = map[string]any{"verifier": verifierStr, "challenge": challenge, "method": method}
	}
	if ap, ok := manifest["authParams"].(map[string]any); ok {
		for _, k := range jsKeys(ap) {
			params = append(params, [2]any{k, ap[k]})
		}
	}
	params = append(params, extra...)
	vars, _ := options["vars"].(map[string]any)
	base, err := SubstituteVars(manifest["authorizeUrl"].(string), vars)
	if err != nil {
		return nil, err
	}
	sepr := "?"
	if strings.Contains(base, "?") {
		sepr = "&"
	}
	for _, kv := range params { // encodeURIComponent throws a URIError on a lone surrogate
		for _, x := range kv {
			if str, ok := x.(string); ok && wtfToUTF8(str) != str {
				return nil, errors.New("URI malformed")
			}
		}
	}
	return &AuthorizeURL{URL: base + sepr + connEncodeForm(params), State: state, Pkce: pkce}, nil
}

// ApplyAccessToken says how to present an access token: {kind: "header" | "query", name, value}, or nil for an unknown
// placement. manifest is used as is (not validated). The token must be printable ASCII without spaces.
func ApplyAccessToken(manifest map[string]any, accessToken any) (map[string]any, error) {
	tok, ok := accessToken.(string)
	if !ok || tok == "" || strings.IndexFunc(tok, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return nil, connectorErr("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces")
	}
	switch manifest["tokenPlacement"] {
	case "bearer":
		return map[string]any{"kind": "header", "name": "Authorization", "value": "Bearer " + tok}, nil
	case "header":
		hn, has := manifest["headerName"]
		if !has {
			return nil, connectorErr("manifest '%s' is header-placed but has no headerName", jsMemberString(manifest, "id"))
		}
		return map[string]any{"kind": "header", "name": hn, "value": tok}, nil
	case "query":
		qp, has := manifest["queryParam"]
		if !has {
			return nil, connectorErr("manifest '%s' is query-placed but has no queryParam", jsMemberString(manifest, "id"))
		}
		return map[string]any{"kind": "query", "name": qp, "value": tok}, nil
	}
	return nil, nil
}

// ---- code exchange, refresh and the vault bridge -----------------------------------------------------------------------------------

const connDefaultTokenLifetimeMs = 3_600_000

// ConnectorBind says where an exchanged or refreshed connection is stored: the vault, the agent, and the authority descriptor
// (Scopes nil = the requested scopes).
type ConnectorBind struct {
	Vault        *TokenVault
	AgentID      string
	ConnectionID *string
	Principal    string
	Scopes       []string
	Audience     *string
}

// TokenExchangeArgs are the arguments of ExchangeCode and RefreshTokens. ClientID / RedirectURI nil = undefined; Scopes nil = the
// manifest's defaults; Registry nil = the default registry; Now nil = the wall clock; Vars is the DNS-label variable map.
type TokenExchangeArgs struct {
	ProviderID   string
	ClientID     *string
	ClientSecret *string
	Code         string // ExchangeCode
	RedirectURI  *string
	CodeVerifier *string
	RefreshToken string // RefreshTokens
	Scopes       []string
	Fetch        ConnectFetch
	Bind         ConnectorBind
	Now          *float64
	Registry     *ProviderRegistry
	Vars         map[string]any
	ExtraParams  map[string]any
}

func connCheckExtraParams(extra map[string]any, what string) error {
	for _, k := range jsKeys(extra) {
		if ReservedTokenParams[k] {
			return connectorErr("%s: extraParams may not set '%s'", what, k)
		}
	}
	return nil
}

type connTokens struct {
	accessToken, refreshToken string
	hasExpires                bool
	expiresInSecs             float64
	scopes                    []string
	hasScopes                 bool
}

func connParseTokenBody(body any, provider string) (*connTokens, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, connectorErr("[%s] token endpoint returned a non-object body", provider)
	}
	at, _ := m["access_token"].(string)
	if at == "" {
		return nil, connectorErr("[%s] token endpoint response has no access_token", provider)
	}
	out := &connTokens{accessToken: at}
	if ex, ok := jsNum(m["expires_in"]); ok && !math.IsNaN(ex) && !math.IsInf(ex, 0) && ex > 0 {
		out.hasExpires, out.expiresInSecs = true, ex
	}
	if rt, _ := m["refresh_token"].(string); rt != "" {
		out.refreshToken = rt
	}
	if sc, ok := m["scope"].(string); ok {
		if t := connJSTrim(sc); t != "" {
			out.hasScopes = true
			out.scopes = connSplitWSOrComma(t)
		}
	}
	return out, nil
}

// connSplitWSOrComma splits on runs of whitespace or commas (a regex `[ws,]+` split keeps empty edge fields).
func connSplitWSOrComma(s string) []string {
	var out []string
	start := 0
	in := false
	for i, r := range s {
		if connIsWSOrComma(r) {
			if !in {
				out = append(out, s[start:i])
				in = true
			}
		} else if in {
			in, start = false, i
		}
	}
	if in {
		out = append(out, "")
	} else {
		out = append(out, s[start:])
	}
	return out
}

func connPostToken(manifest map[string]any, endpoint string, params [][2]string, clientSecret *string, fetch ConnectFetch, haveClientID bool) (*connTokens, error) {
	id := manifest["id"].(string)
	headers := map[string]any{"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
	body := append([][2]string{}, params...)
	get := func(k string) *string {
		for i := range params {
			if params[i][0] == k {
				return &params[i][1]
			}
		}
		return nil
	}
	if manifest["clientAuth"] == "basic" {
		if clientSecret == nil {
			return nil, connectorErr("[%s] clientAuth 'basic' requires a clientSecret", id)
		}
		cid := get("client_id")
		if cid == nil || !haveClientID {
			return nil, connectorErr("[%s] missing client_id for basic auth", id)
		}
		headers["authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(*cid+":"+*clientSecret))
		kept := body[:0]
		for _, kv := range body {
			if kv[0] != "client_id" && kv[0] != "client_secret" {
				kept = append(kept, kv)
			}
		}
		body = kept
	}
	var secs []string
	if clientSecret != nil {
		secs = append(secs, *clientSecret)
	}
	for _, k := range []string{"code", "code_verifier", "refresh_token"} {
		if v := get(k); v != nil {
			secs = append(secs, *v)
		}
	}
	if a, ok := headers["authorization"].(string); ok {
		secs = append(secs, a)
	}
	pairs := make([][2]any, len(body))
	for i, kv := range body {
		pairs[i] = [2]any{kv[0], kv[1]}
	}
	var res *ConnectResponse
	var err error
	if fetch == nil {
		err = errors.New("fetchImpl is not a function")
	} else {
		res, err = fetch(endpoint, map[string]any{"method": "POST", "headers": headers, "body": connEncodeForm(pairs)})
	}
	if err != nil {
		return nil, connectorErr("[%s] token transport error: %s", id, connRedact(err.Error(), secs))
	}
	if !res.OK {
		detail := "<unreadable body>"
		if t, terr := res.Text(); terr == nil {
			detail = connRedact(connU16Prefix(t, 256), secs)
		}
		return nil, connectorErr("[%s] token endpoint %s: %s", id, jsNumberString(res.Status), detail)
	}
	j, err := res.JSON()
	if err != nil {
		return nil, connectorErr("[%s] unparseable token JSON", id)
	}
	return connParseTokenBody(j, id)
}

func connStoreConnection(manifest map[string]any, parsed *connTokens, requested []string, bind ConnectorBind, now float64, prior *string) (*Connection, error) {
	expiresAt := now + connDefaultTokenLifetimeMs
	if parsed.hasExpires {
		expiresAt = now + parsed.expiresInSecs*1000
	}
	granted := requested
	if parsed.hasScopes {
		granted = parsed.scopes
	}
	var rt *string
	if parsed.refreshToken != "" {
		rt = &parsed.refreshToken
	} else {
		rt = prior
	}
	aScopes := bind.Scopes
	if aScopes == nil {
		aScopes = append([]string{}, requested...)
	}
	return bind.Vault.PutConnection(PutConnectionOptions{AgentID: bind.AgentID, Provider: manifest["id"].(string), AccessToken: parsed.accessToken,
		ConnectionID: bind.ConnectionID, RefreshToken: rt, ExpiresAt: expiresAt, Scopes: append([]string{}, granted...),
		AuthorityPrincipal: bind.Principal, AuthorityScopes: aScopes, AuthorityAudience: bind.Audience})
}

func connNow(p *float64) float64 {
	if p != nil {
		return *p
	}
	return float64(time.Now().UnixMilli())
}

func connOrUndef(p *string) string {
	if p == nil {
		return "undefined"
	}
	return *p
}

func connRequested(manifest map[string]any, scopes []string) []string {
	if scopes != nil {
		return scopes
	}
	l, _ := connStrList(manifest["defaultScopes"])
	return l
}

// ExchangeCode exchanges an authorization code for tokens at the provider's token endpoint and stores the connection in the vault.
func ExchangeCode(a TokenExchangeArgs) (*Connection, error) {
	reg := a.Registry
	if reg == nil {
		reg = connDefaultRegistry
	}
	manifest, err := reg.Require(a.ProviderID)
	if err != nil {
		return nil, err
	}
	id := manifest["id"].(string)
	now := connNow(a.Now)
	requested := connRequested(manifest, a.Scopes)
	if a.Code == "" {
		return nil, connectorErr("[%s] an authorization code is required", id)
	}
	if err := connCheckExtraParams(a.ExtraParams, "["+id+"] exchangeCode"); err != nil {
		return nil, err
	}
	if manifest["pkce"] == true && a.CodeVerifier == nil {
		return nil, connectorErr("[%s] provider uses PKCE; a codeVerifier is required to exchange the code", id)
	}
	params := [][2]string{{"grant_type", "authorization_code"}, {"code", a.Code}, {"redirect_uri", connOrUndef(a.RedirectURI)}, {"client_id", connOrUndef(a.ClientID)}}
	if a.ClientSecret != nil {
		params = append(params, [2]string{"client_secret", *a.ClientSecret})
	}
	if a.CodeVerifier != nil {
		params = append(params, [2]string{"code_verifier", *a.CodeVerifier})
	}
	params = connUpdateParams(params, a.ExtraParams)
	endpoint, err := SubstituteVars(manifest["tokenUrl"].(string), a.Vars)
	if err != nil {
		return nil, err
	}
	parsed, err := connPostToken(manifest, endpoint, params, a.ClientSecret, a.Fetch, a.ClientID != nil)
	if err != nil {
		return nil, err
	}
	return connStoreConnection(manifest, parsed, requested, a.Bind, now, nil)
}

func connUpdateParams(params [][2]string, extra map[string]any) [][2]string {
	for _, k := range jsKeys(extra) {
		v := jsValueString(extra[k])
		found := false
		for i := range params {
			if params[i][0] == k {
				params[i][1], found = v, true
				break
			}
		}
		if !found {
			params = append(params, [2]string{k, v})
		}
	}
	return params
}

// RefreshTokens refreshes a connection's tokens at the provider and stores the result in the vault (the refresh token is kept
// unless the provider rotates it).
func RefreshTokens(a TokenExchangeArgs) (*Connection, error) {
	reg := a.Registry
	if reg == nil {
		reg = connDefaultRegistry
	}
	manifest, err := reg.Require(a.ProviderID)
	if err != nil {
		return nil, err
	}
	id := manifest["id"].(string)
	refresh, _ := manifest["refresh"].(map[string]any)
	if refresh["mode"] == "none" {
		return nil, connectorErr("[%s] provider does not support token refresh", id)
	}
	now := connNow(a.Now)
	requested := connRequested(manifest, a.Scopes)
	if a.RefreshToken == "" {
		return nil, connectorErr("[%s] a refresh token is required", id)
	}
	if err := connCheckExtraParams(a.ExtraParams, "["+id+"] refresh"); err != nil {
		return nil, err
	}
	params := [][2]string{{"grant_type", "refresh_token"}, {"refresh_token", a.RefreshToken}, {"client_id", connOrUndef(a.ClientID)}}
	if a.ClientSecret != nil {
		params = append(params, [2]string{"client_secret", *a.ClientSecret})
	}
	if me, ok := refresh["extraParams"].(map[string]any); ok {
		params = connUpdateParams(params, me)
	}
	params = connUpdateParams(params, a.ExtraParams)
	if refresh["supportsScopeNarrowing"] == true && len(requested) > 0 {
		params = connUpdateParams(params, map[string]any{"scope": strings.Join(requested, connSeparator(manifest))})
	}
	tokenURL := manifest["tokenUrl"].(string)
	if te, ok := refresh["tokenEndpoint"].(string); ok {
		tokenURL = te
	}
	endpoint, err := SubstituteVars(tokenURL, a.Vars)
	if err != nil {
		return nil, err
	}
	parsed, err := connPostToken(manifest, endpoint, params, a.ClientSecret, a.Fetch, a.ClientID != nil)
	if err != nil {
		return nil, err
	}
	rt := a.RefreshToken
	return connStoreConnection(manifest, parsed, requested, a.Bind, now, &rt)
}

// ConnectorCredentials are the client credentials of one provider (Vars fills the manifest's URL variables).
type ConnectorCredentials struct {
	ClientID     string
	ClientSecret *string
	Vars         map[string]any
}

// ManifestToProviderConfig is the vault's token-endpoint configuration (a JSON-like map; see ProviderConfigFromMap) for a
// refreshable manifest.
func ManifestToProviderConfig(manifest map[string]any, creds ConnectorCredentials) (map[string]any, error) {
	id := jsMemberString(manifest, "id")
	refresh, _ := manifest["refresh"].(map[string]any)
	if refresh["mode"] == "none" {
		return nil, connectorErr("[%s] provider does not support token refresh; no ProviderConfig", id)
	}
	tokenURL := manifest["tokenUrl"].(string)
	if te, ok := refresh["tokenEndpoint"].(string); ok {
		tokenURL = te
	}
	endpoint, err := SubstituteVars(tokenURL, creds.Vars)
	if err != nil {
		return nil, err
	}
	c := map[string]any{"tokenEndpoint": endpoint, "clientId": creds.ClientID}
	if creds.ClientSecret != nil {
		c["clientSecret"] = *creds.ClientSecret
	}
	if sn, has := refresh["supportsScopeNarrowing"]; has {
		c["supportsScopeNarrowing"] = sn
	}
	if ep, ok := refresh["extraParams"].(map[string]any); ok {
		c["extraParams"] = connCopyMap(ep)
	}
	return c, nil
}

// ProviderConfigFromMap reads a ManifestToProviderConfig result into the vault's ProviderConfig (nil for a non-object).
func ProviderConfigFromMap(v any) *ProviderConfig {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	c := &ProviderConfig{SupportsScopeNarrowing: m["supportsScopeNarrowing"] == true}
	c.TokenEndpoint, _ = m["tokenEndpoint"].(string)
	c.ClientID, _ = m["clientId"].(string)
	if s, ok := m["clientSecret"].(string); ok {
		c.ClientSecret = &s
	}
	if ep, ok := m["extraParams"].(map[string]any); ok {
		for _, k := range jsKeys(ep) {
			s, _ := ep[k].(string)
			c.ExtraParams = append(c.ExtraParams, [2]string{k, s})
		}
	}
	return c
}

// BuildVaultProviders is the provider configuration (as ManifestToProviderConfig maps) for a TokenVault from per-provider
// credentials, in the order of ids; non-refreshable providers are skipped. registry nil = the default registry.
func BuildVaultProviders(ids []string, creds map[string]ConnectorCredentials, registry *ProviderRegistry) (map[string]map[string]any, error) {
	if registry == nil {
		registry = connDefaultRegistry
	}
	out := map[string]map[string]any{}
	for _, pid := range ids {
		manifest, err := registry.Require(pid)
		if err != nil {
			return nil, err
		}
		if refresh, _ := manifest["refresh"].(map[string]any); refresh["mode"] == "none" {
			continue
		}
		c, err := ManifestToProviderConfig(manifest, creds[pid])
		if err != nil {
			return nil, err
		}
		out[pid] = c
	}
	return out, nil
}
