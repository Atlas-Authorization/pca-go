package pca

// OAuth 2.1 / MCP-authorization bridge (port of the TypeScript @atlasauth/pca-oauth): RFC 9728 Protected Resource Metadata, the
// MCP 401 challenge (`WWW-Authenticate: Bearer resource_metadata=...`), RFC 8707 resource indicators, RFC 9396 `pca_grant`
// authorization details and the OAuth scopes derived from a confirmed action. Pure and I/O-free. The PCActn stays the credential
// that is verified; this is the discovery / challenge envelope around it.

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// WellKnownOAuthPRM is the RFC 9728 well-known path component.
const WellKnownOAuthPRM = "/.well-known/oauth-protected-resource"

const defaultPcaHint = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}"

// jsURL is the part of a WHATWG URL the bridge reads. shortcut: built on net/url (scheme / host lowercased, default port dropped,
// dot segments removed, no IDNA); a non-ASCII host or an opaque `https:x` form is refused instead of normalized.
type jsURL struct{ scheme, origin, pathname, search string }

func parseJSURL(s string) (jsURL, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Opaque != "" || (u.Host == "" && u.Scheme != "file") {
		return jsURL{}, false
	}
	host := strings.ToLower(u.Host)
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return jsURL{}, false
		}
	}
	if (u.Scheme == "https" && strings.HasSuffix(host, ":443")) || (u.Scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndexByte(host, ':')]
	}
	p := removeDotSegments(u.EscapedPath())
	if p == "" {
		p = "/"
	}
	q := ""
	if u.RawQuery != "" {
		q = "?" + u.RawQuery
	}
	return jsURL{scheme: u.Scheme, origin: u.Scheme + "://" + host, pathname: p, search: q}, true
}

// removeDotSegments is RFC 3986 section 5.2.4 (empty segments are kept, as WHATWG keeps them).
func removeDotSegments(p string) string {
	if !strings.Contains(p, ".") {
		return p
	}
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		last := i == len(segs)-1
		switch strings.ToLower(s) {
		case ".", "%2e":
			if last {
				out = append(out, "")
			}
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, "/")
}

// ResourceIdentifierProblem returns why resource is not an RFC 9728 resource identifier (an https URL, no fragment), or "".
func ResourceIdentifierProblem(resource any) string {
	s, ok := resource.(string)
	if !ok || s == "" {
		return "resource identifier must be a non-empty string"
	}
	u, ok := parseJSURL(s)
	if !ok {
		return "resource identifier is not an absolute URL"
	}
	if u.scheme != "https" {
		return "resource identifier must use the https scheme"
	}
	if strings.Contains(s, "#") {
		return "resource identifier must not contain a fragment"
	}
	return ""
}

// PrmPathForResource is the RFC 9728 section 3.1 well-known path for a resource identifier (the suffix goes between host and path).
func PrmPathForResource(resource string) (string, error) {
	if p := ResourceIdentifierProblem(resource); p != "" {
		return "", errors.New("prmPathForResource: " + p)
	}
	u, _ := parseJSURL(resource)
	path := u.pathname
	if path == "/" {
		path = ""
	}
	return WellKnownOAuthPRM + path + u.search, nil
}

// PrmURLForResource is the absolute metadata URL for a resource identifier (the `resource_metadata` value).
func PrmURLForResource(resource string) (string, error) {
	p, err := PrmPathForResource(resource)
	if err != nil {
		return "", err
	}
	u, _ := parseJSURL(resource)
	return u.origin + p, nil
}

// PRMOptions configures ProtectedResourceMetadata. Resource is the RS identifier AND the PCActn audience. A nil slice is absent;
// an empty string option is absent.
type PRMOptions struct {
	Resource                           string
	NotStrict                          bool // skip the RFC 9728 identifier check (a local test resource only)
	AuthorizationServers               []string
	BearerMethodsSupported             []string // default ["header"]
	ResourceDocumentation              string
	ScopesSupported                    []string
	ResourceName                       string
	ResourceSigningAlgValuesSupported  []string
	AuthorizationDetailsTypesSupported []string
	PcaConfigurationEndpoint           string // default <resource without query, trailing slashes>/.well-known/pca-configuration
	// forwarded to BuildDiscoveryDocument
	SignatureSuites []string
	PcaVersions     []int
	ActionHeader    string
	RequiredChecks  []string
	Endpoints       map[string]any
	TrustedRoots    []string
	Metadata        map[string]any
}

// ProtectedResourceMetadata builds the RFC 9728 document with the embedded PCA discovery block.
func ProtectedResourceMetadata(o PRMOptions) (map[string]any, error) {
	if o.Resource == "" {
		return nil, errors.New("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required")
	}
	if !o.NotStrict {
		if p := ResourceIdentifierProblem(o.Resource); p != "" {
			return nil, errors.New("protectedResourceMetadata: " + p)
		}
	}
	disc, err := BuildDiscoveryDocument(DiscoveryOptions{Audience: o.Resource, SignatureSuites: o.SignatureSuites, PcaVersions: o.PcaVersions,
		ActionHeader: o.ActionHeader, RequiredChecks: o.RequiredChecks, Endpoints: o.Endpoints, TrustedRoots: o.TrustedRoots, Metadata: o.Metadata})
	if err != nil {
		return nil, err
	}
	cfg := o.PcaConfigurationEndpoint
	if cfg == "" {
		cfg = strings.TrimRight(strings.SplitN(o.Resource, "?", 2)[0], "/") + WellKnownPcaPath
	}
	doc := map[string]any{
		"resource":                   o.Resource,
		"bearer_methods_supported":   jsStrList(orStrings(o.BearerMethodsSupported, []string{"header"})),
		"pca_action_header":          disc["action_header"],
		"pca_signature_suites":       append([]any(nil), disc["signature_suites"].([]any)...),
		"pca_versions":               append([]any(nil), disc["pca_versions"].([]any)...),
		"pca_configuration_endpoint": cfg,
		"pca":                        disc,
	}
	for k, v := range map[string][]string{"authorization_servers": o.AuthorizationServers, "scopes_supported": o.ScopesSupported,
		"resource_signing_alg_values_supported": o.ResourceSigningAlgValuesSupported, "authorization_details_types_supported": o.AuthorizationDetailsTypesSupported} {
		if v != nil {
			doc[k] = jsStrList(v)
		}
	}
	if o.ResourceDocumentation != "" {
		doc["resource_documentation"] = o.ResourceDocumentation
	}
	if o.ResourceName != "" {
		doc["resource_name"] = o.ResourceName
	}
	return doc, nil
}

// ParsePRM validates a fetched RFC 9728 document. expectedResource is the identifier the client fetched the document for;
// RFC 9728 section 3.3 requires the client to compare it, so it is required unless notStrict.
func ParsePRM(value any, expectedResource *string, notStrict bool) (map[string]any, error) {
	fail := func(m string) (map[string]any, error) { return nil, errors.New("parseProtectedResourceMetadata: " + m) }
	v, ok := value.(map[string]any)
	if !ok {
		if _, arr := value.([]any); !arr {
			return fail("not an object")
		}
	}
	res, ok := v["resource"].(string)
	if !ok || res == "" {
		return fail("missing `resource`")
	}
	if !isStrArray(v["bearer_methods_supported"]) {
		return fail("bearer_methods_supported must be a string[]")
	}
	if s, ok := v["pca_action_header"].(string); !ok || s == "" {
		return fail("missing pca_action_header")
	}
	if !isStrArray(v["pca_signature_suites"]) {
		return fail("pca_signature_suites must be a string[]")
	}
	if !isNumArray(v["pca_versions"]) {
		return fail("pca_versions must be a number[]")
	}
	if !isJSObject(v["pca"]) {
		return fail("missing embedded `pca` discovery document")
	}
	pca, _ := v["pca"].(map[string]any)
	aud, ok := pca["audience"].(string)
	if !ok || aud == "" {
		return fail("embedded pca.audience is required")
	}
	if expectedResource != nil {
		if res != *expectedResource {
			return fail("`resource` does not match the expected resource identifier")
		}
		if aud != *expectedResource {
			return fail("embedded pca.audience does not match the expected resource identifier")
		}
	}
	if !notStrict {
		if expectedResource == nil {
			return fail("expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip")
		}
		if p := ResourceIdentifierProblem(res); p != "" {
			return fail(p)
		}
		for _, m := range v["bearer_methods_supported"].([]any) {
			if m != "header" && m != "body" && m != "query" {
				return fail("bearer_methods_supported has a value outside header/body/query")
			}
		}
	}
	doc := map[string]any{"resource": res, "bearer_methods_supported": v["bearer_methods_supported"], "pca_action_header": v["pca_action_header"],
		"pca_signature_suites": v["pca_signature_suites"], "pca_versions": v["pca_versions"], "pca": v["pca"]}
	for _, k := range []string{"pca_configuration_endpoint", "resource_documentation", "resource_name"} {
		if _, ok := v[k].(string); ok {
			doc[k] = v[k]
		}
	}
	for _, k := range []string{"authorization_servers", "scopes_supported", "resource_signing_alg_values_supported"} {
		if isStrArray(v[k]) {
			doc[k] = v[k]
		}
	}
	return doc, nil
}

// WWWAuthOptions shapes the challenge. Nil pointers take the default: Realm "pca", Hint the default hint (an empty Hint omits it).
type WWWAuthOptions struct {
	Error            *string // the Bearer error code (an empty one is omitted from the header)
	ErrorDescription string
	Scope            string
	PcaNeed          map[string]any // a typed need, encoded into pca_need
	OmitPca          bool           // no PCA challenge after the Bearer one
	PcaChallenge     string         // a full PCA challenge to append instead of the default one
	Realm            *string
	Hint             *string
}

func quotedParam(v string) (string, error) {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c == '"' || c == '\\' || c < 0x20 || c == 0x7f {
			return "", errors.New("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline")
		}
	}
	return v, nil
}

// WWWAuthenticate builds the MCP-conformant header: a Bearer challenge with resource_metadata, then the PCA challenge.
func WWWAuthenticate(prmURL string, o WWWAuthOptions) (string, error) {
	if prmURL == "" {
		return "", errors.New("wwwAuthenticate: prmUrl is required")
	}
	var params []string
	add := func(name, v string) error {
		q, err := quotedParam(v)
		if err == nil {
			params = append(params, name+`="`+q+`"`)
		}
		return err
	}
	if err := add("resource_metadata", prmURL); err != nil {
		return "", err
	}
	if o.Error != nil && *o.Error != "" {
		if err := add("error", *o.Error); err != nil {
			return "", err
		}
	}
	if o.ErrorDescription != "" {
		if err := add("error_description", o.ErrorDescription); err != nil {
			return "", err
		}
	}
	if o.Scope != "" {
		if err := add("scope", o.Scope); err != nil {
			return "", err
		}
	}
	if o.PcaNeed != nil {
		enc, err := EncodePcaNeed(o.PcaNeed)
		if err != nil {
			return "", err
		}
		if err := add("pca_need", enc); err != nil {
			return "", err
		}
	}
	challenges := []string{"Bearer " + strings.Join(params, ", ")}
	if o.PcaChallenge != "" {
		for i := 0; i < len(o.PcaChallenge); i++ {
			if c := o.PcaChallenge[i]; (c < 0x20 && c != '\t') || c == 0x7f {
				return "", errors.New("pca-oauth: pcaChallenge may not contain control characters or newlines")
			}
		}
		challenges = append(challenges, o.PcaChallenge)
	} else if !o.OmitPca {
		realm, hint := "pca", defaultPcaHint
		if o.Realm != nil {
			realm = *o.Realm
		}
		if o.Hint != nil {
			hint = *o.Hint
		}
		r, err := quotedParam(realm)
		if err != nil {
			return "", err
		}
		p := `PCA realm="` + r + `"`
		if hint != "" {
			h, err := quotedParam(hint)
			if err != nil {
				return "", err
			}
			p += `, hint="` + h + `"`
		}
		challenges = append(challenges, p)
	}
	return strings.Join(challenges, ", "), nil
}

// ResourceIndicatorResult is the outcome of an audience / resource-indicator check.
type ResourceIndicatorResult struct {
	OK      bool   `json:"ok"`
	Matched string `json:"matched,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// jsonList is JSON.stringify of a value that is a string, a number or an array of those (the reason texts).
// shortcut: an object member order is canonical (sorted), not insertion order; only a reason text is affected.
func jsonList(v any) string {
	s, ok := canonicalLenient(v)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// CheckResourceIndicator checks the RFC 8707 `resource` parameter(s) against the RS audience. resourceParam is a string, a
// []string / []any of them, or nil (absent); a non-string entry never matches.
func CheckResourceIndicator(resourceParam any, expectedAudience string) (ResourceIndicatorResult, error) {
	if expectedAudience == "" {
		return ResourceIndicatorResult{}, errors.New("checkResourceIndicator: expectedAudience is required")
	}
	if resourceParam == nil {
		return ResourceIndicatorResult{Reason: "no resource indicator presented"}, nil
	}
	values := anyList(resourceParam)
	if len(values) == 0 {
		return ResourceIndicatorResult{Reason: "empty resource indicator"}, nil
	}
	for _, r := range values {
		if s, ok := r.(string); ok && s != "" && s == expectedAudience {
			return ResourceIndicatorResult{OK: true, Matched: s}, nil
		}
	}
	return ResourceIndicatorResult{Reason: "resource indicator " + jsonList(values) + " does not match audience " + jsonList(expectedAudience)}, nil
}

func anyList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		return jsStrList(t)
	}
	return []any{v}
}

// CheckTokenAudience checks that an AS-issued token's `aud` (a string or an array) includes this resource (RFC 8707 section 2).
func CheckTokenAudience(aud any, expectedResource string) (ResourceIndicatorResult, error) {
	if expectedResource == "" {
		return ResourceIndicatorResult{}, errors.New("checkTokenAudience: expectedResource is required")
	}
	if aud == nil {
		return ResourceIndicatorResult{Reason: "token has no audience"}, nil
	}
	values := anyList(aud)
	if len(values) == 0 {
		return ResourceIndicatorResult{Reason: "token has an empty audience"}, nil
	}
	for _, a := range values {
		if s, ok := a.(string); ok && s == expectedResource {
			return ResourceIndicatorResult{OK: true, Matched: expectedResource}, nil
		}
	}
	return ResourceIndicatorResult{Reason: "token audience " + jsonList(aud) + " does not include resource " + jsonList(expectedResource)}, nil
}

// OAuthDiscovery is what to mount: serve Body as JSON at Path (the RFC 9728 path for the resource).
type OAuthDiscovery struct {
	Path string         `json:"path"`
	Body map[string]any `json:"body"`
	// RFCPath is an alias of Path.
	RFCPath string `json:"rfcPath"`
}

// OAuthDiscoveryHandler returns the PRM document and the path to serve it at.
func OAuthDiscoveryHandler(o PRMOptions) (OAuthDiscovery, error) {
	body, err := ProtectedResourceMetadata(o)
	if err != nil {
		return OAuthDiscovery{}, err
	}
	path := WellKnownOAuthPRM
	if ResourceIdentifierProblem(o.Resource) == "" {
		path, _ = PrmPathForResource(o.Resource)
	}
	return OAuthDiscovery{Path: path, Body: body, RFCPath: path}, nil
}

// McpUnauthorized is the MCP 401: status, the WWW-Authenticate header and a JSON body.
type McpUnauthorized struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    map[string]any    `json:"body"`
}

// MCPUnauthorized builds the 401 a PCA RS returns to an unauthenticated MCP / OAuth client.
func MCPUnauthorized(prmURL string, o WWWAuthOptions) (McpUnauthorized, error) {
	h, err := WWWAuthenticate(prmURL, o)
	if err != nil {
		return McpUnauthorized{}, err
	}
	e := "invalid_request"
	if o.Error != nil {
		e = *o.Error
	}
	body := map[string]any{"error": e, "resource_metadata": prmURL}
	if o.ErrorDescription != "" {
		body["error_description"] = o.ErrorDescription
	}
	return McpUnauthorized{Status: 401, Headers: map[string]string{"WWW-Authenticate": h}, Body: body}, nil
}

// UpgradeUnauthorizedChallenge returns the header for a 401 whose existing PCA challenge (from the verifier; may be "") should
// follow the Bearer resource_metadata challenge.
func UpgradeUnauthorizedChallenge(existing, prmURL string, o WWWAuthOptions) (string, error) {
	if existing != "" {
		o.PcaChallenge = existing
	}
	return WWWAuthenticate(prmURL, o)
}

// PcaGrantDetailOptions configures BuildPcaGrantDetail.
type PcaGrantDetailOptions struct {
	ChainIDs       []string
	ChainRef       string // https URL; "" = absent
	BundleRevision *int64
	Locations      []string // nil = absent
}

// BuildPcaGrantDetail builds a validated RFC 9396 `pca_grant` authorization detail for a chain.
func BuildPcaGrantDetail(o PcaGrantDetailOptions) (map[string]any, error) {
	dg, err := PcaGrantChainDigest(o.ChainIDs)
	if err != nil {
		return nil, fmt.Errorf("buildPcaGrantDetail: %w", err)
	}
	d := map[string]any{"type": pcaGrantType, "chain_digest": dg, "chain_len": jsNumber(float64(len(o.ChainIDs)))}
	if o.ChainRef != "" {
		d["chain_ref"] = o.ChainRef
	}
	if o.BundleRevision != nil {
		d["bundle_revision"] = jsNumber(float64(*o.BundleRevision))
	}
	if o.Locations != nil {
		d["locations"] = jsStrList(o.Locations)
	}
	if code, ok := ValidatePcaGrantDetail(d); !ok {
		return nil, fmt.Errorf("buildPcaGrantDetail: refused (%s)", code)
	}
	return d, nil
}

var pcaGrantDetailOrder = []string{"type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations"}

// PcaGrantRequestParam is the `authorization_details` request parameter: encodeURIComponent(JSON.stringify(details)), members
// in the order BuildPcaGrantDetail writes them (any other member follows, sorted).
func PcaGrantRequestParam(details []map[string]any) string {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, d := range details {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('{')
		n := 0
		emit := func(k string) {
			if n > 0 {
				sb.WriteByte(',')
			}
			n++
			sb.WriteString(jsonList(k) + ":" + jsonList(d[k]))
		}
		known := map[string]bool{}
		for _, k := range pcaGrantDetailOrder {
			known[k] = true
			if _, has := d[k]; has {
				emit(k)
			}
		}
		var rest []string
		for k := range d {
			if !known[k] {
				rest = append(rest, k)
			}
		}
		sort.Strings(rest)
		for _, k := range rest {
			emit(k)
		}
		sb.WriteByte('}')
	}
	sb.WriteByte(']')
	return encodeURIComponent(sb.String())
}

// encodeURIComponent percent-encodes every UTF-8 byte outside A-Z a-z 0-9 - _ . ! ~ * ' ( ).
func encodeURIComponent(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// AuthorizePcaGrantToken decides an AS-issued token carrying `pca_grant` details at this RS. proofVerified must be the RS's own
// PCActn verification of the presented chain. Returns {allow:true, detail} or {allow:false, status, error, code}.
func AuthorizePcaGrantToken(authorizationDetails any, resource string, chainIDs []string, proofVerified bool) map[string]any {
	details, code := ParsePcaGrantDetails(authorizationDetails)
	if code != "" {
		return map[string]any{"allow": false, "status": jsNumber(401), "error": "invalid_token", "code": code}
	}
	i, code := CheckPcaGrantPresentation(details, resource, chainIDs, proofVerified)
	if code == "" {
		return map[string]any{"allow": true, "detail": details[i]}
	}
	if code == "wrong_location" {
		return map[string]any{"allow": false, "status": jsNumber(403), "error": "insufficient_scope", "code": code}
	}
	return map[string]any{"allow": false, "status": jsNumber(401), "error": "invalid_token", "code": code}
}

// OAuthScopeForAction is the OAuth scope request for a confirmed action at an upstream provider: {ok:true, scope, scopes,
// resource?} or {ok:false, code}. granted nil skips the grant check; resource "" is absent.
func OAuthScopeForAction(action any, provider string, granted []string, resource string) map[string]any {
	d := DeriveActionScopes(action, &provider, granted)
	if d["ok"] != true {
		return map[string]any{"ok": false, "code": d["code"]}
	}
	scopes := d["scopes"].([]any)
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = s.(string)
	}
	out := map[string]any{"ok": true, "scope": strings.Join(parts, " "), "scopes": scopes}
	if resource != "" {
		out["resource"] = resource
	}
	return out
}
