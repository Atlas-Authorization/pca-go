package pca

// Proof-Carrying Authority gateway: the decision logic of a deny-by-default enforcement point, as plain functions over request
// values. A request is {Method, Path, Query?, Authority?, BodySha256?, Body?, Headers}. The proof travels as the `PCA-Action`
// header; the gateway's own audience and a route -> capability map are configured once. Every step denies by default.
//
// Nothing here authorizes on its own: it extracts the proof, verifies it with the fail-closed offline core, checks the capability
// the route maps to, and maps that onto the gateway's contract. The Envoy HTTP and gRPC ext_authz shapes and the AWS Lambda
// authorizers are functions over decoded event maps. Full-policy mode delegates to Authorize with a caller-supplied template
// (GatewayFullPolicy.Input); the provenance gate and the k1 discharge inputs of that mode are not wired here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const GatewayPCAHeader = "PCA-Action"

// GatewayInjectedHeaders are the headers the gateway sets on an allow; a client-supplied copy is never trusted.
var GatewayInjectedHeaders = []string{"x-pca-verdict", "x-pca-verb", "x-pca-grant"}

// GatewayDefaultRequireChecks are the verdict checks that must PASS when RequireChecks is unset (signature-only mode).
var GatewayDefaultRequireChecks = []string{"revocation"}

type gatewayAbsentT struct{}

// GatewayAbsent is what GatewayPresentedProvenance returns when the request presents none (nil is a presented, malformed bundle).
var GatewayAbsent any = &gatewayAbsentT{}

// GatewayRequest is the gateway's view of an HTTP request.
type GatewayRequest struct {
	Method     string
	Path       string
	Query      *string
	Authority  *string
	BodySha256 *string
	Body       *string
	Headers    map[string]any // values: string, []string or []any (the first element is read)
}

// GatewayCapability is the capability a route requires; Resource nil means any resource.
type GatewayCapability struct {
	Verb     string
	Resource *string
}

// GatewayRoute: first matching rule wins. Method nil, "*" or "ANY" matches every method; Path may end in "/*" or "*".
type GatewayRoute struct {
	Method     *string
	Path       string
	Capability GatewayCapability
}

// GatewayBindOptions selects what the proof binds beyond method, path and query. Body nil: bind the body hash when the request
// carries one; true: always; false: never.
type GatewayBindOptions struct {
	Authority bool
	Body      *bool
}

type GatewayHookResult struct {
	Enforced bool
	OK       bool
	Reason   *string
}

type GatewayProofContext struct {
	PCActn   map[string]any
	Grant    map[string]any
	Verdict  *GatewayVerdict
	Request  GatewayRequest
	Required *GatewayCapability
}

// GatewayReplayGuard is a single-use store: Claim returns false when the key was already claimed and live.
type GatewayReplayGuard interface {
	Claim(key string, expiresAtMs float64, nowMs *float64) (bool, error)
}

// GatewayFullPolicy configures full-policy mode. Exactly one of ParamsBody / ParamsFn supplies the params the agent signed. Input
// is the Authorize template (StateStore and IsRevoked are required); the gateway sets Operation, Audience, ResolveGrant and Now.
type GatewayFullPolicy struct {
	ParamsBody bool
	ParamsFn   func(req GatewayRequest) (map[string]any, error)
	Input      AuthorizeInput
}

// GatewayOptions is the gateway configuration. PolicyMode is REQUIRED: "signature-only" or "full".
type GatewayOptions struct {
	Audience                  string
	Routes                    []GatewayRoute
	ResolveGrant              func(ref any, pcactn map[string]any) map[string]any
	AuthorizedPlanRoots       []string // nil: unset
	InsecureSkipPlanRootCheck bool
	UnmatchedRoute            string // "deny" (default), "allow", "require-proof"
	ReplayGuard               GatewayReplayGuard
	BindRequest               *GatewayBindOptions
	BindRequestOff            bool
	Revocation                func(pcactn, grant map[string]any, nowEpoch int64) (GatewayHookResult, error)
	EnforceFreshness          *FreshnessGate
	EnforceTaint              *TaintGate
	RequireChecks             []string // nil: default (signature-only) / none (full)
	CheckProof                func(ctx GatewayProofContext) (allow bool, reason string, err error)
	PathPolicy                string // "strict" (default) or "off"
	Now                       func() int64
	Realm                     *string
	PolicyMode                string
	Full                      *GatewayFullPolicy
}

type GatewayVerdict struct {
	Allow  bool
	Checks map[string]string
	Reason string
}

func (v *GatewayVerdict) json() string {
	m := map[string]any{"allow": v.Allow, "checks": v.Checks}
	if v.Reason != "" {
		m["reason"] = v.Reason
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// GatewayDecision is the outcome of one request.
type GatewayDecision struct {
	Allow         bool
	Status        int
	Code          string
	Reason        string
	Headers       map[string]string
	Verdict       *GatewayVerdict
	PCActn        map[string]any
	Matched       *GatewayCapability
	PolicyVerdict map[string]any
}

// ---- JS helpers ---------------------------------------------------------------------------------------------------------

func gwStr(v any) (string, bool) { s, ok := v.(string); return s, ok }

func gwGet(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		return m[k]
	}
	return nil
}

func gwFirst(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

func gwToString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x != nil {
				parts[i] = gwToString(x)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		return "[object Object]"
	}
	if f, ok := jsNum(v); ok {
		return jsNumberString(f)
	}
	return fmt.Sprint(v)
}

// gwLower is String.prototype.toLowerCase for the cases Go's per-rune mapping gets differently (U+0130 expands to i + U+0307).
func gwLower(s string) string { return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇")) }

func gwNonEmpty(p *string) bool { return p != nil && *p != "" }

func gwStrPtr(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func gwHeaders(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// gwJSONString is JSON.stringify of a string (a lone surrogate prints as \udxxx).
func gwJSONString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\b':
			sb.WriteString(`\b`)
		case c == '\f':
			sb.WriteString(`\f`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&sb, `\u%04x`, c)
		case c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF:
			fmt.Fprintf(&sb, `\u%04x`, 0xD000|int(s[i+1]&0x3f)<<6|int(s[i+2]&0x3f))
			i += 3
			continue
		default:
			sb.WriteByte(c)
		}
		i++
	}
	sb.WriteByte('"')
	return sb.String()
}

func gwErrorBody(code, reason string) string {
	return `{"error":` + gwJSONString(code) + `,"reason":` + gwJSONString(reason) + `}`
}

// ---- canonical query / binding ------------------------------------------------------------------------------------------

func gwHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func gwPercentByte(s string, i int) (byte, bool) {
	if i+2 >= len(s) || s[i] != '%' {
		return 0, false
	}
	h, ok1 := gwHex(s[i+1])
	l, ok2 := gwHex(s[i+2])
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

// gwDecodeURIComponent is decodeURIComponent: a '%' without two hex digits, or bytes that are not UTF-8, fail.
func gwDecodeURIComponent(s string) (string, bool) {
	var out []byte
	for i := 0; i < len(s); {
		if s[i] != '%' {
			out = append(out, s[i])
			i++
			continue
		}
		b, ok := gwPercentByte(s, i)
		if !ok {
			return "", false
		}
		i += 3
		if b < 0x80 {
			out = append(out, b)
			continue
		}
		n := 0
		switch {
		case b >= 0xC0 && b <= 0xDF:
			n = 2
		case b >= 0xE0 && b <= 0xEF:
			n = 3
		case b >= 0xF0 && b <= 0xF7:
			n = 4
		default:
			return "", false
		}
		seq := []byte{b}
		for k := 1; k < n; k++ {
			c, ok := gwPercentByte(s, i)
			if !ok || c < 0x80 || c > 0xBF {
				return "", false
			}
			seq = append(seq, c)
			i += 3
		}
		if !utf8.Valid(seq) {
			return "", false
		}
		out = append(out, seq...)
	}
	return string(out), true
}

func gwU16Less(a, b string) bool {
	x, y := utf16Units(a), utf16Units(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// GatewayCanonicalQuery strips a leading '?', drops empty pairs, sorts the raw pairs (UTF-16 code unit order) and joins them with
// '&'. It errors on a query that is ambiguous across upstream parsers: a repeated parameter name (percent-decoded, '+' as space,
// case-insensitive), a ';' separator, or a malformed percent escape in a name.
func GatewayCanonicalQuery(query *string) (string, error) {
	if query == nil {
		return "", nil
	}
	q := strings.TrimPrefix(*query, "?")
	if strings.Contains(q, ";") {
		return "", errors.New("query contains ';' (parsers disagree on it as a separator)")
	}
	var pairs []string
	seen := map[string]bool{}
	for _, p := range strings.Split(q, "&") {
		if p == "" {
			continue
		}
		pairs = append(pairs, p)
		rawKey := p
		if eq := strings.IndexByte(p, '='); eq >= 0 {
			rawKey = p[:eq]
		}
		dec, ok := gwDecodeURIComponent(strings.ReplaceAll(rawKey, "+", " "))
		if !ok {
			return "", errors.New("query parameter name has a malformed percent escape")
		}
		key := gwLower(dec)
		if seen[key] {
			return "", fmt.Errorf("duplicate query parameter '%s'", key)
		}
		seen[key] = true
	}
	sort.SliceStable(pairs, func(i, j int) bool { return gwU16Less(pairs[i], pairs[j]) })
	return strings.Join(pairs, "&"), nil
}

// GatewayRequestBinding is the canonical binding of a request an agent signs as its action params: upper-cased method, path,
// canonical query and optionally the authority and body hash.
func GatewayRequestBinding(req GatewayRequest, opts *GatewayBindOptions) (map[string]any, error) {
	if opts == nil {
		opts = &GatewayBindOptions{}
	}
	q, err := GatewayCanonicalQuery(req.Query)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"v": json.Number("2"), "method": strings.ToUpper(req.Method), "path": req.Path, "query": q}
	if opts.Authority {
		a := ""
		if req.Authority != nil {
			a = gwLower(*req.Authority)
		}
		b["authority"] = a
	}
	if (opts.Body != nil && *opts.Body) || (opts.Body == nil && req.BodySha256 != nil) {
		h := ""
		if req.BodySha256 != nil {
			h = gwLower(*req.BodySha256)
		}
		b["body_sha256"] = h
	}
	return b, nil
}

// GatewayBindParams is the params an agent signs for a full-policy gateway: the params plus the binding as a `binding` member.
func GatewayBindParams(params, binding map[string]any) (map[string]any, error) {
	if binding == nil {
		return params, nil
	}
	if _, has := params["binding"]; has {
		return nil, errors.New("params already have a 'binding' member")
	}
	out := make(map[string]any, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	out["binding"] = binding
	return out, nil
}

// GatewayAmbiguousPathReason says why a path is ambiguous for route matching (the upstream may route a different path), or "" and
// false when canonical.
func GatewayAmbiguousPathReason(path string) (string, bool) {
	for _, r := range path {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return "control character or backslash in path", true
		}
	}
	if strings.Contains(path, "//") {
		return "repeated slash in path", true
	}
	if strings.Contains(path, ";") {
		return "path parameter (;) in path", true
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return "dot segment in path", true
		}
	}
	for i := 0; i < len(path); {
		if path[i] == '%' && i+2 < len(path) {
			if code, ok := gwPercentByte(path, i); ok {
				switch {
				case code < 0x20 || code == 0x7f:
					return "percent-encoded control character in path", true
				case code == '/' || code == '\\':
					return "percent-encoded slash in path", true
				case code == ';':
					return "percent-encoded path parameter delimiter in path", true
				case code >= 'A' && code <= 'Z', code >= 'a' && code <= 'z', code >= '0' && code <= '9', code == '-', code == '.', code == '_', code == '~':
					return "non-canonical percent-encoding in path", true
				}
				i += 3
				continue
			}
		}
		i++
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '%' {
			if _, ok := gwPercentByte(path, i); !ok {
				return "malformed percent-encoding in path", true
			}
		}
	}
	return "", false
}

// ---- replay guard / provenance log --------------------------------------------------------------------------------------

type gwMemReplay struct {
	mu   sync.Mutex
	seen map[string]float64
	max  int
	now  func() float64
}

// GatewayMemoryReplayGuard is an in-process single-use store (per process: use a shared store for more than one instance). A
// claim stays live through its expiry inclusive. It fails closed (errors) when maxEntries unexpired claims are held.
func GatewayMemoryReplayGuard(maxEntries int, now func() float64) GatewayReplayGuard {
	if now == nil {
		now = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	return &gwMemReplay{seen: map[string]float64{}, max: maxEntries, now: now}
}

func (g *gwMemReplay) Claim(key string, expiresAtMs float64, nowMs *float64) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var t float64
	if nowMs != nil {
		t = *nowMs
	} else {
		t = g.now()
	}
	// a clock or expiry that is not finite cannot say whether a claim is still live: refuse
	if !finite(t) || !finite(expiresAtMs) {
		return false, errors.New("replay guard: the clock and the claim expiry must be finite numbers")
	}
	if len(g.seen) >= g.max {
		for k, exp := range g.seen {
			if exp < t {
				delete(g.seen, k)
			}
		}
		if len(g.seen) >= g.max {
			return false, errors.New("replay guard full")
		}
	}
	if existing, ok := g.seen[key]; ok && existing >= t {
		return false, nil
	}
	g.seen[key] = expiresAtMs
	return true, nil
}

// GatewayProvenanceLog is the gateway's per-session record of untrusted content it relayed: at most max sessions (oldest dropped
// first), 256 observations each.
type GatewayProvenanceLog struct {
	mu    sync.Mutex
	order []string
	m     map[string][]map[string]any
	max   int
}

func GatewayMemoryProvenanceLog(maxSessions int) *GatewayProvenanceLog {
	return &GatewayProvenanceLog{m: map[string][]map[string]any{}, max: maxSessions}
}

func (l *GatewayProvenanceLog) Seen(session string) []any {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []any{}
	for _, x := range l.m[session] {
		c := make(map[string]any, len(x))
		for k, v := range x {
			c[k] = v
		}
		out = append(out, c)
	}
	return out
}

func gwSameMember(a, b map[string]any, k string) bool {
	x, hx := a[k]
	y, hy := b[k]
	return hx == hy && (!hx || jsStrictEq(x, y))
}

func (l *GatewayProvenanceLog) Add(session string, o map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur, had := l.m[session]
	if had {
		for i, s := range l.order {
			if s == session {
				l.order = append(l.order[:i], l.order[i+1:]...)
				break
			}
		}
	}
	entry := map[string]any{}
	for _, k := range []string{"origin", "source"} {
		if v, ok := o[k]; ok {
			entry[k] = v
		}
	}
	dup := false
	for _, x := range cur {
		if gwSameMember(x, entry, "origin") && gwSameMember(x, entry, "source") {
			dup = true
			break
		}
	}
	if !dup && len(cur) < 256 {
		cur = append(cur, entry)
	}
	l.m[session] = cur
	l.order = append(l.order, session)
	for len(l.m) > l.max && len(l.order) > 0 {
		delete(l.m, l.order[0])
		l.order = l.order[1:]
	}
}

// ---- headers / extraction -----------------------------------------------------------------------------------------------

// GatewayHeader is a case-insensitive single-value lookup over a header map: the first key (in sorted order) that matches; a list
// reads as its first element. nil when absent.
func GatewayHeader(headers map[string]any, name string) any {
	lower := strings.ToLower(name)
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.ToLower(k) != lower {
			continue
		}
		switch v := headers[k].(type) {
		case []any:
			if len(v) == 0 {
				return nil
			}
			return v[0]
		case []string:
			if len(v) == 0 {
				return nil
			}
			return v[0]
		default:
			return v
		}
	}
	return nil
}

func gwDecodeHeader(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("PCA-Action header is not strict unpadded base64url")
	}
	b, ok := DecodeB64uStrict(s, -1)
	if !ok {
		return "", errors.New("PCA-Action header is not strict unpadded base64url")
	}
	if !utf8.Valid(b) {
		return "", errors.New("PCA-Action header does not decode to UTF-8 text")
	}
	return string(b), nil
}

func gwDecodePCActn(text string) (map[string]any, error) {
	if len(text) > MaxArtifactBytes { // FIRST: before any parsing
		return nil, errors.New(ArtifactSizeReason)
	}
	v, err := StrictParse(text)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("decodePCActn: not an object")
	}
	return m, nil
}

func gwExtractPCActn(headers map[string]any) (map[string]any, string, string) {
	raw := GatewayHeader(headers, GatewayPCAHeader)
	if raw == nil || raw == "" {
		return nil, "no-proof", "no " + GatewayPCAHeader + " header"
	}
	text, err := gwDecodeHeader(raw)
	if err == nil {
		var m map[string]any
		if m, err = gwDecodePCActn(text); err == nil {
			return m, "", ""
		}
	}
	return nil, "invalid-proof", "undecodable " + GatewayPCAHeader + " header: " + err.Error()
}

func gwBodyObject(req GatewayRequest) map[string]any {
	if req.Body == nil || *req.Body == "" {
		return nil
	}
	v, err := StrictParse(*req.Body)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// GatewayPresentedProvenance is the provenance bundle a request presents: header `PCA-Provenance` (strict base64url JSON), else
// body member `pca_provenance` when the body is not the signed params. GatewayAbsent when none; nil when presented but unreadable.
func GatewayPresentedProvenance(req GatewayRequest, policy *GatewayFullPolicy) any {
	if h := GatewayHeader(req.Headers, "pca-provenance"); h != nil && h != "" {
		text, err := gwDecodeHeader(h)
		if err != nil {
			return nil
		}
		v, err := StrictParse(text)
		if err != nil {
			return nil
		}
		return v
	}
	if policy != nil && policy.ParamsFn != nil {
		if b := gwBodyObject(req); b != nil {
			if v, ok := b["pca_provenance"]; ok {
				return v
			}
		}
	}
	return GatewayAbsent
}

// GatewayPresentedArtifacts is the discharges and narrow block a request presents (headers, then body members when the body is not
// the signed params).
func GatewayPresentedArtifacts(req GatewayRequest, policy *GatewayFullPolicy) map[string]any {
	out := map[string]any{}
	if d := GatewayHeader(req.Headers, "pca-discharges"); d != nil && d != "" {
		if text, err := gwDecodeHeader(d); err == nil {
			if v, err := StrictParse(text); err == nil {
				if arr, ok := v.([]any); ok {
					out["discharges"] = arr
				}
			}
		}
	}
	if n := GatewayHeader(req.Headers, "pca-narrow"); n != nil && n != "" {
		if text, err := gwDecodeHeader(n); err == nil {
			if v, err := StrictParse(text); err == nil {
				out["narrow"] = v
			}
		}
	}
	if policy != nil && policy.ParamsFn != nil {
		if b := gwBodyObject(req); b != nil {
			if _, has := out["discharges"]; !has {
				if arr, ok := b["pca_discharges"].([]any); ok {
					out["discharges"] = arr
				}
			}
			if _, has := out["narrow"]; !has {
				if v, ok := b["pca_narrow"]; ok {
					out["narrow"] = v
				}
			}
		}
	}
	return out
}

// ---- routes / decisions -------------------------------------------------------------------------------------------------

func gwMatchMethod(r GatewayRoute, method string) bool {
	if r.Method == nil || *r.Method == "*" || strings.EqualFold(*r.Method, "ANY") {
		return true
	}
	return strings.ToUpper(*r.Method) == strings.ToUpper(method)
}

func gwMatchPath(pattern, path string) bool {
	switch {
	case pattern == "*" || pattern == "/*":
		return true
	case strings.HasSuffix(pattern, "/*"):
		prefix := pattern[:len(pattern)-2]
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(path, pattern[:len(pattern)-1])
	}
	return path == pattern
}

var gwErrorToken = map[string]string{
	"no-proof": "missing_proof", "invalid-proof": "invalid_proof", "unknown-grant": "invalid_proof",
	"verify-failed": "invalid_proof", "wrong-audience": "invalid_resource", "insufficient-capability": "insufficient_capability",
	"unmapped-route": "access_denied", "invalid-path": "invalid_request", "replayed-proof": "replayed_proof",
	"replay-guard-unavailable": "temporarily_unavailable", "request-mismatch": "proof_not_bound_to_request",
	"proof-rejected": "access_denied",
}

func gwDeny(code string, status int, reason, realm string) GatewayDecision {
	return GatewayDecision{Status: status, Code: code, Reason: reason,
		Headers: map[string]string{"www-authenticate": fmt.Sprintf("PCA realm=\"%s\", error=\"%s\"", realm, gwErrorToken[code])}}
}

func gwAllow(reason string, verdict *GatewayVerdict, pcactn map[string]any, matched *GatewayCapability, pv map[string]any) GatewayDecision {
	h := map[string]string{}
	if verdict != nil {
		h["x-pca-verdict"] = verdict.json()
	}
	if pcactn != nil {
		verb, _ := gwStr(gwGet(pcactn["action"], "verb"))
		ref, _ := gwStr(pcactn["grant_ref"])
		h["x-pca-verb"] = verb
		h["x-pca-grant"] = ref
	}
	return GatewayDecision{Allow: true, Status: 200, Code: "allow", Reason: reason, Headers: h, Verdict: verdict, PCActn: pcactn, Matched: matched, PolicyVerdict: pv}
}

func (d GatewayDecision) with(v *GatewayVerdict, p map[string]any) GatewayDecision {
	d.Verdict, d.PCActn = v, p
	return d
}

func gwMissingText(o *GatewayOptions, missing []string) string {
	who := "the gateway"
	if o.PolicyMode != "" && o.PolicyMode != "signature-only" {
		who = "full policy mode"
	}
	return who + " is missing " + strings.Join(missing, ", ")
}

func gwMissingPolicy(o *GatewayOptions) []string {
	switch o.PolicyMode {
	case "":
		return []string{"policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"}
	case "signature-only":
		var m []string
		if o.ReplayGuard == nil {
			m = append(m, "replayGuard (signature-only mode needs a single-use guard)")
		}
		rc := o.RequireChecks
		if rc == nil {
			rc = GatewayDefaultRequireChecks
		}
		for _, c := range rc {
			if c == "revocation" && o.Revocation == nil {
				m = append(m, "hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)")
				break
			}
		}
		return m
	case "full":
		var m []string
		if o.Audience == "" {
			m = append(m, "audience")
		}
		if o.ResolveGrant == nil {
			m = append(m, "resolveGrant")
		}
		f := o.Full
		if f == nil || f.Input.StateStore == nil {
			m = append(m, "state")
		}
		if f == nil || f.Input.IsRevoked == nil {
			m = append(m, "isRevoked")
		}
		if f == nil || (!f.ParamsBody && f.ParamsFn == nil) {
			m = append(m, "params ('body' or a function)")
		}
		return m
	}
	return []string{"a known policy mode (got '" + o.PolicyMode + "')"}
}

// gwSignedParams: full-policy mode, the params the agent must have signed for this request (or an error text).
func gwSignedParams(req GatewayRequest, f *GatewayFullPolicy, bind *GatewayBindOptions, off bool) (map[string]any, string) {
	var params map[string]any
	if f.ParamsBody {
		if req.Body == nil {
			return nil, "full policy mode reads the params from the body, and the request carries none"
		}
		v, err := StrictParse(*req.Body)
		if err != nil {
			return nil, "the body is not strict JSON: " + err.Error()
		}
		params, _ = v.(map[string]any)
	} else {
		p, err := f.ParamsFn(req)
		if err != nil {
			return nil, "the params function failed: " + err.Error()
		}
		params = p
	}
	if params == nil {
		return nil, "the request params are not a JSON object"
	}
	if off {
		return params, ""
	}
	if bind == nil {
		bind = &GatewayBindOptions{}
	}
	if _, has := params["binding"]; has {
		return nil, "the request params carry a 'binding' member (reserved for the request binding)"
	}
	bodyOn := bind.Body != nil && *bind.Body
	if (bind.Authority && !gwNonEmpty(req.Authority)) || (bodyOn && !gwNonEmpty(req.BodySha256)) {
		return nil, "request lacks an attribute the proof must bind (authority / body hash)"
	}
	binding, err := GatewayRequestBinding(req, &GatewayBindOptions{Authority: bind.Authority, Body: &bodyOn})
	if err != nil {
		return nil, "the request cannot be bound: " + err.Error()
	}
	out, _ := GatewayBindParams(params, binding)
	return out, ""
}

// gwStatuses maps the core verdict's checks onto the reference vocabulary: pass / fail / not-enforced.
func gwStatuses(v Verdict, revocation string) map[string]string {
	st := map[string]string{}
	for k, ok := range v.Checks {
		name := k
		if k == "chain" {
			name = "cap_chain"
		}
		if ok {
			st[name] = "pass"
		} else {
			st[name] = "fail"
		}
	}
	for k := range v.NotEnforced {
		st[k] = "not-enforced"
	}
	st["attestation"] = "not-enforced"
	st["threshold"] = "not-enforced"
	st["revocation"] = revocation
	if _, has := st["taint_gate"]; !has {
		st["taint_gate"] = "not-enforced"
	}
	return st
}

func gwVerify(pcactn, grant map[string]any, o *GatewayOptions, now int64) (verdict *GatewayVerdict, wireOK, audOK bool) {
	vo := VerifyOptions{AuthorizedPlanRoots: o.AuthorizedPlanRoots, InsecureSkipPlanRootCheck: o.InsecureSkipPlanRootCheck,
		EnforceFreshness: o.EnforceFreshness, EnforceTaint: o.EnforceTaint}
	v, err := VerifyPCActnCoreWith(pcactn, grant, now, o.Audience, vo)
	allow, reason := v.Allow, v.Reason
	if err != nil {
		allow, reason = false, err.Error()
	}
	revocation := "not-enforced"
	if o.Revocation != nil && v.Checks["wire"] {
		res, herr := gwRunRevocation(o, pcactn, grant, now)
		switch {
		case herr != nil:
			revocation = "fail"
			if allow || reason == "" {
				reason = "malformed PCActn: " + herr.Error()
			}
			allow = false
		case !res.Enforced:
		case res.OK:
			revocation = "pass"
		default:
			revocation = "fail"
			if allow || reason == "" {
				if res.Reason != nil {
					reason = "revocation: " + *res.Reason
				} else {
					reason = "revocation: rejected"
				}
			}
			allow = false
		}
	}
	return &GatewayVerdict{Allow: allow, Checks: gwStatuses(v, revocation), Reason: reason}, v.Checks["wire"], v.Checks["audience"]
}

func gwRunRevocation(o *GatewayOptions, pcactn, grant map[string]any, now int64) (res GatewayHookResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return o.Revocation(pcactn, grant, now)
}

func gwCheckProof(o *GatewayOptions, ctx GatewayProofContext) (allow bool, reason string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return o.CheckProof(ctx)
}

func gwNumber(v any) float64 { f, _ := jsNum(v); return f }

// GatewayAuthorize is the framework-agnostic core: extract the PCActn, map the request to the capability its route requires,
// verify (fail closed), enforce audience, capability, request binding, required checks, the proof hook, the policy and single use.
func GatewayAuthorize(req GatewayRequest, o *GatewayOptions) GatewayDecision {
	realm := o.Audience
	if o.Realm != nil {
		realm = *o.Realm
	}
	unmatched := o.UnmatchedRoute
	if unmatched == "" {
		unmatched = "deny"
	}

	// 0. an ambiguous request target is never matched against the route map
	if o.PathPolicy == "" || o.PathPolicy == "strict" {
		if bad, ambiguous := GatewayAmbiguousPathReason(req.Path); ambiguous {
			return gwDeny("invalid-path", 400, bad, realm)
		}
	}

	// 1. route -> required capability; an unmapped route follows UnmatchedRoute (default deny)
	var rule *GatewayRoute
	for i := range o.Routes {
		if gwMatchMethod(o.Routes[i], req.Method) && gwMatchPath(o.Routes[i].Path, req.Path) {
			rule = &o.Routes[i]
			break
		}
	}
	if rule == nil {
		switch unmatched {
		case "allow":
			return gwAllow(fmt.Sprintf("route %s %s is unmapped (unmatchedRoute=allow)", req.Method, req.Path), nil, nil, nil, nil)
		case "deny":
			return gwDeny("unmapped-route", 403, fmt.Sprintf("no capability mapping for %s %s (deny-by-default)", req.Method, req.Path), realm)
		}
	}
	var required *GatewayCapability
	if rule != nil {
		c := rule.Capability
		required = &c
	}

	// 2. the proof (fail closed)
	pcactn, code, why := gwExtractPCActn(req.Headers)
	if pcactn == nil {
		return gwDeny(code, 401, why, realm)
	}

	// 3. the grant the chain must root in
	grantRef := pcactn["grant_ref"]
	var grant map[string]any
	if o.ResolveGrant != nil {
		grant = o.ResolveGrant(grantRef, pcactn)
	}
	if grant == nil {
		ref := "undefined"
		if _, has := pcactn["grant_ref"]; has {
			ref = gwToString(grantRef)
		}
		return gwDeny("unknown-grant", 401, "unknown grant_ref "+ref, realm).with(nil, pcactn)
	}

	// 3b. a configuration with a missing component denies every request (fail closed)
	if missing := gwMissingPolicy(o); len(missing) > 0 {
		return gwDeny("proof-rejected", 403, gwMissingText(o, missing)+" (fail closed)", realm).with(nil, pcactn)
	}

	// 4. offline verification, the audience bound to THIS gateway
	var now int64
	if o.Now != nil {
		now = o.Now()
	} else {
		now = time.Now().UnixMilli()
	}
	verdict, wireOK, audOK := gwVerify(pcactn, grant, o, now)
	if !verdict.Allow {
		audFailed := wireOK && !audOK
		r := verdict.Reason
		if r == "" {
			r = "PCActn verification failed"
		}
		if audFailed {
			return gwDeny("wrong-audience", 403, r, realm).with(verdict, pcactn)
		}
		return gwDeny("verify-failed", 401, r, realm).with(verdict, pcactn)
	}
	denyV := func(code string, status int, reason string) GatewayDecision {
		return gwDeny(code, status, reason, realm).with(verdict, pcactn)
	}

	// 5. capability enforcement: the verified proof carries the verb (+ resource) the route requires
	actionVerb, _ := gwStr(gwGet(pcactn["action"], "verb"))
	actionRes, _ := gwStr(gwGet(pcactn["action"], "resource"))
	actionDigest, _ := gwStr(gwGet(pcactn["action"], "params_digest"))
	if required != nil {
		if actionVerb != required.Verb {
			d := denyV("insufficient-capability", 403, fmt.Sprintf("route requires capability '%s' but the proof authorizes '%s'", required.Verb, actionVerb))
			d.Matched = required
			return d
		}
		if required.Resource != nil && actionRes != *required.Resource {
			d := denyV("insufficient-capability", 403, fmt.Sprintf("route is bound to resource '%s' but the proof targets '%s'", *required.Resource, actionRes))
			d.Matched = required
			return d
		}
	}

	full := o.PolicyMode == "full"
	var fullParams map[string]any
	if full {
		// 5b (full). the agent signed the real params plus the request binding: rebuild them from THIS request
		params, errText := gwSignedParams(req, o.Full, o.BindRequest, o.BindRequestOff)
		if errText != "" {
			return denyV("request-mismatch", 403, errText)
		}
		dg, err := ParamsDigest(params)
		if err != nil || actionDigest != dg {
			return denyV("request-mismatch", 403, "the proof is not bound to this request (params/method/path/query/authority)")
		}
		fullParams = params
	} else if !o.BindRequestOff {
		// 5b. request binding: the signed params digest must be the digest of THIS request
		b := o.BindRequest
		if b == nil {
			b = &GatewayBindOptions{}
		}
		if (b.Authority && !gwNonEmpty(req.Authority)) || (b.Body != nil && *b.Body && !gwNonEmpty(req.BodySha256)) {
			return denyV("request-mismatch", 403, "request lacks an attribute the proof must bind (authority / body hash)")
		}
		binding, err := GatewayRequestBinding(req, b)
		if err != nil {
			return denyV("request-mismatch", 403, "the request cannot be bound: "+err.Error())
		}
		bound, err := ParamsDigest(binding)
		if err != nil {
			return denyV("request-mismatch", 403, "the request cannot be bound: "+err.Error())
		}
		if actionDigest != bound {
			return denyV("request-mismatch", 403, "the proof is not bound to this request (method/path/query/authority/body)")
		}
	}

	// 5c. required checks must have PASSED (not merely "not-enforced"); full mode takes revocation from IsRevoked
	rc := o.RequireChecks
	if rc == nil && !full {
		rc = GatewayDefaultRequireChecks
	}
	for _, c := range rc {
		if verdict.Checks[c] != "pass" {
			st, has := verdict.Checks[c]
			if !has {
				st = "absent"
			}
			return denyV("proof-rejected", 403, fmt.Sprintf("required check '%s' is %s", c, st))
		}
	}

	// 5d. per-proof policy hook (limits, budgets, revocation lists); an error denies
	if o.CheckProof != nil {
		ok, reason, err := gwCheckProof(o, GatewayProofContext{PCActn: pcactn, Grant: grant, Verdict: verdict, Request: req, Required: required})
		if err != nil {
			return denyV("proof-rejected", 403, "checkProof failed: "+err.Error())
		}
		if !ok {
			if reason == "" {
				reason = "rejected by checkProof"
			}
			return denyV("proof-rejected", 403, reason)
		}
	}

	// 5e. full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget
	var policyVerdict map[string]any
	if full {
		in := o.Full.Input
		in.Audience = o.Audience
		in.ResolveGrant = func(string) (map[string]any, error) { return grant, nil }
		in.Now = now
		op := &Operation{Verb: actionVerb, Resource: actionRes, Params: fullParams}
		if required != nil {
			op.Verb = required.Verb
			if required.Resource != nil {
				op.Resource = *required.Resource
			}
		}
		in.Operation = op
		res := Authorize(pcactn, in)
		if !res.Allow {
			c := "proof-rejected"
			switch {
			case res.Checks["replay"] == "fail":
				c = "replayed-proof"
			case res.Checks["operation"] == "fail":
				c = "insufficient-capability"
			case res.Status == 401:
				c = "verify-failed"
			}
			r := res.Reason
			if r == "" {
				r = "rejected"
			}
			d := denyV(c, res.Status, r)
			d.PolicyVerdict = map[string]any{"allow": false, "checks": res.Checks, "reason": res.Reason}
			return d
		}
		policyVerdict = map[string]any{"allow": true, "checks": res.Checks}
	}

	// 6. single use, only for a proof that would otherwise be allowed (a denied attempt never burns it)
	if o.ReplayGuard != nil {
		ref, _ := gwStr(pcactn["grant_ref"])
		sig, _ := gwStr(pcactn["sig"])
		nowF := float64(now)
		first, err := o.ReplayGuard.Claim(ref+":"+sig, gwNumber(pcactn["exp"]), &nowF)
		if err != nil {
			return denyV("replay-guard-unavailable", 503, "replay guard unavailable: "+err.Error())
		}
		if !first {
			return denyV("replayed-proof", 403, "this proof has already been used")
		}
	}

	reason := "proof-carrying action verified"
	if policyVerdict != nil {
		reason = "proof-carrying action authorized (full policy)"
	}
	return gwAllow(reason, verdict, pcactn, required, policyVerdict)
}

// GatewayCreate returns a reusable authorizer bound to one frozen configuration. It errors when a component is missing.
func GatewayCreate(o GatewayOptions) (func(GatewayRequest) GatewayDecision, error) {
	if missing := gwMissingPolicy(&o); len(missing) > 0 {
		return nil, errors.New("pca-gateway: " + gwMissingText(&o, missing))
	}
	frozen := o
	frozen.Routes = append([]GatewayRoute(nil), o.Routes...)
	if o.AuthorizedPlanRoots != nil {
		frozen.AuthorizedPlanRoots = append([]string{}, o.AuthorizedPlanRoots...)
	}
	return func(req GatewayRequest) GatewayDecision { return GatewayAuthorize(req, &frozen) }, nil
}

// GatewayProxy joins a gateway to an injected upstream: on allow, upstream is called with every client-supplied x-pca-* header
// removed and the decision's headers set; on deny the 401 / 403 response is returned and the upstream is never called.
func GatewayProxy(o GatewayOptions, upstream func(req GatewayRequest, d GatewayDecision) (any, error)) (func(GatewayRequest) (any, error), error) {
	gw, err := GatewayCreate(o)
	if err != nil {
		return nil, err
	}
	return func(req GatewayRequest) (any, error) {
		d := gw(req)
		if !d.Allow {
			return gwDenyResponse(d), nil
		}
		hdrs := map[string]any{}
		for k, v := range req.Headers {
			if l := strings.ToLower(k); l != "x-pca-verdict" && l != "x-pca-verb" && l != "x-pca-grant" {
				hdrs[k] = v
			}
		}
		for k, v := range d.Headers {
			hdrs[k] = v
		}
		req.Headers = hdrs
		return upstream(req, d)
	}, nil
}

func gwHeaderAny(h map[string]string) map[string]any {
	out := make(map[string]any, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

func gwDenyResponse(d GatewayDecision) map[string]any {
	h := gwHeaderAny(d.Headers)
	h["content-type"] = "application/json"
	return map[string]any{"status": d.Status, "headers": h, "body": gwErrorBody(d.Code, d.Reason)}
}

// ---- Envoy HTTP ext_authz -----------------------------------------------------------------------------------------------

func gwQueryOfTarget(target string) string {
	q := strings.IndexByte(target, '?')
	if q < 0 {
		return ""
	}
	rest := target[q+1:]
	if h := strings.IndexByte(rest, '#'); h >= 0 {
		return rest[:h]
	}
	return rest
}

func gwEnvoyRequest(check map[string]any) GatewayRequest {
	headers := gwHeaders(check["headers"])
	method := gwToString(gwFirst(check["method"], headers[":method"], "*"))
	target := gwToString(gwFirst(check["path"], headers[":path"], "/"))
	rawPath := target
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		rawPath = target[:i]
	}
	if rawPath == "" {
		rawPath = "/"
	}
	q := gwQueryOfTarget(target)
	req := GatewayRequest{Method: method, Path: rawPath, Query: &q, Headers: headers}
	if a := gwFirst(check["authority"], headers[":authority"]); a != nil {
		s := gwToString(a)
		req.Authority = &s
	}
	if check["body"] != nil {
		s := gwToString(check["body"])
		req.Body = &s
	}
	return req
}

// GatewayEnvoyExtAuthz is the Envoy HTTP ext_authz handler: 200 plus the verified verdict headers on allow (every injected header
// is overwritten, the unset ones blank), the guard's 401 / 403 with a WWW-Authenticate challenge and a JSON body on deny.
func GatewayEnvoyExtAuthz(o GatewayOptions) (func(map[string]any) map[string]any, error) {
	gw, err := GatewayCreate(o)
	if err != nil {
		return nil, err
	}
	return func(c map[string]any) map[string]any {
		d := gw(gwEnvoyRequest(c))
		if !d.Allow {
			return gwDenyResponse(d)
		}
		h := map[string]any{}
		for _, k := range GatewayInjectedHeaders {
			h[k] = ""
		}
		for k, v := range d.Headers {
			h[k] = v
		}
		return map[string]any{"status": 200, "headers": h, "body": ""}
	}, nil
}

// ---- Envoy gRPC ext_authz -----------------------------------------------------------------------------------------------

const (
	GatewayGrpcOK               = 0
	GatewayGrpcUnauthenticated  = 16
	GatewayGrpcPermissionDenied = 7
	GatewayGrpcUnavailable      = 14
	gwOverwriteIfExistsOrAdd    = 2
)

// gwHeaderOptions lists headers in a fixed order (the well-known ones first) so the gRPC response is deterministic.
func gwHeaderOptions(h map[string]string) []any {
	order := []string{"content-type", "www-authenticate", "x-pca-verdict", "x-pca-verb", "x-pca-grant"}
	var keys []string
	for _, k := range order {
		if _, ok := h[k]; ok {
			keys = append(keys, k)
		}
	}
	var rest []string
	for k := range h {
		known := false
		for _, o := range order {
			known = known || o == k
		}
		if !known {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	out := []any{}
	for _, k := range append(keys, rest...) {
		out = append(out, map[string]any{"header": map[string]any{"key": k, "value": h[k]}, "appendAction": gwOverwriteIfExistsOrAdd})
	}
	return out
}

// GatewayEnvoyGrpcExtAuthz is the Envoy gRPC ext_authz `Check` handler over a decoded CheckRequest map (camelCase). On allow it
// also lists every x-pca-* header it did not set in `headersToRemove`, so a client cannot smuggle a forged verdict through an
// unmapped-route allow.
func GatewayEnvoyGrpcExtAuthz(o GatewayOptions) (func(map[string]any) map[string]any, error) {
	gw, err := GatewayCreate(o)
	if err != nil {
		return nil, err
	}
	return func(c map[string]any) map[string]any {
		http := gwGet(gwGet(gwGet(c, "attributes"), "request"), "http")
		if !jsTruthy(http) {
			return map[string]any{"status": map[string]any{"code": GatewayGrpcPermissionDenied, "message": "no http request attributes"},
				"deniedResponse": map[string]any{"status": map[string]any{"code": 403}, "headers": []any{},
					"body": gwErrorBody("invalid-request", "CheckRequest carried no HTTP attributes")}}
		}
		headers := gwHeaders(gwGet(http, "headers"))
		check := map[string]any{"headers": headers}
		if m := gwFirst(gwGet(http, "method"), headers[":method"]); m != nil {
			check["method"] = m
		}
		if p := gwFirst(gwGet(http, "path"), headers[":path"]); p != nil {
			check["path"] = p
		}
		if a := gwFirst(gwGet(http, "host"), headers[":authority"]); a != nil {
			check["authority"] = a
		}
		if b := gwGet(http, "body"); b != nil {
			check["body"] = b
		}
		d := gw(gwEnvoyRequest(check))
		if d.Allow {
			remove := []any{}
			for _, h := range GatewayInjectedHeaders {
				if _, set := d.Headers[h]; !set {
					remove = append(remove, h)
				}
			}
			return map[string]any{"status": map[string]any{"code": GatewayGrpcOK, "message": ""},
				"okResponse": map[string]any{"headers": gwHeaderOptions(d.Headers), "headersToRemove": remove}}
		}
		code := GatewayGrpcPermissionDenied
		switch d.Status {
		case 401:
			code = GatewayGrpcUnauthenticated
		case 503:
			code = GatewayGrpcUnavailable
		}
		h := map[string]string{"content-type": "application/json"}
		for k, v := range d.Headers {
			h[k] = v
		}
		return map[string]any{"status": map[string]any{"code": code, "message": d.Reason},
			"deniedResponse": map[string]any{"status": map[string]any{"code": d.Status}, "headers": gwHeaderOptions(h), "body": gwErrorBody(d.Code, d.Reason)}}
	}, nil
}

// ---- AWS Lambda authorizers ---------------------------------------------------------------------------------------------

// gwEncodeURIComponent is encodeURIComponent; a lone surrogate is an error ("URI malformed").
func gwEncodeURIComponent(v any) (string, error) {
	s := gwToString(v)
	if hasLoneSurrogate(s) {
		return "", errors.New("URI malformed")
	}
	const hexd = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&15])
		}
	}
	return sb.String(), nil
}

func gwLambdaMethodPath(event map[string]any) (string, string) {
	http := gwGet(gwGet(event, "requestContext"), "http")
	method := gwFirst(gwGet(http, "method"), event["httpMethod"])
	path := gwFirst(event["rawPath"], event["path"], gwGet(http, "path"))
	if method != nil && path != nil {
		return gwToString(method), gwToString(path)
	}
	if arn := gwFirst(event["methodArn"], event["routeArn"]); arn != nil {
		fields := strings.Split(gwToString(arn), ":")
		rest := ""
		if len(fields) > 5 {
			rest = strings.Join(fields[5:], ":")
		}
		parts := strings.Split(rest, "/")
		var arnMethod any
		if len(parts) > 2 {
			arnMethod = strings.Split(parts[2], " ")[0]
		}
		extra := ""
		if len(parts) > 3 {
			extra = strings.Join(parts[3:], "/")
		}
		return gwToString(gwFirst(method, arnMethod, "*")), gwToString(gwFirst(path, "/"+extra))
	}
	return gwToString(gwFirst(method, "*")), gwToString(gwFirst(path, "/"))
}

func gwLambdaQuery(event map[string]any) (string, error) {
	if raw, ok := event["rawQueryString"].(string); ok {
		return raw, nil
	}
	var pairs []string
	add := func(k string, v any) error {
		ek, err := gwEncodeURIComponent(k)
		if err != nil {
			return err
		}
		ev, err := gwEncodeURIComponent(v)
		if err != nil {
			return err
		}
		pairs = append(pairs, ek+"="+ev)
		return nil
	}
	if multi, ok := event["multiValueQueryStringParameters"].(map[string]any); ok {
		for k, vs := range multi {
			l, _ := vs.([]any)
			for _, v := range l {
				if err := add(k, v); err != nil {
					return "", err
				}
			}
		}
	} else if single, ok := event["queryStringParameters"].(map[string]any); ok {
		for k, v := range single {
			if err := add(k, v); err != nil {
				return "", err
			}
		}
	}
	return strings.Join(pairs, "&"), nil
}

func gwLambdaRequest(event map[string]any) (GatewayRequest, error) {
	m, p := gwLambdaMethodPath(event)
	q, err := gwLambdaQuery(event)
	if err != nil {
		return GatewayRequest{}, err
	}
	return GatewayRequest{Method: m, Path: p, Query: &q, Headers: gwHeaders(event["headers"])}, nil
}

func gwLambdaContext(d GatewayDecision) map[string]any {
	if d.Allow {
		if d.Verdict != nil {
			return map[string]any{"pcaVerdict": d.Verdict.json()}
		}
		return map[string]any{}
	}
	return map[string]any{"pcaDenied": "true", "pcaCode": d.Code, "pcaReason": d.Reason, "pcaStatus": strconv.Itoa(d.Status)}
}

// GatewayLambdaAuthorizer is the AWS API Gateway REQUEST authorizer: an Allow IAM policy (verdict on context.pcaVerdict) on a valid
// proof, else a Deny policy. REST (`methodArn`) and HTTP-API (`routeArn`) payloads.
func GatewayLambdaAuthorizer(o GatewayOptions) (func(map[string]any) (map[string]any, error), error) {
	gw, err := GatewayCreate(o)
	if err != nil {
		return nil, err
	}
	return func(event map[string]any) (map[string]any, error) {
		req, err := gwLambdaRequest(event)
		if err != nil {
			return nil, err
		}
		d := gw(req)
		effect := "Deny"
		if d.Allow {
			effect = "Allow"
		}
		var principal any = "anonymous"
		if d.PCActn != nil && d.PCActn["grant_ref"] != nil {
			principal = d.PCActn["grant_ref"]
		}
		return map[string]any{"principalId": principal,
			"policyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{
				map[string]any{"Action": "execute-api:Invoke", "Effect": effect, "Resource": gwToString(gwFirst(event["methodArn"], event["routeArn"], "*"))}}},
			"context": gwLambdaContext(d)}, nil
	}, nil
}

// GatewayLambdaSimpleAuthorizer is the HTTP-API simple-response variant: {isAuthorized, context} instead of an IAM policy.
func GatewayLambdaSimpleAuthorizer(o GatewayOptions) (func(map[string]any) (map[string]any, error), error) {
	gw, err := GatewayCreate(o)
	if err != nil {
		return nil, err
	}
	return func(event map[string]any) (map[string]any, error) {
		req, err := gwLambdaRequest(event)
		if err != nil {
			return nil, err
		}
		d := gw(req)
		return map[string]any{"isAuthorized": d.Allow, "context": gwLambdaContext(d)}, nil
	}, nil
}
