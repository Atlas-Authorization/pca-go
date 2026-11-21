package pca

// SCIM 2.0 agent provisioning (port of the TypeScript @atlasauth/pca-scim): an attested agent passport is projected as a SCIM
// `Agent` resource (id = the passport fingerprint, so a directory can only provision what is attested), a /Agents handler
// (create / list with `attr eq "value"` filters and paging / get / PUT / PATCH / DELETE, authentication required unless
// explicitly opted out), and push adapters to Entra and Okta. Resources are JSON values (map[string]any).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	AgentSchemaURN         = "urn:ietf:params:scim:schemas:atlas:2.0:Agent"
	ScimListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ScimPatchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ScimErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
	EntraAgentExtensionURN = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent"
	OktaAgentExtensionURN  = "urn:okta:scim:schemas:custom:1.0:Agent"
	scimContentType        = "application/scim+json"
	scimAgentResourceType  = "Agent"
)

// ScimError is a SCIM error with its scimType (invalidSyntax, invalidValue, invalidFilter, mutability, noTarget).
type ScimError struct {
	ScimType string
	Detail   string
}

func (e *ScimError) Error() string { return e.Detail }

func scimErr(t, d string) error { return &ScimError{ScimType: t, Detail: d} }

// ScimMetaInput: nil pointers are absent (BaseURL: no prefix; Created / LastModified: the clock).
type ScimMetaInput struct {
	BaseURL      *string
	Created      *string
	LastModified *string
	Now          func() float64 // epoch ms; nil = the wall clock
}

// jsISOString is Date.prototype.toISOString of an epoch-ms value (TimeClip truncation; RangeError outside +-8.64e15).
func jsISOString(ms float64) (string, error) {
	if !finite(ms) || math.Abs(ms) > 8.64e15 {
		return "", errors.New("Invalid time value")
	}
	t := time.UnixMilli(int64(math.Trunc(ms)) + 0).UTC()
	y := t.Year()
	ys := fmt.Sprintf("%04d", y)
	if y < 0 || y > 9999 {
		sign := "+"
		if y < 0 {
			sign, y = "-", -y
		}
		ys = sign + fmt.Sprintf("%06d", y)
	}
	return ys + t.Format("-01-02T15:04:05.000Z"), nil
}

func (m ScimMetaInput) iso() (string, error) {
	now := float64(time.Now().UnixMilli())
	if m.Now != nil {
		now = m.Now()
	}
	return jsISOString(now)
}

func passportDefaultName(p map[string]any) string {
	return jsMemberString(p, "model_id") + " (" + jsMemberString(p, "operator") + ")"
}

// PassportToScim projects a passport as a SCIM Agent. proj members: owner, displayName?, externalId?, active?, capabilities?,
// holder? (a null displayName / active / capabilities takes the default; a null externalId / holder is kept).
func PassportToScim(passport, proj map[string]any, meta ScimMetaInput) (map[string]any, error) {
	id := passport["id"]
	base := map[string]any{"schemas": []any{AgentSchemaURN}, "passportRef": id, "passport": passport, "displayName": proj["displayName"],
		"active": proj["active"], "capabilities": []any{}}
	if _, has := passport["id"]; !has {
		delete(base, "passportRef")
	} else {
		base["id"] = id
	}
	if base["displayName"] == nil {
		base["displayName"] = passportDefaultName(passport)
	}
	if base["active"] == nil {
		base["active"] = true
	}
	o, hasOwner := proj["owner"]
	if !hasOwner { // the reference builds `owner: proj.owner` (undefined) and its canonicalizer refuses the member
		return nil, errors.New("canonicalize: unsupported type undefined")
	}
	base["owner"] = o
	if c, ok := proj["capabilities"].([]any); ok {
		base["capabilities"] = append([]any{}, c...)
	}
	for _, k := range []string{"externalId", "holder"} {
		if v, has := proj[k]; has {
			base[k] = v
		}
	}
	prefix := ""
	if meta.BaseURL != nil {
		prefix = strings.TrimRight(*meta.BaseURL, "/")
	}
	version, err := HashCanonical(base)
	if err != nil {
		return nil, err
	}
	m := map[string]any{"resourceType": scimAgentResourceType, "location": prefix + "/Agents/" + encodeURIComponent(jsMemberString(passport, "id")),
		"version": `W/"` + version + `"`}
	for _, k := range []string{"created", "lastModified"} { // in this order: a ticking clock is read once per member
		p := meta.Created
		if k == "lastModified" {
			p = meta.LastModified
		}
		if p != nil {
			m[k] = *p
			continue
		}
		s, err := meta.iso()
		if err != nil {
			return nil, err
		}
		m[k] = s
	}
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out["meta"] = m
	return out, nil
}

func asRecord(v any) map[string]any { m, _ := v.(map[string]any); return m }

func asBool(v any) (bool, bool) {
	switch v {
	case true, "true":
		return true, true
	case false, "false":
		return false, true
	}
	return false, false
}

func setStr(dst map[string]any, k string, v any) {
	if s, ok := v.(string); ok {
		dst[k] = s
	}
}

func scimReadIdentity(body map[string]any) (map[string]any, error) {
	if nested := asRecord(body["passport"]); nested != nil {
		mid, ok1 := nested["model_id"].(string)
		op, ok2 := nested["operator"].(string)
		if !ok1 || !ok2 {
			return nil, scimErr("invalidValue", "passport.model_id and passport.operator are required")
		}
		hw, _ := asBool(nested["hardware_rooted"])
		id := map[string]any{"model_id": mid, "operator": op, "hardware_rooted": hw, "issued_at": jsNumber(0)}
		if _, ok := jsNum(nested["issued_at"]); ok {
			id["issued_at"] = nested["issued_at"]
		}
		for _, k := range []string{"weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"} {
			setStr(id, k, nested[k])
		}
		if b, ok := asBool(nested["weights_measured"]); ok {
			id["weights_measured"] = b
		}
		return id, nil
	}
	mid, ok := body["model"].(string)
	if !ok {
		mid, ok = body["model_id"].(string)
	}
	op, ok2 := body["operator"].(string)
	if !ok || !ok2 {
		return nil, scimErr("invalidValue", "an Agent requires either a `passport` object or `model` + `operator`")
	}
	hw, _ := asBool(body["hardwareRooted"])
	return map[string]any{"model_id": mid, "operator": op, "hardware_rooted": hw, "issued_at": jsNumber(0)}, nil
}

func scimReadProjection(body map[string]any) map[string]any {
	owner := ""
	for _, v := range []any{body["owner"], body["operator"], asRecord(body["passport"])["operator"]} {
		if s, ok := v.(string); ok {
			owner = s
			break
		}
	}
	proj := map[string]any{"owner": owner}
	setStr(proj, "displayName", body["displayName"])
	setStr(proj, "externalId", body["externalId"])
	if b, ok := asBool(body["active"]); ok {
		proj["active"] = b
	}
	if isStrArray(body["capabilities"]) {
		proj["capabilities"] = body["capabilities"]
	}
	setStr(proj, "holder", body["holder"])
	return proj
}

// ScimToProvisioningRequest reads a SCIM create body: {identity, projection} or a *ScimError.
func ScimToProvisioningRequest(value any) (map[string]any, error) {
	body := asRecord(value)
	if body == nil {
		return nil, scimErr("invalidSyntax", "request body must be a JSON object")
	}
	if s, has := body["schemas"]; has {
		ok := false
		l, isArr := s.([]any)
		for _, x := range l {
			ok = ok || x == AgentSchemaURN
		}
		if !isArr || !ok {
			return nil, scimErr("invalidValue", "schemas must include "+AgentSchemaURN)
		}
	}
	id, err := scimReadIdentity(body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"identity": id, "projection": scimReadProjection(body)}, nil
}

// StoredAgent is what an AgentStore keeps: the SCIM resource and the passport it projects.
type StoredAgent struct {
	Resource map[string]any
	Passport map[string]any
}

// AgentStore persists SCIM agents by id. Implementations must be safe for concurrent use.
type AgentStore interface {
	All() []StoredAgent // insertion order
	Get(id string) (StoredAgent, bool)
	Put(s StoredAgent)
	Delete(id string) bool
}

type memoryAgentStore struct {
	mu   sync.Mutex
	keys []string
	m    map[string]StoredAgent
}

// NewMemoryAgentStore is the in-process AgentStore.
func NewMemoryAgentStore(seed ...StoredAgent) AgentStore {
	s := &memoryAgentStore{m: map[string]StoredAgent{}}
	for _, a := range seed {
		s.Put(a)
	}
	return s
}

func (s *memoryAgentStore) All() []StoredAgent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StoredAgent, len(s.keys))
	for i, k := range s.keys {
		out[i] = s.m[k]
	}
	return out
}

func (s *memoryAgentStore) Get(id string) (StoredAgent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	return a, ok
}

func (s *memoryAgentStore) Put(a StoredAgent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := jsMemberString(a.Resource, "id")
	if _, has := s.m[id]; !has {
		s.keys = append(s.keys, id)
	}
	s.m[id] = a
}

func (s *memoryAgentStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, has := s.m[id]; !has {
		return false
	}
	delete(s.m, id)
	for i, k := range s.keys {
		if k == id {
			s.keys = append(s.keys[:i:i], s.keys[i+1:]...)
			break
		}
	}
	return true
}

// ScimErrorBody is the SCIM error response body.
func ScimErrorBody(status int, detail string, scimType string) map[string]any {
	b := map[string]any{"schemas": []any{ScimErrorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		b["scimType"] = scimType
	}
	return b
}

// ScimListResponse is the SCIM ListResponse envelope.
func ScimListResponse(resources []any, totalResults, startIndex float64) map[string]any {
	return map[string]any{"schemas": []any{ScimListResponseSchema}, "totalResults": jsNumber(totalResults), "startIndex": jsNumber(startIndex),
		"itemsPerPage": jsNumber(float64(len(resources))), "Resources": resources}
}

var scimFilterable = map[string]bool{"userName": true, "displayName": true, "externalId": true, "id": true, "active": true, "owner": true}

// JavaScript `.` (no s flag): the RE2 dot also matches a carriage return and the line separators.
const jsDot = `[^\n\r\x{2028}\x{2029}]`

var scimFilterRe = regexp.MustCompile(`^[` + jsWS + `]*(\w+)[` + jsWS + `]+[eE][qQ][` + jsWS + `]+(?:"((?:[^"\\]|\\` + jsDot + `)*)"|([tT][rR][uU][eE]|[fF][aA][lL][sS][eE]))[` + jsWS + `]*$`)
var scimUnescapeRe = regexp.MustCompile(`\\(` + jsDot + `)`)

// ParseScimFilter parses the one supported filter form, `attr eq "value"` / `attr eq true|false`: {attr, value}.
func ParseScimFilter(filter any) (map[string]any, error) {
	f, ok := filter.(string)
	if !ok {
		return nil, scimErr("invalidFilter", "filter must be a string")
	}
	m := scimFilterRe.FindStringSubmatchIndex(f)
	if m == nil {
		return nil, scimErr("invalidFilter", "unsupported filter (only `attr eq \"value\"` is supported): "+f)
	}
	attr := f[m[2]:m[3]]
	if !scimFilterable[attr] {
		return nil, scimErr("invalidFilter", "filter attribute not supported: "+attr)
	}
	if m[6] >= 0 {
		return map[string]any{"attr": attr, "value": strings.ToLower(f[m[6]:m[7]]) == "true"}, nil
	}
	raw := ""
	if m[4] >= 0 {
		raw = f[m[4]:m[5]]
	}
	return map[string]any{"attr": attr, "value": scimUnescapeRe.ReplaceAllString(raw, "$1")}, nil
}

func scimMatches(a map[string]any, f map[string]any) bool {
	key := f["attr"].(string)
	if key == "userName" {
		key = "displayName"
	}
	v, has := a[key]
	return has && v == f["value"]
}

var scimMutable = map[string]bool{"active": true, "displayName": true, "externalId": true, "owner": true, "capabilities": true, "holder": true}

type scimPatchOp struct {
	op, path string
	hasPath  bool
	value    any
}

func scimReadPatchOps(value any) ([]scimPatchOp, error) {
	body := asRecord(value)
	if body == nil {
		return nil, scimErr("invalidSyntax", "PATCH body must be a JSON object")
	}
	ops, ok := body["Operations"].([]any)
	if !ok || len(ops) == 0 {
		return nil, scimErr("invalidValue", "PATCH requires a non-empty Operations array")
	}
	out := make([]scimPatchOp, len(ops))
	for i, raw := range ops {
		o := asRecord(raw)
		opv, has := o["op"]
		s, _ := opv.(string)
		op := strings.ToLower(s)
		if op != "add" && op != "replace" && op != "remove" {
			return nil, scimErr("invalidValue", "unsupported PATCH op: "+jsTemplate(opv, has))
		}
		p := scimPatchOp{op: op, value: o["value"]}
		p.path, p.hasPath = o["path"].(string)
		out[i] = p
	}
	return out, nil
}

func scimProjectionOf(r map[string]any) map[string]any {
	caps, _ := r["capabilities"].([]any)
	proj := map[string]any{"owner": r["owner"], "active": r["active"], "capabilities": append([]any{}, caps...)}
	for _, k := range []string{"displayName", "externalId", "holder"} {
		if v, has := r[k]; has {
			proj[k] = v
		}
	}
	return proj
}

func scimApplyScalar(proj map[string]any, path, op string, value any) error {
	switch path {
	case "active":
		if op == "remove" {
			proj["active"] = true
			return nil
		}
		b, ok := asBool(value)
		if !ok {
			return scimErr("invalidValue", "`active` must be a boolean")
		}
		proj["active"] = b
		return nil
	case "capabilities":
		if op == "remove" {
			proj["capabilities"] = []any{}
			return nil
		}
		if !isStrArray(value) {
			return scimErr("invalidValue", "`capabilities` must be a string array")
		}
		arr := value.([]any)
		if op == "add" {
			cur, _ := proj["capabilities"].([]any)
			arr = append(append([]any{}, cur...), arr...)
		}
		proj["capabilities"] = arr
		return nil
	}
	if op == "remove" {
		if path == "displayName" || path == "owner" {
			return scimErr("mutability", "`"+path+"` cannot be removed")
		}
		delete(proj, path) // externalId / holder
		return nil
	}
	s, ok := value.(string)
	if !ok {
		return scimErr("invalidValue", "`"+path+"` must be a string")
	}
	proj[path] = s
	return nil
}

// jsKeyOrder is Object.keys order as far as a Go map can give it: array-index keys ascending, then the rest sorted.
// shortcut: the reference walks the other keys in insertion order, which a parsed Go map does not keep; only which error a
// value with several bad members reports can differ.
func jsKeyOrder(m map[string]any) []string {
	var idx []uint64
	var rest []string
	for k := range m {
		if n, err := strconv.ParseUint(k, 10, 32); err == nil && n < math.MaxUint32 && strconv.FormatUint(n, 10) == k {
			idx = append(idx, n)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i] < idx[j] })
	sort.Strings(rest)
	out := make([]string, 0, len(m))
	for _, n := range idx {
		out = append(out, strconv.FormatUint(n, 10))
	}
	return append(out, rest...)
}

func scimApplyPatchOp(proj map[string]any, op scimPatchOp) error {
	if !op.hasPath {
		if op.op == "remove" {
			return scimErr("noTarget", "a `remove` op requires a `path`")
		}
		obj := asRecord(op.value)
		if obj == nil {
			return scimErr("invalidValue", "a pathless PATCH value must be an object")
		}
		for _, k := range jsKeyOrder(obj) {
			if !scimMutable[k] {
				return scimErr("mutability", "attribute is immutable or unknown: "+k)
			}
			if err := scimApplyScalar(proj, k, "replace", obj[k]); err != nil {
				return err
			}
		}
		return nil
	}
	if !scimMutable[op.path] {
		return scimErr("mutability", "attribute is immutable or unknown: "+op.path)
	}
	return scimApplyScalar(proj, op.path, op.op, op.value)
}

// ScimRequest is one /Agents request. ID nil = the collection; Query holds the query parameters (filter, startIndex, count).
type ScimRequest struct {
	Method string
	ID     *string
	Query  map[string]any
	Body   any
}

// ScimResponse is the handler's answer; Body nil = no body (204).
type ScimResponse struct {
	Status  int               `json:"status"`
	Body    any               `json:"body,omitempty"`
	Headers map[string]string `json:"headers"`
}

// ScimHandlerOptions configures ScimHandler. Authenticate is required unless AllowUnauthenticated is set explicitly.
type ScimHandlerOptions struct {
	BaseURL              *string
	Now                  func() float64
	Authenticate         func(ScimRequest) bool
	AllowUnauthenticated bool
}

func scimJSON(status int, body any, extra map[string]string) ScimResponse {
	h := map[string]string{"content-type": scimContentType}
	for k, v := range extra {
		h[k] = v
	}
	return ScimResponse{Status: status, Body: body, Headers: h}
}

func scimErrorResponse(status int, detail, scimType string) ScimResponse {
	return scimJSON(status, ScimErrorBody(status, detail, scimType), nil)
}

func scimFromErr(err error) ScimResponse {
	var se *ScimError
	if errors.As(err, &se) {
		return scimErrorResponse(400, se.Detail, se.ScimType)
	}
	return scimErrorResponse(500, err.Error(), "")
}

func scimResource(status int, r map[string]any) ScimResponse {
	m := asRecord(r["meta"])
	return scimJSON(status, r, map[string]string{"location": jsMemberString(m, "location"), "etag": jsMemberString(m, "version")})
}

func scimIntParam(q map[string]any, k string, fallback float64) float64 {
	v, has := q[k]
	if !has {
		return fallback
	}
	n := jsToNumber(v)
	if !finite(n) || n != math.Trunc(n) {
		return fallback
	}
	return n
}

// jsSlice is Array.prototype.slice(start, end) index clamping for a non-negative start.
func jsSliceBounds(n int, start, end float64) (int, int) {
	clamp := func(x float64) int {
		if x < 0 {
			x = math.Max(0, float64(n)+x)
		}
		return int(math.Min(x, float64(n)))
	}
	s, e := clamp(start), clamp(end)
	if e < s {
		e = s
	}
	return s, e
}

// ScimHandler is the /Agents endpoint over a store.
func ScimHandler(store AgentStore, o ScimHandlerOptions) (func(ScimRequest) ScimResponse, error) {
	if o.Authenticate == nil && !o.AllowUnauthenticated {
		return nil, errors.New("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)")
	}
	meta := func() ScimMetaInput { return ScimMetaInput{BaseURL: o.BaseURL, Now: o.Now} }
	notFound := func(id string) ScimResponse { return scimErrorResponse(404, "Agent "+id+" not found", "") }
	rematerialize := func(existing StoredAgent, proj map[string]any) (map[string]any, error) {
		m := meta()
		if c, ok := asRecord(existing.Resource["meta"])["created"].(string); ok {
			m.Created = &c
		}
		return PassportToScim(existing.Passport, proj, m)
	}
	list := func(q map[string]any) ScimResponse {
		var items []any
		for _, s := range store.All() {
			items = append(items, s.Resource)
		}
		if f, has := q["filter"]; has && f != "" {
			parsed, err := ParseScimFilter(f)
			if err != nil {
				return scimFromErr(err)
			}
			kept := items[:0:0]
			for _, a := range items {
				if scimMatches(asRecord(a), parsed) {
					kept = append(kept, a)
				}
			}
			items = kept
		}
		total := float64(len(items))
		start := math.Max(1, scimIntParam(q, "startIndex", 1))
		end := math.Inf(1)
		if _, has := q["count"]; has {
			end = start - 1 + math.Max(0, scimIntParam(q, "count", total))
		}
		s, e := jsSliceBounds(len(items), start-1, end)
		page := append([]any{}, items[s:e]...)
		return scimJSON(200, ScimListResponse(page, total, start), nil)
	}
	create := func(body any) ScimResponse {
		req, err := ScimToProvisioningRequest(body)
		if err != nil {
			return scimFromErr(err)
		}
		passport, err := IssuePassport(req["identity"].(map[string]any))
		if err != nil {
			return scimFromErr(err)
		}
		id := jsMemberString(passport, "id")
		if _, exists := store.Get(id); exists {
			return scimErrorResponse(409, "an agent with this attested identity already exists (id "+id+")", "uniqueness")
		}
		r, err := PassportToScim(passport, req["projection"].(map[string]any), meta())
		if err != nil {
			return scimFromErr(err)
		}
		store.Put(StoredAgent{Resource: r, Passport: passport})
		return scimResource(201, r)
	}
	replace := func(id string, body any) ScimResponse {
		existing, ok := store.Get(id)
		if !ok {
			return notFound(id)
		}
		b := asRecord(body)
		if b == nil {
			return scimErrorResponse(400, "request body must be a JSON object", "invalidSyntax")
		}
		proj := scimReadProjection(b)
		if proj["owner"] == "" {
			proj["owner"] = existing.Resource["owner"]
		}
		r, err := rematerialize(existing, proj)
		if err != nil {
			return scimFromErr(err)
		}
		store.Put(StoredAgent{Resource: r, Passport: existing.Passport})
		return scimResource(200, r)
	}
	patch := func(id string, body any) ScimResponse {
		existing, ok := store.Get(id)
		if !ok {
			return notFound(id)
		}
		proj := scimProjectionOf(existing.Resource)
		ops, err := scimReadPatchOps(body)
		if err != nil {
			return scimFromErr(err)
		}
		for _, op := range ops {
			if err := scimApplyPatchOp(proj, op); err != nil {
				return scimFromErr(err)
			}
		}
		r, err := rematerialize(existing, proj)
		if err != nil {
			return scimFromErr(err)
		}
		store.Put(StoredAgent{Resource: r, Passport: existing.Passport})
		return scimResource(200, r)
	}
	return func(req ScimRequest) ScimResponse {
		if o.Authenticate != nil {
			ok := func() (ok bool) {
				defer func() {
					if recover() != nil {
						ok = false
					}
				}()
				return o.Authenticate(req)
			}()
			if !ok {
				r := scimErrorResponse(401, "authentication required", "")
				r.Headers["www-authenticate"] = "Bearer"
				return r
			}
		}
		id := ""
		if req.ID != nil {
			id = *req.ID
		}
		switch req.Method {
		case "GET":
			if req.ID == nil {
				return list(req.Query)
			}
			existing, ok := store.Get(id)
			if !ok {
				return notFound(id)
			}
			return scimResource(200, existing.Resource)
		case "POST":
			if req.ID != nil {
				return scimErrorResponse(405, "POST is not allowed on an individual Agent", "")
			}
			return create(req.Body)
		case "PUT":
			if req.ID == nil {
				return scimErrorResponse(405, "PUT requires an Agent id", "")
			}
			return replace(id, req.Body)
		case "PATCH":
			if req.ID == nil {
				return scimErrorResponse(405, "PATCH requires an Agent id", "")
			}
			return patch(id, req.Body)
		case "DELETE":
			if req.ID == nil {
				return scimErrorResponse(405, "DELETE requires an Agent id", "")
			}
			if !store.Delete(id) {
				return notFound(id)
			}
			return ScimResponse{Status: 204, Headers: map[string]string{}}
		}
		return scimErrorResponse(405, "method not allowed: "+req.Method, "")
	}, nil
}

func scimExtensionAttributes(a map[string]any) map[string]any {
	p := asRecord(a["passport"])
	caps, _ := a["capabilities"].([]any)
	attrs := map[string]any{"owner": a["owner"], "model": p["model_id"], "operator": p["operator"], "hardwareRooted": p["hardware_rooted"],
		"capabilities": append([]any{}, caps...), "passportRef": a["passportRef"]}
	if h, has := a["holder"]; has {
		attrs["holder"] = h
	}
	return attrs
}

func scimExternalID(a map[string]any) any {
	if v := a["externalId"]; v != nil {
		return v
	}
	return a["passportRef"]
}

// ToEntraAgentPayload is the Entra agent-identity SCIM payload for a resource.
func ToEntraAgentPayload(a map[string]any) map[string]any {
	return map[string]any{"schemas": []any{AgentSchemaURN, EntraAgentExtensionURN}, "externalId": scimExternalID(a), "displayName": a["displayName"],
		"active": a["active"], EntraAgentExtensionURN: scimExtensionAttributes(a)}
}

// ToOktaScimPayload is the Okta SCIM payload for a resource.
func ToOktaScimPayload(a map[string]any) map[string]any {
	return map[string]any{"schemas": []any{AgentSchemaURN, OktaAgentExtensionURN}, "userName": a["passportRef"], "externalId": scimExternalID(a),
		"displayName": a["displayName"], "active": a["active"], OktaAgentExtensionURN: scimExtensionAttributes(a)}
}

// the reference's JSON.stringify member order for the push payloads
var scimPayloadOrder = []string{"schemas", "userName", "externalId", "displayName", "active", EntraAgentExtensionURN, OktaAgentExtensionURN,
	"owner", "model", "operator", "hardwareRooted", "capabilities", "passportRef", "holder"}

// orderedJSON is JSON.stringify of v with object members in the given order (others sorted after them).
func orderedJSON(v any, order []string) (string, error) {
	m, ok := v.(map[string]any)
	if !ok {
		if l, ok := v.([]any); ok {
			parts := make([]string, len(l))
			for i, x := range l {
				s, err := orderedJSON(x, order)
				if err != nil {
					return "", err
				}
				parts[i] = s
			}
			return "[" + strings.Join(parts, ",") + "]", nil
		}
		s, ok := canonicalLenient(v)
		if !ok {
			return "", fmt.Errorf("not serializable: %T", v)
		}
		return s, nil
	}
	keys, seen := []string{}, map[string]bool{}
	for _, k := range order {
		if _, has := m[k]; has && !seen[k] {
			keys, seen[k] = append(keys, k), true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range append(keys, rest...) {
		if i > 0 {
			sb.WriteByte(',')
		}
		ks, _ := canonicalLenient(k)
		vs, err := orderedJSON(m[k], order)
		if err != nil {
			return "", err
		}
		sb.WriteString(ks + ":" + vs)
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

// PushTarget is a directory's SCIM endpoint. Client nil = http.DefaultClient.
type PushTarget struct {
	Endpoint string
	Token    string
	Client   interface {
		Do(*http.Request) (*http.Response, error)
	}
}

// PushResult is the directory's answer (Body: the parsed JSON, nil when absent or not JSON).
type PushResult struct {
	OK     bool `json:"ok"`
	Status int  `json:"status"`
	Body   any  `json:"body"`
}

// PushProvision POSTs a payload to the directory with the bearer token.
func PushProvision(payload map[string]any, t PushTarget) (PushResult, error) {
	body, err := orderedJSON(payload, scimPayloadOrder)
	if err != nil {
		return PushResult{}, err
	}
	req, err := http.NewRequest("POST", t.Endpoint, bytes.NewReader([]byte(body)))
	if err != nil {
		return PushResult{}, err
	}
	req.Header.Set("authorization", "Bearer "+t.Token)
	req.Header.Set("content-type", scimContentType)
	c := t.Client
	if c == nil {
		c = http.DefaultClient
	}
	res, err := c.Do(req)
	if err != nil {
		return PushResult{}, err
	}
	defer res.Body.Close()
	out := PushResult{OK: res.StatusCode >= 200 && res.StatusCode <= 299, Status: res.StatusCode}
	if b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20)); err == nil {
		if v, err := ParseJSONLenient(b); err == nil {
			out.Body = v
		}
	}
	return out, nil
}

// PushToEntra provisions the resource into Entra.
func PushToEntra(a map[string]any, t PushTarget) (PushResult, error) {
	return PushProvision(ToEntraAgentPayload(a), t)
}

// PushToOkta provisions the resource into Okta.
func PushToOkta(a map[string]any, t PushTarget) (PushResult, error) {
	return PushProvision(ToOktaScimPayload(a), t)
}

// PassportRegistry is an id-indexed passport set (insertion order; a repeated id keeps its place, last value wins).
type PassportRegistry struct {
	keys []string
	m    map[string]map[string]any
}

// BuildPassportRegistry indexes passports by id.
func BuildPassportRegistry(passports []map[string]any) *PassportRegistry {
	r := &PassportRegistry{m: map[string]map[string]any{}}
	for _, p := range passports {
		id := jsMemberString(p, "id")
		if _, has := r.m[id]; !has {
			r.keys = append(r.keys, id)
		}
		r.m[id] = p
	}
	return r
}

func (r *PassportRegistry) Get(id string) map[string]any { return r.m[id] }
func (r *PassportRegistry) Has(id string) bool           { _, ok := r.m[id]; return ok }
func (r *PassportRegistry) All() []map[string]any {
	out := make([]map[string]any, len(r.keys))
	for i, k := range r.keys {
		out[i] = r.m[k]
	}
	return out
}
