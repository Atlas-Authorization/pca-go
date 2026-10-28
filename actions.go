package pca

// Action kit (native port of the small deterministic core of the TypeScript action-kit package): strict ActionDef
// parse, normalize and canonical digest, the pack Merkle root and inclusion proof. The trait registry, the floor
// decision (rule 22) and T(d)/eff(d) are in actions_traits.go; ActionSchema v2 parsing and the v2 parameter types and
// formats live in action_schema.go. Every function is pure; the shared vectors pin every output.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

const (
	actionDefKind        = "pca-action-def"
	defDigestDomain      = "atlas-pca/action-def/v1"
	traitsDigestDomain   = "atlas-pca/action-traits/v1"
	rolesDigestDomain    = "atlas-pca/action-roles/v1"
	packDigestDomain     = "atlas-pca/action-pack/v1"
	maxDefVerbBytes      = 128
	maxDefTitleBytes     = 120
	maxDefDescBytes      = 1024
	maxDefParams         = 64
	maxDefAliases        = 16
	maxDefTraits         = 32
	maxDefContext        = 16
	maxDefSideEffects    = 16
	maxTraitImpliesDepth = 8
	maxRegistryTraits    = 512
	ppmMax               = 1_000_000
)

var (
	defEffects       = []string{"read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"}
	defReversibility = []string{"reversible", "rate_limited", "irreversible"}
	revRank          = map[string]int{"reversible": 0, "rate_limited": 1, "irreversible": 2}
	defBlastRadii    = []string{"one", "bounded", "tenant", "global"}
	blastPPM         = map[string]int{"one": 50_000, "bounded": 300_000, "tenant": 700_000, "global": 1_000_000}
	defScopes        = []string{"one", "set", "tenant", "global"}
	scopeBlast       = map[string]string{"one": "one", "set": "bounded", "tenant": "tenant", "global": "global"}
	defParamTypes    = []string{"string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"}
	sensitivityRank  = map[string]int{"free": 0, "material": 1, "critical": 2}
	provenanceLevels = []string{"first_party", "tool", "agent"}
	coreRoles        = []string{"money.amount", "money.currency", "money.fee", "party.payee", "party.payer", "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id", "credential.secret", "credential.token", "credential.key", "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target", "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size"}
	paramTags        = []string{"pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"}
	paramFormats     = []string{"email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256"}
	unitKinds        = []string{"money", "count", "bytes", "duration", "ratio"}
	caveatKinds      = []string{"amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"}
	contextKeys      = []string{"approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"}
	paramRuleIDs     = []string{"array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency", "recipient_param_declared", "secret_not_logged"}
	idempotencyModes = []string{"key_param", "natural", "none"}
	reviewStates     = []string{"authored", "unreviewed", "suggested", "confirmed"}
	bindingKinds     = []string{"mcp", "openapi", "http", "graphql", "grpc", "asyncapi"}
	idClasses        = []string{"digits", "hex", "alnum", "slug", "uuid", "any_safe"}
	defIntRoles      = []string{"money.amount", "money.fee", "count.limit", "bytes.size"}
	defParamKeys     = []string{"type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags", "provenance_min", "sensitivity", "accumulates", "default", "principal_neutral_default", "description"}
	defKeys          = []string{"v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects", "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since"}
	reIDRole         = regexp.MustCompile(`^id\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$`)
	reCustomRole     = regexp.MustCompile(`^x\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}$`)
	reIDFormat       = regexp.MustCompile(`^id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$`)
	reTaint          = regexp.MustCompile(`^session_taint_max:[a-z_]{1,16}$`)
	reVerb           = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}$`)
	reAlias          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}$`)
	reParamName      = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$`)
	reTraitID        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$`)
	reResourceType   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}$`)
	reCcy            = regexp.MustCompile(`^[A-Z]{3}$`)
	idClassChars     = map[string]string{}
	digitChars       = "0123456789"
	lowerChars       = "abcdefghijklmnopqrstuvwxyz"
	upperChars       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func init() {
	idClassChars["digits"] = digitChars
	idClassChars["hex"] = digitChars + "abcdef"
	idClassChars["alnum"] = digitChars + lowerChars + upperChars
	idClassChars["slug"] = digitChars + lowerChars + "-_"
	idClassChars["uuid"] = digitChars + "abcdef-"
	idClassChars["any_safe"] = digitChars + lowerChars + upperChars + "._-:/"
}

// ---- small helpers --------------------------------------------------------------------------------------------------

func hasKeyIn(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func sortedKeysStd(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func keysJoin(m map[string]any) string { return strings.Join(sortedKeysStd(m), ",") }

func allKeysIn(m map[string]any, allowed []string) bool { return keysWithin(m, allowed) }

func strOf(v any) (string, bool) { s, ok := v.(string); return s, ok }

func strsOf(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func anyStrs(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func sortUniqS(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func subsetS(a, b []string) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}

func isContextKey(k string) bool { return contains(contextKeys, k) || reTaint.MatchString(k) }

// strListOK: a JSON array of up to max distinct strings that each satisfy ok.
func strListOK(v any, max int, ok func(string) bool) bool {
	ss, isL := strsOf(v)
	if !isL || len(ss) > max {
		return false
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if !ok(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = deepCopy(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = deepCopy(x)
		}
		return a
	}
	return v
}

// ---- strict JSON profile + ActionDef validation -----------------------------------------------------------------------

// defJSONProfileError: plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth <= 32.
func defJSONProfileError(v any, depth int) string {
	if depth > 32 {
		return "nesting deeper than 32"
	}
	switch t := v.(type) {
	case nil, bool:
		return ""
	case json.Number, float64, int, int64:
		if jsIsInt(t) {
			return ""
		}
		return "numbers must be safe integers (no floats, no -0)"
	case string:
		if hasLoneSurrogate(t) {
			return "string has a lone surrogate"
		}
		if !norm.NFC.IsNormalString(t) {
			return "string is not NFC"
		}
		return ""
	case []any:
		for _, x := range t {
			if e := defJSONProfileError(x, depth+1); e != "" {
				return e
			}
		}
		return ""
	case map[string]any:
		for k, x := range t {
			if hasLoneSurrogate(k) || !norm.NFC.IsNormalString(k) {
				return "member name is not NFC / has a lone surrogate"
			}
			if e := defJSONProfileError(x, depth+1); e != "" {
				return e
			}
		}
		return ""
	}
	return "only JSON values are allowed"
}

func isRole(v any) bool {
	r, ok := v.(string)
	return ok && (contains(coreRoles, r) || reIDRole.MatchString(r) || reCustomRole.MatchString(r))
}

func isFormat(v any) bool {
	f, ok := v.(string)
	return ok && (contains(paramFormats, f) || reIDFormat.MatchString(f))
}

func inIDClass(s, c string) bool {
	chars := idClassChars[c]
	for _, r := range s {
		if !strings.ContainsRune(chars, r) {
			return false
		}
	}
	return true
}

func idPatternError(p any) string {
	if s, ok := p.(string); ok && s == "*" {
		return ""
	}
	m, ok := isObj(p)
	if !ok {
		return "resource.id must be '*', {exact} or {prefix, class, len}"
	}
	keys := keysJoin(m)
	if keys == "exact" {
		e, ok := m["exact"].(string)
		if ok && len(e) >= 1 && len(e) <= 128 && inIDClass(e, "any_safe") {
			return ""
		}
		return "resource.id.exact must be 1..128 safe characters"
	}
	if keys != "class,len,prefix" {
		return "resource.id must be '*', {exact} or {prefix, class, len}"
	}
	prefix, ok := m["prefix"].(string)
	if !ok || len(prefix) > 32 || !inIDClass(prefix, "any_safe") {
		return "resource.id.prefix must be up to 32 safe characters"
	}
	if !strIn(m["class"], idClasses) {
		return "resource.id.class is not an id class"
	}
	ln, ok := m["len"].([]any)
	if !ok || len(ln) != 2 || !(jsIsInt(ln[0]) && jsF(ln[0]) >= 1 && jsF(ln[0]) <= 128 && jsIsInt(ln[1]) && jsF(ln[1]) >= 1 && jsF(ln[1]) <= 128) {
		return "resource.id.len must be [min, max] in 1..128"
	}
	if jsF(ln[0]) > jsF(ln[1]) {
		return "resource.id.len: min > max"
	}
	if m["class"] == "uuid" && (prefix != "" || jsF(ln[0]) != 36 || jsF(ln[1]) != 36) {
		return "a uuid id has no prefix and length exactly [36, 36]"
	}
	return ""
}

func paramNameError(name string) string {
	if !reParamName.MatchString(name) {
		return "param name '" + name + "' is malformed"
	}
	for _, seg := range strings.Split(name, ".") {
		if forbiddenSegments[seg] {
			return "param name '" + name + "' is reserved"
		}
	}
	return ""
}

func defParamError(name string, pv any, names map[string]bool) string {
	p, ok := isObj(pv)
	if !ok {
		return name + ": declaration must be an object"
	}
	if !allKeysIn(p, defParamKeys) {
		return name + ": unknown member"
	}
	if !strIn(p["type"], defParamTypes) {
		return name + ": unknown type"
	}
	t := p["type"].(string)
	if r, has := p["role"]; has && !isRole(r) {
		return name + ": unknown role"
	}
	if r, ok := p["role"].(string); ok && contains(defIntRoles, r) && t != "integer" {
		return name + ": role requires an integer parameter"
	}
	if r, has := p["required"]; has {
		if _, ok := r.(bool); !ok {
			return name + ": required must be a boolean"
		}
	}
	if vs, has := p["values"]; has {
		arr, ok := vs.([]any)
		if !ok || len(arr) == 0 || len(arr) > 256 {
			return name + ": values must be 1..256 non-empty strings"
		}
		for _, x := range arr {
			if !schemaStr(x, 256) {
				return name + ": values must be 1..256 non-empty strings"
			}
		}
		if !distinctStrings(arr) {
			return name + ": values must be distinct"
		}
		if t != "string" && t != "set" {
			return name + ": values apply to string and set only"
		}
	}
	if _, has := p["values"]; t == "set" && !has {
		return name + ": a set needs values"
	}
	intLike := t == "integer" || t == "duration" || (t == "array" && p["items"] == "integer")
	for _, k := range []string{"min", "max"} {
		if x, has := p[k]; has && (!jsIsInt(x) || !intLike) {
			return name + ": " + k + " must be a safe integer on an integer parameter"
		}
	}
	if jsIsInt(p["min"]) && jsIsInt(p["max"]) && jsF(p["min"]) > jsF(p["max"]) {
		return name + ": min > max"
	}
	if x, has := p["max_len"]; has && (!jsIsInt(x) || jsF(x) < 1 || jsF(x) > 16_777_216 || !(t == "string" || t == "array" || t == "object_ref")) {
		return name + ": max_len must be 1..16777216 on a string or array"
	}
	if x, has := p["items"]; has && (t != "array" || !schemaStr(x, 64)) {
		return name + ": items applies to array only"
	}
	for _, k := range []string{"min_items", "max_items"} {
		if x, has := p[k]; has && (!jsIsNonNeg(x) || (t != "set" && t != "array")) {
			return name + ": " + k + " must be a non-negative integer on a set or array"
		}
	}
	if jsIsInt(p["min_items"]) && jsIsInt(p["max_items"]) && jsF(p["min_items"]) > jsF(p["max_items"]) {
		return name + ": min_items > max_items"
	}
	if f, has := p["format"]; has && (!isFormat(f) || (t != "string" && t != "object_ref")) {
		return name + ": format must be a known format on a string parameter"
	}
	if u, has := p["unit"]; has {
		if t != "integer" {
			return name + ": unit applies to integer parameters only"
		}
		um, ok := isObj(u)
		if !ok || !strIn(um["kind"], unitKinds) {
			return name + ": unit.kind is not a known kind"
		}
		if um["kind"] == "money" {
			if !allKeysIn(um, []string{"kind", "ccy", "exp"}) {
				return name + ": unit has unknown members"
			}
			if !jsIsInt(um["exp"]) || jsF(um["exp"]) < 0 || jsF(um["exp"]) > 18 {
				return name + ": unit.exp must be an integer in 0..18"
			}
			if c, isS := um["ccy"].(string); isS {
				if !reCcy.MatchString(c) {
					return name + ": unit.ccy must be an ISO 4217 style code"
				}
			} else {
				cm, ok := isObj(um["ccy"])
				from, fok := "", false
				if ok {
					from, fok = cm["from"].(string)
				}
				if !ok || len(cm) != 1 || !fok || !names[from] {
					return name + ": unit.ccy.from must name a declared parameter"
				}
			}
		} else if len(um) != 1 {
			return name + ": unit has unknown members"
		}
	}
	if tg, has := p["tags"]; has {
		arr, ok := tg.([]any)
		if !ok || len(arr) > len(paramTags) {
			return name + ": tags must be distinct known tags"
		}
		for _, x := range arr {
			if !strIn(x, paramTags) {
				return name + ": tags must be distinct known tags"
			}
		}
		if !distinctStrings(arr) {
			return name + ": tags must be distinct known tags"
		}
	}
	if x, has := p["provenance_min"]; has && !strIn(x, provenanceLevels) {
		return name + ": unknown provenance_min"
	}
	if x, has := p["sensitivity"]; has && !strIn(x, sensitivities) {
		return name + ": unknown sensitivity"
	}
	if a, has := p["accumulates"]; has {
		if t != "integer" {
			return name + ": accumulates applies to integer parameters only"
		}
		arr, ok := a.([]any)
		if !ok || len(arr) == 0 || len(arr) > 8 {
			return name + ": accumulates must be 1..8 distinct unit ids"
		}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok || jsLen(s) > 64 || !matchUnitID(s) {
				return name + ": accumulates must be 1..8 distinct unit ids"
			}
		}
		if !distinctStrings(arr) {
			return name + ": accumulates must be 1..8 distinct unit ids"
		}
	}
	if d, has := p["default"]; has && d == nil {
		return name + ": default must not be null (absent = no default)"
	}
	if x, has := p["principal_neutral_default"]; has {
		if _, ok := x.(bool); !ok {
			return name + ": principal_neutral_default must be a boolean"
		}
	}
	if p["principal_neutral_default"] == true && !hasKeyIn(p, "default") {
		return name + ": principal_neutral_default needs a default"
	}
	if x, has := p["description"]; has && !schemaStr(x, maxDefDescBytes) {
		return name + ": description must be a string up to 1024 bytes"
	}
	return ""
}

func defBindingsError(bv any) string {
	b, ok := isObj(bv)
	if !ok {
		return "bindings must be an object"
	}
	shapes := map[string][2][]string{
		"mcp": {{"tool"}, {}}, "openapi": {{"operationId"}, {"method", "path"}}, "http": {{"method", "path"}, {}},
		"graphql": {{"op", "field"}, {}}, "grpc": {{"service", "method"}, {}}, "asyncapi": {{"channel", "op"}, {}},
	}
	for k, v := range b {
		if !contains(bindingKinds, k) {
			return "bindings: unknown kind '" + k + "'"
		}
		req, opt := shapes[k][0], shapes[k][1]
		vm, ok := isObj(v)
		if !ok {
			return "bindings." + k + " must be an object"
		}
		for m := range vm {
			if !contains(req, m) && !contains(opt, m) {
				return "bindings." + k + ": unknown member '" + m + "'"
			}
		}
		for _, m := range req {
			if !schemaStr(vm[m], 256) {
				return "bindings." + k + "." + m + " must be a non-empty string"
			}
		}
		for _, m := range opt {
			if x, has := vm[m]; has && !schemaStr(x, 256) {
				return "bindings." + k + "." + m + " must be a non-empty string"
			}
		}
	}
	if g, ok := b["graphql"].(map[string]any); ok && !strIn(g["op"], []string{"query", "mutation", "subscription"}) {
		return "bindings.graphql.op is not a GraphQL operation kind"
	}
	if g, ok := b["asyncapi"].(map[string]any); ok && !strIn(g["op"], []string{"send", "receive"}) {
		return "bindings.asyncapi.op must be send or receive"
	}
	return ""
}

func defReviewError(rv any) string {
	r, ok := isObj(rv)
	if !ok {
		return "review must be an object"
	}
	if !allKeysIn(r, []string{"state", "attestation", "suggested_by"}) {
		return "review: unknown member"
	}
	if !strIn(r["state"], reviewStates) {
		return "review.state is not a review state"
	}
	if av, has := r["attestation"]; has {
		a, ok := isObj(av)
		if !ok {
			return "review.attestation must be an object"
		}
		if !allKeysIn(a, []string{"def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"}) {
			return "review.attestation: unknown member"
		}
		if !schemaStr(a["def_digest"], 64) || !schemaStr(a["traits_digest"], 64) || !schemaStr(a["facts_digest"], 64) || !schemaStr(a["reviewer_kid"], 128) || !jsIsNonNeg(a["ts"]) {
			return "review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required"
		}
		if !strListOK(a["final_traits"], maxDefTraits, reTraitID.MatchString) {
			return "review.attestation.final_traits must be distinct trait ids"
		}
		d, ok := a["dismissed"].([]any)
		bad := !ok || len(d) > maxDefTraits
		for _, x := range d {
			xm, ok := isObj(x)
			tr, _ := xm["trait"].(string)
			if !ok || keysJoin(xm) != "reason,trait" || !reTraitID.MatchString(tr) || !schemaStr(xm["reason"], 256) {
				bad = true
			}
		}
		if bad {
			return "review.attestation.dismissed must be {trait, reason} entries"
		}
		if s, has := a["sig"]; has && !schemaStr(s, 4096) {
			return "review.attestation.sig must be a string"
		}
	}
	return ""
}

// validateDef returns "" for a well-formed ActionDef (structure only), else the first reason. Never panics.
func validateDef(x any) (reason string) {
	defer func() {
		if r := recover(); r != nil {
			reason = fmt.Sprint("malformed def: ", r)
		}
	}()
	if e := defJSONProfileError(x, 0); e != "" {
		return "not strict JSON: " + e
	}
	d, ok := isObj(x)
	if !ok {
		return "def must be an object"
	}
	if !allKeysIn(d, defKeys) {
		return "unknown member"
	}
	if !jsStrictEq(d["v"], jsNumber(1)) {
		return "unsupported def version"
	}
	if d["kind"] != actionDefKind {
		return "kind must be '" + actionDefKind + "'"
	}
	verb, ok := d["verb"].(string)
	if !ok || !reVerb.MatchString(verb) || len(verb) > maxDefVerbBytes {
		return "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)"
	}
	if al, has := d["aliases"]; has {
		if !strListOK(al, maxDefAliases, func(s string) bool { return reAlias.MatchString(s) && len(s) <= maxDefVerbBytes }) {
			return "aliases must be distinct verb-shaped names other than the verb"
		}
		if ss, _ := strsOf(al); contains(ss, verb) {
			return "aliases must be distinct verb-shaped names other than the verb"
		}
	}
	if !schemaStr(d["title"], maxDefTitleBytes) {
		return "title must be a non-empty string up to 120 bytes"
	}
	if v, has := d["description"]; has && !schemaStr(v, maxDefDescBytes) {
		return "description must be a string"
	}
	if !strListOK(d["effects"], len(defEffects), func(s string) bool { return contains(defEffects, s) }) || len(d["effects"].([]any)) == 0 {
		return "effects must be 1..12 distinct known effects"
	}
	r, ok := isObj(d["resource"])
	if !ok || keysJoin(r) != "id,scope,type" {
		return "resource must be {type, id, scope}"
	}
	if rt, ok := r["type"].(string); !ok || !reResourceType.MatchString(rt) || len(rt) > 128 {
		return "resource.type is malformed"
	}
	if e := idPatternError(r["id"]); e != "" {
		return e
	}
	if !strIn(r["scope"], defScopes) {
		return "resource.scope is not a scope"
	}
	params, ok := isObj(d["params"])
	if !ok {
		return "params must be an object"
	}
	if len(params) > maxDefParams {
		return "more than 64 parameters"
	}
	names := map[string]bool{}
	for n := range params {
		names[n] = true
	}
	for n := range params {
		if e := paramNameError(n); e != "" {
			return e
		}
		for m := range params {
			if m != n && strings.HasPrefix(m, n+".") {
				return "param '" + n + "' is both a value and the parent of '" + m + "'"
			}
		}
	}
	for n, pv := range params {
		if e := defParamError(n, pv, names); e != "" {
			return e
		}
	}
	if rv, has := d["reversibility"]; has {
		if _, isS := rv.(string); !isS {
			rm, ok := isObj(rv)
			if !ok || !allKeysIn(rm, []string{"by", "map", "default"}) {
				return "reversibility must be a class or {by, map, default?}"
			}
			if by, ok := rm["by"].(string); !ok || !names[by] {
				return "reversibility.by must name a declared parameter"
			}
			mm, ok := isObj(rm["map"])
			bad := !ok || len(mm) == 0 || len(mm) > 256
			for k, v := range mm {
				if !schemaStr(k, 128) || !strIn(v, defReversibility) {
					bad = true
				}
			}
			if bad {
				return "reversibility.map must map values to reversibility classes"
			}
			if dv, has := rm["default"]; has && !strIn(dv, defReversibility) {
				return "reversibility.default is not a class"
			}
		} else if !strIn(rv, defReversibility) {
			return "unknown reversibility class"
		}
	}
	if bv, has := d["blast"]; has {
		b, ok := isObj(bv)
		if !ok || !allKeysIn(b, []string{"radius", "ppm"}) || !strIn(b["radius"], defBlastRadii) {
			return "blast must be {radius, ppm?}"
		}
		if p, has := b["ppm"]; has && !(jsIsInt(p) && jsF(p) >= 0 && jsF(p) <= ppmMax) {
			return "blast.ppm must be an integer in 0..1000000"
		}
	}
	if sv, has := d["side_effects"]; has {
		s, ok := sv.([]any)
		bad := !ok || len(s) > maxDefSideEffects
		for _, e := range s {
			em, ok := isObj(e)
			if !ok || keysJoin(em) != "kind,target" || !schemaStr(em["target"], 128) || !strIn(em["kind"], defEffects) {
				bad = true
			}
		}
		if bad {
			return "side_effects must be {target, kind} entries"
		}
	}
	if iv, has := d["idempotency"]; has {
		i, ok := isObj(iv)
		if !ok || !allKeysIn(i, []string{"mode", "param"}) || !strIn(i["mode"], idempotencyModes) {
			return "idempotency must be {mode, param?}"
		}
		p, pIsS := i["param"].(string)
		var bad bool
		if i["mode"] == "key_param" {
			bad = !pIsS || !names[p]
		} else {
			bad = hasKeyIn(i, "param")
		}
		if bad {
			return "idempotency.param is required for key_param (a declared parameter) and forbidden otherwise"
		}
	}
	if c, has := d["context"]; has && !strListOK(c, maxDefContext, isContextKey) {
		return "context must be distinct known context keys"
	}
	if t, has := d["traits"]; has && !strListOK(t, maxDefTraits, reTraitID.MatchString) {
		return "traits must be distinct trait ids"
	}
	if a, has := d["audience"]; has && a != "resource" {
		return "audience must be 'resource'"
	}
	if c, has := d["compensates"]; has {
		if cs, ok := c.(string); !ok || !reVerb.MatchString(cs) {
			return "compensates must be a verb"
		}
	}
	if b, has := d["bindings"]; has {
		if e := defBindingsError(b); e != "" {
			return e
		}
	}
	if exv, has := d["examples"]; has {
		ex, ok := exv.([]any)
		if !ok || len(ex) > 32 {
			return "examples must be an array of up to 32 entries"
		}
		for _, e := range ex {
			em, ok := isObj(e)
			if !ok || !allKeysIn(em, []string{"params", "under", "expect"}) || !strIn(em["expect"], []string{"allow", "escalate", "deny"}) {
				return "example must be {params, under?, expect}"
			}
			if _, ok := isObj(em["params"]); !ok {
				return "example must be {params, under?, expect}"
			}
		}
	}
	if e := defReviewError(d["review"]); e != "" {
		return e
	}
	if sv, has := d["source"]; has {
		s, ok := isObj(sv)
		if !ok || !allKeysIn(s, []string{"kind", "uri", "spec_digest", "licence", "imported_at"}) || !schemaStr(s["kind"], 64) || !schemaStr(s["uri"], 2048) ||
			!schemaStr(s["spec_digest"], 128) || !schemaStr(s["licence"], 128) || (hasKeyIn(s, "imported_at") && !jsIsNonNeg(s["imported_at"])) {
			return "source must be {kind, uri, spec_digest, licence, imported_at?}"
		}
	}
	if s, has := d["since"]; has && !schemaStr(s, 64) {
		return "since must be a string"
	}
	return ""
}

// ---- normalize + digest ---------------------------------------------------------------------------------------------

func isReadOnlyEffects(effects []string) bool {
	if len(effects) == 0 {
		return false
	}
	for _, e := range effects {
		if e != "read" {
			return false
		}
	}
	return true
}

func maxSens(a, b string) string {
	if sensitivityRank[a] >= sensitivityRank[b] {
		return a
	}
	return b
}

func paramSensitivityFloor(p map[string]any) string {
	f := "free"
	if r, ok := p["role"].(string); ok {
		if v, has := roleSensitivityFloor[r]; has {
			f = maxSens(f, v)
		}
	}
	if tg, ok := strsOf(p["tags"]); ok {
		for _, t := range tg {
			if v, has := tagSensitivityFloor[t]; has {
				f = maxSens(f, v)
			}
		}
	}
	return f
}

func effectiveParamSensitivity(p map[string]any) string {
	s, ok := p["sensitivity"].(string)
	if !ok {
		s = "free"
	}
	return maxSens(s, paramSensitivityFloor(p))
}

// declaredReversibility: the declared class (string) or map, else the fail-closed default.
func declaredReversibility(d map[string]any) any {
	if r, has := d["reversibility"]; has {
		return r
	}
	ef, _ := strsOf(d["effects"])
	if isReadOnlyEffects(ef) {
		return "reversible"
	}
	return "irreversible"
}

func maxRevOf(xs []string) string {
	out := "reversible"
	for _, b := range xs {
		if rb, ok := revRank[b]; ok && rb > revRank[out] {
			out = b
		}
	}
	return out
}

// worstReversibility: the worst class any call can have (r is a class string or {by, map, default?}).
func worstReversibility(r any, params map[string]any) string {
	if s, ok := r.(string); ok {
		return s
	}
	rm := r.(map[string]any)
	by, _ := rm["by"].(string)
	mm, _ := rm["map"].(map[string]any)
	mapped := []string{}
	for _, k := range sortedKeysStd(mm) {
		mapped = append(mapped, mm[k].(string))
	}
	var domain []string
	hasDomain := false
	if d, ok := params[by].(map[string]any); ok {
		if d["type"] == "boolean" {
			domain, hasDomain = []string{"true", "false"}, true
		} else if vs, ok := strsOf(d["values"]); d["type"] == "string" && ok {
			domain, hasDomain = vs, true
		}
	}
	covered := hasDomain
	for _, x := range domain {
		if _, has := mm[x]; !has {
			covered = false
		}
	}
	if covered {
		return maxRevOf(mapped)
	}
	dflt := "irreversible"
	if s, ok := rm["default"].(string); ok {
		dflt = s
	}
	return maxRevOf(append(mapped, dflt))
}

func normalizeParam(p map[string]any) map[string]any {
	out := make(map[string]any, len(p)+3)
	for k, v := range p {
		out[k] = v
	}
	if r, has := p["required"]; has {
		out["required"] = r
	} else {
		out["required"] = true
	}
	if tg, ok := strsOf(p["tags"]); ok {
		out["tags"] = anyStrs(sortUniqS(tg))
	}
	if vs, ok := p["values"].([]any); ok {
		out["values"] = append([]any{}, vs...)
	}
	out["sensitivity"] = effectiveParamSensitivity(p)
	if a, ok := strsOf(p["accumulates"]); ok {
		out["accumulates"] = anyStrs(sortUniqS(a))
	} else if u, ok := p["unit"].(map[string]any); ok && p["role"] == "money.amount" && u["kind"] == "money" {
		if c, ok := u["ccy"].(string); ok {
			out["accumulates"] = []any{"money." + strings.ToLower(c)}
		}
	}
	return out
}

// normalizeDef is the authoring-independent form of a def (assumes validateDef passed): defaults filled, sets sorted,
// review / examples / source / since removed.
func normalizeDef(d map[string]any) map[string]any {
	rev := declaredReversibility(d)
	scope := d["resource"].(map[string]any)["scope"].(string)
	radius := scopeBlast[scope]
	ppm := 0
	if b, ok := d["blast"].(map[string]any); ok {
		radius = b["radius"].(string)
		if p, has := b["ppm"]; has {
			ppm = int(jsF(p))
		}
	}
	bp := blastPPM[radius]
	if ppm > bp {
		bp = ppm
	}
	pin := d["params"].(map[string]any)
	params := make(map[string]any, len(pin))
	for k, v := range pin {
		params[k] = normalizeParam(v.(map[string]any))
	}
	var nrev any = rev
	if rm, ok := rev.(map[string]any); ok {
		m := map[string]any{"by": rm["by"], "map": deepCopy(rm["map"])}
		if dv, has := rm["default"]; has {
			m["default"] = dv
		}
		nrev = m
	}
	idem := map[string]any{"mode": "none"}
	if im, ok := d["idempotency"].(map[string]any); ok {
		idem["mode"] = im["mode"]
		if p, has := im["param"]; has {
			idem["param"] = p
		}
	}
	se := []map[string]any{}
	if sv, ok := d["side_effects"].([]any); ok {
		for _, e := range sv {
			em := e.(map[string]any)
			se = append(se, map[string]any{"target": em["target"], "kind": em["kind"]})
		}
	}
	sort.SliceStable(se, func(i, j int) bool {
		ti, tj := se[i]["target"].(string), se[j]["target"].(string)
		if c := compareUnits(utf16Units(ti), utf16Units(tj)); c != 0 {
			return c < 0
		}
		return se[i]["kind"].(string) < se[j]["kind"].(string)
	})
	sel := make([]any, len(se))
	for i, e := range se {
		sel[i] = e
	}
	list := func(k string) []any {
		ss, _ := strsOf(d[k])
		return anyStrs(sortUniqS(ss))
	}
	bindings := any(map[string]any{})
	if b, has := d["bindings"]; has {
		bindings = deepCopy(b)
	}
	res := d["resource"].(map[string]any)
	out := map[string]any{
		"v": 1, "kind": d["kind"], "verb": d["verb"], "aliases": list("aliases"), "title": d["title"], "effects": list("effects"),
		"resource": map[string]any{"type": res["type"], "id": res["id"], "scope": res["scope"]},
		"params":   params, "reversibility": nrev, "blast": map[string]any{"radius": radius, "ppm": bp},
		"side_effects": sel, "idempotency": idem, "context": list("context"), "traits": list("traits"), "bindings": bindings,
	}
	if v, has := d["description"]; has {
		out["description"] = v
	}
	if v, has := d["audience"]; has {
		out["audience"] = v
	}
	if v, has := d["compensates"]; has {
		out["compensates"] = v
	}
	return out
}

// defDigest = b64u(sha256(strictCanonical({d, def: normalize(def)}))).
func defDigest(d map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": defDigestDomain, "def": normalizeDef(d)})
}

// ---- pack Merkle root + inclusion proof -------------------------------------------------------------------------------

func packLeaf(digest string) any { return map[string]any{"d": packDigestDomain, "def": digest} }

func sortedPackDigests(digests []string) ([]string, error) {
	s := sortUniqS(digests)
	if len(s) != len(digests) {
		return nil, fmt.Errorf("duplicate_def: a pack lists a def digest twice")
	}
	if len(s) == 0 {
		return nil, fmt.Errorf("empty_pack: a pack has at least one def")
	}
	return s, nil
}

// packRoot is the Merkle root over the sorted def digests (RFC 6962 shape, domain separated leaves).
func packRoot(digests []string) (string, error) {
	s, err := sortedPackDigests(digests)
	if err != nil {
		return "", err
	}
	leaves := make([]any, len(s))
	for i, d := range s {
		leaves[i] = packLeaf(d)
	}
	return MerkleRoot(leaves)
}

// packProof is the inclusion proof of digest in the pack made of digests: {index, size, path: [{side, hash}]} leaf to root.
func packProof(digests []string, digest string) (map[string]any, error) {
	s, err := sortedPackDigests(digests)
	if err != nil {
		return nil, err
	}
	i := sort.SearchStrings(s, digest)
	if i >= len(s) || s[i] != digest {
		return nil, fmt.Errorf("not_in_pack: the digest is not in the pack")
	}
	hs := make([][]byte, len(s))
	for k, d := range s {
		if hs[k], err = leafHash(packLeaf(d)); err != nil {
			return nil, err
		}
	}
	var path []any
	seg, idx := hs, i
	for len(seg) > 1 {
		k := split(len(seg))
		if idx < k {
			path = append(path, map[string]any{"side": "R", "hash": b64.EncodeToString(build(seg[k:]))})
			seg = seg[:k]
		} else {
			path = append(path, map[string]any{"side": "L", "hash": b64.EncodeToString(build(seg[:k]))})
			seg = seg[k:]
			idx -= k
		}
	}
	for a, b := 0, len(path)-1; a < b; a, b = a+1, b-1 {
		path[a], path[b] = path[b], path[a]
	}
	if path == nil {
		path = []any{}
	}
	return map[string]any{"index": json.Number(strconv.Itoa(i)), "size": json.Number(strconv.Itoa(len(s))), "path": path}, nil
}

// verifyPackProof: does proof show digest is in the pack with root root?
func verifyPackProof(root string, proof map[string]any, digest string) bool {
	return VerifyInclusion(root, proof, packLeaf(digest))
}
