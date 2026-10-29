package pca

// Signed action schemas and the closed-world conformance of rule 14 (packages/pca/src/action-schema.ts):
// `pca-action-schema` v1 shape, the site signature under the discovery key entry (the entry pins the suite), the
// content digest, and conformAction (params_not_object, unknown_verb, undeclared_param, missing_param, bad_type,
// out_of_domain; first failure wins, keys in UTF-8 byte order).

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	actionSchemaDomain    = "atlas-pca/action-schema/v1\x00"
	actionSchemaRefDomain = "atlas-pca/action-schema-ref/v1"
	actionSchemaKind      = "pca-action-schema"
	maxSchemaVerbs        = 256
	maxSchemaParams       = 64
	maxSchemaValues       = 256
	defaultMaxLen         = 1024
	defaultMaxItems       = 64
)

var (
	paramTypes        = []string{"string", "integer", "boolean", "date", "set", "array"}
	sensitivities     = []string{"free", "material", "critical"}
	schemaReversibles = []string{"reversible", "rate_limited", "irreversible"}
	schemaDocKeys     = []string{"v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig"}
	schemaVerbKeys    = []string{"verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description"}
	schemaParamKeys   = []string{"type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items", "min_items",
		"max_items", "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description"}
	schemaSigKeys = []string{"alg", "kid", "value", "pq_value"}

	// v2 (action kit): the same document plus normative verb members effects / traits / def / floors, document members
	// traits_digest / trait_defs / pack, dotted parameter paths and the parameter members role / format / tags / provenance_min.
	paramTypesV2      = []string{"string", "integer", "boolean", "date", "set", "array", "datetime", "duration", "object_ref"}
	schemaDocKeysV2   = append(append([]string{}, schemaDocKeys...), "traits_digest", "trait_defs", "pack")
	schemaVerbKeysV2  = append(append([]string{}, schemaVerbKeys...), "traits", "def", "floors", "confirmation")
	schemaParamKeysV2 = append(append([]string{}, schemaParamKeys...), "role", "format", "tags", "provenance_min")
	schemaV2Effects   = []string{"read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"}
	reParamPathV2     = regexp.MustCompile(`^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$`)
	reDatetime        = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2})T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.[0-9]{1,3})?Z$`)
	reIDValue         = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)
)

// jsWS is the ECMAScript \s class (Go's \s is ASCII only).
const jsWS = `\t\n\x{0B}\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

var formatRes = map[string]*regexp.Regexp{
	"email":        regexp.MustCompile(`^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+$`),
	"url":          regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^` + jsWS + `/?#]+[^` + jsWS + `]*$`),
	"uri_https":    regexp.MustCompile(`^https://[^` + jsWS + `/?#]+[^` + jsWS + `]*$`),
	"uuid":         regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"phone_e164":   regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`),
	"iso_country":  regexp.MustCompile(`^[A-Z]{2}$`),
	"iso_currency": regexp.MustCompile(`^[A-Z]{3}$`),
	"semver":       regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?(?:\+[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?$`),
	"sha256":       regexp.MustCompile(`^[0-9a-f]{64}$`),
}

var (
	reIBAN  = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)
	reCIDR4 = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$`)
	reCIDR6 = regexp.MustCompile(`^([0-9a-fA-F:]{2,39})/([0-9]{1,3})$`)
)

func ibanOK(s string) bool {
	if !reIBAN.MatchString(s) {
		return false
	}
	rem := 0
	for _, ch := range s[4:] + s[:4] {
		v := int(ch) - 48
		if ch >= 'A' {
			v = int(ch) - 55
		}
		if v > 9 {
			rem = (rem*100 + v) % 97
		} else {
			rem = (rem*10 + v) % 97
		}
	}
	return rem == 1
}

// canonDec: the decimal text n has no leading zeros (String(Number(n)) === n).
func canonDec(n string) (int, bool) {
	x := 0
	for _, c := range n {
		x = x*10 + int(c-'0')
	}
	return x, fmt.Sprint(x) == n
}

func cidrOK(s string) bool {
	if m := reCIDR4.FindStringSubmatch(s); m != nil {
		for _, o := range m[1:5] {
			if x, ok := canonDec(o); !ok || x > 255 {
				return false
			}
		}
		x, ok := canonDec(m[5])
		return ok && x <= 32
	}
	m := reCIDR6.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	x, ok := canonDec(m[2])
	return strings.Count(m[1], ":") >= 2 && !strings.Contains(m[1], ":::") && x <= 128 && ok
}

// formatCheck is the checker of a v2 format, or nil when the format is unknown. id:<type> accepts a 1..128 character safe id.
func formatCheck(f string) func(string) bool {
	switch f {
	case "iban":
		return ibanOK
	case "cidr":
		return cidrOK
	case "email":
		return func(s string) bool { return len(s) <= 254 && formatRes["email"].MatchString(s) }
	}
	if re, ok := formatRes[f]; ok {
		return re.MatchString
	}
	if reIDFormat.MatchString(f) {
		return reIDValue.MatchString
	}
	return nil
}

func formatViolation(d map[string]any, x string) (string, string) {
	f, has := d["format"]
	if !has {
		return "", ""
	}
	fs, _ := f.(string)
	if ck := formatCheck(fs); ck == nil || !ck(x) {
		return "out_of_domain", "not a valid " + jsValueString(f)
	}
	return "", ""
}

// schemaFloorsError: "" if f is a well-formed materialized profile (shape only; the semantic check is rule 22).
func schemaFloorsError(f any) string {
	m, ok := f.(map[string]any)
	if !ok {
		return "floors must be an object"
	}
	for k := range m {
		if !contains([]string{"risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"}, k) {
			return "floors: unknown member '" + k + "'"
		}
	}
	rng := func(x any, lo, hi float64) bool { return jsIsInt(x) && jsF(x) >= lo && jsF(x) <= hi }
	if !rng(m["risk"], 0, 3) || !rng(m["esc"], 0, 3) {
		return "floors.risk and floors.esc must be integers in 0..3"
	}
	if !strIn(m["rev"], schemaReversibles) {
		return "floors.rev is not a reversibility class"
	}
	if !rng(m["blast_ppm"], 0, 1_000_000) {
		return "floors.blast_ppm must be an integer in 0..1000000"
	}
	for _, c := range []struct {
		name string
		ok   func(string) bool
	}{
		{"caveats", func(s string) bool { return contains(caveatKinds, s) }},
		{"context", isContextKey},
		{"prules", func(s string) bool { return contains(paramRuleIDs, s) }},
	} {
		a, isL := m[c.name].([]any)
		if !isL || len(a) > 64 {
			return "floors." + c.name + " must be an array of known entries"
		}
		for _, x := range a {
			if s, ok := x.(string); !ok || !c.ok(s) {
				return "floors." + c.name + " must be an array of known entries"
			}
		}
		for i := 1; i < len(a); i++ {
			if !(a[i-1].(string) < a[i].(string)) {
				return "floors." + c.name + " must be sorted and distinct"
			}
		}
	}
	return ""
}

// schemaStr is the reference isStr: a non-empty string without lone surrogates of at most max UTF-8 bytes.
func schemaStr(v any, max int) bool {
	s, ok := v.(string)
	return ok && len(s) > 0 && !hasLoneSurrogate(s) && utf8Len(s) <= max
}

func strIn(v any, set []string) bool {
	s, ok := v.(string)
	return ok && contains(set, s)
}

func keysWithin(m map[string]any, allowed []string) bool {
	for k := range m {
		if !contains(allowed, k) {
			return false
		}
	}
	return true
}

func distinctStrings(a []any) bool {
	seen := map[string]bool{}
	for _, x := range a {
		s := x.(string)
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// paramDeclError is the reference paramDeclError: "" = well-formed, else the refusal text. Members are examined in sorted
// order (Go maps carry no insertion order).
func paramDeclError(path string, dv any, units map[string]any, hasUnits bool) string {
	return paramDeclErrorV(path, dv, units, hasUnits, false)
}

func paramDeclErrorV(path string, dv any, units map[string]any, hasUnits bool, v2 bool) string {
	if v2 && !reParamPathV2.MatchString(path) || !v2 && !matchParamPath(path) {
		return "parameter path '" + path + "' is not action.params.<name>"
	}
	reserved := false
	for _, seg := range strings.Split(strings.TrimPrefix(path, "action.params."), ".") {
		reserved = reserved || forbiddenSegments[seg]
	}
	if reserved {
		return "parameter name '" + path + "' is reserved (__proto__ / constructor / prototype)"
	}
	d, ok := dv.(map[string]any)
	if !ok {
		return path + ": declaration must be an object"
	}
	pk, pt := schemaParamKeys, paramTypes
	if v2 {
		pk, pt = schemaParamKeysV2, paramTypesV2
	}
	if k, ok := firstUnknownKey(d, pk); !ok {
		return path + ": unknown member '" + k + "'"
	}
	if !strIn(d["type"], pt) {
		return path + ": unknown type"
	}
	if !schemaStr(d["semantic"], 128) {
		return path + ": semantic must be a non-empty string"
	}
	if !strIn(d["sensitivity"], sensitivities) {
		return path + ": unknown sensitivity"
	}
	typ := d["type"].(string)
	if r, has := d["required"]; has {
		if _, ok := r.(bool); !ok {
			return path + ": required must be a boolean"
		}
	}
	values, hasValues := d["values"]
	if hasValues {
		arr, ok := values.([]any)
		bad := !ok || len(arr) == 0 || len(arr) > maxSchemaValues
		for _, x := range arr {
			if !schemaStr(x, 256) {
				bad = true
			}
		}
		if bad {
			return fmt.Sprintf("%s: values must be 1..%d strings", path, maxSchemaValues)
		}
		if !distinctStrings(arr) {
			return path + ": values must be distinct"
		}
		if typ != "string" && typ != "set" {
			return path + ": values apply to string and set only"
		}
	}
	if typ == "set" && !hasValues {
		return path + ": a set needs values"
	}
	for _, k := range []string{"min", "max"} {
		if x, has := d[k]; has && (!jsIsInt(x) || (typ != "integer" && !(v2 && typ == "duration") && !(typ == "array" && d["items"] == "integer"))) {
			return path + ": " + k + " must be a safe integer on an integer parameter"
		}
	}
	if jsIsInt(d["min"]) && jsIsInt(d["max"]) && jsF(d["min"]) > jsF(d["max"]) {
		return path + ": min > max"
	}
	if u, has := d["unit"]; has {
		us, isS := u.(string)
		_, own := units[us]
		if typ != "integer" || !isS || !hasUnits || !own {
			return path + ": unit must name a declared unit of an integer parameter"
		}
	}
	if x, has := d["max_len"]; has && (!jsIsInt(x) || jsF(x) < 1) {
		return path + ": max_len must be a positive safe integer"
	}
	if x, has := d["items"]; has && (typ != "array" || !schemaStr(x, 64)) {
		return path + ": items applies to array only"
	}
	for _, k := range []string{"min_items", "max_items"} {
		if x, has := d[k]; has && (!jsIsNonNeg(x) || (typ != "set" && typ != "array")) {
			return path + ": " + k + " must be a non-negative safe integer on a set or array"
		}
	}
	if jsIsInt(d["min_items"]) && jsIsInt(d["max_items"]) && jsF(d["min_items"]) > jsF(d["max_items"]) {
		return path + ": min_items > max_items"
	}
	if dflt, has := d["default"]; has && dflt == nil {
		return path + ": default must not be null (absent = no default)"
	}
	pnd, hasPnd := d["principal_neutral_default"]
	if hasPnd {
		if _, ok := pnd.(bool); !ok {
			return path + ": principal_neutral_default must be a boolean"
		}
	}
	if _, hasDef := d["default"]; pnd == true && !hasDef {
		return path + ": principal_neutral_default needs a default"
	}
	if ai, has := d["accumulates_into"]; has {
		if typ != "integer" {
			return path + ": accumulates_into applies to integer parameters only"
		}
		arr, ok := ai.([]any)
		if !ok || len(arr) == 0 || len(arr) > 8 {
			return path + ": accumulates_into must be 1..8 unit ids"
		}
		for _, u := range arr {
			s, ok := u.(string)
			if !ok || jsLen(s) > 64 || !matchUnitID(s) {
				return path + ": accumulates_into entries must be unit ids"
			}
		}
		if !distinctStrings(arr) {
			return path + ": accumulates_into must be distinct"
		}
	}
	if x, has := d["issued_by_site"]; has {
		if _, ok := x.(bool); !ok {
			return path + ": issued_by_site must be a boolean"
		}
	}
	if x, has := d["description"]; has && !schemaStr(x, 1024) {
		return path + ": description must be a string"
	}
	if v2 {
		if x, has := d["role"]; has && !schemaStr(x, 128) {
			return path + ": role must be a non-empty string"
		}
		if f, has := d["format"]; has {
			fs, isS := f.(string)
			if !isS || formatCheck(fs) == nil || (typ != "string" && typ != "object_ref") {
				return path + ": format must be a known format on a string parameter"
			}
		}
		if tg, has := d["tags"]; has {
			arr, ok := tg.([]any)
			bad := !ok || len(arr) > len(paramTags)
			for _, x := range arr {
				if !strIn(x, paramTags) {
					bad = true
				}
			}
			if bad || !distinctStrings(arr) {
				return path + ": tags must be distinct known tags"
			}
		}
		if x, has := d["provenance_min"]; has && !strIn(x, provenanceLevels) {
			return path + ": unknown provenance_min"
		}
	}
	return ""
}

func paramDeclOK(path string, dv any, units map[string]any, hasUnits bool) bool {
	return paramDeclError(path, dv, units, hasUnits) == ""
}

func verbDeclError(vv any, units map[string]any, hasUnits bool) string {
	return verbDeclErrorV(vv, units, hasUnits, false)
}

func verbDeclErrorV(vv any, units map[string]any, hasUnits bool, v2 bool) string {
	v, ok := vv.(map[string]any)
	if !ok {
		return "verb entry must be an object"
	}
	vk := schemaVerbKeys
	if v2 {
		vk = schemaVerbKeysV2
	}
	if k, ok := firstUnknownKey(v, vk); !ok {
		return "verb entry: unknown member '" + k + "'"
	}
	if !schemaStr(v["verb"], 128) {
		return "verb entry: verb must be a non-empty string"
	}
	at := "verb '" + v["verb"].(string) + "'"
	if k := v["kind"]; k != "read" && k != "write" {
		return at + ": kind must be read or write"
	}
	params, ok := v["params"].(map[string]any)
	if !ok {
		return at + ": params must be an object"
	}
	if len(params) > maxSchemaParams {
		return fmt.Sprintf("%s: more than %d parameters", at, maxSchemaParams)
	}
	for _, p := range sortedKeysUtf8(params) {
		if e := paramDeclErrorV(p, params[p], units, hasUnits, v2); e != "" {
			return at + ": " + e
		}
	}
	if v2 {
		for _, p := range sortedKeysUtf8(params) {
			for _, q := range sortedKeysUtf8(params) {
				if q != p && strings.HasPrefix(q, p+".") {
					return at + ": parameter '" + p + "' is both a value and the parent of '" + q + "'"
				}
			}
		}
	}
	if x, has := v["reversibility"]; has && !strIn(x, schemaReversibles) {
		return at + ": unknown reversibility"
	}
	if x, has := v["reversibility_by"]; has {
		r, ok := x.(map[string]any)
		if !ok || !keysWithin(r, []string{"param", "map", "default"}) {
			return at + ": reversibility_by must be {param, map, default?}"
		}
		ps, isS := r["param"].(string)
		_, own := params[ps]
		if !isS || !own {
			return at + ": reversibility_by.param must be a declared parameter"
		}
		m, ok := r["map"].(map[string]any)
		bad := !ok || len(m) == 0
		for _, y := range m {
			if !strIn(y, schemaReversibles) {
				bad = true
			}
		}
		if bad {
			return at + ": reversibility_by.map must map values to reversibility classes"
		}
		if dft, has := r["default"]; has && !strIn(dft, schemaReversibles) {
			return at + ": reversibility_by.default is not a reversibility class"
		}
	}
	single := func(key, member string, max int) bool {
		x, has := v[key]
		if !has {
			return true
		}
		m, ok := x.(map[string]any)
		return ok && len(m) == 1 && schemaStr(m[member], max) && hasKey(m, member)
	}
	if !single("mcp", "tool", 128) {
		return at + ": mcp must be {tool}"
	}
	if !single("openapi", "operationId", 128) {
		return at + ": openapi must be {operationId}"
	}
	objKeys := []string{"harm", "effects", "returns"}
	if v2 {
		objKeys = []string{"harm", "returns"}
	}
	for _, k := range objKeys {
		if x, has := v[k]; has {
			if _, ok := x.(map[string]any); !ok {
				return at + ": " + k + " must be an object"
			}
		}
	}
	if v2 {
		ef, ok := v["effects"].([]any)
		bad := !ok || len(ef) == 0 || len(ef) > len(schemaV2Effects)
		allRead := true
		for _, x := range ef {
			if !strIn(x, schemaV2Effects) {
				bad = true
			}
			allRead = allRead && x == "read"
		}
		if bad {
			return fmt.Sprintf("%s: effects must be 1..%d known effects", at, len(schemaV2Effects))
		}
		for i := 1; i < len(ef); i++ {
			if !(ef[i-1].(string) < ef[i].(string)) {
				return at + ": effects must be sorted and distinct"
			}
		}
		if (v["kind"] == "read") != allRead {
			return at + ": kind read must hold exactly when every effect is read"
		}
		tr, ok := v["traits"].([]any)
		bad = !ok || len(tr) > 64
		for _, x := range tr {
			if s, isS := x.(string); !isS || !reTraitID.MatchString(s) {
				bad = true
			}
		}
		if bad {
			return at + ": traits must be trait ids"
		}
		for i := 1; i < len(tr); i++ {
			if !(tr[i-1].(string) < tr[i].(string)) {
				return at + ": traits must be sorted and distinct"
			}
		}
		if !b64uOK(v["def"], b32) {
			return at + ": def must be a canonical base64url SHA-256 digest"
		}
		if e := schemaFloorsError(v["floors"]); e != "" {
			return at + ": " + e
		}
		if c, has := v["confirmation"]; has {
			if e := confirmationShapeError(c); e != "" {
				return at + ": " + e
			}
		}
	}
	if x, has := v["world"]; has {
		if _, ok := x.([]any); !ok {
			return at + ": world must be an array"
		}
	}
	if x, has := v["description"]; has && !schemaStr(x, 1024) {
		return at + ": description must be a string"
	}
	return ""
}

// confirmationShapeError: "" iff c is a well-formed `confirmation` (shape only; the signature check is rule 22).
func confirmationShapeError(cv any) string {
	c, ok := cv.(map[string]any)
	if !ok {
		return "confirmation must be an object"
	}
	if k, ok := firstUnknownKey(c, []string{"def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"}); !ok {
		return "confirmation: unknown member '" + k + "'"
	}
	if !b64uOK(c["def_digest"], b32) || !b64uOK(c["traits_digest"], b32) || !b64uOK(c["facts_digest"], b32) {
		return "confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests"
	}
	if !b64uOK(c["sig"], sigLen) {
		return "confirmation: sig must be a canonical base64url 64-byte signature"
	}
	ft, ok := c["final_traits"].([]any)
	if !ok || len(ft) > 64 {
		return "confirmation: final_traits must be trait ids"
	}
	for i, x := range ft {
		if s, ok := x.(string); !ok || !reTraitID.MatchString(s) {
			return "confirmation: final_traits must be trait ids"
		}
		if i > 0 && !(ft[i-1].(string) < x.(string)) {
			return "confirmation: final_traits must be sorted and distinct"
		}
	}
	dm, ok := c["dismissed"].([]any)
	if !ok || len(dm) > 64 {
		return "confirmation: dismissed must be an array"
	}
	for _, x := range dm {
		d, ok := x.(map[string]any)
		t, _ := d["trait"].(string)
		if !ok || !keysWithin(d, []string{"trait", "reason"}) || !reTraitID.MatchString(t) || !schemaStr(d["reason"], 256) {
			return "confirmation: dismissed entries must be {trait, reason}"
		}
	}
	if !schemaStr(c["reviewer_kid"], 128) {
		return "confirmation: reviewer_kid must be a non-empty string"
	}
	if !jsIsSafeInteger(c["ts"]) || jsF(c["ts"]) < 0 {
		return "confirmation: ts must be a non-negative safe integer"
	}
	return ""
}

func verbDeclOK(vv any, units map[string]any, hasUnits bool) bool {
	return verbDeclError(vv, units, hasUnits) == ""
}

// actionSchemaShapeError is the reference actionSchemaShapeError: "" = well-formed, else the refusal text (signed: the
// sig member is required and checked).
func actionSchemaShapeError(dv any, signed bool) string {
	doc, ok := dv.(map[string]any)
	if !ok {
		return "schema is not an object"
	}
	v2 := jsStrictEq(doc["v"], jsNumber(2))
	dk := schemaDocKeys
	if v2 {
		dk = schemaDocKeysV2
	}
	if k, ok := firstUnknownKey(doc, dk); !ok {
		return "unknown member '" + k + "'"
	}
	if !jsStrictEq(doc["v"], jsNumber(1)) && !v2 {
		return "unsupported schema version"
	}
	if doc["kind"] != actionSchemaKind {
		return "kind must be '" + actionSchemaKind + "'"
	}
	if !schemaStr(doc["site"], 2048) || !schemaStr(doc["aud"], 256) || !schemaStr(doc["version"], 128) {
		return "site, aud and version must be non-empty strings"
	}
	unitsV, hasUnits := doc["units"]
	var units map[string]any
	if hasUnits {
		units, ok = unitsV.(map[string]any)
		if !ok {
			return "units must be an object"
		}
		for _, id := range sortedKeysUtf8(units) {
			if !matchUnitID(id) || jsLen(id) > 64 {
				return "unit id '" + id + "' is malformed"
			}
			u, ok := units[id].(map[string]any)
			if !ok || !schemaStr(u["kind"], 64) {
				return "unit '" + id + "' must be an object with a kind"
			}
			if !keysWithin(u, []string{"kind", "currency", "exponent"}) {
				return "unit '" + id + "': unknown member"
			}
			if c, has := u["currency"]; has && !schemaStr(c, 16) {
				return "unit '" + id + "': currency must be a string"
			}
			if e, has := u["exponent"]; has && !(jsIsNonNeg(e) && jsF(e) <= 18) {
				return "unit '" + id + "': exponent must be an integer in [0, 18]"
			}
		}
	}
	if st, has := doc["state"]; has {
		if _, ok := st.([]any); !ok {
			return "state must be an array"
		}
	}
	if v2 {
		if td, has := doc["traits_digest"]; has && !b64uOK(td, b32) {
			return "traits_digest must be a canonical base64url SHA-256 digest"
		}
		if td, has := doc["trait_defs"]; has {
			arr, ok := td.([]any)
			bad := !ok || len(arr) > 64
			for _, x := range arr {
				if _, isO := x.(map[string]any); !isO {
					bad = true
				}
			}
			if bad {
				return "trait_defs must be an array of up to 64 objects"
			}
		}
		if pv, has := doc["pack"]; has {
			pk, ok := pv.(map[string]any)
			if !ok || keysJoin(pk) != "ns,root,version" || !schemaStr(pk["ns"], 64) || !schemaStr(pk["version"], 128) || !b64uOK(pk["root"], b32) {
				return "pack must be {ns, version, root}"
			}
		}
	}
	verbs, ok := doc["verbs"].([]any)
	if !ok || len(verbs) == 0 || len(verbs) > maxSchemaVerbs {
		return fmt.Sprintf("verbs must be 1..%d entries", maxSchemaVerbs)
	}
	seen := map[string]bool{}
	for _, v := range verbs {
		if e := verbDeclErrorV(v, units, hasUnits, v2); e != "" {
			return e
		}
		name := v.(map[string]any)["verb"].(string)
		if seen[name] {
			return "verb '" + name + "' is declared twice"
		}
		seen[name] = true
	}
	sigV, hasSig := doc["sig"]
	if signed {
		s, ok := sigV.(map[string]any)
		if !ok {
			return "sig must be an object"
		}
		if k, ok := firstUnknownKey(s, schemaSigKeys); !ok {
			return "sig: unknown member '" + k + "'"
		}
		alg, algP := s["alg"]
		if e := suiteCapability(alg, algP); e != "" {
			return "sig.alg: " + e
		}
		if suiteAlgName(alg, algP) == "" {
			return "sig.alg: unsupported_suite"
		}
		if !schemaStr(s["kid"], 128) {
			return "sig.kid must be a non-empty string"
		}
		if !b64uOK(s["value"], -1) {
			return "sig.value is not canonical base64url"
		}
		if pv, has := s["pq_value"]; has && !b64uOK(pv, -1) {
			return "sig.pq_value is not canonical base64url"
		}
	} else if hasSig {
		return "an unsigned schema must not carry sig"
	}
	if _, err := canonBytes(withoutKeys(doc, "sig")); err != nil {
		return "malformed schema: " + err.Error()
	}
	return ""
}

// actionSchemaShapeOK is actionSchemaShapeError == null.
func actionSchemaShapeOK(dv any, signed bool) bool { return actionSchemaShapeError(dv, signed) == "" }

// verifyActionSchemaReason: shape, sig.kid names a listed key, sig.alg equals THAT key's suite, signature valid. "" when it
// verifies, else the reference's refusal text.
func verifyActionSchemaReason(dv any, keysV any) string {
	if e := actionSchemaShapeError(dv, true); e != "" {
		return e
	}
	d := dv.(map[string]any)
	sig := d["sig"].(map[string]any)
	keys, ok := keysV.([]any)
	if !ok {
		return "the schema keys must be an array"
	}
	var key map[string]any
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && jsStrictEq(m["kid"], sig["kid"]) {
			key = m
			break
		}
	}
	if key == nil {
		return "no schema key with kid '" + jsValueString(sig["kid"]) + "'"
	}
	if q, has := key["pq_pk"]; has {
		if _, isS := q.(string); !isS {
			return "the schema key pq_pk must be a string" // pq_pk present must be a string (JSON null is malformed)
		}
	}
	pk, ok := key["pk"].(string)
	if !ok || !b64uOK(pk, b32) {
		return "schema key pk is not canonical base64url (32 bytes)"
	}
	ka, kaP := key["alg"]
	if e := suiteCapability(ka, kaP); e != "" {
		return "schema key: " + e
	}
	sa, saP := sig["alg"]
	kn := suiteAlgName(ka, kaP)
	if kn == "" || kn != suiteAlgName(sa, saP) {
		return "sig.alg does not match the pinned key suite"
	}
	msg, ok := domainMessage(actionSchemaDomain, withoutKeys(d, "sig"))
	if !ok {
		return "schema verification error: not strictly canonical"
	}
	pq, pqP := key["pq_pk"]
	pv, _ := sig["pq_value"]
	if !verifyPinnedSuite(kn, true, pk, pq, msg, sig["value"], pv, pinOf(pk, pq, pqP)) {
		return "schema signature invalid"
	}
	return ""
}

func verifyActionSchema(dv any, keysV any) bool { return verifyActionSchemaReason(dv, keysV) == "" }

// actionSchemaDigest = hashCanonical({d: "atlas-pca/action-schema-ref/v1", s: doc}).
func actionSchemaDigest(doc any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": actionSchemaRefDomain, "s": doc})
}

// schemaVerbOf: the verb entry named verb. throws reports a reference TypeError (a null entry is dereferenced).
func schemaVerbOf(doc any, verb string) (v map[string]any, throws bool) {
	d, ok := doc.(map[string]any)
	if !ok {
		return nil, false
	}
	verbs, ok := d["verbs"].([]any)
	if !ok {
		return nil, false
	}
	for _, e := range verbs {
		if e == nil {
			return nil, true
		}
		if m, ok := e.(map[string]any); ok && m["verb"] == verb {
			return m, false
		}
	}
	return nil, false
}

// SchemaConform is the rule-14 conformance verdict (code / path empty when ok).
type SchemaConform struct {
	OK   bool
	Code string
	Path string
}

func isCalendarDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	num := func(a string) int {
		n := 0
		for i := 0; i < len(a); i++ {
			if a[i] < '0' || a[i] > '9' {
				return -1
			}
			n = n*10 + int(a[i]-'0')
		}
		return n
	}
	y, mo, d := num(s[0:4]), num(s[5:7]), num(s[8:10])
	if y < 0 || mo < 0 || d < 0 {
		return false
	}
	if y < 1 || mo < 1 || mo > 12 || d < 1 {
		return false
	}
	leap := (y%4 == 0 && y%100 != 0) || y%400 == 0
	dim := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mo-1]
	if mo == 2 && leap {
		dim = 29
	}
	return d <= dim
}

func strOK(x any, maxLen float64) bool {
	s, ok := x.(string)
	return ok && !hasLoneSurrogate(s) && float64(utf8Len(s)) <= maxLen
}

func numOr(d map[string]any, k string, dft float64) float64 {
	if x, has := d[k]; has {
		return jsF(x)
	}
	return dft
}

// paramValueViolation: "" in the declared domain, else "bad_type" / "out_of_domain".
func paramValueViolation(d map[string]any, x any) string {
	code, _ := paramValueViolationReason(d, x)
	return code
}

// paramValueViolationReason is paramValueViolation plus the reference's reason text.
func paramValueViolationReason(d map[string]any, x any) (string, string) {
	maxLen := numOr(d, "max_len", defaultMaxLen)
	values, _ := d["values"].([]any)
	_, hasValues := d["values"]
	switch d["type"] {
	case "string":
		s, ok := x.(string)
		if !ok || hasLoneSurrogate(s) {
			return "bad_type", "expected a string"
		}
		if float64(utf8Len(s)) > maxLen {
			return "out_of_domain", "longer than " + jsLenientNumber(maxLen) + " UTF-8 bytes"
		}
		if hasValues && !containsV(values, s) {
			return "out_of_domain", "not one of the declared values"
		}
		return formatViolation(d, s)
	case "object_ref":
		s, ok := x.(string)
		if !ok || hasLoneSurrogate(s) || len(s) == 0 {
			return "bad_type", "expected a non-empty id string"
		}
		if float64(utf8Len(s)) > maxLen {
			return "out_of_domain", "longer than " + jsLenientNumber(maxLen) + " UTF-8 bytes"
		}
		return formatViolation(d, s)
	case "datetime":
		s, ok := x.(string)
		if !ok {
			return "bad_type", "expected an RFC 3339 UTC string"
		}
		if m := reDatetime.FindStringSubmatch(s); m != nil && isCalendarDate(m[1]) {
			return "", ""
		}
		return "out_of_domain", "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z"
	case "duration":
		if !jsIsInt(x) {
			return "bad_type", "expected a safe integer (milliseconds)"
		}
		f := jsF(x)
		if f < 0 {
			return "out_of_domain", "a duration is not negative"
		}
		if mn, has := d["min"]; has && f < jsF(mn) {
			return "out_of_domain", "below min " + jsLenientNumber(jsF(mn))
		}
		if mx, has := d["max"]; has && f > jsF(mx) {
			return "out_of_domain", "above max " + jsLenientNumber(jsF(mx))
		}
		return "", ""
	case "integer":
		if !jsIsInt(x) {
			return "bad_type", "expected a safe integer"
		}
		f := jsF(x)
		if mn, has := d["min"]; has && f < jsF(mn) {
			return "out_of_domain", "below min " + jsLenientNumber(jsF(mn))
		}
		if mx, has := d["max"]; has && f > jsF(mx) {
			return "out_of_domain", "above max " + jsLenientNumber(jsF(mx))
		}
		return "", ""
	case "boolean":
		if _, ok := x.(bool); ok {
			return "", ""
		}
		return "bad_type", "expected a boolean"
	case "date":
		s, ok := x.(string)
		if !ok {
			return "bad_type", "expected a YYYY-MM-DD string"
		}
		if isCalendarDate(s) {
			return "", ""
		}
		return "out_of_domain", "not a calendar date YYYY-MM-DD"
	case "set":
		arr, ok := x.([]any)
		if !ok {
			return "bad_type", "expected an array of strings"
		}
		for _, e := range arr {
			if _, ok := e.(string); !ok {
				return "bad_type", "expected an array of strings"
			}
		}
		if !distinctStrings(arr) {
			return "out_of_domain", "set members must be distinct"
		}
		for _, e := range arr {
			if !containsV(values, e) {
				return "out_of_domain", "set member not among the declared values"
			}
		}
		n := float64(len(arr))
		if n < numOr(d, "min_items", 0) || n > numOr(d, "max_items", float64(len(values))) {
			return "out_of_domain", "set size outside the declared bounds"
		}
		return "", ""
	case "array":
		arr, ok := x.([]any)
		if !ok {
			return "bad_type", "expected an array"
		}
		ints := d["items"] == "integer"
		for _, e := range arr {
			if ints && !jsIsInt(e) || !ints && !strOK(e, maxLen) {
				if ints {
					return "bad_type", "array items must be safe integers"
				}
				return "bad_type", "array items must be strings of at most " + jsLenientNumber(maxLen) + " UTF-8 bytes"
			}
			if ints {
				f := jsF(e)
				if mn, has := d["min"]; has && f < jsF(mn) {
					return "out_of_domain", "array item outside min/max"
				}
				if mx, has := d["max"]; has && f > jsF(mx) {
					return "out_of_domain", "array item outside min/max"
				}
			}
		}
		n := float64(len(arr))
		if n < numOr(d, "min_items", 0) || n > numOr(d, "max_items", defaultMaxItems) {
			return "out_of_domain", "array length outside the declared bounds"
		}
		return "", ""
	}
	return "bad_type", "unknown declared type"
}

// conformAction is the closed-world map of an action to Ω or ⊠ (rule 14 step 5).
func conformAction(doc any, verb string, paramsV any) SchemaConform {
	res, _ := conformActionReason(doc, verb, paramsV)
	return res
}

// conformActionReason is conformAction plus the reference's reason text of a violation.
func conformActionReason(doc any, verb string, paramsV any) (res SchemaConform, reason string) {
	defer func() {
		if recover() != nil {
			res = SchemaConform{Code: "bad_type"} // an unusable declaration (only on an unverified document)
			reason = ""
		}
	}()
	params, ok := paramsV.(map[string]any)
	if !ok {
		return SchemaConform{Code: "params_not_object"}, "params must be a JSON object"
	}
	v, _ := schemaVerbOf(doc, verb)
	if v == nil {
		return SchemaConform{Code: "unknown_verb"}, "verb '" + verb + "' is not declared by the schema"
	}
	decls, _ := v["params"].(map[string]any)
	for _, k := range sortedKeysUtf8(params) {
		path := "action.params." + k
		if _, own := decls[path]; !own {
			return SchemaConform{Code: "undeclared_param", Path: path}, "parameter '" + path + "' is not declared for '" + verb + "'"
		}
	}
	for _, path := range sortedKeysUtf8(decls) {
		if decls[path] == nil {
			panic("null declaration")
		}
		d, _ := decls[path].(map[string]any)
		name := strings.TrimPrefix(path, "action.params.")
		x, has := params[name]
		if !has {
			if d["required"] != false {
				return SchemaConform{Code: "missing_param", Path: path}, "required parameter '" + path + "' is missing"
			}
			continue
		}
		if c, why := paramValueViolationReason(d, x); c != "" {
			return SchemaConform{Code: c, Path: path}, "'" + path + "': " + why
		}
	}
	return SchemaConform{OK: true}, ""
}

// canonProjection is env.canon: boolean "true"/"false", set as the strict canonical JSON of its members sorted by
// UTF-8 bytes, array as the strict canonical JSON as sent (present parameters only).
func canonProjection(doc any, verb string, params map[string]any) (map[string]any, bool) {
	out := map[string]any{}
	v, _ := schemaVerbOf(doc, verb)
	if v == nil {
		return out, true
	}
	decls, _ := v["params"].(map[string]any)
	for _, path := range sortedKeysUtf8(decls) {
		d, _ := decls[path].(map[string]any)
		name := strings.TrimPrefix(path, "action.params.")
		x, has := params[name]
		if !has {
			continue
		}
		switch d["type"] {
		case "boolean":
			if x == true {
				out[name] = "true"
			} else {
				out[name] = "false"
			}
		case "set":
			arr, _ := x.([]any)
			ss := make([]string, len(arr))
			for i, e := range arr {
				ss[i], _ = e.(string)
			}
			sortUtf8(ss)
			items := make([]any, len(ss))
			for i, s := range ss {
				items[i] = s
			}
			c, err := Canonicalize(items)
			if err != nil {
				return nil, false
			}
			out[name] = c
		case "array":
			c, err := Canonicalize(x)
			if err != nil {
				return nil, false
			}
			out[name] = c
		}
	}
	return out, true
}

// accumulationParams: the integer params of a verb entry listing unit in accumulates_into, in UTF-8 order. throws
// reports a reference TypeError (an unusable entry of an unverified document).
func accumulationParams(v map[string]any, unit string) (out []string, throws bool) {
	pv, has := v["params"]
	if !has || pv == nil {
		return nil, true
	}
	params, ok := pv.(map[string]any)
	if !ok {
		return nil, false
	}
	for _, p := range sortedKeysUtf8(params) {
		d, ok := params[p].(map[string]any)
		if params[p] == nil {
			return nil, true
		}
		if !ok || d["type"] != "integer" {
			continue
		}
		ai, has := d["accumulates_into"]
		if !has || ai == nil {
			continue
		}
		switch t := ai.(type) {
		case []any:
			if containsV(t, unit) {
				out = append(out, p)
			}
		case string:
			if strings.Contains(t, unit) {
				out = append(out, p)
			}
		default:
			return nil, true
		}
	}
	return out, false
}
