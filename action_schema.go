package pca

// Signed action schemas and the closed-world conformance of rule 14 (packages/pca/src/action-schema.ts):
// `pca-action-schema` v1 shape, the site signature under the discovery key entry (the entry pins the suite), the
// content digest, and conformAction (params_not_object, unknown_verb, undeclared_param, missing_param, bad_type,
// out_of_domain; first failure wins, keys in UTF-8 byte order).

import "strings"

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
)

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

func paramDeclOK(path string, dv any, units map[string]any, hasUnits bool) bool {
	if !matchParamPath(path) || forbiddenSegments[strings.TrimPrefix(path, "action.params.")] {
		return false // __proto__ / constructor / prototype are reserved parameter names
	}
	d, ok := dv.(map[string]any)
	if !ok || !keysWithin(d, schemaParamKeys) || !strIn(d["type"], paramTypes) || !schemaStr(d["semantic"], 128) || !strIn(d["sensitivity"], sensitivities) {
		return false
	}
	typ := d["type"].(string)
	if r, has := d["required"]; has {
		if _, ok := r.(bool); !ok {
			return false
		}
	}
	values, hasValues := d["values"]
	if hasValues {
		arr, ok := values.([]any)
		if !ok || len(arr) == 0 || len(arr) > maxSchemaValues {
			return false
		}
		for _, x := range arr {
			if !schemaStr(x, 256) {
				return false
			}
		}
		if !distinctStrings(arr) || (typ != "string" && typ != "set") {
			return false
		}
	}
	if typ == "set" && !hasValues {
		return false
	}
	for _, k := range []string{"min", "max"} {
		if x, has := d[k]; has && (!jsIsInt(x) || (typ != "integer" && !(typ == "array" && d["items"] == "integer"))) {
			return false
		}
	}
	if jsIsInt(d["min"]) && jsIsInt(d["max"]) && jsF(d["min"]) > jsF(d["max"]) {
		return false
	}
	if u, has := d["unit"]; has {
		us, isS := u.(string)
		if typ != "integer" || !isS || !hasUnits {
			return false
		}
		if _, own := units[us]; !own {
			return false
		}
	}
	if x, has := d["max_len"]; has && (!jsIsInt(x) || jsF(x) < 1) {
		return false
	}
	if x, has := d["items"]; has && (typ != "array" || !schemaStr(x, 64)) {
		return false
	}
	for _, k := range []string{"min_items", "max_items"} {
		if x, has := d[k]; has && (!jsIsNonNeg(x) || (typ != "set" && typ != "array")) {
			return false
		}
	}
	if jsIsInt(d["min_items"]) && jsIsInt(d["max_items"]) && jsF(d["min_items"]) > jsF(d["max_items"]) {
		return false
	}
	if dflt, has := d["default"]; has && dflt == nil {
		return false // a null default is malformed (absent = no default)
	}
	pnd, hasPnd := d["principal_neutral_default"]
	if hasPnd {
		b, ok := pnd.(bool)
		if !ok {
			return false
		}
		if _, hasDef := d["default"]; b && !hasDef {
			return false
		}
	}
	if ai, has := d["accumulates_into"]; has {
		arr, ok := ai.([]any)
		if typ != "integer" || !ok || len(arr) == 0 || len(arr) > 8 {
			return false
		}
		for _, u := range arr {
			s, ok := u.(string)
			if !ok || jsLen(s) > 64 || !matchUnitID(s) {
				return false
			}
		}
		if !distinctStrings(arr) {
			return false
		}
	}
	if x, has := d["issued_by_site"]; has {
		if _, ok := x.(bool); !ok {
			return false
		}
	}
	if x, has := d["description"]; has && !schemaStr(x, 1024) {
		return false
	}
	return true
}

func verbDeclOK(vv any, units map[string]any, hasUnits bool) bool {
	v, ok := vv.(map[string]any)
	if !ok || !keysWithin(v, schemaVerbKeys) || !schemaStr(v["verb"], 128) {
		return false
	}
	if k := v["kind"]; k != "read" && k != "write" {
		return false
	}
	params, ok := v["params"].(map[string]any)
	if !ok || len(params) > maxSchemaParams {
		return false
	}
	for p, d := range params {
		if !paramDeclOK(p, d, units, hasUnits) {
			return false
		}
	}
	if x, has := v["reversibility"]; has && !strIn(x, schemaReversibles) {
		return false
	}
	if x, has := v["reversibility_by"]; has {
		r, ok := x.(map[string]any)
		if !ok || !keysWithin(r, []string{"param", "map", "default"}) {
			return false
		}
		ps, ok := r["param"].(string)
		if !ok {
			return false
		}
		if _, own := params[ps]; !own {
			return false
		}
		m, ok := r["map"].(map[string]any)
		if !ok || len(m) == 0 {
			return false
		}
		for _, y := range m {
			if !strIn(y, schemaReversibles) {
				return false
			}
		}
		if dft, has := r["default"]; has && !strIn(dft, schemaReversibles) {
			return false
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
	if !single("mcp", "tool", 128) || !single("openapi", "operationId", 128) {
		return false
	}
	for _, k := range []string{"harm", "effects", "returns"} {
		if x, has := v[k]; has {
			if _, ok := x.(map[string]any); !ok {
				return false
			}
		}
	}
	if x, has := v["world"]; has {
		if _, ok := x.([]any); !ok {
			return false
		}
	}
	if x, has := v["description"]; has && !schemaStr(x, 1024) {
		return false
	}
	return true
}

// actionSchemaShapeOK is actionSchemaShapeError == null (signed: the sig member is required and checked).
func actionSchemaShapeOK(dv any, signed bool) bool {
	doc, ok := dv.(map[string]any)
	if !ok || !keysWithin(doc, schemaDocKeys) || !jsStrictEq(doc["v"], jsNumber(1)) || doc["kind"] != actionSchemaKind {
		return false
	}
	if !schemaStr(doc["site"], 2048) || !schemaStr(doc["aud"], 256) || !schemaStr(doc["version"], 128) {
		return false
	}
	unitsV, hasUnits := doc["units"]
	var units map[string]any
	if hasUnits {
		units, ok = unitsV.(map[string]any)
		if !ok {
			return false
		}
		for id, uv := range units {
			if !matchUnitID(id) || jsLen(id) > 64 {
				return false
			}
			u, ok := uv.(map[string]any)
			if !ok || !schemaStr(u["kind"], 64) || !keysWithin(u, []string{"kind", "currency", "exponent"}) {
				return false
			}
			if c, has := u["currency"]; has && !schemaStr(c, 16) {
				return false
			}
			if e, has := u["exponent"]; has && !(jsIsNonNeg(e) && jsF(e) <= 18) {
				return false
			}
		}
	}
	if st, has := doc["state"]; has {
		if _, ok := st.([]any); !ok {
			return false
		}
	}
	verbs, ok := doc["verbs"].([]any)
	if !ok || len(verbs) == 0 || len(verbs) > maxSchemaVerbs {
		return false
	}
	seen := map[string]bool{}
	for _, v := range verbs {
		if !verbDeclOK(v, units, hasUnits) {
			return false
		}
		name := v.(map[string]any)["verb"].(string)
		if seen[name] {
			return false
		}
		seen[name] = true
	}
	sigV, hasSig := doc["sig"]
	if signed {
		s, ok := sigV.(map[string]any)
		if !ok || !keysWithin(s, schemaSigKeys) {
			return false
		}
		alg, algP := s["alg"]
		if suiteAlgName(alg, algP) == "" || !schemaStr(s["kid"], 128) || !b64uOK(s["value"], -1) {
			return false
		}
		if pv, has := s["pq_value"]; has && !b64uOK(pv, -1) {
			return false
		}
	} else if hasSig {
		return false
	}
	_, ok = strictBytes(withoutKeys(doc, "sig"))
	return ok
}

// verifyActionSchema: shape, sig.kid names a listed key, sig.alg equals THAT key's suite, signature valid.
func verifyActionSchema(dv any, keysV any) bool {
	if !actionSchemaShapeOK(dv, true) {
		return false
	}
	d := dv.(map[string]any)
	sig := d["sig"].(map[string]any)
	keys, ok := keysV.([]any)
	if !ok {
		return false
	}
	var key map[string]any
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && jsStrictEq(m["kid"], sig["kid"]) {
			key = m
			break
		}
	}
	if key == nil {
		return false
	}
	pk, ok := key["pk"].(string)
	if !ok || !b64uOK(pk, b32) {
		return false
	}
	if q, has := key["pq_pk"]; has {
		if _, isS := q.(string); !isS {
			return false // pq_pk present must be a string (JSON null is malformed)
		}
	}
	ka, kaP := key["alg"]
	sa, saP := sig["alg"]
	kn := suiteAlgName(ka, kaP)
	if kn == "" || kn != suiteAlgName(sa, saP) {
		return false
	}
	msg, ok := domainMessage(actionSchemaDomain, withoutKeys(d, "sig"))
	if !ok {
		return false
	}
	pq, pqP := key["pq_pk"]
	pv, _ := sig["pq_value"]
	return verifyPinnedSuite(kn, true, pk, pq, msg, sig["value"], pv, pinOf(pk, pq, pqP))
}

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
	maxLen := numOr(d, "max_len", defaultMaxLen)
	values, _ := d["values"].([]any)
	_, hasValues := d["values"]
	switch d["type"] {
	case "string":
		s, ok := x.(string)
		if !ok || hasLoneSurrogate(s) {
			return "bad_type"
		}
		if float64(utf8Len(s)) > maxLen {
			return "out_of_domain"
		}
		if hasValues && !containsV(values, s) {
			return "out_of_domain"
		}
		return ""
	case "integer":
		if !jsIsInt(x) {
			return "bad_type"
		}
		f := jsF(x)
		if mn, has := d["min"]; has && f < jsF(mn) {
			return "out_of_domain"
		}
		if mx, has := d["max"]; has && f > jsF(mx) {
			return "out_of_domain"
		}
		return ""
	case "boolean":
		if _, ok := x.(bool); ok {
			return ""
		}
		return "bad_type"
	case "date":
		s, ok := x.(string)
		if !ok {
			return "bad_type"
		}
		if isCalendarDate(s) {
			return ""
		}
		return "out_of_domain"
	case "set":
		arr, ok := x.([]any)
		if !ok {
			return "bad_type"
		}
		for _, e := range arr {
			if _, ok := e.(string); !ok {
				return "bad_type"
			}
		}
		if !distinctStrings(arr) {
			return "out_of_domain"
		}
		for _, e := range arr {
			if !containsV(values, e) {
				return "out_of_domain"
			}
		}
		n := float64(len(arr))
		if n < numOr(d, "min_items", 0) || n > numOr(d, "max_items", float64(len(values))) {
			return "out_of_domain"
		}
		return ""
	case "array":
		arr, ok := x.([]any)
		if !ok {
			return "bad_type"
		}
		ints := d["items"] == "integer"
		for _, e := range arr {
			if ints && !jsIsInt(e) || !ints && !strOK(e, maxLen) {
				return "bad_type"
			}
			if ints {
				f := jsF(e)
				if mn, has := d["min"]; has && f < jsF(mn) {
					return "out_of_domain"
				}
				if mx, has := d["max"]; has && f > jsF(mx) {
					return "out_of_domain"
				}
			}
		}
		n := float64(len(arr))
		if n < numOr(d, "min_items", 0) || n > numOr(d, "max_items", defaultMaxItems) {
			return "out_of_domain"
		}
		return ""
	}
	return "bad_type"
}

// conformAction is the closed-world map of an action to Ω or ⊠ (rule 14 step 5).
func conformAction(doc any, verb string, paramsV any) (res SchemaConform) {
	defer func() {
		if recover() != nil {
			res = SchemaConform{Code: "bad_type"} // an unusable declaration (only on an unverified document)
		}
	}()
	params, ok := paramsV.(map[string]any)
	if !ok {
		return SchemaConform{Code: "params_not_object"}
	}
	v, _ := schemaVerbOf(doc, verb)
	if v == nil {
		return SchemaConform{Code: "unknown_verb"}
	}
	decls, _ := v["params"].(map[string]any)
	for _, k := range sortedKeysUtf8(params) {
		path := "action.params." + k
		if _, own := decls[path]; !own {
			return SchemaConform{Code: "undeclared_param", Path: path}
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
				return SchemaConform{Code: "missing_param", Path: path}
			}
			continue
		}
		if c := paramValueViolation(d, x); c != "" {
			return SchemaConform{Code: c, Path: path}
		}
	}
	return SchemaConform{OK: true}
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
