package pca

// The semantic firewall (`tool_schema` caveats, TypeScript agent-native.ts evaluateToolSchema) and the agent-native
// caveat evaluator (TypeScript evaluateAgentCaveats) Authorize runs over the envelope, root and delegated caveats.
//
// Schema values follow the JavaScript reference: string lengths count UTF-16 code units, an integer is a finite double
// with no fraction (3.0 is an integer), `enum` / `const` compare with `===` (a bool is never a number, numbers compare
// as doubles), and key presence (not null) decides optional members. Where the reference reports the first offending
// member in insertion order, Go reports the first in sorted key order (the same for a single offender).

import (
	"math"
	"sort"
	"strings"
	"unicode/utf16"
)

// Limits of a tool_schema argument schema and of the values checked against it.
const (
	MaxSchemaDepth         = 8
	MaxSchemaNodes         = 256
	MaxObjectProps         = 64
	MaxEnumValues          = 256
	DefaultMaxArrayItems   = 256
	AbsoluteMaxArrayItems  = 4096
	DefaultMaxStringLen    = 65_536
	AbsoluteMaxStringLen   = 1_048_576
	MaxSchemaValueNodes    = 10_000
	maxSchemaConstLen      = 1024
	maxSchemaPrefixLen     = 512
	maxShownArgumentLength = 48
)

var specKeys = map[string][]string{
	"string":  {"type", "enum", "const", "minLength", "maxLength", "prefix"},
	"number":  {"type", "enum", "const", "min", "max"},
	"integer": {"type", "enum", "const", "min", "max"},
	"boolean": {"type", "enum", "const"},
	"object":  {"type", "props", "required"},
	"array":   {"type", "items", "minItems", "maxItems"},
}

// ToolCall is a tool invocation checked against a tool_schema caveat. Args nil is a malformed call;
// ToolSignatureDigest nil means the PCActn signed no tool_binding.
type ToolCall struct {
	Tool                string
	Args                map[string]any
	ToolSignatureDigest *string
}

func safeSchemaName(n string) bool {
	if len(n) < 1 || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func schemaIsInt(x any) bool {
	f, ok := finNum(x)
	return ok && f == math.Trunc(f)
}

func nonNegIntUpTo(x any, mx float64) bool {
	f, ok := finNum(x)
	return ok && f == math.Trunc(f) && f >= 0 && f <= mx
}

func onlyKeys(o map[string]any, allowed []string) bool {
	for k := range o {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func schemaKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// schemaEq is JavaScript `===` on the scalars a schema can hold (numbers compare as doubles; a bool is never a
// number).
func schemaEq(a, b any) bool {
	fa, oka := finNum(a)
	fb, okb := finNum(b)
	if oka || okb {
		return oka && okb && fa == fb
	}
	if ba, ok := a.(bool); ok {
		bb, ok := b.(bool)
		return ok && ba == bb
	}
	if sa, ok := a.(string); ok {
		sb, ok := b.(string)
		return ok && sa == sb
	}
	return false
}

// ValidateArgSchema validates a tool_schema argument schema (closed; shape, depth, node count, bounds). "" when valid.
func ValidateArgSchema(schema any) string {
	s, ok := schema.(map[string]any)
	if !ok {
		return "schema must be an object"
	}
	if !onlyKeys(s, []string{"props", "required"}) {
		return "unknown schema key"
	}
	req, hasReq := s["required"]
	nodes := 0
	return objectSchemaError(s["props"], req, hasReq, 1, &nodes)
}

func objectSchemaError(propsV, required any, hasRequired bool, depth int, nodes *int) string {
	if depth > MaxSchemaDepth {
		return "schema too deep"
	}
	*nodes++
	if *nodes > MaxSchemaNodes {
		return "schema too large"
	}
	props, ok := propsV.(map[string]any)
	if !ok {
		return "props must be an object"
	}
	if len(props) > MaxObjectProps {
		return "too many props"
	}
	for _, n := range schemaKeys(props) {
		if !safeSchemaName(n) {
			return "invalid property name '" + truncUnits(n, 32) + "'"
		}
		if e := specError(props[n], depth+1, nodes); e != "" {
			return n + ": " + e
		}
	}
	if hasRequired {
		r, ok := required.([]any)
		if !ok || len(r) > MaxObjectProps {
			return "required must be a short array"
		}
		for _, x := range r {
			s, ok := x.(string)
			if _, declared := props[s]; !ok || !declared {
				return "required names an undeclared property"
			}
		}
	}
	return ""
}

func specError(specV any, depth int, nodes *int) string {
	if depth > MaxSchemaDepth {
		return "schema too deep"
	}
	*nodes++
	if *nodes > MaxSchemaNodes {
		return "schema too large"
	}
	spec, ok := specV.(map[string]any)
	t, isStr := spec["type"].(string)
	allowed, known := specKeys[t]
	if !ok || !isStr || !known {
		return "unknown type"
	}
	if !onlyKeys(spec, allowed) {
		return "unknown spec key"
	}
	if t == "object" {
		*nodes-- // counted once by objectSchemaError
		req, hasReq := spec["required"]
		return objectSchemaError(spec["props"], req, hasReq, depth, nodes)
	}
	if t == "array" {
		mi, hasMin := spec["minItems"]
		ma, hasMax := spec["maxItems"]
		if hasMin && !nonNegIntUpTo(mi, AbsoluteMaxArrayItems) {
			return "bad minItems"
		}
		if hasMax && !nonNegIntUpTo(ma, AbsoluteMaxArrayItems) {
			return "bad maxItems"
		}
		if hasMin && hasMax && jsF(mi) > jsF(ma) {
			return "minItems > maxItems"
		}
		return specError(spec["items"], depth+1, nodes)
	}
	valueOK := func(v any) bool {
		switch t {
		case "string":
			s, ok := v.(string)
			return ok && jsLen(s) <= maxSchemaConstLen
		case "boolean":
			_, ok := v.(bool)
			return ok
		}
		_, ok := finNum(v)
		return ok && (t == "number" || schemaIsInt(v))
	}
	if c, has := spec["const"]; has && !valueOK(c) {
		return "bad const"
	}
	if ev, has := spec["enum"]; has {
		en, ok := ev.([]any)
		if !ok || len(en) == 0 || len(en) > MaxEnumValues {
			return "bad enum"
		}
		for _, x := range en {
			if !valueOK(x) {
				return "bad enum"
			}
		}
	}
	switch t {
	case "string":
		mi, hasMin := spec["minLength"]
		ma, hasMax := spec["maxLength"]
		if hasMin && !nonNegIntUpTo(mi, AbsoluteMaxStringLen) {
			return "bad minLength"
		}
		if hasMax && !nonNegIntUpTo(ma, AbsoluteMaxStringLen) {
			return "bad maxLength"
		}
		if hasMin && hasMax && jsF(mi) > jsF(ma) {
			return "minLength > maxLength"
		}
		if pv, has := spec["prefix"]; has {
			if s, ok := pv.(string); !ok || jsLen(s) > maxSchemaPrefixLen {
				return "bad prefix"
			}
		}
	case "number", "integer":
		mi, hasMin := spec["min"]
		ma, hasMax := spec["max"]
		fmin, okMin := finNum(mi)
		fmax, okMax := finNum(ma)
		if hasMin && !okMin {
			return "bad min"
		}
		if hasMax && !okMax {
			return "bad max"
		}
		if hasMin && hasMax && fmin > fmax {
			return "min > max"
		}
	}
	return ""
}

// truncUnits is s.slice(0, n) over UTF-16 code units.
func truncUnits(s string, n int) string {
	u := utf16Units(s)
	if len(u) <= n {
		return s
	}
	return string(utf16.Decode(u[:n]))
}

// showArg is the reference `show`: JSON.stringify of the name, cut to 48 code units with an ellipsis.
func showArg(k string) string {
	if jsLen(k) > maxShownArgumentLength {
		k = truncUnits(k, maxShownArgumentLength) + "…"
	}
	var sb strings.Builder
	if jsString(&sb, k) != nil {
		return `"` + k + `"`
	}
	return sb.String()
}

func checkSchemaValue(spec map[string]any, v any, path string, depth int, n *int) string {
	if depth > MaxSchemaDepth+1 {
		return path + ": too deep"
	}
	*n++
	if *n > MaxSchemaValueNodes {
		return path + ": too many values"
	}
	t, _ := spec["type"].(string)
	switch t {
	case "object":
		o, ok := v.(map[string]any)
		if !ok {
			return path + ": expected object"
		}
		props, _ := spec["props"].(map[string]any)
		return checkSchemaObject(props, spec["required"], o, path, depth, n)
	case "array":
		a, ok := v.([]any)
		if !ok {
			return path + ": expected array"
		}
		mx := float64(DefaultMaxArrayItems)
		if m, has := spec["maxItems"]; has {
			mx = jsF(m)
		}
		mx = math.Min(mx, AbsoluteMaxArrayItems)
		if float64(len(a)) > mx {
			return path + ": exceeds maxItems"
		}
		if m, has := spec["minItems"]; has && float64(len(a)) < jsF(m) {
			return path + ": below minItems"
		}
		items, _ := spec["items"].(map[string]any)
		for i, x := range a {
			if e := checkSchemaValue(items, x, path+"["+itoa(i)+"]", depth+1, n); e != "" {
				return e
			}
		}
		return ""
	case "string":
		s, ok := v.(string)
		if !ok {
			return path + ": wrong type (expected string)"
		}
		l := float64(jsLen(s))
		mx := float64(DefaultMaxStringLen)
		if m, has := spec["maxLength"]; has {
			mx = jsF(m)
		}
		if l > math.Min(mx, AbsoluteMaxStringLen) {
			return path + ": exceeds maxLength"
		}
		if m, has := spec["minLength"]; has && l < jsF(m) {
			return path + ": below minLength"
		}
		if pv, has := spec["prefix"]; has {
			pre, _ := pv.(string)
			if !jsStartsWith(s, pre) {
				return path + ": violates prefix"
			}
		}
	case "number", "integer":
		f, ok := finNum(v)
		if !ok || (t == "integer" && f != math.Trunc(f)) {
			return path + ": wrong type (expected " + t + ")"
		}
		if m, has := spec["min"]; has && f < jsF(m) {
			return path + ": below min"
		}
		if m, has := spec["max"]; has && f > jsF(m) {
			return path + ": above max"
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return path + ": wrong type (expected boolean)"
		}
	default:
		return path + ": unknown type"
	}
	if c, has := spec["const"]; has && !schemaEq(c, v) {
		return path + ": violates const"
	}
	if ev, has := spec["enum"]; has {
		en, _ := ev.([]any)
		hit := false
		for _, e := range en {
			if schemaEq(e, v) {
				hit = true
				break
			}
		}
		if !hit {
			return path + ": violates enum"
		}
	}
	return ""
}

func checkSchemaObject(props map[string]any, required any, obj map[string]any, path string, depth int, n *int) string {
	keys := schemaKeys(obj)
	for _, k := range keys {
		if _, declared := props[k]; !declared {
			return path + ": unexpected argument " + showArg(k)
		}
	}
	req, _ := required.([]any)
	for _, rv := range req {
		r, _ := rv.(string)
		if _, has := obj[r]; !has {
			return path + ": missing required argument '" + r + "'"
		}
	}
	for _, k := range keys {
		spec, _ := props[k].(map[string]any)
		if e := checkSchemaValue(spec, obj[k], path+"."+k, depth+1, n); e != "" {
			return e
		}
	}
	return ""
}

// EvaluateToolSchema evaluates a tool call against a `tool_schema` caveat {type, tool, signature_digest?, schema,
// schema_digest, binding_digest}. It returns (true, "") when the call is admitted, else (false, reason). The schema is
// validated and both digests are recomputed before the call is looked at. Same rules and reason texts as the
// TypeScript evaluateToolSchema. Never panics.
func EvaluateToolSchema(caveat any, call *ToolCall) (ok bool, reason string) {
	defer func() {
		if recover() != nil {
			ok, reason = false, "evaluation error (fail closed)"
		}
	}()
	c, isMap := caveat.(map[string]any)
	tool, _ := c["tool"].(string)
	if !isMap || c["type"] != "tool_schema" || tool == "" {
		return false, "malformed tool_schema caveat"
	}
	if e := ValidateArgSchema(c["schema"]); e != "" {
		return false, "malformed tool_schema caveat: " + e
	}
	sd, err := HashCanonical(c["schema"])
	if err != nil {
		return false, "evaluation error (fail closed)"
	}
	if any(sd) != c["schema_digest"] {
		return false, "schema digest mismatch"
	}
	bd, err := HashCanonical(map[string]any{"tool": tool, "signature_digest": jsMemberString(c, "signature_digest"),
		"schema": c["schema"]})
	if err != nil {
		return false, "evaluation error (fail closed)"
	}
	if any(bd) != c["binding_digest"] {
		return false, "binding digest mismatch"
	}
	if call == nil || call.Args == nil {
		return false, "malformed call"
	}
	if call.Tool != tool {
		return false, "tool " + showArg(call.Tool) + " not authorized"
	}
	if call.ToolSignatureDigest != nil && any(*call.ToolSignatureDigest) != c["signature_digest"] {
		return false, "signed tool_binding differs from the authorized tool signature"
	}
	schema := c["schema"].(map[string]any)
	props, _ := schema["props"].(map[string]any)
	n := 0
	if e := checkSchemaObject(props, schema["required"], call.Args, "args", 1, &n); e != "" {
		return false, e
	}
	return true, ""
}

// ---- the agent-native caveat evaluator ------------------------------------------------------------------------------

func agentCaveatSatisfied(cv any, ctx, actionCtx map[string]any, tc *ToolCall, b *regexBudget) (sat bool) {
	defer func() {
		if recover() != nil {
			sat = false
		}
	}()
	c, ok := cv.(map[string]any)
	if !ok {
		return false
	}
	switch c["type"] {
	case "tool_schema":
		ok, _ := EvaluateToolSchema(c, tc)
		return ok
	case "predicates":
		allow, ok := c["allow"].([]any)
		if !ok {
			return false
		}
		for _, p := range allow {
			if predicateMatches(p, actionCtx, b) {
				return true
			}
		}
		return false
	}
	// max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
	ok, _ = EvaluateCaveats([]any{cv}, ctx)
	return ok
}

// EvaluateAgentCaveats evaluates caveats with the agent-native evaluator: the stock types of EvaluateCaveats, plus
// `predicates` (`allow`: the action must match one predicate; needs actionCtx = {"action": {...}, "subject"?, "env"?})
// and `tool_schema` (needs toolCall). ctx is the stock context (now, action, blast_radius, ...). Unknown types fail
// closed. Returns (ok, failed types) like EvaluateCaveats. Never panics.
func EvaluateAgentCaveats(caveats any, ctx, actionCtx map[string]any, toolCall *ToolCall) (ok bool, failed []string) {
	return evaluateAgentCaveats(caveats, ctx, actionCtx, toolCall, &regexBudget{})
}

func evaluateAgentCaveats(caveats any, ctx, actionCtx map[string]any, toolCall *ToolCall, b *regexBudget) (ok bool, failed []string) {
	defer func() {
		if recover() != nil {
			ok, failed = false, []string{"<evaluation error>"}
		}
	}()
	list, isArr := caveats.([]any)
	if !isArr {
		return false, []string{"<malformed caveats>"}
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	failed = []string{}
	for _, cv := range list {
		if !agentCaveatSatisfied(cv, ctx, actionCtx, toolCall, b) {
			name := "<malformed>"
			if m, isMap := cv.(map[string]any); isMap {
				if t, isStr := m["type"].(string); isStr {
					name = t
				}
			}
			failed = append(failed, name)
		}
	}
	return len(failed) == 0, failed
}
