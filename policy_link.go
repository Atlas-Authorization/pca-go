package pca

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// Linked policy templates (security contract C-242, C-243): a port of packages/pca/src/policy-link.ts (the TypeScript is
// authoritative). Template definitions, instantiation with closed slot domains, signed templates and tighten overlays, and
// resolution of a grant's `template_ref`. Total: anything malformed fails closed. Where several problems exist the reported one
// follows sorted key order (Go maps carry no insertion order); the vectors each contain a single problem.

const (
	templateSigDomain = "atlas-pca/policy-template/v1\x00"
	tightenSigDomain  = "atlas-pca/template-tighten/v1\x00"
	maxTemplateSlots  = 32
	maxSlotString     = 256
	maxSlotSet        = 64
)

var templateNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

const templateNameSource = "^[a-z][a-z0-9_]{0,63}$"

func linkSortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func u16len(s string) int { return len(utf16.Encode([]rune(s))) }

func linkMessage(domain, digest string) []byte {
	h := sha256.Sum256([]byte(digest))
	return append([]byte(domain), h[:]...)
}

func isStrList(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(l))
	for i, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func scanSlots(v any, decl map[string]any, used map[string]bool) string {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if r := scanSlots(e, decl, used); r != "" {
				return r
			}
		}
	case map[string]any:
		for _, k := range linkSortedKeys(x) {
			if k == "__proto__" || k == "constructor" || k == "prototype" {
				return fmt.Sprintf("body has the forbidden key '%s'", k)
			}
		}
		if name, has := x["$slot"]; has {
			for _, k := range linkSortedKeys(x) {
				if k != "$slot" && k != "pre" && k != "post" {
					return fmt.Sprintf("placeholder has unknown member '%s'", k)
				}
			}
			s, ok := name.(string)
			if _, declared := decl[s]; !ok || !declared {
				return fmt.Sprintf("placeholder names undeclared slot '%s'", linkJSString(name))
			}
			for _, k := range []string{"pre", "post"} {
				if p, has := x[k]; has {
					if _, ok := p.(string); !ok {
						return fmt.Sprintf("placeholder %s must be a string", k)
					}
				}
			}
			used[s] = true
			return ""
		}
		for _, k := range linkSortedKeys(x) {
			if r := scanSlots(x[k], decl, used); r != "" {
				return r
			}
		}
	}
	return ""
}

func linkJSString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case json.Number:
		return string(x)
	}
	return fmt.Sprint(v)
}

// TemplateDefError is "" for a well formed template definition, else the first problem.
func TemplateDefError(def any) string {
	d, ok := def.(map[string]any)
	if !ok {
		return "template must be an object"
	}
	if d["v"] != jsonOne() || d["kind"] != "pca-policy-template" {
		return "template v / kind mismatch"
	}
	if id, ok := d["id"].(string); !ok || !templateNameRe.MatchString(id) {
		return "template id must match " + templateNameSource
	}
	if v, ok := d["version"].(string); !ok || len(v) == 0 || u16len(v) > 64 {
		return "template version must be a string of 1..64 characters"
	}
	slots, ok := d["slots"].(map[string]any)
	if !ok {
		return "slots must be an object"
	}
	names := linkSortedKeys(slots)
	if len(names) > maxTemplateSlots {
		return fmt.Sprintf("more than %d slots", maxTemplateSlots)
	}
	for _, n := range names {
		if !templateNameRe.MatchString(n) {
			return fmt.Sprintf("slot name '%s' must match %s", n, templateNameSource)
		}
		s, ok := slots[n].(map[string]any)
		if !ok {
			return fmt.Sprintf("slot '%s' must be an object", n)
		}
		typ, _ := s["type"].(string)
		if typ != "string" && typ != "integer" && typ != "set" {
			return fmt.Sprintf("slot '%s'.type must be string, integer or set", n)
		}
		if _, isList := s["values"].([]any); typ == "set" && !isList {
			return fmt.Sprintf("set slot '%s' needs a closed values list", n)
		}
		if vals, has := s["values"]; has {
			l, ok := isStrList(vals)
			if !ok || len(l) > maxSlotSet {
				return fmt.Sprintf("slot '%s'.values must be a list of strings", n)
			}
		}
		if typ == "integer" {
			for _, k := range []string{"min", "max"} {
				if v, has := s[k]; has {
					if _, ok := safeInt(v); !ok {
						return fmt.Sprintf("slot '%s'.%s must be a safe integer", n, k)
					}
				}
			}
		}
	}
	body, ok := d["body"].(map[string]any)
	if _, isList := body["predicates"].([]any); !ok || !isList {
		return "body.predicates must be an array"
	}
	if c, has := body["caveats"]; has {
		if _, ok := c.([]any); !ok {
			return "body.caveats must be an array"
		}
	}
	used := map[string]bool{}
	if r := scanSlots(body, slots, used); r != "" {
		return r
	}
	for _, n := range names {
		if !used[n] {
			return fmt.Sprintf("slot '%s' is declared but never used", n)
		}
	}
	return ""
}

// TemplateDigest is hashCanonical of the definition.
func TemplateDigest(def any) (string, error) { return HashCanonical(def) }

func trustedSigner(trusted []string, signer any) (string, bool) {
	s, ok := signer.(string)
	if !ok {
		return "", false
	}
	for _, t := range trusted {
		if t == s {
			return s, true
		}
	}
	return "", false
}

func verifySigned(key, msgDomain string, digest string, sig any) bool {
	pk, ok := DecodeB64uStrict(key, 32)
	s, ok2 := sig.(string)
	if !ok || !ok2 {
		return false
	}
	sg, ok3 := DecodeB64uStrict(s, 64)
	return ok3 && VerifyStrict(pk, linkMessage(msgDomain, digest), sg)
}

// VerifyTemplate checks a signed template ({def, signer, sig}) against the trusted organisation keys: ("", true) or (reason, false).
func VerifyTemplate(t any, trusted []string) (string, bool) {
	m, _ := t.(map[string]any)
	if e := TemplateDefError(m["def"]); e != "" {
		return e, false
	}
	signer, ok := trustedSigner(trusted, m["signer"])
	if !ok {
		return "template signer is not trusted", false
	}
	digest, err := HashCanonical(m["def"])
	if err != nil || !verifySigned(signer, templateSigDomain, digest, m["sig"]) {
		return "bad template signature", false
	}
	return "", true
}

// TightenOverlayError is "" for a well formed overlay: it may only add where conditions and caveats.
func TightenOverlayError(o any) string {
	m, ok := o.(map[string]any)
	if !ok {
		return "overlay must be an object"
	}
	if m["v"] != jsonOne() || m["kind"] != "pca-template-tighten" {
		return "overlay v / kind mismatch"
	}
	for _, k := range linkSortedKeys(m) {
		switch k {
		case "v", "kind", "template_id", "version_digest", "add_where", "add_caveats":
		default:
			return fmt.Sprintf("overlay has unknown member '%s' (an overlay can only add where conditions and caveats)", k)
		}
	}
	if id, ok := m["template_id"].(string); !ok || !templateNameRe.MatchString(id) {
		return "overlay template_id invalid"
	}
	if d, ok := m["version_digest"].(string); !ok || len(d) == 0 {
		return "overlay version_digest invalid"
	}
	if w, has := m["add_where"]; has {
		l, ok := w.([]any)
		if !ok {
			return "overlay add_where must be a list of conditions"
		}
		for _, c := range l {
			if _, ok := c.(map[string]any); !ok {
				return "overlay add_where must be a list of conditions"
			}
		}
	}
	if w, has := m["add_caveats"]; has {
		l, ok := w.([]any)
		if !ok {
			return "overlay add_caveats must be a list of caveats"
		}
		for _, c := range l {
			cm, ok := c.(map[string]any)
			if _, isStr := cm["type"].(string); !ok || !isStr {
				return "overlay add_caveats must be a list of caveats"
			}
		}
	}
	return ""
}

// VerifyTighten checks a signed overlay ({overlay, signer, sig}): ("", true) or (reason, false).
func VerifyTighten(t any, trusted []string) (string, bool) {
	m, _ := t.(map[string]any)
	if e := TightenOverlayError(m["overlay"]); e != "" {
		return e, false
	}
	signer, ok := trustedSigner(trusted, m["signer"])
	if !ok {
		return "overlay signer is not trusted", false
	}
	digest, err := HashCanonical(m["overlay"])
	if err != nil || !verifySigned(signer, tightenSigDomain, digest, m["sig"]) {
		return "bad overlay signature", false
	}
	return "", true
}

func slotValueError(name string, d map[string]any, v any) string {
	typ, _ := d["type"].(string)
	values, hasValues := isStrList(d["values"])
	switch typ {
	case "string":
		s, ok := v.(string)
		if !ok || len(s) == 0 || u16len(s) > maxSlotString {
			return fmt.Sprintf("slot '%s' must be a string of 1..%d characters", name, maxSlotString)
		}
		if hasValues && !linkContains(values, s) {
			return fmt.Sprintf("slot '%s' is outside its closed value set", name)
		}
	case "integer":
		n, ok := safeInt(v)
		if !ok {
			return fmt.Sprintf("slot '%s' must be a safe integer", name)
		}
		if lo, has := d["min"]; has {
			if m, _ := safeInt(lo); n < m {
				return fmt.Sprintf("slot '%s' is below its minimum", name)
			}
		}
		if hi, has := d["max"]; has {
			if m, _ := safeInt(hi); n > m {
				return fmt.Sprintf("slot '%s' is above its maximum", name)
			}
		}
	default:
		l, ok := isStrList(v)
		if !ok || len(l) == 0 || len(l) > maxSlotSet {
			return fmt.Sprintf("slot '%s' must be a non-empty list of strings", name)
		}
		seen := map[string]bool{}
		for _, x := range l {
			if seen[x] {
				return fmt.Sprintf("slot '%s' has duplicate members", name)
			}
			seen[x] = true
		}
		if hasValues {
			for _, x := range l {
				if !linkContains(values, x) {
					return fmt.Sprintf("slot '%s' has a member outside its closed set", name)
				}
			}
		}
	}
	return ""
}

func linkContains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

type linkRefusal string

func matcherSafe(name string, val any) {
	vals := []any{val}
	if l, ok := val.([]any); ok {
		vals = l
	}
	for _, x := range vals {
		if s, ok := x.(string); ok && (strings.Contains(s, "*") || strings.HasPrefix(s, "re:")) {
			panic(linkRefusal(fmt.Sprintf("slot '%s' would inject a wildcard or regex matcher into a verb or resource", name)))
		}
	}
}

func fillSlots(v any, slots map[string]any, key string) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fillSlots(e, slots, key)
		}
		return out
	case map[string]any:
		if nm, has := x["$slot"]; has {
			name := nm.(string)
			val := slots[name]
			if key == "verb" || key == "resource" {
				matcherSafe(name, val)
			}
			pre, _ := x["pre"].(string)
			post, _ := x["post"].(string)
			if pre == "" && post == "" {
				return val
			}
			s, ok := val.(string)
			if !ok || strings.Contains(s, "*") || strings.Contains(s, "\x00") {
				panic(linkRefusal(fmt.Sprintf("slot '%s' cannot be spliced into a string (wildcard or non-string)", name)))
			}
			out := pre + s + post
			if pre == "" && strings.HasPrefix(out, "re:") {
				panic(linkRefusal(fmt.Sprintf("slot '%s' would inject a regex matcher", name)))
			}
			return out
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = fillSlots(e, slots, k)
		}
		return out
	}
	return v
}

// InstantiateTemplate fills a template's slots. It refuses unfilled, extra, mistyped and out-of-domain slots and any slot value
// that would inject a wildcard or a regex into a verb or resource. On success the policy is {predicates, caveats}.
func InstantiateTemplate(def any, slots any) (policy map[string]any, reason string) {
	defer func() {
		if r := recover(); r != nil {
			policy = nil
			if s, ok := r.(linkRefusal); ok {
				reason = string(s)
			} else {
				reason = "instantiation error (fail closed)"
			}
		}
	}()
	if e := TemplateDefError(def); e != "" {
		return nil, e
	}
	d := def.(map[string]any)
	sl, ok := slots.(map[string]any)
	if !ok {
		return nil, "slots must be an object"
	}
	decl := d["slots"].(map[string]any)
	for _, k := range linkSortedKeys(sl) {
		if _, has := decl[k]; !has {
			return nil, fmt.Sprintf("slot '%s' is not declared by the template", k)
		}
	}
	for _, n := range linkSortedKeys(decl) {
		v, has := sl[n]
		if !has {
			return nil, fmt.Sprintf("slot '%s' is not filled", n)
		}
		if e := slotValueError(n, decl[n].(map[string]any), v); e != "" {
			return nil, e
		}
	}
	body := fillSlots(d["body"], sl, "").(map[string]any)
	caveats, ok := body["caveats"].([]any)
	if !ok {
		caveats = []any{}
	}
	return map[string]any{"predicates": body["predicates"], "caveats": caveats}, ""
}

// TemplateRefError is "" for a well formed reference {template_id, version_digest, slots}.
func TemplateRefError(r any) string {
	m, ok := r.(map[string]any)
	if !ok {
		return "template_ref must be an object"
	}
	for _, k := range linkSortedKeys(m) {
		if k != "template_id" && k != "version_digest" && k != "slots" && k != "bind_params_digest" {
			return fmt.Sprintf("template_ref has unknown member '%s'", k)
		}
	}
	if id, ok := m["template_id"].(string); !ok || !templateNameRe.MatchString(id) {
		return "template_ref.template_id invalid"
	}
	if d, ok := m["version_digest"].(string); !ok || len(d) == 0 || len(d) > 128 {
		return "template_ref.version_digest invalid"
	}
	_, hasSlots := m["slots"]
	_, hasBound := m["bind_params_digest"]
	if hasSlots && hasBound {
		return "template_ref has both slots and bind_params_digest"
	}
	if hasBound {
		if !k3Str(m["bind_params_digest"], 128) {
			return "template_ref.bind_params_digest invalid"
		}
		return ""
	}
	if _, ok := m["slots"].(map[string]any); !ok {
		return "template_ref.slots must be an object"
	}
	return ""
}

// ResolveLink rebuilds the policy a reference denotes from the registry {templates, overlays?, trusted}: the template (signature
// checked) filled with the slots, then every verified overlay for this version. An invalid overlay for this version is a refusal.
func ResolveLink(ref any, reg map[string]any) (policy map[string]any, overlays int, reason string) {
	if e := TemplateRefError(ref); e != "" {
		return nil, 0, e
	}
	r := ref.(map[string]any)
	var trusted []string
	if l, ok := isStrList(reg["trusted"]); ok {
		trusted = l
	}
	templates, _ := reg["templates"].(map[string]any)
	t, has := templates[r["version_digest"].(string)]
	if !has {
		return nil, 0, "template version is not in the registry"
	}
	if why, ok := VerifyTemplate(t, trusted); !ok {
		return nil, 0, why
	}
	def := t.(map[string]any)["def"]
	if d, err := TemplateDigest(def); err != nil || d != r["version_digest"] {
		return nil, 0, "registry entry does not match its digest"
	}
	if def.(map[string]any)["id"] != r["template_id"] {
		return nil, 0, "template id does not match the reference"
	}
	slots := r["slots"]
	if bd, bound := r["bind_params_digest"].(string); bound {
		params, _ := reg["params"].(map[string]any)
		obj, ok := params[bd].(map[string]any)
		if !ok {
			return nil, 0, "parameter object is not available"
		}
		d, err := HashCanonical(obj)
		if err != nil {
			return nil, 0, "link resolution error (fail closed)"
		}
		if d != bd {
			return nil, 0, "parameter object does not match bind_params_digest"
		}
		slots = obj
	}
	inst, why := InstantiateTemplate(def, slots)
	if why != "" {
		return nil, 0, why
	}
	predicates := inst["predicates"].([]any)
	caveats := inst["caveats"].([]any)
	if ovs, ok := reg["overlays"].([]any); ok {
		for _, o := range ovs {
			om, _ := o.(map[string]any)
			ov, ok := om["overlay"].(map[string]any)
			if !ok || ov["version_digest"] != r["version_digest"] || ov["template_id"] != r["template_id"] {
				continue
			}
			if why, ok := VerifyTighten(o, trusted); !ok {
				return nil, 0, why
			}
			add, _ := ov["add_where"].([]any)
			next := make([]any, len(predicates))
			for i, p := range predicates {
				pm := p.(map[string]any)
				cp := make(map[string]any, len(pm)+1)
				for k, v := range pm {
					cp[k] = v
				}
				w, _ := pm["where"].([]any)
				cp["where"] = append(append([]any{}, w...), add...)
				next[i] = cp
			}
			predicates = next
			ac, _ := ov["add_caveats"].([]any)
			caveats = append(append([]any{}, caveats...), ac...)
			overlays++
		}
	}
	return map[string]any{"predicates": predicates, "caveats": caveats}, overlays, ""
}
