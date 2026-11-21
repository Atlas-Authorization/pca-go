package pca

// `pca actions build`: the artifacts of a set of action definitions (schema document, pack body, cards, ontology, MCP annotations,
// generated TypeScript types), the tool-call to operation map, and the unsharded signed pack with its consistency check.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// lintRuleRow is one rule of the lint rule table.
type lintRuleRow struct{ id, severity, title string }

// actionLintRules is the pinned lint rule table (the rule ids, severities and titles the digest covers).
var actionLintRules = []lintRuleRow{
	{"LD-001", "error", "a destroy-like verb whose effects do not delete"},
	{"LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"},
	{"LD-003", "error", "a numeric parameter without min and max"},
	{"LD-004", "error", "a money-moving action without idempotency"},
	{"LD-005", "error", "personal data can leave without the matching effect"},
	{"LD-006", "error", "a declared reversibility or blast below the effective floor"},
	{"LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"},
	{"LD-008", "error", "resource id '*' with scope one"},
	{"LD-009", "error", "a duplicate verb or alias collision"},
	{"LD-010", "error", "a write marked reversible with no compensating action in the pack"},
	{"LD-011", "error", "review state confirmed without a valid attestation for this digest"},
	{"LD-012", "error", "a structural param rule that the effective traits require is violated"},
	{"LD-013", "error", "a read-only action that can mutate or handles credentials"},
	{"LD-014", "error", "one binding in two defs"},
	{"LW-001", "warning", "description missing or too long, or title not imperative"},
	{"LW-002", "warning", "a string parameter without max_len"},
	{"LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"},
	{"LW-004", "warning", "an unreviewed def in a stable pack"},
	{"LW-005", "warning", "a dismissed suggested trait without a reason"},
	{"LW-006", "warning", "an array parameter without max_items"},
	{"LW-007", "warning", "a critical parameter without provenance_min"},
	{"LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"},
	{"LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"},
	{"LW-010", "warning", "since is missing"},
}

// ActionLintRulesDigest is the digest of the lint rule table.
func ActionLintRulesDigest() (string, error) {
	rules := make([]any, len(actionLintRules))
	for i, r := range actionLintRules {
		rules[i] = map[string]any{"id": r.id, "severity": r.severity, "title": r.title}
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/action-lint-rules/v1", "rules": rules})
}

const maxInlinePackDefs = 4096

// ActionBuildConfig is {ns, version, stability, site, aud}.
func actionByVerb(defs []any) []any {
	out := append([]any{}, defs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := out[i].(map[string]any)
		b, _ := out[j].(map[string]any)
		return u16Less(jsAnyString(a["verb"]), jsAnyString(b["verb"]))
	})
	return out
}

// ActionBuildArtifacts builds {schema, pack, cards, ontology, mcp, types} for defs; cfg is {ns, version, stability, site, aud}. The
// pack body is unsigned and unsharded (a pack above 4096 defs must be sharded: an error).
func ActionBuildArtifacts(defsIn []any, cfg map[string]any, reg Registry, confirmed ActionDiffConfirmed) (map[string]any, error) {
	defs := actionByVerb(defsIn)
	if len(defs) > maxInlinePackDefs {
		return nil, fmt.Errorf("a pack above %d defs must be sharded (%d given)", maxInlinePackDefs, len(defs))
	}
	digests := make([]string, len(defs))
	for i, x := range defs {
		d, _ := x.(map[string]any)
		if i > 0 {
			if p, _ := defs[i-1].(map[string]any); p["verb"] == d["verb"] {
				return nil, fmt.Errorf("verb '%s' appears twice", jsAnyString(d["verb"]))
			}
		}
		dg, err := defDigest(d)
		if err != nil {
			return nil, err
		}
		digests[i] = dg
	}
	root, err := packRoot(digests)
	if err != nil {
		return nil, err
	}
	schema, err := ActionToSchemaDoc(defs, reg, map[string]any{"site": cfg["site"], "aud": cfg["aud"], "version": cfg["version"],
		"pack": map[string]any{"ns": cfg["ns"], "version": cfg["version"], "root": root}}, confirmed)
	if err != nil {
		return nil, err
	}
	td, err := traitsDigest(reg)
	if err != nil {
		return nil, err
	}
	rd, err := tablesDigest()
	if err != nil {
		return nil, err
	}
	ld, err := ActionLintRulesDigest()
	if err != nil {
		return nil, err
	}
	pack := map[string]any{"v": jsNumber(1), "kind": actionPackKind, "ns": cfg["ns"], "version": cfg["version"], "stability": cfg["stability"],
		"traits_digest": td, "roles_digest": rd, "rules_digest": ld, "root": root, "defs": defs, "prev": nil, "evolution": []any{}}
	cards := []any{}
	tools := map[string]any{}
	for _, x := range defs {
		d, _ := x.(map[string]any)
		c, err := ActionCardOf(d, confirmed, reg)
		if err != nil {
			return nil, err
		}
		cards = append(cards, c)
	}
	for _, x := range defs {
		d, _ := x.(map[string]any)
		b, _ := d["bindings"].(map[string]any)
		if m, ok := b["mcp"].(map[string]any); ok && m != nil {
			ann, err := ActionMcpAnnotationsOf(d, confirmed)
			if err != nil {
				return nil, err
			}
			tools[jsAnyString(m["tool"])] = map[string]any{"verb": d["verb"], "annotations": ann}
		}
	}
	ont, err := ActionToOntology(defs, reg, confirmed)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schema": schema, "pack": pack, "cards": cards, "ontology": ont, "mcp": map[string]any{"tools": tools},
		"types": ActionGenerateTypes(defs)}, nil
}

// ActionToolAction maps an MCP tool call to {verb, resource}; nil for an unbound tool or a call that is not an operation.
func ActionToolAction(defs []any, tool string, args map[string]any) map[string]any {
	var d map[string]any
	for _, x := range defs {
		m, _ := x.(map[string]any)
		b, _ := m["bindings"].(map[string]any)
		if mc, ok := b["mcp"].(map[string]any); ok && mc != nil && mc["tool"] == tool {
			d = m
		}
	}
	if d == nil {
		return nil
	}
	r := ActionOperationOf(d, args)
	if r["ok"] != true {
		return nil
	}
	op := r["op"].(map[string]any)
	return map[string]any{"verb": op["verb"], "resource": op["resource"]}
}

var (
	typesIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	typesSplitRe = regexp.MustCompile(`[._]`)
)

func typesPascal(s string) string {
	parts := typesSplitRe.Split(s, -1)
	for i, x := range parts {
		if x != "" {
			u := utf16.Encode([]rune(x))
			parts[i] = strings.ToUpper(string(utf16.Decode(u[:1]))) + string(utf16.Decode(u[1:]))
		}
	}
	return strings.Join(parts, "")
}

func typesKey(k string) string {
	if typesIdentRe.MatchString(k) {
		return k
	}
	return typesJSON(k)
}

// typesJSON is JSON.stringify of a string (no HTML escaping).
func typesJSON(s any) string {
	out, _ := canonicalLenient(s)
	return out
}

func typesTs(p map[string]any) string {
	vals := func() []string {
		vs, _ := strsOf(p["values"])
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = typesJSON(v)
		}
		return out
	}
	switch p["type"] {
	case "integer", "duration":
		return "number"
	case "boolean":
		return "boolean"
	case "set":
		if v := vals(); len(v) > 0 {
			return "Array<" + strings.Join(v, " | ") + ">"
		}
		return "Array<string>"
	case "array":
		if p["items"] == "integer" {
			return "number[]"
		}
		return "string[]"
	}
	if _, has := p["values"]; has && p["values"] != nil {
		return strings.Join(vals(), " | ")
	}
	return "string"
}

type typesNode struct {
	leaf map[string]any
	kids map[string]*typesNode
}

func typesRender(n *typesNode, indent string) string {
	keys := make([]string, 0, len(n.kids))
	for k := range n.kids {
		keys = append(keys, k)
	}
	adSortU16(keys)
	var lines []string
	for _, k := range keys {
		c := n.kids[k]
		if c.leaf != nil {
			opt := ""
			if c.leaf["required"] == false {
				opt = "?"
			}
			lines = append(lines, indent+typesKey(k)+opt+": "+typesTs(c.leaf)+";")
		} else {
			lines = append(lines, indent+typesKey(k)+": {\n"+typesRender(c, indent+"  ")+"\n"+indent+"};")
		}
	}
	return strings.Join(lines, "\n")
}

// ActionGenerateTypes is the generated TypeScript parameter types of the defs (normalized parameters: `required` is explicit).
func ActionGenerateTypes(defs []any) string {
	out := []string{"// Generated by `pca actions build`. Do not edit.", ""}
	var names []string
	for _, x := range actionByVerb(defs) {
		d, _ := x.(map[string]any)
		root := &typesNode{kids: map[string]*typesNode{}}
		pnames := make([]string, 0, len(adParamsOf(d)))
		for k := range adParamsOf(d) {
			pnames = append(pnames, k)
		}
		adSortU16(pnames)
		for _, name := range pnames {
			cur := root
			segs := strings.Split(name, ".")
			for i, s := range segs {
				if cur.kids[s] == nil {
					cur.kids[s] = &typesNode{kids: map[string]*typesNode{}}
				}
				cur = cur.kids[s]
				if i == len(segs)-1 {
					cur.leaf, _ = adParamsOf(d)[name].(map[string]any)
				}
			}
		}
		iface := typesPascal(jsAnyString(d["verb"])) + "Params"
		names = append(names, "  "+typesJSON(d["verb"])+": "+iface+";")
		out = append(out, "export interface "+iface+" {", typesRender(root, "  "), "}", "")
	}
	out = append(out, "export interface ActionParams {")
	out = append(out, names...)
	out = append(out, "}", "", "export type ActionVerb = keyof ActionParams;", "")
	return strings.Join(out, "\n")
}

// ActionPackConsistencyError checks an unsharded pack body: defs valid and unique, the root over its defs, the trait registry
// digest. "" = consistent.
func ActionPackConsistencyError(p any, reg Registry) (reason string) {
	defer func() {
		if r := recover(); r != nil {
			reason = fmt.Sprint("malformed pack: ", r)
		}
	}()
	q, ok := p.(map[string]any)
	if !ok {
		return "the pack must be an object"
	}
	if q["kind"] != actionPackKind || !jsStrictEq(q["v"], jsNumber(1)) {
		return "not a pca-action-pack v1"
	}
	defs, ok := q["defs"].([]any)
	if !ok || len(defs) > maxInlinePackDefs {
		return "defs must be a list within the unsharded limit"
	}
	seen := map[string]bool{}
	digests := make([]string, len(defs))
	for i, x := range defs {
		if e := validateDef(x); e != "" {
			verb := "?"
			if m, ok := x.(map[string]any); ok {
				if v, has := m["verb"]; has && v != nil {
					verb = jsAnyString(v)
				}
			}
			return fmt.Sprintf("def %s: %s", verb, e)
		}
		d := x.(map[string]any)
		v := jsAnyString(d["verb"])
		if seen[v] {
			return fmt.Sprintf("verb '%s' is defined twice", v)
		}
		seen[v] = true
		dg, err := defDigest(d)
		if err != nil {
			return "malformed pack: " + err.Error()
		}
		digests[i] = dg
	}
	root, err := packRoot(digests)
	if err != nil { // the reference's root computation throws (an empty pack, a repeated digest) with the message alone
		return "malformed pack: " + reErrCode.ReplaceAllString(err.Error(), "")
	}
	if q["root"] != root {
		return "the pack root does not match its defs"
	}
	if td, err := traitsDigest(reg); err != nil || q["traits_digest"] != td {
		return "traits_digest does not match the trait registry"
	}
	return ""
}

// ActionSignPack signs the unsharded pack body as the registry (Ed25519 seed); the pack must be consistent.
func ActionSignPack(pack map[string]any, kid string, seed []byte, reg Registry) (map[string]any, error) {
	if bad := ActionPackConsistencyError(pack, reg); bad != "" {
		return nil, errors.New("signPack: " + bad)
	}
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	body := withoutKeys(pack, "sig")
	sig, err := signBody(kp, packSigDomain, body)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	out["sig"] = map[string]any{"alg": "ed25519", "kid": kid, "value": sig}
	return out, nil
}

// ActionPackKeyOf is the registry key entry of a signer seed.
func ActionPackKeyOf(kid string, seed []byte) (map[string]any, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return map[string]any{"kid": kid, "alg": "ed25519", "pk": kp.Public}, nil
}

// ActionBuildVerifyPack verifies a pack signed by ActionSignPack against the registry key entries. Never panics.
func ActionBuildVerifyPack(pack any, keys []any, reg Registry) (res map[string]any) {
	fail := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	defer func() {
		if r := recover(); r != nil {
			res = fail(fmt.Sprint("pack verification error: ", r))
		}
	}()
	if bad := ActionPackConsistencyError(pack, reg); bad != "" {
		return fail(bad)
	}
	p := pack.(map[string]any)
	sig, _ := p["sig"].(map[string]any)
	kid, kidOK := sig["kid"].(string)
	val, valOK := sig["value"].(string)
	if sig == nil || sig["alg"] != "ed25519" || !kidOK || !valOK {
		return fail("missing or malformed signature")
	}
	var key map[string]any
	for _, kv := range keys {
		if k, _ := kv.(map[string]any); k["kid"] == kid {
			key = k
			break
		}
	}
	if key == nil {
		return fail(fmt.Sprintf("no registry key with kid '%s'", kid))
	}
	pk, _ := key["pk"].(string)
	pub, pkOK := DecodeB64uStrict(pk, 32)
	if key["alg"] != "ed25519" || !pkOK {
		return fail("the registry key entry is malformed")
	}
	cb, err := canonBytes(withoutKeys(p, "sig"))
	if err != nil {
		return fail("pack verification error: " + err.Error())
	}
	sg, sgOK := DecodeB64uStrict(val, 64)
	if !sgOK || !VerifyStrict(ed25519.PublicKey(pub), append([]byte(packSigDomain), cb...), sg) {
		return fail("pack signature invalid")
	}
	return map[string]any{"ok": true}
}

// reErrCode is the "code: " prefix a native error message leads with.
var reErrCode = regexp.MustCompile(`^[a-z][a-z_]*: `)
