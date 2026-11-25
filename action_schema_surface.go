package pca

// The rest of the site action schema surface: the closed v2 vocabularies, the discovery key entry of a signer, the value-dependent
// reversibility, the MCP annotation hints and the OpenAPI draft.

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

// WellKnownPcaActionsPath is where a site publishes its signed action schema.
const WellKnownPcaActionsPath = "/.well-known/pca-actions.json"

// SchemaReversibility are the reversibility classes of an action schema, mildest first.
var SchemaReversibility = append([]string(nil), schemaReversibles...)

// SchemaV2Caveats are the caveat names a v2 verb's floors may carry.
var SchemaV2Caveats = []string{"amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"}

// SchemaV2Prules are the policy rules a v2 verb's floors may carry.
var SchemaV2Prules = []string{"array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
	"pay_has_idempotency", "recipient_param_declared", "secret_not_logged"}

// SchemaV2Context are the context requirements a v2 verb's floors may carry (a session_taint_max:<level> entry is also allowed).
var SchemaV2Context = []string{"approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"}

// SchemaV2Tags are the data tags a v2 parameter may carry.
var SchemaV2Tags = []string{"pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"}

// SchemaV2Provenance are the provenance levels a v2 parameter's provenance_min may name.
var SchemaV2Provenance = []string{"first_party", "tool", "agent"}

// UnitIDRe matches an accumulation unit id (an accumulates_into entry).
var UnitIDRe = regexp.MustCompile(`^[a-z0-9_]+(?:\.[a-z0-9_]+)*$`)

// SchemaVerb is the verb declaration named verb in a schema document; throws reports a null entry (the reference dereferences it).
func SchemaVerb(doc any, verb string) (v map[string]any, throws bool) { return schemaVerbOf(doc, verb) }

// ReversibilityOf is the value-dependent reversibility class of one action: the class its reversibility_by map gives the
// parameter's value (an unmapped or absent value takes the default, else irreversible: fail closed), else the verb's own class.
func ReversibilityOf(v map[string]any, params map[string]any) string {
	if rb, ok := v["reversibility_by"].(map[string]any); ok {
		param, _ := rb["param"].(string)
		name := strings.TrimPrefix(param, "action.params.")
		key, found := "", false
		if x, has := params[name]; has {
			switch t := x.(type) {
			case string:
				key, found = t, true
			case bool:
				key, found = jsValueString(t), true
			default:
				if jsIsInt(x) {
					key, found = jsNumberString(jsF(x)), true
				}
			}
		}
		if mp, _ := rb["map"].(map[string]any); found {
			if r, has := mp[key]; has {
				return ixS(r)
			}
		}
		if d, ok := rb["default"].(string); ok {
			return d
		}
		return "irreversible"
	}
	if r, ok := v["reversibility"].(string); ok {
		return r
	}
	if v["kind"] == "read" {
		return "reversible"
	}
	return "irreversible"
}

// ActionSchemaKeyOf is the discovery key entry {kid, alg, pk, pq_pk?} for a site signer under the suite (nil: Ed25519).
func ActionSchemaKeyOf(kid string, site *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if !schemaStr(kid, 128) {
		return nil, errors.New("actionSchemaKeyOf: kid must be a non-empty string")
	}
	if site == nil {
		return nil, errors.New("actionSchemaKeyOf: a key is required")
	}
	su, known := resolveSigAlg(suite.alg(), true)
	if !known {
		return nil, errors.New("actionSchemaKeyOf: unknown signature alg " + suite.alg())
	}
	entry := map[string]any{"kid": kid, "alg": su.alg, "pk": site.Public}
	if su.alg != "ed25519" {
		if suite == nil || suite.Pq == nil {
			return nil, errors.New("actionSchemaKeyOf: " + su.alg + " needs a post-quantum key pair")
		}
		entry["pq_pk"] = suite.Pq.Public
	}
	return entry, nil
}

// ReversibilityFromMcpHints reads an MCP tool's annotations as a LOWER bound on reversibility (hints never lower a classification):
// {kind: "read", atLeast: "reversible"} for a read-only hint, {kind: "write", atLeast: "rate_limited"} for a destructive one, else
// {kind: "write", atLeast: "reversible"}.
func ReversibilityFromMcpHints(annotations any) map[string]any {
	if mcpGet(annotations, "readOnlyHint") == true {
		return map[string]any{"kind": "read", "atLeast": "reversible"}
	}
	if mcpGet(annotations, "destructiveHint") == true {
		return map[string]any{"kind": "write", "atLeast": "rate_limited"}
	}
	return map[string]any{"kind": "write", "atLeast": "reversible"}
}

// DraftSchemaFromMcpTools drafts an action schema from an MCP tools/list (see McpDraftActionSchema): {schema, todo}.
func DraftSchemaFromMcpTools(tools, site any) (map[string]any, error) {
	return McpDraftActionSchema(tools, site)
}

var openAPIJSONRe = regexp.MustCompile(`(?i)^application/[^;]*\+json(;|$)`)

// openAPIBodySchema is the schema of the JSON media type of a request body: application/json first, else any application/*+json.
func openAPIBodySchema(b any) any {
	content, ok := mcpGet(b, "content").(map[string]any)
	if !ok {
		return mcpUnd
	}
	keys := mcpKeys(content)
	for _, k := range keys {
		if strings.ToLower(k) == "application/json" {
			return mcpGet(content[k], "schema")
		}
	}
	for _, k := range keys {
		if openAPIJSONRe.MatchString(k) {
			return mcpGet(content[k], "schema")
		}
	}
	return mcpUnd
}

// DraftSchemaFromOpenApi drafts an action schema from an OpenAPI document: one verb per operation with an operationId (x-pca-verb
// names it, else the id). The parameters are the operation's path and query parameters (path-item parameters included, the
// operation's own winning) plus the properties of its JSON request body; local $refs are followed. Header and cookie parameters are
// not action parameters and are noted in todo, as is any name two sources share (the body declaration is kept). Every write verb is
// drafted irreversible unless the operation says otherwise. site = {site, aud, version}. Returns {schema, todo}: the decisions the
// developer must make before signing.
func DraftSchemaFromOpenApi(doc, site any) (map[string]any, error) {
	sm, ok := site.(map[string]any)
	if !ok {
		return nil, errors.New("draftSchemaFromOpenApi: site must be an object")
	}
	c := &mcpCtx{root: doc, left: mcpMaxRefNodes}
	verbs := []map[string]any{}
	deref := func(x any) any {
		if _, isMap := x.(map[string]any); !isMap {
			return mcpUnd
		}
		ref, isStr := mcpGet(x, "$ref").(string)
		if !isStr {
			return x
		}
		t, found := mcpPointer(doc, ref)
		if !found {
			c.note("reference '%s' is not a local reference that resolves", mcpSliceUnits(ref, 120))
			return mcpUnd
		}
		return t
	}
	seen := map[string]bool{}
	paths, _ := mcpGet(doc, "paths").(map[string]any)
	for _, path := range mcpKeys(paths) {
		ops, ok := paths[path].(map[string]any)
		if !ok {
			continue
		}
		shared, _ := ops["parameters"].([]any)
		for _, method := range mcpKeys(ops) {
			op, ok := ops[method].(map[string]any)
			if !ok || !mcpTruthy(op["operationId"]) {
				continue
			}
			opID := mcpJSStr(op["operationId"])
			c.left = mcpMaxRefNodes
			var read bool
			if k := op["x-pca-kind"]; mcpTruthy(k) {
				read = k == "read"
			} else {
				m := strings.ToLower(method)
				read = m == "get" || m == "head"
			}
			verb := opID
			if v := op["x-pca-verb"]; v != nil {
				verb = mcpJSStr(v)
			}
			if seen[verb] {
				c.note("%s: declared by more than one operation; give each a distinct x-pca-verb", verb)
			}
			seen[verb] = true
			params := map[string]any{}
			addName := func(name string, sch any, required bool, source string) error {
				if !mcpNameOK(name) {
					c.note("%s: parameter '%s' is not a schema name; rename it", opID, name)
					return nil
				}
				key := "action.params." + name
				if _, has := params[key]; has {
					c.note("%s: '%s' is declared by both the %s and another source; kept the first", opID, name, source)
					return nil
				}
				d, err := mcpDecl(name, sch, required, c)
				if err != nil {
					return err
				}
				params[key] = d
				return nil
			}
			// the request body first (it wins a name clash), then the operation's own parameters over the path item's
			body, err := mcpFlatten(openAPIBodySchema(deref(op["requestBody"])), c, opID+": request body", 0)
			if err != nil {
				return nil, err
			}
			bprops := body["properties"]
			breq := map[string]bool{}
			if r := body["required"]; r != nil {
				l, err := mcpIter(r)
				if err != nil {
					return nil, err
				}
				for _, x := range l {
					if s, isStr := x.(string); isStr {
						breq[s] = true
					}
				}
			}
			for _, name := range mcpKeys(bprops) {
				if err := addName(name, mcpIndex(bprops, name), breq[name], "request body"); err != nil {
					return nil, err
				}
			}
			merged := map[string]map[string]any{}
			own, _ := op["parameters"].([]any)
			for _, raw := range append(append([]any{}, shared...), own...) {
				q, isMap := deref(raw).(map[string]any)
				if !isMap {
					continue
				}
				qn, nOK := q["name"].(string)
				qi, iOK := q["in"].(string)
				if !nOK || !iOK {
					continue
				}
				merged[qi+":"+qn] = q
			}
			mkeys := make([]string, 0, len(merged))
			for k := range merged {
				mkeys = append(mkeys, k)
			}
			sortUtf8(mkeys)
			for _, key := range mkeys {
				q := merged[key]
				in, _ := q["in"].(string)
				name, _ := q["name"].(string)
				if in != "path" && in != "query" {
					c.note("%s: %s parameter '%s' is not an action parameter (the schema sees path, query and body parameters only)", opID, in, name)
					continue
				}
				sch := mcpSpread(q["schema"])
				if mcpTruthy(q["description"]) && !mcpTruthy(sch["description"]) {
					sch["description"] = q["description"]
				}
				if err := addName(name, sch, in == "path" || q["required"] == true, in+" parameters"); err != nil {
					return nil, err
				}
			}
			var rev any = "irreversible"
			if read {
				rev = "reversible"
			}
			r := op["x-pca-reversibility"]
			if r != nil {
				rev = r
			}
			if !read && !mcpTruthy(r) {
				c.note("%s: reversibility (drafted irreversible)", verb)
			}
			kind := "write"
			if read {
				kind = "read"
			}
			entry := map[string]any{"verb": verb, "kind": kind, "params": params, "reversibility": rev, "openapi": map[string]any{"operationId": op["operationId"]}}
			if mcpTruthy(op["description"]) {
				sl, err := mcpSlice1024(op["description"])
				if err != nil {
					return nil, err
				}
				entry["description"] = sl
			}
			verbs = append(verbs, entry)
		}
	}
	sort.SliceStable(verbs, func(a, b int) bool { return compareUtf8(verbs[a]["verb"].(string), verbs[b]["verb"].(string)) < 0 })
	vl := make([]any, len(verbs))
	for i, v := range verbs {
		vl[i] = v
	}
	schema := map[string]any{"v": 1, "kind": actionSchemaKind, "verbs": vl}
	for _, k := range []string{"site", "aud", "version"} {
		if v, has := sm[k]; has {
			schema[k] = v
		}
	}
	todo := c.todo
	if todo == nil {
		todo = []any{}
	}
	return map[string]any{"schema": schema, "todo": todo}, nil
}
