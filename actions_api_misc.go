package pca

// Remaining public pieces of the action kit: the undo engine, the facade rows derived from defs, the MCP tool map, the review
// verifier, the compiled-rules context, the rule 22 engine, the lint meta-rules, the import ceilings and the GraphQL SDL parser.

// ActionUndoEngine answers undo plans only from confirmed definitions: the def carries a valid signed review by a pinned reviewer
// key, its effective class for these params is reversible, and it names a confirmed compensating action that can be derived before
// the effect runs. Exact verb match only (an alias never confers reversibility). It never panics: what it cannot decide is "not
// undoable".
type ActionUndoEngine struct {
	defs []any
	pins any
	reg  Registry
}

// NewActionUndoEngine builds an undo engine over the verifier's pinned defs and reviewer pins (nil pins: nothing is confirmed,
// nothing is undoable). A nil registry means the core one.
func NewActionUndoEngine(defs []any, pins any, reg Registry) *ActionUndoEngine {
	if reg == nil {
		reg = coreRegistry
	}
	return &ActionUndoEngine{defs: defs, pins: pins, reg: reg}
}

// Plan is the undo plan for op {verb, params}, or nil: {def_digest, compensation, render, render_digest}.
func (e *ActionUndoEngine) Plan(op map[string]any) map[string]any {
	return actionUndoPlanIn(e.defs, e.pins, op, e.reg)
}

// ActionFacadeOptions are the options of the facade rows.
type ActionFacadeOptions struct {
	// Pins are the reviewer keys a confirmation must be signed by (nil: nothing is confirmed).
	Pins any
	// Reviewed prices the def as REVIEWED (its declared and implied traits), not as unconfirmed. Only for the release-attested
	// built-in catalog.
	Reviewed bool
}

// ActionFacadeSpec is the facade's view of a def: {connector, action, verb, reversibility, blastRadius, amountField?, description,
// aliases?, traits}, derived from the effective profile so no trait can make the facade price an action below what the signed
// schema says. amountField is the single money.amount parameter (absent when none or several).
func ActionFacadeSpec(d map[string]any, reg Registry, o ActionFacadeOptions) (map[string]any, error) {
	if reg == nil {
		reg = coreRegistry
	}
	hintT, hintCl, hintEff, err := trHint(d, reg)
	if err != nil {
		return nil, err
	}
	_ = hintT
	rev, blast, closure := hintEff.Rev, hintEff.Blast, hintCl
	if !o.Reviewed {
		e, err := effective(d, reg, o.Pins)
		if err != nil {
			return nil, err
		}
		rev, blast, closure = e.Eff.Rev, e.Eff.Blast, e.Closure
	}
	verb := jsAnyString(d["verb"])
	connector, action := verb, ""
	for i := 0; i < len(verb); i++ {
		if verb[i] == '.' {
			connector, action = verb[:i], verb[i+1:]
			break
		}
	}
	desc := d["description"]
	if desc == nil {
		desc = d["title"]
	}
	out := map[string]any{"connector": connector, "action": action, "verb": verb, "reversibility": rev,
		"blastRadius": jsNumber(float64(blast) / 1_000_000), "description": desc, "traits": anyStrs(closure)}
	if f, err := ActionParamByRole(d, "money.amount"); err == nil {
		out["amountField"] = f
	}
	if al, ok := strsOf(d["aliases"]); ok && len(al) > 0 {
		out["aliases"] = anyStrs(sortUniqS(append([]string{}, al...)))
	}
	return out, nil
}

// ActionFacadeSpecs is the facade rows of a pack, in the pack's own order.
func ActionFacadeSpecs(defs []map[string]any, reg Registry, o ActionFacadeOptions) ([]map[string]any, error) {
	out := make([]map[string]any, len(defs))
	for i, d := range defs {
		s, err := ActionFacadeSpec(d, reg, o)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// ActionToolActionMapOf is the tool-to-action map of the defs' MCP bindings: tool name and arguments to {verb, resource}, or nil.
func ActionToolActionMapOf(defs []any) func(tool string, args map[string]any) map[string]any {
	return func(tool string, args map[string]any) map[string]any { return ActionToolAction(defs, tool, args) }
}

// ActionReviewOptsOf is the confirmation verifier under pinned reviewer keys (nil pins: nothing is confirmed).
func ActionReviewOptsOf(pins any, reg Registry) ActionDiffConfirmed { return hostedReviewOf(pins, reg) }

// ActionRulesContext is the predicate context the compiled business rules are evaluated in (verifier-computed env members only).
func ActionRulesContext(compiled, input map[string]any) map[string]any {
	return rbContext(compiled, input)
}

// ActionRule22Engine is the trait engine the verifier's rule 22 calls: SchemaError recomputes the document's traits and floors from
// the verbs' visible facts and the carried registry; Decide is FloorDecision of the verb's materialized floors against what the
// grant provides and the call context.
type ActionRule22Engine struct{}

// ActionRule22 is the engine value.
var ActionRule22 = ActionRule22Engine{}

// SchemaError is "" for a consistent document, else "<code>: <reason>" (a forged floor or a dropped implied trait refuses it).
func (ActionRule22Engine) SchemaError(doc map[string]any, reviewers any) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = "schema_floor_forged: " + jsAnyString(r)
		}
	}()
	return schemaFloorError(doc, reviewers)
}

// Decide is allow, escalate or deny; anything it cannot read is deny.
func (ActionRule22Engine) Decide(doc map[string]any, verb string, grant map[string]any, context []any) string {
	return rule22Decide(doc, verb, grant, context)
}

// ActionLintRule is a lint rule: id, severity (error, warning, note) and title.
type ActionLintRule struct{ ID, Severity, Title string }

// ActionNoteRule is the lint rule of the loader's informational notes.
var ActionNoteRule = ActionLintRule{"LN-001", "note", "an informational note from the loader"}

// ActionStructureRule is the lint rule of a def that is not well formed and cannot be loaded.
var ActionStructureRule = ActionLintRule{"LD-000", "error", "the def is not well formed and cannot be loaded"}

// ActionDefaultImportLimits are the default bounds every importer enforces before it believes a byte of foreign input.
func ActionDefaultImportLimits() map[string]any { return aimDefaultLimits.asMap() }

// ActionHardImportLimits are the ceilings no caller may raise past: a caller-supplied limit is clamped to these.
func ActionHardImportLimits() map[string]any { return aimHardLimits.asMap() }

// ActionEmptySuggestion is the suggestion with nothing proposed.
func ActionEmptySuggestion() map[string]any {
	return map[string]any{"traits": []any{}, "roles": map[string]any{}, "tags": map[string]any{}, "fired": []any{}}
}

// ActionGqlSchema is a parsed GraphQL schema (types, root operation types).
type ActionGqlSchema = aimGqlSchema

// ActionParseGraphqlSdl parses GraphQL SDL text. maxTokens bounds the lexer (0 means 2,000,000); a source over the bound is an
// error with code import_limit.
func ActionParseGraphqlSdl(src string, maxTokens int) (gs *ActionGqlSchema, err error) {
	defer aimRecover(&err)
	if maxTokens <= 0 {
		maxTokens = 2_000_000
	}
	return aimGqlParseSDL(src, maxTokens), nil
}
