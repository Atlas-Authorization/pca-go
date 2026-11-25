package pca

// Public surface of the action kit's definition, trait-algebra and effective-profile layer: constants, the profile
// lattice helpers, registry construction, T(d) and its parts.

import "regexp"

// ActionDefVersion is the version of the ActionDef document.
const ActionDefVersion = 1

// ActionMaxPackDefs is the number of definitions an inline (unsharded) pack may hold.
const ActionMaxPackDefs = maxInlinePackDefs

// ActionParamTypesV1 lists the parameter types of ActionDef v1.
var ActionParamTypesV1 = append([]string(nil), defParamTypes...)

// ActionSensitivityLevels lists the parameter sensitivity levels, lowest first.
var ActionSensitivityLevels = []string{"free", "material", "critical"}

// ActionTaintContextRe matches the taint context keys (session_taint_max:<level>).
var ActionTaintContextRe = regexp.MustCompile(`^session_taint_max:[a-z_]{1,16}$`)

// ActionKitError is the error of the action kit: a stable code and a message.
type ActionKitError = CodedError

// NewActionKitError builds an action-kit error with a stable code.
func NewActionKitError(code, msg string) *ActionKitError { return &CodedError{Code: code, Msg: msg} }

// ActionIsReadOnly reports whether the effects are a non-empty list of only "read".
func ActionIsReadOnly(effects []string) bool { return isReadOnlyEffects(effects) }

// ActionBottom is the bottom profile: no restriction.
func ActionBottom() Profile { return mkProfile(Profile{}) }

// ActionJoin is the profile join: componentwise maximum and union.
func ActionJoin(p, q Profile) Profile { return joinProfile(p, q) }

// ActionJoinAll folds profiles with join, starting from the bottom.
func ActionJoinAll(ps []Profile) Profile {
	acc := ActionBottom()
	for _, p := range ps {
		acc = joinProfile(acc, p)
	}
	return acc
}

// ActionProfileLeq reports p <= q in the profile order.
func ActionProfileLeq(p, q Profile) bool { return leqProfile(p, q) }

// ActionProfileEq reports p <= q and q <= p.
func ActionProfileEq(p, q Profile) bool { return leqProfile(p, q) && leqProfile(q, p) }

// ActionRegistryError validates trait definitions as a registry ("" when valid); core allows the reserved pca. namespace.
func ActionRegistryError(defs []TraitDef, core bool) string {
	raw := make([]any, len(defs))
	for i, t := range defs {
		raw[i] = t.raw()
	}
	return registryErrorRaw(raw, core)
}

// ActionBuildRegistry builds a registry; an invalid set of definitions is an ActionKitError with code bad_registry.
func ActionBuildRegistry(defs []TraitDef, core bool) (Registry, error) {
	if e := ActionRegistryError(defs, core); e != "" {
		return nil, NewActionKitError("bad_registry", e)
	}
	reg := Registry{}
	for _, t := range defs {
		reg[t.ID] = t
	}
	return reg, nil
}

// ActionMeetDecision is the meet in the order deny < escalate < allow.
func ActionMeetDecision(a, b string) string {
	if decisionRank[a] <= decisionRank[b] {
		return a
	}
	return b
}

// ActionCoreTraitIDs lists the core trait ids in table order.
func ActionCoreTraitIDs() []string {
	out := make([]string, len(coreTable))
	for i, e := range coreTable {
		out[i] = "pca." + e.name
	}
	return out
}

// ActionCoreTraitDefs lists the core trait definitions in table order.
func ActionCoreTraitDefs() []TraitDef {
	out := make([]TraitDef, len(coreTable))
	for i, id := range ActionCoreTraitIDs() {
		out[i] = coreRegistry[id]
	}
	return out
}

// ActionSensitivityFloor is the sensitivity floor the role and tags of a parameter impose ("free" when neither names one).
func ActionSensitivityFloor(p map[string]any) string { return paramSensitivityFloor(p) }

// ActionNormalize is the authoring-independent form of a validated def (defaults filled, sets sorted).
func ActionNormalize(d map[string]any) map[string]any { return normalizeDef(d) }

// ActionIsPlainObject reports whether v is a JSON object.
func ActionIsPlainObject(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

// ActionImpliedTraits is the traits implied by the effects, roles, tags, scope and reversibility of a validated def.
func ActionImpliedTraits(d map[string]any) ([]string, error) {
	n := normalizeDef(d)
	list, pm := normParams(n)
	ef, _ := strsOf(n["effects"])
	return impliedFromFacts(ef, list, n["resource"].(map[string]any)["scope"].(string), worstReversibility(n["reversibility"], pm))
}

// ActionIsConfirmed reports whether the def carries a valid signed confirmation under the pinned reviewer keys (absent: never).
func ActionIsConfirmed(d map[string]any, reg Registry, pins any) bool {
	return defConfirmed(d, reg, pins)
}

// ActionTraitsOf is T(d): the hint traits of a confirmed def, else the top of the registry (unconfirmed means maximally dangerous).
func ActionTraitsOf(d map[string]any, reg Registry, pins any) []string {
	if defConfirmed(d, reg, pins) {
		return hintTraits(d)
	}
	return topTraits(reg)
}

// ActionEffective is the effective profile of a def: decl(d) joined with the floor of T(d).
func ActionEffective(d map[string]any, reg Registry, pins any) (Effective, error) {
	return effective(d, reg, pins)
}

// ActionEffWithTrait is the hint profile of the def after adding trait t to its declared traits (never lower; analysis only).
func ActionEffWithTrait(d map[string]any, t string, reg Registry) (Profile, error) {
	d2 := make(map[string]any, len(d)+1)
	for k, v := range d {
		d2[k] = v
	}
	tr, _ := strsOf(d["traits"])
	d2["traits"] = anyStrs(append(append([]string{}, tr...), t))
	fl, err := reg.floorOf(hintTraits(d2))
	if err != nil {
		return Profile{}, err
	}
	return joinProfile(declProfile(d2), fl), nil
}

// ActionRequiredPrulesViolated is the param rules the effective profile requires and the def does not satisfy.
func ActionRequiredPrulesViolated(d map[string]any, eff Profile) []string {
	if len(eff.Prules) == 0 {
		return []string{} // nil would mean "all rules" to ActionPrulesViolations
	}
	return ActionPrulesViolations(d, eff.Prules)
}

// ActionPackRulesDigest is the digest of the param-rule, caveat and context vocabularies a pack was built against.
func ActionPackRulesDigest() (string, error) { return rulesDigest() }

// ActionVerifyActionPack verifies a signed pack against its shards and trusted keys.
func ActionVerifyActionPack(packV any, keys any, shards map[string]any) (digest string, defCount int, reason string) {
	return verifyPack(packV, keys, shards)
}
