package pca

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Connector action catalog helpers: define and extend action specs, fail-closed lookup, a digest to pin, and the server's risk inputs
// for a catalogued action. This is DATA, not enforcement: the resource server's verifier stays authoritative.

// CatalogReversibilityScore is the reversibility score per class (1 = fully reversible): the scale the hosted adjudicator uses.
func CatalogReversibilityScore() map[string]any {
	return map[string]any{"reversible": jsNumber(1), "rate_limited": jsNumber(0.4), "costly": jsNumber(0.4), "irreversible": jsNumber(0)}
}

var catalogConnectorBad = regexp.MustCompile("[" + jsWS + ".]")

var catalogReversibilityOrder = []string{"reversible", "rate_limited", "irreversible"}

// All returns every action in the catalog in order of first appearance by verb (a later definition of a verb replaces it in place).
func (c *Catalog) All() []CatalogAction {
	out := make([]CatalogAction, 0, len(c.order))
	for _, v := range c.order {
		out = append(out, c.byVerb[v])
	}
	return out
}

// ForConnector returns every action of a connector namespace, in the order of All.
func (c *Catalog) ForConnector(connector string) []CatalogAction {
	var out []CatalogAction
	for _, a := range c.All() {
		if a.Connector == connector {
			out = append(out, a)
		}
	}
	return out
}

// DefineAction validates one action spec and fills its verb (connector.action) when empty; use it with BuildCatalog to extend the
// built-ins.
func DefineAction(s CatalogAction) (CatalogAction, error) {
	if s.Connector == "" || s.Action == "" {
		return CatalogAction{}, errors.New("defineAction: connector and action are required")
	}
	if catalogConnectorBad.MatchString(s.Connector) {
		return CatalogAction{}, errors.New("defineAction: connector must not contain whitespace or a dot")
	}
	if catalogSev(s.Reversibility) < 0 {
		return CatalogAction{}, fmt.Errorf("defineAction: bad reversibility '%s'", s.Reversibility)
	}
	if !(s.BlastRadius >= 0 && s.BlastRadius <= 1) {
		return CatalogAction{}, errors.New("defineAction: blastRadius must be in [0,1]")
	}
	if s.Verb == "" {
		s.Verb = s.Connector + "." + s.Action
	}
	return s, nil
}

// CatalogBlast is the blast-radius presets by shape of action (conservative, overridable).
func CatalogBlast() map[string]any {
	return map[string]any{"read": jsNumber(0.05), "reversibleWrite": jsNumber(0.2), "rateLimitedWrite": jsNumber(0.5), "irreversibleWrite": jsNumber(0.8), "moneyMovement": jsNumber(0.9)}
}

// DefineActionValue is DefineAction over a decoded JSON spec: it keeps every member of the spec (extras included) and fills `verb`
// (connector.action) when it is absent or null; an empty verb stays. A spec that is not an object has no connector and is refused.
func DefineActionValue(spec any) (map[string]any, error) {
	s, ok := spec.(map[string]any)
	if !ok {
		if spec == nil {
			return nil, errors.New("Cannot read properties of null (reading 'connector')")
		}
		s = map[string]any{}
	}
	connector, ok1 := s["connector"].(string)
	action, ok2 := s["action"].(string)
	if !ok1 || !ok2 || connector == "" || action == "" {
		return nil, errors.New("defineAction: connector and action are required")
	}
	if catalogConnectorBad.MatchString(connector) {
		return nil, errors.New("defineAction: connector must not contain whitespace or a dot")
	}
	if af, has := s["amountField"]; has {
		if str, isStr := af.(string); !isStr || str == "" {
			return nil, errors.New("defineAction: amountField must be a non-empty string")
		}
	}
	if r, _ := s["reversibility"].(string); catalogSev(r) < 0 || s["reversibility"] == nil {
		return nil, fmt.Errorf("defineAction: bad reversibility '%s'", jsMemberString(s, "reversibility"))
	}
	if f, isNum := jsNum(s["blastRadius"]); !isNum || !(f >= 0 && f <= 1) {
		return nil, errors.New("defineAction: blastRadius must be in [0,1]")
	}
	out := make(map[string]any, len(s)+1)
	for k, v := range s {
		out[k] = v
	}
	if v, has := s["verb"]; !has || v == nil {
		out["verb"] = connector + "." + action
	}
	return out, nil
}

// BuildCatalog builds a catalog from action specs (later specs override earlier ones by verb); nil is the built-in actions.
func BuildCatalog(actions []CatalogAction) *Catalog {
	if actions == nil {
		actions = BuiltinActions
	}
	return NewCatalog(actions)
}

// UncataloguedSpec is what a verb is treated as when the catalog does not know it: irreversible, maximum blast radius.
func UncataloguedSpec(verb string) CatalogAction {
	parts := strings.Split(verb, ".")
	action := strings.Join(parts[1:], ".")
	if action == "" {
		action = verb
	}
	return CatalogAction{Connector: parts[0], Action: action, Verb: verb, Reversibility: "irreversible", BlastRadius: 1, Description: "(uncatalogued) " + verb}
}

// ResolveAction resolves a verb, failing closed: an unknown verb comes back as UncataloguedSpec with catalogued false.
func ResolveAction(c *Catalog, verb string) (spec CatalogAction, catalogued bool) {
	if s, ok := c.Get(verb); ok {
		return s, true
	}
	return UncataloguedSpec(verb), false
}

// catalogSpecMap is the reference shape of a spec: optional members are present only when set.
func catalogSpecMap(a CatalogAction) map[string]any {
	m := map[string]any{"connector": a.Connector, "action": a.Action, "verb": a.Verb, "reversibility": a.Reversibility,
		"blastRadius": jsNumber(a.BlastRadius), "description": a.Description}
	if a.AmountField != "" {
		m["amountField"] = a.AmountField
	}
	if a.Resource != "" {
		m["resource"] = a.Resource
	}
	strs := func(xs []string) []any {
		o := make([]any, len(xs))
		for i, x := range xs {
			o[i] = x
		}
		return o
	}
	if a.Aliases != nil {
		m["aliases"] = strs(a.Aliases)
	}
	if a.Traits != nil {
		m["traits"] = strs(a.Traits)
	}
	return m
}

// ActionCatalogDigest is a digest of the whole catalog (SHA-256 over canonical JSON, sorted by verb). Pin it: a deployment that
// records the digest of the catalog it reviewed can refuse to start when the catalog has since changed.
func ActionCatalogDigest(c *Catalog) (string, error) {
	all := c.All()
	sort.SliceStable(all, func(i, j int) bool { return utf16Less(all[i].Verb, all[j].Verb) }) // JavaScript's `<`: UTF-16 code units
	specs := make([]any, len(all))
	for i, a := range all {
		specs[i] = catalogSpecMap(a)
	}
	return HashCanonical(specs)
}

// AssertCatalogPinned errors unless the catalog hashes to expected.
func AssertCatalogPinned(c *Catalog, expected string) error {
	d, err := ActionCatalogDigest(c)
	if err != nil {
		return err
	}
	if d != expected {
		return errors.New("catalog does not match the pinned digest")
	}
	return nil
}

func catalogSev(class string) int {
	for i, c := range catalogReversibilityOrder {
		if c == class {
			return i
		}
	}
	return -1
}

// ExtendCatalog extends a catalog with more actions. Unlike BuildCatalog over both lists, an extra action may not replace an existing
// verb with a less cautious one (lower reversibility class or lower blast radius): that would let a plugin quietly relabel
// gmail.send as reversible.
func ExtendCatalog(base *Catalog, extra []CatalogAction) (*Catalog, error) {
	for _, e := range extra {
		if old, ok := base.Get(e.Verb); ok && (catalogSev(e.Reversibility) < catalogSev(old.Reversibility) || e.BlastRadius < old.BlastRadius) {
			return nil, fmt.Errorf("extendCatalog: '%s' would be less cautious than the existing entry", e.Verb)
		}
	}
	return NewCatalog(append(base.All(), extra...)), nil
}

func catalogUnit(x float64) float64 { return math.Min(1, math.Max(0, x)) }

// CatalogRisk is the server's risk inputs for an action the catalog knows: reversibility from the class score, blastRadius from the
// catalog (or, for an amount-bearing action, amount / kappa from the verified params and the grant's risk policy, the worst case 1
// when either is unusable), confidence 1 and, when taint is supplied, taint in [0, 1]. An unknown verb yields an empty map (the
// verifier then prices the inputs at the worst case). catalog nil is the built-in one; taint nil is not supplied.
func CatalogRisk(verb string, params map[string]any, grant any, catalog *Catalog, taint *float64) map[string]any {
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	spec, ok := catalog.Get(verb)
	out := map[string]any{}
	if !ok {
		return out
	}
	rev := 0.0
	if s, known := CatalogReversibilityScore()[spec.Reversibility]; known {
		rev = jsF(s)
	}
	blast := catalogUnit(spec.BlastRadius)
	if spec.AmountField != "" {
		amount := params[spec.AmountField]
		var kappa any
		if env := ReadEnvelope(grant); env != nil {
			kappa = rsMap(env["risk_policy"])["kappa"]
		}
		blast = 1
		if amt, aok := finNum(amount); aok && amt >= 0 {
			if k, kok := finNum(kappa); kok && k > 0 {
				blast = catalogUnit(amt / k)
			}
		}
	}
	out["reversibility"] = rsN(rev)
	out["blastRadius"] = rsN(blast)
	out["confidence"] = jsNumber(1)
	if taint != nil && !math.IsNaN(*taint) && !math.IsInf(*taint, 0) {
		out["taint"] = rsN(catalogUnit(*taint))
	}
	return out
}
