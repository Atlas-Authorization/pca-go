package pca

// Action kit, trait side: the profile lattice, the trait registry (22 core traits + custom traits of a signed document),
// closure / floor, FloorDecision (rule 22), the schema floor integrity check, T(d) and eff(d). Integers and sets only.

import (
	"fmt"
	"sort"
	"strings"
)

// Profile is the restriction profile; sets are sorted and distinct.
type Profile struct {
	Risk    int
	Rev     string
	Blast   int
	Esc     int
	Caveats []string
	Context []string
	Prules  []string
}

func mkProfile(p Profile) Profile {
	if p.Rev == "" {
		p.Rev = "reversible"
	}
	p.Caveats, p.Context, p.Prules = sortUniqS(p.Caveats), sortUniqS(p.Context), sortUniqS(p.Prules)
	return p
}

// raw is the JSON form of the profile.
func (p Profile) raw() map[string]any {
	return map[string]any{"risk": p.Risk, "rev": p.Rev, "blast_ppm": p.Blast, "esc": p.Esc,
		"caveats": anyStrs(p.Caveats), "context": anyStrs(p.Context), "prules": anyStrs(p.Prules)}
}

// profileFromRaw reads a profile that profileErrorRaw accepted.
func profileFromRaw(v any) Profile {
	m := v.(map[string]any)
	cs, _ := strsOf(m["caveats"])
	cx, _ := strsOf(m["context"])
	pr, _ := strsOf(m["prules"])
	rev, _ := m["rev"].(string)
	return Profile{Risk: int(jsF(m["risk"])), Rev: rev, Blast: int(jsF(m["blast_ppm"])), Esc: int(jsF(m["esc"])), Caveats: cs, Context: cx, Prules: pr}
}

func profileErrorRaw(pv any) string {
	p, ok := isObj(pv)
	if !ok {
		return "profile must be an object"
	}
	if !allKeysIn(p, []string{"risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"}) {
		return "profile: unknown member"
	}
	in := func(x any, lo, hi float64) bool { return jsIsInt(x) && jsF(x) >= lo && jsF(x) <= hi }
	if !in(p["risk"], 0, 3) {
		return "profile.risk must be an integer in 0..3"
	}
	if !strIn(p["rev"], defReversibility) {
		return "profile.rev is not a reversibility class"
	}
	if !in(p["blast_ppm"], 0, ppmMax) {
		return "profile.blast_ppm must be an integer in 0..1000000"
	}
	if !in(p["esc"], 0, 3) {
		return "profile.esc must be an integer in 0..3"
	}
	for _, c := range []struct {
		name string
		ok   func(string) bool
	}{
		{"caveats", func(s string) bool { return contains(caveatKinds, s) }},
		{"context", isContextKey},
		{"prules", func(s string) bool { return contains(paramRuleIDs, s) }},
	} {
		a, isL := p[c.name].([]any)
		if !isL || len(a) > 64 {
			return "profile." + c.name + " must be an array of known entries"
		}
		for _, x := range a {
			if s, ok := x.(string); !ok || !c.ok(s) {
				return "profile." + c.name + " must be an array of known entries"
			}
		}
		for i := 1; i < len(a); i++ {
			if !(a[i-1].(string) < a[i].(string)) {
				return "profile." + c.name + " must be sorted and distinct"
			}
		}
	}
	return ""
}

func joinProfile(p, q Profile) Profile {
	r := p.Rev
	if revRank[p.Rev] < revRank[q.Rev] {
		r = q.Rev
	}
	return mkProfile(Profile{Risk: max(p.Risk, q.Risk), Rev: r, Blast: max(p.Blast, q.Blast), Esc: max(p.Esc, q.Esc),
		Caveats: append(append([]string{}, p.Caveats...), q.Caveats...), Context: append(append([]string{}, p.Context...), q.Context...),
		Prules: append(append([]string{}, p.Prules...), q.Prules...)})
}

func leqProfile(p, q Profile) bool {
	return p.Risk <= q.Risk && revRank[p.Rev] <= revRank[q.Rev] && p.Blast <= q.Blast && p.Esc <= q.Esc &&
		subsetS(p.Caveats, q.Caveats) && subsetS(p.Context, q.Context) && subsetS(p.Prules, q.Prules)
}

// TraitDef is one trait of a registry.
type TraitDef struct {
	ID      string
	Implies []string
	Floor   Profile
	Card    string
}

func (t TraitDef) raw() map[string]any {
	return map[string]any{"id": t.ID, "implies": anyStrs(t.Implies), "floor": t.Floor.raw(), "card_phrase": t.Card}
}

// Registry maps a trait id to its definition.
type Registry map[string]TraitDef

// registryErrorRaw validates raw trait definitions: ids well formed and distinct, pca. reserved unless core, implies resolve, the
// implied floors are below the implier's (T5), no cycle, depth <= 8. "" = valid.
func registryErrorRaw(defs []any, core bool) string {
	if len(defs) > maxRegistryTraits {
		return fmt.Sprintf("a registry holds at most %d traits", maxRegistryTraits)
	}
	by := map[string]map[string]any{}
	for _, tv := range defs {
		t, ok := isObj(tv)
		if !ok {
			return "trait must be an object"
		}
		id, ok := t["id"].(string)
		if !ok || !reTraitID.MatchString(id) {
			return "trait id is malformed"
		}
		if strings.HasPrefix(id, "pca.") && !core {
			return "trait '" + id + "': the pca. namespace is reserved for core traits"
		}
		if by[id] != nil {
			return "trait '" + id + "' is defined twice"
		}
		im, isL := t["implies"].([]any)
		strs, allS := strsOf(t["implies"])
		if !isL || len(im) > 8 || !allS || !distinctStrings(im) {
			return "trait '" + id + "': implies must be up to 8 distinct trait ids"
		}
		_ = strs
		if e := profileErrorRaw(t["floor"]); e != "" {
			return "trait '" + id + "': " + e
		}
		cp, ok := t["card_phrase"].(string)
		if !ok || jsLen(cp) == 0 || jsLen(cp) > 120 {
			return "trait '" + id + "': card_phrase must be a non-empty string up to 120 characters"
		}
		by[id] = t
	}
	for _, tv := range defs {
		t := tv.(map[string]any)
		imp, _ := strsOf(t["implies"])
		for _, u := range imp {
			ud := by[u]
			if ud == nil {
				return "trait '" + t["id"].(string) + "' implies unknown trait '" + u + "'"
			}
			if !leqProfile(profileFromRaw(ud["floor"]), profileFromRaw(t["floor"])) {
				return "trait '" + t["id"].(string) + "': floor is below the floor of implied '" + u + "'"
			}
		}
	}
	depth := map[string]int{}
	visiting := map[string]bool{}
	var walk func(id string) int
	walk = func(id string) int {
		if d, ok := depth[id]; ok {
			return d
		}
		if visiting[id] {
			return -1
		}
		visiting[id] = true
		d := 1
		imp, _ := strsOf(by[id]["implies"])
		for _, u := range imp {
			du := walk(u)
			if du < 0 {
				return -1
			}
			d = max(d, du+1)
		}
		delete(visiting, id)
		depth[id] = d
		return d
	}
	for _, tv := range defs {
		id := tv.(map[string]any)["id"].(string)
		d := walk(id)
		if d < 0 {
			return "trait '" + id + "': implies cycle"
		}
		if d > maxTraitImpliesDepth {
			return fmt.Sprintf("trait '%s': implies depth %d exceeds %d", id, d, maxTraitImpliesDepth)
		}
	}
	return ""
}

func registryFromRaw(defs []any) Registry {
	reg := Registry{}
	for _, tv := range defs {
		t := tv.(map[string]any)
		imp, _ := strsOf(t["implies"])
		reg[t["id"].(string)] = TraitDef{ID: t["id"].(string), Implies: imp, Floor: profileFromRaw(t["floor"]), Card: t["card_phrase"].(string)}
	}
	return reg
}

func (r Registry) rawList() []any {
	ids := make([]string, 0, len(r))
	for id := range r {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = r[id].raw()
	}
	return out
}

// extendRegistry is the core registry extended with custom traits (which must not use pca. and must extend what they imply).
func extendRegistry(base Registry, custom []any) (Registry, error) {
	all := base.rawList()
	for _, cv := range custom {
		c, ok := isObj(cv)
		id, isS := c["id"].(string)
		if !ok || !isS {
			return nil, fmt.Errorf("bad_registry: custom trait may not redefine a core trait")
		}
		if _, dup := base[id]; dup || strings.HasPrefix(id, "pca.") {
			return nil, fmt.Errorf("bad_registry: custom trait '%s' may not redefine a core trait", id)
		}
	}
	all = append(all, custom...)
	if e := registryErrorRaw(all, true); e != "" {
		return nil, fmt.Errorf("bad_registry: %s", e)
	}
	return registryFromRaw(all), nil
}

// closure is cl_R(S): the closure of a set of trait ids under implies, sorted. Error code unknown_trait.
func (r Registry) closure(ids []string) ([]string, error) {
	seen := map[string]bool{}
	stack := append([]string{}, ids...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		t, ok := r[id]
		if !ok {
			return nil, fmt.Errorf("unknown_trait: unknown trait '%s'", id)
		}
		seen[id] = true
		stack = append(stack, t.Implies...)
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// floorOf is F_R(S): the join of the floors of the closure of S.
func (r Registry) floorOf(ids []string) (Profile, error) {
	cl, err := r.closure(ids)
	if err != nil {
		return Profile{}, err
	}
	out := mkProfile(Profile{})
	for _, id := range cl {
		out = joinProfile(out, r[id].Floor)
	}
	return out, nil
}

// GrantFacts is what the stored grant provides for the floor check.
type GrantFacts struct {
	Caveats    []string
	MaxEsc     int
	PreauthEsc int
}

// floorDecision is FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a required caveat is missing from G, a
// required context key is missing from the call, or rho.esc > G.preauth_esc; else allow.
func floorDecision(g GrantFacts, callContext []string, rho Profile) string {
	if rho.Esc > g.MaxEsc {
		return "deny"
	}
	if !subsetS(rho.Caveats, g.Caveats) || !subsetS(rho.Context, callContext) || rho.Esc > g.PreauthEsc {
		return "escalate"
	}
	return "allow"
}

// ---- the 22 core traits -----------------------------------------------------------------------------------------------

var coreTable = []struct {
	name    string
	implies []string
	own     Profile
	phrase  string
}{
	{"money_moving", nil, Profile{Risk: 3, Rev: "rate_limited", Blast: 700_000, Esc: 2, Caveats: []string{"amount_cap", "count_cap", "window"}, Context: []string{"idempotency"}, Prules: []string{"money_has_currency", "money_amount_bounded", "pay_has_idempotency"}}, "moves money"},
	{"destructive", nil, Profile{Risk: 2, Rev: "rate_limited", Esc: 1, Caveats: []string{"resource_scope"}, Prules: []string{"id_not_wildcard"}}, "deletes or destroys data"},
	{"irreversible", nil, Profile{Risk: 2, Rev: "irreversible", Esc: 1, Context: []string{"fresh_revocation"}}, "cannot be undone"},
	{"external_communication", nil, Profile{Risk: 2, Rev: "irreversible", Caveats: []string{"recipient_scope", "rate_cap"}, Prules: []string{"recipient_param_declared"}}, "sends to people outside your organisation"},
	{"data_export", nil, Profile{Risk: 2, Caveats: []string{"resource_scope", "count_cap"}, Prules: []string{"export_bounded"}}, "exports data"},
	{"privilege_change", nil, Profile{Risk: 3, Esc: 3, Caveats: []string{"resource_scope", "short_expiry"}}, "changes who can do what"},
	{"code_execution", nil, Profile{Risk: 3, Rev: "irreversible", Esc: 2, Caveats: []string{"resource_scope"}, Context: []string{"sandbox_attested"}}, "runs code or commands"},
	{"credential_access", nil, Profile{Risk: 3, Esc: 3, Prules: []string{"secret_not_logged"}}, "reads or handles credentials"},
	{"bulk", nil, Profile{Risk: 2, Caveats: []string{"count_cap"}, Prules: []string{"array_bounded"}}, "acts on many items at once"},
	{"pii_access", nil, Profile{Risk: 1, Caveats: []string{"resource_scope"}}, "touches personal data"},
	{"public_exposure", nil, Profile{Risk: 2, Rev: "irreversible", Esc: 1}, "makes content public"},
	{"persistence", nil, Profile{Risk: 2, Caveats: []string{"short_expiry"}, Context: []string{"revocable"}}, "creates standing access or infrastructure"},
	{"infra_mutation", nil, Profile{Risk: 2, Rev: "rate_limited", Caveats: []string{"resource_scope"}}, "changes infrastructure"},
	{"cost_incurring", nil, Profile{Risk: 1, Caveats: []string{"amount_cap"}}, "incurs cost"},
	{"legal_binding", nil, Profile{Risk: 3, Rev: "irreversible", Esc: 3}, "legally or cryptographically binds you"},
	{"impersonation", []string{"external_communication"}, Profile{Risk: 2, Esc: 1}, "acts as a person"},
	{"network_egress", nil, Profile{Risk: 1, Caveats: []string{"recipient_scope"}}, "reaches out to the network"},
	{"financial_data_read", nil, Profile{Risk: 1, Caveats: []string{"resource_scope"}}, "reads financial data"},
	{"regulated_data", nil, Profile{Risk: 2, Esc: 1}, "handles regulated data"},
	{"scheduled", nil, Profile{Risk: 2, Caveats: []string{"short_expiry", "count_cap"}}, "runs later or repeatedly"},
	{"unreviewed", nil, Profile{Risk: 3, Rev: "irreversible", Blast: 1_000_000, Esc: 2, Caveats: []string{"approval_ref", "resource_scope"}, Context: []string{"dry_run_first"}}, "has not been reviewed yet"},
	{"agent_spawning", nil, Profile{Risk: 2, Caveats: []string{"count_cap"}}, "starts another agent"},
}

var (
	effectTraits = map[string][]string{
		"read": {}, "create": {}, "update": {}, "delete": {"pca.destructive"}, "send": {"pca.external_communication"}, "pay": {"pca.money_moving"},
		"exec": {"pca.code_execution"}, "privilege": {"pca.privilege_change"}, "export": {"pca.data_export"}, "publish": {"pca.public_exposure"},
		"provision": {"pca.persistence", "pca.scheduled"}, "sign": {"pca.legal_binding"},
	}
	tagTraits = map[string][]string{
		"pii": {"pca.pii_access"}, "phi": {"pca.pii_access", "pca.regulated_data"}, "pci": {"pca.regulated_data"},
		"secret": {"pca.credential_access"}, "credential": {"pca.credential_access"},
	}
	roleTraits = map[string][]string{
		"credential.secret": {"pca.credential_access"}, "credential.token": {"pca.credential_access"}, "credential.key": {"pca.credential_access"},
		"url.target": {"pca.network_egress"},
	}
	roleSensitivityFloor = map[string]string{
		"money.amount": "critical", "money.currency": "material", "money.fee": "material", "party.payee": "critical", "party.payer": "material",
		"contact.email": "material", "contact.phone": "material", "contact.address": "material", "person.name": "material", "person.dob": "material",
		"person.national_id": "critical", "credential.secret": "critical", "credential.token": "critical", "credential.key": "critical",
		"code.command": "critical", "query.sql": "critical", "text.message": "material",
	}
	tagSensitivityFloor = map[string]string{
		"pii": "material", "phi": "material", "pci": "material", "secret": "critical", "credential": "critical",
		"free_text_outbound": "material", "code": "material", "path": "material", "sql": "material",
	}
	coreRegistry = buildCoreRegistry()
)

func buildCoreRegistry() Registry {
	reg := Registry{}
	var raws []any
	for _, e := range coreTable {
		id := "pca." + e.name
		fl := mkProfile(e.own)
		imp := []string{}
		for _, n := range e.implies {
			imp = append(imp, "pca."+n)
			fl = joinProfile(fl, reg["pca."+n].Floor)
		}
		reg[id] = TraitDef{ID: id, Implies: imp, Floor: fl, Card: e.phrase}
		raws = append(raws, reg[id].raw())
	}
	if e := registryErrorRaw(raws, true); e != "" {
		panic("core trait registry: " + e)
	}
	return reg
}

func rawStringMap(m map[string][]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = anyStrs(v)
	}
	return out
}

// traitsDigest is the digest of a trait registry (sorted by id): what a pack pins as traits_digest.
func traitsDigest(reg Registry) (string, error) {
	ts := reg.rawList()
	for _, t := range ts {
		m := t.(map[string]any)
		m["implies"] = anyStrs(sortUniqS(reg[m["id"].(string)].Implies))
	}
	return HashCanonical(map[string]any{"d": traitsDigestDomain, "traits": ts})
}

// tablesDigest is the digest of the implication and sensitivity tables the trait expansion reads.
func tablesDigest() (string, error) {
	sens := func(m map[string]string) map[string]any {
		o := map[string]any{}
		for k, v := range m {
			o[k] = v
		}
		return o
	}
	return HashCanonical(map[string]any{"d": rolesDigestDomain, "roles": anyStrs(coreRoles), "effect_traits": rawStringMap(effectTraits),
		"role_traits": rawStringMap(roleTraits), "tag_traits": rawStringMap(tagTraits),
		"role_sensitivity": sens(roleSensitivityFloor), "tag_sensitivity": sens(tagSensitivityFloor)})
}

// ---- T(d), decl(d), eff(d) --------------------------------------------------------------------------------------------

// impliedFromFacts: traits implied by effects, roles, tags, scope ("" = not known) and reversibility. params carry type /
// role / tags / max_items. An unknown effect is an error (a forged document).
func impliedFromFacts(effects []string, params []map[string]any, scope, worstRev string) ([]string, error) {
	out := []string{}
	for _, e := range effects {
		ts, ok := effectTraits[e]
		if !ok {
			return nil, fmt.Errorf("unknown effect %q", e)
		}
		out = append(out, ts...)
	}
	ro := isReadOnlyEffects(effects)
	for _, p := range params {
		if r, ok := p["role"].(string); ok {
			out = append(out, roleTraits[r]...)
			if ro && strings.HasPrefix(r, "money.") {
				out = append(out, "pca.financial_data_read")
			}
		}
		if tg, ok := strsOf(p["tags"]); ok {
			for _, t := range tg {
				out = append(out, tagTraits[t]...)
			}
		}
		if p["type"] == "array" && !hasKeyIn(p, "max_items") {
			out = append(out, "pca.bulk")
		}
	}
	if scope != "" && scope != "one" {
		out = append(out, "pca.bulk")
	}
	if worstRev == "irreversible" {
		out = append(out, "pca.irreversible")
	}
	return sortUniqS(out), nil
}

func normParams(n map[string]any) ([]map[string]any, map[string]any) {
	pm := n["params"].(map[string]any)
	list := make([]map[string]any, 0, len(pm))
	for _, k := range sortedKeysStd(pm) {
		list = append(list, pm[k].(map[string]any))
	}
	return list, pm
}

// hintTraits is declared + implied-by-its-own-facts: what the def would have if a reviewer signed it as it stands.
func hintTraits(d map[string]any) []string {
	n := normalizeDef(d)
	list, pm := normParams(n)
	ef, _ := strsOf(n["effects"])
	tr, _ := strsOf(n["traits"])
	imp, _ := impliedFromFacts(ef, list, n["resource"].(map[string]any)["scope"].(string), worstReversibility(n["reversibility"], pm))
	return sortUniqS(append(append([]string{}, tr...), imp...))
}

func declProfile(d map[string]any) Profile {
	n := normalizeDef(d)
	list, pm := normParams(n)
	ef, _ := strsOf(n["effects"])
	critical := false
	for _, p := range list {
		if sensitivityRank[effectiveParamSensitivity(p)] >= sensitivityRank["critical"] {
			critical = true
		}
	}
	risk := 1
	if critical {
		risk = 2
	} else if isReadOnlyEffects(ef) {
		risk = 0
	}
	cx, _ := strsOf(n["context"])
	return mkProfile(Profile{Risk: risk, Rev: worstReversibility(n["reversibility"], pm), Blast: n["blast"].(map[string]any)["ppm"].(int), Context: cx})
}

// Effective is {T(d), cl(T(d)), eff(d) = decl(d) join F(T(d))}; an unconfirmed def has the top of the registry as T(d).
type Effective struct {
	Confirmed bool
	Traits    []string
	Closure   []string
	Eff       Profile
}

func effective(d map[string]any, reg Registry, pins any) (Effective, error) {
	confirmed := defConfirmed(d, reg, pins)
	tr := topTraits(reg)
	if confirmed {
		tr = hintTraits(d)
	}
	cl, err := reg.closure(tr)
	if err != nil {
		return Effective{}, err
	}
	fl, _ := reg.floorOf(tr)
	return Effective{Confirmed: confirmed, Traits: tr, Closure: cl, Eff: joinProfile(declProfile(d), fl)}, nil
}

// ---- rule 22: whole-document integrity of the carried traits and floors ---------------------------------------------

const paramsPrefix = "action.params."

func trimParamsPrefix(p string) string {
	if len(p) < len(paramsPrefix) {
		return ""
	}
	return p[len(paramsPrefix):]
}

// errCode is the `<code>` of a "<code>: reason" error text (the code is the first token).
func errCode(e error) string {
	s := e.Error()
	if i := strings.IndexAny(s, ": "); i >= 0 {
		return s[:i]
	}
	return s
}

// schemaVerbFloorError recomputes from the verb's own visible facts that its traits contain every implied trait and that its
// floors are at least the floor of the traits' closure and of the declared reversibility. "" = consistent, else "<code>: <reason>".
func schemaVerbFloorError(v map[string]any, reg Registry, pins any) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = fmt.Sprint("schema_floor_forged: ", r)
		}
	}()
	effects, effOK := strsOf(v["effects"])
	traitsL, trOK := strsOf(v["traits"])
	if !effOK || !trOK || !hasKeyIn(v, "floors") {
		return "schema_floor_forged: not a v2 verb"
	}
	pm := v["params"].(map[string]any)
	byName := map[string]any{}
	plist := []map[string]any{}
	for path, pv := range pm {
		p := pv.(map[string]any)
		e := map[string]any{"type": p["type"]}
		if vs, has := p["values"]; has {
			e["values"] = vs
		}
		byName[trimParamsPrefix(path)] = e
		plist = append(plist, p)
	}
	var decl any
	if rb, ok := v["reversibility_by"].(map[string]any); ok {
		pstr, _ := rb["param"].(string)
		d := map[string]any{"by": trimParamsPrefix(pstr), "map": rb["map"]}
		if dv, has := rb["default"]; has {
			d["default"] = dv
		}
		decl = d
	} else if rv, has := v["reversibility"]; has {
		decl = rv
	} else if v["kind"] == "read" {
		decl = "reversible"
	} else {
		decl = "irreversible"
	}
	worst := worstReversibility(decl, byName)
	implied, err := impliedFromFacts(effects, plist, "", worst)
	if err != nil {
		return "schema_floor_forged: " + err.Error()
	}
	for _, t := range implied {
		if !contains(traitsL, t) {
			return "schema_traits_forged: missing implied trait " + t
		}
	}
	// unconfirmed means maximally dangerous: without a valid signed confirmation the verb must carry EVERY trait of the registry
	if verbConfirmationError(v, reg, pins) != "" {
		for _, t := range topTraits(reg) {
			if !contains(traitsL, t) {
				return "schema_traits_forged: unconfirmed action must carry every trait (missing " + t + ")"
			}
		}
	}
	fl, err := reg.floorOf(traitsL)
	if err != nil {
		return err.Error()
	}
	if e := profileErrorRaw(v["floors"]); e != "" {
		return "schema_floor_forged: " + e
	}
	floors := profileFromRaw(v["floors"])
	if !leqProfile(fl, floors) {
		return "schema_floor_forged: floors are below the floor of the carried traits"
	}
	if wr, ok := revRank[worst]; ok && revRank[floors.Rev] < wr {
		return "schema_floor_forged: floors.rev is below the declared reversibility"
	}
	return ""
}

// registryOfSchema is the core registry plus the document's own trait_defs (checked); when the document carries traits_digest the
// registry must hash to it. Error codes: bad_registry, traits_digest_mismatch.
func registryOfSchema(doc map[string]any) (Registry, error) {
	reg := coreRegistry
	if td, ok := doc["trait_defs"].([]any); ok && len(td) > 0 {
		var err error
		if reg, err = extendRegistry(coreRegistry, td); err != nil {
			return nil, err
		}
	}
	if want, has := doc["traits_digest"]; has {
		got, err := traitsDigest(reg)
		if err != nil || want != got {
			return nil, fmt.Errorf("traits_digest_mismatch: the document's traits_digest does not match its trait registry")
		}
	}
	return reg, nil
}

// schemaFloorError is rule 22's integrity half for a whole v2 document. "" = consistent.
func schemaFloorError(doc map[string]any, pins any) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = fmt.Sprint("bad_registry: ", r)
		}
	}()
	reg, err := registryOfSchema(doc)
	if err != nil {
		return err.Error()
	}
	for _, vv := range doc["verbs"].([]any) {
		v := vv.(map[string]any)
		if e := schemaVerbFloorError(v, reg, pins); e != "" {
			return fmt.Sprint(v["verb"], ": ", e)
		}
	}
	return ""
}
