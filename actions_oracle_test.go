package pca

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Differential / mutation-kill tests for the actions module (trait closure and floor, FloorDecision, digest normalization,
// schema floor integrity). Every expectation comes from an independent oracle written here (eight rounds of one-step
// implication; the literal FloorDecision rule) or from the exact reference messages, so boundary mutants cannot survive.

func oracleClosure(reg Registry, ids []string) ([]string, bool) {
	set := map[string]bool{}
	for _, id := range ids {
		if _, ok := reg[id]; !ok {
			return nil, false
		}
		set[id] = true
	}
	for round := 0; round < 8; round++ {
		for id := range set {
			for _, u := range reg[id].Implies {
				set[u] = true
			}
		}
	}
	out := []string{}
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, true
}

func oracleJoin(ps []Profile) Profile {
	o := Profile{Rev: "reversible"}
	set := func(dst *[]string, src []string) {
		m := map[string]bool{}
		for _, x := range append(append([]string{}, *dst...), src...) {
			m[x] = true
		}
		*dst = []string{}
		for x := range m {
			*dst = append(*dst, x)
		}
		sort.Strings(*dst)
	}
	for _, p := range ps {
		if p.Risk > o.Risk {
			o.Risk = p.Risk
		}
		if revRank[p.Rev] > revRank[o.Rev] {
			o.Rev = p.Rev
		}
		if p.Blast > o.Blast {
			o.Blast = p.Blast
		}
		if p.Esc > o.Esc {
			o.Esc = p.Esc
		}
		set(&o.Caveats, p.Caveats)
		set(&o.Context, p.Context)
		set(&o.Prules, p.Prules)
	}
	return o
}

func customChain(n int, floor Profile) []any {
	out := []any{}
	for i := 0; i < n; i++ {
		imp := []string{}
		if i < n-1 {
			imp = []string{fmt.Sprintf("acme.c%d", i+1)}
		}
		out = append(out, TraitDef{ID: fmt.Sprintf("acme.c%d", i), Implies: imp, Floor: floor, Card: "c"}.raw())
	}
	return out
}

func TestActionsOracleExpandFloor(t *testing.T) {
	rng := rand.New(rand.NewSource(0xa7))
	core := []string{}
	for id := range coreRegistry {
		core = append(core, id)
	}
	sort.Strings(core)
	// custom traits over random core implications, each floor = join of implied floors raised by a random bump
	for iter := 0; iter < 300; iter++ {
		var custom []any
		ids := append([]string{}, core...)
		reg := Registry{}
		for k, v := range coreRegistry {
			reg[k] = v
		}
		for c := 0; c < rng.Intn(4); c++ {
			imp := []string{}
			fl := []Profile{}
			for _, id := range ids {
				if rng.Intn(6) == 0 && len(imp) < 3 {
					imp = append(imp, id)
					fl = append(fl, reg[id].Floor)
				}
			}
			f := oracleJoin(fl)
			f.Esc = (f.Esc + rng.Intn(2)) % 4
			if len(imp) > 0 && f.Esc < oracleJoin(fl).Esc {
				f.Esc = oracleJoin(fl).Esc
			}
			td := TraitDef{ID: fmt.Sprintf("acme.t%d", c), Implies: imp, Floor: mkProfile(f), Card: "t"}
			custom = append(custom, td.raw())
			reg[td.ID] = td
			ids = append(ids, td.ID)
		}
		r, err := coreRegistry, error(nil)
		if len(custom) > 0 {
			if r, err = extendRegistry(coreRegistry, custom); err != nil {
				t.Fatalf("valid custom registry refused: %v", err)
			}
		}
		pick := []string{}
		for _, id := range ids {
			if rng.Intn(5) == 0 {
				pick = append(pick, id)
			}
		}
		want, _ := oracleClosure(r, pick)
		got, err := r.closure(pick)
		if err != nil || !reflect.DeepEqual(append([]string{}, got...), append([]string{}, want...)) {
			t.Fatalf("closure(%v) = %v, %v; oracle %v", pick, got, err, want)
		}
		fl := []Profile{}
		for _, id := range want {
			fl = append(fl, r[id].Floor)
		}
		wf := oracleJoin(fl)
		gf, _ := r.floorOf(pick)
		if !reflect.DeepEqual(gf.raw(), wf.raw()) {
			t.Fatalf("floorOf(%v) = %v; oracle %v", pick, gf.raw(), wf.raw())
		}
		if len(pick) > 0 && len(want) < len(pick) {
			t.Fatal("closure lost a member")
		}
	}
	if _, err := coreRegistry.closure([]string{"pca.nope"}); err == nil {
		t.Fatal("unknown trait must be refused")
	}
	// impersonation implies external_communication (the only core implication)
	cl, _ := coreRegistry.closure([]string{"pca.impersonation"})
	if !reflect.DeepEqual(cl, []string{"pca.external_communication", "pca.impersonation"}) {
		t.Fatalf("impersonation closure %v", cl)
	}
}

func TestActionsRegistryBoundaries(t *testing.T) {
	low := mkProfile(Profile{})
	if _, err := extendRegistry(coreRegistry, customChain(8, low)); err != nil {
		t.Fatalf("depth 8 must be accepted: %v", err)
	}
	if _, err := extendRegistry(coreRegistry, customChain(9, low)); err == nil {
		t.Fatal("depth 9 must be refused")
	}
	// T5: a trait below the floor of what it implies is refused; equal is fine
	mm := coreRegistry["pca.money_moving"].Floor
	mk := func(f Profile) []any {
		return []any{TraitDef{ID: "acme.x", Implies: []string{"pca.money_moving"}, Floor: mkProfile(f), Card: "x"}.raw()}
	}
	if _, err := extendRegistry(coreRegistry, mk(mm)); err != nil {
		t.Fatalf("equal floor refused: %v", err)
	}
	for name, mut := range map[string]func(*Profile){
		"risk": func(p *Profile) { p.Risk-- }, "rev": func(p *Profile) { p.Rev = "reversible" }, "esc": func(p *Profile) { p.Esc-- },
		"blast": func(p *Profile) { p.Blast-- }, "caveat": func(p *Profile) { p.Caveats = p.Caveats[1:] },
		"context": func(p *Profile) { p.Context = nil }, "prule": func(p *Profile) { p.Prules = p.Prules[1:] },
	} {
		f := mm
		f.Caveats, f.Context, f.Prules = append([]string{}, mm.Caveats...), append([]string{}, mm.Context...), append([]string{}, mm.Prules...)
		mut(&f)
		if _, err := extendRegistry(coreRegistry, mk(f)); err == nil {
			t.Fatalf("floor below implied (%s) must be refused", name)
		}
	}
	// rev rank order: rate_limited trait implying an irreversible one is below; irreversible over rate_limited is fine
	if _, err := extendRegistry(coreRegistry, []any{TraitDef{ID: "acme.r", Implies: []string{"pca.irreversible"}, Floor: mkProfile(Profile{Risk: 2, Rev: "rate_limited", Esc: 1, Context: []string{"fresh_revocation"}}), Card: "r"}.raw()}); err == nil {
		t.Fatal("rev rank below implied must be refused")
	}
	// value bounds: ppm max 1_000_000, risk/esc max 3
	for name, f := range map[string]Profile{"ppm-max": {Blast: 1000000}, "risk-max": {Risk: 3}, "esc-max": {Esc: 3}} {
		if _, err := extendRegistry(coreRegistry, []any{TraitDef{ID: "acme.v", Floor: mkProfile(f), Card: "v"}.raw()}); err != nil {
			t.Fatalf("%s must be accepted: %v", name, err)
		}
	}
	for name, f := range map[string]Profile{"ppm": {Blast: 1000001}, "risk": {Risk: 4}, "esc": {Esc: 4}, "neg": {Blast: -1}} {
		if _, err := extendRegistry(coreRegistry, []any{TraitDef{ID: "acme.v", Floor: mkProfile(f), Card: "v"}.raw()}); err == nil {
			t.Fatalf("%s over the bound must be refused", name)
		}
	}
	// reserved namespace, duplicates, cycle, unknown implies
	bad := [][]any{
		{TraitDef{ID: "pca.fresh", Floor: low, Card: "x"}.raw()},
		{TraitDef{ID: "acme.a", Floor: low, Card: "x"}.raw(), TraitDef{ID: "acme.a", Floor: low, Card: "x"}.raw()},
		{TraitDef{ID: "acme.a", Implies: []string{"acme.b"}, Floor: low, Card: "x"}.raw(), TraitDef{ID: "acme.b", Implies: []string{"acme.a"}, Floor: low, Card: "x"}.raw()},
		{TraitDef{ID: "acme.a", Implies: []string{"acme.zzz"}, Floor: low, Card: "x"}.raw()},
		{TraitDef{ID: "acme.a", Floor: low, Card: ""}.raw()},
	}
	for i, b := range bad {
		if _, err := extendRegistry(coreRegistry, b); err == nil {
			t.Fatalf("bad registry %d accepted", i)
		}
	}
}

func TestActionsOracleFloorDecision(t *testing.T) {
	rng := rand.New(rand.NewSource(0xf1))
	cav := []string{"amount_cap", "count_cap", "window", "resource_scope"}
	ctx := []string{"idempotency", "fresh_revocation", "revocable"}
	sub := func(xs []string) []string {
		o := []string{}
		for _, x := range xs {
			if rng.Intn(2) == 0 {
				o = append(o, x)
			}
		}
		return o
	}
	has := func(xs []string, x string) bool {
		for _, y := range xs {
			if y == x {
				return true
			}
		}
		return false
	}
	rank := map[string]int{"deny": 0, "escalate": 1, "allow": 2}
	for i := 0; i < 3000; i++ {
		g := GrantFacts{Caveats: sub(cav), MaxEsc: rng.Intn(4), PreauthEsc: rng.Intn(4)}
		call := sub(ctx)
		rho := mkProfile(Profile{Esc: rng.Intn(4), Caveats: sub(cav), Context: sub(ctx)})
		missing := false
		for _, c := range rho.Caveats {
			missing = missing || !has(g.Caveats, c)
		}
		for _, c := range rho.Context {
			missing = missing || !has(call, c)
		}
		want := "allow"
		if rho.Esc > g.MaxEsc {
			want = "deny"
		} else if missing || rho.Esc > g.PreauthEsc {
			want = "escalate"
		}
		if got := floorDecision(g, call, rho); got != want {
			t.Fatalf("floorDecision(%+v,%v,%+v) = %s want %s", g, call, rho, got, want)
		}
		// antitone: a bigger profile never decides more permissively
		up := rho
		up.Esc = min3(rho.Esc+rng.Intn(2), 3)
		up.Caveats = sortUniqS(append(append([]string{}, rho.Caveats...), sub(cav)...))
		if rank[floorDecision(g, call, up)] > rank[floorDecision(g, call, rho)] {
			t.Fatal("floorDecision is not antitone in the profile")
		}
	}
	// exact boundaries: esc == max_esc is not deny; esc == preauth is allow; one above preauth escalates
	g := GrantFacts{MaxEsc: 2, PreauthEsc: 1}
	if floorDecision(g, nil, Profile{Esc: 2}) != "escalate" || floorDecision(g, nil, Profile{Esc: 3}) != "deny" ||
		floorDecision(g, nil, Profile{Esc: 1}) != "allow" || floorDecision(g, nil, Profile{Esc: 0}) != "allow" {
		t.Fatal("floorDecision boundary")
	}
	// subset direction: a grant caveat the profile does not need never escalates; a needed one the grant lacks always does
	if floorDecision(GrantFacts{Caveats: []string{"window"}, MaxEsc: 3, PreauthEsc: 3}, nil, Profile{}) != "allow" ||
		floorDecision(GrantFacts{MaxEsc: 3, PreauthEsc: 3}, nil, Profile{Caveats: []string{"window"}}) != "escalate" ||
		floorDecision(GrantFacts{MaxEsc: 3, PreauthEsc: 3}, []string{"idempotency"}, Profile{}) != "allow" ||
		floorDecision(GrantFacts{MaxEsc: 3, PreauthEsc: 3}, nil, Profile{Context: []string{"idempotency"}}) != "escalate" {
		t.Fatal("floorDecision subset direction")
	}
}

func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func actionVectorByID(t *testing.T, id string) map[string]any {
	t.Helper()
	for _, c := range loadActionVectors(t) {
		if c["id"] == id {
			return c["input"].(map[string]any)
		}
	}
	t.Fatalf("vector %s missing", id)
	return nil
}

func TestActionsDigestNormalizationInvariance(t *testing.T) {
	in := actionVectorByID(t, "digest-adv-key-order-and-defaults")
	d := in["def"].(map[string]any)
	base, err := defDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if base != "0PCipWqUtp190v4OHVSrr5Utkq86SrXQN4hYsnCkJwU" {
		t.Fatalf("pinned digest %s", base)
	}
	cp := func() map[string]any { return deepCopy(d).(map[string]any) }
	same := func(name string, f func(m map[string]any)) {
		m := cp()
		f(m)
		if g, _ := defDigest(m); g != base {
			t.Fatalf("%s changed the digest", name)
		}
	}
	diff := func(name string, f func(m map[string]any)) {
		m := cp()
		f(m)
		if g, _ := defDigest(m); g == base {
			t.Fatalf("%s did not change the digest", name)
		}
	}
	same("alias order", func(m map[string]any) {
		a := m["aliases"].([]any)
		for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
			a[i], a[j] = a[j], a[i]
		}
	})
	same("review state", func(m map[string]any) { m["review"] = map[string]any{"state": "unreviewed"} })
	same("since", func(m map[string]any) { m["since"] = "9.9.9" })
	same("examples", func(m map[string]any) {
		m["examples"] = []any{map[string]any{"params": map[string]any{}, "expect": "deny"}}
	})
	same("explicit defaults", func(m map[string]any) { m["blast"] = map[string]any{"radius": "one"}; m["context"] = []any{} })
	diff("title", func(m map[string]any) { m["title"] = "Refund a charge." })
	diff("effects", func(m map[string]any) { m["effects"] = []any{"pay", "send"} })
	diff("reversibility", func(m map[string]any) { m["reversibility"] = "rate_limited" })
	diff("param bound", func(m map[string]any) {
		m["params"].(map[string]any)["amount"].(map[string]any)["max"] = float64(10000000001)
	})
	diff("blast ppm raise", func(m map[string]any) { m["blast"] = map[string]any{"radius": "one", "ppm": float64(900000)} })
	diff("alias set", func(m map[string]any) { m["aliases"] = append(m["aliases"].([]any), "extra_alias") })
	diff("trait", func(m map[string]any) { m["traits"] = []any{"pca.bulk"} })
	// an unlisted ppm below the radius default never lowers the blast
	same("ppm below default", func(m map[string]any) { m["blast"] = map[string]any{"radius": "one", "ppm": float64(10)} })
}

func TestActionsSchemaVerbFloorExactMessages(t *testing.T) {
	honest := actionVectorByID(t, "schema-verb-adv-honest")["verb"].(map[string]any)
	mut := func(f func(v map[string]any)) string {
		v := deepCopy(honest).(map[string]any)
		f(v)
		return schemaVerbFloorError(v, coreRegistry, nil)
	}
	if e := schemaVerbFloorError(honest, coreRegistry, nil); e != "" {
		t.Fatalf("honest verb refused: %s", e)
	}
	const below = "schema_floor_forged: floors are below the floor of the carried traits"
	cases := map[string]struct {
		f    func(v map[string]any)
		want string
	}{
		"esc":      {func(v map[string]any) { v["floors"].(map[string]any)["esc"] = float64(1) }, below},
		"blast":    {func(v map[string]any) { v["floors"].(map[string]any)["blast_ppm"] = float64(699999) }, below},
		"risk":     {func(v map[string]any) { v["floors"].(map[string]any)["risk"] = float64(2) }, below},
		"caveat":   {func(v map[string]any) { v["floors"].(map[string]any)["caveats"] = []any{"amount_cap"} }, below},
		"context":  {func(v map[string]any) { v["floors"].(map[string]any)["context"] = []any{} }, below},
		"prules":   {func(v map[string]any) { v["floors"].(map[string]any)["prules"] = []any{} }, below},
		"rev":      {func(v map[string]any) { v["floors"].(map[string]any)["rev"] = "reversible" }, below},
		"rev-rate": {func(v map[string]any) { v["floors"].(map[string]any)["rev"] = "rate_limited" }, below},
		"dropped": {func(v map[string]any) {
			v["traits"] = []any{"pca.irreversible"}
		}, "schema_traits_forged: missing implied trait pca.money_moving"},
		"unknown":  {func(v map[string]any) { v["traits"] = append(v["traits"].([]any), "pca.zzz") }, "unknown_trait: unknown trait 'pca.zzz'"},
		"v1":       {func(v map[string]any) { delete(v, "floors"); delete(v, "traits") }, "schema_floor_forged: not a v2 verb"},
		"no-irrev": {func(v map[string]any) { v["traits"] = []any{"pca.money_moving"} }, "schema_traits_forged: missing implied trait pca.irreversible"},
	}
	for name, c := range cases {
		if got := mut(c.f); got != c.want {
			t.Errorf("%s: got %q want %q", name, got, c.want)
		}
	}
	// raising floors above the minimum is fine (>= not ==)
	if e := mut(func(v map[string]any) { v["floors"].(map[string]any)["blast_ppm"] = float64(1000000) }); e != "" {
		t.Fatalf("higher floors refused: %s", e)
	}
	// an unconfirmed verb with too few traits is refused by the top-of-registry rule before the floors are read
	plain := map[string]any{"verb": "a.b", "kind": "write", "params": map[string]any{}, "effects": []any{"update"}, "traits": []any{}, "reversibility": "rate_limited",
		"floors": map[string]any{"risk": float64(0), "rev": "rate_limited", "blast_ppm": float64(0), "esc": float64(0), "caveats": []any{}, "context": []any{}, "prules": []any{}}}
	if e := schemaVerbFloorError(plain, coreRegistry, nil); !strings.HasPrefix(e, "schema_traits_forged: unconfirmed action must carry every trait (missing ") {
		t.Fatalf("unconfirmed top rule: %q", e)
	}
	// a read verb with the money role gets the financial_data_read implication; dropping it is caught
	rd := deepCopy(honest).(map[string]any)
	rd["kind"], rd["effects"], rd["reversibility"] = "read", []any{"read"}, "reversible"
	rd["traits"] = []any{}
	if e := schemaVerbFloorError(rd, coreRegistry, nil); e != "schema_traits_forged: missing implied trait pca.financial_data_read" {
		t.Fatalf("read money role: %q", e)
	}
}
