package pca

// The outcome space derived from a site's signed action schema: dimensions only for parameters whose effective sensitivity
// (after the wallet floor) is material or critical, canonical projections for boolean / set / array parameters, and default
// sets for silent parameters.

import (
	"math"
	"sort"
	"strings"
)

var (
	ixWalletFloorPrefixes = []any{"money.", "party.", "contact.", "person.", "credential."}
	ixWalletFloorExact    = []any{"text.message"}
	ixRevOrder            = []string{"reversible", "rate_limited", "irreversible"}
)

func ixSortUtf8(ss []string) []string {
	sort.SliceStable(ss, func(i, j int) bool { return compareUtf8(ss[i], ss[j]) < 0 })
	return ss
}

func ixFloorApplies(semantic string, floor map[string]any) bool {
	pre, ex := ixWalletFloorPrefixes, ixWalletFloorExact
	if floor["prefixes"] != nil {
		pre = ixL(floor["prefixes"])
	}
	if floor["exact"] != nil {
		ex = ixL(floor["exact"])
	}
	for _, e := range ex {
		if e == semantic {
			return true
		}
	}
	for _, p := range pre {
		if s, ok := p.(string); ok && strings.HasPrefix(semantic, s) {
			return true
		}
	}
	return false
}

// ixEffectiveSensitivity: a site `free` on a floored semantic type becomes `material`.
func ixEffectiveSensitivity(d, floor map[string]any) any {
	if d["sensitivity"] == "free" && ixFloorApplies(ixS(ixReq(d, "semantic")), floor) {
		return "material"
	}
	return d["sensitivity"]
}

// ixVerbReversibility is rev(v) = max over outcomes of the declared reversibility (the conservative projection).
func ixVerbReversibility(v map[string]any) string {
	rb := ixM(v["reversibility_by"])
	if len(rb) == 0 {
		if ixTruthy(v["reversibility"]) {
			return ixS(v["reversibility"])
		}
		if v["kind"] == "read" {
			return "reversible"
		}
		return "irreversible"
	}
	d := ixM(ixM(ixReq(v, "params"))[ixS(ixReq(rb, "param"))])
	mp := ixM(ixReq(rb, "map"))
	var mapped []string
	for _, k := range ixKeysSorted(mp) {
		mapped = append(mapped, ixS(mp[k]))
	}
	var domain []string
	if d != nil && d["type"] == "boolean" {
		domain = []string{"true", "false"}
	} else if d != nil && d["type"] == "string" && ixTruthy(d["values"]) {
		domain = ixStrList(d["values"])
	}
	covered := domain != nil
	for _, x := range domain {
		if _, ok := mp[x]; !ok {
			covered = false
		}
	}
	items := mapped
	if !covered {
		def := "irreversible"
		if ixTruthy(rb["default"]) {
			def = ixS(rb["default"])
		}
		items = append(append([]string{}, mapped...), def)
	}
	if len(items) == 0 {
		return "reversible"
	}
	best := items[0]
	for _, r := range items[1:] {
		if ixIndexOf(ixRevOrder, r) > ixIndexOf(ixRevOrder, best) {
			best = r
		}
	}
	return best
}

func ixWalletFloorOverrides(verbs []any, floor map[string]any) []any {
	out := []any{}
	for _, vv := range verbs {
		v := ixM(vv)
		params := ixM(ixReq(v, "params"))
		for _, path := range ixSortUtf8(ixKeysSorted(params)) {
			d := ixM(params[path])
			eff := ixEffectiveSensitivity(d, floor)
			if eff != d["sensitivity"] {
				out = append(out, map[string]any{"verb": v["verb"], "path": path, "semantic": d["semantic"], "declared": d["sensitivity"], "effective": eff})
			}
		}
	}
	return out
}

func ixUsesCanon(d map[string]any) bool {
	return d["type"] == "boolean" || d["type"] == "set" || d["type"] == "array"
}

// ixCanonValue is the canonical text a value of a canon-projected parameter has.
func ixCanonValue(d map[string]any, x any) string {
	if d["type"] == "boolean" {
		if x == true {
			return "true"
		}
		return "false"
	}
	v := x
	if d["type"] == "set" {
		l, ok := x.([]any)
		if !ok {
			ixFail("not iterable")
		}
		ss := make([]string, len(l))
		for i, e := range l {
			s, ok := e.(string)
			if !ok {
				ixFail("set element is not a string")
			}
			ss[i] = s
		}
		v = ixToAny(ixSortUtf8(ss))
	}
	s, err := Canonicalize(ixNums(v))
	if err != nil {
		ixFail("%v", err)
	}
	return s
}

func ixIsSafeIntNum(x any) bool {
	f, ok := x.(float64)
	return ok && f == math.Trunc(f) && math.Abs(f) <= 9007199254740991
}

// ixDeriveOmegaFromSchema derives the schema outcome space: {omega, overrides, defaults, canonOf}.
func ixDeriveOmegaFromSchema(o map[string]any) map[string]any {
	schemaVerbs := ixL(ixReq(ixM(ixReq(o, "schema")), "verbs"))
	slots := ixM(o["slots"])
	var verbNames []string
	if o["verbs"] != nil {
		verbNames = ixStrList(o["verbs"])
	} else {
		seen := map[string]bool{}
		add := func(v string) {
			if !seen[v] {
				seen[v] = true
				verbNames = append(verbNames, v)
			}
		}
		for _, sv := range schemaVerbs {
			if s := ixM(sv); s["kind"] == "write" {
				add(ixS(s["verb"]))
			}
		}
		for _, v := range ixL(slots["verbs"]) {
			add(ixS(v))
		}
	}
	policies := ixL(o["policies"])
	if policies == nil {
		policies = []any{}
	}
	base := ixDeriveOmega(map[string]any{"policies": policies, "slots": o["slots"], "extraVerbs": ixToAny(verbNames)})
	defaults := []any{}
	canonOf := map[string]any{}
	verbs := []any{}
	confirmed := ixM(o["confirmed"])
	floor := ixM(o["floor"])
	domains := ixM(o["domains"])
	for _, verb := range ixSortUtf8(append([]string{}, verbNames...)) {
		var decl map[string]any
		for _, sv := range schemaVerbs {
			if ixS(ixM(sv)["verb"]) == verb {
				decl = ixM(sv)
				break
			}
		}
		if decl == nil {
			continue
		}
		var lits map[string]any
		for _, bv := range ixL(base["verbs"]) {
			if ixS(ixM(bv)["verb"]) == verb {
				lits = ixM(bv)
				break
			}
		}
		litDim := func(path string) map[string]any {
			for _, d := range ixL(lits["dims"]) {
				if ixS(ixM(d)["path"]) == path {
					return ixM(d)
				}
			}
			return nil
		}
		dims := []any{}
		for _, d := range ixL(lits["dims"]) {
			if !strings.HasPrefix(ixS(ixM(d)["path"]), "action.params.") {
				dims = append(dims, d)
			}
		}
		params := ixM(ixReq(decl, "params"))
		for _, path := range ixSortUtf8(ixKeysSorted(params)) {
			pd := ixM(params[path])
			if ixEffectiveSensitivity(pd, floor) == "free" {
				continue
			}
			lit := litDim(path)
			silent := lit == nil
			defaultSet := append([]any{}, ixL(confirmed[path])...)
			if pd["principal_neutral_default"] == true && ixHas(pd, "default") {
				defaultSet = append(defaultSet, pd["default"])
			}
			if pd["type"] == "integer" {
				var cuts []float64
				if lit != nil && lit["kind"] == "num" {
					for _, c := range ixL(lit["cuts"]) {
						cuts = append(cuts, ixF(c))
					}
				}
				for _, x := range defaultSet {
					if ixIsSafeIntNum(x) {
						dup := false
						for _, c := range cuts {
							if c == x.(float64) {
								dup = true
							}
						}
						if !dup {
							cuts = append(cuts, x.(float64))
						}
					}
				}
				sort.Float64s(cuts)
				var srt []float64
				for i, c := range cuts {
					if i == 0 || c != cuts[i-1] {
						srt = append(srt, c)
					}
				}
				maxCut := 0.0
				if len(srt) > 0 {
					maxCut = srt[len(srt)-1]
				}
				dom := ixM(domains[path])
				var lo, hi float64
				switch {
				case dom != nil && dom["lo"] != nil:
					lo = ixF(dom["lo"])
				case pd["min"] != nil:
					lo = ixF(pd["min"])
				case len(srt) > 0:
					lo = math.Min(0, srt[0]-1)
				default:
					lo = 0
				}
				switch {
				case dom != nil && dom["hi"] != nil:
					hi = ixF(dom["hi"])
				case pd["max"] != nil:
					hi = ixF(pd["max"])
				default:
					hi = math.Max(10, math.Max(2*maxCut, maxCut+10))
				}
				kept := []any{}
				for _, c := range srt {
					if lo <= c && c <= hi {
						kept = append(kept, c)
					}
				}
				dist := "uniform"
				if lo >= 0 {
					dist = "loguniform"
				}
				dims = append(dims, map[string]any{"kind": "num", "path": path, "lo": lo, "hi": hi, "cuts": kept, "dist": dist})
				var nums []any
				for _, x := range defaultSet {
					if ixIsNum(x) {
						nums = append(nums, x)
					}
				}
				if silent && len(nums) == 1 {
					defaults = append(defaults, map[string]any{"verb": verb, "path": path, "min": nums[0], "max": nums[0]})
				}
				continue
			}
			canon := ixUsesCanon(pd)
			dimPath := path
			if canon {
				dimPath = "env.canon." + path[len("action.params."):]
				canonOf[dimPath] = path
			}
			exacts, prefixes := map[string]bool{}, map[string]bool{}
			if lit != nil && lit["kind"] == "cat" {
				for _, vv := range ixL(lit["values"]) {
					v := ixM(vv)
					if v["kind"] == "exact" {
						exacts[ixS(v["value"])] = true
					} else if v["kind"] == "prefix" {
						prefixes[ixS(v["value"])] = true
					}
				}
			}
			if pd["type"] == "string" && ixTruthy(pd["values"]) {
				for _, v := range ixL(pd["values"]) {
					exacts[ixS(v)] = true
				}
			}
			if pd["type"] == "boolean" {
				exacts["false"], exacts["true"] = true, true
			}
			var defTexts []string
			for _, x := range defaultSet {
				if canon {
					defTexts = append(defTexts, ixCanonValue(pd, x))
				} else {
					defTexts = append(defTexts, jsValueString(x))
				}
			}
			for _, t := range defTexts {
				exacts[t] = true
			}
			values := []any{}
			for _, v := range ixSortUtf8(ixBoolKeys(exacts)) {
				values = append(values, map[string]any{"kind": "exact", "value": v})
			}
			for _, v := range ixSortUtf8(ixBoolKeys(prefixes)) {
				values = append(values, map[string]any{"kind": "prefix", "value": v})
			}
			values = append(values, map[string]any{"kind": "other", "value": ixOther})
			dims = append(dims, map[string]any{"kind": "cat", "path": dimPath, "values": values})
			if silent && len(defTexts) > 0 {
				defaults = append(defaults, map[string]any{"verb": verb, "path": dimPath, "oneOf": ixToAny(ixSortUtf8(ixBoolKeys(ixSetFrom(defTexts))))})
			}
		}
		sort.SliceStable(dims, func(i, j int) bool { return compareUtf8(ixS(ixM(dims[i])["path"]), ixS(ixM(dims[j])["path"])) < 0 })
		verbs = append(verbs, map[string]any{"verb": verb, "reversibility": ixVerbReversibility(decl), "weight": 0.0, "dims": dims})
	}
	n := float64(len(verbs))
	if n == 0 {
		n = 1
	}
	for _, v := range verbs {
		v.(map[string]any)["weight"] = 1 / n
	}
	var inNames []any
	for _, sv := range schemaVerbs {
		if ixIndexOf(verbNames, ixM(sv)["verb"]) >= 0 {
			inNames = append(inNames, sv)
		}
	}
	return map[string]any{"omega": map[string]any{"v": 1.0, "verbs": verbs, "approximate": base["approximate"]},
		"overrides": ixWalletFloorOverrides(inNames, floor), "defaults": defaults, "canonOf": canonOf}
}

func ixBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func ixSetFrom(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}
