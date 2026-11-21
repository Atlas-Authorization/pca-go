package blstkit

import (
	"math/big"
	"strconv"
)

// The replayed corpus carries no key bytes: master and user keys are recipes ({"$abeMsk": label} and
// {"$abeKey": {msk, attrs, id}}, optionally edited by "$patch"/"$edits" or merged by "$pool"). Every scalar is
// sha512("abe-oracle/" + label + name) mod r (abeSc), so the keys are re-derived here, identically to the reference.

func abeSeedMskRaw(label string) (*fameMpk, *fameMsk) {
	s := func(n string) *big.Int { return abeSc(label + "/" + n) }
	mpk, msk, err := fameSetup([2]*big.Int{s("a1"), s("a2")}, [2]*big.Int{s("b1"), s("b2")}, [3]*big.Int{s("d1"), s("d2"), s("d3")})
	if err != nil {
		panic(err)
	}
	return mpk, msk
}

func abeSeedMsk(label string) map[string]any {
	_, sk := abeSeedMskRaw(label)
	return map[string]any{"v": abeV2, "curve": "bls12-381",
		"a": []any{b64s(scalarBE(sk.a[0])), b64s(scalarBE(sk.a[1]))},
		"b": []any{b64s(scalarBE(sk.b[0])), b64s(scalarBE(sk.b[1]))},
		"g": tri1JSON(sk.g)}
}

func abeSeedKey(spec map[string]any) map[string]any {
	label, _ := spec["msk"].(string)
	id, _ := spec["id"].(string)
	_, msk := abeSeedMskRaw(label)
	seen := map[string]bool{}
	var names []string
	for _, a := range anyStrs(spec["attrs"]) {
		if !seen[a] {
			seen[a] = true
			if !isEmptyOrIllFormed(a) {
				names = append(names, a)
			}
		}
	}
	sigmas := make([]*big.Int, len(names))
	for i := range sigmas {
		sigmas[i] = abeSc(id + "/sg" + strconv.Itoa(i))
	}
	key, err := fameKeygen(msk, names, [2]*big.Int{abeSc(id + "/r1"), abeSc(id + "/r2")}, sigmas, abeSc(id+"/sgp"))
	if err != nil {
		panic(err)
	}
	am := make(map[string]any, len(names))
	for _, n := range names {
		am[n] = map[string]any{"k": tri1JSON(key.attrs[n])}
	}
	return map[string]any{"v": abeV2, "curve": "bls12-381", "k0": tri2JSON(key.k0), "kp": tri1JSON(key.kp), "attrs": am}
}

func abeAt(v any, path []any) any {
	for _, p := range path {
		switch c := v.(type) {
		case map[string]any:
			v = c[p.(string)]
		case []any:
			v = c[abeIdx(p)]
		}
	}
	return v
}

func abeIdx(p any) int { f, _ := jsFloat(p); return int(f) }

func abeSet(v any, path []any, val any, del bool) any {
	if len(path) == 0 {
		return val
	}
	switch c := v.(type) {
	case map[string]any:
		k := path[0].(string)
		if len(path) == 1 && del {
			delete(c, k)
		} else {
			c[k] = abeSet(c[k], path[1:], val, del)
		}
		return c
	case []any:
		i := abeIdx(path[0])
		if i == len(c) {
			c = append(c, nil)
		}
		c[i] = abeSet(c[i], path[1:], val, del)
		return c
	}
	panic("abeSet: path through a scalar")
}

// abeResolve replaces every key recipe inside v by the derived key.
func abeResolve(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = abeResolve(e)
		}
		return out
	case map[string]any:
		if l, ok := x["$abeMsk"].(string); ok {
			return abeSeedMsk(l)
		}
		if k, ok := x["$abeKey"].(map[string]any); ok {
			return abeSeedKey(k)
		}
		if p, ok := x["$pool"].([]any); ok {
			base := abeResolve(p[0]).(map[string]any)
			attrs := base["attrs"].(map[string]any)
			for _, o := range p[1:] {
				for n, c := range abeResolve(o).(map[string]any)["attrs"].(map[string]any) {
					attrs[n] = c
				}
			}
			return base
		}
		if p, ok := x["$patch"]; ok {
			var base any = abeResolve(p)
			edits := vecList(x["$edits"])
			vals := make([]any, len(edits)) // a $ref reads the base as it was before any edit
			for i, e := range edits {
				val := vecObj(e)["value"]
				if r, ok := vecObj(val)["$ref"].([]any); ok {
					val = abeAt(base, r)
				}
				vals[i] = val
			}
			for i, e := range edits {
				_, del := vecObj(vals[i])["$undefined"]
				base = abeSet(base, vecList(vecObj(e)["path"]), vals[i], del)
			}
			return base
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = abeResolve(e)
		}
		return out
	}
	return v
}
