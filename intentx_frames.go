package pca

// Frame and side-effect constraints: monitored state snapshots, write sets, the frame condition over everything a verb does not
// write and the verb's postconditions (exact numeric deltas, predicate conditions over env.pre / env.post / env.effect).

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const ixFrameStateDomain = "atlas-pca/intent-frame-state/v1"

// ixStateDigest is the digest of a state value (site-local, never cross-language: the lenient canonical form).
func ixStateDigest(value any) string {
	s, ok := canonicalLenient(map[string]any{"d": ixFrameStateDomain, "v": value})
	if !ok {
		ixFail("state value is not canonicalizable")
	}
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func ixSnapshotState(values map[string]any, keepValues bool) map[string]any {
	out := map[string]any{}
	for k, v := range values {
		e := map[string]any{"digest": ixStateDigest(v)}
		if keepValues {
			e["value"] = v
		}
		out[k] = e
	}
	return out
}

func ixGetDotted(root any, path string) (any, bool) { return ixGetPath(root, strings.Split(path, ".")) }

// ixWriteSetOf is W(action): the declared list, or the parameter-selected list (unknown parameter value: default, else empty).
func ixWriteSetOf(spec, action map[string]any) []string {
	writes := ixM(ixReq(spec, "writes"))
	verb := ixS(ixReq(action, "verb"))
	d, ok := writes[verb]
	if !ok || d == nil {
		return []string{}
	}
	if l, ok := d.([]any); ok {
		return ixStrList(l)
	}
	dm := ixM(d)
	p := ixS(ixReq(dm, "param"))
	params, _ := action["params"].(map[string]any)
	v, _ := ixGetDotted(params, strings.TrimPrefix(p, "action.params."))
	var key string
	hasKey := false
	switch v.(type) {
	case string, bool, float64:
		key, hasKey = jsValueString(v), true
	}
	mp := ixM(ixReq(dm, "map"))
	if hasKey {
		if e, ok := mp[key]; ok {
			return ixStrList(e)
		}
	}
	return ixStrList(dm["default"])
}

func ixEnvReads(cv any, out *[]string) {
	c, ok := cv.(map[string]any)
	if !ok {
		return
	}
	if ixIsGroupCond(c) {
		if l, ok := c["all_of"].([]any); ok {
			for _, x := range l {
				ixEnvReads(x, out)
			}
		} else if l, ok := c["any_of"].([]any); ok {
			for _, x := range l {
				ixEnvReads(x, out)
			}
		} else if ixHas(c, "not") {
			ixEnvReads(c["not"], out)
		}
		return
	}
	if f, ok := c["field"].(string); ok {
		if strings.HasPrefix(f, "env.") {
			*out = append(*out, f)
		}
		if r, ok := c["ref"].(string); ok && strings.HasPrefix(r, "env.") {
			*out = append(*out, r)
		}
	}
}

func ixNest(s map[string]any) map[string]any {
	root := map[string]any{}
	for k, vv := range s {
		v := ixM(vv)
		if _, ok := v["value"]; !ok {
			continue
		}
		segs := strings.Split(k, ".")
		cur := root
		for _, seg := range segs[:len(segs)-1] {
			nxt, ok := cur[seg].(map[string]any)
			if !ok {
				nxt = map[string]any{}
				cur[seg] = nxt
			}
			cur = nxt
		}
		cur[segs[len(segs)-1]] = v["value"]
	}
	return root
}

func ixUniqSortedUtf8(ss []string) []any {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return ixToAny(ixSortUtf8(out))
}

// ixCheckFrame checks one executed action: the frame condition over the monitored state outside its write set and the verb's
// postconditions. Total: never fails. attributions = [{var, actor}] excuse a change by an actor other than `self`.
func ixCheckFrame(spec, action, pre, post any, opts map[string]any) map[string]any {
	var outOfFrame, attributed, postViolated, missing []string
	unmonitored := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				missing = append(missing, fmt.Sprintf("error: %v", r))
			}
		}()
		sp, ok1 := spec.(map[string]any)
		ac, ok2 := action.(map[string]any)
		pr, ok3 := pre.(map[string]any)
		po, ok4 := post.(map[string]any)
		state, ok5 := sp["state"].([]any)
		if !ok1 || !ok5 || !ok2 || !ok3 || !ok4 {
			ixFail("spec, action, pre and post must be objects (spec.state an array)")
		}
		unmonitored = len(state) == 0
		W := map[string]bool{}
		for _, w := range ixWriteSetOf(sp, ac) {
			W[w] = true
		}
		vars := make([]string, len(state))
		for i, v := range state {
			s, ok := v.(string)
			if !ok {
				ixFail("state variable is not a string")
			}
			vars[i] = s
		}
		for _, v := range ixSortUtf8(vars) {
			if W[v] {
				continue
			}
			a, b := ixM(pr[v]), ixM(po[v])
			if pr[v] == nil || po[v] == nil {
				missing = append(missing, v)
				continue
			}
			if ixReq(a, "digest") == ixReq(b, "digest") {
				continue
			}
			other := false
			for _, xv := range ixL(opts["attributions"]) {
				x := ixM(xv)
				if x["var"] == v && x["actor"] != opts["self"] {
					other = true
				}
			}
			if other {
				attributed = append(attributed, v)
			} else {
				outOfFrame = append(outOfFrame, v)
			}
		}
		effect := ixM(opts["effect"])
		if effect == nil {
			effect = map[string]any{}
		}
		env := map[string]any{"pre": ixNest(pr), "post": ixNest(po), "effect": effect}
		params, _ := ac["params"].(map[string]any)
		if params == nil {
			params = map[string]any{}
		}
		ctx := map[string]any{"action": map[string]any{"verb": ixReq(ac, "verb"), "resource": ixReq(ac, "resource"), "params": params}, "env": env}
		for _, pv := range ixL(sp["post"]) {
			pc := ixM(pv)
			if ixReq(pc, "verb") != ac["verb"] {
				continue
			}
			id := ixS(pc["id"])
			pending := false
			for _, dv := range ixL(pc["deltas"]) {
				d := ixM(dv)
				path := ixS(ixReq(d, "path"))
				x, _ := ixGetDotted(env["pre"], path)
				y, _ := ixGetDotted(env["post"], path)
				if !ixIsNum(x) || !ixIsNum(y) {
					missing = append(missing, id+":"+path)
					pending = true
				} else if y.(float64) != x.(float64)+ixF(ixReq(d, "by")) {
					postViolated = append(postViolated, id)
					pending = true
					break
				}
			}
			if pending {
				continue
			}
			var reads []string
			for _, c := range ixL(pc["where"]) {
				ixEnvReads(c, &reads)
			}
			var absent []string
			for _, r := range reads {
				if _, ok := ixGetDotted(map[string]any{"env": env}, r); !ok {
					absent = append(absent, r)
				}
			}
			if len(absent) > 0 {
				for _, r := range absent {
					missing = append(missing, id+":"+r)
				}
				continue
			}
			where := ixL(pc["where"])
			if len(where) > 0 && !evaluatePredicates([]any{map[string]any{"verb": ac["verb"], "where": pc["where"]}}, ctx) {
				postViolated = append(postViolated, id)
			}
		}
	}()
	status := "ok"
	if len(outOfFrame) > 0 || len(postViolated) > 0 {
		status = "violated"
	} else if len(missing) > 0 {
		status = "pending"
	}
	strs := func(ss []string) []any {
		if ss == nil {
			return []any{}
		}
		return ixToAny(ss)
	}
	return map[string]any{"status": status, "outOfFrame": strs(outOfFrame), "attributed": strs(attributed), "postViolated": ixUniqSortedUtf8(postViolated),
		"missing": ixUniqSortedUtf8(missing), "unmonitored": unmonitored}
}
