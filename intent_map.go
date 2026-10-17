package pca

// Rule 19, the committed Intent Map and the Z0 disclosure (packages/pca/src/intent-map-commit.ts; conformance README
// "19. Committed map and Z0 disclosure"). Salted, kind-tagged leaves in an RFC 9162 tree:
//
//	leaf_hash  = SHA-256(TAG_kind || salt || strictCanonical(leaf))
//	node_hash  = SHA-256(TAG_NODE || left || right)
//	map_commit = base64url(SHA-256(TAG_COMMIT || u64be(n) || root))
//
// The `map` check opens the action's verb header, the action's cell and the metrics leaf against intent.map_digest and
// recomputes the cell of the action exactly.

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

const (
	mapTagHeader      = "atlas-pca/intent-map/header/v1\x00"
	mapTagCell        = "atlas-pca/intent-map/cell/v1\x00"
	mapTagMetrics     = "atlas-pca/intent-map/metrics/v1\x00"
	mapTagLearner     = "atlas-pca/intent-map/learner/v1\x00"
	mapTagNode        = "atlas-pca/intent-map/node/v1\x00"
	mapTagCommit      = "atlas-pca/intent-map/commit/v1\x00"
	mapFormCommit     = "commit"
	mapOther          = "⊥"
	maxMapLeaves      = 1 << 24
	maxVerbCells      = 1 << 20
	maxMapDims        = 16
	maxMapCuts        = 256
	maxMapValues      = 256
	maxMapStringBytes = 256
)

var mapMetricFields = []string{"residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm",
	"fidelity_est_ppm", "entropy_mbits", "questions", "conflicts"}

var mapTags = map[string]string{"header": mapTagHeader, "cell": mapTagCell, "metrics": mapTagMetrics, "learner": mapTagLearner}

func mapLeafHash(kind string, salt []byte, leaf any) ([]byte, bool) {
	tag, ok := mapTags[kind]
	if !ok || len(salt) != 32 {
		return nil, false
	}
	b, ok := strictBytes(leaf)
	if !ok {
		return nil, false
	}
	h := sha256.Sum256(append(append([]byte(tag), salt...), b...))
	return h[:], true
}

func mapNodeHash(l, r []byte) []byte {
	b := append([]byte(mapTagNode), l...)
	h := sha256.Sum256(append(b, r...))
	return h[:]
}

func mapCommitOf(size int, root []byte) string {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(size))
	b := append(append([]byte(mapTagCommit), n[:]...), root...)
	h := sha256.Sum256(b)
	return b64.EncodeToString(h[:])
}

func mapTreeRoot(hs [][]byte) []byte {
	if len(hs) == 1 {
		return hs[0]
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	return mapNodeHash(mapTreeRoot(hs[:k]), mapTreeRoot(hs[k:]))
}

// mapRootFromPath is RFC 9162 §2.1.3.2 inclusion verification with the map node hash (nil when the path does not fit).
func mapRootFromPath(index, size int, leaf []byte, path [][]byte) []byte {
	if !(index >= 0 && index < size) {
		return nil
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return nil
		}
		if fn%2 == 1 || fn == sn {
			r = mapNodeHash(p, r)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn /= 2
					sn /= 2
				}
			}
		} else {
			r = mapNodeHash(r, p)
		}
		fn /= 2
		sn /= 2
	}
	if sn != 0 {
		return nil
	}
	return r
}

// ---- leaf shapes (closed and typed) -----------------------------------------------------------------------------

func mapStr(v any, max int) (string, bool) {
	s, ok := v.(string)
	return s, ok && !hasLoneSurrogate(s) && utf8Len(s) <= max
}

func isDimPath(v any) bool {
	s, ok := v.(string)
	return ok && (s == "action.resource" || matchParamPath(s))
}

// mapNumCells: the cells of a numeric dimension as inclusive ranges (empty ranges dropped).
func mapNumCells(d map[string]any) [][2]float64 {
	out := [][2]float64{}
	cur := jsF(d["lo"])
	for _, cv := range d["cuts"].([]any) {
		c := jsF(cv)
		if cur <= c-1 {
			out = append(out, [2]float64{cur, c - 1})
		}
		out = append(out, [2]float64{c, c})
		cur = c + 1
	}
	if hi := jsF(d["hi"]); cur <= hi {
		out = append(out, [2]float64{cur, hi})
	}
	return out
}

func mapDimCells(d map[string]any) int {
	if d["kind"] == "num" {
		return len(mapNumCells(d))
	}
	return len(d["values"].([]any))
}

func mapDimOK(dv any) bool {
	d, ok := dv.(map[string]any)
	if !ok {
		return false
	}
	switch d["kind"] {
	case "num":
		if !closedMembers(d, []string{"kind", "path", "lo", "hi", "cuts"}) || !isDimPath(d["path"]) || d["path"] == "action.resource" {
			return false
		}
		if !jsIsInt(d["lo"]) || !jsIsInt(d["hi"]) || jsF(d["lo"]) > jsF(d["hi"]) {
			return false
		}
		cuts, ok := d["cuts"].([]any)
		if !ok || len(cuts) > maxMapCuts {
			return false
		}
		first := true
		prev := 0.0
		for _, c := range cuts {
			if !jsIsInt(c) || (!first && jsF(c) <= prev) || jsF(c) < jsF(d["lo"]) || jsF(c) > jsF(d["hi"]) {
				return false
			}
			prev, first = jsF(c), false
		}
		return true
	case "cat":
		if !closedMembers(d, []string{"kind", "path", "values"}) || !isDimPath(d["path"]) {
			return false
		}
		vals, ok := d["values"].([]any)
		if !ok || len(vals) == 0 || len(vals) > maxMapValues {
			return false
		}
		seen := map[string]bool{}
		for i, vv := range vals {
			v, ok := vv.(map[string]any)
			if !ok || !closedMembers(v, []string{"kind", "value"}) {
				return false
			}
			k, _ := v["kind"].(string)
			if k != "exact" && k != "prefix" && k != "other" {
				return false
			}
			s, ok := mapStr(v["value"], maxMapStringBytes)
			if !ok {
				return false
			}
			if k == "other" && (i != len(vals)-1 || s != mapOther) || k == "prefix" && s == "" {
				return false
			}
			key := k + ":" + s
			if seen[key] {
				return false
			}
			seen[key] = true
		}
		last, _ := vals[len(vals)-1].(map[string]any)
		return last["kind"] == "other"
	}
	return false
}

func mapHeaderOK(hv any) bool {
	h, ok := hv.(map[string]any)
	if !ok || !closedMembers(h, []string{"verb", "first", "cells", "dims"}) {
		return false
	}
	if v, ok := mapStr(h["verb"], 128); !ok || v == "" {
		return false
	}
	if !jsIsNonNeg(h["first"]) || jsF(h["first"]) >= maxMapLeaves {
		return false
	}
	if !jsIsInt(h["cells"]) || jsF(h["cells"]) < 1 || jsF(h["cells"]) > maxVerbCells {
		return false
	}
	dims, ok := h["dims"].([]any)
	if !ok || len(dims) > maxMapDims {
		return false
	}
	paths := map[string]bool{}
	n := 1
	for _, d := range dims {
		if !mapDimOK(d) {
			return false
		}
		dm := d.(map[string]any)
		p := dm["path"].(string)
		if paths[p] {
			return false
		}
		paths[p] = true
		n *= mapDimCells(dm)
		if n > maxVerbCells {
			return false
		}
	}
	return float64(n) == jsF(h["cells"])
}

func mapCellOK(cv any) bool {
	c, ok := cv.(map[string]any)
	if !ok || !closedMembers(c, []string{"verb", "cell", "p_ppm", "in_grant"}) {
		return false
	}
	if v, ok := mapStr(c["verb"], 128); !ok || v == "" {
		return false
	}
	cell, ok := c["cell"].([]any)
	if !ok || len(cell) > maxMapDims {
		return false
	}
	for _, x := range cell {
		if !jsIsNonNeg(x) {
			return false
		}
	}
	if !jsIsNonNeg(c["p_ppm"]) || jsF(c["p_ppm"]) > ppmOne {
		return false
	}
	_, ok = c["in_grant"].(bool)
	return ok
}

func mapMetricsOK(mv any) bool {
	m, ok := mv.(map[string]any)
	if !ok || !closedMembers(m, mapMetricFields, "log2_vs_mbits") {
		return false
	}
	for k, v := range m {
		_ = k
		if !jsIsNonNeg(v) {
			return false
		}
	}
	return true
}

func mapLearnerOK(lv any) bool {
	l, ok := lv.(map[string]any)
	return ok && closedMembers(l, []string{"learner_digest"}) && isDigestV(l["learner_digest"])
}

// mapCellOf: the per-dimension cell indices of the action under the header and its flat index (ok false: outside).
func mapCellOf(h map[string]any, resource any, params any) ([]int, int, bool) {
	cell := []int{}
	flat := 0
	pm, _ := params.(map[string]any)
	for _, dv := range h["dims"].([]any) {
		d := dv.(map[string]any)
		path := d["path"].(string)
		var x any
		if path == "action.resource" {
			x = resource
		} else {
			x = pm[strings.TrimPrefix(path, "action.params.")] // own member (absent: nil, refused below)
		}
		i := -1
		if d["kind"] == "num" {
			if jsIsInt(x) {
				f := jsF(x)
				for k, r := range mapNumCells(d) {
					if f >= r[0] && f <= r[1] {
						i = k
						break
					}
				}
			}
		} else if s, ok := x.(string); ok && !hasLoneSurrogate(s) {
			vals := d["values"].([]any)
			best, bestLen, exact := -1, -1, false
			for k, vv := range vals {
				v := vv.(map[string]any)
				val := v["value"].(string)
				if v["kind"] == "exact" && val == s {
					best, exact = k, true
					break
				}
				if v["kind"] == "prefix" && jsStartsWith(s, val) && jsLen(val) > bestLen {
					best, bestLen = k, jsLen(val)
				}
			}
			_ = exact
			if best >= 0 {
				i = best
			} else {
				i = len(vals) - 1
			}
		}
		if i < 0 {
			return nil, 0, false
		}
		cell = append(cell, i)
		flat = flat*mapDimCells(d) + i
	}
	return cell, flat, true
}

func mapEntryOK(ev any) bool {
	e, ok := ev.(map[string]any)
	if !ok || !closedMembers(e, []string{"index", "salt", "leaf", "path"}) {
		return false
	}
	if !jsIsNonNeg(e["index"]) || !isDigestV(e["salt"]) {
		return false
	}
	path, ok := e["path"].([]any)
	if !ok || len(path) > 64 {
		return false
	}
	for _, h := range path {
		if !isDigestV(h) {
			return false
		}
	}
	return true
}

// mapDisclosureOK is mapDisclosureError == null.
func mapDisclosureOK(dv any) bool {
	d, ok := dv.(map[string]any)
	if !ok || !closedMembers(d, []string{"size", "header", "cell", "metrics"}) {
		return false
	}
	if !jsIsInt(d["size"]) || jsF(d["size"]) < 4 || jsF(d["size"]) > maxMapLeaves {
		return false
	}
	for _, k := range []string{"header", "cell", "metrics"} {
		if !mapEntryOK(d[k]) {
			return false
		}
	}
	return mapHeaderOK(d["header"].(map[string]any)["leaf"]) && mapCellOK(d["cell"].(map[string]any)["leaf"]) &&
		mapMetricsOK(d["metrics"].(map[string]any)["leaf"])
}

// mapOpens: the entry of kind `kind` opens the commitment in a tree of `size` leaves.
func mapOpens(kind string, e map[string]any, size int, commit string) bool {
	salt, _ := DecodeB64uStrict(e["salt"].(string), 32)
	h, ok := mapLeafHash(kind, salt, e["leaf"])
	if !ok {
		return false
	}
	var path [][]byte
	for _, x := range e["path"].([]any) {
		b, _ := DecodeB64uStrict(x.(string), 32)
		path = append(path, b)
	}
	root := mapRootFromPath(int(jsF(e["index"])), size, h, path)
	return root != nil && mapCommitOf(size, root) == commit
}

type mapDecision struct {
	ok     bool
	cell   []int
	pPpm   float64
	reason string
}

// decideMapDisclosure is the Z0 `map` decision (rule 19 steps 1-8). eps < 0: no ε bound. Never panics.
func decideMapDisclosure(mapCommit any, action map[string]any, params any, paramsP bool, disclosure any, eps float64, epsSet bool) (d mapDecision) {
	defer func() {
		if recover() != nil {
			d = mapDecision{reason: "map error (fail closed)"}
		}
	}()
	bad := func(r string) mapDecision { return mapDecision{reason: r} }
	if !mapDisclosureOK(disclosure) {
		return bad("map disclosure malformed")
	}
	commit, ok := mapCommit.(string)
	if !ok || !isDigestV(commit) {
		return bad("the PCActn carries no map commitment")
	}
	if !paramsP {
		params = map[string]any{}
	}
	pm, ok := params.(map[string]any)
	if !ok {
		return bad("params must be an object")
	}
	if pd, ok := hashCanonicalV(pm); !ok || pd != action["params_digest"] {
		return bad("the params do not hash to action.params_digest")
	}
	dm := disclosure.(map[string]any)
	size := int(jsF(dm["size"]))
	he, ce, me := dm["header"].(map[string]any), dm["cell"].(map[string]any), dm["metrics"].(map[string]any)
	h := he["leaf"].(map[string]any)
	if h["verb"] != action["verb"] {
		return bad("the disclosed header is not the action's verb")
	}
	first, cells := jsF(h["first"]), jsF(h["cells"])
	if !(jsF(he["index"]) < first) || !(first+cells <= float64(size-2)) {
		return bad("the disclosed header does not fit the committed layout")
	}
	if !mapOpens("header", he, size, commit) || !mapOpens("cell", ce, size, commit) || !mapOpens("metrics", me, size, commit) {
		return bad("a disclosed leaf does not open the map commitment")
	}
	cell, flat, ok := mapCellOf(h, action["resource"], pm)
	if !ok {
		return bad("the action lies outside the committed map's dimension")
	}
	c := ce["leaf"].(map[string]any)
	cc := c["cell"].([]any)
	if jsF(ce["index"]) != first+float64(flat) || c["verb"] != h["verb"] || len(cc) != len(cell) {
		return bad("the disclosed cell is not the action's cell")
	}
	for i, x := range cc {
		if jsF(x) != float64(cell[i]) {
			return bad("the disclosed cell is not the action's cell")
		}
	}
	if c["in_grant"] != true {
		return bad("the action's cell is outside the committed grant")
	}
	if jsF(me["index"]) != float64(size-2) {
		return bad("the disclosed metrics leaf is not at its committed position")
	}
	if epsSet && !(jsF(me["leaf"].(map[string]any)["residual_risk_ppm"]) <= eps) {
		return bad("the committed residual risk exceeds ε")
	}
	return mapDecision{ok: true, cell: cell, pPpm: jsF(c["p_ppm"])}
}

// IntentMapCommitPrimitive runs primitives.intent_map_commit on {leaves: [{kind, salt, leaf}]}: {map_commit} of the
// full leaf list (nil result when a leaf has no hash: an unknown kind, a bad salt or a non-canonical leaf).
func IntentMapCommitPrimitive(input any) map[string]any {
	in, _ := normalizeJSON(input).(map[string]any)
	leaves, ok := in["leaves"].([]any)
	if !ok || len(leaves) == 0 || len(leaves) > maxMapLeaves {
		return map[string]any{}
	}
	hs := make([][]byte, 0, len(leaves))
	for _, lv := range leaves {
		l, ok := lv.(map[string]any)
		if !ok {
			return map[string]any{}
		}
		kind, _ := l["kind"].(string)
		saltS, _ := l["salt"].(string)
		salt, ok := DecodeB64uStrict(saltS, 32)
		if !ok {
			return map[string]any{}
		}
		h, ok := mapLeafHash(kind, salt, l["leaf"])
		if !ok {
			return map[string]any{}
		}
		hs = append(hs, h)
	}
	return map[string]any{"map_commit": mapCommitOf(len(hs), mapTreeRoot(hs))}
}

// IntentMapPrimitive runs primitives.intent_map on {map_commit, action: {verb, resource, params_digest}, params?,
// disclosure, max_residual_risk_ppm?}: {ok} and, when ok, {cell, p_ppm}. The second result is the refusal reason.
func IntentMapPrimitive(input any) (map[string]any, string) {
	in, _ := normalizeJSON(input).(map[string]any)
	action, ok := in["action"].(map[string]any)
	if !ok {
		return map[string]any{"ok": false}, "action must be an object"
	}
	params, paramsP := in["params"]
	eps, epsSet := in["max_residual_risk_ppm"]
	d := decideMapDisclosure(in["map_commit"], action, params, paramsP, in["disclosure"], jsF(eps), epsSet)
	if !d.ok {
		return map[string]any{"ok": false}, d.reason
	}
	cell := make([]any, len(d.cell))
	for i, c := range d.cell {
		cell[i] = jsNumber(float64(c))
	}
	return map[string]any{"ok": true, "cell": cell, "p_ppm": jsNumber(d.pPpm)}, ""
}
