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
	"fmt"
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

// The *Error validators return the reference's refusal text ("" = well-formed); the *OK forms are their boolean spelling.
func mapDimError(dv any, j int) string {
	d, ok := dv.(map[string]any)
	if !ok {
		return fmt.Sprintf("dims[%d] must be an object", j)
	}
	switch d["kind"] {
	case "num":
		if !closedMembers(d, []string{"kind", "path", "lo", "hi", "cuts"}) {
			return fmt.Sprintf("dims[%d] must be exactly {kind, path, lo, hi, cuts}", j)
		}
		if !isDimPath(d["path"]) || d["path"] == "action.resource" {
			return fmt.Sprintf("dims[%d].path must be action.params.<name>", j)
		}
		if !jsIsInt(d["lo"]) || !jsIsInt(d["hi"]) || jsF(d["lo"]) > jsF(d["hi"]) {
			return fmt.Sprintf("dims[%d] lo / hi must be safe integers with lo <= hi", j)
		}
		cuts, ok := d["cuts"].([]any)
		if !ok || len(cuts) > maxMapCuts {
			return fmt.Sprintf("dims[%d].cuts must be an array of at most %d", j, maxMapCuts)
		}
		first := true
		prev := 0.0
		for _, c := range cuts {
			if !jsIsInt(c) || (!first && jsF(c) <= prev) || jsF(c) < jsF(d["lo"]) || jsF(c) > jsF(d["hi"]) {
				return fmt.Sprintf("dims[%d].cuts must be strictly increasing safe integers in [lo, hi]", j)
			}
			prev, first = jsF(c), false
		}
		return ""
	case "cat":
		if !closedMembers(d, []string{"kind", "path", "values"}) {
			return fmt.Sprintf("dims[%d] must be exactly {kind, path, values}", j)
		}
		if !isDimPath(d["path"]) {
			return fmt.Sprintf("dims[%d].path must be action.resource or action.params.<name>", j)
		}
		vals, ok := d["values"].([]any)
		if !ok || len(vals) == 0 || len(vals) > maxMapValues {
			return fmt.Sprintf("dims[%d].values must be an array of 1..%d", j, maxMapValues)
		}
		seen := map[string]bool{}
		for i, vv := range vals {
			v, ok := vv.(map[string]any)
			if !ok || !closedMembers(v, []string{"kind", "value"}) {
				return fmt.Sprintf("dims[%d].values[%d] must be exactly {kind, value}", j, i)
			}
			k, _ := v["kind"].(string)
			if k != "exact" && k != "prefix" && k != "other" {
				return fmt.Sprintf("dims[%d].values[%d].kind must be exact, prefix or other", j, i)
			}
			s, ok := mapStr(v["value"], maxMapStringBytes)
			if !ok {
				return fmt.Sprintf("dims[%d].values[%d].value must be a string of at most %d UTF-8 bytes", j, i, maxMapStringBytes)
			}
			if k == "other" && (i != len(vals)-1 || s != mapOther) || k == "prefix" && s == "" {
				return fmt.Sprintf("dims[%d].values: exactly one other ('%s'), last; prefixes non-empty", j, mapOther)
			}
			key := k + ":" + s
			if seen[key] {
				return fmt.Sprintf("dims[%d].values must be distinct", j)
			}
			seen[key] = true
		}
		last, _ := vals[len(vals)-1].(map[string]any)
		if last["kind"] != "other" {
			return fmt.Sprintf("dims[%d].values must end with the other value", j)
		}
		return ""
	}
	return fmt.Sprintf("dims[%d].kind must be num or cat", j)
}

func mapDimOK(dv any) bool { return mapDimError(dv, 0) == "" }

// mapHeaderError: shape of a header leaf; "" = well-formed.
func mapHeaderError(hv any) string {
	h, ok := hv.(map[string]any)
	if !ok || !closedMembers(h, []string{"verb", "first", "cells", "dims"}) {
		return "the header leaf must be exactly {verb, first, cells, dims}"
	}
	if v, ok := mapStr(h["verb"], 128); !ok || v == "" {
		return "header.verb must be a non-empty string of at most 128 UTF-8 bytes"
	}
	if !jsIsNonNeg(h["first"]) || jsF(h["first"]) >= maxMapLeaves {
		return "header.first must be a leaf index"
	}
	if !jsIsInt(h["cells"]) || jsF(h["cells"]) < 1 || jsF(h["cells"]) > maxVerbCells {
		return fmt.Sprintf("header.cells must be a safe integer in [1, %d]", maxVerbCells)
	}
	dims, ok := h["dims"].([]any)
	if !ok || len(dims) > maxMapDims {
		return fmt.Sprintf("header.dims must be an array of at most %d", maxMapDims)
	}
	paths := map[string]bool{}
	n := 1
	for j, d := range dims {
		if e := mapDimError(d, j); e != "" {
			return "header." + e
		}
		dm := d.(map[string]any)
		p := dm["path"].(string)
		if paths[p] {
			return "header.dims paths must be distinct"
		}
		paths[p] = true
		n *= mapDimCells(dm)
		if n > maxVerbCells {
			return "header: too many cells"
		}
	}
	if float64(n) != jsF(h["cells"]) {
		return "header.cells is not the product of the dimensions' cell counts"
	}
	return ""
}

func mapHeaderOK(hv any) bool { return mapHeaderError(hv) == "" }

func mapCellError(cv any) string {
	c, ok := cv.(map[string]any)
	if !ok || !closedMembers(c, []string{"verb", "cell", "p_ppm", "in_grant"}) {
		return "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}"
	}
	if v, ok := mapStr(c["verb"], 128); !ok || v == "" {
		return "cell.verb must be a non-empty string of at most 128 UTF-8 bytes"
	}
	cell, ok := c["cell"].([]any)
	bad := !ok || len(cell) > maxMapDims
	for _, x := range cell {
		if !jsIsNonNeg(x) {
			bad = true
		}
	}
	if bad {
		return "cell.cell must be an array of non-negative safe integers"
	}
	if !jsIsNonNeg(c["p_ppm"]) || jsF(c["p_ppm"]) > ppmOne {
		return "cell.p_ppm must be a safe integer in [0, 1000000]"
	}
	if _, ok = c["in_grant"].(bool); !ok {
		return "cell.in_grant must be a boolean"
	}
	return ""
}

func mapCellOK(cv any) bool { return mapCellError(cv) == "" }

func mapMetricsError(mv any) string {
	m, ok := mv.(map[string]any)
	if !ok || !closedMembers(m, mapMetricFields, "log2_vs_mbits") {
		return "the metrics leaf must be exactly {" + strings.Join(mapMetricFields, ", ") + ", log2_vs_mbits?}"
	}
	for _, k := range append(append([]string{}, mapMetricFields...), "log2_vs_mbits") {
		v, has := m[k]
		if !has && k == "log2_vs_mbits" {
			continue
		}
		if !jsIsNonNeg(v) {
			return "metrics." + k + " must be a non-negative safe integer"
		}
	}
	return ""
}

func mapMetricsOK(mv any) bool { return mapMetricsError(mv) == "" }

func mapLearnerError(lv any) string {
	l, ok := lv.(map[string]any)
	if !ok || !closedMembers(l, []string{"learner_digest"}) {
		return "the learner leaf must be exactly {learner_digest}"
	}
	if !isDigestV(l["learner_digest"]) {
		return "learner.learner_digest must be canonical base64url (32 bytes)"
	}
	return ""
}

func mapLearnerOK(lv any) bool { return mapLearnerError(lv) == "" }

// mapCellOf: the per-dimension cell indices of the action under the header and its flat index (ok false: outside).
func mapCellOf(h map[string]any, resource any, params any) ([]int, int, string) {
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
			return nil, 0, "the action's " + path + " lies outside the committed map's dimension"
		}
		cell = append(cell, i)
		flat = flat*mapDimCells(d) + i
	}
	return cell, flat, ""
}

func mapEntryError(ev any, what string) string {
	e, ok := ev.(map[string]any)
	if !ok || !closedMembers(e, []string{"index", "salt", "leaf", "path"}) {
		return "disclosure." + what + " must be exactly {index, salt, leaf, path}"
	}
	if !jsIsNonNeg(e["index"]) {
		return "disclosure." + what + ".index must be a non-negative safe integer"
	}
	if !isDigestV(e["salt"]) {
		return "disclosure." + what + ".salt must be canonical base64url (32 bytes)"
	}
	path, ok := e["path"].([]any)
	bad := !ok || len(path) > 64
	for _, h := range path {
		if !isDigestV(h) {
			bad = true
		}
	}
	if bad {
		return "disclosure." + what + ".path must be an array of 32-byte digests"
	}
	return ""
}

func mapEntryOK(ev any) bool { return mapEntryError(ev, "x") == "" }

// mapDisclosureError: shape of a Z0 disclosure; "" = well-formed.
func mapDisclosureError(dv any) string {
	d, ok := dv.(map[string]any)
	if !ok || !closedMembers(d, []string{"size", "header", "cell", "metrics"}) {
		return "the disclosure must be exactly {size, header, cell, metrics}"
	}
	if !jsIsInt(d["size"]) || jsF(d["size"]) < 4 || jsF(d["size"]) > maxMapLeaves {
		return fmt.Sprintf("disclosure.size must be a safe integer in [4, %d]", maxMapLeaves)
	}
	for _, k := range []string{"header", "cell", "metrics"} {
		if e := mapEntryError(d[k], k); e != "" {
			return e
		}
	}
	if e := mapHeaderError(d["header"].(map[string]any)["leaf"]); e != "" {
		return e
	}
	if e := mapCellError(d["cell"].(map[string]any)["leaf"]); e != "" {
		return e
	}
	return mapMetricsError(d["metrics"].(map[string]any)["leaf"])
}

func mapDisclosureOK(dv any) bool { return mapDisclosureError(dv) == "" }

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
	if e := mapDisclosureError(disclosure); e != "" {
		return bad("map disclosure malformed: " + e)
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
	for _, o := range []struct {
		kind string
		e    map[string]any
	}{{"header", he}, {"cell", ce}, {"metrics", me}} {
		if !mapOpens(o.kind, o.e, size, commit) {
			return bad("the " + o.kind + " leaf does not open the map commitment")
		}
	}
	cell, flat, cerr := mapCellOf(h, action["resource"], pm)
	if cerr != "" {
		return bad(cerr)
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
		return bad("the committed residual risk " + jsLenientNumber(jsF(me["leaf"].(map[string]any)["residual_risk_ppm"])) + " ppm exceeds ε = " + jsLenientNumber(eps))
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
