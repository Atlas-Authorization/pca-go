package pca

// Measure the suggestion rules against a labeled corpus. Every corpus entry is turned into a source document of its own kind, run
// through the real importer and the real suggestion engine, and the traits the system flags are compared with the labels: precision
// and recall per trait, with an exact Clopper-Pearson bound on each. These are heuristic numbers on a reviewed corpus, published as
// what they are, never as a safety guarantee. Corpus entries and reports are JSON values (map[string]any / []any).

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var aevLabelShort = map[string]string{
	"money": "money_moving", "destr": "destructive", "comm": "external_communication", "priv": "privilege_change", "exp": "data_export", "exec": "code_execution",
	"cred": "credential_access", "bulk": "bulk", "pii": "pii_access", "pub": "public_exposure", "pers": "persistence", "infra": "infra_mutation", "cost": "cost_incurring",
	"legal": "legal_binding", "imp": "impersonation", "egress": "network_egress", "fin": "financial_data_read", "reg": "regulated_data", "sched": "scheduled", "spawn": "agent_spawning",
}

var (
	reAevSpec      = regexp.MustCompile(`^[^:]+:([a-z]+)(?::([^\n\r\x{2028}\x{2029}]+))?$`)
	reAevType      = regexp.MustCompile(`^[^:]+:([a-z]+)`)
	reAevFirstWord = regexp.MustCompile(`^[A-Za-z][a-z0-9]*`)
	reAevPlural    = regexp.MustCompile(`^[a-z]+s?$`)
	reAevPathParam = regexp.MustCompile(`\{([^}]+)\}`)
)

// ActionEvalParseHandTSV parses the hand-labeled corpus (tab separated: kind, name, "METHOD /path" or "-", params, labels, description).
func ActionEvalParseHandTSV(text string) ([]any, error) {
	out := []any{}
	n := 0
	short := map[string]bool{}
	for _, v := range aevLabelShort {
		short[v] = true
	}
	for _, line := range strings.Split(text, "\n") {
		if jsTrim(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) < 6 {
			return nil, fmt.Errorf("hand corpus line needs 6 columns: %s", aisU16Prefix(line, 80))
		}
		kind, name, loc, params, labels, description := c[0], c[1], c[2], c[3], c[4], c[5]
		n++
		e := map[string]any{"id": fmt.Sprintf("hand-%04d", n), "src": "hand", "kind": kind, "name": name, "params": []any{}, "labels": []any{}, "description": description}
		if params != "-" {
			e["params"] = anyStrs(strings.Split(params, ","))
		}
		ls := []string{}
		if labels != "-" {
			for _, l := range strings.Split(labels, ",") {
				if s, ok := aevLabelShort[l]; ok {
					l = s
				}
				ls = append(ls, l)
			}
		}
		e["labels"] = anyStrs(ls)
		if kind == "openapi" {
			parts := strings.Split(loc, " ")
			e["method"] = parts[0]
			e["path"] = strings.Join(parts[1:], " ")
		}
		for _, l := range ls {
			if !short[l] {
				return nil, fmt.Errorf("unknown label '%s' in %s", l, name)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// ActionEvalParseCorpusJSONL parses a JSON Lines corpus.
func ActionEvalParseCorpusJSONL(text string) ([]any, error) {
	out := []any{}
	for _, l := range strings.Split(text, "\n") {
		if jsTrim(l) == "" {
			continue
		}
		v, err := ParseJSONLenient([]byte(l))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ---- entries -> source documents -----------------------------------------------------------------------------------------------

func aevSchemaOf(spec string) map[string]any {
	m := reAevSpec.FindStringSubmatch(spec)
	typ, hasTyp, format := "", false, ""
	if m != nil {
		typ, hasTyp, format = m[1], true, m[2]
	}
	if typ == "array" {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	}
	t := "string"
	if hasTyp {
		t = typ
	}
	out := map[string]any{"type": t}
	if format != "" {
		out["format"] = format
	}
	return out
}

// aevPname is spec.slice(0, spec.indexOf(':')) (no colon: the last character is dropped).
func aevPname(spec string) string {
	if i := strings.Index(spec, ":"); i >= 0 {
		return spec[:i]
	}
	return aisU16Prefix(spec, jsLen(spec)-1)
}

var aevReadFirst = setOf("get", "list", "find", "search", "count", "describe", "show", "lookup", "check", "validate", "preview", "calculate", "estimate", "convert", "format",
	"compare", "summarize", "sort", "filter", "read", "fetch", "query", "view", "browse", "open")

func aevFirstWord(n string) string {
	if w := reAevFirstWord.FindString(n); w != "" {
		return strings.ToLower(w)
	}
	return strings.ToLower(n)
}

func aevParams(e map[string]any) []string { return aisStrList(e["params"]) }

func aevProps(e map[string]any) map[string]any {
	props := map[string]any{}
	for _, p := range aevParams(e) {
		props[aevPname(p)] = aevSchemaOf(p)
	}
	return props
}

func aevOpenAPIDoc(es []map[string]any) map[string]any {
	paths := map[string]any{}
	for _, e := range es {
		method := "get"
		if e["method"] != nil {
			method = strings.ToLower(aisStr(e, "method"))
		}
		body := method == "post" || method == "put" || method == "patch"
		params := aevParams(e)
		path := ""
		if e["path"] != nil {
			path = aisStr(e, "path")
		}
		pathParams := []any{}
		names := map[string]bool{}
		for _, m := range reAevPathParam.FindAllStringSubmatch(path, -1) {
			names[m[1]] = true
			pathParams = append(pathParams, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		op := map[string]any{}
		if aimTruthy(e["name"]) {
			op["operationId"] = e["name"]
		}
		if aimTruthy(e["description"]) {
			op["summary"] = e["description"]
		}
		plist := append([]any{}, pathParams...)
		if !body {
			for _, p := range params {
				if !names[aevPname(p)] {
					plist = append(plist, map[string]any{"name": aevPname(p), "in": "query", "schema": aevSchemaOf(p)})
				}
			}
		}
		op["parameters"] = plist
		if body && len(params) > 0 {
			op["requestBody"] = map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": aevProps(e), "required": []any{}}}}}
		}
		key := "undefined"
		if e["path"] != nil {
			key = aisStr(e, "path")
		}
		pm, _ := paths[key].(map[string]any)
		if pm == nil {
			pm = map[string]any{}
			paths[key] = pm
		}
		pm[method] = op
	}
	return map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": "corpus", "version": "1"}, "paths": paths}
}

func aevTypeWord(spec string) string {
	if m := reAevType.FindStringSubmatch(spec); m != nil {
		return m[1]
	}
	return "string"
}

func aevMapped(tbl map[string]string, spec, dflt string) string {
	if v, ok := tbl[aevTypeWord(spec)]; ok {
		return v
	}
	return dflt
}

func aevGraphQLSDL(es []map[string]any) string {
	gql := map[string]string{"string": "String", "integer": "Int", "boolean": "Boolean", "array": "[String]"}
	var q, m []string
	for _, e := range es {
		args := ""
		if ps := aevParams(e); len(ps) > 0 {
			parts := make([]string, len(ps))
			for i, p := range ps {
				parts[i] = aevPname(p) + ": " + aevMapped(gql, p, "String")
			}
			args = "(" + strings.Join(parts, ", ") + ")"
		}
		name := aisStr(e, "name")
		entry := "  \"" + strings.ReplaceAll(aisStr(e, "description"), `"`, "'") + "\"\n  " + name + args + ": String"
		if aevReadFirst[aevFirstWord(name)] || reAevPlural.MatchString(name) {
			q = append(q, entry)
		} else {
			m = append(m, entry)
		}
	}
	out := ""
	if len(q) > 0 {
		out += "type Query {\n" + strings.Join(q, "\n") + "\n}\n"
	}
	if len(m) > 0 {
		out += "type Mutation {\n" + strings.Join(m, "\n") + "\n}\n"
	}
	return out
}

func aevProtoText(es []map[string]any) string {
	proto := map[string]string{"string": "string", "integer": "int64", "boolean": "bool", "array": "repeated string"}
	var order []string
	svcs := map[string][]map[string]any{}
	for _, e := range es {
		s := strings.Split(aisStr(e, "name"), "/")[0]
		if _, ok := svcs[s]; !ok {
			order = append(order, s)
		}
		svcs[s] = append(svcs[s], e)
	}
	msgs := []string{"message Empty {}"}
	out := []string{}
	for _, s := range order {
		rpcs := []string{}
		for _, e := range svcs[s] {
			parts := strings.Split(aisStr(e, "name"), "/")
			m := "undefined"
			if len(parts) > 1 {
				m = parts[1]
			}
			fields := []string{}
			for i, p := range aevParams(e) {
				fields = append(fields, "  "+aevMapped(proto, p, "string")+" "+aevPname(p)+" = "+strconv.Itoa(i+1)+";")
			}
			msgs = append(msgs, "message "+m+"Request {\n"+strings.Join(fields, "\n")+"\n}")
			rpcs = append(rpcs, "  rpc "+m+"("+m+"Request) returns (Empty);")
		}
		out = append(out, "service "+s+" {\n"+strings.Join(rpcs, "\n")+"\n}")
	}
	return "syntax = \"proto3\";\npackage corpus;\n" + strings.Join(msgs, "\n") + "\n" + strings.Join(out, "\n") + "\n"
}

func aevAsyncDoc(es []map[string]any) map[string]any {
	channels := map[string]any{}
	for _, e := range es {
		channels[aisStr(e, "name")] = map[string]any{"publish": map[string]any{"summary": e["description"], "message": map[string]any{"payload": map[string]any{"type": "object", "properties": aevProps(e)}}}}
	}
	return map[string]any{"asyncapi": "2.6.0", "info": map[string]any{"title": "corpus", "version": "1"}, "channels": channels}
}

func aevMCPDoc(es []map[string]any) []any {
	out := make([]any, len(es))
	for i, e := range es {
		out[i] = map[string]any{"name": e["name"], "description": e["description"], "inputSchema": map[string]any{"type": "object", "properties": aevProps(e)}}
	}
	return out
}

func aevKeyOf(e map[string]any) string {
	if e["kind"] == "openapi" {
		m := "GET"
		if e["method"] != nil {
			m = aisUpper(aisStr(e, "method"))
		}
		return m + " " + aisStr(e, "path")
	}
	return aisStr(e, "name")
}

func aevDefKey(d map[string]any) string {
	b := aisMap(d["bindings"])
	oa, mc, gq, gr, aa := aisMap(b["openapi"]), aisMap(b["mcp"]), aisMap(b["graphql"]), aisMap(b["grpc"]), aisMap(b["asyncapi"])
	if aimTruthy(oa["path"]) {
		return aisStr(oa, "method") + " " + aisStr(oa, "path")
	}
	if v, ok := oa["operationId"]; ok && v != nil {
		return jsValueString(v)
	}
	if v, ok := mc["tool"]; ok && v != nil {
		return jsValueString(v)
	}
	if v, ok := gq["field"]; ok && v != nil {
		return jsValueString(v)
	}
	if b["grpc"] != nil {
		parts := strings.Split(aisStr(gr, "service"), ".")
		return parts[len(parts)-1] + "/" + aisStr(gr, "method")
	}
	if v, ok := aa["channel"]; ok && v != nil {
		return jsValueString(v)
	}
	return ""
}

func aevEntries(v []any) []map[string]any {
	out := make([]map[string]any, len(v))
	for i, x := range v {
		out[i] = aisMap(x)
	}
	return out
}

// ActionEvalImportCorpus imports every entry with the real importer of its kind: {defs: {entry id: def}, todo} (an entry whose def
// was not emitted is absent).
func ActionEvalImportCorpus(entriesV []any) (map[string]any, error) {
	defs, todo, err := aevImportCorpus(aevEntries(entriesV))
	if err != nil {
		return nil, err
	}
	dm := map[string]any{}
	for k, v := range defs {
		dm[k] = v
	}
	return map[string]any{"defs": dm, "todo": jsNumber(float64(todo))}, nil
}

func aevImportCorpus(entries []map[string]any) (map[string]map[string]any, int, error) {
	defs := map[string]map[string]any{}
	todo := 0
	var order []string
	groups := map[string][]map[string]any{}
	for _, e := range entries {
		g := aisStr(e, "kind") + "|"
		if e["spec"] != nil {
			g += aisStr(e, "spec")
		}
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], e)
	}
	for _, g := range order {
		es := groups[g]
		kind := strings.SplitN(g, "|", 2)[0]
		var src any
		switch kind {
		case "openapi":
			src = aevOpenAPIDoc(es)
		case "mcp":
			src = aevMCPDoc(es)
		case "graphql":
			src = aevGraphQLSDL(es)
		case "grpc":
			src = aevProtoText(es)
		default:
			src = aevAsyncDoc(es)
		}
		r, err := ActionImport(kind, src, map[string]any{"ns": "corpus", "limits": map[string]any{"max_ops": jsNumber(50_000), "max_nodes": jsNumber(20_000_000), "max_bytes": jsNumber(200_000_000)}})
		if err != nil {
			return nil, 0, err
		}
		todo += len(r.Todo)
		byKey := map[string]map[string]any{}
		for _, d := range r.Defs {
			byKey[aevDefKey(d)] = d
		}
		for _, e := range es {
			if d, ok := byKey[aevKeyOf(e)]; ok {
				defs[aisStr(e, "id")] = d
			}
		}
	}
	return defs, todo, nil
}

// ---- scoring -----------------------------------------------------------------------------------------------------------------

// ActionEvalRealSplit is the deterministic split of the real corpus by specification: rules are tuned on `tune` specs only;
// `holdout` specs are never looked at when editing rules.
func ActionEvalRealSplit(spec any) string {
	s, _ := spec.(string)
	h := uint32(2166136261)
	u := utf16Units(s)
	for i := 0; i < len(u); i++ {
		c := uint32(u[i]) // charCodeAt(0) of a code point: its first UTF-16 unit
		if c >= 0xD800 && c <= 0xDBFF && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF {
			i++
		}
		h = (h ^ c) * 16777619
	}
	if (h>>7)%2 == 0 {
		return "tune"
	}
	return "holdout"
}

func aevSourceOf(e map[string]any) string {
	if e["src"] == "real" {
		return "real/" + ActionEvalRealSplit(e["spec"])
	}
	return aisStr(e, "src")
}

type aevRow struct{ actual, predicted bool }

func aevStat(trait string, rows []aevRow, alpha float64) (map[string]any, error) {
	tp, fp, fn := 0, 0, 0
	for _, r := range rows {
		switch {
		case r.actual && r.predicted:
			tp++
		case r.predicted:
			fp++
		case r.actual:
			fn++
		}
	}
	pos, pred := tp+fn, tp+fp
	n := func(i int) any { return jsNumber(float64(i)) }
	ratio := func(a, b int) any {
		if b == 0 {
			return nil
		}
		return jsNumber(float64(a) / float64(b))
	}
	lower := func(k, nn int) (any, error) {
		c, err := IntentClopperPearsonCertified(float64(k), float64(nn), alpha)
		if err != nil {
			return nil, err
		}
		return jsNumber(1 - c.Upper), nil
	}
	var rl, pl any
	var err error
	if pos != 0 {
		if rl, err = lower(fn, pos); err != nil {
			return nil, err
		}
	}
	// the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
	if pred != 0 && pred <= 600 {
		if pl, err = lower(fp, pred); err != nil {
			return nil, err
		}
	}
	return map[string]any{"trait": trait, "positives": n(pos), "predicted": n(pred), "tp": n(tp), "fp": n(fp), "fn": n(fn),
		"precision": ratio(tp, pred), "recall": ratio(tp, pos), "recall_lower": rl, "precision_lower": pl}, nil
}

// ActionEvalSuggest scores the rules on the corpus: per trait precision and recall of what a reviewer is shown (`flagged`) and of what
// the rules added (`suggested`), overall and per source. rules nil = the shipped rules, reg nil = the core registry, alpha 0 = 0.05.
func ActionEvalSuggest(entriesV []any, rulesV any, reg Registry, alpha *float64) (map[string]any, error) {
	if rulesV == nil {
		rulesV = ActionDefaultRules()
	}
	rules := aisMap(rulesV)
	if reg == nil {
		reg = coreRegistry
	}
	a := 0.05
	if alpha != nil {
		a = *alpha
	}
	entries := aevEntries(entriesV)
	defs, _, err := aevImportCorpus(entries)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for t := range reg {
		if t != "pca.unreviewed" && t != "pca.irreversible" {
			names = append(names, strings.TrimPrefix(t, "pca."))
		}
	}
	adSortU16(names)
	flagged := map[string]map[string]bool{}
	added := map[string]map[string]bool{}
	for _, e := range entries {
		id := aisStr(e, "id")
		d, ok := defs[id]
		if !ok {
			continue
		}
		s, err := ActionSuggestWithRules(d, rules, reg)
		if err != nil {
			return nil, err
		}
		sd, err := ActionApplySuggestion(d, s, map[string]any{"rules": map[string]any{"version": rules["version"], "digest": "", "fired": s["fired"]}})
		if err != nil {
			return nil, err
		}
		cl, err := reg.closure(hintTraits(sd))
		if err != nil {
			return nil, err
		}
		fs := map[string]bool{}
		for _, t := range cl {
			if t != "pca.unreviewed" {
				fs[strings.TrimPrefix(t, "pca.")] = true
			}
		}
		flagged[id] = fs
		as := map[string]bool{}
		for _, t := range aisStrList(s["traits"]) {
			as[strings.TrimPrefix(t, "pca.")] = true
		}
		added[id] = as
	}
	score := func(es []map[string]any, pred map[string]map[string]bool) (any, error) {
		out := []any{}
		for _, t := range names {
			rows := make([]aevRow, len(es))
			for i, e := range es {
				rows[i] = aevRow{contains(aisStrList(e["labels"]), t), pred[aisStr(e, "id")][t]}
			}
			st, err := aevStat(t, rows, a)
			if err != nil {
				return nil, err
			}
			if st["positives"] != jsNumber(0) || st["predicted"] != jsNumber(0) {
				out = append(out, st)
			}
		}
		return out, nil
	}
	srcSet := map[string]bool{}
	anyReal := false
	for _, e := range entries {
		srcSet[aevSourceOf(e)] = true
		if e["src"] == "real" {
			anyReal = true
		}
	}
	if anyReal {
		srcSet["real"] = true
	}
	bySource := map[string]any{}
	for _, s := range aisSortedKeys(srcSet) {
		var es []map[string]any
		for _, e := range entries {
			if (s == "real" && e["src"] == "real") || (s != "real" && aevSourceOf(e) == s) {
				es = append(es, e)
			}
		}
		fl, err := score(es, flagged)
		if err != nil {
			return nil, err
		}
		bySource[s] = map[string]any{"entries": jsNumber(float64(len(es))), "flagged": fl}
	}
	fl, err := score(entries, flagged)
	if err != nil {
		return nil, err
	}
	sg, err := score(entries, added)
	if err != nil {
		return nil, err
	}
	return map[string]any{"alpha": jsNumber(a), "entries": jsNumber(float64(len(entries))), "mapped": jsNumber(float64(len(defs))), "rules_version": rules["version"],
		"flagged": fl, "suggested": sg, "by_source": bySource}, nil
}

// aevPct is (x * 100).toFixed(1) + '%' ('-' for null): the exact value, ties to the larger digit.
func aevPct(v any) string {
	if v == nil {
		return "-"
	}
	f, _ := jsNum(v)
	x := f * 100
	r := new(big.Rat).SetFloat64(x)
	if r == nil {
		return jsNumberString(x) + "%"
	}
	sign := ""
	if r.Sign() < 0 {
		sign = "-"
		r.Neg(r)
	}
	r.Mul(r, big.NewRat(10, 1))
	r.Add(r, big.NewRat(1, 2))
	n := new(big.Int).Div(r.Num(), r.Denom()).String()
	for len(n) < 2 {
		n = "0" + n
	}
	return sign + n[:len(n)-1] + "." + n[len(n)-1:] + "%"
}

func aevInt(v any) string { return jsValueString(v) }

// ActionEvalRenderMarkdown renders a report as Markdown.
func ActionEvalRenderMarkdown(r map[string]any) string {
	table := func(v any) string {
		lines := []string{"| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |", "|---|---:|---:|---:|---:|---:|---:|---:|"}
		for _, sv := range aisList(v) {
			s := aisMap(sv)
			lines = append(lines, "| "+aisStr(s, "trait")+" | "+aevInt(s["positives"])+" | "+aevInt(s["predicted"])+" | "+aevPct(s["recall"])+" | "+aevPct(s["recall_lower"])+" | "+aevPct(s["precision"])+" | "+aevInt(s["fn"])+" | "+aevInt(s["fp"])+" |")
		}
		return strings.Join(lines, "\n")
	}
	lines := []string{
		"# Suggestion rules " + aisStr(r, "rules_version") + ": measured on a labeled corpus",
		"",
		aevInt(r["entries"]) + " labeled operations (" + aevInt(r["mapped"]) + " imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = " + aevInt(r["alpha"]) + ".",
		"These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.",
		"",
		"## What a reviewer is shown (importer facts plus suggestions)", "", table(r["flagged"]), "",
		"## What the suggestion rules added", "", table(r["suggested"]), "",
	}
	bs := aisMap(r["by_source"])
	keys := sortedKeysStd(bs)
	adSortU16(keys)
	for _, s := range keys {
		v := aisMap(bs[s])
		lines = append(lines, "## Source: "+s+" ("+aevInt(v["entries"])+" operations)", "", table(v["flagged"]), "")
	}
	return strings.Join(lines, "\n")
}

// ActionEvalFloor is one floored trait; the order of a floor list is the order of the failure lines.
type ActionEvalFloor struct {
	Trait        string
	RecallLower  float64
	MinPositives float64 // real floors only
}

// ActionEvalFloors are the recorded floors: the hold-out of the real corpus and the regression set.
type ActionEvalFloors struct {
	RealMinEntries float64
	Real           []ActionEvalFloor
	Regression     []ActionEvalFloor
}

func aevStatOf(src map[string]any, trait string) map[string]any {
	if src == nil {
		return nil
	}
	for _, s := range aisList(src["flagged"]) {
		if m := aisMap(s); m["trait"] == trait {
			return m
		}
	}
	return nil
}

// ActionEvalFloorFailures is empty when the report meets the floors; else one line per failure.
func ActionEvalFloorFailures(r map[string]any, f ActionEvalFloors) []string {
	out := []string{}
	bs := aisMap(r["by_source"])
	var real map[string]any
	if v, ok := bs["real/holdout"]; ok {
		real = aisMap(v)
	}
	if real == nil || jsF(real["entries"]) < f.RealMinEntries {
		n := "0"
		if real != nil {
			n = aevInt(real["entries"])
		}
		out = append(out, "the real-spec hold-out has "+n+" operations, fewer than the required "+jsNumberString(f.RealMinEntries))
	}
	if jsF(r["mapped"]) < jsF(r["entries"]) {
		out = append(out, jsNumberString(jsF(r["entries"])-jsF(r["mapped"]))+" corpus operations were not imported")
	}
	for _, fl := range f.Real {
		s := aevStatOf(real, fl.Trait)
		if s == nil || jsF(s["positives"]) < fl.MinPositives {
			p := "0"
			if s != nil {
				p = aevInt(s["positives"])
			}
			out = append(out, fl.Trait+": "+p+" real labeled positives, fewer than the "+jsNumberString(fl.MinPositives)+" the floor needs")
		} else if s["recall_lower"] == nil || jsF(s["recall_lower"]) < fl.RecallLower {
			out = append(out, fl.Trait+": hold-out recall lower bound "+aevPct(s["recall_lower"])+" is below the recorded floor "+aevPct(jsNumber(fl.RecallLower)))
		}
	}
	var syn map[string]any
	if v, ok := bs["syn"]; ok {
		syn = aisMap(v)
	}
	for _, fl := range f.Regression {
		s := aevStatOf(syn, fl.Trait)
		if s == nil || s["recall_lower"] == nil || jsF(s["recall_lower"]) < fl.RecallLower {
			var rl any
			if s != nil {
				rl = s["recall_lower"]
			}
			out = append(out, fl.Trait+": regression-set recall lower bound "+aevPct(rl)+" is below "+aevPct(jsNumber(fl.RecallLower)))
		}
	}
	return out
}
