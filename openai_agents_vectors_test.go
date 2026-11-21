package pca

// Replays the OpenAI Agents adapter corpus: proof sources, the guard pipeline, per-tool option merging, guardrails and the step-up
// logic. Tools, verifiers, hooks and recorders are rebuilt from the same declarative descriptors the reference used.
//
// Skips: none.

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

var (
	oaTailDecode  = regexp.MustCompile(`(?s)proof could not be decoded: .*$`)
	oaTailMissing = regexp.MustCompile(`(?s)(full policy mode is missing).*$`)
)

// oaNorm cuts the language-specific tails of a message and uses the reference's snake_case name for the guard.
func oaNorm(m string) string {
	m = oaTailDecode.ReplaceAllString(m, "proof could not be decoded: ")
	m = oaTailMissing.ReplaceAllString(m, "$1")
	return strings.ReplaceAll(m, "withPcaTool", "with_pca_tool")
}

func oaClean(v any) any {
	switch t := v.(type) {
	case string:
		return oaNorm(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = oaClean(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = oaClean(x)
		}
		return l
	}
	return v
}

type oaCalls struct{ l []any }

func (c *oaCalls) add(x ...any) { c.l = append(c.l, x) }

type oaRec struct{ c *oaCalls }

func (r oaRec) Tool(name string, output any) (map[string]any, error) {
	r.c.add("recorded", name, output)
	return nil, nil
}

func oaStub(d map[string]any, c *oaCalls) func(map[string]any) (OAVerdict, error) {
	return func(p map[string]any) (OAVerdict, error) {
		c.add("verify", d["stub"], adapterGet(adapterGet(p, "action"), "verb"))
		if th, _ := d["throws"].(string); th != "" {
			return OAVerdict{}, errors.New(th)
		}
		allow, _ := d["allow"].(bool)
		v := OAVerdict{Allow: allow, Checks: map[string]any{"sig": "fail"}}
		if allow {
			v.Checks["sig"] = "pass"
		}
		if r, ok := d["reason"].(string); ok {
			v.Reason = &r
		}
		return v, nil
	}
}

func oaRequire(r map[string]any) func(input, rc any) any {
	if h, ok := r["headers"].([]any); ok {
		var field, header string
		if len(h) > 0 {
			field, _ = h[0].(string)
		}
		if len(h) > 1 {
			header, _ = h[1].(string)
		}
		return OAProofFromInputHeaders(field, header)
	}
	return func(_, _ any) any { return r["const"] }
}

func oaOpts(d map[string]any, c *oaCalls) OAToolOptions {
	o := OAToolOptions{Mode: vecStr(d, "mode"), Verb: vecStr(d, "verb")}
	if _, has := d["audience"]; has {
		o.AudienceSet = true
		if s, ok := d["audience"].(string); ok {
			o.Audience = &s
		}
	}
	if v := vecObj(d["verify"]); v != nil {
		o.Verify = oaStub(v, c)
	}
	if d["authorize"] != nil {
		o.Authorize = &AuthorizeInput{}
	}
	if r := vecObj(d["require"]); r != nil {
		o.Require = oaRequire(r)
	}
	if d["onDeny"] != nil {
		o.OnDeny = func(e *OAToolDenied, in any) { c.add("onDeny", e.Kind, in) }
	}
	if d["onVerified"] != nil {
		o.OnVerified = func(r OAVerdict, p map[string]any, in any) {
			c.add("onVerified", r.Allow, adapterGet(adapterGet(p, "action"), "verb"), in)
		}
	}
	if d["recorder"] != nil {
		o.Recorder = oaRec{c}
	}
	return o
}

func oaTool(td map[string]any, c *oaCalls) *OATool {
	name := vecStr(td, "name")
	var nameV any
	if name != "" {
		nameV = name
	}
	t := &OATool{Name: name, Extra: vecObj(td["extra"])}
	if noExec, _ := td["noExecute"].(bool); !noExec {
		t.Execute = func(input, _ any) (any, error) {
			c.add("exec", nameV, input)
			if th := vecStr(td, "throws"); th != "" {
				return nil, errors.New(th)
			}
			return map[string]any{"echo": input, "tool": nameV}, nil
		}
	}
	return t
}

func oaErr(err error) map[string]any {
	var d *OAToolDenied
	if errors.As(err, &d) {
		out := map[string]any{"err": "PcaToolDenied", "message": oaNorm(err.Error()), "kind": d.Kind, "verb": d.Verb}
		if d.Checks != nil {
			out["checks"] = d.Checks
		}
		return out
	}
	return map[string]any{"err": "Error", "message": oaNorm(err.Error())}
}

func oaOutcome(t *OATool, input, rc any, noRc bool) map[string]any {
	if noRc {
		rc = nil
	}
	out, err := t.Execute(input, rc)
	if err != nil {
		return oaErr(err)
	}
	var name any
	if t.Name != "" {
		name = t.Name
	}
	return map[string]any{"ok": true, "out": out, "name": name, "extra": t.Extra["extra"], "hasNeedsApproval": t.NeedsApproval != nil}
}

func oaBuildError(err error, c *oaCalls) map[string]any {
	return map[string]any{"err": "TypeError", "message": oaNorm(err.Error()), "calls": c.l, "build": true}
}

func oaWithTool(a map[string]any) map[string]any {
	c := &oaCalls{l: []any{}}
	t, err := OAWithPcaTool(oaTool(vecObj(a["tool"]), c), oaOpts(vecObj(a["options"]), c))
	if err != nil {
		return oaBuildError(err, c)
	}
	noRc, _ := a["noRunContext"].(bool)
	out := oaOutcome(t, a["input"], a["runContext"], noRc)
	out["calls"] = c.l
	return out
}

func oaTools(a map[string]any) map[string]any {
	c := &oaCalls{l: []any{}}
	td := vecObj(a["tools"])
	var names []string
	var tools []*OATool
	for _, k := range jsKeys(td) {
		names = append(names, k)
		t := oaTool(vecObj(td[k]), c)
		t.Name = k
		tools = append(tools, t)
	}
	o := vecObj(a["options"])
	var per map[string]*OAToolOptions
	if p := vecObj(o["per"]); p != nil {
		per = map[string]*OAToolOptions{}
		for k, v := range p {
			po := oaOpts(vecObj(v), c)
			per[k] = &po
		}
	}
	var only []string
	if l, ok := o["only"].([]any); ok {
		only = []string{}
		for _, x := range l {
			s, _ := x.(string)
			only = append(only, s)
		}
	}
	g, err := OAPcaTools(tools, per, only, oaOpts(o, c))
	if err != nil {
		return oaBuildError(err, c)
	}
	res := map[string]any{}
	for i, t := range g {
		r := oaOutcome(t, a["input"], a["runContext"], false)
		r["same"] = t == tools[i]
		res[names[i]] = r
	}
	for _, r := range res {
		r.(map[string]any)["calls"] = c.l // the calls log is one shared list, complete once every tool has run
	}
	return res
}

func oaGuard(a map[string]any) map[string]any {
	c := &oaCalls{l: []any{}}
	d := vecObj(a["options"])
	o := oaOpts(d, c)
	var require func(any) any
	if r := vecObj(d["require"]); r != nil {
		f := oaRequire(r)
		require = func(args any) any { return f(args, nil) }
	}
	mk := OAInputGuardrail
	if a["kind"] != "input" {
		mk = OAToolGuard
	}
	g := mk(o.Verify, require, o.Verb, vecStr(d, "name"))
	r, err := g.Execute(a["args"])
	if err != nil {
		return map[string]any{"err": "Error", "message": oaNorm(err.Error()), "calls": c.l}
	}
	return map[string]any{"name": g.Name, "result": map[string]any{"tripwireTriggered": r.TripwireTriggered, "outputInfo": r.OutputInfo}, "calls": c.l}
}

func oaIntentNull(c *oaCalls) func(string, any) map[string]any {
	return func(t string, in any) map[string]any {
		c.add("intent", t, in)
		return nil
	}
}

func oaNeeds(a map[string]any) (any, error) {
	c := &oaCalls{l: []any{}}
	o := OANeedsApprovalOptions{OAReviewOptions: OAReviewOptions{Intent: oaIntentNull(c)}, ToolName: vecStr(a, "toolName")}
	if a["via"] == "direct" {
		v, err := OANeedsApproval(nil, o)(map[string]any{}, a["input"])
		return map[string]any{"value": v, "calls": c.l}, err
	}
	td := vecObj(a["tool"])
	t := OAWithApproval(&OATool{Name: vecStr(td, "name"), Execute: func(any, any) (any, error) { return 1, nil }}, nil, o)
	v, err := t.NeedsApproval(map[string]any{}, a["input"])
	var name any
	if t.Name != "" {
		name = t.Name
	}
	return map[string]any{"value": v, "calls": c.l, "name": name, "extra": nil, "hasExecute": t.Execute != nil}, err
}

func TestOpenAIAgentsVectors(t *testing.T) {
	arg := func(a []any) map[string]any { return vecObj(vecArg(a, 0)) }
	same := func(want, got any) bool { return baseCanon(oaClean(want)) == baseCanon(oaClean(got)) }
	replayVectorsCmp(t, "ref-openai-agents.json.gz", map[string]vecFn{
		"proofFromRunContext": func(a []any) (any, error) {
			return OAProofFromRunContext(arg(a)["input"], arg(a)["runContext"]), nil
		},
		"guardrailProofFromContext": func(a []any) (any, error) { return OAGuardrailProofFromContext(arg(a)["args"]), nil },
		"provenanceFromRunContext": func(a []any) (any, error) {
			return OAProvenanceFromRunContext(nil, arg(a)["runContext"]), nil
		},
		"proofFromInputHeaders": func(a []any) (any, error) {
			return OAProofFromInputHeaders(vecStr(arg(a), "field"), vecStr(arg(a), "header"))(arg(a)["input"], nil), nil
		},
		"pendingStepUps": func(a []any) (any, error) {
			l, _ := vecArg(a, 0).([]any)
			return OAPendingStepUps(l), nil
		},
		"withPcaTool": func(a []any) (any, error) { return oaWithTool(arg(a)), nil },
		"pcaTools":    func(a []any) (any, error) { return oaTools(arg(a)), nil },
		"guardrail":   func(a []any) (any, error) { return oaGuard(arg(a)), nil },
		"reviewToolCall": func(a []any) (any, error) {
			c := &oaCalls{l: []any{}}
			r, err := OAReviewToolCall(nil, vecStr(arg(a), "tool"), arg(a)["input"], OAReviewOptions{Intent: oaIntentNull(c)})
			return map[string]any{"r": r, "calls": c.l}, err
		},
		"needsApproval": func(a []any) (any, error) { return oaNeeds(arg(a)) },
	}, map[string]func(want, got any) bool{
		"withPcaTool": same, "pcaTools": same, "guardrail": same,
	})
}
