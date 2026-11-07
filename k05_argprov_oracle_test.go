package pca

// k05 differential oracle: provenance by default (arg_provenance.go + the middleware's bundle reader) against the TypeScript
// reference arg-provenance.ts / require-pca.ts defaultProvenanceBundle (testdata/k05-argprov.json.gz,
// tools/pca-audit/k05-oracles/argprov-oracle.mts). Throw messages are TS-named (createProvenanceRecorder, ...): a reference
// throw only requires a Go error; a header the reference refuses is Go's unreadable bundle.

import (
	"net/http/httptest"
	"sort"
	"testing"
)

func k05ProvOp(v any) (Operation, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return Operation{}, false
	}
	verb, ok1 := m["verb"].(string)
	res, ok2 := m["resource"].(string)
	params, ok3 := m["params"].(map[string]any)
	return Operation{Verb: verb, Resource: res, Params: params}, ok1 && ok2 && ok3
}

func k05ProvDecision(d ArgProvenanceDecision) map[string]any {
	labels := map[string]any{}
	for k, v := range d.Labels {
		labels[k] = v
	}
	strs := func(xs []string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	m := map[string]any{"sensitive": d.Sensitive, "verified": d.Verified, "control": d.Control, "labels": labels,
		"tainted": strs(d.Tainted), "path": strs(d.Path), "outcome": d.Outcome}
	if d.Code != "" {
		m["code"] = d.Code
	}
	if d.Reason != "" {
		m["reason"] = d.Reason
	}
	return m
}

// k05ProvRecorder replays a recorder spec {mediator, kid, sk, session, clock, steps}: {pin, outs} or a constructor error.
func k05ProvRecorder(spec map[string]any) (map[string]any, error) {
	key, err := KeyPairFromSeedB64u(spec["sk"].(string))
	if err != nil {
		return nil, err
	}
	clock, _ := spec["clock"].([]any)
	var last int64
	med, _ := spec["mediator"].(string)
	kid, _ := spec["kid"].(string)
	sess, _ := spec["session"].(string)
	rec, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: med, Kid: kid, Key: key, Session: sess, Now: func() int64 {
		if len(clock) > 0 {
			f, _ := jsNum(clock[0])
			clock = clock[1:]
			last = int64(f) // the reference truncates a fractional clock
		}
		return last
	}})
	if err != nil {
		return nil, err
	}
	outs := []any{}
	for _, sv := range spec["steps"].([]any) {
		s := sv.([]any)
		var out map[string]any
		var err error
		str := func(i int) string { x, _ := s[i].(string); return x }
		switch s[0] {
		case "principal":
			out, err = rec.Principal(str(1))
		case "tool":
			out, err = rec.Tool(str(1), s[2])
		case "retrieval":
			out, err = rec.Retrieval(str(1), s[2])
		case "web":
			out, err = rec.Web(str(1), s[2])
		case "action", "direct":
			op, _ := k05ProvOp(s[1])
			if s[0] == "action" {
				out, err = rec.ForAction(op)
			} else {
				out, err = PrincipalDirectProvenance(rec, op)
			}
		}
		if err != nil {
			outs = append(outs, map[string]any{"$throws": err.Error()})
		} else {
			outs = append(outs, out)
		}
	}
	return map[string]any{"pin": rec.Pin.JSON(), "outs": outs}, nil
}

// k05ProvThrowsMask replaces every {$throws: msg} with {$throws: true}: a reference throw only requires a Go error.
func k05ProvThrowsMask(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["$throws"]; ok {
			return map[string]any{"$throws": true}
		}
		m := map[string]any{}
		for k, x := range t {
			m[k] = k05ProvThrowsMask(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = k05ProvThrowsMask(x)
		}
		return a
	}
	return v
}

func TestK05ArgProv(t *testing.T) {
	var k k05Tally
	strOrNull := func(c *k05Case, got string) {
		want, _ := c.Out.(string)
		if got != want {
			k.fail(c, "want %v, got %q", c.Out, got)
		}
	}
	boolean := func(c *k05Case, got bool) {
		if got != c.Out {
			k.fail(c, "want %v, got %v", c.Out, got)
		}
	}
	k05Each(t, "k05-argprov.json.gz", func(c *k05Case) {
		a := c.Args
		k.run(c.Fn)
		switch c.Fn {
		case "provReceiptWireError":
			strOrNull(c, ProvReceiptWireError(a[0]))
		case "isProvMediatorPin":
			boolean(c, isProvMediatorPin(a[0]))
		case "provActionInfoError":
			strOrNull(c, ProvActionInfoError(a[0]))
		case "isReadOnlyAction":
			boolean(c, IsReadOnlyAction(a[0]))
		case "provEnvelopeError":
			strOrNull(c, ProvEnvelopeError(a[0]))
		case "occursAsToken":
			boolean(c, OccursAsToken(a[0].(string), a[1].(string)))
		case "provLeaves":
			leaves, ok := ProvLeaves(a[0])
			// leaves are a multiset (every use joins over them): compared sorted, since a Go map has no insertion order
			var got, want any
			if ok {
				got = k05SortedStrs(leaves)
			}
			if ws, isArr := c.Out.([]any); isArr {
				xs := make([]string, len(ws))
				for i, w := range ws {
					xs[i], _ = w.(string)
				}
				want = k05SortedStrs(xs)
			}
			if k05Canon(got) != k05Canon(want) {
				k.fail(c, "want %s, got %s", k05Canon(c.Out), k05Canon(got))
			}
		case "decideArgProvenance":
			in := a[0]
			if m, ok := in.(map[string]any); ok {
				// the Go input spells the reference's principalPlan / principalControl in snake case
				n := make(map[string]any, len(m))
				for key, v := range m {
					switch key {
					case "principalPlan":
						key = "principal_plan"
					case "principalControl":
						key = "principal_control"
					case "principal_plan", "principal_control":
						key = "ts:" + key // not a reference member: must not switch the Go flag on
					}
					n[key] = v
				}
				in = n
			}
			var got, want any = k05ProvDecision(DecideArgProvenance(in)), c.Out
			// the catch-all "evaluation error (fail closed): <exception text>" compares its prefix only (the exception text is
			// the implementation's); outcome, code and every other member must still match
			got, want = k05EvalErr(got), k05EvalErr(want)
			if k05Canon(got) != k05Canon(want) {
				k.fail(c, "want %s, got %s", k05Canon(want), k05Canon(got))
			}
		case "recorder":
			got, err := k05ProvRecorder(a[0].(map[string]any))
			if th, _ := k05Throws(c.Out); th {
				if err == nil {
					k.fail(c, "want a constructor throw, got %s", k05Canon(got))
				}
				return
			}
			if err != nil || k05Canon(k05ProvThrowsMask(got)) != k05Canon(k05ProvThrowsMask(c.Out)) {
				k.fail(c, "want %s, got %s (%v)", k05Canon(k05ProvThrowsMask(c.Out)), k05Canon(k05ProvThrowsMask(got)), err)
			}
		case "provActionDigest":
			op, _ := k05ProvOp(a[0])
			got, err := ProvActionDigest(op)
			if err != nil || got != c.Out {
				k.fail(c, "want %v, got %q (%v)", c.Out, got, err)
			}
		case "provReceiptRef":
			got, ok := ProvReceiptRef(a[0].(map[string]any))
			if !ok || got != c.Out {
				k.fail(c, "want %v, got %q (%v)", c.Out, got, ok)
			}
		case "defaultProvenanceBundle":
			in := a[0].(map[string]any)
			r := httptest.NewRequest("POST", "/", nil)
			if h, ok := in["header"].(string); ok {
				r.Header.Set(ProvenanceHeader, h)
			}
			body, hasBody := in["body"].(string)
			got := extractProvenanceBundle(r, []byte(body), hasBody)
			if th, _ := k05Throws(c.Out); th {
				if _, unreadable := got.(provUnreadable); !unreadable {
					k.fail(c, "want an unreadable bundle, got %v", got)
				}
				return
			}
			if _, unreadable := got.(provUnreadable); unreadable || k05Canon(got) != k05Canon(c.Out) {
				k.fail(c, "want %s, got %v", k05Canon(c.Out), got)
			}
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}

func k05SortedStrs(xs []string) []any {
	ys := append([]string(nil), xs...)
	sort.Strings(ys)
	out := make([]any, len(ys))
	for i, y := range ys {
		out[i] = y
	}
	return out
}

func k05EvalErr(v any) any {
	const pre = "evaluation error (fail closed): "
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if r, _ := m["reason"].(string); len(r) >= len(pre) && r[:len(pre)] == pre {
		n := make(map[string]any, len(m))
		for key, x := range m {
			n[key] = x
		}
		n["reason"] = pre
		return n
	}
	return v
}
