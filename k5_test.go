package pca

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

func k5Null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func k5Anys(l []string) []any {
	out := make([]any, 0, len(l))
	for _, s := range l {
		out = append(out, s)
	}
	return out
}

func k5Equal(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		t.Errorf("got  %s\nwant %s", g, w)
	}
}

func k5WfMap(r WfResult) map[string]any {
	var at any
	if r.At >= 0 {
		at = json.Number(strconv.Itoa(r.At))
	}
	pending := []any{}
	for _, p := range r.Pending {
		pending = append(pending, json.Number(strconv.Itoa(p)))
	}
	return map[string]any{"decision": r.Decision, "code": k5Null(r.Code), "step": k5Null(r.Step), "at": at, "pending": pending}
}

func k5Admit(W map[string]any, c map[string]any) AdmitInput {
	return AdmitInput{Workflow: W["workflows"].(map[string]any)[c["workflow"].(string)], Principal: c["principal"].(string), RsSigner: c["rs_signer"].(string),
		Receipts: c["receipts"], Now: num(c["now"]), Request: c["request"]}
}

// Replays packages/pca/conformance/workflow-vectors.json (a missing file fails: load calls t.Fatal).
func TestK5WorkflowVectors(t *testing.T) {
	W := load(t, "workflow-vectors.json")
	keys := W["keys"].(map[string]any)
	dg := W["digests"].(map[string]any)
	main := W["workflows"].(map[string]any)["main"].(map[string]any)["body"].(map[string]any)
	if d, ok := WorkflowDigest(main); !ok || d != dg["workflow"] {
		t.Errorf("workflow digest %q, want %v", d, dg["workflow"])
	}
	for _, x := range dg["values"].([]any) {
		v := x.(map[string]any)
		if d, ok := WorkflowValueDigest(v["value"]); !ok || d != v["digest"] {
			t.Errorf("value digest %v = %q, want %v", v["value"], d, v["digest"])
		}
	}
	for _, x := range dg["params"].([]any) {
		v := x.(map[string]any)
		if d, err := HashCanonical(v["params"]); err != nil || d != v["digest"] {
			t.Errorf("params digest %q, want %v", d, v["digest"])
		}
	}
	// every committed receipt ref is the ref of a receipt that occurs in the vectors
	refs := map[string]bool{}
	for _, k := range []string{"admit", "bind"} {
		for _, x := range W[k].([]any) {
			for _, r := range x.(map[string]any)["receipts"].([]any) {
				if m, ok := r.(map[string]any); ok {
					if ref, ok := WorkflowReceiptRef(m); ok {
						refs[ref] = true
					}
				}
			}
		}
	}
	want := dg["receipt_refs"].([]any)
	if len(want) != 4 {
		t.Errorf("receipt_refs: %d", len(want))
	}
	matched := 0 // the 4th ref is the head of a chain whose receipt no case carries; the reference only checks the count
	for _, r := range want {
		if refs[r.(string)] {
			matched++
		}
	}
	if matched < 3 {
		t.Errorf("only %d receipt refs match a receipt in the vectors", matched)
	}
	seen := map[string]bool{}
	for _, k := range []string{"admit", "bind"} {
		f := AdmitStep
		if k == "bind" {
			f = BindPromises
		}
		for _, x := range W[k].([]any) {
			c := x.(map[string]any)
			exp := c["expect"].(map[string]any)
			if code, ok := exp["code"].(string); ok {
				seen[code] = true
			}
			t.Run(k+"/"+c["name"].(string), func(t *testing.T) { k5Equal(t, k5WfMap(f(k5Admit(W, c))), exp) })
		}
	}
	for _, x := range W["plan_root"].([]any) {
		c := x.(map[string]any)
		t.Run("plan_root/"+c["name"].(string), func(t *testing.T) {
			got := PlanRootAuthorized(W["workflows"].(map[string]any)[c["workflow"].(string)], c["principal"].(string), num(c["now"]), c["root"].(string))
			if got != c["expect"].(bool) {
				t.Errorf("got %v, want %v", got, c["expect"])
			}
		})
	}
	for _, code := range []string{"bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt", "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed", "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow", "pipeline_unconstrained", "taint_escalate"} {
		if !seen[code] {
			t.Errorf("denial code %q is not exercised by the vectors", code)
		}
	}
	// never panics, never allows on hostile input
	for _, x := range []any{nil, json.Number("1"), "x", []any{}, map[string]any{}, map[string]any{"body": nil}, map[string]any{"body": map[string]any{}, "sig": json.Number("1")}} {
		r := AdmitStep(AdmitInput{Workflow: x, Principal: keys["principal"].(string), RsSigner: keys["rs"].(string), Receipts: []any{}, Now: 1, Request: x})
		if r.Decision != "deny" || r.Code != "bad_workflow" || r.Step != "" || r.At != -1 {
			t.Errorf("hostile %v: %+v", x, r)
		}
	}
	if r := AdmitStep(AdmitInput{Workflow: W["workflows"].(map[string]any)["main"], Principal: keys["principal"].(string), RsSigner: keys["rs"].(string), Receipts: "x", Now: 1, Request: map[string]any{}}); r.Decision != "deny" {
		t.Errorf("receipts as a string: %+v", r)
	}
}

func k5ReadMap(r ReadResult) map[string]any {
	fields := map[string]any{}
	for k, f := range r.Fields {
		fields[k] = map[string]any{"class": f.Class, "action": f.Action, "kind": k5Null(f.Kind), "vd": f.Vd}
	}
	counts := map[string]any{}
	for k, n := range r.Counts {
		counts[k] = json.Number(strconv.FormatInt(n, 10))
	}
	return map[string]any{"decision": r.Decision, "code": k5Null(r.Code), "view": r.View, "fields": fields, "labels": k5Anys(r.Labels), "counts": counts}
}

// Replays packages/pca/conformance/readside-vectors.json (a missing file fails).
func TestK5ReadsideVectors(t *testing.T) {
	R := load(t, "readside-vectors.json")
	grants := R["grants"].(map[string]any)
	keys := R["keys"].(map[string]any)
	dg := R["digests"].(map[string]any)
	if d, ok := ReadGrantDigest(grants["main"].(map[string]any)["body"].(map[string]any)); !ok || d != dg["grant"] {
		t.Errorf("grant digest %q, want %v", d, dg["grant"])
	}
	for _, x := range R["redact"].([]any) {
		c := x.(map[string]any)
		t.Run("redact/"+c["name"].(string), func(t *testing.T) {
			i := c["input"].(map[string]any)
			got := RedactRead(ReadInput{Grant: grants[c["grant"].(string)], Principal: i["principal"].(string), Now: i["now"], Verb: i["verb"].(string), Resource: i["resource"].(string),
				Purpose: i["purpose"].(string), Schema: i["schema"], Record: i["record"], Tighten: i["tighten"], Salt: i["salt"].(string), Counts: i["counts"]})
			k5Equal(t, k5ReadMap(got), c["expect"])
		})
	}
	refs := map[string]bool{}
	for _, x := range R["sinks"].([]any) {
		c := x.(map[string]any)
		for _, r := range c["receipts"].([]any) {
			if m, ok := r.(map[string]any); ok {
				if ref, ok := ReadReceiptRef(m); ok {
					refs[ref] = true
				}
			}
		}
		t.Run("sink/"+c["name"].(string), func(t *testing.T) {
			got := CheckSink(SinkInput{Grant: grants[c["grant"].(string)], Principal: c["principal"].(string), RsSigner: c["rs_signer"].(string), Now: c["now"], Sink: c["sink"].(string), Receipts: c["receipts"]})
			k5Equal(t, map[string]any{"decision": got.Decision, "code": k5Null(got.Code), "labels": k5Anys(got.Labels)}, c["expect"])
		})
		if c["name"] == "chain-of-two-public-reads" {
			labels, code, _ := ReadChainLabels(c["receipts"], keys["rs"].(string), dg["grant"].(string), 1_800_000_000_000)
			k5Equal(t, map[string]any{"labels": k5Anys(labels)}, dg["chain_labels"])
			if code != "" {
				t.Errorf("chain code %q", code)
			}
		}
	}
	for _, r := range dg["receipt_refs"].([]any) {
		if !refs[r.(string)] {
			t.Errorf("receipt ref %v matches no receipt in the vectors", r)
		}
	}
}
