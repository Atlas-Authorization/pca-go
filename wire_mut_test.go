package pca

// Exact-reason golden table for ValidateWireV2 (every structural rule, one violation at a time) and helpers.
// Regenerate with GOLDEN_UPDATE=1 go test -run TestMutWireGolden; the golden was reviewed so each reason names the
// field the case violates.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

type wcase struct {
	name string
	mod  func(p map[string]any)
}

func sub(p map[string]any, k string) map[string]any { return p[k].(map[string]any) }

func hop0(p map[string]any) map[string]any { return p["cap_chain"].([]any)[0].(map[string]any) }

func step0(p map[string]any) map[string]any {
	return sub(sub(p, "plan"), "inclusion_proof")["path"].([]any)[0].(map[string]any)
}

func wireCases() []wcase {
	b32s := b64.EncodeToString(make([]byte, 32))
	cs := []wcase{
		{"valid", func(p map[string]any) {}},
		{"alg ed25519 explicit", func(p map[string]any) { p["alg"] = "ed25519" }},
		{"unknown field", func(p map[string]any) { p["zzz"] = 1 }},
		{"lone surrogate in value", func(p map[string]any) { sub(p, "action")["verb"] = "\xed\xa0\x80" }},
		{"lone surrogate in key", func(p map[string]any) { p["\xed\xa0\x80"] = 1 }},
		{"nesting too deep", func(p map[string]any) { sub(p, "risk_claim")["inputs"] = nested(40, true) }},
		{"nesting ok", func(p map[string]any) { sub(p, "risk_claim")["inputs"] = nested(20, true) }},
	}
	for _, k := range requiredFields {
		k := k
		cs = append(cs, wcase{"missing " + k, func(p map[string]any) { delete(p, k) }})
	}
	for _, k := range []string{"ver", "counter", "iat", "exp"} {
		k := k
		cs = append(cs,
			wcase{k + " string", func(p map[string]any) { p[k] = "1" }},
			wcase{k + " float", func(p map[string]any) { p[k] = json.Number("1.5") }},
			wcase{k + " huge", func(p map[string]any) { p[k] = json.Number("9007199254740992") }},
			wcase{k + " exp-form", func(p map[string]any) { p[k] = json.Number("1e3") }},
		)
	}
	cs = append(cs,
		wcase{"aud number", func(p map[string]any) { p["aud"] = 5 }},
		wcase{"nonce ok", func(p map[string]any) { p["nonce"] = "n" }},
		wcase{"alg number", func(p map[string]any) { p["alg"] = 5 }},
		wcase{"alg unknown", func(p map[string]any) { p["alg"] = "nope" }},
		wcase{"alg ml-dsa-65 no pq_pk", func(p map[string]any) { p["alg"] = "ml-dsa-65" }},
		wcase{"alg hybrid no pq_sig", func(p map[string]any) { p["alg"] = "hybrid-ed25519-ml-dsa-65"; p["pq_pk"] = "x" }},
		wcase{"pq_pk with ed25519", func(p map[string]any) { p["pq_pk"] = "x" }},
		wcase{"pq_sig with ed25519", func(p map[string]any) { p["pq_sig"] = "x" }},
		wcase{"pq_sig with ml-dsa", func(p map[string]any) {
			p["alg"] = "ml-dsa-65"
			p["pq_pk"] = b64.EncodeToString(make([]byte, 1952))
			p["sig"] = b64.EncodeToString(make([]byte, 3309))
			p["pq_sig"] = "x"
		}},
		wcase{"ml-dsa-65 wire ok", func(p map[string]any) {
			p["alg"] = "ml-dsa-65"
			p["pq_pk"] = b64.EncodeToString(make([]byte, 1952))
			p["sig"] = b64.EncodeToString(make([]byte, 3309))
		}},
		wcase{"hybrid wire ok", func(p map[string]any) {
			p["alg"] = "hybrid-ed25519-ml-dsa-65"
			p["pq_pk"] = b64.EncodeToString(make([]byte, 1952))
			p["pq_sig"] = b64.EncodeToString(make([]byte, 3309))
		}},
		wcase{"hybrid bad pq_sig", func(p map[string]any) {
			p["alg"] = "hybrid-ed25519-ml-dsa-65"
			p["pq_pk"] = b64.EncodeToString(make([]byte, 1952))
			p["pq_sig"] = b64.EncodeToString(make([]byte, 5))
		}},
		wcase{"sig short", func(p map[string]any) { p["sig"] = b64.EncodeToString(make([]byte, 63)) }},
		wcase{"sig noncanonical", func(p map[string]any) { p["sig"] = strings.TrimRight(p["sig"].(string), "A") + "=" }},
		wcase{"grant_ref bad", func(p map[string]any) { p["grant_ref"] = "x" }},
		wcase{"action array", func(p map[string]any) { p["action"] = []any{} }},
		wcase{"action unknown field", func(p map[string]any) { sub(p, "action")["extra"] = 1 }},
		wcase{"verb number", func(p map[string]any) { sub(p, "action")["verb"] = 1 }},
		wcase{"resource number", func(p map[string]any) { sub(p, "action")["resource"] = 1 }},
		wcase{"reversibility number", func(p map[string]any) { sub(p, "action")["reversibility_class"] = 1 }},
		wcase{"params_digest bad", func(p map[string]any) { sub(p, "action")["params_digest"] = "x" }},
		wcase{"params_digest missing", func(p map[string]any) { delete(sub(p, "action"), "params_digest") }},
		wcase{"plan string", func(p map[string]any) { p["plan"] = "x" }},
		wcase{"plan unknown field", func(p map[string]any) { sub(p, "plan")["x"] = 1 }},
		wcase{"plan root bad", func(p map[string]any) { sub(p, "plan")["root"] = "x" }},
		wcase{"node_id number", func(p map[string]any) { sub(p, "plan")["node_id"] = 1 }},
		wcase{"node_id missing", func(p map[string]any) { delete(sub(p, "plan"), "node_id") }},
		wcase{"conditions_digest bad", func(p map[string]any) { sub(p, "plan")["conditions_digest"] = "x" }},
		wcase{"conditions_digest absent", func(p map[string]any) { delete(sub(p, "plan"), "conditions_digest") }},
		wcase{"inclusion_proof string", func(p map[string]any) { sub(p, "plan")["inclusion_proof"] = "x" }},
		wcase{"inclusion_proof unknown", func(p map[string]any) { sub(sub(p, "plan"), "inclusion_proof")["x"] = 1 }},
		wcase{"proof index string", func(p map[string]any) { sub(sub(p, "plan"), "inclusion_proof")["index"] = "1" }},
		wcase{"proof size float", func(p map[string]any) { sub(sub(p, "plan"), "inclusion_proof")["size"] = json.Number("1.5") }},
		wcase{"proof path object", func(p map[string]any) { sub(sub(p, "plan"), "inclusion_proof")["path"] = map[string]any{} }},
		wcase{"proof step string", func(p map[string]any) { sub(sub(p, "plan"), "inclusion_proof")["path"].([]any)[0] = "x" }},
		wcase{"proof step unknown", func(p map[string]any) { step0(p)["x"] = 1 }},
		wcase{"proof side X", func(p map[string]any) { step0(p)["side"] = "X" }},
		wcase{"proof side lower", func(p map[string]any) { step0(p)["side"] = "l" }},
		wcase{"proof side missing", func(p map[string]any) { delete(step0(p), "side") }},
		wcase{"proof hash bad", func(p map[string]any) { step0(p)["hash"] = "x" }},
		wcase{"cap_chain object", func(p map[string]any) { p["cap_chain"] = map[string]any{} }},
		wcase{"cap_chain item string", func(p map[string]any) { p["cap_chain"].([]any)[1] = "x" }},
		wcase{"cap unknown field", func(p map[string]any) { hop0(p)["x"] = 1 }},
		wcase{"cap id bad", func(p map[string]any) { hop0(p)["id"] = "x" }},
		wcase{"cap issuer bad", func(p map[string]any) { hop0(p)["issuer"] = "x" }},
		wcase{"cap holder bad", func(p map[string]any) { hop0(p)["holder"] = "x" }},
		wcase{"cap body_digest bad", func(p map[string]any) { hop0(p)["body_digest"] = "x" }},
		wcase{"cap sig bad", func(p map[string]any) { hop0(p)["sig"] = "x" }},
		wcase{"cap alg unknown", func(p map[string]any) { hop0(p)["alg"] = "nope" }},
		wcase{"cap pq_pk with ed25519", func(p map[string]any) { hop0(p)["pq_pk"] = "x" }},
		wcase{"cap parent bad", func(p map[string]any) { p["cap_chain"].([]any)[1].(map[string]any)["parent"] = "x" }},
		wcase{"cap parent ok root", func(p map[string]any) { hop0(p)["parent"] = b32s }},
		wcase{"cap holder_pq bad", func(p map[string]any) { hop0(p)["holder_pq"] = "x" }},
		wcase{"cap holder_pq ok", func(p map[string]any) { hop0(p)["holder_pq"] = b32s }},
		wcase{"cap caveats missing", func(p map[string]any) { delete(hop0(p), "caveats") }},
		wcase{"cap caveats object", func(p map[string]any) { hop0(p)["caveats"] = map[string]any{} }},
		wcase{"cap caveat string", func(p map[string]any) { hop0(p)["caveats"] = []any{"x"} }},
		wcase{"cap caveat no type", func(p map[string]any) { hop0(p)["caveats"] = []any{map[string]any{}} }},
		wcase{"cap caveat type number", func(p map[string]any) { hop0(p)["caveats"] = []any{map[string]any{"type": 1}} }},
		wcase{"cap caveat second bad", func(p map[string]any) {
			hop0(p)["caveats"] = []any{map[string]any{"type": "a"}, map[string]any{"type": 1}}
		}},
		wcase{"attestation array", func(p map[string]any) { p["attestation"] = []any{} }},
		wcase{"attestation epoch missing", func(p map[string]any) { delete(sub(p, "attestation"), "epoch") }},
		wcase{"attestation epoch float", func(p map[string]any) { sub(p, "attestation")["epoch"] = json.Number("1.5") }},
	)
	for _, k := range []string{"quote_digest", "model_id", "measurement", "operator"} {
		k := k
		cs = append(cs, wcase{"attestation " + k + " number", func(p map[string]any) { sub(p, "attestation")[k] = 1 }})
	}
	cs = append(cs,
		wcase{"provenance string", func(p map[string]any) { p["provenance"] = "x" }},
		wcase{"provenance causal_hash number", func(p map[string]any) { sub(p, "provenance")["causal_hash"] = 1 }},
		wcase{"provenance taint string", func(p map[string]any) { sub(p, "provenance")["taint_level"] = "0" }},
		wcase{"provenance taint exp", func(p map[string]any) { sub(p, "provenance")["taint_level"] = json.Number("1e1") }},
		wcase{"provenance refs object", func(p map[string]any) { sub(p, "provenance")["trusted_refs"] = map[string]any{} }},
		wcase{"provenance ref number", func(p map[string]any) { sub(p, "provenance")["trusted_refs"] = []any{"a", 1} }},
		wcase{"provenance refs empty ok", func(p map[string]any) { sub(p, "provenance")["trusted_refs"] = []any{} }},
		wcase{"freshness array", func(p map[string]any) { p["freshness"] = []any{} }},
		wcase{"freshness beacon number", func(p map[string]any) { sub(p, "freshness")["beacon_ref"] = 1 }},
		wcase{"freshness witness number", func(p map[string]any) { sub(p, "freshness")["accumulator_witness"] = 1 }},
		wcase{"freshness epoch string", func(p map[string]any) { sub(p, "freshness")["epoch"] = "1" }},
		wcase{"risk_claim string", func(p map[string]any) { p["risk_claim"] = "x" }},
		wcase{"risk r string", func(p map[string]any) { sub(p, "risk_claim")["r"] = "0.5" }},
		wcase{"risk inputs array", func(p map[string]any) { sub(p, "risk_claim")["inputs"] = []any{} }},
		wcase{"caution string", func(p map[string]any) { p["caution"] = "0.5" }},
		wcase{"caution exp", func(p map[string]any) { p["caution"] = json.Number("1e-1") }},
		wcase{"caution negative", func(p map[string]any) { p["caution"] = json.Number("-0.1") }},
		wcase{"caution zero", func(p map[string]any) { p["caution"] = json.Number("0") }},
		wcase{"caution one", func(p map[string]any) { p["caution"] = json.Number("1") }},
		wcase{"caution half", func(p map[string]any) { p["caution"] = json.Number("0.5") }},
		wcase{"caution above one", func(p map[string]any) { p["caution"] = json.Number("1.1") }},
		wcase{"caution tiny above one", func(p map[string]any) { p["caution"] = json.Number("1.000001") }},
		wcase{"caution tiny negative", func(p map[string]any) { p["caution"] = json.Number("-0.000001") }},
		wcase{"rationale bad", func(p map[string]any) { p["rationale_commitment"] = "x" }},
		wcase{"rationale ok", func(p map[string]any) { p["rationale_commitment"] = b32s }},
		wcase{"tool_binding bad", func(p map[string]any) { p["tool_binding"] = 5 }},
		wcase{"tool_binding ok", func(p map[string]any) { p["tool_binding"] = b32s }},
		wcase{"progress_step string", func(p map[string]any) { p["progress_step"] = "x" }},
		wcase{"progress_step ok", func(p map[string]any) { p["progress_step"] = map[string]any{"a": 1} }},
		wcase{"prohibition string", func(p map[string]any) { p["prohibition_evidence"] = "x" }},
		wcase{"prohibition null", func(p map[string]any) { p["prohibition_evidence"] = nil }},
		wcase{"prohibition object ok", func(p map[string]any) { p["prohibition_evidence"] = map[string]any{} }},
		wcase{"prohibition array ok", func(p map[string]any) { p["prohibition_evidence"] = []any{} }},
		wcase{"threshold string", func(p map[string]any) { p["threshold"] = "x" }},
		wcase{"threshold no shares", func(p map[string]any) { p["threshold"] = map[string]any{} }},
		wcase{"threshold shares object", func(p map[string]any) { p["threshold"] = map[string]any{"shares": map[string]any{}} }},
		wcase{"threshold empty ok", func(p map[string]any) { p["threshold"] = map[string]any{"shares": []any{}} }},
		wcase{"threshold share string", func(p map[string]any) { p["threshold"] = map[string]any{"shares": []any{"x"}} }},
		wcase{"threshold role number", func(p map[string]any) {
			p["threshold"] = map[string]any{"shares": []any{map[string]any{"role": 1, "publicKey": b32s, "sig": b64.EncodeToString(make([]byte, 64))}}}
		}},
		wcase{"threshold pk bad", func(p map[string]any) {
			p["threshold"] = map[string]any{"shares": []any{map[string]any{"role": "a", "publicKey": "x", "sig": b64.EncodeToString(make([]byte, 64))}}}
		}},
		wcase{"threshold sig bad", func(p map[string]any) {
			p["threshold"] = map[string]any{"shares": []any{map[string]any{"role": "a", "publicKey": b32s, "sig": "x"}}}
		}},
		wcase{"threshold second share bad", func(p map[string]any) {
			ok := map[string]any{"role": "a", "publicKey": b32s, "sig": b64.EncodeToString(make([]byte, 64))}
			p["threshold"] = map[string]any{"shares": []any{ok, "x"}}
		}},
		wcase{"threshold ok", func(p map[string]any) {
			p["threshold"] = map[string]any{"shares": []any{map[string]any{"role": "a", "publicKey": b32s, "sig": b64.EncodeToString(make([]byte, 64))}}}
		}},
	)
	return cs
}

func wireDump(t *testing.T) string {
	var sb strings.Builder
	for _, c := range wireCases() {
		f := newFx(t)
		p := f.norm()
		c.mod(p)
		fmt.Fprintf(&sb, "%s => %q\n", c.name, ValidateWireV2(p))
	}
	return sb.String()
}

func TestMutWireGolden(t *testing.T) {
	got := wireDump(t)
	const path = "testdata/wire_mut_golden.txt"
	if os.Getenv("GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	if len(gl) != len(wl) {
		t.Fatalf("line count %d vs %d", len(gl), len(wl))
	}
	for i := range gl {
		if gl[i] != wl[i] {
			t.Fatalf("line %d:\n got  %s\n want %s", i+1, gl[i], wl[i])
		}
	}
	_ = sort.Strings
}
