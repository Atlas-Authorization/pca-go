package pca

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Action-kit conformance: every vector of the shared action corpus (monorepo: packages/pca-conformance/vectors/actions, mirror:
// conformance/actions) must reproduce its `expect` exactly. A missing directory FAILS; nothing is skipped.

func actionVectorDir(t *testing.T) string {
	t.Helper()
	for _, rel := range []string{"../../packages/pca-conformance/vectors/actions", "conformance/actions", "../conformance/actions"} {
		if st, err := os.Stat(rel); err == nil && st.IsDir() {
			return rel
		}
	}
	t.Fatal("the action-kit vectors are missing (a vector directory is never skipped)")
	return ""
}

func codeOfReason(e string) map[string]any {
	if e == "" {
		return map[string]any{"ok": true}
	}
	c := e
	if i := strings.IndexAny(c, ": "); i >= 0 {
		c = c[:i]
	}
	return map[string]any{"ok": false, "code": c}
}

func profileOut(p Profile) map[string]any { return p.raw() }

func replayAction(t *testing.T, kind string, in map[string]any) any {
	t.Helper()
	switch kind {
	case "schema_shape":
		return map[string]any{"ok": actionSchemaShapeError(in["doc"], false) == ""}
	case "parse":
		return map[string]any{"ok": validateDef(in["def"]) == ""}
	case "digest":
		d := in["def"].(map[string]any)
		dg, err := defDigest(d)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"digest": dg, "normalized": normalizeDef(d)}
	case "effective":
		e, err := effective(in["def"].(map[string]any), coreRegistry, in["pins"])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"confirmed": e.Confirmed, "traits": anyStrs(e.Traits), "closure": anyStrs(e.Closure), "eff": profileOut(e.Eff)}
	case "expand", "schema_verb":
		reg := coreRegistry
		if ct, ok := in["custom_traits"].([]any); ok && len(ct) > 0 {
			var err error
			if reg, err = extendRegistry(coreRegistry, ct); err != nil {
				return map[string]any{"error": true}
			}
		}
		if kind == "schema_verb" {
			return codeOfReason(schemaVerbFloorError(in["verb"].(map[string]any), reg, in["pins"]))
		}
		ids, _ := strsOf(in["traits"])
		cl, err := reg.closure(ids)
		if err != nil {
			return map[string]any{"error": true}
		}
		fl, _ := reg.floorOf(ids)
		return map[string]any{"closure": anyStrs(cl), "floor": profileOut(fl)}
	case "floor":
		g := in["grant"].(map[string]any)
		cs, _ := strsOf(g["caveats"])
		cx, _ := strsOf(in["call"].(map[string]any)["context"])
		gf := GrantFacts{Caveats: cs, MaxEsc: int(jsF(g["max_esc"])), PreauthEsc: int(jsF(g["preauth_esc"]))}
		return map[string]any{"decision": floorDecision(gf, cx, profileFromRaw(in["profile"]))}
	case "conform":
		r := conformAction(in["schema"], in["verb"].(string), in["params"])
		if r.OK {
			return map[string]any{"ok": true}
		}
		return map[string]any{"ok": false, "code": r.Code}
	case "pack":
		ds, _ := strsOf(in["digests"])
		root, err := packRoot(ds)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := packProof(ds, ds[int(jsF(in["index"]))])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"root": root, "proof": proof}
	case "rule22_schema":
		return rule22Integrity(in["doc"].(map[string]any), in["pins"])
	case "rule22":
		doc := in["doc"].(map[string]any)
		g := rule22Integrity(doc, in["pins"])
		if g["ok"] != true {
			return map[string]any{"integrity": g["code"], "decision": "deny"}
		}
		ctx, _ := in["context"].([]any)
		return map[string]any{"integrity": "ok", "decision": rule22Decide(doc, in["verb"].(string), in["grant"].(map[string]any), ctx)}
	case "pack_verify":
		sh, _ := in["shards"].(map[string]any)
		d, n, r := verifyPack(in["pack"], in["keys"], sh)
		if r != "" {
			return map[string]any{"ok": false}
		}
		return map[string]any{"ok": true, "digest": d, "defs": float64(n)}
	case "evolution_verify":
		var diff any
		if rec, ok := in["record"].(map[string]any); ok {
			if d, ok := evolutionDiffDigest(rec); ok {
				diff = d
			}
		}
		return map[string]any{"ok": verifyEvolutionRecord(in["record"], in["keys"]) == "", "diff": diff}
	case "reapproval_verify":
		g := in["grant"].(map[string]any)
		return map[string]any{"ok": reapprovalValid(in["reapproval"], g["id"], g["issuer"], in["verb"], in["diff"])}
	case "pin":
		d := decidePin(in)
		if d["ok"] == true {
			return map[string]any{"ok": true, "via": d["via"]}
		}
		o := map[string]any{"ok": false, "code": d["code"], "escalate": d["escalate"]}
		if n, has := d["needs_reapproval"]; has {
			o["needs_reapproval"] = n
		}
		return o
	case "pack_proof_verify":
		pr, _ := in["proof"].(map[string]any)
		return map[string]any{"ok": verifyPackProof(in["root"].(string), pr, in["digest"].(string))}
	case "tracker":
		tr := newPackTracker(in["keys"])
		out := []any{}
		for _, sv := range in["steps"].([]any) {
			st := sv.(map[string]any)
			sh, _ := st["shards"].(map[string]any)
			out = append(out, tr.accept(st["pack"], sh))
		}
		return out
	case "approval_render":
		r, err := RenderApproval(in["def"].(map[string]any), in["params"], in["confirmed"] == true)
		if err != nil {
			return map[string]any{"ok": false, "code": errCode(err)}
		}
		d, err := ApprovalRenderDigest(r)
		if err != nil {
			t.Fatal(err)
		}
		w, _ := BindingWords(d)
		return map[string]any{"ok": true, "render": r, "digest": d, "words": w}
	case "approval_digest":
		if ApprovalRenderShapeError(in["render"]) != "" {
			return map[string]any{"ok": false}
		}
		d, err := ApprovalRenderDigest(in["render"])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"ok": true, "digest": d}
	case "approval_challenge":
		a, _ := in["action_digest"].(string)
		r, _ := in["render_digest"].(string)
		c, err := ApprovalChallenge(a, r)
		if err != nil {
			return map[string]any{"ok": false}
		}
		return map[string]any{"ok": true, "challenge": c}
	case "approval_escalation":
		b := in["bind"].(map[string]any)
		bind := EscalationBinding{PolicyDigest: b["policy_digest"].(string), ActionDigest: b["action_digest"].(string), HistoryHead: b["history_head"].(string)}
		if rd, ok := b["render_digest"].(string); ok {
			bind.RenderDigest = rd
		}
		var pins []string
		for _, p := range in["principals"].([]any) {
			pins = append(pins, p.(string))
		}
		now, _ := safeInt(in["now"])
		v := VerifyEscalationAnswer(in["answer"], Ed25519Pins(pins...), bind, now)
		if v.OK {
			return map[string]any{"ok": true, "decision": v.Decision}
		}
		return map[string]any{"ok": false, "reason": v.Reason}
	}
	t.Fatalf("unknown vector kind %q", kind)
	return nil
}

func replayApprovalProfile(t *testing.T, kind string, in map[string]any) any {
	t.Helper()
	switch kind {
	case "approval_psd2":
		l, err := Psd2Linking(in["render"].(map[string]any))
		if err != nil {
			return map[string]any{"ok": false, "code": errCode(err)}
		}
		return map[string]any{"ok": true, "linking": l}
	case "approval_batch":
		b, err := ApprovalBatch(in["items"].([]any))
		if err != nil {
			return map[string]any{"ok": false, "code": errCode(err)}
		}
		return map[string]any{"ok": true, "batch": b["batch"], "action_digest": b["action_digest"], "render_digest": b["render_digest"], "challenge": b["challenge"], "words": b["words"]}
	}
	t.Fatalf("unknown approval profile vector kind %q", kind)
	return nil
}

func TestApprovalProfileVectors(t *testing.T) {
	var dir string
	for _, rel := range []string{"../../packages/pca-conformance/vectors/approval-profiles", "conformance/approval-profiles", "../conformance/approval-profiles"} {
		if st, err := os.Stat(rel); err == nil && st.IsDir() {
			dir = rel
		}
	}
	if dir == "" {
		t.Fatal("the approval profile vectors are missing (a vector directory is never skipped)")
	}
	names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(names) < 12 {
		t.Fatalf("only %d approval profile vectors", len(names))
	}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ParseJSONLenient(b)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		c := v.(map[string]any)
		got := replayApprovalProfile(t, c["kind"].(string), c["input"].(map[string]any))
		if !sameJSON(got, c["expect"]) {
			g, _ := canonicalLenient(normalizeJSON(got))
			w, _ := canonicalLenient(normalizeJSON(c["expect"]))
			t.Errorf("%s:\n got  %s\n want %s", c["id"], g, w)
		}
	}
}

func loadActionVectors(t *testing.T) []map[string]any {
	t.Helper()
	dir := actionVectorDir(t)
	names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(names)
	var out []map[string]any
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ParseJSONLenient(b)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		out = append(out, v.(map[string]any))
	}
	return out
}

func TestActionsVectorsReplay(t *testing.T) {
	cases := loadActionVectors(t)
	if len(cases) < 781 {
		t.Fatalf("only %d action vectors", len(cases))
	}
	kinds := map[string]int{}
	for _, c := range cases {
		kind := c["kind"].(string)
		kinds[kind]++
		got := replayAction(t, kind, c["input"].(map[string]any))
		if !sameJSON(got, c["expect"]) {
			g, _ := canonicalLenient(normalizeJSON(got))
			w, _ := canonicalLenient(normalizeJSON(c["expect"]))
			t.Errorf("%s (%s):\n got  %s\n want %s", c["id"], kind, g, w)
		}
	}
	for _, k := range []string{"parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "rule22", "rule22_schema", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "schema_shape", "approval_render", "approval_digest", "approval_challenge", "approval_escalation"} {
		if kinds[k] < 8 {
			t.Errorf("kind %s has %d vectors", k, kinds[k])
		}
	}
}

func TestActionsPinnedDigests(t *testing.T) {
	if d, _ := traitsDigest(coreRegistry); d != "W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM" {
		t.Errorf("traitsDigest = %s", d)
	}
	if d, _ := tablesDigest(); d != "I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU" {
		t.Errorf("tablesDigest = %s", d)
	}
}

func TestActionsPackProofTamper(t *testing.T) {
	for _, c := range loadActionVectors(t) {
		if c["id"] != "pack-builtin" {
			continue
		}
		ds, _ := strsOf(c["input"].(map[string]any)["digests"])
		root := c["expect"].(map[string]any)["root"].(string)
		for _, d := range ds {
			p, err := packProof(ds, d)
			if err != nil || !verifyPackProof(root, p, d) {
				t.Fatalf("proof for %s does not verify", d)
			}
		}
		p, _ := packProof(ds, ds[0])
		if verifyPackProof(root, p, ds[1]) {
			t.Fatal("a proof verified for another digest")
		}
		return
	}
	t.Fatal("pack-builtin vector missing")
}

func TestActionsWholeDocumentRule22(t *testing.T) {
	for _, c := range loadActionVectors(t) {
		if c["id"] != "schema-verb-adv-honest" {
			continue
		}
		doc := map[string]any{"verbs": []any{c["input"].(map[string]any)["verb"]}}
		if e := schemaFloorError(doc, nil); e != "" {
			t.Fatalf("honest document refused: %s", e)
		}
		doc["traits_digest"] = strings.Repeat("A", 43)
		if e := schemaFloorError(doc, nil); !strings.HasPrefix(e, "traits_digest_mismatch") {
			t.Fatalf("got %q", e)
		}
		return
	}
	t.Fatal("schema-verb-adv-honest vector missing")
}
