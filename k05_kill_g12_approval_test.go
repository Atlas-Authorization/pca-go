package pca

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestG12BindingWordsTableHas256Words(t *testing.T) {
	if len(bindingWords) != 256 {
		t.Fatalf("table size %d", len(bindingWords))
	}
	for i, w := range bindingWords {
		if w == "" {
			t.Fatalf("word %d is empty", i)
		}
	}
}

func TestG12FlattenEmptyTopLevelKey(t *testing.T) {
	flat, err := flattenForRender(map[string]any{"": map[string]any{"a": jnum(1)}})
	if err != nil || len(flat) != 1 || flat["a"] != jnum(1) {
		t.Fatalf("%v %v", flat, err)
	}
}

func TestG12RenderValueUnknownType(t *testing.T) {
	if renderValueOK("bogus", jnum(1)) {
		t.Fatal("an unknown type must not render")
	}
}

func TestG12RenderApprovalDefDigestError(t *testing.T) {
	def := map[string]any{"resource": map[string]any{"scope": "s"}, "params": map[string]any{}, "title": 1.5}
	r, err := RenderApproval(def, map[string]any{}, true)
	if r != nil || err == nil || err.Error() != "canonicalize: unsupported type float64" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestG12Psd2ZeroAmountIsTheNumberZero(t *testing.T) {
	r := map[string]any{"fields": []any{
		map[string]any{"class": "money.amount", "value": 0, "unit": map[string]any{"kind": "money", "ccy": "EUR", "exp": jnum(2)}},
		map[string]any{"class": "party.payee", "value": "bob"},
	}}
	out, err := Psd2Linking(r)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := out["amount_minor"].(json.Number); !ok || n != "0" {
		t.Fatalf("amount_minor %#v", out["amount_minor"])
	}
}

func g12PayRender() map[string]any {
	return map[string]any{"v": jnum(1), "kind": "pca-approval-render", "verb": "pay", "def_digest": b64.EncodeToString(make([]byte, 32)), "unreviewed": false,
		"fields": []any{
			map[string]any{"id": "amount", "class": "money.amount", "value": jnum(5), "unit": map[string]any{"kind": "money", "ccy": "EUR", "exp": jnum(2)}},
			map[string]any{"id": "payee", "class": "party.payee", "value": "bob"},
		}}
}

func g12PayItems() []any {
	return []any{map[string]any{"render": g12PayRender(), "action_digest": b64.EncodeToString(make([]byte, 32))}}
}

func TestG12ApprovalBatchItemErrors(t *testing.T) {
	if b, err := ApprovalBatch(g12PayItems()); err != nil || b == nil {
		t.Fatalf("baseline: %v", err)
	}
	// linkable, but not a well-formed render
	r := g12PayRender()
	delete(r, "v")
	b, err := ApprovalBatch([]any{map[string]any{"render": r, "action_digest": b64.EncodeToString(make([]byte, 32))}})
	if b != nil || err == nil || err.Error() != "approvalRenderDigest: missing member 'render.v'" {
		t.Fatalf("shape: %v %v", b, err)
	}
	// an action digest that is not canonical JSON fails the items root
	b, err = ApprovalBatch([]any{map[string]any{"render": g12PayRender(), "action_digest": 1.5}})
	if b != nil || err == nil || err.Error() != "canonicalize: unsupported type float64" {
		t.Fatalf("items root: %v %v", b, err)
	}
}

func TestG12ApprovalBatchLaterStepsFailClosed(t *testing.T) {
	seam := errors.New("g12 seam")
	m0, h0, c0, w0 := approvalBatchMerkle, approvalBatchHash, approvalBatchChallenge, approvalBatchWords
	defer func() {
		approvalBatchMerkle, approvalBatchHash, approvalBatchChallenge, approvalBatchWords = m0, h0, c0, w0
	}()
	check := func(name string) {
		t.Helper()
		b, err := ApprovalBatch(g12PayItems())
		if b != nil || err != seam {
			t.Errorf("%s: %v %v", name, b, err)
		}
		approvalBatchMerkle, approvalBatchHash, approvalBatchChallenge, approvalBatchWords = m0, h0, c0, w0
	}
	calls := 0
	approvalBatchMerkle = func(l []any) (string, error) { // only the payees root (the first call) fails
		calls++
		if calls == 1 {
			return "", seam
		}
		return MerkleRoot(l)
	}
	check("payees root")
	approvalBatchHash = func(any) (string, error) { return "", seam }
	check("batch digest")
	approvalBatchChallenge = func(string, string) (string, error) { return "", seam }
	check("challenge")
	approvalBatchWords = func(string) (string, error) { return "", seam }
	check("words")
}
