package pca

import "testing"

// K7: pinned values (a change is a wire break) and the guard's refusals. The shared vectors cover the rest.
func TestApprovalPrimitivesPinned(t *testing.T) {
	zero := b64.EncodeToString(make([]byte, 32))
	c, err := ApprovalChallenge(zero, zero)
	if err != nil || len(c) != 43 {
		t.Fatalf("challenge %q %v", c, err)
	}
	if swapped, _ := ApprovalChallenge(zero, b64.EncodeToString(append(make([]byte, 31), 1))); swapped == c {
		t.Error("a different render digest must change the challenge")
	}
	if _, err := ApprovalChallenge("AAAA", zero); err == nil {
		t.Error("a short action digest must be refused")
	}
	w, err := BindingWords(zero)
	if err != nil || w != "able-able-able-able-able-able" {
		t.Errorf("BindingWords = %q %v", w, err)
	}
	if ApprovalRenderShapeError(map[string]any{"v": 1}) == "" {
		t.Error("an incomplete render must be refused")
	}
}

func TestEscalationRequestCarriesRender(t *testing.T) {
	grant := map[string]any{"id": "g"}
	p := map[string]any{"action": map[string]any{"verb": "v", "resource": "r"}}
	req, err := BuildEscalationRequestWithRender("aud", grant, p, nil, []string{"x"}, 1, 0, "RD")
	if err != nil || req["render_digest"] != "RD" {
		t.Fatalf("%v %v", req, err)
	}
	plain, _ := BuildEscalationRequest("aud", grant, p, nil, []string{"x"}, 1, 0)
	if _, has := plain["render_digest"]; has {
		t.Error("no render, no member")
	}
}
