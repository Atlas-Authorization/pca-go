package pca

import (
	"encoding/json"
	"strings"
	"testing"
)

func azRefusalReq(carried string) map[string]any {
	return map[string]any{"subject": map[string]any{"type": "user", "id": "alice"}, "action": map[string]any{"name": "read"},
		"resource": map[string]any{"type": "doc", "id": "1"}, "context": map[string]any{AuthzenActionKey: carried}}
}

func azRefusalAdmin(t *testing.T, carried string) map[string]any {
	t.Helper()
	out := azTestPdp("auth").Evaluate(azRefusalReq(carried))
	ctx, _ := out["context"].(map[string]any)
	adm, _ := ctx["reason_admin"].(map[string]any)
	if adm == nil {
		t.Fatalf("no admin reason: %v", out)
	}
	return adm
}

func TestAuthzenNullActionNamesNull(t *testing.T) {
	adm := azRefusalAdmin(t, `{"action":null}`)
	if r, _ := adm["reason"].(string); !strings.Contains(r, "null (reading 'verb')") {
		t.Errorf("reason: %v", adm["reason"])
	}
}

func TestAuthzenVerifyChecksAreStatuses(t *testing.T) {
	mapped := AuthzenDefaultToAction(azRefusalReq("")) // the proof must name this verb and resource
	digest, err := ParamsDigest(azParamsOf(mapped))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"action": map[string]any{"verb": mapped["verb"], "resource": mapped["resource"], "params_digest": digest}})
	adm := azRefusalAdmin(t, string(b))
	checks, _ := adm["checks"].(map[string]any)
	if checks["wire"] != "fail" {
		t.Errorf("checks: %v (%v)", checks, adm["reason"])
	}
}
