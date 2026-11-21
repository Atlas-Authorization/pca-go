package pca

import "testing"

func TestMcpWithPCA(t *testing.T) {
	ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Aud: "rs-test", Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	h := func(map[string]any, any) (map[string]any, error) {
		ran++
		return map[string]any{"content": []any{}}, nil
	}
	if _, err := McpWithPCA(ag, McpGuardSpec{Verb: "files.read", Aud: "x"}, h); err == nil {
		t.Fatal("per-call aud accepted")
	}
	if _, err := McpWithPCA(nil, McpGuardSpec{Verb: "files.read"}, h); err == nil {
		t.Fatal("nil agent accepted")
	}
	w, err := McpWithPCA(ag, McpGuardSpec{Verb: "files.write", Resource: "f"}, h)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := w(map[string]any{}, nil); err == nil && res["isError"] != true {
		t.Fatalf("an ungranted verb ran: %v", res)
	}
	if ran != 0 {
		t.Fatal("handler ran for a denied call")
	}
}
