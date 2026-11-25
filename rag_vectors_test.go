package pca

// Replays the pca-rag reference corpus: ACL metadata, policy compilation, principal derivation and the fail-closed document
// filter with its digest-bound decision record. The ordered loader keeps the member order the OpenFGA translator reports in.
//
// Skips: none.

import "testing"

func TestRagVectors(t *testing.T) {
	siemReplay(t, "ref-rag.json.gz", map[string]vecFn{
		"aclsFromMetadata": func(a []any) (any, error) { return RagAclsFromMetadata(vecArg(a, 0), vecArg(a, 1)), nil },
		"compilePolicy":    func(a []any) (any, error) { return RagCompilePolicy(vecArg(a, 0)) },
		"principalFromPCActn": func(a []any) (any, error) {
			return RagPrincipalFromPCActn(vecArg(a, 0), vecObj(vecArg(a, 1)))
		},
		"filterDocuments": func(a []any) (any, error) {
			docs, decision, err := RagFilterDocuments(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), nil)
			if err != nil {
				return nil, err
			}
			return map[string]any{"documents": docs, "decision": decision}, nil
		},
	})
}

func TestRagFailsClosedWithoutACL(t *testing.T) {
	pol := []any{map[string]any{"verb": "can_view", "resource": "document:*"}}
	docs := []any{map[string]any{"id": "d"}}
	out, decision, err := RagFilterDocuments("user:alice", docs, pol, nil)
	if err != nil || len(out) != 0 || decision["droppedIds"].([]any)[0] != "d" {
		t.Fatalf("a document with no ACL must be dropped: %v %v %v", out, decision, err)
	}
}
