package pca

import "testing"

// g09 mutation kills for revocation_nonmembership.go: every single-term failure of a neighbour proof, the index bound,
// null / malformed neighbours, a missing size and a malformed lower neighbour.

func g09rRoot(t *testing.T, size float64, tree []byte) string {
	t.Helper()
	r, ok := bindRevRoot(size, b64.EncodeToString(tree))
	if !ok {
		t.Fatal("bindRevRoot")
	}
	return r
}

func g09rLeaf(t *testing.T, id string) []byte {
	t.Helper()
	h, err := leafHash(id)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestG09RevLeafProof(t *testing.T) {
	root1 := g09rRoot(t, 1, g09rLeaf(t, "m"))
	proof := func(mut func(m map[string]any)) map[string]any {
		m := map[string]any{"index": jnum(0), "size": jnum(1), "path": []any{}}
		if mut != nil {
			mut(m)
		}
		return m
	}
	if !revLeafOK(root1, 1, "m", proof(nil)) {
		t.Fatal("single-leaf proof")
	}
	for name, mut := range map[string]func(map[string]any){
		"no index":       func(m map[string]any) { delete(m, "index") },
		"no size":        func(m map[string]any) { delete(m, "size") },
		"path not array": func(m map[string]any) { m["path"] = "x" },
		"size mismatch":  func(m map[string]any) { m["size"] = jnum(2) },
		"negative index": func(m map[string]any) { m["index"] = jnum(-1) },
		"index == size":  func(m map[string]any) { m["index"] = jnum(1) },
	} {
		if revLeafOK(root1, 1, "m", proof(mut)) {
			t.Errorf("%s must be refused", name)
		}
	}
	if revLeafOK(root1, 1, "m", "x") {
		t.Error("non-object proof")
	}
}

func TestG09RevNonMembership(t *testing.T) {
	if id, p, present, ok := revNeighbour(map[string]any{"lo": nil}, "lo"); id != "" || p != nil || present || !ok {
		t.Errorf("null neighbour: %q %v %v %v", id, p, present, ok)
	}
	if id, p, present, ok := revNeighbour(map[string]any{"lo": "x"}, "lo"); id != "" || p != nil || !present || ok {
		t.Errorf("malformed neighbour: %q %v %v %v", id, p, present, ok)
	}
	empty, _ := bindRevRoot(0, emptyRevTree())
	if !VerifyNonMembership(empty, map[string]any{"size": jnum(0)}, "x") || VerifyNonMembership(empty, map[string]any{}, "x") || VerifyNonMembership(empty, "x", "x") {
		t.Error("empty set: a size is required")
	}
	// set ["", "b"]: "a" lies between them
	h0, h1 := g09rLeaf(t, ""), g09rLeaf(t, "b")
	root2 := g09rRoot(t, 2, revNodeHash(h0, h1))
	p0 := map[string]any{"index": jnum(0), "size": jnum(2), "path": []any{map[string]any{"side": "R", "hash": b64.EncodeToString(h1)}}}
	p1 := map[string]any{"index": jnum(1), "size": jnum(2), "path": []any{map[string]any{"side": "L", "hash": b64.EncodeToString(h0)}}}
	good := map[string]any{"size": jnum(2), "lo": map[string]any{"id": "", "proof": p0}, "hi": map[string]any{"id": "b", "proof": p1}}
	if !VerifyNonMembership(root2, good, "a") {
		t.Fatal("non-membership of a")
	}
	badLo := map[string]any{"size": jnum(2), "lo": map[string]any{"id": jnum(5), "proof": p0}, "hi": map[string]any{"id": "b", "proof": p1}}
	if VerifyNonMembership(root2, badLo, "a") {
		t.Error("a lower neighbour without a string id must be refused")
	}
	stepNotObj := map[string]any{"index": jnum(0), "size": jnum(2), "path": []any{"x"}}
	if revLeafOK(root2, 2, "", stepNotObj) {
		t.Error("a non-object path step")
	}
}
