package pca

import "testing"

func TestChainMemoRemembersOnlyAVerifiedChain(t *testing.T) {
	root, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string]any{"stripe": []string{"refund"}}, Now: 1000})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := root.SubAgent(SubAgentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	chain := make([]any, len(sub.Chain))
	for i, h := range sub.Chain {
		chain[i] = h
	}
	memo := NewChainMemo(ChainMemoOptions{})
	compact, err := memo.RememberVerified(chain, sub.PrincipalPublic, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e := CompactChainShapeError(compact); e != "" {
		t.Fatalf("shape: %s", e)
	}
	if memo.Size() != 1 {
		t.Fatalf("size %d", memo.Size())
	}
	v := memo.Resolve(compact, 2000)
	if !v.OK || v.View.N != len(chain) {
		t.Fatalf("resolve: %+v", v)
	}
	// the view feeds the caveat language exactly like the full chain
	full, _ := BoundCaveats(sub.Grant, chain)
	viaView, _ := BoundCaveats(sub.Grant, v.View)
	if len(full) != len(viaView) {
		t.Fatalf("bound caveats differ: %d vs %d", len(full), len(viaView))
	}
	for i := range full {
		if full[i].Hop != viaView[i].Hop || full[i].CapHash != viaView[i].CapHash {
			t.Fatalf("bound caveat %d differs", i)
		}
	}
	// a chain that was never verified is not in the memo, nor is a forgotten one; an expired entry is refused
	other := NewChainMemo(ChainMemoOptions{})
	if v := other.Resolve(compact, 2000); v.OK {
		t.Fatal("an unknown chain resolved")
	}
	if !memo.Forget(compact["hops_root"].(string)) || memo.Resolve(compact, 2000).OK {
		t.Fatal("a forgotten chain resolved")
	}
	if _, err := memo.RememberVerified(chain, sub.PrincipalPublic, 1000, nil); err != nil {
		t.Fatal(err)
	}
	if memo.Resolve(compact, 1000+ChainMemoMaxTTLMs+1).OK {
		t.Fatal("an expired entry resolved")
	}
	// a chain rooted at another issuer does not verify, so it is never remembered
	if _, err := memo.RememberVerified(chain, "not-the-root", 1000, nil); err == nil {
		t.Fatal("a wrongly rooted chain was remembered")
	}
}
