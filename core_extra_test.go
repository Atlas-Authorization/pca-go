package pca

import "testing"

func TestMerkleProofVerifiesAgainstTheRoot(t *testing.T) {
	leaves := []any{"a", "b", "c", "d", "e"}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range leaves {
		p, err := MerkleProof(leaves, i)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(root, p, l) {
			t.Errorf("proof %d does not verify", i)
		}
		if VerifyInclusion(root, p, "x") {
			t.Errorf("proof %d verifies a foreign leaf", i)
		}
	}
	if _, err := MerkleProof(leaves, 5); err == nil {
		t.Error("an out-of-range index was accepted")
	}
}

func TestReceiptChainDetectsTampering(t *testing.T) {
	p := map[string]any{"iat": jsNumber(5), "action": map[string]any{"verb": "stripe.refund", "resource": "r1"}}
	log, err := AppendReceipt(nil, p, ReceiptVerify{Allow: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := int64(9)
	if log, err = AppendReceipt(log, p, ReceiptVerify{Allow: false}, &at); err != nil {
		t.Fatal(err)
	}
	if c := VerifyActionReceiptChain(log); !c.OK || ReceiptHead(log) != log[1].Hash {
		t.Fatalf("intact chain: %+v", c)
	}
	log[0].Verb = "stripe.payout"
	if c := VerifyActionReceiptChain(log); c.OK || c.BrokenAt != 0 {
		t.Fatalf("tampered chain: %+v", c)
	}
	if ReceiptHead(nil) != "" {
		t.Error("the head of an empty log is empty")
	}
}

func TestBudgetAlgebra(t *testing.T) {
	parent := TrustBudget{B: 1, Tau: 3}
	if _, err := SubBudget(parent, 2); err == nil {
		t.Error("an allocation above the parent was accepted")
	}
	sub, err := SubBudget(parent, 0.5)
	if err != nil || sub.B != 0.5 || sub.AsOf != 3 {
		t.Fatalf("sub %+v %v", sub, err)
	}
	np, ns, err := DebitConsolidated(parent, sub, 0.25)
	if err != nil || np.B != 0.75 || ns.B != 0.25 {
		t.Fatalf("debit %+v %+v %v", np, ns, err)
	}
	if _, _, err := DebitConsolidated(parent, sub, 0.75); err == nil {
		t.Error("a debit above the sub budget was accepted")
	}
	if _, err := DebitConsolidatedPath([]TrustBudget{{B: 1}, {B: 0.1}}, 0.5); err == nil {
		t.Error("a path with an insufficient node was debited")
	}
}

func TestRequestRegexBudgetBoundsAllDocuments(t *testing.T) {
	req := NewRequestRegexBudget()
	for i := 0; i < RegexRequestScale; i++ {
		doc := NewDocumentRegexBudget(req)
		for j := 0; j < MaxRegexEvaluationsPerDocument; j++ {
			if !doc.Charge("a+", 3) {
				t.Fatalf("document %d evaluation %d refused early", i, j)
			}
		}
		if doc.Charge("a+", 3) {
			t.Fatalf("document %d exceeded its own cap", i)
		}
	}
	if NewDocumentRegexBudget(req).Charge("a+", 3) {
		t.Fatal("the request budget did not bound the documents")
	}
	if req.Refusals() == 0 {
		t.Fatal("the refusal was not counted")
	}
}
