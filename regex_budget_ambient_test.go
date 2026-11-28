package pca

import (
	"context"
	"testing"
)

func TestAmbientRegexBudgetProviderChargesDocumentBudgets(t *testing.T) {
	req := NewRequestRegexBudget()
	SetRegexBudgetProvider(func() *RegexBudget { return req })
	defer SetRegexBudgetProvider(nil)
	// 4 documents x 64 evaluations are allowed by the request cap (RegexRequestScale = 4); the 257th is refused.
	ok := 0
	for d := 0; d < 5; d++ {
		doc := NewDocumentRegexBudget(nil)
		for i := 0; i < 64; i++ {
			if ChargeRegex(doc, "a+", 3) {
				ok++
			}
		}
	}
	if ok != 4*64 {
		t.Fatalf("request cap: %d charges allowed, want %d", ok, 4*64)
	}
	if RegexRefusals(req) == 0 {
		t.Fatal("request budget recorded no refusal")
	}
	// provider uninstalled: nothing chains any more
	SetRegexBudgetProvider(nil)
	if !ChargeRegex(NewDocumentRegexBudget(nil), "a+", 3) {
		t.Fatal("unchained document budget refused")
	}
}

func TestWithRegexBudgetAndRefusals(t *testing.T) {
	b := NewDocumentRegexBudget(nil)
	got := WithRegexBudget(func(x *RegexBudget) bool { return x == b }, b)
	if !got {
		t.Fatal("explicit budget not used")
	}
	if !WithRegexBudget(func(x *RegexBudget) bool { return x != nil && x != b }, nil) {
		t.Fatal("nil budget did not open a fresh one")
	}
	if ChargeRegex(b, "(a+)+$[", 1) || RegexRefusals(b) != 1 { // outside the safe subset: refused and counted
		t.Fatal("unsafe pattern not refused")
	}
	if RegexRefusals(nil) != 0 || !ChargeRegex(nil, "a", 1) {
		t.Fatal("nil budget semantics")
	}
	if got := RegexBudgetFromContext(ContextWithRegexBudget(context.Background(), b)); got != b {
		t.Fatal("context round trip")
	}
	SetRegexBudgetProvider(func() *RegexBudget { panic("boom") })
	defer SetRegexBudgetProvider(nil)
	if !ChargeRegex(nil, "a", 1) {
		t.Fatal("panicking provider must read as no budget")
	}
}

func TestIntentExtensionsExported(t *testing.T) {
	if IntentExtensions.IntentBinding == nil || IntentExtensions.IntentV2 == nil || IntentExtensions.FreshAt == nil ||
		IntentExtensions.Wire.Intent == nil || IntentExtensions.Wire.IntentSession == nil || IntentExtensions.Wire.FreshAt == nil {
		t.Fatal("incomplete extension set")
	}
}
