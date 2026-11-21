package pca

import (
	"context"
	"sync/atomic"
)

// The ambient regex budget. A server installs ONE provider (SetRegexBudgetProvider, typically reading the request's budget out of
// its context or a request-keyed table); every document budget opened with no explicit enclosing request budget then also charges
// the provider's budget, so all regex work of a request is bounded without threading a budget through each call. A budget can also
// travel in a context.Context (ContextWithRegexBudget / RegexBudgetFromContext), the Go analogue of the reference's request scope.

type regexBudgetProvider func() *RegexBudget

var regexProvider atomic.Pointer[regexBudgetProvider]

// SetRegexBudgetProvider installs the ambient request-budget provider; nil uninstalls it. A provider that panics is treated as
// returning no budget.
func SetRegexBudgetProvider(fn func() *RegexBudget) {
	if fn == nil {
		regexProvider.Store(nil)
		return
	}
	p := regexBudgetProvider(fn)
	regexProvider.Store(&p)
}

func ambientRegexBudget() (b *RegexBudget) {
	p := regexProvider.Load()
	if p == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			b = nil
		}
	}()
	return (*p)()
}

type regexBudgetCtxKey struct{}

// ContextWithRegexBudget returns ctx carrying b as the request budget.
func ContextWithRegexBudget(ctx context.Context, b *RegexBudget) context.Context {
	return context.WithValue(ctx, regexBudgetCtxKey{}, b)
}

// RegexBudgetFromContext returns the budget ContextWithRegexBudget stored, or nil.
func RegexBudgetFromContext(ctx context.Context) *RegexBudget {
	b, _ := ctx.Value(regexBudgetCtxKey{}).(*RegexBudget)
	return b
}

// WithRegexBudget runs fn as ONE document. With an explicit budget fn runs inside that budget; otherwise it gets a fresh document
// budget chained to the ambient provider's budget. Hand the budget to the evaluators fn calls (EvaluateConditionTri,
// PredicateMatches, AuthorizeInput.RegexBudget, ...): Go scopes by value, not by a goroutine-local slot.
func WithRegexBudget[T any](fn func(b *RegexBudget) T, budget *RegexBudget) T {
	if budget == nil {
		budget = &regexBudget{parent: ambientRegexBudget()}
	}
	return fn(budget)
}

// ChargeRegex charges one evaluation of the pattern src against a subject of subjectLen UTF-16 units to b. It reports false when
// the evaluation is refused (the caller must not match). A nil b is charged to a fresh single-use document budget (still bounded,
// chained to the ambient provider).
func ChargeRegex(b *RegexBudget, src string, subjectLen int) bool {
	if b == nil {
		b = &regexBudget{parent: ambientRegexBudget()}
	}
	return b.Charge(src, subjectLen)
}

// RegexRefusals is b's refusal count (0 for nil). A before/after difference tells a guard that a match was REFUSED.
func RegexRefusals(b *RegexBudget) int {
	if b == nil {
		return 0
	}
	return b.refusals
}
