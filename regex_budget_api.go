package pca

// The regex work budget. A per-document budget is opened by every library entry point (decide, evaluate predicates and caveats,
// check prohibitions and contracts); a verdict is therefore a pure function of (document, subject). A server can also open ONE
// request budget per request (NewRequestRegexBudget) and hand it to AuthorizeInput.RegexBudget: every document budget opened
// inside the call also charges it, with RegexRequestScale documents' worth of caps, so N documents in one request cannot exceed
// the request cap. Charging happens before matching and is a pure function of the document and the subject, never of timing.

// NewRequestRegexBudget returns a request-scoped budget with RegexRequestScale documents' worth of regex work.
func NewRequestRegexBudget() *RegexBudget { return &regexBudget{scale: regexRequestScale} }

// NewRequestRegexBudgetFor is NewRequestRegexBudget for a request of the given source (the server's trusted client key): patterns
// first compiled under it count against that source's share of the compiled-regex cache, so one source cannot flush the cache.
func NewRequestRegexBudgetFor(source string) *RegexBudget {
	return &regexBudget{scale: regexRequestScale, source: source, hasSource: true}
}

// NewDocumentRegexBudget returns a fresh per-document budget. A non-nil request budget is charged by every evaluation too.
func NewDocumentRegexBudget(request *RegexBudget) *RegexBudget { return &regexBudget{parent: request} }

// Charge accounts for one evaluation of the regex source src against a subject of subjectLen UTF-16 units. It reports false when
// the evaluation is refused (a pattern outside the safe subset, or a cap exceeded); the caller must then not match.
func (b *regexBudget) Charge(src string, subjectLen int) bool {
	return b.charge(utf16Units(src), subjectLen)
}

// Refusals is the number of evaluations refused so far. A veto or guard must treat a refusal as "could not decide" and fail closed.
func (b *regexBudget) Refusals() int { return b.refusals }
