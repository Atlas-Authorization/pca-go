package pca

// Replays the agent card reference corpus: constants, RFC 8785 bytes, the A2A 1.0 schema check, card build / sign / verify,
// AgentFacts issue / add / verify, the well-known handlers and the registry entry. Keys cross as JWK objects; the committed
// corpus carries no private key material: a private JWK "d" is replaced by the seed label it was derived from (SHA-256 of
// "atlas-pca-conformance/<label>") and the test restores it. Reasons after the first colon of a library refusal are not
// compared (the reference's own normalization); handler bodies are compared as JSON values (a parsed map has no member order).

import (
	"crypto/sha256"
	"regexp"
	"sort"
	"testing"
)

var agentcardReasonRe = regexp.MustCompile(`(?s)^(signature( \d+)? did not verify|could not resolve verification key): .*$`)

// agentcardRestoreSeeds puts the private "d" back into every JWK object that carries a "$seed" label.
func agentcardRestoreSeeds(v any) {
	switch t := v.(type) {
	case map[string]any:
		if label, ok := t["$seed"].(string); ok {
			d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			delete(t, "$seed")
			t["d"] = b64.EncodeToString(d[:])
		}
		for k, x := range t {
			if label, ok := seedLabelOnly(x); ok { // a member kept as a lone seed label (the JWK d)
				d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
				t[k] = b64.EncodeToString(d[:])
				continue
			}
			agentcardRestoreSeeds(x)
		}
	case []any:
		for _, x := range t {
			agentcardRestoreSeeds(x)
		}
	}
}

func agentcardNormReasons(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	fix := func(x map[string]any) {
		if s, ok := x["reason"].(string); ok {
			x["reason"] = agentcardReasonRe.ReplaceAllString(s, "$1")
		}
	}
	fix(m)
	if l, ok := m["attestations"].([]any); ok {
		for _, a := range l {
			if am, ok := a.(map[string]any); ok {
				fix(am)
			}
		}
	}
	return m
}

func agentcardSortedStrings(v any) {
	if l, ok := v.([]any); ok {
		sort.Slice(l, func(i, j int) bool { a, _ := l[i].(string); b, _ := l[j].(string); return a < b })
	}
}

func TestAgentCardVectors(t *testing.T) {
	call := func(f func(args []any) (any, error)) vecFn {
		return func(args []any) (any, error) {
			agentcardRestoreSeeds(args)
			return f(args)
		}
	}
	handler := func(args []any, mk func(any, ...string) (func(string) map[string]any, error)) (any, error) {
		var h func(string) map[string]any
		var err error
		if p, ok := vecArg(args, 1).(string); ok {
			h, err = mk(args[0], p)
		} else {
			h, err = mk(args[0])
		}
		if err != nil {
			return nil, err
		}
		req, _ := vecArg(args, 2).(string)
		if r := h(req); r != nil {
			return r, nil
		}
		return nil, nil
	}
	sameJSON := func(want, got any) bool { return baseCanon(want) == baseCanon(got) }
	norm := func(want, got any) bool {
		return sameJSON(agentcardNormReasons(want), agentcardNormReasons(got))
	}
	hosted := func(want, got any) bool {
		w, g := vecObj(want), vecObj(got)
		if want == nil && got == nil {
			return true // the handler declines the path
		}
		if w == nil || g == nil || !sameJSON(w["status"], g["status"]) || !sameJSON(w["headers"], g["headers"]) {
			return false
		}
		wb, _ := w["body"].(string)
		gb, _ := g["body"].(string)
		wv, err1 := ParseJSONLenient([]byte(wb))
		gv, err2 := ParseJSONLenient([]byte(gb))
		return err1 == nil && err2 == nil && sameJSON(normalizeJSON(wv), normalizeJSON(gv))
	}
	registry := func(want, got any) bool {
		for _, v := range []any{want, got} {
			if m := vecObj(v); m != nil {
				agentcardSortedStrings(m["attestedClaims"])
				agentcardSortedStrings(m["selfAssertedClaims"])
			}
		}
		return sameJSON(want, got)
	}
	replayVectorsCmp(t, "ref-agentcard.json.gz", map[string]vecFn{
		"constants": call(func(args []any) (any, error) {
			return map[string]any{
				"DEFAULT_ALG": AgentCardDefaultAlg, "AGENT_FACTS_CONTEXT": AgentFactsContext, "PCA_ATTESTOR_ID": AgentCardAttestorID,
				"WELL_KNOWN_AGENT_CARD_PATH": AgentCardWellKnownPath, "WELL_KNOWN_AGENT_FACTS_PATH": AgentFactsWellKnownPath,
			}, nil
		}),
		"jcsBytes": call(func(args []any) (any, error) {
			b, err := AgentCardJCS(args[0])
			if err != nil {
				return nil, err
			}
			return map[string]any{"$bytes": b64.EncodeToString(b)}, nil
		}),
		"validateAgentCard1": call(func(args []any) (any, error) { return AgentCardValidate1(args[0]), nil }),
		"buildAgentCard": call(func(args []any) (any, error) {
			return AgentCardBuild(args[0], vecObj(vecArg(args, 1)))
		}),
		"issueSignedAgentCard": call(func(args []any) (any, error) {
			card, _ := args[0].(map[string]any)
			return AgentCardIssueSigned(card, vecArg(args, 1), vecObj(vecArg(args, 2)))
		}),
		"verifyAgentCard": call(func(args []any) (any, error) {
			return AgentCardVerify(args[0], vecObj(vecArg(args, 1)))
		}),
		"issueAgentFacts": call(func(args []any) (any, error) {
			return AgentFactsIssue(args[0], vecObj(vecArg(args, 1)))
		}),
		"addAttestation": call(func(args []any) (any, error) {
			return AgentFactsAddAttestation(args[0], vecObj(vecArg(args, 1)))
		}),
		"verifyAgentFacts": call(func(args []any) (any, error) {
			return AgentFactsVerify(args[0], vecObj(vecArg(args, 1)))
		}),
		"agentCardHandler":  call(func(args []any) (any, error) { return handler(args, AgentCardHandler) }),
		"agentFactsHandler": call(func(args []any) (any, error) { return handler(args, AgentFactsHandler) }),
		"toRegistryEntry": call(func(args []any) (any, error) {
			return AgentCardToRegistryEntry(args[0], vecArg(args, 1))
		}),
	}, map[string]func(want, got any) bool{
		"verifyAgentCard":   norm,
		"verifyAgentFacts":  norm,
		"agentCardHandler":  hosted,
		"agentFactsHandler": hosted,
		"toRegistryEntry":   registry,
	})
}
