package pca

// Replay of the reference corpus for the A2A adapter: tasks, signed Agent Cards, the AP2 payment-mandate envelope, AUTH_REQUIRED
// mapping, extension declaration, per-hop delegation, push tokens, signed task-update receipts, the extended Agent Card, RFC 8785
// canonical bytes and the A2A 1.0 card schema. Every verification case in the corpus is refused BEFORE the verifier (no proof,
// missing chain, wrong root issuer, mandate binding errors). The card signing key is replaced in the corpus by its seed label
// ("$seed") and re-derived here; receipts are signed with the seed sha256("atlas-pca-conformance/" + label).

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"testing"
)

var a2aTestReason = regexp.MustCompile(`^(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): `)

// a2aNorm cuts the reasons that quote the JOSE library at the first colon, as the reference oracle does.
func a2aNorm(r map[string]any) map[string]any {
	if s, ok := r["reason"].(string); ok {
		if m := a2aTestReason.FindStringSubmatch(s); m != nil {
			out := make(map[string]any, len(r))
			for k, v := range r {
				out[k] = v
			}
			out["reason"] = m[1]
			return out
		}
	}
	return r
}

func a2aTestOpts(v any) A2AVerifyOptions {
	m, _ := v.(map[string]any)
	o := A2AVerifyOptions{}
	o.Aud, _ = m["aud"].(string)
	if s, ok := m["expectedRootIssuer"].(string); ok {
		o.ExpectedRootIssuer = &s
	}
	if g, ok := m["grant"].(map[string]any); ok {
		o.Grant = g
	}
	if f, ok := jsNum(m["now"]); ok {
		n := int64(f)
		o.Now = &n
	}
	if b, ok := m["require"].(bool); ok {
		o.Require = &b
	}
	if l, ok := m["humanSignerSet"].([]any); ok {
		o.HumanSignerSet = l
	}
	if cm, ok := m["context"].(map[string]any); ok {
		o.Context = func(any) map[string]any { return cm }
	}
	return o
}

func a2aTestSeed(label any) ([]byte, error) {
	s, ok := label.(string)
	if !ok {
		return nil, errors.New("the label must be a string")
	}
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + s))
	return d[:], nil
}

func a2aTestStrs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func a2aTestChain(a []any) (any, error) {
	l, isL := vecArg(a, 0).([]any)
	if !isL || len(l) == 0 {
		return map[string]any{"ok": false, "code": "empty"}, nil
	}
	o := vecObj(vecArg(a, 1))
	signer, _ := o["signer"].(string)
	task, _ := o["taskId"].(string)
	r := CheckA2AReceiptChain(l, signer, task, a2aTestStrs(o["chainIds"]))
	if !r.OK {
		out := map[string]any{"ok": false, "code": r.Code}
		if r.At >= 0 {
			out["at"] = r.At
		}
		return out, nil
	}
	return map[string]any{"ok": true, "last": l[len(l)-1], "terminal": r.Terminal}, nil
}

func a2aTestFns() map[string]vecFn {
	opts := func(a []any) A2AVerifyOptions {
		o := a2aTestOpts(vecArg(a, 1))
		return o
	}
	return map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"PCA_A2A_EXTENSION_URI": A2APcaExtensionURI, "TASK_STATE_AUTH_REQUIRED": A2ATaskStateAuthRequired,
				"TASK_STATE_INPUT_REQUIRED": A2ATaskStateInputRequired, "A2A_AP2_CONTEXT": A2AAp2Context, "A2A_RECEIPT_DOMAIN": A2AReceiptDomain,
				"RECEIPT_KEY": A2AReceiptKey}, nil
		},
		"jcsBytes": func(a []any) (any, error) {
			b, err := A2AJcsBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return map[string]any{"$bytes": b64.EncodeToString(b)}, nil
		},
		"validateAgentCard1":    func(a []any) (any, error) { return A2AValidateAgentCard1(vecArg(a, 0)), nil },
		"attachPcaToA2ATask":    func(a []any) (any, error) { return A2AAttachPcaToTask(vecArg(a, 0), vecArg(a, 1)) },
		"attachPcaToA2AMessage": func(a []any) (any, error) { return A2AAttachPcaToMessage(vecArg(a, 0), vecArg(a, 1)) },
		"extractPca":            func(a []any) (any, error) { return A2AExtractPca(vecArg(a, 0)), nil },
		"extractPcaFromMessage": func(a []any) (any, error) { return A2AExtractPcaFromMessage(vecArg(a, 0)), nil },
		"verifyA2ATask":         func(a []any) (any, error) { return A2AVerifyTask(vecArg(a, 0), opts(a)) },
		"middleware": func(a []any) (any, error) {
			guard, err := A2AMiddleware(opts(a))
			if err != nil {
				return nil, err
			}
			return guard(vecArg(a, 0))
		},
		"authRequiredStatus": func(a []any) (any, error) { return A2AAuthRequiredStatus(vecArg(a, 0), vecObj(vecArg(a, 1))) },
		"answerMessage":      func(a []any) (any, error) { return A2AAnswerMessage(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) },
		"readAuthRequiredNeed": func(a []any) (any, error) {
			if r := A2AReadAuthRequiredNeed(vecArg(a, 0)); r != nil {
				return r, nil
			}
			return nil, nil
		},
		"isAuthRequired": func(a []any) (any, error) { return A2AIsAuthRequired(vecArg(a, 0)), nil },
		"resumeGate": func(a []any) (any, error) {
			g, err := A2AResumeGateOf(vecObj(vecArg(a, 0)))
			if err != nil || g == "" {
				return nil, err
			}
			return g, nil
		},
		"resumeAuthRequired": func(a []any) (any, error) {
			return A2AResumeAuthRequired(vecArg(a, 0), vecArg(a, 1), a2aTestOpts(vecArg(a, 2)))
		},
		"pcaExtensionDeclaration": func(a []any) (any, error) {
			required := true
			if len(a) > 1 {
				required, _ = a[1].(bool)
			}
			return A2APcaExtensionDeclaration(vecObj(vecArg(a, 0)), required), nil
		},
		"readPcaExtension":    func(a []any) (any, error) { return A2AReadPcaExtension(vecArg(a, 0)), nil },
		"clientOptsIntoPca":   func(a []any) (any, error) { return A2AClientOptsIntoPca(vecArg(a, 0)), nil },
		"checkChainExtension": func(a []any) (any, error) { return A2ACheckChains(vecArg(a, 0)) },
		"chainExtends": func(a []any) (any, error) {
			p, ok1 := vecArg(a, 0).([]any)
			n, ok2 := vecArg(a, 1).([]any)
			if !ok1 || !ok2 {
				return nil, errors.New("chains must be arrays")
			}
			return A2AChainExtends(p, n), nil
		},
		"verifyA2ADelegation": func(a []any) (any, error) {
			l, ok := vecArg(a, 0).([]any)
			if !ok {
				return nil, errors.New("hops must be an array")
			}
			hops := make([]A2ADelegationHop, 0, len(l))
			for _, h := range l {
				o := a2aTestOpts(acpGet(h, "opts"))
				hops = append(hops, A2ADelegationHop{Task: acpGet(h, "task"), Opts: o})
			}
			return A2AVerifyDelegation(hops)
		},
		"pcaPushToken": func(a []any) (any, error) {
			return A2APcaPushToken(vecArg(a, 0), a2aTestStrs(vecArg(a, 1)), vecArg(a, 2))
		},
		"checkPushNotification": func(a []any) (any, error) { return A2ACheckPushNotification(vecArg(a, 0), vecArg(a, 1)) },
		"uniformTaskNotFound":   func([]any) (any, error) { return A2AUniformTaskNotFound(), nil },
		"signTaskReceipt": func(a []any) (any, error) {
			seed, err := a2aTestSeed(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return A2ASignTaskReceipt(seed, vecObj(vecArg(a, 1)))
		},
		"verifyTaskReceipt": func(a []any) (any, error) {
			s, _ := vecArg(a, 1).(string)
			return VerifyA2AReceipt(vecArg(a, 0), s), nil
		},
		"receiptDigest": func(a []any) (any, error) {
			d, ok := A2AReceiptDigest(vecArg(a, 0))
			if !ok {
				return nil, errors.New("no canonical form")
			}
			return d, nil
		},
		"checkReceiptChain": a2aTestChain,
		"mayTriggerNext": func(a []any) (any, error) {
			l, isL := vecArg(a, 0).([]any)
			if !isL {
				return false, nil
			}
			o := vecObj(vecArg(a, 1))
			signer, _ := o["signer"].(string)
			task, _ := o["taskId"].(string)
			return A2AMayTriggerNext(l, signer, task, a2aTestStrs(o["chainIds"])), nil
		},
		"attachReceipt":    func(a []any) (any, error) { return A2AAttachReceipt(vecArg(a, 0), vecArg(a, 1)) },
		"receiptOfPayload": func(a []any) (any, error) { return A2AReceiptOfPayload(vecArg(a, 0)), nil },
		"extendedAgentCard": func(a []any) (any, error) {
			return A2AExtendedAgentCard(vecArg(a, 0), vecObj(vecArg(a, 1)), nil)
		},
		"issueSignedAgentCard": func(a []any) (any, error) {
			a = acpSeedKeys(a).([]any)
			return A2AIssueSignedAgentCard(vecArg(a, 0), vecArg(a, 1), vecObj(vecArg(a, 2)))
		},
		"verifyAgentCard": func(a []any) (any, error) {
			a = acpSeedKeys(a).([]any)
			return a2aNorm(A2AVerifyAgentCard(vecArg(a, 0), vecObj(vecArg(a, 1)))), nil
		},
		"a2aPaymentMandateFromPca": func(a []any) (any, error) { return A2APaymentMandateFromPca(vecArg(a, 0), vecArg(a, 1)) },
		"pcaBindingFromA2APaymentMandate": func(a []any) (any, error) {
			return A2APcaBindingFromPaymentMandate(vecArg(a, 0))
		},
		"verifyA2APaymentMandate": func(a []any) (any, error) {
			r, err := A2AVerifyPaymentMandate(vecArg(a, 0), vecArg(a, 1), a2aTestOpts(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			return a2aNorm(r), nil
		},
	}
}

func TestA2AReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-a2a.json.gz", a2aTestFns())
}
