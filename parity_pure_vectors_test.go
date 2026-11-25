package pca

import (
	"encoding/json"
	"errors"
)

func ppBudget(v any) TrustBudget {
	b, ok := parseBudget(vecObj(v))
	if !ok {
		panic("not a trust budget")
	}
	return b
}

func ppOrNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ppRefused(err error) map[string]any { return map[string]any{"ok": false, "reason": err.Error()} }

func ppReceipts(v any) ([]ActionReceipt, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var log []ActionReceipt
	return log, json.Unmarshal(b, &log)
}

func ppVerify(v any) ReceiptVerify {
	m := vecObj(v)
	return ReceiptVerify{Allow: m["allow"] == true, Checks: m["checks"]}
}

func ppAt(v any) *int64 {
	if f, ok := jsNum(v); ok {
		n := int64(f)
		return &n
	}
	return nil
}

// ppFns are the entry points of the pure parity corpus other than enforceRequired.
func ppFns() map[string]vecFn {
	str := func(v any) string { s, _ := v.(string); return s }
	return map[string]vecFn{
		"hashCanonical": func(a []any) (any, error) { return HashCanonicalSuite(a[0], str(a[1])) },
		"b64uLen":       func(a []any) (any, error) { return B64uLen(int(jsF(a[0]))), nil },
		"isHashSuite":   func(a []any) (any, error) { return IsHashSuite(a[0]), nil },
		"isCanonicalB64u": func(a []any) (any, error) {
			n := -1
			if f, ok := jsNum(vecArg(a, 1)); ok {
				n = int(f)
			}
			return IsCanonicalB64u(a[0], n), nil
		},
		"strictNumberError":   func(a []any) (any, error) { return ppOrNull(StrictNumberError(jsF(a[0]))), nil },
		"isBudgetAllocCaveat": func(a []any) (any, error) { return IsBudgetAllocCaveat(a[0]), nil },
		"meetAll": func(a []any) (any, error) {
			var ds []string
			for _, x := range a[0].([]any) {
				ds = append(ds, str(x))
			}
			return MeetAll(ds...), nil
		},
		"subBudget": func(a []any) (any, error) {
			sub, err := SubBudget(ppBudget(a[0]), jsF(a[1]))
			if err != nil {
				return ppRefused(err), nil
			}
			return map[string]any{"ok": true, "sub": pdBudgetJSON(sub)}, nil
		},
		"debitConsolidated": func(a []any) (any, error) {
			parent, sub, err := DebitConsolidated(ppBudget(a[0]), ppBudget(a[1]), jsF(a[2]))
			if err != nil {
				return ppRefused(err), nil
			}
			return map[string]any{"ok": true, "parent": pdBudgetJSON(parent), "sub": pdBudgetJSON(sub)}, nil
		},
		"debitConsolidatedPath": func(a []any) (any, error) {
			var path []TrustBudget
			for _, x := range a[0].([]any) {
				path = append(path, ppBudget(x))
			}
			nodes, err := DebitConsolidatedPath(path, jsF(a[1]))
			if err != nil {
				return ppRefused(err), nil
			}
			out := []any{}
			for _, n := range nodes {
				out = append(out, pdBudgetJSON(n))
			}
			return map[string]any{"ok": true, "nodes": out}, nil
		},
		"recharge": func(a []any) (any, error) {
			return pdBudgetJSON(ppBudget(a[0]).Recharge(jsF(a[1]), jsF(a[2]), jsF(a[3]))), nil
		},
		"rechargeFull": func(a []any) (any, error) { return pdBudgetJSON(RechargeFull(jsF(a[1]), jsF(a[2]))), nil },
		"receiptFor": func(a []any) (any, error) {
			return ReceiptFor(str(a[0]), int(jsF(a[1])), vecObj(a[2]), ppVerify(a[3]), ppAt(vecArg(a, 4)))
		},
		"appendReceipt": func(a []any) (any, error) {
			log, err := ppReceipts(a[0])
			if err != nil {
				return nil, err
			}
			out, err := AppendReceipt(log, vecObj(a[1]), ppVerify(a[2]), ppAt(vecArg(a, 3)))
			if out == nil && err == nil {
				out = []ActionReceipt{}
			}
			return out, err
		},
		"verifyReceiptChain": func(a []any) (any, error) {
			log, err := ppReceipts(a[0])
			if err != nil {
				return nil, err
			}
			c := VerifyActionReceiptChain(log)
			if c.OK {
				return map[string]any{"ok": true}, nil
			}
			return map[string]any{"ok": false, "brokenAt": c.BrokenAt, "reason": c.Reason}, nil
		},
		"receiptHead": func(a []any) (any, error) {
			log, err := ppReceipts(a[0])
			return ReceiptHead(log), err
		},
		"parseDiscoveryDocument":    func(a []any) (any, error) { return ParseDiscoveryDocument(a[0]) },
		"parseDiscoveryIntent":      func(a []any) (any, error) { return ParseDiscoveryIntent(a[0]) },
		"acceptsSuite":              func(a []any) (any, error) { return AcceptsSuite(vecObj(a[0]), str(a[1])), nil },
		"detectorPolicyError":       func(a []any) (any, error) { return ppOrNull(DetectorPolicyError(a[0])), nil },
		"detectorReceiptShapeError": func(a []any) (any, error) { return ppOrNull(DetectorReceiptShapeError(a[0])), nil },
		"pcactnCheapClaims": func(a []any) (any, error) {
			m := vecObj(a[0])
			if m == nil {
				return nil, errors.New("not an object")
			}
			check, reason := PcactnCheapClaims(m, str(a[1]), jsF(a[2]))
			if check == "" {
				return nil, nil
			}
			return map[string]any{"check": check, "reason": reason}, nil
		},
		"resolveReversibilityClass": func(a []any) (any, error) {
			plan, _ := vecArg(a, 1).([]any)
			c, _ := ResolveReversibilityClass(vecObj(a[0]), plan, vecArg(a, 2))
			return c, nil
		},
		"agentCaveatContext":  func(a []any) (any, error) { return AgentCaveatContext(vecObj(a[0]), vecObj(vecArg(a, 1))), nil },
		"collectObligations":  func(a []any) (any, error) { return CollectObligations(a[0], vecObj(vecArg(a, 1))), nil },
		"decideLayers":        func(a []any) (any, error) { return DecideLayers(vecObj(a[0]), vecObj(vecArg(a, 1))), nil },
		"decideLayerCeilings": func(a []any) (any, error) { return DecideLayerCeilings(a[0], vecObj(vecArg(a, 1))), nil },
	}
}
