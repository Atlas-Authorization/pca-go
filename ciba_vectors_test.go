package pca

// Replays the reference oracle of the CIBA bridge (testdata/ref-ciba.json.gz). Options travel in the reference's camelCase; a
// JS-typed hostile option the typed API cannot hold maps to NaN (refused like any non-integer) or a refusal. Lifecycles drive a
// broker with a scripted clock; the random auth_req_id is masked as "ID".

import (
	"errors"
	"math"
	"testing"
)

func cibaNumOpt(m map[string]any, k string) *float64 {
	v, has := m[k]
	if !has {
		return nil
	}
	f, ok := jsNum(v)
	if !ok {
		f = math.NaN()
	}
	return &f
}

func cibaOpts(v any) (CibaRequestOptions, error) {
	var o CibaRequestOptions
	m := vecObj(v)
	o.ExpiresInSec, o.Interval = cibaNumOpt(m, "expiresInSec"), cibaNumOpt(m, "interval")
	if m["stepUpScope"] == false {
		f := false
		o.StepUpScope = &f
	}
	if s, ok := m["loginHint"].(string); ok {
		o.LoginHint = &s
	}
	if x, has := m["authReqId"]; has && x != nil {
		s, ok := x.(string)
		if !ok {
			return o, vecSkip("the reference accepts a non-string auth_req_id (its length check reads undefined); the typed native takes a string")
		}
		o.AuthReqID = &s
	}
	if bm, ok := m["bindingMessage"].(map[string]any); ok {
		o.BindingMessage = &CibaBindingMessageOptions{MaxChars: cibaNumOpt(bm, "maxChars"), TokenOnly: bm["tokenOnly"] == true}
	}
	if x, has := m["actsFor"]; has {
		s, ok := x.(string)
		if !ok {
			return o, errors.New("actsFor must be a string")
		}
		o.ActsFor = &s
	}
	return o, nil
}

func cibaSU() map[string]any {
	return map[string]any{"id": "su1", "verb": "stripe.payout", "resource": "acct:1", "params": map[string]any{"amount": 80.0, "currency": "USD", "payee": "bob"},
		"tier": 3.0, "reason": "r", "goalCommit": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", "goal": "pay suppliers", "lineage": map[string]any{}, "r": 0.5, "requestedAt": 1.0}
}

func cibaMask(v any, id string) any {
	switch x := v.(type) {
	case string:
		if id != "" && x == id {
			return "ID"
		}
	case []any:
		for i := range x {
			x[i] = cibaMask(x[i], id)
		}
	case map[string]any:
		for k := range x {
			x[k] = cibaMask(x[k], id)
		}
	}
	return v
}

func cibaBudgetOut(b TrustBudget) map[string]any {
	out := map[string]any{"B": b.B, "tau": b.Tau}
	if b.HasAsOf {
		out["asOf"] = b.AsOf
	}
	return out
}

func cibaLifecycle(a []any) (any, error) {
	kind, _ := vecArg(a, 0).(string)
	t := 1_000_000.0
	now := func() float64 { return t }
	var b CibaBroker
	if kind == "memory" {
		b = NewCibaBroker(now, func(CibaSession) {})
	} else {
		ttl := 100.0
		var err error
		if b, err = NewDurableCibaBroker(NewMemoryApprovalStore(), now, &ttl, nil); err != nil {
			return nil, err
		}
	}
	id := ""
	out := []any{}
	for _, opv := range vecArgList(vecArg(a, 1)) {
		op := vecObj(opv)
		if op["op"] == "now" {
			t, _ = jsNum(op["t"])
			out = append(out, nil)
			continue
		}
		var v any
		var err error
		switch op["op"] {
		case "start":
			su := cibaSU()
			if s, ok := op["stepUp"].(map[string]any); ok {
				su = s
			}
			var o CibaRequestOptions
			if o, err = cibaOpts(op["opts"]); err == nil {
				var r CibaAuthRequest
				if r, err = b.Start(su, o); err == nil {
					id, v = r.AuthReqID, r
				}
			}
		case "poll":
			var st string
			if st, err = b.Poll(id); err == nil {
				v = map[string]any{"status": st}
			}
		case "token":
			v, err = b.Token(id)
		case "resolve":
			d, _ := op["decision"].(string)
			by, _ := op["by"].(string)
			v, err = b.Resolve(id, d, by)
		case "get":
			var s *CibaSession
			if s, err = b.Get(id); err == nil && s != nil {
				v = s
			}
		case "unknown":
			switch op["fn"] {
			case "poll":
				var st string
				if st, err = b.Poll("nope"); err == nil {
					v = map[string]any{"status": st}
				}
			case "token":
				v, err = b.Token("nope")
			case "resolve":
				v, err = b.Resolve("nope", "approve", "x")
			case "get":
				var s *CibaSession
				if s, err = b.Get("nope"); err == nil && s != nil {
					v = s
				}
			}
		}
		if err != nil {
			var skip vecSkip
			if errors.As(err, &skip) {
				return nil, err
			}
			out = append(out, map[string]any{"ok": false})
			continue
		}
		out = append(out, map[string]any{"ok": true, "value": cibaMask(vecJSON(v), id)})
	}
	return out, nil
}

func TestCibaVectors(t *testing.T) {
	replayVectors(t, "ref-ciba.json.gz", map[string]vecFn{
		"cibaActionFromStepUp": func(a []any) (any, error) { return CibaActionFromStepUp(vecObj(vecArg(a, 0))) },
		"asciiForm":            func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return CibaASCIIForm(s), nil },
		"toCibaAuthRequest": func(a []any) (any, error) {
			o, err := cibaOpts(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return ToCibaAuthRequest(vecObj(vecArg(a, 0)), o)
		},
		"requiresCiba": func(a []any) (any, error) {
			r, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("review must be an object")
			}
			return RequiresCiba(r)
		},
		"cibaDecisionToCosign": func(a []any) (any, error) {
			d, _ := vecArg(a, 0).(string)
			bm, pm := vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2))
			var b TrustBudget
			b.B, _ = jsNum(bm["B"])
			b.Tau, _ = jsNum(bm["tau"])
			b.AsOf, b.HasAsOf = jsNum(bm["asOf"])
			var p RiskPolicy
			p.BMax, _ = jsNum(pm["bMax"])
			p.Rho, _ = jsNum(pm["rho"])
			p.Lambda, _ = jsNum(pm["lambda"])
			now, _ := jsNum(vecArg(a, 3))
			nb, cos := CibaDecisionToCosign(d, b, p, now, vecObj(vecArg(a, 4))["full"] == true)
			return map[string]any{"budget": cibaBudgetOut(nb), "cosigned": cos}, nil
		},
		"verifyPingCallback": func(a []any) (any, error) {
			in, fl := vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))
			auth := ""
			if x := in["authorization"]; x != nil {
				auth = jsValueString(x)
			}
			flow := CibaPingFlow{AuthReqID: "\x00absent"}
			if s, ok := fl["authReqId"].(string); ok {
				flow.AuthReqID = s
			}
			if s, ok := fl["clientNotificationToken"].(string); ok {
				flow.ClientNotificationToken = &s
			}
			return VerifyPingCallback(auth, in["body"], flow)
		},
		"lifecycle": cibaLifecycle,
	})
}
