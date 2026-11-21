package pca

// Replays the reference oracle of the WebAuthn step-up co-sign (testdata/ref-webauthn.json.gz). Bytes travel as {"$bytes"}
// anywhere in the args. A JS-typed hostile expectation the typed API cannot hold maps to the value the reference ends up
// comparing (a non-string rpId is empty, a null storedSignCount is NaN) or, where not expressible, a skip.

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func waBytes(v any) ([]byte, bool) {
	if !sdjwtIsBytes(v) {
		return nil, false
	}
	b := vcBytes(v)
	if b == nil {
		b = []byte{}
	}
	return b, true
}

// waStepIn maps a step-up input as the reference reads it: bytes, a string, an object; a primitive or an array destructures to
// its own enumerable members (none, or the array indices); null throws.
func waStepIn(v any) (any, error) {
	if b, ok := waBytes(v); ok {
		return b, nil
	}
	switch x := v.(type) {
	case nil:
		return nil, errors.New("Cannot destructure property 'sig' of 'p' as it is null.")
	case string, map[string]any:
		return x, nil
	case []any:
		m := map[string]any{}
		for i, e := range x {
			m[jsNumberString(float64(i))] = e
		}
		return m, nil
	}
	return map[string]any{}, nil
}

func waPayExp(v any) (SpcPaymentExpectation, error) {
	var e SpcPaymentExpectation
	m, ok := v.(map[string]any)
	if !ok {
		return e, errors.New("payment expectation is not an object")
	}
	t, ok := m["total"].(map[string]any)
	if !ok {
		return e, errors.New("Cannot read properties of undefined (reading 'currency')")
	}
	e.Total.Currency, _ = t["currency"].(string)
	e.Total.Value, _ = t["value"].(string)
	top, ok := m["topOrigin"].(string)
	if !ok {
		return e, vecSkip("an expectation without topOrigin: the typed native requires it (refuses), the reference compares against undefined")
	}
	e.TopOrigin = top
	for k, p := range map[string]**string{"payeeName": &e.PayeeName, "payeeOrigin": &e.PayeeOrigin} {
		if x, has := m[k]; has {
			s, ok := x.(string)
			if !ok {
				s = "\x00non-string" // a non-undefined expectation is compared, and matches no string
			}
			*p = &s
		}
	}
	return e, nil
}

func waVerify(a []any) (any, error) {
	am, em := vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))
	var as Assertion
	as.AuthenticatorData, _ = waBytes(am["authenticatorData"])
	as.ClientDataJSON, _ = waBytes(am["clientDataJSON"])
	as.Signature, _ = waBytes(am["signature"])
	if b, ok := waBytes(am["publicKey"]); ok {
		as.PublicKey = b
	} else {
		as.PublicKey = am["publicKey"]
	}
	var e WebAuthnExpectations
	if b, ok := waBytes(em["expectedChallenge"]); ok {
		e.ExpectedChallenge = b
	} else {
		e.ExpectedChallenge = em["expectedChallenge"]
	}
	e.RPID, _ = em["rpId"].(string)
	if l, ok := em["origins"].([]any); ok {
		e.Origins = []string{}
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				s = "\x00non-string" // never equal to a string origin
			}
			e.Origins = append(e.Origins, s)
		}
	}
	e.RequireUV = jsTruthy(em["requireUV"])
	e.RequireLowS = em["requireLowS"] == true
	if x, has := em["storedSignCount"]; has {
		f, ok := jsNum(x)
		if !ok {
			f = math.NaN()
		}
		e.StoredSignCount = &f
	}
	if em["rejectCrossOrigin"] == false {
		f := false
		e.RejectCrossOrigin = &f
	}
	if x, has := em["payment"]; has {
		if x == nil {
			return nil, vecSkip("a null payment expectation is not expressible (the reference fails closed reading it)")
		}
		p, err := waPayExp(x)
		if err != nil {
			var skip vecSkip
			if errors.As(err, &skip) {
				return nil, err
			}
			return nil, vecSkip("a malformed payment expectation is not expressible (the reference fails closed reading it)")
		}
		e.Payment = &p
	}
	calls := []any{}
	if em["hook"] == true {
		e.OnSignCountRegression = func(st, rep float64) {
			calls = append(calls, map[string]any{"storedSignCount": st, "reportedSignCount": rep})
		}
	}
	r := VerifyAssertion(as, e)
	for _, p := range []string{"public key could not be resolved", "verification error (fail closed)"} {
		if strings.HasPrefix(r.Reason, p+":") {
			r.Reason = p
		}
	}
	return map[string]any{"result": r, "hook": calls}, nil
}

func TestWebAuthnVectors(t *testing.T) {
	str := func(v any) (string, error) {
		s, ok := v.(string)
		if !ok {
			return "", errors.New("renderDigest must be a string")
		}
		return s, nil
	}
	replayVectors(t, "ref-webauthn.json.gz", map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"MAX_AUTHENTICATOR_DATA_BYTES": MaxAuthenticatorDataBytes, "MAX_CLIENT_DATA_BYTES": MaxClientDataBytes, "MAX_SIGNATURE_BYTES": MaxSignatureBytes}, nil
		},
		"coseKeyToJwk": func(a []any) (any, error) {
			b, ok := waBytes(vecArg(a, 0))
			if !ok {
				return nil, errors.New("coseKeyToJwk: expected a Uint8Array")
			}
			return CoseKeyToJwk(b)
		},
		"parseAuthenticatorData": func(a []any) (any, error) {
			b, _ := waBytes(vecArg(a, 0))
			p := ParseAuthenticatorData(b)
			if p == nil {
				return nil, nil
			}
			return map[string]any{"rpIdHash": vcBytesOut(p.RPIDHash), "flags": p.Flags, "signCount": p.SignCount}, nil
		},
		"buildStepUpChallenge": func(a []any) (any, error) {
			x, err := waStepIn(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			b, err := BuildStepUpChallenge(x)
			if err != nil {
				return nil, err
			}
			return vcBytesOut(b), nil
		},
		"stepUpChallengeB64u": func(a []any) (any, error) {
			x, err := waStepIn(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return StepUpChallengeB64u(x)
		},
		"buildApprovalChallenge": func(a []any) (any, error) {
			x, err := waStepIn(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			rd, err := str(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			b, err := BuildApprovalChallenge(x, rd)
			if err != nil {
				return nil, err
			}
			return vcBytesOut(b), nil
		},
		"approvalChallengeForActn": func(a []any) (any, error) {
			x, err := waStepIn(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			rd, err := str(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return ApprovalChallengeForActn(x, rd)
		},
		"spcPaymentError": func(a []any) (any, error) {
			e, err := waPayExp(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			rp, _ := vecArg(a, 2).(string)
			if r := SpcPaymentError(vecArg(a, 0), e, rp); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"verifyAssertion": waVerify,
	})
}
