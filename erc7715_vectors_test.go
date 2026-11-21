package pca

// Replays the reference oracle of the ERC-7715 bridge (testdata/ref-erc7715.json.gz). chainId crosses as a decimal string. An
// option the reference String()-coerces is coerced the same way; where that coercion would let a non-string through (an array
// address, a numeric 0 unit count, a non-boolean adjustment flag echoed back) the typed native cannot express it: skipped.

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

func ercStrOpt(m map[string]any, k string, check func(string) bool) (*string, error) {
	v, has := m[k]
	if !has {
		return nil, nil
	}
	s, isStr := v.(string)
	if !isStr {
		s = jsValueString(v)
		if check(s) {
			return nil, vecSkip("the reference String()-coerces a non-string " + k + " that then passes its check")
		}
	}
	return &s, nil
}

func ercGrantToRequest(a []any) (any, error) {
	gm, ok := vecArg(a, 0).(map[string]any)
	if !ok {
		return nil, errors.New("grant envelope is not an object")
	}
	om, ok := vecArg(a, 1).(map[string]any)
	if !ok {
		return nil, errors.New("options are not an object")
	}
	num := func(m map[string]any, k string) float64 {
		f, ok := jsNum(m[k])
		if !ok {
			return math.NaN()
		}
		return f
	}
	g := Erc7715GrantEnvelope{CapMinor: num(gm, "capMinor"), ExpiresAtSec: num(gm, "expiresAtSec")}
	g.GrantDigest, _ = gm["grantDigest"].(string)
	var o Erc7715MapOptions
	addr := k4HexAddr.MatchString
	sa, err := ercStrOpt(om, "sessionAccount", addr)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		u := "undefined"
		sa = &u
	}
	o.SessionAccount = *sa
	if o.From, err = ercStrOpt(om, "from", addr); err != nil {
		return nil, err
	}
	if o.TokenAddress, err = ercStrOpt(om, "tokenAddress", addr); err != nil {
		return nil, err
	}
	bu, err := ercStrOpt(om, "baseUnitsPerMinor", func(s string) bool { return erc7715Dec.MatchString(s) && s == "0" })
	if err != nil {
		return nil, err
	}
	if bu == nil {
		u := "undefined"
		bu = &u
	}
	o.BaseUnitsPerMinor = *bu
	if s, ok := om["chainId"].(string); ok {
		o.ChainID, _ = new(big.Int).SetString(s, 10)
	}
	switch v := om["isAdjustmentAllowed"].(type) {
	case nil:
	case bool:
		o.IsAdjustmentAllowed = &v
	default:
		return nil, vecSkip("the reference echoes a non-boolean isAdjustmentAllowed; the typed native takes a bool")
	}
	return GrantToPermissionRequest(g, o)
}

func ercVerify(a []any) (any, error) {
	g, op := vecArg(a, 0), vecObj(vecArg(a, 3))
	var owner func(string) (string, bool)
	if ow, ok := op["owners"].(map[string]any); ok {
		owner = func(c string) (string, bool) {
			v, has := ow[c]
			s, _ := v.(string)
			return s, has
		}
	}
	r := verifyGrantedPermission(g, vecArg(a, 1), vecArg(a, 2), op["allowedManagers"], owner)
	if gm, ok := g.(map[string]any); ok && r == "expiry_extended" {
		if _, ok := k4SafeInt(gm["expiresAtSec"]); !ok {
			return nil, vecSkip("a grant without a numeric expiresAtSec: the native refuses, the reference compares against undefined and accepts")
		}
	}
	if r == "" {
		return nil, nil
	}
	return r, nil
}

func TestErc7715Vectors(t *testing.T) {
	replayVectors(t, "ref-erc7715.json.gz", map[string]vecFn{
		"grantToPermissionRequest": ercGrantToRequest,
		"supportsRequest":          func(a []any) (any, error) { return SupportsRequest(vecArg(a, 0), vecArg(a, 1)), nil },
		"revokeParams": func(a []any) (any, error) {
			if len(a) == 0 {
				return nil, vecSkip("undefined is not a Go value")
			}
			return RevokeParams(a[0]), nil
		},
		"verifyGrantedPermission": ercVerify,
		"grantDigestOf":           func(a []any) (any, error) { return GrantDigestOf(vecArg(a, 0)) },
	})
}
