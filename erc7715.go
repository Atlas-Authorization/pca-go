package pca

// ERC-7715 (wallet_grantPermissions) bridge: a PCA grant envelope becomes a token-allowance permission request for a session
// account, a wallet's supported-permissions answer is matched against it, and the wallet's granted permission is verified never
// to exceed the request or the grant (VerifyGrantedPermission, in k4.go).

import (
	"errors"
	"math"
	"math/big"
	"regexp"
	"strings"
)

var erc7715Dec = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// Erc7715GrantEnvelope is the grant side of the mapping: the cap in minor units and the expiry (epoch seconds).
type Erc7715GrantEnvelope struct {
	GrantDigest            string
	CapMinor, ExpiresAtSec float64
}

// Erc7715MapOptions: ChainID > 0; SessionAccount / From / TokenAddress are 0x-prefixed 20-byte hex addresses (TokenAddress set =
// an ERC-20 allowance, else native); BaseUnitsPerMinor is a positive decimal integer string; IsAdjustmentAllowed nil = true.
type Erc7715MapOptions struct {
	ChainID             *big.Int
	SessionAccount      string
	TokenAddress, From  *string
	BaseUnitsPerMinor   string
	IsAdjustmentAllowed *bool
}

func erc7715SafePos(f float64) bool { return f == math.Trunc(f) && f > 0 && f <= 1<<53-1 }

// GrantToPermissionRequest maps a grant to an ERC-7715 permission request: allowance = capMinor * baseUnitsPerMinor (hex), one
// expiry rule at the grant's expiry.
func GrantToPermissionRequest(g Erc7715GrantEnvelope, o Erc7715MapOptions) (map[string]any, error) {
	if !erc7715SafePos(g.CapMinor) || !erc7715SafePos(g.ExpiresAtSec) {
		return nil, errors.New("grantToPermissionRequest: bad envelope")
	}
	if !k4HexAddr.MatchString(o.SessionAccount) || o.From != nil && !k4HexAddr.MatchString(*o.From) || o.TokenAddress != nil && !k4HexAddr.MatchString(*o.TokenAddress) {
		return nil, errors.New("grantToPermissionRequest: bad address")
	}
	if !erc7715Dec.MatchString(o.BaseUnitsPerMinor) || o.BaseUnitsPerMinor == "0" {
		return nil, errors.New("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string")
	}
	if o.ChainID == nil || o.ChainID.Sign() <= 0 {
		return nil, errors.New("grantToPermissionRequest: bad chain")
	}
	units, _ := new(big.Int).SetString(o.BaseUnitsPerMinor, 10)
	allowance := "0x" + new(big.Int).Mul(big.NewInt(int64(g.CapMinor)), units).Text(16)
	adj := true
	if o.IsAdjustmentAllowed != nil {
		adj = *o.IsAdjustmentAllowed
	}
	perm := map[string]any{"type": "native-token-allowance", "isAdjustmentAllowed": adj, "data": map[string]any{"allowance": allowance}}
	if o.TokenAddress != nil {
		perm = map[string]any{"type": "erc20-token-allowance", "isAdjustmentAllowed": adj, "data": map[string]any{"tokenAddress": *o.TokenAddress, "allowance": allowance}}
	}
	req := map[string]any{"chainId": "0x" + o.ChainID.Text(16), "to": o.SessionAccount, "permission": perm,
		"rules": []any{map[string]any{"type": "expiry", "data": map[string]any{"timestamp": g.ExpiresAtSec}}}}
	if o.From != nil {
		req["from"] = *o.From
	}
	return req, nil
}

// SupportsRequest: whether a wallet's supported-permissions answer (wallet_getSupportedExecutionPermissions, JSON) covers the
// request's permission type, chain (case-insensitive) and every rule type. Any malformed answer is false.
func SupportsRequest(supported any, req any) bool {
	rm, ok := req.(map[string]any)
	if !ok || rm["permission"] == nil {
		return false
	}
	pm, _ := rm["permission"].(map[string]any)
	sm, ok := supported.(map[string]any)
	if !ok {
		return false
	}
	s, _ := sm[jsMemberString(pm, "type")].(map[string]any)
	chains, ok := s["chainIds"].([]any)
	want, isStr := rm["chainId"].(string)
	if !ok || !isStr {
		return false
	}
	found := false
	for _, c := range chains {
		cs, ok := c.(string)
		if !ok {
			return false // the reference lower-cases every entry
		}
		found = found || strings.ToLower(cs) == strings.ToLower(want)
	}
	if !found {
		return false
	}
	rt := s["ruleTypes"]
	if rt == nil {
		rt = s["rulesTypes"]
	}
	rts, rtOK := rt.([]any)
	rules := []any{}
	if v := rm["rules"]; v != nil {
		if rules, ok = v.([]any); !ok {
			return false
		}
	}
	for _, r := range rules {
		if r == nil || !rtOK {
			return false
		}
		rmap, _ := r.(map[string]any)
		t, has := rmap["type"]
		hit := false
		for _, x := range rts {
			hit = hit || has && jsStrictEqualScalar(x, t)
		}
		if !hit {
			return false
		}
	}
	return true
}

// jsStrictEqualScalar is === over JSON values: scalars by value, objects and arrays never (identity).
func jsStrictEqualScalar(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	}
	fa, ok1 := jsNum(a)
	fb, ok2 := jsNum(b)
	return ok1 && ok2 && fa == fb
}

// RevokeParams are the wallet_revokeExecutionPermission params for a granted permission's context.
func RevokeParams(context any) map[string]any { return map[string]any{"permissionContext": context} }

// GrantDigestOf is the grant digest a permission context is bound to.
func GrantDigestOf(grant any) (string, error) { return HashCanonical(grant) }
