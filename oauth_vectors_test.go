package pca

// Replays the reference oracle of the OAuth / MCP-authorization bridge (testdata/ref-oauth.json.gz).

import (
	"errors"
	"testing"
)

func vecInts(m map[string]any, k string) []int {
	l, ok := m[k].([]any)
	if !ok {
		return nil
	}
	out := make([]int, len(l))
	for i, x := range l {
		f, _ := jsNum(x)
		out[i] = int(f)
	}
	return out
}

func vecPtrStr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok {
		return &s
	}
	return nil
}

func vecPRM(a any) PRMOptions {
	m := vecObj(a)
	ep, _ := m["endpoints"].(map[string]any)
	md, _ := m["metadata"].(map[string]any)
	return PRMOptions{Resource: vecStr(m, "resource"), NotStrict: m["strict"] == false, AuthorizationServers: vecStrs(m, "authorizationServers"),
		BearerMethodsSupported: vecStrs(m, "bearerMethodsSupported"), ResourceDocumentation: vecStr(m, "resourceDocumentation"),
		ScopesSupported: vecStrs(m, "scopesSupported"), ResourceName: vecStr(m, "resourceName"),
		ResourceSigningAlgValuesSupported:  vecStrs(m, "resourceSigningAlgValuesSupported"),
		AuthorizationDetailsTypesSupported: vecStrs(m, "authorizationDetailsTypesSupported"), PcaConfigurationEndpoint: vecStr(m, "pcaConfigurationEndpoint"),
		SignatureSuites: vecStrs(m, "signatureSuites"), PcaVersions: vecInts(m, "pcaVersions"), ActionHeader: vecStr(m, "actionHeader"),
		RequiredChecks: vecStrs(m, "requiredChecks"), Endpoints: ep, TrustedRoots: vecStrs(m, "trustedRoots"), Metadata: md}
}

func vecWWW(a any) WWWAuthOptions {
	m := vecObj(a)
	need, _ := m["pcaNeed"].(map[string]any)
	return WWWAuthOptions{Error: vecPtrStr(m, "error"), ErrorDescription: vecStr(m, "errorDescription"), Scope: vecStr(m, "scope"), PcaNeed: need,
		OmitPca: m["includePca"] == false, PcaChallenge: vecStr(m, "pcaChallenge"), Realm: vecPtrStr(m, "realm"), Hint: vecPtrStr(m, "hint")}
}

func vecStrArg(args []any, i int) string { s, _ := vecArg(args, i).(string); return s }

func TestOAuthBridgeVectors(t *testing.T) {
	replayVectors(t, "ref-oauth.json.gz", map[string]vecFn{
		"resourceIdentifierProblem": func(a []any) (any, error) {
			if p := ResourceIdentifierProblem(a[0]); p != "" {
				return p, nil
			}
			return nil, nil
		},
		"prmPathForResource": func(a []any) (any, error) { return PrmPathForResource(vecStrArg(a, 0)) },
		"prmUrlForResource":  func(a []any) (any, error) { return PrmURLForResource(vecStrArg(a, 0)) },
		"protectedResourceMetadata": func(a []any) (any, error) {
			return ProtectedResourceMetadata(vecPRM(a[0]))
		},
		"oauthDiscoveryHandler": func(a []any) (any, error) { return OAuthDiscoveryHandler(vecPRM(a[0])) },
		"parseProtectedResourceMetadata": func(a []any) (any, error) {
			p := vecObj(vecArg(a, 1))
			return ParsePRM(a[0], vecPtrStr(p, "expectedResource"), p["strict"] == false)
		},
		"wwwAuthenticate": func(a []any) (any, error) { return WWWAuthenticate(vecStrArg(a, 0), vecWWW(vecArg(a, 1))) },
		"mcpUnauthorized": func(a []any) (any, error) { return MCPUnauthorized(vecStrArg(a, 0), vecWWW(vecArg(a, 1))) },
		"upgradeUnauthorizedChallenge": func(a []any) (any, error) {
			r := vecObj(a[0])
			h, err := UpgradeUnauthorizedChallenge(vecStr(r, "wwwAuthenticate"), vecStrArg(a, 1), vecWWW(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			out := map[string]any{}
			for k, v := range r {
				out[k] = v
			}
			out["wwwAuthenticate"] = h
			return out, nil
		},
		"checkResourceIndicator": func(a []any) (any, error) { return CheckResourceIndicator(a[0], vecStrArg(a, 1)) },
		"checkTokenAudience":     func(a []any) (any, error) { return CheckTokenAudience(a[0], vecStrArg(a, 1)) },
		"buildPcaGrantDetail": func(a []any) (any, error) {
			m := vecObj(a[0])
			o := PcaGrantDetailOptions{ChainIDs: vecStrs(m, "chainIds"), ChainRef: vecStr(m, "chainRef"), Locations: vecStrs(m, "locations")}
			if x, has := m["bundleRevision"]; has {
				n, ok := baseI64(x)
				if !ok {
					return nil, errors.New("bundleRevision is not an integer")
				}
				o.BundleRevision = &n
			}
			return BuildPcaGrantDetail(o)
		},
		"pcaGrantRequestParam": func(a []any) (any, error) {
			l, _ := a[0].([]any)
			ds := make([]map[string]any, len(l))
			for i, x := range l {
				ds[i] = vecObj(x)
			}
			return PcaGrantRequestParam(ds), nil
		},
		"authorizePcaGrantToken": func(a []any) (any, error) {
			m := vecObj(a[0])
			return AuthorizePcaGrantToken(m["authorizationDetails"], vecStr(m, "resource"), vecStrs(m, "chainIds"), m["proofVerified"] == true), nil
		},
		"oauthScopeForAction": func(a []any) (any, error) {
			m := vecObj(a[1])
			return OAuthScopeForAction(a[0], vecStr(m, "provider"), vecStrs(m, "granted"), vecStr(m, "resource")), nil
		},
	})
}
