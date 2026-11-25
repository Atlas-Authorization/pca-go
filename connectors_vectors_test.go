package pca

// Replays the connector catalog reference corpus: manifest validation and digests, the registry, URL variables, PKCE, the authorize
// URL, access-token placement, the manifest-to-vault-provider mapping and code exchange / refresh into a (non-strict) vault.
// Errors are compared as data ({ok:false, name, message, issues?}); a failure that is not a ConnectorError is {ok:false, name:"Error"}.

import (
	"errors"
	"regexp"
	"testing"
)

func cnsErrOut(err error) map[string]any {
	var ce *ConnectorError
	if !errors.As(err, &ce) {
		return map[string]any{"ok": false, "name": "Error"}
	}
	o := map[string]any{"ok": false, "name": ce.Name, "message": ce.Message}
	if ce.Issues != nil {
		o["issues"] = connAnyList(ce.Issues)
	}
	return o
}

func cnsGuard(v any, err error) any {
	if err != nil {
		return cnsErrOut(err)
	}
	return map[string]any{"ok": true, "value": v}
}

func cnsManifestList(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func cnsRegistry(customs any) *ProviderRegistry {
	r := CreateDefaultRegistry()
	for _, m := range sliceOf(customs) {
		_, _ = r.Register(m, RegisterOptions{})
	}
	return r
}

func cnsStrPtr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok {
		return &s
	}
	return nil
}

func cnsRegistryScenario(s map[string]any) any {
	r := CreateDefaultRegistry()
	if s["empty"] == true {
		r = NewProviderRegistry()
	}
	out := []any{}
	for _, oi := range sliceOf(s["ops"]) {
		op := vecObj(oi)
		id, _ := op["id"].(string)
		var v any
		var err error
		switch op["op"] {
		case "register":
			opts := RegisterOptions{}
			if om, ok := op["opts"].(map[string]any); ok {
				if d, ok := om["expectedDigest"].(string); ok {
					opts.ExpectedDigest, opts.HasExpectedDigest = d, true
				}
				opts.Replace = om["replace"] == true
			}
			v, err = r.Register(op["manifest"], opts)
		case "get":
			if m := r.Get(id); m != nil {
				v = m
			}
		case "require":
			v, err = r.Require(id)
		case "has":
			v = r.Has(id)
		case "list":
			v = cnsManifestList(r.List())
		case "ids":
			v = connAnyList(r.IDs())
		default:
			v, err = CatalogDigest(r)
		}
		out = append(out, cnsGuard(v, err))
	}
	return out
}

func cnsExchange(args []any, refresh bool) any {
	c := vecObj(vecArg(args, 0))
	log := []any{}
	store := NewInMemoryConnectionStore()
	now := connTestFloat(c["now"], 0)
	f := false
	vault, _ := NewTokenVault(TokenVaultOptions{Strict: &f, InsecureSkipPlanRootCheck: true, Store: store, Now: func() float64 { return now }})
	b := vecObj(c["bind"])
	a := TokenExchangeArgs{ProviderID: vecStr(c, "providerId"), ClientID: cnsStrPtr(c, "clientId"), ClientSecret: cnsStrPtr(c, "clientSecret"),
		Code: vecStr(c, "code"), RedirectURI: cnsStrPtr(c, "redirectUri"), CodeVerifier: cnsStrPtr(c, "codeVerifier"), RefreshToken: vecStr(c, "refreshToken"),
		Scopes: connStrListOrNil(c["scopes"]), Fetch: connTestTransport(c["script"], &log), Registry: cnsRegistry(c["customs"]),
		Bind: ConnectorBind{Vault: vault, AgentID: vecStr(b, "agentId"), ConnectionID: cnsStrPtr(b, "connectionId"), Principal: vecStr(b, "principal"),
			Scopes: connStrListOrNil(b["scopes"]), Audience: cnsStrPtr(b, "audience")}}
	if _, ok := c["now"]; ok {
		a.Now = &now
	}
	a.Vars, _ = c["vars"].(map[string]any)
	a.ExtraParams, _ = c["extraParams"].(map[string]any)
	var conn *Connection
	var err error
	if refresh {
		conn, err = RefreshTokens(a)
	} else {
		conn, err = ExchangeCode(a)
	}
	var result any
	if err != nil {
		result = cnsErrOut(err)
	} else {
		result = map[string]any{"ok": true, "value": conn}
	}
	cid := "default"
	if p := cnsStrPtr(b, "connectionId"); p != nil {
		cid = *p
	}
	var stored any
	if g, _ := store.Get(ConnectionKey{vecStr(b, "agentId"), vecStr(c, "providerId"), cid}); g != nil {
		stored = g
	}
	return map[string]any{"result": result, "fetchCalls": log, "stored": stored}
}

func cnsCreds(v any) ConnectorCredentials {
	m := vecObj(v)
	c := ConnectorCredentials{ClientID: vecStr(m, "clientId"), ClientSecret: cnsStrPtr(m, "clientSecret")}
	c.Vars, _ = m["vars"].(map[string]any)
	return c
}

var cnsPlaceholderRx = regexp.MustCompile(`\{\w+\}`)

func TestConnectorsReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-connectors.json.gz", map[string]vecFn{
		"validateManifest": func(args []any) (any, error) {
			m, issues := ValidateManifest(vecArg(args, 0))
			if issues != nil {
				return map[string]any{"ok": false, "issues": connAnyList(issues)}, nil
			}
			return map[string]any{"ok": true, "manifest": m}, nil
		},
		"assertManifest": func(args []any) (any, error) {
			m, err := AssertManifest(vecArg(args, 0))
			return cnsGuard(m, err), nil
		},
		"manifestDigest": func(args []any) (any, error) { return ManifestDigest(vecObj(vecArg(args, 0))) },
		"catalog": func(args []any) (any, error) {
			d, err := CatalogDigest(nil)
			if err != nil {
				return nil, err
			}
			var g, n any
			if m := DefaultProviderRegistry().Get("google"); m != nil {
				g = m
			}
			if m := DefaultProviderRegistry().Get("nope"); m != nil {
				n = m
			}
			return map[string]any{"ids": connAnyList(DefaultProviderRegistry().IDs()), "manifests": cnsManifestList(DefaultProviderRegistry().List()), "digest": d, "google": g, "nope": n}, nil
		},
		"registry": func(args []any) (any, error) { return cnsRegistryScenario(vecObj(vecArg(args, 0))), nil },
		"substituteVars": func(args []any) (any, error) {
			url, _ := vecArg(args, 0).(string)
			vars, isMap := vecArg(args, 1).(map[string]any)
			if vecArg(args, 1) == nil && cnsPlaceholderRx.MatchString(url) {
				return map[string]any{"ok": false, "name": "Error"}, nil // the reference reads a member of null
			}
			if !isMap {
				vars = nil
			}
			s, err := SubstituteVars(url, vars)
			return cnsGuard(s, err), nil
		},
		"pkceChallenge": func(args []any) (any, error) {
			v, _ := vecArg(args, 0).(string)
			m, ok := vecArg(args, 1).(string)
			if !ok {
				m = "S256"
			}
			return cnsGuard(PkceChallenge(v, m), nil), nil
		},
		"buildAuthorizeUrl": func(args []any) (any, error) {
			id, _ := vecArg(args, 0).(string)
			r, err := BuildAuthorizeUrl(id, vecObj(vecArg(args, 1)), cnsRegistry(vecArg(args, 2)))
			if err != nil {
				return cnsErrOut(err), nil
			}
			v := map[string]any{"url": r.URL, "state": r.State}
			if r.Pkce != nil {
				v["pkce"] = r.Pkce
			}
			return map[string]any{"ok": true, "value": v}, nil
		},
		"applyAccessToken": func(args []any) (any, error) {
			r, err := ApplyAccessToken(vecObj(vecArg(args, 0)), vecArg(args, 1))
			if err == nil && r == nil {
				return map[string]any{"ok": true, "value": nil}, nil
			}
			return cnsGuard(r, err), nil
		},
		"manifestToProviderConfig": func(args []any) (any, error) {
			id, _ := vecArg(args, 0).(string)
			m := DefaultProviderRegistry().Get(id)
			if m == nil {
				return map[string]any{"ok": false, "name": "Error"}, nil
			}
			c, err := ManifestToProviderConfig(m, cnsCreds(vecArg(args, 1)))
			return cnsGuard(c, err), nil
		},
		"buildVaultProviders": func(args []any) (any, error) {
			in := vecObj(vecArg(args, 0))
			creds := map[string]ConnectorCredentials{}
			for k, v := range in {
				creds[k] = cnsCreds(v)
			}
			out, err := BuildVaultProviders(jsKeys(in), creds, nil)
			return cnsGuard(out, err), nil
		},
		"exchange": func(args []any) (any, error) { return cnsExchange(args, false), nil },
		"refresh":  func(args []any) (any, error) { return cnsExchange(args, true), nil },
	})
}
