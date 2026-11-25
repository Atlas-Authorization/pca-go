package pca

// Replays the outbound connection/token vault reference corpus: oauth_scope caveats, the proxy-mode request extractor, header
// checks, release receipts, token refresh over a scripted transport, the envelope-encrypted store and TokenVault scenarios.
// Skips: none (hostile variants whose reference outcome was an untyped runtime error were not recorded).

import (
	"encoding/json"
	"errors"
	"sort"
	"testing"
)

func connErrOut(err error) map[string]any {
	var ve *VaultError
	if !errors.As(err, &ve) {
		return map[string]any{"ok": false, "name": "Error"}
	}
	o := map[string]any{"ok": false, "name": ve.Name, "code": ve.Code}
	if ve.Code != "not_authorized" {
		o["message"] = ve.Message
	}
	if ve.Status != nil {
		o["status"] = jsNumber(*ve.Status)
	}
	if ve.Missing != nil {
		o["missing"] = connAnyList(ve.Missing)
	}
	return o
}

func connStrListOrNil(v any) []string {
	l, ok := connStrList(v)
	if !ok {
		return nil
	}
	return l
}

func connTestFloat(v any, def float64) float64 {
	if f, ok := jsNum(v); ok {
		return f
	}
	return def
}

func connTestConfig(v any) *ProviderConfig { return ProviderConfigFromMap(v) }

// connTestTransport scripts the token endpoint: each call takes the next element (the last repeats) and is logged.
func connTestTransport(script any, log *[]any) ConnectFetch {
	l, ok := script.([]any)
	if !ok {
		return nil
	}
	i := 0
	return func(url string, init map[string]any) (*ConnectResponse, error) {
		*log = append(*log, map[string]any{"url": url, "method": init["method"], "headers": init["headers"], "body": init["body"]})
		if len(l) == 0 {
			return nil, errors.New("empty script")
		}
		idx := i
		if idx > len(l)-1 {
			idx = len(l) - 1
		}
		i++
		r, _ := l[idx].(map[string]any)
		if th, ok := r["throws"]; ok {
			return nil, errors.New(jsValueString(th))
		}
		return &ConnectResponse{
			OK: r["ok"] == true, Status: connTestFloat(r["status"], 0),
			JSON: func() (any, error) {
				if r["jsonThrows"] == true {
					return nil, errors.New("bad json")
				}
				return r["json"], nil
			},
			Text: func() (string, error) {
				if r["textThrows"] == true {
					return "", errors.New("bad text")
				}
				s, _ := r["text"].(string)
				return s, nil
			},
		}, nil
	}
}

func connTestConn(v any) *Connection {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	c := &Connection{}
	if json.Unmarshal(b, c) != nil {
		return nil
	}
	return c
}

func connTestAction(t map[string]any) *ConnectAction {
	up, _ := t["upstream"].(map[string]any)
	a := &ConnectAction{Verb: vecStr(t, "verb"), DefDigest: vecStr(t, "def_digest"), Confirmed: t["confirmed"] == true,
		UpstreamProvider: vecStr(up, "provider"), ScopesMin: connStrListOrNil(up["scopes_min"])}
	if ex, ok := t["extract"].(map[string]any); ok {
		if f, err := HttpExtractor(ex); err == nil {
			a.Extract = f
		}
	}
	return a
}

func connTestVault(args []any) any {
	s := vecObj(vecArg(args, 0))
	op := vecObj(s["opts"])
	now := connTestFloat(s["nowMs"], 0)
	store := NewInMemoryConnectionStore()
	fetchLog, proxyLog, receipts := []any{}, []any{}, []any{}
	f := false
	o := TokenVaultOptions{Strict: &f, Store: store, Now: func() float64 { return now }, Fetch: connTestTransport(s["fetchScript"], &fetchLog),
		InsecureBearerRelease: op["insecureBearerRelease"] == true, InsecureSkipPlanRootCheck: op["insecureSkipPlanRootCheck"] == true}
	if l, ok := op["authorizedPlanRoots"].([]any); ok {
		o.AuthorizedPlanRoots = append([]string{}, connStrListOrNil(l)...)
	}
	if a, ok := op["audience"].(string); ok {
		o.Audience = a
	}
	if _, ok := op["expiryLeewayMs"]; ok {
		x := connTestFloat(op["expiryLeewayMs"], 0)
		o.ExpiryLeewayMs = &x
	}
	if _, ok := op["defaultTokenLifetimeMs"]; ok {
		x := connTestFloat(op["defaultTokenLifetimeMs"], 0)
		o.DefaultTokenLifetimeMs = &x
	}
	if b, ok := op["requireActionBinding"].(bool); ok {
		o.RequireActionBinding = &b
	}
	if uv, has := op["useVerb"]; has {
		if us, ok := uv.(string); ok {
			o.UseVerb = &us
		} else {
			o.NoUseVerb = true
		}
	}
	if d, ok := op["defaultConnectionId"].(string); ok {
		o.DefaultConnectionID = d
	}
	if pm, ok := op["providers"].(map[string]any); ok {
		o.Providers = map[string]*ProviderConfig{}
		for k, v := range pm {
			o.Providers[k] = connTestConfig(v)
		}
	}
	if pp, ok := op["pqPins"].(map[string]any); ok {
		o.PqPins = map[string]string{}
		for k, v := range pp {
			o.PqPins[k], _ = v.(string)
		}
	}
	if _, ok := op["maxProxyResponseBytes"]; ok {
		x := connTestFloat(op["maxProxyResponseBytes"], 0)
		o.MaxProxyResponseBytes = &x
	}
	if op["replay"] == true {
		o.Replay = NewInMemoryPcactnReplayStore(0)
	}
	switch op["revoked"] {
	case "throws":
		o.IsRevoked = func(map[string]any) (bool, error) { return false, errors.New("src down") }
	case "yes", "no":
		yes := op["revoked"] == "yes"
		o.IsRevoked = func(map[string]any) (bool, error) { return yes, nil }
	}
	if table, ok := s["actionsTable"].(map[string]any); ok {
		o.Actions = func(verb string) *ConnectAction {
			if t, ok := table[verb].(map[string]any); ok {
				return connTestAction(t)
			}
			return nil
		}
	}
	if op["proxy"] == true {
		script, _ := s["proxyScript"].([]any)
		pi := 0
		o.ProxyFetch = func(req map[string]any) (map[string]any, error) {
			body := req["body"]
			proxyLog = append(proxyLog, map[string]any{"method": req["method"], "url": req["url"], "headers": req["headers"], "body": body, "redirect": req["redirect"]})
			idx := pi
			if idx > len(script)-1 {
				idx = len(script) - 1
			}
			pi++
			r, _ := script[idx].(map[string]any)
			if r["throws"] == true {
				return nil, errors.New("net")
			}
			return map[string]any{"status": r["status"], "headers": r["headers"], "body": r["body"]}, nil
		}
	}
	if seed, ok := op["receiptSeed"].(string); ok && seed != "" {
		sk, _ := b64.DecodeString(seed)
		fail := op["failingSink"] == true
		o.Receipts = &ReceiptOptions{SecretKey: sk, Sink: func(r map[string]any) error {
			receipts = append(receipts, r)
			if fail {
				return errors.New("sink")
			}
			return nil
		}}
	}
	vault, err := NewTokenVault(o)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	results := []any{}
	rec := func(v any, err error) {
		if err != nil {
			results = append(results, connErrOut(err))
		} else {
			results = append(results, map[string]any{"ok": true, "value": v})
		}
	}
	optStr := func(m map[string]any, k string) *string {
		if s, ok := m[k].(string); ok {
			return &s
		}
		return nil
	}
	calls, _ := s["calls"].([]any)
	for _, ci := range calls {
		c := vecObj(ci)
		a := vecObj(c["args"])
		pc := vecObj(c["pcActn"])
		switch c["op"] {
		case "put":
			po := PutConnectionOptions{AgentID: vecStr(a, "agentId"), Provider: vecStr(a, "provider"), AccessToken: vecStr(a, "accessToken"),
				ConnectionID: optStr(a, "connectionId"), RefreshToken: optStr(a, "refreshToken"), ExpiresAt: connTestFloat(a["expiresAt"], 0),
				Scopes: connStrListOrNil(a["scopes"])}
			au := vecObj(a["authority"])
			po.AuthorityPrincipal, po.AuthorityScopes, po.AuthorityAudience = vecStr(au, "principal"), connStrListOrNil(au["scopes"]), optStr(au, "audience")
			conn, err := vault.PutConnection(po)
			rec(conn, err)
		case "get":
			r, err := vault.GetConnectionToken(pc, vecStr(a, "provider"), optStr(a, "connectionId"), connStrListOrNil(a["scopes"]))
			if err != nil {
				rec(nil, err)
			} else {
				rec(map[string]any{"provider": r.Provider, "connectionId": r.ConnectionID, "accessToken": r.AccessToken, "scopes": connAnyList(r.Scopes),
					"expiresAt": jsNumber(r.ExpiresAt), "refreshed": r.Refreshed}, nil)
			}
		case "proxy":
			var want []string
			if l, has := a["scopes"].([]any); has {
				want = []string{}
				for _, x := range l {
					str, _ := x.(string)
					want = append(want, str)
				}
			}
			r, err := vault.ProxyCallScopes(pc, vecObj(c["request"]), vecStr(a, "provider"), optStr(a, "connectionId"), want)
			rec(r, err)
		case "delete":
			err := vault.DeleteConnection(vecStr(c, "agentId"), vecStr(c, "provider"), optStr(c, "connectionId"))
			rec(nil, err)
		case "now":
			now = connTestFloat(c["now"], now)
		}
	}
	out := []any{}
	for _, k := range sliceOf(s["watch"]) {
		km := vecObj(k)
		g, _ := store.Get(ConnectionKey{vecStr(km, "agentId"), vecStr(km, "provider"), vecStr(km, "connectionId")})
		if g == nil {
			out = append(out, nil)
		} else {
			out = append(out, g)
		}
	}
	return map[string]any{"results": results, "store": out, "receipts": receipts, "fetchCalls": fetchLog, "proxyCalls": proxyLog}
}

func sliceOf(v any) []any { l, _ := v.([]any); return l }

func TestConnectReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-connect-v2.json.gz", vecSeeded(map[string]vecFn{
		"oauthScopeCaveat": func(args []any) (any, error) {
			p, _ := vecArg(args, 0).(string)
			return OAuthScopeCaveat(p, connStrListOrNil(vecArg(args, 1))), nil
		},
		"isOAuthScopeCaveat": func(args []any) (any, error) { return IsOAuthScopeCaveat(vecArg(args, 0)), nil },
		"grantedOAuthScopes": func(args []any) (any, error) {
			p, _ := vecArg(args, 1).(string)
			sc, ok, err := GrantedOAuthScopes(vecArg(args, 0), p)
			if err != nil || !ok {
				return nil, err
			}
			sort.SliceStable(sc, func(i, j int) bool { return utf16Less(sc[i], sc[j]) })
			return connAnyList(sc), nil
		},
		"httpExtractor": func(args []any) (any, error) {
			ex, err := HttpExtractor(vecObj(vecArg(args, 0)))
			if err != nil {
				return nil, err
			}
			return ex(vecObj(vecArg(args, 1)))
		},
		"checkProxyHeaders": func(args []any) (any, error) {
			return CheckProxyHeaders(vecArg(args, 0), connStrListOrNil(vecArg(args, 1)))
		},
		"DEFAULT_PROXY_HEADERS": func(args []any) (any, error) { return connAnyList(DefaultProxyHeaders), nil },
		"outboundRequestDigest": func(args []any) (any, error) {
			m, _ := vecArg(args, 0).(string)
			u, _ := vecArg(args, 1).(string)
			h := map[string]string{}
			for k, v := range vecObj(vecArg(args, 2)) {
				h[k], _ = v.(string)
			}
			var body *string
			if b, ok := vecArg(args, 3).(string); ok {
				body = &b
			}
			return OutboundRequestDigest(m, u, h, body)
		},
		"signReleaseReceipt": func(args []any) (any, error) {
			seed, _ := vecArg(args, 1).(string)
			sk, err := b64.DecodeString(seed)
			if err != nil {
				return nil, err
			}
			return SignReleaseReceipt(vecObj(vecArg(args, 0)), sk)
		},
		"verifyReleaseReceipt": func(args []any) (any, error) { return VerifyReleaseReceipt(vecArg(args, 0), vecArg(args, 1)), nil },
		"receiptActionDigest":  func(args []any) (any, error) { return ReceiptActionDigest(vecObj(vecArg(args, 0))) },
		"refreshConnection": func(args []any) (any, error) {
			c := vecObj(vecArg(args, 0))
			log := []any{}
			rt, _ := c["refreshToken"].(string)
			conn := connTestConn(c["connection"])
			res, err := RefreshConnection(conn, connTestConfig(c["config"]), rt, connStrListOrNil(c["requested"]), connTestTransport(c["script"], &log),
				connTestFloat(c["now"], 0), connTestFloat(c["defaultTokenLifetimeMs"], 0))
			if err != nil {
				o := connErrOut(err)
				o["calls"] = log
				return o, nil
			}
			return map[string]any{"ok": true, "value": map[string]any{"accessToken": res.AccessToken, "expiresAt": jsNumber(res.ExpiresAt), "scopes": connAnyList(res.Scopes),
				"refreshToken": res.RefreshToken}, "calls": log}, nil
		},
		"decryptRecord": func(args []any) (any, error) {
			c := vecObj(vecArg(args, 0))
			inner := NewInMemoryConnectionStore()
			_ = inner.Set(connTestConn(c["record"]))
			ring := map[string][]byte{}
			for id, v := range vecObj(c["ring"]) {
				s, _ := v.(string)
				ring[id], _ = b64.DecodeString(s)
			}
			active, _ := c["active"].(string)
			w, err := NewLocalKeyWrapper(ring, active)
			if err != nil {
				return nil, err
			}
			k := vecObj(c["key"])
			got, err := NewEncryptedConnectionStore(inner, w).Get(ConnectionKey{vecStr(k, "agentId"), vecStr(k, "provider"), vecStr(k, "connectionId")})
			if err != nil {
				return connErrOut(err), nil
			}
			if got == nil {
				return map[string]any{"ok": true, "value": nil}, nil
			}
			return map[string]any{"ok": true, "value": got}, nil
		},
		"vault": func(args []any) (any, error) { return connTestVault(args), nil },
	}))
}
