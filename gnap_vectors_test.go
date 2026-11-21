package pca

// Replays the reference oracle of the GNAP bridge (testdata/ref-gnap.json.gz). Seeds and secrets cross as base64url text and a
// {"$bytes": ...} value as raw bytes. JS-typed options are mapped onto the typed Go options here; the few shapes a typed Go
// option cannot carry (an explicit null where a member is optional, a key pair whose public half is not its secret's) are
// skipped. interactionScenario runs the authorization-server state machine and redacts the random values, as the reference
// runner does.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"
)

func gnapUnbytes(x any) any {
	if m, ok := x.(map[string]any); ok && len(m) == 1 {
		if s, ok := m["$bytes"].(string); ok {
			b, _ := base64.RawURLEncoding.DecodeString(s)
			return b
		}
	}
	return x
}

func gnapSeed(v any) (*KeyPair, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("secret is not a seed")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return KeyPairFromSeed(b)
}

func gnapAccessList(v any) []any { l, _ := v.([]any); return l }

func gnapMaps(v any) ([]map[string]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not an array")
	}
	out := make([]map[string]any, len(l))
	for i, x := range l {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, errors.New("not an object")
		}
		out[i] = m
	}
	return out, nil
}

func gnapVerifyOpts(v any) GnapVerifyOptions {
	var o GnapVerifyOptions
	m := vecObj(v)
	if e, has := m["expectedRootIssuer"]; has {
		s, _ := e.(string) // null: an issuer no chain has, as the reference compares against null
		o.ExpectedRootIssuer = &s
	}
	if p, ok := m["pqPins"].(map[string]any); ok {
		o.PqPins = map[string]string{}
		for k, x := range p {
			o.PqPins[k], _ = x.(string)
		}
	}
	return o
}

func gnapFloor(v any) int64 { f, _ := jsNum(v); return int64(math.Floor(f)) }

var gnapBadJSON = regexp.MustCompile(`(?s)(bad-json) \(.*\)$`)

func gnapTime(ms float64) time.Time { return time.Unix(0, int64(ms*1e6)) }

func TestGnapVectors(t *testing.T) {
	str := func(v any) string { s, _ := v.(string); return s }
	fns := map[string]vecFn{
		"constants": func(a []any) (any, error) {
			return map[string]any{"GNAP_GRANT_CAVEAT": GnapGrantCaveat, "GNAP_ACCESS_CAVEAT": GnapAccessCaveat, "MAX_DETACHED_JWS_CHARS": GnapMaxDetachedJWSChars,
				"START_MODES": GnapStartModes, "FINISH_METHODS": GnapFinishMethods, "HASH_METHODS": GnapHashMethods}, nil
		},
		"AGENT_GNAP_PROFILE": func(a []any) (any, error) { return AgentGnapProfile(), nil },
		"gnapActionResource": func(a []any) (any, error) { return GnapActionResource(str(a[0]), str(a[1])), nil },
		"normalizeAccess":    func(a []any) (any, error) { return GnapNormalizeAccess(a[0]) },
		"accessToPredicates": func(a []any) (any, error) { return GnapAccessToPredicates(vecObj(a[0])), nil },
		"accessContains":     func(a []any) (any, error) { return GnapAccessContains(vecObj(a[0]), vecObj(a[1])), nil },
		"accessWithin":       func(a []any) (any, error) { return GnapAccessWithin(gnapAccessList(a[0]), vecObj(a[1])), nil },
		"clampAccess": func(a []any) (any, error) {
			g, d := GnapClampAccess(gnapAccessList(a[0]), gnapAccessList(a[1]))
			return map[string]any{"granted": g, "dropped": d}, nil
		},
		"resolveHolder": func(a []any) (any, error) {
			if len(a) > 1 {
				return GnapResolveHolder(a[0], a[1])
			}
			return GnapResolveHolder(a[0])
		},
		"holderJwk": func(a []any) (any, error) { return GnapHolderJwk(str(a[0])), nil },
		"grantRequestToCapability": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 1))
			var o GnapGrantOptions
			if s, has := m["issuerSecret"]; has {
				k, err := gnapSeed(s)
				if err != nil {
					return nil, err
				}
				o.IssuerSecret = k
			}
			o.IssuerPublic = str(m["issuerPublic"])
			o.Parent = m["parent"]
			if c, ok := m["issuerChain"].([]any); ok {
				o.IssuerChain = c
			}
			o.NoClamp = m["clampToIssuer"] == false
			o.Holder, o.HasHolder = m["holder"]
			o.Interacted = m["interacted"] == true
			if n, has := m["now"]; has {
				o.NowMs = gnapFloor(n)
			}
			o.Goal = str(m["goal"])
			o.RiskPolicy, _ = m["riskPolicy"].(map[string]any)
			o.AgentBinding, _ = m["agentBinding"].(map[string]any)
			o.Salt = str(m["salt"])
			return GnapGrantRequestToCapability(a[0], o)
		},
		"grantedAccessOf":     func(a []any) (any, error) { return GnapGrantedAccessOf(a[0]) },
		"authorizeGnapAction": func(a []any) (any, error) { return GnapAuthorizeAction(a[0], a[1], gnapVerifyOpts(vecArg(a, 2))) },
		"encodeBoundToken": func(a []any) (any, error) {
			if len(gnapAccessList(a[0])) == 1 && vecObj(gnapAccessList(a[0])[0])["z"] != nil {
				return nil, vecSkip("member order of a non-capability object (Go maps carry none)")
			}
			return GnapEncodeBoundToken(gnapAccessList(a[0]))
		},
		"capabilityToGrantResponse": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 1))
			var o GnapResponseOptions
			for _, x := range m {
				if x == nil {
					return nil, vecSkip("an explicit null option (absent and null are one in the typed options)")
				}
			}
			if e, has := m["expiresIn"]; has {
				n := gnapFloor(e)
				o.ExpiresIn = &n
			}
			o.Bearer = m["bearer"] == true
			if s, ok := m["instanceId"].(string); ok {
				o.InstanceID = &s
			}
			if s, ok := m["manageUri"].(string); ok {
				o.ManageURI = &s
			}
			o.Continue, _ = m["continue"].(map[string]any)
			return GnapCapabilityToGrantResponse(a[0], o)
		},
		"verifyGnapToken": func(a []any) (any, error) { return GnapVerifyToken(a[0], gnapVerifyOpts(vecArg(a, 1))), nil },
		"gnapContentDigest": func(a []any) (any, error) {
			d, err := GnapContentDigest(gnapUnbytes(a[0]))
			return map[string]any{"$bytes": b64.EncodeToString(d)}, err
		},
		"gnapContentDigestAbsent": func(a []any) (any, error) {
			d, err := GnapContentDigest(GnapNoContent)
			return map[string]any{"$bytes": b64.EncodeToString(d)}, err
		},
		"signGnapRequest": func(a []any) (any, error) {
			m := vecObj(a[0])
			key := vecObj(m["key"])
			kp, err := gnapSeed(key["secretKey"])
			if err != nil {
				return nil, err
			}
			if kp.Public != key["publicKey"] {
				return nil, vecSkip("a key pair whose public half is not its secret's")
			}
			args := GnapSignArgs{Key: kp, URI: str(m["uri"]), Body: GnapNoContent}
			if b, has := m["body"]; has {
				args.Body = gnapUnbytes(b)
			}
			h, ok := m["htm"].(string)
			if !ok {
				return nil, errors.New("htm is not a string")
			}
			args.Htm = h
			if c, has := m["created"]; has {
				f, _ := jsNum(c)
				args.Created = &f
			}
			if k, has := m["kid"]; has {
				s, ok := k.(string)
				if !ok {
					return nil, vecSkip("a non-string kid")
				}
				args.Kid = &s
			}
			if v, has := m["accessTokenValue"]; has {
				s := jsValueString(v)
				args.AccessTokenValue = &s
			}
			return GnapSignRequest(args)
		},
		"verifyGnapRequest": func(a []any) (any, error) {
			m := vecObj(a[0])
			seen := []any{}
			args := GnapVerifyRequestArgs{DetachedJWS: m["detachedJws"], Holder: m["holder"], Htm: m["htm"], URI: m["uri"], Body: GnapNoContent,
				ReplayUnchecked: m["replayCheck"] == "unchecked"}
			if b, has := m["body"]; has {
				args.Body = gnapUnbytes(b)
			}
			if n, has := m["now"]; has {
				f, _ := jsNum(n)
				args.Now = gnapTime(f)
			}
			if x, has := m["maxAgeSec"]; has {
				f, _ := jsNum(x)
				args.MaxAgeSec = &f
			}
			if v, has := m["accessTokenValue"]; has {
				s := jsValueString(v)
				args.AccessTokenValue = &s
			}
			mode := str(m["seenProofMode"])
			if mode != "" {
				args.SeenProof = func(id string, exp float64) (bool, error) {
					seen = append(seen, []any{id, jsNumber(exp)})
					switch mode {
					case "fresh":
						return false, nil
					case "throws":
						return false, errors.New("store down")
					}
					return true, nil // replayed, or a store answering nothing
				}
			}
			r, err := GnapVerifyRequest(args)
			if err != nil {
				return nil, err
			}
			if s, ok := r["reason"].(string); ok {
				r["reason"] = gnapBadJSON.ReplaceAllString(s, "$1")
			}
			return map[string]any{"result": r, "seen": seen}, nil
		},
		"gnapRequestRequiresStepUp": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 1))
			chain, _ := m["issuerChain"].([]any)
			return GnapRequestRequiresStepUp(a[0], chain, m["tier"])
		},
		"beginGnapContinuation": func(a []any) (any, error) { return GnapBeginContinuation(vecObj(a[0])), nil },
		"gnapStepUpShare": func(a []any) (any, error) {
			k, err := gnapSeed(a[2])
			if err != nil {
				return nil, err
			}
			return GnapStepUpShare(vecObj(a[0]), str(a[1]), k, a[3], a[4])
		},
		"completeGnapContinuation": func(a []any) (any, error) {
			m := vecObj(a[0])
			var c GnapContinuationArgs
			var err error
			c.Grant = vecObj(m["grant"])
			if c.Chain, err = gnapMaps(m["chain"]); err != nil {
				return nil, err
			}
			if c.Plan, err = gnapMaps(m["plan"]); err != nil {
				return nil, err
			}
			c.NodeID, c.Aud, c.Params, c.SignerSet, c.T = str(m["nodeId"]), str(m["aud"]), m["params"], m["signerSet"], m["t"]
			c.Counter = gnapFloor(m["counter"])
			if n, has := m["now"]; has {
				c.NowMs = gnapFloor(n)
			}
			if n, has := m["ttlMs"]; has {
				c.TtlMs = gnapFloor(n)
			}
			if c.AgentLeaf, err = gnapSeed(m["agentLeafSecret"]); err != nil {
				return nil, err
			}
			cs, ok := m["cosignSecrets"].([]any)
			if !ok {
				return nil, errors.New("cosignSecrets is not an array")
			}
			for _, x := range cs {
				k, err := gnapSeed(vecObj(x)["secret"])
				if err != nil {
					return nil, err
				}
				c.Cosigns = append(c.Cosigns, GnapCosign{Role: str(vecObj(x)["role"]), Key: k})
			}
			return GnapCompleteContinuation(c)
		},
		"callbackUriOk":           func(a []any) (any, error) { return GnapCallbackURIOk(a[0]), nil },
		"validateInteractRequest": func(a []any) (any, error) { return GnapValidateInteractRequest(a[0]), nil },
		"interactionHash": func(a []any) (any, error) {
			if vecObj(a[0]) == nil {
				return nil, errors.New("not an object")
			}
			return GnapInteractionHash(vecObj(a[0]))
		},
		"verifyInteractionHash": func(a []any) (any, error) { return GnapVerifyInteractionHash(a[0], vecObj(a[1])) },
		"acceptFinish":          func(a []any) (any, error) { return GnapAcceptFinish(a[0], vecObj(a[1])) },
		"newUserCode": func(a []any) (any, error) {
			f, _ := jsNum(a[0])
			return GnapNewUserCode(int(f))
		},
		"accessToNeeds":       func(a []any) (any, error) { return GnapAccessToNeeds(gnapAccessList(a[0])) },
		"interactionScenario": func(a []any) (any, error) { return gnapRunScenario(vecObj(a[0])), nil },
	}
	replayVectors(t, "ref-gnap.json.gz", vecSeeded(fns))
}

func gnapRedact(v any, toks [][2]string) any {
	switch t := v.(type) {
	case string:
		for _, kt := range toks {
			if kt[0] != "" {
				t = strings.ReplaceAll(t, kt[0], kt[1])
			}
		}
		return t
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = gnapRedact(x, toks)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = gnapRedact(x, toks)
		}
		return out
	}
	return v
}

var gnapHashParam = regexp.MustCompile(`[?&]hash=([^&]+)`)

// gnapRunScenario is the reference runner: a scripted AS with a manual clock (seconds from 1000).
func gnapRunScenario(s map[string]any) []any {
	clock := 1000.0
	opts := vecObj(s["opts"])
	ge, ok := opts["grantEndpoint"].(string)
	if !ok {
		ge = "https://as.example/tx"
	}
	so := GnapInteractionServerOptions{GrantEndpoint: ge, Supports: vecStrs(opts, "supports"),
		RedirectURI: func(id string) string { return "https://as.example/i/" + id }, Now: func() float64 { return clock }}
	if jsTruthy(opts["app"]) {
		so.AppURI = func(id string) string { return "app://as/" + id }
	}
	if u, ok := opts["userCodeUri"].(string); ok {
		so.UserCodeURI = u
	}
	if x, has := opts["ttlSec"]; has {
		f, _ := jsNum(x)
		so.TTLSec = &f
	}
	srv := NewGnapInteractionServer(so)
	v := map[string]string{}
	var started [][3]string
	var lastReq any
	sub := func(x any) string {
		s, _ := x.(string)
		if !strings.HasPrefix(s, "$") {
			return s
		}
		code := v["code"]
		switch s {
		case "$code:lower":
			return strings.ToLower(code)
		case "$code:spaced":
			if len(code) < 4 {
				return code + " - "
			}
			return code[:4] + " - " + code[4:]
		}
		if x, ok := v[s[1:]]; ok {
			return x
		}
		return s
	}
	trace := []any{}
	for _, stv := range s["steps"].([]any) {
		st := vecObj(stv)
		op := str0(st["op"])
		var value any
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("panic")
				}
			}()
			switch op {
			case "start":
				lastReq = st["req"]
				it, res, err := srv.Start(st["req"])
				if err != nil {
					return err
				}
				v["id"], v["code"], v["asnonce"] = it.ID, it.UserCode, ""
				if it.Finish != nil {
					v["asnonce"] = it.Finish.AsNonce
				}
				started = append(started, [3]string{v["id"], v["code"], v["asnonce"]})
				value = map[string]any{"interaction": vecJSON(it), "response": res}
			case "lookup":
				if it := srv.LookupUserCode(sub(st["code"])); it != nil {
					value = it
				}
			case "approve":
				r, err := srv.Approve(sub(st["id"]))
				if err != nil {
					return err
				}
				v["ref"] = str0(r["interactRef"])
				it := srv.Get(v["id"])
				var m any
				if f := vecObj(r["finish"]); f != nil {
					if f["method"] == "push" {
						m = vecObj(f["body"])["hash"]
					} else if g := gnapHashParam.FindStringSubmatch(str0(f["url"])); g != nil {
						m = g[1]
					}
				}
				v["hash"] = str0(m)
				var expected any
				if it != nil && it.Finish != nil {
					e, err := GnapInteractionHash(map[string]any{"clientNonce": it.Finish.ClientNonce, "asNonce": it.Finish.AsNonce, "interactRef": r["interactRef"],
						"grantEndpoint": it.GrantEndpoint, "hashMethod": it.Finish.HashMethod})
					if err != nil {
						return err
					}
					expected = e
				}
				value = map[string]any{"result": r, "hashOk": m == expected}
			case "consume":
				it, err := srv.Consume(sub(st["ref"]))
				if err != nil {
					return err
				}
				value = it
			case "finalize":
				srv.Finalize(sub(st["id"]))
			case "get":
				if it := srv.Get(sub(st["id"])); it != nil {
					value = it
				}
			case "advance":
				f, _ := jsNum(st["sec"])
				clock += f
				value = clock
			case "accept":
				fin, ok := vecObj(lastReq)["finish"].(map[string]any)
				if !ok {
					return errors.New("the last request has no finish")
				}
				ctx := map[string]any{"clientNonce": fin["nonce"], "asNonce": v["asnonce"], "grantEndpoint": ge}
				if hm, has := fin["hash_method"]; has && jsTruthy(hm) {
					ctx["hashMethod"] = hm
				}
				r, err := GnapAcceptFinish(map[string]any{"hash": sub(st["hash"]), "interact_ref": sub(st["ref"])}, ctx)
				if err != nil {
					return err
				}
				value = r
			}
			return nil
		}()
		if err != nil {
			code := "other"
			var ce *CodedError
			if errors.As(err, &ce) {
				code = ce.Code
			}
			trace = append(trace, map[string]any{"op": op, "ok": false, "code": code})
			continue
		}
		toks := [][2]string{{v["ref"], "<REF>"}, {v["hash"], "<HASH>"}, {v["asnonce"], "<ASNONCE>"}, {v["id"], "<ID>"}, {v["code"], "<CODE>"}}
		// an earlier started interaction (number n, from 0) is redacted as <ID:n>, <CODE:n> and <ASNONCE:n>; the latest keeps the bare names
		for n, a := range started[:max(len(started)-1, 0)] {
			toks = append(toks, [2]string{a[0], fmt.Sprintf("<ID:%d>", n)}, [2]string{a[1], fmt.Sprintf("<CODE:%d>", n)}, [2]string{a[2], fmt.Sprintf("<ASNONCE:%d>", n)})
		}
		trace = append(trace, map[string]any{"op": op, "ok": true, "value": gnapRedact(vecJSON(value), toks)})
	}
	return trace
}

func str0(v any) string { s, _ := v.(string); return s }
