package pca

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// Replay of the Azure MAA key trust against the reference (ref-attest-maa): the guarded certs fetch, the JWKS evaluation, the
// rotation-safe trust store, multi-vantage corroboration, the durable store adapter and construction. Long strings of the corpus
// live in its blob table. Every case is replayed. A refusal is compared by its code AND its reason text; a rejected key by its kid
// and its reason (only text that comes from the reference's certificate library, which has no counterpart here, is compared by
// presence). The built-in pins and the constants are part of the same corpus.

func mvBlobs(t *testing.T, file string) map[string]any {
	t.Helper()
	f, err := os.Open(vecCorpusPath(file))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Blobs map[string]any `json:"blobs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Blobs
}

func mvStrs(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func mvJwks(v any) *MaaJwks {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := &MaaJwks{}
	keys, _ := m["keys"].([]any)
	for _, k := range keys {
		km, _ := k.(map[string]any)
		jk := MaaJwk{X5c: mvStrs(km["x5c"])}
		for name, dst := range map[string]**string{"kid": &jk.Kid, "kty": &jk.Kty, "alg": &jk.Alg} {
			if s, isStr := km[name].(string); isStr {
				*dst = &s
			}
		}
		out.Keys = append(out.Keys, jk)
	}
	return out
}

func mvIssuerKeys(v any) map[string]AllowlistIssuerKey {
	o, _ := alvOpts(map[string]any{"nowMs": jsNumber(0), "issuerKeys": v})
	return o.IssuerKeys
}

func mvPolicy(v any) MaaKeyPolicy {
	m := vecObj(v)
	p := MaaKeyPolicy{TrustedIssuers: mvStrs(m["trustedIssuers"]), AllowTrustOnFirstUse: m["allowTrustOnFirstUse"] == true,
		ChainRootSpkiSha256: mvStrs(m["chainRootSpkiSha256"]), ChainIntermediateSpkiSha256: mvStrs(m["chainIntermediateSpkiSha256"]), ChainLeafCn: mvStrs(m["chainLeafCn"])}
	switch b := m["builtinPins"].(type) {
	case bool:
		p.DisableBuiltinPins = !b
	case map[string]any:
		src := &BuiltinMaaPinsSource{Manifest: b["manifest"], IssuerKeys: mvIssuerKeys(b["issuerKeys"])}
		if n, ok := alvInt(b["minVersion"]); ok {
			src.MinVersion = n
		}
		p.BuiltinPinsSource = src
	}
	for name, dst := range map[string]**int64{"ttlMs": &p.TtlMs, "maxStaleMs": &p.MaxStaleMs, "maxKeyAgeMs": &p.MaxKeyAgeMs, "clockSkewMs": &p.ClockSkewMs,
		"fetchTimeoutMs": &p.FetchTimeoutMs, "maxBodyBytes": &p.MaxBodyBytes} {
		if n, ok := alvInt(m[name]); ok {
			*dst = &n
		}
	}
	for name, dst := range map[string]**int{"maxNewKeysPerFetch": &p.MaxNewKeysPerFetch, "maxInitialKeys": &p.MaxInitialKeys} {
		if n, ok := alvInt(m[name]); ok {
			i := int(n)
			*dst = &i
		}
	}
	if b, ok := m["requireOverlap"].(bool); ok {
		p.RequireOverlap = &b
	}
	if pins := vecObj(m["initialPins"]); pins != nil {
		p.InitialPins = map[string][]string{}
		for iss, l := range pins {
			p.InitialPins[iss] = mvStrs(l)
		}
	}
	return p
}

// mvResponse is the scripted HTTP answer of one step: a response description, a bare JWKS (the body) or {$throws}.
func mvResponse(step any) (MaaFetchResponse, error) {
	r := vecObj(step)
	if msg, thrown := r["$throws"].(string); thrown {
		return MaaFetchResponse{}, errors.New(msg)
	}
	if _, bare := r["keys"]; bare {
		if _, has := r["body"]; !has {
			r = map[string]any{"body": step}
		}
	}
	res := MaaFetchResponse{Status: 200, ContentLength: -1}
	if n, ok := alvInt(r["status"]); ok {
		res.Status = int(n)
	}
	if n, ok := alvInt(r["contentLength"]); ok {
		res.ContentLength = n
	}
	res.URL, _ = r["url"].(string)
	body := vecObj(r["body"])
	switch {
	case vecObj(r["bodyBytes"]) != nil:
		b, ok := DecodeB64uStrict(vecStr(vecObj(r["bodyBytes"]), "$bytes"), -1)
		if !ok {
			return res, errors.New("bad $bytes")
		}
		res.Body = b
	case body != nil && len(body) == 1 && body["$text"] != nil:
		res.Body = []byte(vecStr(body, "$text"))
	default:
		b, err := json.Marshal(r["body"])
		if err != nil {
			return res, err
		}
		res.Body = b
	}
	return res, nil
}

func mvFetch(steps []any, log *[]any) MaaFetch {
	i := 0
	return func(url string, _, _ int64) (MaaFetchResponse, error) {
		*log = append(*log, url+" [redirect:error]") // a MaaFetch never follows redirects
		n := i
		if n > len(steps)-1 {
			n = len(steps) - 1
		}
		i++
		return mvResponse(steps[n])
	}
}

func mvAnchors(l []MaaAnchorRecord, firstSeen bool) []any {
	out := []any{}
	for _, a := range l {
		m := map[string]any{"spki": a.Spki, "kind": a.Kind, "notBeforeMs": a.NotBeforeMs, "notAfterMs": a.NotAfterMs}
		if firstSeen {
			m["firstSeenMs"] = a.FirstSeenMs
		}
		out = append(out, m)
	}
	return out
}

func mvRejected(l []MaaRejectedKey) []any {
	out := []any{}
	for _, r := range l {
		out = append(out, map[string]any{"kid": r.Kid, "reason": r.Reason})
	}
	return out
}

func mvList(l []string) []any {
	out := []any{}
	for _, s := range l {
		out = append(out, s)
	}
	return out
}

// mvSameRejected compares rejected-key lists: kid and reason exactly (the reference's certificate-library text by presence).
func mvSameRejected(want, got any) bool {
	w, _ := want.([]any)
	g, _ := got.([]any)
	if len(w) != len(g) {
		return false
	}
	for i := range w {
		wm, gm := vecObj(w[i]), vecObj(g[i])
		wr, gr := vecStr(wm, "reason"), vecStr(gm, "reason")
		if wm["kid"] != gm["kid"] || gr == "" {
			return false
		}
		if strings.HasPrefix(wr, "error:") || strings.HasPrefix(wr, "The first argument") {
			continue
		}
		if wr != gr {
			return false
		}
	}
	return true
}

func mvSameTrust(want, got any) bool {
	w, g := vecObj(want), vecObj(got)
	if w["ok"] != g["ok"] {
		return false
	}
	if w["ok"] != true {
		return w["code"] == g["code"] && w["reason"] == g["reason"]
	}
	for _, k := range []string{"trustAnchors", "source", "anchors", "newKeys", "removedKeys"} {
		if baseCanon(w[k]) != baseCanon(g[k]) {
			return false
		}
	}
	return mvSameRejected(w["rejected"], g["rejected"])
}

// mvStore is a key-state store over raw values, so a scenario can start from a corrupt state.
type mvStore struct{ m map[string]any }

func (s *mvStore) Get(issuer string) (any, bool, error) {
	v, ok := s.m[issuer]
	return v, ok, nil
}

func (s *mvStore) Set(issuer string, state MaaKeyState) error {
	s.m[issuer] = vecJSON(maaStateAsAny(state))
	return nil
}

func TestMaaKeyTrustMatchesTheReference(t *testing.T) {
	blobs := mvBlobs(t, "ref-attest-maa.json.gz")
	hyd := func(v any) any {
		h, err := hydrateBlobs(v, blobs)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	counts := map[string]int{}
	fn := func(name string, f func(a []any) (any, error)) vecFn {
		return func(a []any) (any, error) {
			counts[name]++
			v, err := f(hyd(a).([]any))
			if err != nil {
				return nil, err
			}
			return vecJSON(v), nil
		}
	}
	replayAll(t, "ref-attest-maa.json.gz", 261, map[string]vecFn{
		"constants": fn("constants", func([]any) (any, error) {
			keys, id := map[string]any{}, ""
			for issuer, k := range BuiltinMaaPinsIssuerKeys() {
				id = issuer
				keys[issuer] = map[string]any{"alg": k.Alg, "keys": map[string]any{"edPub": k.EdPub, "mlDsaPub": k.PqPub}}
			}
			return map[string]any{"BUILTIN_CHAIN_LEAF_CN": BuiltinChainLeafCn, "BUILTIN_MAA_PINS_ISSUER_ID": id, "BUILTIN_MAA_PINS_ISSUER_KEYS": keys}, nil
		}),
		"loadBuiltinMaaPins": fn("loadBuiltinMaaPins", func(a []any) (any, error) {
			in := vecObj(a[0])
			now, ok := alvInt(in["nowMs"])
			if _, isStr := in["nowMs"].(string); !ok || isStr { // the typed clock cannot carry it
				return map[string]any{"ok": false, "reason": "nowMs must be an integer"}, nil
			}
			var source *BuiltinMaaPinsSource
			if src := vecObj(in["source"]); src != nil {
				source = &BuiltinMaaPinsSource{Manifest: src["manifest"], IssuerKeys: mvIssuerKeys(src["issuerKeys"])}
				if n, given := alvInt(src["minVersion"]); given {
					source.MinVersion = n
				}
			}
			pins, err := LoadBuiltinMaaPins(now, source)
			if err != nil {
				return map[string]any{"ok": false, "reason": err.Error()}, nil
			}
			lists := func(m map[string][]string) map[string]any {
				out := map[string]any{}
				for k, l := range m {
					out[k] = mvList(l)
				}
				return out
			}
			return map[string]any{"ok": true, "version": pins.Version, "digest": pins.Digest, "expiresAt": pins.ExpiresAt, "maaSigningSpkis": lists(pins.MaaSigningSpkis),
				"revokedSigningSpkis": lists(pins.RevokedSigningSpkis), "maaChainRootSpkis": mvList(pins.MaaChainRootSpkis),
				"maaChainIntermediateSpkis": mvList(pins.MaaChainIntermediateSpkis), "vantages": pins.Vantages, "method": pins.Method}, nil
		}),
		"evaluateMaaJwks": fn("evaluateMaaJwks", func(a []any) (any, error) {
			now, ok := alvInt(a[3])
			if !ok {
				return nil, errors.New("the clock reading of the case is not an integer")
			}
			pol := mvPolicy(a[2])
			issuer, _ := a[1].(string)
			ev := EvaluateMaaJwks(mvJwks(a[0]), issuer, &pol, now)
			return map[string]any{"accepted": mvAnchors(ev.Accepted, false), "rejected": mvRejected(ev.Rejected)}, nil
		}),
		"corroborate": fn("corroborate", func(a []any) (any, error) {
			var sets []MaaVantageObservation
			raw, isList := a[0].([]any)
			if !isList { // the typed list cannot carry it
				return map[string]any{"ok": false, "code": "malformed", "reason": "sets must be an array"}, nil
			}
			for _, x := range raw {
				m := vecObj(x)
				sets = append(sets, MaaVantageObservation{Vantage: vecStr(m, "vantage"), Issuer: vecStr(m, "issuer"), Jwks: mvJwks(m["jwks"])})
			}
			k := 0 // anything that is not an integer is refused as k < 2
			if n, ok := alvInt(a[1]); ok {
				if _, isStr := a[1].(string); !isStr {
					k = int(n)
				}
			}
			o := vecObj(a[2])
			now, ok := alvInt(o["nowMs"])
			if !ok {
				return map[string]any{"ok": false, "code": "malformed", "reason": "issuer/nowMs invalid"}, nil
			}
			var pol *MaaKeyPolicy
			if _, has := o["policy"]; has {
				p := mvPolicy(o["policy"])
				if p.TrustedIssuers == nil {
					p.TrustedIssuers = []string{vecStr(o, "issuer")}
				}
				pol = &p
			}
			r := CorroborateMaaKeySets(sets, k, vecStr(o, "issuer"), now, pol)
			if !r.Ok {
				return map[string]any{"ok": false, "code": r.Code, "reason": r.Reason}, nil
			}
			return map[string]any{"ok": true, "issuer": r.Issuer, "spkis": mvList(r.Spkis), "vantages": mvList(r.Vantages), "k": r.K}, nil
		}),
		"fetchCerts": fn("fetchCerts", func(a []any) (any, error) {
			in := vecObj(a[0])
			log := []any{}
			o := FetchMaaCertsOptions{Fetch: mvFetch([]any{in["response"]}, &log)}
			opts := vecObj(in["opts"])
			if n, ok := alvInt(opts["maxBytes"]); ok {
				o.MaxBytes = n
			}
			if n, ok := alvInt(opts["timeoutMs"]); ok {
				o.TimeoutMs = n
			}
			jwks, err := FetchMaaCerts(vecStr(in, "issuer"), o)
			if err != nil {
				return map[string]any{"ok": false, "error": err.Error(), "requests": log}, nil
			}
			keys := []any{}
			for _, k := range jwks.Keys {
				m := map[string]any{"x5c": mvList(k.X5c)}
				for name, p := range map[string]*string{"kid": k.Kid, "kty": k.Kty, "alg": k.Alg} {
					if p != nil {
						m[name] = *p
					}
				}
				keys = append(keys, m)
			}
			return map[string]any{"ok": true, "jwks": map[string]any{"keys": keys}, "requests": log}, nil
		}),
		"kvStore": fn("kvStore", func(a []any) (any, error) {
			kv := CreateMemoryDurableKv()
			st := DurableMaaKeyStateStore(kv)
			results := []any{}
			steps, _ := vecObj(a[0])["steps"].([]any)
			for _, s := range steps {
				sm := vecObj(s)
				if set, isSet := sm["set"].([]any); isSet {
					issuer, _ := set[0].(string)
					state := parseMaaKeyState(set[1], issuer)
					if state == nil { // a raw value the typed store cannot carry is written as it is
						if err := kv.Set("maa-keys/"+issuer, set[1]); err != nil {
							return nil, err
						}
					} else if err := st.Set(issuer, *state); err != nil {
						return nil, err
					}
					results = append(results, nil)
					continue
				}
				v, ok, err := st.Get(vecStr(sm, "get"))
				if err != nil {
					return nil, err
				}
				if !ok {
					v = nil
				}
				results = append(results, v)
			}
			return map[string]any{"results": results, "kv": kv.Snapshot()}, nil
		}),
		"buildTrust": fn("buildTrust", func(a []any) (any, error) {
			c := vecObj(a[0])
			o := MaaKeyTrustOptions{Policy: mvPolicy(c["policy"]), Store: CreateMemoryMaaKeyStateStore()}
			if c["noFetch"] != true {
				o.Fetch = func(string, int64, int64) (MaaFetchResponse, error) {
					return MaaFetchResponse{Status: 200, Body: []byte("{}")}, nil
				}
			}
			if _, err := NewMaaKeyTrust(o); err != nil {
				return nil, err
			}
			return map[string]any{"built": true}, nil
		}),
		"trust": fn("trust", func(a []any) (any, error) {
			sc := vecObj(a[0])
			store := &mvStore{m: map[string]any{}}
			for k, v := range vecObj(sc["initial"]) {
				store.m[k] = v
			}
			log := []any{}
			fetches, _ := sc["fetches"].([]any)
			trust, err := NewMaaKeyTrust(MaaKeyTrustOptions{Policy: mvPolicy(sc["policy"]), Store: store, Fetch: mvFetch(fetches, &log)})
			if err != nil {
				return nil, err
			}
			results := []any{}
			calls, _ := sc["calls"].([]any)
			for _, cv := range calls {
				c := vecObj(cv)
				now, ok := alvInt(c["nowMs"])
				if !ok { // the typed clock cannot carry it; the reference refuses it as a clock regression
					results = append(results, map[string]any{"ok": false, "code": "clock-regression", "reason": "nowMs must be an integer"})
					continue
				}
				var repin *MaaRepin
				if rp := vecObj(c["repin"]); rp != nil {
					vo := VerifyAllowlistOptions{NowMs: now}
					if parsed, bad := alvOpts(pdMerge(map[string]any{"nowMs": jsNumber(float64(now))}, vecObj(rp["verify"]))); bad == "" {
						vo = parsed
					}
					repin = &MaaRepin{Manifest: rp["manifest"], Verify: vo}
				}
				r := trust.GetTrustAnchors(vecStr(c, "issuer"), now, repin)
				if !r.Ok {
					results = append(results, map[string]any{"ok": false, "code": string(r.Code), "reason": r.Reason})
					continue
				}
				results = append(results, map[string]any{"ok": true, "trustAnchors": map[string]any{"rootSpkiSha256": mvList(r.RootSpkiSha256)}, "source": r.Source,
					"anchors": mvAnchors(r.Anchors, true), "newKeys": mvList(r.NewKeys), "removedKeys": mvList(r.RemovedKeys), "rejected": mvRejected(r.Rejected)})
			}
			return map[string]any{"results": results, "store": store.m, "fetches": log}, nil
		}),
	}, map[string]func(want, got any) bool{
		"evaluateMaaJwks": func(want, got any) bool {
			w, g := vecObj(hyd(want)), vecObj(got)
			return baseCanon(w["accepted"]) == baseCanon(g["accepted"]) && mvSameRejected(w["rejected"], g["rejected"])
		},
		"corroborate": func(want, got any) bool {
			w, g := vecObj(hyd(want)), vecObj(got)
			if w["ok"] != true {
				return g["ok"] != true && w["code"] == g["code"] && w["reason"] == g["reason"]
			}
			return baseCanon(w) == baseCanon(g)
		},
		"constants":          func(want, got any) bool { return baseCanon(hyd(want)) == baseCanon(got) },
		"loadBuiltinMaaPins": func(want, got any) bool { return baseCanon(hyd(want)) == baseCanon(got) },
		"fetchCerts": func(want, got any) bool {
			w, g := vecObj(hyd(want)), vecObj(got)
			return w["ok"] == g["ok"] && w["error"] == g["error"] && baseCanon(w["requests"]) == baseCanon(g["requests"]) &&
				(w["ok"] != true || baseCanon(w["jwks"]) == baseCanon(g["jwks"]))
		},
		"kvStore":    func(want, got any) bool { return baseCanon(hyd(want)) == baseCanon(got) },
		"buildTrust": func(want, got any) bool { return baseCanon(want) == baseCanon(got) },
		"trust": func(want, got any) bool {
			w, g := vecObj(hyd(want)), vecObj(got)
			wr, _ := w["results"].([]any)
			gr, _ := g["results"].([]any)
			if len(wr) != len(gr) || baseCanon(w["store"]) != baseCanon(g["store"]) || baseCanon(w["fetches"]) != baseCanon(g["fetches"]) {
				return false
			}
			for i := range wr {
				if !mvSameTrust(wr[i], gr[i]) {
					return false
				}
			}
			return true
		},
	}, map[string]bool{"buildTrust": true})
	for name, n := range map[string]int{"constants": 1, "loadBuiltinMaaPins": 32, "evaluateMaaJwks": 92, "corroborate": 26, "fetchCerts": 36, "kvStore": 5, "buildTrust": 9, "trust": 60} {
		if counts[name] != n {
			t.Fatalf("%s: replayed %d cases, the corpus has %d", name, counts[name], n)
		}
	}
}
