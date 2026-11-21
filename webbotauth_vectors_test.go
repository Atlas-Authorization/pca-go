package pca

// Replays the Web Bot Auth reference corpus: RFC 9421 signing and verification (with the RFC 9421 appendix and the web-bot-auth
// draft vectors), the replay cache, the key directory and its handler, the PCA proof binding, Content-Digest, signed directory
// responses and the scripted directory fetch. The committed corpus carries no secret key: a signing key's secretKey is replaced
// by the seed label it was derived from (SHA-256 of "atlas-pca-conformance/<label>"), except the published RFC 9421 appendix
// B.1.4 test key, which is named "rfc9421-b-1-4" and held below. Duplicate header names that differ in case merge in the member
// order of the header object, which a decoded Go map does not keep: those cases are skipped when the order changes the value.

import (
	"crypto/sha256"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
)

const wbaRFC9421SeedB64u = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" // the RFC 9421 appendix B.1.4 Ed25519 test key (published)

var wbaProofReasonRe = regexp.MustCompile(`(?s)^(invalid PCActn in PCA-Action): .*$`)

func wbaTestKey(v any) (*KeyPair, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not a key spec")
	}
	if seedStr, isStr := m["secretKey"].(string); isStr { // a published test key (the RFC's) crosses as its base64url seed
		seed, ok := DecodeB64uStrict(seedStr, 32)
		if !ok {
			return nil, errors.New("secretKey is not a 32-byte base64url seed")
		}
		return KeyPairFromSeed(seed)
	}
	if sk, isSK := m["secretKey"].(map[string]any); isSK { // {"secretKey": {"$seed": label}, "publicKey": ...}
		m = sk
	}
	label, _ := m["$seed"].(string)
	if label == "rfc9421-b-1-4" {
		seed, _ := DecodeB64uStrict(wbaRFC9421SeedB64u, 32)
		return KeyPairFromSeed(seed)
	}
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return KeyPairFromSeed(d[:])
}

// wbaWithKey is the oracle's withKey: a signing input whose key is a key spec gets the key pair.
func wbaWithKey(in map[string]any) map[string]any {
	k, ok := in["key"].(map[string]any)
	if !ok {
		return in
	}
	out := agentcardCopy(in)
	if kp, err := wbaTestKey(k); err == nil {
		out["key"] = kp
	}
	return out
}

func wbaTestBytes(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil, false
	}
	b, err := b64.DecodeString(s)
	return b, err == nil
}

func wbaTestBody(v any) any {
	if b, ok := wbaTestBytes(v); ok {
		return b
	}
	return v
}

// wbaOrderMatters reports whether header names that collide case-insensitively carry different values (their merge order is the
// member order of the object).
func wbaOrderMatters(h any) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	groups := map[string][]string{}
	for k, v := range m {
		lk := strings.ToLower(k)
		var s string
		if l, isL := v.([]any); isL {
			parts := make([]string, len(l))
			for i, x := range l {
				parts[i] = wbaTrim(jsValueString(x))
			}
			s = strings.Join(parts, ", ")
		} else {
			s = wbaTrim(jsValueString(v))
		}
		groups[lk] = append(groups[lk], s)
	}
	for _, g := range groups {
		for _, x := range g[1:] {
			if x != g[0] {
				return true
			}
		}
	}
	return false
}

const wbaOrderSkip = vecSkip("duplicate header names that differ in case with different values: they merge in the member order of the header object, which a decoded Go map does not keep")

type wbaFixedCache struct {
	result bool
	err    error
}

func (c wbaFixedCache) Claim(string, float64, float64) (bool, error) { return c.result, c.err }

func wbaTestCache(spec any) any {
	s, ok := spec.(string)
	switch {
	case !ok:
		return spec
	case s == "always":
		return wbaFixedCache{result: true}
	case s == "never":
		return wbaFixedCache{}
	case s == "throw":
		return wbaFixedCache{err: errors.New("cache down")}
	case s == "memory":
		return NewWebBotAuthMemoryReplayCache()
	case strings.HasPrefix(s, "memory:"):
		return NewWebBotAuthMemoryReplayCache(int(jsStringToNumber(s[7:])))
	}
	return spec
}

func wbaTestOpts(op map[string]any) map[string]any {
	out := agentcardCopy(op)
	if spec, ok := out["resolveKey"].(map[string]any); ok {
		out["resolveKey"] = func(kid string) (any, error) {
			v := spec[kid]
			if m, ok := v.(map[string]any); ok {
				if jsTruthy(m["$throw"]) {
					return nil, errors.New("resolver down")
				}
				if b, ok := wbaTestBytes(m); ok {
					return b, nil
				}
			}
			return v, nil
		}
	}
	if out["maxLifetimeSec"] == "Infinity" {
		out["maxLifetimeSec"] = math.Inf(1)
	}
	if c, has := out["replayCache"]; has {
		out["replayCache"] = wbaTestCache(c)
	}
	return out
}

func wbaTestNorm(r map[string]any) map[string]any {
	if s, ok := r["reason"].(string); ok {
		r["reason"] = wbaProofReasonRe.ReplaceAllString(s, "$1")
	}
	return r
}

func wbaTestKeys(v any) []any {
	l, _ := v.([]any)
	out := make([]any, len(l))
	for i, k := range l {
		if m, ok := k.(map[string]any); ok {
			c := agentcardCopy(m)
			if b, ok := wbaTestBytes(m["publicKey"]); ok {
				c["publicKey"] = b
			}
			out[i] = c
		} else {
			out[i] = k
		}
	}
	return out
}

func wbaTestStrings(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(l))
	for i, x := range l {
		out[i], _ = x.(string)
	}
	return out
}

func wbaTestFetch(args []any) (any, error) {
	rawURL, _ := vecArg(args, 0).(string)
	spec := vecObj(vecArg(args, 1))
	var called map[string]any
	opts := map[string]any{}
	if o := vecObj(spec["options"]); o != nil {
		opts = agentcardCopy(o)
	}
	res := spec["response"]
	opts["fetch"] = WebBotAuthFetchFunc(func(u string, fetchInit map[string]any) (*WebBotAuthFetchResponse, error) {
		called = map[string]any{"url": u, "headers": fetchInit["headers"], "redirect": fetchInit["redirect"]}
		if res == "throw" {
			return nil, errors.New("network down")
		}
		r := vecObj(res)
		status, _ := jsNum(r["status"])
		headers := map[string]string{}
		for k, v := range vecObj(r["headers"]) {
			headers[strings.ToLower(k)], _ = v.(string)
		}
		body, _ := r["body"].(string)
		return &WebBotAuthFetchResponse{Status: int(status), Headers: headers, Body: body}, nil
	})
	d, err := WebBotAuthFetchKeyDirectory(rawURL, opts)
	var calledOut any
	if called != nil {
		calledOut = called
	}
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "directory ") || strings.HasPrefix(msg, "Invalid URL") {
			if strings.HasPrefix(msg, "directory signature: ") {
				msg = "directory signature"
			}
		} else {
			msg = "other"
		}
		return map[string]any{"error": true, "message": msg, "called": calledOut}, nil
	}
	return map[string]any{"directory": d, "called": calledOut}, nil
}

func TestWebBotAuthVectors(t *testing.T) {
	sameJSON := func(want, got any) bool { return baseCanon(want) == baseCanon(got) }
	bodyAsJSON := func(want, got any) bool {
		w, g := vecObj(want), vecObj(got)
		if w == nil || g == nil || !sameJSON(w["headers"], g["headers"]) {
			return false
		}
		wb, _ := w["body"].(string)
		gb, _ := g["body"].(string)
		wv, err1 := ParseJSONLenient([]byte(wb))
		gv, err2 := ParseJSONLenient([]byte(gb))
		return err1 == nil && err2 == nil && sameJSON(normalizeJSON(wv), normalizeJSON(gv))
	}
	verify := func(args []any, withProof bool) (any, error) {
		req := vecObj(args[0])
		if req != nil && wbaOrderMatters(req["headers"]) {
			return nil, wbaOrderSkip
		}
		opts := wbaTestOpts(vecObj(vecArg(args, 1)))
		times := 1
		if n, ok := jsNum(vecArg(args, 2)); ok {
			times = int(n)
		}
		var rs []any
		for i := 0; i < times; i++ {
			var r map[string]any
			if withProof {
				var err error
				if r, err = WebBotAuthVerifyWithProof(req, opts); err != nil {
					return nil, err
				}
			} else {
				r = WebBotAuthVerify(req, opts)
			}
			rs = append(rs, wbaTestNorm(r))
		}
		if times == 1 {
			return rs[0], nil
		}
		return rs, nil
	}
	sign := func(args []any, withProof bool) (any, error) {
		in, _ := args[0].(map[string]any)
		if in != nil && wbaOrderMatters(in["headers"]) {
			return nil, wbaOrderSkip
		}
		if in != nil {
			in = wbaWithKey(in)
		}
		if withProof {
			return WebBotAuthSignWithProof(in)
		}
		return WebBotAuthSign(in)
	}
	signDir := func(args []any) (any, error) {
		in := agentcardCopy(vecObj(args[0]))
		if l, ok := in["keys"].([]any); ok {
			keys := make([]any, len(l))
			for i, k := range l {
				kp, err := wbaTestKey(k)
				if err != nil {
					return nil, err
				}
				keys[i] = kp
			}
			in["keys"] = keys
		}
		return WebBotAuthSignDirectory(in)
	}
	stringHeader := func(args []any, i int) *string {
		s, ok := vecArg(args, i).(string)
		if !ok {
			return nil
		}
		return &s
	}
	replayCacheRun := func(args []any) (any, error) {
		var c *WebBotAuthMemoryReplayCache
		if n, ok := jsNum(vecArg(args, 0)); ok {
			c = NewWebBotAuthMemoryReplayCache(int(n))
		} else {
			c = NewWebBotAuthMemoryReplayCache()
		}
		ops, _ := vecArg(args, 1).([]any)
		out := make([]any, len(ops))
		for i, op := range ops {
			l, _ := op.([]any)
			k, _ := l[0].(string)
			e, _ := jsNum(l[1])
			n, _ := jsNum(l[2])
			first, err := c.Claim(k, e, n)
			if err != nil {
				out[i] = "throw"
			} else {
				out[i] = first
			}
		}
		return out, nil
	}
	handlerRun := func(args []any) (any, error) {
		h, err := WebBotAuthDirectoryHandler(wbaTestKeys(args[0]))
		if err != nil {
			return nil, err
		}
		paths, _ := vecArg(args, 1).([]any)
		out := make([]any, len(paths))
		for i, p := range paths {
			s, _ := p.(string)
			if r := h(s); r != nil {
				out[i] = r
			}
		}
		return out, nil
	}
	replayVectorsCmp(t, "ref-webbotauth.json.gz", map[string]vecFn{
		"constants": func(args []any) (any, error) {
			return map[string]any{
				"tag": WebBotAuthTag, "alg": WebBotAuthAlg, "path": WebBotAuthWellKnownDirectoryPath, "ct": WebBotAuthDirectoryContentType,
				"label": WebBotAuthDefaultSignatureLabel, "exp": WebBotAuthDefaultExpiresSec, "agent": WebBotAuthSignatureAgentHeader,
				"pca": WebBotAuthPCAHeader, "comp": WebBotAuthPCAProofComponent, "cd": WebBotAuthContentDigestHeaderName,
				"algs": WebBotAuthContentDigestAlgs, "dtag": WebBotAuthDirectorySignatureTag,
			}, nil
		},
		"jwkThumbprint": func(args []any) (any, error) {
			b, _ := wbaTestBytes(args[0])
			return WebBotAuthJWKThumbprint(b), nil
		},
		"signRequest":          func(args []any) (any, error) { return sign(args, false) },
		"signRequestWithProof": func(args []any) (any, error) { return sign(args, true) },
		"verifySignedRequest":  func(args []any) (any, error) { return verify(args, false) },
		"verifySignedRequestWithProof": func(args []any) (any, error) {
			return verify(args, true)
		},
		"buildKeyDirectory": func(args []any) (any, error) { return WebBotAuthBuildKeyDirectory(wbaTestKeys(args[0])) },
		"resolveFromDirectory": func(args []any) (any, error) {
			id, _ := vecArg(args, 1).(string)
			m, err := WebBotAuthResolveFromDirectory(args[0], id)
			if m == nil {
				return nil, err
			}
			return m, err
		},
		"directoryHandler":  handlerRun,
		"memoryReplayCache": replayCacheRun,
		"proofHeaders": func(args []any) (any, error) {
			h, err := WebBotAuthProofHeaders(args[0])
			if err != nil {
				return nil, err
			}
			return map[string]any{WebBotAuthPCAHeader: h[WebBotAuthPCAHeader]}, nil
		},
		"decodeProofHeader": func(args []any) (any, error) {
			s, ok := args[0].(string)
			if !ok {
				return nil, errors.New("PCA-Action header is empty")
			}
			return WebBotAuthDecodeProofHeader(s)
		},
		"contentDigestBytes": func(args []any) (any, error) {
			alg, _ := vecArg(args, 1).(string)
			b, err := WebBotAuthContentDigestBytes(wbaTestBody(args[0]), alg)
			if err != nil {
				return nil, err
			}
			return map[string]any{"$bytes": b64.EncodeToString(b)}, nil
		},
		"contentDigestHeader": func(args []any) (any, error) {
			var algs []string
			if l, ok := vecArg(args, 1).([]any); ok {
				algs = make([]string, len(l))
				for i, x := range l {
					algs[i], _ = x.(string)
				}
			}
			return WebBotAuthContentDigestHeaderValue(wbaTestBody(args[0]), algs)
		},
		"parseContentDigest": func(args []any) (any, error) {
			s, _ := args[0].(string)
			m, err := WebBotAuthParseContentDigest(s)
			if err != nil {
				return nil, err
			}
			out := map[string]any{}
			for k, v := range m {
				out[k] = map[string]any{"$bytes": b64.EncodeToString(v)}
			}
			return out, nil
		},
		"verifyContentDigest": func(args []any) (any, error) {
			var require []string
			if o := vecObj(vecArg(args, 2)); o != nil {
				require = wbaTestStrings(o["require"])
			}
			return WebBotAuthVerifyContentDigest(stringHeader(args, 0), wbaTestBody(vecArg(args, 1)), require), nil
		},
		"parseKeyDirectory": func(args []any) (any, error) {
			s, _ := args[0].(string)
			return WebBotAuthParseKeyDirectory(s)
		},
		"signDirectoryResponse": signDir,
		"verifyDirectoryResponse": func(args []any) (any, error) {
			return WebBotAuthVerifyDirectory(vecObj(args[0])), nil
		},
		"fetchKeyDirectory": func(args []any) (any, error) { return wbaTestFetch(args) },
	}, map[string]func(want, got any) bool{
		"signDirectoryResponse": bodyAsJSON,
	})
}
