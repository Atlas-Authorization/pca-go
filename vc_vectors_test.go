package pca

// Replays the reference oracle of the VC bridge (testdata/ref-vc.json.gz). Keys travel as seeds / raw public keys ({"$bytes"});
// the reference clock is pinned to vcNow. passportToVC output carries random salts, so it is compared after the reference's
// normalization (header, payload without the digest list, [name, value] disclosures, digest agreement, verify result). Header
// objects keep their document order (which is the reference's key order) via the raw corpus.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
)

const vcNow = 1700000100.0

func vcBytes(v any) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(vecStr(vecObj(v), "$bytes"))
	return b
}

func vcBytesOut(b []byte) any {
	return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(b)}
}

// vcHeaders reads a headers object in document order; a non-string value becomes the sentinel when lenient, else a refusal.
func vcHeaders(v any, raw json.RawMessage, lenient bool) ([]HTTPHeader, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("headers is not an object")
	}
	var members map[string]json.RawMessage
	json.Unmarshal(raw, &members)
	var out []HTTPHeader
	for _, k := range vecObjectKeys(members["headers"]) {
		s, ok := m[k].(string)
		if !ok {
			if !lenient {
				return nil, errors.New("v.trim is not a function")
			}
			s = oidcNoMatch
		}
		out = append(out, HTTPHeader{k, s})
	}
	return out, nil
}

func vcNormalize(sd string) (any, error) {
	parts := strings.Split(sd, "~")
	ds := parts[1 : len(parts)-1]
	seg := strings.Split(parts[0], ".")
	dec := func(s string) any {
		b, _ := base64.RawURLEncoding.DecodeString(s)
		v, _ := ParseJSONLenient(b)
		return v
	}
	h, p := dec(seg[0]), vecObj(dec(seg[1]))
	cs := vecObj(vecObj(p["vc"])["credentialSubject"])
	var sdl []string
	if l, ok := cs["_sd"].([]any); ok {
		for _, x := range l {
			s, _ := x.(string)
			sdl = append(sdl, s)
		}
	}
	sort.Strings(sdl)
	delete(cs, "_sd")
	pub := ed25519.NewKeyFromSeed(vcSeed(1)).Public().(ed25519.PublicKey)
	_, verr := VerifyPassportVC(sd, pub, VerifyPassportVCOptions{NowSec: ptrF(vcNow)})
	var shas []string
	disc := []any{}
	for _, d := range ds {
		x := sha256.Sum256([]byte(d))
		shas = append(shas, base64.RawURLEncoding.EncodeToString(x[:]))
		a, _ := dec(d).([]any)
		disc = append(disc, []any{a[1], a[2]})
	}
	sort.Strings(shas)
	sort.Slice(disc, func(i, j int) bool { return disc[i].([]any)[0].(string) < disc[j].([]any)[0].(string) })
	return map[string]any{"end": parts[len(parts)-1], "header": h, "payload": p, "n": len(ds), "digestsOk": strings.Join(shas, ",") == strings.Join(sdl, ","),
		"disclosures": disc, "verified": verr == nil}, nil
}

func vcSeed(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n
	}
	return b
}

func ptrF(f float64) *float64 { return &f }

func TestVcVectors(t *testing.T) {
	const file = "ref-vc.json.gz"
	raw := vecRawArgs(t, "testdata/"+file)
	rawArg0 := func(a []any) json.RawMessage {
		if r := raw[baseCanon(a)]; len(r) > 0 {
			return r[0]
		}
		return nil
	}
	replayVectors(t, file, map[string]vecFn{
		"base58btcEncode": func(a []any) (any, error) { return Base58btcEncode(vcBytes(vecArg(a, 0))), nil },
		"base58btcDecode": func(a []any) (any, error) {
			s, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, errors.New("str is not a string")
			}
			b, err := Base58btcDecode(s)
			return vcBytesOut(b), err
		},
		"didKeyFromEd25519": func(a []any) (any, error) { return DidKeyFromEd25519(vcBytes(vecArg(a, 0))) },
		"ed25519FromDidKey": func(a []any) (any, error) {
			s, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, errors.New("did.startsWith is not a function")
			}
			b, err := Ed25519FromDidKey(s)
			return vcBytesOut(b), err
		},
		"constants": func([]any) (any, error) {
			return map[string]any{"VC_CONTEXT": VCContext, "AGENT_PASSPORT_CONTEXT": AgentPassportContext, "AGENT_PASSPORT_VC_TYPE": AgentPassportVCType,
				"AGENT_PASSPORT_CONTEXT_DIGEST": AgentPassportContextDigest(), "AGENT_PASSPORT_CONTEXT_DOC": AgentPassportContextDoc()}, nil
		},
		"resolveAgentPassportContext": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			if d := ResolveAgentPassportContext(s); d != nil {
				return d, nil
			}
			return nil, nil
		},
		"passportToVC": func(a []any) (any, error) {
			var passport map[string]any
			switch p := vecArg(a, 0).(type) {
			case map[string]any:
				passport = p
			case []any:
				passport = map[string]any{}
			default:
				return nil, errors.New("passport is null")
			}
			m := vecObj(vecArg(a, 1))
			o := PassportToVCArgs{IssuerSeed: vcBytes(m["issuer_seed"]), IssuerDid: vecPtrIfPresent(m, "issuer_did"), SubjectDid: vecPtrIfPresent(m, "subject_did"), NowSec: ptrF(vcNow)}
			if x, has := m["ttl_sec"]; has { // now + ttl, JS addition: null is 0, a boolean 0/1, a string concatenates (refused)
				switch v := x.(type) {
				case nil:
					o.TTLSec = ptrF(0)
				case bool:
					o.TTLSec = ptrF(map[bool]float64{false: 0, true: 1}[v])
				case string:
					return nil, errors.New("setExpirationTime: invalid input")
				default:
					f, _ := jsNum(v)
					o.TTLSec = &f
				}
			}
			sd, err := PassportToVC(passport, o)
			if err != nil {
				return nil, err
			}
			return vcNormalize(sd)
		},
		"verifyPassportVC": func(a []any) (any, error) {
			vc, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, errors.New("vc.split is not a function")
			}
			var o VerifyPassportVCOptions
			o.NowSec = ptrF(vcNow)
			if len(a) > 2 {
				om, ok := a[2].(map[string]any)
				if !ok {
					return nil, errors.New("options is null")
				}
				if x, has := om["expectedIssuerDid"]; has {
					s, ok := x.(string)
					if !ok {
						s = oidcNoMatch
					}
					o.ExpectedIssuerDid = &s
				}
			}
			return VerifyPassportVC(vc, vcBytes(vecArg(a, 1)), o)
		},
		"signRequestMessage": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 0))
			hs, err := vcHeaders(m["headers"], rawArg0(a), false)
			if err != nil {
				return nil, err
			}
			o := SignRequestArgs{Headers: hs, Seed: vcBytes(m["key"]), KeyID: jsValueString(m["keyid"])}
			o.Method, _ = m["method"].(string)
			o.URL, _ = m["url"].(string)
			switch c := m["created"].(type) {
			case nil:
				o.Created = ptrF(vcNow) // `?? now` under the pinned clock
			case string:
				f := jsStringToNumber(c)
				if jsNumberString(f) != c {
					return nil, errors.New("non-numeric created string has no typed equivalent")
				}
				o.Created = &f
			default:
				f, _ := jsNum(c)
				o.Created = &f
			}
			if x, has := m["signature_agent"]; has {
				s := jsValueString(x)
				o.SignatureAgent = &s
			}
			return SignRequestMessage(o)
		},
		"verifyRequestSignature": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 0))
			hs, err := vcHeaders(m["headers"], rawArg0(a), true)
			if err != nil {
				return false, nil
			}
			in, ok1 := m["signature_input"].(string)
			sig, ok2 := m["signature"].(string)
			if !ok1 || !ok2 {
				return false, nil
			}
			o := VerifyRequestArgs{Headers: hs, SignatureInput: in, Signature: sig, SignatureAgent: oidcStrOpt(m, "signature_agent")}
			o.Method, _ = m["method"].(string)
			o.URL, _ = m["url"].(string)
			if l, ok := m["required_components"].([]any); ok {
				for _, x := range l {
					s, ok := x.(string)
					if !ok {
						s = oidcNoMatch
					}
					o.RequiredComponents = append(o.RequiredComponents, s)
				}
			}
			if x, has := m["max_age_sec"]; has {
				f, _ := jsNum(x) // null compares as 0
				o.MaxAgeSec = &f
			}
			if x, ok := jsNum(m["now_sec"]); ok {
				o.NowSec = &x
			}
			return VerifyRequestSignature(o, vcBytes(vecArg(a, 1))), nil
		},
	})
}
