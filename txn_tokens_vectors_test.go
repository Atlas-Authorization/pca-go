package pca

// Replays the reference oracle of the RFC 8693 act projection and Transaction Tokens (testdata/ref-txn-tokens.json.gz).

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func txnDecode(tok string) (map[string]any, map[string]any) {
	parts := strings.Split(tok, ".")
	dec := func(s string) map[string]any {
		b, _ := base64.RawURLEncoding.DecodeString(s)
		v, _ := ParseJSONLenient(b)
		m, _ := normalizeJSON(v).(map[string]any)
		return m
	}
	return dec(parts[0]), dec(parts[1])
}

func TestTxnTokensVectors(t *testing.T) {
	replayVectors(t, "ref-txn-tokens.json.gz", vecSeeded(map[string]vecFn{
		"subActChain":  func(a []any) (any, error) { return SubActChain(a[0]) },
		"actDepth":     func(a []any) (any, error) { return ActDepth(a[0]) },
		"toRfc8693Act": func(a []any) (any, error) { return ToRfc8693Act(a[0]) },
		"toTransactionToken": func(a []any) (any, error) {
			m := vecObj(a[0])
			seed, _ := base64.RawURLEncoding.DecodeString(vecStr(m, "seed"))
			args := TxnTokenArgs{Profile: vecStr(m, "profile"), Scope: vecStr(m, "scope"), ReqWl: vecStr(m, "reqWl"), Txn: vecStr(m, "txn"),
				TrustDomain: vecPtrStr(m, "trustDomain"), Chain: m["chain"], Action: vecObj(m["action"]), IssuerSeed: seed, Issuer: vecStr(m, "issuer"),
				TTLSec: vecF64Ptr(m, "ttlSec"), Now: func() time.Time { return time.UnixMilli(1_800_000_000_000) }}
			if p, has := m["profile"]; has && p != "legacy" && p != "draft-11" {
				args.Profile = jsValueString(p)
			}
			if m["action"] == nil {
				args.Action = nil
			}
			tok, err := ToTransactionToken(args)
			if err != nil {
				return nil, err
			}
			h, c := txnDecode(tok)
			iat, _ := jsNum(c["iat"])
			exp, _ := jsNum(c["exp"])
			keep := map[string]any{}
			for k, v := range c {
				if k != "iat" && k != "exp" && k != "jti" && k != "txn" {
					keep[k] = v
				}
			}
			keep["ttl"] = jsNumber(exp - iat)
			if _, has := c["jti"]; has {
				keep["jti"] = true
			}
			if txn, has := c["txn"]; has {
				if _, given := m["txn"]; given {
					keep["txn"] = txn
				} else {
					keep["txn"] = true
				}
			}
			return map[string]any{"header": h, "claims": keep}, nil
		},
		"fromTransactionToken": func(a []any) (any, error) {
			w := vecObj(vecArg(a, 2))
			pk, _ := base64.RawURLEncoding.DecodeString(vecStrArg(a, 1))
			o := TxnVerifyOptions{Profile: vecStr(w, "profile"), Audience: vecStr(w, "audience"), ReplayUnchecked: w["unchecked"] == true}
			if p, has := w["profile"]; has && p != "legacy" && p != "draft-11" {
				o.Profile = jsValueString(p)
			}
			if f, ok := jsNum(w["clockToleranceSec"]); ok {
				o.ClockToleranceSec = f
			}
			if f, ok := jsNum(w["nowMs"]); ok {
				s := f / 1000
				o.NowSec = &s
			}
			if l, ok := w["seen"].([]any); ok {
				o.SeenTxn = func(id string, _ float64) (bool, error) {
					for _, x := range l {
						if x == id {
							return true, nil
						}
					}
					return false, nil
				}
			}
			return FromTransactionToken(a[0], pk, o)
		},
	}))
}
