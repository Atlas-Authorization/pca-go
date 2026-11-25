package pca

// Replays the reference corpus for pack transparency entries. Signing seeds are labels ({"$seed": label}, resolved by vecSeeded): the key
// is ed25519 over sha256("atlas-pca-conformance/" + label).

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"testing"
)

func packLogKey(v any) (ed25519.PrivateKey, error) {
	s, _ := v.(string) // a resolved seed: base64url of the 32-byte ed25519 seed
	h, ok := DecodeB64uStrict(s, 32)
	if !ok {
		return nil, errors.New("no seed")
	}
	return ed25519.NewKeyFromSeed(h), nil
}

func TestActionPackLogVectors(t *testing.T) {
	replayVectors(t, "ref-actions-pack-log.json.gz", vecSeeded(map[string]vecFn{
		"appendPackToLog": func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 1))
			reg, err := packLogKey(spec["regSeed"])
			if err != nil {
				return nil, err
			}
			ts, err := packLogKey(spec["tsSeed"])
			if err != nil {
				return nil, err
			}
			other, _ := packLogKey(vecResolveSeeds(map[string]any{"$seed": "ref-actions-pack-log/other"}))
			iss := "ts"
			svc := NewScittTransparencyService(ScittReceiptSigner{Alg: "EdDSA", Key: ts, Issuer: &iss})
			for i := 0; i < int(jsF(spec["preload"])); i++ {
				subj := "s" + jsNumberString(float64(i))
				st, err := ScittSignStatement(map[string]any{"i": jsNumber(float64(i))}, ScittSignStatementOpts{Alg: "EdDSA", Key: other, Issuer: "other", Subject: &subj})
				if err != nil {
					return nil, err
				}
				if _, err := svc.Register(st); err != nil {
					return nil, err
				}
			}
			e, err := ActionAppendPackToLog(vecObj(vecArg(a, 0)), svc, "EdDSA", reg, vecStr(spec, "issuer"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"statement": vcBytesOut(e.Statement), "receipt": vcBytesOut(e.Receipt), "index": jsNumber(float64(e.Index)), "root": e.Root}, nil
		},
		"verifyPackLogEntry": func(a []any) (any, error) {
			entry, keys := vecObj(vecArg(a, 1)), vecObj(vecArg(a, 2))
			pub := func(k string) (crypto.PublicKey, error) {
				raw, ok := DecodeB64uStrict(vecStr(keys, k), 32)
				if !ok {
					return nil, errors.New("bad key")
				}
				return ed25519.PublicKey(raw), nil
			}
			rk, err := pub("registry")
			if err != nil {
				return false, nil
			}
			lk, err := pub("log")
			if err != nil {
				return false, nil
			}
			var root *string
			if s, ok := vecArg(a, 3).(string); ok {
				root = &s
			}
			return ActionVerifyPackLogEntry(vecObj(vecArg(a, 0)), vcBytes(entry["statement"]), vcBytes(entry["receipt"]), rk, lk, root), nil
		},
	}))
}
