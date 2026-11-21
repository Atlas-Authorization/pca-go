package pca

// Replays the reference corpus of suite signing for the intent artifacts: for every suite (Ed25519, ML-DSA, hybrid) a signed
// statement, observation and profile has the reference's shape (suite members, signature lengths, remaining members) and verifies under
// the matching pin.

import (
	"strings"
	"testing"
)

func isjKey(a []any) (*KeyPair, *SuiteOpts, error) {
	seed, _ := vecArg(a, 1).(string)
	kp, err := KeyPairFromSeedB64u(seed)
	if err != nil {
		return nil, nil, err
	}
	alg, _ := vecArg(a, 2).(string)
	if alg == "" && vecArg(a, 2) != nil { // an empty alg is an unknown suite in the reference; SuiteOpts reads "" as the default
		return nil, nil, isjErr("signWithSuite: unknown signature alg ''")
	}
	if alg == "ed25519" {
		return kp, nil, nil
	}
	family := "ML-DSA-65"
	if strings.HasSuffix(alg, "ml-dsa-87") {
		family = "ML-DSA-87"
	}
	pqSeed, _ := vecArg(a, 3).(string)
	raw, ok := DecodeB64uStrict(pqSeed, 32)
	if !ok {
		return nil, nil, isjErr("bad pq seed")
	}
	pq, err := GeneratePqKeyPairFromSeed(family, raw)
	if err != nil {
		return nil, nil, err
	}
	return kp, &SuiteOpts{Alg: alg, Pq: pq}, nil
}

type isjErr string

func (e isjErr) Error() string { return string(e) }

func isjLen(v any) any {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	b, ok := DecodeB64uStrict(s, -1)
	if !ok {
		return nil
	}
	return float64(len(b))
}

func isjShape(a map[string]any, ok bool) map[string]any {
	rest := map[string]any{}
	for k, v := range a {
		if k != "sig" && k != "pq_sig" && k != "alg" && k != "pq_pk" {
			rest[k] = v
		}
	}
	return map[string]any{"alg": a["alg"], "pq_pk": a["pq_pk"], "rest": rest, "sig_len": isjLen(a["sig"]), "pq_sig_len": isjLen(a["pq_sig"]), "ok": ok}
}

func isjPins(a map[string]any, who string) map[string]any {
	p := map[string]any{}
	if pk, has := a["pq_pk"]; has && pk != nil {
		p[who] = pk
	}
	return map[string]any{"pqPins": p}
}

func TestIntentSuiteSignVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-intent-suite-sign-java.json.gz", map[string]vecFn{
		"signStatement": func(a []any) (any, error) {
			kp, suite, err := isjKey(a)
			if err != nil {
				return nil, err
			}
			s, err := SignIntentStatement(vecObj(vecArg(a, 0)), kp, suite)
			if err != nil {
				return nil, err
			}
			return isjShape(s, VerifyIntentStatement(s, isjPins(s, ixS(s["principal"])))["ok"] == true), nil
		},
		"signObservation": func(a []any) (any, error) {
			kp, suite, err := isjKey(a)
			if err != nil {
				return nil, err
			}
			s, err := SignIntentObservation(vecObj(vecArg(a, 0)), kp, suite)
			if err != nil {
				return nil, err
			}
			return isjShape(s, VerifyIntentObservation(s, isjPins(s, ixS(s["signer"])))["ok"] == true), nil
		},
		"signProfile": func(a []any) (any, error) {
			kp, suite, err := isjKey(a)
			if err != nil {
				return nil, err
			}
			s, err := SignIntentProfile(vecObj(vecArg(a, 0)), kp, suite)
			if err != nil {
				return nil, err
			}
			return isjShape(s, IntentVerifyIntentProfile(s, isjPins(s, ixS(s["owner"])))["ok"] == true), nil
		},
	})
}
