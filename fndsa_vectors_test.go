package pca

// Differential replay of the FN-DSA registry, framing, hybrid composition and backend seam against the TypeScript reference
// (@atlasauth/pca-fndsa) corpus. The Falcon primitive is not covered (the reference ships none): every case runs through the
// deterministic hash-derived test backend below (TEST ONLY: anyone can forge its signatures) or an explicit stub backend.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

var fnMockSkTag = []byte("atlas-pca/fn-dsa/mock-sk/v1\x00")

func fnHashKat(seed []byte, n int) []byte {
	var out []byte
	for ctr := uint32(0); len(out) < n; ctr++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		h := sha256.Sum256(append(append([]byte(nil), seed...), c[:]...))
		out = append(out, h[:]...)
	}
	return out[:n]
}

func fnMockSigFor(pk, msg []byte) []byte {
	n := map[int]int{FnDsa512PublicKeyBytes: FnDsa512SignatureBytes, FnDsa1024PublicKeyBytes: FnDsa1024SignatureBytes}[len(pk)]
	if n == 0 {
		return nil
	}
	return fnHashKat(append(append([]byte("fn-dsa/mock-sig/v1\x00"), pk...), msg...), n)
}

type fnKat struct{ pk, msg, sig []byte }

func fnMockKeypair(variant string, seed any) (map[string]any, error) {
	if !IsFnDsaVariant(variant) {
		return nil, fmt.Errorf("mockKeypair: unknown FN-DSA variant %q", variant)
	}
	var sb []byte
	if s, ok := seed.(string); ok {
		sb = fnDsaUTF8(variant + "/" + s)
	} else if b, ok := seed.([]byte); ok {
		sb = append(fnDsaUTF8(variant+"/"), b...)
	} else {
		return nil, errors.New("mockKeypair: seed must be a string or bytes")
	}
	pk := fnHashKat(sb, fnDsaVariantPk[variant])
	return map[string]any{"pk": vecBytesOut(pk), "sk": vecBytesOut(append(append([]byte(nil), fnMockSkTag...), pk...))}, nil
}

// fnMockBackend: explicit known-answer vectors take precedence over the hash-derived signature.
func fnMockBackend(vectors []fnKat) *FalconBackend {
	table := map[string][]byte{}
	for _, v := range vectors {
		table[string(v.pk)+"|"+string(v.msg)] = v.sig
	}
	return &FalconBackend{
		Verify: func(pk, msg, sig []byte) (bool, error) {
			exp, ok := table[string(pk)+"|"+string(msg)]
			if !ok {
				if exp = fnMockSigFor(pk, msg); exp == nil {
					return false, nil
				}
			}
			return len(sig) == len(exp) && subtle.ConstantTimeCompare(sig, exp) == 1, nil
		},
		Sign: func(sk, msg []byte) ([]byte, error) {
			if len(sk) <= len(fnMockSkTag) || !bytes.Equal(sk[:len(fnMockSkTag)], fnMockSkTag) {
				return nil, errors.New("mock FN-DSA backend: secret key was not minted by mockKeypair()")
			}
			pk := sk[len(fnMockSkTag):]
			if k, ok := table[string(pk)+"|"+string(msg)]; ok {
				return k, nil
			}
			if d := fnMockSigFor(pk, msg); d != nil {
				return d, nil
			}
			return nil, errors.New("mock FN-DSA backend: public key length matches no FN-DSA variant")
		},
	}
}

func fnInstall(kind string) error {
	mock := fnMockBackend(nil)
	switch kind {
	case "mock":
		return SetFalconBackend(mock)
	case "none":
		ResetFalconBackend()
		return nil
	case "verify-only":
		return SetFalconBackend(&FalconBackend{Verify: mock.Verify})
	case "short-sig":
		return SetFalconBackend(&FalconBackend{Verify: mock.Verify, Sign: func(_, _ []byte) ([]byte, error) { return make([]byte, 10), nil }})
	case "all-true":
		return SetFalconBackend(&FalconBackend{Verify: func(_, _, _ []byte) (bool, error) { return true, nil }, Sign: mock.Sign})
	case "throws":
		return SetFalconBackend(&FalconBackend{Verify: func(_, _, _ []byte) (bool, error) { return false, errors.New("backend exploded") }, Sign: mock.Sign})
	}
	return fmt.Errorf("unknown backend kind %q", kind)
}

func fnWith[T any](kind string, f func() (T, error)) (T, error) {
	defer ResetFalconBackend()
	if err := fnInstall(kind); err != nil {
		var z T
		return z, err
	}
	return f()
}

func fnBytes(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return nil, false
	}
	if sm, ok := m["$bytes"].(map[string]any); ok { // a seed label: the bytes are sha256("atlas-pca-conformance/" + label)
		label, ok := sm["$seed"].(string)
		if !ok || len(sm) != 1 {
			return nil, false
		}
		d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
		return d[:], true
	}
	if _, ok := m["$bytes"].(string); !ok {
		return nil, false
	}
	b := baseBytes(v)
	if b == nil {
		b = []byte{}
	}
	return b, true
}

func fnStr(v any) string { s, _ := v.(string); return s }

func fnKats(v any) []fnKat {
	l, _ := v.([]any)
	out := make([]fnKat, 0, len(l))
	for _, x := range l {
		m := vecObj(x)
		pk, _ := fnBytes(m["pk"])
		msg, _ := fnBytes(m["msg"])
		sig, _ := fnBytes(m["sig"])
		out = append(out, fnKat{pk, msg, sig})
	}
	return out
}

func fnSuiteOut(alg string) (any, error) {
	s, ok := ResolveFnDsaAlg(alg)
	if !ok {
		return nil, nil
	}
	return map[string]any{"alg": s.Alg, "variant": s.Variant, "hasEd25519": s.HasEd25519, "sigBytes": s.SigBytes, "needsPqPk": s.NeedsPqPk,
		"pqPkBytes": s.PqPkBytes, "needsPqSig": s.NeedsPqSig, "pqSigBytes": s.PqSigBytes, "fnSigBytes": s.FnSigBytes}, nil
}

func fnVerifyIn(kind string) vecFn {
	return func(a []any) (any, error) {
		in := vecObj(vecArg(a, 0))
		leaf := vecObj(in["leaf"])
		if leaf == nil {
			return nil, errors.New("leaf is not an object")
		}
		return fnWith(kind, func() (bool, error) {
			return VerifyPcaFndsa(fnStr(in["alg"]), leaf, fnStr(in["holder"]), fnStr(in["pq_pk"]), fnStr(in["sig"]), fnStr(in["pq_sig"]))
		})
	}
}

func fnSignOut(m map[string]string, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return m, nil
}

func TestFnDsaCorpus(t *testing.T) {
	defer ResetFalconBackend()
	replayVectorsCmp(t, "ref-fndsa.json.gz", map[string]vecFn{
		"resolveFnDsaAlg": func(a []any) (any, error) { return fnSuiteOut(fnStr(vecArg(a, 0))) },
		"isKnownFnDsaAlg": func(a []any) (any, error) { return IsKnownFnDsaAlg(fnStr(vecArg(a, 0))), nil },
		"isFnDsaVariant":  func(a []any) (any, error) { return IsFnDsaVariant(fnStr(vecArg(a, 0))), nil },
		"hashKat": func(a []any) (any, error) {
			seed, _ := fnBytes(vecArg(a, 0))
			n, _ := jsNum(vecArg(a, 1))
			if n < 0 {
				return nil, fmt.Errorf("Invalid typed array length: %v", n)
			}
			return vecBytesOut(fnHashKat(seed, int(n))), nil
		},
		"mockKeypair": func(a []any) (any, error) {
			seed := vecArg(a, 1)
			if b, ok := fnBytes(seed); ok {
				seed = b
			}
			return fnMockKeypair(fnStr(vecArg(a, 0)), seed)
		},
		"fndsaLeafMessage": func(a []any) (any, error) {
			leaf := vecObj(vecArg(a, 0))
			if leaf == nil {
				return nil, errors.New("leaf is not an object")
			}
			b, err := FnDsaLeafMessage(leaf, fnStr(vecArg(a, 1)), fnStr(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(b), nil
		},
		"fndsaSignWith": func(a []any) (any, error) {
			sk, ok1 := fnBytes(vecArg(a, 2))
			msg, ok2 := fnBytes(vecArg(a, 3))
			if !ok1 || !ok2 { // the reference refuses a non-byte key or message
				return nil, errors.New("secret key and message must be byte strings")
			}
			sig, err := fnWith(fnStr(vecArg(a, 0)), func() ([]byte, error) { return FnDsaSign(fnStr(vecArg(a, 1)), sk, msg) })
			if err != nil {
				return nil, err
			}
			return vecBytesOut(sig), nil
		},
		"fndsaVerifyWith": func(a []any) (any, error) {
			pk, ok1 := fnBytes(vecArg(a, 2))
			msg, ok2 := fnBytes(vecArg(a, 3))
			sig, ok3 := fnBytes(vecArg(a, 4))
			if !ok1 || !ok2 || !ok3 {
				return false, nil
			}
			return fnWith(fnStr(vecArg(a, 0)), func() (bool, error) { return FnDsaVerify(fnStr(vecArg(a, 1)), pk, msg, sig) })
		},
		"fndsaVerifyKat": func(a []any) (any, error) {
			pk, ok1 := fnBytes(vecArg(a, 1))
			msg, ok2 := fnBytes(vecArg(a, 2))
			sig, ok3 := fnBytes(vecArg(a, 3))
			if !ok1 || !ok2 || !ok3 {
				return false, nil
			}
			defer ResetFalconBackend()
			if err := SetFalconBackend(fnMockBackend(fnKats(vecArg(a, 4)))); err != nil {
				return nil, err
			}
			return FnDsaVerify(fnStr(vecArg(a, 0)), pk, msg, sig)
		},
		"fndsaSignKat": func(a []any) (any, error) {
			// the case name carries the variant (fndsaSignKat/<variant>); the kat table must win over the hash-derived signature
			return nil, vecSkip("variant is in the case name: replayed by TestFnDsaSignKat")
		},
		"signPcaWithFndsa": func(a []any) (any, error) {
			in := vecObj(vecArg(a, 0))
			leaf := vecObj(in["leaf"])
			if leaf == nil {
				return nil, errors.New("leaf is not an object")
			}
			fd := vecObj(in["fnDsa"])
			pk, _ := fnBytes(fd["pk"])
			sk, _ := fnBytes(fd["sk"])
			ed, _ := fnBytes(in["edSecret"])
			return fnWith("mock", func() (any, error) { return fnSignOut(SignPcaWithFndsa(fnStr(in["alg"]), leaf, pk, sk, ed)) })
		},
		"verifyPcaFndsa":     fnVerifyIn("mock"),
		"verifyPcaFndsaNone": fnVerifyIn("none"),
	}, nil)
}

func TestFnDsaSignKat(t *testing.T) {
	defer ResetFalconBackend()
	baseEach(t, "ref-fndsa.json.gz", func(c *baseCase) {
		if c.Fn != "fndsaSignKat" {
			return
		}
		variant := c.Name[len("fndsaSignKat/"):]
		kp, err := fnMockKeypair(variant, "ref")
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		sk, _ := fnBytes(kp["sk"])
		if err := SetFalconBackend(fnMockBackend(fnKats(vecArg(c.Args, 0)))); err != nil {
			t.Fatal(err)
		}
		got, err := FnDsaSign(variant, sk, []byte("m"))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if want := baseBytes(c.Out); !bytes.Equal(got, want) {
			t.Fatalf("%s: kat signature not returned", c.Name)
		}
		replayRan("fndsaSignKat")
	})
}

func TestFnDsaNoBackendRefuses(t *testing.T) {
	ResetFalconBackend()
	ok, err := FnDsaVerify("fn-dsa-512", make([]byte, FnDsa512PublicKeyBytes), []byte("m"), make([]byte, FnDsa512SignatureBytes))
	if ok || !errors.Is(err, ErrFnDsaBackendMissing) {
		t.Fatalf("want ErrFnDsaBackendMissing, got %v %v", ok, err)
	}
}
