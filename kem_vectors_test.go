package pca

// Replays the reference corpus of the key-encapsulation module: the hybrid X25519 + ML-KEM-768 / -1024 KEMs, X-Wing (including the
// draft-09 known-answer vectors) and the FIPS 203 key checks. Secrets in the corpus are seed labels (resolved by the harness); the
// cases that pin the platform CSPRNG feed the derandomised entry points. A reference throw requires a refusal; a JS type confusion
// (a null where bytes are needed) is a refusal too.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

const kemCorpusCases = 464

func kemBytesOut(b []byte) map[string]any {
	return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(b)}
}

// kemArgBytes reads {"$bytes": b64u}, {"$hybridSk": ...} or {"$mlkemDk": ...}.
func kemArgBytes(v any) ([]byte, error) {
	m := vecObj(v)
	if m == nil {
		return nil, errors.New("not bytes")
	}
	if _, ok := m["$bytes"]; ok {
		if b := baseBytes(m); b != nil {
			return b, nil
		}
		return nil, errors.New("bad bytes")
	}
	spec := vecObj(m["$hybridSk"])
	isHybrid := spec != nil
	if !isHybrid {
		if spec = vecObj(m["$mlkemDk"]); spec == nil {
			return nil, errors.New("unknown argument form")
		}
	}
	var lv *kemLevel
	lvlNum, _ := jsNum(spec["level"]) // the corpus carries the level as a JSON number (json.Number), a string in one older form
	switch lvl, _ := spec["level"].(string); {
	case lvl == "768" || lvlNum == 768:
		lv = kemLevel768
	case lvl == "1024" || lvlNum == 1024:
		lv = kemLevel1024
	default:
		return nil, errors.New("bad level")
	}
	d, z := baseBytes(spec["d"]), baseBytes(spec["z"])
	_, dk := lv.fromSeed(append(append([]byte{}, d...), z...))
	out := dk
	if isHybrid {
		out = append(append([]byte{}, baseBytes(spec["x"])...), dk...)
	}
	if n, ok := jsNum(spec["trim"]); ok {
		out = out[:len(out)-int(n)]
	}
	if n, ok := jsNum(spec["pad"]); ok {
		out = append(out, make([]byte, int(n))...)
	}
	if set, ok := spec["set"].([]any); ok {
		for _, p := range set {
			pair, _ := p.([]any)
			off, _ := jsNum(pair[0])
			val, _ := jsNum(pair[1])
			out[int(off)] = byte(val)
		}
	}
	if re, _ := spec["rehash"].(bool); re {
		k := lv.k
		h := sha3.Sum256(out[384*k : 768*k+32])
		copy(out[768*k+32:768*k+64], h[:])
	}
	return out, nil
}

// kemArgRng concatenates a single {"$bytes"} or an array of them.
func kemArgRng(v any) ([]byte, error) {
	if l, ok := v.([]any); ok {
		var out []byte
		for _, p := range l {
			b, err := kemArgBytes(p)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	}
	return kemArgBytes(v)
}

func kemArgs(a []any, n int) ([][]byte, error) {
	out := make([][]byte, n)
	for i := range out {
		b, err := kemArgBytes(vecArg(a, i))
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func kemKeyOut(pub, sk []byte) any {
	h := sha256.Sum256(sk)
	return map[string]any{"publicKey": kemBytesOut(pub), "secretKeySha256": hex.EncodeToString(h[:]), "secretKeyLen": len(sk)}
}

func kemEncOut(e HybridEncapsulation) any {
	return map[string]any{"ciphertext": kemBytesOut(e.Ciphertext), "sharedSecret": kemBytesOut(e.SharedSecret)}
}

// kemLevelArg reads the reference's `level in MLKEM_LEVELS`: the property key is the argument's String(), so the number 768, the
// string "768" and a one-element array of either all name level 768; anything else is no level.
func kemLevelArg(v any) (int, error) {
	switch v.(type) {
	case json.Number, float64, string, []any:
		switch jsValueString(v) {
		case "768":
			return 768, nil
		case "1024":
			return 1024, nil
		}
	}
	return 0, errors.New("level")
}

func kemTestFns(count *int) map[string]vecFn {
	wrap := func(f vecFn) vecFn {
		return func(a []any) (any, error) { *count++; return f(a) }
	}
	hybrid := func(lv *kemLevel, pkLen int, domain, who string, ctLen int) map[string]vecFn {
		return map[string]vecFn{
			"keygen": func(a []any) (any, error) {
				rng, err := kemArgRng(vecArg(a, 0))
				if err != nil {
					return nil, err
				}
				kp, err := kemKeygen(lv, rng)
				if err != nil {
					return nil, err
				}
				return kemKeyOut(kp.PublicKey, kp.SecretKey), nil
			},
			"enc": func(a []any) (any, error) {
				pk, err := kemArgBytes(vecArg(a, 0))
				if err != nil {
					return nil, err
				}
				rng, err := kemArgRng(vecArg(a, 1))
				if err != nil {
					return nil, err
				}
				e, err := kemEncapsulate(lv, pkLen, domain, who, pk, rng)
				if err != nil {
					return nil, err
				}
				return kemEncOut(e), nil
			},
			"dec": func(a []any) (any, error) {
				b, err := kemArgs(a, 2)
				if err != nil {
					return nil, err
				}
				ss, err := kemDecapsulate(lv, ctLen, domain, who, b[0], b[1])
				if err != nil {
					return nil, err
				}
				return kemBytesOut(ss), nil
			},
		}
	}
	h768 := hybrid(kemLevel768, HybridPublicKeyLen, kemDomain768, "HybridEncapsulate", HybridCiphertextLen)
	h1024 := hybrid(kemLevel1024, Hybrid1024PublicKeyLen, kemDomain1024, "HybridEncapsulate1024", Hybrid1024CiphertextLen)
	fns := map[string]vecFn{
		"hybridKemKeygen": h768["keygen"], "hybridEncapsulate": h768["enc"], "hybridDecapsulate": h768["dec"],
		"hybridKem1024Keygen": h1024["keygen"], "hybridEncapsulate1024": h1024["enc"], "hybridDecapsulate1024": h1024["dec"],
		"constants": func(a []any) (any, error) {
			return map[string]any{
				"HYBRID_PUBLIC_KEY_LEN": HybridPublicKeyLen, "HYBRID_CIPHERTEXT_LEN": HybridCiphertextLen,
				"HYBRID_SHARED_SECRET_LEN": HybridSharedSecretLen, "HYBRID_KEM_SUITE": HybridKemSuite, "XWING_SUITE": XWingSuite,
				"XWING_SEED_LEN": XWingSeedLen, "XWING_SECRET_KEY_LEN": XWingSecretKeyLen, "XWING_PUBLIC_KEY_LEN": XWingPublicKeyLen,
				"XWING_CIPHERTEXT_LEN": XWingCiphertextLen, "XWING_SHARED_SECRET_LEN": XWingSharedSecretLen, "XWING_ESEED_LEN": XWingESeedLen,
				"XWING_LABEL": kemBytesOut(XWingLabel()), "HYBRID1024_PUBLIC_KEY_LEN": Hybrid1024PublicKeyLen,
				"HYBRID1024_CIPHERTEXT_LEN": Hybrid1024CiphertextLen, "HYBRID1024_SHARED_SECRET_LEN": Hybrid1024SharedSecretLen,
				"HYBRID1024_KEM_SUITE": Hybrid1024KemSuite,
			}, nil
		},
		"xwingKeygen": func(a []any) (any, error) {
			seed, err := kemArgBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			kp, err := XWingKeygenFromSeed(seed)
			if err != nil {
				return nil, err
			}
			return kemKeyOut(kp.PublicKey, kp.SecretKey), nil
		},
		"xwingEncapsulateDerand": func(a []any) (any, error) {
			pk, err := kemArgBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			eseed, err := kemArgRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			e, err := XWingEncapsulateDerand(pk, eseed)
			if err != nil {
				return nil, err
			}
			return kemEncOut(HybridEncapsulation(e)), nil
		},
		"xwingEncapsulate": func(a []any) (any, error) { // the pinned stream is the 64-byte eseed
			pk, err := kemArgBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			rng, err := kemArgRng(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			e, err := XWingEncapsulateDerand(pk, rng)
			if err != nil {
				return nil, err
			}
			return kemEncOut(HybridEncapsulation(e)), nil
		},
		"xwingDecapsulate": func(a []any) (any, error) {
			b, err := kemArgs(a, 2)
			if err != nil {
				return nil, err
			}
			ss, err := XWingDecapsulate(b[0], b[1])
			if err != nil {
				return nil, err
			}
			return kemBytesOut(ss), nil
		},
		"mlKemEncapsulationKeyCheck": func(a []any) (any, error) {
			lv, err := kemLevelArg(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			ek, _ := kemArgBytes(vecArg(a, 1)) // a non-bytes ek is false, not a refusal
			return MlKemEncapsulationKeyCheck(lv, ek)
		},
		"mlKemDecapsulationKeyCheck": func(a []any) (any, error) {
			lv, err := kemLevelArg(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			dk, _ := kemArgBytes(vecArg(a, 1))
			return MlKemDecapsulationKeyCheck(lv, dk)
		},
	}
	enc := map[string]func([]byte) string{
		"encodeHybridPublicKey": EncodeHybridPublicKey, "encodeHybridCiphertext": EncodeHybridCiphertext,
		"encodeXWingPublicKey": EncodeXWingPublicKey, "encodeXWingCiphertext": EncodeXWingCiphertext,
	}
	for n, f := range enc {
		f := f
		fns[n] = func(a []any) (any, error) {
			b, err := kemArgBytes(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return f(b), nil
		}
	}
	dec := map[string]func(string) ([]byte, error){
		"decodeHybridPublicKey": DecodeHybridPublicKey, "decodeHybridCiphertext": DecodeHybridCiphertext,
		"decodeXWingPublicKey": DecodeXWingPublicKey, "decodeXWingCiphertext": DecodeXWingCiphertext,
	}
	for n, f := range dec {
		f := f
		fns[n] = func(a []any) (any, error) {
			s, ok := vecArg(a, 0).(string)
			if !ok {
				return nil, errors.New("string expected")
			}
			b, err := f(s)
			if err != nil {
				return nil, err
			}
			return kemBytesOut(b), nil
		}
	}
	for n, f := range fns {
		fns[n] = wrap(f)
	}
	return fns
}

func TestKemReferenceVectors(t *testing.T) {
	count := 0
	replayVectorsSeeded(t, "ref-kem.json.gz", kemTestFns(&count))
	if count != kemCorpusCases {
		t.Fatalf("replayed %d cases, the corpus has %d", count, kemCorpusCases)
	}
}

// The randomised entry points are not in the corpus: keygen, encapsulate and decapsulate must agree, and two calls must differ.
func TestKemRoundTrips(t *testing.T) {
	type suite struct {
		keygen func() (HybridKemKeyPair, error)
		enc    func([]byte) (HybridEncapsulation, error)
		dec    func(ct, sk []byte) ([]byte, error)
	}
	for name, s := range map[string]suite{
		"768":  {HybridKemKeygen, HybridEncapsulate, HybridDecapsulate},
		"1024": {HybridKem1024Keygen, HybridEncapsulate1024, HybridDecapsulate1024},
	} {
		kp, err := s.keygen()
		if err != nil {
			t.Fatal(name, err)
		}
		a, err := s.enc(kp.PublicKey)
		if err != nil {
			t.Fatal(name, err)
		}
		b, _ := s.enc(kp.PublicKey)
		got, err := s.dec(a.Ciphertext, kp.SecretKey)
		if err != nil || string(got) != string(a.SharedSecret) {
			t.Fatalf("%s: decapsulate disagrees (%v)", name, err)
		}
		if string(a.SharedSecret) == string(b.SharedSecret) || string(a.Ciphertext) == string(b.Ciphertext) {
			t.Fatalf("%s: two encapsulations are equal", name)
		}
	}
	kp, err := XWingKeygen()
	if err != nil {
		t.Fatal(err)
	}
	a, err := XWingEncapsulate(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := XWingDecapsulate(a.Ciphertext, kp.SecretKey)
	if err != nil || string(got) != string(a.SharedSecret) {
		t.Fatalf("xwing: decapsulate disagrees (%v)", err)
	}
	seed := make([]byte, XWingSeedLen)
	_, _ = rand.Read(seed)
	if k2, _ := XWingKeygenFromSeed(seed); string(k2.SecretKey) != string(seed) {
		t.Fatal("xwing: the secret key is not the seed")
	}
}
