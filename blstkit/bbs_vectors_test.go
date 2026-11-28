package blstkit

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
)

// The corpus carries no signing keys: {"$bbssk": n} is BbsKeyGen(32 bytes of n, no info), as an argument and as a keyGen result
// (a key equal to one of the three labelled keys is written as its label).

func bbsSecretOf(v any) *big.Int {
	if k, ok := vecObj(v)["$bbssk"].(json.Number); ok {
		n64, err := k.Int64()
		if err != nil {
			panic(err)
		}
		sk, err := BbsKeyGen(bytesOf(byte(n64), 32), nil)
		if err != nil {
			panic(err)
		}
		return sk
	}
	if label, ok := vecObj(v)["$seed"].(string); ok {
		n := int(label[len(label)-1] - '0')
		sk, err := BbsKeyGen(bytesOf(byte(n), 32), nil)
		if err != nil {
			panic(err)
		}
		return sk
	}
	return unhexScalar(v.(string))
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func unhexScalar(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad scalar " + s)
	}
	return n
}

func hexScalar(n *big.Int) string { return hex.EncodeToString(n.FillBytes(make([]byte, 32))) }

func vecInt(v any) int {
	n, err := v.(json.Number).Int64()
	if err != nil {
		panic(err)
	}
	return int(n)
}

func vecInts(v any) []int {
	l := vecList(v)
	out := make([]int, len(l))
	for i, x := range l {
		if n, ok := x.(json.Number); ok {
			out[i] = vecInt(n)
		} else {
			out[i] = -1 // a JS null or other non-integer index is never a valid index
		}
	}
	return out
}

func bbsRes(r BbsResult) map[string]any {
	if r.Ok {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": r.Reason}
}

func TestBbsMatchesReference(t *testing.T) {
	replay(t, "ref-bbs.json.gz", map[string]vecFn{
		"hashToScalar": func(a []any) (any, error) { return hexScalar(BbsHashToScalar(vecBytes(a[0]), a[1].(string))), nil },
		"mapMessageToScalarAsHash": func(a []any) (any, error) {
			return hexScalar(BbsMapMessageToScalarAsHash(vecBytes(a[0]))), nil
		},
		"createGenerators": func(a []any) (any, error) { return BbsCreateGenerators(vecInt(a[0])) },
		"keyGen": func(a []any) (any, error) {
			sk, err := BbsKeyGen(vecBytes(a[0]), vecBytes(a[1]))
			if err != nil {
				return nil, err
			}
			return hexScalar(sk), nil
		},
		"skToPk": func(a []any) (any, error) { return bytesRes(BbsSkToPk(bbsSecretOf(a[0]))) },
		"sign": func(a []any) (any, error) {
			return bytesRes(BbsSign(bbsSecretOf(a[0]), vecBytes(a[1]), vecBytes(a[2]), vecByteList(a[3])))
		},
		"verifyDetailed": func(a []any) (any, error) {
			return bbsRes(BbsVerifyDetailed(vecBytes(a[0]), vecBytes(a[1]), vecBytes(a[2]), vecByteList(a[3]))), nil
		},
		"proofGen": func(a []any) (any, error) {
			var rs []*big.Int
			for _, s := range vecList(a[6]) {
				rs = append(rs, unhexScalar(s.(string)))
			}
			if rs == nil {
				rs = []*big.Int{}
			}
			return bytesRes(BbsProofGen(vecBytes(a[0]), vecBytes(a[1]), vecBytes(a[2]), vecBytes(a[3]), vecByteList(a[4]), vecInts(a[5]), rs))
		},
		"proofVerifyDetailed": func(a []any) (any, error) {
			return bbsRes(BbsProofVerifyDetailed(vecBytes(a[0]), vecBytes(a[1]), vecBytes(a[2]), vecBytes(a[3]), vecByteList(a[4]), vecInts(a[5]))), nil
		},
		"capabilityAttributes": func(a []any) (any, error) { return BbsCapabilityAttributes(vecObj(a[0])) },
		"issueCapabilityCredential": func(a []any) (any, error) {
			return BbsIssueCapabilityCredential(vecObj(a[0]), bbsSecretOf(a[1]), vecBytes(a[2]), vecBytes(a[3]))
		},
		"verifyCredential": func(a []any) (any, error) { return BbsVerifyCredential(vecObj(a[0])), nil },
		"verifyPresentation": func(a []any) (any, error) {
			o := vecObj(a[1])
			opts := &BbsPresentOptions{}
			if _, ok := o["pk"]; ok {
				opts.PublicKey = vecBytes(o["pk"])
			}
			if _, ok := o["presentationHeader"]; ok {
				opts.PresentationHeader = vecBytes(o["presentationHeader"])
			}
			if d, ok := o["disclosed"]; ok {
				opts.Disclosed = vecList(d)
			}
			return BbsVerifyPresentation(vecObj(a[0]), opts), nil
		},
	}, func(c *vecCase) {
		if c.Fn != "keyGen" {
			return
		}
		if _, ok := vecObj(c.Out)["$bbssk"]; ok {
			c.Out = hexScalar(bbsSecretOf(c.Out))
		}
	})
}

func TestBbsRoundTrip(t *testing.T) {
	sk, pk, err := BbsGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msgs := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	sig, err := BbsSign(sk, pk, []byte("h"), msgs)
	if err != nil || !BbsVerify(pk, sig, []byte("h"), msgs) {
		t.Fatalf("sign/verify: %v", err)
	}
	proof, err := BbsProofGen(pk, sig, []byte("h"), []byte("ph"), msgs, []int{0, 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !BbsProofVerify(pk, proof, []byte("h"), []byte("ph"), [][]byte{msgs[0], msgs[2]}, []int{0, 2}) {
		t.Fatal("proof does not verify")
	}
	if BbsProofVerify(pk, proof, []byte("h"), []byte("other"), [][]byte{msgs[0], msgs[2]}, []int{0, 2}) {
		t.Fatal("proof verified under another presentation header")
	}
}
