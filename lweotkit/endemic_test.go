package lweotkit

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The reference corpus (testdata/ref-mpc-endemic.json.gz): bytes are {"$bytes": b64url}; {"$throws": ...} means the native must refuse.
type refCase struct {
	Fn   string `json:"fn"`
	Name string `json:"name"`
	Args []any  `json:"args"`
	Out  any    `json:"out"`
}

func cases(t *testing.T, fn string) []refCase {
	t.Helper()
	f, err := os.Open("testdata/ref-mpc-endemic.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []refCase `json:"cases"`
	}
	if err := json.NewDecoder(gz).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	var out []refCase
	for _, c := range doc.Cases {
		if c.Fn == fn {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no oracle cases for %s", fn)
	}
	return out
}

func b64(b []byte) any { return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(b)} }

func by(v any) []byte {
	b, err := base64.RawURLEncoding.DecodeString(v.(map[string]any)["$bytes"].(string))
	if err != nil {
		panic(err)
	}
	return b
}

func bl(a [][]byte) []any {
	o := make([]any, len(a))
	for i, x := range a {
		o[i] = b64(x)
	}
	return o
}

func bp(a [][2][]byte) []any {
	o := make([]any, len(a))
	for i, x := range a {
		o[i] = []any{b64(x[0]), b64(x[1])}
	}
	return o
}

func ints(v any) []int {
	l := v.([]any)
	o := make([]int, len(l))
	for i, x := range l {
		o[i] = int(x.(float64))
	}
	return o
}

func rng(v any) *SplitMix64 {
	n, err := strconv.ParseUint(v.(string), 10, 64)
	if err != nil {
		panic(err)
	}
	return NewSplitMix64(n)
}

// seed is the receiver key seed for a label, as the generator derives it.
func seed(label any) []byte {
	h := sha256.Sum256([]byte("atlas-pca-conformance/" + label.(string)))
	return h[:]
}

func canon(v any) string { b, _ := json.Marshal(v); return string(b) } // encoding/json sorts map keys

// replay runs f over every case of fn: a reference throw needs an error, else the result must equal the reference value.
func replay(t *testing.T, fn string, f func(a []any) (any, error)) {
	t.Helper()
	var bad []string
	for _, c := range cases(t, fn) {
		om, _ := c.Out.(map[string]any)
		_, isThrow := om["$throws"]
		got, err := func() (g any, e error) {
			defer func() {
				if r := recover(); r != nil {
					e = fmt.Errorf("panic: %v", r)
				}
			}()
			return f(c.Args)
		}()
		switch {
		case isThrow && err == nil:
			bad = append(bad, c.Name+": want a refusal, got a value")
		case !isThrow && err != nil:
			bad = append(bad, c.Name+": unexpected "+err.Error())
		case !isThrow:
			var round any
			raw, _ := json.Marshal(got)
			_ = json.Unmarshal(raw, &round)
			if !reflect.DeepEqual(round, c.Out) {
				bad = append(bad, c.Name+": value differs from the reference")
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("%d divergent case(s) of %s:\n%s", len(bad), fn, strings.Join(bad[:min(len(bad), 20)], "\n"))
	}
}

func fill(n, k int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + k*7 + (i >> 3))
	}
	return b
}

func flip(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[i] ^ 1
	}
	return o
}

func TestLweKeygenFips(t *testing.T) {
	replay(t, "lweKeygenFips", func(a []any) (any, error) {
		pk, sk, err := KPKEKeygenFips203(seed(a[0]))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(sk)
		return map[string]any{"pk": b64(pk), "skSha256": hex.EncodeToString(h[:])}, nil
	})
}

func TestLweKeygen(t *testing.T) {
	replay(t, "lweKeygen", func(a []any) (any, error) {
		pk, sk, err := KPKEKeygen(seed(a[0]))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(sk)
		return map[string]any{"pk": b64(pk), "skSha256": hex.EncodeToString(h[:])}, nil
	})
}

func TestLweEnc(t *testing.T) {
	replay(t, "lweEnc", func(a []any) (any, error) {
		pk, _, err := KPKEKeygen(seed(a[0]))
		if err != nil {
			return nil, err
		}
		ct, err := KPKEEnc(pk, by(a[1]), by(a[2]))
		return b64(ct), err
	})
}

func TestLweDec(t *testing.T) {
	replay(t, "lweDec", func(a []any) (any, error) {
		_, sk, err := KPKEKeygen(seed(a[0]))
		if err != nil {
			return nil, err
		}
		m, err := KPKEDec(sk, by(a[1]))
		return b64(m), err
	})
}

func TestLweRing(t *testing.T) {
	replay(t, "lweRing", func(a []any) (any, error) {
		f := RingSub
		if a[0] == "add" {
			f = RingAdd
		}
		o, err := f(by(a[1]), by(a[2]))
		return b64(o), err
	})
}

func TestLweHash(t *testing.T) {
	replay(t, "lweHash", func(a []any) (any, error) {
		o, err := HashToRing(by(a[0]))
		return b64(o), err
	})
}

func TestRandomOt(t *testing.T) {
	replay(t, "randomOt", func(a []any) (any, error) {
		m, st, err := Receive(ints(a[0]), rng(a[1]))
		if err != nil {
			return nil, err
		}
		sm, err := SendRandom(m, rng(a[2]), nil)
		if err != nil {
			return nil, err
		}
		rp, err := RecoverRandom(st, sm)
		if err != nil {
			return nil, err
		}
		return map[string]any{"rn": b64(m.Rn), "points": bp(m.Points), "rhos": bl(m.Rhos), "ciphertexts": bp(sm.Ciphertexts), "senderPads": bp(sm.SenderPads), "recvPads": bl(rp)}, nil
	})
}

func TestRandomOtTamper(t *testing.T) {
	replay(t, "randomOtTamper", func(a []any) (any, error) {
		m, st, err := Receive(ints(a[0]), rng(a[1]))
		if err != nil {
			return nil, err
		}
		sm, err := SendRandom(m, rng(a[2]), func(c [][2][]byte) { c[0][0] = c[0][0][:1087] })
		if err != nil {
			return nil, err
		}
		rp, err := RecoverRandom(st, sm)
		return bl(rp), err
	})
}

func TestBaseOt(t *testing.T) {
	replay(t, "baseOt", func(a []any) (any, error) {
		var msgs [][2][]byte
		for _, p := range a[0].([]any) {
			pp := p.([]any)
			msgs = append(msgs, [2][]byte{by(pp[0]), by(pp[1])})
		}
		choices := ints(a[1])
		r := rng(a[2]) // one generator serves the receiver and then the sender, as the reference does
		var tamper func([][2][]byte)
		switch a[3] {
		case "enc":
			tamper = func(e [][2][]byte) { e[0][0] = flip(e[0][0]) }
		case "encChosen":
			tamper = func(e [][2][]byte) { c := choices[0] & 1; e[0][c] = flip(e[0][c]) }
		}
		got, tr, err := BaseOT(msgs, choices, r, r, tamper)
		if err != nil {
			return nil, err
		}
		return map[string]any{"received": bl(got), "ciphertexts": bp(tr.Ciphertexts), "encrypted": bp(tr.Encrypted), "commitments": bp(tr.Commitments)}, nil
	})
}

func TestSendMalformed(t *testing.T) {
	replay(t, "sendMalformed", func(a []any) (any, error) {
		m, _, err := Receive([]int{0, 1}, rng("77"))
		if err != nil {
			return nil, err
		}
		mm := &ReceiverMessage{Rn: m.Rn, Points: append([][2][]byte{}, m.Points...), Rhos: append([][]byte{}, m.Rhos...)}
		switch a[0] {
		case "nonce":
			mm.Rn = fill(31, 1)
		case "count":
			mm.Rhos = mm.Rhos[1:]
		case "point":
			mm.Points[1][0] = fill(1151, 1)
		case "rho":
			mm.Rhos[0] = fill(33, 1)
		}
		sm, err := SendRandom(mm, rng("78"), nil)
		if err != nil {
			return nil, err
		}
		return len(sm.Ciphertexts), nil
	})
}
