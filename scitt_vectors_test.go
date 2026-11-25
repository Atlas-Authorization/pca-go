package pca

// Replays the SCITT reference corpus (deterministic CBOR codec, RFC 9162 tree, COSE Signed Statements and Receipts, the in-memory
// and durable transparency services, the file log store). A corpus byte string is {"$bytes": b64url}; a CBOR value is JSON with
// {"$bytes"} (bstr), {"$map": [[key, value], ...]} and {"$tag": n, "v": value}. Keys are never committed: a private key is
// {"alg", "$seed": label} (ES256 also carries x and y) and the test re-derives it from sha256("atlas-pca-conformance/" + label)
// (an ES256 scalar clears the top bit of that digest). ES256 signatures are randomized, so those cases compare outcomes only.
//
// Skipped cases (all JSON-representation limits of the adapter, recorded by the tally):
//   - cborEncode of the bare number 0 (the reference case is -0, which JSON cannot carry; Go refuses nothing for 0).
// Everything else in the corpus must match. The corpus predates the 0.5 rule that a present-but-empty verification key is a
// refusal; the corpus carries no such case, so TestScittEmptyKeysRefuse covers it.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func scTB(b []byte) map[string]any { return map[string]any{"$bytes": b64.EncodeToString(b)} }

func scTBytes(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil, false
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func scTBytesOrEmpty(v any) []byte {
	b, _ := scTBytes(v)
	return b
}

func scTList(v any) [][]byte {
	l, _ := v.([]any)
	out := make([][]byte, 0, len(l))
	for _, x := range l {
		out = append(out, scTBytesOrEmpty(x))
	}
	return out
}

func scTBList(l [][]byte) []any {
	out := make([]any, 0, len(l))
	for _, b := range l {
		out = append(out, scTB(b))
	}
	return out
}

// scTInt reads a JSON integer; anything else (a non-integer, a non-number) becomes MinInt64, which every entry point refuses.
func scTInt(v any) int64 {
	f, ok := jsNum(v)
	if !ok || f != math.Trunc(f) || math.Abs(f) > 1<<62 {
		return math.MinInt64
	}
	return int64(f)
}

func scFromCj(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, _ := jsNum(t)
		if f == math.Trunc(f) && math.Abs(f) <= maxSafeInt { // -0 is the integer 0 (the reference encodes a -0 key as 0)
			return int64(f)
		}
		return f
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = scFromCj(x)
		}
		return out
	case map[string]any:
		if _, ok := t["$bytes"]; ok {
			return scTBytesOrEmpty(t)
		}
		if l, ok := t["$map"].([]any); ok {
			m := ScittCborMap{}
			for _, e := range l {
				pair, _ := e.([]any)
				if len(pair) != 2 {
					continue
				}
				m = append(m, ScittCborEntry{Key: scFromCj(pair[0]), Value: scFromCj(pair[1])})
			}
			return m
		}
		if tg, ok := t["$tag"]; ok {
			n := int64(-1)
			if f, ok := jsNum(tg); ok && f == math.Trunc(f) && math.Abs(f) <= maxSafeInt {
				n = int64(f)
			}
			return ScittCborTag{Tag: n, Value: scFromCj(t["v"])}
		}
	}
	return v
}

func scToCj(v any) any {
	switch t := v.(type) {
	case []byte:
		return scTB(t)
	case ScittCborMap:
		l := make([]any, 0, len(t))
		for _, e := range t {
			l = append(l, []any{e.Key, scToCj(e.Value)})
		}
		return map[string]any{"$map": l}
	case ScittCborTag:
		return map[string]any{"$tag": t.Tag, "v": scToCj(t.Value)}
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = scToCj(x)
		}
		return out
	}
	return v
}

func scPubKey(spec any) (crypto.PublicKey, error) {
	m := vecObj(spec)
	switch vecStr(m, "alg") {
	case "EdDSA":
		b, err := b64.DecodeString(vecStr(m, "pub"))
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(b), nil
	case "ES256":
		x, err := b64.DecodeString(vecStr(m, "x"))
		if err != nil {
			return nil, err
		}
		y, err := b64.DecodeString(vecStr(m, "y"))
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	}
	return nil, errors.New("bad public key spec")
}

func scPrivKey(spec any) (string, crypto.PrivateKey, error) {
	m := vecObj(spec)
	alg := vecStr(m, "alg")
	label := vecStr(m, "$seed")
	for _, k := range []string{"seed", "d"} { // the corpus names the key by label: {alg, seed: {$seed}} or, for ES256, {d: {$seed, es256}, x, y}
		if label == "" {
			label = vecStr(vecObj(m[k]), "$seed")
		}
	}
	if label == "" {
		return "", nil, errors.New("bad private key spec")
	}
	h := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	switch alg {
	case "EdDSA":
		return alg, ed25519.NewKeyFromSeed(h[:]), nil
	case "ES256":
		pub, err := scPubKey(spec)
		if err != nil {
			return "", nil, err
		}
		d := h
		d[0] &= 0x7f
		return alg, &ecdsa.PrivateKey{PublicKey: *(pub.(*ecdsa.PublicKey)), D: new(big.Int).SetBytes(d[:])}, nil
	}
	return "", nil, errors.New("bad private key spec")
}

func scSignOpts(spec any) (ScittSignStatementOpts, error) {
	m := vecObj(spec)
	alg, key, err := scPrivKey(m["key"])
	if err != nil {
		return ScittSignStatementOpts{}, err
	}
	o := ScittSignStatementOpts{Alg: alg, Key: key, Issuer: vecStr(m, "issuer")}
	if s, ok := m["subject"].(string); ok {
		o.Subject = &s
	}
	if s, ok := m["contentType"].(string); ok {
		o.ContentType = &s
	}
	return o, nil
}

func scSigner(spec any) (ScittReceiptSigner, error) {
	m := vecObj(spec)
	key := m["key"]
	if key == nil {
		key = spec
	}
	alg, k, err := scPrivKey(key)
	if err != nil {
		return ScittReceiptSigner{}, err
	}
	s := ScittReceiptSigner{Alg: alg, Key: k}
	if iss, ok := m["issuer"].(string); ok {
		s.Issuer = &iss
	}
	return s, nil
}

func scVerifyOpts(op any) (ScittVerifyReceiptOpts, error) {
	var o ScittVerifyReceiptOpts
	m := vecObj(op)
	if s, ok := m["treeRoot"].(string); ok {
		o.TreeRoot = &s
	}
	for _, f := range []struct {
		k string
		p *crypto.PublicKey
	}{{"verificationKey", &o.VerificationKey}, {"statementKey", &o.StatementKey}} {
		if v, ok := m[f.k]; ok && v != nil {
			pk, err := scPubKey(v)
			if err != nil {
				return o, err
			}
			*f.p = pk
		}
	}
	o.AllowHighS, _ = m["allowHighS"].(bool)
	return o, nil
}

func scProofFrom(v any) (ScittInclusionProof, error) {
	m := vecObj(v)
	if m == nil {
		return ScittInclusionProof{}, errors.New("bad proof")
	}
	p := ScittInclusionProof{Index: scTInt(m["index"]), Size: scTInt(m["size"]), Path: []ScittProofStep{}}
	l, ok := m["path"].([]any)
	if !ok {
		return p, errors.New("bad proof")
	}
	for _, x := range l {
		sm := vecObj(x)
		if sm == nil {
			return p, errors.New("bad proof")
		}
		p.Path = append(p.Path, ScittProofStep{Side: vecStr(sm, "side"), Hash: vecStr(sm, "hash")})
	}
	return p, nil
}

// scEncodeProofLoose is encodeInclusionProof over JS-typed members: a string or null size/index is still a CBOR value.
func scEncodeProofLoose(v any) (any, error) {
	m := vecObj(v)
	size, hasSize := m["size"]
	index, hasIndex := m["index"]
	pl, ok := m["path"].([]any)
	if !ok {
		return nil, errors.New("path is not an array")
	}
	sibs := []any{}
	for _, st := range pl {
		sm := vecObj(st)
		if sm == nil {
			return nil, errors.New("bad step")
		}
		h, ok := DecodeB64uStrict(vecStr(sm, "hash"), 32)
		if !ok {
			return nil, errors.New("scitt: proof step hash is not a 32-byte b64u hash")
		}
		sibs = append(sibs, h)
	}
	if !hasSize || !hasIndex {
		return nil, errors.New("cbor: unsupported value")
	}
	b, err := ScittCborEncode([]any{scFromCj(size), scFromCj(index), sibs})
	if err != nil {
		return nil, err
	}
	return scTB(b), nil
}

func scCheckOut(c ScittStatementCheck) map[string]any {
	if c.OK {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": c.Reason}
}

func scErrCode(err error) any {
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return true
}

func scRegMap(r *ScittRegistration) map[string]any {
	return map[string]any{"index": r.Index, "receipt": scTB(r.Receipt), "root": r.Root}
}

func scAppendMap(r *ScittAppendResult) map[string]any {
	m := scRegMap(&r.ScittRegistration)
	m["statement"] = scTB(r.Statement)
	return m
}

func scConsistencyMap(r *ScittConsistencyProofResult) map[string]any {
	return map[string]any{"oldSize": r.OldSize, "newSize": r.NewSize, "oldRoot": r.OldRoot, "newRoot": r.NewRoot, "proof": scTB(r.Proof)}
}

// scFaultStore wraps a store with the corpus fault injections.
type scFaultStore struct {
	inner            ScittLogStore
	drop, short      []int64
	negSize, staleOp bool
}

func (f *scFaultStore) Size() (int64, error) {
	if f.negSize {
		return -1, nil
	}
	return f.inner.Size()
}
func (f *scFaultStore) GetEntry(i int64) ([]byte, bool, error) { return f.inner.GetEntry(i) }
func (f *scFaultStore) GetNode(l, i int64) ([]byte, bool, error) {
	if len(f.drop) == 2 && f.drop[0] == l && f.drop[1] == i {
		return nil, false, nil
	}
	if len(f.short) == 2 && f.short[0] == l && f.short[1] == i {
		return make([]byte, 31), true, nil
	}
	return f.inner.GetNode(l, i)
}
func (f *scFaultStore) Append(n int64, e []byte, nodes []ScittStoredNode) (bool, error) {
	if f.staleOp {
		return false, nil
	}
	return f.inner.Append(n, e, nodes)
}

func scIntList(v any) []int64 {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]int64, 0, len(l))
	for _, x := range l {
		out = append(out, scTInt(x))
	}
	return out
}

func scService(spec any) (any, error) {
	m := vecObj(spec)
	signer, err := scSigner(m)
	if err != nil {
		return nil, err
	}
	var mem *ScittTransparencyService
	var dur *ScittDurableService
	if vecStr(m, "kind") == "memory" {
		mem = NewScittTransparencyService(signer)
	} else {
		var store ScittLogStore = NewScittMemoryLogStore()
		if f := vecObj(m["storeFault"]); f != nil {
			fs := &scFaultStore{inner: store, drop: scIntList(f["dropNode"]), short: scIntList(f["shortNode"])}
			fs.negSize, _ = f["negSize"].(bool)
			fs.staleOp, _ = f["stale"].(bool)
			store = fs
		}
		dur, err = NewScittDurableService(store, signer)
		if err != nil {
			return nil, err
		}
	}
	stmtAlg, stmtKey, err := scPrivKey(m["stmtKey"])
	if err != nil {
		return nil, err
	}
	ops, _ := m["ops"].([]any)
	res := make([]any, 0, len(ops))
	for _, o := range ops {
		op := vecObj(o)
		var v any
		var oerr error
		// a non-integer index / size is refused by the reference like any out-of-range one
		idx := func(k string) int64 { return scTInt(op[k]) }
		switch vecStr(op, "op") {
		case "append":
			so := ScittSignStatementOpts{Alg: stmtAlg, Key: stmtKey, Issuer: "https://issuer.example"}
			if s, ok := op["subject"].(string); ok {
				so.Subject = &s
			}
			if s, ok := op["contentType"].(string); ok {
				so.ContentType = &s
			}
			var r *ScittAppendResult
			if mem != nil {
				r, oerr = mem.AppendAndReceipt(op["payload"], so)
			} else {
				r, oerr = dur.AppendAndReceipt(op["payload"], so)
			}
			if oerr == nil {
				v = scAppendMap(r)
			}
		case "register":
			st, _ := scTBytes(op["statement"])
			var r *ScittRegistration
			if mem != nil {
				r, oerr = mem.Register(st)
			} else {
				r, oerr = dur.Register(st)
			}
			if oerr == nil {
				v = scRegMap(r)
			}
		case "receipt":
			var r *ScittRegistration
			if mem != nil {
				r, oerr = mem.GetReceipt(idx("i"))
			} else {
				r, oerr = dur.GetReceipt(idx("i"))
			}
			if oerr == nil {
				v = scRegMap(r)
			}
		case "consistency":
			var r *ScittConsistencyProofResult
			if mem != nil {
				r, oerr = mem.ConsistencyProof(idx("m"))
			} else {
				r, oerr = dur.ConsistencyProof(idx("m"))
			}
			if oerr == nil {
				v = scConsistencyMap(r)
			}
		case "entry":
			if mem != nil { // the in-memory reference service has no getEntry
				oerr = errors.New("getEntry is not a function")
			} else {
				var e []byte
				e, oerr = dur.GetEntry(idx("i"))
				if oerr == nil {
					v = scTB(e)
				}
			}
		case "snapshot":
			if mem != nil {
				l := []any{}
				for _, s := range mem.Snapshot() {
					l = append(l, s)
				}
				v = l
			} else { // the durable service has no snapshot
				oerr = errors.New("snapshot is not a function")
			}
		case "root":
			if mem != nil {
				v = mem.Root()
			} else {
				v, oerr = dur.Root()
			}
		case "size":
			if mem != nil {
				v = mem.Size()
			} else {
				v, oerr = dur.Size()
			}
		default:
			oerr = errors.New("op")
		}
		if oerr != nil {
			res = append(res, map[string]any{"err": scErrCode(oerr)})
		} else {
			res = append(res, map[string]any{"ok": v})
		}
	}
	return res, nil
}

func scEs256SignVerify(args []any) (any, error) {
	_, key, err := scPrivKey(vecArg(args, 0))
	if err != nil {
		return nil, err
	}
	pub, err := scPubKey(vecArg(args, 0))
	if err != nil {
		return nil, err
	}
	st, err := ScittSignStatement(vecArg(args, 1), ScittSignStatementOpts{Alg: ScittAlgES256, Key: key, Issuer: fmt.Sprint(vecArg(args, 2))})
	if err != nil {
		return nil, err
	}
	c, err := ScittDecodeCoseSign1(st)
	if err != nil {
		return nil, err
	}
	payload, err := ScittStatementPayload(st)
	if err != nil {
		return nil, err
	}
	s := new(big.Int).SetBytes(c.Signature[32:])
	return map[string]any{
		"check":          scCheckOut(ScittCheckStatement(st, pub, false)),
		"payload":        scTB(payload),
		"lowS":           s.Cmp(scP256Half) <= 0,
		"protectedBytes": scTB(c.ProtectedBytes),
	}, nil
}

func scEs256Receipt(args []any) (any, error) {
	signer, err := scSigner(map[string]any{"key": vecArg(args, 0), "issuer": "ts"})
	if err != nil {
		return nil, err
	}
	pub, err := scPubKey(vecArg(args, 0))
	if err != nil {
		return nil, err
	}
	n, index := scTInt(vecArg(args, 1)), scTInt(vecArg(args, 2))
	edAlg, edKey, err := scPrivKey(vecArg(args, 3))
	if err != nil {
		return nil, err
	}
	edPub := edKey.(ed25519.PrivateKey).Public()
	wrong, err := scPubKey(vecArg(args, 4))
	if err != nil {
		return nil, err
	}
	ts := NewScittTransparencyService(signer)
	var sts [][]byte
	for i := int64(0); i < n; i++ {
		r, err := ts.AppendAndReceipt(map[string]any{"i": json.Number(strconv.FormatInt(i, 10))}, ScittSignStatementOpts{Alg: edAlg, Key: edKey, Issuer: "iss"})
		if err != nil {
			return nil, err
		}
		sts = append(sts, r.Statement)
	}
	r, err := ts.GetReceipt(index)
	if err != nil {
		return nil, err
	}
	root := r.Root
	return map[string]any{
		"key":            ScittVerifyReceipt(r.Receipt, sts[index], ScittVerifyReceiptOpts{VerificationKey: pub}),
		"root":           ScittVerifyReceipt(r.Receipt, sts[index], ScittVerifyReceiptOpts{TreeRoot: &root}),
		"both":           ScittVerifyReceipt(r.Receipt, sts[index], ScittVerifyReceiptOpts{VerificationKey: pub, TreeRoot: &root, StatementKey: edPub}),
		"wrongKey":       ScittVerifyReceipt(r.Receipt, sts[index], ScittVerifyReceiptOpts{VerificationKey: wrong}),
		"otherStatement": ScittVerifyReceipt(r.Receipt, sts[(index+1)%n], ScittVerifyReceiptOpts{VerificationKey: pub}),
		"none":           ScittVerifyReceipt(r.Receipt, sts[index], ScittVerifyReceiptOpts{}),
	}, nil
}

func TestScittVectors(t *testing.T) {
	tmp, err := os.MkdirTemp("", "scitt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	fileN := 0
	nextFile := func(prefix string) string {
		fileN++
		return filepath.Join(tmp, prefix+strconv.Itoa(fileN)+".log")
	}
	opt := func(args []any, i int) any { return vecArg(args, i) }
	zeroEncodes := 0

	replayVectors(t, "ref-scitt.json.gz", map[string]vecFn{
		"cborEncode": func(a []any) (any, error) {
			// the corpus lists the number 0 first and the reference's -0 last; JSON cannot tell them apart, and Go refuses a float64 -0
			if n, ok := opt(a, 0).(json.Number); ok {
				if f, _ := jsNum(n); f == 0 {
					if zeroEncodes++; zeroEncodes > 1 {
						// DELIBERATE: the reference refuses -0 too, but JSON cannot carry it here; the native's refusal of a float64 -0 is
						// asserted with its exact error instead of the case silently passing.
						if _, err := ScittCborEncode(math.Copysign(0, -1)); err == nil || err.Error() != "cbor: unsupported value" {
							t.Errorf("a float64 -0 must be refused with %q, got %v", "cbor: unsupported value", err)
						}
						return nil, vecSkip("negative zero has no JSON representation: native refusal asserted above")
					}
				}
			}
			b, err := ScittCborEncode(scFromCj(opt(a, 0)))
			if err != nil {
				return nil, err
			}
			return scTB(b), nil
		},
		"cborDecode": func(a []any) (any, error) {
			v, err := ScittCborDecode(scTBytesOrEmpty(opt(a, 0)))
			if err != nil {
				return nil, err
			}
			return scToCj(v), nil
		},
		"emptyRoot": func(a []any) (any, error) { return scTB(ScittEmptyRoot()), nil },
		"leafHash":  func(a []any) (any, error) { return scTB(ScittLeafHash(scTBytesOrEmpty(opt(a, 0)))), nil },
		"nodeHash": func(a []any) (any, error) {
			return scTB(ScittNodeHash(scTBytesOrEmpty(opt(a, 0)), scTBytesOrEmpty(opt(a, 1)))), nil
		},
		"treeHash": func(a []any) (any, error) { return scTB(ScittTreeHash(scTList(opt(a, 0)))), nil },
		"inclusionPath": func(a []any) (any, error) {
			p, err := ScittInclusionPath(scTList(opt(a, 0)), scTInt(opt(a, 1)))
			if err != nil {
				return nil, err
			}
			return scTBList(p), nil
		},
		"rootFromInclusionPath": func(a []any) (any, error) {
			r := ScittRootFromInclusionPath(scTBytesOrEmpty(opt(a, 0)), scTInt(opt(a, 1)), scTInt(opt(a, 2)), scTList(opt(a, 3)))
			if r == nil {
				return nil, nil
			}
			return scTB(r), nil
		},
		"verifyInclusionPath": func(a []any) (any, error) {
			return ScittVerifyInclusionPath(scTBytesOrEmpty(opt(a, 0)), scTInt(opt(a, 1)), scTInt(opt(a, 2)), scTList(opt(a, 3)), scTBytesOrEmpty(opt(a, 4))), nil
		},
		"consistencyPath": func(a []any) (any, error) {
			p, err := ScittConsistencyPath(scTList(opt(a, 0)), scTInt(opt(a, 1)))
			if err != nil {
				return nil, err
			}
			return scTBList(p), nil
		},
		"verifyConsistencyPath": func(a []any) (any, error) {
			return ScittVerifyConsistencyPath(scTInt(opt(a, 0)), scTInt(opt(a, 1)), scTBytesOrEmpty(opt(a, 2)), scTBytesOrEmpty(opt(a, 3)), scTList(opt(a, 4))), nil
		},
		"siblingSides": func(a []any) (any, error) {
			out := []any{}
			for _, s := range ScittSiblingSides(scTInt(opt(a, 0)), scTInt(opt(a, 1))) {
				out = append(out, s)
			}
			return out, nil
		},
		"encodeInclusionProof": func(a []any) (any, error) { return scEncodeProofLoose(opt(a, 0)) },
		"decodeInclusionProof": func(a []any) (any, error) {
			p, err := ScittDecodeInclusionProof(scTBytesOrEmpty(opt(a, 0)))
			if err != nil {
				return nil, err
			}
			return p, nil
		},
		"signStatement": func(a []any) (any, error) {
			o, err := scSignOpts(opt(a, 1))
			if err != nil {
				return nil, err
			}
			b, err := ScittSignStatement(opt(a, 0), o)
			if err != nil {
				return nil, err
			}
			return scTB(b), nil
		},
		"decodeCoseSign1": func(a []any) (any, error) {
			c, err := ScittDecodeCoseSign1(scTBytesOrEmpty(opt(a, 0)))
			if err != nil {
				return nil, err
			}
			var payload any
			if !c.Detached {
				payload = scTB(c.Payload)
			}
			return map[string]any{
				"protectedBytes": scTB(c.ProtectedBytes),
				"protectedMap":   scToCj(c.ProtectedMap),
				"unprotected":    scToCj(c.Unprotected),
				"payload":        payload,
				"signature":      scTB(c.Signature),
			}, nil
		},
		"checkStatement": func(a []any) (any, error) {
			pub, err := scPubKey(opt(a, 1))
			if err != nil {
				return nil, err
			}
			hi, _ := vecObj(opt(a, 2))["allowHighS"].(bool)
			return scCheckOut(ScittCheckStatement(scTBytesOrEmpty(opt(a, 0)), pub, hi)), nil
		},
		"verifyStatement": func(a []any) (any, error) {
			pub, err := scPubKey(opt(a, 1))
			if err != nil {
				return nil, err
			}
			hi, _ := vecObj(opt(a, 2))["allowHighS"].(bool)
			return ScittVerifyStatement(scTBytesOrEmpty(opt(a, 0)), pub, hi), nil
		},
		"statementPayload": func(a []any) (any, error) {
			p, err := ScittStatementPayload(scTBytesOrEmpty(opt(a, 0)))
			if err != nil {
				return nil, err
			}
			return scTB(p), nil
		},
		"statementLeaf": func(a []any) (any, error) { return ScittStatementLeaf(scTBytesOrEmpty(opt(a, 0))), nil },
		"buildReceipt": func(a []any) (any, error) {
			root, _ := opt(a, 0).(string)
			p, err := scProofFrom(opt(a, 1))
			if err != nil {
				return nil, err
			}
			signer, err := scSigner(opt(a, 2))
			if err != nil {
				return nil, err
			}
			b, err := ScittBuildReceipt(root, p, signer)
			if err != nil {
				return nil, err
			}
			return scTB(b), nil
		},
		"verifyReceipt": func(a []any) (any, error) {
			o, err := scVerifyOpts(opt(a, 2))
			if err != nil {
				return nil, err
			}
			return ScittVerifyReceipt(scTBytesOrEmpty(opt(a, 0)), scTBytesOrEmpty(opt(a, 1)), o), nil
		},
		"verifyConsistencyProof": func(a []any) (any, error) {
			o, _ := opt(a, 1).(string)
			n, _ := opt(a, 2).(string)
			return ScittVerifyConsistencyProof(scTBytesOrEmpty(opt(a, 0)), o, n), nil
		},
		"constants": func(a []any) (any, error) {
			return map[string]any{
				"COSE_SIGN1_TAG": ScittCoseSign1Tag, "HDR_ALG": ScittHdrAlg, "HDR_CONTENT_TYPE": ScittHdrContentType,
				"HDR_CWT_CLAIMS": ScittHdrCwtClaims, "CWT_ISS": ScittCwtIss, "CWT_SUB": ScittCwtSub, "HDR_VDS": ScittHdrVds,
				"HDR_VDS_PROOFS": ScittHdrVdsProofs, "VDS_RFC9162_SHA256": ScittVdsRfc9162Sha256,
				"PROOF_TYPE_INCLUSION": ScittProofTypeInclusion, "DEFAULT_CONTENT_TYPE": ScittDefaultContentType,
			}, nil
		},
		"es256SignVerify": scEs256SignVerify,
		"es256Receipt":    scEs256Receipt,
		"service":         func(a []any) (any, error) { return scService(opt(a, 0)) },
		"fileStoreBytes": func(a []any) (any, error) {
			path := nextFile("f")
			s, err := OpenScittFileLogStore(path)
			if err != nil {
				return nil, err
			}
			ops, _ := opt(a, 0).([]any)
			for _, o := range ops {
				op := vecObj(o)
				var nodes []ScittStoredNode
				nl, _ := op["nodes"].([]any)
				for _, n := range nl {
					parts, _ := n.([]any)
					if len(parts) != 3 {
						continue
					}
					hs, _ := parts[2].(string)
					h, _ := b64.DecodeString(hs)
					nodes = append(nodes, ScittStoredNode{Level: scTInt(parts[0]), Index: scTInt(parts[1]), Hash: h})
				}
				// a refused / malformed append writes nothing
				_, _ = s.Append(scTInt(op["expected"]), scTBytesOrEmpty(op["entry"]), nodes)
			}
			s.Close()
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			return scTB(b), nil
		},
		"fileStoreOpen": func(a []any) (any, error) {
			path := nextFile("o")
			if err := os.WriteFile(path, scTBytesOrEmpty(opt(a, 0)), 0o644); err != nil {
				return nil, err
			}
			s, err := OpenScittFileLogStore(path)
			if err != nil {
				return nil, err
			}
			defer s.Close()
			size, _ := s.Size()
			entries := []any{}
			nodes0 := []any{}
			for i := int64(0); i < size; i++ {
				e, _, err := s.GetEntry(i)
				if err != nil {
					return nil, err
				}
				entries = append(entries, scTB(e))
				h, found, err := s.GetNode(0, i)
				if err != nil {
					return nil, err
				}
				if found {
					nodes0 = append(nodes0, scTB(h))
				} else {
					nodes0 = append(nodes0, nil)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			return map[string]any{"size": size, "entries": entries, "nodes0": nodes0, "after": scTB(after)}, nil
		},
		"checkScittLogStore": func(a []any) (any, error) {
			kind, _ := opt(a, 0).(string)
			newStore := func() (ScittLogStore, error) { return NewScittMemoryLogStore(), nil }
			if kind == "file" {
				newStore = func() (ScittLogStore, error) { return OpenScittFileLogStore(nextFile("c")) }
			}
			out := []any{}
			for _, f := range ScittCheckLogStore(newStore) {
				out = append(out, f)
			}
			return out, nil
		},
	})
}

// A present-but-unusable verification key is a refusal (the reference fixed a fail-open where an empty key skipped the check):
// a nil key, an empty ed25519 key, a nil EC key, the wrong key type and a missing anchor all refuse; no corpus case covers them.
func TestScittEmptyKeysRefuse(t *testing.T) {
	seed := sha256.Sum256([]byte("atlas-pca-conformance/scitt/ts"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	stmt, err := ScittSignStatement(map[string]any{"a": json.Number("1")}, ScittSignStatementOpts{Alg: ScittAlgEdDSA, Key: priv, Issuer: "iss"})
	if err != nil {
		t.Fatal(err)
	}
	ts := NewScittTransparencyService(ScittReceiptSigner{Alg: ScittAlgEdDSA, Key: priv})
	reg, err := ts.Register(stmt)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	root := reg.Root
	if !ScittVerifyReceipt(reg.Receipt, stmt, ScittVerifyReceiptOpts{VerificationKey: pub, TreeRoot: &root, StatementKey: pub}) {
		t.Fatal("the genuine receipt must verify")
	}
	var nilEC *ecdsa.PublicKey
	bad := []crypto.PublicKey{ed25519.PublicKey(nil), ed25519.PublicKey{}, ed25519.PublicKey(make([]byte, 31)), nilEC, &ecdsa.PublicKey{}, "key", 7}
	for i, k := range bad {
		if ScittVerifyStatement(stmt, k, false) {
			t.Errorf("bad key %d verified a statement", i)
		}
		if ScittVerifyReceipt(reg.Receipt, stmt, ScittVerifyReceiptOpts{VerificationKey: k}) {
			t.Errorf("bad key %d verified a receipt as the service key", i)
		}
		if ScittVerifyReceipt(reg.Receipt, stmt, ScittVerifyReceiptOpts{TreeRoot: &root, VerificationKey: k}) {
			t.Errorf("bad key %d was skipped next to a pinned root", i)
		}
		if ScittVerifyReceipt(reg.Receipt, stmt, ScittVerifyReceiptOpts{TreeRoot: &root, StatementKey: k}) {
			t.Errorf("bad key %d was skipped as the statement key", i)
		}
	}
	if ScittVerifyReceipt(reg.Receipt, stmt, ScittVerifyReceiptOpts{}) {
		t.Error("a receipt with no anchor verified")
	}
}

// The reference refuses a negative zero (the corpus cannot carry one); a Go float64 is never a CBOR integer here.
func TestScittCborRefusesNegativeZero(t *testing.T) {
	if _, err := ScittCborEncode(math.Copysign(0, -1)); err == nil || err.Error() != "cbor: unsupported value" {
		t.Errorf("a float64 negative zero must be refused with the exact error, got %v", err)
	}
}
