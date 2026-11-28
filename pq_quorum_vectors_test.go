package pca

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

// Replay of the quorum certificates against the reference (ref-pq-threshold-quorum), every case: set building and loading, the
// signed message, share signing (ML-DSA keys from seed labels, deterministic), proof verification with every refusal reason,
// the guardian-approval adapter, rotation digests, certificates and chains, fork detection and size accounting. Results compare
// as JSON values; a reference throw requires a refusal. Sets handed to the signing and size functions are read without
// validation, as the reference reads them.

// qvSet reads a quorum set object as the reference's untyped functions do: members of the wrong kind read as absent.
func qvSet(v any) (QuorumSet, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return QuorumSet{}, errors.New("not a set object")
	}
	l, ok := m["signers"].([]any)
	if !ok {
		return QuorumSet{}, errors.New("a set without signers")
	}
	set := QuorumSet{}
	if f, ok := jsNum(m["t"]); ok {
		set.T = int(f)
	}
	set.ID, _ = m["id"].(string)
	for _, s := range l {
		e, ok := s.(map[string]any)
		if !ok {
			return QuorumSet{}, errors.New("a signer that is not an object")
		}
		alg, _ := e["alg"].(string)
		ed, _ := e["ed"].(string)
		pq, _ := e["pq"].(string)
		set.Signers = append(set.Signers, QuorumSignerEntry{Alg: alg, Ed: ed, Pq: pq})
	}
	return set, nil
}

// qvIndex is the property-key reading of an index: an integer number, or a canonical numeric string; -1 is no signer.
func qvIndex(v any) int {
	if f, ok := jsNum(v); ok {
		if f == math.Trunc(f) && f >= 0 && f <= maxSafeInt {
			return int(f)
		}
		return -1
	}
	if s, ok := v.(string); ok {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && strconv.Itoa(n) == s {
			return n
		}
	}
	return -1
}

func qvBytes(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return nil, false
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil, false
	}
	b, ok := DecodeB64uStrict(s, -1)
	if ok && b == nil {
		b = []byte{}
	}
	return b, ok
}

// qvList is `[...x]`: an array copies, a string spreads into its UTF-16 units, anything else is not iterable.
func qvList(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return append([]any(nil), x...), nil
	case string:
		out := []any{}
		for _, u := range utf16.Encode([]rune(x)) {
			out = append(out, string(rune(u)))
		}
		return out, nil
	}
	return nil, errors.New("not iterable")
}

// qvKeys builds the key material of a signer from the reference's key object: Ed from edSecret, the ML-DSA pair of the suite
// from mlDsa (65) or mlDsa87 (87), each a 32-byte key generation seed.
func qvKeys(alg string, v any) (SuiteKeys, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return SuiteKeys{}, errors.New("keys is not an object")
	}
	var k SuiteKeys
	if s, ok := m["edSecret"].(string); ok {
		ed, err := KeyPairFromSeedB64u(s)
		if err != nil {
			return SuiteKeys{}, err
		}
		k.Ed = ed
	}
	member, family := "", ""
	switch {
	case strings.HasSuffix(alg, "ml-dsa-65"):
		member, family = "mlDsa", "ML-DSA-65"
	case strings.HasSuffix(alg, "ml-dsa-87"):
		member, family = "mlDsa87", "ML-DSA-87"
	}
	if s, ok := m[member].(string); ok && member != "" {
		seed, ok := DecodeB64uStrict(s, 32)
		if !ok {
			return SuiteKeys{}, errors.New("a key generation seed is 32 bytes")
		}
		pq, err := GeneratePqKeyPairFromSeed(family, seed)
		if err != nil {
			return SuiteKeys{}, err
		}
		k.Opts = &SuiteOpts{Pq: pq}
	}
	return k, nil
}

func qvSign(set QuorumSet, index any, epoch, digest any, keys any) (QuorumShare, error) {
	i := qvIndex(index)
	alg := ""
	if i >= 0 && i < len(set.Signers) {
		alg = set.Signers[i].Alg
	}
	k, err := qvKeys(alg, keys)
	if err != nil {
		return QuorumShare{}, err
	}
	return signQuorumShareValue(set, i, epoch, digest, k)
}

func TestPqQuorumMatchesTheReference(t *testing.T) {
	seeded := func(f vecFn) vecFn {
		return func(a []any) (any, error) { return f(vecResolveSeeds(a).([]any)) }
	}
	asJSON := func(v any) any { return quorumWire(v) }
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"PQ_QUORUM_MAX_SIGNERS": json.Number(strconv.Itoa(PqQuorumMaxSigners)), "PQ_QUORUM_MAX_CHAIN": json.Number(strconv.Itoa(PqQuorumMaxChain))}, nil
		},
		"buildQuorumSet": func(a []any) (any, error) {
			var k any = json.Number("0")
			if len(a) > 2 {
				k = a[2]
			}
			return BuildQuorumSetValue(vecArg(a, 0), vecArg(a, 1), k).JSON(), nil
		},
		"loadQuorumSet": func(a []any) (any, error) { return LoadQuorumSet(vecArg(a, 0)).JSON(), nil },
		"quorumMessage": func(a []any) (any, error) {
			b, err := quorumMessageValue(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(b), nil
		},
		"quorumActionDigest": func(a []any) (any, error) {
			if s, ok := vecArg(a, 0).(string); ok { // the hash utf-8 encodes a string
				return QuorumActionDigest([]byte(s)), nil
			}
			b, ok := qvBytes(vecArg(a, 0))
			if !ok {
				return nil, errors.New("Uint8Array expected")
			}
			return QuorumActionDigest(b), nil
		},
		"signQuorumShare": seeded(func(a []any) (any, error) {
			set, err := qvSet(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			sh, err := qvSign(set, vecArg(a, 1), vecArg(a, 2), vecArg(a, 3), vecArg(a, 4))
			if err != nil {
				return nil, err
			}
			out := asJSON(sh).(map[string]any)
			if s, ok := vecArg(a, 1).(string); ok { // the index is echoed as given
				out["i"] = s
			}
			return out, nil
		}),
		"assembleQuorumProof": func(a []any) (any, error) {
			var set QuorumSet // the reference reads only set.id
			if m, ok := vecArg(a, 0).(map[string]any); ok {
				set.ID, _ = m["id"].(string)
			} else if _, err := qvSet(vecArg(a, 0)); err != nil {
				return nil, err
			}
			l, err := qvList(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return AssembleQuorumProof(set, l), nil
		},
		"verifyQuorum": func(a []any) (any, error) { return VerifyQuorumValue(vecArg(a, 0)).JSON(), nil },
		"verifyQuorumApproval": func(a []any) (any, error) {
			msg, _ := qvBytes(vecArg(a, 2))
			var opts map[string]any
			if len(a) > 4 {
				opts, _ = a[4].(map[string]any)
			}
			return VerifyQuorumApproval(vecArg(a, 0), vecArg(a, 1), msg, vecArg(a, 3), opts), nil
		},
		"rotationActionDigest": func(a []any) (any, error) { return rotationDigestValue(vecArg(a, 0), vecArg(a, 1), true, true) },
		"buildRotationCert": func(a []any) (any, error) {
			from, err := qvSet(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			to, err := qvSet(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			fs, isStr := vecArg(a, 1).(string) // a string epoch is kept and "+ 1" concatenates
			fe, ok := jsNum(vecArg(a, 1))
			if !ok && !isStr {
				return nil, errors.New("from epoch is not a number")
			}
			l, err := qvList(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			cert := BuildRotationCert(from, fe, to, l)
			if isStr {
				out := asJSON(cert).(map[string]any)
				out["from_epoch"], out["to_epoch"] = fs, fs+"1"
				return out, nil
			}
			return cert, nil
		},
		"signRotationShare": seeded(func(a []any) (any, error) {
			from, err := qvSet(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			fe, ok := jsNum(vecArg(a, 2))
			if !ok {
				return nil, errors.New("from epoch is not a number")
			}
			var id any
			hasID := false
			switch to := vecArg(a, 3).(type) {
			case nil:
				return nil, errors.New("to is null") // `to.id` of null throws; of a number it is undefined (left out of the digest)
			case map[string]any:
				id, hasID = to["id"]
			}
			d, err := rotationDigestValue(id, jsNumber(fe+1), hasID, true)
			if err != nil {
				return nil, err
			}
			sh, err := qvSign(from, vecArg(a, 1), jsNumber(fe), d, vecArg(a, 4))
			if err != nil {
				return nil, err
			}
			return asJSON(sh), nil
		}),
		"verifyRotationChain": func(a []any) (any, error) {
			return VerifyRotationChain(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)).JSON(), nil
		},
		"isRotationFork": func(a []any) (any, error) { return IsRotationFork(vecArg(a, 0), vecArg(a, 1)), nil },
		"quorumProofSize": func(a []any) (any, error) {
			set, err := qvSet(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			var idx []int
			if len(a) > 1 {
				l, ok := a[1].([]any)
				if !ok {
					return nil, errors.New("indices.map is not a function")
				}
				idx = []int{}
				for _, x := range l {
					idx = append(idx, qvIndex(x))
				}
			}
			return QuorumProofSize(set, idx)
		},
	}
	replayAll(t, "ref-pq-threshold-quorum.json.gz", 389, fns, nil, nil)
}

// TestPqQuorumTypedAPI drives the typed entry points end to end: a 2-of-3 set of ML-DSA signers, a proof, the refusals of a
// short and a doubled proof, and one rotation to a second set.
func TestPqQuorumTypedAPI(t *testing.T) {
	type who struct {
		pq *PqKeyPair
	}
	mk := func(label string) who {
		enc, _ := vecSeedValue(map[string]any{"$seed": label})
		seed, _ := DecodeB64uStrict(enc, 32)
		pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", seed)
		if err != nil {
			t.Fatal(err)
		}
		return who{pq}
	}
	build := func(ws []who, th int) (QuorumSet, []who) {
		in := make([]QuorumSignerInput, len(ws))
		for i, w := range ws {
			in[i] = QuorumSignerInput{Alg: "ml-dsa-65", Keys: QuorumKeys{MlDsaPub: w.pq.Public}}
		}
		r := BuildQuorumSet(in, th, 0)
		if !r.OK {
			t.Fatalf("set refused: %s", r.Reason)
		}
		ordered := make([]who, len(r.Set.Signers)) // the set sorts its signers
		for i, e := range r.Set.Signers {
			for _, w := range ws {
				if w.pq.Public == e.Pq {
					ordered[i] = w
				}
			}
		}
		return r.Set, ordered
	}
	old, oldW := build([]who{mk("t/a"), mk("t/b"), mk("t/c")}, 2)
	digest := QuorumActionDigest([]byte("approve"))
	share := func(set QuorumSet, ws []who, i int, epoch float64, d string) QuorumShare {
		s, err := SignQuorumShare(set, i, epoch, d, SuiteKeys{Opts: &SuiteOpts{Pq: ws[i].pq}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	proof := AssembleQuorumProof(old, []any{share(old, oldW, 2, 5, digest), share(old, oldW, 0, 5, digest)})
	v := VerifyQuorum(VerifyQuorumInput{Set: old, Proof: proof, Epoch: 5.0, ActionDigest: digest, ExpectedSetID: old.ID})
	if !v.OK || v.Count != 2 || len(v.Signers) != 2 || v.Signers[0] != 0 || v.Signers[1] != 2 {
		t.Fatalf("verdict %+v", v)
	}
	short := AssembleQuorumProof(old, []any{share(old, oldW, 1, 5, digest)})
	if v := VerifyQuorum(VerifyQuorumInput{Set: old, Proof: short, Epoch: 5, ActionDigest: digest}); v.OK || v.Reason != "below-threshold" {
		t.Fatalf("a short proof: %+v", v)
	}
	twice := AssembleQuorumProof(old, []any{share(old, oldW, 1, 5, digest), share(old, oldW, 1, 5, digest)})
	if v := VerifyQuorum(VerifyQuorumInput{Set: old, Proof: twice, Epoch: 5, ActionDigest: digest}); v.OK || v.Reason != "duplicate-signer" || v.Detail != 1 {
		t.Fatalf("a doubled signer: %+v", v)
	}
	if v := VerifyQuorum(VerifyQuorumInput{Set: old, Proof: proof, Epoch: 6, ActionDigest: digest}); v.OK || v.Reason != "bad-signature" {
		t.Fatalf("another epoch: %+v", v)
	}
	msg, err := QuorumMessage(old.ID, 5, digest)
	if err != nil || len(msg) == 0 {
		t.Fatalf("message: %v", err)
	}
	if !VerifyQuorumApproval(old, proof, []byte("approve"), 5.0, nil) {
		t.Fatal("the approval adapter refuses a valid proof")
	}
	// rotation to a fresh set
	next, _ := build([]who{mk("t/d"), mk("t/e")}, 1)
	rd, err := RotationActionDigest(next.ID, 6)
	if err != nil {
		t.Fatal(err)
	}
	_ = rd
	var shares []any
	for _, i := range []int{0, 1} {
		s, err := SignRotationShare(old, i, 5, next, SuiteKeys{Opts: &SuiteOpts{Pq: oldW[i].pq}})
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, s)
	}
	cert := BuildRotationCert(old, 5, next, shares)
	c := VerifyRotationChain(old, 5.0, []any{cert})
	if !c.OK || c.Epoch != 6 || c.Length != 1 || c.Set.ID != next.ID {
		t.Fatalf("chain %+v", c)
	}
	if c := VerifyRotationChain(old, 4.0, []any{cert}); c.OK || c.Reason != "non-monotone-epoch" {
		t.Fatalf("chain at the wrong epoch: %+v", c)
	}
	rep, err := QuorumProofSize(old, []int{0, 9})
	if err != nil || rep.Compact || rep.ChosenBytes == nil || *rep.ChosenBytes != 3309 || rep.MinBytes != 2*3309 {
		t.Fatalf("size %+v %v", rep, err)
	}
}
