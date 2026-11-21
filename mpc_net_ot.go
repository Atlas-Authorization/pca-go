package pca

// Pairwise base oblivious transfer over the pinned mesh (a functional-correctness demonstration, wire-compatible with the
// reference): kind "ec" is the malicious-secure Ed25519 base OT; kind "lwe" is the post-quantum endemic OT, whose lattice core
// lives in a separate cgo module and is plugged in with MpcRegisterLweOt. After the OT the receiver reveals its choices and a hash
// of each received pad so the sender can check the two sides agree (demo only, not part of the OT).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// MpcLweOt is the endemic-LWE base OT in plain bytes. A binary without cgo leaves it unregistered, so kind "lwe" fails closed.
type MpcLweOt interface {
	// Receive builds the receiver message (rn, points, rhos) and its private state.
	Receive(choices []int) (rn []byte, points [][2][]byte, rhos [][]byte, state any, err error)
	// SendRandom answers a receiver message with ciphertexts and the sender's two pads per transfer.
	SendRandom(rn []byte, points [][2][]byte, rhos [][]byte) (cts, pads [][2][]byte, err error)
	// RecoverRandom decrypts the chosen ciphertext of each transfer into the receiver's pad.
	RecoverRandom(state any, cts [][2][]byte) ([][]byte, error)
}

var (
	mpcLweMu  sync.RWMutex
	mpcLweImp MpcLweOt
)

// MpcRegisterLweOt installs the endemic-LWE implementation (call once, at start-up, from an lwe-capable binary).
func MpcRegisterLweOt(impl MpcLweOt) {
	mpcLweMu.Lock()
	mpcLweImp = impl
	mpcLweMu.Unlock()
}

func mpcLweOt() MpcLweOt {
	mpcLweMu.RLock()
	defer mpcLweMu.RUnlock()
	return mpcLweImp
}

// MpcOtNetResult is the verdict of one OT role, with the reference's member names minus the wasm flag.
type MpcOtNetResult struct {
	Kind      string
	Role      string
	Count     int
	Ms        float64
	Matched   bool
	PadDigest string
}

func mpcOtSha(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// mpcUnb64 is strict standard base64 (re-encoding must reproduce the text) of the given length (-1 = any).
func mpcUnb64(v any, ln int) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("bad base64")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("bad base64")
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("non-canonical base64")
	}
	if ln >= 0 && len(b) != ln {
		return nil, errors.New("bad length")
	}
	return b, nil
}

func mpcB64Pairs(p [][2][]byte) []any {
	out := make([]any, len(p))
	for i, x := range p {
		out[i] = []any{base64.StdEncoding.EncodeToString(x[0]), base64.StdEncoding.EncodeToString(x[1])}
	}
	return out
}

func mpcUnb64Pairs(v any, count int, what string) ([][2][]byte, error) {
	l, ok := v.([]any)
	if !ok || len(l) != count {
		return nil, fmt.Errorf("bad %s array", what)
	}
	out := make([][2][]byte, count)
	for i, e := range l {
		pp, ok := e.([]any)
		if !ok || len(pp) != 2 {
			return nil, fmt.Errorf("bad %s pair", what)
		}
		a, err := mpcUnb64(pp[0], -1)
		if err != nil {
			return nil, err
		}
		b, err := mpcUnb64(pp[1], -1)
		if err != nil {
			return nil, err
		}
		out[i] = [2][]byte{a, b}
	}
	return out, nil
}

// mpcOtMalformed fails the mesh naming peer, as the reference's parsing() does.
func mpcOtMalformed(mesh *MpcMesh, peer int, detail string) error {
	ne := mpcAbortF("malformed", mpcIntP(peer), mesh.selfID, detail, "")
	mesh.Fail(ne)
	return ne
}

func mpcOtBinding(mesh *MpcMesh, sender, receiver int) MpcBaseOtBinding {
	sid := sha256.Sum256(append([]byte("atlas-pca-mpc/net-session/v2"), wellFormedUTF8(mesh.SessionID())...))
	return MpcBaseOtBinding{SessionID: sid[:], SenderIndex: int64(sender), ReceiverIndex: int64(receiver), Round: "ot-ec"}
}

func mpcOtKindOK(kind string) error {
	switch kind {
	case "ec":
		return nil
	case "lwe":
		if mpcLweOt() == nil {
			return errors.New("ot kind 'lwe' needs the endemic-LWE library, which this binary was built without (use the lwe-capable party build); refusing, not falling back to ec")
		}
		return nil
	}
	return fmt.Errorf("unknown ot kind %q", kind)
}

// MpcRunOtSender is the OT sender role against peer.
func MpcRunOtSender(mesh *MpcMesh, peer int, kind string, count int) (*MpcOtNetResult, error) {
	if err := mpcOtKindOK(kind); err != nil {
		return nil, err
	}
	t0 := time.Now()
	rng := MpcSecureOtRandom()
	var pads [][2][]byte
	if kind == "ec" {
		b := mpcOtBinding(mesh, mesh.selfID, peer)
		setup, err := MpcMalBaseOtSenderSetup(rng, b)
		if err != nil {
			return nil, err
		}
		if err := mesh.Send(peer, "ot-S", map[string]any{"S": MpcPtJ(setup.S), "U": MpcPtJ(setup.Proof.U), "z": MpcHx(setup.Proof.Z)}); err != nil {
			return nil, err
		}
		rRaw, err := mesh.Recv(peer, "ot-R", 0)
		if err != nil {
			return nil, err
		}
		l, ok := rRaw.([]any)
		if !ok || len(l) != count {
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-R': bad R array")
		}
		R := make([]*ed.Point, count)
		for i, x := range l {
			if R[i], err = MpcJPt(x); err != nil {
				return nil, mpcOtMalformed(mesh, peer, "round 'ot-R': "+err.Error())
			}
		}
		if pads, err = MpcMalBaseOtSenderDerive(setup.Y, setup.T, R, setup.S, b); err != nil {
			return nil, mpcOtMalformed(mesh, peer, err.Error())
		}
	} else {
		mRaw, err := mesh.Recv(peer, "ot-recv", 0)
		if err != nil {
			return nil, err
		}
		m, ok := mRaw.(map[string]any)
		if !ok {
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-recv': bad receiver message")
		}
		rn, err1 := mpcUnb64(m["rn"], 32)
		points, err2 := mpcUnb64Pairs(m["points"], count, "point")
		rl, okR := m["rhos"].([]any)
		if err := errors.Join(err1, err2); err != nil || !okR || len(rl) != count {
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-recv': bad receiver message")
		}
		rhos := make([][]byte, count)
		for i, r := range rl {
			if rhos[i], err = mpcUnb64(r, 32); err != nil {
				return nil, mpcOtMalformed(mesh, peer, "round 'ot-recv': "+err.Error())
			}
		}
		cts, sp, err := mpcLweOt().SendRandom(rn, points, rhos)
		if err != nil || len(sp) != count || len(cts) != count {
			detail := "bad sender output"
			if err != nil {
				detail = err.Error()
			}
			return nil, mpcOtMalformed(mesh, peer, "lwe sender: "+detail)
		}
		pads = sp
		if err := mesh.Send(peer, "ot-ct", mpcB64Pairs(cts)); err != nil {
			return nil, err
		}
	}
	vRaw, err := mesh.Recv(peer, "ot-verify", 0)
	if err != nil {
		return nil, err
	}
	v, _ := vRaw.(map[string]any)
	cs, ok1 := v["choices"].([]any)
	hs, ok2 := v["padHashes"].([]any)
	if !ok1 || !ok2 || len(cs) != count || len(hs) != count {
		return nil, mpcOtMalformed(mesh, peer, "round 'ot-verify': bad verify message")
	}
	matched := true
	for i, c := range cs {
		f, isNum := jsNum(c)
		if !isNum || (f != 0 && f != 1) {
			matched = false
			continue
		}
		if h, _ := hs[i].(string); mpcOtSha(pads[i][int(f)]) != h {
			matched = false
		}
	}
	if err := mesh.Send(peer, "ot-done", map[string]any{"matched": matched}); err != nil {
		return nil, err
	}
	mesh.Finish()
	var all [][]byte
	for _, p := range pads {
		all = append(all, p[0], p[1])
	}
	return &MpcOtNetResult{Kind: kind, Role: "sender", Count: count, Ms: float64(time.Since(t0).Microseconds()) / 1000, Matched: matched, PadDigest: mpcOtSha(all...)}, nil
}

// MpcRunOtReceiver is the OT receiver role against peer.
func MpcRunOtReceiver(mesh *MpcMesh, peer int, kind string, count int) (*MpcOtNetResult, error) {
	if err := mpcOtKindOK(kind); err != nil {
		return nil, err
	}
	t0 := time.Now()
	rng := MpcSecureOtRandom()
	choices := make([]int, count)
	for i, b := range rng.Bytes(count) {
		choices[i] = int(b & 1)
	}
	var recvPads [][]byte
	if kind == "ec" {
		sRaw, err := mesh.Recv(peer, "ot-S", 0)
		if err != nil {
			return nil, err
		}
		o, ok := sRaw.(map[string]any)
		if !ok {
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-S': bad S message")
		}
		U, errU := MpcJPt(o["U"])
		z, errZ := MpcHexBig(o["z"])
		S, errS := MpcJPt(o["S"])
		if err := errors.Join(errU, errZ, errS); err != nil {
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-S': "+err.Error())
		}
		R, pads, err := MpcMalBaseOtReceiverRespond(S, MpcSchnorrProof{U: U, Z: z}, choices, rng, mpcOtBinding(mesh, peer, mesh.selfID))
		if err != nil {
			ak := "malformed"
			var oa *MpcBaseOtAbort
			if errors.As(err, &oa) {
				ak = "commitment"
			}
			ne := mpcAbortF(ak, mpcIntP(peer), mesh.selfID, err.Error(), "")
			mesh.Fail(ne)
			return nil, ne
		}
		recvPads = pads
		rj := make([]any, len(R))
		for i, p := range R {
			rj[i] = MpcPtJ(p)
		}
		if err := mesh.Send(peer, "ot-R", rj); err != nil {
			return nil, err
		}
	} else {
		lwe := mpcLweOt()
		rn, points, rhos, state, err := lwe.Receive(choices)
		if err != nil {
			return nil, err
		}
		rh := make([]any, len(rhos))
		for i, r := range rhos {
			rh[i] = base64.StdEncoding.EncodeToString(r)
		}
		if err := mesh.Send(peer, "ot-recv", map[string]any{"rn": base64.StdEncoding.EncodeToString(rn), "points": mpcB64Pairs(points), "rhos": rh}); err != nil {
			return nil, err
		}
		ctRaw, err := mesh.Recv(peer, "ot-ct", 0)
		if err != nil {
			return nil, err
		}
		cts, err := mpcUnb64Pairs(ctRaw, count, "ciphertext")
		if err != nil {
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-ct': "+err.Error())
		}
		if recvPads, err = lwe.RecoverRandom(state, cts); err != nil || len(recvPads) != count {
			detail := "bad recovered pads"
			if err != nil {
				detail = err.Error()
			}
			return nil, mpcOtMalformed(mesh, peer, "round 'ot-ct': "+detail)
		}
	}
	hashes := make([]any, count)
	cj := make([]any, count)
	for i, p := range recvPads {
		hashes[i], cj[i] = mpcOtSha(p), choices[i]
	}
	if err := mesh.Send(peer, "ot-verify", map[string]any{"choices": cj, "padHashes": hashes}); err != nil {
		return nil, err
	}
	dRaw, err := mesh.Recv(peer, "ot-done", 0)
	if err != nil {
		return nil, err
	}
	d, _ := dRaw.(map[string]any)
	matched := d["matched"] == true
	mesh.Finish()
	return &MpcOtNetResult{Kind: kind, Role: "receiver", Count: count, Ms: float64(time.Since(t0).Microseconds()) / 1000, Matched: matched, PadDigest: mpcOtSha(recvPads...)}, nil
}
