package pca

// The OT demonstration roles over a two-node mesh: kind "ec" end to end, kind "lwe" through the registration hook (with a
// transparent stand-in for the lattice library, which lives in a separate cgo module), and the fail-closed refusals.

import (
	"crypto/rand"
	"strings"
	"sync"
	"testing"
)

// fakeLwe carries the pads in the clear: it exercises the wire format and hook plumbing, not the cryptography.
type fakeLwe struct{}

func (fakeLwe) Receive(choices []int) ([]byte, [][2][]byte, [][]byte, any, error) {
	rn := make([]byte, 32)
	_, _ = rand.Read(rn)
	pts, rhos := make([][2][]byte, len(choices)), make([][]byte, len(choices))
	for i := range choices {
		pts[i] = [2][]byte{{1}, {2}}
		rhos[i] = make([]byte, 32)
	}
	return rn, pts, rhos, choices, nil
}

func (fakeLwe) SendRandom(rn []byte, points [][2][]byte, rhos [][]byte) ([][2][]byte, [][2][]byte, error) {
	pads := make([][2][]byte, len(points))
	for i := range pads {
		pads[i] = [2][]byte{make([]byte, 32), make([]byte, 32)}
		_, _ = rand.Read(pads[i][0])
		_, _ = rand.Read(pads[i][1])
	}
	return pads, pads, nil
}

func (fakeLwe) RecoverRandom(state any, cts [][2][]byte) ([][]byte, error) {
	ch := state.([]int)
	out := make([][]byte, len(cts))
	for i := range cts {
		out[i] = cts[i][ch[i]]
	}
	return out, nil
}

func mpcoRun(t *testing.T, kind string) (snd, rcv *MpcOtNetResult, errS, errR error) {
	t.Helper()
	g := mpcmSetup(t, 2)
	ms := []*MpcMesh{g.mesh(t, 0, nil, nil), g.mesh(t, 1, nil, nil)}
	mpcmConnectAll(t, ms)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); snd, errS = MpcRunOtSender(ms[1], 0, kind, 8) }()
	go func() { defer wg.Done(); rcv, errR = MpcRunOtReceiver(ms[0], 1, kind, 8) }()
	wg.Wait()
	return
}

func TestMpcNetOtEcMatches(t *testing.T) {
	s, r, es, er := mpcoRun(t, "ec")
	if es != nil || er != nil {
		t.Fatal(es, er)
	}
	if !s.Matched || !r.Matched || s.Count != 8 || s.Role != "sender" || r.Role != "receiver" || len(s.PadDigest) != 64 || len(r.PadDigest) != 64 {
		t.Fatalf("%+v %+v", s, r)
	}
}

func TestMpcNetOtLweFailsClosedWithoutTheLibrary(t *testing.T) {
	MpcRegisterLweOt(nil)
	_, _, es, er := mpcoRun(t, "lwe")
	for _, err := range []error{es, er} {
		if err == nil || !strings.Contains(err.Error(), "without") {
			t.Fatalf("an lwe request without the library must be refused, got %v", err)
		}
	}
}

func TestMpcNetOtLweRunsThroughTheRegisteredHook(t *testing.T) {
	MpcRegisterLweOt(fakeLwe{})
	t.Cleanup(func() { MpcRegisterLweOt(nil) })
	s, r, es, er := mpcoRun(t, "lwe")
	if es != nil || er != nil {
		t.Fatal(es, er)
	}
	if !s.Matched || !r.Matched || s.Kind != "lwe" {
		t.Fatalf("%+v %+v", s, r)
	}
}

func TestMpcNetOtUnknownKindIsRefused(t *testing.T) {
	_, _, es, _ := mpcoRun(t, "rsa")
	if es == nil {
		t.Fatal("unknown kind must be refused")
	}
}
