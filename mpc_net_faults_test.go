package pca

// Replays the reference's fault-injection and injectable-clock behaviours: the frame tamperer, the byte-level fault proxy (driven
// by hand with a scripted sink and a manual clock, then over real sockets), the manual mesh clock, a mesh receive deadline that
// fires only when the clock is advanced, and the test-only offline misbehaviours.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

func mpcfFrame(t *testing.T, seq int, rd string) []byte {
	t.Helper()
	b, err := MpcEncodeFrame(MpcWireVersion, "msg", "sess", seq, rd, map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mpcfParse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var sp MpcFrameSplitter
	bodies, err := sp.Push(b)
	if err != nil || len(bodies) != 1 {
		t.Fatalf("not one frame: %v %d", err, len(bodies))
	}
	f := MpcParseFrame(bodies[0])
	if f == nil {
		t.Fatal("frame does not parse")
	}
	return f
}

func TestMpcTamperPassThrough(t *testing.T) {
	kinds := []string{"duplicate", "reorder", "skip-seq", "garbage", "truncate", "bitflip", "wrong-round", "wrong-session", "oversize", "drop", "silent-from", "extra-field", "false-accuse"}
	two := 2
	for _, k := range kinds {
		raw := mpcfFrame(t, 5, "other")
		if out := MpcTamperFor(MpcFrameFault{Kind: k, Round: "mul0"})(1, raw); len(out) != 1 || !bytes.Equal(out[0], raw) {
			t.Fatalf("%s: other rounds must pass untouched", k)
		}
		raw = mpcfFrame(t, 5, "mul0")
		if out := MpcTamperFor(MpcFrameFault{Kind: k, Round: "mul0", To: &two})(1, raw); len(out) != 1 || !bytes.Equal(out[0], raw) {
			t.Fatalf("%s: other recipients must pass untouched", k)
		}
	}
	zero := 0
	if out := MpcTamperFor(MpcFrameFault{Kind: "drop", Round: "mul0", To: &zero})(0, mpcfFrame(t, 1, "mul0")); len(out) != 0 {
		t.Fatal("a matching to=0 applies the fault")
	}
}

func TestMpcTamperKinds(t *testing.T) {
	raw := mpcfFrame(t, 9, "mul0")
	run := func(k string) [][]byte { return MpcTamperFor(MpcFrameFault{Kind: k, Round: "mul0"})(1, raw) }
	if o := run("duplicate"); len(o) != 2 || !bytes.Equal(o[0], raw) || !bytes.Equal(o[1], raw) {
		t.Fatal("duplicate")
	}
	if f := mpcfParse(t, run("skip-seq")[0]); func() bool { n, ok := jsNum(f["seq"]); return !ok || n != 10 }() {
		t.Fatalf("skip-seq: %v", f["seq"])
	}
	g := run("garbage")[0]
	if len(g) != len(raw) || binary.BigEndian.Uint32(g) != uint32(len(raw)-4) || MpcParseFrame(g[4:]) != nil {
		t.Fatal("garbage")
	}
	for _, c := range g[4:] {
		if c != 0x5a {
			t.Fatal("garbage body must be 0x5a")
		}
	}
	if tr := run("truncate")[0]; len(tr) != len(raw)/2 || !bytes.Equal(tr, raw[:len(tr)]) {
		t.Fatal("truncate")
	}
	tiny := []byte{0, 0, 0, 2, 1, 2, 3}
	if MpcParseFrame(tiny[4:]) != nil {
		t.Fatal("tiny is not a frame")
	}
	b := run("bitflip")[0]
	idx := len(raw) * 6 / 10
	for i := range raw {
		want := raw[i]
		if i == idx {
			want ^= 0x04
		}
		if b[i] != want {
			t.Fatalf("bitflip byte %d", i)
		}
	}
	if f := mpcfParse(t, run("wrong-round")[0]); f["rd"] != "zzz-mul0" {
		t.Fatalf("wrong-round: %v", f["rd"])
	}
	if f := mpcfParse(t, run("wrong-session")[0]); f["sid"] != "not-this-session" {
		t.Fatal("wrong-session")
	}
	if o := run("oversize"); len(o) != 1 || !bytes.Equal(o[0], []byte{0x7f, 0xff, 0xff, 0xff}) {
		t.Fatal("oversize")
	}
	if len(run("drop")) != 0 {
		t.Fatal("drop")
	}
	fa := MpcTamperFor(MpcFrameFault{Kind: "false-accuse", Round: "mul0", Accuse: 3})(1, raw)
	f := mpcfParse(t, fa[0])
	d, _ := f["d"].(map[string]any)
	if f["ty"] != "abort" || f["rd"] != "abort" || d["kind"] != "timeout" || d["detail"] != "forged accusation" {
		t.Fatalf("false-accuse: %v", f)
	}
	if bl, _ := jsNum(d["blamed"]); bl != 3 {
		t.Fatal("false-accuse blamed")
	}
	x := run("extra-field")[0]
	if o := mpcParseObject(x[4:]); len(o) != 7 || o["x"] == nil || binary.BigEndian.Uint32(x) != uint32(len(x)-4) {
		t.Fatalf("extra-field must add exactly one envelope key: %v", o)
	}
	if MpcParseFrame(x[4:]) != nil {
		t.Fatal("the strict envelope parser must refuse the extra key")
	}
}

func TestMpcTamperSilenceIsStickyAndPerTamperer(t *testing.T) {
	one := 1
	tm := MpcTamperFor(MpcFrameFault{Kind: "silent-from", Round: "mul0", To: &one})
	if len(tm(2, mpcfFrame(t, 1, "a"))) != 1 || len(tm(1, mpcfFrame(t, 2, "a"))) != 1 {
		t.Fatal("non-hits pass")
	}
	if len(tm(1, mpcfFrame(t, 3, "mul0"))) != 0 || len(tm(2, mpcfFrame(t, 4, "a"))) != 0 || len(tm(1, mpcfFrame(t, 5, "b"))) != 0 {
		t.Fatal("after the first hit everything is dropped")
	}
	if len(MpcTamperFor(MpcFrameFault{Kind: "silent-from", Round: "mul0"})(1, mpcfFrame(t, 1, "a"))) != 1 {
		t.Fatal("silence state is per tamperer")
	}
}

func TestMpcTamperReorderHoldsPerRecipient(t *testing.T) {
	tm := MpcTamperFor(MpcFrameFault{Kind: "reorder", Round: "mul0"})
	a1, a2, b1, b2 := mpcfFrame(t, 1, "mul0"), mpcfFrame(t, 2, "next"), mpcfFrame(t, 1, "mul0"), mpcfFrame(t, 2, "next")
	if len(tm(1, a1)) != 0 || len(tm(2, b1)) != 0 {
		t.Fatal("the first hit to each recipient is held")
	}
	if o := tm(3, mpcfFrame(t, 9, "other")); len(o) != 1 {
		t.Fatal("a non-hit with nothing held passes")
	}
	if o := tm(1, a2); len(o) != 2 || !bytes.Equal(o[0], a2) || !bytes.Equal(o[1], a1) {
		t.Fatal("the later frame goes first, then the held one")
	}
	if o := tm(2, b2); len(o) != 2 || !bytes.Equal(o[1], b1) {
		t.Fatal("per-recipient stash")
	}
	a3 := mpcfFrame(t, 3, "next")
	if o := tm(1, a3); len(o) != 1 || !bytes.Equal(o[0], a3) {
		t.Fatal("stash emptied")
	}
	if len(tm(1, mpcfFrame(t, 4, "mul0"))) != 0 {
		t.Fatal("hit again: held again")
	}
}

// ---- the manual clock

func TestMpcManualClockFiresInDueOrder(t *testing.T) {
	c := NewMpcManualClock()
	var order []int
	c.AfterFunc(30*time.Millisecond, func() { order = append(order, 3) })
	c.AfterFunc(10*time.Millisecond, func() { order = append(order, 1) })
	stop := c.AfterFunc(20*time.Millisecond, func() { order = append(order, 2) })
	stop()
	c.AfterFunc(10*time.Millisecond, func() { order = append(order, 11) })
	if c.Pending() != 3 || !c.Now().Equal(time.Unix(0, 0)) {
		t.Fatal("nothing fires before Advance")
	}
	c.Advance(9 * time.Millisecond)
	if len(order) != 0 {
		t.Fatal("not due yet")
	}
	c.Advance(1 * time.Millisecond)
	if !reflect.DeepEqual(order, []int{1, 11}) || !c.Now().Equal(time.Unix(0, int64(10*time.Millisecond))) {
		t.Fatalf("due at 10ms: %v", order)
	}
	// a timer armed by a firing timer that is itself due inside the same Advance also fires
	c.AfterFunc(5*time.Millisecond, func() { c.AfterFunc(5*time.Millisecond, func() { order = append(order, 99) }) })
	c.Advance(100 * time.Millisecond)
	if !reflect.DeepEqual(order, []int{1, 11, 99, 3}) && !reflect.DeepEqual(order, []int{1, 11, 3, 99}) {
		t.Fatalf("order %v", order)
	}
	if c.Pending() != 0 || !c.Now().Equal(time.Unix(0, int64(110*time.Millisecond))) {
		t.Fatal("Advance ends exactly at the target")
	}
}

func TestMpcWallClockTimer(t *testing.T) {
	var w MpcWallClock
	done := make(chan struct{})
	w.AfterFunc(5*time.Millisecond, func() { close(done) })
	cancelled := false
	w.AfterFunc(5*time.Millisecond, func() { cancelled = true })()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wall timer did not fire")
	}
	time.Sleep(20 * time.Millisecond)
	if cancelled {
		t.Fatal("a cancelled timer must not fire")
	}
}

// A mesh receive deadline is decided by the injected clock: it does not fire on real time and fires on Advance.
func TestMpcMeshRecvDeadlineFollowsInjectedClock(t *testing.T) {
	g := mpcmSetup(t, 2)
	clk := NewMpcManualClock()
	ms := []*MpcMesh{g.mesh(t, 0, nil, func(c *MpcMeshConfig) { c.Clock = clk }), g.mesh(t, 1, nil, nil)}
	mpcmConnectAll(t, ms)
	type res struct {
		v   any
		err error
	}
	ch := make(chan res, 1)
	go func() { v, err := ms[0].Recv(1, "r1", 5*time.Second); ch <- res{v, err} }()
	for i := 0; clk.Pending() == 0; i++ {
		if i > 500 {
			t.Fatal("the receive never armed its deadline on the injected clock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	clk.Advance(4999 * time.Millisecond)
	select {
	case r := <-ch:
		t.Fatalf("returned 1ms early: %+v", r)
	case <-time.After(150 * time.Millisecond):
	}
	clk.Advance(time.Millisecond)
	select {
	case r := <-ch:
		a := mpcmWantAbort(t, r.err, "timeout", 1)
		if a.DeadlineMs == nil || *a.DeadlineMs != 5000 {
			t.Fatalf("deadline ms: %v", a.DeadlineMs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadline did not fire on Advance")
	}
}

// ---- the byte-level fault pipe, driven by hand

type mpcfSink struct {
	mu      sync.Mutex
	writes  [][]byte
	ended   int
	destroy int
	dead    bool
}

func (s *mpcfSink) Write(b []byte) {
	s.mu.Lock()
	s.writes = append(s.writes, append([]byte(nil), b...))
	s.mu.Unlock()
}
func (s *mpcfSink) End()            { s.mu.Lock(); s.ended++; s.mu.Unlock() }
func (s *mpcfSink) Destroy()        { s.mu.Lock(); s.destroy++; s.dead = true; s.mu.Unlock() }
func (s *mpcfSink) Destroyed() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.dead }

type mpcfPiped struct {
	p   *mpcPipe
	dst *mpcfSink
	clk *MpcManualClock
	log []string
}

func mpcfPipe(f MpcWireFault, dir string) *mpcfPiped {
	x := &mpcfPiped{dst: &mpcfSink{}, clk: NewMpcManualClock()}
	x.p = newMpcPipe(f, dir, x.dst, x.clk, func(s string) { x.log = append(x.log, s) })
	return x
}

func (x *mpcfPiped) send(chunks ...[]byte) {
	for _, c := range chunks {
		x.p.onData(c)
	}
}

func bs(n ...byte) []byte { return n }

func mpcfWrites(t *testing.T, s *mpcfSink, want ...[]byte) {
	t.Helper()
	if !reflect.DeepEqual(s.writes, want) {
		t.Fatalf("writes %v want %v", s.writes, want)
	}
}

func TestMpcPipeNoneAndOtherDirection(t *testing.T) {
	a := mpcfPipe(MpcWireFault{Kind: "none", Dir: "c2s"}, "c2s")
	a.send(bs(1, 2, 3), bs(4))
	mpcfWrites(t, a.dst, bs(1, 2, 3), bs(4))
	b := mpcfPipe(MpcWireFault{Kind: "drop", Dir: "c2s"}, "s2c")
	b.send(bs(7, 7))
	mpcfWrites(t, b.dst, bs(7, 7))
	if len(a.log)+len(b.log) != 0 {
		t.Fatal("nothing is logged")
	}
}

func TestMpcPipeDropIsABlackHole(t *testing.T) {
	a := mpcfPipe(MpcWireFault{Kind: "drop", Dir: "c2s", AfterBytes: 3}, "c2s")
	a.send(bs(1, 2, 3), bs(4, 5), bs(6, 7))
	mpcfWrites(t, a.dst, bs(1, 2, 3))
	if !reflect.DeepEqual(a.log, []string{"fault drop c2s after 3B"}) {
		t.Fatalf("log %v", a.log)
	}
	b := mpcfPipe(MpcWireFault{Kind: "drop", Dir: "s2c", AfterBytes: 2}, "s2c")
	b.send(bs(1, 2, 3), bs(4))
	mpcfWrites(t, b.dst) // the straddling chunk is faulted whole
}

func TestMpcPipeDelayOrderAndDefault(t *testing.T) {
	a := mpcfPipe(MpcWireFault{Kind: "delay", Dir: "c2s", AfterBytes: 2, Delay: 300 * time.Millisecond}, "c2s")
	a.send(bs(1, 2), bs(3, 4), bs(5))
	mpcfWrites(t, a.dst, bs(1, 2))
	a.clk.Advance(299 * time.Millisecond)
	mpcfWrites(t, a.dst, bs(1, 2))
	a.clk.Advance(time.Millisecond)
	mpcfWrites(t, a.dst, bs(1, 2), bs(3, 4), bs(5))
	if a.dst.ended != 0 || !reflect.DeepEqual(a.log, []string{"fault delay c2s after 2B"}) {
		t.Fatal("the destination stays open")
	}
	b := mpcfPipe(MpcWireFault{Kind: "delay", Dir: "c2s"}, "c2s")
	b.send(bs(9))
	b.clk.Advance(999 * time.Millisecond)
	mpcfWrites(t, b.dst)
	b.clk.Advance(time.Millisecond)
	mpcfWrites(t, b.dst, bs(9))
}

func TestMpcPipeDelayedWritesOutliveASourceEndAndClose(t *testing.T) {
	a := mpcfPipe(MpcWireFault{Kind: "delay", Dir: "c2s", Delay: 100 * time.Millisecond}, "c2s")
	a.send(bs(1))
	a.clk.Advance(50 * time.Millisecond)
	a.send(bs(2))
	a.p.onEnd()
	if a.dst.ended != 0 {
		t.Fatal("a half-close must not overtake delayed writes")
	}
	a.clk.Advance(50 * time.Millisecond)
	mpcfWrites(t, a.dst, bs(1))
	if a.dst.ended != 0 {
		t.Fatal("one write is still in flight")
	}
	a.clk.Advance(50 * time.Millisecond)
	mpcfWrites(t, a.dst, bs(1), bs(2))
	if a.dst.ended != 1 {
		t.Fatal("ended only after the last delayed write")
	}
	// close while writes are pending: ended AND destroyed after the last one
	b := mpcfPipe(MpcWireFault{Kind: "delay", Dir: "c2s", Delay: 100 * time.Millisecond}, "c2s")
	b.send(bs(5))
	b.p.onClose()
	if b.dst.destroy != 0 {
		t.Fatal("close must wait for the delayed bytes")
	}
	b.clk.Advance(100 * time.Millisecond)
	if b.dst.ended != 1 || b.dst.destroy != 1 {
		t.Fatalf("ended %d destroyed %d", b.dst.ended, b.dst.destroy)
	}
	// nothing is written to a destination destroyed in the meantime
	c := mpcfPipe(MpcWireFault{Kind: "delay", Dir: "c2s", Delay: 100 * time.Millisecond}, "c2s")
	c.send(bs(1))
	c.dst.Destroy()
	c.clk.Advance(100 * time.Millisecond)
	mpcfWrites(t, c.dst)
	// an end with nothing pending ends at once; a close with nothing pending destroys at once
	d := mpcfPipe(MpcWireFault{Kind: "delay", Dir: "c2s", Delay: 100 * time.Millisecond}, "c2s")
	d.p.onEnd()
	d.p.onClose()
	if d.dst.ended != 1 || d.dst.destroy != 1 {
		t.Fatal("immediate end/close")
	}
}

func TestMpcPipeTruncateBitflipDuplicateReorder(t *testing.T) {
	tr := mpcfPipe(MpcWireFault{Kind: "truncate", Dir: "c2s", AfterBytes: 2}, "c2s")
	tr.send(bs(1, 2), bs(3, 4, 5, 6, 7), bs(8, 9))
	mpcfWrites(t, tr.dst, bs(1, 2), bs(3, 4), bs(8, 9))
	if tr.dst.ended != 1 {
		t.Fatal("truncate ends the destination once")
	}
	bf := mpcfPipe(MpcWireFault{Kind: "bitflip", Dir: "c2s", AfterBytes: 1}, "c2s")
	orig := bs(10, 20, 30, 40)
	bf.send(bs(0), orig, bs(50, 60))
	mpcfWrites(t, bf.dst, bs(0), bs(10, 20, 31, 40), bs(50, 60))
	if !bytes.Equal(orig, bs(10, 20, 30, 40)) {
		t.Fatal("the flip is on a copy")
	}
	odd := mpcfPipe(MpcWireFault{Kind: "bitflip", Dir: "c2s"}, "c2s")
	odd.send(bs(4, 4, 4, 4, 4))
	mpcfWrites(t, odd.dst, bs(4, 4, 5, 4, 4))
	du := mpcfPipe(MpcWireFault{Kind: "duplicate", Dir: "c2s", AfterBytes: 1}, "c2s")
	du.send(bs(0), bs(1, 2), bs(3))
	mpcfWrites(t, du.dst, bs(0), bs(1, 2), bs(1, 2), bs(3))
	ro := mpcfPipe(MpcWireFault{Kind: "reorder", Dir: "c2s", AfterBytes: 1}, "c2s")
	ro.send(bs(0), bs(1, 2), bs(3, 4), bs(5), bs(6))
	mpcfWrites(t, ro.dst, bs(0), bs(3, 4), bs(1, 2), bs(5), bs(6))
	r2 := mpcfPipe(MpcWireFault{Kind: "reorder", Dir: "c2s", AfterBytes: 1}, "c2s")
	r2.send(bs(0), bs(1, 2))
	mpcfWrites(t, r2.dst, bs(0))
	r2.p.onEnd()
	mpcfWrites(t, r2.dst, bs(0), bs(1, 2))
	if r2.dst.ended != 1 {
		t.Fatal("end after flush")
	}
	un := mpcfPipe(MpcWireFault{Kind: "bogus", Dir: "c2s"}, "c2s")
	un.send(bs(1, 2))
	mpcfWrites(t, un.dst, bs(1, 2))
}

// ---- over real sockets

func mpcfEcho(t *testing.T, got *[]byte, mu *sync.Mutex) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write(bs(9, 8))
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					mu.Lock()
					*got = append(*got, buf[:n]...)
					mu.Unlock()
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln
}

func mpcfWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestMpcFaultProxyNoneRelaysBothWays(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	srv := mpcfEcho(t, &got, &mu)
	p, err := NewMpcFaultProxy(0, srv.Addr().String(), MpcWireFault{Kind: "none", Dir: "c2s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if a := p.ln.Addr().(*net.TCPAddr); !a.IP.IsLoopback() {
		t.Fatal("the proxy listens on loopback only")
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(bs(1, 2, 3))
	back := make([]byte, 2)
	if _, err := io.ReadFull(c, back); err != nil || !bytes.Equal(back, bs(9, 8)) {
		t.Fatalf("s2c: %v %v", back, err)
	}
	mpcfWait(t, "c2s bytes", func() bool { mu.Lock(); defer mu.Unlock(); return bytes.Equal(got, bs(1, 2, 3)) })
	if len(p.Log()) != 0 {
		t.Fatal("none logs nothing")
	}
}

func TestMpcFaultProxyListenFailsWhenPortTaken(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	srv := mpcfEcho(t, &got, &mu)
	p, err := NewMpcFaultProxy(0, srv.Addr().String(), MpcWireFault{Kind: "none", Dir: "c2s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewMpcFaultProxy(p.Port(), srv.Addr().String(), MpcWireFault{Kind: "none", Dir: "c2s"}, nil); err == nil {
		t.Fatal("a second listen on the same port must fail")
	}
	port := p.Port()
	p.Close()
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a closed proxy must refuse connections")
	}
}

func TestMpcFaultProxyDelayThenCloseDeliversInOrder(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	srv := mpcfEcho(t, &got, &mu)
	p, err := NewMpcFaultProxy(0, srv.Addr().String(), MpcWireFault{Kind: "delay", Dir: "c2s", Delay: 300 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("a"))
	time.Sleep(60 * time.Millisecond)
	_, _ = c.Write([]byte("b"))
	time.Sleep(60 * time.Millisecond)
	_ = c.(*net.TCPConn).CloseWrite()
	mpcfWait(t, "both delayed bytes", func() bool { mu.Lock(); defer mu.Unlock(); return string(got) == "ab" })
}

// A byte-level fault on a real mesh link is never a silently corrupted value: TLS rejects it, so the run fails closed.
func TestMpcFaultProxyBitflipOnMeshFailsClosed(t *testing.T) {
	g := mpcmSetup(t, 2)
	p, err := NewMpcFaultProxy(0, net.JoinHostPort("127.0.0.1", strconv.Itoa(g.nodes[0].Port)), MpcWireFault{Kind: "bitflip", Dir: "c2s", AfterBytes: 3000}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	viaProxy := []MpcNodeAddr{{ID: 0, Host: "127.0.0.1", Port: p.Port(), CertPEM: g.certs[0]}, g.nodes[1]}
	m0 := g.mesh(t, 0, nil, func(c *MpcMeshConfig) { c.ConnectTimeout = 10 * time.Second })
	m1 := g.mesh(t, 1, viaProxy, nil)
	go func() { _ = m0.Connect() }()
	if err := m1.Connect(); err != nil {
		t.Fatalf("the handshake is below the fault offset: %v", err)
	}
	_ = m1.Send(0, "r1", make([]any, 0))
	big := make([]any, 400)
	for i := range big {
		big[i] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	}
	_ = m1.Send(0, "r2", big)
	_, e1 := m0.Recv(1, "r1", 5*time.Second)
	_, e2 := m0.Recv(1, "r2", 5*time.Second)
	var a *MpcNetAbort
	if !errors.As(errors.Join(e1, e2), &a) {
		t.Fatalf("a flipped byte must abort, got %v %v", e1, e2)
	}
	if len(p.Log()) == 0 {
		t.Fatal("the fault never fired")
	}
}

// ---- test-only offline behaviours (no-dealer, two parties)

// mpcfHonest runs two no-dealer parties where party 1 misbehaves and returns what honest party 0 reports.
func mpcfHonest(t *testing.T, behavior string) *MpcNetAbort {
	t.Helper()
	outs := mpcpRun(t, MpcLaunchOptions{N: 2, Q: 3, Vectors: mpcpVectors(2), Offline: "no-dealer", RecvTimeout: 120 * time.Second, Behavior: map[int]string{1: behavior}})
	mpcpAllAborted(t, outs)
	var a *MpcNetAbort
	if !errors.As(outs[0].Err, &a) || a.Blamed == nil || *a.Blamed != 1 {
		t.Fatalf("party 0 must name party 1, got %v", outs[0].Err)
	}
	return a
}

func TestMpcNetOtProofLieIsNamedByTheReceiver(t *testing.T) {
	if a := mpcfHonest(t, "ot-proof-lie"); a.Kind != "ot-check" {
		t.Fatalf("want ot-check, got %v", a)
	}
}

func TestMpcNetOtULieIsNamedByTheKosCheck(t *testing.T) {
	if a := mpcfHonest(t, "ot-u-lie"); a.Kind != "ot-check" {
		t.Fatalf("want ot-check, got %v", a)
	}
}

func TestMpcNetOfflineLieFailsTheSacrifice(t *testing.T) {
	if a := mpcfHonest(t, "offline-lie"); a.Kind != "mac-check" {
		t.Fatalf("want mac-check, got %v", a)
	}
}

func TestMpcNetBehaviorHookNeedsUnsafeTestHooks(t *testing.T) {
	_, err := MpcRunParty(MpcPartyConfig{ID: 0, N: 2, Input: mpcpVectors(2)[0], Behavior: "offline-lie", SessionID: "s"})
	var a *MpcNetAbort
	if !errors.As(err, &a) || a.Kind != "local" {
		t.Fatalf("the behavior hook must be refused: %v", err)
	}
	two := 2
	tm := MpcTamperFor(MpcFrameFault{Kind: "drop", Round: "x", To: &two})
	if _, err := NewMpcMesh(MpcMeshConfig{Tamper: tm}); err == nil {
		t.Fatal("the tamper hook needs UnsafeTestHooks")
	}
}
