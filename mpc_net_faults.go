package pca

// TEST-ONLY fault injection for the networked MPC, the native twin of the reference's fault module. Two layers:
//   - MpcTamperFor: a MALICIOUS SENDER rewriting its own outgoing frames (duplicate, reorder, skipped sequence, garbage,
//     truncation, wrong round/session, oversize length, drop, silence). The bytes still travel inside valid TLS, so the
//     receiver's framing checks decide.
//   - MpcFaultProxy: a NETWORK adversary on the wire (a TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder
//     at the byte level. TLS 1.3 record authentication rejects tampering, so the expected outcome is an attributable-to-the-link
//     disconnect, never a silently corrupted value.

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// MpcFrameFault selects one frame-level fault. Kind is one of duplicate, reorder, skip-seq, garbage, truncate, bitflip,
// wrong-round, wrong-session, oversize, drop, silent-from, extra-field, false-accuse.
type MpcFrameFault struct {
	Kind  string
	Round string // protocol round to attack (e.g. "mul0")
	To    *int   // restrict to one recipient; nil = all
	// Accuse is the (honest) party a false-accuse frame names (default 0).
	Accuse int
}

// MpcTamperFor builds the MpcMeshConfig.Tamper hook (which also needs UnsafeTestHooks) for spec. State (the silence flag, the
// reorder stash) lives in the returned closure, so every tamperer is independent.
func MpcTamperFor(spec MpcFrameFault) func(to int, raw []byte) [][]byte {
	var mu sync.Mutex
	stash := map[int][]byte{}
	silent := false
	reenc := func(f map[string]any, over map[string]any) []byte {
		g := map[string]any{}
		for k, v := range f {
			g[k] = v
		}
		for k, v := range over {
			g[k] = v
		}
		b, err := MpcEncodeFrame(g["v"], g["ty"].(string), g["sid"].(string), g["seq"], g["rd"].(string), g["d"])
		if err != nil {
			return nil
		}
		return b
	}
	return func(to int, raw []byte) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		if silent {
			return nil
		}
		var f map[string]any
		if len(raw) > 4 {
			f = MpcParseFrame(raw[4:])
		}
		rd, _ := f["rd"].(string)
		hit := f != nil && rd == spec.Round && (spec.To == nil || *spec.To == to)
		if spec.Kind == "reorder" {
			if held, ok := stash[to]; ok {
				delete(stash, to)
				return [][]byte{raw, held} // the later frame first, then the held-back one
			}
			if hit {
				stash[to] = raw
				return nil
			}
			return [][]byte{raw}
		}
		if !hit {
			return [][]byte{raw}
		}
		switch spec.Kind {
		case "duplicate":
			return [][]byte{raw, raw}
		case "skip-seq":
			sq, _ := jsNum(f["seq"])
			return [][]byte{reenc(f, map[string]any{"seq": int64(sq) + 1})}
		case "garbage":
			g := make([]byte, len(raw))
			for i := range g {
				g[i] = 0x5a
			}
			binary.BigEndian.PutUint32(g, uint32(len(raw)-4))
			return [][]byte{g}
		case "truncate":
			return [][]byte{raw[:max(5, len(raw)/2)]}
		case "bitflip":
			b := append([]byte(nil), raw...)
			b[len(b)*6/10] ^= 0x04
			return [][]byte{b}
		case "wrong-round":
			return [][]byte{reenc(f, map[string]any{"rd": "zzz-" + rd})}
		case "wrong-session":
			return [][]byte{reenc(f, map[string]any{"sid": "not-this-session"})}
		case "oversize":
			return [][]byte{{0x7f, 0xff, 0xff, 0xff}}
		case "drop":
			return nil
		case "silent-from":
			silent = true
			return nil
		case "false-accuse":
			return [][]byte{reenc(f, map[string]any{"ty": "abort", "rd": "abort", "d": map[string]any{"kind": "timeout", "blamed": spec.Accuse, "detail": "forged accusation"}})}
		case "extra-field":
			body := raw[4:]
			nb := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"x":1}`)...)
			return [][]byte{append(binary.BigEndian.AppendUint32(nil, uint32(len(nb))), nb...)}
		}
		return [][]byte{raw}
	}
}

// ----------------------------------------------------------------------------- TCP fault proxy

// MpcWireFault is one byte-level misbehaviour. Kind is none, drop, delay, truncate, bitflip, duplicate or reorder.
type MpcWireFault struct {
	Kind string
	Dir  string // "c2s" (client to server) or "s2c"
	// AfterBytes: the fault starts after this many bytes passed in that direction (skips the TLS handshake).
	AfterBytes int
	Delay      time.Duration // kind=delay; 0 = one second
}

// mpcSink is the destination side of one proxied direction.
type mpcSink interface {
	Write([]byte)
	End()     // half-close
	Destroy() // close at once
	Destroyed() bool
}

// mpcPipe is the fault state machine of one direction; the proxy drives it from the socket, tests drive it by hand.
type mpcPipe struct {
	mu      sync.Mutex
	f       MpcWireFault
	active  bool
	clk     MpcMeshClock
	to      mpcSink
	logf    func(string)
	seen    int
	fired   bool
	done    bool
	held    []byte
	pending int // delayed writes in flight: a half-close must not overtake them
	ended   bool
	closed  bool
}

func newMpcPipe(f MpcWireFault, dir string, to mpcSink, clk MpcMeshClock, logf func(string)) *mpcPipe {
	if clk == nil {
		clk = MpcWallClock{}
	}
	return &mpcPipe{f: f, active: f.Kind != "none" && f.Dir == dir, clk: clk, to: to, logf: logf}
}

func (p *mpcPipe) onData(chunk []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := p.f
	before := p.seen
	p.seen += len(chunk)
	if !p.active || p.done || before+len(chunk) <= f.AfterBytes {
		if p.active && f.Kind == "drop" && p.fired {
			return // a black hole stays black
		}
		p.to.Write(chunk)
		return
	}
	if !p.fired {
		p.fired = true
		p.logf("fault " + f.Kind + " " + f.Dir + " after " + strconv.Itoa(f.AfterBytes) + "B")
	}
	switch f.Kind {
	case "drop":
	case "delay":
		d := f.Delay
		if d <= 0 {
			d = time.Second
		}
		p.pending++
		c := append([]byte(nil), chunk...)
		p.clk.AfterFunc(d, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if !p.to.Destroyed() {
				p.to.Write(c)
			}
			p.pending--
			if p.pending == 0 && p.closed {
				p.to.End()
				p.to.Destroy()
			} else if p.pending == 0 && p.ended {
				p.to.End()
			}
		})
	case "truncate":
		p.done = true
		p.to.Write(chunk[:len(chunk)/2])
		p.to.End()
	case "bitflip":
		p.done = true
		b := append([]byte(nil), chunk...)
		b[len(b)/2] ^= 0x01
		p.to.Write(b)
	case "duplicate":
		p.done = true
		p.to.Write(chunk)
		p.to.Write(chunk)
	case "reorder":
		if p.held == nil {
			p.held = append([]byte(nil), chunk...)
		} else {
			p.done = true
			p.to.Write(chunk)
			p.to.Write(p.held)
			p.held = nil
		}
	default:
		p.to.Write(chunk)
	}
}

func (p *mpcPipe) onEnd() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held != nil {
		p.to.Write(p.held)
	}
	p.ended = true
	if p.pending == 0 {
		p.to.End()
	}
}

func (p *mpcPipe) onClose() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.pending == 0 {
		p.to.Destroy()
	}
}

type mpcConnSink struct {
	c  net.Conn
	mu sync.Mutex
	d  bool
}

func (s *mpcConnSink) Write(b []byte) { _, _ = s.c.Write(b) }
func (s *mpcConnSink) End() {
	if cw, ok := s.c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
func (s *mpcConnSink) Destroy() {
	s.mu.Lock()
	s.d = true
	s.mu.Unlock()
	_ = s.c.Close()
}
func (s *mpcConnSink) Destroyed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d
}

// MpcFaultProxy is a transparent loopback TCP proxy that misbehaves once, after AfterBytes bytes, in one direction.
type MpcFaultProxy struct {
	ln     net.Listener
	target string
	fault  MpcWireFault
	clk    MpcMeshClock
	mu     sync.Mutex
	log    []string
}

// NewMpcFaultProxy listens on 127.0.0.1:port (0 = ephemeral; see Port) and relays to target ("host:port"). clk nil = real time.
func NewMpcFaultProxy(port int, target string, fault MpcWireFault, clk MpcMeshClock) (*MpcFaultProxy, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	p := &MpcFaultProxy{ln: ln, target: target, fault: fault, clk: clk}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.onClient(c)
		}
	}()
	return p, nil
}

func (p *MpcFaultProxy) Port() int { return p.ln.Addr().(*net.TCPAddr).Port }
func (p *MpcFaultProxy) Close()    { _ = p.ln.Close() }

// Log is a copy of the fault log lines.
func (p *MpcFaultProxy) Log() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.log...)
}

func (p *MpcFaultProxy) logf(s string) {
	p.mu.Lock()
	p.log = append(p.log, s)
	p.mu.Unlock()
}

func (p *MpcFaultProxy) onClient(c net.Conn) {
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = c.Close()
		return
	}
	cs, us := &mpcConnSink{c: c}, &mpcConnSink{c: up}
	c2s := newMpcPipe(p.fault, "c2s", us, p.clk, p.logf)
	s2c := newMpcPipe(p.fault, "s2c", cs, p.clk, p.logf)
	// A closed side tears down the other one only after that direction's delayed bytes are delivered: a real network delays
	// data, it does not drop what the sender wrote before it closed. Both directions at EOF = the connection is closed.
	var wg sync.WaitGroup
	wg.Add(2)
	run := func(from net.Conn, pp *mpcPipe) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := from.Read(buf)
			if n > 0 {
				pp.onData(append([]byte(nil), buf[:n]...))
			}
			if err == io.EOF {
				pp.onEnd()
				return
			}
			if err != nil { // reset or local close: tear both sides down at once
				_ = c.Close()
				_ = up.Close()
				return
			}
		}
	}
	go run(c, c2s)
	go run(up, s2c)
	go func() {
		wg.Wait()
		c2s.onClose()
		s2c.onClose()
	}()
}
