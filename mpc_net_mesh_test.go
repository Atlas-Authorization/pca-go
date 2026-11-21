package pca

// Loopback tests of the TLS mesh: a clean three-node exchange and the refusal behaviour (unpinned or wrong certificate, a hello
// that names another id, an oversize frame, an early close, a wrong round, abort propagation, signatures). Identities are
// generated per test; nothing is stored.

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

type mpcmNet struct {
	keys, certs []string
	lns         []net.Listener
	nodes       []MpcNodeAddr
}

func mpcmSetup(t *testing.T, n int) *mpcmNet {
	t.Helper()
	g := &mpcmNet{}
	for i := 0; i < n; i++ {
		k, c, err := MpcGenerateIdentity("node-"+strconv.Itoa(i), nil)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		g.keys, g.certs, g.lns = append(g.keys, k), append(g.certs, c), append(g.lns, ln)
		g.nodes = append(g.nodes, MpcNodeAddr{ID: i, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, CertPEM: c})
	}
	t.Cleanup(func() {
		for _, ln := range g.lns {
			_ = ln.Close()
		}
	})
	return g
}

func (g *mpcmNet) mesh(t *testing.T, i int, nodes []MpcNodeAddr, mod func(*MpcMeshConfig)) *MpcMesh {
	t.Helper()
	if nodes == nil {
		nodes = g.nodes
	}
	cfg := MpcMeshConfig{SelfID: i, Nodes: nodes, KeyPEM: g.keys[i], CertPEM: g.certs[i], SessionID: "sess-1", Listener: g.lns[i],
		ConnectTimeout: 10 * time.Second, RecvTimeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	m, err := NewMpcMesh(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func mpcmConnectAll(t *testing.T, ms []*MpcMesh) {
	t.Helper()
	errs := make([]error, len(ms))
	var wg sync.WaitGroup
	for i, m := range ms {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = m.Connect() }()
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("node %d connect: %v", i, e)
		}
	}
}

func mpcmWantAbort(t *testing.T, err error, kind string, blamed int) *MpcNetAbort {
	t.Helper()
	var a *MpcNetAbort
	if !errors.As(err, &a) {
		t.Fatalf("want abort %s, got %v", kind, err)
	}
	if a.Kind != kind || a.Blamed == nil || *a.Blamed != blamed {
		t.Fatalf("want %s blaming %d, got %v", kind, blamed, a)
	}
	return a
}

// mpcmRaw is a raw TLS client holding node i's identity: it speaks the wire format by hand so a test can misbehave.
func mpcmRaw(t *testing.T, g *mpcmNet, as int, to int) *tls.Conn {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(g.certs[as]), []byte(g.keys[as]))
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(g.nodes[to].Port)),
		&tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func mpcmRawFrame(t *testing.T, c net.Conn, ty, rd string, seq int, d any) {
	t.Helper()
	raw, err := MpcEncodeFrame(MpcWireVersion, ty, "sess-1", seq, rd, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
}

func TestMpcMeshLoopbackThreeNodes(t *testing.T) {
	g := mpcmSetup(t, 3)
	ms := []*MpcMesh{g.mesh(t, 0, nil, nil), g.mesh(t, 1, nil, nil), g.mesh(t, 2, nil, nil)}
	mpcmConnectAll(t, ms)
	for i, m := range ms {
		for _, p := range m.Peers() {
			if err := m.Send(p, "r1", []any{"from", i}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i, m := range ms {
		got, err := m.Collect("r1", m.Peers(), 0)
		if err != nil {
			t.Fatal(err)
		}
		for p, v := range got {
			s, _ := MpcStringify(v)
			if s != `["from",`+strconv.Itoa(p)+`]` {
				t.Fatalf("node %d from %d: %s", i, p, s)
			}
		}
	}
	// a signature verifies against the pinned certificate of its signer and nobody else's
	sig, err := ms[0].Sign([]byte("statement"))
	if err != nil {
		t.Fatal(err)
	}
	if !ms[1].Verify(0, []byte("statement"), sig) || ms[1].Verify(2, []byte("statement"), sig) || ms[1].Verify(0, []byte("other"), sig) || ms[1].Verify(1, []byte("statement"), sig) {
		t.Fatal("signature pinning is wrong")
	}
	for _, m := range ms {
		m.Finish()
	}
}

func TestMpcMeshWrongRoundAndAbortPropagation(t *testing.T) {
	g := mpcmSetup(t, 3)
	ms := []*MpcMesh{g.mesh(t, 0, nil, nil), g.mesh(t, 1, nil, nil), g.mesh(t, 2, nil, nil)}
	mpcmConnectAll(t, ms)
	if err := ms[1].Send(0, "alpha", "x"); err != nil {
		t.Fatal(err)
	}
	_, err := ms[0].Recv(1, "beta", 0)
	mpcmWantAbort(t, err, "wrong-round", 1)
	// node 0 failed: node 2 learns it as a CLAIM by 0 and blames 0, not whoever 0 accused
	_, err = ms[2].Recv(0, "alpha", 0)
	a := mpcmWantAbort(t, err, "peer-abort", 0)
	if a.ClaimedKind == nil || *a.ClaimedKind != "wrong-round" {
		t.Fatalf("claimed kind: %v", a.ClaimedKind)
	}
	// after a failure nothing is sent as protocol data
	if err := ms[0].Send(1, "gamma", "x"); err == nil {
		t.Fatal("send after failure must be refused")
	}
}

func TestMpcMeshRefusesWrongPeerCertificate(t *testing.T) {
	g := mpcmSetup(t, 2)
	_, imposter, err := MpcGenerateIdentity("imposter", nil)
	if err != nil {
		t.Fatal(err)
	}
	// node 1 pins an imposter certificate for node 0, so the real node 0 must be refused at the dial
	bad := []MpcNodeAddr{{ID: 0, Host: "127.0.0.1", Port: g.nodes[0].Port, CertPEM: imposter}, g.nodes[1]}
	m0 := g.mesh(t, 0, nil, func(c *MpcMeshConfig) { c.ConnectTimeout = 3 * time.Second })
	m1 := g.mesh(t, 1, bad, nil)
	go func() { _ = m0.Connect() }()
	err = m1.Connect()
	mpcmWantAbort(t, err, "identity", 0)
}

func TestMpcMeshRefusesUnpinnedClient(t *testing.T) {
	g := mpcmSetup(t, 2)
	// a stranger with a valid-looking self-signed certificate that nobody pinned
	k, c, _ := MpcGenerateIdentity("stranger", nil)
	g2 := &mpcmNet{keys: []string{g.keys[0], k}, certs: []string{g.certs[0], c}, nodes: g.nodes}
	m0 := g.mesh(t, 0, nil, func(c *MpcMeshConfig) { c.ConnectTimeout = 1500 * time.Millisecond })
	done := make(chan error, 1)
	go func() { done <- m0.Connect() }()
	conn := mpcmRaw(t, g2, 1, 0)
	raw, _ := MpcEncodeFrame(MpcWireVersion, "hello", "sess-1", 0, "hello", map[string]any{"id": 1})
	_, _ = conn.Write(raw) // the door may already be closed: ignore the error
	err := <-done
	mpcmWantAbort(t, err, "timeout", 1) // no authenticated link ever came
	if len(m0.Events()) == 0 {
		t.Fatal("the rejected client must be noted")
	}
}

func TestMpcMeshRefusesHelloNamingAnotherID(t *testing.T) {
	g := mpcmSetup(t, 3)
	m0 := g.mesh(t, 0, nil, nil)
	done := make(chan error, 1)
	go func() { done <- m0.Connect() }()
	conn := mpcmRaw(t, g, 1, 0) // authenticated as node 1 ...
	mpcmRawFrame(t, conn, "hello", "hello", 0, map[string]any{"id": 2})
	mpcmWantAbort(t, <-done, "identity", 1) // ... but claims to be 2
}

// mpcmRawLinked connects a 2-node mesh whose node 1 is a raw client that has completed the hello.
func mpcmRawLinked(t *testing.T) (*MpcMesh, *tls.Conn) {
	g := mpcmSetup(t, 2)
	m0 := g.mesh(t, 0, nil, nil)
	done := make(chan error, 1)
	go func() { done <- m0.Connect() }()
	conn := mpcmRaw(t, g, 1, 0)
	mpcmRawFrame(t, conn, "hello", "hello", 0, map[string]any{"id": 1})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return m0, conn
}

func TestMpcMeshRefusesOversizeFrame(t *testing.T) {
	m0, conn := mpcmRawLinked(t)
	if _, err := conn.Write([]byte{0x00, 0x50, 0x00, 0x00}); err != nil { // 5 MiB length prefix
		t.Fatal(err)
	}
	_, err := m0.Recv(1, "r", 0)
	mpcmWantAbort(t, err, "oversize", 1)
}

func TestMpcMeshRefusesEarlyClose(t *testing.T) {
	m0, conn := mpcmRawLinked(t)
	_ = conn.Close()
	_, err := m0.Recv(1, "r", 0)
	mpcmWantAbort(t, err, "disconnect", 1)
}

func TestMpcMeshRefusesReplayedAndSkippedSequence(t *testing.T) {
	m0, conn := mpcmRawLinked(t)
	mpcmRawFrame(t, conn, "msg", "r", 1, "a")
	if v, err := m0.Recv(1, "r", 0); err != nil || v != "a" {
		t.Fatalf("%v %v", v, err)
	}
	mpcmRawFrame(t, conn, "msg", "r", 1, "again") // seq 1 replayed
	_, err := m0.Recv(1, "r", 0)
	mpcmWantAbort(t, err, "duplicate", 1)

	m0, conn = mpcmRawLinked(t)
	mpcmRawFrame(t, conn, "msg", "r", 5, "skip")
	_, err = m0.Recv(1, "r", 0)
	mpcmWantAbort(t, err, "out-of-order", 1)
}

func TestMpcMeshRefusesForeignSessionAndSilence(t *testing.T) {
	m0, conn := mpcmRawLinked(t)
	raw, _ := MpcEncodeFrame(MpcWireVersion, "msg", "other-session", 1, "r", "x")
	_, _ = conn.Write(raw)
	_, err := m0.Recv(1, "r", 0)
	mpcmWantAbort(t, err, "wrong-session", 1)

	m0, _ = mpcmRawLinked(t)
	_, err = m0.Recv(1, "r", 200*time.Millisecond)
	a := mpcmWantAbort(t, err, "timeout", 1)
	if a.DeadlineMs == nil || *a.DeadlineMs != 200 {
		t.Fatalf("deadline: %v", a.DeadlineMs)
	}
}
