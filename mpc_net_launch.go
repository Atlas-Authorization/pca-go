package pca

// Local launcher: n parties (plus the trusted dealer) as goroutines on loopback, each with a fresh per-run identity and its own
// TLS mesh. The same MpcRunParty / MpcRunDealer code drives a real multi-host run, where each node builds its own MpcMesh from
// its own key and the other nodes' public certificates.

import (
	"errors"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"
)

// MpcLaunchOptions configures a local run. Offline is "no-dealer" (default: n nodes, the parties derive everything from OT) or
// "trusted-dealer" (n+1 nodes; needs InsecureTrustedDealer).
type MpcLaunchOptions struct {
	N, Q                  int
	Offline               string
	Vectors               []MpcDecisionVector
	InsecureTrustedDealer bool
	RecvTimeout           time.Duration
	DealerSeed            *big.Int
	DealerFault           *MpcDealerFault
	MacFaultAtInput       *int
	// Tamper is TEST ONLY: per node id, a (malicious) sender rewriting its own outgoing frames.
	Tamper map[int]func(to int, raw []byte) [][]byte
	// Behavior is TEST ONLY: per party id, a no-dealer offline misbehaviour ("offline-lie", "ot-u-lie", "ot-proof-lie").
	Behavior map[int]string
	// BehaviorRound is TEST ONLY: per party id, the round the online behaviors ("open-lie", "mac-lie", "bad-tag", "crash", "silent") act in.
	BehaviorRound map[int]string
}

// MpcNodeOutput is one node's verdict: Result for a party that finished, Err for any node that aborted.
type MpcNodeOutput struct {
	ID     int
	Role   string // "party" or "dealer"
	Result *MpcPartyResult
	Err    error
}

// MpcLaunchLocal runs the whole session in this process and returns every node's output (party ids 0..n-1, then the dealer).
func MpcLaunchLocal(o MpcLaunchOptions) ([]MpcNodeOutput, error) {
	mode := o.Offline
	if mode == "" {
		mode = "no-dealer"
	}
	if mode != "no-dealer" && mode != "trusted-dealer" {
		return nil, errors.New("MpcLaunchLocal: unknown offline mode")
	}
	if mode == "trusted-dealer" && !o.InsecureTrustedDealer {
		return nil, errors.New("MpcLaunchLocal: offline 'trusted-dealer' requires InsecureTrustedDealer")
	}
	n := o.N
	if n < 1 || len(o.Vectors) != n {
		return nil, errors.New("MpcLaunchLocal: need n >= 1 and one decision vector per party")
	}
	nodeCount := n
	if mode == "trusted-dealer" {
		nodeCount = n + 1
	}
	keys, certs := make([]string, nodeCount), make([]string, nodeCount)
	lns := make([]net.Listener, nodeCount)
	nodes := make([]MpcNodeAddr, nodeCount)
	defer func() {
		for _, ln := range lns {
			if ln != nil {
				_ = ln.Close()
			}
		}
	}()
	for i := 0; i < nodeCount; i++ {
		var err error
		if keys[i], certs[i], err = MpcGenerateIdentity("mpc-node-"+strconv.Itoa(i), nil); err != nil {
			return nil, err
		}
		if lns[i], err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			return nil, err
		}
		nodes[i] = MpcNodeAddr{ID: i, Host: "127.0.0.1", Port: lns[i].Addr().(*net.TCPAddr).Port, CertPEM: certs[i]}
	}
	sid := "local-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	recv := o.RecvTimeout
	if recv <= 0 {
		recv = 30 * time.Second
	}
	meshes := make([]*MpcMesh, nodeCount)
	for i := range meshes {
		cfg := MpcMeshConfig{SelfID: i, Nodes: nodes, KeyPEM: keys[i], CertPEM: certs[i], SessionID: sid, Listener: lns[i],
			ConnectTimeout: 120 * time.Second, RecvTimeout: recv}
		if t := o.Tamper[i]; t != nil {
			cfg.Tamper, cfg.UnsafeTestHooks = t, true
		}
		m, err := NewMpcMesh(cfg)
		if err != nil {
			return nil, err
		}
		meshes[i] = m
		defer m.Close()
	}
	out := make([]MpcNodeOutput, nodeCount)
	var wg sync.WaitGroup
	for i := 0; i < nodeCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := meshes[i]
			out[i] = MpcNodeOutput{ID: i, Role: "party"}
			if err := m.Connect(); err != nil {
				out[i].Err = err
				return
			}
			if i == n { // only in trusted-dealer mode
				out[i].Role = "dealer"
				out[i].Err = MpcRunDealer(MpcDealerConfig{InsecureTrustedDealer: true, N: n, Q: o.Q, Mesh: m, Seed: o.DealerSeed, Fault: o.DealerFault, MacFaultAtInput: o.MacFaultAtInput})
				return
			}
			out[i].Result, out[i].Err = MpcRunParty(MpcPartyConfig{ID: i, N: n, Q: o.Q, Input: o.Vectors[i], Mesh: m, Offline: mode,
				InsecureTrustedDealer: o.InsecureTrustedDealer, SessionID: sid, Behavior: o.Behavior[i], BehaviorRound: o.BehaviorRound[i], UnsafeTestHooks: o.Behavior[i] != ""})
		}()
	}
	wg.Wait()
	return out, nil
}
