// Package partycli is the body of the pca-mpc-party command: one MPC node (a party or the trusted dealer) as its own OS process, talking to the others only over
// the pinned mutual-TLS mesh. Usage:
//
//	pca-mpc-party <config.json>
//	pca-mpc-party keygen <dir> <cn>     (writes <dir>/key.pem and <dir>/cert.pem)
//
// It prints exactly one JSON line on stdout: the result, or the attributable abort (exit status 3). Roles: party, dealer, and the
// base-OT demonstrations ot-sender / ot-receiver (ot.kind "ec", or "lwe" when the binary registered the endemic-LWE library).
package partycli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	pca "github.com/Atlas-Authorization/pca-go"
)

// behavior is the reference's {kind, round?} object; a bare string is accepted as the kind.
type behavior struct{ Kind, Round string }

func (b *behavior) UnmarshalJSON(raw []byte) error {
	var kind string
	if json.Unmarshal(raw, &kind) == nil {
		b.Kind = kind
		return nil
	}
	var o struct {
		Kind  string `json:"kind"`
		Round string `json:"round"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return err
	}
	b.Kind, b.Round = o.Kind, o.Round
	return nil
}

type nodeConfig struct {
	Role      string `json:"role"` // "party", "dealer", "ot-sender" or "ot-receiver"
	ID        int    `json:"id"`
	N         int    `json:"n"`
	Q         int    `json:"Q"`
	SessionID string `json:"sessionId"`
	Input     *struct {
		Allow  int `json:"allow"`
		T      int `json:"t"`
		RQuant int `json:"rQuant"`
	} `json:"input"`
	// OT is the base OT of the ot-sender / ot-receiver roles (default ec, 128 transfers).
	OT *struct {
		Kind  string `json:"kind"`
		Count int    `json:"count"`
	} `json:"ot"`
	ListenHost string `json:"listenHost"`
	Nodes      []struct {
		ID       int    `json:"id"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		CertPath string `json:"certPath"`
	} `json:"nodes"`
	// BindFirst: bind this node's listener (its own port may be 0), print {"listening":port,"id":id}, then read one stdin line
	// {"ports":{"<id>":port,...}} carrying every peer's real port before dialing anyone.
	BindFirst        bool   `json:"bindFirst"`
	KeyPath          string `json:"keyPath"`
	CertPath         string `json:"certPath"`
	RecvTimeoutMs    int    `json:"recvTimeoutMs"`
	ConnectTimeoutMs int    `json:"connectTimeoutMs"`
	DealerSeed       string `json:"dealerSeed"`
	// Offline is "no-dealer" (default; no dealer node) or "trusted-dealer", which also needs InsecureTrustedDealer.
	Offline               string `json:"offline"`
	InsecureTrustedDealer bool   `json:"insecureTrustedDealer"`
	// TEST-ONLY hooks: refused unless UnsafeTestHooks is true AND the environment has PCA_MPC_UNSAFE_TEST_HOOKS=1.
	UnsafeTestHooks bool      `json:"unsafeTestHooks"`
	Behavior        *behavior `json:"behavior"` // {kind, round?}: see MpcPartyConfig.Behavior
	FrameFault      *struct {
		Kind   string `json:"kind"`
		Round  string `json:"round"`
		To     *int   `json:"to"`
		Accuse int    `json:"accuse"`
	} `json:"frameFault"`
	DealerFault *struct {
		KeepCDelta      string   `json:"keepCDelta"`
		PartnerCDelta   []string `json:"partnerCDelta"` // "" = no delta
		MacFaultAtInput *int     `json:"macFaultAtInput"`
	} `json:"dealerFault"`
}

// resultJSON renders the party's verdict with the reference's member names (the Go struct has no JSON tags).
func resultJSON(r *pca.MpcPartyResult) map[string]any {
	rounds := make([]map[string]any, len(r.Rounds))
	for i, x := range r.Rounds {
		rounds[i] = map[string]any{"rd": x.Rd, "ms": x.Ms, "bytesOut": x.BytesOut, "bytesIn": x.BytesIn}
	}
	return map[string]any{
		"id": r.ID, "n": r.N, "Q": r.Q,
		"composed":         map[string]any{"allow": r.Composed.Allow, "t": r.Composed.T, "rQuant": r.Composed.RQuant},
		"rounds":           rounds,
		"transcriptDigest": r.TranscriptDigest, "wallMs": r.WallMs, "multiplications": r.Multiplications, "opens": r.Opens,
		"offlineMode": r.OfflineMode, "macKeys": r.MacKeys, "sacrificedTriples": r.SacrificedTriples,
		"sacrificePartners": r.SacrificePartners, "identifiableAbort": r.IdentifiableAbort,
	}
}

func out(o any) {
	b, _ := json.Marshal(o)
	fmt.Println(string(b))
}

// Main runs the command for args (os.Args form: program name first) and returns its exit status.
func Main(args []string) int {
	if len(args) >= 2 && args[1] == "keygen" {
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: pca-mpc-party keygen <dir> [cn]")
			return 2
		}
		cn := "mpc-node"
		if len(args) > 3 {
			cn = args[3]
		}
		k, c, err := pca.MpcGenerateIdentity(cn, nil)
		if err == nil {
			err = pca.MkdirAllOwnerOnly(args[2])
		}
		if err == nil {
			err = pca.WriteFileOwnerOnly(filepath.Join(args[2], "key.pem"), []byte(k)) // owner-only from the instant it exists
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(args[2], "cert.pem"), []byte(c), 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		out(map[string]string{"keyPath": filepath.Join(args[2], "key.pem"), "certPath": filepath.Join(args[2], "cert.pem")})
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pca-mpc-party <config.json> | keygen <dir> [cn]")
		return 2
	}
	raw, err := os.ReadFile(args[1])
	var cfg nodeConfig
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	if err != nil {
		out(map[string]any{"ok": false, "error": map[string]any{"kind": "local", "blamed": nil, "message": err.Error()}})
		return 3
	}
	return run(cfg)
}

func fail(cfg nodeConfig, err error, mesh *pca.MpcMesh) int {
	var a *pca.MpcNetAbort
	if mesh != nil && mesh.Failed() != nil {
		a = mesh.Failed()
	} else if !errors.As(err, &a) {
		a = pca.NewMpcNetAbort("local", nil, cfg.ID, err.Error(), nil, nil, nil, nil, nil)
	}
	e := map[string]any{"kind": a.Kind, "blamed": a.Blamed, "reporter": a.Reporter, "claimedKind": a.ClaimedKind, "claimedBlame": a.ClaimedBlame,
		"reason": a.Reason, "evidence": a.Evidence, "deadlineMs": a.DeadlineMs, "message": a.Error()}
	o := map[string]any{"ok": false, "role": cfg.Role, "id": cfg.ID, "error": e}
	if mesh != nil {
		o["links"], o["events"] = mesh.Stats(), mesh.Events()
	}
	out(o)
	time.Sleep(300 * time.Millisecond) // let abort frames flush
	return 3
}

// bindFirst binds this node's listener on its own configured port (0 = the OS picks), reports the port it holds, and writes every peer's
// real port into cfg.Nodes from one stdin line before anyone dials.
func bindFirst(cfg *nodeConfig) (net.Listener, error) {
	self := -1
	for i, x := range cfg.Nodes {
		if x.ID == cfg.ID {
			self = i
		}
	}
	if self < 0 {
		return nil, errors.New("bind first: this node is not in the node list")
	}
	host := cfg.ListenHost
	if host == "" {
		host = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(cfg.Nodes[self].Port)))
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	cfg.Nodes[self].Port = port
	out(map[string]any{"listening": port, "id": cfg.ID})
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		ln.Close()
		return nil, errors.New("stdin closed before the port map arrived")
	}
	var m struct {
		Ports map[string]int `json:"ports"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		ln.Close()
		return nil, err
	}
	for i := range cfg.Nodes {
		if p, ok := m.Ports[strconv.Itoa(cfg.Nodes[i].ID)]; ok && i != self {
			cfg.Nodes[i].Port = p
		}
	}
	return ln, nil
}

func run(cfg nodeConfig) int {
	hooks := cfg.Behavior != nil || cfg.FrameFault != nil || cfg.DealerFault != nil
	if hooks && !(cfg.UnsafeTestHooks && os.Getenv("PCA_MPC_UNSAFE_TEST_HOOKS") == "1") {
		return fail(cfg, errors.New("refusing to start: test hooks (behavior/frameFault/dealerFault) are not enabled in this environment"), nil)
	}
	var bound net.Listener
	if cfg.BindFirst {
		var err error
		if bound, err = bindFirst(&cfg); err != nil {
			return fail(cfg, err, nil)
		}
	}
	var nodes []pca.MpcNodeAddr
	for _, x := range cfg.Nodes {
		pem, err := os.ReadFile(x.CertPath)
		if err != nil {
			return fail(cfg, err, nil)
		}
		nodes = append(nodes, pca.MpcNodeAddr{ID: x.ID, Host: x.Host, Port: x.Port, CertPEM: string(pem)})
	}
	key, err1 := os.ReadFile(cfg.KeyPath)
	cert, err2 := os.ReadFile(cfg.CertPath)
	if err := errors.Join(err1, err2); err != nil {
		return fail(cfg, err, nil)
	}
	mc := pca.MpcMeshConfig{SelfID: cfg.ID, Nodes: nodes, KeyPEM: string(key), CertPEM: string(cert), SessionID: cfg.SessionID, ListenHost: cfg.ListenHost,
		RecvTimeout: time.Duration(cfg.RecvTimeoutMs) * time.Millisecond, ConnectTimeout: time.Duration(cfg.ConnectTimeoutMs) * time.Millisecond}
	if bound != nil {
		mc.Listener = bound // the held listener, never released and re-bound
	}
	if f := cfg.FrameFault; f != nil {
		mc.Tamper = pca.MpcTamperFor(pca.MpcFrameFault{Kind: f.Kind, Round: f.Round, To: f.To, Accuse: f.Accuse})
		mc.UnsafeTestHooks = true
	}
	if cfg.Role == "dealer" {
		for _, x := range nodes {
			if x.ID < cfg.N {
				mc.LinkTo = append(mc.LinkTo, x.ID)
			}
		}
	}
	mesh, err := pca.NewMpcMesh(mc)
	if err != nil {
		return fail(cfg, err, nil)
	}
	defer mesh.Close()
	t0 := time.Now()
	if err := mesh.Connect(); err != nil {
		return fail(cfg, err, mesh)
	}
	connectMs := time.Since(t0).Milliseconds()
	if cfg.Role == "dealer" {
		var seed *big.Int
		if cfg.DealerSeed != "" {
			var ok bool
			if seed, ok = new(big.Int).SetString(cfg.DealerSeed, 10); !ok {
				return fail(cfg, errors.New("bad dealerSeed"), mesh)
			}
		}
		var fault *pca.MpcDealerFault
		var macFault *int
		if df := cfg.DealerFault; df != nil {
			macFault = df.MacFaultAtInput
			dec := func(x string) (*big.Int, bool) {
				if x == "" {
					return nil, true
				}
				return new(big.Int).SetString(x, 10)
			}
			var ok bool
			fault = &pca.MpcDealerFault{}
			if fault.KeepCDelta, ok = dec(df.KeepCDelta); !ok {
				return fail(cfg, errors.New("bad dealerFault.keepCDelta"), mesh)
			}
			for _, x := range df.PartnerCDelta {
				d, ok := dec(x)
				if !ok {
					return fail(cfg, errors.New("bad dealerFault.partnerCDelta"), mesh)
				}
				fault.PartnerCDelta = append(fault.PartnerCDelta, d)
			}
		}
		if err := pca.MpcRunDealer(pca.MpcDealerConfig{InsecureTrustedDealer: cfg.InsecureTrustedDealer, N: cfg.N, Q: cfg.Q, Mesh: mesh, Seed: seed, Fault: fault, MacFaultAtInput: macFault}); err != nil {
			return fail(cfg, err, mesh)
		}
		out(map[string]any{"ok": true, "role": "dealer", "id": cfg.ID, "connectMs": connectMs, "links": mesh.Stats(), "events": mesh.Events()})
		return 0
	}
	if cfg.Role == "ot-sender" || cfg.Role == "ot-receiver" {
		kind, count := "ec", 128
		if cfg.OT != nil {
			kind, count = cfg.OT.Kind, cfg.OT.Count
		}
		peer := 0
		var r *pca.MpcOtNetResult
		if cfg.Role == "ot-sender" {
			peer = 1
			r, err = pca.MpcRunOtSender(mesh, peer, kind, count)
		} else {
			r, err = pca.MpcRunOtReceiver(mesh, peer, kind, count)
		}
		if err != nil {
			return fail(cfg, err, mesh)
		}
		out(map[string]any{"ok": true, "role": cfg.Role, "connectMs": connectMs, "result": map[string]any{"kind": r.Kind, "role": r.Role, "count": r.Count,
			"ms": r.Ms, "matched": r.Matched, "padDigest": r.PadDigest}, "links": mesh.Stats(), "events": mesh.Events()})
		time.Sleep(300 * time.Millisecond)
		return 0
	}
	if cfg.Input == nil {
		return fail(cfg, errors.New("a party needs an input"), mesh)
	}
	var beh behavior
	if cfg.Behavior != nil {
		beh = *cfg.Behavior
	}
	r, err := pca.MpcRunParty(pca.MpcPartyConfig{ID: cfg.ID, N: cfg.N, Q: cfg.Q, Input: pca.MpcDecisionVector{Allow: cfg.Input.Allow, T: cfg.Input.T, RQuant: cfg.Input.RQuant},
		Mesh: mesh, Offline: cfg.Offline, InsecureTrustedDealer: cfg.InsecureTrustedDealer, SessionID: cfg.SessionID,
		Behavior: beh.Kind, BehaviorRound: beh.Round, UnsafeTestHooks: hooks})
	if errors.Is(err, pca.ErrMpcSilentParty) {
		time.Sleep(time.Hour) // stay connected and say nothing: the peers must time out (their launcher ends this process)
	}
	if err != nil {
		return fail(cfg, err, mesh)
	}
	out(map[string]any{"ok": true, "role": "party", "connectMs": connectMs, "result": resultJSON(r), "links": mesh.Stats(), "events": mesh.Events()})
	time.Sleep(300 * time.Millisecond)
	return 0
}
