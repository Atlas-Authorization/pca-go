package pca

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The wire codec, the inbox, the in-memory network, the driver over a scripted channel and the framing of the FROST DKG against the
// reference corpora (see frost_dkg_vectors_test.go).

func dkgBodiesOut(c []DkgCollected) map[string]any {
	m := map[string]any{}
	for _, x := range c {
		m[strconv.FormatInt(x.From, 10)] = x.Body
	}
	return m
}

func dkgDecodeFn(f func(body any) (any, error)) vecFn {
	return frostCall(func(a []any) (any, error) { return f(vecArg(a, 0)) })
}

var dkgPhases = []string{"round1", "share", "complaints", "rebuttals", "echo"}

func dkgPhase(kind string) int {
	for i, p := range dkgPhases {
		if p == kind {
			return i
		}
	}
	return 99
}

// dkgScriptedChannel is the driver's channel in a party replay: the inbound messages are delivered, in list order, before each collect
// of their phase or a later one; every broadcast and send is recorded as the wire bytes.
type dkgScriptedChannel struct {
	self     int64
	peers    []int64
	session  []byte
	inbox    *DkgInbox
	pending  []map[string]any
	outbound []any
}

func (c *dkgScriptedChannel) Self() int64    { return c.self }
func (c *dkgScriptedChannel) Peers() []int64 { return c.peers }

func (c *dkgScriptedChannel) record(op, kind string, to int64, body any) error {
	b, err := dkgEncodeEnvelope(c.session, kind, body)
	if err != nil {
		return err
	}
	m := map[string]any{"op": op, "kind": kind, "bytes": vecBytesOut(b)}
	if op == "send" {
		m["to"] = dkgNum(to)
	}
	c.outbound = append(c.outbound, m)
	return nil
}

func (c *dkgScriptedChannel) Broadcast(kind string, body any) error {
	return c.record("broadcast", kind, 0, body)
}

func (c *dkgScriptedChannel) Send(to int64, kind string, body any) error {
	for _, p := range c.peers {
		if p == to {
			return c.record("send", kind, to, body)
		}
	}
	return dkgErrPeer("identity", to, "not a connected peer")
}

func (c *dkgScriptedChannel) Collect(kind string, from []int64, timeoutMs float64) ([]DkgCollected, error) {
	lim := dkgPhase(kind)
	keep := c.pending[:0:0]
	for _, m := range c.pending {
		if dkgPhase(rsStr(m["kind"])) <= lim {
			sender, _ := dkgInt(m["from"])
			c.inbox.Accept(sender, frostBytes(m["bytes"]))
		} else {
			keep = append(keep, m)
		}
	}
	c.pending = keep
	return c.inbox.Collect(kind, from, timeoutMs)
}

func (c *dkgScriptedChannel) Close() error { c.inbox.Close(); return nil }

func dkgChannelFns() map[string]vecFn {
	return map[string]vecFn{
		"encodeDkgMessage": frostCall(func(a []any) (any, error) {
			sid, ok := vecArg(a, 0).([]byte)
			if !ok {
				return nil, errDkgTypedGap
			}
			b, err := dkgEncodeEnvelope(sid, vecArg(a, 1), vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(b), nil
		}),
		"decodeDkgMessage": frostCall(func(a []any) (any, error) {
			b, ok1 := vecArg(a, 0).([]byte)
			sid, ok2 := vecArg(a, 1).([]byte)
			if !ok1 && ok2 { // the reference refuses a message that is not bytes with the channel's malformed code
				return nil, dkgErr("malformed", "message is not bytes")
			}
			if !ok1 || !ok2 {
				return nil, errDkgTypedGap
			}
			kind, body, err := DecodeDkgMessage(b, sid)
			if err != nil {
				return nil, err
			}
			return map[string]any{"kind": kind, "body": body}, nil
		}),
		"decodeDkgRound1Package": frostCall(func(a []any) (any, error) {
			t, ok := dkgInt(vecArg(a, 1))
			if !ok {
				t = -1 // a threshold that is no integer matches no commitment count
			}
			p, err := DecodeDkgRound1Package(vecArg(a, 0), int(t))
			if err != nil {
				return nil, err
			}
			return dkgPkgOut(p), nil
		}),
		"decodeDkgShareMessage": dkgDecodeFn(func(b any) (any, error) {
			s, err := DecodeDkgShareMessage(b)
			if err != nil {
				return nil, err
			}
			return dkgShareOut(s), nil
		}),
		"decodeDkgComplaints": dkgDecodeFn(func(b any) (any, error) {
			l, err := DecodeDkgComplaints(b)
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, c := range l {
				out = append(out, dkgComplaintOut(c))
			}
			return out, nil
		}),
		"decodeDkgRebuttals": dkgDecodeFn(func(b any) (any, error) {
			l, err := DecodeDkgRebuttals(b)
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, r := range l {
				out = append(out, dkgRebuttalOut(r))
			}
			return out, nil
		}),
		"decodeDkgEcho": dkgDecodeFn(func(b any) (any, error) {
			e, err := DecodeDkgEcho(b)
			if err != nil {
				return nil, err
			}
			return dkgEchoOut(e), nil
		}),
		"dkgInbox": frostCall(func(a []any) (any, error) {
			cfg := vecObj(vecArg(a, 0))
			peers, _ := dkgIDs(cfg["peers"])
			in := NewDkgInbox(dkgOnlyBytes(cfg["sessionId"]), peers)
			out := []any{}
			for _, x := range rsList(cfg["ops"]) {
				op := vecObj(x)
				switch rsStr(op["op"]) {
				case "accept":
					sender, _ := dkgInt(op["sender"])
					in.Accept(sender, dkgOnlyBytes(op["bytes"]))
					out = append(out, map[string]any{"ok": true})
				case "fail":
					peer, _ := dkgInt(op["peer"])
					in.Fail(peer, dkgErr(rsStr(op["code"]), rsStr(op["message"])))
					out = append(out, map[string]any{"ok": true})
				case "peerGone":
					peer, _ := dkgInt(op["peer"])
					in.PeerGone(peer)
					out = append(out, map[string]any{"ok": true})
				case "close":
					in.Close()
					out = append(out, map[string]any{"ok": true})
				case "collect":
					from, _ := dkgIDs(op["from"])
					tm, _ := jsNum(op["timeoutMs"])
					got, err := in.Collect(rsStr(op["kind"]), from, tm)
					if err != nil {
						out = append(out, frostErrOut(err))
					} else {
						out = append(out, map[string]any{"ok": true, "bodies": dkgBodiesOut(got)})
					}
				default:
					return nil, errDkgTypedGap
				}
			}
			return out, nil
		}),
		"memoryNetwork": frostCall(func(a []any) (any, error) {
			cfg := vecObj(vecArg(a, 0))
			ids, _ := dkgIDs(cfg["ids"])
			var hook func(DkgDelivery) []byte
			if m := vecObj(cfg["intercept"]); m != nil {
				hook = func(d DkgDelivery) []byte {
					hit := true
					if v, has := m["kind"]; has && v != d.Kind {
						hit = false
					}
					if v, has := m["from"]; has {
						if f, _ := dkgInt(v); f != d.From {
							hit = false
						}
					}
					if v, has := m["to"]; has {
						if f, _ := dkgInt(v); f != d.To {
							hit = false
						}
					}
					if !hit {
						return d.Bytes
					}
					switch m["action"] {
					case "drop":
						return nil
					case "replace":
						return dkgOnlyBytes(m["bytes"])
					}
					return d.Bytes
				}
			}
			net := NewMemoryDkgNetwork(ids, dkgOnlyBytes(cfg["sessionId"]), hook)
			chans := map[string]any{}
			keys := make([]int64, 0, len(net.Channels))
			for id := range net.Channels {
				keys = append(keys, id)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, id := range keys {
				chans[strconv.FormatInt(id, 10)] = map[string]any{"self": dkgNum(id), "peers": dkgIDsOut(net.Channels[id].Peers())}
			}
			out := []any{map[string]any{"channels": chans}}
			for _, x := range rsList(cfg["ops"]) {
				op := vecObj(x)
				chOf := func(k string) DkgChannel {
					id, _ := dkgInt(op[k])
					return net.Channels[id]
				}
				var err error
				var got []DkgCollected
				collected := false
				switch rsStr(op["op"]) {
				case "broadcast":
					if ch := chOf("from"); ch != nil {
						err = ch.Broadcast(rsStr(op["kind"]), op["body"])
					}
				case "send":
					to, _ := dkgInt(op["to"])
					if ch := chOf("from"); ch != nil {
						err = ch.Send(to, rsStr(op["kind"]), op["body"])
					}
				case "deliver":
					from, _ := dkgInt(op["from"])
					to, _ := dkgInt(op["to"])
					net.Deliver(from, to, dkgOnlyBytes(op["bytes"]))
				case "collect":
					fromIDs, _ := dkgIDs(op["fromIds"])
					tm, _ := jsNum(op["timeoutMs"])
					got, err = chOf("at").Collect(rsStr(op["kind"]), fromIDs, tm)
					collected = err == nil
				case "close":
					err = chOf("at").Close()
				default:
					return nil, errDkgTypedGap
				}
				switch {
				case err != nil:
					out = append(out, frostErrOut(err))
				case collected:
					out = append(out, map[string]any{"ok": true, "bodies": dkgBodiesOut(got)})
				default:
					out = append(out, map[string]any{"ok": true})
				}
			}
			return out, nil
		}),
		"runDkgOverChannel": frostCall(func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 0))
			ids := []int64{}
			for _, x := range rsList(spec["participants"]) {
				id, ok := dkgInt(x)
				if !ok {
					id = 0 // no positive integer: refused by the driver
				}
				ids = append(ids, id)
			}
			self, _ := dkgInt(spec["self"])
			var peers []int64
			if l, has := spec["peers"]; has {
				for _, x := range rsList(l) {
					id, ok := dkgInt(x)
					if !ok {
						id = 0
					}
					peers = append(peers, id)
				}
			} else {
				for _, id := range ids {
					if id != self {
						peers = append(peers, id)
					}
				}
				sort.Slice(peers, func(i, j int) bool { return peers[i] < peers[j] })
			}
			sid := dkgOnlyBytes(spec["sessionId"])
			ch := &dkgScriptedChannel{self: self, peers: peers, session: sid, inbox: NewDkgInbox(sid, peers)}
			for _, x := range rsList(spec["inbound"]) {
				ch.pending = append(ch.pending, vecObj(x))
			}
			for _, x := range rsList(spec["gone"]) {
				id, _ := dkgInt(x)
				ch.inbox.PeerGone(id)
			}
			t, ok := dkgInt(spec["t"])
			if !ok {
				t = 0 // a threshold that is no integer: refused by the driver
			}
			tm, _ := jsNum(spec["timeoutMs"])
			res, err := RunDkgOverChannel(ch, RunDkgOpts{T: int(t), Participants: ids, SessionID: sid, TimeoutMs: &tm})
			out := map[string]any{"outbound": append([]any{}, ch.outbound...)}
			if err != nil {
				out["error"] = frostErrOut(err)
				return out, nil
			}
			cs := []any{}
			for _, c := range res.Complaints {
				cs = append(cs, dkgComplaintOut(c))
			}
			out["result"] = map[string]any{"qualified": dkgIDsOut(res.Qualified), "complaints": cs, "keyPackage": dkgKeyPackageOut(res.KeyPackage)}
			return out, nil
		}),
		"tlsFrameEncode": frostCall(func(a []any) (any, error) {
			p, ok := vecArg(a, 0).([]byte)
			if !ok {
				return nil, errDkgTypedGap
			}
			return vecBytesOut(DkgFrame(p)), nil
		}),
		"tlsFrameDecode": frostCall(func(a []any) (any, error) {
			var r DkgFrameReader
			accepted := []any{}
			var failure any
			for _, c := range rsList(vecObj(vecArg(a, 0))["chunks"]) {
				if failure != nil {
					break
				}
				frames, err := r.Push(dkgOnlyBytes(c))
				for _, f := range frames {
					accepted = append(accepted, vecBytesOut(f))
				}
				if err != nil {
					failure = "oversize"
				}
			}
			return map[string]any{"accepted": accepted, "error": failure, "buffered": dkgNum(int64(r.Buffered()))}, nil
		}),
	}
}

func dkgAllFns() map[string]vecFn {
	fns := dkgCoreFns()
	for k, f := range dkgChannelFns() {
		fns[k] = f
	}
	return fns
}

func TestFrostDkgMatchesTheReference(t *testing.T) {
	fns := vecSeeded(dkgAllFns())
	n, unhandled := frostReplay(t, "ref-frost-dkg.json.gz", fns, nil)
	if len(unhandled) > 0 {
		t.Fatalf("functions of the corpus without a Go entry point: %v", unhandled)
	}
	if n != 439 {
		t.Fatalf("the corpus holds %d cases, 439 are expected", n)
	}
	replaySecretGen(t, "ref-frost-dkg.json.gz", func(t *testing.T, p string) {
		n, unhandled := frostReplay(t, p, fns, nil)
		if len(unhandled) > 0 {
			t.Fatalf("functions of the secret corpus without a Go entry point: %v", unhandled)
		}
		if n != 286 {
			t.Fatalf("the secret corpus holds %d cases, 286 are expected", n)
		}
	})
}

// The refusal reasons the reference words are compared exactly where the corpus carries them (see the verdict and resolution fns).
func TestDkgChannelErrorText(t *testing.T) {
	e := dkgErrPeer("timeout", 3, "no echo message from 3")
	if got := e.Error(); got != "dkg channel (timeout, peer 3): no echo message from 3" {
		t.Fatal(got)
	}
	var ce *DkgChannelError
	if !errors.As(error(dkgErr("closed", "x")), &ce) || ce.HasPeer || strings.Contains(ce.Error(), "peer") {
		t.Fatal("a refusal without a peer names none")
	}
}
