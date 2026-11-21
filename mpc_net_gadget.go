package pca

// Agreement on the joint choice-bit gadget seeds, and the commit-first forensic disclosure exchange of the no-dealer mode.
//
// Gadget seeds: a signed commit / reveal / echo, so ONE corrupt party cannot make honest parties derive different gadgets and
// then blame each other. Every commitment and opening is signed with the sender's pinned TLS identity key; after the reveal each
// party echoes the signed values it received from each third party. An echoed signature that does not verify is a forgery by the
// echoer; an echoed statement that verifies but differs from the one received directly means the signer signed two values for one
// round (blamed, with both statements as transferable evidence). With n = 2 there is no third party, so the echo is skipped.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

var (
	mpcHexSig = regexp.MustCompile(`^[0-9a-f]{16,200}$`)
	mpcHex256 = mpcHex64
)

// mpcExchange is one un-echoed all-to-all round; an error from parse aborts naming that peer.
type mpcExchange func(rd string, mine func(peer int) any, parse mpcParse, timeout time.Duration) (map[int]any, error)

type mpcSigned struct{ v, s string }

func mpcAsSigned(x any) (mpcSigned, bool) {
	m, ok := x.(map[string]any)
	if !ok {
		return mpcSigned{}, false
	}
	v, ok1 := m["v"].(string)
	s, ok2 := m["s"].(string)
	if !ok1 || !ok2 || !mpcHex256.MatchString(v) || !mpcHexSig.MatchString(s) {
		return mpcSigned{}, false
	}
	return mpcSigned{v, s}, true
}

func (s mpcSigned) wire() map[string]any { return map[string]any{"v": s.v, "s": s.s} }

// mpcAgreeGadgetSeeds returns every party's seed in party order (mine included).
func mpcAgreeGadgetSeeds(mesh *MpcMesh, id, n int, ex mpcExchange, bad func(int, string) error) ([][]byte, error) {
	sid := mesh.SessionID()
	mySeed := make([]byte, 32)
	if _, err := rand.Read(mySeed); err != nil {
		return nil, err
	}
	sign := func(round, value string) (mpcSigned, error) {
		st, err := MpcGadgetStatement(sid, round, id, value)
		if err != nil {
			return mpcSigned{}, err
		}
		sig, err := mesh.Sign(st)
		if err != nil {
			return mpcSigned{}, err
		}
		return mpcSigned{value, hex.EncodeToString(sig)}, nil
	}
	check := func(signer int, round string, m mpcSigned) bool {
		st, err := MpcGadgetStatement(sid, round, signer, m.v)
		sig, err2 := hex.DecodeString(m.s)
		return err == nil && err2 == nil && mesh.Verify(signer, st, sig)
	}
	myCommit := MpcGadgetCommit(sid, id, mySeed)
	sc, err := sign("gd-c", myCommit)
	if err != nil {
		return nil, err
	}
	commits, err := ex("gd-c", func(int) any { return sc.wire() }, func(p int, raw any) (any, error) {
		m, ok := mpcAsSigned(raw)
		if !ok {
			return nil, bad(p, "bad gadget commitment")
		}
		if !check(p, "gd-c", m) {
			return nil, bad(p, "gadget commitment signature does not verify")
		}
		return m, nil
	}, 0)
	if err != nil {
		return nil, err
	}
	so, err := sign("gd-o", hex.EncodeToString(mySeed))
	if err != nil {
		return nil, err
	}
	opens, err := ex("gd-o", func(int) any { return so.wire() }, func(p int, raw any) (any, error) {
		m, ok := mpcAsSigned(raw)
		if !ok {
			return nil, bad(p, "bad gadget seed")
		}
		if !check(p, "gd-o", m) {
			return nil, bad(p, "gadget seed signature does not verify")
		}
		sd, _ := hex.DecodeString(m.v)
		if MpcGadgetCommit(sid, p, sd) != commits[p].(mpcSigned).v {
			return nil, mpcAbortF("commitment", mpcIntP(p), id, fmt.Sprintf("party %d opened a gadget seed that does not match its commitment", p), "")
		}
		return m, nil
	}, 0)
	if err != nil {
		return nil, err
	}
	if n >= 3 {
		var others []int
		for i := 0; i < n; i++ {
			if i != id {
				others = append(others, i)
			}
		}
		without := func(p int) []int {
			var out []int
			for _, j := range others {
				if j != p {
					out = append(out, j)
				}
			}
			return out
		}
		_, err := ex("gd-e", func(peer int) any {
			var out []any
			for _, j := range without(peer) {
				out = append(out, map[string]any{"j": j, "c": commits[j].(mpcSigned).wire(), "o": opens[j].(mpcSigned).wire()})
			}
			return out
		}, func(p int, raw any) (any, error) {
			expect := without(p)
			l, ok := raw.([]any)
			if !ok || len(l) != len(expect) {
				return nil, bad(p, "bad gadget echo")
			}
			for k, j := range expect {
				e, _ := l[k].(map[string]any)
				jf, okj := jsNum(e["j"])
				c, okc := mpcAsSigned(e["c"])
				o, oko := mpcAsSigned(e["o"])
				if e == nil || !okj || jf != float64(j) || !okc || !oko {
					return nil, bad(p, "bad gadget echo entry")
				}
				if !check(j, "gd-c", c) || !check(j, "gd-o", o) {
					return nil, bad(p, fmt.Sprintf("gadget echo carries a statement that party %d did not sign", j))
				}
				mineC, mineO := commits[j].(mpcSigned), opens[j].(mpcSigned)
				if c.v != mineC.v || o.v != mineO.v {
					what, round, pair := "seeds", "gd-o", []any{mineO.wire(), o.wire()}
					if c.v != mineC.v {
						what, round, pair = "commitments", "gd-c", []any{mineC.wire(), c.wire()}
					}
					return nil, NewMpcNetAbort("equivocation", mpcIntP(j), id,
						fmt.Sprintf("party %d signed different gadget %s for different parties (shown by party %d's echo)", j, what, p), nil, nil, nil,
						map[string]any{"signer": j, "round": round, "statements": pair}, nil)
				}
			}
			return true, nil
		}, 0)
		if err != nil {
			return nil, err
		}
	}
	out := make([][]byte, n)
	for p := range out {
		if p == id {
			out[p] = append([]byte(nil), mySeed...)
		} else {
			out[p], _ = hex.DecodeString(opens[p].(mpcSigned).v)
		}
	}
	return out, nil
}

// mpcExchangeDisclosures is the commit-first disclosure exchange: nobody opens before every commitment is in hand, so no party's
// disclosure can depend on another's. It returns every OTHER party's verified disclosure.
func mpcExchangeDisclosures(sessionID string, id, n, tripleIndex int, mine []MpcSlotDisclosure, slots, rows int, deadlineMs int, ex mpcExchange, bad func(int, string) error) (map[int][]MpcSlotDisclosure, error) {
	wire := MpcWireDisclosure(mine)
	nb := make([]byte, 32)
	if _, err := rand.Read(nb); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nb)
	myCommit, err := MpcDisclosureCommit(sessionID, id, tripleIndex, int64(deadlineMs), nonce, wire)
	if err != nil {
		return nil, err
	}
	to := time.Duration(deadlineMs) * time.Millisecond
	commits, err := ex("forensic-c", func(int) any { return map[string]any{"c": myCommit, "d": deadlineMs} }, func(p int, raw any) (any, error) {
		o, _ := raw.(map[string]any)
		c, ok := o["c"].(string)
		if !ok || !mpcHex64.MatchString(c) {
			return nil, bad(p, "bad forensic commitment")
		}
		if d, ok := jsNum(o["d"]); !ok || d != float64(deadlineMs) {
			return nil, bad(p, fmt.Sprintf("forensic deadline differs from the agreed %d", deadlineMs))
		}
		return c, nil
	}, to)
	if err != nil {
		return nil, err
	}
	res, err := ex("forensic-o", func(int) any { return map[string]any{"w": wire, "nonce": nonce} }, func(p int, raw any) (any, error) {
		o, _ := raw.(map[string]any)
		nn, ok := o["nonce"].(string)
		if !ok || !mpcHex64.MatchString(nn) {
			return nil, bad(p, "bad forensic opening")
		}
		c, err := MpcDisclosureCommit(sessionID, p, tripleIndex, int64(deadlineMs), nn, o["w"])
		if err != nil || c != commits[p].(string) {
			return nil, mpcAbortF("commitment", mpcIntP(p), id, fmt.Sprintf("party %d opened a forensic disclosure that does not match its commitment", p), "")
		}
		var peers []int
		for q := 0; q < n; q++ {
			if q != p {
				peers = append(peers, q)
			}
		}
		return MpcParseDisclosure(o["w"], slots, rows, peers)
	}, to)
	if err != nil {
		return nil, err
	}
	out := map[int][]MpcSlotDisclosure{}
	for p, v := range res {
		out[p] = v.([]MpcSlotDisclosure)
	}
	return out, nil
}
