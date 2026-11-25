package pca

import (
	"errors"
	"math"
)

// Replay of the FROST distributed key generation against the reference, every case: ref-frost-dkg (439, committed) and
// ref-frost-dkg-gen (286, the cases that carry derived secrets; CI generates it). Typed-gap convention: an argument the typed Go API
// cannot hold (a fractional or string identifier, a share that is no byte string, a malformed package given to a function that never
// refuses) is mapped here to the refusal or the false the reference gives for it, and such a case is still replayed and compared.

func dkgNum(i int64) any { return jsNumber(float64(i)) }

// dkgInt reads an integer argument; ok is false for anything else (a string, a fraction, null, a value beyond the safe range).
func dkgInt(v any) (int64, bool) {
	f, ok := jsNum(v)
	if !ok || f != math.Trunc(f) || math.Abs(f) > frostMaxSafeInt {
		return 0, false
	}
	return int64(f), true
}

func dkgStr(v any) (string, bool) { s, ok := v.(string); return s, ok }

func dkgPkgIn(v any) (DkgRound1Package, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return DkgRound1Package{}, false
	}
	var p DkgRound1Package
	p.Identifier, _ = dkgInt(m["identifier"]) // the identifier of a package is not read by the verifiers: the caller's is used
	if p.SessionID, ok = dkgStr(m["sessionId"]); !ok {
		return p, false
	}
	l, ok := m["coefficientCommitments"].([]any)
	if !ok {
		return p, false
	}
	p.CoefficientCommitments = []string{}
	for _, c := range l {
		s, ok := dkgStr(c)
		if !ok {
			return p, false
		}
		p.CoefficientCommitments = append(p.CoefficientCommitments, s)
	}
	pk, ok := m["proofOfKnowledge"].(map[string]any)
	if !ok {
		return p, false
	}
	if p.ProofOfKnowledge.R, ok = dkgStr(pk["R"]); !ok {
		return p, false
	}
	p.ProofOfKnowledge.Mu, ok = dkgStr(pk["mu"])
	return p, ok
}

func dkgPkgsIn(v any) ([]DkgRound1Package, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []DkgRound1Package{}
	for _, x := range l {
		p, ok := dkgPkgIn(x)
		if !ok {
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

// dkgPkgsLoose reads only the identifier and the session of each package (what the share derivation uses).
func dkgPkgsLoose(v any) ([]DkgRound1Package, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []DkgRound1Package{}
	for _, x := range l {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		id, ok1 := dkgInt(m["identifier"])
		sid, ok2 := dkgStr(m["sessionId"])
		if !ok1 || !ok2 {
			return nil, false
		}
		out = append(out, DkgRound1Package{Identifier: id, SessionID: sid})
	}
	return out, true
}

func dkgPkgOut(p DkgRound1Package) map[string]any {
	cc := []any{}
	for _, c := range p.CoefficientCommitments {
		cc = append(cc, c)
	}
	return map[string]any{"identifier": dkgNum(p.Identifier), "sessionId": p.SessionID, "coefficientCommitments": cc,
		"proofOfKnowledge": map[string]any{"R": p.ProofOfKnowledge.R, "mu": p.ProofOfKnowledge.Mu}}
}

func dkgComplaintIn(v any) (DkgComplaint, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return DkgComplaint{}, false
	}
	var c DkgComplaint
	var a, b, d, e bool
	c.Accused, a = dkgInt(m["accused"])
	c.Accuser, b = dkgInt(m["accuser"])
	c.SessionID, d = dkgStr(m["sessionId"])
	c.RevealedShare, e = dkgStr(m["revealedShare"])
	var f bool
	c.ShareSig, f = dkgStr(m["shareSig"])
	return c, a && b && d && e && f
}

func dkgComplaintOut(c DkgComplaint) map[string]any {
	return map[string]any{"accused": dkgNum(c.Accused), "accuser": dkgNum(c.Accuser), "sessionId": c.SessionID, "revealedShare": c.RevealedShare, "shareSig": c.ShareSig}
}

func dkgRebuttalIn(v any) (DkgRebuttal, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return DkgRebuttal{}, false
	}
	var r DkgRebuttal
	var a, b, d, e, f bool
	r.Accused, a = dkgInt(m["accused"])
	r.Accuser, b = dkgInt(m["accuser"])
	r.SessionID, d = dkgStr(m["sessionId"])
	r.PresentedShare, e = dkgStr(m["presentedShare"])
	r.ShareSig, f = dkgStr(m["shareSig"])
	return r, a && b && d && e && f
}

func dkgRebuttalOut(r DkgRebuttal) map[string]any {
	return map[string]any{"accused": dkgNum(r.Accused), "accuser": dkgNum(r.Accuser), "sessionId": r.SessionID, "presentedShare": r.PresentedShare, "shareSig": r.ShareSig}
}

func dkgEchoIn(v any) (DkgEcho, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return DkgEcho{}, false
	}
	var e DkgEcho
	var a, b, c bool
	e.Identifier, a = dkgInt(m["identifier"])
	e.SessionID, b = dkgStr(m["sessionId"])
	e.TranscriptDigest, c = dkgStr(m["transcriptDigest"])
	return e, a && b && c
}

func dkgEchoOut(e DkgEcho) map[string]any {
	return map[string]any{"identifier": dkgNum(e.Identifier), "sessionId": e.SessionID, "transcriptDigest": e.TranscriptDigest}
}

func dkgIDs(v any) ([]int64, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []int64{}
	for _, x := range l {
		id, ok := dkgInt(x)
		if !ok {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

func dkgIDsOut(ids []int64) []any {
	out := []any{}
	for _, i := range ids {
		out = append(out, dkgNum(i))
	}
	return out
}

func dkgBytesOutList(l [][]byte) []any {
	out := []any{}
	for _, b := range l {
		out = append(out, vecBytesOut(b))
	}
	return out
}

func dkgKeyPackageOut(k DkgKeyPackage) map[string]any {
	vs := []any{}
	for _, v := range k.PublicKeyPackage.VerifyingShares {
		vs = append(vs, map[string]any{"identifier": dkgNum(v.Identifier), "publicKey": vecBytesOut(v.PublicKey)})
	}
	return map[string]any{"identifier": dkgNum(k.Identifier), "signingShare": vecBytesOut(k.SigningShare), "groupPublicKey": vecBytesOut(k.GroupPublicKey),
		"verifyingShare": vecBytesOut(k.VerifyingShare), "publicKeyPackage": map[string]any{"groupPublicKey": vecBytesOut(k.PublicKeyPackage.GroupPublicKey),
			"groupCommitment": dkgBytesOutList(k.PublicKeyPackage.GroupCommitment), "verifyingShares": vs}}
}

func dkgShareOut(s DkgShareToSend) map[string]any {
	return map[string]any{"from": dkgNum(s.From), "to": dkgNum(s.To), "sessionId": s.SessionID, "share": vecBytesOut(s.Share), "sig": s.Sig}
}

// dkgByteList reads a list of byte strings; ok is false for anything else.
func dkgByteList(v any) ([][]byte, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := [][]byte{}
	for _, x := range l {
		b, ok := x.([]byte)
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}

var errDkgTypedGap = errors.New("an argument the reference refuses for its type")

// dkgSpecState rebuilds a participant state from its spec {id, t, n, sessionId, coefficients, popNonce}.
func dkgSpecState(v any) (*DkgParticipantState, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errDkgTypedGap
	}
	id, a := dkgInt(m["id"])
	t, b := dkgInt(m["t"])
	n, c := dkgInt(m["n"])
	if !a || !b || !c {
		return nil, errDkgTypedGap
	}
	var o DkgRound1Opts
	if l, has := dkgByteList(m["coefficients"]); has {
		o.Coefficients = l
	}
	if nonce, has := m["popNonce"].([]byte); has {
		o.PopNonce = nonce
	}
	r, err := DkgRound1(id, int(t), int(n), frostBytes(m["sessionId"]), o)
	if err != nil {
		return nil, err
	}
	return r.State, nil
}

func dkgComplaintsIn(v any) ([]DkgComplaint, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []DkgComplaint{}
	for _, x := range l {
		c, ok := dkgComplaintIn(x)
		if !ok {
			return nil, false
		}
		out = append(out, c)
	}
	return out, true
}

func dkgEchoesIn(v any) ([]DkgEcho, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []DkgEcho{}
	for _, x := range l {
		e, ok := dkgEchoIn(x)
		if !ok {
			return nil, false
		}
		out = append(out, e)
	}
	return out, true
}

// dkgSigAsString is the argument with a shareSig member that is no string read as the empty signature (which never verifies).
func dkgSigAsString(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if _, isStr := m["shareSig"].(string); isStr {
		return v
	}
	if _, has := m["shareSig"]; !has {
		return v
	}
	cp := make(map[string]any, len(m))
	for k, x := range m {
		cp[k] = x
	}
	cp["shareSig"] = ""
	return cp
}

func dkgOnlyBytes(v any) []byte { b, _ := v.([]byte); return b }

func dkgCoreFns() map[string]vecFn {
	return map[string]vecFn{
		"constants": frostCall(func(a []any) (any, error) {
			k := []any{}
			for _, x := range DkgMessageKinds {
				k = append(k, x)
			}
			return map[string]any{"DKG_WIRE_VERSION": dkgNum(DkgWireVersion), "DKG_MAX_MESSAGE_BYTES": dkgNum(DkgMaxMessageBytes), "DKG_MAX_PARTICIPANTS": dkgNum(DkgMaxParticipants), "DKG_MESSAGE_KINDS": k}, nil
		}),
		"dkgRound1": frostCall(func(a []any) (any, error) {
			id, ok1 := dkgInt(vecArg(a, 0))
			t, ok2 := dkgInt(vecArg(a, 1))
			n, ok3 := dkgInt(vecArg(a, 2))
			if !ok1 || !ok2 || !ok3 || t < 0 || t > 1<<20 || n < 0 || n > 1<<20 {
				return nil, errDkgTypedGap
			}
			var o DkgRound1Opts
			if m, ok := vecArg(a, 4).(map[string]any); ok {
				if l, has := m["coefficients"]; has {
					cs, ok := dkgByteList(l)
					if !ok {
						return nil, errDkgTypedGap
					}
					o.Coefficients = cs
				}
				if nonce, has := m["popNonce"]; has {
					b, ok := nonce.([]byte)
					if !ok {
						return nil, errDkgTypedGap
					}
					o.PopNonce = b
				}
			}
			r, err := DkgRound1(id, int(t), int(n), dkgOnlyBytes(vecArg(a, 3)), o)
			if err != nil {
				return nil, err
			}
			return map[string]any{"package": dkgPkgOut(r.Package)}, nil
		}),
		"dkgVerifyRound1": frostCall(func(a []any) (any, error) {
			from, ok1 := dkgInt(vecArg(a, 0))
			pkg, ok2 := dkgPkgIn(vecArg(a, 1))
			sid, ok3 := vecArg(a, 2).([]byte)
			return ok1 && ok2 && ok3 && DkgVerifyRound1(from, pkg, sid), nil
		}),
		"dkgSignShare": frostCall(func(a []any) (any, error) {
			st, err := dkgSpecState(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			to, ok1 := dkgInt(vecArg(a, 1))
			share, ok2 := vecArg(a, 2).([]byte)
			if !ok1 || !ok2 {
				return nil, errDkgTypedGap
			}
			return DkgSignShare(st, to, share)
		}),
		"dkgRound2": frostCall(func(a []any) (any, error) {
			st, err := dkgSpecState(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			pkgs, ok := dkgPkgsIn(vecArg(a, 1))
			if !ok { // dkgRound2 reads only each package's identifier and session: the commitments and the proof are not validated
				pkgs, ok = dkgPkgsLoose(vecArg(a, 1))
			}
			if !ok {
				return nil, errDkgTypedGap
			}
			outs, err := DkgRound2(st, pkgs)
			if err != nil {
				return nil, err
			}
			l := []any{}
			for _, s := range outs {
				l = append(l, dkgShareOut(s))
			}
			return l, nil
		}),
		"dkgVerifyShare": frostCall(func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return false, nil
			}
			from, ok1 := dkgInt(m["from"])
			share, ok2 := m["share"].([]byte)
			sig, _ := m["sig"].(string)
			pkg, ok3 := dkgPkgIn(vecArg(a, 1))
			my, ok4 := dkgInt(vecArg(a, 2))
			sid, ok5 := vecArg(a, 3).([]byte)
			if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
				return false, nil
			}
			return DkgVerifyShare(DkgSignedShare{From: from, Share: share, Sig: sig}, pkg, my, sid), nil
		}),
		"dkgFileComplaint": frostCall(func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errDkgTypedGap
			}
			accused, ok1 := dkgInt(m["accused"])
			accuser, ok2 := dkgInt(m["accuser"])
			share, ok3 := m["receivedShare"].([]byte)
			sig, ok4 := m["shareSig"].(string)
			if !ok1 || !ok2 || !ok3 || (!ok4 && m["shareSig"] != nil) {
				return nil, errDkgTypedGap
			}
			c, err := DkgFileComplaint(DkgFileComplaintParams{Accused: accused, Accuser: accuser, ReceivedShare: share, ShareSig: sig, SessionID: dkgOnlyBytes(m["sessionId"])})
			if err != nil {
				return nil, err
			}
			return dkgComplaintOut(c), nil
		}),
		"dkgVerifyComplaint": frostCall(func(a []any) (any, error) {
			c, ok := dkgComplaintIn(vecArg(a, 0))
			pkgs, ok2 := dkgPkgsIn(vecArg(a, 1))
			if !ok || !ok2 {
				return map[string]any{"justified": false, "reason": "malformed complaint"}, nil
			}
			v := DkgVerifyComplaint(c, pkgs)
			out := map[string]any{"justified": v.Justified, "reason": v.Reason}
			if v.Disqualify != nil {
				out["disqualify"] = dkgNum(*v.Disqualify)
			}
			if v.AtFault != nil {
				out["atFault"] = dkgNum(*v.AtFault)
			}
			return out, nil
		}),
		"dkgRebut": frostCall(func(a []any) (any, error) {
			accused, ok1 := dkgInt(vecArg(a, 0))
			c, ok2 := dkgComplaintIn(vecArg(a, 1))
			st, err := dkgSpecState(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			if !ok1 || !ok2 {
				return nil, errDkgTypedGap
			}
			r, err := DkgRebut(accused, c, st)
			if err != nil {
				return nil, err
			}
			return dkgRebuttalOut(r), nil
		}),
		"dkgResolveBlame": frostCall(func(a []any) (any, error) {
			// a signature that is no string cannot verify in the reference (it is a plain false); an empty one cannot either
			c, ok := dkgComplaintIn(dkgSigAsString(vecArg(a, 0)))
			if !ok {
				return nil, errDkgTypedGap
			}
			pkgs, ok2 := dkgPkgsIn(vecArg(a, 2))
			if !ok2 {
				if _, isList := vecArg(a, 2).([]any); !isList { // the reference's find on a non-list throws inside its try: the malformed verdict
					return map[string]any{"guilty": dkgNum(c.Accuser), "reason": "malformed complaint — inadmissible"}, nil
				}
				return nil, errDkgTypedGap
			}
			var reb *DkgRebuttal
			if vecArg(a, 1) != nil {
				r, ok := dkgRebuttalIn(dkgSigAsString(vecArg(a, 1)))
				if !ok {
					return nil, errDkgTypedGap
				}
				reb = &r
			}
			r := DkgResolveBlame(c, reb, pkgs)
			return map[string]any{"guilty": dkgNum(r.Guilty), "reason": r.Reason}, nil
		}),
		"dkgQualifiedSet": frostCall(func(a []any) (any, error) {
			parts, ok := dkgIDs(vecArg(a, 0))
			pkgs, ok2 := dkgPkgsIn(vecArg(a, 2))
			if !ok || !ok2 {
				return nil, errDkgTypedGap
			}
			// a complaint or rebuttal that is not well formed names nobody in the reference (it removes nobody): it is left out
			var complaints []DkgComplaint
			for _, x := range rsList(vecArg(a, 1)) {
				if c, ok := dkgComplaintIn(x); ok {
					complaints = append(complaints, c)
				}
			}
			var rebuttals []DkgRebuttal
			for _, x := range rsList(vecArg(a, 3)) {
				if r, ok := dkgRebuttalIn(x); ok {
					rebuttals = append(rebuttals, r)
				}
			}
			return dkgIDsOut(DkgQualifiedSet(parts, complaints, pkgs, rebuttals)), nil
		}),
		"dkgTranscriptDigest": frostCall(func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errDkgTypedGap
			}
			pkgs, ok1 := dkgPkgsIn(m["round1Packages"])
			cs, ok2 := dkgComplaintsIn(m["complaints"])
			q, ok3 := dkgIDs(m["qualified"])
			if !ok1 || !ok2 || !ok3 {
				return nil, errDkgTypedGap
			}
			return DkgTranscriptDigest(pkgs, cs, q, dkgOnlyBytes(m["sessionId"]))
		}),
		"dkgEcho": frostCall(func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errDkgTypedGap
			}
			pkgs, ok1 := dkgPkgsIn(m["round1Packages"])
			cs, ok2 := dkgComplaintsIn(m["complaints"])
			q, ok3 := dkgIDs(m["qualified"])
			if !ok1 || !ok2 || !ok3 {
				return nil, errDkgTypedGap
			}
			// the identifier is carried through unchecked: an identifier of any type is echoed as given
			e, err := DkgMakeEcho(0, pkgs, cs, q, dkgOnlyBytes(m["sessionId"]))
			if err != nil {
				return nil, err
			}
			out := dkgEchoOut(e)
			out["identifier"] = m["identifier"]
			return out, nil
		}),
		"dkgCheckEchoes": frostCall(func(a []any) (any, error) {
			malformed := map[string]any{"agreed": false, "reason": "malformed echoes"}
			q, ok := dkgIDs(vecArg(a, 0))
			echoes, ok2 := dkgEchoesIn(vecArg(a, 1))
			sid, ok3 := vecArg(a, 2).([]byte)
			if !ok || !ok2 || !ok3 {
				return malformed, nil
			}
			r := DkgCheckEchoes(q, echoes, sid)
			if r.Agreed {
				return map[string]any{"agreed": true, "digest": r.Digest}, nil
			}
			return map[string]any{"agreed": false, "reason": r.Reason}, nil
		}),
		"dkgFinalize": frostCall(func(a []any) (any, error) {
			my, ok := dkgInt(vecArg(a, 0))
			st, err := dkgSpecState(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			var recv []DkgReceivedShare
			for _, x := range rsList(vecArg(a, 2)) {
				m, ok := x.(map[string]any)
				from, ok1 := dkgInt(m["from"])
				sid, ok2 := dkgStr(m["sessionId"])
				share, ok3 := m["share"].([]byte)
				if !ok || !ok1 || !ok2 || !ok3 {
					return nil, errDkgTypedGap
				}
				sig, _ := m["sig"].(string)
				recv = append(recv, DkgReceivedShare{From: from, SessionID: sid, Share: share, Sig: sig})
			}
			pkgs, ok2 := dkgPkgsIn(vecArg(a, 3))
			if !ok || !ok2 {
				return nil, errDkgTypedGap
			}
			var q []int64
			if vecArg(a, 4) != nil {
				if q, ok = dkgIDs(vecArg(a, 4)); !ok {
					return nil, errDkgTypedGap
				}
			}
			var ag *DkgAgreement
			if am, isObj := vecArg(a, 5).(map[string]any); isObj {
				ag = &DkgAgreement{}
				if _, has := am["echoes"]; has {
					if ag.Echoes, ok = dkgEchoesIn(am["echoes"]); !ok {
						return nil, errDkgTypedGap
					}
				}
				if _, has := am["complaints"]; has {
					if ag.Complaints, ok = dkgComplaintsIn(am["complaints"]); !ok {
						return nil, errDkgTypedGap
					}
				}
			}
			kp, err := DkgFinalize(my, st, recv, pkgs, q, ag)
			if err != nil {
				return nil, err
			}
			return dkgKeyPackageOut(*kp), nil
		}),
		"frostDkgSimulate": frostCall(func(a []any) (any, error) {
			t, ok1 := dkgInt(vecArg(a, 0))
			n, ok2 := dkgInt(vecArg(a, 1))
			if !ok1 || !ok2 || t < 0 || n < 0 || t > 1<<20 || n > 1<<20 {
				return nil, errDkgTypedGap
			}
			var o DkgSimulateOpts
			if m, ok := vecArg(a, 2).(map[string]any); ok {
				if l, has := m["identifiers"]; has {
					ids := []int64{}
					for _, x := range rsList(l) {
						id, ok := dkgInt(x)
						if !ok {
							id = 0 // refused by the reference as no positive integer
						}
						ids = append(ids, id)
					}
					o.Identifiers = ids
				}
				if l, has := m["coefficientsByParticipant"]; has {
					for _, x := range rsList(l) {
						cs, ok := dkgByteList(x)
						if !ok {
							return nil, errDkgTypedGap
						}
						o.CoefficientsByParticipant = append(o.CoefficientsByParticipant, cs)
					}
				}
				if sid, has := m["sessionId"].([]byte); has {
					o.SessionID = sid
				}
				if l, has := m["cheaters"]; has {
					o.Cheaters, _ = dkgIDs(l)
				}
				if v, has := m["equivocateEchoFor"]; has {
					o.EquivocateEchoFor, _ = dkgInt(v)
				}
			}
			r, err := FrostDkgSimulate(int(t), int(n), o)
			if err != nil {
				return nil, err
			}
			ps := []any{}
			for _, p := range r.ParticipantShares {
				ps = append(ps, map[string]any{"identifier": dkgNum(p.Identifier), "share": vecBytesOut(p.Share), "publicKey": vecBytesOut(p.PublicKey)})
			}
			kps, r1, cs, rb, es := []any{}, []any{}, []any{}, []any{}, []any{}
			for _, k := range r.KeyPackages {
				kps = append(kps, dkgKeyPackageOut(k))
			}
			for _, p := range r.Round1Packages {
				r1 = append(r1, dkgPkgOut(p))
			}
			for _, c := range r.Complaints {
				cs = append(cs, dkgComplaintOut(c))
			}
			for _, x := range r.Rebuttals {
				rb = append(rb, dkgRebuttalOut(x))
			}
			for _, e := range r.Echoes {
				es = append(es, dkgEchoOut(e))
			}
			return map[string]any{"groupPublicKey": vecBytesOut(r.GroupPublicKey), "participantShares": ps, "groupCommitment": dkgBytesOutList(r.GroupCommitment), "keyPackages": kps,
				"round1Packages": r1, "qualified": dkgIDsOut(r.Qualified), "complaints": cs, "rebuttals": rb, "echoes": es, "sessionId": vecBytesOut(r.SessionID)}, nil
		}),
	}
}
