package pca

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The agent-side signers' own refusals and suite paths: a body that does not normalize, a member nested past the depth
// limit once wrapped in the signed message, a suite without its key, and the exact bytes each signer signs. Keys are the
// producer-vector keys; the post-quantum half is a fixed stand-in signer so every signature is byte-exact.

const smkBadUTF8 = "canonicalize: invalid UTF-8"

func smkFakePq() *PqKeyPair {
	return &PqKeyPair{prim: pqMlDsa65, Public: "cHEtcGs", sign: func([]byte) ([]byte, error) { return []byte("pq-sig"), nil }}
}

func smkHybrid() *SuiteOpts { return &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: smkFakePq()} }

// smkNest is k objects nested in one another.
func smkNest(k int) map[string]any {
	if k == 1 {
		return map[string]any{}
	}
	return map[string]any{"x": smkNest(k - 1)}
}

func smkB64(s string) string { return b64.EncodeToString([]byte(s)) }

func TestSignersShareMessageTagsEveryRegisteredSuite(t *testing.T) {
	doc := sreDoc(t)
	set := sreCaseArgs(t, doc, "threshold-share-guardian")["signer_set"].([]any)
	m := []byte("m")
	plain, err := ShareMessage("guardian", m, set, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	ssh, _ := SignerSetHash(set)
	h := sha256.Sum256(m)
	want := append(append(append([]byte("atlas-pca/share/guardian\x00"), h[:]...), ssh...), 2)
	if !bytes.Equal(plain, want) {
		t.Fatalf("share message %q", plain)
	}
	// ed25519 and an unknown name add nothing; every registered non-ed25519 suite (one this package cannot sign too) is tagged
	for _, alg := range []string{"ed25519", "rot13"} {
		if got, err := ShareMessage("guardian", m, set, 2, alg); err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%s: %q %v", alg, got, err)
		}
	}
	for _, alg := range []string{"ml-dsa-65", "fn-dsa-512"} {
		got, err := ShareMessage("guardian", m, set, 2, alg)
		if err != nil || !bytes.Equal(got, append(append([]byte{}, plain...), "\x00atlas-pca/share-suite/v1\x00"+alg...)) {
			t.Errorf("%s: %q %v", alg, got, err)
		}
	}
	_, err = ShareMessage("guardian", m, []any{"\xff"}, 2, "")
	sreErr(t, "signer set that does not normalize", err, smkBadUTF8)
	_, err = ShareMessage("guardian", m, []any{"x"}, 2, "")
	sreErr(t, "signer set of a string", err, "ShareMessage: malformed signer set")
	s, err := SignThresholdShare("guardian", sreKey(t, doc, "guardian"), m, set, 0, nil)
	sreErr(t, "share for t 0", err, "ShareMessage: t must be 1, 2 or 3")
	if s != nil {
		t.Errorf("share for t 0: %v", s)
	}
}

func TestSignersPreparedShareUnderASuite(t *testing.T) {
	k := sreKey(t, sreDoc(t), "guardian")
	prepared := []byte("prepared share")
	edSig := b64.EncodeToString(k.Sign(prepared))
	for _, c := range []struct {
		s    *SuiteOpts
		want map[string]any
	}{
		{nil, map[string]any{"role": "guardian", "publicKey": k.Public, "sig": edSig}},
		{smkHybrid(), map[string]any{"role": "guardian", "publicKey": k.Public, "sig": edSig, "alg": "hybrid-ed25519-ml-dsa-65", "pq_sig": smkB64("pq-sig")}},
		// a pure ML-DSA share names the identity, carries the PQ signature as sig and no pq_sig
		{&SuiteOpts{Alg: "ml-dsa-65", Pq: smkFakePq()}, map[string]any{"role": "guardian", "publicKey": k.Public, "sig": smkB64("pq-sig"), "alg": "ml-dsa-65"}},
	} {
		got, err := SignPreparedShare("guardian", k, prepared, c.s)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v %v", c.s.alg(), got, err)
		}
	}
	_, err := SignPreparedShare("guardian", nil, prepared, nil)
	sreErr(t, "share without a key", err, "SignPreparedShare: a share needs the role's Ed25519 key")
}

func TestSignersPqBindingSignsTheDecimalEpoch(t *testing.T) {
	k := sreKey(t, sreDoc(t), "agent")
	for _, c := range []struct {
		epoch int64
		text  string
	}{{10, "10"}, {255, "255"}} {
		b, err := SignPqBinding(k, "PQ", c.epoch, "ins_1")
		if err != nil {
			t.Fatal(err)
		}
		msg := "atlas-pca/pq-binding/v2\x00" + k.Public + "\x00PQ\x00" + c.text + "\x00ins_1"
		if b["sig"] != b64.EncodeToString(k.Sign([]byte(msg))) || b["epoch"] != c.epoch {
			t.Errorf("epoch %d: %v", c.epoch, b)
		}
	}
}

func TestSignersRefuseABodyThatDoesNotNormalize(t *testing.T) {
	doc := sreDoc(t)
	k := sreKey(t, doc, "agent")
	bad := map[string]any{"x": "\xff"}
	check := func(name string, out map[string]any, err error) {
		t.Helper()
		sreErr(t, name, err, smkBadUTF8)
		if out != nil {
			t.Errorf("%s: %v", name, out)
		}
	}
	out, err := SignCaution(k, bad)
	check("caution", out, err)
	out, err = SignHeartbeat(k, bad)
	check("heartbeat", out, err)
	out, err = SignSessionRoot(k, bad, nil)
	check("session root", out, err)
	out, err = SignActionSchema(bad, "site-k1", k, nil)
	check("action schema", out, err)
	out, err = SignIntentRequired(bad, "site-k1", k, nil)
	check("intent required", out, err)
	out, err = SignTemplate(bad, k)
	check("template", out, err)
	out, err = SignTighten(bad, k)
	check("tighten", out, err)
	out, err = SignProgressStep(bad, k)
	check("progress step", out, err)
}

// a member 31 objects deep normalizes, but is one level too deep inside the signed {d, b} message
func TestSignersRefuseAMemberTooDeepForTheSignedMessage(t *testing.T) {
	doc := sreDoc(t)
	k := sreKey(t, doc, "agent")
	hb, err := SignHeartbeat(k, map[string]any{"cap_id": smkNest(31), "seq": 1, "at": 2, "holder": k.Public, "lease_issued_at": 1})
	sreErr(t, "heartbeat", err, "canonicalize: nesting too deep")
	if hb != nil {
		t.Errorf("heartbeat: %v", hb)
	}
	step := sreCaseArgs(t, doc, "progress-step")["step"].(map[string]any)
	step["goal_commitment"] = smkNest(31)
	ps, err := SignProgressStep(step, k)
	sreErr(t, "progress step", err, "canonicalize: nesting too deep")
	if ps != nil {
		t.Errorf("progress step: %v", ps)
	}
}

func TestSignersReadReceiptRefusals(t *testing.T) {
	doc := sreDoc(t)
	rs := sreKey(t, doc, "rs")
	grant := map[string]any{"v": 1, "id": "rg-1"}
	sign := func(g, fields, prev map[string]any) (map[string]any, error) {
		return SignReadReceipt(rs, g, "read", "customers/7", "support", fields, []string{"pii"}, 1800000000000, prev)
	}
	for _, c := range []struct {
		name            string
		g, fields, prev map[string]any
		want            string
	}{
		{"grant", map[string]any{"x": "\xff"}, map[string]any{}, nil, smkBadUTF8},
		{"previous receipt", grant, map[string]any{}, map[string]any{"x": "\xff"}, smkBadUTF8},
		{"previous seq", grant, map[string]any{}, map[string]any{"seq": "x"}, "SignReadReceipt: malformed previous receipt"},
		{"fields", grant, map[string]any{"x": "\xff"}, nil, smkBadUTF8},
	} {
		r, err := sign(c.g, c.fields, c.prev)
		sreErr(t, c.name, err, c.want)
		if r != nil {
			t.Errorf("%s: %v", c.name, r)
		}
	}
	signBodyFault = func(d string) error {
		if d == k5ReadReceiptDomain {
			return errors.New("read receipt fault")
		}
		return nil
	}
	r, err := sign(grant, map[string]any{}, nil)
	signBodyFault = nil
	sreErr(t, "signing fault", err, "read receipt fault")
	if r != nil {
		t.Errorf("signing fault: %v", r)
	}
}

func TestSignersMeshActionRefusals(t *testing.T) {
	k := sreKey(t, sreDoc(t), "agent")
	chain := []map[string]any{{"id": "c0"}}
	action := map[string]any{"verb": "read"}
	for _, c := range []struct {
		name   string
		chain  []map[string]any
		action map[string]any
		want   string
	}{
		{"empty chain", nil, action, "SignMeshAction: empty chain"},
		{"tip", []map[string]any{{"x": "\xff"}}, action, smkBadUTF8},
		{"action", chain, map[string]any{"x": "\xff"}, smkBadUTF8},
		// 32 objects deep normalizes, but not under the signed {action, tip}
		{"deep action", chain, smkNest(32), "SignMeshAction: the action is not canonicalizable"},
	} {
		s, err := SignMeshAction(c.chain, c.action, k)
		sreErr(t, c.name, err, c.want)
		if s != "" {
			t.Errorf("%s: %q", c.name, s)
		}
	}
}

func TestSignersMeshProofEvidence(t *testing.T) {
	k := sreKey(t, sreDoc(t), "agent")
	chain := []map[string]any{{"id": "c0"}}
	action := map[string]any{"verb": "read", "resource": "r"}
	const sig = "MmEtoeXSTO-qty4DQVdxGTad6bQMeGEve9Qbd3ocCZo6oC0pGMHRePj_iKXUL-P9a8uxj8rdkQVKd9nT8lREDg" // the reference's, over action and chain
	hop := func(cosigs string) string {
		return `{"domain":"d","head":{"head":1,"sig":"s","cosigs":` + cosigs + `},"inclusion":{},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}`
	}
	assemble := func(hops ...string) (map[string]any, error) {
		return AssembleMeshProof(chain, sreObjs(sreJSON(t, "["+strings.Join(hops, ",")+"]")), action, k, nil)
	}
	proof := func(heads, hops string) string {
		return sreCanon(t, sreJSON(t, `{"chain":[{"id":"c0"}],"heads":`+heads+`,"rev_leaves":[],"hops":`+hops+
			`,"action":{"verb":"read","resource":"r"},"action_sig":"`+sig+`"}`))
	}
	hopOut := `{"domain":"d","head":0,"inclusion":{},"revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}`
	two := "[" + hopOut + "," + hopOut + "]"
	for _, c := range []struct {
		name   string
		hops   []string
		cosigs string // the merged head's cosignatures
	}{
		// the reference's Set of witnesses: a non-object cosignature and one without a witness both read as undefined
		{"non-object then witness-less", []string{hop(`["junk"]`), hop(`[{"sig":"z"},5]`)}, `["junk"]`},
		{"witness-less after a witness", []string{hop(`[{"witness":"w1"}]`), hop(`[5,{"sig":"z"},{"witness":"w1","sig":"q"}]`)}, `[{"witness":"w1"},5,{"sig":"z"}]`},
		{"distinct object witnesses", []string{hop(`[{"witness":{"k":1}}]`), hop(`[{"witness":{"k":2}}]`)}, `[{"witness":{"k":1}},{"witness":{"k":2}}]`},
		{"null witness", []string{hop(`[{"witness":"w1"}]`), hop(`[{"witness":null},{"witness":null}]`)}, `[{"witness":"w1"},{"witness":null},{"witness":null}]`},
	} {
		p, err := assemble(c.hops...)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if g, w := sreCanon(t, p), proof(`[{"head":1,"sig":"s","cosigs":`+c.cosigs+`}]`, two); g != w {
			t.Errorf("%s\n got  %s\n want %s", c.name, g, w)
		}
	}
	// a null cosignature is copied on first sight, and refused once a later hop merges into its head (the reference throws)
	p, err := assemble(hop(`[null]`))
	if g, w := sreCanon(t, p), proof(`[{"head":1,"sig":"s","cosigs":[null]}]`, "["+hopOut+"]"); err != nil || g != w {
		t.Errorf("null cosignature first: %v\n got  %s\n want %s", err, g, w)
	}
	// a revocation side without size or bracketing leaves is empty
	p, err = assemble(`{"domain":"d","head":{"head":1,"sig":"s","cosigs":[]},"inclusion":{},"revocation":{"cap":{},"issuer_key":5},"binding":""}`)
	if g, w := sreCanon(t, p), proof(`[{"head":1,"sig":"s","cosigs":[]}]`, `[{"domain":"d","head":0,"inclusion":{},"revocation":{"cap":{},"issuer_key":{}}}]`); err != nil || g != w {
		t.Errorf("bare evidence: %v\n got  %s\n want %s", err, g, w)
	}
	for _, c := range []struct {
		name string
		hops []string
		want string
	}{
		{"null cosignature merged", []string{hop(`[]`), hop(`[null]`)}, "AssembleMeshProof: a cosignature is null"},
		{"null cosignature merged into", []string{hop(`[null]`), hop(`[]`)}, "AssembleMeshProof: a cosignature is null"},
		{"no head", []string{`{"domain":"d","revocation":{"cap":{"size":1},"issuer_key":{"size":1}}}`}, "AssembleMeshProof: hop evidence needs a cosigned head"},
		{"no revocation", []string{`{"domain":"d","head":{"head":1,"sig":"s","cosigs":[]}}`}, "AssembleMeshProof: hop evidence needs its revocation bracketing"},
		{"null cap", []string{`{"domain":"d","head":{"head":1,"sig":"s","cosigs":[]},"revocation":{"cap":null,"issuer_key":{"size":1}}}`}, "AssembleMeshProof: hop evidence needs its revocation bracketing"},
		{"no issuer_key", []string{`{"domain":"d","head":{"head":1,"sig":"s","cosigs":[]},"revocation":{"cap":{"size":1}}}`}, "AssembleMeshProof: hop evidence needs its revocation bracketing"},
	} {
		p, err := assemble(c.hops...)
		sreErr(t, c.name, err, c.want)
		if p != nil {
			t.Errorf("%s: %v", c.name, p)
		}
	}
	p, err = AssembleMeshProof(chain, []map[string]any{{"x": "\xff"}}, action, k, nil)
	sreErr(t, "hop that does not normalize", err, smkBadUTF8)
	if p != nil {
		t.Errorf("hop that does not normalize: %v", p)
	}
	p, err = AssembleMeshProof(nil, sreObjs(sreJSON(t, "["+hop(`[]`)+"]")), action, k, nil)
	sreErr(t, "empty chain", err, "SignMeshAction: empty chain")
	if p != nil {
		t.Errorf("empty chain: %v", p)
	}
}

func TestSignersSessionRootAndGrantRefusals(t *testing.T) {
	doc := sreDoc(t)
	principal := sreKey(t, doc, "principal")
	body := sreCaseArgs(t, doc, "session-root")["body"].(map[string]any)
	r, err := SignSessionRoot(principal, body, &SuiteOpts{Alg: "ml-dsa-65"})
	sreErr(t, "session root without its PQ key", err, "ml-dsa-65 needs a post-quantum key pair")
	if r != nil {
		t.Errorf("session root without its PQ key: %v", r)
	}

	a := sreCaseArgs(t, doc, "session-grant-g0")
	in := func() SessionGrantInput {
		return SessionGrantInput{Principal: principal, Holder: sreKey(t, doc, "agent").Public, Session: a["session"].(string), Root: a["root"].(string),
			MapDigest: a["map_digest"].(string), Predicates: a["predicates"].([]any), Salt: a["salt"].(string)}
	}
	for _, c := range []struct {
		name string
		edit func(*SessionGrantInput)
		want string
	}{
		{"session", func(g *SessionGrantInput) { g.Session = "\xff" }, smkBadUTF8},
		{"delta without prev", func(g *SessionGrantInput) { g.Seq = 1 }, "MintSessionGrant: intent_session caveat: prev is present exactly when seq > 0"},
		{"map digest", func(g *SessionGrantInput) { g.MapDigest = "AA" }, "MintSessionGrant: mapDigest must be canonical base64url (32 bytes)"},
		{"salt", func(g *SessionGrantInput) { g.Salt = "\xed\xa0\x80" }, "canonicalize: lone surrogate in string"},
		{"predicates", func(g *SessionGrantInput) { g.Predicates = []any{"\xff"} }, smkBadUTF8},
		{"suite", func(g *SessionGrantInput) { g.Suite = &SuiteOpts{Alg: "ml-dsa-65"} }, "ml-dsa-65 needs a post-quantum key pair"},
	} {
		g := in()
		c.edit(&g)
		grant, salt, err := MintSessionGrant(g)
		sreErr(t, c.name, err, c.want)
		if grant != nil || salt != "" {
			t.Errorf("%s: %v %q", c.name, grant, salt)
		}
	}
}

func TestSignersActionSchemaSuitesAndSignedShape(t *testing.T) {
	doc := sreDoc(t)
	site := sreKey(t, doc, "site")
	schema := func() map[string]any { return sreCaseArgs(t, doc, "action-schema")["doc"].(map[string]any) }
	cb, _ := canonBytes(sreClone(t, schema()))
	edValue := b64.EncodeToString(site.Sign(append([]byte(actionSchemaDomain), cb...)))
	d, err := SignActionSchema(schema(), "site-k1", site, smkHybrid())
	if err != nil || !reflect.DeepEqual(d["sig"], map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "kid": "site-k1", "value": edValue, "pq_value": smkB64("pq-sig")}) {
		t.Errorf("hybrid schema: %v %v", d["sig"], err)
	}
	d, err = SignActionSchema(schema(), "site-k1", site, nil)
	if err != nil || !reflect.DeepEqual(d["sig"], map[string]any{"alg": "ed25519", "kid": "site-k1", "value": edValue}) {
		t.Errorf("ed25519 schema: %v %v", d["sig"], err)
	}
	// the signed document passes the verifier's shape check: a kid it refuses is refused here
	for _, kid := range []string{"", strings.Repeat("k", 129)} {
		d, err := SignActionSchema(schema(), kid, site, nil)
		sreErr(t, "kid "+kid, err, "signActionSchema: sig.kid must be a non-empty string")
		if d != nil {
			t.Errorf("kid %q: %v", kid, d)
		}
	}
	if d, err := SignActionSchema(schema(), strings.Repeat("k", 128), site, nil); err != nil || d["sig"].(map[string]any)["kid"] != strings.Repeat("k", 128) {
		t.Errorf("kid of 128: %v", err)
	}
	for _, c := range []struct {
		s    *SuiteOpts
		want string
	}{
		{&SuiteOpts{Alg: "rot13"}, `SignActionSchema: unknown signature alg "rot13"`},
		{&SuiteOpts{Alg: "ml-dsa-65"}, "ml-dsa-65 needs a matching post-quantum key pair"},
	} {
		d, err := SignActionSchema(schema(), "site-k1", site, c.s)
		sreErr(t, c.s.Alg, err, c.want)
		if d != nil {
			t.Errorf("%s: %v", c.s.Alg, d)
		}
	}
}

func TestSignersIntentRequiredSuitesAndBounds(t *testing.T) {
	doc := sreDoc(t)
	site := sreKey(t, doc, "site")
	body := func() map[string]any { return sreCaseArgs(t, doc, "intent-required")["body"].(map[string]any) }
	cb, _ := canonBytes(sreClone(t, body()))
	edValue := b64.EncodeToString(site.Sign(append([]byte("atlas-pca/intent-required/v1\x00"), cb...)))
	d, err := SignIntentRequired(body(), "site-k1", site, smkHybrid())
	if err != nil || !reflect.DeepEqual(d["sig"], map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "kid": "site-k1", "value": edValue, "pq_value": smkB64("pq-sig")}) {
		t.Errorf("hybrid question: %v %v", d["sig"], err)
	}
	d, err = SignIntentRequired(body(), "site-k1", site, nil)
	if err != nil || !reflect.DeepEqual(d["sig"], map[string]any{"alg": "ed25519", "kid": "site-k1", "value": edValue}) {
		t.Errorf("ed25519 question: %v %v", d["sig"], err)
	}
	for _, c := range []struct {
		s    *SuiteOpts
		want string
	}{
		{&SuiteOpts{Alg: "rot13"}, `SignIntentRequired: unknown signature alg "rot13"`},
		{&SuiteOpts{Alg: "ml-dsa-65"}, "ml-dsa-65 needs a matching post-quantum key pair"},
	} {
		d, err := SignIntentRequired(body(), "site-k1", site, c.s)
		sreErr(t, c.s.Alg, err, c.want)
		if d != nil {
			t.Errorf("%s: %v", c.s.Alg, d)
		}
	}

	if e := IntentRequiredShapeError("x"); e != "not an object" {
		t.Errorf("a string body: %q", e)
	}
	// the reference's isInt: a safe integer, never -0
	const expErr = "expires_at must be a non-negative safe integer"
	for _, c := range []struct {
		v    any
		want string
	}{
		{jsonNumberOf(maxSafeInt), ""}, {jsonNumberOf(0), ""}, {jsonNumberOf(-1), expErr}, {jsonNumberOf(maxSafeInt + 1), expErr},
		{json.Number("-0"), expErr}, {"5", expErr},
	} {
		b := body()
		b["expires_at"] = c.v
		if e := IntentRequiredShapeError(b); e != c.want {
			t.Errorf("expires_at %v: %q", c.v, e)
		}
	}
	emoji := "\U0001F600" // two UTF-16 units: a path's length is counted in them
	const pathErr = "a coordinate path must be 1..256 characters"
	for _, c := range []struct {
		coords map[string]any
		want   string
	}{
		{map[string]any{"a": []any{jsonNumberOf(-maxSafeInt), jsonNumberOf(0)}}, "coords 'a': need 0 <= lo <= hi"},
		{map[string]any{"a": []any{jsonNumberOf(-maxSafeInt - 1), jsonNumberOf(0)}}, "coords 'a': an index range [lo, hi] or a value set"},
		{map[string]any{"a": []any{jsonNumberOf(maxSafeInt), jsonNumberOf(maxSafeInt)}}, ""},
		{map[string]any{"": []any{"x"}}, pathErr},
		{map[string]any{"b": []any{"x"}}, ""},
		{map[string]any{strings.Repeat(emoji, 128): []any{"x"}}, ""},
		{map[string]any{strings.Repeat(emoji, 128) + "b": []any{"x"}}, pathErr},
	} {
		b := body()
		b["cell"] = map[string]any{"verb": "refund", "coords": c.coords}
		if e := IntentRequiredShapeError(b); e != c.want {
			t.Errorf("coords %v: %q", c.coords, e)
		}
	}
}
