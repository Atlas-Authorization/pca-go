package pca

import (
	"bytes"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

// R5 N5: attest_intel_collateral.go, attest_maa.go, provenance_gate.go, a2a.go, escalation.go, ed25519strict.go survivors.

func TestR5N5IntelSmallHelpers(t *testing.T) {
	if s, ok := asTcbStatus(tcbStatusOrder[2]); !ok || s != tcbStatusOrder[2] {
		t.Errorf("known status: %q %v", s, ok)
	}
	if s, ok := asTcbStatus("nonsense"); ok || s != "" {
		t.Errorf("unknown status: %q %v", s, ok)
	}
	if s, ok := asTcbStatus(5); ok || s != "" {
		t.Errorf("non-string status: %q %v", s, ok)
	}
	if got := advisoryList(map[string]any{"advisoryIDs": []any{"A", 5, "B"}}); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Errorf("advisoryList: %q", got)
	}
	if got := advisoryList(map[string]any{"advisoryIDs": "A"}); got != nil {
		t.Errorf("advisoryList of a string: %q", got)
	}
	if b, ok := hexDecodeLoose("0aFf"); !ok || !bytes.Equal(b, []byte{0x0a, 0xff}) {
		t.Errorf("hexDecodeLoose: %x %v", b, ok)
	}
	if b, ok := hexDecodeLoose("0g"); ok || b != nil {
		t.Errorf("hexDecodeLoose of a bad digit: %x %v", b, ok)
	}
}

func TestR5N5IntelRawJSONObjectEscapes(t *testing.T) {
	text := `{"tcbInfo":{"a":"x\"y","b":"}"},"signature":"00"}`
	got, ok := rawJSONObject(text, "tcbInfo")
	if !ok || got != `{"a":"x\"y","b":"}"}` {
		t.Errorf("rawJSONObject: %q %v", got, ok)
	}
}

func TestR5N5IntelVerifySignedJSONNotJSON(t *testing.T) {
	// the member is found, the document as a whole is not JSON
	body, why := verifySignedJSON(`{"tcbInfo":{"a":1},`, "tcbInfo", certKey{})
	if body != nil || why != "tcbInfo document is not valid JSON" {
		t.Errorf("%v %q", body, why)
	}
}

func TestR5N5IntelCRLElementAfterThisUpdate(t *testing.T) {
	// a malformed element where nextUpdate would be is a parse error, not a CRL without nextUpdate
	der := g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, []byte{0x17, 0x80}))
	crl, err := parseCRL(der)
	if err == nil || err.Error() != "DER bad length" || crl != nil {
		t.Errorf("%v %v", crl, err)
	}
}

func TestR5N5IntelTdxIdentityFirstWins(t *testing.T) {
	info := map[string]any{"tdxModuleIdentities": []any{
		map[string]any{"id": "TDX_01", "m": "first"}, "junk", map[string]any{"id": "TDX_01", "m": "second"}, map[string]any{"id": "TDX_02"}}}
	if got := tdxIdentity(info, "TDX_01"); got == nil || got["m"] != "first" {
		t.Errorf("TDX_01: %v", got)
	}
	if got := tdxIdentity(info, "TDX_09"); got != nil {
		t.Errorf("TDX_09: %v", got)
	}
	if got := tdxIdentity(map[string]any{"tdxModuleIdentities": "x"}, "TDX_01"); got != nil {
		t.Errorf("not a list: %v", got)
	}
}

func TestR5N5IntelPckChainRolesFirstMatch(t *testing.T) {
	c := func(subject, issuer string) *attCert {
		return &attCert{RawSubject: []byte(subject), RawIssuer: []byte(issuer)}
	}
	leaf, leaf2 := c("L", "C"), c("L2", "C")
	ca, ca2 := c("C", "R"), c("C", "R2")
	root, root2 := c("R", "R"), c("R2", "R2")
	gl, gca, groot := pckChainRoles([]*attCert{leaf, leaf2, ca, ca2, root, root2})
	if gl != leaf || gca != ca || groot != root {
		t.Errorf("first matches: %v %v %v", gl == leaf, gca == ca, groot == root)
	}
	// every certificate issues another: no leaf, so nothing else is picked either
	a, b := c("A", "B"), c("B", "A")
	if l, x, r := pckChainRoles([]*attCert{a, b}); l != nil || x != nil || r != nil {
		t.Errorf("no leaf: %v %v %v", l, x, r)
	}
}

func TestR5N5MaaListLenAndFirstString(t *testing.T) {
	if listLen([]any{1, 2}) != 2 || listLen("abc") != 3 || listLen(5) != 0 {
		t.Errorf("listLen: %d %d %d", listLen([]any{1, 2}), listLen("abc"), listLen(5))
	}
	if s, ok := firstString(map[string]any{"a": ""}, []string{"a", "b"}); ok || s != "" {
		t.Errorf("firstString: %q %v", s, ok)
	}
	if s, ok := firstString(map[string]any{"a": "", "b": "v"}, []string{"a", "b"}); !ok || s != "v" {
		t.Errorf("firstString hit: %q %v", s, ok)
	}
}

func TestR5N5MaaSevSnpMinTcbMustBeObject(t *testing.T) {
	cfg := map[string]any{
		"trustedIssuers": []any{"https://i"},
		"trustAnchors":   map[string]any{"rootSpkiSha256": []any{"aa"}},
		"policy":         map[string]any{"tdxMrtds": []any{"aa"}, "sevSnpMinTcb": "x"},
	}
	v, err := newMaaVerifier(cfg)
	if err == nil || v != nil || err.Error() != "createAzureMaaVerifier: policy.sevSnpMinTcb must be an object" {
		t.Errorf("%v %v", v, err)
	}
}

func TestR5N5MaaResolveSigningX5cByKid(t *testing.T) {
	jwks := map[string]any{"keys": []any{map[string]any{"kid": "a", "x5c": []any{"A"}}, map[string]any{"kid": "b", "x5c": []any{"B", "C"}}}}
	c, why := resolveSigningX5c(&jwtParsed{hasKid: true, kid: "b"}, jwks)
	if why != "" || len(c) != 2 {
		t.Errorf("kid match: %v %q", c, why)
	}
}

// The first configured anchor decides the chain: an unrelated later certificate whose key is also pinned does not extend it.
func TestR5N5MaaX5cFirstAnchorWins(t *testing.T) {
	kR, kI, kL, kS := g03ecKey(t), g03ecKey(t), g03ecKey(t), g03ecKey(t)
	R := g03x509(t, "R", &kR.PublicKey, nil, kR, 0)
	I := g03x509(t, "I", &kI.PublicKey, R, kR, 0)
	LbyI := scCert(t, "L", kL, I, kI, scLeaf)
	S := g03x509(t, "S", &kS.PublicKey, nil, kS, 0)
	fp := func(der []byte) string {
		c, err := certFromPEM(g03pem(der))
		if err != nil {
			t.Fatal(err)
		}
		k, err := keyOfCert(c)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ToLower(k.spkiSHA256())
	}
	a := maaAnchors{rootSpki: []string{fp(I.Raw), fp(S.Raw)}}
	leaf, why := a.verifyX5cChain([]any{g03b64(LbyI.Raw), g03b64(I.Raw), g03b64(S.Raw)}, tokNow, 0)
	if why != "" || leaf == nil {
		t.Errorf("chain anchored at I: %q", why)
	}
}

func TestR5N5ProvenanceInclusionProofLengths(t *testing.T) {
	ls := make([][]byte, 6)
	for i := range ls {
		ls[i] = sha([]byte{byte(i)})
	}
	left := rfc9162Node(rfc9162Node(ls[0], ls[1]), rfc9162Node(ls[2], ls[3]))
	root := rfc9162Node(left, rfc9162Node(ls[4], ls[5]))
	// index 4 of 6: fn == sn becomes 2 (even) on the second step, which enters the inner shift loop
	if !VerifyRFC9162Inclusion(ls[4], 4, 6, [][]byte{ls[5], left}, root) {
		t.Error("index 4 of 6")
	}
	if VerifyRFC9162Inclusion(ls[4], 4, 6, [][]byte{ls[5], ls[0]}, root) {
		t.Error("wrong sibling accepted")
	}
	// a sibling that is not 32 bytes is refused even when the root was built from it
	p31 := make([]byte, 31)
	r31 := rfc9162Node(p31, ls[0])
	if VerifyRFC9162Inclusion(ls[0], 1, 2, [][]byte{p31}, r31) {
		t.Error("31-byte sibling accepted")
	}
}

func TestR5N5A2APushTokenShortSalt(t *testing.T) {
	if tok, ok := A2APushToken("t", []string{"a"}, "short"); ok || tok != "" {
		t.Errorf("short salt: %q %v", tok, ok)
	}
}

// The first pin naming the principal decides (the reference's find): a later pin for the same principal does not override it.
func TestR5N5EscalationFirstPinDecides(t *testing.T) {
	pq := newWBPQKey(t)
	dg := func(s string) string { return b64.EncodeToString(sha([]byte(s))) }
	pid, pd, ad, hh := dg("principal"), dg("policy"), dg("action"), dg("head")
	body := map[string]any{"v": jnum(1), "kind": "pca-escalation-answer", "principal": pid, "policy_digest": pd, "action_digest": ad,
		"history_head": hh, "decision": "allow", "iat": jnum(1000), "expires_at": jnum(2000), "nonce": "CQkJCQkJCQkJCQkJCQkJCQ"}
	ans := signArtPQ(t, pq, EscalationAnswerDomain, body)
	bind := EscalationBinding{PolicyDigest: pd, ActionDigest: ad, HistoryHead: hh}
	pins := []PinnedSigner{{PK: pid, PQPK: pq.pk}, {PK: pid, PQPK: "another"}}
	if r := VerifyEscalationAnswer(ans, pins, bind, 1500); !r.OK || r.Decision != "allow" || r.Principal != pid {
		t.Errorf("first pin: %+v", r)
	}
}

func TestR5N5EdStrictPointMemoHitIsUsed(t *testing.T) {
	enc := make([]byte, 32)
	enc[0] = 1 // y = 1: the identity, which edStrictPoint refuses
	if edStrictPoint(enc) {
		t.Fatal("identity accepted")
	}
	edPointMemo.Lock()
	old := edPointMemo.m
	edPointMemo.m = map[[32]byte]bool{[32]byte(enc): true}
	edPointMemo.Unlock()
	defer func() {
		edPointMemo.Lock()
		edPointMemo.m = old
		edPointMemo.Unlock()
	}()
	if !edStrictPoint(enc) {
		t.Error("a memoised verdict was recomputed")
	}
}

// About half of all valid encodings decode through the sqrt(-1) correction; the walk below covers both branches.
func TestR5N5EdDecodeBranches(t *testing.T) {
	n := 0
	for y := int64(2); y < 200; y++ {
		if _, ok := edDecode(encY(big.NewInt(y), 0)); ok {
			n++
		}
	}
	if n < 20 {
		t.Errorf("only %d of 198 small y values decode", n)
	}
}

func TestR5N5IntentMapDimAndAction(t *testing.T) {
	if got := mapDimError("x", 3); got != "dims[3] must be an object" {
		t.Errorf("mapDimError: %q", got)
	}
	got, why := IntentMapPrimitive(map[string]any{})
	if got["ok"] != false || why != "action must be an object" {
		t.Errorf("no action: %v %q", got, why)
	}
}

func TestR5N5IntentMapOpensUnhashableLeaf(t *testing.T) {
	salt := make([]byte, 32)
	p := sha([]byte("p"))
	e := map[string]any{"salt": b64.EncodeToString(salt), "leaf": "\xed\xa0\x80", "path": []any{b64.EncodeToString(p)}, "index": jnum(0)}
	// the root a nil leaf hash would give
	commit := mapCommitOf(2, mapNodeHash(nil, p))
	if mapOpens("header", e, 2, commit) {
		t.Error("a leaf with no canonical form opened the commitment")
	}
}

func TestR5N5IntentMapDecisionRecovers(t *testing.T) {
	m := buildMap(t, 500)
	in := mapInput(t, m, map[string]any{"total": jnum(1)}, "skyair.example/bookings", 0)
	old := mapOpensFn
	defer func() { mapOpensFn = old }()
	mapOpensFn = func(string, map[string]any, int, string) bool { panic("r5") }
	var got map[string]any
	var why string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic escaped the map decision: %v", r)
			}
		}()
		got, why = IntentMapPrimitive(deep(t, in))
	}()
	if got["ok"] != false || why != "map error (fail closed)" {
		t.Errorf("%v %q", got, why)
	}
}

// Reaches every loop of the map tree and of the RFC 9162 path walk (the 6-leaf tree, index 4: fn == sn is even on step two).
func TestR5N5IntentMapTreeAndPathWalks(t *testing.T) {
	ls := make([][]byte, 6)
	for i := range ls {
		ls[i] = sha([]byte{byte(i), 7})
	}
	left := mapNodeHash(mapNodeHash(ls[0], ls[1]), mapNodeHash(ls[2], ls[3]))
	root := mapNodeHash(left, mapNodeHash(ls[4], ls[5]))
	if !bytes.Equal(mapTreeRoot(ls), root) {
		t.Error("6-leaf root")
	}
	if !bytes.Equal(mapTreeRoot(ls[:3]), mapNodeHash(mapNodeHash(ls[0], ls[1]), ls[2])) {
		t.Error("3-leaf root")
	}
	if !bytes.Equal(mapTreeRoot(ls[:2]), mapNodeHash(ls[0], ls[1])) {
		t.Error("2-leaf root")
	}
	if got := mapRootFromPath(4, 6, ls[4], [][]byte{ls[5], left}); !bytes.Equal(got, root) {
		t.Error("index 4 of 6")
	}
}
