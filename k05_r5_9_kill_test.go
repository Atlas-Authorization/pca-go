package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// r5n9noPanic fails (an ordinary assertion) when f lets a panic escape: a fail-closed recover must contain it.
func r5n9noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s let a panic escape: %v", what, r)
		}
	}()
	f()
}

// ---- actions_traits.go ---------------------------------------------------------------------------------------------------

func r5n9Tiny() Registry { return Registry{"t.one": {ID: "t.one", Floor: mkProfile(Profile{})}} }

// r5n9TinyVerb is an unconfirmed verb of the one-trait registry that carries that trait and its floor: consistent.
func r5n9TinyVerb(mut func(v map[string]any)) map[string]any {
	fl, _ := r5n9Tiny().floorOf([]string{"t.one"})
	v := map[string]any{"verb": "a.b", "kind": "write", "params": map[string]any{}, "effects": []any{}, "traits": []any{"t.one"},
		"floors": fl.raw(), "reversibility": "reversible"}
	if mut != nil {
		mut(v)
	}
	return v
}

func TestR5N9_TraitsSchemaVerbFloorReversibility(t *testing.T) {
	strParam := map[string]any{"action.params.s": map[string]any{"type": "string", "values": []any{"a", "b"}}}
	cases := []struct {
		name string
		mut  func(v map[string]any)
		want string
	}{
		{"consistent", nil, ""},
		// the declared class is above what the floors carry
		{"floors.rev below the declared class", func(v map[string]any) { v["reversibility"] = "rate_limited" },
			"schema_floor_forged: floors.rev is below the declared reversibility"},
		// reversibility_by over a string parameter with values: covered values decide the class (no irreversible default)
		{"values cover the map", func(v map[string]any) {
			delete(v, "reversibility")
			v["params"] = strParam
			v["reversibility_by"] = map[string]any{"param": "action.params.s", "map": map[string]any{"a": "reversible", "b": "reversible"}}
		}, ""},
		// an uncovered value falls to the declared default
		{"declared default", func(v map[string]any) {
			delete(v, "reversibility")
			v["params"] = strParam
			v["reversibility_by"] = map[string]any{"param": "action.params.s", "map": map[string]any{"a": "reversible"}, "default": "reversible"}
		}, ""},
		// no default declared: irreversible
		{"no default", func(v map[string]any) {
			delete(v, "reversibility")
			v["params"] = strParam
			v["reversibility_by"] = map[string]any{"param": "action.params.s", "map": map[string]any{"a": "reversible"}}
		}, "schema_traits_forged: missing implied trait pca.irreversible"},
	}
	for _, c := range cases {
		if got := schemaVerbFloorError(r5n9TinyVerb(c.mut), r5n9Tiny(), nil); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := schemaVerbShapeError(map[string]any{"params": map[string]any{}, "reversibility_by": true}); got != "reversibility_by must be an object" {
		t.Errorf("a truthy non-object reversibility_by: %q", got)
	}
}

func TestR5N9_TraitsFaultsAreContained(t *testing.T) {
	defer func() { traitsFault = nil }()
	var got string
	traitsFault = func(scope string) {
		if scope == "verb" {
			panic("boom")
		}
	}
	r5n9noPanic(t, "schemaVerbFloorError", func() { got = schemaVerbFloorError(r5n9TinyVerb(nil), r5n9Tiny(), nil) })
	if got != "schema_floor_forged: boom" {
		t.Errorf("a panic in the floor check: %q", got)
	}
	// a panic while reading the confirmation means no confirmation: the verb is then judged as unconfirmed (and this one carries every trait)
	traitsFault = func(scope string) {
		if scope == "confirm" {
			panic("boom")
		}
	}
	r5n9noPanic(t, "confirmation check", func() { got = schemaVerbFloorError(r5n9TinyVerb(nil), r5n9Tiny(), nil) })
	if got != "" {
		t.Errorf("a panic in the confirmation check: %q", got)
	}
}

// ---- jsval.go ------------------------------------------------------------------------------------------------------------

func TestR5N9_JsvalSpecialLexemesAndStrings(t *testing.T) {
	if f, ok := jsNum(json.Number("Infinity")); !ok || !math.IsInf(f, 1) {
		t.Errorf("Infinity: %v %v", f, ok)
	}
	if f, ok := jsNum(json.Number("-Infinity")); !ok || !math.IsInf(f, -1) {
		t.Errorf("-Infinity: %v %v", f, ok)
	}
	for in, want := range map[string]string{"true": "true", "false": "false", "abc": "abc", "": ""} {
		var v any = in
		if in == "true" {
			v = true
		} else if in == "false" {
			v = false
		}
		if got := jsValueString(v); got != want {
			t.Errorf("jsValueString(%v) = %q, want %q", v, got, want)
		}
	}
	if got := jsValueString(nil); got != "null" {
		t.Errorf("jsValueString(nil) = %q", got)
	}
	for _, c := range []struct {
		a, b any
		want bool
	}{{"a", "a", true}, {"a", "b", false}, {json.Number("1"), json.Number("1"), true}, {json.Number("1"), "1", false}, {"1", json.Number("1"), false},
		{true, true, true}, {true, json.Number("1"), false}, {nil, json.Number("0"), false}} {
		if got := scalarEqV(c.a, c.b); got != c.want {
			t.Errorf("scalarEqV(%v, %v) = %v", c.a, c.b, got)
		}
	}
}

// ---- attest_common.go ----------------------------------------------------------------------------------------------------

func TestR5N9_AttestCommonHelpers(t *testing.T) {
	if f, ok := asFinite(7); !ok || f != 7 {
		t.Errorf("asFinite(int): %v %v", f, ok)
	}
	if f, ok := asFinite(int64(8)); !ok || f != 8 {
		t.Errorf("asFinite(int64): %v %v", f, ok)
	}
	for _, c := range []struct {
		curve elliptic.Curve
		want  string
	}{{elliptic.P256(), "prime256v1"}, {elliptic.P384(), "secp384r1"}, {elliptic.P521(), "secp521r1"}, {elliptic.P224(), "secp224r1"}} {
		if got := curveOpenSSLName(c.curve); got != c.want {
			t.Errorf("curveOpenSSLName(%s) = %q, want %q", c.curve.Params().Name, got, c.want)
		}
	}
	if k := keyInfoOf(struct{}{}, nil); k.typ != "unknown" {
		t.Errorf("an unrecognised key type: %q", k.typ)
	}
	if k := keyInfoOf(ed25519.PublicKey(make([]byte, 32)), nil); k.typ != "ed25519" {
		t.Errorf("ed25519 key type: %q", k.typ)
	}
	const trailing = "unexpected data after the JSON value"
	for _, in := range []string{`{"a":1} 2`, `{"a":1} x`, `1 {}`} {
		if v, err := jsonLenient([]byte(in)); err == nil || err.Error() != trailing || v != nil {
			t.Errorf("jsonLenient(%q) = %v, %v", in, v, err)
		}
	}
	if v, err := jsonLenient([]byte("{\"a\":1} \n")); err != nil || v == nil {
		t.Errorf("trailing white space: %v %v", v, err)
	}
	for _, c := range []string{",", "+", "\"", "\\", "<", ">", ";"} {
		if got, want := escapeDNValue("a"+c+"b"), "a\\"+c+"b"; got != want {
			t.Errorf("escapeDNValue(%q) = %q, want %q", "a"+c+"b", got, want)
		}
	}
}

// ---- attest_gcp.go -------------------------------------------------------------------------------------------------------

func TestR5N9_GcpJwkKeyNonStringX5c(t *testing.T) {
	_, why := jwkKey(map[string]any{"x5c": []any{json.Number("5")}})
	if why != "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate" {
		t.Errorf("a non-string x5c entry: %q", why)
	}
}

func TestR5N9_GcpNewVerifierPolicyShapes(t *testing.T) {
	cfg := func(policy string) map[string]any {
		return cfgOf(t, `{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":`+policy+`}`)
	}
	// as the reference (Array.isArray): a non-array allowedTeeTypes is no allowlist
	v, err := newGcpVerifier(cfg(`{"imageDigests":["sha256:x"],"allowedTeeTypes":"tdx"}`))
	if err != nil || v.hasTeeTypes {
		t.Errorf("a string allowedTeeTypes: %v %v", err, v)
	}
	if _, err := newGcpVerifier(cfg(`{"imageDigests":["sha256:x"],"allowedTeeTypes":[]}`)); err == nil {
		t.Error("an empty allowedTeeTypes must be refused")
	}
}

// r5n9GcpRun verifies a token signed under a generated key that the config pins as a trusted JWK.
func r5n9GcpRun(t *testing.T, policy string, mut func(m map[string]any)) HardwareResult {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nowSec := tokNow / 1000
	m := map[string]any{
		"iss": gcpIssuer, "exp": nowSec + 3600, "iat": nowSec - 60, "nbf": nowSec - 60,
		"swname": "CONFIDENTIAL_SPACE", "swversion": []any{"240500"}, "hwmodel": "GCP_AMD_SEV", "dbgstat": "disabled-since-boot",
		"eat_nonce": []any{bindingB64(t, testBinding)},
		"submods":   map[string]any{"confidential_space": map[string]any{"support_attributes": []any{}}, "container": map[string]any{"image_digest": "sha256:ABC"}},
	}
	if mut != nil {
		mut(m)
	}
	token := signES256(t, key, `{"alg":"ES256","kid":"k1"}`, mustJSON(t, m))
	c := cfgOf(t, `{"trustedIssuers":["`+gcpIssuer+`"],"trustAnchors":{},"policy":`+policy+`}`)
	c["trustAnchors"] = map[string]any{"trustedJwks": map[string]any{"keys": []any{jwkOf(key, "k1")}}}
	ver, err := VerifierFromConfig("gcp-confidential-space", c)
	if err != nil {
		t.Fatal(err)
	}
	return ver.Verify(map[string]any{"token": token}, testBinding, tokNow)
}

func TestR5N9_GcpVerifyHostAndSwVersions(t *testing.T) {
	// no image_reference in the token: none is reported
	r := r5n9GcpRun(t, `{"imageDigests":["sha256:abc"]}`, nil)
	if !r.OK {
		t.Fatalf("baseline: %+v", r)
	}
	if _, has := r.HostAsserted["image_reference"]; has {
		t.Errorf("an absent image_reference must not be reported: %v", r.HostAsserted)
	}
	if r.HostAsserted["image_digest"] != "sha256:ABC" || r.HostAsserted["attestation_type"] != "sev-snp" {
		t.Errorf("host: %v", r.HostAsserted)
	}
	// an allowedSwVersions member that is not a string matches nothing (as the reference's Set of the raw members): an empty
	// token version is not allowed by it
	r = r5n9GcpRun(t, `{"imageDigests":["sha256:abc"],"allowedSwVersions":[1]}`, func(m map[string]any) { m["swversion"] = []any{""} })
	if r.OK || r.Reason != "swversion not in policy allowlist" {
		t.Errorf("swversion '' under [1]: %+v", r)
	}
	// hardware models map to their family by exact name and by prefix, case-folded
	for hw, want := range map[string]string{"GCP_AMD_SEV": "sev-snp", "GCP_AMD_SEV_SNP": "sev-snp", "GCP_AMD_SEV_ES": "sev-snp", "gcp_amd_sev_snp": "sev-snp",
		"GCP_INTEL_TDX": "tdx", "gcp_intel_tdx": "tdx", "GCP_OTHER": "", "": ""} {
		if got := gcpTeeType(hw); got != want {
			t.Errorf("gcpTeeType(%q) = %q, want %q", hw, got, want)
		}
	}
}

// A root certificate whose key the strict reader cannot take is no trust root (not an "ok" empty key).
func TestR5N9_GcpRootKeyFromPEMUnsupportedKey(t *testing.T) {
	key := g09gKey(t)
	base := time.UnixMilli(tokNow).UTC()
	c := g09gCert(t, key, "ca", nil, nil, base.Add(-time.Hour), base.Add(time.Hour))
	der := append([]byte(nil), c.Raw...)
	ecOID := []byte{0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01} // id-ecPublicKey
	i := bytes.Index(der, ecOID)
	if i < 0 {
		t.Skip("no id-ecPublicKey in the generated certificate")
	}
	der[i+8] = 0x03 // an algorithm OID no reader takes
	ac, err := parseCertDER(der)
	if err != nil {
		t.Skipf("the patched certificate does not parse: %v", err)
	}
	if _, err := keyOfCert(ac); err == nil {
		t.Skip("the patched key is still readable")
	}
	got, ok := rootKeyFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	if ok || got.pub != nil || got.spki != nil {
		t.Errorf("a certificate with an unreadable key: %+v %v", got, ok)
	}
}

// ---- intent.go -----------------------------------------------------------------------------------------------------------

func TestR5N9_IntentSmallReturns(t *testing.T) {
	if ev, why := decideIntent(map[string]any{}, map[string]any{}, nil); ev || why != "" {
		t.Errorf("no slot and no policy: %v %q", ev, why)
	}
	bad := ApprovedGoalRef{GoalDigest: "x", PolicyDigest: "y"}
	if s, err := IntentGoalV3(bad); s != "" || err == nil {
		t.Errorf("IntentGoalV3 of a malformed ref: %q %v", s, err)
	}
	if s, err := IntentGoalCommitV3(bad, "salt"); s != "" || err == nil {
		t.Errorf("IntentGoalCommitV3 of a malformed ref: %q %v", s, err)
	}
	if gc, ok := rootGoalCommit(map[string]any{}); gc != "" || ok {
		t.Errorf("rootGoalCommit without caveats: %q %v", gc, ok)
	}
	if gc, ok := rootGoalCommit(map[string]any{"caveats": []any{"x", map[string]any{"type": "other"}}}); gc != "" || ok {
		t.Errorf("rootGoalCommit without an envelope caveat: %q %v", gc, ok)
	}
	if got := validateIntentWire("x"); got != "'intent' must be an object" {
		t.Errorf("validateIntentWire(non-object) = %q", got)
	}
}

// ---- actions_registry.go -------------------------------------------------------------------------------------------------

func TestR5N9_RegistryFaultsAreContained(t *testing.T) {
	defer func() { registryFault = nil }()
	fault := func(scope string) {
		registryFault = func(s string) {
			if s == scope {
				panic("boom")
			}
		}
	}
	fault("sig")
	var s string
	r5n9noPanic(t, "verifyRegistrySig", func() { s = verifyRegistrySig("d", map[string]any{}, map[string]any{}, []any{}) })
	if s != "verification error: boom" {
		t.Errorf("verifyRegistrySig: %q", s)
	}
	fault("reapproval")
	ok := true
	r5n9noPanic(t, "reapprovalValid", func() { ok = reapprovalValid(map[string]any{}, "g", "i", "v", "d") })
	if ok {
		t.Error("a panic in reapprovalValid must refuse")
	}
	fault("pin")
	var pin map[string]any
	r5n9noPanic(t, "decidePin", func() { pin = decidePin(map[string]any{}) })
	if pin["ok"] != false || pin["code"] != "bad_pin" || pin["reason"] != "pin evaluation error (fail closed): boom" {
		t.Errorf("decidePin: %v", pin)
	}
	fault("pack")
	r5n9noPanic(t, "packShapeError", func() { s = packShapeError(map[string]any{}, false) })
	if s != "pack: boom" {
		t.Errorf("packShapeError: %q", s)
	}
}

// ---- intent_wb.go --------------------------------------------------------------------------------------------------------

func TestR5N9_WBFaultsAreContained(t *testing.T) {
	defer func() { wbFault = nil }()
	fault := func(scope string) {
		wbFault = func(s string) {
			if s == scope {
				panic("boom")
			}
		}
	}
	var r map[string]any
	var why string
	fault("world")
	r5n9noPanic(t, "rule 16", func() { r, why = IntentWorldPrimitive(map[string]any{}) })
	if r["ok"] != false || why != "facts: evaluation error (fail closed)" {
		t.Errorf("rule 16: %v %q", r, why)
	}
	fault("prov")
	r5n9noPanic(t, "rule 17", func() { r, why = IntentProvenancePrimitive(map[string]any{"action": map[string]any{}}) })
	if r["outcome"] != "deny" || why != "provenance: evaluation error (fail closed)" {
		t.Errorf("rule 17: %v %q", r, why)
	}
	fault("classes")
	r5n9noPanic(t, "rule 18", func() { r, why = IntentClassifierPrimitive(map[string]any{}) })
	if r["ok"] != false || why != "classes: evaluation error (fail closed)" {
		t.Errorf("rule 18: %v %q", r, why)
	}
}

func TestR5N9_WBPrimitiveInputErrors(t *testing.T) {
	if r, why := IntentProvenancePrimitive("x"); r["outcome"] != "deny" || why != "provenance: input must be an object" {
		t.Errorf("provenance non-object: %v %q", r, why)
	}
	if r, why := IntentProvenancePrimitive(map[string]any{}); r["outcome"] != "deny" || why != "provenance: action must be an object" {
		t.Errorf("provenance without action: %v %q", r, why)
	}
	if r, why := IntentClassifierPrimitive("x"); r["ok"] != false || why != "classes: input must be an object" {
		t.Errorf("classifier non-object: %v %q", r, why)
	}
	if r, why := IntentWorldPrimitive("x"); r["ok"] != false || why != "facts: input must be an object" {
		t.Errorf("world non-object: %v %q", r, why)
	}
	for _, in := range []any{"x", nil, map[string]any{"fields": []any{"s"}, "purpose": "p", "coverage": map[string]any{}},
		map[string]any{"fields": []any{map[string]any{"path": "a"}}, "purpose": "p", "coverage": map[string]any{}}} {
		if got := IntentReadPurposePrimitive(in); got["outcome"] != "deny" {
			t.Errorf("read purpose %v: %v", in, got)
		}
	}
	if rankOf("bogus") <= taintedRank || rankOf("trusted") != 0 {
		t.Errorf("an unknown taint level ranks as the lowest trust: %d", rankOf("bogus"))
	}
	if got := validateWorldPolicyError(map[string]any{"relational": []any{"x"}}); got != "relational entry must be an object" {
		t.Errorf("a non-object relational entry: %q", got)
	}
}

// An invalid fact is skipped, not the end of the list.
func TestR5N9_WorldSkipsInvalidFacts(t *testing.T) {
	ks := []fxKey{newKey(t)}
	in := worldInput(t, ks, []map[string]any{fact(t, ks[0], "o0", jnum(5), v2Now)}, farePolicy(ks, 1, 0, 1000, nil))
	in["facts"] = append([]any{"junk"}, in["facts"].([]any)...)
	if r, why := IntentWorldPrimitive(deep(t, in)); r["ok"] != true {
		t.Fatalf("a valid fact after an invalid one: %v %q", r, why)
	}
}

// Two label keys for one site and kid: the first decides (the reference's find).
func TestR5N9_ProvenanceFirstLabelKeyWins(t *testing.T) {
	lk, other := newKey(t), newKey(t)
	rc := signArt(t, lk, labelsDomain, map[string]any{"v": jnum(1), "kind": "pca-labels", "site": v2Aud, "session": dg("session"), "response_digest": dg("r"),
		"fields": map[string]any{"f": map[string]any{"class": "public", "value_digest": dg("v")}}, "issued_at": jnum(v2Now), "kid": "k1"})
	ref := refOf(t, labelsRefDomain, "l", rc)
	run := func(keys ...any) (map[string]any, string) {
		return IntentProvenancePrimitive(deep(t, map[string]any{"aud": v2Aud, "session": dg("session"), "action": map[string]any{"params": map[string]any{"a": "x"}},
			"prov": map[string]any{"action.params.a": []any{labelRefPrefix + ref + "#f"}}, "committed_labels": []any{ref}, "labels": []any{rc},
			"policy": map[string]any{"params": map[string]any{}, "label_keys": keys}}))
	}
	good := map[string]any{"site": v2Aud, "kid": "k1", "pk": lk.id}
	bad := map[string]any{"site": v2Aud, "kid": "k1", "pk": other.id}
	if _, why := run(good, bad); strings.Contains(why, "bad label receipt signature") {
		t.Errorf("the first matching key must decide: %q", why)
	}
	if r, why := run(bad, good); r["outcome"] != "deny" || !strings.Contains(why, "bad label receipt signature") {
		t.Errorf("the first matching key (a wrong one) must decide: %v %q", r, why)
	}
}

// The unit reports the predicate env members it computed for rules 17 and 18.
func TestR5N9_WBUnitEnv(t *testing.T) {
	act := map[string]any{"verb": "v", "resource": "r", "params": map[string]any{"body": "x"}}
	wb := decideIntentWB(float64(v2Now), v2Aud, dg("session"), act, map[string]any{"session": dg("session"), "prov": map[string]any{}}, nil, map[string]any{})
	if wb.checks["provenance"] != "pass" {
		t.Fatalf("provenance: %v %q", wb.checks, wb.reason)
	}
	if _, has := wb.env["prov"]; !has {
		t.Errorf("env.prov missing: %v", wb.env)
	}

	judge := newKey(t)
	cd, _ := hashCanonicalV("x")
	verdict := signArt(t, judge, classifierDomain, map[string]any{"v": jnum(1), "kind": "pca-intent-classification", "classifier": "tone", "session": dg("session"),
		"content_digest": cd, "label": "a", "measurement": "m", "judge": judge.id})
	pol := map[string]any{"classifiers": []any{map[string]any{"id": "tone", "param": "action.params.body", "labels": []any{"a"}, "keys": []any{judge.id}, "k": jnum(1)}}}
	is := map[string]any{"session": dg("session"), "classes": []any{refOf(t, classifierRefDomain, "c", verdict)}}
	wb = decideIntentWB(float64(v2Now), v2Aud, dg("session"), act, deepM(t, is), deep(t, map[string]any{"verdicts": []any{verdict}}), deep(t, pol))
	if wb.checks["classes"] != "pass" {
		t.Fatalf("classes: %v %q", wb.checks, wb.reason)
	}
	if got, has := wb.env["class"].(map[string]any); !has || got["tone"] != "a" {
		t.Errorf("env.class: %v", wb.env)
	}
}

// IntentSchemaPrimitive reports a digest exactly when the schema digest can be computed.
func TestR5N9_SchemaPrimitiveDigestFollowsHash(t *testing.T) {
	site := newKey(t)
	kid := "k\xed\xa0\x80" // a lone surrogate: the signature body (without sig) is canonical, the whole document is not
	doc := v2Schema()
	doc["sig"] = map[string]any{"alg": "ed25519", "kid": kid, "value": signDomain(t, site, actionSchemaDomain, doc)}
	keys := []any{map[string]any{"kid": kid, "alg": "ed25519", "pk": site.id}}
	out := IntentSchemaPrimitive(map[string]any{"schema": doc, "keys": keys, "verb": "air.book", "params": map[string]any{}})
	_, digestOK := actionSchemaDigest(doc)
	_, has := out["digest"]
	if out["sig"] == true && has != digestOK {
		t.Errorf("digest reported %v, computable %v", has, digestOK)
	}
}

// ---- readside.go ---------------------------------------------------------------------------------------------------------

func r5n9ReadGrant(t *testing.T, reads []any) (map[string]any, fxKey) {
	t.Helper()
	pk := newKey(t)
	body := map[string]any{"v": jnum(1), "id": "rg-1", "principal": pk.id, "issued_at": jnum(1), "expires_at": jnum(1000), "reads": reads,
		"caps": map[string]any{}, "sinks": map[string]any{"ext": map[string]any{"allow": []any{}, "escalate": []any{}}}}
	return map[string]any{"body": body, "sig": signDomain(t, pk, k5ReadGrantDomain, body)}, pk
}

func r5n9ReadEntry(defaultMode string) map[string]any {
	return map[string]any{"verb": "v.get", "resource_prefix": "r/", "purposes": []any{"p"}, "modes": map[string]any{}, "default_mode": defaultMode}
}

func r5n9ReadInput(grant map[string]any, pk fxKey) ReadInput {
	return ReadInput{Grant: grant, Principal: pk.id, Now: jnum(50), Verb: "v.get", Resource: "r/1", Purpose: "p",
		Schema: map[string]any{"fields": map[string]any{"a": "c1"}, "required": []any{}}, Record: map[string]any{"a": "x"},
		Tighten: map[string]any{}, Salt: strings.Repeat("s", 16), Counts: map[string]any{}}
}

func TestR5N9_ReadSideRedact(t *testing.T) {
	// a class with no mode of its own gets the entry's default mode
	g, pk := r5n9ReadGrant(t, []any{r5n9ReadEntry("show")})
	if r := RedactRead(r5n9ReadInput(g, pk)); r.Decision != "allow" || r.View["a"] != "x" {
		t.Errorf("default mode show: %s %s %v", r.Decision, r.Code, r.View)
	}
	// two entries match: the first decides (the reference's find)
	g, pk = r5n9ReadGrant(t, []any{r5n9ReadEntry("show"), r5n9ReadEntry("drop")})
	if r := RedactRead(r5n9ReadInput(g, pk)); r.Decision != "allow" || r.View["a"] != "x" {
		t.Errorf("first matching entry: %s %s %v", r.Decision, r.Code, r.View)
	}
	// counts must be an object
	in := r5n9ReadInput(g, pk)
	in.Counts = "x"
	if r := RedactRead(in); r.Decision != "deny" || r.Code != "bad_request" {
		t.Errorf("counts not an object: %s %s", r.Decision, r.Code)
	}
}

func TestR5N9_ReadSideSinkAndChain(t *testing.T) {
	g, pk := r5n9ReadGrant(t, []any{r5n9ReadEntry("show")})
	rs := newKey(t)
	sink := SinkInput{Grant: g, Principal: pk.id, RsSigner: rs.id, Now: jnum(50), Sink: "ext", Receipts: []any{}}
	if r := CheckSink(sink); r.Decision != "allow" || r.Code != "" {
		t.Fatalf("baseline sink: %+v", r)
	}
	deny := func(r SinkResult) bool {
		return r.Decision == "deny" && r.Code == "bad_request" && r.Labels != nil && len(r.Labels) == 0
	}
	defer func() { k5GrantDigest, k5SinkFault = ReadGrantDigest, nil }()
	k5GrantDigest = func(map[string]any) (string, bool) { return "", false }
	if r := CheckSink(sink); !deny(r) {
		t.Errorf("a grant digest that cannot be computed: %+v", r)
	}
	k5GrantDigest = ReadGrantDigest
	k5SinkFault = func() { panic("boom") }
	var r SinkResult
	r5n9noPanic(t, "CheckSink", func() { r = CheckSink(sink) })
	if !deny(r) {
		t.Errorf("a panic in CheckSink: %+v", r)
	}
	k5SinkFault = nil

	// a receipt's labels are exactly the classes of its non-dropped fields: a same-length different list is refused
	gd := dg("r5n9-grant")
	receipt := func(labels []any) map[string]any {
		rc := map[string]any{"v": jnum(1), "grant": gd, "verb": "v.get", "resource": "r/1", "purpose": "p", "seq": jnum(0), "prev": nil,
			"fields": map[string]any{"a": map[string]any{"class": "c1", "action": "shown", "kind": nil, "vd": dg("vd")}},
			"labels": labels, "issued_at": jnum(1), "signer": rs.id}
		rc["sig"] = signDomain(t, rs, k5ReadReceiptDomain, k5ReadReceiptBody(rc))
		return rc
	}
	if l, code, at := ReadChainLabels([]any{receipt([]any{"c1"})}, rs.id, gd, 100); code != "" || at != -1 || !reflect.DeepEqual(l, []string{"c1"}) {
		t.Errorf("honest receipt: %v %q %d", l, code, at)
	}
	if l, code, at := ReadChainLabels([]any{receipt([]any{"c2"})}, rs.id, gd, 100); code != "bad_receipt" || at != 0 || l != nil {
		t.Errorf("receipt naming another class: %v %q %d", l, code, at)
	}
}
