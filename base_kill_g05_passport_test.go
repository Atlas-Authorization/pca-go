package pca

import (
	"errors"
	"testing"
)

// g05: VerifyPassport boundaries (clock skew cap, evidence age default, -0/maxSafe clocks) and the malformed-shape guards,
// each with an input the later checks would otherwise answer differently.

const (
	g05Iat = int64(1_000_000)
	g05Exp = g05Iat + 200_000_000
)

func g05NotRevoked(string, string, string) (bool, error) { return false, nil }

func g05Passport(t *testing.T, hw bool, evidence map[string]any) (map[string]any, *KeyPair) {
	t.Helper()
	issuer := g05Key(t, 0x61)
	pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": hw, "issued_at": g05Iat})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := SignPassport(pp, issuer, g05Key(t, 0x62).Public, 0, 0, g05Exp, evidence, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sp, issuer
}

func g05PassOpts(issuer *KeyPair, now int64) PassportOptions {
	return PassportOptions{TrustedIssuers: []string{issuer.Public}, NowMs: now, Revoked: g05NotRevoked}
}

// g05Resign re-signs the passport after f edits its top level.
func g05Resign(t *testing.T, sp map[string]any, k *KeyPair, f func(m map[string]any)) map[string]any {
	t.Helper()
	b := copyMap(sp)
	delete(b, "sig")
	delete(b, "pq_sig")
	f(b)
	out, err := SignArtifact(passportSigDomain, b, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func g05Want(t *testing.T, label string, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %q, want %q", label, got, want)
	}
}

func TestG05PassportShapeGuards(t *testing.T) {
	sp, iss := g05Passport(t, false, nil)
	o := g05PassOpts(iss, g05Iat+1)
	g05Want(t, "valid", VerifyPassport(sp, o), "")
	noRev := o
	noRev.Revoked = nil
	g05Want(t, "no revocation source", VerifyPassport(sp, noRev), "revocation_unavailable")

	emptyIss := copyMap(sp)
	emptyIss["iss"] = ""
	g05Want(t, "empty iss", VerifyPassport(emptyIss, o), "malformed")
	noIss := copyMap(sp)
	delete(noIss, "iss")
	g05Want(t, "missing iss", VerifyPassport(noIss, o), "malformed")

	wrongTyp := g05Resign(t, sp, iss, func(m map[string]any) { m["typ"] = "atlas-pca/other" })
	g05Want(t, "signed wrong typ", VerifyPassport(wrongTyp, o), "malformed")

	noNbf := copyMap(sp)
	delete(noNbf, "nbf")
	g05Want(t, "missing nbf", VerifyPassport(noNbf, o), "malformed")
	expIsNbf := copyMap(sp)
	expIsNbf["exp"] = sp["nbf"]
	g05Want(t, "exp == nbf", VerifyPassport(expIsNbf, o), "malformed")

	// the clock bound is inclusive: +-maxSafe is a valid clock (the untrusted issuer answers first)
	far := PassportOptions{NowMs: 9007199254740991}
	g05Want(t, "now = maxSafe", VerifyPassport(sp, far), "unknown_issuer")
	far.NowMs = -9007199254740991
	g05Want(t, "now = -maxSafe", VerifyPassport(sp, far), "unknown_issuer")
}

func TestG05PassportClockSkew(t *testing.T) {
	sp, iss := g05Passport(t, false, nil)
	at := func(now, skew int64) string {
		o := g05PassOpts(iss, now)
		o.ClockSkewMs = ptr(skew)
		return VerifyPassport(sp, o)
	}
	// a skew over the cap counts as exactly 60 s
	g05Want(t, "nbf-60000 skew 60001", at(g05Iat-60_000, 60_001), "")
	g05Want(t, "nbf-60001 skew 60001", at(g05Iat-60_001, 60_001), "not_yet_valid")
	// a zero (or negative) skew is none
	g05Want(t, "nbf-1 skew 0", at(g05Iat-1, 0), "not_yet_valid")
	g05Want(t, "nbf-1 skew -5", at(g05Iat-1, -5), "not_yet_valid")
	g05Want(t, "nbf skew 0", at(g05Iat, 0), "")
	// expiry subtracts the skew
	g05Want(t, "exp-1000 skew 1000", at(g05Exp-1000, 1000), "")
	g05Want(t, "exp skew 1000", at(g05Exp+1000, 1000), "expired")
}

func TestG05PassportHardwareEvidence(t *testing.T) {
	ev := func(doc map[string]any) map[string]any { return map[string]any{"document": doc, "at": g05Iat} }
	sp, iss := g05Passport(t, true, ev(map[string]any{"nonce": "n"}))
	run := func(now int64, maxAge *int64) string {
		o := g05PassOpts(iss, now)
		o.MaxEvidenceAgeMs = maxAge
		return VerifyPassport(sp, o)
	}
	// the default evidence age is 24 h, inclusive
	g05Want(t, "age 24h", run(g05Iat+86_400_000, nil), "hardware_verifier_missing")
	g05Want(t, "age 24h+1", run(g05Iat+86_400_001, nil), "hardware_evidence_stale")
	// evidence taken exactly now, with no skew and a zero maximum age, is fresh
	g05Want(t, "age 0", run(g05Iat, nil), "hardware_verifier_missing")
	g05Want(t, "age 0 max 0", run(g05Iat, ptr(0)), "hardware_verifier_missing")
	g05Want(t, "age 1 max 0", run(g05Iat+1, ptr(0)), "hardware_evidence_stale")
	g05Want(t, "max -1", run(g05Iat, ptr(-1)), "hardware_evidence_stale")

	noNonce, iss2 := g05Passport(t, true, ev(map[string]any{}))
	g05Want(t, "no nonce", VerifyPassport(noNonce, g05PassOpts(iss2, g05Iat)), "hardware_evidence_missing")

	att := func(m map[string]any, err error) PassportOptions {
		o := g05PassOpts(iss, g05Iat)
		o.Attest = func(map[string]any, PassportBinding) (PassportAttestation, error) {
			return PassportAttestation{OK: true, Bound: true, Measured: m}, err
		}
		return o
	}
	g05Want(t, "measured nil", VerifyPassport(sp, att(nil, nil)), "hardware_identity_mismatch")
	g05Want(t, "measured match", VerifyPassport(sp, att(map[string]any{"model_id": "m", "operator": "acme"}, nil)), "")
	g05Want(t, "attest error", VerifyPassport(sp, att(map[string]any{"model_id": "m", "operator": "acme"}, errors.New("x"))), "hardware_attestation_failed")
}
