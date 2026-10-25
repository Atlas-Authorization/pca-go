//go:build less && cgo

package pca

import (
	"encoding/json"
	"testing"
)

// killCLessOneByteSig is a less-cat1 signature (1313 bytes, below the maximum) over the ONE-byte message "x" under
// less-vectors.json keys.main, made by the TS reference backend (@atlasauth/pca-less-wasm, keygen seed "less-kg-main",
// signing seed "killc-one-byte").
const killCLessOneByteSig = "qfQiJdNbwilkbv7oE1dl-My6SOZMRsblKupRDWu1BH7wDIqBRtUfT1CAL-iaWuozye3mCA9-fY8Vwd7wzKZow8s07eyvdVmxGv3OYi8jj6hR32q4wTgjJ-OMCFBe1MACvtqK-7okzr2QI59ki9CVCqEUTkoEcdr00fvAjij7owc9e7H3jRgsAnAY5g3qCHizlQ9ucT2W48gLWoYrltR_Dv0ZOKjyAiH_gIbX7P0QqA0nDWsobYbvZ0ZF40Vi9U8Okr3kmZGO-3CY7yvAJGYrM9S7aMieibiia2Bo58tLHQlDfyYMO59Ku4SlBuyvuGlDB2dhov6qdKEw2bqeGSVmBZFmy2qztfLJncy1HBj5Vw20owmnJtpZNBOYeAFRXbsOdjZ59TNljCCMD2ofM6W_o65lpgvgrltoKi8dIrkZpgShKIxnY-O-zbMygltBbeK0CLfMbdJeYCX2HEHm-XRWDaveLIdNtqCVhcVSCKf-FK7wFxMFrp7QfvggqruuOVsEs5heYuiO8II5QwmX8a_GHYzWOz5oMdDWg0aL8gng_w6HeNKDDSW10KMxvvKFXDl-QQBfvaGvoNO_DJHO76DJBrwcs4KLm1xhrkcgw1au8cP4xoJda8X17wOlR1EgsXgOfq47XgEk3kVLDFawiUzI3E6mYu7Z6ZBVdzzUfXnZQAOxfUTx8H4trLKPoLmEt6zQ5onETCT893wBTdY4AC57DnL-_QYTvX5IHQUh5GvWoJMbFlxRAbPQhlYq_evvjJkEiDl39HXDoi-xU5ALKExfABNl2XsI3Rdvq78Q1XOqlwJ9VBSC1ERjTExUhWm2-lj9nMOShv_6UYbW9O1gX7JMCMa6zHRoG2EKrS4t6HrfH2jYSD-bB9FU8UGRe0o5imYH-wKYyTkWMQ6EtEORLzr1tijx70Iy__b4zeEwae0A9AUjTreD6qZqqfxfwrDg6kPc-_FNMqD3LROiMBxJHjcOAZTNKz7zmAJ7QYOFqRVLUwOdV8r5SsU-GKllVrAn_8oNddJXIfdfDPoTqCVVHSJU5JlHRu7xNJsiyyW_WpEg1wmQIGxmjQpKz7WSxdVhV9u_48p5jbbIQpWwj4Mz3KXxAQZmGXcfNwXLB9EmX3AjAzBvIPYWhcKpyfdQb7C76esO8VLQ2K3mNAI16i3TrojzcGqX4W8U6Rs_BMC4-dTMJwWZJS4jE-VqurZPXn-SoT6N0FZOTdDA4hoc4Putd6SFAimpTLwJhlkMOPHiulpaUYeuSi3Nur1dkB8_tobVYHwJ-14-kw7YgMN9ImRWnXBPI07eDMjPE1scJNJqzR_jwA5dVrPtmkRwFb_TbsrJAfBnTkQXZ6L4l5kY2YKwAcXfDsFXKMD27FCExVx4VH7e0LzFTFhcGK8O6fzmOOsbclEOUkkcFAIRrO6lpYvblXlWGU9a46XfgIqbnRV7XU6Sow9dP057zjBg5o7xwzz7pQMx-OJlgtsNk9OsMWsaHTA0AiX8lc0qVSu8ikbZX0KMNobmBmK1TxTdH5O8AfGLjBcPc-f-UShdn6comL-ZDTvFC1FC3YY4vhZDDWpnIwYyA9pKgpy2h5rWxpDo-MtseddQ5BHyfHgDBrpFxdUPSuJFBeLrvmkVPHP3yi4ymOKycSSHpp858KG2wjGu1bSGIIwG1AJfMcLl7o3ONrNItqpkbtRj1c1lzBbtQ_XVNSNaojVJMokSUG0bMdcp2FAlYDW-pcZRMoJqnYK8BUhyxD7Ywwo"

func killCLessMainPk(t *testing.T) []byte {
	t.Helper()
	var doc struct {
		Keys map[string]struct {
			PqPk string `json:"pq_pk"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(mustRead(t, dir+"less-vectors.json"), &doc); err != nil {
		t.Fatal(err)
	}
	pk, ok := DecodeB64uStrict(doc.Keys["main"].PqPk, lessPublicKeyBytes)
	if !ok {
		t.Fatal("main pq_pk")
	}
	return pk
}

// cgoLessCat1Verify: a valid signature over a one-byte message verifies (and only over that message); a wrong-length
// key or signature is refused before the C reference.
func TestKillCLessCgoVerify(t *testing.T) {
	pk := killCLessMainPk(t)
	sig, ok := DecodeB64uStrict(killCLessOneByteSig, -1)
	if !ok || len(sig) != 1313 {
		t.Fatal("embedded sig")
	}
	if !cgoLessCat1Verify(pk, []byte("x"), sig) {
		t.Fatal("valid LESS signature over a 1-byte message refused")
	}
	if cgoLessCat1Verify(pk, []byte("y"), sig) || cgoLessCat1Verify(pk, nil, sig) {
		t.Fatal("LESS signature verified over another message")
	}
	if cgoLessCat1Verify(pk[:len(pk)-1], []byte("x"), sig) {
		t.Fatal("short LESS key accepted")
	}
	if cgoLessCat1Verify(pk, []byte("x"), sig[:len(sig)-1]) {
		t.Fatal("wrong-length LESS signature accepted")
	}
	// the suite dispatch end to end (pure suite, variable-length sig through the wire rule)
	art := map[string]any{"alg": "less-cat1", "sig": killCLessOneByteSig, "pq_pk": b64.EncodeToString(pk)}
	if r := validateSignatureWire(art); r != "" {
		t.Fatalf("wire: %s", r)
	}
	if !verifyLeafSuite("less-cat1", true, "", callerVouchedPqKey(art["pq_pk"]), []byte("x"), art["sig"], nil) {
		t.Fatal("verifyLeafSuite refused the 1-byte-message LESS signature")
	}
}
