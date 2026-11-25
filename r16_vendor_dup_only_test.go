package pca

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// The vendor attestation parsers use the duplicate-only check: a repeated member is refused, numbers stay as written (a genuine
// vendor document is not canonical JSON) and the 16 MiB bound holds.

func TestAzureRuntimeDataRefusesARepeatedMember(t *testing.T) {
	reportFor := func(runtime []byte) []byte {
		sum := sha256.Sum256(runtime)
		return append(sum[:], make([]byte, 32)...)
	}
	check := func(runtime string) string {
		return checkAzureRuntimeDataBinding(reportFor([]byte(runtime)), []byte(runtime), &AttestationBinding{})
	}
	if got := check(`{"user-data":"x","user-data":"y"}`); got != "runtime data is not valid JSON" {
		t.Errorf("a repeated member: %q", got)
	}
	if got := check(`not json`); got != "runtime data is not valid JSON" {
		t.Errorf("not json: %q", got)
	}
	// numbers as written: the document parses and fails later, on its own claims
	if got := check(`{"n":1e3,"m":8.0,"k":-0}`); got != "runtime data carries no 64-byte hex user-data" {
		t.Errorf("non-canonical numbers: %q", got)
	}
}

func TestIntelSignedDocumentBoundsAndNumbers(t *testing.T) {
	// 16 MiB is the bound: one byte over is refused with the reference's words
	over := `{"tcbInfo":{"a":"` + strings.Repeat("a", maxLenientJSONBytes) + `"},"signature":""}`
	if _, why := verifySignedJSON(over, "tcbInfo", certKey{}); why != "tcbInfo: malformed JSON segment: input too large" {
		t.Errorf("over the bound: %q", why)
	}
	// a document written with 1e3 and 8.0 is not refused as JSON (it fails later, on its signature)
	doc := `{"tcbInfo":{"a":1e3,"b":8.0},"signature":"` + strings.Repeat("0", 128) + `"}`
	if _, why := verifySignedJSON(doc, "tcbInfo", certKey{}); why == "tcbInfo document is not valid JSON" {
		t.Errorf("non-canonical numbers must be read: %q", why)
	}
	if _, why := verifySignedJSON(strings.Replace(doc, `"b":8.0`, `"b":8.0,"a":2`, 1), "tcbInfo", certKey{}); why != "tcbInfo document is not valid JSON" {
		t.Errorf("a repeated member: %q", why)
	}
}
