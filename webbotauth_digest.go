package pca

// RFC 9530 Content-Digest for Web Bot Auth: the field is a Structured Field Dictionary of hash algorithm names to byte sequences
// (`:base64:`) over the message content. Only the two algorithms the RFC marks Active, sha-256 and sha-512, are produced or
// accepted; the deprecated ones are never accepted. Cover `content-digest` in the signature (coverHeaders) so the signature
// protects the body too. Verification fails closed: a malformed field, a mismatching digest for any supported algorithm, or no
// supported algorithm at all is {"valid": false, "reason": ...}.

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// WebBotAuthContentDigestHeaderName is the Content-Digest field name.
const WebBotAuthContentDigestHeaderName = "Content-Digest"

// WebBotAuthContentDigestAlgs are the accepted digest algorithms, in verification order.
var WebBotAuthContentDigestAlgs = []string{"sha-256", "sha-512"}

var wbaDigestMemberRe = regexp.MustCompile(`^([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):$`)

func wbaBodyBytes(body any) ([]byte, error) {
	switch b := body.(type) {
	case string:
		return wbaUTF8(b), nil
	case []byte:
		return b, nil
	}
	return nil, errors.New("the body must be a string or bytes")
}

// WebBotAuthContentDigestBytes is the raw digest of body (a string, read as UTF-8, or bytes) under alg ("sha-256" or "sha-512").
func WebBotAuthContentDigestBytes(body any, alg string) ([]byte, error) {
	b, err := wbaBodyBytes(body)
	if err != nil {
		return nil, err
	}
	switch alg {
	case "sha-256":
		d := sha256.Sum256(b)
		return d[:], nil
	case "sha-512":
		d := sha512.Sum512(b)
		return d[:], nil
	}
	return nil, errors.New("unsupported digest algorithm")
}

// WebBotAuthContentDigestHeaderValue builds the Content-Digest field value, e.g. `sha-256=:X48E9q...=:`, with the members in the
// given order and repeats dropped. algs nil is ["sha-256"]; an empty list refuses.
func WebBotAuthContentDigestHeaderValue(body any, algs []string) (string, error) {
	if algs == nil {
		algs = []string{"sha-256"}
	}
	if len(algs) == 0 {
		return "", errors.New("contentDigestHeader: name at least one algorithm")
	}
	seen := map[string]bool{}
	var parts []string
	for _, alg := range algs {
		if alg != "sha-256" && alg != "sha-512" {
			return "", fmt.Errorf("contentDigestHeader: unsupported algorithm %s", alg)
		}
		if seen[alg] {
			continue
		}
		seen[alg] = true
		d, err := WebBotAuthContentDigestBytes(body, alg)
		if err != nil {
			return "", err
		}
		parts = append(parts, alg+"=:"+base64.StdEncoding.EncodeToString(d)+":")
	}
	return strings.Join(parts, ", "), nil
}

// WebBotAuthParseContentDigest parses the dictionary into key -> byte sequence. Anything that is not `key=:base64:` refuses
// (parameters, non-canonical base64 and a repeated key included).
func WebBotAuthParseContentDigest(value string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, raw := range strings.Split(value, ",") {
		member := wbaTrim(raw)
		if len(member) == 0 {
			return nil, errors.New("empty dictionary member")
		}
		m := wbaDigestMemberRe.FindStringSubmatch(member)
		if m == nil {
			return nil, fmt.Errorf(`malformed Content-Digest member "%s"`, member)
		}
		key, enc := m[1], m[2]
		if len(enc)%4 != 0 {
			return nil, fmt.Errorf(`member "%s" is not canonical base64`, key)
		}
		data := wbaNodeB64(enc)
		if base64.StdEncoding.EncodeToString(data) != enc {
			return nil, fmt.Errorf(`member "%s" is not canonical base64`, key)
		}
		// RFC 8941 lets a repeated key override the earlier one; a digest field with two values for one algorithm is ambiguous
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf(`member "%s" appears twice`, key)
		}
		out[key] = data
	}
	return out, nil
}

// WebBotAuthVerifyContentDigest checks body against a Content-Digest field value (nil header = absent). Every supported member
// present must match (one mismatch fails the whole field); unsupported members are ignored, as RFC 9530 section 2 allows; at
// least one supported member must be present; and every algorithm in require must be among the matched ones.
func WebBotAuthVerifyContentDigest(header *string, body any, require []string) map[string]any {
	fail := func(reason string) map[string]any { return map[string]any{"valid": false, "reason": reason} }
	if header == nil || wbaTrim(*header) == "" {
		return fail("missing Content-Digest")
	}
	members, err := WebBotAuthParseContentDigest(*header)
	if err != nil {
		return fail("malformed Content-Digest: " + err.Error())
	}
	matched := []any{}
	matchedSet := map[string]bool{}
	for _, alg := range WebBotAuthContentDigestAlgs {
		got, has := members[alg]
		if !has {
			continue
		}
		want, err := WebBotAuthContentDigestBytes(body, alg)
		if err != nil {
			return fail("malformed Content-Digest: " + err.Error())
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return fail(alg + " digest does not match the content")
		}
		matched = append(matched, alg)
		matchedSet[alg] = true
	}
	if len(matched) == 0 {
		return fail("no supported digest algorithm (sha-256 or sha-512)")
	}
	for _, alg := range require {
		if !matchedSet[alg] {
			return fail("required " + alg + " digest is absent")
		}
	}
	return map[string]any{"valid": true, "matched": matched}
}
