package pca

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// StrictParseBytes decodes UTF-8 bytes (invalid sequences refused, no BOM stripping) and parses them under the strict profile.
// Every deviation is a *StrictJsonError.
func StrictParseBytes(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, &StrictJsonError{Message: "input is not valid UTF-8", whole: "strict JSON: input is not valid UTF-8 (at offset 0)"}
	}
	return StrictParse(string(b))
}

// CanonicalJwsError is a refusal of the canonical compact-JWS gate: Reason is one of not-a-string, too-long, bad-segment-count,
// bad-character, empty-segment, non-canonical-base64url, bad-utf8, bom, bad-json, not-an-object.
type CanonicalJwsError struct {
	Reason string
	Detail string
}

func (e *CanonicalJwsError) Error() string {
	if e.Detail != "" {
		return "non-canonical compact JWS: " + e.Reason + " (" + e.Detail + ")"
	}
	return "non-canonical compact JWS: " + e.Reason
}

// AsCanonicalJwsError recovers the typed refusal from an error the canonical gate returned.
func AsCanonicalJwsError(err error) (*CanonicalJwsError, bool) {
	var typed *CanonicalJwsError
	if errors.As(err, &typed) {
		return typed, true
	}
	if err == nil {
		return nil, false
	}
	rest, ok := strings.CutPrefix(err.Error(), "non-canonical compact JWS: ")
	if !ok {
		return nil, false
	}
	reason, detail, _ := strings.Cut(rest, " (")
	return &CanonicalJwsError{Reason: reason, Detail: strings.TrimSuffix(detail, ")")}, true
}

// IsCanonicalCompactJws reports whether token is the one canonical spelling of a compact JWS (parts 3 or 5; maxBytes 0 = the
// default cap; jsonPayload parses a 3-part payload as a strict JSON object).
func IsCanonicalCompactJws(token any, parts, maxBytes int, jsonPayload bool) bool {
	_, err := AssertCanonicalCompactJWS(token, parts, maxBytes, jsonPayload)
	return err == nil
}

// DecodeCanonicalJsonSegment decodes one canonical base64url segment that holds a strict-JSON document of any type (an SD-JWT
// disclosure). It returns a *CanonicalJwsError on any deviation.
func DecodeCanonicalJsonSegment(seg string) (any, error) {
	b, err := decodeCanonicalBase64url(seg)
	if err != nil {
		return nil, err
	}
	return jwsJSONSegment(b)
}

// AssertCanonicalJwsSegments is the canonical gate for the protected and signature segments of a flattened or detached JWS
// (the payload travels out of band). It returns the parsed protected header.
func AssertCanonicalJwsSegments(protected, signature any, maxBytes int) (map[string]any, error) {
	p, ok1 := protected.(string)
	s, ok2 := signature.(string)
	if !ok1 || !ok2 {
		return nil, &CanonicalJwsError{Reason: "not-a-string"}
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxJWSBytes
	}
	if utf16Len(p)+utf16Len(s) > maxBytes {
		return nil, &CanonicalJwsError{Reason: "too-long"}
	}
	if p == "" || s == "" {
		return nil, &CanonicalJwsError{Reason: "empty-segment"}
	}
	pb, err := decodeCanonicalBase64url(p)
	if err != nil {
		return nil, err
	}
	h, err := jwsJSONSegment(pb)
	if err != nil {
		return nil, err
	}
	hm, ok := h.(map[string]any)
	if !ok {
		return nil, &CanonicalJwsError{Reason: "not-an-object"}
	}
	if _, err := decodeCanonicalBase64url(s); err != nil {
		return nil, err
	}
	return hm, nil
}
