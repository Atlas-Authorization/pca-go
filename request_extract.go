package pca

import (
	"net/http"
	"strings"
)

// PcaRequest is the framework-agnostic request shape of the default extractors: anything with headers and, optionally, a
// parsed or raw body.
type PcaRequest struct {
	// Headers: field names are case-insensitive (RFC 9110 section 5.1). A name that appears in several case variants with DIFFERENT
	// first values is ambiguous and reads as absent (the caller then denies), never silently as one of them.
	Headers map[string][]string
	// Body is the raw body text (string or []byte, parsed with the strict JSON profile) or an already parsed JSON value.
	Body any
}

// PcaRequestFromHTTP builds a PcaRequest from an *http.Request and its (already read) body bytes (nil: none).
func PcaRequestFromHTTP(r *http.Request, body []byte) PcaRequest {
	req := PcaRequest{Headers: map[string][]string(r.Header)}
	if body != nil {
		req.Body = string(body)
	}
	return req
}

func (r PcaRequest) header(name string) (string, bool) {
	want := strings.ToLower(name)
	found, have := "", false
	for k, vs := range r.Headers {
		if strings.ToLower(k) != want || len(vs) == 0 {
			continue
		}
		if have && found != vs[0] {
			return "", false
		}
		found, have = vs[0], true
	}
	return found, have
}

// body returns the body as a parsed value: a string or []byte body is parsed with the strict JSON profile (ok false when it does
// not parse); anything else is used as is.
func (r PcaRequest) bodyValue() (any, bool) {
	switch b := r.Body.(type) {
	case string:
		v, err := StrictParse(b)
		return v, err == nil
	case []byte:
		v, err := StrictParse(string(b))
		return v, err == nil
	}
	return r.Body, true
}

// DefaultExtract is the default PCActn extraction: the `PCA-Action: <base64url PCActn JSON>` header, else a JSON body {"pcactn": ...}.
// A header is decoded with the strict unpadded base64url profile (a malformed one is an error, which the guard turns into a 401) and
// returned as its JSON text. A STRING body is parsed with the strict JSON profile, like the header path (byte-distinct bodies never
// verify as the same signed PCActn): one that is not strict JSON yields nil (deny). An already parsed body has lost its spelling:
// send the PCActn as a string. The result is the PCActn object (map[string]any) or its JSON text; nil is "none presented".
func DefaultExtract(req PcaRequest) (any, error) {
	if h, ok := req.header(PCAHeader); ok && h != "" {
		return DecodePCAHeader(h)
	}
	b, ok := req.bodyValue()
	if !ok {
		return nil, nil
	}
	m, _ := b.(map[string]any)
	switch x := m["pcactn"].(type) {
	case string:
		return x, nil
	case map[string]any:
		return x, nil
	}
	return nil, nil
}

// DefaultProvenanceBundle is the default provenance-bundle extraction: the `PCA-Provenance` header (strict base64url JSON), else the
// body member pca_provenance. A malformed header is an error; an unparsable body is no bundle (nil).
func DefaultProvenanceBundle(req PcaRequest) (any, error) {
	if h, ok := req.header(ProvenanceHeader); ok && h != "" {
		raw, err := DecodePCAHeader(h)
		if err != nil {
			return nil, err
		}
		return StrictParse(raw)
	}
	b, ok := req.bodyValue()
	if !ok {
		return nil, nil
	}
	m, _ := b.(map[string]any)
	return m["pca_provenance"], nil
}
