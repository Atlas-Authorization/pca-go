package pca

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Deep nesting on every decoder that reads untrusted input. A Go stack overflow is fatal and recover cannot catch it, so a
// missing bound fails this file by killing the test binary. The effective stack limit is 512 MiB (the runtime doubles the
// stack and refuses 1 GiB), so 8M levels is past it for every walk here; 100k alone is not.
//
// Reference results (Node 26): JSON.parse is iterative (`[` x 8M is "Unexpected end of JSON input"; balanced parses). asn1js
// accepts 101 levels and refuses 102. xmldom parses 100k levels and the profile walk then overflows a catchable stack,
// "RIM: verification error (fail closed): Maximum call stack size exceeded".

const baseDeepHuge = 8 << 20

func baseDeepOpen(n int) string     { return strings.Repeat("[", n) }
func baseDeepBalanced(n int) string { return baseDeepOpen(n) + strings.Repeat("]", n) }

// baseDeepTLV is a DER element with a minimal length of any size (the shared test helper stops at two length bytes).
func baseDeepTLV(tag byte, body []byte) []byte {
	n := len(body)
	if n < 0x80 {
		return append([]byte{tag, byte(n)}, body...)
	}
	var l []byte
	for m := n; m > 0; m >>= 8 {
		l = append([]byte{byte(m)}, l...)
	}
	return append(append([]byte{tag, 0x80 | byte(len(l))}, l...), body...)
}

// baseDeepDER is `levels` nested SEQUENCEs, built from the inside in one buffer.
func baseDeepDER(levels int) []byte {
	b := make([]byte, levels*6)
	p := len(b)
	for i := 0; i < levels; i++ {
		n := len(b) - p
		if n < 0x80 {
			p--
			b[p] = byte(n)
		} else {
			k := 0
			for m := n; m > 0; m >>= 8 {
				p--
				b[p] = byte(m)
				k++
			}
			p--
			b[p] = 0x80 | byte(k)
		}
		p--
		b[p] = 0x30
	}
	return b[p:]
}

// baseDeepRetag sets the tag of every level of a baseDeepDER chain.
func baseDeepRetag(b []byte, tag byte) []byte {
	for i := 0; i < len(b); {
		tv, err := tlvAt(b, i)
		if err != nil {
			panic(err)
		}
		b[i] = tag
		i = tv.start
	}
	return b
}

func TestBaseDeepStrictJSON(t *testing.T) {
	for _, in := range []string{baseDeepOpen(100000), baseDeepBalanced(100000), baseDeepOpen(baseDeepHuge)} {
		if _, err := StrictParse(in); err == nil {
			t.Fatal("StrictParse accepted deep input")
		}
		if _, err := ParseJSON([]byte(in)); err == nil {
			t.Fatal("ParseJSON accepted deep input")
		}
		if _, err := ParsePCActn(in); err == nil {
			t.Fatal("ParsePCActn accepted deep input")
		}
	}
}

// encoding/json refuses past its own 10000 limit, on every path, before anything recurses over the value.
func TestBaseDeepJSONLenient(t *testing.T) {
	for _, in := range []string{baseDeepOpen(100000), baseDeepBalanced(100000), baseDeepOpen(baseDeepHuge), baseDeepBalanced(10001)} {
		if _, err := jsonLenient([]byte(in)); err == nil || !strings.Contains(err.Error(), "exceeded max depth") {
			t.Fatalf("jsonLenient(%d bytes): %v", len(in), err)
		}
	}
	if _, err := jsonLenient([]byte(baseDeepBalanced(10000))); err != nil {
		t.Fatalf("10000 levels: %v", err)
	}
}

func TestBaseDeepV8JSON(t *testing.T) {
	const eof = "Unexpected end of JSON input"
	for _, c := range []struct {
		in, want string
	}{
		{baseDeepOpen(100000), eof},
		{baseDeepOpen(MaxLenientDepth), eof},
		{baseDeepOpen(MaxLenientDepth + 1), "nesting too deep"},
		{baseDeepOpen(baseDeepHuge), "nesting too deep"},
		{baseDeepBalanced(100000), ""},
		{baseDeepBalanced(MaxLenientDepth), ""},
		{baseDeepBalanced(MaxLenientDepth + 1), "nesting too deep"},
		{strings.Repeat(`{"a":`, 1<<20), "nesting too deep"},
	} {
		if got := v8JSONError(c.in); got != c.want {
			t.Fatalf("v8JSONError(%d bytes) = %q, want %q", len(c.in), got, c.want)
		}
	}
}

// The token path: this is the route a crafted MAA or GCP token takes, before any signature check. The strict profile refuses all of
// these as "invalid JSON" (the engine's own wording is no longer reported).
func TestBaseDeepJWS(t *testing.T) {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	hdr := seg(`{"alg":"RS256"}`)
	for _, c := range []struct {
		token, want string
	}{
		{seg(baseDeepOpen(100000)) + "." + hdr + ".AA", "parseMaaJwt: malformed JSON segment: invalid JSON"},
		{hdr + "." + seg(baseDeepOpen(100000)) + ".AA", "parseMaaJwt: malformed JSON segment: invalid JSON"},
		{seg(baseDeepOpen(baseDeepHuge)) + "." + hdr + ".AA", "parseMaaJwt: malformed JSON segment: invalid JSON"},
		{hdr + "." + seg(baseDeepOpen(baseDeepHuge)) + ".AA", "parseMaaJwt: malformed JSON segment: invalid JSON"},
	} {
		if _, err := parseJWT(c.token, "parseMaaJwt"); err == nil || err.Error() != c.want {
			t.Fatalf("parseJWT(%d bytes): %v, want %q", len(c.token), err, c.want)
		}
	}
	// balanced: the engine parses it (the reference then says "header is not a JSON object"), the decoder refuses it: still a refusal
	if _, err := parseJWT(seg(baseDeepBalanced(100000))+"."+hdr+".AA", "parseMaaJwt"); err == nil {
		t.Fatal("balanced deep header accepted")
	}
}

// ParseJSONLenient also reads untrusted input (the list cursor, intent text): its cap holds, and so does every walk over what it allowed.
func TestBaseDeepLenientPaths(t *testing.T) {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, in := range []string{baseDeepOpen(100000), baseDeepBalanced(100000), baseDeepOpen(baseDeepHuge)} {
		if got := VerifyListCursor(seg(in)+".AA", "k", nil); got.OK || got.Reason != "malformed" {
			t.Fatalf("cursor(%d bytes): %+v", len(in), got)
		}
		if _, err := IntentPolicyFromJSONText(in); err == nil {
			t.Fatalf("intent policy(%d bytes) accepted", len(in))
		}
		if _, err := IntentV2ContextFromJSONText(in); err == nil {
			t.Fatalf("intent context(%d bytes) accepted", len(in))
		}
	}
	// an object is accepted and normalised: the walk over 100k levels must return
	obj := strings.Repeat(`{"a":`, 100000) + "1" + strings.Repeat("}", 100000)
	if _, err := IntentV2ContextFromJSONText(obj); err != nil {
		t.Fatalf("deep context object: %v", err)
	}
}

// The recursive walks at the deepest value the lenient loader can produce.
func TestBaseDeepWalksOverLenientValue(t *testing.T) {
	n := MaxLenientDepth - 1
	arr, err := ParseJSONLenient([]byte(baseDeepBalanced(n)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Canonicalize(arr); err == nil {
		t.Fatal("Canonicalize accepted a value past MaxJSONDepth")
	}
	normalizeJSON(arr)
	deepCopy(arr)
	jsValueString(arr)
	serLenient(&strings.Builder{}, arr)
	scanSlots(arr, map[string]any{}, map[string]bool{})
	cond, err := ParseJSONLenient([]byte(strings.Repeat(`{"all_of":[`, n/2) + "{}" + strings.Repeat("]}", n/2)))
	if err != nil {
		t.Fatal(err)
	}
	if evaluateConditionTri(cond, map[string]any{}, &regexBudget{}) == triTrue {
		t.Fatal("deep condition evaluated true")
	}
	if VerifyThresholdShare(map[string]any{"role": "agent", "t": 1, "signer_set": []any{arr}, "threshold_message": "AA", "share": arr}) {
		t.Fatal("deep share accepted")
	}
	if ValidateWireV2(map[string]any{"ver": arr}) == "" {
		t.Fatal("deep wire accepted")
	}
}

// The DER readers of the attestation chains are iterative: they read a fixed number of levels and never descend further.
func TestBaseDeepCertDER(t *testing.T) {
	deep := baseDeepDER(1 << 20)
	if _, err := parseCertDER(deep); err == nil {
		t.Fatal("parseCertDER accepted nested SEQUENCEs")
	}
	if from, to := derValidity(deep); from.ok || to.ok {
		t.Fatal("derValidity read a window from nested SEQUENCEs")
	}
	// nesting is a well-formed shape for these: the point is that they return
	_, _ = tbsOfCertificate(deep)
	_, _ = parseTbsExtensions(deep)
	_, _ = readCertRoleInfo(deep)
	_, _, _ = unrecognisedCriticalExtension(deep, nil)
}

func TestBaseDeepOCSP(t *testing.T) {
	f := g02newFx(t)
	verify := func(der []byte) ocspResult {
		return verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs)
	}
	wrapBasic := func(basic []byte) []byte {
		return baseDeepTLV(0x30, append(derTLV(0x0a, []byte{0}), baseDeepTLV(0xa0, baseDeepTLV(0x30, append(g02oid(oidOcspBasic), baseDeepTLV(0x04, basic)...)))...))
	}
	notDER, basicNotDER := ocspFail("response is not valid DER"), ocspFail("BasicOCSPResponse is not valid DER")
	alg := derTLV(0x30, g02oid("1.2.840.10045.4.3.2"))
	sig := derTLV(0x03, []byte{0})
	for _, n := range []int{102, 1000, 100000, 3 << 20, baseDeepHuge} {
		if got := verify(baseDeepDER(n)); got != notDER {
			t.Errorf("top %d levels: %+v", n, got)
		}
		// past 16 MiB the response itself is refused: its content limit applies to the OCTET STRING holding the basic response
		want := basicNotDER
		if n == baseDeepHuge {
			want = notDER
		}
		if got := verify(wrapBasic(baseDeepDER(n))); got != want {
			t.Errorf("basic %d levels: %+v", n, got)
		}
	}
	// a constructed UTF8String's content is not parsed, so it passes the parse check: the time walk must still stop
	opaque := baseDeepRetag(baseDeepDER(3<<20), 0x2c)
	if got := verify(wrapBasic(baseDeepTLV(0x30, append(append(baseDeepTLV(0x30, opaque), alg...), sig...)))); got.ok || got == basicNotDER {
		t.Errorf("deep constructed string: %+v", got)
	}
	// 101 levels pass the limit, as in asn1js, and are refused for their shape instead
	if got, want := verify(baseDeepDER(101)), g02rej("malformed OCSPResponse"); got != want {
		t.Errorf("top 101 levels: %+v", got)
	}
	if got, want := verify(wrapBasic(baseDeepDER(101))), g02rej("malformed BasicOCSPResponse"); got != want {
		t.Errorf("basic 101 levels: %+v", got)
	}
	// the limit is the nesting of any member, not of the first one
	if got := verify(wrapBasic(baseDeepTLV(0x30, append(append(baseDeepDER(101), alg...), sig...)))); got != basicNotDER {
		t.Errorf("deep first member: %+v", got)
	}
	if got := verify(wrapBasic(baseDeepTLV(0x30, append(append(baseDeepDER(100), alg...), sig...)))); got == basicNotDER {
		t.Error("100-level first member (101 in all) refused as nested too deep")
	}
	// a deep member of the OCSPResponse itself
	if got := verify(baseDeepTLV(0x30, append(derTLV(0x0a, []byte{0}), baseDeepDER(101)...))); got != notDER {
		t.Errorf("deep top member: %+v", got)
	}
	// the content of a primitive OCTET STRING is not nesting (asn1js swallows a failed parse of it too)
	if got := verify(baseDeepTLV(0x30, append(derTLV(0x0a, []byte{0}), baseDeepTLV(0x04, baseDeepDER(1<<20))...))); got == notDER {
		t.Errorf("deep content of a primitive refused as nesting: %+v", got)
	}
}

func TestBaseDeepXML(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("<a>", n) + strings.Repeat("</a>", n) }
	if _, err := parseXML(nest(maxXMLDepth)); err != nil {
		t.Fatalf("%d levels: %v", maxXMLDepth, err)
	}
	if _, err := parseXML(nest(maxXMLDepth + 1)); err == nil || err.Error() != "XML nesting too deep" {
		t.Fatalf("%d levels: %v", maxXMLDepth+1, err)
	}
	// closing an element gives its level back: width is not depth
	if _, err := parseXML("<r>" + strings.Repeat("<a></a>", 2*maxXMLDepth) + "</r>"); err != nil {
		t.Fatalf("wide: %v", err)
	}
	// a self-closed child of the deepest element opens nothing
	if _, err := parseXML(strings.Repeat("<a>", maxXMLDepth) + "<b/>" + strings.Repeat("</a>", maxXMLDepth)); err != nil {
		t.Fatalf("self-closed at the limit: %v", err)
	}
	// the deepest walkers run on what the cap lets through
	doc, err := parseXML("<r>" + strings.Repeat("<a>", maxXMLDepth-1) + "t" + strings.Repeat("</a>", maxXMLDepth-1) + "</r>")
	if err != nil {
		t.Fatal(err)
	}
	if doc.root.textContent() != "t" || doc.root.descendantsNS("", "a") != maxXMLDepth-1 || canonicalize(doc.root, map[string]string{}, nil) == "" {
		t.Fatal("walk over the deepest accepted document")
	}
	const refused = "RIM: verification error (fail closed): XML nesting is too deep" // the reference's pre-scan wording
	for _, c := range []struct {
		name, xml string
	}{
		{"100k", "<SoftwareIdentity>" + nest(100000) + "</SoftwareIdentity>"},
		{"most the size limit allows", "<SoftwareIdentity>" + nest(570000) + "</SoftwareIdentity>"},
		{"unclosed", strings.Repeat("<a>", 1300000)},
	} {
		if got, why := verifyNvidiaRim(c.xml, []string{"x"}, 1); got != nil || why != refused {
			t.Errorf("%s: %v %q", c.name, got, why)
		}
	}
	// the reference admits 64 open elements and refuses the 65th before parsing
	if got, why := verifyNvidiaRim("<SoftwareIdentity>"+nest(rimMaxXMLDepth-1)+"</SoftwareIdentity>", []string{"x"}, 1); got != nil || why != "RIM: expected exactly one Signature element" {
		t.Errorf("deepest accepted document: %v %q", got, why)
	}
	if got, why := verifyNvidiaRim("<SoftwareIdentity>"+nest(rimMaxXMLDepth)+"</SoftwareIdentity>", []string{"x"}, 1); got != nil || why != refused {
		t.Errorf("one level too deep: %v %q", got, why)
	}
}
