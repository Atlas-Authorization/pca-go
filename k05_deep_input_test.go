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

const k05DeepHuge = 8 << 20

func k05DeepOpen(n int) string     { return strings.Repeat("[", n) }
func k05DeepBalanced(n int) string { return k05DeepOpen(n) + strings.Repeat("]", n) }

// k05DeepTLV is a DER element with a minimal length of any size (the shared test helper stops at two length bytes).
func k05DeepTLV(tag byte, body []byte) []byte {
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

// k05DeepDER is `levels` nested SEQUENCEs, built from the inside in one buffer.
func k05DeepDER(levels int) []byte {
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

// k05DeepRetag sets the tag of every level of a k05DeepDER chain.
func k05DeepRetag(b []byte, tag byte) []byte {
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

func TestK05DeepStrictJSON(t *testing.T) {
	for _, in := range []string{k05DeepOpen(100000), k05DeepBalanced(100000), k05DeepOpen(k05DeepHuge)} {
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
func TestK05DeepJSONLenient(t *testing.T) {
	for _, in := range []string{k05DeepOpen(100000), k05DeepBalanced(100000), k05DeepOpen(k05DeepHuge), k05DeepBalanced(10001)} {
		if _, err := jsonLenient([]byte(in)); err == nil || !strings.Contains(err.Error(), "exceeded max depth") {
			t.Fatalf("jsonLenient(%d bytes): %v", len(in), err)
		}
	}
	if _, err := jsonLenient([]byte(k05DeepBalanced(10000))); err != nil {
		t.Fatalf("10000 levels: %v", err)
	}
}

func TestK05DeepV8JSON(t *testing.T) {
	const eof = "Unexpected end of JSON input"
	for _, c := range []struct {
		in, want string
	}{
		{k05DeepOpen(100000), eof},
		{k05DeepOpen(MaxLenientDepth), eof},
		{k05DeepOpen(MaxLenientDepth + 1), "nesting too deep"},
		{k05DeepOpen(k05DeepHuge), "nesting too deep"},
		{k05DeepBalanced(100000), ""},
		{k05DeepBalanced(MaxLenientDepth), ""},
		{k05DeepBalanced(MaxLenientDepth + 1), "nesting too deep"},
		{strings.Repeat(`{"a":`, 1<<20), "nesting too deep"},
	} {
		if got := v8JSONError(c.in); got != c.want {
			t.Fatalf("v8JSONError(%d bytes) = %q, want %q", len(c.in), got, c.want)
		}
	}
}

// The token path: this is the route a crafted MAA or GCP token takes, before any signature check.
func TestK05DeepJWS(t *testing.T) {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	hdr := seg(`{"alg":"RS256"}`)
	for _, c := range []struct {
		token, want string
	}{
		{seg(k05DeepOpen(100000)) + "." + hdr + ".AA", "parseMaaJwt: malformed JSON segment: Unexpected end of JSON input"},
		{hdr + "." + seg(k05DeepOpen(100000)) + ".AA", "parseMaaJwt: malformed JSON segment: Unexpected end of JSON input"},
		{seg(k05DeepOpen(k05DeepHuge)) + "." + hdr + ".AA", "parseMaaJwt: malformed JSON segment: nesting too deep"},
		{hdr + "." + seg(k05DeepOpen(k05DeepHuge)) + ".AA", "parseMaaJwt: malformed JSON segment: nesting too deep"},
	} {
		if _, err := parseJWT(c.token, "parseMaaJwt"); err == nil || err.Error() != c.want {
			t.Fatalf("parseJWT(%d bytes): %v, want %q", len(c.token), err, c.want)
		}
	}
	// balanced: the engine parses it (the reference then says "header is not a JSON object"), the decoder refuses it: still a refusal
	if _, err := parseJWT(seg(k05DeepBalanced(100000))+"."+hdr+".AA", "parseMaaJwt"); err == nil {
		t.Fatal("balanced deep header accepted")
	}
}

// ParseJSONLenient also reads untrusted input (the list cursor, intent text): its cap holds, and so does every walk over what it allowed.
func TestK05DeepLenientPaths(t *testing.T) {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, in := range []string{k05DeepOpen(100000), k05DeepBalanced(100000), k05DeepOpen(k05DeepHuge)} {
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
func TestK05DeepWalksOverLenientValue(t *testing.T) {
	n := MaxLenientDepth - 1
	arr, err := ParseJSONLenient([]byte(k05DeepBalanced(n)))
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
func TestK05DeepCertDER(t *testing.T) {
	deep := k05DeepDER(1 << 20)
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

func TestK05DeepOCSP(t *testing.T) {
	f := g02newFx(t)
	verify := func(der []byte) ocspResult {
		return verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs)
	}
	wrapBasic := func(basic []byte) []byte {
		return k05DeepTLV(0x30, append(derTLV(0x0a, []byte{0}), k05DeepTLV(0xa0, k05DeepTLV(0x30, append(g02oid(oidOcspBasic), k05DeepTLV(0x04, basic)...)))...))
	}
	notDER, basicNotDER := ocspFail("response is not valid DER"), ocspFail("BasicOCSPResponse is not valid DER")
	alg := derTLV(0x30, g02oid("1.2.840.10045.4.3.2"))
	sig := derTLV(0x03, []byte{0})
	for _, n := range []int{102, 1000, 100000, 3 << 20, k05DeepHuge} {
		if got := verify(k05DeepDER(n)); got != notDER {
			t.Errorf("top %d levels: %+v", n, got)
		}
		// past 16 MiB the response itself is refused: its content limit applies to the OCTET STRING holding the basic response
		want := basicNotDER
		if n == k05DeepHuge {
			want = notDER
		}
		if got := verify(wrapBasic(k05DeepDER(n))); got != want {
			t.Errorf("basic %d levels: %+v", n, got)
		}
	}
	// a constructed UTF8String's content is not parsed, so it passes the parse check: the time walk must still stop
	opaque := k05DeepRetag(k05DeepDER(3<<20), 0x2c)
	if got := verify(wrapBasic(k05DeepTLV(0x30, append(append(k05DeepTLV(0x30, opaque), alg...), sig...)))); got.ok || got == basicNotDER {
		t.Errorf("deep constructed string: %+v", got)
	}
	// 101 levels pass the limit, as in asn1js, and are refused for their shape instead
	if got, want := verify(k05DeepDER(101)), g02rej("malformed OCSPResponse"); got != want {
		t.Errorf("top 101 levels: %+v", got)
	}
	if got, want := verify(wrapBasic(k05DeepDER(101))), g02rej("malformed BasicOCSPResponse"); got != want {
		t.Errorf("basic 101 levels: %+v", got)
	}
	// the limit is the nesting of any member, not of the first one
	if got := verify(wrapBasic(k05DeepTLV(0x30, append(append(k05DeepDER(101), alg...), sig...)))); got != basicNotDER {
		t.Errorf("deep first member: %+v", got)
	}
	if got := verify(wrapBasic(k05DeepTLV(0x30, append(append(k05DeepDER(100), alg...), sig...)))); got == basicNotDER {
		t.Error("100-level first member (101 in all) refused as nested too deep")
	}
	// a deep member of the OCSPResponse itself
	if got := verify(k05DeepTLV(0x30, append(derTLV(0x0a, []byte{0}), k05DeepDER(101)...))); got != notDER {
		t.Errorf("deep top member: %+v", got)
	}
	// the content of a primitive OCTET STRING is not nesting (asn1js swallows a failed parse of it too)
	if got := verify(k05DeepTLV(0x30, append(derTLV(0x0a, []byte{0}), k05DeepTLV(0x04, k05DeepDER(1<<20))...))); got == notDER {
		t.Errorf("deep content of a primitive refused as nesting: %+v", got)
	}
}

func TestK05DeepXML(t *testing.T) {
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
	const refused = "RIM: verification error (fail closed): XML nesting too deep"
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
	if got, why := verifyNvidiaRim("<SoftwareIdentity>"+nest(maxXMLDepth-1)+"</SoftwareIdentity>", []string{"x"}, 1); got != nil || why != "RIM: expected exactly one Signature element" {
		t.Errorf("deepest accepted document: %v %q", got, why)
	}
}
