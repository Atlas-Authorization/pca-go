package pca

// g04 mutation kills for attest_xml.go (the RIM XML reader and canonicaliser): every decode / parse / start-tag branch
// pinned to its exact output or error text, plus the canonical form's namespace and attribute ordering rules.

import (
	"strings"
	"testing"
)

func TestG04XMLDecode(t *testing.T) {
	ok := map[string]string{
		"":                          "",
		"plain":                     "plain",
		"a&amp;b":                   "a&b",
		"&amp;xy":                   "&xy",
		"&lt;&gt;&amp;&quot;&apos;": "<>&\"'",
		"&#65;":                     "A",
		"x&#65;y":                   "xAy",
		"&#x41;":                    "A",
		"&#x4a;":                    "J",
		"&#9;":                      "\t",
		"&#x9;":                     "\t",
		"&#xA;":                     "\n",
		"&#xD;":                     "\r",
		"&#x20;":                    " ",
		"&#xD7FF;":                  "퟿",
		"&#xE000;":                  "",
		"&#xFFFD;":                  "�",
		"&#x10000;":                 "\U00010000",
		"&#x10FFFF;":                "\U0010ffff",
		"&#000065;":                 "A", // leading zeros are legal XML 1.0; the reference accepts them
		"&#x0041;":                  "A",
	}
	for in, want := range ok {
		got, err := xmlDecode(in)
		if err != nil || got != want {
			t.Errorf("xmlDecode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"a&b":            "unterminated entity reference",
		"&amp":           "unterminated entity reference",
		"&foo;":          "undefined entity &foo;",
		"x&nbsp;":        "undefined entity &nbsp;",
		"&#;":            "invalid character reference &#;",
		"&#x;":           "invalid character reference &#x;",
		"&#X41;":         "invalid character reference &#X41;",
		"&#+65;":         "invalid character reference &#+65;",
		"&#x+41;":        "invalid character reference &#x+41;",
		"&#-65;":         "invalid character reference &#-65;",
		"&# 65;":         "invalid character reference &# 65;",
		"&#99999999999;": "invalid character reference &#99999999999;",
		"&#x-1;":         "invalid character reference &#x-1;",
		"&#x-FFFFFFBF;":  "invalid character reference &#x-FFFFFFBF;",
		"&#-4294967231;": "invalid character reference &#-4294967231;",
		"&#0;":           "invalid character reference &#0;",
		"&#1;":           "invalid character reference &#1;",
		"&#x1;":          "invalid character reference &#x1;",
		"&#x8;":          "invalid character reference &#x8;",
		"&#xB;":          "invalid character reference &#xB;",
		"&#xC;":          "invalid character reference &#xC;",
		"&#xE;":          "invalid character reference &#xE;",
		"&#x1F;":         "invalid character reference &#x1F;",
		"&#xD800;":       "invalid character reference &#xD800;",
		"&#xDFFF;":       "invalid character reference &#xDFFF;",
		"&#xFFFE;":       "invalid character reference &#xFFFE;",
		"&#xFFFF;":       "invalid character reference &#xFFFF;",
		"&#x110000;":     "invalid character reference &#x110000;",
		"&#x7FFFFFFF;":   "invalid character reference &#x7FFFFFFF;",
		"&#x80000000;":   "invalid character reference &#x80000000;",
	}
	for in, want := range bad {
		got, err := xmlDecode(in)
		if err == nil || err.Error() != want || got != "" {
			t.Errorf("xmlDecode(%q) = %q, %v; want error %q", in, got, err, want)
		}
	}
}

func TestG04XMLNames(t *testing.T) {
	for in, want := range map[string][2]string{":a": {"", "a"}, "p:a": {"p", "a"}, "a": {"", "a"}, "p:": {"p", ""}} {
		if p, l := splitQName(in); p != want[0] || l != want[1] {
			t.Errorf("splitQName(%q) = %q %q", in, p, l)
		}
	}
	root := &xmlNode{elem: true, decls: []xmlDecl{{"a", "ua"}, {"b", "ub"}}}
	child := &xmlNode{elem: true, parent: root, decls: []xmlDecl{{"", "ud"}}}
	if u, ok := child.lookupNS("b"); !ok || u != "ub" {
		t.Errorf("lookup b: %q %v", u, ok)
	}
	if u, ok := child.lookupNS(""); !ok || u != "ud" {
		t.Errorf("lookup default: %q %v", u, ok)
	}
	if u, ok := child.lookupNS("c"); ok || u != "" {
		t.Errorf("lookup unbound: %q %v", u, ok)
	}
}

// g04xParse parses s and fails unless the error text is exactly want ("" = success, doc returned).
func g04xParse(t *testing.T, s, want string) *xmlDoc {
	t.Helper()
	doc, err := parseXML(s)
	if want == "" {
		if err != nil || doc == nil || doc.root == nil {
			t.Fatalf("parseXML(%q): %v", s, err)
		}
		return doc
	}
	if err == nil || err.Error() != want || doc != nil {
		t.Fatalf("parseXML(%q) = %v, %v; want error %q", s, doc, err, want)
	}
	return nil
}

func TestG04XMLParseErrors(t *testing.T) {
	for s, want := range map[string]string{
		"x<a/>":                   "text outside the document element",
		"<a/>x":                   "text outside the document element",
		"<a>&foo;</a>":            "undefined entity &foo;",
		"<a/><!-- x":              "unterminated comment",
		"<a/><?x":                 "unterminated processing instruction",
		"<![CDATA[x]]><a/>":       "misplaced or unterminated CDATA section",
		"<a><![CDATA[x</a>":       "misplaced or unterminated CDATA section",
		"<a/><!DOCTYPE a":         "unterminated DOCTYPE",
		"<!DOCTYPE a [ <a/>":      "unterminated DOCTYPE",
		"</a>":                    "unexpected end tag",
		"<a></a":                  "unexpected end tag",
		"<a></b>":                 "end tag </b> does not match <a>",
		"<a x></a>":               "malformed attribute",
		"<a/><b/>":                "more than one document element",
		"<p:a/>":                  "namespace prefix p is not bound",
		"<a p:b='1'/>":            "namespace prefix p is not bound",
		"<a>":                     "element <a> is not closed",
		"<a><b></b>":              "element <a> is not closed",
		"":                        "no document element",
		" \n\t\r ":                "no document element",
		"<!-- c -->":              "no document element",
		"<a":                      "unterminated start tag",
		"<a ":                     "unterminated start tag",
		"<a b='1'":                "unterminated start tag",
		"< a/>":                   "malformed start tag",
		"<a/":                     "malformed start tag",
		"<a/ >":                   "malformed start tag",
		"<a b":                    "malformed attribute",
		"<a b ":                   "malformed attribute",
		"<a b>":                   "malformed attribute",
		"<a =x>":                  "malformed attribute",
		"<a b=x/>":                "unquoted attribute value",
		"<a b=":                   "unquoted attribute value",
		"<a b= ":                  "unquoted attribute value",
		"<a b='x":                 "unterminated attribute value",
		"<a b='<'/>":              "'<' in an attribute value",
		"<a b='&foo;'/>":          "undefined entity &foo;",
		"<a b='1' b='2'/>":        "attribute b is repeated",
		"<a xml:lang='en'/>":      "namespace prefix xml is not bound",
		"<a b='&#x+41;'/>":        "invalid character reference &#x+41;",
		"<a>&#xFFFE;</a>":         "invalid character reference &#xFFFE;",
		"<a><![CDATA[x]]></a><b>": "more than one document element",
	} {
		g04xParse(t, s, want)
	}
}

func TestG04XMLParseProlog(t *testing.T) {
	for s, viol := range map[string]string{
		"<a/>":                                    "",
		" \n<a/>\t ":                              "",
		"<!--abc--><a/>":                          "XML comments are not permitted",
		"<!----><a/>":                             "XML comments are not permitted",
		"<a><!--x--></a>":                         "XML comments are not permitted",
		`<?xml version="1.0"?><a/>`:               "XML processing instructions are not permitted",
		"<?x?><!--c--><a/>":                       "XML processing instructions are not permitted",
		"<!--c--><?x?><a/>":                       "XML comments are not permitted",
		"<!DOCTYPE a><a/>":                        "DTD / DOCTYPE is not permitted",
		`<!DOCTYPE a [<!ENTITY e "v">]><a/>`:      "DTD / DOCTYPE is not permitted",
		`<!DOCTYPE a [<!ENTITY e "v"> [x] ]><a/>`: "DTD / DOCTYPE is not permitted",
		"<!DOCTYPE a><!--c--><a/>":                "DTD / DOCTYPE is not permitted",
	} {
		doc := g04xParse(t, s, "")
		if doc.violation != viol || doc.root.name != "a" || len(doc.root.children) != 0 {
			t.Errorf("parseXML(%q): violation %q root %q children %d, want %q", s, doc.violation, doc.root.name, len(doc.root.children), viol)
		}
	}
}

func TestG04XMLParseTree(t *testing.T) {
	doc := g04xParse(t, "<a>x<![CDATA[<y>&amp;]]>z&lt;</a >", "")
	r := doc.root
	if len(r.children) != 1 || r.children[0].elem || r.children[0].text != "x<y>&amp;z<" || r.textContent() != "x<y>&amp;z<" {
		t.Fatalf("text children: %d %q", len(r.children), r.textContent())
	}
	doc = g04xParse(t, "<a><![CDATA[q]]></a>", "")
	if len(doc.root.children) != 1 || doc.root.children[0].text != "q" {
		t.Fatalf("cdata only: %v", doc.root.children)
	}
	doc = g04xParse(t, `<a b = 'x' c`+"\t=\n"+`"y&amp;" xmlns='u' xmlns:p='v'><p:e p:f='1' g='2'/>t<h/></a>`, "")
	r = doc.root
	if r.attr("b") != "x" || r.attr("c") != "y&" || r.attr("zz") != "" || len(r.attrs) != 2 || len(r.decls) != 2 || r.ns != "u" || r.local != "a" {
		t.Fatalf("root: %+v", r)
	}
	if len(r.children) != 3 || len(r.elementChildren()) != 2 {
		t.Fatalf("children: %d / %d", len(r.children), len(r.elementChildren()))
	}
	e := r.elementChildren()[0]
	if e.ns != "v" || e.prefix != "p" || e.local != "e" || e.parent != r || e.attrs[0].ns != "v" || e.attrs[0].local != "f" || e.attrs[1].ns != "" {
		t.Fatalf("child: %+v", e)
	}
	if got := r.elementChildrenNS("v", "e"); len(got) != 1 || got[0] != e {
		t.Fatalf("elementChildrenNS: %v", got)
	}
	if got := r.elementChildrenNS("u", "h"); len(got) != 1 {
		t.Fatalf("elementChildrenNS h: %v", got)
	}
	doc = g04xParse(t, "<a><b><b/></b><c><b/></c></a>", "")
	if n := doc.root.descendantsNS("", "b"); n != 3 {
		t.Fatalf("descendantsNS = %d", n)
	}
	if n := doc.root.descendantsNS("", "c"); n != 1 {
		t.Fatalf("descendantsNS c = %d", n)
	}
}

func TestG04XMLStartTagDirect(t *testing.T) {
	nop := func(string) {}
	for s, want := range map[string]string{
		"< a/>":            "malformed start tag",
		"<a":               "unterminated start tag",
		"<a/x":             "malformed start tag",
		"<a b>":            "malformed attribute",
		"<a b=x/>":         "unquoted attribute value",
		"<a b='x":          "unterminated attribute value",
		"<a b='<'/>":       "'<' in an attribute value",
		"<a b='&foo;'/>":   "undefined entity &foo;",
		"<a b='1' b='2'/>": "attribute b is repeated",
	} {
		node, self, n, err := parseStartTag(s, nop)
		if node != nil || self || n != 0 || err == nil || err.Error() != want {
			t.Errorf("parseStartTag(%q) = %v %v %d %v; want %q", s, node, self, n, err, want)
		}
	}
	for s, want := range map[string]struct {
		self bool
		n    int
	}{"<a>": {false, 3}, "<a/>": {true, 4}, "<a b='1' />x": {true, 11}, "<a b=\"1\">": {false, 9}} {
		node, self, n, err := parseStartTag(s, nop)
		if err != nil || node == nil || node.name != "a" || self != want.self || n != want.n {
			t.Errorf("parseStartTag(%q) = %v %v %d %v", s, node, self, n, err)
		}
	}
	var notes []string
	note := func(v string) { notes = append(notes, v) }
	if _, _, _, err := parseStartTag("<a xml:lang='en' XML:x='1' xmlx='2'/>", note); err != nil {
		t.Fatal(err)
	}
	want := []string{"xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)", "xml:* attribute 'XML:x' is not permitted (C14N 1.1 profile)"}
	if strings.Join(notes, "|") != strings.Join(want, "|") {
		t.Fatalf("notes %q", notes)
	}
}

func TestG04XMLRemoveChild(t *testing.T) {
	mk := func() (*xmlNode, []*xmlNode) {
		n := &xmlNode{elem: true}
		cs := []*xmlNode{{text: "x"}, {text: "y"}, {text: "z"}}
		n.children = append([]*xmlNode{}, cs...)
		return n, cs
	}
	texts := func(n *xmlNode) string {
		var s []string
		for _, c := range n.children {
			s = append(s, c.text)
		}
		return strings.Join(s, ",")
	}
	n, cs := mk()
	n.removeChild(cs[1])
	if texts(n) != "x,z" {
		t.Fatalf("remove middle: %s", texts(n))
	}
	n, cs = mk()
	n.removeChild(cs[2])
	if texts(n) != "x,y" {
		t.Fatalf("remove last: %s", texts(n))
	}
	n, _ = mk()
	n.removeChild(&xmlNode{text: "y"})
	if texts(n) != "x,y,z" {
		t.Fatalf("remove stranger: %s", texts(n))
	}
}

func TestG04XMLEscapes(t *testing.T) {
	if got := xmlEscapeText("&<>\r\"'\t\n"); got != "&amp;&lt;&gt;&#xD;\"'\t\n" {
		t.Errorf("text: %q", got)
	}
	if got := xmlEscapeAttr("&<>\"\t\n\r'"); got != "&amp;&lt;>&quot;&#x9;&#xA;&#xD;'" {
		t.Errorf("attr: %q", got)
	}
}

func TestG04XMLCanonical(t *testing.T) {
	// invalid UTF-8 in a raw name is repaired
	if got := canonicalize(&xmlNode{elem: true, name: "a\xff"}, map[string]string{}, nil); got != "<a�></a�>" {
		t.Errorf("invalid utf-8: %q", got)
	}
	// an undeclared prefix (xmlns:p="") and the xml prefix are never rendered
	doc := g04xParse(t, `<a xmlns:p="v"><b xmlns:p=""/></a>`, "")
	if got := canonicalize(doc.root, map[string]string{}, nil); got != `<a xmlns:p="v"><b></b></a>` {
		t.Errorf("undeclared prefix: %q", got)
	}
	doc = g04xParse(t, `<a/>`, "")
	if got := canonicalize(doc.root, map[string]string{"xml": "http://www.w3.org/XML/1998/namespace", "q": "w"}, nil); got != `<a xmlns:q="w"></a>` {
		t.Errorf("xml prefix: %q", got)
	}
	// attributes sort by (namespace URI + local name) concatenated, stable for equal keys (xml-crypto's attrCompare)
	doc = g04xParse(t, `<a xmlns:p="u" xmlns:q="ua" q:b="2" p:ab="1" z="0"/>`, "")
	if got := canonicalize(doc.root, map[string]string{}, nil); got != `<a xmlns:p="u" xmlns:q="ua" z="0" q:b="2" p:ab="1"></a>` {
		t.Errorf("attr order: %q", got)
	}
	// the skipped subtree and escaped text
	doc = g04xParse(t, `<a xmlns="d"><s/>t&amp;<k/></a>`, "")
	s := doc.root.elementChildren()[0]
	if got := canonicalize(doc.root, map[string]string{}, s); got != `<a xmlns="d">t&amp;<k></k></a>` {
		t.Errorf("skip: %q", got)
	}
}
