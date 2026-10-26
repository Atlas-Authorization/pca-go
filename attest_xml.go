package pca

// A small XML reader and a canonicaliser (inclusive C14N; identical to C14N 1.1 for documents without xml:* attributes,
// which the RIM profile refuses) for the NVIDIA RIM XMLDSig check. Only the subset the profile needs is supported:
// elements, attributes, namespaces, text, CDATA and the predefined and numeric character references. A comment,
// processing instruction or DOCTYPE is not interpreted: the first of them (in document order) is recorded as a profile
// violation, and the verifier refuses the document before any cryptography.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type xmlAttr struct {
	name, prefix, local, ns, value string
}

type xmlDecl struct{ prefix, uri string }

type xmlNode struct {
	elem                    bool
	name, prefix, local, ns string
	attrs                   []xmlAttr
	decls                   []xmlDecl
	children                []*xmlNode
	text                    string
	parent                  *xmlNode
}

type xmlDoc struct {
	root      *xmlNode
	violation string
}

func isXMLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func xmlDecode(s string) (string, error) {
	if !strings.Contains(s, "&") {
		return s, nil
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '&' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		j := strings.IndexByte(s[i:], ';')
		if j < 0 {
			return "", errors.New("unterminated entity reference")
		}
		ent := s[i+1 : i+j]
		i += j + 1
		switch ent {
		case "lt":
			sb.WriteByte('<')
		case "gt":
			sb.WriteByte('>')
		case "amp":
			sb.WriteByte('&')
		case "quot":
			sb.WriteByte('"')
		case "apos":
			sb.WriteByte('\'')
		default:
			if !strings.HasPrefix(ent, "#") {
				return "", fmt.Errorf("undefined entity &%s;", ent)
			}
			var n int64
			var err error
			if strings.HasPrefix(ent, "#x") {
				n, err = strconv.ParseInt(ent[2:], 16, 32)
			} else {
				n, err = strconv.ParseInt(ent[1:], 10, 32)
			}
			r := rune(n)
			if err != nil || !(r == 0x9 || r == 0xa || r == 0xd || (r >= 0x20 && r <= 0xd7ff) || (r >= 0xe000 && r <= 0xfffd) || (r >= 0x10000 && r <= 0x10ffff)) {
				return "", fmt.Errorf("invalid character reference &%s;", ent)
			}
			sb.WriteRune(r)
		}
	}
	return sb.String(), nil
}

func splitQName(name string) (prefix, local string) {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// lookupNS resolves a prefix ("" is the default namespace) through the element's ancestors.
func (n *xmlNode) lookupNS(prefix string) (string, bool) {
	for e := n; e != nil; e = e.parent {
		for _, d := range e.decls {
			if d.prefix == prefix {
				return d.uri, true
			}
		}
	}
	return "", false
}

func parseXML(s string) (*xmlDoc, error) {
	doc := &xmlDoc{}
	note := func(v string) {
		if doc.violation == "" {
			doc.violation = v
		}
	}
	var cur *xmlNode
	i := 0
	for i < len(s) {
		if s[i] != '<' {
			end := strings.IndexByte(s[i:], '<')
			if end < 0 {
				end = len(s)
			} else {
				end += i
			}
			txt := s[i:end]
			i = end
			if cur == nil {
				if strings.TrimFunc(txt, func(r rune) bool { return r < 0x80 && isXMLSpace(byte(r)) }) != "" {
					return nil, errors.New("text outside the document element")
				}
				continue
			}
			dec, err := xmlDecode(txt)
			if err != nil {
				return nil, err
			}
			cur.appendText(dec)
			continue
		}
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			j := strings.Index(rest[4:], "-->")
			if j < 0 {
				return nil, errors.New("unterminated comment")
			}
			note("XML comments are not permitted")
			i += 4 + j + 3
		case strings.HasPrefix(rest, "<?"):
			j := strings.Index(rest, "?>")
			if j < 0 {
				return nil, errors.New("unterminated processing instruction")
			}
			note("XML processing instructions are not permitted")
			i += j + 2
		case strings.HasPrefix(rest, "<![CDATA["):
			j := strings.Index(rest, "]]>")
			if j < 0 || cur == nil {
				return nil, errors.New("misplaced or unterminated CDATA section")
			}
			cur.appendText(rest[9:j])
			i += j + 3
		case strings.HasPrefix(rest, "<!DOCTYPE"):
			depth := 0
			j := 0
			for ; j < len(rest); j++ {
				if rest[j] == '[' {
					depth++
				} else if rest[j] == ']' {
					depth--
				} else if rest[j] == '>' && depth <= 0 {
					break
				}
			}
			if j >= len(rest) {
				return nil, errors.New("unterminated DOCTYPE")
			}
			note("DTD / DOCTYPE is not permitted")
			i += j + 1
		case strings.HasPrefix(rest, "</"):
			j := strings.IndexByte(rest, '>')
			if j < 0 || cur == nil {
				return nil, errors.New("unexpected end tag")
			}
			name := strings.TrimRight(rest[2:j], " \t\r\n")
			if name != cur.name {
				return nil, fmt.Errorf("end tag </%s> does not match <%s>", name, cur.name)
			}
			cur = cur.parent
			i += j + 1
		default:
			node, selfClose, n, err := parseStartTag(rest, note)
			if err != nil {
				return nil, err
			}
			i += n
			node.parent = cur
			if cur == nil {
				if doc.root != nil {
					return nil, errors.New("more than one document element")
				}
				doc.root = node
			} else {
				cur.children = append(cur.children, node)
			}
			if err := node.resolveNames(); err != nil {
				return nil, err
			}
			if !selfClose {
				cur = node
			}
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("element <%s> is not closed", cur.name)
	}
	if doc.root == nil {
		return nil, errors.New("no document element")
	}
	return doc, nil
}

func (n *xmlNode) appendText(t string) {
	if k := len(n.children); k > 0 && !n.children[k-1].elem {
		n.children[k-1].text += t
		return
	}
	n.children = append(n.children, &xmlNode{text: t, parent: n})
}

// parseStartTag reads one start tag at the beginning of rest; n is the number of bytes consumed.
func parseStartTag(rest string, note func(string)) (node *xmlNode, selfClose bool, n int, err error) {
	i := 1
	j := i
	for j < len(rest) && !isXMLSpace(rest[j]) && rest[j] != '/' && rest[j] != '>' {
		j++
	}
	name := rest[i:j]
	if name == "" {
		return nil, false, 0, errors.New("malformed start tag")
	}
	node = &xmlNode{elem: true, name: name}
	seen := map[string]bool{}
	i = j
	for {
		for i < len(rest) && isXMLSpace(rest[i]) {
			i++
		}
		if i >= len(rest) {
			return nil, false, 0, errors.New("unterminated start tag")
		}
		if rest[i] == '>' {
			return node, false, i + 1, nil
		}
		if rest[i] == '/' {
			if i+1 < len(rest) && rest[i+1] == '>' {
				return node, true, i + 2, nil
			}
			return nil, false, 0, errors.New("malformed start tag")
		}
		k := i
		for k < len(rest) && !isXMLSpace(rest[k]) && rest[k] != '=' && rest[k] != '>' && rest[k] != '/' {
			k++
		}
		aname := rest[i:k]
		for k < len(rest) && isXMLSpace(rest[k]) {
			k++
		}
		if aname == "" || k >= len(rest) || rest[k] != '=' {
			return nil, false, 0, errors.New("malformed attribute")
		}
		k++
		for k < len(rest) && isXMLSpace(rest[k]) {
			k++
		}
		if k >= len(rest) || (rest[k] != '"' && rest[k] != '\'') {
			return nil, false, 0, errors.New("unquoted attribute value")
		}
		q := rest[k]
		e := strings.IndexByte(rest[k+1:], q)
		if e < 0 {
			return nil, false, 0, errors.New("unterminated attribute value")
		}
		raw := rest[k+1 : k+1+e]
		if strings.Contains(raw, "<") {
			return nil, false, 0, errors.New("'<' in an attribute value")
		}
		val, derr := xmlDecode(raw)
		if derr != nil {
			return nil, false, 0, derr
		}
		i = k + 1 + e + 1
		if seen[aname] {
			return nil, false, 0, fmt.Errorf("attribute %s is repeated", aname)
		}
		seen[aname] = true
		if strings.HasPrefix(strings.ToLower(aname), "xml:") {
			note(fmt.Sprintf("xml:* attribute '%s' is not permitted (C14N 1.1 profile)", aname))
		}
		switch {
		case aname == "xmlns":
			node.decls = append(node.decls, xmlDecl{prefix: "", uri: val})
		case strings.HasPrefix(aname, "xmlns:"):
			node.decls = append(node.decls, xmlDecl{prefix: aname[6:], uri: val})
		default:
			p, l := splitQName(aname)
			node.attrs = append(node.attrs, xmlAttr{name: aname, prefix: p, local: l, value: val})
		}
	}
}

// resolveNames binds the element's and its attributes' prefixes (the declarations of the element itself are in scope).
func (n *xmlNode) resolveNames() error {
	n.prefix, n.local = splitQName(n.name)
	uri, ok := n.lookupNS(n.prefix)
	if n.prefix != "" && !ok {
		return fmt.Errorf("namespace prefix %s is not bound", n.prefix)
	}
	n.ns = uri
	for i := range n.attrs {
		a := &n.attrs[i]
		if a.prefix == "" {
			continue
		}
		u, ok := n.lookupNS(a.prefix)
		if !ok {
			return fmt.Errorf("namespace prefix %s is not bound", a.prefix)
		}
		a.ns = u
	}
	return nil
}

func (n *xmlNode) attr(name string) string {
	for _, a := range n.attrs {
		if a.name == name {
			return a.value
		}
	}
	return ""
}

func (n *xmlNode) textContent() string {
	if !n.elem {
		return n.text
	}
	var sb strings.Builder
	for _, c := range n.children {
		sb.WriteString(c.textContent())
	}
	return sb.String()
}

func (n *xmlNode) elementChildren() []*xmlNode {
	var out []*xmlNode
	for _, c := range n.children {
		if c.elem {
			out = append(out, c)
		}
	}
	return out
}

func (n *xmlNode) elementChildrenNS(ns, local string) []*xmlNode {
	var out []*xmlNode
	for _, c := range n.elementChildren() {
		if c.ns == ns && c.local == local {
			out = append(out, c)
		}
	}
	return out
}

// descendantsNS counts the descendant elements with the given namespace and local name.
func (n *xmlNode) descendantsNS(ns, local string) int {
	total := 0
	for _, c := range n.elementChildren() {
		if c.ns == ns && c.local == local {
			total++
		}
		total += c.descendantsNS(ns, local)
	}
	return total
}

func (n *xmlNode) removeChild(c *xmlNode) {
	for i, x := range n.children {
		if x == c {
			n.children = append(n.children[:i], n.children[i+1:]...)
			return
		}
	}
}

// scope is the in-scope namespace bindings of the element (its own declarations included).
func (n *xmlNode) scope() map[string]string {
	var chain []*xmlNode
	for e := n; e != nil; e = e.parent {
		chain = append(chain, e)
	}
	out := map[string]string{}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, d := range chain[i].decls {
			out[d.prefix] = d.uri
		}
	}
	return out
}

func xmlEscapeText(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '\r':
			sb.WriteString("&#xD;")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func xmlEscapeAttr(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '"':
			sb.WriteString("&quot;")
		case '\t':
			sb.WriteString("&#x9;")
		case '\n':
			sb.WriteString("&#xA;")
		case '\r':
			sb.WriteString("&#xD;")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// canonicalize is the inclusive canonical form of the subtree at n, omitting the subtree skip (the enveloped-signature
// transform). parentScope is the in-scope bindings of n's ancestors: an apex element renders every in-scope namespace.
func canonicalize(n *xmlNode, parentScope map[string]string, skip *xmlNode) string {
	var sb strings.Builder
	c14nElement(&sb, n, parentScope, map[string]string{}, skip)
	if !utf8.ValidString(sb.String()) {
		return strings.ToValidUTF8(sb.String(), "�")
	}
	return sb.String()
}

func c14nElement(sb *strings.Builder, n *xmlNode, parentScope, rendered map[string]string, skip *xmlNode) {
	scope := make(map[string]string, len(parentScope)+len(n.decls))
	for k, v := range parentScope {
		scope[k] = v
	}
	for _, d := range n.decls {
		scope[d.prefix] = d.uri
	}
	var emit []string
	for p, uri := range scope {
		if p == "xml" || (uri == "" && p != "") {
			continue
		}
		if rendered[p] == uri {
			continue
		}
		emit = append(emit, p)
	}
	sort.Strings(emit)
	newRendered := make(map[string]string, len(rendered)+len(emit))
	for k, v := range rendered {
		newRendered[k] = v
	}
	sb.WriteString("<" + n.name)
	for _, p := range emit {
		if p == "" {
			sb.WriteString(` xmlns="` + xmlEscapeAttr(scope[p]) + `"`)
		} else {
			sb.WriteString(" xmlns:" + p + `="` + xmlEscapeAttr(scope[p]) + `"`)
		}
		newRendered[p] = scope[p]
	}
	attrs := append([]xmlAttr{}, n.attrs...)
	sort.SliceStable(attrs, func(i, j int) bool {
		a, b := attrs[i], attrs[j]
		if (a.ns == "") != (b.ns == "") {
			return a.ns == ""
		}
		return a.ns+a.local < b.ns+b.local
	})
	for _, a := range attrs {
		sb.WriteString(" " + a.name + `="` + xmlEscapeAttr(a.value) + `"`)
	}
	sb.WriteString(">")
	for _, c := range n.children {
		if c == skip {
			continue
		}
		if c.elem {
			c14nElement(sb, c, scope, newRendered, skip)
		} else {
			sb.WriteString(xmlEscapeText(c.text))
		}
	}
	sb.WriteString("</" + n.name + ">")
}
