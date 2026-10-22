package pca

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

// Kill tests for saferegex.go: the linear-time regular-expression subset (parser, NFA, Pike simulation, the
// isSafeRegexSource guard and the per-document budget). Expected verdicts come either from Go's RE2 engine (a
// differential over patterns whose JavaScript and RE2 meaning coincide) or from the ECMAScript specification.

func u16s(s string) []uint16 { return utf16.Encode([]rune(s)) }

func compiles(p string) bool { return compileSafeRegex(u16s(p)) != nil }

func fullMatch(t *testing.T, pat, subj string) bool {
	t.Helper()
	m, ok := safeRegexFullMatch(u16s(pat), u16s(subj))
	if !ok {
		t.Fatalf("pattern %q refused (subject %q)", pat, subj)
	}
	return m
}

func TestSafeRegexCharSetHas(t *testing.T) {
	cs := &charSet{ranges: []charRange{{1, 3}, {10, 10}, {20, 29}, {100, 200}, {300, 300}}}
	for u := 0; u < 400; u++ {
		want := u >= 1 && u <= 3 || u == 10 || u >= 20 && u <= 29 || u >= 100 && u <= 200 || u == 300
		if cs.has(u) != want {
			t.Errorf("has(%d) = %v", u, !want)
		}
		neg := &charSet{ranges: cs.ranges, negated: true}
		if neg.has(u) == want {
			t.Errorf("negated has(%d)", u)
		}
	}
	empty := &charSet{}
	if empty.has(0) || empty.has(5) {
		t.Error("empty set")
	}
	one := &charSet{ranges: []charRange{{7, 7}}}
	if !one.has(7) || one.has(6) || one.has(8) {
		t.Error("single set")
	}
}

func jsSpaceUnit(u int) bool {
	switch u {
	case 9, 10, 11, 12, 13, 32, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return u >= 0x2000 && u <= 0x200a
}

func jsWordUnit(u int) bool {
	return u >= '0' && u <= '9' || u >= 'A' && u <= 'Z' || u >= 'a' && u <= 'z' || u == '_'
}

func TestSafeRegexClassEscapesExhaustive(t *testing.T) {
	type cls struct {
		pat  string
		want func(int) bool
	}
	for _, c := range []cls{
		{`\d`, func(u int) bool { return u >= '0' && u <= '9' }},
		{`\D`, func(u int) bool { return !(u >= '0' && u <= '9') }},
		{`\w`, jsWordUnit},
		{`\W`, func(u int) bool { return !jsWordUnit(u) }},
		{`\s`, jsSpaceUnit},
		{`\S`, func(u int) bool { return !jsSpaceUnit(u) }},
		{`.`, func(u int) bool { return u != 10 && u != 13 && u != 0x2028 && u != 0x2029 }},
		{`[\d]`, func(u int) bool { return u >= '0' && u <= '9' }},
		{`[\D]`, func(u int) bool { return !(u >= '0' && u <= '9') }},
		{`[\w]`, jsWordUnit},
		{`[\W]`, func(u int) bool { return !jsWordUnit(u) }},
		{`[\s]`, jsSpaceUnit},
		{`[\S]`, func(u int) bool { return !jsSpaceUnit(u) }},
		{`[^\s]`, func(u int) bool { return !jsSpaceUnit(u) }},
		{`[^\S]`, jsSpaceUnit},
		{`[^\W]`, jsWordUnit},
		{`[\W\d]`, func(u int) bool { return !jsWordUnit(u) || u >= '0' && u <= '9' }},
		{`[\S\s]`, func(int) bool { return true }},
		{`[^]`, func(int) bool { return true }},
		{`[]`, func(int) bool { return false }},
	} {
		prog := compileSafeRegex(u16s(c.pat))
		if prog == nil {
			t.Fatalf("%s refused", c.pat)
		}
		for u := 0; u <= 0xffff; u++ {
			m, ok := runSafeRegex(prog, []uint16{uint16(u)})
			if !ok || m != c.want(u) {
				t.Fatalf("%s on U+%04X = %v, want %v", c.pat, u, m, c.want(u))
			}
		}
	}
}

func TestSafeRegexSingleEscapesExhaustive(t *testing.T) {
	for _, c := range []struct {
		pat  string
		unit int
	}{
		{`\t`, 9}, {`\n`, 10}, {`\v`, 11}, {`\f`, 12}, {`\r`, 13}, {`\0`, 0}, {`[\b]`, 8},
		{`\cA`, 1}, {`\ca`, 1}, {`\cJ`, 10}, {`\cj`, 10}, {`\cZ`, 26}, {`\cz`, 26}, {`\cM`, 13}, {`\cm`, 13},
		{`\.`, '.'}, {`\*`, '*'}, {`\\`, '\\'}, {`\/`, '/'}, {`\-`, '-'}, {`\^`, '^'}, {`\$`, '$'}, {`\|`, '|'}, {`\(`, '('}, {`\)`, ')'},
		{`\[`, '['}, {`\]`, ']'}, {`\{`, '{'}, {`\}`, '}'}, {`\+`, '+'}, {`\?`, '?'}, {`\ `, ' '}, {"\\é", 0xe9}, {`\:`, ':'}, {`\@`, '@'},
		{`\x41`, 0x41}, {`\x4a`, 0x4a}, {`\x4A`, 0x4a}, {`\xaF`, 0xaf}, {`\xFf`, 0xff}, {`\x00`, 0}, {`\x09`, 9}, {`\x7f`, 0x7f}, {`\x80`, 0x80},
		{`\u0041`, 0x41}, {`\u00e9`, 0xe9}, {`\uD83D`, 0xd83d}, {`\uffff`, 0xffff}, {`\uABCD`, 0xabcd}, {`\u1234`, 0x1234}, {`\u0000`, 0},
		{`\ufedc`, 0xfedc}, {`\u0f0f`, 0x0f0f}, {`\u9a8b`, 0x9a8b}, {`\uA5c3`, 0xa5c3},
		{`[\x41]`, 0x41}, {`[\u0041]`, 0x41}, {`[\n]`, 10}, {`[\cJ]`, 10}, {`[\0]`, 0},
	} {
		prog := compileSafeRegex(u16s(c.pat))
		if prog == nil {
			t.Fatalf("%s refused", c.pat)
		}
		for u := 0; u < 0x100; u++ {
			m, ok := runSafeRegex(prog, []uint16{uint16(u)})
			if !ok || m != (u == c.unit) {
				t.Fatalf("%s on %d = %v", c.pat, u, m)
			}
		}
		for _, u := range []int{0x1234, 0xabcd, 0xfedc, 0x0f0f, 0x9a8b, 0xa5c3, 0xd83d, 0xffff, 0x00e9, 0xd83c, 0xd83e} {
			m, _ := runSafeRegex(prog, []uint16{uint16(u)})
			if m != (u == c.unit) {
				t.Fatalf("%s on U+%04X = %v", c.pat, u, m)
			}
		}
	}
}

func TestSafeRegexHexEscapesAllValues(t *testing.T) {
	for v := 0; v < 256; v++ {
		for _, f := range []string{`\x%02x`, `\x%02X`} {
			prog := compileSafeRegex(u16s(fmt.Sprintf(f, v)))
			if prog == nil {
				t.Fatalf("\\x%02x refused", v)
			}
			for _, u := range []int{v, v ^ 1, v ^ 0x10, v + 0x100} {
				m, _ := runSafeRegex(prog, []uint16{uint16(u)})
				if m != (u == v) {
					t.Fatalf("\\x%02x on %d = %v", v, u, m)
				}
			}
		}
	}
	for v := 0; v < 0x10000; v += 37 {
		for _, f := range []string{`\u%04x`, `\u%04X`} {
			prog := compileSafeRegex(u16s(fmt.Sprintf(f, v)))
			if prog == nil {
				t.Fatalf("\\u%04x refused", v)
			}
			for _, u := range []int{v, v ^ 1, v ^ 0x10, v ^ 0x100, v ^ 0x1000} {
				m, _ := runSafeRegex(prog, []uint16{uint16(u)})
				if m != (u == v) {
					t.Fatalf("\\u%04x on %d = %v", v, u, m)
				}
			}
		}
	}
	// every hex digit in every position of \xHH and \uHHHH
	for _, d := range "0123456789abcdefABCDEF" {
		for pos := 0; pos < 2; pos++ {
			b := []rune("00")
			b[pos] = d
			if !compiles(`\x` + string(b)) {
				t.Errorf("\\x%s refused", string(b))
			}
		}
		for pos := 0; pos < 4; pos++ {
			b := []rune("0000")
			b[pos] = d
			if !compiles(`\u` + string(b)) {
				t.Errorf("\\u%s refused", string(b))
			}
		}
	}
	// the digit just outside each hex range is refused
	for _, d := range "/:@G`g _-" {
		for pos := 0; pos < 2; pos++ {
			b := []rune("00")
			b[pos] = d
			if compiles(`\x` + string(b)) {
				t.Errorf("\\x%s accepted", string(b))
			}
		}
		for pos := 0; pos < 4; pos++ {
			b := []rune("0000")
			b[pos] = d
			if compiles(`\u` + string(b)) {
				t.Errorf("\\u%s accepted", string(b))
			}
		}
	}
}

func TestSafeRegexEscapeRefusals(t *testing.T) {
	for c := 33; c < 127; c++ {
		ch := string(rune(c))
		alnum := c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_'
		ok := !alnum || strings.ContainsRune("dDwWsStnvfr0", rune(c))
		if got := compiles(`\` + ch); got != ok {
			t.Errorf("compiles(\\%s) = %v, want %v", ch, got, ok)
		}
		// the same escape inside a class (\b is a backspace there)
		okc := ok || c == 'b'
		if got := compiles(`[\` + ch + `]`); got != okc {
			t.Errorf("compiles([\\%s]) = %v, want %v", ch, got, okc)
		}
	}
	for _, p := range []string{`\`, `a\`, `\00`, `\01`, `\09`, `\x`, `\x4`, `\xg0`, `\x0g`, `\u`, `\u004`, `\u00`, `\u0`, `\u004g`, `\uzzzz`, `\c`, `\c1`, `\c@`, `\c[`, `\c_`, `\c `,
		`\xa`, `\ug123`, `[\x4]`, `[\u00]`, `[\c1]`, `[\`, `[\x`} {
		if compiles(p) {
			t.Errorf("%q must be refused", p)
		}
	}
	for _, p := range []string{`\0/`, `\0:`, `\0a`, `\x41`, `\u0041`, `\ca`, `\cz`, `\cA`, `\cZ`, `\x4141`, `\u00411`} {
		if !compiles(p) {
			t.Errorf("%q must compile", p)
		}
	}
	if !fullMatch(t, `\x4142`, "A42") || fullMatch(t, `\x41`, "AB") || !fullMatch(t, `\u0041B`, "AB") || !fullMatch(t, `\x41\x42`, "AB") {
		t.Error("escape widths")
	}
	if !fullMatch(t, `\0a`, "\x00a") || fullMatch(t, `\0`, "0") {
		t.Error(`\0`)
	}
}

func TestSafeRegexParserRefusals(t *testing.T) {
	refused := []string{
		`*`, `+`, `?`, `{`, `{1}`, `a**`, `a+*`, `a*+`, `a*??`, `|*`, `(*)`, `a|*`, `(`, `a)`, `)`, `(a`, `(a|b`, `(?`, `(?=a)`, `(?!a)`, `(?<n>a)`, `(?i)`, `(?:`, `(?:a`,
		`(?`, `(?a:b)`, `[`, `[a`, `[a-`, `[a-z`, `[z-a]`, `[\x42-\x41]`, `[b-a]`, `^*`, `$*`, `^+`, `$+`, `^?`, `$?`, `^{1}`, `${2}`, `^{1,2}`,
		`a{`, `a{1`, `a{1,`, `a{1,2`, `a{,2}`, `a{x}`, `a{1x}`, `a{1,x}`, `a{}`, `a{2,1}`, `a{3,2}`, `a{2,0}`, `a{65}`, `a{0,65}`, `a{65,}`, `a{65,65}`, `a{65,70}`, `a{12345}`, `a{1,12345}`,
		`a{1234}`, `a{999}`, `a{2}{3}`, `a{2}*`, `a{2}+`, `a{2}?*`, `\b`, `\B`, `\1`, `\k`, `\a`, `(?:a)**`,
	}
	for _, p := range refused {
		if compiles(p) {
			t.Errorf("%q must be refused", p)
		}
	}
	accepted := []string{
		``, `a`, `ab`, `a|b`, `a||b`, `|a`, `a|`, `|`, `()`, `(?:)`, `(a)`, `(?:a)`, `(a|b)c`, `a*`, `a+`, `a?`, `a*?`, `a+?`, `a??`, `a{2}`, `a{2}?`, `a{2,}`, `a{2,}?`, `a{2,3}`, `a{2,3}?`,
		`a{0}`, `a{0,0}`, `a{0,}`, `a{1,1}`, `a{2,2}`, `a{64}`, `a{64,64}`, `a{0,64}`, `a{64,}`, `a{1,64}`, `a{3,64}`, `a{12}`, `a{1,2}`, `a{12,34}`, `a{0,9}`,
		`^`, `$`, `^a$`, `(^)*`, `(^a)*`, `(?:$)+`, `(^a|b$)`, `[a]`, `[^a]`, `[a-]`, `[-a]`, `[a-b-c]`, `[\d-a]`, `[a-\d]`, `[\w-\d]`, `[]`, `[^]`, `[a-a]`, `[\]]`, `[a\]b]`,
		`a{1}`, `.`, `.*`, `(a*)*`, `(a|b)*c`, `(a+)+`, `((a))`, `(?:(?:a))`, `(a(b(c)))`, `a.b`,
	}
	for _, p := range accepted {
		if !compiles(p) {
			t.Errorf("%q must compile", p)
		}
	}
}

func TestSafeRegexClassSemantics(t *testing.T) {
	type tc struct {
		pat, subj string
		want      bool
	}
	for _, c := range []tc{
		{`[a-]`, "-", true}, {`[a-]`, "a", true}, {`[a-]`, "b", false},
		{`[-a]`, "-", true}, {`[-a]`, "a", true}, {`[-a]`, "b", false},
		{`[a-b-c]`, "-", true}, {`[a-b-c]`, "c", true}, {`[a-b-c]`, "b", true}, {`[a-b-c]`, "d", false},
		{`[\d-a]`, "-", true}, {`[\d-a]`, "a", true}, {`[\d-a]`, "5", true}, {`[\d-a]`, "b", false}, {`[\d-a]`, "/", false},
		{`[a-\d]`, "-", true}, {`[a-\d]`, "a", true}, {`[a-\d]`, "5", true}, {`[a-\d]`, "b", false},
		{`[\w-\d]`, "-", true}, {`[\w-\d]`, "z", true}, {`[\w-\d]`, ".", false},
		{`[\d-]`, "-", true}, {`[\d-]`, "7", true}, {`[\d-]`, "x", false},
		{`[a\-z]`, "-", true}, {`[a\-z]`, "a", true}, {`[a\-z]`, "z", true}, {`[a\-z]`, "m", false},
		{`[a-z]`, "m", true}, {`[a-z]`, "a", true}, {`[a-z]`, "z", true}, {`[a-z]`, "`", false}, {`[a-z]`, "{", false},
		{`[^a-z]`, "m", false}, {`[^a-z]`, "A", true}, {`[^a-z]`, "\n", true},
		{`[a-cx-z]`, "b", true}, {`[a-cx-z]`, "y", true}, {`[a-cx-z]`, "m", false},
		{`[z-za-a]`, "a", true}, {`[z-za-a]`, "z", true}, {`[z-za-a]`, "b", false},
		{`[\x41-\x43]`, "B", true}, {`[\x41-\x43]`, "D", false}, {`[\x41-\x43]`, "@", false},
		{`[\u0041-\u0043]`, "C", true}, {`[\u0041-\u0043]`, "D", false},
		{`[a\]b]`, "]", true}, {`[a\]b]`, "b", true}, {`[a\]b]`, "c", false},
		{`[\\]`, `\`, true}, {`[\\]`, "a", false}, {`[\^]`, "^", true}, {`[a^]`, "^", true}, {`[\[]`, "[", true},
		{`[.]`, ".", true}, {`[.]`, "a", false}, {`[*]`, "*", true}, {`[(]`, "(", true}, {`[|]`, "|", true},
		{`[^]`, "\n", true}, {`[]`, "a", false}, {`[^\n]`, "\n", false}, {`[^\n]`, "a", true},
		{`[ab]*`, "abba", true}, {`[ab]*`, "abca", false}, {`[^ab]+`, "cde", true}, {`[^ab]+`, "cab", false},
		{`[\b]`, "\b", true}, {`[\b]`, "b", false},
		{`[a-c\d]`, "5", true}, {`[a-c\d]`, "b", true}, {`[a-c\d]`, "x", false},
		{`[\s\d]`, " ", true}, {`[\s\d]`, "3", true}, {`[\s\d]`, "a", false},
		{`[^\d]`, "3", false}, {`[^\d]`, "a", true},
		{`[\D\d]`, "a", true}, {`[\D\d]`, "7", true},
		{`.`, "\n", false}, {`.`, "\r", false}, {`.`, "\u2028", false}, {`.`, "\u2029", false}, {`.`, "a", true}, {`.`, "\u0085", true}, {`.`, "é", true}, {`.`, "\x00", true},
		{`\s`, "\u00a0", true}, {`\s`, "\u3000", true}, {`\s`, "\ufeff", true}, {`\s`, "\u180e", false}, {`\s`, "\u200b", false}, {`\S`, "\u00a0", false},
		{`\w`, "é", false}, {`\W`, "é", true}, {`\w`, "_", true}, {`\d`, "٣", false},
		{`\uD83D\uDE00`, "😀", true}, {`\uD83D\uDE00`, "😁", false}, {`..`, "😀", true}, {`.`, "😀", false}, {`...`, "😀", false},
	} {
		if got := fullMatch(t, c.pat, c.subj); got != c.want {
			t.Errorf("%q on %q = %v, want %v", c.pat, c.subj, got, c.want)
		}
	}
}

func TestSafeRegexAnchors(t *testing.T) {
	type tc struct {
		pat, subj string
		want      bool
	}
	for _, c := range []tc{
		{`^`, "", true}, {`^`, "a", false}, {`$`, "", true}, {`$`, "a", false}, {`^$`, "", true}, {`^a$`, "a", true}, {`^a$`, "aa", false},
		{`^a`, "a", true}, {`a$`, "a", true}, {`a^`, "a", false}, {`$a`, "a", false}, {`a$b`, "ab", false}, {`a^b`, "ab", false},
		{`^^a`, "a", true}, {`a$$`, "a", true}, {`(^a|b)`, "a", true}, {`(^a|b)`, "b", true}, {`(^a|b)`, "ab", false},
		{`a|^b`, "b", true}, {`a|^b`, "ab", false}, {`^|a`, "", true}, {`^|a`, "a", true}, {`(a|$)`, "", true},
		{`a*^`, "", true}, {`a*^`, "a", false}, {`a*$`, "aa", true}, {`^a*`, "aa", true}, {`b^a`, "ba", false},
		{`(?:^a)*`, "", true}, {`(?:^a)*`, "a", true}, {`(?:^a)*`, "aa", false}, {`(?:a$)+`, "a", true}, {`(?:a$)+`, "aa", false},
		{`(^)*a`, "a", true}, {`x(^)*`, "x", true}, {`x(^)`, "x", false},
		{``, "", true}, {``, "a", false}, {`a`, "", false}, {`a`, "b", false}, {`a`, "aa", false}, {`ab`, "ab", true}, {`ab`, "a", false}, {`ab`, "abc", false},
	} {
		if got := fullMatch(t, c.pat, c.subj); got != c.want {
			t.Errorf("%q on %q = %v, want %v", c.pat, c.subj, got, c.want)
		}
	}
}

func TestSafeRegexDifferential(t *testing.T) {
	pats := []string{
		`a`, `ab`, `abc`, `a|b`, `a|b|c`, `ab|cd`, `(a|b)`, `(?:a|b)c`, `(a|b)*c`, `(a|b)+`, `a*`, `a+`, `a?`, `a*?`, `a+?`, `a??`, `ab*`, `ab+`, `ab?`, `a*b*`, `a+b+`, `a?b?`,
		`a{0}`, `a{1}`, `a{2}`, `a{3}`, `a{0,}`, `a{1,}`, `a{2,}`, `a{0,1}`, `a{0,2}`, `a{1,2}`, `a{2,3}`, `a{1,4}`, `a{2,5}`, `a{3,3}`, `a{4,6}`,
		`(ab){2}`, `(ab){1,2}`, `(ab)+`, `(ab)*`, `(ab)?`, `(?:ab)+c?`, `(a{2}){2}`, `(?:a{2}){1,2}`, `(a|b){2}`, `(a|b){2,3}`, `(a|ab)(c|bcd)(d*)`,
		`[abc]`, `[^abc]`, `[a-c]`, `[a-cA-C0-2]`, `[a-]`, `[-a]`, `[^a-]`, `[\d_]`, `[^\d]`, `[\w.]`, `[.]`, `[ab]+`, `[ab]*c`, `[^ab]+`, `[a-c]{2}`, `[a-c]{1,3}`, `[0-9]+`, `[0-9a-f]+`, `[^0-9]`,
		`\d`, `\d+`, `\d{2}`, `\d{1,3}`, `\w`, `\w+`, `\w*`, `\W`, `\D`, `\D+`, `\s`, `\S`, `\S+`, `\s*`, `\.`, `\*`, `\\`, `\|`, `\(`, `\)`, `a\.b`, `a\*`, `\w+\.\w+`, `\d+\.\d+`,
		`^a`, `a$`, `^a$`, `^$`, `^`, `$`, `(^a|b)`, `a|^b`, `^|a`, `(a|)`, `(|a)`, `()`, `a||b`, `^a*$`, `^\w+$`, `^[a-z]+$`, `^\d+$`,
		`.`, `.*`, `.+`, `a.c`, `a.*c`, `.?`, `..`, `...`, `.{2}`, `.{1,3}`, `a.`, `.a`, `x*y*z*`, `(a*)*`, `(a*)*b`, `(a|b)*`, `(a+)+`, `(a*)+`, `(a?)*`, `(a|b)*c`, `((a|b)c)*`, `(a(b)?)+`,
		`(?:a|b)*`, `(?:a|b)+`, `(?:a*)*`, `(?:a?){3}`, `(?:ab|a)(?:bc|c)`, `a(?:b|c)d`, `(a|b|c|d)+`, `(ab|cd)*`, `((a))`, `(((a)))`, `a(b(c))`, `(a)(b)(c)`, `(a|(b|(c)))`,
		`1`, `12`, `1|2`, `_`, `-`, `a-b`, `a_1`, `a b`, ` `, `\ `, `\t`, `\n`, `\x61`, `\x61b`, `a\x62`, `[\x61-\x63]`,
	}
	subjects := []string{"", "a", "b", "c", "d", "ab", "ba", "abc", "aab", "abab", "ababab", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "a1", "1", "2", "12", "123", "1234", "_", "a_1", "a b", " ", "\t", "\n", "a\nb",
		"-", "a-b", "A", "Z", "z", "0", "9", "é", "aé", "x", "xyz", "xxyyzz", "a.b", "a*", "(a)", "a|b", "ab12", "AB", "Ab", "\\", "a\\b", "abcd", "abbcd", "abbbcd", "abcabc", "cd", "cdab", "bc", "bcd",
		"ad", "aXd", "1.5", "12.34", "ab.cd", "a-", "-a", "ac", "abd", "acd", "aaab", "aabb", "aabbcc", "ccc", "bbb", "bb", "cab", "abac", "7", "f", "g", "af09", "AF", "..", "a.", ".a", "...", "....", "ccdd"}
	for _, p := range pats {
		re := regexp.MustCompile(`^(?:` + p + `)$`)
		prog := compileSafeRegex(u16s(p))
		if prog == nil {
			t.Fatalf("pattern %q refused", p)
		}
		for _, s := range subjects {
			m, ok := runSafeRegex(prog, u16s(s))
			if !ok || m != re.MatchString(s) {
				t.Errorf("%q on %q = %v (ok %v), RE2 says %v", p, s, m, ok, re.MatchString(s))
			}
		}
	}
}

func TestSafeRegexProgramShape(t *testing.T) {
	sh := func(p string) []reInst { return compileSafeRegex(u16s(p)) }
	ops := func(prog []reInst) string {
		var sb strings.Builder
		for _, i := range prog {
			sb.WriteString(fmt.Sprintf("%d:%d:%d ", i.op, i.x, i.y))
		}
		return sb.String()
	}
	// op:x:y per instruction; a=Set(0) split=1 jmp=2 bol=3 eol=4 match=5
	for p, want := range map[string]string{
		``:       "5:0:0 ",
		`a`:      "0:0:0 5:0:0 ",
		`ab`:     "0:0:0 0:0:0 5:0:0 ",
		`^a$`:    "3:0:0 0:0:0 4:0:0 5:0:0 ",
		`a|b`:    "1:1:3 0:0:0 2:4:0 0:0:0 5:0:0 ",
		`a|b|c`:  "1:1:3 0:0:0 2:7:0 1:4:6 0:0:0 2:7:0 0:0:0 5:0:0 ",
		`a*`:     "1:1:3 0:0:0 2:0:0 5:0:0 ",
		`a+`:     "0:0:0 1:2:4 0:0:0 2:1:0 5:0:0 ",
		`a?`:     "1:1:2 0:0:0 5:0:0 ",
		`a{2}`:   "0:0:0 0:0:0 5:0:0 ",
		`a{1,3}`: "0:0:0 1:2:5 0:0:0 1:4:5 0:0:0 5:0:0 ",
		`a{2,}`:  "0:0:0 0:0:0 1:3:5 0:0:0 2:2:0 5:0:0 ",
		`a{0}`:   "5:0:0 ",
	} {
		got := ops(sh(p))
		// the set pointer is not printed; compare the structural fields only
		if got != want {
			t.Errorf("program of %q:\n got %s\nwant %s", p, got, want)
		}
	}
	prog := sh(`(?:a|b)c`)
	if prog[1].set == nil || prog[1].set.ranges[0] != (charRange{'a', 'a'}) {
		t.Error("set contents")
	}
}

func TestSafeRegexInstructionLimit(t *testing.T) {
	if !compiles(strings.Repeat("a", 4095)) {
		t.Error("4095 atoms + match = 4096 instructions must compile")
	}
	if compiles(strings.Repeat("a", 4096)) {
		t.Error("4096 atoms + match = 4097 instructions must be refused")
	}
	if compiles(strings.Repeat("a", 5000)) {
		t.Error("5000 atoms")
	}
	if p := compileSafeRegex(u16s(strings.Repeat("a", 4095))); len(p) != 4096 {
		t.Errorf("len %d", len(p))
	}
	// a repeat whose expansion crosses the limit is refused during emission
	if compiles(strings.Repeat(`a{64}`, 65)) {
		t.Error("65 x a{64} = 4160 sets")
	}
	if !compiles(strings.Repeat(`a{64}`, 63) + strings.Repeat("a", 63)) {
		t.Error("4095 sets via repeats must compile")
	}
	if compiles(strings.Repeat(`a{64}`, 63) + strings.Repeat("a", 64)) {
		t.Error("4096 sets via repeats must be refused")
	}
	if !compiles(`(?:a{64}){63}` + strings.Repeat("a", 63)) {
		t.Error("nested 4095")
	}
	if compiles(`(?:a{64}){64}`) {
		t.Error("nested 4096 sets + match")
	}
	if compiles(`(?:(?:(?:a{64}){64}){64}){64}`) {
		t.Error("nested blow-up")
	}
	// an unbounded repeat and a bounded optional tail count their instructions too
	if compiles(strings.Repeat("a", 4093) + `a*`) {
		t.Error("4093 + (split,set,jmp) + match = 4097")
	}
	if !compiles(strings.Repeat("a", 4092) + `a*`) {
		t.Error("4092 + 3 + match = 4096")
	}
	if compiles(strings.Repeat("a", 4094) + `a{0,2}`) {
		t.Error("optional tail")
	}
	if !compiles(strings.Repeat("a", 4091) + `a{0,2}`) {
		t.Error("optional tail fits (4091 + 4 + match = 4096)")
	}
}

func TestSafeRegexRunBudget(t *testing.T) {
	empty := compileSafeRegex(nil)
	if len(empty) != 1 {
		t.Fatalf("empty program %d", len(empty))
	}
	// len(prog) * (n+1) <= 2_000_000
	if _, ok := runSafeRegex(empty, make([]uint16, 1_999_999)); !ok {
		t.Error("product exactly 2,000,000 must run")
	}
	if _, ok := runSafeRegex(empty, make([]uint16, 2_000_000)); ok {
		t.Error("product 2,000,001 must be refused")
	}
	two := compileSafeRegex(u16s("a"))
	if len(two) != 2 {
		t.Fatal("prog")
	}
	if _, ok := runSafeRegex(two, make([]uint16, 999_999)); !ok {
		t.Error("2 x 1,000,000 must run")
	}
	if m, ok := runSafeRegex(two, make([]uint16, 1_000_000)); ok || m {
		t.Error("2 x 1,000,001 must be refused with (false,false)")
	}
	if _, ok := safeRegexFullMatch(u16s("a"), make([]uint16, 1_000_000)); ok {
		t.Error("safeRegexFullMatch must propagate the budget refusal")
	}
	if m, ok := safeRegexFullMatch(u16s("("), nil); m || ok {
		t.Error("an invalid pattern is (false,false)")
	}
	if m, ok := safeRegexFullMatch(u16s("a"), u16s("a")); !m || !ok {
		t.Error("simple match")
	}
	if m, ok := safeRegexFullMatch(u16s("a"), u16s("b")); m || !ok {
		t.Error("simple mismatch is (false,true)")
	}
}

func TestSafeRegexLongSubjects(t *testing.T) {
	long := strings.Repeat("ab", 500)
	for _, c := range []struct {
		pat, subj string
		want      bool
	}{
		{`(?:ab)*`, long, true}, {`(?:ab)*`, long + "a", false}, {`(?:a|b)*`, long, true}, {`a*`, strings.Repeat("a", 3000), true},
		{`(a*)*b`, strings.Repeat("a", 2000), false}, {`(a*)*b`, strings.Repeat("a", 2000) + "b", true}, {`(a|a)*b`, strings.Repeat("a", 500), false},
		{`[a-b]*`, long, true}, {`.*x`, strings.Repeat("a", 2000) + "x", true}, {`.*x`, strings.Repeat("a", 2000), false},
	} {
		if got := fullMatch(t, c.pat, c.subj); got != c.want {
			t.Errorf("%q on len %d = %v", c.pat, len(c.subj), got)
		}
	}
}

func TestSafeRegexNormalizeAndComplement(t *testing.T) {
	r := func(x ...int) []charRange {
		out := []charRange{}
		for i := 0; i < len(x); i += 2 {
			out = append(out, charRange{x[i], x[i+1]})
		}
		return out
	}
	for i, c := range []struct{ in, want []charRange }{
		{r(), r()},
		{r(5, 7), r(5, 7)},
		{r(1, 2, 3, 4), r(1, 4)},
		{r(1, 2, 4, 5), r(1, 2, 4, 5)},
		{r(4, 5, 1, 2), r(1, 2, 4, 5)},
		{r(1, 10, 2, 3), r(1, 10)},
		{r(1, 10, 5, 12), r(1, 12)},
		{r(1, 10, 11, 12), r(1, 12)},
		{r(1, 10, 12, 13), r(1, 10, 12, 13)},
		{r(1, 10, 10, 12), r(1, 12)},
		{r(2, 3, 1, 10), r(1, 10)},
		{r(1, 1, 1, 1), r(1, 1)},
		{r(0, 0, 1, 1), r(0, 1)},
		{r(9, 9, 5, 5, 7, 7), r(5, 5, 7, 7, 9, 9)},
		{r(20, 30, 1, 3, 10, 12, 4, 5), r(1, 5, 10, 12, 20, 30)},
		{r(0, 0xffff), r(0, 0xffff)},
		{r(1, 5, 3, 3, 9, 9), r(1, 5, 9, 9)},
		{r(1, 5, 2, 9), r(1, 9)},
	} {
		if got := normalizeRanges(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("normalizeRanges %d %v = %v, want %v", i, c.in, got, c.want)
		}
	}
	in := r(4, 5, 1, 2)
	normalizeRanges(in)
	if !reflect.DeepEqual(in, r(4, 5, 1, 2)) {
		t.Error("normalizeRanges must not modify its argument")
	}
	for i, c := range []struct{ in, want []charRange }{
		{r(), r(0, 0xffff)},
		{r(0x30, 0x39), r(0, 0x2f, 0x3a, 0xffff)},
		{r(0, 5), r(6, 0xffff)},
		{r(5, 0xffff), r(0, 4)},
		{r(0, 0xffff), r()},
		{r(0, 0), r(1, 0xffff)},
		{r(0xffff, 0xffff), r(0, 0xfffe)},
		{r(3, 3, 1, 1), r(0, 0, 2, 2, 4, 0xffff)},
		{r(1, 2, 3, 4), r(0, 0, 5, 0xffff)},
		{r(1, 2, 4, 5), r(0, 0, 3, 3, 6, 0xffff)},
		{r(0, 9, 20, 29), r(10, 19, 30, 0xffff)},
		{r(10, 19, 0, 9), r(20, 0xffff)},
		{r(1, 1), r(0, 0, 2, 0xffff)},
		{r(0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a), r(0, 0x2f, 0x3a, 0x40, 0x5b, 0x5e, 0x60, 0x60, 0x7b, 0xffff)},
	} {
		if got := complementRanges(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("complementRanges %d %v = %v, want %v", i, c.in, got, c.want)
		}
	}
}

func TestSafeRegexBraceQuant(t *testing.T) {
	type res struct {
		lo, hi        float64
		comma, emptyH bool
		n             int
		ok            bool
	}
	run := func(src string, i, window, md int) res {
		lo, hi, comma, emptyHi, n, ok := braceQuant(u16s(src), i, window, md)
		return res{lo, hi, comma, emptyHi, n, ok}
	}
	for _, c := range []struct {
		name         string
		src          string
		i, win, maxD int
		want         res
	}{
		{"single", "{2}", 0, -1, -1, res{2, 2, false, false, 3, true}},
		{"single-wide", "{123}", 0, -1, -1, res{123, 123, false, false, 5, true}},
		{"open", "{2,}", 0, -1, -1, res{2, 0, true, true, 4, true}},
		{"range", "{2,5}", 0, -1, -1, res{2, 5, true, false, 5, true}},
		{"range-wide", "{12,345}", 0, -1, -1, res{12, 345, true, false, 8, true}},
		{"range-zero", "{0,0}", 0, -1, -1, res{0, 0, true, false, 5, true}},
		{"offset", "ab{2,5}c", 2, -1, -1, res{2, 5, true, false, 5, true}},
		{"offset-single", "ab{7}", 2, -1, -1, res{7, 7, false, false, 3, true}},
		{"offset-miss", "{2}", 1, -1, -1, res{}},
		{"offset-miss2", "a{2}", 0, -1, -1, res{}},
		{"unterminated", "{2", 0, -1, -1, res{}},
		{"unterminated-comma", "{2,", 0, -1, -1, res{}},
		{"unterminated-range", "{2,5", 0, -1, -1, res{}},
		{"empty", "{}", 0, -1, -1, res{}},
		{"no-lo", "{,5}", 0, -1, -1, res{}},
		{"alpha", "{a}", 0, -1, -1, res{}},
		{"lo-alpha", "{2a}", 0, -1, -1, res{}},
		{"hi-alpha", "{2,x}", 0, -1, -1, res{}},
		{"just-brace", "{", 0, -1, -1, res{}},
		{"slash", "{/}", 0, -1, -1, res{}},
		{"colon", "{:}", 0, -1, -1, res{}},
		{"nine-edge", "{9}", 0, -1, -1, res{9, 9, false, false, 3, true}},
		{"zero-edge", "{0}", 0, -1, -1, res{0, 0, false, false, 3, true}},
		{"md4-ok", "{1234}", 0, -1, 4, res{1234, 1234, false, false, 6, true}},
		{"md4-5digits", "{12345}", 0, -1, 4, res{}},
		{"md3-4digits", "{1234}", 0, -1, 3, res{}},
		{"md4-hi-ok", "{1,1234}", 0, -1, 4, res{1, 1234, true, false, 8, true}},
		{"md4-hi-5", "{1,12345}", 0, -1, 4, res{}},
		{"md3-hi-4", "{1,1234}", 0, -1, 3, res{}},
		{"md1-ok", "{1,2}", 0, -1, 1, res{1, 2, true, false, 5, true}},
		{"md1-lo-2", "{12}", 0, -1, 1, res{}},
		{"md1-hi-2", "{1,23}", 0, -1, 1, res{}},
		{"md1-open", "{1,}", 0, -1, 1, res{1, 0, true, true, 4, true}},
		{"win-exact", "{1}", 0, 3, -1, res{1, 1, false, false, 3, true}},
		{"win-short", "{1}", 0, 2, -1, res{}},
		{"win-short-range", "{1,2}", 0, 4, -1, res{}},
		{"win-exact-range", "{1,2}", 0, 5, -1, res{1, 2, true, false, 5, true}},
		{"win-long", "{1,2}", 0, 100, -1, res{1, 2, true, false, 5, true}},
		{"win-offset", "xx{1,2}yy", 2, 5, -1, res{1, 2, true, false, 5, true}},
		{"win-offset-short", "xx{1,2}yy", 2, 4, -1, res{}},
		{"win-offset-16", "xx{1,2}" + strings.Repeat("y", 40), 2, 16, 4, res{1, 2, true, false, 5, true}},
		{"win-0", "{1}", 0, 0, -1, res{}},
		{"win-cuts-digits", "{12}", 0, 3, -1, res{}},
		{"win-cuts-brace", "{12}", 0, 4, -1, res{12, 12, false, false, 4, true}},
		{"win-cuts-comma", "{1,2}", 0, 2, -1, res{}},
		{"comma-then-brace-in-window", "{1,}", 0, 4, -1, res{1, 0, true, true, 4, true}},
		{"comma-then-brace-cut", "{1,}", 0, 3, -1, res{}},
	} {
		got := run(c.src, c.i, c.win, c.maxD)
		if !got.ok {
			if c.want.ok {
				t.Errorf("%s: %q refused, want %+v", c.name, c.src, c.want)
			}
			continue
		}
		if got != c.want {
			t.Errorf("%s: %q = %+v, want %+v", c.name, c.src, got, c.want)
		}
	}
	if digitsValue(u16s("0")) != 0 || digitsValue(u16s("7")) != 7 || digitsValue(u16s("12")) != 12 || digitsValue(u16s("007")) != 7 ||
		digitsValue(u16s("100")) != 100 || digitsValue(u16s("99")) != 99 || digitsValue(u16s("4096")) != 4096 || digitsValue(u16s("65")) != 65 {
		t.Error("digitsValue")
	}
	if got := digitsValue(u16s("1234567890123456")); got != 1234567890123456.0 {
		t.Errorf("digitsValue large %v", got)
	}
	if hexVal(u16s("0")) != 0 || hexVal(u16s("9")) != 9 || hexVal(u16s("a")) != 10 || hexVal(u16s("f")) != 15 || hexVal(u16s("A")) != 10 || hexVal(u16s("F")) != 15 ||
		hexVal(u16s("10")) != 16 || hexVal(u16s("ff")) != 255 || hexVal(u16s("FFFF")) != 65535 || hexVal(u16s("1a2B")) != 0x1a2b || hexVal(u16s("c0")) != 192 {
		t.Error("hexVal")
	}
	for _, c := range "0123456789abcdefABCDEF" {
		if !isHex(uint16(c)) {
			t.Errorf("isHex(%q)", c)
		}
	}
	for _, c := range "/:@G`g _-\x00zZ" {
		if isHex(uint16(c)) {
			t.Errorf("isHex(%q)", c)
		}
	}
}

func TestSafeRegexParserAt(t *testing.T) {
	p := &reParser{s: u16s("ab")}
	if c, ok := p.at(0); !ok || c != 'a' {
		t.Error("at 0")
	}
	if c, ok := p.at(1); !ok || c != 'b' {
		t.Error("at 1")
	}
	if c, ok := p.at(2); ok || c != 0 {
		t.Errorf("at 2 = (%d,%v)", c, ok)
	}
	if c, ok := p.at(100); ok || c != 0 {
		t.Error("at 100")
	}
}

func TestSafeRegexQuantifierSemantics(t *testing.T) {
	type tc struct {
		pat, subj string
		want      bool
	}
	for _, c := range []tc{
		{`a*`, "", true}, {`a*`, "aaa", true}, {`a*`, "b", false},
		{`a+`, "", false}, {`a+`, "a", true}, {`a+`, "aaaa", true},
		{`a?`, "", true}, {`a?`, "a", true}, {`a?`, "aa", false},
		{`a{2}`, "a", false}, {`a{2}`, "aa", true}, {`a{2}`, "aaa", false},
		{`a{2,}`, "a", false}, {`a{2,}`, "aa", true}, {`a{2,}`, "aaaaaaa", true},
		{`a{1,3}`, "", false}, {`a{1,3}`, "a", true}, {`a{1,3}`, "aaa", true}, {`a{1,3}`, "aaaa", false},
		{`a{0,2}`, "", true}, {`a{0,2}`, "aa", true}, {`a{0,2}`, "aaa", false},
		{`a{0}`, "", true}, {`a{0}`, "a", false}, {`a{0,0}b`, "b", true},
		{`a{3,3}`, "aaa", true}, {`a{3,3}`, "aa", false}, {`a{3,3}`, "aaaa", false},
		{`a{64}`, strings.Repeat("a", 64), true}, {`a{64}`, strings.Repeat("a", 63), false}, {`a{64}`, strings.Repeat("a", 65), false},
		{`a{0,64}`, strings.Repeat("a", 64), true}, {`a{0,64}`, strings.Repeat("a", 65), false},
		{`a{64,}`, strings.Repeat("a", 64), true}, {`a{64,}`, strings.Repeat("a", 63), false}, {`a{64,}`, strings.Repeat("a", 200), true},
		{`a{12}`, strings.Repeat("a", 12), true}, {`a{12}`, strings.Repeat("a", 11), false}, {`a{12,34}`, strings.Repeat("a", 34), true}, {`a{12,34}`, strings.Repeat("a", 35), false},
		{`a*?`, "aaa", true}, {`a+?`, "aaa", true}, {`a??`, "a", true}, {`a{2}?`, "aa", true}, {`a{1,2}?`, "aa", true}, {`a{2,}?`, "aaa", true},
		{`(ab){2}`, "abab", true}, {`(ab){2}`, "ab", false}, {`(?:ab){1,2}c`, "ababc", true}, {`(?:ab){1,2}c`, "abababc", false},
		{`(a*)*b`, "aab", true}, {`(a|b)*c`, "abbac", true}, {`(a|b)*c`, "abbad", false},
		{`x*y`, "y", true}, {`x+y`, "y", false}, {`x?y`, "y", true},
		{`a|b`, "a", true}, {`a|b`, "b", true}, {`a|b`, "c", false}, {`a|b`, "ab", false}, {`a|b|c`, "c", true}, {`a|b|c`, "d", false}, {`a||b`, "", true},
		{`ab|cd`, "cd", true}, {`ab|cd`, "ad", false}, {`(a|b)(c|d)`, "bc", true}, {`(a|b)(c|d)`, "bd", true}, {`(a|b)(c|d)`, "ab", false},
		{`a(?:b|c)d`, "acd", true}, {`a(?:b|c)d`, "ad", false}, {`(?:a|b)`, "b", true},
	} {
		if got := fullMatch(t, c.pat, c.subj); got != c.want {
			t.Errorf("%q on len %d (%.20q) = %v, want %v", c.pat, len(c.subj), c.subj, got, c.want)
		}
	}
}

func TestSafeRegexGuard(t *testing.T) {
	rep := func(s string, n int) string { return strings.Repeat(s, n) }
	type tc struct {
		src  string
		want bool
	}
	for _, c := range []tc{
		{``, true}, {`abc`, true}, {`a|b`, true}, {`a*`, true}, {`a+`, true}, {`a?`, true}, {`*`, false}, {`+a`, false}, {`?`, false}, {`a**`, false}, {`a*+`, false}, {`a*?`, true}, {`a*??`, false},
		{`|*`, false}, {`(*)`, false}, {`a|*`, false}, {`(a*)*`, false}, {`(a*)+`, false}, {`(a*)?`, false}, {`(a|b)*`, false}, {`(a|b)+`, false}, {`(a|b)?`, false}, {`(a|b){2}`, false},
		{`(ab)*`, true}, {`(a)+`, true}, {`(?:ab){2}`, true}, {`(a|b)`, true}, {`(a|b)c`, true}, {`(a*)b?`, true}, {`(a*)`, true}, {`((a*))`, true}, {`((a*))*`, false}, {`((a*)b)+`, false}, {`((a|b)c)+`, false},
		{`((a)b)+`, true}, {`(a)(b*)`, true}, {`(a*)b*`, true}, {`(?:a*)+`, false}, {`(?:a|b)+`, false}, {`((a|b))`, true}, {`(a|b)(c)*`, true}, {`(a)*(b|c)`, true}, {`(a*)(b|c)*`, false},
		{`\1`, false}, {`\9`, false}, {`\8`, false}, {`\k`, false}, {`\k<n>`, false}, {`\0`, true}, {`\/`, true}, {`\:`, true}, {`\d`, true}, {`\d*`, true}, {`\**`, true}, {`\\`, true}, {`\\*`, true}, {`a\`, false}, {`\`, false},
		{`\(`, true}, {`\)`, true}, {`\[`, true}, {`\|`, true}, {`\(a`, true}, {`a\)`, true}, {`\|*`, true}, {`\b`, false}, {`\B`, false}, {`\d\1`, false}, {`\.`, true},
		{`[abc]`, true}, {`[^abc]`, true}, {`[a`, false}, {`[`, false}, {`[\]]`, true}, {`[a\`, false}, {`[\`, false}, {`[]*`, true}, {`[^]*`, true}, {`[(]`, true}, {`[|]`, true}, {`[a*b*c*]`, true},
		{`[)]`, true}, {`[\]*]`, true}, {`[a\]`, false}, {`[a\]]`, true}, {`[a-z]+`, true}, {`[a-z]{2}`, true}, {`[*]`, true}, {`[(]a`, true}, {`[^`, false}, {`[^a`, false}, {`[^]`, true}, {`[]`, true},
		{`(?:a)`, true}, {`(?=a)`, false}, {`(?!a)`, false}, {`(?<n>a)`, false}, {`(?`, false}, {`(?:`, false}, {`(`, false}, {`)`, false}, {`a)`, false}, {`(a`, false}, {`((a)`, false}, {`(?i)`, false},
		{`a{2}`, true}, {`a{2,3}`, true}, {`a{2,}`, true}, {`a{3,2}`, false}, {`a{`, false}, {`{1}`, false}, {`a{64}`, true}, {`a{65}`, false}, {`a{0,64}`, true}, {`a{0,65}`, false}, {`a{65,}`, false},
		{`a{12345}`, false}, {`a{2,2}`, true}, {`a{1,2}?`, true}, {`a{1,2}??`, false}, {`a{,2}`, false}, {`a{x}`, false}, {`a{2}{3}`, false}, {`a{2}b{3}`, true}, {`a{0}`, true}, {`a{0,0}`, true}, {`a{1,1}`, true},
		{`^*`, false}, {`$+`, false}, {`^a$`, true}, {`^`, true}, {`$`, true}, {`^{2}`, false},
		{rep(`a?`, 22), true}, {rep(`a?`, 23), false}, {rep(`a*`, 2), true}, {rep(`a*`, 3), false}, {rep(`a+`, 2), true}, {rep(`a+`, 3), false}, {`a*b*c`, true}, {`a*b*||||||`, true},
		{`a*b*` + rep(`|`, 6), true}, {`a*b*` + rep(`|`, 7), false}, {rep(`|`, 22), true}, {rep(`|`, 23), false}, {`a*` + rep(`|`, 14), true}, {`a*` + rep(`|`, 15), false},
		{rep(`a{0,3}`, 11), true}, {rep(`a{0,3}`, 12), false}, {rep(`a{0,4}`, 7), true}, {rep(`a{0,4}`, 8), false}, {rep(`a{1,3}`, 11), true}, {rep(`a{1,3}`, 12), false},
		{rep(`a{0,1}`, 22), true}, {rep(`a{0,1}`, 23), false}, {rep(`a{2}`, 50), true}, {rep(`a{5}`, 100), true}, {rep(`a{3,3}`, 50), true}, {rep(`a{2,4}`, 11), true}, {rep(`a{2,4}`, 12), false},
		{rep(`a{0,7}`, 7), true}, {rep(`a{0,7}`, 8), false}, {rep(`a{0,8}`, 5), true}, {rep(`a{0,8}`, 6), false}, {rep(`a{0,9}`, 5), true}, {rep(`a{0,9}`, 6), false},
		{rep(`a{0,15}`, 5), true}, {rep(`a{0,15}`, 6), false}, {rep(`a{0,16}`, 4), true}, {rep(`a{0,16}`, 5), false}, {rep(`a{0,17}`, 4), true}, {rep(`a{0,17}`, 5), false},
		{`a{0,63}b{0,63}c{0,63}`, true}, {`a{0,63}b{0,63}c{0,63}d{0,63}`, false}, {`a{0,63}b{0,63}c{0,63}d{0,3}e{0,3}`, true}, {`a{0,63}b{0,63}c{0,63}d{0,3}e{0,3}f?`, false},
		{`a{0,2}b?` + rep(`c?`, 19), true}, {`a{0,2}b?` + rep(`c?`, 20), false},
		{`a*b?` + rep(`c?`, 13), true}, {`a*b?` + rep(`c?`, 14), false}, {`a*b*` + rep(`c?`, 6), true}, {`a*b*` + rep(`c?`, 7), false},
		{`a{2,}b{3,}`, true}, {`a{2,}b{3,}c{4,}`, false}, {`a{2,}b?` + rep(`c?`, 13), true}, {`a{2,}b?` + rep(`c?`, 14), false},
		{rep(`a`, 4095), true}, {rep(`a`, 4096), false},
		{`(a)|(b)|(c)`, true}, {`(a|b)|(c|d)`, true}, {`((a|b)|c)d`, true}, {`((a*)|c)d`, true}, {`(?:(?:a|b)|c)+`, false},
		{`x(a|b)+`, false}, {`x(a)+`, true}, {`x(a*)b`, true}, {`(a*)(b*)`, true}, {`((a*)(b*))`, true},
		{`a*|b`, true}, {`a|b*`, true}, {`(a*|b)c`, true}, {`(a*|b)*`, false}, {`(a|b*)+`, false},
	} {
		src := c.src
		if got := isSafeRegexSource(u16s(src)); got != c.want {
			t.Errorf("isSafeRegexSource(%.40q len %d) = %v, want %v", src, len(src), got, c.want)
		}
	}
	// the quantifier and the guard agree with compileSafeRegex for what they both see
	for _, p := range []string{`a{2,5}`, `a?`, `(ab)+`, `[a-z]*`} {
		if !isSafeRegexSource(u16s(p)) || !compiles(p) {
			t.Errorf("%q", p)
		}
	}
}

func TestSafeRegexBudget(t *testing.T) {
	// evaluations: 64 per document
	var b regexBudget
	for i := 0; i < 64; i++ {
		if !b.charge(u16s("a"), 1) {
			t.Fatalf("evaluation %d refused", i+1)
		}
	}
	if b.evaluations != 64 || b.chars != 64 || b.steps != 64*2*2 {
		t.Errorf("budget state %+v", b)
	}
	if b.charge(u16s("a"), 1) {
		t.Error("evaluation 65 must be refused")
	}
	if b.evaluations != 65 {
		t.Errorf("a refusal poisons the budget: evaluations = %d", b.evaluations)
	}
	if b.charge(u16s("a"), 1) {
		t.Error("a poisoned budget stays refused")
	}
	// an invalid source is refused without charging
	var c regexBudget
	if c.charge(u16s("("), 3) || c.evaluations != 0 || c.chars != 0 || c.steps != 0 {
		t.Errorf("invalid source charged: %+v", c)
	}
	for i := 0; i < 64; i++ {
		if !c.charge(u16s("a"), 0) {
			t.Fatalf("after an invalid source evaluation %d refused", i+1)
		}
	}
	// chars: 8192 per document
	var d regexBudget
	for i := 0; i < 4; i++ {
		if !d.charge(u16s(strings.Repeat("a", 2048)), 0) {
			t.Fatalf("chunk %d refused", i)
		}
	}
	if d.chars != 8192 {
		t.Errorf("chars %d", d.chars)
	}
	if d.charge(u16s("a"), 0) {
		t.Error("the 8193rd source character must be refused")
	}
	var d2 regexBudget
	if !d2.charge(u16s(strings.Repeat("a", 2048)), 0) || !d2.charge(u16s(strings.Repeat("a", 2048)), 0) || !d2.charge(u16s(strings.Repeat("a", 2047)), 0) ||
		!d2.charge(u16s(strings.Repeat("a", 2047)), 0) || !d2.charge(u16s("aa"), 0) {
		t.Error("8192 characters in total must be accepted")
	}
	if d2.chars != 8192 || d2.evaluations != 5 {
		t.Errorf("d2 %+v", d2)
	}
	// steps: 5_000_000 per document: len(prog) * (subjectLen + 1)
	var e regexBudget
	if !e.charge(nil, 4_999_999) { // the empty pattern: 1 instruction
		t.Error("1 x 5,000,000 steps must be accepted")
	}
	if e.steps != 5_000_000 {
		t.Errorf("steps %d", e.steps)
	}
	if e.charge(nil, 0) {
		t.Error("5,000,001 steps must be refused")
	}
	var f regexBudget
	if f.charge(nil, 5_000_000) {
		t.Error("1 x 5,000,001 steps must be refused")
	}
	var g regexBudget
	if !g.charge(u16s("a"), 2_499_999) || g.steps != 5_000_000 {
		t.Errorf("2 x 2,500,000 steps: %+v", g)
	}
	var h regexBudget
	if h.charge(u16s("a"), 2_500_000) {
		t.Error("2 x 2,500,001 steps must be refused")
	}
	var i2 regexBudget
	if !i2.charge(nil, 2_000_000) || !i2.charge(nil, 2_999_998) || i2.steps != 5_000_000 || i2.charge(nil, 0) {
		t.Errorf("accumulated steps %+v", i2)
	}
	// subject length 0 still costs len(prog)
	var j regexBudget
	j.charge(u16s("abc"), 0)
	if j.steps != 4 || j.chars != 3 || j.evaluations != 1 {
		t.Errorf("%+v", j)
	}
}
