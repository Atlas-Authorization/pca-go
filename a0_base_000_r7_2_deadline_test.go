package pca

// r7 N2: mutants of saferegex.go, predicates.go (glob matcher) and atomic_kv.go that make a loop never end, allocate without
// bound, or index out of range. The covering tests used to hang, exhaust memory or crash the process with no test failing.
// This file sorts before every other test file, runs each call under a recover and a deadline, and fails with an ordinary
// assertion. The memory-bound test comes first and has the shortest deadline.

import (
	"testing"
	"time"
)

func r7n2within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- recover() == nil }()
		f()
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatalf("%s panicked", what)
		}
	case <-time.After(d):
		t.Fatalf("%s did not return: a loop does not end", what)
	}
}

// The alternation loop ends at the first token that is not `|`, end of input included; without that exit it appends empty
// concatenations for ever.
func TestR7N2_RegexAlternationParseEnds(t *testing.T) {
	for _, src := range []string{"a", "a|b", "(a)", ""} {
		var prog []reInst
		r7n2within(t, 400*time.Millisecond, "compileSafeRegex "+src, func() { prog = compileSafeRegex(utf16Units(src)) })
		if prog == nil {
			t.Errorf("compileSafeRegex(%q) refused a valid pattern", src)
		}
	}
}

// The set lookup is a binary search over sorted ranges: every probe must move an end past mid, and the first probe must stay
// inside the slice.
func TestR7N2_CharSetBinarySearchTerminates(t *testing.T) {
	cs := &charSet{ranges: []charRange{{1, 1}, {3, 3}, {5, 5}}}
	neg := &charSet{ranges: cs.ranges, negated: true}
	r7n2within(t, 2*time.Second, "charSet.has", func() {
		for u, want := range map[int]bool{0: false, 1: true, 2: false, 3: true, 4: false, 5: true, 6: false, 100: false} {
			if got := cs.has(u); got != want {
				t.Errorf("has(%d) = %v, want %v", u, got, want)
			}
			if got := neg.has(u); got == want {
				t.Errorf("negated has(%d) = %v", u, got)
			}
		}
		if (&charSet{}).has(7) {
			t.Error("empty set has 7")
		}
	})
}

func TestR7N2_RegexCompileAndRunTerminate(t *testing.T) {
	for _, c := range []struct {
		src, subject string
		want         bool
	}{
		{"a", "a", true}, {"a", "b", false}, {"a|b", "b", true}, {"ab", "ab", true}, {"ab", "", false}, {"a*b", "aab", true},
		{"(a)", "a", true}, {"[a-c]", "b", true}, {"[^a]", "a", false}, {"^a$", "a", true}, {"(?:ab|cd)+", "abcd", true},
	} {
		r7n2within(t, 2*time.Second, "safeRegexFullMatch "+c.src, func() {
			m, ok := safeRegexFullMatch(utf16Units(c.src), utf16Units(c.subject))
			if !ok || m != c.want {
				t.Errorf("safeRegexFullMatch(%q, %q) = %v %v, want %v true", c.src, c.subject, m, ok, c.want)
			}
		})
	}
}

// isSafeRegexSource scans the source by index; a wrong bound or step indexes outside it.
func TestR7N2_IsSafeRegexSourceScansWithinBounds(t *testing.T) {
	for src, want := range map[string]bool{
		"a": true, "ab": true, "[a]": true, "[^a]": true, "[a\\]]": true, "(a)": true, "(?:a)": true, "a|b": true, "a*": true,
		"a{2,3}": true, "\\d": true, "(a)(b)": true, "((a))": true, "(": false, ")": false, "[a": false, "a\\": false, "*": false,
	} {
		r7n2within(t, 2*time.Second, "isSafeRegexSource "+src, func() {
			if got := isSafeRegexSource(utf16Units(src)); got != want {
				t.Errorf("isSafeRegexSource(%q) = %v, want %v", src, got, want)
			}
		})
	}
}

// The glob matcher retries after a star one subject unit further each time, and a literal token is not a star.
func TestR7N2_GlobMatchTerminatesAndDecides(t *testing.T) {
	for _, c := range []struct {
		glob, s string
		want    bool
	}{
		{"*a", "ba", true}, {"*ab", "aab", true}, {"a*", "abc", true}, {"?b", "ab", true}, {"a", "b", false}, {"a", "ab", false},
		{"*a", "bb", false}, {"a*c", "abxc", true}, {"**", "", true}, {"a", "a", true},
	} {
		r7n2within(t, 2*time.Second, "globMatch "+c.glob, func() {
			m, ok := globMatch(utf16Units(c.glob), utf16Units(c.s))
			if !ok || m != c.want {
				t.Errorf("globMatch(%q, %q) = %v %v, want %v true", c.glob, c.s, m, ok, c.want)
			}
		})
	}
}

// Every MemoryAtomicKV method that takes the lock gives it back: a second call would block for ever otherwise.
func TestR7N2_MemoryAtomicKVReleasesItsLock(t *testing.T) {
	kv := NewMemoryAtomicKV()
	var got []byte
	var ok bool
	r7n2within(t, 2*time.Second, "MemoryAtomicKV", func() {
		for i := 0; i < 2; i++ {
			_ = kv.Update("k", func(prev []byte) []byte { return append(prev, 'x') })
			got, ok, _ = kv.Get("k")
			got, ok, _ = kv.Get("k")
		}
	})
	if !ok || string(got) != "xx" {
		t.Fatalf("value %q ok %v, want xx", got, ok)
	}
}
