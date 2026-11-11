package pca

import (
	"testing"
	"time"
)

// This file sorts first in the package so that, for a mutant that stops a loop or a lock release, the deadline below fails the
// run before any other covering test can spin or block on it. r5n7within decides such a mutant by an ordinary assertion within
// two seconds.

func r5n7within(t *testing.T, what string, f func()) {
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
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return: a loop does not end or a lock is still held", what)
	}
}

// Every construct the XML reader steps over must move the cursor on (no entity here: that loop is a run error of its own).
func TestR5N7_XMLReaderTerminatesOnEveryConstruct(t *testing.T) {
	for _, c := range []struct{ name, doc, violation string }{
		{"doctype", "<!DOCTYPE d><r/>", "DTD / DOCTYPE is not permitted"},
		{"doctype with a subset", "<!DOCTYPE d [<!ENTITY e \"x\">]><r/>", "DTD / DOCTYPE is not permitted"},
		{"processing instruction", "<?p x?><r/>", "XML processing instructions are not permitted"},
		{"comment", "<!-- c --><r/>", "XML comments are not permitted"},
		{"cdata", "<r><![CDATA[x]]></r>", ""},
		{"text", "<r>t</r>", ""},
		{"start and end tags", "<r a=\"1\"><c></c></r>", ""},
	} {
		var doc *xmlDoc
		var err error
		r5n7within(t, c.name, func() { doc, err = parseXML(c.doc) })
		if err != nil || doc.root == nil || doc.root.name != "r" || doc.violation != c.violation {
			t.Errorf("%s: %+v %v", c.name, doc, err)
		}
	}
}

// A prefix no ancestor declares ends the walk up the tree.
func TestR5N7_XMLLookupNSEnds(t *testing.T) {
	leaf := &xmlNode{elem: true, name: "c", parent: &xmlNode{elem: true, name: "r", decls: []xmlDecl{{prefix: "p", uri: "u"}}}}
	var uri string
	var ok bool
	r5n7within(t, "lookupNS", func() { uri, ok = leaf.lookupNS("q") })
	if ok || uri != "" {
		t.Fatalf("undeclared prefix: %q %v", uri, ok)
	}
	if uri, ok = leaf.lookupNS("p"); !ok || uri != "u" {
		t.Fatalf("declared on the parent: %q %v", uri, ok)
	}
}

// Every method of the in-memory vault gives its lock back: a second call would block for ever otherwise.
func TestR5N7_MemVaultReleasesItsLock(t *testing.T) {
	v := NewMemoryVault()
	var got VaultEntry
	var has, hasMissing bool
	r5n7within(t, "memVault", func() {
		v.Put("a", VaultEntry{Cls: "ref", Value: "1"})
		v.Put("b", VaultEntry{Cls: "ref", Value: "2"})
		got, has = v.Get("a")
		_, _ = v.Get("a")
		v.Put("c", VaultEntry{Cls: "ref", Value: "3"})
		_, hasMissing = v.Get("zz")
		_, _ = v.Get("b")
	})
	if !has || got.Value != "1" || hasMissing {
		t.Fatalf("vault: %+v %v %v", got, has, hasMissing)
	}
}
