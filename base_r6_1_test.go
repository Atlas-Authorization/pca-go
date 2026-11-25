package pca

import "testing"

// A second CA, or a second self-issued root, later in the PCK chain must never replace the first one: the CRLs are signed by
// the first CA / root only, so taking the last match fails the CRL signature check (verifyIntelTdxCollateral re-selects both).
func TestR6N1IntelCollateralFirstCaAndRootWin(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	k2 := g06key(t)
	ca2 := g06cert(t, "g06 platform ca", 22, true, g06nb, g06na, f.root, &k2.PublicKey, f.rootKey)
	root2 := g06cert(t, "g06 root two", 23, true, g06nb, g06na, nil, &k2.PublicKey, k2)
	for name, ders := range map[string][][]byte{
		"second CA":   {f.pck.Raw, f.ca.Raw, ca2.Raw, f.root.Raw},
		"second root": {f.pck.Raw, f.ca.Raw, f.root.Raw, root2.Raw},
	} {
		quote := g06quote(g06body(), g06qeBody(), g06pem(ders...))
		res := verifyIntelTdxCollateral(quote, f.col, g06now, nil, f.pin, false)
		if !res.ok || res.reason != "" {
			t.Errorf("%s: ok=%v reason %q", name, res.ok, res.reason)
		}
	}
}
