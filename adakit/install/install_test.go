package install_test

import (
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
	"github.com/Atlas-Authorization/pca-go/adakit"
	_ "github.com/Atlas-Authorization/pca-go/adakit/install"
)

// Importing the package installs Ada: a fullwidth host maps to ASCII under UTS #46 (the core's built-in mapping would punycode it).
func TestImportInstallsAda(t *testing.T) {
	const in = "ＥＸＡＭＰＬＥ.com"
	if got := pca.CibaASCIIForm(in); got != "example.com" {
		t.Fatalf("Ada not installed by the import: %q", got)
	}
	pca.SetWhatwgDomainToASCII(nil)
	t.Cleanup(adakit.Install)
	if got := pca.CibaASCIIForm(in); got == "example.com" {
		t.Fatal("the control did not change the result: this test cannot tell an installed Ada from none")
	}
}
