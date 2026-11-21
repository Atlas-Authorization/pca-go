// Command pca-mpc-party runs one MPC node (a party, the trusted dealer, or an OT demonstration role) as its own OS process; see
// package partycli. This build has no endemic-LWE library, so an ot kind "lwe" request fails closed.
package main

import (
	"os"

	"github.com/Atlas-Authorization/pca-go/partycli"
)

func main() { os.Exit(partycli.Main(os.Args)) }
