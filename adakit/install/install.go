// Package install installs the Ada-backed domain-to-ASCII on import (see package adakit).
package install

import "github.com/Atlas-Authorization/pca-go/adakit"

func init() { adakit.Install() }
