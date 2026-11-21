//go:build linux && amd64

package wasmhostbin

import _ "embed"

// Empty in a source checkout; a tagged release carries the reference host built for this platform.
//
//go:embed bin/pca-wasmtime-host_linux_amd64
var hostBinary []byte
