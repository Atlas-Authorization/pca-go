//go:build darwin && arm64

package wasmhostbin

import _ "embed"

// Empty in a source checkout; a tagged release carries the reference host built for this platform.
//
//go:embed bin/pca-wasmtime-host_darwin_arm64
var hostBinary []byte
