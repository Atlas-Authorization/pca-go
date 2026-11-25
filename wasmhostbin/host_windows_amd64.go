//go:build windows && amd64

package wasmhostbin

import _ "embed"

// Empty in a source checkout; a tagged release carries the reference host built for this platform.
//
//go:embed bin/pca-wasmtime-host_windows_amd64.exe
var hostBinary []byte
