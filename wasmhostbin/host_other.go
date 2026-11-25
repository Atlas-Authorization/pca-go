//go:build !((linux || darwin) && (amd64 || arm64)) && !(windows && amd64)

package wasmhostbin

var hostBinary []byte
