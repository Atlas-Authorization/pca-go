//go:build less && cgo

package pca

// LESS (less-252-45, the `less-cat1` suites) through the patched reference C in lessc/, which less_cgo.c compiles into this
// package. lessc/ is a copy of the repository's sdks/pca-less-c (kept by its sync-copies.sh) inside the module, so the
// published module builds on its own. Built only with `-tags less` and cgo; a pure-Go build keeps refusing the LESS suites
// as unsupported.

/*
#cgo CFLAGS: -O2 -std=c99 -DCATEGORY=252 -DTARGET=45 -I${SRCDIR}/lessc/include -I${SRCDIR}/lessc
#cgo !windows LDFLAGS: -lpthread
#include <stdint.h>
#include <stddef.h>
#include "atlas_less.h"
*/
import "C"

import "unsafe"

func init() {
	lessCat1Verify = cgoLessCat1Verify
	sigSuites["less-cat1"] = pureSuite("less-cat1", pqLessCat1)
	sigSuites["hybrid-ed25519-less-cat1"] = hybridSuite("hybrid-ed25519-less-cat1", pqLessCat1, false)
}

// cgoLessCat1Verify: the detached signature opens under pk and yields exactly msg. Total.
func cgoLessCat1Verify(pk, msg, sig []byte) bool {
	if len(pk) != lessPublicKeyBytes || !pqLessCat1.sigLenOK(len(sig)) {
		return false
	}
	var m *C.uint8_t
	if len(msg) > 0 {
		m = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	// The C side reads only within the given lengths, writes nothing it was handed, and returns after joining its worker
	// thread, so the Go memory is pinned for the whole call (cgo pointer rules: no Go pointers are retained).
	return C.atlas_less_cat1_verify((*C.uint8_t)(unsafe.Pointer(&pk[0])), C.size_t(len(pk)), m, C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) == 1
}
