package blstkit

/*
#cgo CFLAGS: -I${SRCDIR} -O2
#include <stddef.h>
int pca_gt_mul(unsigned char *out, const unsigned char *a, const unsigned char *b);
int pca_gt_pow(unsigned char *out, const unsigned char *a, const unsigned char *k);
int pca_gt_is_element(const unsigned char *a);
int pca_gt_pairing(unsigned char *out, const unsigned char *g1s, const unsigned char *g2s, size_t n);
*/
import "C"

import "unsafe"

// GT (the pairing target group) values travel as 576 bytes: the twelve Fp coordinates in tower order, 48 bytes big-endian
// each. Every operation returns false on malformed input (non-canonical coordinate, bad point, identity point).

const gtBytes = 576

func cptr(b []byte) *C.uchar { return (*C.uchar)(unsafe.Pointer(&b[0])) }

// gtMul multiplies two GT elements (canonical Fp12 encodings).
func gtMul(a, b []byte) ([]byte, bool) {
	if len(a) != gtBytes || len(b) != gtBytes {
		return nil, false
	}
	out := make([]byte, gtBytes)
	return out, C.pca_gt_mul(cptr(out), cptr(a), cptr(b)) == 1
}

// gtPow raises a to a 32-byte big-endian exponent (all 256 bits processed, branch-free swap).
func gtPow(a, k []byte) ([]byte, bool) {
	if len(a) != gtBytes || len(k) != 32 {
		return nil, false
	}
	out := make([]byte, gtBytes)
	return out, C.pca_gt_pow(cptr(out), cptr(a), cptr(k)) == 1
}

// gtIsElement: canonical encoding of a non-identity element of the order-r subgroup.
func gtIsElement(a []byte) bool { return len(a) == gtBytes && C.pca_gt_is_element(cptr(a)) == 1 }

// gtPairing is prod e(g1s[i], g2s[i]) with one final exponentiation. Points are canonical compressed non-identity
// prime-order points (48 and 96 bytes); at least one pair is required.
func gtPairing(g1s, g2s [][]byte) ([]byte, bool) {
	n := len(g1s)
	if n == 0 || len(g2s) != n {
		return nil, false
	}
	flat1 := make([]byte, 0, 48*n)
	flat2 := make([]byte, 0, 96*n)
	for i := 0; i < n; i++ {
		if len(g1s[i]) != 48 || len(g2s[i]) != 96 {
			return nil, false
		}
		flat1 = append(flat1, g1s[i]...)
		flat2 = append(flat2, g2s[i]...)
	}
	out := make([]byte, gtBytes)
	return out, C.pca_gt_pairing(cptr(out), cptr(flat1), cptr(flat2), C.size_t(n)) == 1
}
