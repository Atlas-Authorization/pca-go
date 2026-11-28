package pca

// Word-array kernels of the OT-extension hot path: the AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four
// little-endian u32 words, and the batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key
// AES-128 truncated to 64 bits.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"
)

// MpcOtCols is the number of bit columns of the IKNP matrix (the security parameter kappa).
const MpcOtCols = 128

var (
	mpcTagPrgKey      = []byte("atlas-pca-mpc/ot-prg-aes")
	mpcTagCrhKey      = []byte("atlas-pca-mpc/ot-crh-aes-fixed-key")
	mpcTagTweakDomain = []byte("atlas-pca-mpc/ot-crh-tweak-domain/v2")
)

// MpcOtxBigToBytes is the low n little-endian bytes of a non-negative integer.
func MpcOtxBigToBytes(v *big.Int, n int) ([]byte, error) {
	if v == nil || v.Sign() < 0 || n < 0 {
		return nil, errors.New("bigToBytes: a non-negative value and length are required")
	}
	be := v.Bytes()
	out := make([]byte, n)
	for i := 0; i < n && i < len(be); i++ {
		out[i] = be[len(be)-1-i]
	}
	return out, nil
}

// MpcOtxBytesToBig is the integer with the given little-endian bytes.
func MpcOtxBytesToBig(b []byte) *big.Int { return new(big.Int).SetBytes(mpcReverse(b)) }

func mpcOtxLeWords(b []byte, n int) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return out
}

func mpcOtxLeBytes(w []uint32, n int) []byte {
	out := make([]byte, 4*n)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], w[i])
	}
	return out
}

// MpcOtxPrgColumn is nwords u32 words of the PRG stream of seed from AES block startBlock (the unused high bits are not masked).
func MpcOtxPrgColumn(seed []byte, startBlock uint64, nwords int) []uint32 {
	k := sha256.Sum256(append(append([]byte{}, mpcTagPrgKey...), seed...))
	blk, err := aes.NewCipher(k[:16])
	if err != nil {
		panic("mpc: aes key: " + err.Error())
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint64(iv[8:], startBlock)
	ks := make([]byte, nwords*4)
	cipher.NewCTR(blk, iv).XORKeyStream(ks, ks)
	return mpcOtxLeWords(ks, nwords)
}

// MpcOtxMaskTail clears the bits at positions >= nbits in a little-endian word column.
func MpcOtxMaskTail(col []uint32, nbits int) {
	full := nbits >> 5
	rem := nbits & 31
	if rem != 0 && full < len(col) {
		col[full] &= uint32(1)<<uint(rem) - 1
	}
	start := full
	if rem != 0 {
		start = full + 1
	}
	for i := start; i < len(col); i++ {
		col[i] = 0
	}
}

// MpcOtxTranspose32 transposes in place the 32x32 bit matrix held as 32 words from off.
func MpcOtxTranspose32(a []uint32, off int) {
	m := uint32(0x0000ffff)
	for j := 16; j != 0; {
		for k := 0; k < 32; k = (k + j + 1) &^ j {
			t := ((a[off+k] >> uint(j)) ^ a[off+k+j]) & m
			a[off+k] ^= t << uint(j)
			a[off+k+j] ^= t
		}
		j >>= 1
		m ^= m << uint(j)
	}
}

// MpcOtxTransposeCols turns COLS bit-columns (each W words, concatenated) into rows of four words: bit i of row j is bit j of column i.
func MpcOtxTransposeCols(cols []uint32, W, rows int) ([]uint32, error) {
	if W < 0 || rows < 0 || len(cols) < MpcOtCols*W || (rows+31)>>5 > W {
		return nil, errors.New("transposeCols: columns too short for the requested rows")
	}
	out := make([]uint32, rows*4)
	tmp := make([]uint32, 32)
	blocks := (rows + 31) >> 5
	for rb := 0; rb < blocks; rb++ {
		for cb := 0; cb < 4; cb++ {
			for c := 0; c < 32; c++ {
				tmp[c] = cols[(cb*32+c)*W+rb]
			}
			MpcOtxTranspose32(tmp, 0)
			lim := min(32, rows-rb*32)
			for r := 0; r < lim; r++ {
				out[(rb*32+r)*4+cb] = tmp[r]
			}
		}
	}
	return out, nil
}

// MpcOtxGfXorInto: acc ^= the four-word element at v[vo:].
func MpcOtxGfXorInto(acc, v []uint32, vo int) {
	acc[0] ^= v[vo]
	acc[1] ^= v[vo+1]
	acc[2] ^= v[vo+2]
	acc[3] ^= v[vo+3]
}

// MpcOtxGfMulX: acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1).
func MpcOtxGfMulX(acc []uint32) {
	carry := acc[3] >> 31
	acc[3] = acc[3]<<1 | acc[2]>>31
	acc[2] = acc[2]<<1 | acc[1]>>31
	acc[1] = acc[1]<<1 | acc[0]>>31
	acc[0] <<= 1
	if carry != 0 {
		acc[0] ^= 0x87
	}
}

// MpcOtxAccumColumn XORs into acc chi[j] (four words) for every set bit j of the word column col.
func MpcOtxAccumColumn(col, chi, acc []uint32) {
	for w, x := range col {
		base := w << 5
		for x != 0 {
			o := (base + bits.TrailingZeros32(x)) << 2
			acc[0] ^= chi[o]
			acc[1] ^= chi[o+1]
			acc[2] ^= chi[o+2]
			acc[3] ^= chi[o+3]
			x &= x - 1
		}
	}
}

// MpcOtxKosCombine is sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the COLS columns of W words.
func MpcOtxKosCombine(cols []uint32, W int, chi []uint32) ([]uint32, error) {
	if W < 0 || len(cols) < MpcOtCols*W {
		return nil, errors.New("kosCombine: columns or challenges too short")
	}
	if len(chi) < 4*32*W { // the challenges cover the m rows only; the tail bits of every column are masked to zero, so pad with zeros
		chi = append(append(make([]uint32, 0, 4*32*W), chi...), make([]uint32, 4*32*W-len(chi))...)
	}
	acc := make([]uint32, 4)
	part := make([]uint32, 4)
	for i := MpcOtCols - 1; i >= 0; i-- {
		MpcOtxGfMulX(acc)
		clear(part)
		MpcOtxAccumColumn(cols[i*W:(i+1)*W], chi, part)
		MpcOtxGfXorInto(acc, part, 0)
	}
	return acc, nil
}

// MpcOtxGfFromBig and MpcOtxGfToBig convert a 128-bit integer to and from its four little-endian words.
func MpcOtxGfFromBig(v *big.Int) []uint32 {
	out := make([]uint32, 4)
	m := new(big.Int).SetUint64(0xffffffff)
	for i := range out {
		out[i] = uint32(new(big.Int).And(new(big.Int).Rsh(v, uint(32*i)), m).Uint64())
	}
	return out
}

func MpcOtxGfToBig(w []uint32) *big.Int {
	v := new(big.Int)
	for i := 3; i >= 0; i-- {
		v.Lsh(v, 32)
		v.Or(v, new(big.Int).SetUint64(uint64(w[i])))
	}
	return v
}

func mpcOtxAesEcb(b cipher.Block, buf []byte) []byte {
	out := make([]byte, len(buf))
	for i := 0; i+16 <= len(buf); i += 16 {
		b.Encrypt(out[i:i+16], buf[i:i+16])
	}
	return out
}

// MpcOtTweak is the 128-bit tweak of a hash call: the channel-global row Offset (rows hashed in earlier rounds, a non-negative
// safe integer) and the two-word session Domain (MpcOtxTweakDomain).
type MpcOtTweak struct {
	Offset int64
	Domain []uint32
}

// MpcOtxTweakDomain is the 64-bit session domain of a channel: SHA-256(tag, binding)[0:8] as two little-endian words.
func MpcOtxTweakDomain(binding []byte) []uint32 {
	d := sha256.Sum256(append(append([]byte{}, mpcTagTweakDomain...), binding...))
	return []uint32{binary.LittleEndian.Uint32(d[0:]), binary.LittleEndian.Uint32(d[4:])}
}

// MpcOtxTmmoCrh is H(tweak, row_j) for n rows of four words: two u32 words (the low 64 bits of the TMMO hash) per row.
func MpcOtxTmmoCrh(rows []uint32, n int, tweak *MpcOtTweak) ([]uint32, error) {
	offset, dom := int64(0), []uint32{0, 0}
	if tweak != nil {
		offset, dom = tweak.Offset, tweak.Domain
	}
	if offset < 0 || offset > 1<<53-1 {
		return nil, errors.New("tmmoCrh: tweak offset must be a non-negative safe integer")
	}
	if len(dom) != 2 {
		return nil, errors.New("tmmoCrh: tweak domain must be 2 words")
	}
	if n < 0 || len(rows) < n*4 {
		return nil, errors.New("tmmoCrh: rows too short")
	}
	k := sha256.Sum256(mpcTagCrhKey)
	blk, err := aes.NewCipher(k[:16])
	if err != nil {
		return nil, err
	}
	a := mpcOtxAesEcb(blk, mpcOtxLeBytes(rows, n*4))
	aw := mpcOtxLeWords(a, n*4)
	b := make([]uint32, n*4)
	for j := 0; j < n; j++ {
		o := j * 4
		v := uint64(offset) + uint64(j)
		b[o] = aw[o] ^ uint32(v)
		b[o+1] = aw[o+1] ^ uint32(v>>32)
		b[o+2] = aw[o+2] ^ dom[0]
		b[o+3] = aw[o+3] ^ dom[1]
	}
	cw := mpcOtxLeWords(mpcOtxAesEcb(blk, mpcOtxLeBytes(b, n*4)), n*4)
	out := make([]uint32, n*2)
	for j := 0; j < n; j++ {
		out[2*j] = cw[4*j] ^ aw[4*j]
		out[2*j+1] = cw[4*j+1] ^ aw[4*j+1]
	}
	return out, nil
}

// MpcOtxWord64 is the 64-bit value of the two words at index j of a MpcOtxTmmoCrh output.
func MpcOtxWord64(h []uint32, j int) uint64 { return uint64(h[2*j+1])<<32 | uint64(h[2*j]) }
