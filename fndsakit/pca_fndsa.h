/* C ABI of the FN-DSA core (cargo feature "capi"; fn-dsa 0.4.0 by Thomas Pornin). Mirrors the wasm exports: parameter sets
 * 512 and 1024, 32-byte seeds for key generation and for signing (SHAKE256-seeded RNG; pass fresh randomness as the
 * signing seed), raw messages (no pre-hash, no domain) of at most fndsa_cap_msg() bytes. Every buffer is caller-owned and
 * passed with its length; a null pointer (except an empty message), an unsupported tag, or a length different from the
 * exact fixed size is refused and nothing is written. No global state: calls are thread-safe.
 * Return: 0 ok, negative refused or failed. */
#ifndef PCA_FNDSA_H
#define PCA_FNDSA_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define FNDSA_OK 0
#define FNDSA_ERR_ARG (-1)      /* null pointer, wrong length, unsupported tag, message over the cap */
#define FNDSA_ERR_INTERNAL (-2) /* sign: signing key failed to decode or signing failed */
#define FNDSA_ERR_INVALID (-3)  /* verify: well-formed input, the signature (or key) does not verify */

/* Fixed sizes by tag (512 or 1024); -1 for any other tag. 512: vk 897, sig 666; 1024: vk 1793, sig 1280. */
ptrdiff_t fndsa_len_vk(int32_t tag);
ptrdiff_t fndsa_len_sk(int32_t tag);
ptrdiff_t fndsa_len_sig(int32_t tag);
size_t fndsa_len_seed(void); /* 32 */
size_t fndsa_cap_msg(void);  /* 8192 */

/* (sk, vk) = FN-DSA.KeyGen(tag; seed), deterministic. */
int32_t fndsa_c_keygen(int32_t tag, const uint8_t *seed, size_t seed_len, uint8_t *sk, size_t sk_len, uint8_t *vk, size_t vk_len);
/* sig = FN-DSA.Sign(tag, sk, msg; seed), deterministic in seed. msg may be NULL only with msg_len 0. */
int32_t fndsa_c_sign(int32_t tag, const uint8_t *sk, size_t sk_len, const uint8_t *msg, size_t msg_len,
                     const uint8_t *seed, size_t seed_len, uint8_t *sig, size_t sig_len);
/* 0 if sig verifies under vk over msg, -3 if not, -1 for refused input. */
int32_t fndsa_c_verify(int32_t tag, const uint8_t *vk, size_t vk_len, const uint8_t *sig, size_t sig_len,
                       const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif
#endif
