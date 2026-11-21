/* The slice of Microsoft SEAL's C export API (native/src/seal/c, the one SEAL.NET binds) that the BFV gate uses. SEAL's own headers are C++
 * (extern "C" + <cstddef>), so the prototypes are restated here; they follow SEAL 4.1.x exactly. HRESULT is `long` off Windows. */
#ifndef PCA_SEALKIT_SEALC_H
#define PCA_SEALKIT_SEALC_H
#include <stdbool.h>
#include <stdint.h>

long EncParams_Create1(uint8_t scheme, void **enc_params);
long EncParams_Destroy(void *thisptr);
long EncParams_SetPolyModulusDegree(void *thisptr, uint64_t degree);
long EncParams_SetCoeffModulus(void *thisptr, uint64_t length, void **coeffs);
long EncParams_SetPlainModulus1(void *thisptr, void *modulus);
long CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs);
long CoeffModulus_Create1(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs);
long Modulus_Destroy(void *thisptr);
long Modulus_Value(void *thisptr, uint64_t *value);
long SEALContext_Create(void *encryptionParams, bool expand_mod_chain, int sec_level, void **context);
long SEALContext_Destroy(void *thisptr);
long SEALContext_ParametersSet(void *thisptr, bool *params_set);
long BatchEncoder_Create(void *context, void **batch_encoder);
long BatchEncoder_Destroy(void *thisptr);
long BatchEncoder_Encode2(void *thisptr, uint64_t count, int64_t *values, void *destination);
long BatchEncoder_Decode2(void *thisptr, void *plain, uint64_t *count, int64_t *destination, void *pool);
long BatchEncoder_GetSlotCount(void *thisptr, uint64_t *slot_count);
long KeyGenerator_Create1(void *context, void **key_generator);
long KeyGenerator_Destroy(void *thisptr);
long KeyGenerator_SecretKey(void *thisptr, void **secret_key);
long KeyGenerator_CreatePublicKey(void *thisptr, bool save_seed, void **public_key);
long KeyGenerator_CreateRelinKeys(void *thisptr, bool save_seed, void **relin_keys);
long KeyGenerator_CreateGaloisKeysAll(void *thisptr, bool save_seed, void **galois_keys);
long PublicKey_Create1(void **public_key);
long PublicKey_Destroy(void *thisptr);
long PublicKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long PublicKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long PublicKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long SecretKey_Create1(void **secret_key);
long SecretKey_Destroy(void *thisptr);
long SecretKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long SecretKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long SecretKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long KSwitchKeys_Create1(void **kswitch_keys);
long KSwitchKeys_Destroy(void *thisptr);
long KSwitchKeys_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long KSwitchKeys_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long KSwitchKeys_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long Ciphertext_Create1(void *pool, void **cipher);
long Ciphertext_Create2(void *copy, void **cipher);
long Ciphertext_Destroy(void *thisptr);
long Ciphertext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);
long Ciphertext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);
long Ciphertext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
long Plaintext_Create1(void *memoryPoolHandle, void **plaintext);
long Plaintext_Destroy(void *thisptr);
long Encryptor_Create(void *context, void *public_key, void *secret_key, void **encryptor);
long Encryptor_Encrypt(void *thisptr, void *plaintext, void *destination, void *pool_handle);
long Encryptor_Destroy(void *thisptr);
long Decryptor_Create(void *context, void *secret_key, void **decryptor);
long Decryptor_Destroy(void *thisptr);
long Decryptor_Decrypt(void *thisptr, void *encrypted, void *destination);
long Decryptor_InvariantNoiseBudget(void *thisptr, void *encrypted, int *invariant_noise_budget);
long Evaluator_Create(void *context, void **evaluator);
long Evaluator_Destroy(void *thisptr);
long Evaluator_Negate(void *thisptr, void *encrypted, void *destination);
long Evaluator_Add(void *thisptr, void *encrypted1, void *encrypted2, void *destination);
long Evaluator_AddPlain(void *thisptr, void *encrypted, void *plain, void *destination);
long Evaluator_MultiplyPlain(void *thisptr, void *encrypted, void *plain, void *destination, void *pool);
long Evaluator_RotateRows(void *thisptr, void *encrypted, int steps, void *galoisKeys, void *destination, void *pool);
long Evaluator_RotateColumns(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool);
#endif
