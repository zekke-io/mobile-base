#ifndef ZEKKE_NATIVE_H
#define ZEKKE_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#define ZEKKE_X25519_KEY_BYTES 32
#define ZEKKE_ED25519_SEED_BYTES 32
#define ZEKKE_ED25519_PUBLIC_KEY_BYTES 32
#define ZEKKE_ED25519_SIGNATURE_BYTES 64
#define ZEKKE_RISTRETTO255_POINT_BYTES 32
#define ZEKKE_RISTRETTO255_SCALAR_BYTES 32
#define ZEKKE_RISTRETTO255_UNIFORM_BYTES 64
#define ZEKKE_MLKEM768_SEED_BYTES 64
#define ZEKKE_MLKEM768_PUBLIC_KEY_BYTES 1184
#define ZEKKE_MLKEM768_SECRET_KEY_BYTES 2400
#define ZEKKE_MLKEM768_CIPHERTEXT_BYTES 1088
#define ZEKKE_MLKEM768_SHARED_SECRET_BYTES 32

#define ZEKKE_OK 0
#define ZEKKE_FAILURE (-1)

int zekke_native_init(void);

void zekke_random_bytes(uint8_t *out, size_t out_len);

int zekke_x25519_public_key(uint8_t public_key[ZEKKE_X25519_KEY_BYTES],
                            const uint8_t private_key[ZEKKE_X25519_KEY_BYTES]);

int zekke_x25519_shared_secret(uint8_t shared_secret[ZEKKE_X25519_KEY_BYTES],
                               const uint8_t private_key[ZEKKE_X25519_KEY_BYTES],
                               const uint8_t public_key[ZEKKE_X25519_KEY_BYTES]);

int zekke_ed25519_public_key(uint8_t public_key[ZEKKE_ED25519_PUBLIC_KEY_BYTES],
                             const uint8_t seed[ZEKKE_ED25519_SEED_BYTES]);

int zekke_ed25519_sign(uint8_t signature[ZEKKE_ED25519_SIGNATURE_BYTES],
                       const uint8_t *message, size_t message_len,
                       const uint8_t seed[ZEKKE_ED25519_SEED_BYTES]);

int zekke_ed25519_verify(const uint8_t signature[ZEKKE_ED25519_SIGNATURE_BYTES],
                         const uint8_t *message, size_t message_len,
                         const uint8_t public_key[ZEKKE_ED25519_PUBLIC_KEY_BYTES]);

int zekke_ristretto255_is_valid_point(const uint8_t point[ZEKKE_RISTRETTO255_POINT_BYTES]);

int zekke_ristretto255_from_uniform_bytes(uint8_t point[ZEKKE_RISTRETTO255_POINT_BYTES],
                                          const uint8_t uniform_bytes[ZEKKE_RISTRETTO255_UNIFORM_BYTES]);

int zekke_ristretto255_scalar_mult(uint8_t result[ZEKKE_RISTRETTO255_POINT_BYTES],
                                   const uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES],
                                   const uint8_t point[ZEKKE_RISTRETTO255_POINT_BYTES]);

int zekke_ristretto255_scalar_mult_base(uint8_t result[ZEKKE_RISTRETTO255_POINT_BYTES],
                                        const uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES]);

int zekke_ristretto255_scalar_invert(uint8_t inverse[ZEKKE_RISTRETTO255_SCALAR_BYTES],
                                     const uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES]);

void zekke_ristretto255_scalar_reduce(uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES],
                                      const uint8_t wide_scalar[ZEKKE_RISTRETTO255_UNIFORM_BYTES]);

void zekke_ristretto255_scalar_random(uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES]);

int zekke_argon2id(uint8_t *out, size_t out_len,
                   const uint8_t *password, size_t password_len,
                   const uint8_t *salt, size_t salt_len,
                   uint32_t iterations, uint32_t memory_kib, uint32_t parallelism);

int zekke_mlkem768_key_pair_from_seed(uint8_t public_key[ZEKKE_MLKEM768_PUBLIC_KEY_BYTES],
                                      uint8_t secret_key[ZEKKE_MLKEM768_SECRET_KEY_BYTES],
                                      const uint8_t seed[ZEKKE_MLKEM768_SEED_BYTES]);

int zekke_mlkem768_encapsulate(uint8_t ciphertext[ZEKKE_MLKEM768_CIPHERTEXT_BYTES],
                               uint8_t shared_secret[ZEKKE_MLKEM768_SHARED_SECRET_BYTES],
                               const uint8_t public_key[ZEKKE_MLKEM768_PUBLIC_KEY_BYTES]);

int zekke_mlkem768_decapsulate(uint8_t shared_secret[ZEKKE_MLKEM768_SHARED_SECRET_BYTES],
                               const uint8_t ciphertext[ZEKKE_MLKEM768_CIPHERTEXT_BYTES],
                               const uint8_t secret_key[ZEKKE_MLKEM768_SECRET_KEY_BYTES]);

#endif
