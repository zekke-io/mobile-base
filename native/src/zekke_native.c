#include "zekke_native.h"

#include <sodium.h>
#include <argon2.h>
#include <mlkem_native.h>

int zekke_native_init(void)
{
    return sodium_init() >= 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

void zekke_random_bytes(uint8_t *out, size_t out_len)
{
    randombytes_buf(out, out_len);
}

int zekke_x25519_public_key(uint8_t public_key[ZEKKE_X25519_KEY_BYTES],
                            const uint8_t private_key[ZEKKE_X25519_KEY_BYTES])
{
    return crypto_scalarmult_curve25519_base(public_key, private_key) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_x25519_shared_secret(uint8_t shared_secret[ZEKKE_X25519_KEY_BYTES],
                               const uint8_t private_key[ZEKKE_X25519_KEY_BYTES],
                               const uint8_t public_key[ZEKKE_X25519_KEY_BYTES])
{
    return crypto_scalarmult_curve25519(shared_secret, private_key, public_key) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ed25519_public_key(uint8_t public_key[ZEKKE_ED25519_PUBLIC_KEY_BYTES],
                             const uint8_t seed[ZEKKE_ED25519_SEED_BYTES])
{
    uint8_t expanded_secret_key[crypto_sign_ed25519_SECRETKEYBYTES];
    int status = crypto_sign_ed25519_seed_keypair(public_key, expanded_secret_key, seed);
    sodium_memzero(expanded_secret_key, sizeof expanded_secret_key);
    return status == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ed25519_sign(uint8_t signature[ZEKKE_ED25519_SIGNATURE_BYTES],
                       const uint8_t *message, size_t message_len,
                       const uint8_t seed[ZEKKE_ED25519_SEED_BYTES])
{
    uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t expanded_secret_key[crypto_sign_ed25519_SECRETKEYBYTES];
    int status = crypto_sign_ed25519_seed_keypair(public_key, expanded_secret_key, seed);
    if (status == 0) {
        status = crypto_sign_ed25519_detached(signature, NULL, message, message_len, expanded_secret_key);
    }
    sodium_memzero(expanded_secret_key, sizeof expanded_secret_key);
    return status == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ed25519_verify(const uint8_t signature[ZEKKE_ED25519_SIGNATURE_BYTES],
                         const uint8_t *message, size_t message_len,
                         const uint8_t public_key[ZEKKE_ED25519_PUBLIC_KEY_BYTES])
{
    return crypto_sign_ed25519_verify_detached(signature, message, message_len, public_key) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ristretto255_is_valid_point(const uint8_t point[ZEKKE_RISTRETTO255_POINT_BYTES])
{
    return crypto_core_ristretto255_is_valid_point(point) == 1 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ristretto255_from_uniform_bytes(uint8_t point[ZEKKE_RISTRETTO255_POINT_BYTES],
                                          const uint8_t uniform_bytes[ZEKKE_RISTRETTO255_UNIFORM_BYTES])
{
    return crypto_core_ristretto255_from_hash(point, uniform_bytes) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ristretto255_scalar_mult(uint8_t result[ZEKKE_RISTRETTO255_POINT_BYTES],
                                   const uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES],
                                   const uint8_t point[ZEKKE_RISTRETTO255_POINT_BYTES])
{
    return crypto_scalarmult_ristretto255(result, scalar, point) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ristretto255_scalar_mult_base(uint8_t result[ZEKKE_RISTRETTO255_POINT_BYTES],
                                        const uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES])
{
    return crypto_scalarmult_ristretto255_base(result, scalar) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_ristretto255_scalar_invert(uint8_t inverse[ZEKKE_RISTRETTO255_SCALAR_BYTES],
                                     const uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES])
{
    return crypto_core_ristretto255_scalar_invert(inverse, scalar) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

void zekke_ristretto255_scalar_reduce(uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES],
                                      const uint8_t wide_scalar[ZEKKE_RISTRETTO255_UNIFORM_BYTES])
{
    crypto_core_ristretto255_scalar_reduce(scalar, wide_scalar);
}

void zekke_ristretto255_scalar_random(uint8_t scalar[ZEKKE_RISTRETTO255_SCALAR_BYTES])
{
    crypto_core_ristretto255_scalar_random(scalar);
}

int zekke_argon2id(uint8_t *out, size_t out_len,
                   const uint8_t *password, size_t password_len,
                   const uint8_t *salt, size_t salt_len,
                   uint32_t iterations, uint32_t memory_kib, uint32_t parallelism)
{
    return argon2id_hash_raw(iterations, memory_kib, parallelism,
                             password, password_len, salt, salt_len,
                             out, out_len) == ARGON2_OK ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_mlkem768_key_pair_from_seed(uint8_t public_key[ZEKKE_MLKEM768_PUBLIC_KEY_BYTES],
                                      uint8_t secret_key[ZEKKE_MLKEM768_SECRET_KEY_BYTES],
                                      const uint8_t seed[ZEKKE_MLKEM768_SEED_BYTES])
{
    return zekke_mlkem768_keypair_derand(public_key, secret_key, seed) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_mlkem768_encapsulate(uint8_t ciphertext[ZEKKE_MLKEM768_CIPHERTEXT_BYTES],
                               uint8_t shared_secret[ZEKKE_MLKEM768_SHARED_SECRET_BYTES],
                               const uint8_t public_key[ZEKKE_MLKEM768_PUBLIC_KEY_BYTES])
{
    uint8_t coins[MLKEM_SYMBYTES];
    randombytes_buf(coins, sizeof coins);
    int status = zekke_mlkem768_enc_derand(ciphertext, shared_secret, public_key, coins);
    sodium_memzero(coins, sizeof coins);
    return status == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}

int zekke_mlkem768_decapsulate(uint8_t shared_secret[ZEKKE_MLKEM768_SHARED_SECRET_BYTES],
                               const uint8_t ciphertext[ZEKKE_MLKEM768_CIPHERTEXT_BYTES],
                               const uint8_t secret_key[ZEKKE_MLKEM768_SECRET_KEY_BYTES])
{
    return zekke_mlkem768_dec(shared_secret, ciphertext, secret_key) == 0 ? ZEKKE_OK : ZEKKE_FAILURE;
}
