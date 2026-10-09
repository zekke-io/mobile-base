#include <jni.h>
#include <stdlib.h>

#include "zekke_native.h"

#define JNI_FUNCTION(name) Java_zekke_core_primitives_ZekkeNativeJni_##name

static void wipe(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *) buffer;
    while (length--) {
        *bytes++ = 0;
    }
}

static int has_length(JNIEnv *env, jbyteArray array, jsize expected)
{
    return array != NULL && (*env)->GetArrayLength(env, array) == expected;
}

static uint8_t *copy_in(JNIEnv *env, jbyteArray array, jsize *length)
{
    *length = (*env)->GetArrayLength(env, array);
    uint8_t *buffer = malloc(*length > 0 ? (size_t) *length : 1);
    if (buffer != NULL && *length > 0) {
        (*env)->GetByteArrayRegion(env, array, 0, *length, (jbyte *) buffer);
    }
    return buffer;
}

static void release(uint8_t *buffer, jsize length)
{
    if (buffer != NULL) {
        wipe(buffer, (size_t) length);
        free(buffer);
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) vm;
    (void) reserved;
    return zekke_native_init() == ZEKKE_OK ? JNI_VERSION_1_6 : JNI_ERR;
}

JNIEXPORT void JNICALL JNI_FUNCTION(randomBytes)(JNIEnv *env, jobject receiver, jbyteArray out)
{
    (void) receiver;
    jsize length;
    uint8_t *buffer = copy_in(env, out, &length);
    if (buffer == NULL) {
        return;
    }
    zekke_random_bytes(buffer, (size_t) length);
    (*env)->SetByteArrayRegion(env, out, 0, length, (const jbyte *) buffer);
    release(buffer, length);
}

JNIEXPORT jint JNICALL JNI_FUNCTION(x25519PublicKey)(JNIEnv *env, jobject receiver, jbyteArray publicKey,
                                                      jbyteArray privateKey)
{
    (void) receiver;
    if (!has_length(env, publicKey, ZEKKE_X25519_KEY_BYTES) || !has_length(env, privateKey, ZEKKE_X25519_KEY_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t private_bytes[ZEKKE_X25519_KEY_BYTES];
    uint8_t public_bytes[ZEKKE_X25519_KEY_BYTES];
    (*env)->GetByteArrayRegion(env, privateKey, 0, ZEKKE_X25519_KEY_BYTES, (jbyte *) private_bytes);
    int status = zekke_x25519_public_key(public_bytes, private_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, publicKey, 0, ZEKKE_X25519_KEY_BYTES, (const jbyte *) public_bytes);
    }
    wipe(private_bytes, sizeof private_bytes);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(x25519SharedSecret)(JNIEnv *env, jobject receiver, jbyteArray sharedSecret,
                                                         jbyteArray privateKey, jbyteArray publicKey)
{
    (void) receiver;
    if (!has_length(env, sharedSecret, ZEKKE_X25519_KEY_BYTES) || !has_length(env, privateKey, ZEKKE_X25519_KEY_BYTES) ||
        !has_length(env, publicKey, ZEKKE_X25519_KEY_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t private_bytes[ZEKKE_X25519_KEY_BYTES];
    uint8_t public_bytes[ZEKKE_X25519_KEY_BYTES];
    uint8_t shared_bytes[ZEKKE_X25519_KEY_BYTES];
    (*env)->GetByteArrayRegion(env, privateKey, 0, ZEKKE_X25519_KEY_BYTES, (jbyte *) private_bytes);
    (*env)->GetByteArrayRegion(env, publicKey, 0, ZEKKE_X25519_KEY_BYTES, (jbyte *) public_bytes);
    int status = zekke_x25519_shared_secret(shared_bytes, private_bytes, public_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, sharedSecret, 0, ZEKKE_X25519_KEY_BYTES, (const jbyte *) shared_bytes);
    }
    wipe(private_bytes, sizeof private_bytes);
    wipe(shared_bytes, sizeof shared_bytes);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ed25519PublicKey)(JNIEnv *env, jobject receiver, jbyteArray publicKey, jbyteArray seed)
{
    (void) receiver;
    if (!has_length(env, publicKey, ZEKKE_ED25519_PUBLIC_KEY_BYTES) || !has_length(env, seed, ZEKKE_ED25519_SEED_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t seed_bytes[ZEKKE_ED25519_SEED_BYTES];
    uint8_t public_bytes[ZEKKE_ED25519_PUBLIC_KEY_BYTES];
    (*env)->GetByteArrayRegion(env, seed, 0, ZEKKE_ED25519_SEED_BYTES, (jbyte *) seed_bytes);
    int status = zekke_ed25519_public_key(public_bytes, seed_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, publicKey, 0, ZEKKE_ED25519_PUBLIC_KEY_BYTES, (const jbyte *) public_bytes);
    }
    wipe(seed_bytes, sizeof seed_bytes);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ed25519Sign)(JNIEnv *env, jobject receiver, jbyteArray signature, jbyteArray message,
                                                  jbyteArray seed)
{
    (void) receiver;
    if (!has_length(env, signature, ZEKKE_ED25519_SIGNATURE_BYTES) || message == NULL ||
        !has_length(env, seed, ZEKKE_ED25519_SEED_BYTES)) {
        return ZEKKE_FAILURE;
    }
    jsize message_length;
    uint8_t *message_bytes = copy_in(env, message, &message_length);
    if (message_bytes == NULL) {
        return ZEKKE_FAILURE;
    }
    uint8_t seed_bytes[ZEKKE_ED25519_SEED_BYTES];
    uint8_t signature_bytes[ZEKKE_ED25519_SIGNATURE_BYTES];
    (*env)->GetByteArrayRegion(env, seed, 0, ZEKKE_ED25519_SEED_BYTES, (jbyte *) seed_bytes);
    int status = zekke_ed25519_sign(signature_bytes, message_bytes, (size_t) message_length, seed_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, signature, 0, ZEKKE_ED25519_SIGNATURE_BYTES, (const jbyte *) signature_bytes);
    }
    wipe(seed_bytes, sizeof seed_bytes);
    release(message_bytes, message_length);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ed25519Verify)(JNIEnv *env, jobject receiver, jbyteArray signature, jbyteArray message,
                                                    jbyteArray publicKey)
{
    (void) receiver;
    if (!has_length(env, signature, ZEKKE_ED25519_SIGNATURE_BYTES) || message == NULL ||
        !has_length(env, publicKey, ZEKKE_ED25519_PUBLIC_KEY_BYTES)) {
        return ZEKKE_FAILURE;
    }
    jsize message_length;
    uint8_t *message_bytes = copy_in(env, message, &message_length);
    if (message_bytes == NULL) {
        return ZEKKE_FAILURE;
    }
    uint8_t signature_bytes[ZEKKE_ED25519_SIGNATURE_BYTES];
    uint8_t public_bytes[ZEKKE_ED25519_PUBLIC_KEY_BYTES];
    (*env)->GetByteArrayRegion(env, signature, 0, ZEKKE_ED25519_SIGNATURE_BYTES, (jbyte *) signature_bytes);
    (*env)->GetByteArrayRegion(env, publicKey, 0, ZEKKE_ED25519_PUBLIC_KEY_BYTES, (jbyte *) public_bytes);
    int status = zekke_ed25519_verify(signature_bytes, message_bytes, (size_t) message_length, public_bytes);
    release(message_bytes, message_length);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255IsValidPoint)(JNIEnv *env, jobject receiver, jbyteArray point)
{
    (void) receiver;
    if (!has_length(env, point, ZEKKE_RISTRETTO255_POINT_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t point_bytes[ZEKKE_RISTRETTO255_POINT_BYTES];
    (*env)->GetByteArrayRegion(env, point, 0, ZEKKE_RISTRETTO255_POINT_BYTES, (jbyte *) point_bytes);
    return zekke_ristretto255_is_valid_point(point_bytes);
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255FromUniformBytes)(JNIEnv *env, jobject receiver, jbyteArray point,
                                                                   jbyteArray uniformBytes)
{
    (void) receiver;
    if (!has_length(env, point, ZEKKE_RISTRETTO255_POINT_BYTES) ||
        !has_length(env, uniformBytes, ZEKKE_RISTRETTO255_UNIFORM_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t uniform[ZEKKE_RISTRETTO255_UNIFORM_BYTES];
    uint8_t point_bytes[ZEKKE_RISTRETTO255_POINT_BYTES];
    (*env)->GetByteArrayRegion(env, uniformBytes, 0, ZEKKE_RISTRETTO255_UNIFORM_BYTES, (jbyte *) uniform);
    int status = zekke_ristretto255_from_uniform_bytes(point_bytes, uniform);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, point, 0, ZEKKE_RISTRETTO255_POINT_BYTES, (const jbyte *) point_bytes);
    }
    wipe(uniform, sizeof uniform);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255ScalarMult)(JNIEnv *env, jobject receiver, jbyteArray result,
                                                             jbyteArray scalar, jbyteArray point)
{
    (void) receiver;
    if (!has_length(env, result, ZEKKE_RISTRETTO255_POINT_BYTES) ||
        !has_length(env, scalar, ZEKKE_RISTRETTO255_SCALAR_BYTES) ||
        !has_length(env, point, ZEKKE_RISTRETTO255_POINT_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t scalar_bytes[ZEKKE_RISTRETTO255_SCALAR_BYTES];
    uint8_t point_bytes[ZEKKE_RISTRETTO255_POINT_BYTES];
    uint8_t result_bytes[ZEKKE_RISTRETTO255_POINT_BYTES];
    (*env)->GetByteArrayRegion(env, scalar, 0, ZEKKE_RISTRETTO255_SCALAR_BYTES, (jbyte *) scalar_bytes);
    (*env)->GetByteArrayRegion(env, point, 0, ZEKKE_RISTRETTO255_POINT_BYTES, (jbyte *) point_bytes);
    int status = zekke_ristretto255_scalar_mult(result_bytes, scalar_bytes, point_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, result, 0, ZEKKE_RISTRETTO255_POINT_BYTES, (const jbyte *) result_bytes);
    }
    wipe(scalar_bytes, sizeof scalar_bytes);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255ScalarMultBase)(JNIEnv *env, jobject receiver, jbyteArray result,
                                                                 jbyteArray scalar)
{
    (void) receiver;
    if (!has_length(env, result, ZEKKE_RISTRETTO255_POINT_BYTES) ||
        !has_length(env, scalar, ZEKKE_RISTRETTO255_SCALAR_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t scalar_bytes[ZEKKE_RISTRETTO255_SCALAR_BYTES];
    uint8_t result_bytes[ZEKKE_RISTRETTO255_POINT_BYTES];
    (*env)->GetByteArrayRegion(env, scalar, 0, ZEKKE_RISTRETTO255_SCALAR_BYTES, (jbyte *) scalar_bytes);
    int status = zekke_ristretto255_scalar_mult_base(result_bytes, scalar_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, result, 0, ZEKKE_RISTRETTO255_POINT_BYTES, (const jbyte *) result_bytes);
    }
    wipe(scalar_bytes, sizeof scalar_bytes);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255ScalarInvert)(JNIEnv *env, jobject receiver, jbyteArray inverse,
                                                               jbyteArray scalar)
{
    (void) receiver;
    if (!has_length(env, inverse, ZEKKE_RISTRETTO255_SCALAR_BYTES) ||
        !has_length(env, scalar, ZEKKE_RISTRETTO255_SCALAR_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t scalar_bytes[ZEKKE_RISTRETTO255_SCALAR_BYTES];
    uint8_t inverse_bytes[ZEKKE_RISTRETTO255_SCALAR_BYTES];
    (*env)->GetByteArrayRegion(env, scalar, 0, ZEKKE_RISTRETTO255_SCALAR_BYTES, (jbyte *) scalar_bytes);
    int status = zekke_ristretto255_scalar_invert(inverse_bytes, scalar_bytes);
    if (status == ZEKKE_OK) {
        (*env)->SetByteArrayRegion(env, inverse, 0, ZEKKE_RISTRETTO255_SCALAR_BYTES, (const jbyte *) inverse_bytes);
    }
    wipe(scalar_bytes, sizeof scalar_bytes);
    wipe(inverse_bytes, sizeof inverse_bytes);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255ScalarReduce)(JNIEnv *env, jobject receiver, jbyteArray scalar,
                                                               jbyteArray wideScalar)
{
    (void) receiver;
    if (!has_length(env, scalar, ZEKKE_RISTRETTO255_SCALAR_BYTES) ||
        !has_length(env, wideScalar, ZEKKE_RISTRETTO255_UNIFORM_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t wide_bytes[ZEKKE_RISTRETTO255_UNIFORM_BYTES];
    uint8_t scalar_bytes[ZEKKE_RISTRETTO255_SCALAR_BYTES];
    (*env)->GetByteArrayRegion(env, wideScalar, 0, ZEKKE_RISTRETTO255_UNIFORM_BYTES, (jbyte *) wide_bytes);
    zekke_ristretto255_scalar_reduce(scalar_bytes, wide_bytes);
    (*env)->SetByteArrayRegion(env, scalar, 0, ZEKKE_RISTRETTO255_SCALAR_BYTES, (const jbyte *) scalar_bytes);
    wipe(wide_bytes, sizeof wide_bytes);
    wipe(scalar_bytes, sizeof scalar_bytes);
    return ZEKKE_OK;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(ristretto255ScalarRandom)(JNIEnv *env, jobject receiver, jbyteArray scalar)
{
    (void) receiver;
    if (!has_length(env, scalar, ZEKKE_RISTRETTO255_SCALAR_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t scalar_bytes[ZEKKE_RISTRETTO255_SCALAR_BYTES];
    zekke_ristretto255_scalar_random(scalar_bytes);
    (*env)->SetByteArrayRegion(env, scalar, 0, ZEKKE_RISTRETTO255_SCALAR_BYTES, (const jbyte *) scalar_bytes);
    wipe(scalar_bytes, sizeof scalar_bytes);
    return ZEKKE_OK;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(argon2id)(JNIEnv *env, jobject receiver, jbyteArray out, jbyteArray password,
                                               jbyteArray salt, jint iterations, jint memoryKib, jint parallelism)
{
    (void) receiver;
    if (out == NULL || password == NULL || salt == NULL || iterations <= 0 || memoryKib <= 0 || parallelism <= 0) {
        return ZEKKE_FAILURE;
    }
    jsize out_length = (*env)->GetArrayLength(env, out);
    jsize password_length;
    jsize salt_length;
    uint8_t *password_bytes = copy_in(env, password, &password_length);
    uint8_t *salt_bytes = copy_in(env, salt, &salt_length);
    uint8_t *out_bytes = malloc(out_length > 0 ? (size_t) out_length : 1);
    int status = ZEKKE_FAILURE;
    if (password_bytes != NULL && salt_bytes != NULL && out_bytes != NULL) {
        status = zekke_argon2id(out_bytes, (size_t) out_length, password_bytes, (size_t) password_length,
                                salt_bytes, (size_t) salt_length, (uint32_t) iterations, (uint32_t) memoryKib,
                                (uint32_t) parallelism);
        if (status == ZEKKE_OK) {
            (*env)->SetByteArrayRegion(env, out, 0, out_length, (const jbyte *) out_bytes);
        }
    }
    release(password_bytes, password_length);
    release(salt_bytes, salt_length);
    release(out_bytes, out_length);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(mlKem768KeyPairFromSeed)(JNIEnv *env, jobject receiver, jbyteArray publicKey,
                                                              jbyteArray secretKey, jbyteArray seed)
{
    (void) receiver;
    if (!has_length(env, publicKey, ZEKKE_MLKEM768_PUBLIC_KEY_BYTES) ||
        !has_length(env, secretKey, ZEKKE_MLKEM768_SECRET_KEY_BYTES) ||
        !has_length(env, seed, ZEKKE_MLKEM768_SEED_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t seed_bytes[ZEKKE_MLKEM768_SEED_BYTES];
    uint8_t *public_bytes = malloc(ZEKKE_MLKEM768_PUBLIC_KEY_BYTES);
    uint8_t *secret_bytes = malloc(ZEKKE_MLKEM768_SECRET_KEY_BYTES);
    int status = ZEKKE_FAILURE;
    if (public_bytes != NULL && secret_bytes != NULL) {
        (*env)->GetByteArrayRegion(env, seed, 0, ZEKKE_MLKEM768_SEED_BYTES, (jbyte *) seed_bytes);
        status = zekke_mlkem768_key_pair_from_seed(public_bytes, secret_bytes, seed_bytes);
        if (status == ZEKKE_OK) {
            (*env)->SetByteArrayRegion(env, publicKey, 0, ZEKKE_MLKEM768_PUBLIC_KEY_BYTES, (const jbyte *) public_bytes);
            (*env)->SetByteArrayRegion(env, secretKey, 0, ZEKKE_MLKEM768_SECRET_KEY_BYTES, (const jbyte *) secret_bytes);
        }
    }
    wipe(seed_bytes, sizeof seed_bytes);
    release(public_bytes, ZEKKE_MLKEM768_PUBLIC_KEY_BYTES);
    release(secret_bytes, ZEKKE_MLKEM768_SECRET_KEY_BYTES);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(mlKem768Encapsulate)(JNIEnv *env, jobject receiver, jbyteArray ciphertext,
                                                          jbyteArray sharedSecret, jbyteArray publicKey)
{
    (void) receiver;
    if (!has_length(env, ciphertext, ZEKKE_MLKEM768_CIPHERTEXT_BYTES) ||
        !has_length(env, sharedSecret, ZEKKE_MLKEM768_SHARED_SECRET_BYTES) ||
        !has_length(env, publicKey, ZEKKE_MLKEM768_PUBLIC_KEY_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t shared_bytes[ZEKKE_MLKEM768_SHARED_SECRET_BYTES];
    uint8_t *public_bytes = malloc(ZEKKE_MLKEM768_PUBLIC_KEY_BYTES);
    uint8_t *ciphertext_bytes = malloc(ZEKKE_MLKEM768_CIPHERTEXT_BYTES);
    int status = ZEKKE_FAILURE;
    if (public_bytes != NULL && ciphertext_bytes != NULL) {
        (*env)->GetByteArrayRegion(env, publicKey, 0, ZEKKE_MLKEM768_PUBLIC_KEY_BYTES, (jbyte *) public_bytes);
        status = zekke_mlkem768_encapsulate(ciphertext_bytes, shared_bytes, public_bytes);
        if (status == ZEKKE_OK) {
            (*env)->SetByteArrayRegion(env, ciphertext, 0, ZEKKE_MLKEM768_CIPHERTEXT_BYTES, (const jbyte *) ciphertext_bytes);
            (*env)->SetByteArrayRegion(env, sharedSecret, 0, ZEKKE_MLKEM768_SHARED_SECRET_BYTES, (const jbyte *) shared_bytes);
        }
    }
    wipe(shared_bytes, sizeof shared_bytes);
    release(public_bytes, ZEKKE_MLKEM768_PUBLIC_KEY_BYTES);
    release(ciphertext_bytes, ZEKKE_MLKEM768_CIPHERTEXT_BYTES);
    return status;
}

JNIEXPORT jint JNICALL JNI_FUNCTION(mlKem768Decapsulate)(JNIEnv *env, jobject receiver, jbyteArray sharedSecret,
                                                          jbyteArray ciphertext, jbyteArray secretKey)
{
    (void) receiver;
    if (!has_length(env, sharedSecret, ZEKKE_MLKEM768_SHARED_SECRET_BYTES) ||
        !has_length(env, ciphertext, ZEKKE_MLKEM768_CIPHERTEXT_BYTES) ||
        !has_length(env, secretKey, ZEKKE_MLKEM768_SECRET_KEY_BYTES)) {
        return ZEKKE_FAILURE;
    }
    uint8_t shared_bytes[ZEKKE_MLKEM768_SHARED_SECRET_BYTES];
    uint8_t *ciphertext_bytes = malloc(ZEKKE_MLKEM768_CIPHERTEXT_BYTES);
    uint8_t *secret_bytes = malloc(ZEKKE_MLKEM768_SECRET_KEY_BYTES);
    int status = ZEKKE_FAILURE;
    if (ciphertext_bytes != NULL && secret_bytes != NULL) {
        (*env)->GetByteArrayRegion(env, ciphertext, 0, ZEKKE_MLKEM768_CIPHERTEXT_BYTES, (jbyte *) ciphertext_bytes);
        (*env)->GetByteArrayRegion(env, secretKey, 0, ZEKKE_MLKEM768_SECRET_KEY_BYTES, (jbyte *) secret_bytes);
        status = zekke_mlkem768_decapsulate(shared_bytes, ciphertext_bytes, secret_bytes);
        if (status == ZEKKE_OK) {
            (*env)->SetByteArrayRegion(env, sharedSecret, 0, ZEKKE_MLKEM768_SHARED_SECRET_BYTES, (const jbyte *) shared_bytes);
        }
    }
    wipe(shared_bytes, sizeof shared_bytes);
    release(ciphertext_bytes, ZEKKE_MLKEM768_CIPHERTEXT_BYTES);
    release(secret_bytes, ZEKKE_MLKEM768_SECRET_KEY_BYTES);
    return status;
}
