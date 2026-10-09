package zekke.core.primitives

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import zekke.core.primitives.cinterop.zekke_argon2id
import zekke.core.primitives.cinterop.zekke_ed25519_public_key
import zekke.core.primitives.cinterop.zekke_ed25519_sign
import zekke.core.primitives.cinterop.zekke_ed25519_verify
import zekke.core.primitives.cinterop.zekke_mlkem768_decapsulate
import zekke.core.primitives.cinterop.zekke_mlkem768_encapsulate
import zekke.core.primitives.cinterop.zekke_mlkem768_key_pair_from_seed
import zekke.core.primitives.cinterop.zekke_native_init
import zekke.core.primitives.cinterop.zekke_random_bytes
import zekke.core.primitives.cinterop.zekke_ristretto255_from_uniform_bytes
import zekke.core.primitives.cinterop.zekke_ristretto255_is_valid_point
import zekke.core.primitives.cinterop.zekke_ristretto255_scalar_invert
import zekke.core.primitives.cinterop.zekke_ristretto255_scalar_mult
import zekke.core.primitives.cinterop.zekke_ristretto255_scalar_mult_base
import zekke.core.primitives.cinterop.zekke_ristretto255_scalar_random
import zekke.core.primitives.cinterop.zekke_ristretto255_scalar_reduce
import zekke.core.primitives.cinterop.zekke_x25519_public_key
import zekke.core.primitives.cinterop.zekke_x25519_shared_secret

@OptIn(ExperimentalForeignApi::class)
private inline fun <R> ByteArray.withPointer(block: (CPointer<UByteVar>?) -> R): R =
    if (isEmpty()) block(null) else usePinned { block(it.addressOf(0).reinterpret()) }

@OptIn(ExperimentalForeignApi::class)
internal object ZekkeNativeCinterop : ZekkeNative {
    init {
        check(zekke_native_init() == ZEKKE_NATIVE_OK) { "libsodium failed to initialise" }
    }

    override fun randomBytes(out: ByteArray) =
        out.withPointer { zekke_random_bytes(it, out.size.convert()) }

    override fun x25519PublicKey(publicKey: ByteArray, privateKey: ByteArray): Int =
        publicKey.withPointer { publicPointer ->
            privateKey.withPointer { privatePointer -> zekke_x25519_public_key(publicPointer, privatePointer) }
        }

    override fun x25519SharedSecret(sharedSecret: ByteArray, privateKey: ByteArray, publicKey: ByteArray): Int =
        sharedSecret.withPointer { sharedPointer ->
            privateKey.withPointer { privatePointer ->
                publicKey.withPointer { publicPointer -> zekke_x25519_shared_secret(sharedPointer, privatePointer, publicPointer) }
            }
        }

    override fun ed25519PublicKey(publicKey: ByteArray, seed: ByteArray): Int =
        publicKey.withPointer { publicPointer ->
            seed.withPointer { seedPointer -> zekke_ed25519_public_key(publicPointer, seedPointer) }
        }

    override fun ed25519Sign(signature: ByteArray, message: ByteArray, seed: ByteArray): Int =
        signature.withPointer { signaturePointer ->
            message.withPointer { messagePointer ->
                seed.withPointer { seedPointer ->
                    zekke_ed25519_sign(signaturePointer, messagePointer, message.size.convert(), seedPointer)
                }
            }
        }

    override fun ed25519Verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Int =
        signature.withPointer { signaturePointer ->
            message.withPointer { messagePointer ->
                publicKey.withPointer { publicPointer ->
                    zekke_ed25519_verify(signaturePointer, messagePointer, message.size.convert(), publicPointer)
                }
            }
        }

    override fun ristretto255IsValidPoint(point: ByteArray): Int =
        point.withPointer { zekke_ristretto255_is_valid_point(it) }

    override fun ristretto255FromUniformBytes(point: ByteArray, uniformBytes: ByteArray): Int =
        point.withPointer { pointPointer ->
            uniformBytes.withPointer { uniformPointer -> zekke_ristretto255_from_uniform_bytes(pointPointer, uniformPointer) }
        }

    override fun ristretto255ScalarMult(result: ByteArray, scalar: ByteArray, point: ByteArray): Int =
        result.withPointer { resultPointer ->
            scalar.withPointer { scalarPointer ->
                point.withPointer { pointPointer -> zekke_ristretto255_scalar_mult(resultPointer, scalarPointer, pointPointer) }
            }
        }

    override fun ristretto255ScalarMultBase(result: ByteArray, scalar: ByteArray): Int =
        result.withPointer { resultPointer ->
            scalar.withPointer { scalarPointer -> zekke_ristretto255_scalar_mult_base(resultPointer, scalarPointer) }
        }

    override fun ristretto255ScalarInvert(inverse: ByteArray, scalar: ByteArray): Int =
        inverse.withPointer { inversePointer ->
            scalar.withPointer { scalarPointer -> zekke_ristretto255_scalar_invert(inversePointer, scalarPointer) }
        }

    override fun ristretto255ScalarReduce(scalar: ByteArray, wideScalar: ByteArray): Int =
        scalar.withPointer { scalarPointer ->
            wideScalar.withPointer { widePointer -> zekke_ristretto255_scalar_reduce(scalarPointer, widePointer) }
            ZEKKE_NATIVE_OK
        }

    override fun ristretto255ScalarRandom(scalar: ByteArray): Int =
        scalar.withPointer { scalarPointer ->
            zekke_ristretto255_scalar_random(scalarPointer)
            ZEKKE_NATIVE_OK
        }

    override fun argon2id(out: ByteArray, password: ByteArray, salt: ByteArray, iterations: Int, memoryKib: Int, parallelism: Int): Int =
        out.withPointer { outPointer ->
            password.withPointer { passwordPointer ->
                salt.withPointer { saltPointer ->
                    zekke_argon2id(
                        outPointer, out.size.convert(),
                        passwordPointer, password.size.convert(),
                        saltPointer, salt.size.convert(),
                        iterations.toUInt(), memoryKib.toUInt(), parallelism.toUInt(),
                    )
                }
            }
        }

    override fun mlKem768KeyPairFromSeed(publicKey: ByteArray, secretKey: ByteArray, seed: ByteArray): Int =
        publicKey.withPointer { publicPointer ->
            secretKey.withPointer { secretPointer ->
                seed.withPointer { seedPointer -> zekke_mlkem768_key_pair_from_seed(publicPointer, secretPointer, seedPointer) }
            }
        }

    override fun mlKem768Encapsulate(ciphertext: ByteArray, sharedSecret: ByteArray, publicKey: ByteArray): Int =
        ciphertext.withPointer { ciphertextPointer ->
            sharedSecret.withPointer { sharedPointer ->
                publicKey.withPointer { publicPointer -> zekke_mlkem768_encapsulate(ciphertextPointer, sharedPointer, publicPointer) }
            }
        }

    override fun mlKem768Decapsulate(sharedSecret: ByteArray, ciphertext: ByteArray, secretKey: ByteArray): Int =
        sharedSecret.withPointer { sharedPointer ->
            ciphertext.withPointer { ciphertextPointer ->
                secretKey.withPointer { secretPointer -> zekke_mlkem768_decapsulate(sharedPointer, ciphertextPointer, secretPointer) }
            }
        }
}
