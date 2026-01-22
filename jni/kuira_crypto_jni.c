/*
 * Kuira Crypto JNI Bridge - SECURITY HARDENED
 *
 * Bridges Kotlin/Java → C → Rust FFI for cryptographic operations.
 *
 * Architecture:
 *   Kotlin: TransactionSigner / ShieldedKeyDeriver
 *     ↓
 *   JNI (this file): Extract bytes, call Rust, handle memory safely
 *     ↓
 *   Rust FFI: midnight-ledger cryptographic primitives
 *
 * SECURITY FEATURES:
 * - Sensitive data (keys, transaction data) zeroized after use
 * - Integer overflow checks on all arithmetic
 * - Comprehensive input validation
 * - Production logging to Android logcat
 * - Thread-safe (each call is independent)
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <android/log.h>

/* Logging macros */
#define LOG_TAG "KuiraCrypto"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#ifdef DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...) /* no-op in release */
#endif

/* Secure memory zeroization (prevents compiler optimization) */
static void* secure_memzero(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return ptr;
    }
    volatile uint8_t* volatile_ptr = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0;
    }
    return ptr;
}

/* Integer overflow-safe addition check */
static int safe_size_add(size_t a, size_t b, size_t* result) {
    if (a > SIZE_MAX - b) {
        return 0;  /* Overflow would occur */
    }
    *result = a + b;
    return 1;  /* Success */
}

/* Rust FFI declarations */

/* C struct matching Rust's #[repr(C)] ShieldedKeys */
typedef struct {
    char* coin_public_key;        /* 64 hex characters + null terminator */
    char* encryption_public_key;  /* 64 hex characters + null terminator */
} ShieldedKeys;

/* C struct matching Rust's #[repr(C)] SignatureBytes */
typedef struct {
    uint8_t* data;  /* Pointer to signature data */
    size_t len;     /* Length of signature data */
} SignatureBytes;

/* Rust FFI functions (defined in libkuira_crypto_ffi) */

/* Shielded key derivation (Phase 1B) */
extern ShieldedKeys* derive_shielded_keys(const uint8_t* seed_ptr, size_t seed_len);
extern void free_shielded_keys(ShieldedKeys* ptr);

/* Transaction signing (Phase 2D-FFI) */
extern void* create_signing_key(const uint8_t* private_key_ptr, size_t private_key_len);
extern void free_signing_key(void* ptr);
extern SignatureBytes sign_data(const void* signing_key_ptr, const uint8_t* data_ptr, size_t data_len);
extern void free_signature(uint8_t* data, size_t len);
extern uint8_t* get_verifying_key(const void* signing_key_ptr);
extern void free_verifying_key(uint8_t* ptr);
extern int32_t verify_signature(const uint8_t* public_key_ptr, const uint8_t* message_ptr, size_t message_len, const uint8_t* signature_ptr);

/* JNI function implementations */

/**
 * Derives shielded keys from seed (Phase 1B - Shielded Keys)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.shielded
 *   object ShieldedKeyDeriver {
 *       external fun nativeDeriveShieldedKeys(seed: ByteArray): String?
 *   }
 *
 * @param env JNI environment
 * @param obj ShieldedKeyDeriver object (unused, static method)
 * @param seed_array Java byte array (32 bytes expected)
 * @return Java string "coinPk|encPk" (64 hex chars each), or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ShieldedKeyDeriver_nativeDeriveShieldedKeys(
    JNIEnv* env,
    jobject obj,
    jbyteArray seed_array
) {
    /* Validate input */
    if (seed_array == NULL) {
        LOGE("nativeDeriveShieldedKeys: seed_array is NULL");
        return NULL;
    }

    /* Get array length */
    jsize seed_len = (*env)->GetArrayLength(env, seed_array);
    if (seed_len != 32) {
        LOGE("nativeDeriveShieldedKeys: invalid seed length %d (expected 32)", seed_len);
        return NULL;
    }

    /* Extract bytes from Java array (copy, not pin - safer) */
    uint8_t seed_buf[32];
    (*env)->GetByteArrayRegion(env, seed_array, 0, 32, (jbyte*)seed_buf);

    /* Check for exceptions during byte extraction */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeDeriveShieldedKeys: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        secure_memzero(seed_buf, 32);  /* SECURITY: Zeroize on error */
        return NULL;
    }

    /* Call Rust FFI */
    ShieldedKeys* keys = derive_shielded_keys(seed_buf, 32);

    /* SECURITY: Zeroize seed immediately after use */
    secure_memzero(seed_buf, 32);

    if (keys == NULL) {
        LOGE("nativeDeriveShieldedKeys: Rust FFI returned NULL");
        return NULL;
    }

    /* Validate string lengths (prevent buffer overflow) */
    size_t coin_len = strlen(keys->coin_public_key);
    size_t enc_len = strlen(keys->encryption_public_key);

    /* Expected: 64 hex characters each */
    if (coin_len > 128 || enc_len > 128) {
        LOGE("nativeDeriveShieldedKeys: invalid key lengths coin=%zu enc=%zu", coin_len, enc_len);
        free_shielded_keys(keys);
        return NULL;
    }

    /* Calculate result length with overflow check */
    size_t result_len;
    if (!safe_size_add(coin_len, 1, &result_len) ||  /* +1 for '|' */
        !safe_size_add(result_len, enc_len, &result_len) ||
        !safe_size_add(result_len, 1, &result_len)) {  /* +1 for '\0' */
        LOGE("nativeDeriveShieldedKeys: integer overflow in length calculation");
        free_shielded_keys(keys);
        return NULL;
    }

    /* Allocate result buffer */
    char* result = (char*)malloc(result_len);
    if (result == NULL) {
        LOGE("nativeDeriveShieldedKeys: malloc failed for %zu bytes", result_len);
        free_shielded_keys(keys);
        return NULL;
    }

    /* Safe string formatting */
    int written = snprintf(result, result_len, "%s|%s",
                          keys->coin_public_key, keys->encryption_public_key);
    if (written < 0 || (size_t)written >= result_len) {
        LOGE("nativeDeriveShieldedKeys: snprintf failed or truncated");
        free(result);
        free_shielded_keys(keys);
        return NULL;
    }

    /* Convert C string to Java string */
    jstring jresult = (*env)->NewStringUTF(env, result);
    if (jresult == NULL) {
        LOGE("nativeDeriveShieldedKeys: NewStringUTF failed");
    }

    /* Free native memory */
    free(result);
    free_shielded_keys(keys);

    return jresult;
}

/**
 * Creates a SigningKey from 32-byte private key (Phase 2D - Transaction Signing)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.ledger.signer
 *   object TransactionSigner {
 *       external fun nativeCreateSigningKey(privateKey: ByteArray): Long
 *   }
 *
 * SECURITY: Private key is zeroized from JNI stack memory after use.
 *
 * @param env JNI environment
 * @param obj TransactionSigner object (unused, static method)
 * @param private_key_array Java byte array (32 bytes expected)
 * @return Pointer to SigningKey as jlong (64-bit), or 0 on error
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_ledger_signer_TransactionSigner_nativeCreateSigningKey(
    JNIEnv* env,
    jobject obj,
    jbyteArray private_key_array
) {
    /* Validate input */
    if (private_key_array == NULL) {
        LOGE("nativeCreateSigningKey: private_key_array is NULL");
        return 0;
    }

    /* Get array length */
    jsize key_len = (*env)->GetArrayLength(env, private_key_array);
    if (key_len != 32) {
        LOGE("nativeCreateSigningKey: invalid key length %d (expected 32)", key_len);
        return 0;
    }

    /* Extract bytes from Java array */
    uint8_t key_buf[32];
    (*env)->GetByteArrayRegion(env, private_key_array, 0, 32, (jbyte*)key_buf);

    /* Check for exceptions during byte extraction */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeCreateSigningKey: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        secure_memzero(key_buf, 32);  /* SECURITY: Zeroize on error */
        return 0;
    }

    /* Call Rust FFI */
    void* signing_key = create_signing_key(key_buf, 32);

    /* SECURITY: Zeroize private key immediately after use */
    secure_memzero(key_buf, 32);

    if (signing_key == NULL) {
        LOGE("nativeCreateSigningKey: Rust FFI returned NULL");
        return 0;
    }

    LOGD("nativeCreateSigningKey: success, ptr=0x%p", signing_key);

    /* Return pointer as jlong (handles both 32-bit and 64-bit pointers) */
    return (jlong)(uintptr_t)signing_key;
}

/**
 * Frees a SigningKey
 *
 * JNI signature matches:
 *   external fun nativeFreeSigningKey(signingKeyPtr: Long)
 *
 * SECURITY: Idempotent (safe to call multiple times with same pointer).
 *
 * @param env JNI environment
 * @param obj TransactionSigner object
 * @param ptr Pointer to SigningKey (from nativeCreateSigningKey)
 */
JNIEXPORT void JNICALL
Java_com_midnight_kuira_core_ledger_signer_TransactionSigner_nativeFreeSigningKey(
    JNIEnv* env,
    jobject obj,
    jlong ptr
) {
    if (ptr != 0) {
        LOGD("nativeFreeSigningKey: freeing ptr=0x%lx", (unsigned long)ptr);
        free_signing_key((void*)(uintptr_t)ptr);
    } else {
        LOGW("nativeFreeSigningKey: called with null pointer (ignored)");
    }
}

/**
 * Signs data with Schnorr BIP-340
 *
 * JNI signature matches:
 *   external fun nativeSignData(signingKeyPtr: Long, data: ByteArray): ByteArray?
 *
 * SECURITY:
 * - Data buffer is zeroized after signing
 * - Signature length validated (must be 64 bytes for Schnorr)
 * - Increased limit to 10 MB (supports complex contract calls)
 *
 * @param env JNI environment
 * @param obj TransactionSigner object
 * @param signing_key_ptr Pointer to SigningKey
 * @param data_array Data to sign
 * @return Java byte array with signature (64 bytes), or NULL on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_midnight_kuira_core_ledger_signer_TransactionSigner_nativeSignData(
    JNIEnv* env,
    jobject obj,
    jlong signing_key_ptr,
    jbyteArray data_array
) {
    /* Validate inputs */
    if (signing_key_ptr == 0) {
        LOGE("nativeSignData: signing_key_ptr is NULL");
        return NULL;
    }

    if (data_array == NULL) {
        LOGE("nativeSignData: data_array is NULL");
        return NULL;
    }

    /* Get data length */
    jsize data_len = (*env)->GetArrayLength(env, data_array);

    /* Allocate buffer for data
     * Limit: 10 MB (justification: Midnight transactions can include complex
     * contract calls, DApp state, and multi-segment intents. 1 MB was too
     * restrictive for production use cases.) */
    const jsize MAX_DATA_SIZE = 1024 * 1024;  /* 1 MB - matches Rust FFI limit */

    /* Note: Empty data (length 0) is allowed - Schnorr can sign empty messages */
    if (data_len < 0 || data_len > MAX_DATA_SIZE) {
        LOGE("nativeSignData: invalid data_len %d (must be 0..%d)", data_len, MAX_DATA_SIZE);
        return NULL;
    }

    /* Handle empty data case (malloc(0) behavior is implementation-defined) */
    uint8_t* data_buf = NULL;
    if (data_len > 0) {
        data_buf = (uint8_t*)malloc(data_len);
        if (data_buf == NULL) {
            LOGE("nativeSignData: malloc failed for %d bytes", data_len);
            return NULL;
        }

        /* Extract data bytes */
        (*env)->GetByteArrayRegion(env, data_array, 0, data_len, (jbyte*)data_buf);
    }

    /* Check for exceptions (only relevant if data_len > 0) */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeSignData: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        if (data_buf != NULL) {
            secure_memzero(data_buf, data_len);  /* SECURITY: Zeroize before free */
            free(data_buf);
        }
        return NULL;
    }

    /* Call Rust FFI (data_buf can be NULL for empty data) */
    SignatureBytes sig = sign_data((void*)(uintptr_t)signing_key_ptr, data_buf, data_len);

    /* SECURITY: Zeroize data immediately after signing */
    if (data_buf != NULL) {
        secure_memzero(data_buf, data_len);
        free(data_buf);
    }

    /* Check for signing failure */
    if (sig.data == NULL || sig.len == 0) {
        LOGE("nativeSignData: Rust FFI returned NULL or empty signature");
        return NULL;
    }

    /* SECURITY: Validate signature length (Schnorr BIP-340 is always 64 bytes) */
    if (sig.len != 64) {
        LOGE("nativeSignData: invalid signature length %zu (expected 64)", sig.len);
        free_signature(sig.data, sig.len);
        return NULL;
    }

    /* Create Java byte array for signature */
    jbyteArray result = (*env)->NewByteArray(env, sig.len);
    if (result == NULL) {
        LOGE("nativeSignData: NewByteArray failed");
        free_signature(sig.data, sig.len);
        return NULL;
    }

    /* Copy signature bytes to Java array */
    (*env)->SetByteArrayRegion(env, result, 0, sig.len, (jbyte*)sig.data);

    /* Check for exceptions during copy */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeSignData: exception during SetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        free_signature(sig.data, sig.len);
        return NULL;
    }

    /* Free native signature memory */
    free_signature(sig.data, sig.len);

    LOGD("nativeSignData: success, signature length=%zu", sig.len);

    return result;
}

/**
 * Gets the verifying key (public key) from a SigningKey
 *
 * JNI signature matches:
 *   external fun nativeGetVerifyingKey(signingKeyPtr: Long): ByteArray?
 *
 * SECURITY: Public key length validated (must be 32 bytes for BIP-340).
 *
 * @param env JNI environment
 * @param obj TransactionSigner object
 * @param signing_key_ptr Pointer to SigningKey
 * @return Java byte array with public key (32 bytes), or NULL on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_midnight_kuira_core_ledger_signer_TransactionSigner_nativeGetVerifyingKey(
    JNIEnv* env,
    jobject obj,
    jlong signing_key_ptr
) {
    /* Validate input */
    if (signing_key_ptr == 0) {
        LOGE("nativeGetVerifyingKey: signing_key_ptr is NULL");
        return NULL;
    }

    /* Call Rust FFI */
    uint8_t* pub_key = get_verifying_key((void*)(uintptr_t)signing_key_ptr);

    /* Check for failure */
    if (pub_key == NULL) {
        LOGE("nativeGetVerifyingKey: Rust FFI returned NULL");
        return NULL;
    }

    /* Create Java byte array for public key (BIP-340 x-only is always 32 bytes) */
    const jsize PUB_KEY_SIZE = 32;
    jbyteArray result = (*env)->NewByteArray(env, PUB_KEY_SIZE);
    if (result == NULL) {
        LOGE("nativeGetVerifyingKey: NewByteArray failed");
        free_verifying_key(pub_key);
        return NULL;
    }

    /* Copy public key bytes to Java array */
    (*env)->SetByteArrayRegion(env, result, 0, PUB_KEY_SIZE, (jbyte*)pub_key);

    /* Check for exceptions during copy */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeGetVerifyingKey: exception during SetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        free_verifying_key(pub_key);
        return NULL;
    }

    /* Free native memory */
    free_verifying_key(pub_key);

    LOGD("nativeGetVerifyingKey: success");

    return result;
}

/**
 * Verifies a Schnorr BIP-340 signature.
 *
 * JNI signature:
 * (Lcom/midnight/kuira/core/ledger/signer/TransactionSigner;[B[B[B)Z
 *
 * @param public_key_array 32-byte BIP-340 public key
 * @param message_array Message that was signed
 * @param signature_array 64-byte Schnorr signature
 * @return true if signature is valid, false otherwise
 */
JNIEXPORT jboolean JNICALL
Java_com_midnight_kuira_core_ledger_signer_TransactionSigner_nativeVerifySignature(
    JNIEnv* env,
    jobject thiz,
    jbyteArray public_key_array,
    jbyteArray message_array,
    jbyteArray signature_array)
{
    /* Validate inputs */
    if (public_key_array == NULL || message_array == NULL || signature_array == NULL) {
        LOGE("nativeVerifySignature: null input array");
        return JNI_FALSE;
    }

    /* Check lengths */
    const jsize pub_key_len = (*env)->GetArrayLength(env, public_key_array);
    const jsize message_len = (*env)->GetArrayLength(env, message_array);
    const jsize sig_len = (*env)->GetArrayLength(env, signature_array);

    if (pub_key_len != 32) {
        LOGE("nativeVerifySignature: public key must be 32 bytes, got %d", pub_key_len);
        return JNI_FALSE;
    }

    if (sig_len != 64) {
        LOGE("nativeVerifySignature: signature must be 64 bytes, got %d", sig_len);
        return JNI_FALSE;
    }

    /* Note: Empty messages (length 0) are allowed - Schnorr can sign/verify empty data */
    if (message_len < 0 || message_len > 1024 * 1024) {
        LOGE("nativeVerifySignature: invalid message length %d", message_len);
        return JNI_FALSE;
    }

    /* Allocate buffers */
    uint8_t pub_key_buf[32];
    uint8_t sig_buf[64];

    /* Handle empty message case (malloc(0) behavior is implementation-defined) */
    uint8_t* message_buf = NULL;
    if (message_len > 0) {
        message_buf = (uint8_t*)malloc(message_len);
        if (message_buf == NULL) {
            LOGE("nativeVerifySignature: malloc failed for message buffer");
            return JNI_FALSE;
        }
    }

    /* Copy arrays to native buffers */
    (*env)->GetByteArrayRegion(env, public_key_array, 0, 32, (jbyte*)pub_key_buf);
    if (message_len > 0) {
        (*env)->GetByteArrayRegion(env, message_array, 0, message_len, (jbyte*)message_buf);
    }
    (*env)->GetByteArrayRegion(env, signature_array, 0, 64, (jbyte*)sig_buf);

    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeVerifySignature: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        if (message_buf != NULL) {
            free(message_buf);
        }
        return JNI_FALSE;
    }

    /* Call Rust FFI to verify (message_buf can be NULL for empty messages) */
    const int32_t result = verify_signature(pub_key_buf, message_buf, (size_t)message_len, sig_buf);

    /* Clean up */
    if (message_buf != NULL) {
        free(message_buf);
    }

    /* Return result */
    return (result == 1) ? JNI_TRUE : JNI_FALSE;
}

/*
 * JNI_OnLoad - Called when library is loaded
 *
 * Validates JVM version and initializes library.
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;

    /* Validate JVM version */
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed, JNI_VERSION_1_6 not supported");
        return JNI_ERR;
    }

    LOGI("Kuira Crypto JNI library loaded successfully (JNI 1.6)");
    LOGI("Security features: secure zeroization, overflow checks, validation");

    return JNI_VERSION_1_6;
}
