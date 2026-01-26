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

/* Library initialization */
extern void kuira_crypto_init(void);

/* Shielded key derivation (Phase 1B) */
extern ShieldedKeys* derive_shielded_keys(const uint8_t* seed_ptr, size_t seed_len);
extern void free_shielded_keys(ShieldedKeys* ptr);

/* Dust key derivation (Phase 2D-1) */
extern char* derive_dust_public_key(const uint8_t* seed_ptr, size_t seed_len);
extern void free_c_string(char* ptr);

/* Dust state management (Phase 2D-2) */
extern void* create_dust_local_state(void);
extern char* dust_wallet_balance(const void* state_ptr, int64_t time_millis);
extern uint8_t* serialize_dust_state(const void* state_ptr);
extern void* deserialize_dust_state(const uint8_t* data_ptr, size_t data_len);
extern void free_dust_local_state(void* ptr);
extern void free_byte_array(uint8_t* ptr);

/* Dust UTXO iteration (Phase 2D-3) */
extern size_t dust_utxo_count(const void* state_ptr);
extern char* dust_get_utxo_at(const void* state_ptr, size_t index);

/* Dust event replay (Phase 2D-4) */
extern void* dust_replay_events(const void* state_ptr, const uint8_t* seed_ptr, size_t seed_len, const char* events_hex);

/* Transaction signing (Phase 2D-FFI) */
extern void* create_signing_key(const uint8_t* private_key_ptr, size_t private_key_len);
extern void free_signing_key(void* ptr);
extern SignatureBytes sign_data(const void* signing_key_ptr, const uint8_t* data_ptr, size_t data_len);
extern void free_signature(uint8_t* data, size_t len);
extern uint8_t* get_verifying_key(const void* signing_key_ptr);
extern void free_verifying_key(uint8_t* ptr);
extern int32_t verify_signature(const uint8_t* public_key_ptr, const uint8_t* message_ptr, size_t message_len, const uint8_t* signature_ptr);

/* Transaction serialization (Phase 2E) */
extern char* serialize_unshielded_transaction_stub(uint64_t ttl);
extern char* serialize_unshielded_transaction(const char* inputs_hex, const char* outputs_hex, const char* signatures_hex, uint64_t ttl, const char* binding_commitment_hex);
extern void free_serialized_transaction(char* ptr);

/* Signing message generation (Phase 2E) */
extern char* get_signing_message_for_input(const char* inputs_json, const char* outputs_json, uint32_t input_index, uint64_t ttl, const char* binding_commitment_hex);
extern void free_signing_message(char* ptr);

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

/**
 * Serializes a signed unshielded transaction to SCALE codec (Phase 2E STUB).
 *
 * **STUB VERSION:** Returns test hex for architecture testing.
 * Real SCALE serialization will be implemented iteratively.
 *
 * JNI signature:
 * (Lcom/midnight/kuira/core/ledger/signer/TransactionSigner;J)Ljava/lang/String;
 *
 * @param ttl Transaction time-to-live (milliseconds since epoch)
 * @return Hex-encoded SCALE bytes, or null on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_signer_TransactionSigner_nativeSerializeTransactionStub(
    JNIEnv* env,
    jobject thiz,
    jlong ttl)
{
    /* Validate TTL */
    if (ttl <= 0) {
        LOGE("nativeSerializeTransactionStub: invalid TTL %lld", (long long)ttl);
        return NULL;
    }

    /* Call Rust FFI stub */
    char* hex_str = serialize_unshielded_transaction_stub((uint64_t)ttl);
    if (hex_str == NULL) {
        LOGE("nativeSerializeTransactionStub: Rust FFI returned null");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, hex_str);

    /* Free Rust-allocated string */
    free_serialized_transaction(hex_str);

    if (result == NULL) {
        LOGE("nativeSerializeTransactionStub: NewStringUTF failed");
        return NULL;
    }

    LOGI("Transaction serialized (stub): %zu bytes hex", strlen(hex_str));
    return result;
}

/**
 * Serializes a signed unshielded transaction to SCALE codec (Phase 2E - REAL).
 *
 * JNI signature:
 * (Lcom/midnight/kuira/core/ledger/api/TransactionSerializer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)Ljava/lang/String;
 *
 * @param inputs_json JSON array of UtxoSpend objects
 * @param outputs_json JSON array of UtxoOutput objects
 * @param signatures_json JSON array of signature hex strings
 * @param ttl Transaction time-to-live (milliseconds since epoch)
 * @param binding_commitment_hex Hex-encoded binding commitment (MUST match the one from nativeGetSigningMessageForInput!)
 * @return Hex-encoded SCALE bytes, or null on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_api_FfiTransactionSerializer_nativeSerializeTransaction(
    JNIEnv* env,
    jobject thiz,
    jstring inputs_json,
    jstring outputs_json,
    jstring signatures_json,
    jlong ttl,
    jstring binding_commitment_hex)
{
    /* Validate inputs */
    if (inputs_json == NULL || outputs_json == NULL || signatures_json == NULL || binding_commitment_hex == NULL) {
        LOGE("nativeSerializeTransaction: null parameter");
        return NULL;
    }

    if (ttl <= 0) {
        LOGE("nativeSerializeTransaction: invalid TTL %lld", (long long)ttl);
        return NULL;
    }

    /* Convert Java strings to C strings */
    const char* inputs_c = (*env)->GetStringUTFChars(env, inputs_json, NULL);
    if (inputs_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for inputs");
        return NULL;
    }

    const char* outputs_c = (*env)->GetStringUTFChars(env, outputs_json, NULL);
    if (outputs_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for outputs");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        return NULL;
    }

    const char* signatures_c = (*env)->GetStringUTFChars(env, signatures_json, NULL);
    if (signatures_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for signatures");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        return NULL;
    }

    const char* binding_commitment_c = (*env)->GetStringUTFChars(env, binding_commitment_hex, NULL);
    if (binding_commitment_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for binding_commitment");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        return NULL;
    }

    /* Call Rust FFI with binding_commitment */
    char* hex_str = serialize_unshielded_transaction(inputs_c, outputs_c, signatures_c, (uint64_t)ttl, binding_commitment_c);

    /* Release Java string buffers */
    (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
    (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
    (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
    (*env)->ReleaseStringUTFChars(env, binding_commitment_hex, binding_commitment_c);

    if (hex_str == NULL) {
        LOGE("nativeSerializeTransaction: Rust FFI returned null");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, hex_str);

    /* Free Rust-allocated string */
    free_serialized_transaction(hex_str);

    if (result == NULL) {
        LOGE("nativeSerializeTransaction: NewStringUTF failed");
        return NULL;
    }

    LOGI("Transaction serialized (SCALE): %zu bytes hex", strlen(hex_str));
    return result;
}

/**
 * Generates signing message for a specific UTXO input (Phase 2E - CRITICAL for real transactions).
 *
 * This function builds an Intent, binds it, and returns the signature data that must be
 * signed for the given input index. This is THE key function for real on-chain transactions.
 *
 * JNI signature:
 * (Lcom/midnight/kuira/core/ledger/api/FfiTransactionSerializer;Ljava/lang/String;Ljava/lang/String;IJ)Ljava/lang/String;
 *
 * @param inputs_json JSON array of UtxoSpend objects (WITHOUT signatures)
 * @param outputs_json JSON array of UtxoOutput objects
 * @param input_index Which input to generate signature data for (0-based)
 * @param ttl Transaction time-to-live (milliseconds since epoch)
 * @return Hex-encoded signing message bytes, or null on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_api_FfiTransactionSerializer_nativeGetSigningMessageForInput(
    JNIEnv* env,
    jobject thiz,
    jstring inputs_json,
    jstring outputs_json,
    jint input_index,
    jlong ttl)
{
    /* Validate inputs */
    if (inputs_json == NULL || outputs_json == NULL) {
        LOGE("nativeGetSigningMessageForInput: null JSON string");
        return NULL;
    }

    if (input_index < 0) {
        LOGE("nativeGetSigningMessageForInput: invalid input_index %d (must be >= 0)", input_index);
        return NULL;
    }

    if (ttl <= 0) {
        LOGE("nativeGetSigningMessageForInput: invalid TTL %lld", (long long)ttl);
        return NULL;
    }

    /* Convert Java strings to C strings */
    const char* inputs_c = (*env)->GetStringUTFChars(env, inputs_json, NULL);
    if (inputs_c == NULL) {
        LOGE("nativeGetSigningMessageForInput: GetStringUTFChars failed for inputs");
        return NULL;
    }

    const char* outputs_c = (*env)->GetStringUTFChars(env, outputs_json, NULL);
    if (outputs_c == NULL) {
        LOGE("nativeGetSigningMessageForInput: GetStringUTFChars failed for outputs");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        return NULL;
    }

    LOGI("Getting signing message for input %d", input_index);

    /* Call Rust FFI to generate signing message (pass NULL to generate random binding_commitment) */
    char* json_response = get_signing_message_for_input(
        inputs_c,
        outputs_c,
        (uint32_t)input_index,
        (uint64_t)ttl,
        NULL  /* Generate random binding_commitment */
    );

    /* Release Java string buffers */
    (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
    (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);

    if (json_response == NULL) {
        LOGE("nativeGetSigningMessageForInput: Rust FFI returned null");
        return NULL;
    }

    LOGI("Generated signing message JSON: %s", json_response);

    /* Convert C string to Java string (returns JSON: {"signing_message": "hex", "binding_commitment": "hex"}) */
    jstring result = (*env)->NewStringUTF(env, json_response);

    /* Free Rust-allocated string */
    free_signing_message(json_response);

    if (result == NULL) {
        LOGE("nativeGetSigningMessageForInput: NewStringUTF failed");
        return NULL;
    }

    return result;
}

/*
 * JNI_OnLoad - Called when library is loaded
 *
 * Validates JVM version and initializes library.
 */
/**
 * Derives dust public key from seed (Phase 2D-1 - Dust Keys)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   object DustKeyDeriver {
 *       external fun nativeDeriveDustPublicKey(seed: ByteArray): String?
 *   }
 *
 * @param env JNI environment
 * @param obj DustKeyDeriver object (unused, static method)
 * @param seed_array Java byte array (32 bytes expected)
 * @return Java string with 64 hex characters (dust public key), or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustKeyDeriver_nativeDeriveDustPublicKey(
    JNIEnv* env,
    jobject obj,
    jbyteArray seed_array
) {
    /* Validate input */
    if (seed_array == NULL) {
        LOGE("nativeDeriveDustPublicKey: seed_array is NULL");
        return NULL;
    }

    /* Get array length */
    jsize seed_len = (*env)->GetArrayLength(env, seed_array);
    if (seed_len != 32) {
        LOGE("nativeDeriveDustPublicKey: invalid seed length %d (expected 32)", seed_len);
        return NULL;
    }

    /* Extract bytes from Java array (copy, not pin - safer) */
    uint8_t seed_buf[32];
    (*env)->GetByteArrayRegion(env, seed_array, 0, 32, (jbyte*)seed_buf);

    /* Check for exceptions during byte extraction */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeDeriveDustPublicKey: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        secure_memzero(seed_buf, 32);  /* SECURITY: Zeroize on error */
        return NULL;
    }

    /* Call Rust FFI */
    char* dust_pk = derive_dust_public_key(seed_buf, 32);

    /* SECURITY: Zeroize seed immediately after use */
    secure_memzero(seed_buf, 32);

    if (dust_pk == NULL) {
        LOGE("nativeDeriveDustPublicKey: Rust FFI returned NULL");
        return NULL;
    }

    /* Validate string length (prevent buffer overflow) */
    size_t pk_len = strlen(dust_pk);

    /* Expected: 66 hex characters (33 bytes: 1-byte tag + 32 bytes data) */
    /* Use <= for forward compatibility with potential shorter encodings */
    if (pk_len > 66 || pk_len < 64) {
        LOGE("nativeDeriveDustPublicKey: invalid key length %zu (expected 64-66 chars)", pk_len);
        free_c_string(dust_pk);
        return NULL;
    }

    /* Convert C string to Java string */
    jstring jresult = (*env)->NewStringUTF(env, dust_pk);
    if (jresult == NULL) {
        LOGE("nativeDeriveDustPublicKey: NewStringUTF failed");
    }

    /* Free native memory */
    free_c_string(dust_pk);

    return jresult;
}

/**
 * Creates a new DustLocalState instance (Phase 2D-2 - Dust State)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   class DustLocalState {
 *       companion object {
 *           private external fun nativeCreateDustLocalState(): Long
 *       }
 *   }
 *
 * Note: Companion object methods have "$Companion" in their JNI signature
 *
 * @param env JNI environment
 * @param obj DustLocalState$Companion object
 * @return Native pointer to DustLocalState as jlong, or 0 on error
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_00024Companion_nativeCreateDustLocalState(
    JNIEnv* env,
    jobject obj
) {
    /* Call Rust FFI to create state */
    void* state_ptr = create_dust_local_state();

    if (state_ptr == NULL) {
        LOGE("nativeCreateDustLocalState: Rust FFI returned NULL");
        return 0;
    }

    LOGD("nativeCreateDustLocalState: created state at %p", state_ptr);

    /* Return pointer as jlong */
    return (jlong)(uintptr_t)state_ptr;
}

/**
 * Gets wallet balance at a specific time (Phase 2D-2 - Dust State)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   object DustLocalState {
 *       external fun nativeDustWalletBalance(statePtr: Long, timeMillis: Long): String?
 *   }
 *
 * @param env JNI environment
 * @param obj DustLocalState object (unused, static method)
 * @param state_ptr Native pointer to DustLocalState
 * @param time_millis Unix timestamp in milliseconds
 * @return Balance as decimal string, or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_nativeDustWalletBalance(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr,
    jlong time_millis
) {
    /* Validate pointer */
    if (state_ptr == 0) {
        LOGE("nativeDustWalletBalance: state_ptr is 0 (null)");
        return NULL;
    }

    /* Call Rust FFI */
    void* state = (void*)(uintptr_t)state_ptr;
    char* balance_str = dust_wallet_balance(state, (int64_t)time_millis);

    if (balance_str == NULL) {
        LOGE("nativeDustWalletBalance: Rust FFI returned NULL");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring jresult = (*env)->NewStringUTF(env, balance_str);
    if (jresult == NULL) {
        LOGE("nativeDustWalletBalance: NewStringUTF failed");
    }

    /* Free native memory */
    free_c_string(balance_str);

    return jresult;
}

/**
 * Serializes DustLocalState to bytes (Phase 2D-2 - Dust State)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   object DustLocalState {
 *       external fun nativeSerializeDustState(statePtr: Long): ByteArray?
 *   }
 *
 * @param env JNI environment
 * @param obj DustLocalState object (unused, static method)
 * @param state_ptr Native pointer to DustLocalState
 * @return Serialized bytes, or NULL on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_nativeSerializeDustState(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr
) {
    /* Validate pointer */
    if (state_ptr == 0) {
        LOGE("nativeSerializeDustState: state_ptr is 0 (null)");
        return NULL;
    }

    /* Call Rust FFI */
    void* state = (void*)(uintptr_t)state_ptr;
    uint8_t* bytes_ptr = serialize_dust_state(state);

    if (bytes_ptr == NULL) {
        LOGE("nativeSerializeDustState: Rust FFI returned NULL");
        return NULL;
    }

    /* Read length from first 8 bytes (little-endian u64) */
    /* Safe bounds: bytes_ptr guaranteed to have at least 8 bytes from Rust */
    uint64_t data_len =
        ((uint64_t)bytes_ptr[0])       |
        ((uint64_t)bytes_ptr[1] << 8)  |
        ((uint64_t)bytes_ptr[2] << 16) |
        ((uint64_t)bytes_ptr[3] << 24) |
        ((uint64_t)bytes_ptr[4] << 32) |
        ((uint64_t)bytes_ptr[5] << 40) |
        ((uint64_t)bytes_ptr[6] << 48) |
        ((uint64_t)bytes_ptr[7] << 56);

    LOGD("nativeSerializeDustState: serialized %llu bytes", (unsigned long long)data_len);

    /* Check for JNI array size limit (max 2GB = INT_MAX) */
    if (data_len > (uint64_t)INT_MAX) {
        LOGE("nativeSerializeDustState: data too large (%llu bytes, max %d)",
             (unsigned long long)data_len, INT_MAX);
        free_byte_array(bytes_ptr);
        return NULL;
    }

    /* Create Java byte array (skip the 8-byte length prefix) */
    jbyteArray jresult = (*env)->NewByteArray(env, (jsize)data_len);
    if (jresult == NULL) {
        LOGE("nativeSerializeDustState: NewByteArray failed");
        free_byte_array(bytes_ptr);
        return NULL;
    }

    /* Copy data to Java array (starting after the 8-byte length) */
    (*env)->SetByteArrayRegion(env, jresult, 0, (jsize)data_len, (jbyte*)(bytes_ptr + 8));

    /* Check for exceptions */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeSerializeDustState: exception during SetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        free_byte_array(bytes_ptr);
        return NULL;
    }

    /* Free native memory */
    free_byte_array(bytes_ptr);

    return jresult;
}

/**
 * Deserializes DustLocalState from bytes (Phase 2D-4 - State Persistence)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   class DustLocalState {
 *       companion object {
 *           private external fun nativeDeserializeDustState(data: ByteArray): Long
 *       }
 *   }
 *
 * @param env JNI environment
 * @param clazz DustLocalState$Companion class (static companion object)
 * @param data_array Serialized DustLocalState bytes
 * @return Native pointer to DustLocalState, or 0 on error
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_00024Companion_nativeDeserializeDustState(
    JNIEnv* env,
    jclass clazz,
    jbyteArray data_array
) {
    /* Validate input */
    if (data_array == NULL) {
        LOGE("nativeDeserializeDustState: data_array is NULL");
        return 0;
    }

    /* Get array length */
    jsize data_len = (*env)->GetArrayLength(env, data_array);
    if (data_len == 0) {
        LOGE("nativeDeserializeDustState: data_array is empty");
        return 0;
    }

    LOGD("nativeDeserializeDustState: deserializing %d bytes", data_len);

    /* Get array data (pinned - guaranteed not to move) */
    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data_array, NULL);
    if (data_bytes == NULL) {
        LOGE("nativeDeserializeDustState: GetByteArrayElements failed");
        return 0;
    }

    /* Call Rust FFI to deserialize */
    void* state_ptr = deserialize_dust_state((const uint8_t*)data_bytes, (size_t)data_len);

    /* Release array (no copy back needed - JNI_ABORT) */
    (*env)->ReleaseByteArrayElements(env, data_array, data_bytes, JNI_ABORT);

    if (state_ptr == NULL) {
        LOGE("nativeDeserializeDustState: Rust FFI returned NULL (deserialization failed)");
        return 0;
    }

    LOGD("nativeDeserializeDustState: successfully deserialized state at %p", state_ptr);

    return (jlong)(uintptr_t)state_ptr;
}

/**
 * Frees a DustLocalState instance (Phase 2D-2 - Dust State)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   object DustLocalState {
 *       external fun nativeFreeDustLocalState(statePtr: Long)
 *   }
 *
 * @param env JNI environment
 * @param obj DustLocalState object (unused, static method)
 * @param state_ptr Native pointer to DustLocalState
 */
JNIEXPORT void JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_nativeFreeDustLocalState(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr
) {
    /* Validate pointer */
    if (state_ptr == 0) {
        LOGW("nativeFreeDustLocalState: state_ptr is 0 (null), ignoring");
        return;
    }

    LOGD("nativeFreeDustLocalState: freeing state at %p", (void*)(uintptr_t)state_ptr);

    /* Call Rust FFI to free */
    void* state = (void*)(uintptr_t)state_ptr;
    free_dust_local_state(state);
}

/**
 * Gets the count of dust UTXOs in the wallet (Phase 2D-3 - UTXO Iteration)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   object DustLocalState {
 *       external fun nativeDustUtxoCount(statePtr: Long): Int
 *   }
 *
 * @param env JNI environment
 * @param obj DustLocalState object (unused, static method)
 * @param state_ptr Native pointer to DustLocalState
 * @return Number of UTXOs, or 0 on error
 */
JNIEXPORT jint JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_nativeDustUtxoCount(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr
) {
    /* Validate pointer */
    if (state_ptr == 0) {
        LOGE("nativeDustUtxoCount: state_ptr is 0 (null)");
        return 0;
    }

    /* Call Rust FFI */
    void* state = (void*)(uintptr_t)state_ptr;
    size_t count = dust_utxo_count(state);

    /* Check for overflow (size_t → jint) */
    if (count > (size_t)INT_MAX) {
        LOGE("nativeDustUtxoCount: count too large (%zu)", count);
        return INT_MAX;
    }

    return (jint)count;
}

/**
 * Gets a dust UTXO at a specific index (Phase 2D-3 - UTXO Iteration)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   object DustLocalState {
 *       external fun nativeDustGetUtxoAt(statePtr: Long, index: Int): String?
 *   }
 *
 * @param env JNI environment
 * @param obj DustLocalState object (unused, static method)
 * @param state_ptr Native pointer to DustLocalState
 * @param index Index of UTXO to retrieve
 * @return Hex-encoded serialized UTXO, or NULL if out of bounds
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_nativeDustGetUtxoAt(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr,
    jint index
) {
    /* Validate pointer */
    if (state_ptr == 0) {
        LOGE("nativeDustGetUtxoAt: state_ptr is 0 (null)");
        return NULL;
    }

    /* Validate index */
    if (index < 0) {
        LOGE("nativeDustGetUtxoAt: negative index %d", index);
        return NULL;
    }

    /* Call Rust FFI */
    void* state = (void*)(uintptr_t)state_ptr;
    char* utxo_hex = dust_get_utxo_at(state, (size_t)index);

    if (utxo_hex == NULL) {
        LOGD("nativeDustGetUtxoAt: index %d out of bounds or error", index);
        return NULL;
    }

    /* Convert C string to Java string */
    jstring jresult = (*env)->NewStringUTF(env, utxo_hex);
    if (jresult == NULL) {
        LOGE("nativeDustGetUtxoAt: NewStringUTF failed");
    }

    /* Free native memory */
    free_c_string(utxo_hex);

    return jresult;
}

/**
 * Replays blockchain events into DustLocalState to sync wallet (Phase 2D-4 - Event Replay)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.crypto.dust
 *   class DustLocalState {
 *       private external fun nativeDustReplayEvents(
 *           statePtr: Long,
 *           seed: ByteArray,
 *           eventsHex: String
 *       ): Long
 *   }
 *
 * @param env JNI environment
 * @param obj DustLocalState object
 * @param state_ptr Native pointer to DustLocalState
 * @param seed_array 32-byte seed for deriving DustSecretKey
 * @param events_hex Hex-encoded SCALE-serialized events
 * @return Pointer to new DustLocalState with events applied, or 0 on error
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_dust_DustLocalState_nativeDustReplayEvents(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr,
    jbyteArray seed_array,
    jstring events_hex
) {
    /* Validate inputs */
    if (state_ptr == 0) {
        LOGE("nativeDustReplayEvents: state_ptr is 0 (null)");
        return 0;
    }

    if (seed_array == NULL) {
        LOGE("nativeDustReplayEvents: seed_array is NULL");
        return 0;
    }

    if (events_hex == NULL) {
        LOGE("nativeDustReplayEvents: events_hex is NULL");
        return 0;
    }

    /* Get seed length */
    jsize seed_len = (*env)->GetArrayLength(env, seed_array);
    if (seed_len != 32) {
        LOGE("nativeDustReplayEvents: invalid seed length %d (expected 32)", seed_len);
        return 0;
    }

    /* Extract seed bytes */
    uint8_t seed_buf[32];
    (*env)->GetByteArrayRegion(env, seed_array, 0, 32, (jbyte*)seed_buf);

    /* Check for exceptions */
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeDustReplayEvents: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        secure_memzero(seed_buf, 32);
        return 0;
    }

    /* Convert events hex string to C string */
    const char* events_hex_c = (*env)->GetStringUTFChars(env, events_hex, NULL);
    if (events_hex_c == NULL) {
        LOGE("nativeDustReplayEvents: GetStringUTFChars failed for events_hex");
        secure_memzero(seed_buf, 32);
        return 0;
    }

    LOGD("nativeDustReplayEvents: replaying events hex (length=%zu)", strlen(events_hex_c));

    /* Call Rust FFI */
    void* state = (void*)(uintptr_t)state_ptr;
    void* new_state = dust_replay_events(state, seed_buf, 32, events_hex_c);

    /* SECURITY: Zeroize seed after use */
    secure_memzero(seed_buf, 32);

    /* Release Java string */
    (*env)->ReleaseStringUTFChars(env, events_hex, events_hex_c);

    if (new_state == NULL) {
        LOGE("nativeDustReplayEvents: Rust FFI returned NULL");
        return 0;
    }

    LOGD("nativeDustReplayEvents: success, new_state=%p", new_state);

    /* Return new state pointer as jlong */
    return (jlong)(uintptr_t)new_state;
}

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

    /* Initialize Rust library (sets up Android logging) */
    kuira_crypto_init();
    LOGI("Rust library initialized with Android logging");

    return JNI_VERSION_1_6;
}
