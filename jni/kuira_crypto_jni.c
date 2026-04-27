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

/* Dust spend creation (Phase 2E) */
extern char* create_dust_spend(const void* state_ptr, const uint8_t* seed_ptr, size_t seed_len, size_t utxo_index, const char* v_fee_str, int64_t current_time_ms);

/* Zswap (shielded) state management (Phase 4B-Shielded) */
extern void* create_zswap_local_state(void);
extern void free_zswap_local_state(void* ptr);
extern void* zswap_replay_events(const void* state_ptr, const uint8_t* seed_ptr, size_t seed_len, const char* events_hex);
extern const char* zswap_get_balances(const void* state_ptr);
extern int32_t zswap_get_coin_count(const void* state_ptr);
extern uint64_t zswap_get_first_free(const void* state_ptr);
extern const char* zswap_serialize(const void* state_ptr);
extern void* zswap_deserialize(const char* hex_ptr);
extern void free_zswap_string(char* ptr);

/* Zswap transfer primitives (Phase 3 — Step 7, ADR-001) */
typedef struct {
    void* new_state;    /* New ZswapLocalState pointer (null on error) */
    char* result_json;  /* JSON with input_hex + binding_randomness_hex (null on error) */
} ZswapSpendResult;

extern const char* zswap_select_coins(const void* state_ptr, const char* token_type_hex, const char* amount_str);
extern ZswapSpendResult zswap_spend_coin(const void* state_ptr, const uint8_t* seed_ptr, size_t seed_len, const char* coin_json);
extern const char* zswap_create_output(const char* recipient_coin_pk_hex, const char* recipient_enc_pk_hex, const char* token_type_hex, const char* amount_str);
extern const char* zswap_build_offer(const char* inputs_hex_json, const char* outputs_hex_json);
extern const char* zswap_merge_offers(const char* offer1_hex, const char* offer2_hex);
extern const char* zswap_serialize_offer(const char* offer_hex);
extern const char* zswap_build_shielded_transaction(const char* offer_hex, const char* network_id, const char* dust_tx_hex, size_t reserved1, const char* reserved2, uint64_t reserved3, uint64_t ttl_ms);
extern const char* zswap_build_shielded_transaction_with_dust(const char* offer_hex, const char* network_id, const void* dust_state_ptr, const uint8_t* dust_seed_ptr, size_t dust_seed_len, const char* dust_utxos_json, uint64_t current_time_ms, uint64_t ttl_ms);

/* Local ZK proving (Phase 4C) */
extern const char* zkir_prove_transaction_local(const char* unproven_tx_hex, const char* keys_dir);
extern void free_proven_string(char* ptr);

/* Contract runtime (Phase 6) */
extern uint64_t contract_state_create(const char* state_hex);
extern uint64_t contract_state_create_with_nulls(uint32_t num_slots);
extern void contract_state_set_operation(uint64_t handle, const char* name);
extern const char* contract_state_serialize(uint64_t handle);
extern void contract_state_free(uint64_t handle);
extern const char* contract_state_read_fields(uint64_t handle);
extern const char* contract_query(uint64_t handle, const char* opcodes_json);
extern const char* contract_persistent_hash(const char* input_hex);
extern const char* contract_persistent_hash_aligned(const char* aligned_value_json);
extern const char* contract_big_int_to_value(const char* bigint_str);
extern const char* contract_value_to_big_int(const char* value_json);
extern void contract_free_string(char* ptr);
extern const char* contract_assemble_call_tx(const char* params_json);
extern uint64_t contract_state_clone(uint64_t handle);

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
extern char* serialize_unshielded_transaction(const char* inputs_hex, const char* outputs_hex, const char* signatures_hex, const char* dust_actions_hex, uint64_t ttl, const char* binding_commitment_hex, const char* network_id);
extern char* serialize_unshielded_transaction_with_dust(const char* inputs_hex, const char* outputs_hex, const char* signatures_hex, const void* dust_state_ptr, const uint8_t* seed_ptr, size_t seed_len, const char* dust_utxos_json, int64_t current_time_ms, uint64_t ttl, const char* binding_commitment_hex, const char* network_id);
extern void free_serialized_transaction(char* ptr);

/* Signing message generation (Phase 2E) */
extern char* get_signing_message_for_input(const char* inputs_json, const char* outputs_json, uint32_t input_index, uint64_t ttl, const char* binding_commitment_hex);
extern void free_signing_message(char* ptr);

/* Transaction sealing (Phase 2) */
extern char* seal_proven_transaction(const char* proven_tx_hex);

/* Transaction hash extraction (Phase 2) */
extern char* get_transaction_hash(const char* sealed_tx_hex);

/* Fee calculation (Phase 2E) */
extern char* calculate_transaction_fee(const char* tx_hex, const char* params_hex, uint32_t fee_blocks_margin);

/* Dust registration transaction builder (serialize.rs) */
extern char* build_dust_registration_transaction(const uint8_t* night_private_key_ptr, size_t night_private_key_len, const char* dust_public_key_hex, const char* allow_fee_payment_str, uint64_t ttl_millis, int64_t current_time_millis, const char* utxos_json, const char* network_id);

/* Transaction balancing — balance proven tx with dust fees (balance_ffi.rs) */
extern char* balance_proven_transaction(const char* proven_tx_hex, void* dust_state_ptr, const uint8_t* seed_ptr, size_t seed_len, const char* ledger_params_hex, int64_t current_time_ms, const char* keys_dir, const char* network_id);
extern void free_balanced_transaction(char* ptr);

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
 * Serializes a signed unshielded transaction to SCALE codec (Phase 2E - REAL with DUST).
 *
 * JNI signature:
 * (Lcom/midnight/kuira/core/ledger/api/TransactionSerializer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)Ljava/lang/String;
 *
 * @param inputs_json JSON array of UtxoSpend objects
 * @param outputs_json JSON array of UtxoOutput objects
 * @param signatures_json JSON array of signature hex strings
 * @param dust_actions_json JSON array of DustSpend objects (empty array if no dust)
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
    jstring dust_actions_json,
    jlong ttl,
    jstring binding_commitment_hex,
    jstring network_id)
{
    /* Validate inputs */
    if (inputs_json == NULL || outputs_json == NULL || signatures_json == NULL || dust_actions_json == NULL || binding_commitment_hex == NULL || network_id == NULL) {
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

    const char* dust_actions_c = (*env)->GetStringUTFChars(env, dust_actions_json, NULL);
    if (dust_actions_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for dust_actions");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        return NULL;
    }

    const char* binding_commitment_c = (*env)->GetStringUTFChars(env, binding_commitment_hex, NULL);
    if (binding_commitment_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for binding_commitment");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        (*env)->ReleaseStringUTFChars(env, dust_actions_json, dust_actions_c);
        return NULL;
    }

    const char* network_id_c = (*env)->GetStringUTFChars(env, network_id, NULL);
    if (network_id_c == NULL) {
        LOGE("nativeSerializeTransaction: GetStringUTFChars failed for network_id");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        (*env)->ReleaseStringUTFChars(env, dust_actions_json, dust_actions_c);
        (*env)->ReleaseStringUTFChars(env, binding_commitment_hex, binding_commitment_c);
        return NULL;
    }

    /* Call Rust FFI with dust actions */
    char* hex_str = serialize_unshielded_transaction(inputs_c, outputs_c, signatures_c, dust_actions_c, (uint64_t)ttl, binding_commitment_c, network_id_c);

    /* Release Java string buffers */
    (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
    (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
    (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
    (*env)->ReleaseStringUTFChars(env, dust_actions_json, dust_actions_c);
    (*env)->ReleaseStringUTFChars(env, binding_commitment_hex, binding_commitment_c);
    (*env)->ReleaseStringUTFChars(env, network_id, network_id_c);

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

    LOGI("Transaction serialized (SCALE) with dust: %zu bytes hex", strlen(hex_str));
    return result;
}

/**
 * Serializes a signed unshielded transaction with REAL dust fee payment to SCALE codec.
 *
 * This function creates real DustActions by calling state.spend() on the DustLocalState,
 * following the TypeScript SDK pattern. This is the CORRECT way to add dust fees.
 *
 * JNI signature:
 * (Lcom/midnight/kuira/core/ledger/api/TransactionSerializer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJ[BLjava/lang/String;JJLjava/lang/String;)Ljava/lang/String;
 *
 * @param inputs_json JSON array of UtxoSpend objects
 * @param outputs_json JSON array of UtxoOutput objects
 * @param signatures_json JSON array of signature hex strings
 * @param dust_state_ptr Pointer to DustLocalState (long from Kotlin)
 * @param seed ByteArray (32 bytes)
 * @param dust_utxos_json JSON array of {utxo_index, v_fee} objects
 * @param current_time_ms Current time in milliseconds
 * @param ttl Transaction time-to-live (milliseconds since epoch)
 * @param binding_commitment_hex Hex-encoded binding commitment
 * @return Hex-encoded SCALE bytes, or null on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_api_FfiTransactionSerializer_nativeSerializeTransactionWithDust(
    JNIEnv* env,
    jobject thiz,
    jstring inputs_json,
    jstring outputs_json,
    jstring signatures_json,
    jlong dust_state_ptr,
    jbyteArray seed,
    jstring dust_utxos_json,
    jlong current_time_ms,
    jlong ttl,
    jstring binding_commitment_hex,
    jstring network_id)
{
    /* Validate inputs */
    if (inputs_json == NULL || outputs_json == NULL || signatures_json == NULL ||
        dust_state_ptr == 0 || seed == NULL || dust_utxos_json == NULL ||
        binding_commitment_hex == NULL || network_id == NULL) {
        LOGE("nativeSerializeTransactionWithDust: null parameter");
        return NULL;
    }

    if (ttl <= 0) {
        LOGE("nativeSerializeTransactionWithDust: invalid TTL %lld", (long long)ttl);
        return NULL;
    }

    /* Get seed bytes */
    jsize seed_len = (*env)->GetArrayLength(env, seed);
    if (seed_len != 32) {
        LOGE("nativeSerializeTransactionWithDust: seed must be 32 bytes, got %d", (int)seed_len);
        return NULL;
    }

    jbyte* seed_bytes = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seed_bytes == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetByteArrayElements failed for seed");
        return NULL;
    }

    /* Convert Java strings to C strings */
    const char* inputs_c = (*env)->GetStringUTFChars(env, inputs_json, NULL);
    if (inputs_c == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetStringUTFChars failed for inputs");
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* outputs_c = (*env)->GetStringUTFChars(env, outputs_json, NULL);
    if (outputs_c == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetStringUTFChars failed for outputs");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* signatures_c = (*env)->GetStringUTFChars(env, signatures_json, NULL);
    if (signatures_c == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetStringUTFChars failed for signatures");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* dust_utxos_c = (*env)->GetStringUTFChars(env, dust_utxos_json, NULL);
    if (dust_utxos_c == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetStringUTFChars failed for dust_utxos");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* binding_commitment_c = (*env)->GetStringUTFChars(env, binding_commitment_hex, NULL);
    if (binding_commitment_c == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetStringUTFChars failed for binding_commitment");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        (*env)->ReleaseStringUTFChars(env, dust_utxos_json, dust_utxos_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* network_id_c = (*env)->GetStringUTFChars(env, network_id, NULL);
    if (network_id_c == NULL) {
        LOGE("nativeSerializeTransactionWithDust: GetStringUTFChars failed for network_id");
        (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
        (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
        (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
        (*env)->ReleaseStringUTFChars(env, dust_utxos_json, dust_utxos_c);
        (*env)->ReleaseStringUTFChars(env, binding_commitment_hex, binding_commitment_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    /* Call Rust FFI with real dust state */
    char* hex_str = serialize_unshielded_transaction_with_dust(
        inputs_c,
        outputs_c,
        signatures_c,
        (const void*)dust_state_ptr,
        (const uint8_t*)seed_bytes,
        (size_t)seed_len,
        dust_utxos_c,
        current_time_ms,
        (uint64_t)ttl,
        binding_commitment_c,
        network_id_c
    );

    /* Zeroize sensitive data */
    secure_memzero(seed_bytes, seed_len);

    /* Release Java string buffers */
    (*env)->ReleaseStringUTFChars(env, inputs_json, inputs_c);
    (*env)->ReleaseStringUTFChars(env, outputs_json, outputs_c);
    (*env)->ReleaseStringUTFChars(env, signatures_json, signatures_c);
    (*env)->ReleaseStringUTFChars(env, dust_utxos_json, dust_utxos_c);
    (*env)->ReleaseStringUTFChars(env, binding_commitment_hex, binding_commitment_c);
    (*env)->ReleaseStringUTFChars(env, network_id, network_id_c);
    (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);

    if (hex_str == NULL) {
        LOGE("nativeSerializeTransactionWithDust: Rust FFI returned null");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, hex_str);

    /* Free Rust-allocated string */
    free_serialized_transaction(hex_str);

    if (result == NULL) {
        LOGE("nativeSerializeTransactionWithDust: NewStringUTF failed");
        return NULL;
    }

    LOGI("Transaction serialized (SCALE) with REAL dust: %zu bytes hex", strlen(hex_str));
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

/**
 * Seals a proven transaction by transforming the binding commitment (Phase 2)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.ledger.api
 *   class FfiTransactionSerializer {
 *       private external fun nativeSealProvenTransaction(provenTxHex: String): String?
 *   }
 *
 * @param env JNI environment
 * @param thiz FfiTransactionSerializer object
 * @param proven_tx_hex Hex-encoded proven transaction from proof server
 * @return Hex-encoded finalized (sealed) transaction, or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_api_FfiTransactionSerializer_nativeSealProvenTransaction(
    JNIEnv* env,
    jobject thiz,
    jstring proven_tx_hex)
{
    /* Validate input */
    if (proven_tx_hex == NULL) {
        LOGE("nativeSealProvenTransaction: proven_tx_hex is NULL");
        return NULL;
    }

    /* Convert Java string to C string */
    const char* proven_hex_c = (*env)->GetStringUTFChars(env, proven_tx_hex, NULL);
    if (proven_hex_c == NULL) {
        LOGE("nativeSealProvenTransaction: GetStringUTFChars failed");
        return NULL;
    }

    LOGI("Sealing proven transaction: %zu hex chars", strlen(proven_hex_c));

    /* Call Rust FFI to seal transaction */
    char* sealed_hex = seal_proven_transaction(proven_hex_c);

    /* Release Java string */
    (*env)->ReleaseStringUTFChars(env, proven_tx_hex, proven_hex_c);

    if (sealed_hex == NULL) {
        LOGE("nativeSealProvenTransaction: Rust FFI returned NULL");
        return NULL;
    }

    /* Log before freeing */
    size_t sealed_len = strlen(sealed_hex);
    LOGI("Transaction sealed successfully: %zu hex chars", sealed_len);

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, sealed_hex);

    /* Free Rust-allocated string */
    free_serialized_transaction(sealed_hex);

    if (result == NULL) {
        LOGE("nativeSealProvenTransaction: NewStringUTF failed");
        return NULL;
    }

    return result;
}

/**
 * Gets the Midnight transaction hash from a sealed transaction (Phase 2)
 *
 * This returns the hash that will appear in the indexer, NOT the extrinsic hash
 * that the node RPC returns. These are different hashes:
 * - Extrinsic hash: Hash of the Substrate extrinsic wrapper (from node RPC)
 * - Midnight tx hash: Hash of the actual Midnight transaction (what indexer uses)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.ledger.api
 *   class FfiTransactionSerializer {
 *       private external fun nativeGetTransactionHash(sealedTxHex: String): String?
 *   }
 *
 * @param env JNI environment
 * @param thiz FfiTransactionSerializer object
 * @param sealed_tx_hex Hex-encoded sealed transaction
 * @return Hex-encoded Midnight transaction hash (64 hex chars), or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_api_FfiTransactionSerializer_nativeGetTransactionHash(
    JNIEnv* env,
    jobject thiz,
    jstring sealed_tx_hex)
{
    /* Validate input */
    if (sealed_tx_hex == NULL) {
        LOGE("nativeGetTransactionHash: sealed_tx_hex is NULL");
        return NULL;
    }

    /* Convert Java string to C string */
    const char* sealed_hex_c = (*env)->GetStringUTFChars(env, sealed_tx_hex, NULL);
    if (sealed_hex_c == NULL) {
        LOGE("nativeGetTransactionHash: GetStringUTFChars failed");
        return NULL;
    }

    LOGI("Getting Midnight transaction hash from sealed tx: %zu hex chars", strlen(sealed_hex_c));

    /* Call Rust FFI to get transaction hash */
    char* hash_hex = get_transaction_hash(sealed_hex_c);

    /* Release Java string */
    (*env)->ReleaseStringUTFChars(env, sealed_tx_hex, sealed_hex_c);

    if (hash_hex == NULL) {
        LOGE("nativeGetTransactionHash: Rust FFI returned NULL");
        return NULL;
    }

    /* Log the hash */
    LOGI("Midnight transaction hash: %s", hash_hex);

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, hash_hex);

    /* Free Rust-allocated string */
    free_c_string(hash_hex);

    if (result == NULL) {
        LOGE("nativeGetTransactionHash: NewStringUTF failed");
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

/**
 * Calculates transaction fee using midnight-ledger (Phase 2E)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.ledger.fee
 *   object FeeCalculator {
 *       external fun nativeCalculateFee(
 *           txHex: String,
 *           paramsHex: String,
 *           margin: Int
 *       ): String?
 *   }
 *
 * @param env JNI environment
 * @param obj FeeCalculator object (unused, static method)
 * @param tx_hex SCALE-serialized transaction (hex string)
 * @param params_hex SCALE-serialized ledger parameters (hex string)
 * @param margin Fee blocks margin (typically 5)
 * @return Fee in Specks as decimal string, or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_fee_FeeCalculator_nativeCalculateFee(
    JNIEnv* env,
    jobject obj,
    jstring tx_hex,
    jstring params_hex,
    jint margin
) {
    /* Validate inputs */
    if (tx_hex == NULL) {
        LOGE("nativeCalculateFee: tx_hex is NULL");
        return NULL;
    }

    if (params_hex == NULL) {
        LOGE("nativeCalculateFee: params_hex is NULL");
        return NULL;
    }

    /* Extract Java strings to C strings */
    const char* tx_hex_c = (*env)->GetStringUTFChars(env, tx_hex, NULL);
    if (tx_hex_c == NULL) {
        LOGE("nativeCalculateFee: GetStringUTFChars failed for tx_hex");
        return NULL;
    }

    const char* params_hex_c = (*env)->GetStringUTFChars(env, params_hex, NULL);
    if (params_hex_c == NULL) {
        LOGE("nativeCalculateFee: GetStringUTFChars failed for params_hex");
        (*env)->ReleaseStringUTFChars(env, tx_hex, tx_hex_c);
        return NULL;
    }

    /* Call Rust FFI */
    char* fee_str = calculate_transaction_fee(tx_hex_c, params_hex_c, (uint32_t)margin);

    /* Release Java strings */
    (*env)->ReleaseStringUTFChars(env, tx_hex, tx_hex_c);
    (*env)->ReleaseStringUTFChars(env, params_hex, params_hex_c);

    if (fee_str == NULL) {
        LOGE("nativeCalculateFee: Rust FFI returned NULL");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, fee_str);

    /* Free Rust-allocated string */
    free_c_string(fee_str);

    if (result == NULL) {
        LOGE("nativeCalculateFee: NewStringUTF failed");
        return NULL;
    }

    LOGD("nativeCalculateFee: success");
    return result;
}

/**
 * Creates DustSpend action for fee payment (Phase 2E)
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.ledger.fee
 *   object DustSpendCreator {
 *       external fun nativeCreateDustSpend(
 *           statePtr: Long,
 *           seed: ByteArray,
 *           utxoIndex: Int,
 *           vFee: String,
 *           currentTimeMs: Long
 *       ): String?
 *   }
 *
 * @param env JNI environment
 * @param obj DustSpendCreator object (unused, static method)
 * @param state_ptr Pointer to DustLocalState (from deserialize_dust_state)
 * @param seed Java byte array (32 bytes)
 * @param utxo_index Index of UTXO to spend
 * @param v_fee Fee amount as decimal string (Specks)
 * @param current_time_ms Current time in milliseconds
 * @return JSON string containing DustSpend object, or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_fee_DustSpendCreator_nativeCreateDustSpend(
    JNIEnv* env,
    jobject obj,
    jlong state_ptr,
    jbyteArray seed,
    jint utxo_index,
    jstring v_fee,
    jlong current_time_ms
) {
    /* Validate inputs */
    if (state_ptr == 0) {
        LOGE("nativeCreateDustSpend: state_ptr is null");
        return NULL;
    }

    if (seed == NULL) {
        LOGE("nativeCreateDustSpend: seed is null");
        return NULL;
    }

    if (v_fee == NULL) {
        LOGE("nativeCreateDustSpend: v_fee is null");
        return NULL;
    }

    /* Validate seed length */
    jsize seed_len = (*env)->GetArrayLength(env, seed);
    if (seed_len != 32) {
        LOGE("nativeCreateDustSpend: invalid seed length %d (expected 32)", seed_len);
        return NULL;
    }

    /* Extract seed bytes */
    uint8_t seed_buf[32];
    (*env)->GetByteArrayRegion(env, seed, 0, 32, (jbyte*)seed_buf);
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeCreateDustSpend: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        secure_memzero(seed_buf, 32);
        return NULL;
    }

    /* Extract v_fee string */
    const char* v_fee_c = (*env)->GetStringUTFChars(env, v_fee, NULL);
    if (v_fee_c == NULL) {
        LOGE("nativeCreateDustSpend: GetStringUTFChars failed for v_fee");
        secure_memzero(seed_buf, 32);
        return NULL;
    }

    /* Call Rust FFI */
    char* spend_json = create_dust_spend(
        (void*)(uintptr_t)state_ptr,
        seed_buf,
        32,
        (size_t)utxo_index,
        v_fee_c,
        (int64_t)current_time_ms
    );

    /* SECURITY: Zeroize seed after use */
    secure_memzero(seed_buf, 32);

    /* Release Java string */
    (*env)->ReleaseStringUTFChars(env, v_fee, v_fee_c);

    if (spend_json == NULL) {
        LOGE("nativeCreateDustSpend: Rust FFI returned NULL");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, spend_json);

    /* Free Rust-allocated string */
    free_c_string(spend_json);

    if (result == NULL) {
        LOGE("nativeCreateDustSpend: NewStringUTF failed");
        return NULL;
    }

    LOGD("nativeCreateDustSpend: success");
    return result;
}

/*
 * Build a complete dust registration transaction (signed, SCALE-encoded).
 *
 * Creates a transaction that registers a NIGHT address for dust generation.
 * Includes a guaranteed UnshieldedOffer that consolidates NIGHT UTXOs.
 * The transaction is fully signed and serialized, ready for proof server submission.
 *
 * JNI signature matches:
 *   package com.midnight.kuira.core.ledger.dust
 *   object DustRegistrationBuilder {
 *       external fun nativeBuildDustRegistrationTransaction(
 *           nightPrivateKey: ByteArray,
 *           dustPublicKeyHex: String,
 *           allowFeePayment: String,
 *           ttlMillis: Long,
 *           currentTimeMillis: Long,
 *           utxosJson: String
 *       ): String?
 *   }
 *
 * @param env JNI environment
 * @param obj DustRegistrationBuilder object (unused, static method)
 * @param night_private_key Java byte array (32-byte NIGHT signing key)
 * @param dust_public_key_hex Hex-encoded DustPublicKey
 * @param allow_fee_payment Max fee as decimal string (u128 Specks)
 * @param ttl_millis Transaction TTL in milliseconds since epoch
 * @param current_time_millis Current time in milliseconds since epoch
 * @param utxos_json JSON array of NIGHT UTXOs: [{"value":"...","intent_hash":"...","output_no":N}]
 * @return Hex-encoded SCALE transaction, or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_ledger_dust_DustRegistrationBuilder_nativeBuildDustRegistrationTransaction(
    JNIEnv* env,
    jobject obj,
    jbyteArray night_private_key,
    jstring dust_public_key_hex,
    jstring allow_fee_payment,
    jlong ttl_millis,
    jlong current_time_millis,
    jstring utxos_json,
    jstring network_id
) {
    /* Validate inputs */
    if (night_private_key == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: night_private_key is null");
        return NULL;
    }

    if (dust_public_key_hex == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: dust_public_key_hex is null");
        return NULL;
    }

    if (allow_fee_payment == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: allow_fee_payment is null");
        return NULL;
    }

    if (utxos_json == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: utxos_json is null");
        return NULL;
    }

    if (network_id == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: network_id is null");
        return NULL;
    }

    /* Validate key length */
    jsize key_len = (*env)->GetArrayLength(env, night_private_key);
    if (key_len != 32) {
        LOGE("nativeBuildDustRegistrationTransaction: invalid key length %d (expected 32)", key_len);
        return NULL;
    }

    /* Extract key bytes */
    uint8_t key_buf[32];
    (*env)->GetByteArrayRegion(env, night_private_key, 0, 32, (jbyte*)key_buf);
    if ((*env)->ExceptionCheck(env)) {
        LOGE("nativeBuildDustRegistrationTransaction: exception during GetByteArrayRegion");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        secure_memzero(key_buf, 32);
        return NULL;
    }

    /* Extract string parameters */
    const char* dust_pk_c = (*env)->GetStringUTFChars(env, dust_public_key_hex, NULL);
    if (dust_pk_c == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: GetStringUTFChars failed for dust_public_key_hex");
        secure_memzero(key_buf, 32);
        return NULL;
    }

    const char* fee_c = (*env)->GetStringUTFChars(env, allow_fee_payment, NULL);
    if (fee_c == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: GetStringUTFChars failed for allow_fee_payment");
        (*env)->ReleaseStringUTFChars(env, dust_public_key_hex, dust_pk_c);
        secure_memzero(key_buf, 32);
        return NULL;
    }

    const char* utxos_c = (*env)->GetStringUTFChars(env, utxos_json, NULL);
    if (utxos_c == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: GetStringUTFChars failed for utxos_json");
        (*env)->ReleaseStringUTFChars(env, allow_fee_payment, fee_c);
        (*env)->ReleaseStringUTFChars(env, dust_public_key_hex, dust_pk_c);
        secure_memzero(key_buf, 32);
        return NULL;
    }

    const char* network_id_c = (*env)->GetStringUTFChars(env, network_id, NULL);
    if (network_id_c == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: GetStringUTFChars failed for network_id");
        (*env)->ReleaseStringUTFChars(env, utxos_json, utxos_c);
        (*env)->ReleaseStringUTFChars(env, allow_fee_payment, fee_c);
        (*env)->ReleaseStringUTFChars(env, dust_public_key_hex, dust_pk_c);
        secure_memzero(key_buf, 32);
        return NULL;
    }

    /* Call Rust FFI */
    char* tx_hex = build_dust_registration_transaction(
        key_buf,
        32,
        dust_pk_c,
        fee_c,
        (uint64_t)ttl_millis,
        (int64_t)current_time_millis,
        utxos_c,
        network_id_c
    );

    /* SECURITY: Zeroize key after use */
    secure_memzero(key_buf, 32);

    /* Release Java strings */
    (*env)->ReleaseStringUTFChars(env, dust_public_key_hex, dust_pk_c);
    (*env)->ReleaseStringUTFChars(env, allow_fee_payment, fee_c);
    (*env)->ReleaseStringUTFChars(env, utxos_json, utxos_c);
    (*env)->ReleaseStringUTFChars(env, network_id, network_id_c);

    if (tx_hex == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: Rust FFI returned NULL");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, tx_hex);

    /* Free Rust-allocated string */
    free_serialized_transaction(tx_hex);

    if (result == NULL) {
        LOGE("nativeBuildDustRegistrationTransaction: NewStringUTF failed");
        return NULL;
    }

    LOGD("nativeBuildDustRegistrationTransaction: success");
    return result;
}

/* ======================================================================
 * Zswap (Shielded) State Management — Phase 4B-Shielded
 * ====================================================================== */

JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeCreate(
    JNIEnv* env, jclass clazz) {
    void* state = create_zswap_local_state();
    return (jlong)(intptr_t)state;
}

JNIEXPORT void JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeFree(
    JNIEnv* env, jobject obj, jlong statePtr) {
    if (statePtr != 0) {
        free_zswap_local_state((void*)(intptr_t)statePtr);
    }
}

/* Static version of nativeFree for ZswapTransferBuilder cleanup */
JNIEXPORT void JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_00024Companion_nativeFreeStatic(
    JNIEnv* env, jobject companion, jlong statePtr) {
    if (statePtr != 0) {
        free_zswap_local_state((void*)(intptr_t)statePtr);
    }
}

JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeReplayEvents(
    JNIEnv* env, jobject obj, jlong statePtr, jbyteArray seed, jstring eventsHex) {
    if (statePtr == 0 || seed == NULL || eventsHex == NULL) {
        LOGE("nativeZswapReplayEvents: null parameter");
        return 0;
    }

    jsize seed_len = (*env)->GetArrayLength(env, seed);
    if (seed_len != 32) {
        LOGE("nativeZswapReplayEvents: seed must be 32 bytes, got %d", seed_len);
        return 0;
    }

    jbyte* seed_buf = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seed_buf == NULL) return 0;

    const char* events_hex_c = (*env)->GetStringUTFChars(env, eventsHex, NULL);
    if (events_hex_c == NULL) {
        (*env)->ReleaseByteArrayElements(env, seed, seed_buf, JNI_ABORT);
        return 0;
    }

    void* new_state = zswap_replay_events(
        (void*)(intptr_t)statePtr,
        (const uint8_t*)seed_buf,
        32,
        events_hex_c
    );

    (*env)->ReleaseStringUTFChars(env, eventsHex, events_hex_c);
    /* Securely wipe seed from JNI buffer without copying back to Java array */
    memset(seed_buf, 0, seed_len);
    (*env)->ReleaseByteArrayElements(env, seed, seed_buf, JNI_ABORT);

    return (jlong)(intptr_t)new_state;
}

JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeGetBalances(
    JNIEnv* env, jobject obj, jlong statePtr) {
    if (statePtr == 0) return NULL;

    const char* json = zswap_get_balances((void*)(intptr_t)statePtr);
    if (json == NULL) return NULL;

    jstring result = (*env)->NewStringUTF(env, json);
    free_zswap_string((char*)json);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeGetCoinCount(
    JNIEnv* env, jobject obj, jlong statePtr) {
    if (statePtr == 0) return 0;
    return (jint)zswap_get_coin_count((void*)(intptr_t)statePtr);
}

JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeGetFirstFree(
    JNIEnv* env, jobject obj, jlong statePtr) {
    if (statePtr == 0) return 0;
    return (jlong)zswap_get_first_free((void*)(intptr_t)statePtr);
}

JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeSerialize(
    JNIEnv* env, jobject obj, jlong statePtr) {
    if (statePtr == 0) return NULL;

    const char* hex = zswap_serialize((void*)(intptr_t)statePtr);
    if (hex == NULL) return NULL;

    jstring result = (*env)->NewStringUTF(env, hex);
    free_zswap_string((char*)hex);
    return result;
}

JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapLocalState_nativeDeserialize(
    JNIEnv* env, jclass clazz, jstring hexStr) {
    if (hexStr == NULL) return 0;

    const char* hex_c = (*env)->GetStringUTFChars(env, hexStr, NULL);
    if (hex_c == NULL) return 0;

    void* state = zswap_deserialize(hex_c);
    (*env)->ReleaseStringUTFChars(env, hexStr, hex_c);

    return (jlong)(intptr_t)state;
}

/* ======================================================================
 * Zswap Transfer Primitives — Phase 3, Step 7 (ADR-001)
 *
 * Kotlin class: com.midnight.kuira.core.crypto.shielded.ZswapTransferBuilder
 * ====================================================================== */

/*
 * 7a: Select coins from state to cover an amount.
 *
 * Returns JSON array of coin objects, or null if insufficient balance.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeSelectCoins(
    JNIEnv* env, jclass clazz, jlong statePtr, jstring tokenTypeHex, jstring amountStr) {

    if (statePtr == 0 || tokenTypeHex == NULL || amountStr == NULL) {
        LOGE("nativeSelectCoins: null parameter");
        return NULL;
    }

    const char* token_c = (*env)->GetStringUTFChars(env, tokenTypeHex, NULL);
    if (token_c == NULL) return NULL;

    const char* amount_c = (*env)->GetStringUTFChars(env, amountStr, NULL);
    if (amount_c == NULL) {
        (*env)->ReleaseStringUTFChars(env, tokenTypeHex, token_c);
        return NULL;
    }

    const char* result = zswap_select_coins((void*)(intptr_t)statePtr, token_c, amount_c);

    (*env)->ReleaseStringUTFChars(env, tokenTypeHex, token_c);
    (*env)->ReleaseStringUTFChars(env, amountStr, amount_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/*
 * 7b: Spend a coin, creating an Input<ProofPreimage>.
 *
 * Returns JSON: {"new_state_ptr":<long>, "input_hex":"...", "binding_randomness_hex":"..."}
 * The new_state_ptr is a native pointer that Kotlin uses for subsequent operations.
 * Caller must free the state via ZswapLocalState.freeNativePtr when done.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeSpendCoinFull(
    JNIEnv* env, jclass clazz, jlong statePtr, jbyteArray seed, jstring coinJson) {

    if (statePtr == 0 || seed == NULL || coinJson == NULL) {
        LOGE("nativeSpendCoinFull: null parameter");
        return NULL;
    }

    jsize seed_len = (*env)->GetArrayLength(env, seed);
    if (seed_len != 32) {
        LOGE("nativeSpendCoinFull: seed must be 32 bytes, got %d", seed_len);
        return NULL;
    }

    jbyte* seed_buf = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seed_buf == NULL) return NULL;

    const char* coin_c = (*env)->GetStringUTFChars(env, coinJson, NULL);
    if (coin_c == NULL) {
        memset(seed_buf, 0, seed_len);
        (*env)->ReleaseByteArrayElements(env, seed, seed_buf, JNI_ABORT);
        return NULL;
    }

    ZswapSpendResult result = zswap_spend_coin(
        (void*)(intptr_t)statePtr,
        (const uint8_t*)seed_buf,
        32,
        coin_c
    );

    (*env)->ReleaseStringUTFChars(env, coinJson, coin_c);
    memset(seed_buf, 0, seed_len);
    (*env)->ReleaseByteArrayElements(env, seed, seed_buf, JNI_ABORT);

    if (result.new_state == NULL || result.result_json == NULL) {
        if (result.new_state != NULL) free_zswap_local_state(result.new_state);
        if (result.result_json != NULL) free_zswap_string(result.result_json);
        return NULL;
    }

    /* Build combined JSON: {"new_state_ptr": <long>, ...rest of result_json} */
    /* result_json is: {"input_hex":"...", "binding_randomness_hex":"..."} */
    /* We insert new_state_ptr at the beginning */
    jlong new_state_ptr = (jlong)(intptr_t)result.new_state;

    /* Calculate buffer size: {"new_state_ptr":NNNN, + rest without leading { */
    size_t json_len = strlen(result.result_json);
    size_t buf_size;
    if (!safe_size_add(json_len, 64, &buf_size)) {
        free_zswap_local_state(result.new_state);
        free_zswap_string(result.result_json);
        LOGE("nativeSpendCoinFull: buffer size overflow");
        return NULL;
    }
    char* combined = (char*)malloc(buf_size);
    if (combined == NULL) {
        free_zswap_local_state(result.new_state);
        free_zswap_string(result.result_json);
        LOGE("nativeSpendCoinFull: malloc failed");
        return NULL;
    }

    /* Merge: skip leading '{' of result_json, prepend our field */
    snprintf(combined, buf_size, "{\"new_state_ptr\":%lld,%s",
             (long long)new_state_ptr,
             result.result_json + 1); /* +1 skips the '{' */

    free_zswap_string(result.result_json);

    jstring jresult = (*env)->NewStringUTF(env, combined);
    free(combined);

    return jresult;
}

/*
 * 7c: Create an encrypted output for a recipient.
 *
 * Returns JSON: {"output_hex":"...", "binding_randomness_hex":"..."}
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeCreateOutput(
    JNIEnv* env, jclass clazz, jstring coinPkHex, jstring encPkHex,
    jstring tokenTypeHex, jstring amountStr) {

    if (coinPkHex == NULL || encPkHex == NULL || tokenTypeHex == NULL || amountStr == NULL) {
        LOGE("nativeCreateOutput: null parameter");
        return NULL;
    }

    const char* cpk_c = (*env)->GetStringUTFChars(env, coinPkHex, NULL);
    const char* epk_c = (*env)->GetStringUTFChars(env, encPkHex, NULL);
    const char* token_c = (*env)->GetStringUTFChars(env, tokenTypeHex, NULL);
    const char* amount_c = (*env)->GetStringUTFChars(env, amountStr, NULL);

    if (cpk_c == NULL || epk_c == NULL || token_c == NULL || amount_c == NULL) {
        if (cpk_c) (*env)->ReleaseStringUTFChars(env, coinPkHex, cpk_c);
        if (epk_c) (*env)->ReleaseStringUTFChars(env, encPkHex, epk_c);
        if (token_c) (*env)->ReleaseStringUTFChars(env, tokenTypeHex, token_c);
        if (amount_c) (*env)->ReleaseStringUTFChars(env, amountStr, amount_c);
        return NULL;
    }

    const char* result = zswap_create_output(cpk_c, epk_c, token_c, amount_c);

    (*env)->ReleaseStringUTFChars(env, coinPkHex, cpk_c);
    (*env)->ReleaseStringUTFChars(env, encPkHex, epk_c);
    (*env)->ReleaseStringUTFChars(env, tokenTypeHex, token_c);
    (*env)->ReleaseStringUTFChars(env, amountStr, amount_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/*
 * 7d: Build an Offer from inputs + outputs.
 *
 * Returns JSON: {"offer_hex":"...", "binding_randomness_hex":"..."}
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeBuildOffer(
    JNIEnv* env, jclass clazz, jstring inputsHexJson, jstring outputsHexJson) {

    if (inputsHexJson == NULL || outputsHexJson == NULL) {
        LOGE("nativeBuildOffer: null parameter");
        return NULL;
    }

    const char* inputs_c = (*env)->GetStringUTFChars(env, inputsHexJson, NULL);
    const char* outputs_c = (*env)->GetStringUTFChars(env, outputsHexJson, NULL);

    if (inputs_c == NULL || outputs_c == NULL) {
        if (inputs_c) (*env)->ReleaseStringUTFChars(env, inputsHexJson, inputs_c);
        if (outputs_c) (*env)->ReleaseStringUTFChars(env, outputsHexJson, outputs_c);
        return NULL;
    }

    const char* result = zswap_build_offer(inputs_c, outputs_c);

    (*env)->ReleaseStringUTFChars(env, inputsHexJson, inputs_c);
    (*env)->ReleaseStringUTFChars(env, outputsHexJson, outputs_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/*
 * 7e: Merge two offers into one.
 *
 * Returns merged offer hex string, or null on error.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeMergeOffers(
    JNIEnv* env, jclass clazz, jstring offer1Hex, jstring offer2Hex) {

    if (offer1Hex == NULL || offer2Hex == NULL) {
        LOGE("nativeMergeOffers: null parameter");
        return NULL;
    }

    const char* o1_c = (*env)->GetStringUTFChars(env, offer1Hex, NULL);
    const char* o2_c = (*env)->GetStringUTFChars(env, offer2Hex, NULL);

    if (o1_c == NULL || o2_c == NULL) {
        if (o1_c) (*env)->ReleaseStringUTFChars(env, offer1Hex, o1_c);
        if (o2_c) (*env)->ReleaseStringUTFChars(env, offer2Hex, o2_c);
        return NULL;
    }

    const char* result = zswap_merge_offers(o1_c, o2_c);

    (*env)->ReleaseStringUTFChars(env, offer1Hex, o1_c);
    (*env)->ReleaseStringUTFChars(env, offer2Hex, o2_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/*
 * 7f: Validate and re-serialize an offer.
 *
 * Returns validated SCALE hex, or null if malformed.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeSerializeOffer(
    JNIEnv* env, jclass clazz, jstring offerHex) {

    if (offerHex == NULL) {
        LOGE("nativeSerializeOffer: null parameter");
        return NULL;
    }

    const char* hex_c = (*env)->GetStringUTFChars(env, offerHex, NULL);
    if (hex_c == NULL) return NULL;

    const char* result = zswap_serialize_offer(hex_c);

    (*env)->ReleaseStringUTFChars(env, offerHex, hex_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/*
 * 7g: Build full unproven Transaction for proof server.
 *
 * Returns hex-encoded (Transaction, HashMap) tuple.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeBuildShieldedTransaction(
    JNIEnv* env, jclass clazz, jstring offerHex, jstring networkId,
    jstring dustTxHex, jlong ttlMs) {

    if (offerHex == NULL || networkId == NULL) {
        LOGE("nativeBuildShieldedTransaction: null required parameter");
        return NULL;
    }

    const char* offer_c = (*env)->GetStringUTFChars(env, offerHex, NULL);
    const char* network_c = (*env)->GetStringUTFChars(env, networkId, NULL);
    const char* dust_c = NULL;

    if (offer_c == NULL || network_c == NULL) {
        if (offer_c) (*env)->ReleaseStringUTFChars(env, offerHex, offer_c);
        if (network_c) (*env)->ReleaseStringUTFChars(env, networkId, network_c);
        return NULL;
    }

    /* dustTxHex is optional */
    if (dustTxHex != NULL) {
        dust_c = (*env)->GetStringUTFChars(env, dustTxHex, NULL);
    }

    const char* result = zswap_build_shielded_transaction(
        offer_c,
        network_c,
        dust_c,  /* may be NULL */
        0, NULL, 0,  /* reserved params */
        (uint64_t)ttlMs
    );

    (*env)->ReleaseStringUTFChars(env, offerHex, offer_c);
    (*env)->ReleaseStringUTFChars(env, networkId, network_c);
    if (dust_c) (*env)->ReleaseStringUTFChars(env, dustTxHex, dust_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/*
 * 7g+dust: Build shielded transaction with dust fee payment.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_shielded_ZswapTransferBuilder_nativeBuildShieldedTransactionWithDust(
    JNIEnv* env, jclass clazz, jstring offerHex, jstring networkId,
    jlong dustStatePtr, jbyteArray dustSeed, jstring dustUtxosJson,
    jlong currentTimeMs, jlong ttlMs) {

    if (offerHex == NULL || networkId == NULL) {
        LOGE("nativeBuildShieldedTransactionWithDust: null required parameter");
        return NULL;
    }

    const char* offer_c = (*env)->GetStringUTFChars(env, offerHex, NULL);
    const char* network_c = (*env)->GetStringUTFChars(env, networkId, NULL);
    if (offer_c == NULL || network_c == NULL) {
        if (offer_c) (*env)->ReleaseStringUTFChars(env, offerHex, offer_c);
        if (network_c) (*env)->ReleaseStringUTFChars(env, networkId, network_c);
        return NULL;
    }

    /* Dust params (all optional — may be null/0) */
    jbyte* dust_seed_buf = NULL;
    jsize dust_seed_len = 0;
    const char* dust_utxos_c = NULL;

    if (dustSeed != NULL && dustStatePtr != 0 && dustUtxosJson != NULL) {
        dust_seed_len = (*env)->GetArrayLength(env, dustSeed);
        dust_seed_buf = (*env)->GetByteArrayElements(env, dustSeed, NULL);
        dust_utxos_c = (*env)->GetStringUTFChars(env, dustUtxosJson, NULL);
    }

    const char* result = zswap_build_shielded_transaction_with_dust(
        offer_c, network_c,
        (void*)(intptr_t)dustStatePtr,
        dust_seed_buf ? (const uint8_t*)dust_seed_buf : NULL,
        (size_t)dust_seed_len,
        dust_utxos_c,
        (uint64_t)currentTimeMs,
        (uint64_t)ttlMs
    );

    (*env)->ReleaseStringUTFChars(env, offerHex, offer_c);
    (*env)->ReleaseStringUTFChars(env, networkId, network_c);
    if (dust_seed_buf) {
        memset(dust_seed_buf, 0, dust_seed_len);
        (*env)->ReleaseByteArrayElements(env, dustSeed, dust_seed_buf, JNI_ABORT);
    }
    if (dust_utxos_c) (*env)->ReleaseStringUTFChars(env, dustUtxosJson, dust_utxos_c);

    if (result == NULL) return NULL;
    jstring jresult = (*env)->NewStringUTF(env, result);
    free_zswap_string((char*)result);
    return jresult;
}

/* ======================================================================
 * Local ZK Proving — Phase 4C
 *
 * Kotlin class: com.midnight.kuira.core.crypto.proving.LocalProver
 * ====================================================================== */

/*
 * Prove a transaction locally using cached proving keys.
 * Same input/output format as the proof server.
 *
 * Two JNI entry points for the same function:
 * - core.crypto.proving.LocalProver (original package, kept for wallet compatibility)
 * - core.compact.proving.LocalProver (SDK package, used by compact-engine)
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_proving_LocalProver_nativeProveTransactionLocal(
    JNIEnv* env, jclass clazz, jstring unprovenTxHex, jstring keysDir);

JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_crypto_proving_LocalProver_nativeProveTransactionLocal(
    JNIEnv* env, jclass clazz, jstring unprovenTxHex, jstring keysDir) {

    if (unprovenTxHex == NULL || keysDir == NULL) {
        LOGE("nativeProveTransactionLocal: null parameter");
        return NULL;
    }

    const char* tx_c = (*env)->GetStringUTFChars(env, unprovenTxHex, NULL);
    const char* dir_c = (*env)->GetStringUTFChars(env, keysDir, NULL);

    if (tx_c == NULL || dir_c == NULL) {
        if (tx_c) (*env)->ReleaseStringUTFChars(env, unprovenTxHex, tx_c);
        if (dir_c) (*env)->ReleaseStringUTFChars(env, keysDir, dir_c);
        return NULL;
    }

    LOGI("Starting local proving (keys_dir=%s)", dir_c);

    const char* result = zkir_prove_transaction_local(tx_c, dir_c);

    (*env)->ReleaseStringUTFChars(env, unprovenTxHex, tx_c);
    (*env)->ReleaseStringUTFChars(env, keysDir, dir_c);

    if (result == NULL) {
        LOGE("Local proving failed");
        return NULL;
    }

    jstring jresult = (*env)->NewStringUTF(env, result);
    free_proven_string((char*)result);

    LOGI("Local proving succeeded");
    return jresult;
}

/*
 * SDK package alias for local proving (delegates to same implementation).
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_proving_LocalProver_nativeProveTransactionLocal(
    JNIEnv* env, jclass clazz, jstring unprovenTxHex, jstring keysDir) {
    return Java_com_midnight_kuira_core_crypto_proving_LocalProver_nativeProveTransactionLocal(
        env, clazz, unprovenTxHex, keysDir);
}

/*
 * Create a contract state with N null slots.
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeStateCreateWithNulls(
    JNIEnv* env, jclass clazz, jint numSlots) {
    return (jlong)contract_state_create_with_nulls((uint32_t)numSlots);
}

/*
 * Set an operation on a contract state.
 */
JNIEXPORT void JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeStateSetOperation(
    JNIEnv* env, jclass clazz, jlong handle, jstring operationName) {

    if (operationName == NULL) return;
    const char* name_c = (*env)->GetStringUTFChars(env, operationName, NULL);
    if (name_c == NULL) return;

    contract_state_set_operation((uint64_t)handle, name_c);
    (*env)->ReleaseStringUTFChars(env, operationName, name_c);
}

/*
 * Create a contract state from SCALE hex, return handle.
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeStateCreate(
    JNIEnv* env, jclass clazz, jstring stateHex) {

    if (stateHex == NULL) return 0;
    const char* hex_c = (*env)->GetStringUTFChars(env, stateHex, NULL);
    if (hex_c == NULL) return 0;

    uint64_t handle = contract_state_create(hex_c);
    (*env)->ReleaseStringUTFChars(env, stateHex, hex_c);
    return (jlong)handle;
}

/*
 * Free a contract state handle.
 */
JNIEXPORT void JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeStateFree(
    JNIEnv* env, jclass clazz, jlong handle) {
    contract_state_free((uint64_t)handle);
}

/*
 * Read contract state fields as JSON.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeStateReadFields(
    JNIEnv* env, jclass clazz, jlong handle) {

    const char* result = contract_state_read_fields((uint64_t)handle);
    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/*
 * Contract query — execute opcodes against contract state via Rust VM.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeContractQuery(
    JNIEnv* env, jclass clazz, jlong handle, jstring opcodesJson) {

    if (opcodesJson == NULL) return NULL;

    const char* ops_c = (*env)->GetStringUTFChars(env, opcodesJson, NULL);
    if (ops_c == NULL) return NULL;

    const char* result = contract_query((uint64_t)handle, ops_c);
    (*env)->ReleaseStringUTFChars(env, opcodesJson, ops_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/*
 * Persistent hash — SHA-256 for Compact contracts (raw bytes).
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativePersistentHash(
    JNIEnv* env, jclass clazz, jstring inputHex) {

    if (inputHex == NULL) return NULL;
    const char* input_c = (*env)->GetStringUTFChars(env, inputHex, NULL);
    if (input_c == NULL) return NULL;

    const char* result = contract_persistent_hash(input_c);
    (*env)->ReleaseStringUTFChars(env, inputHex, input_c);
    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/*
 * Persistent hash with proper AlignedValue encoding (matches WASM).
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativePersistentHashAligned(
    JNIEnv* env, jclass clazz, jstring alignedValueJson) {

    if (alignedValueJson == NULL) return NULL;
    const char* json_c = (*env)->GetStringUTFChars(env, alignedValueJson, NULL);
    if (json_c == NULL) return NULL;

    const char* result = contract_persistent_hash_aligned(json_c);
    (*env)->ReleaseStringUTFChars(env, alignedValueJson, json_c);
    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/*
 * BigInt to Value encoding.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeBigIntToValue(
    JNIEnv* env, jclass clazz, jstring bigintStr) {

    if (bigintStr == NULL) return NULL;
    const char* str_c = (*env)->GetStringUTFChars(env, bigintStr, NULL);
    if (str_c == NULL) return NULL;

    const char* result = contract_big_int_to_value(str_c);
    (*env)->ReleaseStringUTFChars(env, bigintStr, str_c);
    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/*
 * Value to BigInt decoding.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeValueToBigInt(
    JNIEnv* env, jclass clazz, jstring valueJson) {

    if (valueJson == NULL) return NULL;
    const char* json_c = (*env)->GetStringUTFChars(env, valueJson, NULL);
    if (json_c == NULL) return NULL;

    const char* result = contract_value_to_big_int(json_c);
    (*env)->ReleaseStringUTFChars(env, valueJson, json_c);
    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/*
 * Clone a contract state handle (for saving initial state before queries).
 */
JNIEXPORT jlong JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeStateClone(
    JNIEnv* env, jclass clazz, jlong handle) {
    return (jlong)contract_state_clone((uint64_t)handle);
}

/*
 * Assemble a contract call transaction from circuit execution output.
 * Takes JSON with proof data, returns hex-encoded serialized UnprovenTransaction.
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_core_compact_ContractRuntime_nativeAssembleContractCallTx(
    JNIEnv* env, jclass clazz, jstring paramsJson) {

    if (paramsJson == NULL) return NULL;

    const char* params_c = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    if (params_c == NULL) return NULL;

    const char* result = contract_assemble_call_tx(params_c);
    (*env)->ReleaseStringUTFChars(env, paramsJson, params_c);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    contract_free_string((char*)result);
    return jresult;
}

/**
 * Balance a proven transaction with dust fee payment (SDK — balance_ffi.rs)
 *
 * Takes a proven (but unsealed) Compact contract transaction, adds dust fees
 * via local proving, seals it, and returns the balanced+sealed transaction.
 * Replaces the remote DAppConnectorClient.balanceTransaction() call.
 *
 * JNI signature matches:
 *   package com.midnight.kuira.sdk
 *   object TransactionBalancerNative {
 *       external fun nativeBalanceProvenTransaction(
 *           provenTxHex: String,
 *           dustStatePtr: Long,
 *           seed: ByteArray,
 *           ledgerParamsHex: String,
 *           currentTimeMs: Long,
 *           keysDir: String,
 *           networkId: String
 *       ): String?
 *   }
 */
JNIEXPORT jstring JNICALL
Java_com_midnight_kuira_sdk_TransactionBalancerNative_nativeBalanceProvenTransaction(
    JNIEnv* env,
    jobject obj,
    jstring proven_tx_hex,
    jlong dust_state_ptr,
    jbyteArray seed,
    jstring ledger_params_hex,
    jlong current_time_ms,
    jstring keys_dir,
    jstring network_id)
{
    /* Validate inputs */
    if (proven_tx_hex == NULL || dust_state_ptr == 0 || seed == NULL ||
        ledger_params_hex == NULL || keys_dir == NULL || network_id == NULL) {
        LOGE("nativeBalanceProvenTransaction: null parameter");
        return NULL;
    }

    /* Get seed bytes */
    jsize seed_len = (*env)->GetArrayLength(env, seed);
    if (seed_len != 32) {
        LOGE("nativeBalanceProvenTransaction: seed must be 32 bytes, got %d", (int)seed_len);
        return NULL;
    }

    jbyte* seed_bytes = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seed_bytes == NULL) {
        LOGE("nativeBalanceProvenTransaction: GetByteArrayElements failed for seed");
        return NULL;
    }

    /* Convert Java strings to C strings */
    const char* proven_c = (*env)->GetStringUTFChars(env, proven_tx_hex, NULL);
    if (proven_c == NULL) {
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* params_c = (*env)->GetStringUTFChars(env, ledger_params_hex, NULL);
    if (params_c == NULL) {
        (*env)->ReleaseStringUTFChars(env, proven_tx_hex, proven_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* keys_c = (*env)->GetStringUTFChars(env, keys_dir, NULL);
    if (keys_c == NULL) {
        (*env)->ReleaseStringUTFChars(env, proven_tx_hex, proven_c);
        (*env)->ReleaseStringUTFChars(env, ledger_params_hex, params_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    const char* network_c = (*env)->GetStringUTFChars(env, network_id, NULL);
    if (network_c == NULL) {
        (*env)->ReleaseStringUTFChars(env, proven_tx_hex, proven_c);
        (*env)->ReleaseStringUTFChars(env, ledger_params_hex, params_c);
        (*env)->ReleaseStringUTFChars(env, keys_dir, keys_c);
        (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);
        return NULL;
    }

    /* Call Rust FFI */
    char* result_hex = balance_proven_transaction(
        proven_c,
        (void*)dust_state_ptr,
        (const uint8_t*)seed_bytes,
        (size_t)seed_len,
        params_c,
        current_time_ms,
        keys_c,
        network_c
    );

    /* Zeroize sensitive data */
    secure_memzero(seed_bytes, seed_len);

    /* Release Java string buffers */
    (*env)->ReleaseStringUTFChars(env, proven_tx_hex, proven_c);
    (*env)->ReleaseStringUTFChars(env, ledger_params_hex, params_c);
    (*env)->ReleaseStringUTFChars(env, keys_dir, keys_c);
    (*env)->ReleaseStringUTFChars(env, network_id, network_c);
    (*env)->ReleaseByteArrayElements(env, seed, seed_bytes, JNI_ABORT);

    if (result_hex == NULL) {
        LOGE("nativeBalanceProvenTransaction: Rust FFI returned null");
        return NULL;
    }

    /* Convert C string to Java string */
    jstring result = (*env)->NewStringUTF(env, result_hex);

    /* Free Rust-allocated string */
    free_balanced_transaction(result_hex);

    if (result == NULL) {
        LOGE("nativeBalanceProvenTransaction: NewStringUTF failed");
        return NULL;
    }

    LOGI("Proven transaction balanced and sealed successfully");
    return result;
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
