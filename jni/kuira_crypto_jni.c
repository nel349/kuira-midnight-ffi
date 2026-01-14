/*
 * Kuira Crypto JNI Bridge
 *
 * Bridges Kotlin/Java → C → Rust FFI for shielded key derivation.
 *
 * Architecture:
 *   Kotlin: ShieldedKeyDeriver.nativeDeriveShieldedKeys(ByteArray)
 *     ↓
 *   JNI (this file): Extract bytes, call Rust, format result
 *     ↓
 *   Rust FFI: derive_shielded_keys(seed_ptr, seed_len) → ShieldedKeys*
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Rust FFI declarations */

/* C struct matching Rust's #[repr(C)] ShieldedKeys */
typedef struct {
    char* coin_public_key;        /* 64 hex characters + null terminator */
    char* encryption_public_key;  /* 64 hex characters + null terminator */
} ShieldedKeys;

/* Rust FFI functions (defined in libkuira_crypto_ffi) */
extern ShieldedKeys* derive_shielded_keys(const uint8_t* seed_ptr, size_t seed_len);
extern void free_shielded_keys(ShieldedKeys* ptr);

/* JNI function implementations */

/**
 * JNI entry point called from Kotlin.
 *
 * Signature matches:
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
        return NULL;  /* Return null to Kotlin */
    }

    /* Get array length */
    jsize seed_len = (*env)->GetArrayLength(env, seed_array);
    if (seed_len != 32) {
        /* Kotlin already validates this, but double-check */
        return NULL;
    }

    /* Extract bytes from Java array (copy, not pin - safer) */
    uint8_t seed_buf[32];
    (*env)->GetByteArrayRegion(env, seed_array, 0, 32, (jbyte*)seed_buf);

    /* Check for exceptions during byte extraction */
    if ((*env)->ExceptionCheck(env)) {
        return NULL;
    }

    /* Call Rust FFI */
    ShieldedKeys* keys = derive_shielded_keys(seed_buf, 32);
    if (keys == NULL) {
        /* Rust function failed (logged to stderr) */
        return NULL;
    }

    /* Format result as "coinPk|encPk" */
    size_t coin_len = strlen(keys->coin_public_key);
    size_t enc_len = strlen(keys->encryption_public_key);
    size_t result_len = coin_len + 1 + enc_len + 1;  /* +1 for '|', +1 for '\0' */

    char* result = (char*)malloc(result_len);
    if (result == NULL) {
        /* Out of memory (unlikely) */
        free_shielded_keys(keys);
        return NULL;
    }

    /* Safe string formatting */
    snprintf(result, result_len, "%s|%s", keys->coin_public_key, keys->encryption_public_key);

    /* Convert C string to Java string */
    jstring jresult = (*env)->NewStringUTF(env, result);

    /* Free native memory */
    free(result);
    free_shielded_keys(keys);

    /* Return Java string (or NULL if NewStringUTF failed) */
    return jresult;
}

/*
 * JNI_OnLoad - Called when library is loaded
 *
 * Optional: Can be used for initialization/version checking.
 * Currently not needed since we have no global state.
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    return JNI_VERSION_1_6;  /* Minimum JNI version */
}
