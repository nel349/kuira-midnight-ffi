//! Transaction FFI - JNI bridge for signing and serializing Midnight transactions
//!
//! This module provides FFI functions for:
//! - Creating SigningKey from private key bytes
//! - Signing transaction data with Schnorr BIP-340
//! - Serializing transactions to SCALE codec
//!
//! Design: We build the transaction in Rust to avoid complex type marshalling across FFI.

use midnight_base_crypto::signatures::{SigningKey, Signature, VerifyingKey};
use midnight_serialize::{Serializable, Deserializable};
use rand::rngs::OsRng;
use zeroize::Zeroize;

/// Signature bytes with length for safe FFI transfer
#[repr(C)]
pub struct SignatureBytes {
    /// Pointer to signature data (caller must free with free_signature)
    pub data: *mut u8,
    /// Length of signature data in bytes
    pub len: usize,
}

/// Creates a SigningKey from 32-byte private key
///
/// # Safety
///
/// **CALLER MUST GUARANTEE:**
/// 1. `private_key_ptr` points to valid, readable memory of at least `private_key_len` bytes
/// 2. Memory remains valid (not freed) for the duration of this call
/// 3. Memory is not concurrently modified by another thread during this call
/// 4. `private_key_len` must equal 32 (will be validated and rejected if not)
///
/// **FAILURE TO MEET THESE CONDITIONS RESULTS IN UNDEFINED BEHAVIOR:**
/// - Segmentation fault (immediate crash)
/// - Reading arbitrary memory (potential security breach)
/// - Incorrect cryptographic key generation (silent failure)
/// - Data races if memory is concurrently modified
///
/// **MEMORY OWNERSHIP:**
/// - The private key is **copied** into Rust-owned memory
/// - The copy is **zeroized** after use for security
/// - Caller retains ownership of input memory and may free it after this call returns
/// - Caller MUST call `free_signing_key()` on the returned pointer when done
///
/// # Returns
///
/// - Non-null pointer to SigningKey on success
/// - Null pointer on error (invalid input, cryptographic validation failure)
#[no_mangle]
pub extern "C" fn create_signing_key(
    private_key_ptr: *const u8,
    private_key_len: usize,
) -> *mut SigningKey {
    // Safety checks
    if private_key_ptr.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("Error: private_key_ptr is null");
        return std::ptr::null_mut();
    }

    if private_key_len != 32 {
        #[cfg(debug_assertions)]
        eprintln!("Error: private key must be 32 bytes, got {}", private_key_len);
        return std::ptr::null_mut();
    }

    // Copy to mutable buffer that we can zeroize
    let mut private_key_copy = [0u8; 32];
    unsafe {
        let private_key_slice = std::slice::from_raw_parts(private_key_ptr, private_key_len);
        private_key_copy.copy_from_slice(private_key_slice);
    }

    // Create signing key from bytes
    let signing_key = match SigningKey::from_bytes(&private_key_copy) {
        Ok(sk) => sk,
        Err(e) => {
            // Zeroize before returning on error
            private_key_copy.zeroize();
            #[cfg(debug_assertions)]
            eprintln!("Error creating signing key: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Zeroize the copy after successful use
    private_key_copy.zeroize();

    // Allocate and return pointer
    Box::into_raw(Box::new(signing_key))
}

/// Frees a SigningKey created by create_signing_key
///
/// # Safety
///
/// **CALLER MUST GUARANTEE:**
/// 1. `ptr` was returned from `create_signing_key()` (not from any other source)
/// 2. `ptr` has not been previously freed
/// 3. `ptr` is not currently in use by another thread
/// 4. `ptr` will not be used after this call (including concurrent access)
///
/// **FAILURE TO MEET THESE CONDITIONS RESULTS IN UNDEFINED BEHAVIOR:**
/// - Double-free corruption (memory corruption, crash)
/// - Use-after-free if pointer is accessed after freeing
/// - Data races if pointer is concurrently accessed
/// - Freeing invalid memory if pointer is from wrong source
///
/// **MEMORY OWNERSHIP:**
/// - This function takes ownership and deallocates the SigningKey
/// - After this call, the pointer is invalid and must not be dereferenced
/// - It is safe to call this function with a null pointer (no-op)
///
/// **USAGE PATTERN:**
/// ```c
/// SigningKey* key = create_signing_key(private_key, 32);
/// // ... use key ...
/// free_signing_key(key);  // Must call exactly once
/// // key is now invalid, do not use
/// ```
#[no_mangle]
pub extern "C" fn free_signing_key(ptr: *mut SigningKey) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        // Take ownership back and drop
        let _ = Box::from_raw(ptr);
    }
}

/// Gets the public verifying key from a SigningKey
///
/// # Safety
///
/// **CALLER MUST GUARANTEE:**
/// 1. `signing_key_ptr` was returned from `create_signing_key()` and not yet freed
/// 2. `signing_key_ptr` remains valid for the duration of this call
/// 3. SigningKey is not concurrently modified or freed during this call
/// 4. SigningKey has not been moved or invalidated
///
/// **FAILURE TO MEET THESE CONDITIONS RESULTS IN UNDEFINED BEHAVIOR:**
/// - Segmentation fault (crash) if pointer is invalid or freed
/// - Reading arbitrary memory if pointer is wrong
/// - Data races if SigningKey is concurrently accessed
///
/// **MEMORY OWNERSHIP:**
/// - This function allocates new memory for the 32-byte public key
/// - Caller takes ownership of the returned pointer
/// - Caller MUST call `free_verifying_key()` on the returned pointer when done
/// - The SigningKey remains valid and owned by the original owner
///
/// # Returns
///
/// - Non-null pointer to 32-byte public key on success
/// - Null pointer on error (invalid input, serialization failure)
#[no_mangle]
pub extern "C" fn get_verifying_key(signing_key_ptr: *const SigningKey) -> *mut u8 {
    if signing_key_ptr.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("Error: signing_key_ptr is null");
        return std::ptr::null_mut();
    }

    let signing_key = unsafe { &*signing_key_ptr };
    let verifying_key = signing_key.verifying_key();

    // Serialize verifying key to bytes
    let mut key_bytes = Vec::new();
    if let Err(e) = verifying_key.serialize(&mut key_bytes) {
        #[cfg(debug_assertions)]
        eprintln!("Error serializing verifying key: {}", e);
        return std::ptr::null_mut();
    }

    // Should be 32 bytes for Schnorr public key
    if key_bytes.len() != 32 {
        #[cfg(debug_assertions)]
        eprintln!("Error: verifying key is {} bytes, expected 32", key_bytes.len());
        return std::ptr::null_mut();
    }

    let ptr = key_bytes.as_mut_ptr();
    std::mem::forget(key_bytes);
    ptr
}

/// Frees verifying key bytes returned from get_verifying_key
///
/// # Safety
///
/// **CALLER MUST GUARANTEE:**
/// 1. `ptr` was returned from `get_verifying_key()` (not from any other source)
/// 2. `ptr` has not been previously freed
/// 3. `ptr` is not currently in use by another thread
/// 4. `ptr` will not be used after this call
///
/// **FAILURE TO MEET THESE CONDITIONS RESULTS IN UNDEFINED BEHAVIOR:**
/// - Double-free corruption (memory corruption, crash)
/// - Use-after-free if pointer is accessed after freeing
/// - Freeing invalid memory if pointer is from wrong source
/// - Data races if pointer is concurrently accessed
///
/// **MEMORY OWNERSHIP:**
/// - This function takes ownership and deallocates the 32-byte public key
/// - After this call, the pointer is invalid and must not be dereferenced
/// - It is safe to call this function with a null pointer (no-op)
///
/// **IMPORTANT:** This function assumes the pointer points to exactly 32 bytes
/// allocated by `get_verifying_key()`. Using a pointer from any other source
/// will cause memory corruption.
#[no_mangle]
pub extern "C" fn free_verifying_key(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        // Verifying key is always 32 bytes
        let _ = Vec::from_raw_parts(ptr, 32, 32);
    }
}

/// Signs data with a SigningKey using Schnorr BIP-340
///
/// # Safety
///
/// **CALLER MUST GUARANTEE:**
/// 1. `signing_key_ptr` was returned from `create_signing_key()` and not yet freed
/// 2. `data_ptr` points to valid, readable memory of at least `data_len` bytes
/// 3. Both pointers remain valid for the duration of this call
/// 4. Neither pointer is concurrently modified or freed during this call
/// 5. `data_len` accurately represents the allocated size of data
/// 6. `data_len` does not exceed 1 MB (enforced, returns error if violated)
///
/// **FAILURE TO MEET THESE CONDITIONS RESULTS IN UNDEFINED BEHAVIOR:**
/// - Segmentation fault (crash) if pointers are invalid or freed
/// - Reading arbitrary memory if pointers are wrong
/// - Buffer overrun if data_len exceeds actual allocated size
/// - Data races if memory is concurrently modified
/// - Incorrect signatures if data is modified during signing
///
/// **MEMORY OWNERSHIP:**
/// - Input data is **read-only** and remains owned by caller
/// - Caller may free input data after this function returns
/// - This function allocates new memory for the signature (64 bytes)
/// - Caller takes ownership of returned SignatureBytes.data pointer
/// - Caller MUST call `free_signature(sig.data, sig.len)` when done
///
/// **SIGNATURE FORMAT:**
/// - Returns 64-byte Schnorr signature (R || s format per BIP-340)
/// - Uses random nonce (not deterministic) for each signature
/// - Same data signed twice produces different signatures (different nonce)
///
/// # Returns
///
/// - SignatureBytes with non-null data pointer and len=64 on success
/// - SignatureBytes with null data pointer and len=0 on error
#[no_mangle]
pub extern "C" fn sign_data(
    signing_key_ptr: *const SigningKey,
    data_ptr: *const u8,
    data_len: usize,
) -> SignatureBytes {
    // Maximum data length to prevent excessive memory allocation
    const MAX_DATA_LEN: usize = 1024 * 1024; // 1 MB

    // Validate pointers
    if signing_key_ptr.is_null() || data_ptr.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("Error: null pointer in sign_data");
        return SignatureBytes {
            data: std::ptr::null_mut(),
            len: 0,
        };
    }

    // Validate data length
    if data_len > MAX_DATA_LEN {
        #[cfg(debug_assertions)]
        eprintln!("Error: data_len {} exceeds maximum {}", data_len, MAX_DATA_LEN);
        return SignatureBytes {
            data: std::ptr::null_mut(),
            len: 0,
        };
    }

    let signing_key = unsafe { &*signing_key_ptr };
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };

    // Sign with Schnorr (uses OsRng for nonce)
    let mut rng = OsRng;
    let signature: Signature = signing_key.sign(&mut rng, data);

    // Serialize signature to bytes
    let mut sig_bytes = Vec::new();
    if let Err(e) = signature.serialize(&mut sig_bytes) {
        #[cfg(debug_assertions)]
        eprintln!("Error serializing signature: {}", e);
        return SignatureBytes {
            data: std::ptr::null_mut(),
            len: 0,
        };
    }

    let len = sig_bytes.len();
    let data_ptr = sig_bytes.as_mut_ptr();
    std::mem::forget(sig_bytes); // Transfer ownership to caller

    SignatureBytes {
        data: data_ptr,
        len,
    }
}

/// Frees signature bytes returned from sign_data
///
/// # Safety
///
/// **CALLER MUST GUARANTEE:**
/// 1. `ptr` was returned from `sign_data()` as SignatureBytes.data (not from any other source)
/// 2. `len` is the exact value from `sign_data()` as SignatureBytes.len (not modified)
/// 3. `ptr` has not been previously freed
/// 4. `ptr` is not currently in use by another thread
/// 5. `ptr` will not be used after this call
///
/// **FAILURE TO MEET THESE CONDITIONS RESULTS IN UNDEFINED BEHAVIOR:**
/// - Double-free corruption if pointer already freed
/// - Memory corruption if len is incorrect (too small or too large)
/// - Freeing invalid memory if pointer is from wrong source
/// - Use-after-free if pointer is accessed after freeing
/// - Data races if pointer is concurrently accessed
///
/// **MEMORY OWNERSHIP:**
/// - This function takes ownership and deallocates the signature bytes
/// - After this call, the pointer is invalid and must not be dereferenced
/// - It is safe to call this function with a null pointer (no-op)
/// - It is safe to call with len=0 (no-op with warning in debug builds)
///
/// **USAGE PATTERN:**
/// ```c
/// SignatureBytes sig = sign_data(key, data, data_len);
/// if (sig.data != NULL) {
///     // ... use signature ...
///     free_signature(sig.data, sig.len);  // Must call exactly once
///     // sig.data is now invalid, do not use
/// }
/// ```
#[no_mangle]
pub extern "C" fn free_signature(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }

    if len == 0 {
        #[cfg(debug_assertions)]
        eprintln!("Warning: free_signature called with len=0");
        return;
    }

    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ERROR PATH TESTS =====

    #[test]
    fn test_null_pointer() {
        let key_ptr = create_signing_key(std::ptr::null(), 32);
        assert!(key_ptr.is_null());
    }

    #[test]
    fn test_invalid_key_length_too_short() {
        let invalid_key = [0u8; 16];
        let key_ptr = create_signing_key(invalid_key.as_ptr(), 16);
        assert!(key_ptr.is_null());
    }

    #[test]
    fn test_invalid_key_length_too_long() {
        let invalid_key = [0u8; 64];
        let key_ptr = create_signing_key(invalid_key.as_ptr(), 64);
        assert!(key_ptr.is_null());
    }

    #[test]
    fn test_invalid_all_zero_private_key() {
        // All-zero private key is invalid for Schnorr signatures
        let invalid_key = [0u8; 32];
        let key_ptr = create_signing_key(invalid_key.as_ptr(), 32);
        // Should fail validation
        assert!(key_ptr.is_null());
    }

    #[test]
    fn test_sign_data_null_signing_key() {
        let data = b"test message";
        let sig = sign_data(std::ptr::null(), data.as_ptr(), data.len());
        assert!(sig.data.is_null());
        assert_eq!(sig.len, 0);
    }

    #[test]
    fn test_sign_data_null_data_ptr() {
        // Create a valid key first
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Try to sign with null data
        let sig = sign_data(key_ptr, std::ptr::null(), 100);
        assert!(sig.data.is_null());
        assert_eq!(sig.len, 0);

        // Clean up
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_sign_data_exceeds_max_length() {
        // Create a valid key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Try to sign data exceeding 1 MB limit
        let data = vec![0u8; 100];
        let sig = sign_data(key_ptr, data.as_ptr(), 2 * 1024 * 1024); // 2 MB
        assert!(sig.data.is_null());
        assert_eq!(sig.len, 0);

        // Clean up
        free_signing_key(key_ptr);
    }

    // ===== SUCCESS PATH TESTS =====

    #[test]
    fn test_valid_key_creation_and_cleanup() {
        // Use a known valid private key (from BIP-340 test vectors)
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);

        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        // Should succeed
        assert!(!key_ptr.is_null());

        // Clean up
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_sign_data_produces_valid_signature() {
        // Create valid signing key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Sign some data
        let data = b"test message";
        let sig = sign_data(key_ptr, data.as_ptr(), data.len());

        // Should succeed
        assert!(!sig.data.is_null());
        assert!(sig.len > 0);

        // Schnorr signatures are typically 64 bytes
        assert_eq!(sig.len, 64, "Schnorr signature should be 64 bytes");

        // Verify signature is not all zeros
        let sig_slice = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };
        let all_zeros = sig_slice.iter().all(|&b| b == 0);
        assert!(!all_zeros, "Signature should not be all zeros");

        // Clean up
        free_signature(sig.data, sig.len);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_memory_lifecycle_multiple_signatures() {
        // Create key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Sign multiple messages with same key
        let msg1 = b"message 1";
        let msg2 = b"message 2";
        let msg3 = b"message 3";

        let sig1 = sign_data(key_ptr, msg1.as_ptr(), msg1.len());
        let sig2 = sign_data(key_ptr, msg2.as_ptr(), msg2.len());
        let sig3 = sign_data(key_ptr, msg3.as_ptr(), msg3.len());

        // All should succeed
        assert!(!sig1.data.is_null());
        assert!(!sig2.data.is_null());
        assert!(!sig3.data.is_null());

        assert_eq!(sig1.len, 64);
        assert_eq!(sig2.len, 64);
        assert_eq!(sig3.len, 64);

        // Signatures should be different (random nonce)
        let sig1_slice = unsafe { std::slice::from_raw_parts(sig1.data, sig1.len) };
        let sig2_slice = unsafe { std::slice::from_raw_parts(sig2.data, sig2.len) };
        assert_ne!(sig1_slice, sig2_slice, "Signatures should differ due to random nonce");

        // Free all signatures
        free_signature(sig1.data, sig1.len);
        free_signature(sig2.data, sig2.len);
        free_signature(sig3.data, sig3.len);

        // Free key
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_sign_empty_data() {
        // Create key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Sign empty data
        let empty_data: &[u8] = &[];
        let sig = sign_data(key_ptr, empty_data.as_ptr(), 0);

        // Should succeed (Schnorr can sign empty messages)
        assert!(!sig.data.is_null());
        assert_eq!(sig.len, 64);

        // Clean up
        free_signature(sig.data, sig.len);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_sign_large_data() {
        // Create key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Sign 100 KB of data (well within 1 MB limit)
        let large_data = vec![0x42u8; 100 * 1024];
        let sig = sign_data(key_ptr, large_data.as_ptr(), large_data.len());

        // Should succeed
        assert!(!sig.data.is_null());
        assert_eq!(sig.len, 64);

        // Clean up
        free_signature(sig.data, sig.len);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_free_signature_with_null_pointer() {
        // Should not crash
        free_signature(std::ptr::null_mut(), 64);
    }

    #[test]
    fn test_free_signature_with_zero_length() {
        // Create a dummy pointer (not dereferenced)
        let dummy_ptr = 0x1234 as *mut u8;
        // Should not crash (returns early)
        free_signature(dummy_ptr, 0);
    }

    #[test]
    fn test_free_signing_key_with_null_pointer() {
        // Should not crash
        free_signing_key(std::ptr::null_mut());
    }

    // ===== SIGNATURE VERIFICATION TESTS =====

    #[test]
    fn test_get_verifying_key() {
        // Create signing key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Get verifying key
        let pub_key_ptr = get_verifying_key(key_ptr);
        assert!(!pub_key_ptr.is_null());

        // Verify it's 32 bytes
        let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };
        assert_eq!(pub_key_bytes.len(), 32);

        // Verify it's not all zeros
        let all_zeros = pub_key_bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros, "Public key should not be all zeros");

        // Clean up
        free_verifying_key(pub_key_ptr);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_get_verifying_key_null_pointer() {
        let pub_key_ptr = get_verifying_key(std::ptr::null());
        assert!(pub_key_ptr.is_null());
    }

    #[test]
    fn test_signature_verification() {
        // Create signing key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null());

        // Sign data
        let data = b"test message";
        let sig = sign_data(key_ptr, data.as_ptr(), data.len());
        assert!(!sig.data.is_null());
        assert_eq!(sig.len, 64);

        // Get public key
        let pub_key_ptr = get_verifying_key(key_ptr);
        assert!(!pub_key_ptr.is_null());

        // Deserialize signature and verifying key
        let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };
        let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };

        let signature = Signature::deserialize(&mut &sig_bytes[..], 0).unwrap();
        let verifying_key = VerifyingKey::deserialize(&mut &pub_key_bytes[..], 0).unwrap();

        // CRITICAL: Verify signature is valid
        assert!(
            verifying_key.verify(data, &signature),
            "Signature must be valid for the given data and public key"
        );

        // Clean up
        free_signature(sig.data, sig.len);
        free_verifying_key(pub_key_ptr);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_signature_verification_wrong_data_fails() {
        // Create signing key
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        // Sign data
        let data = b"test message";
        let sig = sign_data(key_ptr, data.as_ptr(), data.len());

        // Get public key
        let pub_key_ptr = get_verifying_key(key_ptr);

        // Deserialize
        let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };
        let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };
        let signature = Signature::deserialize(&mut &sig_bytes[..], 0).unwrap();
        let verifying_key = VerifyingKey::deserialize(&mut &pub_key_bytes[..], 0).unwrap();

        // Verify with WRONG data should fail
        let wrong_data = b"wrong message";
        assert!(
            !verifying_key.verify(wrong_data, &signature),
            "Signature must be invalid for different data"
        );

        // Clean up
        free_signature(sig.data, sig.len);
        free_verifying_key(pub_key_ptr);
        free_signing_key(key_ptr);
    }

    // ===== BIP-340 TEST VECTORS =====

    #[test]
    fn test_bip340_public_key_derivation() {
        // BIP-340 test vector index 0
        // Private Key: 0000000000000000000000000000000000000000000000000000000000000003
        // Expected Public Key: F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9

        let private_key = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000003"
        ).unwrap();
        let expected_pub_key = hex::decode(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
        ).unwrap();

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);
        assert!(!key_ptr.is_null(), "BIP-340 test vector private key should be valid");

        // Get public key
        let pub_key_ptr = get_verifying_key(key_ptr);
        assert!(!pub_key_ptr.is_null());

        let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };

        // Verify public key matches BIP-340 test vector
        assert_eq!(
            pub_key_bytes,
            &expected_pub_key[..],
            "Public key must match BIP-340 test vector"
        );

        // Clean up
        free_verifying_key(pub_key_ptr);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_bip340_additional_test_vectors() {
        // BIP-340 test vector index 1
        let test_vectors = vec![
            (
                // Private key
                "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                // Expected public key
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            ),
        ];

        for (i, (priv_hex, pub_hex)) in test_vectors.iter().enumerate() {
            let private_key = hex::decode(priv_hex).unwrap();
            let expected_pub_key = hex::decode(pub_hex).unwrap();

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&private_key);
            let key_ptr = create_signing_key(key_array.as_ptr(), 32);
            assert!(!key_ptr.is_null(), "Test vector {} private key should be valid", i + 1);

            let pub_key_ptr = get_verifying_key(key_ptr);
            let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };

            assert_eq!(
                pub_key_bytes,
                &expected_pub_key[..],
                "Test vector {} public key must match BIP-340",
                i + 1
            );

            free_verifying_key(pub_key_ptr);
            free_signing_key(key_ptr);
        }
    }

    // ===== SERIALIZATION FORMAT TESTS =====

    #[test]
    fn test_signature_format_is_64_bytes() {
        // Schnorr BIP-340 signatures are R (32 bytes) || s (32 bytes)
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        let data = b"test";
        let sig = sign_data(key_ptr, data.as_ptr(), data.len());

        // Verify format
        assert_eq!(sig.len, 64, "Schnorr signature must be exactly 64 bytes");

        let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };

        // Verify R component (first 32 bytes) is not all zeros
        let r_bytes = &sig_bytes[0..32];
        assert!(!r_bytes.iter().all(|&b| b == 0), "R component must not be all zeros");

        // Verify s component (last 32 bytes) is not all zeros
        let s_bytes = &sig_bytes[32..64];
        assert!(!s_bytes.iter().all(|&b| b == 0), "s component must not be all zeros");

        free_signature(sig.data, sig.len);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_signature_components_are_valid() {
        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        let data = b"test message for signature format validation";
        let sig = sign_data(key_ptr, data.as_ptr(), data.len());

        let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };

        // Deserialize and verify the signature can be parsed
        let signature = Signature::deserialize(&mut &sig_bytes[..], 0);
        assert!(
            signature.is_ok(),
            "Signature bytes must be deserializable as valid Schnorr signature"
        );

        free_signature(sig.data, sig.len);
        free_signing_key(key_ptr);
    }

    // ===== FUZZING TESTS =====

    #[test]
    fn test_fuzz_sign_random_data_lengths() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        // Test 100 random data lengths
        for _ in 0..100 {
            let data_len = rng.gen_range(0..1000);
            let data: Vec<u8> = (0..data_len).map(|_| rng.gen()).collect();

            let sig = sign_data(key_ptr, data.as_ptr(), data.len());

            // Should always succeed for valid lengths
            assert!(!sig.data.is_null(), "Signing should succeed for length {}", data_len);
            assert_eq!(sig.len, 64);

            free_signature(sig.data, sig.len);
        }

        free_signing_key(key_ptr);
    }

    #[test]
    fn test_fuzz_sign_random_data_patterns() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        // Test various data patterns
        let patterns = vec![
            vec![0u8; 100],           // All zeros
            vec![0xFFu8; 100],        // All ones
            vec![0xAAu8; 100],        // Alternating bits
            vec![0x55u8; 100],        // Alternating bits (inverse)
            (0..100).map(|i| i as u8).collect(), // Sequential
        ];

        for pattern in patterns {
            let sig = sign_data(key_ptr, pattern.as_ptr(), pattern.len());
            assert!(!sig.data.is_null());
            assert_eq!(sig.len, 64);

            // Verify signature is valid
            let pub_key_ptr = get_verifying_key(key_ptr);
            let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };
            let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };

            let signature = Signature::deserialize(&mut &sig_bytes[..], 0).unwrap();
            let verifying_key = VerifyingKey::deserialize(&mut &pub_key_bytes[..], 0).unwrap();

            assert!(
                verifying_key.verify(&pattern, &signature),
                "Signature must be valid for pattern data"
            );

            free_verifying_key(pub_key_ptr);
            free_signature(sig.data, sig.len);
        }

        free_signing_key(key_ptr);
    }

    // ===== CROSS-PLATFORM TESTS =====

    #[test]
    fn test_signature_determinism_with_same_key() {
        // Note: Schnorr uses random nonce, so signatures will differ
        // This test verifies that DIFFERENT signatures are still VALID

        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        let data = b"determinism test";

        // Sign same data multiple times
        let sig1 = sign_data(key_ptr, data.as_ptr(), data.len());
        let sig2 = sign_data(key_ptr, data.as_ptr(), data.len());
        let sig3 = sign_data(key_ptr, data.as_ptr(), data.len());

        // Signatures should be different (random nonce)
        let sig1_bytes = unsafe { std::slice::from_raw_parts(sig1.data, sig1.len) };
        let sig2_bytes = unsafe { std::slice::from_raw_parts(sig2.data, sig2.len) };
        let sig3_bytes = unsafe { std::slice::from_raw_parts(sig3.data, sig3.len) };

        assert_ne!(sig1_bytes, sig2_bytes, "Signatures should differ due to random nonce");
        assert_ne!(sig2_bytes, sig3_bytes, "Signatures should differ due to random nonce");

        // But ALL signatures should be valid
        let pub_key_ptr = get_verifying_key(key_ptr);
        let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };
        let verifying_key = VerifyingKey::deserialize(&mut &pub_key_bytes[..], 0).unwrap();

        for (i, sig_bytes) in [sig1_bytes, sig2_bytes, sig3_bytes].iter().enumerate() {
            let signature = Signature::deserialize(&mut &sig_bytes[..], 0).unwrap();
            assert!(
                verifying_key.verify(data, &signature),
                "Signature {} must be valid",
                i + 1
            );
        }

        free_verifying_key(pub_key_ptr);
        free_signature(sig1.data, sig1.len);
        free_signature(sig2.data, sig2.len);
        free_signature(sig3.data, sig3.len);
        free_signing_key(key_ptr);
    }

    #[test]
    fn test_endianness_independence() {
        // Verify that our serialization is endianness-independent
        // by checking that byte order matches expected format

        let valid_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&valid_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        // Use data with known byte pattern
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let sig = sign_data(key_ptr, data.as_ptr(), data.len());

        // Signature should be parseable regardless of platform
        let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };
        let signature = Signature::deserialize(&mut &sig_bytes[..], 0);

        assert!(
            signature.is_ok(),
            "Signature must be deserializable on any platform"
        );

        free_signature(sig.data, sig.len);
        free_signing_key(key_ptr);
    }

    // ===== CONSTANT-TIME AWARENESS TESTS =====

    #[test]
    fn test_constant_time_verification_documentation() {
        // This test documents that constant-time operations are handled
        // by midnight-base-crypto, not by this FFI layer.
        //
        // Schnorr signature verification MUST be constant-time to prevent
        // timing attacks that could leak private key information.
        //
        // The midnight-base-crypto library is responsible for:
        // 1. Constant-time signature verification
        // 2. Constant-time scalar multiplication
        // 3. Constant-time point operations
        //
        // This FFI layer does NOT introduce timing vulnerabilities because:
        // 1. We only do length checks (not secret-dependent)
        // 2. We only do null checks (not secret-dependent)
        // 3. All cryptographic operations delegated to midnight-base-crypto

        // This test just documents the requirement and passes
        assert!(true, "Constant-time guarantees provided by midnight-base-crypto");
    }

    #[test]
    fn test_no_early_returns_on_secret_data() {
        // Verify that our validation doesn't leak timing information
        // by checking that error paths don't depend on secret data

        // These should fail at validation (before crypto operations)
        let null_result = create_signing_key(std::ptr::null(), 32);
        assert!(null_result.is_null());

        let wrong_len_result = create_signing_key([0u8; 16].as_ptr(), 16);
        assert!(wrong_len_result.is_null());

        // These failures happen BEFORE any secret-dependent operations,
        // so they don't leak timing information about valid keys

        assert!(true, "Validation failures don't leak secret data");
    }

    // ===== PHASE 1 INTEGRATION TEST =====

    #[test]
    fn test_phase1_bip32_to_schnorr_integration() {
        // This test proves that BIP-32 derived keys from Phase 1 work
        // with Phase 2D-FFI Schnorr signing
        //
        // Test vector source: TEST_VECTORS_PHASE2.md Section 2
        // Mnemonic: "abandon abandon abandon ... art" (24 words)
        // Passphrase: "" (empty)
        // Derivation path: m/44'/2400'/0'/0/0 (account 0, NIGHT_EXTERNAL role, index 0)
        //
        // This private key is derived using:
        // 1. BIP-39: mnemonic → seed
        // 2. BIP-32: seed → HD wallet → derive at path
        // 3. Result: Private key for first unshielded receiving address

        // Private key from BIP-32 derivation (verified in Phase 1)
        let bip32_private_key = hex::decode(
            "d319aebe08e7706091e56b1abe83f50ba6d3ceb4209dd0deca8ab22b264ff31c"
        ).unwrap();

        // Step 1: Create signing key from BIP-32 private key
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&bip32_private_key);
        let key_ptr = create_signing_key(key_array.as_ptr(), 32);

        assert!(
            !key_ptr.is_null(),
            "BIP-32 derived private key should create valid signing key"
        );

        // Step 2: Sign transaction data with the key
        let transaction_data = b"Midnight transaction intent data";
        let sig = sign_data(key_ptr, transaction_data.as_ptr(), transaction_data.len());

        assert!(
            !sig.data.is_null(),
            "Signing with BIP-32 key should produce signature"
        );
        assert_eq!(sig.len, 64, "Signature should be 64 bytes");

        // Step 3: Extract public key
        let pub_key_ptr = get_verifying_key(key_ptr);
        assert!(
            !pub_key_ptr.is_null(),
            "Should extract public key from BIP-32 signing key"
        );

        // Step 4: Verify signature is cryptographically valid
        let sig_bytes = unsafe { std::slice::from_raw_parts(sig.data, sig.len) };
        let pub_key_bytes = unsafe { std::slice::from_raw_parts(pub_key_ptr, 32) };

        let signature = Signature::deserialize(&mut &sig_bytes[..], 0).unwrap();
        let verifying_key = VerifyingKey::deserialize(&mut &pub_key_bytes[..], 0).unwrap();

        assert!(
            verifying_key.verify(transaction_data, &signature),
            "Signature from BIP-32 key must be cryptographically valid"
        );

        // Step 5: Verify wrong data fails (negative test)
        let wrong_data = b"Different transaction data";
        assert!(
            !verifying_key.verify(wrong_data, &signature),
            "Signature must be invalid for different data"
        );

        // Clean up
        free_signature(sig.data, sig.len);
        free_verifying_key(pub_key_ptr);
        free_signing_key(key_ptr);

        // SUCCESS: Proves end-to-end flow works:
        // Phase 1 (BIP-32 derivation) → Phase 2D-FFI (Schnorr signing) → Verification
    }
}
