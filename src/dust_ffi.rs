//! Dust Key Derivation FFI
//!
//! Provides C FFI interfaces for deriving Midnight dust keys.
//! Dust is Midnight's fee payment mechanism.

use std::ffi::CString;
use std::os::raw::c_char;

// Import midnight-ledger dust types
use midnight_ledger::dust::{DustSecretKey, DustPublicKey, Seed};
use midnight_serialize::Serializable;

/// Derives dust public key from a 32-byte seed.
///
/// # Safety
///
/// - `seed_ptr` must be a valid pointer to a 32-byte array
/// - `seed_len` must be exactly 32
/// - Caller must call `free_c_string` to free the returned pointer
///
/// # Returns
///
/// Pointer to C string containing hex-encoded public key (64 chars), or null on error
#[no_mangle]
pub extern "C" fn derive_dust_public_key(
    seed_ptr: *const u8,
    seed_len: usize,
) -> *mut c_char {
    // Safety checks
    if seed_ptr.is_null() {
        eprintln!("Error: seed_ptr is null");
        return std::ptr::null_mut();
    }

    if seed_len != 32 {
        eprintln!("Error: seed must be 32 bytes, got {}", seed_len);
        return std::ptr::null_mut();
    }

    // Convert to Rust slice (unsafe)
    let seed_slice = unsafe {
        std::slice::from_raw_parts(seed_ptr, seed_len)
    };

    // Convert to fixed-size array (Seed is just [u8; 32])
    let mut seed_array: Seed = [0u8; 32];
    seed_array.copy_from_slice(seed_slice);

    // Create DustSecretKey from seed
    let dust_secret_key = DustSecretKey::derive_secret_key(&seed_array);

    // Derive public key using From trait
    let dust_public_key = DustPublicKey::from(dust_secret_key);

    // Serialize public key
    let mut pk_bytes = Vec::new();
    if let Err(e) = dust_public_key.serialize(&mut pk_bytes) {
        eprintln!("Error serializing dust public key: {}", e);
        return std::ptr::null_mut();
    }

    // Convert to hex string
    let pk_hex = hex::encode(&pk_bytes);

    // Convert to C string
    let pk_cstr = match CString::new(pk_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error creating C string for dust public key: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Transfer ownership to caller
    pk_cstr.into_raw()
}

/// Frees a C string allocated by this module
///
/// # Safety
///
/// - `ptr` must be a pointer returned from a function in this module
/// - `ptr` must not be used after calling this function
/// - Must be called exactly once per pointer
#[no_mangle]
pub extern "C" fn free_c_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        // Take ownership back and drop
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_dust_public_key() {
        // Test with a known seed
        let seed_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let seed = hex::decode(seed_hex).unwrap();

        // Call FFI function
        let pk_ptr = derive_dust_public_key(seed.as_ptr(), seed.len());
        assert!(!pk_ptr.is_null());

        unsafe {
            // Convert C string to Rust string
            let pk_str = std::ffi::CStr::from_ptr(pk_ptr)
                .to_str()
                .unwrap();

            // Should be 66 hex characters (33 bytes: 1-byte tag + 32 bytes data)
            assert_eq!(pk_str.len(), 66, "Public key should be 66 hex chars (with tag)");

            // Free memory
            free_c_string(pk_ptr);
        }
    }

    #[test]
    fn test_invalid_seed_length() {
        let invalid_seed = vec![0u8; 16]; // Wrong size
        let pk_ptr = derive_dust_public_key(invalid_seed.as_ptr(), invalid_seed.len());
        assert!(pk_ptr.is_null());
    }

    #[test]
    fn test_null_pointer() {
        let pk_ptr = derive_dust_public_key(std::ptr::null(), 32);
        assert!(pk_ptr.is_null());
    }
}
