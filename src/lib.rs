//! Kuira Crypto FFI - JNI bridge to Midnight's Rust cryptography
//!
//! This crate provides C FFI interfaces for:
//! - Deriving shielded keys (zswap)
//! - Signing transactions (Schnorr BIP-340)
//! - Serializing transactions (SCALE codec)

use std::ffi::CString;
use std::os::raw::c_char;
use midnight_zswap::keys::{SecretKeys, Seed};
use midnight_serialize::Serializable;

// Initialize Android logging
#[cfg(target_os = "android")]
use android_logger::Config;

#[cfg(target_os = "android")]
fn init_logging() {
    android_logger::init_once(
        Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("KuiraCrypto")
    );
}

#[cfg(not(target_os = "android"))]
fn init_logging() {
    // No-op on non-Android platforms
}

/// Initialize the library (called from JNI_OnLoad)
#[no_mangle]
pub extern "C" fn kuira_crypto_init() {
    init_logging();
}

// Transaction signing FFI
pub mod transaction_ffi;

// Transaction serialization (SCALE codec)
pub mod serialize;

// Dust key derivation FFI
pub mod dust_ffi;

// Zswap (shielded) wallet FFI (Phase 4B-Shielded)
pub mod zswap_ffi;

// Fee calculation FFI (Phase 2E)
pub mod fee_ffi;

// Local ZK proving FFI (Phase 4C)
pub mod prove_ffi;

// Contract operations FFI (Phase 6)
pub mod contract_ffi;

// Transaction balancing FFI (SDK — balance proven tx with dust)
pub mod balance_ffi;

// Key validity tests
#[cfg(test)]
mod test_key_validity;

/// Result struct containing hex-encoded public keys
#[repr(C)]
pub struct ShieldedKeys {
    /// Coin public key (64 hex characters)
    pub coin_public_key: *mut c_char,
    /// Encryption public key (64 hex characters)
    pub encryption_public_key: *mut c_char,
}

/// Derives shielded public keys from a 32-byte seed.
///
/// # Safety
///
/// - `seed_ptr` must be a valid pointer to a 32-byte array
/// - `seed_len` must be exactly 32
/// - Caller must call `free_shielded_keys` to free the returned pointer
///
/// # Returns
///
/// Pointer to ShieldedKeys struct, or null on error
#[no_mangle]
pub extern "C" fn derive_shielded_keys(
    seed_ptr: *const u8,
    seed_len: usize,
) -> *mut ShieldedKeys {
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

    // Convert to fixed-size array
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed_slice);
    let seed = Seed::from(seed_array);

    // Derive keys using Midnight's implementation
    let secret_keys = SecretKeys::from(seed);

    // Debug: Print coin secret key
    eprintln!("DEBUG coin_secret_key bytes: {:?}", &secret_keys.coin_secret_key.0.0[..]);

    let coin_pk = secret_keys.coin_public_key();
    let enc_pk = secret_keys.enc_public_key();

    // Debug: Print raw coin public key bytes
    eprintln!("DEBUG coin_pk HashOutput bytes: {:?}", &coin_pk.0.0[..]);

    // Serialize both public keys using Serializable trait
    // This matches what the WASM wrapper does via to_value_hex_ser
    let mut coin_pk_bytes = Vec::new();
    if let Err(e) = coin_pk.serialize(&mut coin_pk_bytes) {
        eprintln!("Error serializing coin public key: {}", e);
        return std::ptr::null_mut();
    }

    let mut enc_pk_bytes = Vec::new();
    if let Err(e) = enc_pk.serialize(&mut enc_pk_bytes) {
        eprintln!("Error serializing encryption public key: {}", e);
        return std::ptr::null_mut();
    }

    // Debug: Print serialized lengths
    eprintln!("DEBUG coin_pk serialized length: {} bytes", coin_pk_bytes.len());
    eprintln!("DEBUG enc_pk serialized length: {} bytes", enc_pk_bytes.len());

    // Convert to hex strings
    let coin_hex = hex::encode(&coin_pk_bytes);
    let enc_hex = hex::encode(&enc_pk_bytes);

    // Convert to C strings
    let coin_cstr = match CString::new(coin_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error creating C string for coin key: {}", e);
            return std::ptr::null_mut();
        }
    };

    let enc_cstr = match CString::new(enc_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error creating C string for encryption key: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Allocate result and transfer ownership to caller
    Box::into_raw(Box::new(ShieldedKeys {
        coin_public_key: coin_cstr.into_raw(),
        encryption_public_key: enc_cstr.into_raw(),
    }))
}

/// Frees memory allocated by derive_shielded_keys
///
/// # Safety
///
/// - `ptr` must be a pointer returned from `derive_shielded_keys`
/// - `ptr` must not be used after calling this function
/// - Must be called exactly once per pointer
#[no_mangle]
pub extern "C" fn free_shielded_keys(ptr: *mut ShieldedKeys) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        // Take ownership back and drop
        let keys = Box::from_raw(ptr);

        // Free the C strings
        if !keys.coin_public_key.is_null() {
            let _ = CString::from_raw(keys.coin_public_key);
        }
        if !keys.encryption_public_key.is_null() {
            let _ = CString::from_raw(keys.encryption_public_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_serialize::Serializable;

    #[test]
    fn test_serialization_lengths() {
        // Test with known seed to verify serialization format
        let seed_hex = "b7637860b12f892ee07c67ad441c7935e37ac2153cefa39ae79083284f6d9180";
        let seed_bytes = hex::decode(seed_hex).unwrap();
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed_bytes);
        let seed = Seed::from(seed_array);

        let secret_keys = SecretKeys::from(seed);
        let coin_pk = secret_keys.coin_public_key();
        let enc_pk = secret_keys.enc_public_key();

        // Serialize both keys
        let mut coin_pk_bytes = Vec::new();
        coin_pk.serialize(&mut coin_pk_bytes).unwrap();

        let mut enc_pk_bytes = Vec::new();
        enc_pk.serialize(&mut enc_pk_bytes).unwrap();

        println!("Coin PK serialized: {} bytes", coin_pk_bytes.len());
        println!("Coin PK hex: {}", hex::encode(&coin_pk_bytes));
        println!("Enc PK serialized: {} bytes", enc_pk_bytes.len());
        println!("Enc PK hex: {}", hex::encode(&enc_pk_bytes));

        // Expected from Midnight SDK (verified with TypeScript SDK):
        // - Coin PK should be 32 bytes
        // - Enc PK should be 32 bytes (NOT 58 - that was from outdated test vectors)
        assert_eq!(coin_pk_bytes.len(), 32, "Coin PK should be 32 bytes");
        assert_eq!(enc_pk_bytes.len(), 32, "Enc PK should be 32 bytes");
    }

    #[test]
    fn test_derive_shielded_keys_with_test_vector() {
        // Test vector from "abandon abandon ... art" mnemonic at m/44'/2400'/0'/3/0
        let seed_hex = "b7637860b12f892ee07c67ad441c7935e37ac2153cefa39ae79083284f6d9180";
        let seed = hex::decode(seed_hex).unwrap();

        // Call FFI function
        let keys_ptr = derive_shielded_keys(seed.as_ptr(), seed.len());
        assert!(!keys_ptr.is_null());

        unsafe {
            let keys = &*keys_ptr;

            // Convert C strings back to Rust strings
            let coin_pk = std::ffi::CStr::from_ptr(keys.coin_public_key)
                .to_str()
                .unwrap();
            let enc_pk = std::ffi::CStr::from_ptr(keys.encryption_public_key)
                .to_str()
                .unwrap();

            // Expected values from Midnight SDK (v8 — updated for audit-fixed domain separators)
            assert_eq!(
                coin_pk,
                "9408aeffbeedc6b9b45e1bcc621d1a273fb67f77de3f65bfbb1814d84f8b6524",
                "Coin public key mismatch"
            );
            assert_eq!(
                enc_pk,
                "f3ae706bf28c856a407690b468081a7f5a123e523501b69f4395abcd7e19032b",
                "Encryption public key mismatch"
            );

            // Free memory
            free_shielded_keys(keys_ptr);
        }
    }

    #[test]
    fn test_invalid_seed_length() {
        let invalid_seed = vec![0u8; 16]; // Wrong size
        let keys_ptr = derive_shielded_keys(invalid_seed.as_ptr(), invalid_seed.len());
        assert!(keys_ptr.is_null());
    }

    #[test]
    fn test_null_pointer() {
        let keys_ptr = derive_shielded_keys(std::ptr::null(), 32);
        assert!(keys_ptr.is_null());
    }
}
