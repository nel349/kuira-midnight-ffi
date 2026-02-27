//! Dust Wallet FFI
//!
//! Provides C FFI interfaces for Midnight dust wallet operations:
//! - Dust key derivation
//! - Dust local state management
//! - Dust token tracking and spending
//!
//! Dust is Midnight's fee payment mechanism.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

// Import midnight-ledger dust types
use midnight_ledger::dust::{
    DustSecretKey, DustPublicKey, Seed, DustLocalState, INITIAL_DUST_PARAMETERS,
    QualifiedDustOutput, DustGenerationInfo,
};
use midnight_ledger::events::Event;
use midnight_base_crypto::time::Timestamp;
use midnight_storage::db::InMemoryDB;
use midnight_serialize::{Serializable, Deserializable};

// Android logging macro
#[cfg(target_os = "android")]
macro_rules! android_log {
    ($level:expr, $tag:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        let c_tag = std::ffi::CString::new($tag).unwrap();
        let c_msg = std::ffi::CString::new(msg).unwrap();
        unsafe {
            __android_log_write($level, c_tag.as_ptr(), c_msg.as_ptr());
        }
    }};
}

#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write(prio: std::os::raw::c_int, tag: *const std::os::raw::c_char, text: *const std::os::raw::c_char) -> std::os::raw::c_int;
}

#[cfg(target_os = "android")]
const ANDROID_LOG_ERROR: std::os::raw::c_int = 6;

#[cfg(not(target_os = "android"))]
macro_rules! android_log {
    ($level:expr, $tag:expr, $($arg:tt)*) => {{
        eprintln!("[{}] {}", $tag, format!($($arg)*));
    }};
}

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

//
// ============================================================================
// DustLocalState FFI Functions
// ============================================================================
//

/// Type alias for DustLocalState with InMemoryDB
type DustState = DustLocalState<InMemoryDB>;

/// Creates a new DustLocalState with default parameters.
///
/// # Safety
///
/// - Caller must call `free_dust_local_state` to free the returned pointer
///
/// # Returns
///
/// Pointer to DustLocalState, or null on error
#[no_mangle]
pub extern "C" fn create_dust_local_state() -> *mut DustState {
    let state = DustLocalState::new(INITIAL_DUST_PARAMETERS);
    Box::into_raw(Box::new(state))
}

/// Gets the wallet balance at a specific time as a decimal string.
///
/// # Safety
///
/// - `state_ptr` must be a valid pointer to DustLocalState
/// - `time_millis` is Unix timestamp in milliseconds
/// - Caller must call `free_c_string` to free the returned pointer
///
/// # Returns
///
/// Balance in Specks as decimal string (e.g., "1000000"), or null on error
#[no_mangle]
pub extern "C" fn dust_wallet_balance(
    state_ptr: *const DustState,
    time_millis: i64,
) -> *mut c_char {
    if state_ptr.is_null() {
        eprintln!("Error: state_ptr is null");
        return ptr::null_mut();
    }

    unsafe {
        let state = &*state_ptr;
        // Convert milliseconds to seconds for Timestamp
        let time_secs = (time_millis / 1000) as u64;
        let time = Timestamp::from_secs(time_secs);
        let balance = state.wallet_balance(time);

        // Convert u128 to decimal string
        let balance_str = balance.to_string();

        // Convert to C string
        let balance_cstr = match CString::new(balance_str) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error creating C string for balance: {}", e);
                return ptr::null_mut();
            }
        };

        // Transfer ownership to caller
        balance_cstr.into_raw()
    }
}

/// Serializes DustLocalState to bytes.
///
/// # Safety
///
/// - `state_ptr` must be a valid pointer to DustLocalState
/// - Caller must call `free_byte_array` to free the returned data
///
/// # Returns
///
/// Pointer to serialized bytes (format: length as first 8 bytes, then data),
/// or null on error
#[no_mangle]
pub extern "C" fn serialize_dust_state(
    state_ptr: *const DustState,
) -> *mut u8 {
    if state_ptr.is_null() {
        eprintln!("Error: state_ptr is null");
        return ptr::null_mut();
    }

    unsafe {
        let state = &*state_ptr;
        let mut bytes = Vec::new();

        if let Err(e) = state.serialize(&mut bytes) {
            eprintln!("Error serializing dust state: {}", e);
            return ptr::null_mut();
        }

        // Prepend length (8 bytes, little-endian)
        let len = bytes.len() as u64;
        let mut result = Vec::with_capacity(8 + bytes.len());
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&bytes);

        // Leak the vec and return pointer
        let ptr = result.as_mut_ptr();
        std::mem::forget(result);
        ptr
    }
}

/// Deserializes DustLocalState from bytes.
///
/// # Safety
///
/// - `data_ptr` must point to valid serialized DustLocalState bytes
/// - `data_len` must be the exact length of the serialized data
/// - Caller must call `free_dust_local_state` to free the returned pointer
///
/// # Returns
///
/// Pointer to DustLocalState, or null on error (invalid data, deserialization failure)
#[no_mangle]
pub extern "C" fn deserialize_dust_state(
    data_ptr: *const u8,
    data_len: usize,
) -> *mut DustState {
    if data_ptr.is_null() {
        eprintln!("Error: data_ptr is null");
        return ptr::null_mut();
    }

    if data_len == 0 {
        eprintln!("Error: data_len is 0");
        return ptr::null_mut();
    }

    unsafe {
        // Get slice of serialized data
        let data_slice = std::slice::from_raw_parts(data_ptr, data_len);

        // Deserialize using SCALE codec (recursion_depth=0 for top-level)
        match <DustState as Deserializable>::deserialize(&mut &data_slice[..], 0) {
            Ok(state) => {
                // Box and return pointer
                Box::into_raw(Box::new(state))
            }
            Err(e) => {
                eprintln!("Error deserializing dust state: {}", e);
                ptr::null_mut()
            }
        }
    }
}

/// Frees a DustLocalState pointer.
///
/// # Safety
///
/// - `ptr` must be a pointer returned from `create_dust_local_state` or `deserialize_dust_state`
/// - `ptr` must not be used after calling this function
/// - Must be called exactly once per pointer
#[no_mangle]
pub extern "C" fn free_dust_local_state(ptr: *mut DustState) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        // Take ownership back and drop
        let _ = Box::from_raw(ptr);
    }
}

/// Frees a byte array allocated by this module.
///
/// # Safety
///
/// - `ptr` must be a pointer returned from a function that allocates byte arrays
/// - First 8 bytes must contain the length (little-endian u64)
/// - Must be called exactly once per pointer
#[no_mangle]
pub extern "C" fn free_byte_array(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        // Read length from first 8 bytes
        let len_bytes = std::slice::from_raw_parts(ptr, 8);

        // Convert to array - if this fails, the pointer is corrupted
        let len_array: [u8; 8] = match len_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                eprintln!("Error: free_byte_array called with corrupted pointer (cannot read 8-byte length)");
                return; // Graceful failure instead of panic
            }
        };

        let len = u64::from_le_bytes(len_array) as usize;

        // Reconstruct the Vec and drop it
        let _ = Vec::from_raw_parts(ptr, 8 + len, 8 + len);
    }
}

/// Gets the count of dust UTXOs in the wallet.
///
/// # Safety
///
/// - `state_ptr` must be a valid pointer to DustLocalState
///
/// # Returns
///
/// Number of UTXOs, or 0 if state_ptr is null
#[no_mangle]
pub extern "C" fn dust_utxo_count(state_ptr: *const DustState) -> usize {
    if state_ptr.is_null() {
        eprintln!("Error: state_ptr is null");
        return 0;
    }

    unsafe {
        let state = &*state_ptr;
        state.utxos().count()
    }
}

/// Gets a dust UTXO at a specific index as hex-encoded bytes.
///
/// # Safety
///
/// - `state_ptr` must be a valid pointer to DustLocalState
/// - `index` must be less than dust_utxo_count()
/// - Caller must call `free_c_string` to free the returned pointer
///
/// # Returns
///
/// Pointer to C string containing hex-encoded serialized UTXO, or null if index out of bounds
#[no_mangle]
pub extern "C" fn dust_get_utxo_at(
    state_ptr: *const DustState,
    index: usize,
) -> *mut c_char {
    if state_ptr.is_null() {
        eprintln!("Error: state_ptr is null");
        return ptr::null_mut();
    }

    unsafe {
        let state = &*state_ptr;

        // Get UTXO at index
        let utxo = match state.utxos().nth(index) {
            Some(u) => u,
            None => {
                eprintln!("Error: UTXO index {} out of bounds", index);
                return ptr::null_mut();
            }
        };

        // Serialize using Midnight's Serializable trait
        let mut bytes = Vec::new();
        if let Err(e) = utxo.serialize(&mut bytes) {
            eprintln!("Error serializing UTXO: {}", e);
            return ptr::null_mut();
        }

        // Convert to hex string for FFI transport
        let hex = hex::encode(&bytes);

        // Convert to C string
        let hex_cstr = match CString::new(hex) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error creating C string for UTXO hex: {}", e);
                return ptr::null_mut();
            }
        };

        // Transfer ownership to caller
        hex_cstr.into_raw()
    }
}

/// Replays blockchain events into DustLocalState to sync wallet state.
///
/// # Safety
///
/// - `state_ptr` must be a valid pointer to DustLocalState
/// - `seed_ptr` must be a valid pointer to a 32-byte seed
/// - `seed_len` must be exactly 32
/// - `events_hex` must be a valid null-terminated C string containing hex-encoded SCALE serialized events
/// - Caller must call `free_dust_local_state` to free the returned pointer
///
/// # Returns
///
/// Pointer to new DustLocalState with events applied, or null on error
///
/// # Event Format
///
/// Events should be SCALE-encoded as a Vec<Event<InMemoryDB>>, then hex-encoded.
/// This matches how events are transmitted from Midnight blockchain.
#[no_mangle]
pub extern "C" fn dust_replay_events(
    state_ptr: *const DustState,
    seed_ptr: *const u8,
    seed_len: usize,
    events_hex: *const c_char,
) -> *mut DustState {
    // Validate inputs
    if state_ptr.is_null() {
        eprintln!("Error: state_ptr is null");
        return ptr::null_mut();
    }

    if seed_ptr.is_null() {
        eprintln!("Error: seed_ptr is null");
        return ptr::null_mut();
    }

    if seed_len != 32 {
        eprintln!("Error: seed must be 32 bytes, got {}", seed_len);
        return ptr::null_mut();
    }

    if events_hex.is_null() {
        eprintln!("Error: events_hex is null");
        return ptr::null_mut();
    }

    unsafe {
        // Convert seed to array
        let seed_slice = std::slice::from_raw_parts(seed_ptr, seed_len);
        let mut seed_array: Seed = [0u8; 32];
        seed_array.copy_from_slice(seed_slice);

        // Derive secret key
        let sk = DustSecretKey::derive_secret_key(&seed_array);

        // Convert C string to Rust string
        let events_hex_str = match std::ffi::CStr::from_ptr(events_hex).to_str() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error converting events_hex to string: {}", e);
                return ptr::null_mut();
            }
        };

        // Split events by "midnight:event[v9]:" prefix
        // Each event from GraphQL has this prefix + SCALE-encoded Event
        const EVENT_PREFIX: &str = "6d69646e696768743a6576656e745b76395d3a"; // "midnight:event[v9]:"

        let event_hex_strings: Vec<&str> = events_hex_str
            .split(EVENT_PREFIX)
            .filter(|s| !s.is_empty())
            .collect();

        android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Split into {} event hex strings", event_hex_strings.len());

        // Deserialize each event individually
        let mut events: Vec<Event<InMemoryDB>> = Vec::new();
        for (i, event_hex) in event_hex_strings.iter().enumerate() {
            // Decode hex to bytes
            let event_bytes = match hex::decode(event_hex) {
                Ok(b) => b,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Error decoding event {} hex: {}", i, e);
                    return ptr::null_mut();
                }
            };

            // Deserialize single Event
            let event: Event<InMemoryDB> = match <Event<InMemoryDB> as Deserializable>::deserialize(&mut &event_bytes[..], 0) {
                Ok(e) => e,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Error deserializing event {}: {} (bytes_len={})", i, e, event_bytes.len());
                    android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Event {} first 50 bytes: {:02x?}", i, &event_bytes[..std::cmp::min(50, event_bytes.len())]);
                    return ptr::null_mut();
                }
            };

            events.push(event);
        }

        android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Successfully deserialized {} events", events.len());

        // Get current state
        let state = &*state_ptr;

        // Replay events
        let new_state = match state.replay_events(&sk, events.iter()) {
            Ok(s) => s,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Error replaying events: {:?}", e);
                return ptr::null_mut();
            }
        };

        android_log!(ANDROID_LOG_ERROR, "KuiraDustFFI", "Successfully replayed events!");

        // Return new state (boxed)
        Box::into_raw(Box::new(new_state))
    }
}

/// Creates a DustSpend action for fee payment (Phase 2E).
///
/// # Safety
///
/// - `state_ptr` must be a valid DustLocalState pointer
/// - `seed_ptr` must be a valid 32-byte array
/// - `v_fee_str` must be a valid null-terminated UTF-8 string containing a decimal number
/// - Caller must call `free_c_string()` on the returned pointer
///
/// # Parameters
///
/// - `state_ptr`: DustLocalState pointer (from deserialize_dust_state or create_dust_local_state)
/// - `seed_ptr`: 32-byte seed for deriving DustSecretKey
/// - `seed_len`: Must be 32
/// - `utxo_index`: Index of UTXO to spend (from dust_get_utxo_at)
/// - `v_fee_str`: Fee amount in Specks as decimal string (e.g., "1000000000000")
/// - `current_time_ms`: Current time in milliseconds since epoch
///
/// # Returns
///
/// JSON string containing DustSpend object:
/// ```json
/// {
///   "v_fee": "1000000000000",
///   "old_nullifier": "0x...",
///   "new_commitment": "0x...",
///   "proof": "proof-preimage"
/// }
/// ```
///
/// Returns null on error.
///
/// # DustSpend Creation
///
/// ```text
/// 1. Derive DustSecretKey from seed
/// 2. Get UTXO at index from DustLocalState
/// 3. Call state.spend(sk, utxo, v_fee, time)
/// 4. Serialize DustSpend to JSON
/// 5. Update state (caller should save new state)
/// ```
#[no_mangle]
pub extern "C" fn create_dust_spend(
    state_ptr: *const DustState,
    seed_ptr: *const u8,
    seed_len: usize,
    utxo_index: usize,
    v_fee_str: *const c_char,
    current_time_ms: i64,
) -> *mut c_char {
    // Validate inputs
    if state_ptr.is_null() {
        eprintln!("Error: state_ptr is null");
        return ptr::null_mut();
    }

    if seed_ptr.is_null() {
        eprintln!("Error: seed_ptr is null");
        return ptr::null_mut();
    }

    if seed_len != 32 {
        eprintln!("Error: seed must be 32 bytes, got {}", seed_len);
        return ptr::null_mut();
    }

    if v_fee_str.is_null() {
        eprintln!("Error: v_fee_str is null");
        return ptr::null_mut();
    }

    unsafe {
        // Convert seed to array
        let seed_slice = std::slice::from_raw_parts(seed_ptr, seed_len);
        let mut seed_array: Seed = [0u8; 32];
        seed_array.copy_from_slice(seed_slice);

        // Derive DustSecretKey
        let sk = DustSecretKey::derive_secret_key(&seed_array);

        // Parse v_fee from string
        let v_fee_cstr = match std::ffi::CStr::from_ptr(v_fee_str).to_str() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error converting v_fee_str to string: {}", e);
                return ptr::null_mut();
            }
        };

        let v_fee: u128 = match v_fee_cstr.parse() {
            Ok(fee) => fee,
            Err(e) => {
                eprintln!("Error parsing v_fee '{}': {}", v_fee_cstr, e);
                return ptr::null_mut();
            }
        };

        // Convert milliseconds to Timestamp (seconds)
        let timestamp = Timestamp::from_secs((current_time_ms / 1000) as u64);

        // Get state reference
        let state = &*state_ptr;

        // Get UTXO at index
        let utxos: Vec<_> = state.utxos().collect();
        if utxo_index >= utxos.len() {
            eprintln!("Error: utxo_index {} out of bounds (total: {})", utxo_index, utxos.len());
            return ptr::null_mut();
        }

        let utxo = utxos[utxo_index];

        // Create DustSpend
        let (_new_state, dust_spend) = match state.spend(&sk, &utxo, v_fee, timestamp) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Error creating dust spend: {:?}", e);
                return ptr::null_mut();
            }
        };

        // Serialize DustSpend fields to JSON
        // Note: DustNullifier and DustCommitment are newtype wrappers around Fr
        // We need to use Serializable trait to convert Fr to bytes

        // Serialize nullifier
        let mut nullifier_bytes = Vec::new();
        if let Err(e) = dust_spend.old_nullifier.0.serialize(&mut nullifier_bytes) {
            eprintln!("Error serializing nullifier: {}", e);
            return ptr::null_mut();
        }

        // Serialize commitment
        let mut commitment_bytes = Vec::new();
        if let Err(e) = dust_spend.new_commitment.0.serialize(&mut commitment_bytes) {
            eprintln!("Error serializing commitment: {}", e);
            return ptr::null_mut();
        }

        let spend_json = serde_json::json!({
            "v_fee": dust_spend.v_fee.to_string(),
            "old_nullifier": hex::encode(&nullifier_bytes),
            "new_commitment": hex::encode(&commitment_bytes),
            "proof": "proof-preimage" // ProofPreimageMarker for unproven transactions
        });

        let json_string = match serde_json::to_string(&spend_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error serializing dust spend to JSON: {}", e);
                return ptr::null_mut();
            }
        };

        // Convert to C string
        match CString::new(json_string) {
            Ok(c_str) => c_str.into_raw(),
            Err(e) => {
                eprintln!("Error creating C string: {}", e);
                ptr::null_mut()
            }
        }
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

    #[test]
    fn test_create_dust_local_state() {
        // Create state
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null(), "Should create state successfully");

        // Free state
        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_dust_wallet_balance_empty() {
        // Create new state (should have zero balance)
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        // Get balance at current time (use a fixed timestamp for determinism)
        let time_millis = 1000000000i64;  // Some arbitrary time
        let balance_cstr = dust_wallet_balance(state_ptr, time_millis);
        assert!(!balance_cstr.is_null(), "Balance string should not be null");

        unsafe {
            // Convert C string to Rust string
            let balance_str = std::ffi::CStr::from_ptr(balance_cstr)
                .to_str()
                .unwrap();

            // New state should have zero balance
            assert_eq!(balance_str, "0", "New state should have zero balance");

            // Free balance string
            free_c_string(balance_cstr);
        }

        // Free state
        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_serialize_dust_state() {
        // Create state
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        // Serialize
        let bytes_ptr = serialize_dust_state(state_ptr);
        assert!(!bytes_ptr.is_null(), "Serialization should succeed");

        unsafe {
            // Read length
            let len_bytes = std::slice::from_raw_parts(bytes_ptr, 8);
            let len = u64::from_le_bytes(len_bytes.try_into().unwrap());

            // Should have some data
            assert!(len > 0, "Serialized data should have non-zero length");

            println!("Serialized dust state length: {} bytes", len);

            // Free bytes
            free_byte_array(bytes_ptr);
        }

        // Free state
        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_dust_wallet_balance_null_ptr() {
        let balance_ptr = dust_wallet_balance(std::ptr::null(), 0);
        assert!(balance_ptr.is_null(), "Should return null for null pointer");
    }

    #[test]
    fn test_serialize_dust_state_null_ptr() {
        let bytes_ptr = serialize_dust_state(std::ptr::null());
        assert!(bytes_ptr.is_null(), "Should return null for null pointer");
    }

    #[test]
    fn test_deserialize_dust_state_round_trip() {
        // Create state
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        // Serialize
        let bytes_ptr = serialize_dust_state(state_ptr);
        assert!(!bytes_ptr.is_null(), "Serialization should succeed");

        unsafe {
            // Read length and data
            let len_bytes = std::slice::from_raw_parts(bytes_ptr, 8);
            let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

            // Get data pointer (skip first 8 bytes which contain length)
            let data_ptr = bytes_ptr.add(8);

            // Deserialize
            let deserialized_ptr = deserialize_dust_state(data_ptr, len);
            assert!(!deserialized_ptr.is_null(), "Deserialization should succeed");

            // Verify both states have same balance
            let time_millis = 1000000000i64;

            let balance1_cstr = dust_wallet_balance(state_ptr, time_millis);
            let balance2_cstr = dust_wallet_balance(deserialized_ptr, time_millis);

            assert!(!balance1_cstr.is_null());
            assert!(!balance2_cstr.is_null());

            let balance1 = std::ffi::CStr::from_ptr(balance1_cstr).to_str().unwrap();
            let balance2 = std::ffi::CStr::from_ptr(balance2_cstr).to_str().unwrap();

            assert_eq!(balance1, balance2, "Deserialized state should have same balance");

            // Verify both have same UTXO count
            let count1 = dust_utxo_count(state_ptr);
            let count2 = dust_utxo_count(deserialized_ptr);
            assert_eq!(count1, count2, "Deserialized state should have same UTXO count");

            println!("✅ Round-trip serialization successful!");
            println!("   Balance: {} Specks", balance1);
            println!("   UTXO count: {}", count1);

            // Free everything
            free_c_string(balance1_cstr);
            free_c_string(balance2_cstr);
            free_byte_array(bytes_ptr);
            free_dust_local_state(deserialized_ptr);
        }

        // Free original state
        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_deserialize_dust_state_null_ptr() {
        let state_ptr = deserialize_dust_state(std::ptr::null(), 100);
        assert!(state_ptr.is_null(), "Should return null for null pointer");
    }

    #[test]
    fn test_deserialize_dust_state_zero_length() {
        let dummy_data = [0u8; 10];
        let state_ptr = deserialize_dust_state(dummy_data.as_ptr(), 0);
        assert!(state_ptr.is_null(), "Should return null for zero length");
    }

    #[test]
    fn test_deserialize_dust_state_invalid_data() {
        // Invalid SCALE-encoded data
        let invalid_data = [0xFF, 0xFF, 0xFF, 0xFF];
        let state_ptr = deserialize_dust_state(invalid_data.as_ptr(), invalid_data.len());
        assert!(state_ptr.is_null(), "Should return null for invalid data");
    }

    #[test]
    fn test_dust_utxo_count_empty() {
        // Create new state (should have zero UTXOs)
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        // Get UTXO count
        let count = dust_utxo_count(state_ptr);

        // New state should have zero UTXOs
        assert_eq!(count, 0, "New state should have zero UTXOs");

        // Free state
        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_dust_utxo_count_null_ptr() {
        let count = dust_utxo_count(std::ptr::null());
        assert_eq!(count, 0, "Should return 0 for null pointer");
    }

    #[test]
    fn test_dust_get_utxo_at_out_of_bounds() {
        // Create new state (should have zero UTXOs)
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        // Try to get UTXO at index 0 (should fail - no UTXOs)
        let utxo_hex = dust_get_utxo_at(state_ptr, 0);
        assert!(utxo_hex.is_null(), "Should return null for out of bounds index");

        // Free state
        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_dust_get_utxo_at_null_ptr() {
        let utxo_hex = dust_get_utxo_at(std::ptr::null(), 0);
        assert!(utxo_hex.is_null(), "Should return null for null pointer");
    }

    #[test]
    fn test_dust_replay_events_null_state() {
        let seed = [0u8; 32];
        let empty_events = Vec::<Event<InMemoryDB>>::new();
        let mut events_bytes = Vec::new();
        empty_events.serialize(&mut events_bytes).unwrap();
        let events_hex = hex::encode(&events_bytes);
        let events_cstr = CString::new(events_hex).unwrap();

        let new_state = dust_replay_events(
            std::ptr::null(),
            seed.as_ptr(),
            32,
            events_cstr.as_ptr(),
        );
        assert!(new_state.is_null(), "Should return null for null state pointer");
    }

    #[test]
    fn test_dust_replay_events_null_seed() {
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        let empty_events = Vec::<Event<InMemoryDB>>::new();
        let mut events_bytes = Vec::new();
        empty_events.serialize(&mut events_bytes).unwrap();
        let events_hex = hex::encode(&events_bytes);
        let events_cstr = CString::new(events_hex).unwrap();

        let new_state = dust_replay_events(
            state_ptr,
            std::ptr::null(),
            32,
            events_cstr.as_ptr(),
        );
        assert!(new_state.is_null(), "Should return null for null seed pointer");

        free_dust_local_state(state_ptr);
    }

    #[test]
    fn test_dust_replay_events_empty() {
        // Create state and seed
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        let seed = [0u8; 32];

        // Create empty events vector
        let empty_events = Vec::<Event<InMemoryDB>>::new();
        let mut events_bytes = Vec::new();
        empty_events.serialize(&mut events_bytes).unwrap();
        let events_hex = hex::encode(&events_bytes);
        let events_cstr = CString::new(events_hex).unwrap();

        // Replay empty events (should succeed and return new state)
        let new_state_ptr = dust_replay_events(
            state_ptr,
            seed.as_ptr(),
            32,
            events_cstr.as_ptr(),
        );

        assert!(!new_state_ptr.is_null(), "Should return new state for empty events");

        // Verify new state has zero balance (no events = no UTXOs)
        let balance_cstr = dust_wallet_balance(new_state_ptr, 1000000000);
        assert!(!balance_cstr.is_null());

        unsafe {
            let balance_str = std::ffi::CStr::from_ptr(balance_cstr).to_str().unwrap();
            assert_eq!(balance_str, "0", "Empty events should result in zero balance");
            free_c_string(balance_cstr);
        }

        // Free both states
        free_dust_local_state(state_ptr);
        free_dust_local_state(new_state_ptr);
    }

    #[test]
    fn test_dust_accumulation_with_mock_event() {
        use midnight_ledger::events::{EventDetails, EventSource};
        use midnight_ledger::structure::TransactionHash;
        use midnight_base_crypto::hash::BLANK_HASH;
        use midnight_ledger::dust::InitialNonce;
        use midnight_transient_crypto::curve::Fr;

        // Create state and seed
        let state_ptr = create_dust_local_state();
        assert!(!state_ptr.is_null());

        let seed = [0u8; 32];
        let sk = DustSecretKey::derive_secret_key(&seed);
        let pk = DustPublicKey::from(sk.clone());

        // Create mock DustInitialUtxo event
        // Simulates: 1 NIGHT token (1,000,000 Stars) registered for dust generation

        // IMPORTANT: Two different value fields with different units:
        // 1. DustGenerationInfo.value = backing Night UTXO value in STARS
        // 2. QualifiedDustOutput.initial_value = initial dust value in SPECKS

        let night_value_stars: u128 = 1_000_000; // DustGenerationInfo.value (Stars - backing Night)
        let generation_rate_per_star: u128 = 8_267; // Specks per Star per second
        let dust_capacity_per_star: u128 = 5_000_000; // 5 Dust per Star = 5M Specks per Star

        let initial_value: u128 = 0; // QualifiedDustOutput.initial_value (Specks - dust starts at zero)
        let total_rate = night_value_stars * generation_rate_per_star; // 8,267,000,000 Specks/sec
        let _total_capacity = night_value_stars * dust_capacity_per_star; // 5 trillion Specks

        // Use seconds for timestamp (1 second = 1000ms)
        let creation_time = Timestamp::from_secs(1); // Creation at t=1s
        let destruction_time = Timestamp::from_secs(1000); // Destruction far in future (t=1000s)

        // Create mock nonces
        let mock_nonce_fr = Fr::from(0u64);
        let mock_initial_nonce = InitialNonce(BLANK_HASH);

        let mock_utxo = QualifiedDustOutput {
            initial_value,
            owner: pk,
            nonce: mock_nonce_fr,
            seq: 0,
            ctime: creation_time,
            backing_night: mock_initial_nonce,
            mt_index: 0,
        };

        let mock_generation = DustGenerationInfo {
            value: night_value_stars,
            owner: pk,
            nonce: mock_initial_nonce,
            dtime: destruction_time, // Far future so dust can accumulate
        };

        let mock_event: Event<InMemoryDB> = Event {
            source: EventSource {
                transaction_hash: TransactionHash(BLANK_HASH),
                logical_segment: 0,
                physical_segment: 0,
            },
            content: EventDetails::DustInitialUtxo {
                output: mock_utxo,
                generation: mock_generation,
                generation_index: 0,
                block_time: creation_time,
            },
        };

        // Serialize event
        let events = vec![mock_event];
        let mut events_bytes = Vec::new();
        events.serialize(&mut events_bytes).unwrap();
        let events_hex = hex::encode(&events_bytes);
        let events_cstr = CString::new(events_hex).unwrap();

        // Replay event into state
        let new_state_ptr = dust_replay_events(
            state_ptr,
            seed.as_ptr(),
            32,
            events_cstr.as_ptr(),
        );

        assert!(!new_state_ptr.is_null(), "Event replay should succeed");

        // Test 1: Balance at creation time should be zero
        // Note: dust_wallet_balance takes millis, so 1000ms = 1 second
        let balance_at_creation = dust_wallet_balance(new_state_ptr, 1000); // t=1s (1000ms)
        assert!(!balance_at_creation.is_null());

        unsafe {
            let balance_str = std::ffi::CStr::from_ptr(balance_at_creation).to_str().unwrap();
            let balance = balance_str.parse::<u128>().unwrap();
            assert_eq!(balance, 0, "Balance at creation should be zero");
            free_c_string(balance_at_creation);
        }

        // Test 2: Balance after 1 second should be ~8,267,000,000 Specks
        let balance_after_1_sec = dust_wallet_balance(new_state_ptr, 2000); // t=2s (2000ms, 1 second later)
        assert!(!balance_after_1_sec.is_null());

        unsafe {
            let balance_str = std::ffi::CStr::from_ptr(balance_after_1_sec).to_str().unwrap();
            let balance = balance_str.parse::<u128>().unwrap();

            // Expected: 1 second * 8,267,000,000 Specks/sec = 8,267,000,000 Specks
            let expected = total_rate;

            // Allow 1% tolerance for rounding
            let tolerance = expected / 100;
            assert!(
                balance >= expected - tolerance && balance <= expected + tolerance,
                "Balance after 1 second should be ~{}, got {}",
                expected,
                balance
            );

            println!("✅ DUST ACCUMULATION TEST PASSED!");
            println!("   Created UTXO at t=1s");
            println!("   Balance at t=1s: 0 Specks");
            println!("   Balance at t=2s: {} Specks", balance);
            println!("   Expected: {} Specks", expected);
            println!("   Dust is accumulating correctly! 🎉");

            free_c_string(balance_after_1_sec);
        }

        // Test 3: UTXO count should be 1
        let utxo_count = dust_utxo_count(new_state_ptr);
        assert_eq!(utxo_count, 1, "Should have 1 UTXO after replaying event");

        // Free states
        free_dust_local_state(state_ptr);
        free_dust_local_state(new_state_ptr);
    }
}
