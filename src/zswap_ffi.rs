//! Zswap (Shielded) Wallet FFI
//!
//! Provides C FFI interfaces for Midnight shielded wallet operations:
//! - ZswapLocalState lifecycle (create, free)
//! - Event replay (process blockchain events to discover shielded coins)
//! - Balance queries (iterate coins, sum by token type)
//! - State persistence (serialize/deserialize)
//!
//! Mirrors the pattern established by dust_ffi.rs.
//! See docs/planning/SHIELDED_IMPLEMENTATION_PLAN.md for architecture.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use midnight_zswap::keys::{Seed, SecretKeys};
use midnight_zswap::local::State as ZswapState;
use midnight_ledger::events::Event;
use midnight_ledger::semantics::ZswapLocalStateExt; // Provides replay_events()
use midnight_storage::db::InMemoryDB;
use midnight_serialize::{Serializable, Deserializable};

// Android logging macro (same as dust_ffi.rs)
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
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

#[cfg(target_os = "android")]
const ANDROID_LOG_ERROR: std::os::raw::c_int = 6;
#[cfg(target_os = "android")]
const ANDROID_LOG_INFO: std::os::raw::c_int = 4;

#[cfg(not(target_os = "android"))]
macro_rules! android_log {
    ($level:expr, $tag:expr, $($arg:tt)*) => {{
        eprintln!("[{}] {}", $tag, format!($($arg)*));
    }};
}

#[cfg(not(target_os = "android"))]
const ANDROID_LOG_ERROR: std::os::raw::c_int = 6;
#[cfg(not(target_os = "android"))]
const ANDROID_LOG_INFO: std::os::raw::c_int = 4;

const TAG: &str = "KuiraZswapFFI";

// Event prefix: "midnight:event[v9]:" hex-encoded
// Same prefix as dust events — unified Event<D> structure
const EVENT_PREFIX: &str = "6d69646e696768743a6576656e745b76395d3a";

// ── Lifecycle ──

/// Creates a new empty ZswapLocalState.
///
/// Returns a heap-allocated pointer. Caller must free with `free_zswap_local_state`.
#[no_mangle]
pub extern "C" fn create_zswap_local_state() -> *mut ZswapState<InMemoryDB> {
    let state = ZswapState::<InMemoryDB>::new();
    Box::into_raw(Box::new(state))
}

/// Frees a ZswapLocalState.
///
/// # Safety
/// `ptr` must be a valid pointer from `create_zswap_local_state` or `zswap_replay_events`.
#[no_mangle]
pub extern "C" fn free_zswap_local_state(ptr: *mut ZswapState<InMemoryDB>) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

// ── Event Replay ──

/// Replays blockchain events into ZswapLocalState, discovering shielded coins.
///
/// Events are hex-encoded, concatenated with the `midnight:event[v9]:` prefix separator.
/// The Rust code deserializes each event and attempts to decrypt outputs using the
/// wallet's secret keys. Only coins belonging to this wallet are added to the state.
///
/// # Parameters
/// - `state_ptr`: Current state (not consumed — a NEW state is returned)
/// - `seed_ptr`: 32-byte zswap seed (derived at m/44'/2400'/0'/3/0)
/// - `seed_len`: Must be 32
/// - `events_hex`: Concatenated hex-encoded events with prefix separators
///
/// # Returns
/// New state pointer on success, null on failure. Caller must free with `free_zswap_local_state`.
///
/// # Safety
/// All pointers must be valid. `seed_ptr` must point to `seed_len` bytes.
#[no_mangle]
pub extern "C" fn zswap_replay_events(
    state_ptr: *const ZswapState<InMemoryDB>,
    seed_ptr: *const u8,
    seed_len: usize,
    events_hex: *const c_char,
) -> *mut ZswapState<InMemoryDB> {
    if state_ptr.is_null() || seed_ptr.is_null() || events_hex.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_replay_events");
        return ptr::null_mut();
    }

    if seed_len != 32 {
        android_log!(ANDROID_LOG_ERROR, TAG, "Seed must be 32 bytes, got {}", seed_len);
        return ptr::null_mut();
    }

    unsafe {
        // Derive SecretKeys from seed (SecretKeys has ZeroizeOnDrop)
        let seed_slice = std::slice::from_raw_parts(seed_ptr, seed_len);
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed_slice);
        let secret_keys = SecretKeys::from(Seed::from(seed_array));
        // Wipe local copy of seed material
        seed_array.fill(0);

        // Convert C string to Rust string
        let events_hex_str = match std::ffi::CStr::from_ptr(events_hex).to_str() {
            Ok(s) => s,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid UTF-8 in events_hex: {}", e);
                return ptr::null_mut();
            }
        };

        // Handle empty events
        if events_hex_str.is_empty() {
            android_log!(ANDROID_LOG_INFO, TAG, "Empty events — returning clone of current state");
            let state = &*state_ptr;
            return Box::into_raw(Box::new(state.clone()));
        }

        // Deserialize events (same prefix-splitting as dust_ffi.rs)
        let event_hex_strings: Vec<&str> = events_hex_str
            .split(EVENT_PREFIX)
            .filter(|s| !s.is_empty())
            .collect();

        android_log!(ANDROID_LOG_INFO, TAG, "Split into {} event hex strings", event_hex_strings.len());

        let mut events: Vec<Event<InMemoryDB>> = Vec::new();
        for (i, event_hex) in event_hex_strings.iter().enumerate() {
            let event_bytes = match hex::decode(event_hex) {
                Ok(b) => b,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Error decoding event {} hex: {}", i, e);
                    return ptr::null_mut();
                }
            };

            let event: Event<InMemoryDB> = match <Event<InMemoryDB> as Deserializable>::deserialize(
                &mut &event_bytes[..],
                0,
            ) {
                Ok(e) => e,
                Err(e) => {
                    android_log!(
                        ANDROID_LOG_ERROR, TAG,
                        "Error deserializing event {}: {} (bytes_len={})", i, e, event_bytes.len()
                    );
                    return ptr::null_mut();
                }
            };

            events.push(event);
        }

        android_log!(ANDROID_LOG_INFO, TAG, "Successfully deserialized {} events", events.len());

        // Replay events into state
        let state = &*state_ptr;
        let new_state = match state.replay_events(&secret_keys, events.iter()) {
            Ok(s) => s,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error replaying events: {:?}", e);
                return ptr::null_mut();
            }
        };

        let coin_count = new_state.coins.iter().count();
        android_log!(ANDROID_LOG_INFO, TAG, "Replay complete: {} coins in state", coin_count);

        Box::into_raw(Box::new(new_state))
    }
}

// ── Balance Queries ──

/// Returns shielded balances as JSON: {"token_type_hex": "balance_string", ...}
///
/// Iterates all coins in the state and sums values by token type.
/// Token type is the hex-encoded ShieldedTokenType. For NIGHT, this is all zeros.
///
/// # Returns
/// JSON string on success, null on failure. Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_get_balances(
    state_ptr: *const ZswapState<InMemoryDB>,
) -> *const c_char {
    if state_ptr.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null state_ptr in zswap_get_balances");
        return ptr::null();
    }

    unsafe {
        let state = &*state_ptr;

        // Sum balances by token type
        let mut balances: std::collections::HashMap<String, u128> = std::collections::HashMap::new();
        for (_, coin) in state.coins.iter() {
            // Serialize token type to hex for JSON key
            let mut type_bytes = Vec::new();
            if let Err(e) = coin.type_.serialize(&mut type_bytes) {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing token type: {}", e);
                continue;
            }
            let type_hex = hex::encode(&type_bytes);

            let current = balances.get(&type_hex).copied().unwrap_or(0);
            balances.insert(type_hex, current.saturating_add(coin.value));
        }

        // Build JSON
        let mut json = String::from("{");
        let mut first = true;
        for (type_hex, value) in &balances {
            if !first {
                json.push(',');
            }
            json.push_str(&format!("\"{}\":\"{}\"", type_hex, value));
            first = false;
        }
        json.push('}');

        android_log!(ANDROID_LOG_INFO, TAG, "Balances: {}", json);

        match CString::new(json) {
            Ok(c) => c.into_raw(),
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error creating CString: {}", e);
                ptr::null()
            }
        }
    }
}

/// Returns the number of coins in the state.
#[no_mangle]
pub extern "C" fn zswap_get_coin_count(
    state_ptr: *const ZswapState<InMemoryDB>,
) -> i32 {
    if state_ptr.is_null() {
        return 0;
    }

    unsafe {
        let state = &*state_ptr;
        state.coins.iter().count() as i32
    }
}

/// Returns the firstFree merkle tree index (for tracking sync position).
#[no_mangle]
pub extern "C" fn zswap_get_first_free(
    state_ptr: *const ZswapState<InMemoryDB>,
) -> u64 {
    if state_ptr.is_null() {
        return 0;
    }

    unsafe {
        let state = &*state_ptr;
        state.first_free
    }
}

// ── Persistence ──

/// Serializes ZswapLocalState to hex-encoded bytes.
///
/// # Returns
/// Hex string on success, null on failure. Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_serialize(
    state_ptr: *const ZswapState<InMemoryDB>,
) -> *const c_char {
    if state_ptr.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null state_ptr in zswap_serialize");
        return ptr::null();
    }

    unsafe {
        let state = &*state_ptr;
        let mut bytes = Vec::new();
        if let Err(e) = state.serialize(&mut bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing zswap state: {}", e);
            return ptr::null();
        }

        let hex_str = hex::encode(&bytes);
        android_log!(ANDROID_LOG_INFO, TAG, "Serialized zswap state: {} bytes", bytes.len());

        match CString::new(hex_str) {
            Ok(c) => c.into_raw(),
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error creating CString: {}", e);
                ptr::null()
            }
        }
    }
}

/// Deserializes ZswapLocalState from hex-encoded bytes.
///
/// # Returns
/// New state pointer on success, null on failure. Caller must free with `free_zswap_local_state`.
#[no_mangle]
pub extern "C" fn zswap_deserialize(
    hex_ptr: *const c_char,
) -> *mut ZswapState<InMemoryDB> {
    if hex_ptr.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null hex_ptr in zswap_deserialize");
        return ptr::null_mut();
    }

    unsafe {
        let hex_str = match std::ffi::CStr::from_ptr(hex_ptr).to_str() {
            Ok(s) => s,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid UTF-8: {}", e);
                return ptr::null_mut();
            }
        };

        let bytes = match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid hex: {}", e);
                return ptr::null_mut();
            }
        };

        let state: ZswapState<InMemoryDB> =
            match <ZswapState<InMemoryDB> as Deserializable>::deserialize(&mut &bytes[..], 0) {
                Ok(s) => s,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing zswap state: {}", e);
                    return ptr::null_mut();
                }
            };

        android_log!(
            ANDROID_LOG_INFO, TAG,
            "Deserialized zswap state: {} coins, firstFree={}",
            state.coins.iter().count(),
            state.first_free
        );

        Box::into_raw(Box::new(state))
    }
}

// ── Memory ──

/// Frees a string returned by zswap FFI functions.
#[no_mangle]
pub extern "C" fn free_zswap_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_free() {
        let state = create_zswap_local_state();
        assert!(!state.is_null());

        let count = zswap_get_coin_count(state);
        assert_eq!(count, 0);

        let first_free = zswap_get_first_free(state);
        assert_eq!(first_free, 0);

        free_zswap_local_state(state);
    }

    #[test]
    fn test_empty_balances() {
        let state = create_zswap_local_state();
        assert!(!state.is_null());

        let json_ptr = zswap_get_balances(state);
        assert!(!json_ptr.is_null());

        let json = unsafe { std::ffi::CStr::from_ptr(json_ptr).to_str().unwrap() };
        assert_eq!(json, "{}");

        free_zswap_string(json_ptr as *mut c_char);
        free_zswap_local_state(state);
    }

    #[test]
    fn test_replay_empty_events() {
        let state = create_zswap_local_state();
        assert!(!state.is_null());

        let seed = [0u8; 32];
        let events = CString::new("").unwrap();

        let new_state = zswap_replay_events(
            state,
            seed.as_ptr(),
            32,
            events.as_ptr(),
        );

        assert!(!new_state.is_null(), "Empty events should return new state");
        assert_eq!(zswap_get_coin_count(new_state), 0);

        free_zswap_local_state(new_state);
        free_zswap_local_state(state);
    }

    #[test]
    fn test_serialize_deserialize_empty() {
        let state = create_zswap_local_state();
        assert!(!state.is_null());

        // Serialize
        let hex_ptr = zswap_serialize(state);
        assert!(!hex_ptr.is_null());

        let hex = unsafe { std::ffi::CStr::from_ptr(hex_ptr).to_str().unwrap() };
        assert!(!hex.is_empty(), "Serialized state should not be empty");

        // Deserialize
        let hex_cstr = CString::new(hex).unwrap();
        let restored = zswap_deserialize(hex_cstr.as_ptr());
        assert!(!restored.is_null(), "Should deserialize successfully");

        // Verify
        assert_eq!(zswap_get_coin_count(restored), 0);
        assert_eq!(zswap_get_first_free(restored), 0);

        free_zswap_string(hex_ptr as *mut c_char);
        free_zswap_local_state(restored);
        free_zswap_local_state(state);
    }

    #[test]
    fn test_replay_events_does_not_modify_seed() {
        // Regression test: JNI was zeroing the seed array after replay.
        // The Rust FFI must NOT modify the input seed.
        let state = create_zswap_local_state();
        assert!(!state.is_null());

        let mut seed = [42u8; 32]; // Non-zero seed
        let seed_copy = seed;
        let events = CString::new("").unwrap();

        let new_state = zswap_replay_events(
            state,
            seed.as_ptr(),
            32,
            events.as_ptr(),
        );

        assert!(!new_state.is_null());
        // Seed must NOT be modified by replay_events
        assert_eq!(seed, seed_copy, "replay_events must not modify the seed array");

        free_zswap_local_state(new_state);
        free_zswap_local_state(state);
    }

    #[test]
    fn test_null_safety() {
        // All functions should handle null gracefully
        assert!(zswap_replay_events(ptr::null(), ptr::null(), 0, ptr::null()).is_null());
        assert!(zswap_get_balances(ptr::null()).is_null());
        assert_eq!(zswap_get_coin_count(ptr::null()), 0);
        assert_eq!(zswap_get_first_free(ptr::null()), 0);
        assert!(zswap_serialize(ptr::null()).is_null());
        assert!(zswap_deserialize(ptr::null()).is_null());

        // Free null should not crash
        free_zswap_local_state(ptr::null_mut());
        free_zswap_string(ptr::null_mut());
    }
}
