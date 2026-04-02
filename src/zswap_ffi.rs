//! Zswap (Shielded) Wallet FFI
//!
//! Provides C FFI interfaces for Midnight shielded wallet operations:
//! - ZswapLocalState lifecycle (create, free)
//! - Event replay (process blockchain events to discover shielded coins)
//! - Balance queries (iterate coins, sum by token type)
//! - State persistence (serialize/deserialize)
//! - Composable transfer primitives (select, spend, output, offer, merge)
//!
//! Architecture: composable primitives per ADR-001.
//! See docs/decisions/ADR-001-COMPOSABLE-ZSWAP-FFI.md for rationale.
//! See docs/planning/SHIELDED_IMPLEMENTATION_PLAN.md for implementation plan.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use midnight_zswap::keys::{Seed, SecretKeys};
use midnight_zswap::local::State as ZswapState;
use midnight_zswap::{Output, Offer};
use midnight_ledger::events::Event;
use midnight_ledger::semantics::ZswapLocalStateExt; // Provides replay_events()
use midnight_storage::db::InMemoryDB;
use midnight_serialize::{Serializable, Deserializable};
use midnight_coin_structure::coin::{
    Info as CoinInfo, QualifiedInfo as QualifiedCoinInfo, ShieldedTokenType,
    PublicKey as CoinPublicKey, Nonce,
};
use midnight_transient_crypto::encryption;
use midnight_transient_crypto::proofs::ProofPreimage;
use midnight_transient_crypto::commitment::PedersenRandomness;
use midnight_transient_crypto::proofs::ProvingKeyMaterial;
use midnight_ledger::structure::{Intent, Transaction, StandardTransaction, ProofPreimageMarker};
use midnight_base_crypto::signatures::Signature;
use midnight_base_crypto::time::Timestamp;
use midnight_storage::storage::HashMap as StorageHashMap;
use rand::Rng;
use rand::rngs::OsRng;
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

// ── FFI Helpers (reduce duplication across primitives) ──

/// Converts a C string pointer to a Rust &str, logging errors.
///
/// # Safety
/// `ptr` must be a valid, null-terminated C string pointer.
pub(crate) unsafe fn c_str_to_rust<'a>(ptr: *const c_char, name: &str) -> Option<&'a str> {
    match std::ffi::CStr::from_ptr(ptr).to_str() {
        Ok(s) => Some(s),
        Err(e) => {
            android_log!(ANDROID_LOG_ERROR, TAG, "Invalid UTF-8 in {}: {}", name, e);
            None
        }
    }
}

/// Decodes a hex C string into bytes, logging errors.
///
/// # Safety
/// `ptr` must be a valid, null-terminated C string pointer containing hex.
pub(crate) unsafe fn c_hex_to_bytes(ptr: *const c_char, name: &str) -> Option<Vec<u8>> {
    let hex_str = c_str_to_rust(ptr, name)?;
    match hex::decode(hex_str) {
        Ok(b) => Some(b),
        Err(e) => {
            android_log!(ANDROID_LOG_ERROR, TAG, "Invalid hex in {}: {}", name, e);
            None
        }
    }
}

/// Decodes a hex C string and deserializes into a typed value.
///
/// # Safety
/// `ptr` must be a valid, null-terminated C string pointer containing hex-encoded SCALE data.
unsafe fn c_hex_deserialize<T: Deserializable>(ptr: *const c_char, name: &str) -> Option<T> {
    let bytes = c_hex_to_bytes(ptr, name)?;
    match Deserializable::deserialize(&mut &bytes[..], 0) {
        Ok(v) => Some(v),
        Err(e) => {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing {}: {}", name, e);
            None
        }
    }
}

/// Converts a String to a C string pointer for FFI return, logging errors.
/// Caller must free with `free_zswap_string`.
pub(crate) fn string_to_c_ptr(s: String) -> *const c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(e) => {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error creating CString: {}", e);
            ptr::null()
        }
    }
}

// ── Transfer Primitives (Step 7, ADR-001) ──

/// 7a: Selects coins from state to cover the requested amount.
///
/// Returns JSON array of coin objects sorted by value (ascending).
/// Selection strategy: greedy — accumulate coins until sum >= amount.
///
/// # Parameters
/// - `state_ptr`: Current ZswapLocalState
/// - `token_type_hex`: Hex-encoded ShieldedTokenType to match
/// - `amount_str`: Requested amount as decimal string (u128)
///
/// # Returns
/// JSON string: `[{"type_hex":"...","value":"...","nonce_hex":"...","mt_index":N}, ...]`
/// Returns null if insufficient balance or on error.
/// Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_select_coins(
    state_ptr: *const ZswapState<InMemoryDB>,
    token_type_hex: *const c_char,
    amount_str: *const c_char,
) -> *const c_char {
    if state_ptr.is_null() || token_type_hex.is_null() || amount_str.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_select_coins");
        return ptr::null();
    }

    // SAFETY: All pointers validated non-null above. state_ptr is a valid ZswapState
    // from create/replay/deserialize. token_type_hex and amount_str are JNI-provided C strings.
    unsafe {
        let state = &*state_ptr;

        let token_type: ShieldedTokenType = match c_hex_deserialize(token_type_hex, "token_type") {
            Some(t) => t,
            None => return ptr::null(),
        };

        let amount_s = match c_str_to_rust(amount_str, "amount") {
            Some(s) => s,
            None => return ptr::null(),
        };
        let amount: u128 = match amount_s.parse() {
            Ok(a) => a,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid amount '{}': {}", amount_s, e);
                return ptr::null();
            }
        };

        // Collect coins in pending_spends so we can exclude them
        let pending_nullifiers: std::collections::HashSet<Vec<u8>> = state.pending_spends.iter()
            .filter_map(|(nul, _)| {
                let mut bytes = Vec::new();
                nul.serialize(&mut bytes).ok()?;
                Some(bytes)
            })
            .collect();

        // Collect matching coins, excluding those already pending spend
        let mut matching_coins: Vec<(Vec<u8>, QualifiedCoinInfo)> = Vec::new();
        for (nullifier, coin) in state.coins.iter() {
            if coin.type_ == token_type {
                let mut nul_bytes = Vec::new();
                if let Err(e) = nullifier.serialize(&mut nul_bytes) {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing nullifier: {}", e);
                    continue;
                }
                // Skip coins that are already pending spend (prevents double-spend)
                if pending_nullifiers.contains(&nul_bytes) {
                    android_log!(ANDROID_LOG_INFO, TAG, "Skipping coin at mt_index={} (pending spend)", coin.mt_index);
                    continue;
                }
                matching_coins.push((nul_bytes, *coin));
            }
        }
        matching_coins.sort_by_key(|(_, c)| c.value);

        // Greedy selection: accumulate until we have enough
        let mut selected = Vec::new();
        let mut total: u128 = 0;
        for (nul_bytes, coin) in &matching_coins {
            selected.push((nul_bytes, coin));
            total = total.saturating_add(coin.value);
            if total >= amount {
                break;
            }
        }

        if total < amount {
            android_log!(
                ANDROID_LOG_ERROR, TAG,
                "Insufficient shielded balance: have {} but need {}", total, amount
            );
            return ptr::null();
        }

        // Build JSON array
        let mut json = String::from("[");
        for (i, (nul_bytes, coin)) in selected.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            let mut type_bytes = Vec::new();
            if let Err(e) = coin.type_.serialize(&mut type_bytes) {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing coin type: {}", e);
                return ptr::null();
            }
            let mut nonce_bytes = Vec::new();
            if let Err(e) = coin.nonce.serialize(&mut nonce_bytes) {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing nonce: {}", e);
                return ptr::null();
            }
            json.push_str(&format!(
                "{{\"type_hex\":\"{}\",\"value\":\"{}\",\"nonce_hex\":\"{}\",\"mt_index\":{},\"nullifier_hex\":\"{}\"}}",
                hex::encode(&type_bytes),
                coin.value,
                hex::encode(&nonce_bytes),
                coin.mt_index,
                hex::encode(nul_bytes),
            ));
        }
        json.push(']');

        android_log!(
            ANDROID_LOG_INFO, TAG,
            "Selected {} coins totaling {} (requested {})", selected.len(), total, amount
        );

        string_to_c_ptr(json)
    }
}

/// Result of spending a coin. Caller must:
/// - Free `new_state` with `free_zswap_local_state` when done
/// - Free `result_json` with `free_zswap_string` when done
#[repr(C)]
pub struct ZswapSpendResult {
    /// New state with coin moved to pending_spends. Null on error.
    pub new_state: *mut ZswapState<InMemoryDB>,
    /// JSON: `{"input_hex":"...", "binding_randomness_hex":"..."}`. Null on error.
    pub result_json: *mut c_char,
}

/// 7b: Creates a spending Input<ProofPreimage> from a coin in the state.
///
/// Returns a `ZswapSpendResult` containing:
/// - `new_state`: NEW state pointer (coin moved to pending_spends). Original state unchanged.
/// - `result_json`: JSON with serialized input and binding randomness.
///
/// Both fields are null on error. Caller must free both (see `ZswapSpendResult` docs).
///
/// # Parameters
/// - `state_ptr`: Current ZswapLocalState (not consumed)
/// - `seed_ptr`: 32-byte zswap seed (m/44'/2400'/0'/3/0)
/// - `seed_len`: Must be 32
/// - `coin_json`: JSON object from `zswap_select_coins` output
///
/// # Safety
/// All pointers must be valid. `seed_ptr` must point to `seed_len` bytes.
#[no_mangle]
pub extern "C" fn zswap_spend_coin(
    state_ptr: *const ZswapState<InMemoryDB>,
    seed_ptr: *const u8,
    seed_len: usize,
    coin_json: *const c_char,
) -> ZswapSpendResult {
    let null_result = ZswapSpendResult { new_state: ptr::null_mut(), result_json: ptr::null_mut() };

    if state_ptr.is_null() || seed_ptr.is_null() || coin_json.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_spend_coin");
        return null_result;
    }

    if seed_len != 32 {
        android_log!(ANDROID_LOG_ERROR, TAG, "Seed must be 32 bytes, got {}", seed_len);
        return null_result;
    }

    // SAFETY: All pointers validated non-null above. seed_ptr points to seed_len (32) bytes.
    // state_ptr is a valid ZswapState. coin_json is a JNI-provided C string.
    unsafe {
        let state = &*state_ptr;

        // Derive SecretKeys from seed (auto-zeroizes on drop via ZeroizeOnDrop)
        let seed_slice = std::slice::from_raw_parts(seed_ptr, seed_len);
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed_slice);
        let secret_keys = SecretKeys::from(Seed::from(seed_array));
        seed_array.fill(0);

        // Parse coin JSON
        let coin_str = match c_str_to_rust(coin_json, "coin_json") {
            Some(s) => s,
            None => return null_result,
        };

        let coin = match parse_qualified_coin_info(coin_str) {
            Ok(c) => c,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error parsing coin JSON: {}", e);
                return null_result;
            }
        };

        // Verify coin exists in state before attempting spend
        let coin_exists = state.coins.iter().any(|(_, c)|
            c.mt_index == coin.mt_index && c.value == coin.value && c.type_ == coin.type_
        );
        if !coin_exists {
            android_log!(
                ANDROID_LOG_ERROR, TAG,
                "Coin not found in state (mt_index={}, value={})", coin.mt_index, coin.value
            );
            return null_result;
        }

        // Spend the coin (creates Input<ProofPreimage>)
        let (new_state, input) = match state.spend(&mut OsRng, &secret_keys, &coin, None) {
            Ok(result) => result,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error spending coin: {:?}", e);
                return null_result;
            }
        };

        // Serialize input
        let mut input_bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&input, &mut input_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing input: {}", e);
            return null_result;
        }

        // Extract binding randomness
        let binding_randomness = input.binding_randomness();
        let mut br_bytes = Vec::new();
        if let Err(e) = binding_randomness.serialize(&mut br_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing binding randomness: {}", e);
            return null_result;
        }

        let json = format!(
            "{{\"input_hex\":\"{}\",\"binding_randomness_hex\":\"{}\"}}",
            hex::encode(&input_bytes),
            hex::encode(&br_bytes),
        );

        android_log!(ANDROID_LOG_INFO, TAG, "Spent coin: input_size={}", input_bytes.len());

        let result_json = string_to_c_ptr(json) as *mut c_char;
        if result_json.is_null() {
            return null_result;
        }

        ZswapSpendResult {
            new_state: Box::into_raw(Box::new(new_state)),
            result_json,
        }
    }
}

/// 7c: Creates an Output<ProofPreimage> — an encrypted coin for the recipient.
///
/// The output contains a CoinCiphertext encrypted with the recipient's encryption
/// public key. Only the recipient can decrypt it to discover the coin.
///
/// # Parameters
/// - `recipient_coin_pk_hex`: Recipient's coin public key (64-char hex, 32 bytes)
/// - `recipient_enc_pk_hex`: Recipient's encryption public key (64-char hex, 32 bytes)
/// - `token_type_hex`: Hex-encoded ShieldedTokenType
/// - `amount_str`: Coin value as decimal string (u128)
///
/// # Returns
/// JSON: `{"output_hex":"...", "binding_randomness_hex":"..."}`
/// Returns null on error. Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_create_output(
    recipient_coin_pk_hex: *const c_char,
    recipient_enc_pk_hex: *const c_char,
    token_type_hex: *const c_char,
    amount_str: *const c_char,
) -> *const c_char {
    if recipient_coin_pk_hex.is_null() || recipient_enc_pk_hex.is_null()
        || token_type_hex.is_null() || amount_str.is_null()
    {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_create_output");
        return ptr::null();
    }

    // SAFETY: All pointers validated non-null above. All are JNI-provided C strings.
    unsafe {
        let coin_pk: CoinPublicKey = match c_hex_deserialize(recipient_coin_pk_hex, "coin_pk") {
            Some(pk) => pk,
            None => return ptr::null(),
        };
        let enc_pk: encryption::PublicKey = match c_hex_deserialize(recipient_enc_pk_hex, "enc_pk") {
            Some(pk) => pk,
            None => return ptr::null(),
        };
        let token_type: ShieldedTokenType = match c_hex_deserialize(token_type_hex, "token_type") {
            Some(t) => t,
            None => return ptr::null(),
        };
        let amount_s = match c_str_to_rust(amount_str, "amount") {
            Some(s) => s,
            None => return ptr::null(),
        };
        let amount: u128 = match amount_s.parse() {
            Ok(a) => a,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid amount '{}': {}", amount_s, e);
                return ptr::null();
            }
        };

        // Create coin info with random nonce
        let coin_info = CoinInfo {
            type_: token_type,
            value: amount,
            nonce: OsRng.r#gen(),
        };

        // Create output (encrypted coin for recipient)
        let output: Output<ProofPreimage, InMemoryDB> = match Output::new(
            &mut OsRng,
            &coin_info,
            None, // segment
            &coin_pk,
            Some(enc_pk),
        ) {
            Ok(o) => o,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error creating output: {:?}", e);
                return ptr::null();
            }
        };

        // Serialize output
        let mut output_bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&output, &mut output_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing output: {}", e);
            return ptr::null();
        }

        // Extract binding randomness
        let binding_randomness = output.binding_randomness();
        let mut br_bytes = Vec::new();
        if let Err(e) = binding_randomness.serialize(&mut br_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing binding randomness: {}", e);
            return ptr::null();
        }

        let json = format!(
            "{{\"output_hex\":\"{}\",\"binding_randomness_hex\":\"{}\"}}",
            hex::encode(&output_bytes),
            hex::encode(&br_bytes),
        );

        android_log!(ANDROID_LOG_INFO, TAG, "Created output: {} bytes, amount={}", output_bytes.len(), amount);

        string_to_c_ptr(json)
    }
}

/// 7d: Builds an Offer<ProofPreimage> from serialized inputs and outputs.
///
/// Auto-calculates deltas (token balance sheet).
///
/// # Parameters
/// - `inputs_hex_json`: JSON array of tagged-serialized Input hex strings: `["hex1", "hex2"]`
/// - `outputs_hex_json`: JSON array of tagged-serialized Output hex strings: `["hex1", "hex2"]`
///
/// # Returns
/// JSON: `{"offer_hex":"...", "binding_randomness_hex":"..."}`
/// Returns null if both arrays are empty, or on error.
/// Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_build_offer(
    inputs_hex_json: *const c_char,
    outputs_hex_json: *const c_char,
) -> *const c_char {
    if inputs_hex_json.is_null() || outputs_hex_json.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_build_offer");
        return ptr::null();
    }

    // SAFETY: All pointers validated non-null above. Both are JNI-provided C strings.
    unsafe {
        let inputs_str = match c_str_to_rust(inputs_hex_json, "inputs_json") {
            Some(s) => s,
            None => return ptr::null(),
        };
        let inputs_arr: Vec<String> = match serde_json::from_str(inputs_str) {
            Ok(v) => v,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid JSON array for inputs: {}", e);
                return ptr::null();
            }
        };

        let outputs_str = match c_str_to_rust(outputs_hex_json, "outputs_json") {
            Some(s) => s,
            None => return ptr::null(),
        };
        let outputs_arr: Vec<String> = match serde_json::from_str(outputs_str) {
            Ok(v) => v,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Invalid JSON array for outputs: {}", e);
                return ptr::null();
            }
        };

        if inputs_arr.is_empty() && outputs_arr.is_empty() {
            android_log!(ANDROID_LOG_ERROR, TAG, "Both inputs and outputs are empty — cannot build offer");
            return ptr::null();
        }

        // Deserialize inputs
        let mut inputs: Vec<midnight_zswap::Input<ProofPreimage, InMemoryDB>> = Vec::new();
        for (i, hex_str) in inputs_arr.iter().enumerate() {
            let bytes = match hex::decode(hex_str) {
                Ok(b) => b,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Invalid hex for input {}: {}", i, e);
                    return ptr::null();
                }
            };
            let input = match midnight_serialize::tagged_deserialize(&mut &bytes[..]) {
                Ok(inp) => inp,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing input {}: {}", i, e);
                    return ptr::null();
                }
            };
            inputs.push(input);
        }

        // Deserialize outputs
        let mut outputs: Vec<Output<ProofPreimage, InMemoryDB>> = Vec::new();
        for (i, hex_str) in outputs_arr.iter().enumerate() {
            let bytes = match hex::decode(hex_str) {
                Ok(b) => b,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Invalid hex for output {}: {}", i, e);
                    return ptr::null();
                }
            };
            let output = match midnight_serialize::tagged_deserialize(&mut &bytes[..]) {
                Ok(out) => out,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing output {}: {}", i, e);
                    return ptr::null();
                }
            };
            outputs.push(output);
        }

        // Build offer (auto-calculates deltas)
        let offer = match Offer::new(inputs, outputs, vec![]) {
            Some(o) => o,
            None => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Offer::new returned None (empty inputs/outputs)");
                return ptr::null();
            }
        };

        // Serialize offer
        let mut offer_bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&offer, &mut offer_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing offer: {}", e);
            return ptr::null();
        }

        // Extract binding randomness
        let binding_randomness = offer.binding_randomness();
        let mut br_bytes = Vec::new();
        if let Err(e) = binding_randomness.serialize(&mut br_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing binding randomness: {}", e);
            return ptr::null();
        }

        let json = format!(
            "{{\"offer_hex\":\"{}\",\"binding_randomness_hex\":\"{}\"}}",
            hex::encode(&offer_bytes),
            hex::encode(&br_bytes),
        );

        android_log!(
            ANDROID_LOG_INFO, TAG,
            "Built offer: {} inputs, {} outputs, {} bytes",
            offer.inputs.iter().count(),
            offer.outputs.iter().count(),
            offer_bytes.len()
        );

        string_to_c_ptr(json)
    }
}

/// 7e: Merges two Offer<ProofPreimage> into one.
///
/// The two offers must have disjoint coins (no overlapping nullifiers or commitments).
/// Used for: combining a transfer offer with contract balancing, or combining
/// multiple independent shielded operations into a single transaction.
///
/// # Parameters
/// - `offer1_hex`: Tagged-serialized Offer hex string
/// - `offer2_hex`: Tagged-serialized Offer hex string
///
/// # Returns
/// Merged offer hex string (tagged-serialized).
/// Returns null on error (e.g., overlapping coins).
/// Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_merge_offers(
    offer1_hex: *const c_char,
    offer2_hex: *const c_char,
) -> *const c_char {
    if offer1_hex.is_null() || offer2_hex.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_merge_offers");
        return ptr::null();
    }

    // SAFETY: All pointers validated non-null above. Both are JNI-provided C strings.
    unsafe {
        let bytes1 = match c_hex_to_bytes(offer1_hex, "offer1") {
            Some(b) => b,
            None => return ptr::null(),
        };
        let offer1: Offer<ProofPreimage, InMemoryDB> = match midnight_serialize::tagged_deserialize(&mut &bytes1[..]) {
            Ok(o) => o,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing offer1: {}", e);
                return ptr::null();
            }
        };

        let bytes2 = match c_hex_to_bytes(offer2_hex, "offer2") {
            Some(b) => b,
            None => return ptr::null(),
        };
        let offer2: Offer<ProofPreimage, InMemoryDB> = match midnight_serialize::tagged_deserialize(&mut &bytes2[..]) {
            Ok(o) => o,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing offer2: {}", e);
                return ptr::null();
            }
        };

        // Merge
        let merged = match offer1.merge(&offer2) {
            Ok(m) => m,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error merging offers: {:?}", e);
                return ptr::null();
            }
        };

        // Serialize merged offer
        let mut merged_bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&merged, &mut merged_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing merged offer: {}", e);
            return ptr::null();
        }

        android_log!(
            ANDROID_LOG_INFO, TAG,
            "Merged offers: {} inputs, {} outputs, {} bytes",
            merged.inputs.iter().count(),
            merged.outputs.iter().count(),
            merged_bytes.len()
        );

        string_to_c_ptr(hex::encode(&merged_bytes))
    }
}

/// 7f: Validates and re-serializes an Offer to tagged SCALE format.
///
/// This function round-trips the offer through deserialize/serialize to verify
/// structural integrity. Use after `zswap_merge_offers` or manual offer construction
/// to catch corruption before sending to the proof server.
///
/// Note: `zswap_build_shielded_transaction` (7g) handles the final proof-server
/// format `(Transaction, HashMap)`. This function validates the offer alone.
///
/// # Parameters
/// - `offer_hex`: Tagged-serialized Offer hex string (from build_offer or merge_offers)
///
/// # Returns
/// Validated SCALE hex string, or null if the offer is malformed.
/// Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_serialize_offer(
    offer_hex: *const c_char,
) -> *const c_char {
    if offer_hex.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null pointer in zswap_serialize_offer");
        return ptr::null();
    }

    // SAFETY: Pointer validated non-null above. JNI-provided C string.
    unsafe {
        let bytes = match c_hex_to_bytes(offer_hex, "offer") {
            Some(b) => b,
            None => return ptr::null(),
        };

        let offer: Offer<ProofPreimage, InMemoryDB> = match midnight_serialize::tagged_deserialize(&mut &bytes[..]) {
            Ok(o) => o,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing offer: {}", e);
                return ptr::null();
            }
        };

        let mut scale_bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&offer, &mut scale_bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing offer to SCALE: {}", e);
            return ptr::null();
        }

        android_log!(ANDROID_LOG_INFO, TAG, "Validated offer: {} bytes", scale_bytes.len());
        string_to_c_ptr(hex::encode(&scale_bytes))
    }
}

/// 7g: Builds a full unproven Transaction from a ZswapOffer, ready for the proof server.
///
/// Assembles a `Transaction::Standard` with:
/// - `guaranteed_coins` = the zswap offer
/// - `intents` = an empty intent with TTL (+ dust intent merged if dust_tx_hex provided)
/// - `binding_randomness` = auto-computed by `StandardTransaction::new()`
///
/// The returned hex is serialized as `(Transaction, HashMap<String, ProvingKeyMaterial>)`
/// tuple — the format the proof server expects.
///
/// # Parameters
/// - `offer_hex`: Tagged-serialized unproven ZswapOffer hex
/// - `network_id`: Network identifier ("undeployed", "preprod", "preview")
/// - `dust_tx_hex`: Optional pre-built dust Transaction hex (from `serialize_unshielded_transaction_with_dust`
///   or similar). If non-null, merged into the shielded transaction. If null, no dust fees.
/// - `ttl_ms`: Transaction TTL in milliseconds since epoch
///
/// # Returns
/// Hex-encoded `(Transaction, HashMap)` tuple for proof server.
/// Returns null on error. Caller must free with `free_zswap_string`.
#[no_mangle]
pub extern "C" fn zswap_build_shielded_transaction(
    offer_hex: *const c_char,
    network_id: *const c_char,
    dust_tx_hex: *const c_char, // optional pre-built dust transaction
    _reserved1: usize,         // reserved for future use
    _reserved2: *const c_char, // reserved for future use
    _reserved3: u64,           // reserved for future use
    ttl_ms: u64,
) -> *const c_char {
    if offer_hex.is_null() || network_id.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null offer_hex or network_id in zswap_build_shielded_transaction");
        return ptr::null();
    }

    // SAFETY: offer_hex and network_id validated non-null above. dust_tx_hex may be null (optional).
    unsafe {
        let network_str = match c_str_to_rust(network_id, "network_id") {
            Some(s) => s,
            None => return ptr::null(),
        };

        let offer_bytes = match c_hex_to_bytes(offer_hex, "offer") {
            Some(b) => b,
            None => return ptr::null(),
        };
        let offer: Offer<ProofPreimage, InMemoryDB> = match midnight_serialize::tagged_deserialize(&mut &offer_bytes[..]) {
            Ok(o) => o,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing offer: {}", e);
                return ptr::null();
            }
        };

        // Build base intent (empty — shielded coins go in guaranteed_coins, not in intents)
        let base_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: None,
            actions: std::iter::empty().collect(),
            dust_actions: None,
            ttl: Timestamp::from_secs(ttl_ms / 1000),
            binding_commitment: PedersenRandomness::default(),
        };

        // Build intents map (segment 1 for base intent)
        let intents_map = StorageHashMap::default().insert(1u16, base_intent);

        // Build StandardTransaction with guaranteed_coins = our zswap offer
        // StandardTransaction::new auto-computes binding_randomness
        let mut transaction = Transaction::Standard(StandardTransaction::new(
            network_str,
            intents_map,
            Some(offer),
            StorageHashMap::default(), // no fallible coins
        ));

        // If dust transaction provided, merge it (same pattern as serialize.rs:772-775)
        if !dust_tx_hex.is_null() {
            let dust_hex = match c_str_to_rust(dust_tx_hex, "dust_tx_hex") {
                Some(s) => s,
                None => return ptr::null(),
            };

            if !dust_hex.is_empty() {
                let dust_bytes = match c_hex_to_bytes(dust_tx_hex, "dust_tx") {
                    Some(b) => b,
                    None => return ptr::null(),
                };

                // Deserialize as (Transaction, HashMap) tuple (same format we produce)
                let (dust_transaction, _dust_proof_data): (
                    Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
                    std::collections::HashMap<String, ProvingKeyMaterial>,
                ) = match midnight_serialize::tagged_deserialize(&mut &dust_bytes[..]) {
                    Ok(t) => t,
                    Err(e) => {
                        android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing dust tx: {}", e);
                        return ptr::null();
                    }
                };

                // Merge dust transaction into shielded transaction
                transaction = match transaction.merge(&dust_transaction) {
                    Ok(merged) => merged,
                    Err(e) => {
                        android_log!(ANDROID_LOG_ERROR, TAG, "Error merging dust transaction: {:?}", e);
                        return ptr::null();
                    }
                };

                android_log!(ANDROID_LOG_INFO, TAG, "Merged dust transaction into shielded transaction");
            }
        }

        // Serialize as (Transaction, HashMap<String, ProvingKeyMaterial>) tuple
        // proof_data is empty — the proof server has its own proving keys
        let proof_data = std::collections::HashMap::<String, ProvingKeyMaterial>::new();

        let mut bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&(&transaction, &proof_data), &mut bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing transaction tuple: {}", e);
            return ptr::null();
        }

        android_log!(
            ANDROID_LOG_INFO, TAG,
            "Built shielded transaction: {} bytes, network={}",
            bytes.len(), network_str
        );

        string_to_c_ptr(hex::encode(&bytes))
    }
}

/// 7g+dust: Builds a shielded Transaction with dust fee payment.
///
/// Same as `zswap_build_shielded_transaction` but builds dust actions
/// internally from a DustLocalState, matching the pattern from serialize.rs.
///
/// # Parameters
/// - `offer_hex`: Tagged-serialized unproven ZswapOffer hex
/// - `network_id`: Network identifier ("undeployed", "preprod", "preview")
/// - `dust_state_ptr`: DustLocalState pointer (from create/replay)
/// - `dust_seed_ptr`: 32-byte dust seed (m/44'/2400'/0'/2/0)
/// - `dust_seed_len`: Must be 32
/// - `dust_utxos_json`: JSON array: [{"utxo_index":0,"v_fee":"1"}]
/// - `current_time_ms`: Current time in milliseconds (for dust fee calculation)
/// - `ttl_ms`: Transaction TTL in milliseconds since epoch
#[no_mangle]
pub extern "C" fn zswap_build_shielded_transaction_with_dust(
    offer_hex: *const c_char,
    network_id: *const c_char,
    dust_state_ptr: *const std::ffi::c_void,
    dust_seed_ptr: *const u8,
    dust_seed_len: usize,
    dust_utxos_json: *const c_char,
    current_time_ms: u64,
    ttl_ms: u64,
) -> *const c_char {
    if offer_hex.is_null() || network_id.is_null() {
        android_log!(ANDROID_LOG_ERROR, TAG, "Null offer_hex or network_id");
        return ptr::null();
    }

    // SAFETY: All required pointers validated. dust params may be null (no fees).
    unsafe {
        let network_str = match c_str_to_rust(network_id, "network_id") {
            Some(s) => s,
            None => return ptr::null(),
        };

        let offer_bytes = match c_hex_to_bytes(offer_hex, "offer") {
            Some(b) => b,
            None => return ptr::null(),
        };
        let offer: Offer<ProofPreimage, InMemoryDB> = match midnight_serialize::tagged_deserialize(&mut &offer_bytes[..]) {
            Ok(o) => o,
            Err(e) => {
                android_log!(ANDROID_LOG_ERROR, TAG, "Error deserializing offer: {}", e);
                return ptr::null();
            }
        };

        // Build transaction with guaranteed_coins only (no empty intent)
        // Intents will be added by dust merge if dust params provided
        let mut transaction = Transaction::Standard(StandardTransaction::new(
            network_str,
            StorageHashMap::default(), // no intents — dust adds its own
            Some(offer),
            StorageHashMap::default(),
        ));

        // Build and merge dust if dust params provided
        if !dust_state_ptr.is_null() && !dust_seed_ptr.is_null() && !dust_utxos_json.is_null() && dust_seed_len == 32 {
            use midnight_ledger::dust::{DustActions, DustLocalState as DustState, DustSecretKey, Seed as DustSeed};
            use midnight_storage::storage::Array as StorageArray;

            let dust_state = &*(dust_state_ptr as *const DustState<InMemoryDB>);

            // Derive dust secret key (same pattern as dust_ffi.rs)
            let dust_seed_slice = std::slice::from_raw_parts(dust_seed_ptr, dust_seed_len);
            let mut dust_seed_array: [u8; 32] = [0u8; 32];
            dust_seed_array.copy_from_slice(dust_seed_slice);
            let dust_secret_key = DustSecretKey::derive_secret_key(&dust_seed_array);
            dust_seed_array.fill(0);

            // Parse dust UTXOs JSON
            let utxos_str = match c_str_to_rust(dust_utxos_json, "dust_utxos") {
                Some(s) => s,
                None => return ptr::null(),
            };

            #[derive(serde::Deserialize)]
            struct DustUtxoSel { utxo_index: usize, v_fee: String }

            let utxo_selections: Vec<DustUtxoSel> = match serde_json::from_str(utxos_str) {
                Ok(v) => v,
                Err(e) => {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Invalid dust utxos JSON: {}", e);
                    return ptr::null();
                }
            };

            // Build dust spends (same pattern as dust_ffi.rs:656)
            let ctime = Timestamp::from_secs(current_time_ms / 1000);
            let all_utxos: Vec<_> = dust_state.utxos().collect();
            let mut dust_spends = Vec::new();

            for sel in &utxo_selections {
                let v_fee: u128 = match sel.v_fee.parse() {
                    Ok(v) => v,
                    Err(e) => {
                        android_log!(ANDROID_LOG_ERROR, TAG, "Invalid v_fee: {}", e);
                        return ptr::null();
                    }
                };

                if sel.utxo_index >= all_utxos.len() {
                    android_log!(ANDROID_LOG_ERROR, TAG, "Dust UTXO index {} out of bounds ({})", sel.utxo_index, all_utxos.len());
                    return ptr::null();
                }

                let utxo = all_utxos[sel.utxo_index];
                match dust_state.spend(&dust_secret_key, &utxo, v_fee, ctime) {
                    Ok((_new_state, spend)) => {
                        android_log!(ANDROID_LOG_INFO, TAG, "Created dust spend from UTXO {}", sel.utxo_index);
                        dust_spends.push(spend);
                    }
                    Err(e) => {
                        android_log!(ANDROID_LOG_ERROR, TAG, "Dust spend failed for UTXO {}: {:?}", sel.utxo_index, e);
                        return ptr::null();
                    }
                }
            }

            if !dust_spends.is_empty() {
                let spends_array: StorageArray<_, InMemoryDB> = dust_spends.into_iter().collect();
                let registrations_array: StorageArray<midnight_ledger::dust::DustRegistration<Signature, InMemoryDB>, InMemoryDB> = std::iter::empty().collect();

                let dust_actions = DustActions {
                    spends: spends_array,
                    registrations: registrations_array,
                    ctime,
                };

                let dust_segment_id: u16 = OsRng.gen_range(2..u16::MAX);
                let dust_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
                    guaranteed_unshielded_offer: None,
                    fallible_unshielded_offer: None,
                    actions: std::iter::empty().collect(),
                    dust_actions: Some(midnight_storage::arena::Sp::new(dust_actions)),
                    ttl: Timestamp::from_secs(ttl_ms / 1000),
                    binding_commitment: PedersenRandomness::from(0),
                };

                let dust_intents_map = StorageHashMap::default().insert(dust_segment_id, dust_intent);
                let dust_transaction = Transaction::Standard(StandardTransaction::new(
                    network_str,
                    dust_intents_map,
                    None,
                    StorageHashMap::default(),
                ));

                transaction = match transaction.merge(&dust_transaction) {
                    Ok(merged) => merged,
                    Err(e) => {
                        android_log!(ANDROID_LOG_ERROR, TAG, "Failed to merge dust: {:?}", e);
                        return ptr::null();
                    }
                };

                android_log!(ANDROID_LOG_INFO, TAG, "Merged dust into shielded transaction");
            }
        }

        let proof_data = std::collections::HashMap::<String, ProvingKeyMaterial>::new();

        let mut bytes = Vec::new();
        if let Err(e) = midnight_serialize::tagged_serialize(&(&transaction, &proof_data), &mut bytes) {
            android_log!(ANDROID_LOG_ERROR, TAG, "Error serializing transaction: {}", e);
            return ptr::null();
        }

        android_log!(ANDROID_LOG_INFO, TAG, "Built shielded tx with dust: {} bytes", bytes.len());
        string_to_c_ptr(hex::encode(&bytes))
    }
}

// ── Internal Helpers ──

/// Parses a JSON coin object from zswap_select_coins output into a QualifiedCoinInfo.
fn parse_qualified_coin_info(json_str: &str) -> Result<QualifiedCoinInfo, String> {
    // Parse using serde_json
    let v: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let type_hex = v["type_hex"].as_str()
        .ok_or("Missing type_hex")?;
    let value_str = v["value"].as_str()
        .ok_or("Missing value")?;
    let nonce_hex = v["nonce_hex"].as_str()
        .ok_or("Missing nonce_hex")?;
    let mt_index = v["mt_index"].as_u64()
        .ok_or("Missing mt_index")?;

    // Deserialize type
    let type_bytes = hex::decode(type_hex)
        .map_err(|e| format!("Invalid type hex: {}", e))?;
    let type_: ShieldedTokenType = Deserializable::deserialize(&mut &type_bytes[..], 0)
        .map_err(|e| format!("Error deserializing type: {}", e))?;

    // Deserialize nonce
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    let nonce: Nonce = Deserializable::deserialize(&mut &nonce_bytes[..], 0)
        .map_err(|e| format!("Error deserializing nonce: {}", e))?;

    // Parse value
    let value: u128 = value_str.parse()
        .map_err(|e| format!("Invalid value: {}", e))?;

    Ok(QualifiedCoinInfo {
        nonce,
        type_,
        value,
        mt_index,
    })
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

        // Transfer primitives null safety
        assert!(zswap_select_coins(ptr::null(), ptr::null(), ptr::null()).is_null());
        let spend_result = zswap_spend_coin(ptr::null(), ptr::null(), 0, ptr::null());
        assert!(spend_result.new_state.is_null());
        assert!(spend_result.result_json.is_null());
        assert!(zswap_create_output(ptr::null(), ptr::null(), ptr::null(), ptr::null()).is_null());

        // Free null should not crash
        free_zswap_local_state(ptr::null_mut());
        free_zswap_string(ptr::null_mut());
    }

    // ── Transfer Primitive Tests ──

    #[test]
    fn test_select_coins_empty_state() {
        let state = create_zswap_local_state();
        let token_type = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let amount = CString::new("1000000").unwrap();

        let result = zswap_select_coins(state, token_type.as_ptr(), amount.as_ptr());
        assert!(result.is_null(), "Should return null for empty state (insufficient balance)");

        free_zswap_local_state(state);
    }

    #[test]
    fn test_select_coins_invalid_amount() {
        let state = create_zswap_local_state();
        let token_type = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let amount = CString::new("not_a_number").unwrap();

        let result = zswap_select_coins(state, token_type.as_ptr(), amount.as_ptr());
        assert!(result.is_null(), "Should return null for invalid amount");

        free_zswap_local_state(state);
    }

    #[test]
    fn test_spend_coin_invalid_seed_len() {
        let state = create_zswap_local_state();
        let seed = [0u8; 16]; // Wrong size
        let coin_json = CString::new("{}").unwrap();

        let result = zswap_spend_coin(state, seed.as_ptr(), 16, coin_json.as_ptr());
        assert!(result.new_state.is_null(), "Should return null state for invalid seed length");
        assert!(result.result_json.is_null(), "Should return null json for invalid seed length");

        free_zswap_local_state(state);
    }

    #[test]
    fn test_spend_coin_not_found_in_state() {
        // Spend a coin that doesn't exist in an empty state
        let state = create_zswap_local_state();
        let seed = [0u8; 32];
        let coin_json = CString::new(
            r#"{"type_hex":"0000000000000000000000000000000000000000000000000000000000000000","value":"5000000","nonce_hex":"0000000000000000000000000000000000000000000000000000000000000000","mt_index":0}"#
        ).unwrap();

        let result = zswap_spend_coin(state, seed.as_ptr(), 32, coin_json.as_ptr());
        assert!(result.new_state.is_null(), "Should return null for coin not in state");
        assert!(result.result_json.is_null(), "Should return null json for coin not in state");

        free_zswap_local_state(state);
    }

    #[test]
    fn test_create_output_valid() {
        // Use test vector keys from derive_shielded_keys test
        let coin_pk = CString::new("9408aeffbeedc6b9b45e1bcc621d1a273fb67f77de3f65bfbb1814d84f8b6524").unwrap();
        let enc_pk = CString::new("f3ae706bf28c856a407690b468081a7f5a123e523501b69f4395abcd7e19032b").unwrap();
        let token_type = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let amount = CString::new("5000000").unwrap();

        let result = zswap_create_output(
            coin_pk.as_ptr(),
            enc_pk.as_ptr(),
            token_type.as_ptr(),
            amount.as_ptr(),
        );
        assert!(!result.is_null(), "Should create output successfully");

        unsafe {
            let json = std::ffi::CStr::from_ptr(result).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            assert!(v["output_hex"].is_string(), "Should have output_hex");
            assert!(v["binding_randomness_hex"].is_string(), "Should have binding_randomness_hex");

            let output_hex = v["output_hex"].as_str().unwrap();
            assert!(!output_hex.is_empty(), "Output hex should not be empty");

            free_zswap_string(result as *mut c_char);
        }
    }

    #[test]
    fn test_create_output_different_recipients_differ() {
        let token_type = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let amount = CString::new("1000000").unwrap();

        // Recipient A (test vector keys)
        let cpk_a = CString::new("9408aeffbeedc6b9b45e1bcc621d1a273fb67f77de3f65bfbb1814d84f8b6524").unwrap();
        let epk_a = CString::new("f3ae706bf28c856a407690b468081a7f5a123e523501b69f4395abcd7e19032b").unwrap();
        let result_a = zswap_create_output(cpk_a.as_ptr(), epk_a.as_ptr(), token_type.as_ptr(), amount.as_ptr());
        assert!(!result_a.is_null());

        // Recipient B (different keys — use a different seed's keys)
        let seed_b = [0x02u8; 32];
        let keys_b = crate::derive_shielded_keys(seed_b.as_ptr(), 32);
        assert!(!keys_b.is_null());

        unsafe {
            let cpk_b_str = std::ffi::CStr::from_ptr((*keys_b).coin_public_key).to_str().unwrap();
            let epk_b_str = std::ffi::CStr::from_ptr((*keys_b).encryption_public_key).to_str().unwrap();
            let cpk_b = CString::new(cpk_b_str).unwrap();
            let epk_b = CString::new(epk_b_str).unwrap();

            let result_b = zswap_create_output(cpk_b.as_ptr(), epk_b.as_ptr(), token_type.as_ptr(), amount.as_ptr());
            assert!(!result_b.is_null());

            // Outputs should differ (different commitments due to different recipients)
            let json_a = std::ffi::CStr::from_ptr(result_a).to_str().unwrap();
            let json_b = std::ffi::CStr::from_ptr(result_b).to_str().unwrap();
            let v_a: serde_json::Value = serde_json::from_str(json_a).unwrap();
            let v_b: serde_json::Value = serde_json::from_str(json_b).unwrap();
            assert_ne!(
                v_a["output_hex"].as_str().unwrap(),
                v_b["output_hex"].as_str().unwrap(),
                "Different recipients should produce different outputs"
            );

            free_zswap_string(result_a as *mut c_char);
            free_zswap_string(result_b as *mut c_char);
            crate::free_shielded_keys(keys_b);
        }
    }

    #[test]
    fn test_parse_qualified_coin_info() {
        let json = r#"{"type_hex":"0000000000000000000000000000000000000000000000000000000000000000","value":"5000000","nonce_hex":"0000000000000000000000000000000000000000000000000000000000000000","mt_index":42}"#;
        let coin = parse_qualified_coin_info(json).unwrap();
        assert_eq!(coin.value, 5000000);
        assert_eq!(coin.mt_index, 42);
    }

    #[test]
    fn test_parse_qualified_coin_info_invalid() {
        assert!(parse_qualified_coin_info("not json").is_err());
        assert!(parse_qualified_coin_info(r#"{"type_hex":"ff"}"#).is_err()); // missing fields
    }

    // ── 7d: build_offer tests ──

    /// Helper: creates an output hex string via zswap_create_output
    fn helper_create_output_hex() -> String {
        let coin_pk = CString::new("9408aeffbeedc6b9b45e1bcc621d1a273fb67f77de3f65bfbb1814d84f8b6524").unwrap();
        let enc_pk = CString::new("f3ae706bf28c856a407690b468081a7f5a123e523501b69f4395abcd7e19032b").unwrap();
        let token_type = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let amount = CString::new("5000000").unwrap();

        let result = zswap_create_output(coin_pk.as_ptr(), enc_pk.as_ptr(), token_type.as_ptr(), amount.as_ptr());
        assert!(!result.is_null(), "helper_create_output_hex: create_output failed");

        unsafe {
            let json = std::ffi::CStr::from_ptr(result).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            let output_hex = v["output_hex"].as_str().unwrap().to_string();
            free_zswap_string(result as *mut c_char);
            output_hex
        }
    }

    #[test]
    fn test_build_offer_with_single_output() {
        let output_hex = helper_create_output_hex();
        let outputs_json = format!("[\"{}\"]", output_hex);
        let inputs_json = CString::new("[]").unwrap();
        let outputs_cstr = CString::new(outputs_json).unwrap();

        let result = zswap_build_offer(inputs_json.as_ptr(), outputs_cstr.as_ptr());
        assert!(!result.is_null(), "Should build offer from single output");

        unsafe {
            let json = std::ffi::CStr::from_ptr(result).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            assert!(v["offer_hex"].is_string(), "Should have offer_hex");
            assert!(v["binding_randomness_hex"].is_string(), "Should have binding_randomness_hex");

            let offer_hex = v["offer_hex"].as_str().unwrap();
            assert!(!offer_hex.is_empty(), "Offer hex should not be empty");

            free_zswap_string(result as *mut c_char);
        }
    }

    #[test]
    fn test_build_offer_empty_inputs_and_outputs() {
        let inputs_json = CString::new("[]").unwrap();
        let outputs_json = CString::new("[]").unwrap();

        let result = zswap_build_offer(inputs_json.as_ptr(), outputs_json.as_ptr());
        assert!(result.is_null(), "Should return null for empty offer (no inputs or outputs)");
    }

    #[test]
    fn test_build_offer_null_safety() {
        assert!(zswap_build_offer(ptr::null(), ptr::null()).is_null());
    }

    // ── 7e: merge_offers tests ──

    #[test]
    fn test_merge_offers_two_output_offers() {
        // Create two different offers with different outputs
        let output1 = helper_create_output_hex();
        let output2 = helper_create_output_hex(); // different nonce → different commitment

        let inputs_json = CString::new("[]").unwrap();
        let outputs1 = CString::new(format!("[\"{}\"]", output1)).unwrap();
        let outputs2 = CString::new(format!("[\"{}\"]", output2)).unwrap();

        let offer1_ptr = zswap_build_offer(inputs_json.as_ptr(), outputs1.as_ptr());
        let offer2_ptr = zswap_build_offer(inputs_json.as_ptr(), outputs2.as_ptr());
        assert!(!offer1_ptr.is_null());
        assert!(!offer2_ptr.is_null());

        unsafe {
            let offer1_json = std::ffi::CStr::from_ptr(offer1_ptr).to_str().unwrap();
            let offer2_json = std::ffi::CStr::from_ptr(offer2_ptr).to_str().unwrap();
            let v1: serde_json::Value = serde_json::from_str(offer1_json).unwrap();
            let v2: serde_json::Value = serde_json::from_str(offer2_json).unwrap();

            let offer1_hex = CString::new(v1["offer_hex"].as_str().unwrap()).unwrap();
            let offer2_hex = CString::new(v2["offer_hex"].as_str().unwrap()).unwrap();

            let merged = zswap_merge_offers(offer1_hex.as_ptr(), offer2_hex.as_ptr());
            assert!(!merged.is_null(), "Should merge two disjoint offers");

            free_zswap_string(merged as *mut c_char);
            free_zswap_string(offer1_ptr as *mut c_char);
            free_zswap_string(offer2_ptr as *mut c_char);
        }
    }

    #[test]
    fn test_merge_offers_null_safety() {
        assert!(zswap_merge_offers(ptr::null(), ptr::null()).is_null());
    }

    // ── 7f: serialize_offer tests ──

    #[test]
    fn test_serialize_offer_round_trip() {
        let output_hex = helper_create_output_hex();
        let inputs_json = CString::new("[]").unwrap();
        let outputs_json = CString::new(format!("[\"{}\"]", output_hex)).unwrap();

        let offer_ptr = zswap_build_offer(inputs_json.as_ptr(), outputs_json.as_ptr());
        assert!(!offer_ptr.is_null());

        unsafe {
            let offer_json = std::ffi::CStr::from_ptr(offer_ptr).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(offer_json).unwrap();
            let offer_hex = CString::new(v["offer_hex"].as_str().unwrap()).unwrap();

            let serialized = zswap_serialize_offer(offer_hex.as_ptr());
            assert!(!serialized.is_null(), "Should serialize offer to SCALE format");

            // The serialized output should be a hex string
            let scale_hex = std::ffi::CStr::from_ptr(serialized).to_str().unwrap();
            assert!(!scale_hex.is_empty(), "SCALE hex should not be empty");

            free_zswap_string(serialized as *mut c_char);
            free_zswap_string(offer_ptr as *mut c_char);
        }
    }

    #[test]
    fn test_serialize_offer_null_safety() {
        assert!(zswap_serialize_offer(ptr::null()).is_null());
    }

    // ── 7g: build_shielded_transaction tests ──

    // ── Internal (non-FFI) tests with real coins ──

    #[test]
    fn test_internal_select_and_spend_with_real_coin() {
        // Test the full flow: create keys → create output → apply to state → select → spend
        // This tests via the Rust API directly (not FFI), validating coin selection and spending.

        // 1. Create secret keys from a known seed
        let seed_bytes = [0x42u8; 32];
        let secret_keys = SecretKeys::from(Seed::from(seed_bytes));
        let coin_pk = secret_keys.coin_public_key();
        let enc_pk = secret_keys.enc_public_key();

        // 2. Create a coin for ourselves
        let coin_info = CoinInfo {
            type_: ShieldedTokenType(midnight_base_crypto::hash::HashOutput::default()),
            value: 10_000_000, // 10 NIGHT in micro-units
            nonce: OsRng.r#gen(),
        };

        // 3. Create an output encrypted to our own keys
        let output: Output<ProofPreimage, InMemoryDB> = Output::new(
            &mut OsRng,
            &coin_info,
            None,
            &coin_pk,
            Some(enc_pk),
        ).expect("Output creation should succeed");

        // 4. Build an offer from this output
        let offer = Offer::new(vec![], vec![output], vec![])
            .expect("Offer with one output should not be None");

        // 5. Apply the offer to an empty state (simulates receiving a coin)
        let state = ZswapState::<InMemoryDB>::new();
        let state_with_coin = state.apply(&secret_keys, &offer);

        // 6. Verify the coin was added
        let coin_count = state_with_coin.coins.iter().count();
        assert_eq!(coin_count, 1, "State should have 1 coin after apply");

        // 7. Verify we can find the coin by token type
        let matching: Vec<_> = state_with_coin.coins.iter()
            .filter(|(_, c)| c.type_ == coin_info.type_)
            .collect();
        assert_eq!(matching.len(), 1, "Should find 1 matching coin");

        let (_, ref found_coin) = matching[0];
        assert_eq!(found_coin.value, 10_000_000);

        // 8. Spend the coin
        let (new_state, input) = state_with_coin.spend(
            &mut OsRng,
            &secret_keys,
            &found_coin,
            None,
        ).expect("Spending should succeed");

        // 9. Verify state transition: coin added to pending_spends
        // Note: spend() does NOT remove from coins — coin stays until on-chain confirmation
        // via apply(). pending_spends tracks coins awaiting confirmation.
        assert_eq!(new_state.coins.iter().count(), 1, "Coin should still be in coins (pending confirmation)");
        assert_eq!(new_state.pending_spends.iter().count(), 1, "Coin should also be in pending_spends");

        // 10. Verify the input has a non-default nullifier
        let nul_bytes = input.nullifier.0.0;
        assert!(nul_bytes.iter().any(|&b| b != 0), "Input should have a non-zero nullifier");
    }

    #[test]
    fn test_internal_select_and_spend_with_change() {
        // Test scenario: coin value (10M) > transfer amount (6M) → need 4M change output

        let seed_bytes = [0x43u8; 32];
        let secret_keys = SecretKeys::from(Seed::from(seed_bytes));
        let coin_pk = secret_keys.coin_public_key();
        let enc_pk = secret_keys.enc_public_key();
        let night_type = ShieldedTokenType(midnight_base_crypto::hash::HashOutput::default());

        // Create a 10M coin for ourselves
        let coin_info = CoinInfo {
            type_: night_type,
            value: 10_000_000,
            nonce: OsRng.r#gen(),
        };
        let output = Output::<ProofPreimage, InMemoryDB>::new(
            &mut OsRng, &coin_info, None, &coin_pk, Some(enc_pk),
        ).unwrap();
        let offer = Offer::new(vec![], vec![output], vec![]).unwrap();
        let state = ZswapState::<InMemoryDB>::new().apply(&secret_keys, &offer);
        assert_eq!(state.coins.iter().count(), 1);

        // Spend the coin (spending the full 10M coin)
        let (_, coin) = state.coins.iter().next().unwrap();
        let (state_after_spend, spend_input) = state.spend(
            &mut OsRng, &secret_keys, &coin, None,
        ).unwrap();

        // Create recipient output for 6M
        let recipient_seed = [0x99u8; 32];
        let recipient_keys = SecretKeys::from(Seed::from(recipient_seed));
        let recipient_output = Output::<ProofPreimage, InMemoryDB>::new(
            &mut OsRng,
            &CoinInfo { type_: night_type, value: 6_000_000, nonce: OsRng.r#gen() },
            None,
            &recipient_keys.coin_public_key(),
            Some(recipient_keys.enc_public_key()),
        ).unwrap();

        // Create change output for 4M (back to ourselves)
        let change_output = Output::<ProofPreimage, InMemoryDB>::new(
            &mut OsRng,
            &CoinInfo { type_: night_type, value: 4_000_000, nonce: OsRng.r#gen() },
            None,
            &coin_pk,
            Some(enc_pk),
        ).unwrap();

        // Build offer with 1 input + 2 outputs
        let transfer_offer = Offer::new(
            vec![spend_input],
            vec![recipient_output, change_output],
            vec![],
        ).unwrap();

        // Verify deltas balance: 10M in - 6M out - 4M out = 0
        let total_delta: i128 = transfer_offer.deltas.iter()
            .map(|d| d.value)
            .sum();
        assert_eq!(total_delta, 0, "Transfer should be balanced (input = outputs)");
    }

    #[test]
    fn test_internal_select_excludes_pending_spends() {
        // Verify that after spending a coin, select_coins won't pick it again

        let seed_bytes = [0x44u8; 32];
        let secret_keys = SecretKeys::from(Seed::from(seed_bytes));
        let coin_pk = secret_keys.coin_public_key();
        let enc_pk = secret_keys.enc_public_key();
        let night_type = ShieldedTokenType(midnight_base_crypto::hash::HashOutput::default());

        // Create two coins: 5M and 3M
        let coin1 = CoinInfo { type_: night_type, value: 5_000_000, nonce: OsRng.r#gen() };
        let coin2 = CoinInfo { type_: night_type, value: 3_000_000, nonce: OsRng.r#gen() };

        let output1 = Output::<ProofPreimage, InMemoryDB>::new(
            &mut OsRng, &coin1, None, &coin_pk, Some(enc_pk),
        ).unwrap();
        let output2 = Output::<ProofPreimage, InMemoryDB>::new(
            &mut OsRng, &coin2, None, &coin_pk, Some(enc_pk),
        ).unwrap();

        let offer = Offer::new(vec![], vec![output1, output2], vec![]).unwrap();
        let state = ZswapState::<InMemoryDB>::new().apply(&secret_keys, &offer);
        assert_eq!(state.coins.iter().count(), 2, "Should have 2 coins");

        // Spend the 5M coin
        let (_, coin_5m) = state.coins.iter()
            .find(|(_, c)| c.value == 5_000_000)
            .expect("Should find 5M coin");
        let (state_after_spend, _input) = state.spend(
            &mut OsRng, &secret_keys, &coin_5m, None,
        ).unwrap();

        // State should have 2 coins + 1 pending
        assert_eq!(state_after_spend.coins.iter().count(), 2);
        assert_eq!(state_after_spend.pending_spends.iter().count(), 1);

        // Now use the FFI select_coins on the state_after_spend
        // It should only find the 3M coin (5M is pending)
        let state_ptr = Box::into_raw(Box::new(state_after_spend));
        let token_type_hex = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let amount = CString::new("1").unwrap();

        let result = zswap_select_coins(state_ptr, token_type_hex.as_ptr(), amount.as_ptr());
        assert!(!result.is_null(), "Should find coins (3M is available)");

        unsafe {
            let json = std::ffi::CStr::from_ptr(result).to_str().unwrap();
            let arr: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
            assert_eq!(arr.len(), 1, "Should only select 1 coin (the 3M, not the pending 5M)");
            assert_eq!(arr[0]["value"].as_str().unwrap(), "3000000", "Selected coin should be the 3M one");

            free_zswap_string(result as *mut c_char);
        }

        // Selecting 4M should fail (only 3M available, 5M is pending)
        let amount_too_high = CString::new("4000000").unwrap();
        let result2 = zswap_select_coins(state_ptr, token_type_hex.as_ptr(), amount_too_high.as_ptr());
        assert!(result2.is_null(), "Should fail — only 3M available, 5M is pending");

        unsafe { free_zswap_local_state(state_ptr); }
    }

    // ── 7g: build_shielded_transaction tests ──

    #[test]
    fn test_build_shielded_transaction_null_safety() {
        assert!(zswap_build_shielded_transaction(
            ptr::null(), ptr::null(), ptr::null(), 0, ptr::null(), 0, 0
        ).is_null());
    }

    #[test]
    fn test_build_shielded_transaction_with_output_only_offer() {
        // Build an output-only offer (no inputs — like receiving coins)
        let output_hex = helper_create_output_hex();
        let inputs_json = CString::new("[]").unwrap();
        let outputs_json = CString::new(format!("[\"{}\"]", output_hex)).unwrap();

        let offer_ptr = zswap_build_offer(inputs_json.as_ptr(), outputs_json.as_ptr());
        assert!(!offer_ptr.is_null());

        unsafe {
            let offer_json = std::ffi::CStr::from_ptr(offer_ptr).to_str().unwrap();
            let v: serde_json::Value = serde_json::from_str(offer_json).unwrap();
            let offer_hex_str = v["offer_hex"].as_str().unwrap();
            let offer_hex = CString::new(offer_hex_str).unwrap();

            let network_id = CString::new("undeployed").unwrap();
            let ttl_ms: u64 = 1711584000000; // some fixed timestamp

            // No dust for this test
            let result = zswap_build_shielded_transaction(
                offer_hex.as_ptr(),
                network_id.as_ptr(),
                ptr::null(), // no dust state
                0,           // no dust seed
                ptr::null(), // no dust utxos
                0,           // no current_time
                ttl_ms,
            );
            assert!(!result.is_null(), "Should build transaction from output-only offer");

            let tx_hex = std::ffi::CStr::from_ptr(result).to_str().unwrap();
            assert!(!tx_hex.is_empty(), "Transaction hex should not be empty");

            free_zswap_string(result as *mut c_char);
            free_zswap_string(offer_ptr as *mut c_char);
        }
    }
}
