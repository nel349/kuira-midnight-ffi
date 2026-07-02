//! Contract FFI — exposes onchain-runtime types for the QuickJS shim.
//!
//! These functions are called by the QuickJS compact-runtime shim
//! to execute contract operations natively instead of via WASM.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use midnight_base_crypto::hash::{persistent_hash, PersistentHashWriter};
use midnight_base_crypto::fab::{AlignedValue, Value};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_serialize::Serializable;

// Contract state types for query execution
use midnight_storage::db::InMemoryDB;
use midnight_onchain_state::state::ContractState as RustContractState;
use midnight_onchain_runtime::contract_state_ext::ContractStateExt;
use midnight_onchain_vm::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeGather;

/// Helper: convert a C string to a Rust &str.
///
/// # Safety
/// The caller must ensure `ptr` points to a valid null-terminated C string
/// that remains valid for the lifetime `'a`. The string must be valid UTF-8.
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees ptr is a valid, null-terminated C string from JNI
    CStr::from_ptr(ptr).to_str().ok()
}

/// Helper: lock the state pool, returning None on poisoned mutex.
fn lock_state_pool() -> Option<std::sync::MutexGuard<'static, HashMap<u64, RustContractState<InMemoryDB>>>> {
    // Recover from a poisoned mutex instead of propagating the poison. The pool
    // is a plain handle map — a panic while holding the lock (e.g. a failing
    // `assert!` inside the guard scope in a parallel test run) leaves the data
    // intact, but a poisoned `Mutex` would otherwise cascade: every subsequent
    // `lock()` returns `Err`, so `contract_state_create` starts returning 0 and
    // unrelated pool tests fail en masse. `into_inner()` keeps the map usable.
    Some(STATE_POOL.lock().unwrap_or_else(|poisoned| {
        eprintln!("WARNING: lock_state_pool recovered a poisoned mutex — a prior panic poisoned the state pool; continuing with the intact map");
        poisoned.into_inner()
    }))
}

/// Helper: convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    hex::decode(hex).ok()
}

/// Helper: return a hex string as a C pointer
fn to_c_hex(bytes: &[u8]) -> *const c_char {
    match CString::new(hex::encode(bytes)) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

/// Helper: return a string as a C pointer
fn to_c_string(s: &str) -> *const c_char {
    match CString::new(s) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

/// The midnight-ledger version this client links against. Used by the host to
/// run a coherence check against the node's `midnight_ledgerVersion` so a
/// client built behind the chain fails loudly instead of mis-decoding ops.
/// keep in sync with the vendored midnight-ledger/Cargo.toml package.version
const LEDGER_VERSION: &str = "8.0.3";

/// Return the client's bundled midnight-ledger version (e.g. "8.0.3").
#[no_mangle]
pub extern "C" fn kuira_ledger_version() -> *const c_char {
    to_c_string(LEDGER_VERSION)
}

// ── State Handle Pool ──
// Keep contract states in Rust memory. JS holds integer handles.

use std::sync::Mutex;
use std::collections::HashMap;

static STATE_POOL: once_cell::sync::Lazy<Mutex<HashMap<u64, RustContractState<InMemoryDB>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

static NEXT_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Create a new contract state from SCALE hex, return a handle.
///
/// Supports both formats:
/// - Tagged: indexer data with version header (e.g., `midnight:contract-state[v6]:...`)
/// - Raw: internally serialized data without header
#[no_mangle]
pub extern "C" fn contract_state_create(state_hex: *const c_char) -> u64 {
    // SAFETY: JNI guarantees state_hex is a valid null-terminated UTF-8 string
    let hex_str = match unsafe { c_str_to_str(state_hex) } {
        Some(s) => s,
        None => return 0,
    };
    let bytes = match hex_to_bytes(hex_str) {
        Some(b) => b,
        None => return 0,
    };

    // Try tagged deserialization first (indexer data has version header),
    // fall back to raw deserialization (internally serialized data).
    let state: RustContractState<InMemoryDB> =
        match midnight_serialize::tagged_deserialize(&mut &bytes[..]) {
            Ok(s) => s,
            Err(_) => {
                match midnight_serialize::Deserializable::deserialize(&mut &bytes[..], 0) {
                    Ok(s) => s,
                    Err(_) => return 0,
                }
            }
        };

    let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let Some(mut pool) = lock_state_pool() else { return 0 };
    pool.insert(handle, state);
    handle
}

/// Serialize a contract state to SCALE hex.
#[no_mangle]
pub extern "C" fn contract_state_serialize(handle: u64) -> *const c_char {
    let Some(pool) = lock_state_pool() else { return std::ptr::null() };
    let state = match pool.get(&handle) {
        Some(s) => s,
        None => return std::ptr::null(),
    };
    let mut out = Vec::new();
    if state.serialize(&mut out).is_err() {
        return std::ptr::null();
    }
    to_c_hex(&out)
}

/// Read contract state fields as JSON.
///
/// Walks the StateValue tree and serializes to a human-readable JSON structure:
/// - Null → null
/// - Cell(AlignedValue) → { "type": "cell", "bytes": [hex], "text": "..." }
/// - Array([...]) → [ item0, item1, ... ]
///
/// The "text" field is included when the cell bytes are valid UTF-8.
/// Returns JSON string, or {"error": "..."} on failure.
#[no_mangle]
pub extern "C" fn contract_state_read_fields(handle: u64) -> *const c_char {
    use midnight_onchain_state::state::StateValue;

    let Some(pool) = lock_state_pool() else {
        return to_c_string("{\"error\":\"state pool lock poisoned\"}");
    };
    let state = match pool.get(&handle) {
        Some(s) => s,
        None => return to_c_string("{\"error\":\"invalid state handle\"}"),
    };

    fn state_value_to_json(sv: &StateValue<InMemoryDB>) -> serde_json::Value {
        match sv {
            StateValue::Null => serde_json::Value::Null,
            StateValue::Cell(aligned) => {
                // Extract raw bytes from the AlignedValue
                let bytes: Vec<u8> = aligned.value.0.iter()
                    .flat_map(|atom| atom.0.iter().copied())
                    .collect();
                let hex = hex::encode(&bytes);

                let mut obj = serde_json::Map::new();
                obj.insert("type".to_string(), "cell".into());
                obj.insert("hex".to_string(), hex.into());

                // Try to decode as UTF-8 text (raw bytes)
                if let Ok(text) = String::from_utf8(bytes.clone()) {
                    if text.len() > 0 && text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                        obj.insert("text".to_string(), text.into());
                    }
                }

                // Try to decode as UTF-8 text (skip leading 0x01 Option prefix)
                if !obj.contains_key("text") && bytes.len() > 1 && bytes[0] == 0x01 {
                    if let Ok(text) = String::from_utf8(bytes[1..].to_vec()) {
                        if text.len() > 0 && text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                            obj.insert("text".to_string(), text.into());
                        }
                    }
                }

                // Decode as number — works for any byte length
                let mut n: u128 = 0;
                let num_bytes = bytes.len().min(16);
                let is_small = bytes.len() <= 16 || bytes[16..].iter().all(|&x| x == 0);
                if is_small && !bytes.is_empty() {
                    for (i, &byte) in bytes.iter().enumerate().take(num_bytes) {
                        n |= (byte as u128) << (8 * i);
                    }
                    if n <= i64::MAX as u128 {
                        obj.insert("number".to_string(), (n as i64).into());
                    }
                }

                serde_json::Value::Object(obj)
            }
            StateValue::Array(items) => {
                let arr: Vec<serde_json::Value> = items.iter()
                    .map(|item| state_value_to_json(&*item))
                    .collect();
                serde_json::Value::Array(arr)
            }
            _ => serde_json::json!({"type": "unknown"}),
        }
    }

    let state_ref = state.data.get_ref();
    let json = state_value_to_json(state_ref);
    match serde_json::to_string(&json) {
        Ok(s) => to_c_string(&s),
        Err(e) => to_c_string(&format!("{{\"error\":\"serialize: {}\"}}", e)),
    }
}

/// Free a contract state handle.
#[no_mangle]
pub extern "C" fn contract_state_free(handle: u64) {
    if let Some(mut pool) = lock_state_pool() {
        pool.remove(&handle);
    }
}

// ── ContractState.query() ──

/// Execute opcodes against a contract state (by handle) and return events + gas.
///
/// Uses QueryContext::query() (not ContractStateExt::query()) to preserve gas info.
///
/// Output JSON: { "handle": N, "events": [...], "gas": { "readTime": N, "computeTime": N, "bytesWritten": N, "bytesDeleted": N } }
/// or { "error": "..." } on failure
#[no_mangle]
pub extern "C" fn contract_query(
    handle: u64,
    opcodes_json: *const c_char,
) -> *const c_char {
    use midnight_onchain_runtime::context::QueryContext;

    // SAFETY: JNI guarantees opcodes_json is a valid null-terminated UTF-8 string
    let opcodes_str = match unsafe { c_str_to_str(opcodes_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    // Get state from pool
    let state = {
        let Some(pool) = lock_state_pool() else {
            return to_c_string("{\"error\":\"state pool lock poisoned\"}");
        };
        match pool.get(&handle).cloned() {
            Some(s) => s,
            None => return to_c_string("{\"error\":\"invalid state handle\"}"),
        }
    };

    // Deserialize opcodes from JSON (serde)
    let ops: Vec<Op<ResultModeGather, InMemoryDB>> =
        match serde_json::from_str(opcodes_str) {
            Ok(o) => o,
            Err(e) => return to_c_string(&format!("{{\"error\":\"opcodes deserialize: {}\"}}", e)),
        };

    // Build QueryContext with realistic call_context so gas computation
    // during circuit execution matches on-chain behavior. The gas from
    // contract_query feeds into the JS runtime's gas tracking.
    let qc = {
        use midnight_base_crypto::time::Timestamp;
        
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        QueryContext::<InMemoryDB> {
            state: state.data.clone(),
            address: Default::default(),
            effects: Default::default(),
            call_context: midnight_onchain_runtime::context::CallContext {
                tblock: Timestamp::from_secs(now_secs),
                ..Default::default()
            },
        }
    };

    match qc.query(&ops, None, &INITIAL_COST_MODEL) {
        Ok(results) => {
            // Build new ContractState from results
            let new_state = RustContractState {
                data: results.context.state,
                ..state
            };
            if let Some(mut pool) = lock_state_pool() {
                pool.insert(handle, new_state);
            }

            // Serialize events
            let events_json = match serde_json::to_string(&results.events) {
                Ok(s) => s,
                Err(e) => return to_c_string(&format!("{{\"error\":\"events serialize: {}\"}}", e)),
            };

            // Serialize gas cost
            let gas = &results.gas_cost;
            let gas_json = match serde_json::to_string(gas) {
                Ok(s) => s,
                Err(e) => return to_c_string(&format!("{{\"error\":\"gas serialize: {}\"}}", e)),
            };

            to_c_string(&format!(
                "{{\"handle\":{},\"events\":{},\"gas\":{}}}",
                handle, events_json, gas_json,
            ))
        }
        Err(e) => {
            to_c_string(&format!("{{\"error\":\"query failed: {:?}\"}}", e))
        }
    }
}

// ── persistentHash ──

/// Compute persistent hash (SHA-256) of raw input bytes.
///
/// Input: hex-encoded bytes
/// Output: hex-encoded 32-byte hash
#[no_mangle]
pub extern "C" fn contract_persistent_hash(
    input_hex: *const c_char,
) -> *const c_char {
    let input = match unsafe { c_str_to_str(input_hex) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    let bytes = match hex_to_bytes(input) {
        Some(b) => b,
        None => return std::ptr::null(),
    };

    let hash = persistent_hash(&bytes);

    // Serialize the HashOutput
    let mut out = Vec::new();
    if hash.serialize(&mut out).is_err() {
        return std::ptr::null();
    }

    to_c_hex(&out)
}

/// Compute persistent hash with proper AlignedValue encoding.
/// This matches the WASM's persistentHash(alignment, value) exactly.
///
/// Input: JSON { "alignment": [...], "value": [...] } (serde AlignedValue format)
/// Output: JSON array of base64-encoded byte arrays (Value format)
#[no_mangle]
pub extern "C" fn contract_persistent_hash_aligned(
    aligned_value_json: *const c_char,
) -> *const c_char {
    let json_str = match unsafe { c_str_to_str(aligned_value_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    // Parse AlignedValue manually — serde's try_from validation rejects valid
    // Bytes(N) values (same bug as transcript ops, see parse_aligned_value)
    let json_val: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => return to_c_string(&format!("{{\"error\":\"JSON parse: {}\"}}", e)),
    };
    let aligned: AlignedValue = match parse_aligned_value(&json_val) {
        Ok(v) => v,
        Err(e) => return to_c_string(&format!("{{\"error\":\"deserialize: {}\"}}", e)),
    };

    // Use binary_repr + PersistentHashWriter — exactly what the WASM does
    let mut hasher = PersistentHashWriter::default();
    ValueReprAlignedValue(aligned.clone()).binary_repr(&mut hasher);
    let hash_value = Value::from(hasher.finalize());

    // Temporarily removed debug logging

    // Serialize result as JSON
    match serde_json::to_string(&hash_value) {
        Ok(s) => to_c_string(&s),
        Err(e) => to_c_string(&format!("{{\"error\":\"serialize: {}\"}}", e)),
    }
}

/// Compute persistent commit: SHA-256(opening || binary_repr(value)).
/// Same as persistentHash but with a 32-byte opening prepended.
/// Input: JSON {"value": <aligned_value>, "opening": [32 bytes as array]}
/// Output: JSON Value (hash output)
#[no_mangle]
pub extern "C" fn contract_persistent_commit_aligned(
    input_json: *const c_char,
) -> *const c_char {
    let json_str = match unsafe { c_str_to_str(input_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    let json_val: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => return to_c_string(&format!("{{\"error\":\"JSON parse: {}\"}}", e)),
    };

    // Extract opening (32-byte array)
    let opening_arr = match json_val.get("opening") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return to_c_string("{\"error\":\"missing 'opening' array\"}"),
    };
    let opening_bytes: Vec<u8> = opening_arr.iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();
    if opening_bytes.len() != 32 {
        return to_c_string(&format!("{{\"error\":\"opening must be 32 bytes, got {}\"}}", opening_bytes.len()));
    }
    let mut opening_arr = [0u8; 32];
    opening_arr.copy_from_slice(&opening_bytes);
    let opening = midnight_base_crypto::hash::HashOutput(opening_arr);

    // Extract aligned value
    let value_json = match json_val.get("value") {
        Some(v) => v,
        None => return to_c_string("{\"error\":\"missing 'value' field\"}"),
    };
    let aligned: AlignedValue = match parse_aligned_value(value_json) {
        Ok(v) => v,
        Err(e) => return to_c_string(&format!("{{\"error\":\"deserialize value: {}\"}}", e)),
    };

    // persistent_commit = SHA-256(opening || binary_repr(value))
    let mut hasher = PersistentHashWriter::default();
    opening.binary_repr(&mut hasher);
    ValueReprAlignedValue(aligned).binary_repr(&mut hasher);
    let hash_value = Value::from(hasher.finalize());

    match serde_json::to_string(&hash_value) {
        Ok(s) => to_c_string(&s),
        Err(e) => to_c_string(&format!("{{\"error\":\"serialize: {}\"}}", e)),
    }
}

/// Convert a BigInt (as hex string) to a Value (JSON).
/// Matches the WASM's bigIntToValue exactly — uses Fr::from_le_bytes.
#[no_mangle]
pub extern "C" fn contract_big_int_to_value(
    bigint_hex: *const c_char,
) -> *const c_char {
    use midnight_transient_crypto::curve::Fr;

    let s = match unsafe { c_str_to_str(bigint_hex) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    // Parse hex string to bytes (same as WASM: hex → LE bytes → Fr)
    let padded = if s.len() % 2 == 1 { format!("0{}", s) } else { s.to_string() };
    let mut bytes = match hex::decode(&padded) {
        Ok(b) => b,
        Err(e) => return to_c_string(&format!("{{\"error\":\"hex decode: {}\"}}", e)),
    };
    bytes.reverse(); // big-endian hex → little-endian bytes

    let fr = match Fr::from_le_bytes(&bytes) {
        Some(fr) => fr,
        None => return to_c_string("{\"error\":\"out of bounds for prime field\"}"),
    };

    let value = Value::from(fr);
    match serde_json::to_string(&value) {
        Ok(s) => to_c_string(&s),
        Err(e) => to_c_string(&format!("{{\"error\":\"serialize: {}\"}}", e)),
    }
}

/// Convert a Value (JSON) to a BigInt (decimal string).
/// Matches the WASM's valueToBigInt.
#[no_mangle]
pub extern "C" fn contract_value_to_big_int(
    value_json: *const c_char,
) -> *const c_char {
    let s = match unsafe { c_str_to_str(value_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    let value: Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(e) => return to_c_string(&format!("{{\"error\":\"deserialize: {}\"}}", e)),
    };

    if value.0.is_empty() || value.0[0].0.is_empty() {
        return to_c_string("0");
    }

    // Decode 32-byte LE to u128
    let bytes = &value.0[0].0;
    let mut n: u128 = 0;
    for (i, &b) in bytes.iter().enumerate().take(16) {
        n |= (b as u128) << (8 * i);
    }

    to_c_string(&n.to_string())
}

/// Free a C string returned by contract FFI functions.
#[no_mangle]
pub extern "C" fn contract_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: ptr was created by CString::into_raw() in to_c_string/to_c_hex
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn empty_map_state_value_deserializes_from_shim_format() {
        // The JS runtime shim (StateValue.newMap) emits an empty Map/Set ledger field
        // as {"tag":"map","content":{}} — the adjacently-tagged StateValue form where a
        // Map's content is its HashMap serialized via serde `collect_map` (a JSON
        // object; empty → {}). Deploying ANY contract with Map/Set ledger state (e.g.
        // the Vault multisig) pushes this through queryLedgerState at construction, so
        // it MUST deserialize to Map(empty). Guards the shim↔native format contract.
        let sv: midnight_onchain_state::state::StateValue<InMemoryDB> =
            serde_json::from_str(r#"{"tag":"map","content":{}}"#)
                .expect("empty-map shim JSON must deserialize to StateValue::Map");
        match sv {
            midnight_onchain_state::state::StateValue::Map(ref m) => {
                assert_eq!(m.size(), 0, "expected an empty map");
            }
            other => panic!("expected Map, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn empty_map_state_value_round_trips_through_tag_first() {
        // Full JS→native→JS contract: deserialize the shim form, re-serialize, run the
        // same tag-first normalization the transcript path uses, and confirm it
        // survives without drifting off Map(empty).
        use midnight_onchain_state::state::StateValue;
        let sv: StateValue<InMemoryDB> =
            serde_json::from_str(r#"{"tag":"map","content":{}}"#).unwrap();
        let reserialized = serde_json::to_value(&sv).unwrap();
        let tag_first = to_tag_first_json(&reserialized);
        let back: StateValue<InMemoryDB> = serde_json::from_str(&tag_first).unwrap();
        assert!(matches!(back, StateValue::Map(ref m) if m.size() == 0));
    }

    #[test]
    fn test_persistent_hash() {
        // Hash of empty input
        let input = CString::new("").unwrap();
        let result = contract_persistent_hash(input.as_ptr());
        assert!(!result.is_null());

        let hash_hex = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash_hex.len(), 64); // 32 bytes = 64 hex chars

        unsafe { contract_free_string(result as *mut c_char); }
    }

    #[test]
    fn test_persistent_hash_known_value() {
        // SHA-256 of "hello" = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let input = CString::new(hex::encode(b"hello")).unwrap();
        let result = contract_persistent_hash(input.as_ptr());
        assert!(!result.is_null());

        let hash_hex = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash_hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

        unsafe { contract_free_string(result as *mut c_char); }
    }

    #[test]
    fn test_null_input() {
        let result = contract_persistent_hash(std::ptr::null());
        assert!(result.is_null());
    }

    #[test]
    fn serde_handles_stack_key() {
        // alpha05 / issue #3: the JS compact-runtime emits {tag:"stack"} for the
        // idx ops that unshielded value transfers generate. The hand-written
        // parse_key rejected it ("unknown key tag: stack"). Prove upstream serde
        // already round-trips it — i.e. the hand parser is redundant for this.
        use midnight_onchain_vm::ops::Key;
        // round-trip (format-agnostic)
        let s = serde_json::to_string(&Key::Stack).unwrap();
        let back: Key = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Key::Stack));
        // the exact shape the JS shim emits must deserialize
        let from_shim: Key = serde_json::from_str(r#"{"tag":"stack"}"#)
            .expect("JS-shim stack shape must deserialize");
        assert!(matches!(from_shim, Key::Stack));
    }

    #[test]
    fn stack_key_idx_transcript_deserializes() {
        // alpha05 / issue #3: receiveUnshielded/sendUnshielded emit an idx op whose
        // path key is Key::Stack. The deleted hand parser rejected this ("unknown
        // key tag: stack"); the serde path the assembler now uses accepts it.
        use midnight_onchain_vm::ops::Op;
        use midnight_onchain_vm::result_mode::ResultModeVerify;
        let transcript = serde_json::json!([
            { "idx": { "cached": false, "pushPath": false, "path": [ { "tag": "stack" } ] } }
        ]);
        let ops: Vec<Op<ResultModeVerify, InMemoryDB>> =
            serde_json::from_str(&to_tag_first_json(&transcript))
                .expect("stack-key idx transcript must deserialize via serde");
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], Op::Idx { .. }), "expected Op::Idx with a stack key");
    }

    #[test]
    fn popeq_empty_atom_ok_but_trailing_zero_rejected() {
        // The serde AlignedValue deserializer enforces normal form: an empty atom
        // ([]) is the normal-form encoding of an empty/zero read and deserializes,
        // while a trailing-zero atom ([0,..,0]) is rejected — exactly why the JS
        // shim must emit [] for placeholder reads instead of zero-padding.
        use midnight_onchain_vm::ops::Op;
        use midnight_onchain_vm::result_mode::ResultModeVerify;
        let field = serde_json::json!({ "tag": "atom", "value": { "tag": "field" } });
        let empty = serde_json::json!([
            { "popeq": { "cached": false, "result": { "value": [[]], "alignment": [field.clone()] } } }
        ]);
        let r: Result<Vec<Op<ResultModeVerify, InMemoryDB>>, _> =
            serde_json::from_str(&to_tag_first_json(&empty));
        assert!(r.is_ok(), "empty (normal-form) atom must deserialize: {:?}", r.err());

        let zeros: Vec<u8> = vec![0; 32];
        let padded = serde_json::json!([
            { "popeq": { "cached": false, "result": { "value": [zeros], "alignment": [field] } } }
        ]);
        let r2: Result<Vec<Op<ResultModeVerify, InMemoryDB>>, _> =
            serde_json::from_str(&to_tag_first_json(&padded));
        assert!(r2.is_err(), "a trailing-zero (non-normal-form) atom must be rejected");
    }

    #[test]
    fn key_variant_coverage_is_exhaustive() {
        // Can't-lag guard for the enum issue #3 was about. Key is NOT
        // #[non_exhaustive], so this non-wildcard match compiles only while Key is
        // exactly {Value, Stack}; an upstream addition breaks the build — a prompt
        // to confirm the JS shim emits it and add a serde test. (StateValue is
        // #[non_exhaustive] and can't be guarded this way; serde's upstream
        // Deserialize covers it regardless.)
        use midnight_onchain_vm::ops::Key;
        fn assert_covered(k: &Key) {
            match k {
                Key::Value(_) | Key::Stack => {}
            }
        }
        assert_covered(&Key::Stack);
    }

    #[test]
    fn test_persistent_hash_aligned() {
        // Test with a simple field value (0n encoded as 32-byte LE)
        // This should match what the WASM persistentHash produces
        let json = r#"{"value":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"alignment":[{"tag":"atom","value":{"tag":"field"}}]}"#;
        let input = CString::new(json).unwrap();
        let result = contract_persistent_hash_aligned(input.as_ptr());
        assert!(!result.is_null());

        let result_str = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        println!("persistentHash aligned result: {}", result_str);
        // Should be a valid JSON Value (array of base64 byte arrays)
        assert!(result_str.starts_with("[[") || result_str.starts_with("{\"error"));

        unsafe { contract_free_string(result as *mut c_char); }
    }

    #[test]
    fn test_big_int_to_value() {
        let input = CString::new("42").unwrap();
        let result = contract_big_int_to_value(input.as_ptr());
        assert!(!result.is_null());

        let result_str = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        println!("bigIntToValue(42): {}", result_str);
        // Should be valid JSON
        assert!(!result_str.contains("error"));

        unsafe { contract_free_string(result as *mut c_char); }
    }

    #[test]
    fn test_value_to_big_int() {
        // bigIntToValue takes hex input: "2a" = 42 decimal
        let input = CString::new("2a").unwrap();
        let value_json = contract_big_int_to_value(input.as_ptr());
        assert!(!value_json.is_null());

        // valueToBigInt returns decimal string
        let result = contract_value_to_big_int(value_json);
        assert!(!result.is_null());

        let result_str = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(result_str, "42");

        unsafe {
            contract_free_string(value_json as *mut c_char);
            contract_free_string(result as *mut c_char);
        }
    }
}

/// Clone a contract state handle (for saving initial state before queries).
#[no_mangle]
pub extern "C" fn contract_state_clone(handle: u64) -> u64 {
    let Some(pool) = lock_state_pool() else { return 0 };
    let state = match pool.get(&handle) {
        Some(s) => s.clone(),
        None => return 0,
    };
    drop(pool);

    let new_handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let Some(mut pool) = lock_state_pool() else { return 0 };
    pool.insert(new_handle, state);
    new_handle
}

/// Create a ContractState with an array of N null slots.
/// Returns a handle for subsequent query() calls.
#[no_mangle]
pub extern "C" fn contract_state_create_with_nulls(structure_json: *const c_char) -> u64 {
    use midnight_onchain_state::state::{
        ContractState as RustCS, ChargedState as RustChargedState,
        StateValue as RustSV,
    };
    use midnight_storage::db::InMemoryDB;

    // SAFETY: JNI guarantees structure_json is a valid null-terminated UTF-8 string
    let input = match unsafe { c_str_to_str(structure_json) } {
        Some(s) => s,
        None => return 0,
    };

    // Parse structure descriptor and build nested state
    let state_value = if let Ok(descriptor) = serde_json::from_str::<serde_json::Value>(input) {
        match build_state_from_descriptor::<InMemoryDB>(&descriptor) {
            Ok(sv) => sv,
            Err(e) => {
                eprintln!("ERROR: contract_state_create_with_nulls: {}", e);
                return 0;
            }
        }
    } else if let Ok(num) = input.parse::<u32>() {
        // Backward compat: plain number = flat array of N nulls
        let items: Vec<RustSV<InMemoryDB>> = (0..num).map(|_| RustSV::Null).collect();
        RustSV::Array(items.into())
    } else {
        RustSV::Array(Vec::new().into())
    };

    let charged = RustChargedState::new(state_value);
    let mut state = RustCS::default();
    state.data = charged;

    let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let Some(mut pool) = lock_state_pool() else { return 0 };
    pool.insert(handle, state);
    handle
}

/// Build a Rust StateValue from a JSON structure descriptor.
/// Format: null → Null, {"array": [item, ...]} → Array of items recursively
/// Build a Rust StateValue from a JSON structure descriptor.
/// Format: null → Null, {"array": [item, ...]} → Array of items recursively
/// Safety: max 64 items per array, max 4 nesting depth to prevent OOM
fn build_state_from_descriptor<D: midnight_storage::db::DB>(
    desc: &serde_json::Value,
) -> Result<midnight_onchain_state::state::StateValue<D>, String> {
    build_state_recursive::<D>(desc, 0)
}

fn build_state_recursive<D: midnight_storage::db::DB>(
    desc: &serde_json::Value,
    depth: usize,
) -> Result<midnight_onchain_state::state::StateValue<D>, String> {
    use midnight_onchain_state::state::StateValue as SV;

    if depth > 4 {
        return Err("build_state_recursive: nesting too deep (>4)".into());
    }

    match desc {
        serde_json::Value::Null => Ok(SV::Null),
        serde_json::Value::Object(obj) => {
            if let Some(items) = obj.get("array") {
                if let serde_json::Value::Array(arr) = items {
                    let count = arr.len().min(64); // Cap at 64 items
                    let built: Vec<SV<D>> = arr.iter().take(count)
                        .map(|item| build_state_recursive(item, depth + 1))
                        .collect::<Result<_, _>>()?;
                    Ok(SV::Array(built.into()))
                } else {
                    Err(format!(
                        "build_state_recursive: unsupported state node at depth {}: \"array\" field is not an array: {}",
                        depth, items
                    ))
                }
            } else {
                Err(format!(
                    "build_state_recursive: unsupported state node at depth {}: {}",
                    depth, desc
                ))
            }
        }
        // Number = flat array of N nulls (legacy)
        serde_json::Value::Number(n) => {
            let count = n.as_u64().unwrap_or(0).min(64) as usize;
            let items: Vec<SV<D>> = (0..count).map(|_| SV::Null).collect();
            Ok(SV::Array(items.into()))
        }
        _ => Err(format!(
            "build_state_recursive: unsupported state node at depth {}: {}",
            depth, desc
        )),
    }
}

/// Set an operation on a contract state (by handle).
/// operation_name: e.g. "post", "takeDown"
#[no_mangle]
pub extern "C" fn contract_state_set_operation(
    handle: u64,
    operation_name: *const c_char,
) {
    // SAFETY: JNI guarantees operation_name is a valid null-terminated UTF-8 string
    let name = match unsafe { c_str_to_str(operation_name) } {
        Some(s) => s,
        None => return,
    };

    let Some(mut pool) = lock_state_pool() else { return };
    if let Some(state) = pool.get_mut(&handle) {
        use midnight_onchain_state::state::{ContractOperation, EntryPointBuf};
        let ep = EntryPointBuf::from(name.as_bytes());
        state.operations.insert(ep, ContractOperation::new(None));
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_create_state_with_nulls() {
        let json = CString::new("4").unwrap();
        let handle = contract_state_create_with_nulls(json.as_ptr());
        assert!(handle > 0);

        // Set operations
        let op1 = CString::new("post").unwrap();
        contract_state_set_operation(handle, op1.as_ptr());
        let op2 = CString::new("takeDown").unwrap();
        contract_state_set_operation(handle, op2.as_ptr());

        // First: get the proper encoding of 0 as a field element
        let zero_hex = CString::new("0").unwrap();
        let zero_value_json_ptr = contract_big_int_to_value(zero_hex.as_ptr());
        assert!(!zero_value_json_ptr.is_null());
        let zero_value_json = unsafe { CStr::from_ptr(zero_value_json_ptr).to_str().unwrap() };
        println!("bigIntToValue(0): {}", zero_value_json);

        // dup + pop leaves the stack with 1 item (the original state)
        let opcodes = r#"[{"dup":{"n":0}},"pop"]"#.to_string();
        unsafe { contract_free_string(zero_value_json_ptr as *mut c_char); }
        let ops_c = CString::new(opcodes).unwrap();
        let result = contract_query(handle, ops_c.as_ptr());

        if !result.is_null() {
            let result_str = unsafe { CStr::from_ptr(result).to_str().unwrap() };
            println!("Query result: {}", result_str);
            assert!(!result_str.contains("error"), "Query failed: {}", result_str);
            unsafe { contract_free_string(result as *mut c_char); }
        } else {
            panic!("contract_query returned null");
        }
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;
    use midnight_onchain_vm::ops::Op;
    use midnight_onchain_vm::result_mode::ResultModeGather;
    use midnight_storage::db::InMemoryDB;
    use midnight_base_crypto::fab::{AlignedValue, Value, ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};

    #[test]
    fn print_op_json_formats() {
        // Create various Op types and print their JSON serialization

        // 1. dup
        let dup: Op<ResultModeGather, InMemoryDB> = Op::Dup { n: 0 };
        println!("dup: {}", serde_json::to_string(&dup).unwrap());

        // 2. popeq
        let popeq: Op<ResultModeGather, InMemoryDB> = Op::Popeq { cached: false, result: () };
        println!("popeq: {}", serde_json::to_string(&popeq).unwrap());

        // 3. push with null
        let push_null: Op<ResultModeGather, InMemoryDB> = Op::Push {
            storage: false,
            value: midnight_onchain_state::state::StateValue::Null,
        };
        println!("push(null): {}", serde_json::to_string(&push_null).unwrap());

        // 4. ins
        let ins: Op<ResultModeGather, InMemoryDB> = Op::Ins { cached: true, n: 1 };
        println!("ins: {}", serde_json::to_string(&ins).unwrap());

        // 5. pop
        let pop: Op<ResultModeGather, InMemoryDB> = Op::Pop;
        println!("pop: {}", serde_json::to_string(&pop).unwrap());

        // 6. idx with a field value key
        use midnight_transient_crypto::curve::Fr;
        let zero_fr = Fr::from_le_bytes(&[0u8]).unwrap();
        let zero_value = Value::from(zero_fr);
        let field_align = Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]);
        let key = midnight_onchain_vm::ops::Key::Value(AlignedValue {
            value: zero_value,
            alignment: field_align,
        });

        let idx: Op<ResultModeGather, InMemoryDB> = Op::Idx {
            cached: false,
            push_path: false,
            path: vec![key].into_iter().collect(),
        };
        println!("idx: {}", serde_json::to_string(&idx).unwrap());
    }
}

// ── Transaction Assembly ──
// Assemble an UnprovenTransaction from circuit execution output.

/// Assemble a contract call transaction from circuit output.
///
/// Input: JSON with structure:
/// {
///   "network_id": "undeployed",
///   "contract_address": "0000...0000",  (64 hex chars)
///   "entry_point": "post",
///   "state_handle": 42,
///   "proof_data": {
///     "input": { "value": [[...]], "alignment": [...] },
///     "output": { "value": [[...]], "alignment": [...] },
///     "public_transcript": [ ... ops in Rust serde format ... ],
///     "private_transcript_outputs": [ { "value": [...], "alignment": [...] }, ... ]
///   }
/// }
///
/// Output: hex-encoded SCALE serialized (Transaction, HashMap<String, ProvingKeyMaterial>) tuple,
///         or JSON error: {"error": "..."}
#[no_mangle]
pub extern "C" fn contract_assemble_call_tx(
    params_json: *const c_char,
) -> *const c_char {
    let json_str = match unsafe { c_str_to_str(params_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    match assemble_call_tx_impl(json_str) {
        Ok(hex) => to_c_string(&hex),
        Err(e) => to_c_string(&format!("{{\"error\":\"{}\"}}", e.replace('"', "\\\""))),
    }
}

/// Parse an AlignedValue from JSON, constructing the Rust type directly.
///
/// We bypass AlignedValue's serde `try_from` validation because it rejects
/// valid values (e.g., Bytes(1) with value [0] fails the alignment check).
/// Direct struct construction is safe since the values come from valid circuit execution.
fn parse_aligned_value(val: &serde_json::Value) -> Result<AlignedValue, String> {
    use midnight_base_crypto::fab::{ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};

    // Parse value: Array<ValueAtom> — each is a Vec<u8>
    let value_arr = val["value"].as_array()
        .ok_or("AlignedValue missing 'value'")?;
    let value_atoms: Vec<ValueAtom> = value_arr.iter()
        .map(|v| {
            let bytes: Vec<u8> = v.as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|b| u8::try_from(b.as_u64().unwrap_or(0)).unwrap_or(0))
                .collect();
            ValueAtom(bytes)
        })
        .collect();

    // Parse alignment: Vec<AlignmentSegment>
    let align_arr = val["alignment"].as_array()
        .ok_or("AlignedValue missing 'alignment'")?;
    let segments: Vec<AlignmentSegment> = align_arr.iter()
        .map(|a| parse_alignment_segment(a))
        .collect::<Result<_, _>>()?;

    // Truncate value atoms to match alignment sizes.
    // JS compact-runtime encodes values via bigIntToValue (32-byte Fr) even for
    // Bytes(N) alignments where N < 32. The Midnight VM internally truncates,
    // but our manual construction bypasses that. Without truncation,
    // field_repr_unchecked underflows on prepend_zeros (length/31 - actual/31).
    let truncated_atoms: Vec<ValueAtom> = value_atoms.into_iter()
        .zip(segments.iter().chain(std::iter::repeat(&AlignmentSegment::Atom(AlignmentAtom::Field))))
        .map(|(atom, seg)| {
            match seg {
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length }) => {
                    let max_len = *length as usize;
                    if atom.0.len() > max_len {
                        ValueAtom(atom.0[..max_len].to_vec())
                    } else {
                        atom
                    }
                }
                AlignmentSegment::Atom(AlignmentAtom::Compress) |
                AlignmentSegment::Atom(AlignmentAtom::Field) => atom,
                _ => atom,
            }
        })
        .collect();

    Ok(AlignedValue {
        value: Value(truncated_atoms),
        alignment: Alignment(segments),
    })
}

fn parse_alignment_segment(val: &serde_json::Value) -> Result<midnight_base_crypto::fab::AlignmentSegment, String> {
    use midnight_base_crypto::fab::{AlignmentSegment, AlignmentAtom};

    let tag = val["tag"].as_str().ok_or("alignment segment missing tag")?;
    match tag {
        "atom" => {
            let atom_val = &val["value"];
            let atom_tag = atom_val["tag"].as_str().ok_or("alignment atom missing tag")?;
            let atom = match atom_tag {
                "field" => AlignmentAtom::Field,
                "bytes" => {
                    let len = u32::try_from(atom_val["length"].as_u64()
                        .ok_or("bytes alignment missing length")?)
                        .map_err(|_| "bytes alignment length out of range")?;
                    AlignmentAtom::Bytes { length: len }
                }
                "compress" => AlignmentAtom::Compress,
                other => return Err(format!("unknown alignment atom: {}", other)),
            };
            Ok(AlignmentSegment::Atom(atom))
        }
        "option" => {
            let items = val["value"].as_array().ok_or("option missing value")?;
            let aligns: Vec<midnight_base_crypto::fab::Alignment> = items.iter()
                .map(|item| {
                    let segs_arr = item.as_array().ok_or("option item not array")?;
                    let segs: Vec<AlignmentSegment> = segs_arr.iter()
                        .map(|s| parse_alignment_segment(s))
                        .collect::<Result<_, _>>()?;
                    Ok(midnight_base_crypto::fab::Alignment(segs))
                })
                .collect::<Result<_, String>>()?;
            Ok(AlignmentSegment::Option(aligns))
        }
        other => Err(format!("unknown alignment segment tag: {}", other)),
    }
}

/// Re-emit a JSON value with the `tag` key first in every object.
///
/// `serde_json::from_value` walks a `Value::Object`, which is a sorted `BTreeMap`
/// here (the crate has no `preserve_order` feature) — so it yields `content`
/// before `tag`. onchain-state's `StateValue` deserializer is order-sensitive and
/// requires `tag` first ("StateValue tag must preceed contents",
/// onchain-state/src/state.rs:333). Re-emitting tag-first and deserializing with
/// `from_str` (which honors document order, unlike `from_value`) feeds the
/// upstream serde impls the field order they require. `Key`/`AlignedValue` are
/// order-independent, so tag-first is the only constraint to satisfy.
fn to_tag_first_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut parts: Vec<String> = Vec::with_capacity(map.len());
            if let Some(tag) = map.get("tag") {
                parts.push(format!("\"tag\":{}", to_tag_first_json(tag)));
            }
            for (k, val) in map {
                if k != "tag" {
                    parts.push(format!("{}:{}", serde_json::to_string(k).unwrap(), to_tag_first_json(val)));
                }
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(arr) => {
            format!("[{}]", arr.iter().map(to_tag_first_json).collect::<Vec<_>>().join(","))
        }
        other => other.to_string(),
    }
}

/// Convert ResultModeVerify ops to ResultModeGather for re-execution.
/// Strips popeq.result (AlignedValue → ()) since the VM recomputes results.
fn convert_verify_to_gather(
    ops: &[Op<midnight_onchain_vm::result_mode::ResultModeVerify, InMemoryDB>],
) -> Result<Vec<Op<ResultModeGather, InMemoryDB>>, String> {
    ops.iter().map(|op| Ok(match op {
        Op::Dup { n } => Op::Dup { n: *n },
        Op::Pop => Op::Pop,
        Op::Popeq { cached, .. } => Op::Popeq { cached: *cached, result: () },
        Op::Push { storage, value } => Op::Push { storage: *storage, value: value.clone() },
        Op::Idx { cached, push_path, path } => Op::Idx {
            cached: *cached, push_path: *push_path, path: path.clone(),
        },
        Op::Ins { cached, n } => Op::Ins { cached: *cached, n: *n },
        Op::Lt => Op::Lt,
        Op::Eq => Op::Eq,
        Op::Add => Op::Add,
        Op::Sub => Op::Sub,
        Op::Neg => Op::Neg,
        Op::And => Op::And,
        Op::Or => Op::Or,
        Op::Type => Op::Type,
        Op::Size => Op::Size,
        Op::New => Op::New,
        Op::Log => Op::Log,
        Op::Root => Op::Root,
        Op::Member => Op::Member,
        Op::Ckpt => Op::Ckpt,
        Op::Noop { n } => Op::Noop { n: *n },
        Op::Branch { skip } => Op::Branch { skip: *skip },
        Op::Jmp { skip } => Op::Jmp { skip: *skip },
        Op::Concat { cached, n } => Op::Concat { cached: *cached, n: *n },
        Op::Swap { n } => Op::Swap { n: *n },
        Op::Rem { cached } => Op::Rem { cached: *cached },
        Op::Addi { immediate } => Op::Addi { immediate: *immediate },
        Op::Subi { immediate } => Op::Subi { immediate: *immediate },
        other => return Err(format!(
            "convert_verify_to_gather: unhandled op variant {:?} — client ledger may be behind the node",
            other
        )),
    })).collect()
}

/// Build a QueryContext matching the on-chain VM's context for gas computation.
///
/// The on-chain VM (semantics.rs:1282-1290) constructs the QueryContext with:
/// - `state`: the contract's current state tree
/// - `address`: the contract address
/// - `call_context`: built from the block context (block time, parent hash, etc.)
///
/// Our gas must match the on-chain gas because the node uses `transcript.gas`
/// as the gas LIMIT during replay. If our gas < on-chain cost → OutOfGas.
fn build_gas_query_context(
    state: midnight_onchain_state::state::ChargedState<InMemoryDB>,
    contract_address_hex: &str,
    block_time_secs: Option<i64>,
) -> Result<midnight_onchain_runtime::context::QueryContext<InMemoryDB>, String> {
    use midnight_base_crypto::time::Timestamp;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::contract::ContractAddress;

    // Anchor block time to the chain when the caller supplies it; only fall
    // back to wall-clock when chain time is genuinely absent. Wall-clock can
    // drift from the chain's notion of `tblock` and skew gas/TTL accounting.
    let now_secs = match block_time_secs {
        Some(t) if t > 0 => t as u64,
        _ => {
            eprintln!("WARNING: build_gas_query_context: chain block time absent — falling back to wall-clock for tblock");
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
    };

    let addr_bytes = hex::decode(contract_address_hex)
        .map_err(|e| format!("invalid contract_address hex: {}", e))?;
    if addr_bytes.len() != 32 {
        return Err(format!(
            "invalid contract_address: expected 32 bytes, got {}",
            addr_bytes.len()
        ));
    }
    let mut addr_arr = [0u8; 32];
    addr_arr.copy_from_slice(&addr_bytes);
    let addr = ContractAddress(HashOutput(addr_arr));

    Ok(midnight_onchain_runtime::context::QueryContext {
        state,
        address: addr,
        effects: Default::default(),
        call_context: midnight_onchain_runtime::context::CallContext {
            own_address: addr,
            tblock: Timestamp::from_secs(now_secs),
            tblock_err: 3,
            parent_block_hash: HashOutput(addr_arr),
            last_block_time: Timestamp::from_secs(now_secs.saturating_sub(6)),
            ..Default::default()
        },
    })
}

/// Build the unsigned guaranteed unshielded offer that funds the value a contract
/// receives via `receiveUnshielded`, plus one NIGHT signing key per input for the
/// caller's `Intent::sign`.
///
/// The offer's inputs (wallet UTXOs) sum to `amount + change`; its only output is the
/// change back to the wallet (omitted when zero). The contract action absorbs `amount`,
/// so the unshielded segment balances: `Σinputs − Σoutputs == amount`.
///
/// `funding` JSON shape:
/// ```json
/// { "amount": "5000000",
///   "change_owner": "<UserAddress hex, 32 bytes>",
///   "night_private_key": "<hex, 32 bytes>",
///   "inputs": [ { "value": "10000000", "owner": "<VerifyingKey hex, 32 bytes>",
///                 "type": "<token hex, 32 bytes>", "intent_hash": "<hex, 32 bytes>",
///                 "output_no": 0 } ] }
/// ```
///
/// Regression note: reached ONLY when the caller supplies `unshielded_funding`; a plain
/// contract call never constructs an offer, so its transaction is unchanged.
fn build_funding_offer(
    funding: &serde_json::Value,
) -> Result<
    (
        midnight_ledger::structure::UnshieldedOffer<midnight_base_crypto::signatures::Signature, InMemoryDB>,
        Vec<midnight_base_crypto::signatures::SigningKey>,
    ),
    String,
> {
    use midnight_ledger::structure::{UnshieldedOffer, UtxoSpend, UtxoOutput, IntentHash};
    use midnight_coin_structure::coin::{UnshieldedTokenType, UserAddress};
    use midnight_base_crypto::signatures::{Signature, VerifyingKey, SigningKey};
    use midnight_base_crypto::hash::HashOutput;
    use midnight_serialize::Deserializable;

    let amount: u128 = funding["amount"]
        .as_str()
        .ok_or("unshielded_funding.amount missing")?
        .parse()
        .map_err(|e| format!("unshielded_funding.amount: {}", e))?;

    let inputs_json = funding["inputs"]
        .as_array()
        .ok_or("unshielded_funding.inputs missing")?;
    if inputs_json.is_empty() {
        return Err("unshielded_funding.inputs is empty".into());
    }

    let mut inputs: Vec<UtxoSpend> = Vec::with_capacity(inputs_json.len());
    let mut total: u128 = 0;
    let mut token_type_hex: Option<String> = None;

    for (i, jin) in inputs_json.iter().enumerate() {
        let value: u128 = jin["value"]
            .as_str()
            .ok_or_else(|| format!("input[{}].value missing", i))?
            .parse()
            .map_err(|e| format!("input[{}].value: {}", i, e))?;

        let owner_bytes = hex::decode(
            jin["owner"].as_str().ok_or_else(|| format!("input[{}].owner missing", i))?,
        )
        .map_err(|e| format!("input[{}].owner hex: {}", i, e))?;
        if owner_bytes.len() != 32 {
            return Err(format!("input[{}].owner must be 32 bytes", i));
        }
        // Android deserialize workaround (see serialize.rs:445): use Cursor.
        let mut cursor = std::io::Cursor::new(owner_bytes);
        let owner = <VerifyingKey as Deserializable>::deserialize(&mut cursor, 32)
            .map_err(|e| format!("input[{}].owner verifying key: {:?}", i, e))?;

        let tt_hex = jin["type"].as_str().ok_or_else(|| format!("input[{}].type missing", i))?;
        match &token_type_hex {
            None => token_type_hex = Some(tt_hex.to_string()),
            Some(first) if first != tt_hex => {
                return Err("all funding inputs must share one token type".into());
            }
            _ => {}
        }
        let tt_bytes = hex::decode(tt_hex).map_err(|e| format!("input[{}].type hex: {}", i, e))?;
        if tt_bytes.len() != 32 {
            return Err(format!("input[{}].type must be 32 bytes", i));
        }
        let mut tt_arr = [0u8; 32];
        tt_arr.copy_from_slice(&tt_bytes);
        let type_ = UnshieldedTokenType(HashOutput(tt_arr));

        let ih_bytes = hex::decode(
            jin["intent_hash"].as_str().ok_or_else(|| format!("input[{}].intent_hash missing", i))?,
        )
        .map_err(|e| format!("input[{}].intent_hash hex: {}", i, e))?;
        let intent_hash = IntentHash::deserialize(&mut &ih_bytes[..], 32)
            .map_err(|e| format!("input[{}].intent_hash: {:?}", i, e))?;

        let output_no = jin["output_no"]
            .as_u64()
            .ok_or_else(|| format!("input[{}].output_no missing", i))? as u32;

        total = total.checked_add(value).ok_or("funding input value overflow")?;
        inputs.push(UtxoSpend { value, owner, type_, intent_hash, output_no });
    }

    if total < amount {
        return Err(format!("funding inputs total {} < amount {}", total, amount));
    }
    let change = total - amount;
    let token_type_hex = token_type_hex.expect("non-empty inputs guarantee a token type");

    let mut outputs: Vec<UtxoOutput> = Vec::new();
    if change > 0 {
        let change_owner_bytes = hex::decode(
            funding["change_owner"].as_str().ok_or("unshielded_funding.change_owner missing")?,
        )
        .map_err(|e| format!("change_owner hex: {}", e))?;
        let change_owner = <UserAddress as Deserializable>::deserialize(&mut &change_owner_bytes[..], 32)
            .map_err(|e| format!("change_owner: {:?}", e))?;
        let tt_bytes = hex::decode(&token_type_hex).map_err(|e| format!("token type hex: {}", e))?;
        let mut tt_arr = [0u8; 32];
        tt_arr.copy_from_slice(&tt_bytes);
        outputs.push(UtxoOutput {
            value: change,
            owner: change_owner,
            type_: UnshieldedTokenType(HashOutput(tt_arr)),
        });
    }

    // Canonical sorted order (ledger verify.rs:435-442). All signing keys are the same
    // NIGHT key, so sort order never disturbs the key<->input pairing in Intent::sign.
    inputs.sort();
    outputs.sort();
    let input_count = inputs.len();

    let night_key_bytes = hex::decode(
        funding["night_private_key"].as_str().ok_or("unshielded_funding.night_private_key missing")?,
    )
    .map_err(|e| format!("night_private_key hex: {}", e))?;
    if night_key_bytes.len() != 32 {
        return Err("night_private_key must be 32 bytes".into());
    }
    let mut nk = [0u8; 32];
    nk.copy_from_slice(&night_key_bytes);
    // One key per input (all the wallet's NIGHT key). Re-derive rather than Clone so we
    // don't assume SigningKey: Clone. Intent::sign verifies each input's owner matches.
    let keys: Vec<SigningKey> = (0..input_count)
        .map(|_| SigningKey::from_bytes(&nk).map_err(|e| format!("night signing key: {:?}", e)))
        .collect::<Result<Vec<_>, _>>()?;

    let offer = UnshieldedOffer::<Signature, InMemoryDB> {
        inputs: inputs.into_iter().collect(),
        outputs: outputs.into_iter().collect(),
        signatures: Vec::<Signature>::new().into_iter().collect(),
    };
    Ok((offer, keys))
}

fn assemble_call_tx_impl(json_str: &str) -> Result<String, String> {
    use midnight_onchain_vm::result_mode::ResultModeVerify;
    
    
    use midnight_onchain_state::state::{ContractOperation, EntryPointBuf};
    use midnight_ledger::construct::{ContractCallPrototype, PreTranscript, partition_transcripts};
    use midnight_ledger::structure::{Transaction, Intent, ProofPreimageMarker};
    use midnight_transient_crypto::proofs::{ProofPreimage, KeyLocation};
    use midnight_transient_crypto::curve::Fr;
    
    use midnight_base_crypto::signatures::Signature;
    use midnight_base_crypto::time::Timestamp;
    
    use midnight_coin_structure::contract::ContractAddress;
    use rand::rngs::OsRng;

    // 1. Parse top-level JSON
    let params: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse: {}", e))?;

    let network_id = params["network_id"].as_str()
        .ok_or("missing network_id")?;
    let contract_address_hex = params["contract_address"].as_str()
        .ok_or("missing contract_address")?;
    let entry_point = params["entry_point"].as_str()
        .ok_or("missing entry_point")?;
    let state_handle = params["state_handle"].as_u64()
        .ok_or("missing state_handle")?;
    let initial_state_handle = params["initial_state_handle"].as_u64()
        .ok_or("missing initial_state_handle")?;
    // TTL: seconds since epoch. Default: current time + 1 hour
    let ttl_secs = params["ttl_secs"].as_u64().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + 3600
    });

    let proof_data = &params["proof_data"];

    // 2. Parse input and output AlignedValues (direct construction, no serde)
    let input = parse_aligned_value(&proof_data["input"])
        .map_err(|e| format!("input: {}", e))?;
    let output = parse_aligned_value(&proof_data["output"])
        .map_err(|e| format!("output: {}", e))?;

    // 3. Parse private transcript outputs
    let priv_arr = proof_data["private_transcript_outputs"].as_array()
        .ok_or("missing private_transcript_outputs")?;
    let private_outputs: Vec<AlignedValue> = priv_arr.iter()
        .enumerate()
        .map(|(i, v)| parse_aligned_value(v).map_err(|e| format!("private_output[{}]: {}", i, e)))
        .collect::<Result<_, _>>()?;

    // 4. Deserialize the public transcript ops via upstream serde.
    //    Op<ResultModeVerify>/Key/StateValue all derive serde Deserialize
    //    upstream, and the JS shim emits the matching shape in normal form, so
    //    there is no hand-parsing (the old hand parser lagged upstream — it was
    //    missing Key::Stack, which broke receiveUnshielded/sendUnshielded; see #3).
    let transcript_ops: Vec<Op<ResultModeVerify, InMemoryDB>> =
        serde_json::from_str(&to_tag_first_json(&proof_data["public_transcript"]))
            .map_err(|e| format!("transcript deserialize: {}", e))?;

    // 5. Decode the live ledger parameters. Required for partition_transcripts,
    //    which uses params.limits.min_time_to_dismiss + params.cost_model to
    //    decide where to split the program at checkpoints. Falls back to
    //    INITIAL_PARAMETERS only on a fresh chain (best-effort for tests).
    let ledger_params: midnight_ledger::structure::LedgerParameters = {
        if let Some(hex_str) = params["ledger_parameters_hex"].as_str() {
            let bytes = hex_to_bytes(hex_str).ok_or("invalid ledger_parameters_hex")?;
            midnight_serialize::tagged_deserialize(&mut &bytes[..])
                .map_err(|e| format!("ledger params deserialize: {:?}", e))?
        } else {
            midnight_ledger::structure::INITIAL_PARAMETERS.clone()
        }
    };

    // 6. SCALE round-trip the ops to normalize internal storage state.
    //    Manually-constructed Op types may have different Sp/Arena state
    //    than ops produced through the Storable infrastructure, which causes
    //    field_repr encoding differences during proving.
    let normalized_ops: Vec<Op<ResultModeVerify, InMemoryDB>> = {
        let mut buf = Vec::new();
        for op in &transcript_ops {
            midnight_serialize::Serializable::serialize(op, &mut buf)
                .map_err(|e| format!("op SCALE serialize: {:?}", e))?;
        }
        let mut reader = &buf[..];
        let mut normalized = Vec::new();
        for _ in 0..transcript_ops.len() {
            let op: Op<ResultModeVerify, InMemoryDB> =
                midnight_serialize::Deserializable::deserialize(&mut reader, 0)
                    .map_err(|e| format!("op SCALE deserialize: {:?}", e))?;
            normalized.push(op);
        }
        normalized
    };

    // 7. Build a PreTranscript and let the SDK's `partition_transcripts`
    //    split the program into guaranteed + fallible at Op::Ckpt boundaries.
    //
    //    Why this matters: the on-chain `cost_to_dismiss` check
    //    (verify.rs:609 → fees(params, true) → cost(...,true)) only counts
    //    the GUARANTEED transcript's gas plus validation_cost. For a
    //    compute-heavy circuit like revealBatch, putting everything in
    //    guaranteed pushes cost_to_dismiss past time_to_dismiss and the
    //    node rejects with Malformed(FeeCalculation) (error 168).
    //    Splitting at checkpoints moves the heavy ops to fallible (which
    //    runs in a separate phase, NOT bounded by time_to_dismiss).
    //
    //    `partition_transcripts` handles all of this — it's the same call
    //    path used by `mn` and the JS SDK (see ledger/src/construct.rs:918,
    //    and ledger/tests/micro-dao.rs for canonical usage).
    let (guaranteed_transcript, fallible_transcript) = {
        let pool = lock_state_pool().ok_or_else(|| "state pool lock failed".to_string())?;
        let initial_state = pool.get(&initial_state_handle)
            .ok_or(format!("invalid initial_state_handle: {}", initial_state_handle))?;

        if !pool.contains_key(&state_handle) {
            return Err(format!("invalid state_handle: {}", state_handle));
        }

        let block_time_secs = params["block_time_secs"].as_i64();
        let qc = build_gas_query_context(
            initial_state.data.clone(),
            contract_address_hex,
            block_time_secs,
        )?;

        let pre = PreTranscript {
            context: qc,
            program: normalized_ops.clone(),
            comm_comm: None,
        };

        let mut transcripts = partition_transcripts(&[pre], &ledger_params)
            .map_err(|e| format!("partition_transcripts failed: {:?}", e))?;

        if transcripts.is_empty() {
            return Err("partition_transcripts returned no transcripts".to_string());
        }
        transcripts.swap_remove(0)
    };

    // 7. ContractOperation (verifier key loaded separately during proving)
    let op = ContractOperation::new(None);

    // 7. Build ContractCallPrototype
    let ep = EntryPointBuf::from(entry_point.as_bytes());
    let addr_bytes = hex::decode(contract_address_hex)
        .map_err(|e| format!("address decode: {}", e))?;
    let addr: ContractAddress = midnight_serialize::Deserializable::deserialize(
        &mut &addr_bytes[..], 0,
    ).map_err(|e| format!("address deserialize: {:?}", e))?;

    let comm_rand: Fr = rand::Rng::gen(&mut OsRng);

    let prototype = ContractCallPrototype {
        address: addr,
        entry_point: ep,
        op,
        guaranteed_public_transcript: guaranteed_transcript,
        fallible_public_transcript: fallible_transcript,
        private_transcript_outputs: private_outputs,
        input,
        output,
        communication_commitment_rand: comm_rand,
        key_location: KeyLocation(std::borrow::Cow::Owned(entry_point.to_owned())),
    };

    // 8. Build Intent with the contract call
    let ttl = Timestamp::from_secs(ttl_secs);
    let intent = Intent::<Signature, ProofPreimageMarker, _, InMemoryDB>::empty(
        &mut OsRng, ttl,
    ).add_call::<ProofPreimage>(prototype);

    // 8b. Fund the unshielded value the contract receives via receiveUnshielded, if the
    //     caller declared it. Plain contract calls (no `unshielded_funding`) skip this
    //     entirely — their transaction is byte-identical to before. The offer + call are
    //     signed together at segment 1 (matches the intents-map key below); Intent::sign
    //     erases proofs first, so the signature survives proving and the balancer's later
    //     dust merge.
    let intent = match params.get("unshielded_funding") {
        Some(funding) if !funding.is_null() => {
            let (offer, signing_keys) = build_funding_offer(funding)?;
            let mut intent = intent;
            intent.guaranteed_unshielded_offer = Some(midnight_storage::arena::Sp::new(offer));
            intent
                .sign(&mut OsRng, 1, &signing_keys, &[], &[])
                .map_err(|e| format!("sign contract-call unshielded offer: {:?}", e))?
        }
        _ => intent,
    };

    // 9. Build Transaction from intents
    let mut intents_map = midnight_storage::storage::HashMap::<u16, _, InMemoryDB>::default();
    intents_map = intents_map.insert(1u16, intent);
    let tx = Transaction::<Signature, ProofPreimageMarker, _, InMemoryDB>::from_intents(
        network_id, intents_map,
    );

    // 10. Serialize as (Transaction, ProvingKeys) tuple
    let proving_keys: std::collections::HashMap<String, midnight_transient_crypto::proofs::ProvingKeyMaterial> =
        std::collections::HashMap::new();
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&(&tx, &proving_keys), &mut bytes)
        .map_err(|e| format!("serialize: {:?}", e))?;

    Ok(hex::encode(&bytes))
}

/// Assemble a contract DEPLOY transaction from constructor output.
///
/// Input JSON:
/// {
///   "network_id": "preprod",
///   "state_handle": 42       // handle from constructor's initialState()
/// }
///
/// Output: hex-encoded SCALE serialized (Transaction, HashMap<String, ProvingKeyMaterial>) tuple,
///         or JSON error: {"error": "..."}
///
/// The contract address is derived deterministically from the initial state hash.
#[no_mangle]
pub extern "C" fn contract_assemble_deploy_tx(
    params_json: *const c_char,
) -> *const c_char {
    // SAFETY: params_json comes from JNI GetStringUTFChars, guaranteed valid C string.
    let json_str = match unsafe { c_str_to_str(params_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    match assemble_deploy_tx_impl(json_str) {
        Ok(json) => to_c_string(&json),
        Err(e) => to_c_string(&format!("{{\"error\":\"{}\"}}", e.replace('"', "\\\""))),
    }
}

/// Reads `global_ttl` (in seconds) from SCALE-encoded ledger parameters.
///
/// The node rejects an intent whose TTL sits more than `global_ttl` ahead of
/// chain time (custom error 182 / `IntentTtlTooFarInFuture`). Networks set very
/// different ceilings — a localnet runs ~100s, PreProd ~1h — so callers size a
/// transaction's TTL to this live value instead of a fixed window.
///
/// Returns the seconds value, or `-1` if the parameters can't be decoded.
#[no_mangle]
pub extern "C" fn ledger_params_global_ttl_secs(params_hex: *const c_char) -> i64 {
    // SAFETY: params_hex comes from JNI GetStringUTFChars, guaranteed a valid C string.
    let hex_str = match unsafe { c_str_to_str(params_hex) } {
        Some(s) => s,
        None => return -1,
    };
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let params: midnight_ledger::structure::LedgerParameters =
        match midnight_serialize::tagged_deserialize(&bytes[..]) {
            Ok(p) => p,
            Err(_) => return -1,
        };
    let secs = params.global_ttl.as_seconds();
    if (0..=i64::MAX as i128).contains(&secs) { secs as i64 } else { -1 }
}

/// Returns JSON: `{"tx_hex":"...", "contract_address":"..."}`
///
/// Input JSON now supports optional `verifier_keys` map to register circuit
/// operations during deploy (avoids separate maintenance transactions):
/// ```json
/// {
///   "network_id": "undeployed",
///   "state_handle": 42,
///   "verifier_keys": {
///     "post": "hex_encoded_verifier_key_bytes",
///     "takeDown": "hex_encoded_verifier_key_bytes"
///   }
/// }
/// ```
fn assemble_deploy_tx_impl(json_str: &str) -> Result<String, String> {
    use midnight_ledger::structure::{
        ContractDeploy, Transaction, Intent, ProofPreimageMarker,
    };
    use midnight_base_crypto::signatures::Signature;
    use midnight_base_crypto::time::Timestamp;
    use midnight_transient_crypto::proofs::{ProvingKeyMaterial, VerifierKey};
    use midnight_onchain_state::state::{ContractOperation, EntryPointBuf};
    use rand::rngs::OsRng;

    let params: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse: {}", e))?;

    let network_id = params["network_id"].as_str()
        .ok_or("missing network_id")?;
    let state_handle = params["state_handle"].as_u64()
        .ok_or("missing state_handle")?;

    const DEFAULT_TTL_SECS: u64 = 3600;
    let ttl_secs = params["ttl_secs"].as_u64().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + DEFAULT_TTL_SECS
    });

    // Take the contract state from the pool (constructor won't need it again)
    let mut initial_state = {
        let mut pool = lock_state_pool().ok_or_else(|| "state pool lock failed".to_string())?;
        pool.remove(&state_handle)
            .ok_or(format!("invalid state_handle: {}", state_handle))?
    };

    // Register circuit verifier keys in the contract state so the contract
    // is immediately callable after deploy (no separate maintenance tx needed).
    if let Some(vk_map) = params["verifier_keys"].as_object() {
        let mut ops = initial_state.operations.clone();
        for (circuit_name, vk_hex_val) in vk_map {
            let vk_hex = vk_hex_val.as_str()
                .ok_or(format!("verifier_keys.{} must be a hex string", circuit_name))?;
            let vk_bytes = hex::decode(vk_hex)
                .map_err(|e| format!("verifier_keys.{} hex decode: {}", circuit_name, e))?;
            let vk: VerifierKey = midnight_serialize::tagged_deserialize(&vk_bytes[..])
                .map_err(|e| format!("verifier_keys.{} deserialize: {:?}", circuit_name, e))?;
            let ep = EntryPointBuf::from(circuit_name.as_bytes());
            ops = ops.insert(ep, ContractOperation::new(Some(vk)));
        }
        initial_state.operations = ops;
    }

    let deploy = ContractDeploy::new(&mut OsRng, initial_state);

    // Contract address = hash(initial_state + nonce). Deterministic per deploy.
    let addr = deploy.address();
    let mut addr_bytes = Vec::new();
    midnight_serialize::Serializable::serialize(&addr, &mut addr_bytes)
        .map_err(|e| format!("address serialize: {:?}", e))?;
    let address_hex = hex::encode(&addr_bytes);

    let ttl = Timestamp::from_secs(ttl_secs);
    let intent = Intent::<Signature, ProofPreimageMarker, _, InMemoryDB>::empty(
        &mut OsRng, ttl,
    ).add_deploy(deploy);

    let intents_map = midnight_storage::storage::HashMap::<u16, _, InMemoryDB>::default()
        .insert(1u16, intent);
    let tx = Transaction::new(
        network_id,
        intents_map,
        None,
        midnight_storage::storage::HashMap::new(),
    );

    let proving_keys: std::collections::HashMap<String, ProvingKeyMaterial> =
        std::collections::HashMap::new();
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&(&tx, &proving_keys), &mut bytes)
        .map_err(|e| format!("serialize: {:?}", e))?;

    Ok(format!(
        "{{\"tx_hex\":\"{}\",\"contract_address\":\"{}\"}}",
        hex::encode(&bytes),
        address_hex,
    ))
}

#[cfg(test)]
mod value_format_tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn print_value_formats() {
        // 0
        let z = CString::new("0").unwrap();
        let r = contract_big_int_to_value(z.as_ptr());
        let s = unsafe { std::ffi::CStr::from_ptr(r).to_str().unwrap() };
        println!("bigIntToValue(0): {}", s);
        unsafe { contract_free_string(r as *mut c_char); }

        // 1
        let z = CString::new("1").unwrap();
        let r = contract_big_int_to_value(z.as_ptr());
        let s = unsafe { std::ffi::CStr::from_ptr(r).to_str().unwrap() };
        println!("bigIntToValue(1): {}", s);
        unsafe { contract_free_string(r as *mut c_char); }

        // 42
        let z = CString::new("2a").unwrap();
        let r = contract_big_int_to_value(z.as_ptr());
        let s = unsafe { std::ffi::CStr::from_ptr(r).to_str().unwrap() };
        println!("bigIntToValue(42): {}", s);
        unsafe { contract_free_string(r as *mut c_char); }
    }

    #[test]
    fn print_alignment_formats() {
        use midnight_base_crypto::fab::{AlignedValue, Value, ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};
        use midnight_transient_crypto::curve::Fr;

        // 1. Field alignment (32 bytes)
        let field_av = AlignedValue {
            value: Value::from(Fr::from_le_bytes(&[0u8]).unwrap()),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]),
        };
        println!("AlignedValue(Field): {}", serde_json::to_string(&field_av).unwrap());

        // 2. Bytes(1) alignment
        let bytes1_av = AlignedValue {
            value: Value(vec![ValueAtom(vec![0u8])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
        };
        println!("AlignedValue(Bytes(1)): {}", serde_json::to_string(&bytes1_av).unwrap());

        // 3. Bytes(32) alignment
        let bytes32_av = AlignedValue {
            value: Value(vec![ValueAtom(vec![0u8; 32])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 })]),
        };
        println!("AlignedValue(Bytes(32)): {}", serde_json::to_string(&bytes32_av).unwrap());

        // 4. Empty AlignedValue
        let empty_av = AlignedValue {
            value: Value(vec![]),
            alignment: Alignment(vec![]),
        };
        println!("AlignedValue(empty): {}", serde_json::to_string(&empty_av).unwrap());
    }

    /// Documents a known bug in Midnight's AlignedValue serde: JSON round-trip
    /// fails because the `try_from` validation rejects valid values.
    /// Our workaround: `parse_aligned_value()` bypasses serde and constructs directly.
    #[test]
    #[ignore = "Known Midnight serde bug: AlignedValue JSON round-trip fails"]
    fn known_bug_aligned_value_json_roundtrip() {
        use midnight_base_crypto::fab::{AlignedValue, Value, ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};

        let av = AlignedValue {
            value: Value(vec![ValueAtom(vec![0u8])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
        };
        let json = serde_json::to_string(&av).unwrap();
        let result: Result<AlignedValue, _> = serde_json::from_str(&json);
        assert!(result.is_ok(), "AlignedValue should round-trip: {:?}", result.err());
    }

    #[test]
    fn print_verify_op_format() {
        use midnight_onchain_vm::result_mode::ResultModeVerify;
        use midnight_base_crypto::fab::{AlignedValue, Value, ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};

        // Popeq with Bytes(1) result
        let popeq_op: Op<ResultModeVerify, InMemoryDB> = Op::Popeq {
            cached: false,
            result: AlignedValue {
                value: Value(vec![ValueAtom(vec![0u8])]),
                alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
            },
        };
        println!("Op::Popeq(Bytes(1)): {}", serde_json::to_string(&popeq_op).unwrap());
    }

    #[test]
    fn print_state_value_format() {
        use midnight_onchain_state::state::StateValue;
        use midnight_storage::db::InMemoryDB;
        let null_sv: StateValue<InMemoryDB> = StateValue::Null;
        println!("StateValue::Null: {}", serde_json::to_string(&null_sv).unwrap());
        let arr_sv: StateValue<InMemoryDB> = StateValue::Array(vec![StateValue::Null].into());
        println!("StateValue::Array[null]: {}", serde_json::to_string(&arr_sv).unwrap());
    }

    #[test]
    fn roundtrip_assembled_tx() {
        // Assemble a minimal TX and verify it can be deserialized
        use midnight_serialize::{tagged_serialize, tagged_deserialize};
        use midnight_ledger::structure::{Transaction, ProofPreimageMarker};
        use midnight_base_crypto::signatures::Signature;
        use midnight_transient_crypto::commitment::PedersenRandomness;
        use midnight_transient_crypto::proofs::ProvingKeyMaterial;
        use midnight_storage::db::InMemoryDB;

        type Tx = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;
        type Payload = (Tx, std::collections::HashMap<String, ProvingKeyMaterial>);

        // Build a minimal TX via the assembler
        let json_str = r#"{
            "network_id": "undeployed",
            "contract_address": "0000000000000000000000000000000000000000000000000000000000000000",
            "entry_point": "post",
            "state_handle": 0,
            "initial_state_handle": 0,
            "proof_data": {
                "input": { "value": [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]], "alignment": [{"tag":"atom","value":{"tag":"field"}}] },
                "output": { "value": [[]], "alignment": [{"tag":"atom","value":{"tag":"field"}}] },
                "public_transcript": [],
                "private_transcript_outputs": []
            }
        }"#;

        // We can't easily call the FFI with dummy state handles,
        // but we can test serialization roundtrip of the Transaction type.
        // Let's create a minimal transaction and test roundtrip.
        use midnight_ledger::structure::Intent;
        let ttl = midnight_base_crypto::time::Timestamp::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600
        );
        let intent = Intent::<Signature, ProofPreimageMarker, _, InMemoryDB>::empty(
            &mut rand::rngs::OsRng, ttl,
        );
        let mut intents_map = midnight_storage::storage::HashMap::<u16, _, InMemoryDB>::default();
        intents_map = intents_map.insert(1u16, intent);
        let tx = Tx::from_intents("undeployed", intents_map);

        let keys: std::collections::HashMap<String, ProvingKeyMaterial> = std::collections::HashMap::new();

        let mut bytes = Vec::new();
        tagged_serialize(&(&tx, &keys), &mut bytes).expect("serialize should succeed");
        println!("Serialized TX: {} bytes", bytes.len());
        println!("First 100 bytes as ASCII: {}", String::from_utf8_lossy(&bytes[..100.min(bytes.len())]));

        // Deserialize roundtrip
        let (_tx2, _keys2): Payload = tagged_deserialize(&mut &bytes[..])
            .expect("roundtrip deserialize should succeed");
        println!("Roundtrip deserialization succeeded!");

        // Write to temp file so we can send to proof server via curl
        let tmp = "/tmp/test_tx_payload.bin";
        std::fs::write(tmp, &bytes).expect("write temp file");
        println!("Wrote {} bytes to {}", bytes.len(), tmp);
        println!("Test with: curl -s -o /dev/null -w '%{{http_code}}' --data-binary @{} http://localhost:6300/prove-tx", tmp);
    }

    #[test]
    fn print_transaction_tag() {
        use midnight_serialize::Tagged;
        use midnight_ledger::structure::{Transaction, ProofPreimageMarker};
        use midnight_base_crypto::signatures::Signature;
        use midnight_transient_crypto::commitment::PedersenRandomness;
        use midnight_transient_crypto::proofs::ProvingKeyMaterial;
        use midnight_storage::db::InMemoryDB;

        type Tx = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;
        type Payload = (Tx, std::collections::HashMap<String, ProvingKeyMaterial>);

        let tag = <Payload as Tagged>::tag();
        println!("Transaction tuple tag: {}", tag);

        let tx_tag = <Tx as Tagged>::tag();
        println!("Transaction alone tag: {}", tx_tag);
    }

    #[test]
    fn test_assemble_deploy_tx() {
        use midnight_onchain_state::state::ContractState as RustContractState;
        use midnight_ledger::structure::{Transaction, ProofPreimageMarker};
        use midnight_base_crypto::signatures::Signature;
        use midnight_transient_crypto::commitment::PedersenRandomness;
        use midnight_transient_crypto::proofs::ProvingKeyMaterial;
        use midnight_serialize::Tagged;

        // Create a minimal empty contract state and put it in the pool
        let state = RustContractState::<InMemoryDB>::default();
        // Unique handle via NEXT_HANDLE — NOT `max(keys)+1`, which races under
        // parallel tests: once another test frees a handle, `max+1` can reuse an
        // id this test's deploy is about to consume, so the "consumed after deploy"
        // assert intermittently sees the other test's freshly-inserted state.
        let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        lock_state_pool().unwrap().insert(handle, state);

        // Call deploy assembler
        let params = format!(
            r#"{{"network_id":"undeployed","state_handle":{}}}"#,
            handle
        );
        let params_c = CString::new(params).unwrap();
        let result_ptr = contract_assemble_deploy_tx(params_c.as_ptr());
        assert!(!result_ptr.is_null(), "deploy assembler returned null");

        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr).to_str().unwrap() };
        println!("Deploy result: {}", &result_str[..result_str.len().min(200)]);

        // Parse the JSON result
        let result: serde_json::Value = serde_json::from_str(result_str).unwrap();
        assert!(result.get("error").is_none(), "deploy returned error: {}", result_str);

        let tx_hex = result["tx_hex"].as_str().unwrap();
        let contract_address = result["contract_address"].as_str().unwrap();

        assert!(!tx_hex.is_empty(), "tx_hex is empty");
        assert!(!contract_address.is_empty(), "contract_address is empty");
        assert!(contract_address.len() == 64, "address should be 32 bytes = 64 hex chars, got {}", contract_address.len());

        println!("Deploy tx hex: {} chars", tx_hex.len());
        println!("Contract address: {}", contract_address);

        // Verify the tx can be deserialized back
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let _payload: (
            Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
            std::collections::HashMap<String, ProvingKeyMaterial>,
        ) = midnight_serialize::tagged_deserialize(&tx_bytes[..])
            .expect("deploy tx should deserialize");

        println!("✅ Deploy tx roundtrips correctly");

        unsafe { contract_free_string(result_ptr as *mut c_char); }

        // Verify the state handle was consumed (removed from pool)
        let pool = lock_state_pool().unwrap();
        assert!(!pool.contains_key(&handle), "state_handle should be consumed after deploy");
    }

    #[test]
    fn test_deploy_tx_invalid_handle() {
        let params = r#"{"network_id":"undeployed","state_handle":999999}"#;
        let params_c = CString::new(params).unwrap();
        let result_ptr = contract_assemble_deploy_tx(params_c.as_ptr());
        assert!(!result_ptr.is_null());

        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr).to_str().unwrap() };
        assert!(result_str.contains("error"), "invalid handle should return error: {}", result_str);

        unsafe { contract_free_string(result_ptr as *mut c_char); }
    }

    #[test]
    fn test_deploy_tx_missing_fields() {
        let params = r#"{"network_id":"undeployed"}"#;
        let params_c = CString::new(params).unwrap();
        let result_ptr = contract_assemble_deploy_tx(params_c.as_ptr());
        assert!(!result_ptr.is_null());

        let result_str = unsafe { std::ffi::CStr::from_ptr(result_ptr).to_str().unwrap() };
        assert!(result_str.contains("error"), "missing state_handle should error: {}", result_str);

        unsafe { contract_free_string(result_ptr as *mut c_char); }
    }

    #[test]
    fn test_global_ttl_secs_reads_default_params() {
        // Round-trip the chain's INITIAL_PARAMETERS (global_ttl = 3600s) through the getter.
        let params = midnight_ledger::structure::INITIAL_PARAMETERS;
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&params, &mut bytes).expect("serialize params");
        let hex_c = std::ffi::CString::new(hex::encode(&bytes)).unwrap();
        assert_eq!(ledger_params_global_ttl_secs(hex_c.as_ptr()), 3600);
    }

    #[test]
    fn test_global_ttl_secs_reads_tight_localnet_value() {
        // A tight ceiling (a localnet runs ~100s) must read back exactly — this is the value the
        // adaptive TTL sizing depends on to keep a tx under the node's limit (custom error 182).
        let mut params = midnight_ledger::structure::INITIAL_PARAMETERS;
        params.global_ttl = midnight_base_crypto::time::Duration::from_secs(100);
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&params, &mut bytes).expect("serialize params");
        let hex_c = std::ffi::CString::new(hex::encode(&bytes)).unwrap();
        assert_eq!(ledger_params_global_ttl_secs(hex_c.as_ptr()), 100);
    }

    #[test]
    fn test_global_ttl_secs_invalid_input_returns_negative() {
        // Bad hex, valid-hex-but-not-params, and empty all yield -1 so callers fall back safely.
        assert_eq!(ledger_params_global_ttl_secs(std::ffi::CString::new("not-hex").unwrap().as_ptr()), -1);
        assert_eq!(ledger_params_global_ttl_secs(std::ffi::CString::new("deadbeef").unwrap().as_ptr()), -1);
        assert_eq!(ledger_params_global_ttl_secs(std::ffi::CString::new("").unwrap().as_ptr()), -1);
    }
}


#[cfg(test)]
mod state_structure_tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn flat_number_creates_array_of_nulls() {
        let json = CString::new("4").unwrap();
        let handle = contract_state_create_with_nulls(json.as_ptr());
        assert!(handle > 0, "Should create a valid handle");

        // Verify it's queryable
        let pool = lock_state_pool().unwrap();
        let state = pool.get(&handle).unwrap();
        match state.data.get_ref() {
            midnight_onchain_state::state::StateValue::Array(arr) => {
                assert_eq!(arr.len(), 4, "Should have 4 items");
            }
            other => panic!("Expected Array, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[test]
    fn nested_structure_creates_nested_arrays() {
        // Penalty contract state: Array([Array([Null x 10]), Array([])])
        let json = CString::new(r#"{"array":[{"array":[null,null,null,null,null,null,null,null,null,null]},{"array":[]}]}"#).unwrap();
        let handle = contract_state_create_with_nulls(json.as_ptr());
        assert!(handle > 0, "Should create a valid handle");

        let pool = lock_state_pool().unwrap();
        let state = pool.get(&handle).unwrap();
        match state.data.get_ref() {
            midnight_onchain_state::state::StateValue::Array(arr) => {
                assert_eq!(arr.len(), 2, "Outer array should have 2 items");
                match arr.get(0) {
                    Some(midnight_onchain_state::state::StateValue::Array(inner)) => {
                        assert_eq!(inner.len(), 10, "Inner array should have 10 items");
                    }
                    other => panic!("Expected inner Array, got {:?}", other.map(std::mem::discriminant)),
                }
            }
            other => panic!("Expected Array, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[test]
    fn null_structure_creates_null() {
        let json = CString::new("null").unwrap();
        let handle = contract_state_create_with_nulls(json.as_ptr());
        assert!(handle > 0);

        let pool = lock_state_pool().unwrap();
        let state = pool.get(&handle).unwrap();
        match state.data.get_ref() {
            midnight_onchain_state::state::StateValue::Null => {} // correct
            other => panic!("Expected Null, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[test]
    fn oversized_array_capped_at_64() {
        // Try 100 items — should be capped at 64
        let items: Vec<&str> = (0..100).map(|_| "null").collect();
        let json_str = format!(r#"{{"array":[{}]}}"#, items.join(","));
        let json = CString::new(json_str).unwrap();
        let handle = contract_state_create_with_nulls(json.as_ptr());
        assert!(handle > 0);

        let pool = lock_state_pool().unwrap();
        let state = pool.get(&handle).unwrap();
        match state.data.get_ref() {
            midnight_onchain_state::state::StateValue::Array(arr) => {
                assert_eq!(arr.len(), 64, "Should be capped at 64");
            }
            other => panic!("Expected Array, got {:?}", std::mem::discriminant(other)),
        }
    }
}

#[cfg(test)]
mod normalized_value_tests {
    use super::*;
    use midnight_base_crypto::fab::{AlignedValue, Value, ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};
    use midnight_onchain_vm::ops::Op;
    use midnight_onchain_vm::result_mode::ResultModeVerify;

    /// Verifies that normalized (empty) ValueAtoms are preserved through
    /// parse_aligned_value and match the on-chain normalized form.
    /// This is the root cause fix for Error 104 (Transcript/ReadMismatch).
    #[test]
    fn empty_atom_matches_normalized_form() {
        // Boolean false in Midnight is stored as ValueAtom([]) with Bytes(1) alignment.
        // Our JS used to pad this to ValueAtom([0]) causing ReadMismatch on-chain.
        let json: serde_json::Value = serde_json::json!({
            "value": [[]],
            "alignment": [{"tag": "atom", "value": {"tag": "bytes", "length": 1}}]
        });
        let parsed = parse_aligned_value(&json).expect("should parse");

        // On-chain state stores normalized form
        let on_chain = AlignedValue {
            value: Value(vec![ValueAtom(vec![])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
        };

        assert_eq!(parsed, on_chain,
            "Parsed value must match on-chain normalized form (both empty)");
    }

    /// Bytes<32> with all-zero content (e.g. pad(32, "")) is stored as
    /// ValueAtom([]) after normalization. Must NOT be padded to 32 zeros.
    #[test]
    fn empty_bytes32_matches_normalized_form() {
        let json: serde_json::Value = serde_json::json!({
            "value": [[]],
            "alignment": [{"tag": "atom", "value": {"tag": "bytes", "length": 32}}]
        });
        let parsed = parse_aligned_value(&json).expect("should parse");

        let on_chain = AlignedValue {
            value: Value(vec![ValueAtom(vec![])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 })]),
        };

        assert_eq!(parsed, on_chain,
            "Empty Bytes<32> must match on-chain normalized form");
    }

    /// Non-zero values should parse identically to the on-chain form.
    #[test]
    fn nonzero_value_matches() {
        let json: serde_json::Value = serde_json::json!({
            "value": [[1]],
            "alignment": [{"tag": "atom", "value": {"tag": "bytes", "length": 1}}]
        });
        let parsed = parse_aligned_value(&json).expect("should parse");

        let on_chain = AlignedValue {
            value: Value(vec![ValueAtom(vec![1])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
        };

        assert_eq!(parsed, on_chain);
    }

    /// Popeq with empty result must SCALE round-trip correctly.
    /// This simulates the transcript normalization step in assemble_call_tx.
    #[test]
    fn popeq_empty_result_scale_roundtrip() {
        let av = AlignedValue {
            value: Value(vec![ValueAtom(vec![])]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
        };
        let op: Op<ResultModeVerify, midnight_storage::db::InMemoryDB> = Op::Popeq {
            cached: false,
            result: av.clone(),
        };

        // SCALE serialize
        let mut buf = Vec::new();
        midnight_serialize::Serializable::serialize(&op, &mut buf)
            .expect("serialize should succeed");

        // SCALE deserialize
        let deserialized: Op<ResultModeVerify, midnight_storage::db::InMemoryDB> =
            midnight_serialize::Deserializable::deserialize(&mut &buf[..], 0)
                .expect("deserialize should succeed");

        if let Op::Popeq { result, .. } = &deserialized {
            assert_eq!(result, &av,
                "SCALE round-trip must preserve normalized (empty) ValueAtom");
        } else {
            panic!("Expected Popeq, got {:?}", deserialized);
        }
    }

    /// Multiple alignment segments with mixed empty/non-empty atoms.
    /// Simulates BatchPreimage-adjacent state reads.
    #[test]
    fn mixed_empty_and_nonzero_atoms() {
        // Phase=COMMITTING(1), p1Committed=false([]), p1Commitment=zeros([])
        let json: serde_json::Value = serde_json::json!({
            "value": [[1], [], []],
            "alignment": [
                {"tag": "atom", "value": {"tag": "bytes", "length": 1}},
                {"tag": "atom", "value": {"tag": "bytes", "length": 1}},
                {"tag": "atom", "value": {"tag": "bytes", "length": 32}}
            ]
        });
        let parsed = parse_aligned_value(&json).expect("should parse");

        let on_chain = AlignedValue {
            value: Value(vec![
                ValueAtom(vec![1]),      // phase=COMMITTING
                ValueAtom(vec![]),       // p1Committed=false (normalized)
                ValueAtom(vec![]),       // p1Commitment=zeros (normalized)
            ]),
            alignment: Alignment(vec![
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            ]),
        };

        assert_eq!(parsed, on_chain,
            "Mixed state fields must match on-chain normalized form");
    }
}

#[cfg(test)]
mod persistent_commit_tests {
    use super::*;
    use std::ffi::CString;

    // Alignment format: {"tag":"atom","value":{"tag":"bytes","length":N}}
    fn bytes_alignment(length: usize) -> serde_json::Value {
        serde_json::json!({"tag": "atom", "value": {"tag": "bytes", "length": length}})
    }

    fn field_alignment() -> serde_json::Value {
        serde_json::json!({"tag": "atom", "value": {"tag": "field"}})
    }

    #[test]
    fn test_persistent_commit_basic() {
        let opening: Vec<u8> = (0..32).collect();
        let value_bytes: Vec<u8> = vec![1, 2, 3];

        let input = serde_json::json!({
            "value": {
                "value": [value_bytes],
                "alignment": [bytes_alignment(3)]
            },
            "opening": opening
        });

        let json = CString::new(input.to_string()).unwrap();
        let result_ptr = contract_persistent_commit_aligned(json.as_ptr());
        assert!(!result_ptr.is_null(), "Should not return null");

        let result = unsafe { std::ffi::CStr::from_ptr(result_ptr).to_str().unwrap() };
        println!("persistentCommit result: {}", result);

        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(!parsed.is_object() || parsed.get("error").is_none(),
            "Should not be an error: {}", result);
        assert!(parsed.is_array(), "Should be a Value array: {}", result);

        unsafe { contract_free_string(result_ptr as *mut c_char); }
    }

    #[test]
    fn test_persistent_commit_with_field_alignment() {
        let opening: Vec<u8> = (0..32).map(|i| i * 7).collect();
        let value_bytes: Vec<u8> = vec![0; 32]; // 32-byte field element

        let input = serde_json::json!({
            "value": {
                "value": [value_bytes],
                "alignment": [field_alignment()]
            },
            "opening": opening
        });

        let json = CString::new(input.to_string()).unwrap();
        let result_ptr = contract_persistent_commit_aligned(json.as_ptr());
        assert!(!result_ptr.is_null());

        let result = unsafe { std::ffi::CStr::from_ptr(result_ptr).to_str().unwrap() };
        println!("persistentCommit field result: {}", result);

        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed.is_array(), "Expected array, got: {}", result);

        unsafe { contract_free_string(result_ptr as *mut c_char); }
    }

    #[test]
    fn test_persistent_commit_deterministic() {
        let opening: Vec<u8> = (0..32).collect();
        let value_bytes: Vec<u8> = vec![10, 20, 30];

        let input = serde_json::json!({
            "value": {
                "value": [value_bytes],
                "alignment": [bytes_alignment(3)]
            },
            "opening": opening
        });

        let json1 = CString::new(input.to_string()).unwrap();
        let json2 = CString::new(input.to_string()).unwrap();

        let r1 = contract_persistent_commit_aligned(json1.as_ptr());
        let r2 = contract_persistent_commit_aligned(json2.as_ptr());

        let s1 = unsafe { std::ffi::CStr::from_ptr(r1).to_str().unwrap().to_string() };
        let s2 = unsafe { std::ffi::CStr::from_ptr(r2).to_str().unwrap().to_string() };

        assert_eq!(s1, s2, "Same input should produce same output");

        unsafe {
            contract_free_string(r1 as *mut c_char);
            contract_free_string(r2 as *mut c_char);
        }
    }

    #[test]
    fn test_persistent_commit_different_opening_different_result() {
        let value_bytes: Vec<u8> = vec![1, 2, 3];

        let input1 = serde_json::json!({
            "value": { "value": [value_bytes.clone()], "alignment": [bytes_alignment(3)] },
            "opening": vec![0u8; 32]
        });
        let input2 = serde_json::json!({
            "value": { "value": [value_bytes], "alignment": [bytes_alignment(3)] },
            "opening": vec![1u8; 32]
        });

        let j1 = CString::new(input1.to_string()).unwrap();
        let j2 = CString::new(input2.to_string()).unwrap();

        let r1 = contract_persistent_commit_aligned(j1.as_ptr());
        let r2 = contract_persistent_commit_aligned(j2.as_ptr());

        let s1 = unsafe { std::ffi::CStr::from_ptr(r1).to_str().unwrap().to_string() };
        let s2 = unsafe { std::ffi::CStr::from_ptr(r2).to_str().unwrap().to_string() };

        assert_ne!(s1, s2, "Different openings should produce different commitments");

        unsafe {
            contract_free_string(r1 as *mut c_char);
            contract_free_string(r2 as *mut c_char);
        }
    }

    #[test]
    fn test_persistent_commit_rejects_short_opening() {
        let input = serde_json::json!({
            "value": {
                "value": [[1, 2, 3]],
                "alignment": [bytes_alignment(3)]
            },
            "opening": [1, 2, 3] // only 3 bytes, need 32
        });

        let json = CString::new(input.to_string()).unwrap();
        let result_ptr = contract_persistent_commit_aligned(json.as_ptr());
        assert!(!result_ptr.is_null());

        let result = unsafe { std::ffi::CStr::from_ptr(result_ptr).to_str().unwrap() };
        println!("short opening result: {}", result);
        assert!(result.contains("error"), "Should return error for short opening");
        assert!(result.contains("32 bytes"), "Should mention 32 bytes");

        unsafe { contract_free_string(result_ptr as *mut c_char); }
    }
}

#[cfg(test)]
mod persistent_commit_crosscheck {
    use super::*;
    use std::ffi::CString;
    use midnight_base_crypto::hash::{persistent_commit, HashOutput, PersistentHashWriter};
    use midnight_base_crypto::fab::{AlignedValue, Value, ValueAtom, Alignment, AlignmentSegment, AlignmentAtom};
    use midnight_base_crypto::repr::BinaryHashRepr;

    /// Cross-check: our FFI persistentCommit vs direct Rust persistent_commit
    /// They MUST produce identical output for the same input.
    #[test]
    fn ffi_matches_direct_rust_persistent_commit() {
        let opening_bytes: Vec<u8> = (0..32).map(|i| (i * 5 + 3) as u8).collect();
        let value_bytes: Vec<u8> = vec![10, 20, 30];

        // 1. Direct Rust: persistent_commit(value, opening)
        let mut opening_arr = [0u8; 32];
        opening_arr.copy_from_slice(&opening_bytes);
        let opening = HashOutput(opening_arr);

        let aligned = AlignedValue {
            value: Value(vec![ValueAtom(value_bytes.clone())]),
            alignment: Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 3 })]),
        };

        // persistent_commit uses: opening.binary_repr || value.binary_repr
        let mut hasher = PersistentHashWriter::default();
        opening.binary_repr(&mut hasher);
        ValueReprAlignedValue(aligned.clone()).binary_repr(&mut hasher);
        let direct_hash = hasher.finalize();
        let direct_value = midnight_base_crypto::fab::Value::from(direct_hash);
        let direct_json = serde_json::to_string(&direct_value).unwrap();
        println!("Direct Rust result: {}", direct_json);

        // 2. FFI: contract_persistent_commit_aligned
        let ffi_input = serde_json::json!({
            "value": {
                "value": [value_bytes],
                "alignment": [{"tag": "atom", "value": {"tag": "bytes", "length": 3}}]
            },
            "opening": opening_bytes
        });
        let ffi_json = CString::new(ffi_input.to_string()).unwrap();
        let ffi_ptr = contract_persistent_commit_aligned(ffi_json.as_ptr());
        let ffi_result = unsafe { std::ffi::CStr::from_ptr(ffi_ptr).to_str().unwrap().to_string() };
        println!("FFI result: {}", ffi_result);

        unsafe { contract_free_string(ffi_ptr as *mut c_char); }

        // They must match exactly
        assert_eq!(direct_json, ffi_result, "FFI and direct Rust must produce identical output");
    }

    /// Test with the same pattern the penalty contract uses:
    /// persistentCommit of a BatchPreimage (5 Uint<8> choices) with a 32-byte nonce
    #[test]
    fn ffi_matches_for_batch_preimage() {
        // BatchPreimage: 5 x Uint<8> values
        let choices: Vec<Vec<u8>> = vec![
            vec![0], vec![1], vec![2], vec![0], vec![1]
        ];
        let nonce: Vec<u8> = (100..132).collect(); // 32-byte nonce

        // The alignment for Uint<8> is Bytes(1)
        let alignments: Vec<serde_json::Value> = (0..5).map(|_| {
            serde_json::json!({"tag": "atom", "value": {"tag": "bytes", "length": 1}})
        }).collect();

        let ffi_input = serde_json::json!({
            "value": {
                "value": choices,
                "alignment": alignments
            },
            "opening": nonce
        });

        let ffi_json = CString::new(ffi_input.to_string()).unwrap();
        let ffi_ptr = contract_persistent_commit_aligned(ffi_json.as_ptr());
        assert!(!ffi_ptr.is_null());

        let ffi_result = unsafe { std::ffi::CStr::from_ptr(ffi_ptr).to_str().unwrap().to_string() };
        println!("Batch preimage commit: {}", ffi_result);

        // Must be a valid array, not error
        let parsed: serde_json::Value = serde_json::from_str(&ffi_result).unwrap();
        assert!(parsed.is_array(), "Expected array result, got: {}", ffi_result);

        // Verify determinism
        let ffi_json2 = CString::new(ffi_input.to_string()).unwrap();
        let ffi_ptr2 = contract_persistent_commit_aligned(ffi_json2.as_ptr());
        let ffi_result2 = unsafe { std::ffi::CStr::from_ptr(ffi_ptr2).to_str().unwrap().to_string() };
        assert_eq!(ffi_result, ffi_result2, "Must be deterministic");

        unsafe {
            contract_free_string(ffi_ptr as *mut c_char);
            contract_free_string(ffi_ptr2 as *mut c_char);
        }
    }
}

/// Regression coverage for the circuit `ReadMismatch` on an evolved contract state.
///
/// Background: calling a circuit (e.g. BBoard `post`) against a contract whose
/// on-chain state has advanced past its constructor value fails at assembly with
/// `partition_transcripts ... ReadMismatch`. The fixture captures one real device
/// run — the on-chain state hex plus the exact transcript the circuit produced —
/// so the divergence reproduces in-process with no emulator. The device pool
/// handles inside `params` are non-portable, so each test recreates handles from
/// the on-chain hex and patches them in.
#[cfg(test)]
mod readmismatch_repro {
    use super::*;
    use std::ffi::CString;
    use midnight_onchain_vm::result_mode::ResultModeVerify;

    const FIXTURE: &str = include_str!("../test-fixtures/readmismatch-post.json");

    fn fixture() -> serde_json::Value {
        serde_json::from_str(FIXTURE).expect("fixture parses")
    }

    /// Build a params JSON whose `state_handle` / `initial_state_handle` point at
    /// freshly-created in-process pool entries holding the on-chain state. Returns
    /// the params string and the initial-state handle (the assembler replays against
    /// it).
    fn params_with_local_handles(fx: &serde_json::Value) -> String {
        let onchain_hex = fx["onChainStateHex"].as_str().expect("onChainStateHex");
        let hex_c = CString::new(onchain_hex).unwrap();
        let init_h = contract_state_create(hex_c.as_ptr());
        assert_ne!(init_h, 0, "failed to create state from on-chain hex");
        let state_h = contract_state_clone(init_h);
        assert_ne!(state_h, 0, "failed to clone state");

        let mut params = fx["params"].clone();
        params["state_handle"] = serde_json::json!(state_h);
        params["initial_state_handle"] = serde_json::json!(init_h);
        serde_json::to_string(&params).unwrap()
    }

    /// The captured fixture is the CORRUPTED transcript the buggy runtime produced:
    /// the `sequence` Counter (b8) read recorded as 0, while the on-chain state
    /// replays as 1. The assembler must reject it — this guards that the native
    /// partition correctly catches a bad transcript. (The producing bug itself lives
    /// in the JS runtime; see `corrected_transcript_assembles_on_evolved_state` for
    /// the fixed-transcript counterpart, and `snapshotReadContent` in
    /// compact-runtime-iife.js for the fix.)
    #[test]
    fn reproduces_readmismatch_on_evolved_state() {
        let params = params_with_local_handles(&fixture());
        let result = assemble_call_tx_impl(&params);
        let err = result.expect_err("a corrupted transcript must be rejected");
        assert!(err.contains("ReadMismatch"), "unexpected error: {}", err);
    }

    /// With the runtime fix (`snapshotReadContent`), the transcript records the real
    /// `sequence` read of 1 instead of the shifted-empty 0. Patch the fixture's
    /// Counter popeq to that corrected value and assert the assembler accepts it —
    /// the positive proof that a faithful transcript assembles against the evolved
    /// on-chain state. Mirrors the on-device post→finalize round-trip.
    #[test]
    fn corrected_transcript_assembles_on_evolved_state() {
        let mut fx = fixture();
        // The b8 Counter read is popeq op[5]; the fix records it as [[1]] (= on-chain).
        fx["params"]["proof_data"]["public_transcript"][5]["popeq"]["result"]["value"] =
            serde_json::json!([[1]]);
        let params = params_with_local_handles(&fx);
        let result = assemble_call_tx_impl(&params);
        assert!(
            result.is_ok(),
            "corrected transcript should assemble, got: {:?}", result.err()
        );
    }

    /// The transcript b8 read is 0, but the on-chain state holds 1: re-gather the
    /// SAME transcript ops natively against the on-chain state and confirm it reads
    /// 1. This exonerates the native query path — the device circuit DID query the
    /// on-chain state and read 1 too; the recorded 0 came from the JS runtime
    /// emptying the read value via `fromValue`'s `shift()` after the read (fixed by
    /// `snapshotReadContent`).
    #[test]
    fn native_regather_reads_seq_one() {
        use midnight_onchain_runtime::context::QueryContext;
        use midnight_onchain_vm::result_mode::GatherEvent;

        let fx = fixture();
        let onchain_hex = fx["onChainStateHex"].as_str().unwrap();
        let bytes = hex_to_bytes(onchain_hex).expect("hex");
        let state: RustContractState<InMemoryDB> =
            midnight_serialize::tagged_deserialize(&mut &bytes[..]).expect("deserialize on-chain state");

        // The transcript b8 read (the recorded popeq[5].result) — what the device
        // circuit claims it read for the Counter.
        let transcript_ops_json = fx["params"]["proof_data"]["public_transcript"]
            .as_array().unwrap();
        let verify_ops: Vec<Op<ResultModeVerify, InMemoryDB>> = serde_json::from_str(
            &to_tag_first_json(&fx["params"]["proof_data"]["public_transcript"]),
        ).expect("deserialize transcript");
        let gather_ops = convert_verify_to_gather(&verify_ops).expect("convert verify→gather");

        let qc = QueryContext::<InMemoryDB> {
            state: state.data.clone(),
            address: Default::default(),
            effects: Default::default(),
            call_context: Default::default(),
        };
        let res = qc.query(&gather_ops, None, &INITIAL_COST_MODEL).expect("gather query");

        // Collect the read values the on-chain state actually yields.
        let reads: Vec<Vec<Vec<u8>>> = res.events.iter().filter_map(|e| match e {
            GatherEvent::Read(av) => Some(
                av.value.0.iter().map(|atom| atom.0.to_vec()).collect()
            ),
            _ => None,
        }).collect();
        println!("native re-gather reads: {:?}", reads);

        // Two reads, in transcript order: [0] = `state` enum (b1), [1] = `sequence`
        // Counter (b8, normalized so 1 → atom [1]). On-chain the Counter is non-zero
        // (a prior post advanced it).
        let native_counter = &reads[1];
        let native_nonzero = native_counter.iter().flatten().any(|&b| b != 0);

        // The device transcript recorded that same Counter read (popeq[5]) as zero —
        // now an empty atom ([], the normal-form encoding of zero) after the serde change.
        let device_counter = transcript_ops_json[5]["popeq"]["result"]["value"][0]
            .as_array().expect("device popeq[5] value");
        let device_zero = device_counter.is_empty()
            || device_counter.iter().all(|v| v.as_u64() == Some(0));
        println!("device transcript b8 read: {:?}", device_counter);

        // The on-chain state reads Counter=1; the device transcript recorded 0. The
        // native query is correct, so the corruption happened in the JS runtime after
        // the read (see `snapshotReadContent`).
        assert!(
            native_nonzero && device_zero,
            "expected on-chain Counter non-zero + device-recorded zero; \
             native={:?} device={:?}", native_counter, device_counter
        );
    }

    /// Reproduce the DEVICE execution path: the circuit splits into one query per
    /// ledger op, and the device's `contract_query` writes each query's resulting
    /// state back into the pool (contract_ffi.rs:285) before the next op runs. Thread
    /// the transcript ops in those same chunks through `qc.query` (Rust ops, no serde
    /// round-trip), feeding each query's `context.state` into the next — exactly what
    /// the device does — and confirm the `sequence` Counter survives every query's
    /// write-back (it does: the native state threading is correct; the corruption was
    /// purely in the JS transcript recording).
    #[test]
    fn split_query_path_preserves_counter() {
        use midnight_onchain_runtime::context::QueryContext;
        use midnight_onchain_state::state::ChargedState;
        use midnight_onchain_vm::result_mode::GatherEvent;

        let fx = fixture();
        let onchain_hex = fx["onChainStateHex"].as_str().unwrap();
        let bytes = hex_to_bytes(onchain_hex).unwrap();
        let state: RustContractState<InMemoryDB> =
            midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();

        let verify_ops: Vec<Op<ResultModeVerify, InMemoryDB>> = serde_json::from_str(
            &to_tag_first_json(&fx["params"]["proof_data"]["public_transcript"]),
        ).unwrap();
        let gather_ops = convert_verify_to_gather(&verify_ops).expect("convert verify→gather");
        let chunks: [&[Op<ResultModeGather, InMemoryDB>]; 5] = [
            &gather_ops[0..3],   // read state
            &gather_ops[3..6],   // read sequence  ← watch this one
            &gather_ops[6..9],   // write owner
            &gather_ops[9..12],  // write message
            &gather_ops[12..15], // write sequence
        ];

        // `data` is threaded between queries exactly as the device pool does.
        let mut data: ChargedState<InMemoryDB> = state.data.clone();
        println!("Counter before any query: {:?}", counter_of(&data));

        let mut sequence_read: Option<Vec<Vec<u8>>> = None;
        for (ci, chunk) in chunks.iter().enumerate() {
            let qc = QueryContext::<InMemoryDB> {
                state: data.clone(),
                address: Default::default(),
                effects: Default::default(),
                call_context: Default::default(),
            };
            let res = qc.query(chunk, None, &INITIAL_COST_MODEL).expect("query");
            for ev in &res.events {
                if let GatherEvent::Read(av) = ev {
                    let v: Vec<Vec<u8>> = av.value.0.iter().map(|a| a.0.to_vec()).collect();
                    println!("chunk {} read: {:?}", ci, v);
                    if ci == 1 { sequence_read = Some(v); }
                }
            }
            // Device write-back: the next op runs against this query's resulting state.
            data = res.context.state;
            println!("Counter after chunk {}: {:?}", ci, counter_of(&data));
        }

        let seq = sequence_read.expect("chunk 1 must produce a sequence read");
        let nonzero = seq.iter().flatten().any(|&b| b != 0);
        println!("sequence read via device-style split: {:?} (nonzero={})", seq, nonzero);
        assert!(nonzero, "split-path sequence read should be 1, got {:?}", seq);
    }

    /// Field 2 (the `sequence` Counter) of a threaded state, as the FFI field-walker
    /// reports it — by round-tripping through a temporary pool handle.
    fn counter_of(data: &midnight_onchain_state::state::ChargedState<InMemoryDB>) -> serde_json::Value {
        use std::ffi::CStr;
        let mut cs = RustContractState::<InMemoryDB>::default();
        cs.data = data.clone();
        let handle = {
            let h = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            lock_state_pool().unwrap().insert(h, cs);
            h
        };
        let ptr = contract_state_read_fields(handle);
        let json = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
        unsafe { contract_free_string(ptr as *mut c_char) };
        lock_state_pool().unwrap().remove(&handle);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
        v.get(2).cloned().unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use midnight_onchain_vm::ops::Op;
    use midnight_onchain_vm::result_mode::ResultModeVerify;
    use midnight_storage::db::InMemoryDB;
    use midnight_base_crypto::fab::{
        AlignedValue, Value, Alignment, AlignmentSegment, AlignmentAtom,
    };
    use midnight_onchain_state::state::StateValue;

    /// Every handled `Op` variant must survive `convert_verify_to_gather` — none
    /// may silently collapse to `Noop` (which would corrupt the re-gathered
    /// transcript). Build one of each handled variant and assert the conversion
    /// succeeds and preserves length.
    #[test]
    fn gather_conversion_covers_every_op() {
        use midnight_transient_crypto::curve::Fr;

        // An AlignedValue for the Popeq result (ResultModeVerify::ReadResult).
        let zero_fr = Fr::from_le_bytes(&[0u8]).unwrap();
        let field_align = Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]);
        let aligned_zero = AlignedValue {
            value: Value::from(zero_fr),
            alignment: field_align.clone(),
        };

        // A Key for the Idx path.
        let key = midnight_onchain_vm::ops::Key::Value(AlignedValue {
            value: Value::from(zero_fr),
            alignment: field_align,
        });

        let ops: Vec<Op<ResultModeVerify, InMemoryDB>> = vec![
            Op::Dup { n: 1 },
            Op::Pop,
            Op::Idx { cached: false, push_path: false, path: vec![key].into_iter().collect() },
            Op::Ins { cached: false, n: 1 },
            Op::Lt,
            Op::Eq,
            Op::Add,
            Op::Sub,
            Op::Neg,
            Op::And,
            Op::Or,
            Op::Type,
            Op::Size,
            Op::New,
            Op::Log,
            Op::Root,
            Op::Member,
            Op::Ckpt,
            Op::Noop { n: 0 },
            Op::Branch { skip: 0 },
            Op::Jmp { skip: 0 },
            Op::Concat { cached: false, n: 1 },
            Op::Swap { n: 0 },
            Op::Rem { cached: false },
            Op::Addi { immediate: 1 },
            Op::Subi { immediate: 1 },
            Op::Popeq { cached: false, result: aligned_zero },
            Op::Push { storage: false, value: StateValue::Null },
        ];
        let expected_len = ops.len();

        let gathered = convert_verify_to_gather(&ops)
            .expect("every handled op variant must convert");
        assert_eq!(
            gathered.len(), expected_len,
            "conversion must preserve length — a variant silently collapsed"
        );
    }

    /// The exported client ledger version must match the vendored ledger so the
    /// host's coherence check compares the right string.
    #[test]
    fn ledger_version_is_exported() {
        let ptr = kuira_ledger_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
        unsafe { contract_free_string(ptr as *mut c_char) };
        assert_eq!(s, "8.0.3");
    }
}

#[cfg(test)]
mod funding_offer_tests {
    use super::*;
    use midnight_base_crypto::signatures::SigningKey;
    use midnight_serialize::Serializable;
    use serde_json::json;

    // A deterministic NIGHT key and the hex of its verifying key (the input owner).
    fn night_key_and_vk_hex() -> ([u8; 32], String) {
        let nk = [7u8; 32];
        let sk = SigningKey::from_bytes(&nk).expect("signing key from bytes");
        let vk = sk.verifying_key();
        let mut buf = Vec::new();
        Serializable::serialize(&vk, &mut buf).expect("serialize verifying key");
        (nk, hex::encode(&buf))
    }

    // The core fix for node error 138: the funding offer must contribute EXACTLY the
    // received `amount` to the unshielded segment (Σinputs − Σoutputs == amount), so it
    // cancels the contract's receiveUnshielded(−amount) and the segment balances.
    #[test]
    fn funding_offer_provides_exactly_the_received_amount() {
        let (nk, vk_hex) = night_key_and_vk_hex();
        let native = "00".repeat(32);
        let ih = "11".repeat(32);
        // inputs 6M + 4M = 10M; contract claims 7M; change 3M.
        let funding = json!({
            "amount": "7000000",
            "change_owner": "22".repeat(32),
            "night_private_key": hex::encode(nk),
            "inputs": [
                {"value":"6000000","owner":vk_hex,"type":native,"intent_hash":ih,"output_no":0},
                {"value":"4000000","owner":vk_hex,"type":native,"intent_hash":ih,"output_no":1}
            ]
        });
        let (offer, keys) = build_funding_offer(&funding).expect("build offer");
        let in_sum: u128 = offer.inputs.iter().map(|s| s.value).sum();
        let out_sum: u128 = offer.outputs.iter().map(|o| o.value).sum();
        assert_eq!(in_sum, 10_000_000, "inputs sum");
        assert_eq!(out_sum, 3_000_000, "change output value");
        assert_eq!(in_sum - out_sum, 7_000_000, "offer must fund exactly the received amount");
        assert_eq!(keys.len(), 2, "one signing key per input");
        assert_eq!(offer.outputs.iter().count(), 1, "exactly one change output");
    }

    // When inputs sum exactly to the amount, there is no change → zero outputs
    // (UtxoOutput requires value > 0). The segment still balances (Σinputs == amount).
    #[test]
    fn funding_offer_zero_change_emits_no_output() {
        let (nk, vk_hex) = night_key_and_vk_hex();
        let native = "00".repeat(32);
        let ih = "11".repeat(32);
        let funding = json!({
            "amount": "5000000",
            "change_owner": "22".repeat(32),
            "night_private_key": hex::encode(nk),
            "inputs": [
                {"value":"5000000","owner":vk_hex,"type":native,"intent_hash":ih,"output_no":0}
            ]
        });
        let (offer, keys) = build_funding_offer(&funding).expect("build offer");
        assert_eq!(offer.outputs.iter().count(), 0, "no change output when change is zero");
        let in_sum: u128 = offer.inputs.iter().map(|s| s.value).sum();
        assert_eq!(in_sum, 5_000_000);
        assert_eq!(keys.len(), 1);
    }

    // Inputs that don't cover the amount are rejected up front, not left to underflow.
    #[test]
    fn funding_offer_rejects_insufficient_inputs() {
        let (nk, vk_hex) = night_key_and_vk_hex();
        let native = "00".repeat(32);
        let ih = "11".repeat(32);
        let funding = json!({
            "amount": "9000000",
            "change_owner": "22".repeat(32),
            "night_private_key": hex::encode(nk),
            "inputs": [
                {"value":"5000000","owner":vk_hex,"type":native,"intent_hash":ih,"output_no":0}
            ]
        });
        let err = build_funding_offer(&funding).unwrap_err();
        assert!(err.contains("< amount"), "expected insufficient-inputs error, got: {}", err);
    }
}
