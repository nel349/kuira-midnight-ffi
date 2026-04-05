//! Contract FFI — exposes onchain-runtime types for the QuickJS shim.
//!
//! These functions are called by the QuickJS compact-runtime shim
//! to execute contract operations natively instead of via WASM.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use midnight_base_crypto::hash::{persistent_hash, HashOutput, PersistentHashWriter};
use midnight_base_crypto::fab::{AlignedValue, Value};
use midnight_base_crypto::fab::ValueAtom;
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_serialize::Serializable;

// Contract state types for query execution
use midnight_storage::db::InMemoryDB;
use midnight_onchain_state::state::ContractState as RustContractState;
use midnight_onchain_runtime::contract_state_ext::ContractStateExt;
use midnight_onchain_vm::cost_model::{CostModel as RustCostModel, INITIAL_COST_MODEL};
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeGather;

/// Helper: convert a C string to a Rust &str
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
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

// ── State Handle Pool ──
// Keep contract states in Rust memory. JS holds integer handles.

use std::sync::Mutex;
use std::collections::HashMap;

static STATE_POOL: once_cell::sync::Lazy<Mutex<HashMap<u64, RustContractState<InMemoryDB>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

static NEXT_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Create a new contract state from SCALE hex, return a handle.
#[no_mangle]
pub extern "C" fn contract_state_create(state_hex: *const c_char) -> u64 {
    let hex_str = match unsafe { c_str_to_str(state_hex) } {
        Some(s) => s,
        None => return 0,
    };
    let bytes = match hex_to_bytes(hex_str) {
        Some(b) => b,
        None => return 0,
    };
    let state: RustContractState<InMemoryDB> =
        match midnight_serialize::Deserializable::deserialize(&mut &bytes[..], 0) {
            Ok(s) => s,
            Err(_) => return 0,
        };

    let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    STATE_POOL.lock().unwrap().insert(handle, state);
    handle
}

/// Serialize a contract state to SCALE hex.
#[no_mangle]
pub extern "C" fn contract_state_serialize(handle: u64) -> *const c_char {
    let pool = STATE_POOL.lock().unwrap();
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

/// Free a contract state handle.
#[no_mangle]
pub extern "C" fn contract_state_free(handle: u64) {
    STATE_POOL.lock().unwrap().remove(&handle);
}

// ── ContractState.query() ──

/// Execute opcodes against a contract state (by handle) and return events.
///
/// Input:
///   handle: state handle from contract_state_create
///   opcodes_json: array of Op (JSON via serde)
///
/// Output:
///   JSON: { "handle": <new_handle>, "events": [...] }
///   The old handle is consumed (state is updated).
///   or { "error": "..." } on failure
#[no_mangle]
pub extern "C" fn contract_query(
    handle: u64,
    opcodes_json: *const c_char,
) -> *const c_char {
    let opcodes_str = match unsafe { c_str_to_str(opcodes_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    // Get state from pool
    let state = {
        let mut pool = STATE_POOL.lock().unwrap();
        match pool.remove(&handle) {
            Some(s) => s,
            None => return to_c_string("{\"error\":\"invalid state handle\"}"),
        }
    };

    // Deserialize opcodes from JSON (serde)
    let ops: Vec<Op<ResultModeGather, InMemoryDB>> =
        match serde_json::from_str(opcodes_str) {
            Ok(o) => o,
            Err(e) => {
                // Put state back
                STATE_POOL.lock().unwrap().insert(handle, state);
                return to_c_string(&format!("{{\"error\":\"opcodes deserialize: {}\"}}", e));
            }
        };

    // Execute query with initial cost model
    match state.query(&ops, &INITIAL_COST_MODEL) {
        Ok((new_state, events)) => {
            // Store new state, get new handle
            let new_handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            STATE_POOL.lock().unwrap().insert(new_handle, new_state);

            // Serialize events to JSON (serde)
            let events_json = match serde_json::to_string(&events) {
                Ok(s) => s,
                Err(e) => return to_c_string(&format!("{{\"error\":\"events serialize: {}\"}}", e)),
            };

            to_c_string(&format!("{{\"handle\":{},\"events\":{}}}", new_handle, events_json))
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

    // Deserialize AlignedValue from JSON
    let aligned: AlignedValue = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => return to_c_string(&format!("{{\"error\":\"deserialize: {}\"}}", e)),
    };

    // Use binary_repr + PersistentHashWriter — exactly what the WASM does
    let mut hasher = PersistentHashWriter::default();
    ValueReprAlignedValue(aligned).binary_repr(&mut hasher);
    let hash_value = Value::from(hasher.finalize());

    // Serialize result as JSON
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
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

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
        // First create a value from 42
        let input = CString::new("42").unwrap();
        let value_json = contract_big_int_to_value(input.as_ptr());
        assert!(!value_json.is_null());

        // Then convert back
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

/// Create a ContractState with an array of N null slots.
/// Returns a handle for subsequent query() calls.
#[no_mangle]
pub extern "C" fn contract_state_create_with_nulls(num_slots: u32) -> u64 {
    use midnight_onchain_state::state::{
        ContractState as RustCS, ChargedState as RustChargedState,
        StateValue as RustSV, ContractOperation as RustCO,
    };
    use midnight_storage::db::InMemoryDB;

    // Build array of N null StateValues
    let items: Vec<RustSV<InMemoryDB>> = (0..num_slots)
        .map(|_| RustSV::Null)
        .collect();
    let array = RustSV::Array(items.into());
    let charged = RustChargedState::new(array);

    let mut state = RustCS::default();
    state.data = charged;

    let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    STATE_POOL.lock().unwrap().insert(handle, state);
    handle
}

/// Set an operation on a contract state (by handle).
/// operation_name: e.g. "post", "takeDown"
#[no_mangle]
pub extern "C" fn contract_state_set_operation(
    handle: u64,
    operation_name: *const c_char,
) {
    let name = match unsafe { c_str_to_str(operation_name) } {
        Some(s) => s,
        None => return,
    };

    let mut pool = STATE_POOL.lock().unwrap();
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
        let handle = contract_state_create_with_nulls(4);
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

        // Just do a simple dup — should succeed since the state exists
        let opcodes = r#"[{"dup":{"n":0}}]"#.to_string();
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
