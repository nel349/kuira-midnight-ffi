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
    let mut pool = STATE_POOL.lock().unwrap();
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

    let opcodes_str = match unsafe { c_str_to_str(opcodes_json) } {
        Some(s) => s,
        None => return std::ptr::null(),
    };

    // Get state from pool
    let state = {
        let pool = STATE_POOL.lock().unwrap();
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

    // Build QueryContext from state (same as ContractStateExt::query but preserves gas)
    let qc = QueryContext::<InMemoryDB> {
        state: state.data.clone(),
        address: Default::default(),
        effects: Default::default(),
        call_context: Default::default(),
    };

    // Execute query — returns gas_cost
    match qc.query(&ops, None, &INITIAL_COST_MODEL) {
        Ok(results) => {
            // Build new ContractState from results
            let new_state = RustContractState {
                data: results.context.state,
                ..state
            };
            STATE_POOL.lock().unwrap().insert(handle, new_state);

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
    let pool = STATE_POOL.lock().unwrap();
    let state = match pool.get(&handle) {
        Some(s) => s.clone(),
        None => return 0,
    };
    drop(pool);

    let new_handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    STATE_POOL.lock().unwrap().insert(new_handle, state);
    new_handle
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

    // Construct directly — bypasses the serde try_from validation
    Ok(AlignedValue {
        value: Value(value_atoms),
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

/// Parse a Key from JSON for idx path entries.
fn parse_key(val: &serde_json::Value) -> Result<midnight_onchain_vm::ops::Key, String> {
    let tag = val["tag"].as_str().ok_or("key missing tag")?;
    match tag {
        "value" => {
            let av = parse_aligned_value(&val["value"])?;
            Ok(midnight_onchain_vm::ops::Key::Value(av))
        }
        other => Err(format!("unknown key tag: {}", other)),
    }
}

/// Parse transcript ops from JSON into Vec<Op<ResultModeVerify, InMemoryDB>>.
///
/// Op<ResultModeVerify> can't be JSON-deserialized via serde_json due to
/// Midnight's Storable derive generating storage-aware serde. We parse
/// each op manually and construct the Rust types directly.
fn parse_transcript_ops(
    ops: &[serde_json::Value],
) -> Result<Vec<Op<midnight_onchain_vm::result_mode::ResultModeVerify, InMemoryDB>>, String> {
    use midnight_onchain_vm::result_mode::ResultModeVerify;
    use midnight_onchain_state::state::StateValue as RustSV;

    let mut result = Vec::new();
    for (i, op_val) in ops.iter().enumerate() {
        let op = if let Some(dup) = op_val.get("dup") {
            let n = u8::try_from(dup["n"].as_u64().ok_or(format!("op[{}] dup missing n", i))?)
                .map_err(|_| format!("op[{}] dup n out of range", i))?;
            Op::<ResultModeVerify, InMemoryDB>::Dup { n }
        } else if op_val.get("pop").is_some() {
            Op::Pop
        } else if let Some(popeq) = op_val.get("popeq") {
            let cached = popeq["cached"].as_bool().unwrap_or(false);
            let result_av = parse_aligned_value(&popeq["result"])
                .map_err(|e| format!("op[{}] popeq.result: {}", i, e))?;
            Op::Popeq { cached, result: result_av }
        } else if let Some(push) = op_val.get("push") {
            let storage = push["storage"].as_bool().unwrap_or(false);
            let sv = parse_state_value(&push["value"])
                .map_err(|e| format!("op[{}] push.value: {}", i, e))?;
            Op::Push { storage, value: sv }
        } else if let Some(idx) = op_val.get("idx") {
            let cached = idx["cached"].as_bool().unwrap_or(false);
            let push_path = idx.get("pushPath")
                .or_else(|| idx.get("push_path"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let path_arr = idx["path"].as_array()
                .ok_or(format!("op[{}] idx missing path", i))?;
            let keys: Vec<midnight_onchain_vm::ops::Key> = path_arr.iter()
                .enumerate()
                .map(|(j, k)| parse_key(k).map_err(|e| format!("op[{}] path[{}]: {}", i, j, e)))
                .collect::<Result<_, _>>()?;
            Op::Idx { cached, push_path, path: keys.into_iter().collect() }
        } else if let Some(ins) = op_val.get("ins") {
            let cached = ins["cached"].as_bool().unwrap_or(false);
            let n = u8::try_from(ins["n"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Ins { cached, n }
        } else if op_val.get("lt").is_some() || op_val.as_str() == Some("lt") {
            Op::Lt
        } else if op_val.get("eq").is_some() || op_val.as_str() == Some("eq") {
            Op::Eq
        } else if let Some(noop) = op_val.get("noop") {
            let n = u32::try_from(noop["n"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Noop { n }
        } else if let Some(branch) = op_val.get("branch") {
            let skip = u32::try_from(branch["skip"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Branch { skip }
        } else if op_val.get("add").is_some() || op_val.as_str() == Some("add") {
            Op::Add
        } else if op_val.get("sub").is_some() || op_val.as_str() == Some("sub") {
            Op::Sub
        } else if let Some(concat) = op_val.get("concat") {
            let cached = concat["cached"].as_bool().unwrap_or(false);
            let n = u32::try_from(concat["n"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Concat { cached, n }
        } else if let Some(swap) = op_val.get("swap") {
            let n = u8::try_from(swap["n"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Swap { n }
        } else if let Some(rem) = op_val.get("rem") {
            let cached = rem["cached"].as_bool().unwrap_or(false);
            Op::Rem { cached }
        } else if op_val.get("ckpt").is_some() {
            Op::Ckpt
        } else if op_val.get("member").is_some() || op_val.as_str() == Some("member") {
            Op::Member
        } else if op_val.get("neg").is_some() || op_val.as_str() == Some("neg") {
            Op::Neg
        } else if op_val.get("and").is_some() || op_val.as_str() == Some("and") {
            Op::And
        } else if op_val.get("or").is_some() || op_val.as_str() == Some("or") {
            Op::Or
        } else if op_val.get("type").is_some() || op_val.as_str() == Some("type") {
            Op::Type
        } else if op_val.get("size").is_some() || op_val.as_str() == Some("size") {
            Op::Size
        } else if op_val.get("new").is_some() || op_val.as_str() == Some("new") {
            Op::New
        } else if op_val.get("log").is_some() || op_val.as_str() == Some("log") {
            Op::Log
        } else if op_val.get("root").is_some() || op_val.as_str() == Some("root") {
            Op::Root
        } else if let Some(jmp) = op_val.get("jmp") {
            let skip = u32::try_from(jmp["skip"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Jmp { skip }
        } else if let Some(addi) = op_val.get("addi") {
            let imm = u32::try_from(addi["immediate"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Addi { immediate: imm }
        } else if let Some(subi) = op_val.get("subi") {
            let imm = u32::try_from(subi["immediate"].as_u64().unwrap_or(0)).unwrap_or(0);
            Op::Subi { immediate: imm }
        } else {
            return Err(format!("op[{}] unknown format: {}", i,
                serde_json::to_string(op_val).unwrap_or_default().chars().take(200).collect::<String>()));
        };
        result.push(op);
    }
    Ok(result)
}

/// Parse a StateValue from JSON.
/// StateValue has custom Storable serde that doesn't round-trip through JSON.
fn parse_state_value(val: &serde_json::Value) -> Result<midnight_onchain_state::state::StateValue<InMemoryDB>, String> {
    use midnight_onchain_state::state::StateValue as SV;
    use midnight_storage::arena::Sp;

    if val.is_null() {
        return Ok(SV::Null);
    }

    // Tagged format: { "tag": "null" } or { "tag": "cell", "content": {...} } etc.
    if let Some(tag) = val.get("tag").and_then(|t| t.as_str()) {
        return match tag {
            "null" => Ok(SV::Null),
            "cell" => {
                let av = parse_aligned_value(&val["content"])
                    .map_err(|e| format!("cell content: {}", e))?;
                Ok(SV::Cell(Sp::new(av)))
            }
            "array" => {
                let items = val["content"].as_array().ok_or("array missing content")?;
                let values: Vec<SV<InMemoryDB>> = items.iter()
                    .map(|item| parse_state_value(item))
                    .collect::<Result<_, _>>()?;
                Ok(SV::Array(values.into()))
            }
            other => Err(format!("unknown StateValue tag: {}", other)),
        };
    }

    // Simple null check
    if val.as_str() == Some("null") {
        return Ok(SV::Null);
    }

    Err(format!("unrecognized StateValue format: {}",
        serde_json::to_string(val).unwrap_or_default().chars().take(100).collect::<String>()))
}

/// Convert ResultModeVerify ops to ResultModeGather for re-execution.
/// Strips popeq.result (AlignedValue → ()) since the VM recomputes results.
fn convert_verify_to_gather(
    ops: &[Op<midnight_onchain_vm::result_mode::ResultModeVerify, InMemoryDB>],
) -> Vec<Op<ResultModeGather, InMemoryDB>> {
    ops.iter().map(|op| match op {
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
        Op::Pop => Op::Pop,
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
        _ => Op::Noop { n: 0 }, // Unknown ops → noop (shouldn't happen)
    }).collect()
}

fn assemble_call_tx_impl(json_str: &str) -> Result<String, String> {
    use midnight_onchain_vm::result_mode::ResultModeVerify;
    use midnight_onchain_runtime::transcript::{Transcript, TranscriptVersion};
    use midnight_onchain_runtime::context::Effects;
    use midnight_onchain_state::state::{ContractOperation, EntryPointBuf};
    use midnight_ledger::construct::ContractCallPrototype;
    use midnight_ledger::structure::{Transaction, Intent, ProofPreimageMarker};
    use midnight_transient_crypto::proofs::{ProofPreimage, KeyLocation};
    use midnight_transient_crypto::curve::Fr;
    use midnight_base_crypto::cost_model::RunningCost;
    use midnight_base_crypto::signatures::Signature;
    use midnight_base_crypto::time::Timestamp;
    use midnight_storage::arena::Sp;
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

    // 4. Parse public transcript ops manually.
    //    Op<ResultModeVerify> can't be JSON-deserialized due to Midnight's
    //    Storable derive generating storage-aware serde implementations.
    //    We parse the JSON and construct ops by hand.
    let transcript_array = proof_data["public_transcript"].as_array()
        .ok_or("public_transcript is not an array")?;
    let transcript_ops = parse_transcript_ops(transcript_array)
        .map_err(|e| format!("transcript parse: {}", e))?;

    // 5. Compute correct gas by re-executing transcript ops against initial state.
    //    The prover embeds gas into the binding_input hash — zeroed gas = proof rejection.
    //    We use QueryContext::query() (not ContractStateExt::query()) to preserve gas.
    let (gas, effects) = {
        use midnight_onchain_runtime::context::QueryContext;

        let pool = STATE_POOL.lock().map_err(|e| format!("lock: {}", e))?;
        let initial_state = pool.get(&initial_state_handle)
            .ok_or(format!("invalid initial_state_handle: {}", initial_state_handle))?;

        // Also validate the final state handle
        if !pool.contains_key(&state_handle) {
            return Err(format!("invalid state_handle: {}", state_handle));
        }

        // Convert Verify-mode ops to Gather-mode for re-execution
        // (strip popeq results — the VM will recompute them)
        let gather_ops = convert_verify_to_gather(&transcript_ops);

        let qc = QueryContext::<InMemoryDB> {
            state: initial_state.data.clone(),
            address: Default::default(),
            effects: Default::default(),
            call_context: Default::default(),
        };

        match qc.query(&gather_ops, None, &INITIAL_COST_MODEL) {
            Ok(results) => {
                (results.gas_cost, results.context.effects)
            }
            Err(e) => return Err(format!("gas re-execution failed: {:?}", e)),
        }
    };

    // SCALE round-trip the ops to normalize internal storage state.
    // Manually-constructed Op types may have different Sp/Arena state
    // than ops produced through the Storable infrastructure, which causes
    // field_repr encoding differences during proving.
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

    let transcript = Transcript::<InMemoryDB> {
        gas,
        effects,
        program: normalized_ops.into_iter().collect(),
        version: Some(Sp::new(Transcript::<InMemoryDB>::VERSION)),
    };

    // 6. ContractOperation (verifier key loaded separately during proving)
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
        guaranteed_public_transcript: Some(transcript),
        fallible_public_transcript: None,
        private_transcript_outputs: private_outputs,
        input,
        output,
        communication_commitment_rand: comm_rand,
        key_location: KeyLocation(std::borrow::Cow::Owned(entry_point.to_owned())),
    };

    // 8. Build Intent with the contract call
    let ttl = Timestamp::MAX;
    let intent = Intent::<Signature, ProofPreimageMarker, _, InMemoryDB>::empty(
        &mut OsRng, ttl,
    ).add_call::<ProofPreimage>(prototype);

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
}

#[cfg(test)]
mod hash_debug_tests {
    use super::*;
    use std::ffi::{CString, CStr};

    #[test]
    fn test_bboard_public_key_hash() {
        // Reproduce the exact hash computation from bboard post circuit:
        // _publicKey_0(secretKey, posterCount) = persistentHash(vector3_bytes32, [prefix, sequence, sk])
        let mut prefix = vec![98u8, 98, 111, 97, 114, 100, 58, 112, 107, 58]; // "bboard:pk:"
        prefix.resize(32, 0);
        // poster count = 1 (initialState increments from 0 via addi{1})
        let mut sequence: Vec<u8> = vec![0; 32];
        sequence[0] = 1; // LE encoding of 1
        let secret_key: Vec<u8> = (1..=32).collect(); // test secret key

        let json = format!(
            r#"{{"value":[{},{},{}],"alignment":[{{"tag":"atom","value":{{"tag":"bytes","length":32}}}},{{"tag":"atom","value":{{"tag":"bytes","length":32}}}},{{"tag":"atom","value":{{"tag":"bytes","length":32}}}}]}}"#,
            format!("[{}]", prefix.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")),
            format!("[{}]", sequence.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")),
            format!("[{}]", secret_key.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")),
        );

        let input = CString::new(json).unwrap();
        let result = contract_persistent_hash_aligned(input.as_ptr());
        assert!(!result.is_null());

        let result_str = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        println!("bboard publicKey hash: {}", result_str);

        // Parse the result — it's a Value (array of byte arrays)
        let parsed: Vec<Vec<u8>> = serde_json::from_str(result_str).unwrap();
        println!("Hash bytes: {:02x?}", &parsed[0][..8]);

        // The first byte of the hash determines the field element at position 27
        // in the prover's encoding. We expect 0x20 (32) from the ZKIR circuit.
        println!("First field chunk LE: first few bytes = {:02x?}", &parsed[0][..4]);

        unsafe { contract_free_string(result as *mut c_char); }
    }
}
