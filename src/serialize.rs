//! Transaction Serialization - SCALE codec for Midnight transactions
//!
//! Provides serialization of signed Intents to SCALE format for node submission.
//! Phase 2: Unshielded transactions only (guaranteed offer)

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Android logging
#[cfg(target_os = "android")]
// use log::{info, error}; // Unused - we use android_log macros directly

// Logging macro that works on both Android and other platforms
#[cfg(target_os = "android")]
macro_rules! log_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*);
    }
}

#[cfg(not(target_os = "android"))]
macro_rules! log_info {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    }
}

// Error logging macro that shows in Android logcat
#[cfg(target_os = "android")]
macro_rules! log_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*);
    }
}

#[cfg(not(target_os = "android"))]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!("[ERROR] {}", format!($($arg)*));
    }
}

use midnight_ledger::structure::{Intent, UnshieldedOffer, UtxoSpend, UtxoOutput, IntentHash, ProofPreimageMarker, Transaction, ProofMarker};
use midnight_ledger::dust::{DustActions, DustLocalState, DustSecretKey, Seed};
use midnight_coin_structure::coin::{UnshieldedTokenType, UserAddress};
use midnight_storage::DefaultDB;
use midnight_serialize::{tagged_serialize, tagged_deserialize};  // CRITICAL: Use tagged serialization
use midnight_storage::arena::Sp;
use midnight_base_crypto::signatures::{Signature, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use rand::{SeedableRng, rngs::StdRng};
use midnight_base_crypto::hash::HashOutput;
use midnight_transient_crypto::commitment::{Pedersen, PedersenRandomness, PureGeneratorPedersen};
use midnight_transient_crypto::curve::EmbeddedFr;
use midnight_transient_crypto::proofs::ProvingKeyMaterial;
use midnight_serialize::Deserializable;
use serde::{Deserialize as SerdeDeserialize, Serialize};
use rand::Rng;

/// Serialize a signed Intent with dust fee payment to SCALE hex.
///
/// This function creates real DustActions by calling state.spend() on the provided
/// DustLocalState, following the TypeScript SDK pattern.
///
/// # Parameters
///
/// - `inputs_hex`: JSON array of UtxoSpend objects
/// - `outputs_hex`: JSON array of UtxoOutput objects
/// - `signatures_hex`: JSON array of signature hex strings
/// - `dust_state_ptr`: Pointer to DustLocalState (from create_dust_local_state)
/// - `seed_ptr`: Pointer to 32-byte seed for deriving DustSecretKey
/// - `seed_len`: Length of seed (must be 32)
/// - `dust_utxos_json`: JSON array of {utxo_index, v_fee} objects
/// - `current_time_ms`: Current time in milliseconds
/// - `ttl`: Transaction time-to-live (milliseconds since epoch)
/// - `binding_randomness_hex`: Hex-encoded binding commitment (32 bytes)
///
/// # Returns
///
/// - Non-null C string containing hex-encoded SCALE bytes
/// - Null pointer on error
#[no_mangle]
pub extern "C" fn serialize_unshielded_transaction_with_dust(
    inputs_hex: *const c_char,
    outputs_hex: *const c_char,
    signatures_hex: *const c_char,
    dust_state_ptr: *mut DustLocalState<DefaultDB>,
    seed_ptr: *const u8,
    seed_len: usize,
    dust_utxos_json: *const c_char,
    current_time_ms: i64,
    ttl: u64,
    binding_randomness_hex: *const c_char,
    network_id: *const c_char,
) -> *mut c_char {
    // Safety checks
    if inputs_hex.is_null() || outputs_hex.is_null() || signatures_hex.is_null() ||
       dust_state_ptr.is_null() || seed_ptr.is_null() || dust_utxos_json.is_null() ||
       binding_randomness_hex.is_null() || network_id.is_null() {
        log_error!("[Kuira FFI] Null pointer passed to serialize_unshielded_transaction_with_dust");
        return std::ptr::null_mut();
    }

    if seed_len != 32 {
        log_error!("[Kuira FFI] Seed must be 32 bytes, got {}", seed_len);
        return std::ptr::null_mut();
    }

    // Convert C strings to Rust strings
    let inputs_str = match unsafe { CStr::from_ptr(inputs_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Invalid UTF-8 in inputs: {}", e);
            return std::ptr::null_mut();
        }
    };

    let outputs_str = match unsafe { CStr::from_ptr(outputs_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Invalid UTF-8 in outputs: {}", e);
            return std::ptr::null_mut();
        }
    };

    let signatures_str = match unsafe { CStr::from_ptr(signatures_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Invalid UTF-8 in signatures: {}", e);
            return std::ptr::null_mut();
        }
    };

    let dust_utxos_str = match unsafe { CStr::from_ptr(dust_utxos_json).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Invalid UTF-8 in dust_utxos: {}", e);
            return std::ptr::null_mut();
        }
    };

    let binding_randomness_str = match unsafe { CStr::from_ptr(binding_randomness_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Invalid UTF-8 in binding_commitment: {}", e);
            return std::ptr::null_mut();
        }
    };

    let network_id_str = match unsafe { CStr::from_ptr(network_id).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Invalid UTF-8 in network_id: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Convert seed to Seed type
    let seed_slice = unsafe { std::slice::from_raw_parts(seed_ptr, seed_len) };
    let mut seed_array: Seed = [0u8; 32];
    seed_array.copy_from_slice(seed_slice);

    // Derive DustSecretKey from seed
    let dust_secret_key = DustSecretKey::derive_secret_key(&seed_array);

    // Get DustLocalState reference
    let dust_state = unsafe { &*dust_state_ptr };

    // Parse dust UTXO selections
    #[derive(SerdeDeserialize)]
    struct DustUtxoSelection {
        utxo_index: usize,
        v_fee: String,
    }

    let dust_selections: Vec<DustUtxoSelection> = match serde_json::from_str(dust_utxos_str) {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] Failed to parse dust_utxos JSON: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Create current timestamp
    let timestamp = Timestamp::from_secs((current_time_ms / 1000) as u64);

    // Call state.spend() for each UTXO to create DustSpend objects
    // CRITICAL: state.spend() returns (new_state, dust_spend)
    // We need to chain the calls to track state updates
    let utxos: Vec<_> = dust_state.utxos().collect();

    let mut current_state = dust_state.clone();
    let mut dust_spends = Vec::new();

    // Calculate total fee to pay (sum of all v_fee values from Kotlin)
    let total_fee: u128 = dust_selections.iter()
        .map(|s| s.v_fee.parse::<u128>().unwrap_or(0))
        .sum();

    if total_fee == 0 {
        log_error!("[Kuira FFI] Total fee is 0 - nothing to pay");
        return std::ptr::null_mut();
    }

    // Smart UTXO selection: try each UTXO until we find one with enough balance.
    // Kotlin doesn't know which UTXOs have balance, so we find the right one here.
    // Stop once fee is covered - don't create extra DustSpends with v_fee=0.
    let mut fee_remaining = total_fee;

    for (idx, utxo) in utxos.iter().enumerate() {
        if fee_remaining == 0 {
            break;  // Fee is covered, stop creating DustSpends
        }

        // Try to pay the remaining fee from this UTXO
        match current_state.spend(&dust_secret_key, utxo, fee_remaining, timestamp) {
            Ok((new_state, dust_spend)) => {
                current_state = new_state;
                dust_spends.push(dust_spend);
                log_info!("[Kuira FFI] Created DustSpend from UTXO {}: v_fee={}", idx, fee_remaining);
                fee_remaining = 0;  // Full fee paid from this UTXO
            }
            Err(e) => {
                // This UTXO doesn't have enough balance - try the next one
                log_info!("[Kuira FFI] Skipping UTXO {} (insufficient balance: {:?})", idx, e);
                continue;
            }
        }
    }

    if fee_remaining > 0 {
        log_error!("[Kuira FFI] No UTXO has enough balance to pay fee. Need: {}", total_fee);
        return std::ptr::null_mut();
    }

    log_info!("[Kuira FFI] Created {} DustSpend(s) for total fee {}", dust_spends.len(), total_fee);
    match build_and_serialize_intent_with_dust(
        inputs_str,
        outputs_str,
        signatures_str,
        Some((dust_spends, timestamp)),
        ttl,
        binding_randomness_str.to_string(),
        network_id_str,
    ) {
        Ok(hex) => {
            log_info!("[Kuira FFI] Serialization succeeded! Hex length: {}", hex.len());

            // CRITICAL: Update the original state with the new state (nullifier recorded)
            // This ensures Kotlin saves the correct state after transaction finalization
            unsafe {
                *dust_state_ptr = current_state;
            }
            log_info!("[Kuira FFI] ✅ Updated dust state pointer with spent nullifier");

            match CString::new(hex) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    log_error!("[Kuira FFI] Failed to create C string: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            log_error!("[Kuira FFI] ❌ SERIALIZATION ERROR: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// Serialize a signed Intent to SCALE hex (Phase 2: Real implementation)
///
/// Takes hex-encoded components and builds a complete Intent for SCALE serialization.
///
/// # Parameters
///
/// - `inputs_hex`: JSON array of UtxoSpend objects (hex-serialized)
/// - `outputs_hex`: JSON array of UtxoOutput objects (hex-serialized)
/// - `signatures_hex`: JSON array of signature hex strings
/// - `ttl`: Transaction time-to-live in milliseconds
/// - `binding_randomness_hex`: Hex-encoded Pedersen randomness (32 bytes scalar).
///   MUST be the same randomness returned by get_signing_message_for_input!
///
/// # Safety
///
/// - `inputs_hex`, `outputs_hex`, `signatures_hex`, `binding_randomness_hex` must be valid C strings
/// - Caller must call `free_serialized_transaction` on result
///
/// # Returns
///
/// - Non-null C string containing hex-encoded SCALE bytes
/// - Null pointer on error
#[no_mangle]
pub extern "C" fn serialize_unshielded_transaction(
    inputs_hex: *const c_char,
    outputs_hex: *const c_char,
    signatures_hex: *const c_char,
    dust_actions_hex: *const c_char,
    ttl: u64,
    binding_randomness_hex: *const c_char,
    network_id: *const c_char,
) -> *mut c_char {
    // Safety checks
    if inputs_hex.is_null() || outputs_hex.is_null() || signatures_hex.is_null() || dust_actions_hex.is_null() || binding_randomness_hex.is_null() || network_id.is_null() {
        eprintln!("[Kuira FFI] Null pointer passed to serialize_unshielded_transaction");
        return std::ptr::null_mut();
    }

    // Convert C strings to Rust strings
    let inputs_str = match unsafe { CStr::from_ptr(inputs_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in inputs: {}", e);
            return std::ptr::null_mut();
        }
    };

    let outputs_str = match unsafe { CStr::from_ptr(outputs_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in outputs: {}", e);
            return std::ptr::null_mut();
        }
    };

    let signatures_str = match unsafe { CStr::from_ptr(signatures_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in signatures: {}", e);
            return std::ptr::null_mut();
        }
    };

    let dust_actions_str = match unsafe { CStr::from_ptr(dust_actions_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in dust_actions: {}", e);
            return std::ptr::null_mut();
        }
    };

    let binding_randomness_str = match unsafe { CStr::from_ptr(binding_randomness_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in binding_commitment: {}", e);
            return std::ptr::null_mut();
        }
    };

    let network_id_str = match unsafe { CStr::from_ptr(network_id).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in network_id: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Build and serialize Intent with dust actions
    match build_and_serialize_intent(inputs_str, outputs_str, signatures_str, dust_actions_str, ttl, binding_randomness_str.to_string(), network_id_str) {
        Ok(hex) => {
            match CString::new(hex) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    eprintln!("[Kuira FFI] Failed to create C string: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            eprintln!("[Kuira FFI] Serialization error: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// JSON structures for FFI (matches Kotlin Intent model)
#[derive(Debug, SerdeDeserialize, Serialize)]
struct JsonUtxoSpend {
    value: String,  // u128 as string
    owner: String,  // hex-encoded verifying key (33 bytes)
    #[serde(rename = "type")]
    token_type: String,  // hex-encoded token type (32 bytes)
    intent_hash: String,  // hex-encoded intent hash (32 bytes)
    output_no: u32,
}

#[derive(Debug, SerdeDeserialize, Serialize)]
struct JsonUtxoOutput {
    value: String,  // u128 as string
    owner: String,  // hex-encoded user address
    #[serde(rename = "type")]
    token_type: String,  // hex-encoded token type (32 bytes)
}

/// Simplified UTXO input for dust registration.
/// Owner and token type are derived internally (owner = night verifying key,
/// type = NIGHT = all-zero 32 bytes), so only value and UTXO location needed.
#[derive(Debug, SerdeDeserialize, Serialize, Clone)]
struct JsonDustUtxo {
    value: String,        // u128 as string
    intent_hash: String,  // hex-encoded intent hash (32 bytes)
    output_no: u32,
    ctime: u64,           // UTXO creation time (Unix seconds) — for dust calculation
}

/// Build an Intent from JSON strings and serialize to SCALE hex
pub fn build_and_serialize_intent(
    inputs_json: &str,
    outputs_json: &str,
    signatures_json: &str,
    dust_actions_json: &str,
    ttl_ms: u64,
    binding_randomness_hex: String,
    network_id: &str,
) -> Result<String, String> {
    // Parse JSON inputs
    let json_inputs: Vec<JsonUtxoSpend> = serde_json::from_str(inputs_json)
        .map_err(|e| format!("Failed to parse inputs JSON: {}", e))?;

    let json_outputs: Vec<JsonUtxoOutput> = serde_json::from_str(outputs_json)
        .map_err(|e| format!("Failed to parse outputs JSON: {}", e))?;

    let json_signatures: Vec<String> = serde_json::from_str(signatures_json)
        .map_err(|e| format!("Failed to parse signatures JSON: {}", e))?;

    // TODO Phase 2E-DUST: Replace JSON approach with DustLocalState pointer
    // For now, dust_actions will be None (transactions without fees)

    // Convert to midnight-ledger types
    let mut inputs = Vec::new();
    for json_input in json_inputs {
        let value: u128 = json_input.value.parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let owner_bytes = hex::decode(&json_input.owner)
            .map_err(|e| format!("Invalid owner hex: {}", e))?;

        // WORKAROUND: Deserializable::deserialize has a platform-specific bug on Android
        // when using &mut &bytes[..]. Use std::io::Cursor instead.
        if owner_bytes.len() != 32 {
            return Err(format!("VerifyingKey must be 32 bytes, got {}", owner_bytes.len()));
        }
        let mut cursor = std::io::Cursor::new(owner_bytes.clone());
        let verifying_key = <VerifyingKey as Deserializable>::deserialize(&mut cursor, 32)
            .map_err(|e| format!("Invalid verifying key: {:?}", e))?;

        let token_type_bytes = hex::decode(&json_input.token_type)
            .map_err(|e| format!("Invalid token type hex: {}", e))?;
        if token_type_bytes.len() != 32 {
            return Err(format!("Token type must be 32 bytes, got {}", token_type_bytes.len()));
        }
        let mut token_type_array = [0u8; 32];
        token_type_array.copy_from_slice(&token_type_bytes);
        let token_type = UnshieldedTokenType(HashOutput(token_type_array));

        let intent_hash_bytes = hex::decode(&json_input.intent_hash)
            .map_err(|e| format!("Invalid intent hash hex: {}", e))?;
        let intent_hash = IntentHash::deserialize(&mut &intent_hash_bytes[..], 32)
            .map_err(|e| format!("Invalid intent hash: {:?}", e))?;

        inputs.push(UtxoSpend {
            value,
            owner: verifying_key,
            type_: token_type,
            intent_hash,
            output_no: json_input.output_no,
        });
    }

    // Convert outputs
    let mut outputs = Vec::new();
    for json_output in json_outputs {
        let value: u128 = json_output.value.parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let owner_bytes = hex::decode(&json_output.owner)
            .map_err(|e| format!("Invalid owner hex: {}", e))?;
        let user_address = <UserAddress as Deserializable>::deserialize(&mut &owner_bytes[..], 32)
            .map_err(|e| format!("Invalid user address: {:?}", e))?;

        let token_type_bytes = hex::decode(&json_output.token_type)
            .map_err(|e| format!("Invalid token type hex: {}", e))?;
        if token_type_bytes.len() != 32 {
            return Err(format!("Token type must be 32 bytes, got {}", token_type_bytes.len()));
        }
        let mut token_type_array = [0u8; 32];
        token_type_array.copy_from_slice(&token_type_bytes);
        let token_type = UnshieldedTokenType(HashOutput(token_type_array));

        outputs.push(UtxoOutput {
            value,
            owner: user_address,
            type_: token_type,
        });
    }

    // Convert signatures
    let mut signatures = Vec::new();
    for sig_hex in json_signatures {
        let sig_bytes = hex::decode(&sig_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        let signature = Signature::deserialize(&mut &sig_bytes[..], 32)
            .map_err(|e| format!("Invalid signature: {:?}", e))?;
        signatures.push(signature);
    }

    // Sort inputs and outputs (required by midnight-ledger verify.rs:435-442)
    inputs.sort();
    outputs.sort();

    // Store lengths for logging
    let input_count = inputs.len();
    let output_count = outputs.len();
    let _signature_count = signatures.len();

    // Build UnshieldedOffer (EXACT same pattern as diagnostic program)
    let unshielded_offer = UnshieldedOffer::<Signature, DefaultDB> {
        inputs: inputs.into_iter().collect(),
        outputs: outputs.into_iter().collect(),
        signatures: signatures.into_iter().collect(),
    };

    // Build Intent with PROVIDED binding_randomness
    // CRITICAL: Construct EmbeddedFr from raw 32 bytes, NOT SCALE deserialization!
    let randomness_bytes = hex::decode(&binding_randomness_hex)
        .map_err(|e| format!("Invalid binding_randomness hex: {}", e))?;

    // CRITICAL: Use from_le_bytes() to construct from raw field element bytes.
    // SCALE deserialization expects a compact length prefix, but we have raw bytes from .0.to_bytes()
    let binding_randomness: PedersenRandomness = EmbeddedFr::from_le_bytes(&randomness_bytes)
        .ok_or_else(|| "Failed to parse binding_randomness as EmbeddedFr".to_string())?;

    // Parse dust_actions_json (empty array "[]" means no dust)
    let dust_actions_opt = if dust_actions_json.trim() == "[]" {
        None
    } else {
        None
    };

    // CRITICAL: Use ProofPreimageMarker (not ()) to match TypeScript SDK wire format
    // This affects the tagged type in the serialization:
    // - () = proof-erased (wrong)
    // - ProofPreimageMarker = proof-preimage (correct for unproven transactions)
    //
    // CRITICAL: Use PedersenRandomness for unproven transactions (official Midnight type)
    // From midnight-node/ledger/helpers/src/versions/common/transaction.rs:
    //   UnprovenTransaction = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, D>
    //   FinalizedTransaction = Transaction<Signature, ProofMarker, PureGeneratorPedersen, D>
    // Type parameter determines tag: PedersenRandomness → embedded-fr[v1]
    // Proof server transforms: embedded-fr[v1] → pedersen-schnorr[v1]
    let intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: Some(Sp::new(unshielded_offer)),
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: dust_actions_opt,
        ttl: Timestamp::from_secs(ttl_ms / 1000),
        binding_commitment: binding_randomness,  // PedersenRandomness (scalar)
    };

    // CRITICAL FIX: Wrap Intent in Transaction::Standard
    // The Midnight node expects a tagged Transaction type, not a raw Intent!
    use midnight_ledger::structure::{Transaction, StandardTransaction};
    use midnight_storage::storage::HashMap as StorageHashMap;

    // CRITICAL: insert() returns a NEW HashMap (persistent data structure)
    // CRITICAL: Use segment 1, not 0! Segment 0 is reserved for guaranteed offers.
    // Intents MUST use segment >= 1 (see midnight-ledger verify.rs:616-618)
    let intents_map = StorageHashMap::default().insert(1u16, intent);

    let transaction = Transaction::Standard(StandardTransaction {
        network_id: network_id.into(),
        intents: intents_map,
        guaranteed_coins: None,
        fallible_coins: StorageHashMap::default(),
        binding_randomness,
    });

    // CRITICAL: Proof server expects tuple format: (Transaction, HashMap<String, ProvingKeyMaterial>)
    // For simple unshielded transactions, the HashMap is empty (no ZK circuits)
    let proof_data = std::collections::HashMap::<String, ProvingKeyMaterial>::new();

    // Serialize as tuple: (transaction, proof_data)
    let mut bytes = Vec::new();
    tagged_serialize(&(&transaction, &proof_data), &mut bytes)
        .map_err(|e| format!("Tagged SCALE serialization of tuple failed: {:?}", e))?;

    log_info!("[Kuira FFI] Serialized base tx: {} bytes, {} inputs, {} outputs",
              bytes.len(), input_count, output_count);

    Ok(hex::encode(&bytes))
}

/// Build an Intent with DustActions from real DustSpend objects and serialize to SCALE hex.
///
/// This function follows the TypeScript SDK pattern by accepting DustSpend objects
/// created from state.spend(), not JSON.
pub fn build_and_serialize_intent_with_dust(
    inputs_json: &str,
    outputs_json: &str,
    signatures_json: &str,
    dust_spends_opt: Option<(Vec<midnight_ledger::dust::DustSpend<ProofPreimageMarker, DefaultDB>>, Timestamp)>,
    ttl_ms: u64,
    binding_randomness_hex: String,
    network_id: &str,
) -> Result<String, String> {
    // Parse JSON inputs (same as build_and_serialize_intent)
    let json_inputs: Vec<JsonUtxoSpend> = serde_json::from_str(inputs_json)
        .map_err(|e| format!("Failed to parse inputs JSON: {}", e))?;

    let json_outputs: Vec<JsonUtxoOutput> = serde_json::from_str(outputs_json)
        .map_err(|e| format!("Failed to parse outputs JSON: {}", e))?;

    let json_signatures: Vec<String> = serde_json::from_str(signatures_json)
        .map_err(|e| format!("Failed to parse signatures JSON: {}", e))?;

    // Convert to midnight-ledger types (same as original function)
    let mut inputs = Vec::new();
    for json_input in json_inputs {
        let value: u128 = json_input.value.parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let owner_bytes = hex::decode(&json_input.owner)
            .map_err(|e| format!("Invalid owner hex: {}", e))?;

        if owner_bytes.len() != 32 {
            return Err(format!("VerifyingKey must be 32 bytes, got {}", owner_bytes.len()));
        }
        let mut cursor = std::io::Cursor::new(owner_bytes.clone());
        let verifying_key = <VerifyingKey as Deserializable>::deserialize(&mut cursor, 32)
            .map_err(|e| format!("Invalid verifying key: {:?}", e))?;

        let token_type_bytes = hex::decode(&json_input.token_type)
            .map_err(|e| format!("Invalid token type hex: {}", e))?;
        if token_type_bytes.len() != 32 {
            return Err(format!("Token type must be 32 bytes, got {}", token_type_bytes.len()));
        }
        let mut token_type = [0u8; 32];
        token_type.copy_from_slice(&token_type_bytes);
        let token_type = UnshieldedTokenType(HashOutput(token_type));

        let intent_hash_bytes = hex::decode(&json_input.intent_hash)
            .map_err(|e| format!("Invalid intent hash hex: {}", e))?;
        if intent_hash_bytes.len() != 32 {
            return Err(format!("Intent hash must be 32 bytes, got {}", intent_hash_bytes.len()));
        }
        let mut intent_hash = [0u8; 32];
        intent_hash.copy_from_slice(&intent_hash_bytes);
        let intent_hash = IntentHash(HashOutput(intent_hash));

        inputs.push(UtxoSpend {
            value,
            owner: verifying_key,
            type_: token_type,
            intent_hash,
            output_no: json_input.output_no,
        });
    }

    let mut outputs = Vec::new();
    for json_output in json_outputs {
        let value: u128 = json_output.value.parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let user_address_bytes = hex::decode(&json_output.owner)
            .map_err(|e| format!("Invalid user address hex: {}", e))?;
        if user_address_bytes.len() != 32 {
            return Err(format!("UserAddress must be 32 bytes, got {}", user_address_bytes.len()));
        }
        let mut user_address = [0u8; 32];
        user_address.copy_from_slice(&user_address_bytes);
        let user_address = UserAddress(HashOutput(user_address));

        let token_type_bytes = hex::decode(&json_output.token_type)
            .map_err(|e| format!("Invalid token type hex: {}", e))?;
        if token_type_bytes.len() != 32 {
            return Err(format!("Token type must be 32 bytes, got {}", token_type_bytes.len()));
        }
        let mut token_type = [0u8; 32];
        token_type.copy_from_slice(&token_type_bytes);
        let token_type = UnshieldedTokenType(HashOutput(token_type));

        outputs.push(UtxoOutput {
            value,
            owner: user_address,
            type_: token_type,
        });
    }

    // Convert signatures
    let mut signatures = Vec::new();
    for sig_hex in json_signatures {
        let sig_bytes = hex::decode(&sig_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        let signature = Signature::deserialize(&mut &sig_bytes[..], 32)
            .map_err(|e| format!("Invalid signature: {:?}", e))?;
        signatures.push(signature);
    }

    // Sort inputs and outputs (required by midnight-ledger)
    inputs.sort();
    outputs.sort();

    // Build UnshieldedOffer
    let unshielded_offer = UnshieldedOffer::<Signature, DefaultDB> {
        inputs: inputs.into_iter().collect(),
        outputs: outputs.into_iter().collect(),
        signatures: signatures.into_iter().collect(),
    };

    // Deserialize binding_randomness from raw 32-byte field element
    let randomness_bytes = hex::decode(&binding_randomness_hex)
        .map_err(|e| format!("Invalid binding_randomness hex: {}", e))?;
    // Use from_le_bytes() instead of SCALE deserialization (same as build_and_serialize_intent)
    let binding_randomness: PedersenRandomness = EmbeddedFr::from_le_bytes(&randomness_bytes)
        .ok_or_else(|| "Failed to parse binding_randomness as EmbeddedFr".to_string())?;

    use midnight_ledger::structure::Transaction;
    use midnight_storage::storage::HashMap as StorageHashMap;

    // STEP 1: Create base transaction with unshielded offer at segment 1
    // CRITICAL: Segment 0 is RESERVED for guaranteed offers (zswap).
    // Intents MUST use segment >= 1 (see midnight-ledger verify.rs:616-618)
    // Lace SDK uses segment 1 for base intent (Transaction.fromParts())
    let base_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: Some(Sp::new(unshielded_offer)),
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: None,  // NO dust in base intent
        ttl: Timestamp::from_secs(ttl_ms / 1000),
        binding_commitment: binding_randomness,
    };

    let mut base_intents_map = StorageHashMap::default();
    base_intents_map = base_intents_map.insert(1u16, base_intent);
    log_info!("[Kuira FFI] ✅ Created base intent at segment 1 (unshielded offer)");

    // Create base transaction with ONLY the unshielded offer intent
    let mut base_transaction = Transaction::new(
        network_id,
        base_intents_map,
        None,  // No guaranteed_coins
        midnight_storage::storage::HashMap::new(),  // No fallible_coins
    );

    // STEP 2: If dust spends provided, create SEPARATE dust transaction and merge
    if let Some((dust_spends, ctime)) = dust_spends_opt {
        let dust_spend_count = dust_spends.len();

        // Convert Vec<DustSpend> to storage::Array<DustSpend>
        use midnight_storage::storage::Array as StorageArray;
        let spends_array: StorageArray<_, DefaultDB> = dust_spends.into_iter().collect();

        // Create empty registrations (Lace passes empty array for fee payment)
        let registrations_array: StorageArray<midnight_ledger::dust::DustRegistration<Signature, DefaultDB>, DefaultDB> = std::iter::empty().collect();

        // Create DustActions with real spends
        let dust_actions = DustActions {
            spends: spends_array,
            registrations: registrations_array,
            ctime,
        };

        // Generate random segment ID for dust intent (like TypeScript SDK fromPartsRandomized)
        use rand::Rng;
        let dust_segment_id: u16 = rand::rngs::OsRng.gen_range(2..u16::MAX);

        // Dust intent uses zero binding_commitment (no unshielded inputs/outputs)
        // This matches Lace: `let dust_intent_commitment = PedersenRandomness::from(0);`
        let dust_intent_commitment = PedersenRandomness::from(0);

        // Create dust-only intent (matches Lace's addFeePayment at line 325)
        let dust_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
            guaranteed_unshielded_offer: None,  // NO unshielded offer
            fallible_unshielded_offer: None,
            actions: std::iter::empty().collect(),
            dust_actions: Some(Sp::new(dust_actions)),
            ttl: Timestamp::from_secs(ttl_ms / 1000),  // Same TTL as base intent
            binding_commitment: dust_intent_commitment,
        };

        let mut dust_intents_map = StorageHashMap::default();
        dust_intents_map = dust_intents_map.insert(dust_segment_id, dust_intent);

        // Create dust transaction with ONLY the dust intent
        // This matches Lace: `const feeTransaction = Transaction.fromPartsRandomized(network, undefined, undefined, intent);`
        let dust_transaction = Transaction::new(
            network_id,
            dust_intents_map,
            None,  // No guaranteed_coins
            midnight_storage::storage::HashMap::new(),  // No fallible_coins
        );

        // CRITICAL: Merge the two transactions (matches Lace: `transaction.merge(feeTransaction)`)
        // The merge() function combines intents and SUMS binding_randomness values
        base_transaction = base_transaction.merge(&dust_transaction)
            .map_err(|e| format!("Failed to merge dust transaction: {:?}", e))?;

        log_info!("[Kuira FFI] Merged {} dust spends at segment {}", dust_spend_count, dust_segment_id);
    }

    // Final transaction is either:
    // - Just base transaction (if no dust)
    // - Merged base + dust transaction (if dust present)
    let transaction = base_transaction;

    let intent_count = transaction.intents().count();

    // CRITICAL: Proof server expects tuple format: (Transaction, HashMap<String, ProvingKeyMaterial>)
    // For simple unshielded transactions, the HashMap is empty (no ZK circuits)
    let proof_data = std::collections::HashMap::<String, ProvingKeyMaterial>::new();

    // Serialize as tuple: (transaction, proof_data)
    // DO NOT seal the transaction - proof server expects unproven transaction
    let mut bytes = Vec::new();
    tagged_serialize(&(&transaction, &proof_data), &mut bytes)
        .map_err(|e| format!("Tagged SCALE serialization of tuple failed: {:?}", e))?;

    log_info!("[Kuira FFI] Serialized tx with dust: {} bytes, {} intent(s)", bytes.len(), intent_count);

    Ok(hex::encode(&bytes))
}

/// Frees a serialized transaction string.
///
/// # Safety
///
/// `ptr` must be from `serialize_unshielded_transaction()` and not previously freed.
#[no_mangle]
pub extern "C" fn free_serialized_transaction(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// Generate signing message for a specific input in an unshielded transaction.
///
/// This function builds an Intent, binds it, and returns the signature data
/// that must be signed for the given input index. This is the CRITICAL function
/// for real on-chain transactions.
///
/// **IMPORTANT:** The binding_commitment returned by this function MUST be used
/// when serializing the transaction. Otherwise the signature won't match!
///
/// **Flow:**
/// 1. Build Intent from inputs/outputs with provided binding_commitment
/// 2. Bind Intent with segment ID (always 1 for unshielded)
/// 3. Call bound.signatureData(input_index)
/// 4. Return both the signing message and the binding_commitment used
///
/// # Parameters
///
/// - `inputs_json`: JSON array of UtxoSpend objects
/// - `outputs_json`: JSON array of UtxoOutput objects
/// - `input_index`: Which input to generate signature data for (0-based)
/// - `ttl`: Transaction time-to-live in milliseconds
/// - `binding_randomness_hex`: Optional hex-encoded binding commitment (64 bytes).
///   If NULL, generates a random one.
///
/// # Safety
///
/// - `inputs_json`, `outputs_json` must be valid C strings
/// - Caller must call `free_signing_message` on result
///
/// # Returns
///
/// - Non-null C string containing JSON: {"signing_message": "hex", "binding_randomness": "hex"}
/// - Null pointer on error
#[no_mangle]
pub extern "C" fn get_signing_message_for_input(
    inputs_json: *const c_char,
    outputs_json: *const c_char,
    input_index: u32,
    ttl: u64,
    binding_randomness_hex: *const c_char,
) -> *mut c_char {
    // Safety checks
    if inputs_json.is_null() || outputs_json.is_null() {
        eprintln!("[Kuira FFI] Null pointer passed to get_signing_message_for_input");
        return std::ptr::null_mut();
    }

    // Convert C strings to Rust strings
    let inputs_str = match unsafe { CStr::from_ptr(inputs_json).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in inputs: {}", e);
            return std::ptr::null_mut();
        }
    };

    let outputs_str = match unsafe { CStr::from_ptr(outputs_json).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Kuira FFI] Invalid UTF-8 in outputs: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Parse binding_commitment if provided
    let binding_commitment_opt = if binding_randomness_hex.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(binding_randomness_hex).to_str() } {
            Ok(s) if !s.is_empty() => Some(s.to_string()),
            _ => None
        }
    };

    // Build Intent and get signing message
    match build_intent_and_get_signature_data(inputs_str, outputs_str, input_index, ttl, binding_commitment_opt) {
        Ok(json) => {
            match CString::new(json) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    eprintln!("[Kuira FFI] Failed to create C string: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            eprintln!("[Kuira FFI] Failed to generate signing message: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// Build an Intent from JSON and get signature data for a specific input
///
/// Returns JSON: {"signing_message": "hex", "binding_randomness": "hex"}
fn build_intent_and_get_signature_data(
    inputs_json: &str,
    outputs_json: &str,
    input_index: u32,
    ttl_ms: u64,
    binding_randomness_hex: Option<String>,
) -> Result<String, String> {
    // Parse JSON inputs
    let json_inputs: Vec<JsonUtxoSpend> = serde_json::from_str(inputs_json)
        .map_err(|e| format!("Failed to parse inputs JSON: {}", e))?;

    let json_outputs: Vec<JsonUtxoOutput> = serde_json::from_str(outputs_json)
        .map_err(|e| format!("Failed to parse outputs JSON: {}", e))?;

    // Validate input_index
    if input_index as usize >= json_inputs.len() {
        return Err(format!("input_index {} out of bounds (have {} inputs)", input_index, json_inputs.len()));
    }

    // Convert to midnight-ledger types (without signatures yet)
    let mut inputs = Vec::new();
    for json_input in json_inputs {
        let value: u128 = json_input.value.parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let owner_bytes = hex::decode(&json_input.owner)
            .map_err(|e| format!("Invalid owner hex: {}", e))?;

        // WORKAROUND: Deserializable::deserialize has a platform-specific bug on Android
        // when using &mut &bytes[..]. Use std::io::Cursor instead.
        if owner_bytes.len() != 32 {
            return Err(format!("VerifyingKey must be 32 bytes, got {}", owner_bytes.len()));
        }
        let mut cursor = std::io::Cursor::new(owner_bytes.clone());
        let verifying_key = <VerifyingKey as Deserializable>::deserialize(&mut cursor, 32)
            .map_err(|e| format!("Invalid verifying key: {:?}", e))?;

        let token_type_bytes = hex::decode(&json_input.token_type)
            .map_err(|e| format!("Invalid token type hex: {}", e))?;
        if token_type_bytes.len() != 32 {
            return Err(format!("Token type must be 32 bytes, got {}", token_type_bytes.len()));
        }
        let mut token_type_array = [0u8; 32];
        token_type_array.copy_from_slice(&token_type_bytes);
        let token_type = UnshieldedTokenType(HashOutput(token_type_array));

        let intent_hash_bytes = hex::decode(&json_input.intent_hash)
            .map_err(|e| format!("Invalid intent hash hex: {}", e))?;
        let intent_hash = IntentHash::deserialize(&mut &intent_hash_bytes[..], 32)
            .map_err(|e| format!("Invalid intent hash: {:?}", e))?;

        inputs.push(UtxoSpend {
            value,
            owner: verifying_key,
            type_: token_type,
            intent_hash,
            output_no: json_input.output_no,
        });
    }

    // Convert outputs
    let mut outputs = Vec::new();
    for json_output in json_outputs {
        let value: u128 = json_output.value.parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let owner_bytes = hex::decode(&json_output.owner)
            .map_err(|e| format!("Invalid owner hex: {}", e))?;
        let user_address = <UserAddress as Deserializable>::deserialize(&mut &owner_bytes[..], 32)
            .map_err(|e| format!("Invalid user address: {:?}", e))?;

        let token_type_bytes = hex::decode(&json_output.token_type)
            .map_err(|e| format!("Invalid token type hex: {}", e))?;
        if token_type_bytes.len() != 32 {
            return Err(format!("Token type must be 32 bytes, got {}", token_type_bytes.len()));
        }
        let mut token_type_array = [0u8; 32];
        token_type_array.copy_from_slice(&token_type_bytes);
        let token_type = UnshieldedTokenType(HashOutput(token_type_array));

        outputs.push(UtxoOutput {
            value,
            owner: user_address,
            type_: token_type,
        });
    }

    // CRITICAL: sort inputs/outputs into the ledger's canonical order (UtxoSpend/UtxoOutput
    // derive Ord) BEFORE computing data_to_sign — the serialize paths
    // (build_and_serialize_intent[_with_dust]) sort identically, and the ledger requires a
    // sorted offer (verify.rs InputsNotSorted/OutputsNotSorted). If we sign the caller's
    // (e.g. largest-first) order while the submitted tx is sorted, data_to_sign won't match
    // and the node rejects with IntentSignatureVerificationFailure (custom error 175).
    inputs.sort();
    outputs.sort();

    // Build UnshieldedOffer WITHOUT signatures (we're generating the data to sign)
    let unshielded_offer = UnshieldedOffer::<Signature, DefaultDB> {
        inputs: inputs.into_iter().collect(),
        outputs: outputs.into_iter().collect(),
        signatures: std::iter::empty().collect(), // Empty - we're generating signature data
    };

    // Build Intent (WITH signatures initially, will be erased)
    // Use provided binding_commitment or generate a random one
    let binding_randomness: PedersenRandomness = if let Some(ref hex) = binding_randomness_hex {
        let commitment_bytes = hex::decode(hex)
            .map_err(|e| format!("Invalid binding_commitment hex: {}", e))?;
        // CRITICAL: reconstruct from the RAW 32-byte field element via from_le_bytes — the
        // exact inverse of the `.0.to_bytes()` we return below. SCALE `Deserializable`
        // expects a compact length prefix and does NOT round-trip these raw scalar bytes
        // (it yields a DIFFERENT scalar), which silently breaks multi-input signing: every
        // input must sign the SAME binding. Mirrors build_and_serialize_intent's reuse path.
        EmbeddedFr::from_le_bytes(&commitment_bytes)
            .ok_or_else(|| "Failed to parse binding_randomness as EmbeddedFr".to_string())?
    } else {
        // Generate random binding_commitment as per midnight-ledger construct.rs:172
        let mut rng = rand::thread_rng();
        rng.gen()
    };

    // CRITICAL: Use ProofPreimageMarker to match TypeScript SDK wire format
    let intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: Some(Sp::new(unshielded_offer)),
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: None,
        ttl: Timestamp::from_secs(ttl_ms / 1000),
        binding_commitment: binding_randomness,
    };

    // CRITICAL: Downgrade to Pedersen, then erase signatures and proofs to get the data to sign
    // Step 1: PedersenRandomness -> Pedersen (required for data_to_sign)
    let intent_pedersen = Intent::<Signature, ProofPreimageMarker, Pedersen, DefaultDB> {
        guaranteed_unshielded_offer: intent.guaranteed_unshielded_offer.clone(),
        fallible_unshielded_offer: intent.fallible_unshielded_offer.clone(),
        actions: intent.actions.clone(),
        dust_actions: intent.dust_actions.clone(),
        ttl: intent.ttl,
        binding_commitment: Pedersen::from(binding_randomness),
    };

    // Step 2: Erase signatures -> Intent<(), ProofPreimageMarker, Pedersen, D>
    let sig_erased = intent_pedersen.erase_signatures();

    // Step 3: Erase proofs -> Intent<(), (), Pedersen, D>
    let fully_erased = sig_erased.erase_proofs();

    // Step 4: Get the data to sign for segment ID 1 (standard for unshielded transactions)
    let signature_data = fully_erased.data_to_sign(1);

    // The signature_data includes ALL the intent data that needs to be signed
    // For multi-input transactions, the SAME data is signed by each input owner
    // (unlike Bitcoin where each input signs different data)

    // Serialize the PedersenRandomness (scalar) to return it
    // NOTE: We return the RANDOMNESS, not the Pedersen commitment (curve point)!
    // CRITICAL: Get RAW 32 bytes from EmbeddedFr, NOT SCALE-encoded!
    // Using SCALE serialization adds a length prefix, making it 33 bytes instead of 32.
    // We need the raw field element bytes.
    // EmbeddedFr is a newtype wrapper, so access inner embedded::Scalar with .0
    let randomness_bytes = binding_randomness.0.to_bytes();  // Returns Vec<u8> with exactly 32 bytes

    // Return JSON with both signing_message and binding_randomness
    let result = serde_json::json!({
        "signing_message": hex::encode(&signature_data),
        "binding_randomness": hex::encode(&randomness_bytes)  // Exactly 32 bytes
    });

    Ok(result.to_string())
}

/// Frees a signing message string.
///
/// # Safety
///
/// `ptr` must be from `get_signing_message_for_input()` and not previously freed.
#[no_mangle]
pub extern "C" fn free_signing_message(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// STUB function for backward compatibility during transition
#[no_mangle]
pub extern "C" fn serialize_unshielded_transaction_stub(
    _ttl: u64,
) -> *mut c_char {
    eprintln!("[Kuira FFI] WARNING: Using stub serializer. Use serialize_unshielded_transaction instead.");

    let stub_hex = "4d4e01000000000001704f2d4200000000";

    match CString::new(stub_hex) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            eprintln!("[Kuira FFI] Failed to create C string: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// Build a dust registration transaction and serialize to SCALE hex.
///
/// Creates a complete transaction with a DustRegistration action AND a
/// guaranteed UnshieldedOffer that consolidates the user's NIGHT UTXOs.
/// The node requires this offer to validate the registration.
///
/// # Flow
///
/// 1. Parse NIGHT UTXOs, build UnshieldedOffer (inputs → single output back to owner)
/// 2. Create DustRegistration with None signature
/// 3. Build Intent with guaranteed_unshielded_offer + dust_actions
/// 4. Erase signatures/proofs, call data_to_sign(segment_id)
/// 5. Sign once with night key
/// 6. Clone signature for DustRegistration AND each offer input
/// 7. Rebuild signed Intent → Transaction
/// 8. Serialize to SCALE hex
///
/// # Parameters
///
/// - `night_private_key_ptr`: 32-byte private key for NIGHT address (signs the registration)
/// - `night_private_key_len`: Must be 32
/// - `dust_public_key_hex`: Hex-encoded DustPublicKey (from derive_dust_public_key)
/// - `allow_fee_payment_str`: Max fee this registration pays, as decimal string (u128)
/// - `ttl_millis`: Transaction TTL in milliseconds since epoch
/// - `current_time_millis`: Current time in milliseconds since epoch
/// - `utxos_json`: JSON array of NIGHT UTXOs: `[{"value":"...","intent_hash":"...","output_no":N}]`
///
/// # Returns
///
/// - Non-null C string containing hex-encoded SCALE bytes (transaction tuple)
/// - Null pointer on error
///
/// # Safety
///
/// - `night_private_key_ptr` must point to valid 32-byte memory
/// - `dust_public_key_hex`, `allow_fee_payment_str`, `utxos_json` must be valid C strings
/// - Caller must call `free_serialized_transaction` on result
#[no_mangle]
pub extern "C" fn build_dust_registration_transaction(
    night_private_key_ptr: *const u8,
    night_private_key_len: usize,
    dust_public_key_hex: *const c_char,
    allow_fee_payment_str: *const c_char,
    ttl_millis: u64,
    current_time_millis: i64,
    utxos_json: *const c_char,
    network_id: *const c_char,
) -> *mut c_char {
    // Validate inputs
    if night_private_key_ptr.is_null() {
        log_error!("[Kuira FFI] build_dust_registration_transaction: night_private_key_ptr is null");
        return std::ptr::null_mut();
    }
    if night_private_key_len != 32 {
        log_error!("[Kuira FFI] build_dust_registration_transaction: key must be 32 bytes, got {}", night_private_key_len);
        return std::ptr::null_mut();
    }
    if dust_public_key_hex.is_null() || allow_fee_payment_str.is_null() || utxos_json.is_null() || network_id.is_null() {
        log_error!("[Kuira FFI] build_dust_registration_transaction: null string parameter");
        return std::ptr::null_mut();
    }

    // Convert inputs — copy key to mutable buffer for zeroization
    use zeroize::Zeroize;
    let key_slice = unsafe { std::slice::from_raw_parts(night_private_key_ptr, 32) };
    let mut key_buf = [0u8; 32];
    key_buf.copy_from_slice(key_slice);

    let dust_pk_str = match unsafe { CStr::from_ptr(dust_public_key_hex).to_str() } {
        Ok(s) => s,
        Err(e) => {
            key_buf.zeroize();
            log_error!("[Kuira FFI] Invalid UTF-8 in dust_public_key_hex: {}", e);
            return std::ptr::null_mut();
        }
    };

    let fee_str = match unsafe { CStr::from_ptr(allow_fee_payment_str).to_str() } {
        Ok(s) => s,
        Err(e) => {
            key_buf.zeroize();
            log_error!("[Kuira FFI] Invalid UTF-8 in allow_fee_payment_str: {}", e);
            return std::ptr::null_mut();
        }
    };

    let utxos_str = match unsafe { CStr::from_ptr(utxos_json).to_str() } {
        Ok(s) => s,
        Err(e) => {
            key_buf.zeroize();
            log_error!("[Kuira FFI] Invalid UTF-8 in utxos_json: {}", e);
            return std::ptr::null_mut();
        }
    };

    let network_id_str = match unsafe { CStr::from_ptr(network_id).to_str() } {
        Ok(s) => s,
        Err(e) => {
            key_buf.zeroize();
            log_error!("[Kuira FFI] Invalid UTF-8 in network_id: {}", e);
            return std::ptr::null_mut();
        }
    };

    let result = build_dust_registration_transaction_impl(
        &key_buf,
        dust_pk_str,
        fee_str,
        ttl_millis,
        current_time_millis,
        utxos_str,
        network_id_str,
    );

    // SECURITY: Always zeroize key buffer before returning
    key_buf.zeroize();

    match result {
        Ok(hex) => {
            match CString::new(hex) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    log_error!("[Kuira FFI] Failed to create C string: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            log_error!("[Kuira FFI] build_dust_registration_transaction failed: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// Filter NIGHT UTXOs down to those NOT yet generating dust (i.e. unregistered).
///
/// Drives the per-UTXO registration loop: register exactly the UTXOs this returns,
/// and terminate when it returns empty. A NIGHT UTXO generates dust iff its
/// `initial_nonce` is the backing-night of some dust UTXO in `dust_state` — the same
/// value `apply_registration` stamps onto the generated dust output. We compute each
/// candidate's `UtxoSpend::initial_nonce()` and keep only those absent from the
/// generating set. All comparison is `InitialNonce`-in-Rust, so there is no
/// cross-language hex matching (synced DustTokens are placeholders and unreliable).
///
/// # Safety
/// - `dust_state_ptr` must be a valid `DustLocalState` pointer (or null → null return)
/// - `night_utxos_json` must be a valid C string `[{value,intent_hash,output_no,ctime}]`
/// - Caller frees the returned string via `free_serialized_transaction`
#[no_mangle]
pub extern "C" fn dust_filter_unregistered_night(
    dust_state_ptr: *const DustLocalState<DefaultDB>,
    night_utxos_json: *const c_char,
) -> *mut c_char {
    if dust_state_ptr.is_null() || night_utxos_json.is_null() {
        log_error!("[Kuira FFI] dust_filter_unregistered_night: null argument");
        return std::ptr::null_mut();
    }

    let json_str = match unsafe { CStr::from_ptr(night_utxos_json).to_str() } {
        Ok(s) => s,
        Err(e) => {
            log_error!("[Kuira FFI] filter: invalid UTF-8 in night utxos: {}", e);
            return std::ptr::null_mut();
        }
    };
    let night_utxos: Vec<JsonDustUtxo> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            log_error!("[Kuira FFI] filter: bad night utxos json: {}", e);
            return std::ptr::null_mut();
        }
    };

    let state = unsafe { &*dust_state_ptr };
    // Generating backing-nights, as raw 32-byte InitialNonce values.
    let generating: std::collections::HashSet<[u8; 32]> =
        state.utxos().map(|u| u.backing_night.0.0).collect();

    // Owner is irrelevant to initial_nonce (it hashes only output_no + intent_hash);
    // a fixed dummy verifying key keeps UtxoSpend construction cheap.
    let dummy_owner = match midnight_base_crypto::signatures::SigningKey::from_bytes(&[1u8; 32]) {
        Ok(k) => k.verifying_key(),
        Err(e) => {
            log_error!("[Kuira FFI] filter: dummy key derivation failed: {}", e);
            return std::ptr::null_mut();
        }
    };

    let unregistered: Vec<JsonDustUtxo> = night_utxos
        .into_iter()
        .filter(|u| {
            let ih = match hex::decode(&u.intent_hash) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let intent_hash = match IntentHash::deserialize(&mut &ih[..], 32) {
                Ok(h) => h,
                Err(_) => return false,
            };
            let spend = UtxoSpend {
                value: 0,
                owner: dummy_owner.clone(),
                type_: UnshieldedTokenType(HashOutput([0u8; 32])), // NIGHT
                intent_hash,
                output_no: u.output_no,
            };
            !generating.contains(&spend.initial_nonce().0 .0)
        })
        .collect();

    log_info!(
        "[Kuira FFI] dust_filter_unregistered_night: {} of {} NIGHT UTXOs not yet generating",
        unregistered.len(),
        generating.len() + unregistered.len()
    );

    let out = serde_json::to_string(&unregistered).unwrap_or_else(|_| "[]".to_string());
    match CString::new(out) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn build_dust_registration_transaction_impl(
    night_private_key: &[u8; 32],
    dust_public_key_hex: &str,
    _allow_fee_payment_str: &str, // Ignored: calculated from UTXO values and creation times
    ttl_millis: u64,
    current_time_millis: i64,
    utxos_json: &str,
    network_id: &str,
) -> Result<String, String> {
    use midnight_ledger::dust::{DustRegistration, DustActions, DustPublicKey};
    use midnight_storage::storage::Array as StorageArray;
    use midnight_storage::storage::HashMap as StorageHashMap;

    // 1. Create SigningKey and derive VerifyingKey
    let signing_key = midnight_base_crypto::signatures::SigningKey::from_bytes(night_private_key)
        .map_err(|e| format!("Invalid night private key: {}", e))?;
    let verifying_key = signing_key.verifying_key();

    // 2. Parse DustPublicKey from hex
    let dust_pk_bytes = hex::decode(dust_public_key_hex)
        .map_err(|e| format!("Invalid dust public key hex: {}", e))?;
    let dust_pk = <DustPublicKey as Deserializable>::deserialize(&mut &dust_pk_bytes[..], 0)
        .map_err(|e| format!("Failed to deserialize DustPublicKey: {:?}", e))?;

    // 3. Create timestamps
    let current_time_secs = (current_time_millis / 1000) as u64;
    let ctime = Timestamp::from_secs(current_time_secs);
    let ttl = Timestamp::from_secs(ttl_millis / 1000);

    // 4. Generate random binding randomness
    let binding_randomness: PedersenRandomness = rand::rngs::OsRng.gen();

    // 5. Parse NIGHT UTXOs and build UnshieldedOffer
    //    Matches SDK pattern: include all NIGHT UTXOs as guaranteed offer inputs,
    //    with a single consolidation output back to the same owner.
    let json_utxos: Vec<JsonDustUtxo> = serde_json::from_str(utxos_json)
        .map_err(|e| format!("Failed to parse UTXOs JSON: {}", e))?;

    if json_utxos.is_empty() {
        return Err("At least one NIGHT UTXO is required for dust registration".to_string());
    }

    // Dust generation constants from INITIAL_DUST_PARAMETERS
    // (midnight-ledger/ledger/src/dust.rs:1266-1270)
    //   night_dust_ratio: 5 * (SPECKS_PER_DUST / STARS_PER_NIGHT) = 5_000_000_000
    //   generation_decay_rate: 8_267 (Specks/Star/second, ~1 week to capacity)
    const NIGHT_DUST_RATIO: u128 = 5_000_000_000;
    const GENERATION_DECAY_RATE: u128 = 8_267;

    let user_address = UserAddress::from(verifying_key.clone());

    // Include only the SINGLE highest-dust NIGHT UTXO in the registration offer.
    //
    // Each unshielded input adds ~7ms of validation `cost_to_dismiss`, and the ledger's
    // `min_time_to_dismiss` budget is 15ms (small txs are floored there and can't earn
    // more budget by size). Two inputs already exceed it, so a multi-UTXO offer is
    // rejected by enforcing nodes (PreProd) as MalformedError::FeeCalculation — RPC
    // "Custom error: 168". Registration is key-level, so one UTXO suffices: it registers
    // the night key (every UTXO of that key generates dust afterward), and one mature
    // UTXO's generationless dust far exceeds the registration fee.
    //
    // Per-UTXO generationless dust (= the allow_fee_payment ceiling), from
    // generationless_fee_availability() in dust.rs: min(dt * value * decay_rate,
    // value * night_dust_ratio).
    let mut best: Option<(UtxoSpend, u128, u128)> = None; // (spend, night_value, dust)
    for json_utxo in &json_utxos {
        let value: u128 = json_utxo.value.parse()
            .map_err(|e| format!("Invalid UTXO value '{}': {}", json_utxo.value, e))?;
        let vfull = value.saturating_mul(NIGHT_DUST_RATIO);
        let rate = value.saturating_mul(GENERATION_DECAY_RATE);
        let dt = current_time_secs.saturating_sub(json_utxo.ctime) as u128;
        let generated = u128::min(dt.saturating_mul(rate), vfull);

        let intent_hash_bytes = hex::decode(&json_utxo.intent_hash)
            .map_err(|e| format!("Invalid intent_hash hex: {}", e))?;
        let intent_hash = IntentHash::deserialize(&mut &intent_hash_bytes[..], 32)
            .map_err(|e| format!("Invalid intent hash: {:?}", e))?;

        let spend = UtxoSpend {
            value,
            owner: verifying_key.clone(),
            type_: UnshieldedTokenType(HashOutput([0u8; 32])),  // NIGHT
            intent_hash,
            output_no: json_utxo.output_no,
        };
        if best.as_ref().map_or(true, |(_, _, d)| generated > *d) {
            best = Some((spend, value, generated));
        }
    }

    let (selected_spend, total_night_value, allow_fee_payment) = best
        .ok_or_else(|| "No NIGHT UTXOs available for dust registration".to_string())?;
    let utxo_inputs: Vec<UtxoSpend> = vec![selected_spend];
    let input_count = utxo_inputs.len();
    log_info!("[Kuira FFI] Dust registration: selected 1 of {} NIGHT UTXOs, night={}, allow_fee_payment={}",
        json_utxos.len(), total_night_value, allow_fee_payment);

    // Single output: consolidate all NIGHT back to same owner
    let utxo_output = UtxoOutput {
        value: total_night_value,
        owner: user_address,
        type_: UnshieldedTokenType(HashOutput([0u8; 32])),  // NIGHT
    };

    // Build unsigned offer (empty signatures — filled after signing)
    let unsigned_offer = UnshieldedOffer::<Signature, DefaultDB> {
        inputs: utxo_inputs.iter().cloned().collect(),
        outputs: vec![utxo_output.clone()].into_iter().collect(),
        signatures: std::iter::empty().collect(),
    };

    // 7. Create DustRegistration WITHOUT signature (for signing data computation)
    let unsigned_registration = DustRegistration::<Signature, DefaultDB> {
        night_key: verifying_key.clone(),
        dust_address: Some(Sp::new(dust_pk.clone())),
        allow_fee_payment,
        signature: None,
    };

    // 8. Build DustActions with the unsigned registration
    let unsigned_registrations: StorageArray<DustRegistration<Signature, DefaultDB>, DefaultDB> =
        vec![unsigned_registration].into_iter().collect();
    let unsigned_spends: StorageArray<midnight_ledger::dust::DustSpend<ProofPreimageMarker, DefaultDB>, DefaultDB> =
        std::iter::empty().collect();

    let unsigned_dust_actions = DustActions {
        spends: unsigned_spends.clone(),
        registrations: unsigned_registrations,
        ctime,
    };

    // 9. Build the unsigned Intent WITH guaranteed unshielded offer
    let segment_id: u16 = 1;

    let unsigned_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: Some(Sp::new(unsigned_offer)),
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: Some(Sp::new(unsigned_dust_actions)),
        ttl,
        binding_commitment: binding_randomness,
    };

    // 10. Downgrade to Pedersen, erase signatures/proofs, get signing data
    let intent_pedersen = Intent::<Signature, ProofPreimageMarker, Pedersen, DefaultDB> {
        guaranteed_unshielded_offer: unsigned_intent.guaranteed_unshielded_offer.clone(),
        fallible_unshielded_offer: unsigned_intent.fallible_unshielded_offer.clone(),
        actions: unsigned_intent.actions.clone(),
        dust_actions: unsigned_intent.dust_actions.clone(),
        ttl: unsigned_intent.ttl,
        binding_commitment: Pedersen::from(binding_randomness),
    };

    let sig_erased = intent_pedersen.erase_signatures();
    let fully_erased = sig_erased.erase_proofs();
    let signature_data = fully_erased.data_to_sign(segment_id);

    log_info!("[Kuira FFI] Dust registration signing data: {} bytes", signature_data.len());

    // 11. Sign with night key (same signature used for both offer inputs and dust registration)
    let mut rng = rand::rngs::OsRng;
    let signature: Signature = signing_key.sign(&mut rng, &signature_data);

    // 12. Rebuild DustRegistration WITH signature
    let signed_registration = DustRegistration::<Signature, DefaultDB> {
        night_key: verifying_key.clone(),
        dust_address: Some(Sp::new(dust_pk)),
        allow_fee_payment,
        signature: Some(Sp::new(signature.clone())),
    };

    // 13. Build signed DustActions
    let signed_registrations: StorageArray<DustRegistration<Signature, DefaultDB>, DefaultDB> =
        vec![signed_registration].into_iter().collect();

    let signed_dust_actions = DustActions {
        spends: unsigned_spends,
        registrations: signed_registrations,
        ctime,
    };

    // 14. Build signed UnshieldedOffer: clone the signature for each input
    //     (SDK uses same signature for all — same key signs same data_to_sign)
    let signed_signatures: Vec<Signature> = (0..input_count).map(|_| signature.clone()).collect();
    let signed_offer = UnshieldedOffer::<Signature, DefaultDB> {
        inputs: utxo_inputs.into_iter().collect(),
        outputs: vec![utxo_output].into_iter().collect(),
        signatures: signed_signatures.into_iter().collect(),
    };

    // 15. Build the signed Intent
    let signed_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: Some(Sp::new(signed_offer)),
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: Some(Sp::new(signed_dust_actions)),
        ttl,
        binding_commitment: binding_randomness,
    };

    // 16. Build Transaction
    let mut intents_map = StorageHashMap::default();
    intents_map = intents_map.insert(segment_id, signed_intent);

    let transaction = Transaction::new(
        network_id,
        intents_map,
        None,
        midnight_storage::storage::HashMap::new(),  // No fallible_coins
    );

    // 17. Serialize as (Transaction, HashMap<String, ProvingKeyMaterial>) tuple
    // Proof server expects this format — empty proof data for dust registration
    let proof_data = std::collections::HashMap::<String, ProvingKeyMaterial>::new();

    let mut bytes = Vec::new();
    tagged_serialize(&(&transaction, &proof_data), &mut bytes)
        .map_err(|e| format!("SCALE serialization failed: {:?}", e))?;

    log_info!("[Kuira FFI] Dust registration tx serialized: {} bytes", bytes.len());

    Ok(hex::encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_still_works() {
        let hex_ptr = serialize_unshielded_transaction_stub(1704067200000);
        assert!(!hex_ptr.is_null());
        free_serialized_transaction(hex_ptr);
    }

    #[test]
    fn test_empty_intent_serialization() {
        let inputs = CString::new("[]").unwrap();
        let outputs = CString::new("[]").unwrap();
        let signatures = CString::new("[]").unwrap();
        let dust_actions = CString::new("").unwrap();
        let binding = CString::new("0500000000000000000000000000000000000000000000000000000000000000").unwrap();
        let network_id = CString::new("undeployed").unwrap();

        let hex_ptr = serialize_unshielded_transaction(
            inputs.as_ptr(),
            outputs.as_ptr(),
            signatures.as_ptr(),
            dust_actions.as_ptr(),
            1704067200000,
            binding.as_ptr(),
            network_id.as_ptr(),
        );

        assert!(!hex_ptr.is_null());

        let hex_str = unsafe { CStr::from_ptr(hex_ptr).to_str().unwrap() };
        assert!(hex_str.len() > 0);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));

        free_serialized_transaction(hex_ptr);
    }

    #[test]
    fn test_build_dust_registration_transaction() {
        use midnight_ledger::dust::{DustSecretKey, DustPublicKey, Seed};
        use midnight_serialize::Serializable;

        // 1. Create a night signing key from deterministic bytes (same pattern as midnight tests)
        let night_private_key: [u8; 32] = [42u8; 32];
        let signing_key = midnight_base_crypto::signatures::SigningKey::from_bytes(&night_private_key)
            .expect("Valid signing key");
        let verifying_key = signing_key.verifying_key();

        // 2. Derive a dust public key from a deterministic seed
        let seed: Seed = [7u8; 32];
        let dust_sk = DustSecretKey::derive_secret_key(&seed);
        let dust_pk = DustPublicKey::from(dust_sk);
        let mut pk_bytes = Vec::new();
        dust_pk.serialize(&mut pk_bytes).unwrap();
        let dust_pk_hex = hex::encode(&pk_bytes);

        // 3. Set fee and timestamps
        let allow_fee_payment = "0"; // Ignored — calculated from UTXO ctime internally
        let ttl_millis = 1737658800000u64;  // ~Jan 23 2025
        let current_time_millis = 1737658700000i64;  // ~100s before TTL
        let current_time_secs = (current_time_millis / 1000) as u64;  // 1737658700

        // 4. Create UTXO JSON (NIGHT UTXOs to include in guaranteed offer)
        //    ctime = 2 weeks before current time → UTXO is well past full dust capacity
        //    (time to capacity ≈ 604,836s ≈ ~1 week, so 2 weeks guarantees vfull)
        let utxo_ctime = current_time_secs - (2 * 604800);
        let utxos_json = format!(
            r#"[{{"value":"1000000","intent_hash":"ab6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":0,"ctime":{}}}]"#,
            utxo_ctime
        );
        let utxos_json = utxos_json.as_str();

        // 5. Call the impl function
        let result = build_dust_registration_transaction_impl(
            &night_private_key,
            &dust_pk_hex,
            allow_fee_payment,
            ttl_millis,
            current_time_millis,
            utxos_json,
            "undeployed",
        );

        let hex = result.expect("Dust registration transaction build should succeed");

        // 6. Verify valid hex output with reasonable size
        assert!(!hex.is_empty(), "Serialized hex should not be empty");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "Output must be valid hex");
        assert!(hex.len() / 2 > 100, "Transaction should be at least 100 bytes");
        eprintln!("Dust registration tx: {} bytes", hex.len() / 2);

        // 7. Deserialize round-trip: verify the SCALE output is a valid (Transaction, ProofData) tuple
        let tx_bytes = hex::decode(&hex).expect("Valid hex");
        let (tx, _proof_data): (
            Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
            std::collections::HashMap<String, ProvingKeyMaterial>,
        ) = tagged_deserialize(&tx_bytes[..]).expect("SCALE deserialization should succeed");

        // 8. Extract the intent from segment 1 and verify structure
        let intent = tx.intents().find(|(seg_id, _)| *seg_id == 1)
            .expect("Transaction should have segment 1")
            .1;

        // Verify guaranteed unshielded offer IS present (required for dust registration)
        let offer = intent.guaranteed_unshielded_offer.as_ref()
            .expect("Guaranteed unshielded offer must be present for dust registration");
        assert_eq!(offer.inputs.len(), 1, "Should have 1 UTXO input");
        assert_eq!(offer.outputs.len(), 1, "Should have 1 consolidation output");
        assert_eq!(offer.signatures.len(), 1, "Should have 1 signature (one per input)");
        assert!(intent.fallible_unshielded_offer.is_none(), "No fallible offer");

        // Verify offer input matches our UTXO
        let input = offer.inputs.iter().next().unwrap();
        assert_eq!(input.value, 1_000_000u128, "Input value should match UTXO");
        assert_eq!(input.owner, verifying_key, "Input owner should be our verifying key");
        assert_eq!(input.type_, UnshieldedTokenType(HashOutput([0u8; 32])), "Input type should be NIGHT");

        // Verify offer output consolidates back to same owner
        let output = offer.outputs.iter().next().unwrap();
        assert_eq!(output.value, 1_000_000u128, "Output value should equal total input");
        assert_eq!(output.owner, UserAddress::from(verifying_key.clone()), "Output owner should be our address");
        assert_eq!(output.type_, UnshieldedTokenType(HashOutput([0u8; 32])), "Output type should be NIGHT");

        // Verify dust actions exist with exactly 1 registration
        let dust_actions = intent.dust_actions.as_ref().expect("Dust actions should be present");
        assert_eq!(dust_actions.registrations.len(), 1, "Should have exactly 1 registration");
        assert_eq!(dust_actions.spends.len(), 0, "Should have no dust spends");

        // 9. Verify the registration fields
        let reg = dust_actions.registrations.iter().next().unwrap();
        assert_eq!(reg.night_key, verifying_key, "night_key should match our verifying key");
        // allow_fee_payment = min(dt * rate, vfull) where:
        //   dt = 604800, rate = 1_000_000 * 8267, vfull = 1_000_000 * 5_000_000_000
        //   dt * rate = 5_000_569_600_000_000 > vfull = 5_000_000_000_000_000
        //   → clamped to vfull
        assert_eq!(reg.allow_fee_payment, 5_000_000_000_000_000u128,
            "allow_fee_payment should equal dust generated from NIGHT UTXOs (vfull for mature UTXO)");
        assert!(reg.dust_address.is_some(), "dust_address should be present");
        assert!(reg.signature.is_some(), "signature should be present");

        // 10. Verify signatures: both dust registration and offer inputs should verify
        let erased_intent = intent.erase_signatures().erase_proofs();
        let signing_data = erased_intent.data_to_sign(1u16);

        // Dust registration signature
        let dust_sig = reg.signature.as_ref().unwrap();
        assert!(
            verifying_key.verify(&signing_data, dust_sig),
            "Dust registration signature must verify against data_to_sign(segment_id)"
        );

        // Offer input signature (same data, same key)
        let offer_sig = offer.signatures.iter().next().unwrap();
        assert!(
            verifying_key.verify(&signing_data, &offer_sig),
            "Offer input signature must verify against data_to_sign(segment_id)"
        );

        eprintln!("All signature verifications passed (dust registration + offer)");
    }

    /// Regression for PreProd `Custom error: 168` (MalformedError::FeeCalculation /
    /// OutsideTimeToDismiss): the dust-registration builder must emit a SINGLE-input tx
    /// regardless of how many NIGHT UTXOs it is handed, so its cost-to-dismiss stays under
    /// the ledger's enforced budget. Before the per-UTXO fix an all-UTXOs registration
    /// exceeded the budget and the node rejected it. Dust registration carries no ZK
    /// proofs, so the unproven tx's cost == what the node computes on the proven tx.
    #[test]
    fn dust_registration_is_single_input_under_budget() {
        use midnight_ledger::dust::{DustSecretKey, DustPublicKey, Seed};
        use midnight_ledger::structure::INITIAL_PARAMETERS;
        use midnight_serialize::Serializable;

        let night_private_key: [u8; 32] = [42u8; 32];

        let seed: Seed = [7u8; 32];
        let dust_sk = DustSecretKey::derive_secret_key(&seed);
        let dust_pk = DustPublicKey::from(dust_sk);
        let mut pk_bytes = Vec::new();
        dust_pk.serialize(&mut pk_bytes).unwrap();
        let dust_pk_hex = hex::encode(&pk_bytes);

        let ttl_millis = 1737658800000u64;
        let current_time_millis = 1737658700000i64;
        let current_time_secs = (current_time_millis / 1000) as u64;
        // 2 weeks old → past full dust capacity (saturated), matching the PreProd case
        let utxo_ctime = current_time_secs - (2 * 604800);

        // 2 NIGHT UTXOs totalling 6_000_000_000 — mirrors the failing logcat
        let utxos_json = format!(
            r#"[{{"value":"3000000000","intent_hash":"ab6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":0,"ctime":{c}}},{{"value":"3000000000","intent_hash":"cd6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":1,"ctime":{c}}}]"#,
            c = utxo_ctime
        );

        let hex = build_dust_registration_transaction_impl(
            &night_private_key,
            &dust_pk_hex,
            "0",
            ttl_millis,
            current_time_millis,
            utxos_json.as_str(),
            "undeployed",
        )
        .expect("build should succeed");

        let tx_bytes = hex::decode(&hex).unwrap();
        let (tx, _proof_data): (
            Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
            std::collections::HashMap<String, ProvingKeyMaterial>,
        ) = tagged_deserialize(&tx_bytes[..]).expect("deserialize");

        // Post-fix invariant: the builder selects a single NIGHT UTXO, so the tx is
        // single-input and clears the ledger's enforced time-to-dismiss budget — the
        // OutsideTimeToDismiss / FeeCalculation that the node surfaced as Custom error 168.
        let intent = tx
            .intents()
            .find(|(seg, _)| *seg == 1)
            .expect("segment 1")
            .1;
        let offer = intent
            .guaranteed_unshielded_offer
            .as_ref()
            .expect("offer");
        assert_eq!(offer.inputs.len(), 1, "2-UTXO registration must be single-input");
        assert!(
            tx.cost(&INITIAL_PARAMETERS, true).is_ok(),
            "single-input registration must clear cost(enforce_ttd) — was Custom error 168"
        );

        // The invariant holds however many NIGHT UTXOs the builder is handed: still one
        // input, still under budget (an all-UTXOs registration is what tripped 168).
        for n in 1..=6usize {
            let utxos: String = {
                let items: Vec<String> = (0..n)
                    .map(|i| format!(
                        r#"{{"value":"3000000000","intent_hash":"{:02x}6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":{},"ctime":{}}}"#,
                        0xa0 + i, i, utxo_ctime
                    ))
                    .collect();
                format!("[{}]", items.join(","))
            };
            let hx = build_dust_registration_transaction_impl(
                &night_private_key, &dust_pk_hex, "0", ttl_millis, current_time_millis,
                utxos.as_str(), "undeployed",
            ).expect("build");
            let b = hex::decode(&hx).unwrap();
            let (t, _): (
                Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
                std::collections::HashMap<String, ProvingKeyMaterial>,
            ) = tagged_deserialize(&b[..]).unwrap();
            let inputs = t.intents().find(|(s, _)| *s == 1).unwrap().1
                .guaranteed_unshielded_offer.as_ref().unwrap().inputs.len();
            assert_eq!(inputs, 1, "registration from {n} NIGHT UTXOs must be single-input");
            assert!(
                t.cost(&INITIAL_PARAMETERS, true).is_ok(),
                "{n}-UTXO registration must clear cost(enforce_ttd)"
            );
        }
    }

    /// Test that mirrors midnight-ledger/ledger/tests/dust.rs `test_registration_dust_payment`.
    ///
    /// Uses the library's own `Intent::empty()` + `intent.sign()` + `Transaction::from_intents()`
    /// to build the same kind of registration transaction the ledger tests build, proving our
    /// manual construction is compatible with the library's signing/verification pipeline.
    #[test]
    fn test_dust_registration_via_library_sign_method() {
        use midnight_ledger::dust::{DustSecretKey, DustPublicKey, DustRegistration, DustActions, Seed};
        use rand::{SeedableRng, rngs::StdRng};

        // Deterministic RNG (same pattern as midnight test: StdRng::seed_from_u64(0x42))
        let mut rng = StdRng::seed_from_u64(0x42);

        // Create signing key
        let night_private_key: [u8; 32] = [42u8; 32];
        let signing_key = midnight_base_crypto::signatures::SigningKey::from_bytes(&night_private_key)
            .expect("Valid signing key");
        let verifying_key = signing_key.verifying_key();

        // Derive dust public key
        let seed: Seed = [7u8; 32];
        let dust_sk = DustSecretKey::derive_secret_key(&seed);
        let dust_pk = DustPublicKey::from(dust_sk);

        let ttl = Timestamp::from_secs(1737658800);
        let ctime = Timestamp::from_secs(1737658700);

        // 1. Build unsigned intent using the library's Intent::empty()
        //    Use Signature kind (not ()) so we get real Schnorr signatures
        let mut intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>::empty(
            &mut rng, ttl,
        );

        // 2. Add dust registration (unsigned, same as midnight test pattern)
        intent.dust_actions = Some(Sp::new(DustActions {
            spends: vec![].into(),
            registrations: vec![DustRegistration {
                allow_fee_payment: 1_000_000u128,
                dust_address: Some(Sp::new(dust_pk)),
                night_key: verifying_key.clone(),
                signature: None,
            }]
            .into(),
            ctime,
        }));

        // 3. Sign using the library's intent.sign() method
        //    This is the same code path midnight-ledger uses internally
        let segment_id: u16 = 1;
        let signed_intent = intent
            .sign(
                &mut rng,
                segment_id,
                &[],                        // no guaranteed signing keys
                &[],                        // no fallible signing keys
                &[signing_key.clone()],     // dust registration signing keys
            )
            .expect("Library sign() should succeed");

        // 4. Build transaction using the library's Transaction::from_intents()
        let intents_map = [(segment_id, signed_intent)].into_iter().collect();
        let tx: Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>
            = Transaction::from_intents("undeployed", intents_map);

        // 5. Verify: extract intent and check dust registration
        let (_, intent_ref) = tx.intents().find(|(seg_id, _)| *seg_id == segment_id)
            .expect("Should have segment 1");

        let dust_actions = intent_ref.dust_actions.as_ref()
            .expect("Dust actions should be present");
        assert_eq!(dust_actions.registrations.len(), 1);
        assert_eq!(dust_actions.spends.len(), 0);

        let reg = dust_actions.registrations.iter().next().unwrap();
        assert_eq!(reg.night_key, verifying_key);
        assert_eq!(reg.allow_fee_payment, 1_000_000u128);
        assert!(reg.signature.is_some(), "Library sign() should have set signature");

        // 6. Verify signature using the same pattern as DustRegistration::well_formed()
        let erased = intent_ref.erase_signatures().erase_proofs();
        let data = erased.data_to_sign(segment_id);
        let sig = reg.signature.as_ref().unwrap();
        assert!(
            verifying_key.verify(&data, sig),
            "Library-signed registration must verify"
        );

        // 7. Serialize to SCALE and verify round-trip (same format our FFI produces)
        let proof_data = std::collections::HashMap::<String, ProvingKeyMaterial>::new();
        let mut bytes = Vec::new();
        tagged_serialize(&(&tx, &proof_data), &mut bytes)
            .expect("SCALE serialization should succeed");

        let (tx_rt, _): (
            Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
            std::collections::HashMap<String, ProvingKeyMaterial>,
        ) = tagged_deserialize(&bytes[..]).expect("Round-trip deserialization should succeed");

        let (_, intent_rt) = tx_rt.intents().find(|(seg_id, _)| *seg_id == segment_id).unwrap();
        let reg_rt = intent_rt.dust_actions.as_ref().unwrap()
            .registrations.iter().next().unwrap();
        assert!(reg_rt.signature.is_some(), "Signature should survive round-trip");

        eprintln!("Library-path dust registration: build + sign + serialize + round-trip all passed");
    }

    #[test]
    fn test_build_dust_registration_transaction_invalid_dust_key() {
        let night_private_key: [u8; 32] = [42u8; 32];
        let utxos_json = r#"[{"value":"1000000","intent_hash":"ab6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":0,"ctime":1737054000}]"#;
        let result = build_dust_registration_transaction_impl(
            &night_private_key,
            "not_valid_hex!!!",
            "1000000",
            1737658800000,
            1737658700000,
            utxos_json,
            "undeployed",
        );
        assert!(result.is_err(), "Should fail on invalid dust public key hex");
    }

    #[test]
    fn test_build_dust_registration_transaction_empty_utxos() {
        use midnight_ledger::dust::{DustSecretKey, DustPublicKey, Seed};
        use midnight_serialize::Serializable;

        let night_private_key: [u8; 32] = [42u8; 32];
        let seed: Seed = [7u8; 32];
        let dust_sk = DustSecretKey::derive_secret_key(&seed);
        let dust_pk = DustPublicKey::from(dust_sk);
        let mut pk_bytes = Vec::new();
        dust_pk.serialize(&mut pk_bytes).unwrap();
        let dust_pk_hex = hex::encode(&pk_bytes);

        let utxos_json = r#"[]"#;
        let result = build_dust_registration_transaction_impl(
            &night_private_key,
            &dust_pk_hex,
            "0",
            1737658800000,
            1737658700000,
            utxos_json,
            "undeployed",
        );
        assert!(result.is_err(), "Should fail with empty UTXOs");
        assert!(result.unwrap_err().contains("At least one NIGHT UTXO"));
    }

    #[test]
    fn test_build_dust_registration_transaction_ttl_preserved() {
        use midnight_ledger::dust::{DustSecretKey, DustPublicKey, Seed};
        use midnight_serialize::Serializable;

        let night_private_key: [u8; 32] = [42u8; 32];
        let seed: Seed = [7u8; 32];
        let dust_sk = DustSecretKey::derive_secret_key(&seed);
        let dust_pk = DustPublicKey::from(dust_sk);
        let mut pk_bytes = Vec::new();
        dust_pk.serialize(&mut pk_bytes).unwrap();
        let dust_pk_hex = hex::encode(&pk_bytes);

        let ttl_millis = 1800000000000u64; // ~2027
        let ctime_millis = 1737658700000i64; // ~2025

        let utxos_json = r#"[{"value":"1000000","intent_hash":"ab6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":0,"ctime":1737054000}]"#;
        let hex = build_dust_registration_transaction_impl(
            &night_private_key,
            &dust_pk_hex,
            "0",
            ttl_millis,
            ctime_millis,
            utxos_json,
            "undeployed",
        ).expect("Should succeed");

        // Deserialize and verify timestamps
        let tx_bytes = hex::decode(&hex).unwrap();
        let (tx, _): (
            Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
            std::collections::HashMap<String, ProvingKeyMaterial>,
        ) = tagged_deserialize(&tx_bytes[..]).unwrap();

        let intent = tx.intents().find(|(seg_id, _)| *seg_id == 1).unwrap().1;

        // TTL should be ttl_millis / 1000 in seconds
        let expected_ttl = Timestamp::from_secs(ttl_millis / 1000);
        assert_eq!(intent.ttl, expected_ttl, "TTL should match input");

        // ctime on dust actions should be ctime_millis / 1000 in seconds
        let dust_actions = intent.dust_actions.as_ref().unwrap();
        let expected_ctime = Timestamp::from_secs((ctime_millis / 1000) as u64);
        assert_eq!(dust_actions.ctime, expected_ctime, "ctime should match input");
    }

    /// Runs the whole dust-registration path the Android app uses (build → sign →
    /// serialize) and hands the resulting transaction to `well_formed()` against a
    /// LedgerState that holds the registering NIGHT UTXO. This is the same call the
    /// node makes during mempool admission — a pass here means the node will accept
    /// the tx; any `MalformedTransaction::*` here reproduces the exact error code
    /// the node would have returned (e.g. 170 InvalidDustSpendProof).
    ///
    /// Uses `midnight_ledger::test_utilities::TestState` (dev-dep only) so we never
    /// have to go through the proof server / node / Docker stack to iterate.
    #[tokio::test]
    async fn test_dust_registration_passes_well_formed() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_ledger::verify::WellFormedStrictness;
        use midnight_ledger::structure::Transaction as LedgerTx;
        use midnight_ledger::dust::{DustPublicKey, INITIAL_DUST_PARAMETERS};
        use midnight_serialize::Serializable;
        use rand::{SeedableRng, rngs::StdRng};
        use midnight_storage::db::InMemoryDB;

        // 1. Seeded TestState — network_id is "local-test" (what TestState::new hardcodes).
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);

        // 2. Fund the test wallet with a NIGHT UTXO and age it to dust-cap so
        //    there's enough generationless dust to cover the registration fee.
        const NIGHT_VAL: u128 = 1_000_000;
        state.reward_night(&mut rng, NIGHT_VAL).await;
        state.fast_forward(INITIAL_DUST_PARAMETERS.time_to_cap());

        // 3. Extract the funded UTXO's identity (intent_hash + output_no + ctime) —
        //    this is what Android pulls from the indexer and hands to the FFI.
        let utxo_entry = state.ledger.utxo.utxos.iter().next().unwrap();
        let utxo = &utxo_entry.0;
        let utxo_meta = &utxo_entry.1;
        let utxo_intent_hash_hex = {
            let mut buf = Vec::new();
            utxo.intent_hash.serialize(&mut buf).unwrap();
            hex::encode(&buf)
        };
        let utxo_ctime_secs = utxo_meta.ctime.to_secs();

        // 4. Serialize the night signing key and dust public key in the exact
        //    format the FFI expects (matches DustRegistrationBuilder.build).
        let mut night_key_bytes = Vec::new();
        state.night_key.serialize(&mut night_key_bytes).unwrap();
        let night_key_arr: [u8; 32] = night_key_bytes.as_slice().try_into().unwrap();

        let dust_pk_hex = {
            let pk = DustPublicKey::from(state.dust_key.clone());
            let mut buf = Vec::new();
            pk.serialize(&mut buf).unwrap();
            hex::encode(&buf)
        };

        let utxos_json = format!(
            r#"[{{"value":"{NIGHT_VAL}","intent_hash":"{utxo_intent_hash_hex}","output_no":{},"ctime":{utxo_ctime_secs}}}]"#,
            utxo.output_no
        );

        // 5. Build the same transaction the Android flow builds.
        let current_time_ms = (state.time.to_secs() as i64) * 1000;
        let ttl_ms = (current_time_ms as u64) + 60_000; // 60s future

        let tx_hex = build_dust_registration_transaction_impl(
            &night_key_arr,
            &dust_pk_hex,
            "0",
            ttl_ms,
            current_time_ms,
            &utxos_json,
            "local-test", // matches TestState's LedgerState network_id
        )
        .expect("FFI should produce a serialized tx");

        // 6. Round-trip back into a typed Transaction and run the node's own
        //    gate: tx.well_formed(&ledger_state, strictness, tblock).
        let tx_bytes = hex::decode(&tx_hex).unwrap();
        let (tx, _proof_data): (
            LedgerTx<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
            std::collections::HashMap<String, ProvingKeyMaterial>,
        ) = tagged_deserialize(&tx_bytes[..]).unwrap();

        let strictness = WellFormedStrictness::default();
        let verified = tx.well_formed(&state.ledger, strictness, state.time);

        match verified {
            Ok(_) => eprintln!("✅ tx passed well_formed — node would accept."),
            Err(e) => panic!(
                "well_formed rejected our dust registration tx.\n\
                 This reproduces the node's rejection locally.\n\
                 Error variant: {e:?}\n\
                 Hex (first 200): {}",
                &tx_hex[..tx_hex.len().min(200)]
            ),
        }
    }

    /// Phase 8B.x: network_id is a parameter, not hardcoded "undeployed".
    /// This test pins down what actually gets embedded in the Transaction wire
    /// format — if it drifts from the caller's input, multi-network support is
    /// broken at the Rust boundary and the node will reject with `InvalidNetworkId`.
    #[test]
    fn test_build_dust_registration_network_id_round_trips() {
        use midnight_ledger::dust::{DustSecretKey, DustPublicKey, Seed};
        use midnight_serialize::Serializable;
        use midnight_ledger::structure::Transaction as LedgerTx;

        let night_private_key: [u8; 32] = [42u8; 32];
        let seed: Seed = [7u8; 32];
        let dust_sk = DustSecretKey::derive_secret_key(&seed);
        let dust_pk = DustPublicKey::from(dust_sk);
        let mut pk_bytes = Vec::new();
        dust_pk.serialize(&mut pk_bytes).unwrap();
        let dust_pk_hex = hex::encode(&pk_bytes);

        let utxos_json = r#"[{"value":"1000000","intent_hash":"ab6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed","output_no":0,"ctime":1737054000}]"#;

        // Cover every production network identifier, including the two that were
        // impossible to hit while the FFI hardcoded "undeployed".
        for expected in ["undeployed", "preprod", "preview", "mainnet"] {
            let hex_str = build_dust_registration_transaction_impl(
                &night_private_key,
                &dust_pk_hex,
                "0",
                1800000000000u64,
                1737658700000i64,
                utxos_json,
                expected,
            )
            .unwrap_or_else(|e| panic!("Should succeed for {expected}: {e}"));

            let tx_bytes = hex::decode(&hex_str).unwrap();
            let (tx, _): (
                LedgerTx<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>,
                std::collections::HashMap<String, ProvingKeyMaterial>,
            ) = tagged_deserialize(&tx_bytes[..]).unwrap();

            match tx {
                LedgerTx::Standard(stx) => {
                    assert_eq!(
                        stx.network_id, expected,
                        "Transaction.network_id must match caller's input"
                    );
                }
                other => panic!("Expected Standard transaction, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_serialize_with_android_data() {
        // EXACT same values as Android test
        let inputs_json = r#"[{
            "value": "10000000",
            "owner": "5a6202f7b2491e09d62e3cdf3c5ec67fd98bb3743a65e67f397f8b12a6460d46",
            "type": "0000000000000000000000000000000000000000000000000000000000000000",
            "intent_hash": "ab6642ef7dd8420c4673a56c57da96adeeedfc5a98140c8a42500b8369464fed",
            "output_no": 0
        }]"#;

        let outputs_json = r#"[{
            "value": "1000000",
            "owner": "246751a9a263a0233fea1f079a0882c8ea462f98bdb23d4acb79ff2c957aaad4",
            "type": "0000000000000000000000000000000000000000000000000000000000000000"
        }, {
            "value": "9000000",
            "owner": "5125024980cfab62f99febb1ec72d72079298cb28f51fe47fbc2a3313d641a19",
            "type": "0000000000000000000000000000000000000000000000000000000000000000"
        }]"#;

        let signatures_json = r#"["7fcd704b204a598d87375b046ff9b4c1bd26e039f471c1cbbb107d4f962507151f17d58df17a7b2772649faa67a7bd25821c229470bcc9d85e8d21f9fb80757e"]"#;

        let ttl_ms = 1737658800000u64;
        let binding_commitment = "0500000000000000000000000000000000000000000000000000000000000000".to_string();

        eprintln!("\n🔬 Testing FFI serialize with same data as Android test...\n");

        let dust_actions_json = "";

        let result = build_and_serialize_intent(
            inputs_json,
            outputs_json,
            signatures_json,
            dust_actions_json,
            ttl_ms,
            binding_commitment,
            "undeployed",
        );

        match result {
            Ok(hex) => {
                eprintln!("\n✅ Serialization successful!");
                eprintln!("SCALE length: {} bytes", hex.len() / 2);
                eprintln!("First 100 hex chars: {}", &hex[..hex.len().min(100)]);
                eprintln!("\nExpected (from diagnostic): 30009501025a62025a6202f7b2491e09d62e3cdf3c5ec67fd98bb3743a65e67f397f8b12a6460d46...");
                eprintln!("Got:                        {}", &hex[..hex.len().min(100)]);
            }
            Err(e) => {
                panic!("\n❌ Serialization failed: {}", e);
            }
        }
    }
}

/// Seals a proven transaction by transforming the binding commitment.
///
/// **Purpose:** After receiving a proven transaction from the proof server, we need to
/// call `.seal()` to transform the binding from `PedersenRandomness` (embedded-fr[v1])
/// to `PureGeneratorPedersen` (pedersen-schnorr[v1]) before submitting to the node.
///
/// **Input:** Hex-encoded proven transaction from proof server
/// **Output:** Hex-encoded finalized (sealed) transaction ready for node submission
///
/// # Safety
/// Requires valid C string pointer for proven_tx_hex
#[no_mangle]
pub extern "C" fn seal_proven_transaction(
    proven_tx_hex: *const c_char,
) -> *mut c_char {
    if proven_tx_hex.is_null() {
        log_error!("seal_proven_transaction: proven_tx_hex is null");
        return std::ptr::null_mut();
    }

    // Convert C string to Rust string
    let proven_hex = match unsafe { CStr::from_ptr(proven_tx_hex).to_str() } {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            log_error!("seal_proven_transaction: Invalid UTF-8 in proven_tx_hex: {}", e);
            return std::ptr::null_mut();
        }
    };

    match seal_proven_transaction_impl(&proven_hex) {
        Ok(sealed_hex) => {
            match CString::new(sealed_hex) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    log_error!("seal_proven_transaction: Failed to create C string: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            log_error!("seal_proven_transaction: {}", e);
            std::ptr::null_mut()
        }
    }
}

fn seal_proven_transaction_impl(proven_hex: &str) -> Result<String, String> {
    use midnight_transient_crypto::commitment::PedersenRandomness;

    // Decode hex to bytes
    let proven_bytes = hex::decode(proven_hex)
        .map_err(|e| format!("Failed to decode proven transaction hex: {}", e))?;

    // Deserialize the proven transaction
    let proven_tx: Transaction<Signature, ProofMarker, PedersenRandomness, DefaultDB> =
        tagged_deserialize(&proven_bytes[..])
            .map_err(|e| format!("Failed to deserialize proven transaction: {:?}", e))?;

    // Seal the transaction (transforms binding: PedersenRandomness → PureGeneratorPedersen)
    // Use a deterministic RNG for reproducibility (same as midnight-node uses for testing)
    let rng = StdRng::seed_from_u64(0x00);
    let finalized_tx: Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB> =
        proven_tx.seal(rng);

    // Serialize the finalized transaction
    let mut finalized_bytes = Vec::new();
    tagged_serialize(&finalized_tx, &mut finalized_bytes)
        .map_err(|e| format!("Failed to serialize finalized transaction: {:?}", e))?;

    let finalized_hex = hex::encode(&finalized_bytes);

    log_info!("[Kuira FFI] Sealed tx: {} bytes", finalized_bytes.len());

    Ok(finalized_hex)
}

/// Get the Midnight transaction hash from a sealed transaction.
///
/// This returns the hash that will appear in the indexer, NOT the extrinsic hash
/// that the node RPC returns. These are different hashes:
/// - Extrinsic hash: Hash of the Substrate extrinsic wrapper (from node RPC)
/// - Midnight tx hash: Hash of the Midnight transaction (what indexer uses)
///
/// # Arguments
/// * `sealed_tx_hex` - Hex-encoded sealed transaction (from seal_proven_transaction)
///
/// # Returns
/// - Non-null C string containing hex-encoded transaction hash (64 hex chars)
/// - Null pointer on error
///
/// # Safety
/// Requires valid C string pointer for sealed_tx_hex
#[no_mangle]
pub extern "C" fn get_transaction_hash(
    sealed_tx_hex: *const c_char,
) -> *mut c_char {
    if sealed_tx_hex.is_null() {
        log_error!("get_transaction_hash: sealed_tx_hex is null");
        return std::ptr::null_mut();
    }

    // Convert C string to Rust string
    let sealed_hex = match unsafe { CStr::from_ptr(sealed_tx_hex).to_str() } {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            log_error!("get_transaction_hash: Invalid UTF-8 in sealed_tx_hex: {}", e);
            return std::ptr::null_mut();
        }
    };

    match get_transaction_hash_impl(&sealed_hex) {
        Ok(hash_hex) => {
            match CString::new(hash_hex) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    log_error!("get_transaction_hash: Failed to create C string: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            log_error!("get_transaction_hash: {}", e);
            std::ptr::null_mut()
        }
    }
}

fn get_transaction_hash_impl(sealed_hex: &str) -> Result<String, String> {
    // Decode hex to bytes
    let sealed_bytes = hex::decode(sealed_hex)
        .map_err(|e| format!("Failed to decode sealed transaction hex: {}", e))?;

    // Deserialize the sealed transaction
    let sealed_tx: Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB> =
        tagged_deserialize(&sealed_bytes[..])
            .map_err(|e| format!("Failed to deserialize sealed transaction: {:?}", e))?;

    // Calculate transaction hash
    let tx_hash = sealed_tx.transaction_hash();
    let hash_hex = hex::encode(tx_hash.0.0);

    log_info!("[Kuira FFI] Tx hash: {}", hash_hex);

    Ok(hash_hex)
}
