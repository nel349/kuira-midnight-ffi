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
use midnight_serialize::{Serializable, Deserializable};
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
    dust_state_ptr: *const DustLocalState<DefaultDB>,
    seed_ptr: *const u8,
    seed_len: usize,
    dust_utxos_json: *const c_char,
    current_time_ms: i64,
    ttl: u64,
    binding_randomness_hex: *const c_char,
) -> *mut c_char {
    // Safety checks
    if inputs_hex.is_null() || outputs_hex.is_null() || signatures_hex.is_null() ||
       dust_state_ptr.is_null() || seed_ptr.is_null() || dust_utxos_json.is_null() ||
       binding_randomness_hex.is_null() {
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
        binding_randomness_str.to_string()
    ) {
        Ok(hex) => {
            log_info!("[Kuira FFI] Serialization succeeded! Hex length: {}", hex.len());
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
) -> *mut c_char {
    // Safety checks
    if inputs_hex.is_null() || outputs_hex.is_null() || signatures_hex.is_null() || dust_actions_hex.is_null() || binding_randomness_hex.is_null() {
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

    // Build and serialize Intent with dust actions
    match build_and_serialize_intent(inputs_str, outputs_str, signatures_str, dust_actions_str, ttl, binding_randomness_str.to_string()) {
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

/// Build an Intent from JSON strings and serialize to SCALE hex
pub fn build_and_serialize_intent(
    inputs_json: &str,
    outputs_json: &str,
    signatures_json: &str,
    dust_actions_json: &str,
    ttl_ms: u64,
    binding_randomness_hex: String,
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
    let signature_count = signatures.len();

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
        network_id: "undeployed".into(),
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
        "undeployed",
        base_intents_map,
        None,  // No guaranteed_coins
        std::collections::HashMap::new(),  // No fallible_coins
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
            "undeployed",
            dust_intents_map,
            None,  // No guaranteed_coins
            std::collections::HashMap::new(),  // No fallible_coins
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

    // Build UnshieldedOffer WITHOUT signatures (we're generating the data to sign)
    let unshielded_offer = UnshieldedOffer::<Signature, DefaultDB> {
        inputs: inputs.into_iter().collect(),
        outputs: outputs.into_iter().collect(),
        signatures: std::iter::empty().collect(), // Empty - we're generating signature data
    };

    // Build Intent (WITH signatures initially, will be erased)
    // Use provided binding_commitment or generate a random one
    let binding_randomness: PedersenRandomness = if let Some(ref hex) = binding_randomness_hex {
        // Deserialize binding_commitment from hex
        let commitment_bytes = hex::decode(hex)
            .map_err(|e| format!("Invalid binding_commitment hex: {}", e))?;
        // Deserialize directly as PedersenRandomness
        // NOTE: When deserializing from Pedersen bytes, we lose the randomness property
        // but this is OK since we're reusing a commitment that was already randomly generated
        <PedersenRandomness as Deserializable>::deserialize(&mut &commitment_bytes[..], 32)
            .map_err(|e| format!("Invalid PedersenRandomness: {:?}", e))?
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
        let binding = CString::new("09c2a8bc7eb805257257fe7bc69db72334d2f9c21574ec6a78398453a5c67a2d").unwrap();

        let hex_ptr = serialize_unshielded_transaction(
            inputs.as_ptr(),
            outputs.as_ptr(),
            signatures.as_ptr(),
            1704067200000,
            binding.as_ptr()
        );

        assert!(!hex_ptr.is_null());

        let hex_str = unsafe { CStr::from_ptr(hex_ptr).to_str().unwrap() };
        assert!(hex_str.len() > 0);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));

        free_serialized_transaction(hex_ptr);
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
        let binding_commitment = "09c2a8bc7eb805257257fe7bc69db72334d2f9c21574ec6a78398453a5c67a2d".to_string();

        eprintln!("\n🔬 Testing FFI serialize with same data as Android test...\n");

        let result = build_and_serialize_intent(
            inputs_json,
            outputs_json,
            signatures_json,
            ttl_ms,
            binding_commitment
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
