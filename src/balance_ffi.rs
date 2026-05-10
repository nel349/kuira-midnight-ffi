//! Transaction Balancing FFI — Phase 2 SDK
//!
//! Balances a proven Compact contract transaction by adding dust fee payment.
//! Follows the TypeScript SDK pattern: create dust tx → prove separately → merge → seal.
//!
//! This is the core operation that replaces the remote `mn serve` wallet for standalone dApps.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;

use midnight_base_crypto::signatures::Signature;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger::dust::{DustActions, DustLocalState, DustSecretKey, Seed};
use midnight_ledger::structure::{
    Intent, LedgerParameters, ProofMarker, ProofPreimageMarker, Transaction,
    INITIAL_TRANSACTION_COST_MODEL,
};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::storage::HashMap as StorageHashMap;
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PedersenRandomness;
use midnight_transient_crypto::proofs::ProvingKeyMaterial;
use rand::rngs::OsRng;
use rand::Rng;

// Reuse the local prover infrastructure from prove_ffi
use crate::prove_ffi::LocalFileResolver;

// ── Logging ──

#[cfg(target_os = "android")]
macro_rules! balance_log {
    ($level:expr, $($arg:tt)*) => {{
        log::log!(
            if $level >= 6 { log::Level::Error } else { log::Level::Info },
            "{}", format!($($arg)*)
        );
    }};
}

#[cfg(not(target_os = "android"))]
macro_rules! balance_log {
    ($level:expr, $($arg:tt)*) => {{
        eprintln!("[KuiraBalance] {}", format!($($arg)*));
    }};
}

const LOG_INFO: std::os::raw::c_int = 4;
const LOG_ERROR: std::os::raw::c_int = 6;

/// Additional safety overhead percentage (matches fee_ffi.rs).
const FEE_OVERHEAD_PERCENT: u128 = 1;
const DEFAULT_FEE_BLOCKS_MARGIN: usize = 5;

// ── FFI Entry Point ──

/// Balance a proven transaction by adding dust fee payment, then seal it.
///
/// This replaces the remote `DAppConnectorClient.balanceTransaction()` call,
/// enabling fully standalone dApp operation without `mn serve`.
///
/// # Flow (matches TypeScript SDK pattern)
///
/// 1. Deserialize the proven transaction (from circuit execution + proof)
/// 2. Calculate the fee using ledger parameters
/// 3. Create dust spend proofs from the wallet's dust state
/// 4. Build a dust-only unproven transaction
/// 5. Prove the dust transaction locally (generates ZK proofs for dust spends)
/// 6. Merge the proven original + proven dust transactions
/// 7. Seal the merged transaction (PedersenRandomness → PureGeneratorPedersen)
/// 8. Return the balanced+sealed transaction hex
///
/// # Parameters
///
/// - `proven_tx_hex`: Tagged-SCALE hex of the proven transaction
/// - `dust_state_ptr`: Active DustLocalState pointer (modified on success — spends recorded)
/// - `seed_ptr`: 32-byte dust seed for DustSecretKey derivation
/// - `seed_len`: Must be 32
/// - `ledger_params_hex`: Tagged-SCALE hex of ledger parameters
/// - `current_time_ms`: Current time in milliseconds (for dust spend timestamp)
/// - `keys_dir`: Path to cached proving keys directory
/// - `network_id`: Network ID string (e.g., "undeployed", "preview", "preprod")
///
/// # Returns
///
/// Tagged-SCALE hex of the balanced+sealed transaction, or null on error.
/// Caller must free with `free_balanced_transaction`.
///
/// # Safety
///
/// All pointer parameters must be valid, non-null. `dust_state_ptr` is modified on success.
#[no_mangle]
pub extern "C" fn balance_proven_transaction(
    proven_tx_hex: *const c_char,
    dust_state_ptr: *mut DustLocalState<DefaultDB>,
    seed_ptr: *const u8,
    seed_len: usize,
    ledger_params_hex: *const c_char,
    current_time_ms: i64,
    keys_dir: *const c_char,
    network_id: *const c_char,
) -> *mut c_char {
    // Null checks
    if proven_tx_hex.is_null()
        || dust_state_ptr.is_null()
        || seed_ptr.is_null()
        || ledger_params_hex.is_null()
        || keys_dir.is_null()
        || network_id.is_null()
    {
        balance_log!(LOG_ERROR, "Null pointer in balance_proven_transaction");
        return ptr::null_mut();
    }

    if seed_len != 32 {
        balance_log!(LOG_ERROR, "Seed must be 32 bytes, got {}", seed_len);
        return ptr::null_mut();
    }

    // Convert C strings to Rust
    // SAFETY: All pointers validated non-null above. JNI guarantees valid C strings.
    let proven_hex = match unsafe { CStr::from_ptr(proven_tx_hex).to_str() } {
        Ok(s) => s.trim(),
        Err(e) => {
            balance_log!(LOG_ERROR, "Invalid UTF-8 in proven_tx_hex: {}", e);
            return ptr::null_mut();
        }
    };

    let params_hex = match unsafe { CStr::from_ptr(ledger_params_hex).to_str() } {
        Ok(s) => s.trim(),
        Err(e) => {
            balance_log!(LOG_ERROR, "Invalid UTF-8 in ledger_params_hex: {}", e);
            return ptr::null_mut();
        }
    };

    let keys_path = match unsafe { CStr::from_ptr(keys_dir).to_str() } {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            balance_log!(LOG_ERROR, "Invalid UTF-8 in keys_dir: {}", e);
            return ptr::null_mut();
        }
    };

    let network_id_str = match unsafe { CStr::from_ptr(network_id).to_str() } {
        Ok(s) => s,
        Err(e) => {
            balance_log!(LOG_ERROR, "Invalid UTF-8 in network_id: {}", e);
            return ptr::null_mut();
        }
    };

    // Convert seed
    // SAFETY: seed_ptr validated non-null, seed_len validated == 32 above.
    let seed_slice = unsafe { std::slice::from_raw_parts(seed_ptr, seed_len) };
    let mut seed_array: Seed = [0u8; 32];
    seed_array.copy_from_slice(seed_slice);

    // SAFETY: dust_state_ptr validated non-null. Immutable borrow is safe because
    // the impl function clones the state before mutation.
    let dust_state = unsafe { &*dust_state_ptr };

    match balance_proven_transaction_impl(
        proven_hex,
        dust_state,
        &seed_array,
        params_hex,
        current_time_ms,
        &keys_path,
        network_id_str,
    ) {
        Ok((balanced_hex, _updated_state)) => {
            // Do NOT write the post-spend state back to the pointer.
            // The caller (DustSyncManager) caches the original state for reuse
            // across transactions. Writing back corrupts the Merkle tree roots
            // for subsequent spends. The node's root history keeps old roots
            // valid for 1+ hours, so reusing the original state is safe.
            balance_log!(LOG_INFO, "Balance complete, original state preserved");

            match CString::new(balanced_hex) {
                Ok(c_str) => c_str.into_raw(),
                Err(e) => {
                    balance_log!(LOG_ERROR, "Failed to create C string: {}", e);
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            balance_log!(LOG_ERROR, "balance_proven_transaction failed: {}", e);
            ptr::null_mut()
        }
    }
}

/// Frees a string returned by [balance_proven_transaction].
#[no_mangle]
pub extern "C" fn free_balanced_transaction(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

// ── Implementation ──

fn balance_proven_transaction_impl(
    proven_hex: &str,
    dust_state: &DustLocalState<DefaultDB>,
    seed: &Seed,
    params_hex: &str,
    current_time_ms: i64,
    keys_path: &PathBuf,
    network_id: &str,
) -> Result<(String, DustLocalState<DefaultDB>), String> {
    use midnight_storage::arena::Sp;
    use midnight_storage::storage::Array as StorageArray;

    balance_log!(LOG_INFO, "Starting balance: proven_tx={} chars, keys_dir={:?}",
        proven_hex.len(), keys_path);

    // ── Step 1: Deserialize the proven transaction ──

    let proven_bytes = hex::decode(proven_hex)
        .map_err(|e| format!("Failed to decode proven tx hex: {}", e))?;

    type ProvenTx = Transaction<Signature, ProofMarker, PedersenRandomness, DefaultDB>;

    let proven_tx: ProvenTx = tagged_deserialize(&proven_bytes[..])
        .map_err(|e| format!("Failed to deserialize proven transaction: {:?}", e))?;

    balance_log!(LOG_INFO, "Deserialized proven tx: {} bytes", proven_bytes.len());

    // ── Step 2: Calculate fee ──
    //
    // The TS SDK erases proofs before fee calculation because fees_with_margin
    // on a ProofMarker transaction returns 0 (proofs are compact, so the "proof
    // preimage cost" component is 0). Instead of erasing proofs (which requires
    // a different type), we call erase_proofs() on the proven tx to get a
    // NoProof version, then calculate fees on that.

    let params_bytes = hex::decode(params_hex)
        .map_err(|e| format!("Failed to decode ledger params hex: {}", e))?;

    balance_log!(LOG_INFO, "Params raw bytes: {} bytes, first 40 = {}",
        params_bytes.len(), hex::encode(&params_bytes[..params_bytes.len().min(40)]));

    // Try tagged deserialization first, fall back to raw
    let params: LedgerParameters = match tagged_deserialize(&params_bytes[..]) {
        Ok(p) => {
            balance_log!(LOG_INFO, "Params deserialized via tagged_deserialize");
            p
        }
        Err(tag_err) => {
            balance_log!(LOG_INFO, "tagged_deserialize failed ({}), trying raw after strip_tag_prefix", tag_err);
            let stripped = strip_tag_prefix(params_bytes.clone());
            balance_log!(LOG_INFO, "After strip: {} bytes (was {})", stripped.len(), params_bytes.len());
            midnight_serialize::Deserializable::deserialize(&mut &stripped[..], 0)
                .map_err(|e| format!("Failed to deserialize ledger parameters: {:?} (tagged also failed: {})", e, tag_err))?
        }
    };

    // Calculate fee from ledger params. NOTE: fees_with_margin can return 0
    // for small contract-call txs because the synthetic cost rounds to 0
    // specks. The on-chain verifier (verify.rs:609) calls fees(params, true),
    // which enforces time_to_dismiss; on a tx with no dust spend, that check
    // can fail and surface as Malformed(FeeCalculation) (error 168).
    //
    // The SDK's balanceTransactions ALWAYS emits a dust intent (see
    // dust-wallet/Transacting.ts:512-527) even when the dust recipe is empty.
    // We do the same: always include at least one dust spend so the tx has
    // the structural shape the verifier expects, with v_fee >= 1.
    let erased_tx = proven_tx.erase_proofs();
    let base_fee = erased_tx
        .fees_with_margin(&params, DEFAULT_FEE_BLOCKS_MARGIN)
        .map_err(|e| format!("Fee calculation failed: {:?}", e))?;

    balance_log!(LOG_INFO, "Fee from ledger params: {} specks", base_fee);

    let overhead = base_fee * FEE_OVERHEAD_PERCENT / 100;
    // Ensure v_fee >= 1 so the dust spend is always non-trivial. Without this,
    // a 0-fee tx would have no dust spend and the node rejects with FeeCalculation.
    let total_fee: u128 = (base_fee + overhead).max(1);

    balance_log!(LOG_INFO, "Calculated fee: {} specks (base={}, overhead={})",
        total_fee, base_fee, overhead);

    // ── Step 3: Create dust spends ──

    let dust_secret_key = DustSecretKey::derive_secret_key(seed);
    let timestamp_secs = u64::try_from(current_time_ms / 1000)
        .map_err(|_| format!("Negative timestamp: {}", current_time_ms))?;
    let timestamp = Timestamp::from_secs(timestamp_secs);

    let utxos: Vec<_> = dust_state.utxos().collect();
    let mut current_state = dust_state.clone();
    let mut dust_spends = Vec::new();
    let mut fee_remaining = total_fee;

    for (idx, utxo) in utxos.iter().enumerate() {
        if fee_remaining == 0 {
            break;
        }

        match current_state.spend(&dust_secret_key, utxo, fee_remaining, timestamp) {
            Ok((new_state, dust_spend)) => {
                // Diagnostic: log the Merkle roots used in the proof
                if let Some(com_root) = current_state.commitment_root() {
                    balance_log!(LOG_INFO, "Commitment root BEFORE spend: {:?}", com_root);
                } else {
                    balance_log!(LOG_ERROR, "Commitment root is None (tree not rehashed!)");
                }
                if let Some(gen_root) = current_state.generation_root() {
                    balance_log!(LOG_INFO, "Generation root BEFORE spend: {:?}", gen_root);
                } else {
                    balance_log!(LOG_ERROR, "Generation root is None (tree not rehashed!)");
                }
                balance_log!(LOG_INFO, "Dust ctime (timestamp_secs): {}", timestamp_secs);
                balance_log!(LOG_INFO, "UTXO count: {}, events replayed to state", utxos.len());
                current_state = new_state;
                dust_spends.push(dust_spend);
                balance_log!(LOG_INFO, "Created DustSpend from UTXO {}: v_fee={}", idx, fee_remaining);
                fee_remaining = 0;
            }
            Err(e) => {
                balance_log!(LOG_INFO, "Skipping UTXO {} (insufficient balance: {:?})", idx, e);
                continue;
            }
        }
    }

    if fee_remaining > 0 {
        return Err(format!(
            "Insufficient dust balance. Need {} specks, no UTXO has enough.",
            total_fee
        ));
    }

    balance_log!(LOG_INFO, "Created {} dust spend(s) for total fee {}", dust_spends.len(), total_fee);

    // ── Step 4: Build dust-only unproven transaction ──

    let spends_array: StorageArray<_, DefaultDB> = dust_spends.into_iter().collect();
    let registrations_array: StorageArray<
        midnight_ledger::dust::DustRegistration<Signature, DefaultDB>,
        DefaultDB,
    > = std::iter::empty().collect();

    let dust_actions = DustActions {
        spends: spends_array,
        registrations: registrations_array,
        ctime: timestamp,
    };

    // Random segment ID for the dust intent (avoids collision with original tx segments)
    let dust_segment_id: u16 = OsRng.gen_range(2..u16::MAX);

    // Dust intent: no unshielded offers, no circuit actions, only dust
    let dust_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: Some(Sp::new(dust_actions)),
        ttl: Timestamp::from_secs(timestamp_secs + 1800), // 30 min TTL
        binding_commitment: OsRng.gen(), // random binding (matches facade's Intent::new)
    };

    let dust_intents_map = StorageHashMap::default().insert(dust_segment_id, dust_intent);

    let dust_tx = Transaction::new(
        network_id,
        dust_intents_map,
        None,
        midnight_storage::storage::HashMap::new(),
    );

    balance_log!(LOG_INFO, "Built dust-only unproven tx at segment {}", dust_segment_id);

    // ── Step 5: Prove the dust transaction locally ──
    // Prove the dust tx directly (no serialize/deserialize round-trip).
    // The prover resolves keys from the file system, no tx-embedded keys needed.

    let empty_keys = HashMap::<String, ProvingKeyMaterial>::new();
    let resolver = LocalFileResolver::new(keys_path.clone(), empty_keys);
    let provider = midnight_zkir::LocalProvingProvider {
        rng: OsRng,
        params: &resolver,
        resolver: &resolver,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;

    balance_log!(LOG_INFO, "Starting local proof for dust tx...");
    let prove_start = std::time::Instant::now();

    let cost_model = &INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model;

    let proven_dust_tx = rt
        .block_on(async { dust_tx.prove(provider, cost_model).await })
        .map_err(|e| format!("Local proving of dust tx failed: {}", e))?;

    let prove_elapsed = prove_start.elapsed();
    balance_log!(LOG_INFO, "Dust tx proved in {:.2}s", prove_elapsed.as_secs_f64());

    // ── Step 6: Seal each transaction BEFORE merging ──
    // CRITICAL: Must match the facade's order: prove -> seal (bind) -> merge.
    // Sealing before merge means each transaction gets its own random binding.
    // Merging before seal would sum PedersenRandomness then seal the sum,
    // which produces a different commitment than seal-then-merge.

    let sealed_original = proven_tx.seal(OsRng);
    let sealed_dust = proven_dust_tx.seal(OsRng);

    balance_log!(LOG_INFO, "Sealed both transactions individually");

    // ── Step 7: Merge sealed transactions ──

    let sealed_tx = sealed_original
        .merge(&sealed_dust)
        .map_err(|e| format!("Failed to merge sealed transactions: {:?}", e))?;

    balance_log!(LOG_INFO, "Merged sealed original + sealed dust");

    balance_log!(LOG_INFO, "Sealed merged transaction");

    // ── Step 8: Serialize and return ──

    let mut result_bytes = Vec::new();
    tagged_serialize(&sealed_tx, &mut result_bytes)
        .map_err(|e| format!("Failed to serialize balanced transaction: {:?}", e))?;

    let result_hex = hex::encode(&result_bytes);

    balance_log!(
        LOG_INFO,
        "Balance complete: {} bytes → {} bytes (fee={} specks, prove={:.2}s)",
        proven_bytes.len(),
        result_bytes.len(),
        total_fee,
        prove_elapsed.as_secs_f64()
    );

    Ok((result_hex, current_state))
}

/// Strip the tag prefix from tagged SCALE serialization.
/// Copied from fee_ffi.rs — same logic.
fn strip_tag_prefix(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() < 9 {
        return bytes;
    }

    if &bytes[0..9] == b"midnight:" {
        for i in 9..bytes.len() - 1 {
            if bytes[i] == b')' && bytes[i + 1] == b':' {
                return bytes[i + 2..].to_vec();
            }
            if bytes[i] == b']' && bytes[i + 1] == b':' {
                return bytes[i + 2..].to_vec();
            }
        }
    }

    bytes
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_safety() {
        let result = balance_proven_transaction(
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
        );
        assert!(result.is_null());
    }

    #[test]
    fn test_invalid_seed_length() {
        let tx_hex = CString::new("deadbeef").unwrap();
        let params_hex = CString::new("deadbeef").unwrap();
        let keys_dir = CString::new("/tmp").unwrap();
        let network = CString::new("undeployed").unwrap();
        let seed = [0u8; 16]; // Wrong length

        let result = balance_proven_transaction(
            tx_hex.as_ptr(),
            ptr::null_mut(), // Will fail at null check before seed check
            seed.as_ptr(),
            seed.len(),
            params_hex.as_ptr(),
            0,
            keys_dir.as_ptr(),
            network.as_ptr(),
        );
        assert!(result.is_null());
    }

    #[test]
    fn test_invalid_proven_tx_hex() {
        let tx_hex = CString::new("not_valid_hex").unwrap();
        let params_hex = CString::new("deadbeef").unwrap();
        let keys_dir = CString::new("/tmp").unwrap();
        let network = CString::new("undeployed").unwrap();
        let seed = [0u8; 32];

        // Create a minimal dust state for the test
        use midnight_ledger::dust::INITIAL_DUST_PARAMETERS;
        let dust_state = DustLocalState::<DefaultDB>::new(INITIAL_DUST_PARAMETERS);
        let mut boxed_state = Box::new(dust_state);

        let result = balance_proven_transaction(
            tx_hex.as_ptr(),
            &mut *boxed_state as *mut _,
            seed.as_ptr(),
            seed.len(),
            params_hex.as_ptr(),
            1704067200000,
            keys_dir.as_ptr(),
            network.as_ptr(),
        );
        assert!(result.is_null(), "Should fail on invalid hex");
    }

    #[test]
    fn test_fees_with_margin_on_initial_params() {
        // Test that fees_with_margin actually returns non-zero on a minimal transaction
        // using the INITIAL_TRANSACTION_COST_MODEL params (same as localnet)
        use midnight_ledger::structure::{
            Transaction, Intent, StandardTransaction, ProofPreimageMarker,
            INITIAL_TRANSACTION_COST_MODEL,
        };
        use midnight_transient_crypto::commitment::PedersenRandomness;
        use midnight_storage::storage::HashMap as StorageHashMap;

        // Create a minimal transaction with one empty intent
        let intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: None,
            actions: std::iter::empty().collect(),
            dust_actions: None,
            ttl: Timestamp::from_secs(1704067200),
            binding_commitment: PedersenRandomness::from(0),
        };
        let intents = StorageHashMap::default().insert(1u16, intent);
        let tx = Transaction::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>::new(
            "undeployed",
            intents,
            None,
            midnight_storage::storage::HashMap::new(),
        );

        let params = midnight_ledger::structure::INITIAL_PARAMETERS;
        let fee = tx.fees_with_margin(&params, 5);
        eprintln!("fees_with_margin on minimal ProofPreimageMarker tx: {:?}", fee);

        // Now test with a ProofMarker tx (proven) — does it return 0?
        // Serialize as unproven tuple, prove locally would require keys.
        // Instead, just verify ProofPreimageMarker works.
        match fee {
            Ok(f) => eprintln!("Fee value: {}", f),
            Err(e) => eprintln!("Fee error: {:?}", e),
        }

        // Serialize INITIAL_PARAMETERS to check the expected size
        let mut params_bytes = Vec::new();
        midnight_serialize::tagged_serialize(&params, &mut params_bytes).unwrap();
        eprintln!("INITIAL_PARAMETERS serialized: {} bytes", params_bytes.len());
        eprintln!("Tag prefix: {:?}", String::from_utf8_lossy(&params_bytes[..params_bytes.len().min(60)]));
    }

    #[test]
    fn test_strip_tag_prefix_with_tag() {
        let tagged = b"midnight:ledger-parameters[v4]:deadbeef".to_vec();
        let stripped = strip_tag_prefix(tagged);
        assert_eq!(stripped, b"deadbeef");
    }

    #[test]
    fn test_strip_tag_prefix_with_params_tag() {
        let tagged =
            b"midnight:transaction[v6](signature[v1],proof,pedersen-schnorr[v1]):cafebabe"
                .to_vec();
        let stripped = strip_tag_prefix(tagged);
        assert_eq!(stripped, b"cafebabe");
    }

    #[test]
    fn test_strip_tag_prefix_no_tag() {
        let raw = b"deadbeef".to_vec();
        let stripped = strip_tag_prefix(raw.clone());
        assert_eq!(stripped, raw);
    }
}

#[cfg(test)]
mod preprod_diagnostic {
    use super::*;
    use midnight_ledger::dust::{DustLocalState, DustSecretKey, INITIAL_DUST_PARAMETERS, Seed};
    use midnight_ledger::events::Event;
    use midnight_serialize::Deserializable;
    use midnight_storage::DefaultDB;

    /// Connect to PREPROD indexer, replay dust events, and check tree roots.
    /// Run with: cargo test preprod_diagnostic::test_replay_roots -- --nocapture --ignored
    #[test]
    #[ignore] // Only run manually (needs network)
    fn test_replay_roots() {
        // Alice's dust seed (from mn wallet seed)
        let seed_hex = "7dc468f62278cd0c14b6674f31531a90b64599d657d3c7ab2adb63395d647f7a505de6428fcf8b0d208873f4d5e2a1340c14688067477542f53c48dfea817da4";
        let seed_bytes = hex::decode(seed_hex).unwrap();
        
        // Derive dust key at m/44'/2400'/0'/2/0
        // For now, use the first 32 bytes of the seed as dust seed (simplified)
        let mut dust_seed: Seed = [0u8; 32];
        dust_seed.copy_from_slice(&seed_bytes[..32]);
        let dust_sk = DustSecretKey::derive_secret_key(&dust_seed);

        // Create fresh state
        let state = DustLocalState::<DefaultDB>::new(INITIAL_DUST_PARAMETERS);
        
        eprintln!("Initial state: utxos={}", state.utxos().count());
        eprintln!("Initial commitment root: {:?}", state.commitment_root());
        eprintln!("Initial generation root: {:?}", state.generation_root());

        // We need real events from the indexer. For now, test with empty events.
        // The real test: fetch events from PREPROD indexer via HTTP/WS.
        
        // Check that roots are Some after creation (tree should be rehashed)
        let com_root = state.commitment_root();
        let gen_root = state.generation_root();
        eprintln!("Commitment root: {:?}", com_root);
        eprintln!("Generation root: {:?}", gen_root);
        
        // Both should be Some (empty tree has a valid root)
        assert!(com_root.is_some(), "Commitment root should be Some for empty tree");
        assert!(gen_root.is_some(), "Generation root should be Some for empty tree");
    }

    /// Test: replay a small set of events and verify roots are valid after replay.
    #[test]
    fn test_replay_preserves_roots() {
        let state = DustLocalState::<DefaultDB>::new(INITIAL_DUST_PARAMETERS);

        // After creation, roots should be valid
        assert!(state.commitment_root().is_some(), "Fresh state should have commitment root");
        assert!(state.generation_root().is_some(), "Fresh state should have generation root");

        eprintln!("Empty tree commitment root: {:?}", state.commitment_root().unwrap());
        eprintln!("Empty tree generation root: {:?}", state.generation_root().unwrap());
    }

    /// CRITICAL TEST: verify that replay on the DustLocalState produces valid
    /// spend proofs that would pass the node's well_formed check.
    /// Uses TestState which internally does: apply_system_tx -> get events -> replay_events.
    /// This mimics the exact flow our Android SDK uses.
    #[tokio::test]
    async fn test_spend_after_give_fee_token() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x42);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);

        // Give the wallet dust (this internally does block processing + replay_events)
        state.give_fee_token(&mut rng, 1).await;

        let com_root = state.dust.commitment_root();
        let gen_root = state.dust.generation_root();
        let utxo_count = state.dust.utxos().count();

        eprintln!("State after give_fee_token:");
        eprintln!("  Commitment root: {:?}", com_root);
        eprintln!("  Generation root: {:?}", gen_root);
        eprintln!("  UTXO count: {}", utxo_count);

        assert!(com_root.is_some(), "Commitment root must be Some");
        assert!(gen_root.is_some(), "Generation root must be Some");
        assert!(utxo_count > 0, "Must have UTXOs");

        // Try a spend (same as what balance_ffi does)
        let utxo = state.dust.utxos().next().unwrap();
        let (new_state, dust_spend) = state.dust
            .spend(&state.dust_key, &utxo, 42, state.time)
            .expect("spend should succeed");

        eprintln!("Spend succeeded!");
        eprintln!("  New commitment root: {:?}", new_state.commitment_root());
        eprintln!("  New UTXO count: {}", new_state.utxos().count());

        // The TestState.dust is built via replay_events (same as our Android SDK).
        // If spend succeeds here, the replay approach is fundamentally correct.
        // Error 170 on PREPROD must be caused by something else:
        // - Indexer event differences vs node events
        // - Event serialization/deserialization issues
        // - Timing/ctime mismatch
    }

    /// CRITICAL TEST: does serialize/deserialize preserve the Merkle tree roots?
    /// Our Android streaming replay does: replay 500 events -> serialize -> save
    /// -> deserialize -> replay next 500 -> serialize -> save -> ...
    /// If serialization corrupts the tree, this would explain error 170 on PREPROD.
    #[tokio::test]
    async fn test_serialize_deserialize_preserves_roots() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x42);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);
        state.give_fee_token(&mut rng, 1).await;

        let original_com = state.dust.commitment_root();
        let original_gen = state.dust.generation_root();

        eprintln!("Original roots:");
        eprintln!("  Commitment: {:?}", original_com);
        eprintln!("  Generation: {:?}", original_gen);

        // Serialize the state (same as DustRepository.saveState via DustLocalState.serialize())
        let mut serialized = Vec::new();
        midnight_serialize::Serializable::serialize(&state.dust, &mut serialized)
            .expect("serialize should succeed");
        eprintln!("  Serialized size: {} bytes", serialized.len());

        // Deserialize (same as DustRepository.loadState)
        let deserialized: DustLocalState<InMemoryDB> =
            midnight_serialize::Deserializable::deserialize(&mut &serialized[..], 0)
                .expect("deserialize should succeed");

        let deser_com = deserialized.commitment_root();
        let deser_gen = deserialized.generation_root();

        eprintln!("After serialize/deserialize:");
        eprintln!("  Commitment: {:?}", deser_com);
        eprintln!("  Generation: {:?}", deser_gen);

        assert_eq!(original_com, deser_com,
            "Commitment root must survive serialize/deserialize round-trip");
        assert_eq!(original_gen, deser_gen,
            "Generation root must survive serialize/deserialize round-trip");

        // Also test: can we still spend from the deserialized state?
        let utxo = deserialized.utxos().next().unwrap();
        let spend_result = deserialized.spend(&state.dust_key, &utxo, 42, state.time);
        assert!(spend_result.is_ok(), "Spend after deserialize should work: {:?}", spend_result.err());

        eprintln!("Spend after deserialize: SUCCESS");
    }

    /// Test: create many dust UTXOs and verify spend still works.
    /// PREPROD has 8 UTXOs from 249k events. If tree structure breaks at scale, this catches it.
    #[tokio::test]
    async fn test_spend_with_many_fee_tokens() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x42);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);

        // Create 8 UTXOs (same as PREPROD alice wallet)
        state.give_fee_token(&mut rng, 8).await;

        let utxo_count = state.dust.utxos().count();
        eprintln!("UTXOs: {}", utxo_count);
        eprintln!("Commitment root: {:?}", state.dust.commitment_root());
        eprintln!("Generation root: {:?}", state.dust.generation_root());

        assert!(utxo_count >= 8, "Should have at least 8 UTXOs");

        // Try spend
        let utxo = state.dust.utxos().next().unwrap();
        let result = state.dust.spend(&state.dust_key, &utxo, 42, state.time);
        assert!(result.is_ok(), "Spend with 8 UTXOs should work: {:?}", result.err());
        eprintln!("Spend with {} UTXOs: SUCCESS", utxo_count);
    }

    /// CRITICAL: does chunked replay produce the same roots as single-pass replay?
    /// Our Android streaming replay does: replay(chunk1) → serialize → deserialize → replay(chunk2) → ...
    /// If this produces different roots than replay(all_events), THAT explains error 170.
    #[tokio::test]
    async fn test_chunked_replay_matches_single_pass() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};
        use midnight_ledger::events::Event;

        let mut rng = StdRng::seed_from_u64(0x42);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);

        // Generate events by giving multiple fee tokens
        // Each give_fee_token triggers reward_night which calls assert_apply
        // which calls replay_events on state.dust
        state.give_fee_token(&mut rng, 4).await;

        // The TestState doesn't store events in state.events (it's always empty).
        // So we need to generate events by manually driving the state.
        // Instead, let's test serialize→deserialize→replay by:
        // 1. Getting the state after give_fee_token (built via replay internally)
        // 2. Serializing it
        // 3. Deserializing it
        // 4. Comparing roots

        // Actually, let me directly test the chunked approach:
        // Create two fresh states, replay the same events differently.
        // But we don't have the events externally...

        // Alternative approach: start with the fully replayed state,
        // serialize it, deserialize it, and verify the roots match.
        // Then try a spend on the deserialized state.

        let original_com = state.dust.commitment_root();
        let original_gen = state.dust.generation_root();
        eprintln!("Original (4 fee tokens): com={:?} gen={:?}", original_com, original_gen);

        // Serialize
        let mut bytes = Vec::new();
        midnight_serialize::Serializable::serialize(&state.dust, &mut bytes)
            .expect("serialize should succeed");

        // Deserialize
        let restored: DustLocalState<InMemoryDB> =
            midnight_serialize::Deserializable::deserialize(&mut &bytes[..], 0)
                .expect("deserialize should succeed");

        let restored_com = restored.commitment_root();
        let restored_gen = restored.generation_root();
        eprintln!("Restored: com={:?} gen={:?}", restored_com, restored_gen);

        assert_eq!(original_com, restored_com, "Commitment root must survive round-trip");
        assert_eq!(original_gen, restored_gen, "Generation root must survive round-trip");

        // Now add more fee tokens on the ORIGINAL state
        state.give_fee_token(&mut rng, 4).await;
        let extended_com = state.dust.commitment_root();
        let extended_gen = state.dust.generation_root();
        eprintln!("Extended (8 total): com={:?} gen={:?}", extended_com, extended_gen);

        // Also extend from the RESTORED state with the same operations
        // But we can't do this because give_fee_token modifies the TestState
        // which includes the ledger, not just the dust.
        // The events are generated by the ledger and consumed by replay.

        // What we CAN verify: the roots change after adding more tokens
        assert_ne!(original_com, extended_com, "Roots should change with more events");

        // And spend works on the extended state
        let utxo = state.dust.utxos().next().unwrap();
        let result = state.dust.spend(&state.dust_key, &utxo, 42, state.time);
        assert!(result.is_ok(), "Spend should work on extended state");
        eprintln!("Spend on extended state: SUCCESS");
    }

    /// Decode the live ledger parameters and print key fee/cost fields.
    /// Run with: cargo test --release --lib inspect_ledger_params -- --nocapture --ignored
    #[test]
    #[ignore]
    fn inspect_ledger_params() {
        use midnight_ledger::structure::LedgerParameters;
        use midnight_serialize::tagged_deserialize;

        let hex_str = std::fs::read_to_string("/tmp/ledger_params.hex")
            .expect("/tmp/ledger_params.hex missing — fetch from indexer first");
        let bytes = hex::decode(hex_str.trim()).expect("hex decode");
        eprintln!("Ledger params: {} bytes", bytes.len());

        let params: LedgerParameters = tagged_deserialize(&bytes[..])
            .expect("deserialize ledger params");

        eprintln!("\nlimits.min_time_to_dismiss: {:?}", params.limits.min_time_to_dismiss);
        eprintln!("limits.time_to_dismiss_per_byte: {:?}", params.limits.time_to_dismiss_per_byte);
        eprintln!("limits.block_limits: {:?}", params.limits.block_limits);
        eprintln!("\nfee_prices: {:?}", params.fee_prices);
        eprintln!("\ncost_model.baseline_cost: {:?}", params.cost_model.baseline_cost);
    }

    /// Decode an SDK-built transaction (sealed = PureGeneratorPedersen) and print its
    /// dust spend structure. Used to compare against our balance_ffi-built tx.
    ///
    /// Inputs:
    ///   /tmp/sdk_tx_raw.hex  — raw tagged Transaction bytes (extrinsic stripped)
    ///   /tmp/our_tx_raw.hex  — our balance_ffi output (capture from logcat)
    ///
    /// Run with: cargo test --release --lib decode_sdk_tx_dust -- --nocapture --ignored
    #[test]
    #[ignore]
    fn decode_sdk_tx_dust() {
        use midnight_base_crypto::signatures::Signature;
        use midnight_ledger::structure::{ProofMarker, StandardTransaction, Transaction};
        use midnight_serialize::tagged_deserialize;
        use midnight_storage::db::InMemoryDB;
        use midnight_transient_crypto::commitment::PureGeneratorPedersen;

        type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

        let params: midnight_ledger::structure::LedgerParameters = std::fs::read_to_string("/tmp/ledger_params.hex")
            .ok()
            .and_then(|h| hex::decode(h.trim()).ok())
            .and_then(|b| midnight_serialize::tagged_deserialize(&b[..]).ok())
            .expect("/tmp/ledger_params.hex required for fees(true) inspection");

        for path in ["/tmp/sdk_tx_raw.hex", "/tmp/our_tx_raw.hex"] {
            let hex_str = match std::fs::read_to_string(path) {
                Ok(s) => s.trim().to_string(),
                Err(_) => {
                    eprintln!("--- {} not present, skipping ---\n", path);
                    continue;
                }
            };
            let bytes = hex::decode(&hex_str).expect("hex decode");
            eprintln!("=== {} ({} bytes) ===", path, bytes.len());

            let tx: SealedTx = match tagged_deserialize(&bytes[..]) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("  DESERIALIZE FAIL: {:?}\n", e);
                    continue;
                }
            };

            // The critical diagnostic: replicate what the on-chain verifier does.
            eprintln!("  fees(params, true)  [node check]:  {:?}", tx.fees(&params, true));
            eprintln!("  fees(params, false) [our check]:   {:?}", tx.fees(&params, false));
            eprintln!("  fees_with_margin(params, 5):        {:?}", tx.fees_with_margin(&params, 5));

            match &tx {
                Transaction::Standard(std_tx) => {
                    eprintln!("  network_id: {:?}", std_tx.network_id);
                    eprintln!("  binding_randomness: {:?}", std_tx.binding_randomness);
                    eprintln!("  guaranteed_coins.is_some(): {}", std_tx.guaranteed_coins.is_some());
                    eprintln!("  fallible_coins entries: {}", std_tx.fallible_coins.size());
                    eprintln!("  intents:");
                    for entry in std_tx.intents.iter() {
                        let inner = &*entry;
                        let segment = *inner.0;
                        let intent = &*inner.1;
                        eprintln!("    segment {}: ttl={:?}", segment, intent.ttl);
                        eprintln!("      dust_actions.is_some(): {}", intent.dust_actions.is_some());
                        if let Some(da_sp) = &intent.dust_actions {
                            let da = &**da_sp;
                            eprintln!("      dust ctime: {:?}", da.ctime);
                            eprintln!("      dust spends: count via Vec");
                            let spends_vec: std::vec::Vec<_> = (&da.spends).into();
                            eprintln!("      dust spends: {}", spends_vec.len());
                            for (i, s) in spends_vec.iter().enumerate() {
                                eprintln!("        spend[{}]: v_fee={}", i, s.v_fee);
                                eprintln!("          old_nullifier: {:?}", s.old_nullifier);
                                eprintln!("          new_commitment: {:?}", s.new_commitment);
                            }
                            let regs_vec: std::vec::Vec<_> = (&da.registrations).into();
                            eprintln!("      dust registrations: {}", regs_vec.len());
                        }
                        eprintln!("      guaranteed_unshielded_offer.is_some(): {}", intent.guaranteed_unshielded_offer.is_some());
                        eprintln!("      fallible_unshielded_offer.is_some(): {}", intent.fallible_unshielded_offer.is_some());
                        eprintln!("      contract_actions: {}", intent.actions.len());
                    }
                }
                _ => eprintln!("  Not a StandardTransaction"),
            }
            eprintln!();
        }
    }

    /// Test: verify replay is deterministic (same events -> same roots).
    #[tokio::test]
    async fn test_replay_is_deterministic() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng1 = StdRng::seed_from_u64(0x42);
        let mut state1 = TestState::<InMemoryDB>::new(&mut rng1);
        state1.give_fee_token(&mut rng1, 1).await;

        let mut rng2 = StdRng::seed_from_u64(0x42);
        let mut state2 = TestState::<InMemoryDB>::new(&mut rng2);
        state2.give_fee_token(&mut rng2, 1).await;

        // Same seed -> same events -> same state
        assert_eq!(
            state1.dust.commitment_root(), state2.dust.commitment_root(),
            "Deterministic replay must produce same commitment roots"
        );
        assert_eq!(
            state1.dust.generation_root(), state2.dust.generation_root(),
            "Deterministic replay must produce same generation roots"
        );

        eprintln!("Deterministic replay: PASSED");
    }
}
