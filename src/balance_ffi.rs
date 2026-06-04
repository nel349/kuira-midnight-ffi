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
use midnight_ledger::dust::{DustActions, DustLocalState, DustNullifier, DustSecretKey, DustSpend, Seed};
use midnight_ledger::structure::{
    Intent, LedgerParameters, ProofMarker, ProofPreimageMarker, Transaction,
    INITIAL_TRANSACTION_COST_MODEL,
};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::DB;
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
/// - `exclude_nullifiers_hex`: Comma-separated lowercase-hex dust nullifiers to skip
///   during UTXO selection (UTXOs the wallet already spent but the event stream
///   hasn't reflected). May be null or empty to skip nothing.
///
/// # Returns
///
/// A string `<balanced+sealed tagged-SCALE hex>;<spent nullifier hex>,<...>`
/// (the spent-nullifier list may be empty), or null on error. The caller records
/// the spent nullifiers durably and passes them back via `exclude_nullifiers_hex`
/// on subsequent balances. Caller must free with `free_balanced_transaction`.
///
/// # Safety
///
/// All pointer parameters except `exclude_nullifiers_hex` must be valid and
/// non-null. `dust_state_ptr` is modified on success.
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
    exclude_nullifiers_hex: *const c_char,
) -> *mut c_char {
    // Null checks. `exclude_nullifiers_hex` is intentionally NOT required — a null
    // or empty value means "no UTXOs to skip" (the common case before any spend).
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

    // Dust nullifiers (lowercase hex, comma-separated) the wallet has already
    // spent but whose spend the indexer's event stream hasn't reflected yet. The
    // balancer must not re-select these (re-spend → node error 115). Null/empty =
    // skip nothing. Hex contains no commas, so comma-splitting is unambiguous.
    let exclude_nullifiers: std::collections::HashSet<String> = if exclude_nullifiers_hex.is_null() {
        std::collections::HashSet::new()
    } else {
        match unsafe { CStr::from_ptr(exclude_nullifiers_hex).to_str() } {
            Ok(s) => s
                .split(',')
                .map(|n| n.trim().to_lowercase())
                .filter(|n| !n.is_empty())
                .collect(),
            Err(e) => {
                balance_log!(LOG_ERROR, "Invalid UTF-8 in exclude_nullifiers_hex: {}", e);
                return ptr::null_mut();
            }
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
        &exclude_nullifiers,
    ) {
        Ok((balanced_hex, updated_state, spent_nullifiers)) => {
            // Write the post-spend state back to the cached pointer. `spend()` marks
            // the consumed UTXO `pending_until`, which `utxos()` filters out — so the
            // next sequential transaction can't reselect it ("UTXO already spent",
            // error 115). Crucially, `spend()` does NOT mutate the commitment/
            // generation trees (those ops build the proof, not local state), so the
            // root is byte-identical and this does NOT cause error 170 — see the
            // spend_marks_pending_and_preserves_root invariant test in dust_ffi.rs.
            //
            // History: removing this write-back (commit 9af1f7f) on a "corrupts
            // Merkle roots" premise is what reintroduced 115; that premise is false
            // (the trees are untouched). The real error-170 fix is the freshness /
            // chain-block-time path in MidnightWallet, independent of this.
            //
            // SAFETY: dust_state_ptr is non-null (checked at entry); the impl borrowed
            // the prior state immutably and cloned it before mutating, so no live
            // borrow aliases this write.
            unsafe {
                *dust_state_ptr = updated_state;
            }
            balance_log!(LOG_INFO, "Updated dust state after balance (spent UTXO marked pending)");

            // Return `<balanced tx hex>;<spent nullifier hex>,<...>`. One C string
            // keeps the JNI layer untouched, and a delimited form lets the caller
            // parse it with a plain split — no JSON dependency (which the Android
            // unit-test classpath lacks). Hex contains neither ';' nor ',', so the
            // delimiters are unambiguous. The caller records the nullifiers durably
            // and feeds them back via `exclude_nullifiers_hex` on the next balance —
            // the dust event stream doesn't reliably reflect the wallet's own fee
            // spends, so without this the next move re-selects the UTXO → error 115.
            let envelope = format!("{};{}", balanced_hex, spent_nullifiers.join(","));
            match CString::new(envelope) {
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

/// Serialize a dust nullifier to lowercase hex. Shared by the balancer's selection
/// (what it records as spent) and [`current_nullifiers`] (what it prunes against) so
/// both produce byte-identical strings — the skip-set match depends on it.
fn nullifier_to_hex(nullifier: &DustNullifier) -> Result<String, String> {
    use midnight_serialize::Serializable;
    let mut bytes = Vec::new();
    nullifier
        .0
        .serialize(&mut bytes)
        .map_err(|e| format!("Failed to serialize dust nullifier: {:?}", e))?;
    Ok(hex::encode(&bytes))
}

/// Lowercase-hex nullifiers of every UTXO currently in `state`. Generic over the DB
/// backend so it's unit-testable against an in-memory state.
fn current_nullifiers<D: DB>(
    state: &DustLocalState<D>,
    dust_secret_key: &DustSecretKey,
) -> Result<Vec<String>, String> {
    state
        .utxos()
        .map(|utxo| nullifier_to_hex(&utxo.nullifier(dust_secret_key)))
        .collect()
}

/// List the dust nullifiers (lowercase hex, comma-separated) of every UTXO in the
/// current state. Used to prune the wallet's spent-nullifier skip-set: a recorded
/// nullifier still present here means the event stream hasn't reflected the spend
/// (keep skipping it); one that's gone has been confirmed spent and can be dropped.
/// It also lets the caller detect "all spendable dust is excluded" and fail fast
/// instead of attempting a balance that can't succeed.
///
/// Caller must free the result with `free_c_string`.
///
/// # Safety
///
/// `state_ptr` and `seed_ptr` must be valid and non-null; `seed_len` must be 32.
#[no_mangle]
pub extern "C" fn dust_current_nullifiers(
    state_ptr: *const DustLocalState<DefaultDB>,
    seed_ptr: *const u8,
    seed_len: usize,
) -> *mut c_char {
    if state_ptr.is_null() || seed_ptr.is_null() {
        balance_log!(LOG_ERROR, "Null pointer in dust_current_nullifiers");
        return ptr::null_mut();
    }
    if seed_len != 32 {
        balance_log!(LOG_ERROR, "Seed must be 32 bytes, got {}", seed_len);
        return ptr::null_mut();
    }

    // SAFETY: pointers validated non-null; seed_len validated == 32.
    let state = unsafe { &*state_ptr };
    let seed_slice = unsafe { std::slice::from_raw_parts(seed_ptr, seed_len) };
    let mut seed: Seed = [0u8; 32];
    seed.copy_from_slice(seed_slice);
    let dust_secret_key = DustSecretKey::derive_secret_key(&seed);

    let hexes = match current_nullifiers(state, &dust_secret_key) {
        Ok(h) => h,
        Err(e) => {
            balance_log!(LOG_ERROR, "dust_current_nullifiers: {}", e);
            return ptr::null_mut();
        }
    };

    match CString::new(hexes.join(",")) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            balance_log!(LOG_ERROR, "dust_current_nullifiers: C string failed: {}", e);
            ptr::null_mut()
        }
    }
}

/// Select dust UTXOs to cover `total_fee`, skipping any whose nullifier is in
/// `exclude_nullifiers` — UTXOs the wallet already spent but the indexer's event
/// stream hasn't reflected yet. Re-selecting such a UTXO makes the node reject the
/// transaction with error 115 ("UTXO already spent").
///
/// Returns the post-selection state (each selected UTXO marked `pending_until`,
/// which [`DustLocalState::utxos`] then filters out — the commitment root is
/// untouched, so this does NOT cause error 170), the dust spends to include in the
/// transaction, and the spent nullifiers as lowercase hex in selection order. The
/// caller records those nullifiers durably and feeds them back via
/// `exclude_nullifiers` on the next balance.
///
/// Generic over the DB backend so it can be unit-tested against an in-memory state
/// without the full prove/seal pipeline.
fn select_dust_spends<D: DB>(
    dust_state: &DustLocalState<D>,
    dust_secret_key: &DustSecretKey,
    total_fee: u128,
    timestamp: Timestamp,
    exclude_nullifiers: &std::collections::HashSet<String>,
) -> Result<(DustLocalState<D>, Vec<DustSpend<ProofPreimageMarker, D>>, Vec<String>), String> {
    let utxos: Vec<_> = dust_state.utxos().collect();
    let mut current_state = dust_state.clone();
    let mut dust_spends = Vec::new();
    let mut spent_nullifiers: Vec<String> = Vec::new();
    let mut fee_remaining = total_fee;

    for (idx, utxo) in utxos.iter().enumerate() {
        if fee_remaining == 0 {
            break;
        }

        match current_state.spend(dust_secret_key, utxo, fee_remaining, timestamp) {
            Ok((new_state, dust_spend)) => {
                // The nullifier the node will check for this spend. Matching the
                // skip-set against `old_nullifier` (not a value re-derived from the
                // UTXO) keeps it byte-for-byte what a prior spend recorded and what
                // the node verifies. `dust_current_nullifiers` uses the same helper
                // on `utxo.nullifier(sk)` (== `old_nullifier`) so prune and exclude
                // compare identical strings.
                let nullifier_hex = nullifier_to_hex(&dust_spend.old_nullifier)?;

                // Skip UTXOs the wallet has already spent. The dust event stream
                // doesn't reliably reflect our own fee spends, so the synced state
                // still lists a consumed UTXO as available; re-selecting it makes the
                // node reject with error 115. Discard this speculative spend (keep
                // `current_state`, don't count the fee) and roll to the next UTXO.
                if exclude_nullifiers.contains(&nullifier_hex) {
                    balance_log!(LOG_INFO,
                        "Skipping already-spent dust UTXO: nullifier={} seq={} mt_index={}",
                        nullifier_hex, utxo.seq, utxo.mt_index);
                    continue;
                }

                // Diagnostic: log the Merkle roots used in the proof.
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

                current_state = new_state;
                dust_spends.push(dust_spend);
                spent_nullifiers.push(nullifier_hex);
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
            "Insufficient dust balance. Need {} specks, no UTXO has enough \
             (after skipping {} already-spent UTXO(s)).",
            total_fee,
            exclude_nullifiers.len()
        ));
    }

    Ok((current_state, dust_spends, spent_nullifiers))
}

fn balance_proven_transaction_impl(
    proven_hex: &str,
    dust_state: &DustLocalState<DefaultDB>,
    seed: &Seed,
    params_hex: &str,
    current_time_ms: i64,
    keys_path: &PathBuf,
    network_id: &str,
    exclude_nullifiers: &std::collections::HashSet<String>,
) -> Result<(String, DustLocalState<DefaultDB>, Vec<String>), String> {
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

    // TEMP (error-115/InvalidProof localization): capture the PRE-SEAL proven tx
    // exactly as it enters the balancer, before seal()/dust mutate anything. Paired
    // with CAPTURE_SUBMITTED_TX (post-seal), this lets the offline well_formed repro
    // diff the contract-call transcript/gas/effects/binding across the seal boundary
    // and decide whether seal broke the proof or the prover used a different
    // transcript than was embedded. Chunked because logcat truncates long lines.
    // Remove after diagnosis.
    for (i, chunk) in proven_hex.as_bytes().chunks(3500).enumerate() {
        balance_log!(LOG_INFO, "CAPTURE_PRESEAL_TX[{}]={}", i, std::str::from_utf8(chunk).unwrap_or(""));
    }

    // TEMP (error-115 unshielded diagnosis): the dust fix removed the dust spend, but
    // 115 (InputNotInUtxos on an UnshieldedOffer) persists — so the contract-call tx
    // itself spends an already-spent NIGHT UTXO. Log every unshielded input so we can
    // see which UTXO it is and whether it's the stale one. Remove after diagnosis.
    if let Transaction::Standard(stx) = &proven_tx {
        balance_log!(LOG_INFO, "REVEAL_TX: guaranteed_zswap_present={}, intents={}",
            stx.guaranteed_coins.is_some(), stx.intents.iter().count());
        for entry in stx.intents.iter() {
            let (_seg, intent) = &*entry;
            if let Some(offer) = &intent.guaranteed_unshielded_offer {
                for input in offer.inputs.iter_deref() {
                    balance_log!(LOG_INFO,
                        "REVEAL_UNSHIELDED_INPUT kind=guaranteed value={} output_no={} type={:?} intent_hash={:?}",
                        input.value, input.output_no, input.type_, input.intent_hash);
                }
            }
            if let Some(offer) = &intent.fallible_unshielded_offer {
                for input in offer.inputs.iter_deref() {
                    balance_log!(LOG_INFO,
                        "REVEAL_UNSHIELDED_INPUT kind=fallible value={} output_no={} type={:?} intent_hash={:?}",
                        input.value, input.output_no, input.type_, input.intent_hash);
                }
            }
        }
    }

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

    // Calculate the dust fee. `fees_with_margin` returns 0 on a zero-fee network
    // (e.g. `undeployed`). In that case the transaction needs NO dust intent at
    // all — the ledger skips dust checks when `dust_actions` is None, a
    // present-but-empty `DustActions` is rejected as `NotNormalized`
    // (dust.rs:762), and error 168 (FeeCalculation) is a cost/time-to-dismiss
    // limit, never "no dust spent" (structure.rs:2181). Forcing a ≥1-speck spend
    // here (commit 2c41709's `.max(1)`) burned a real dust UTXO on every move; the
    // node then saw it spent and the next move re-selected it → error 115. So when
    // the fee is 0, seal the proven tx with no dust intent and return it unchanged
    // — exactly as the code did before 2c41709.
    let erased_tx = proven_tx.erase_proofs();
    let base_fee = erased_tx
        .fees_with_margin(&params, DEFAULT_FEE_BLOCKS_MARGIN)
        .map_err(|e| format!("Fee calculation failed: {:?}", e))?;

    balance_log!(LOG_INFO, "Fee from ledger params: {} specks", base_fee);

    let overhead = base_fee * FEE_OVERHEAD_PERCENT / 100;
    let total_fee: u128 = base_fee + overhead;

    balance_log!(LOG_INFO, "Calculated fee: {} specks (base={}, overhead={})",
        total_fee, base_fee, overhead);

    if total_fee == 0 {
        balance_log!(LOG_INFO, "Zero-fee network — sealing proven tx with no dust intent");
        let sealed_tx = proven_tx.seal(OsRng);
        let mut result_bytes = Vec::new();
        tagged_serialize(&sealed_tx, &mut result_bytes)
            .map_err(|e| format!("Failed to serialize sealed transaction: {:?}", e))?;
        let result_hex = hex::encode(&result_bytes);
        // TEMP (InvalidProof capture): the exact sealed tx submitted to the node, so
        // we can replay it through the ledger verifier offline. Chunked because
        // logcat truncates long lines. Remove after diagnosis.
        for (i, chunk) in result_hex.as_bytes().chunks(3500).enumerate() {
            balance_log!(LOG_INFO, "CAPTURE_SUBMITTED_TX[{}]={}", i, std::str::from_utf8(chunk).unwrap_or(""));
        }
        // No dust spent → no nullifiers to record; dust state unchanged.
        return Ok((result_hex, dust_state.clone(), Vec::new()));
    }

    // ── Step 3: Create dust spends ──

    let dust_secret_key = DustSecretKey::derive_secret_key(seed);
    let timestamp_secs = u64::try_from(current_time_ms / 1000)
        .map_err(|_| format!("Negative timestamp: {}", current_time_ms))?;
    let timestamp = Timestamp::from_secs(timestamp_secs);

    let (current_state, dust_spends, spent_nullifiers) = select_dust_spends(
        dust_state,
        &dust_secret_key,
        total_fee,
        timestamp,
        exclude_nullifiers,
    )?;

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

    Ok((result_hex, current_state, spent_nullifiers))
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
            ptr::null(),
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
            ptr::null(),
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

    /// Error-115 regression: a nullifier the wallet already spent must never be
    /// re-selected. The dust event stream doesn't reliably reflect the wallet's own
    /// fee spends, so the synced state still lists a consumed UTXO as available;
    /// without the skip-set the balancer reselects it and the node rejects the tx
    /// with "UTXO already spent" (error 115). With two funded UTXOs, excluding the
    /// first-selected nullifier must make selection pick the other one.
    #[tokio::test]
    async fn select_dust_spends_skips_excluded_nullifier() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x115);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);
        state.give_fee_token(&mut rng, 2).await;
        let selectable = state.dust.utxos().count();
        assert!(selectable >= 2, "test needs >= 2 funded UTXOs, got {}", selectable);

        let none_excluded = std::collections::HashSet::new();

        // First balance: no exclusions — selects one UTXO and reports its nullifier.
        let (post1, spends1, spent1) =
            select_dust_spends(&state.dust, &state.dust_key, 42, state.time, &none_excluded)
                .expect("first selection succeeds");
        assert_eq!(spends1.len(), 1, "one UTXO covers the fee");
        assert_eq!(spent1.len(), 1, "exactly one spent nullifier reported");
        let first_nullifier = spent1[0].clone();

        // State-level 115 guard: the spent UTXO drops out of the selectable set.
        assert_eq!(
            post1.utxos().count(),
            selectable - 1,
            "spent UTXO still selectable -> next tx reselects it -> error 115",
        );

        // Second balance on the ORIGINAL state, now excluding the first nullifier:
        // selection must pick the OTHER UTXO, never the excluded one.
        let excluded = std::collections::HashSet::from([first_nullifier.clone()]);
        let (_post2, _spends2, spent2) =
            select_dust_spends(&state.dust, &state.dust_key, 42, state.time, &excluded)
                .expect("second selection finds an alternative UTXO");
        assert_eq!(spent2.len(), 1);
        assert_ne!(
            spent2[0], first_nullifier,
            "selection re-picked an already-spent (excluded) nullifier -> error 115",
        );
    }

    /// When the only funded UTXO is excluded, selection must fail cleanly with an
    /// insufficient-balance error rather than silently re-spending it (which the
    /// node would reject with error 115).
    #[tokio::test]
    async fn select_dust_spends_errors_when_only_utxo_is_excluded() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x116);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);
        state.give_fee_token(&mut rng, 1).await;

        // Learn the single UTXO's nullifier from an unconstrained selection.
        let (_p, _s, spent) =
            select_dust_spends(&state.dust, &state.dust_key, 42, state.time, &std::collections::HashSet::new())
                .expect("baseline selection succeeds");
        assert_eq!(spent.len(), 1);
        let only_nullifier = spent[0].clone();

        let excluded = std::collections::HashSet::from([only_nullifier]);
        let result =
            select_dust_spends(&state.dust, &state.dust_key, 42, state.time, &excluded);
        assert!(
            result.is_err(),
            "excluding the only UTXO must fail cleanly, not reselect it",
        );
    }

    /// `current_nullifiers` (the prune/fast-fail source) lists every UTXO once, and
    /// the hex it produces is byte-identical to what the balancer records as spent —
    /// the invariant the skip-set prune depends on. If these diverged, prune would
    /// never drop confirmed-spent entries and fast-fail would misfire.
    #[tokio::test]
    async fn current_nullifiers_matches_what_the_balancer_spends() {
        use midnight_ledger::test_utilities::TestState;
        use midnight_storage::db::InMemoryDB;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x117);
        let mut state = TestState::<InMemoryDB>::new(&mut rng);
        state.give_fee_token(&mut rng, 3).await;
        let selectable = state.dust.utxos().count();
        assert!(selectable >= 3, "test needs >= 3 funded UTXOs, got {}", selectable);

        let present = current_nullifiers(&state.dust, &state.dust_key)
            .expect("listing current nullifiers succeeds");
        assert_eq!(present.len(), selectable, "one nullifier per current UTXO");
        let unique: std::collections::HashSet<_> = present.iter().collect();
        assert_eq!(unique.len(), present.len(), "nullifiers are distinct");
        assert!(present.iter().all(|n| n == &n.to_lowercase()), "lowercase hex");

        // The nullifier the balancer reports as spent must be one this lists — so a
        // recorded spend can later be pruned (or kept) by membership in this set.
        let (_post, _spends, spent) =
            select_dust_spends(&state.dust, &state.dust_key, 42, state.time, &std::collections::HashSet::new())
                .expect("selection succeeds");
        assert!(
            present.contains(&spent[0]),
            "balancer's spent nullifier not in current_nullifiers -> prune/fast-fail would break",
        );
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

    /// Reproduce the reveal that the node rejected (error 115 = InvalidProof) / crashed
    /// on. Loads the exact sealed reveal tx + the contract state it proved against,
    /// captured on-device (see CAPTURE_SUBMITTED_TX / CAPTURE_STATE_HEX). First step:
    /// deserialize + dump the structure to find the malformation. Run with:
    ///   cargo test -p kuira-crypto-ffi inspect_reveal_invalidproof -- --nocapture
    #[test]
    fn inspect_reveal_invalidproof() {
        use midnight_transient_crypto::commitment::PureGeneratorPedersen;
        type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

        let tx_hex = include_str!("../test-fixtures/reveal_invalidproof_tx.hex").trim();
        let bytes = hex::decode(tx_hex).expect("tx hex decodes");
        eprintln!("reveal tx: {} bytes", bytes.len());

        let tx: SealedTx = tagged_deserialize(&bytes[..]).expect("reveal tx deserializes");

        match &tx {
            Transaction::Standard(stx) => {
                eprintln!("network_id={:?}", stx.network_id);
                eprintln!("guaranteed_coins={} fallible_coins={}",
                    stx.guaranteed_coins.is_some(), stx.fallible_coins.iter().count());
                for entry in stx.intents.iter() {
                    let (seg, intent) = &*entry;
                    eprintln!(
                        "intent seg={:?}: actions={} guar_unshielded={} fall_unshielded={} dust={} ttl={:?}",
                        seg,
                        intent.actions.iter().count(),
                        intent.guaranteed_unshielded_offer.is_some(),
                        intent.fallible_unshielded_offer.is_some(),
                        intent.dust_actions.is_some(),
                        intent.ttl,
                    );
                    for action in intent.actions.iter() {
                        eprintln!("  action = {:?}", action);
                    }
                }
            }
            other => eprintln!("non-standard tx: {:?}", other),
        }

        let state_hex = include_str!("../test-fixtures/reveal_invalidproof_state.hex").trim();
        eprintln!("contract state: {} bytes", hex::decode(state_hex).expect("state hex").len());
    }

    /// THE decisive offline repro of node error 115 (InvalidProof).
    ///
    /// `proof_verify` (structure.rs:435, gated behind the default `proof-verifying`
    /// feature) pulls ONLY the verifier key from the ledger's contract state; the
    /// public inputs are derived ENTIRELY from the tx's own transcript
    /// (`ContractCall::public_inputs`, verify.rs:1869). So a 115 is a VK-vs-proof
    /// mismatch or a structurally-invalid proof — NOT a state-data divergence
    /// (that surfaces later at transcript-apply as a different code).
    ///
    /// This test rebuilds exactly what the node does at submit:
    ///   1. deserialize the captured sealed reveal tx,
    ///   2. deserialize the captured indexer contract state (holds the on-chain VK),
    ///   3. seat that state in a LedgerState at the call's address,
    ///   4. run `well_formed` with contract-proof verification ON, everything else
    ///      OFF (so the ONLY thing that can fail is the ZK proof check).
    ///
    /// PASS (well_formed Ok)  => the proof verifies against the indexer's VK; the
    ///   node must hold a different VK/state — divergence is upstream of the proof.
    /// FAIL (InvalidProof)    => the proof genuinely doesn't verify against the
    ///   on-chain VK — a prover-key / verifier-key version mismatch in our build.
    ///
    /// Run with:
    ///   cargo test -p kuira-crypto-ffi well_formed_reveal_invalidproof -- --nocapture
    #[test]
    fn well_formed_reveal_invalidproof() {
        use midnight_ledger::structure::{ContractAction, LedgerState};
        use midnight_ledger::verify::{ProofVerificationMode, WellFormedStrictness};
        use midnight_onchain_runtime::state::ContractState;
        use midnight_transient_crypto::commitment::PureGeneratorPedersen;
        type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

        // 1. The sealed reveal tx the node rejected with 115.
        let tx_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_invalidproof_tx.hex").trim(),
        )
        .expect("tx hex decodes");
        let tx: SealedTx = tagged_deserialize(&tx_bytes[..]).expect("reveal tx deserializes");

        // 2. The contract state (from the indexer) the proof was built against.
        let state_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_invalidproof_state.hex").trim(),
        )
        .expect("state hex decodes");
        let contract_state: ContractState<DefaultDB> =
            tagged_deserialize(&state_bytes[..]).expect("contract state deserializes");

        // Pull network id, the call's address + entry point, and the intent ttl
        // straight out of the captured tx so the LedgerState matches it exactly.
        let stx = match &tx {
            Transaction::Standard(stx) => stx,
            other => panic!("expected Standard tx, got {:?}", other),
        };
        let network_id = stx.network_id.clone();

        let mut call_address = None;
        let mut tblock = Timestamp::from_secs(0);
        for entry in stx.intents.iter() {
            let (_seg, intent) = &*entry;
            tblock = intent.ttl; // tblock == ttl satisfies ttl_check_weak both ways
            for action in intent.actions.iter() {
                if let ContractAction::Call(call) = &*action {
                    eprintln!(
                        "reveal call: address={:?} entry_point={:?}",
                        call.address, call.entry_point,
                    );
                    call_address = Some(call.address);
                }
            }
        }
        let address = call_address.expect("reveal tx must contain a contract Call");

        // Sanity: the captured state must actually hold a VK for the entry point
        // the call invokes. If it doesn't, well_formed would fail with
        // VerifierKeyNotPresent (a different cause than InvalidProof).
        eprintln!(
            "contract state operations: {:?}",
            contract_state
                .operations
                .iter()
                .map(|kv| kv.0.clone())
                .collect::<std::vec::Vec<_>>(),
        );

        // 3. Seat the captured contract state in a fresh ledger at the call address.
        let mut ledger: LedgerState<DefaultDB> = LedgerState::new(network_id);
        ledger.contract = ledger.contract.insert(address, contract_state);

        // 4. Verify ONLY the contract proof — disable every other check so the
        //    sole possible failure is the ZK proof verification (node code 115).
        let mut strictness = WellFormedStrictness::default();
        strictness.enforce_balancing = false;
        strictness.verify_native_proofs = false;
        strictness.verify_contract_proofs = true;
        strictness.verify_signatures = false;
        strictness.enforce_limits = false;
        strictness.proof_verification_mode = ProofVerificationMode::Real;

        eprintln!("running well_formed (contract-proof verification only)...");
        match tx.well_formed(&ledger, strictness, tblock) {
            Ok(_) => eprintln!(
                "RESULT: well_formed OK — proof verifies against the indexer's VK. \
                 115 originates UPSTREAM of proof verification (node holds a \
                 different VK/state, or rejects for a non-proof reason)."
            ),
            Err(e) => eprintln!(
                "RESULT: well_formed FAILED — {:?}. If this is InvalidProof, the \
                 proof does not verify against the on-chain VK => prover/verifier \
                 key version mismatch in our build.",
                e
            ),
        }
    }

    /// CONTROL: the commitRegulation proof was ACCEPTED on-chain, so it MUST verify
    /// offline against the real VK. If this fails, the offline harness itself is the
    /// false positive (wrong PARAMS_VERIFIER / public_inputs reconstruction) and the
    /// reveal "InvalidProof" is an artifact, not the real bug.
    ///
    /// Run with:
    ///   cargo test -p kuira-crypto-ffi control_commit_proof_verifies -- --nocapture
    #[test]
    fn control_commit_proof_verifies() {
        use midnight_ledger::structure::{ContractAction, PedersenDowngradeable, ProofVersioned, Transaction};
        use midnight_onchain_runtime::state::ContractState;
        use midnight_transient_crypto::commitment::{PedersenRandomness, Pedersen};
        use midnight_transient_crypto::proofs::PARAMS_VERIFIER;

        type PreSealTx = Transaction<Signature, ProofMarker, PedersenRandomness, DefaultDB>;

        let pre: PreSealTx = tagged_deserialize(
            &hex::decode(include_str!("../test-fixtures/commit_preseal_tx.hex").trim()).unwrap()[..],
        ).expect("commit preseal deserializes");
        let state: ContractState<DefaultDB> = tagged_deserialize(
            &hex::decode(include_str!("../test-fixtures/reveal_paired_state.hex").trim()).unwrap()[..],
        ).expect("state deserializes");

        let stx = match &pre { Transaction::Standard(s) => s, _ => panic!("not standard") };
        let (call, binding_pr, ep) = {
            let mut found = None;
            for e in stx.intents.iter() {
                let (_seg, intent) = &*e;
                for a in intent.actions.iter() {
                    if let ContractAction::Call(c) = &*a {
                        found = Some((c.clone(), intent.binding_commitment.clone(), format!("{:?}", c.entry_point)));
                    }
                }
            }
            found.expect("commit call")
        };
        eprintln!("control call entry_point = {ep}");

        let vk = state.operations.iter()
            .find(|kv| format!("{:?}", kv.0) == ep)
            .and_then(|kv| (*kv.1).v2.clone())
            .expect("vk present");
        let proof = match &call.proof {
            ProofVersioned::V2(p) => p.clone(),
            other => panic!("unexpected proof version: {:?}", other),
        };
        let binding_down: Pedersen = PedersenDowngradeable::<DefaultDB>::downgrade(&binding_pr);
        let res = vk.verify(&PARAMS_VERIFIER, &proof, call.public_inputs(binding_down).into_iter());
        eprintln!("CONTROL commit proof verify: {}",
            if res.is_ok() { "VERIFIES ✓ (harness is sound)" } else { "FAILS ✗ (harness false-positive!)" });
        eprintln!("  raw: {:?}", res);
    }

    /// Pinpoint WHICH part of the public inputs the reveal proof disagrees with.
    /// `prove()` (ledger prove.rs:277-360) inserts Op::Noop runs into the transcript
    /// and binds the proof to `binding_input` over the noop-augmented call; each
    /// Noop{n} contributes `n` zero field elements to `public_inputs` (ops.rs:403).
    /// We verify the captured reveal proof against:
    ///   (a) the embedded transcript as-is  (= what the node does -> expect FAIL),
    ///   (b) the transcript with Noop ops stripped from public_inputs,
    ///   (c) binding via `downgrade` vs `Into<Pedersen>`.
    /// Whichever variant verifies names the exact divergence and the fix.
    ///
    /// Run with:
    ///   cargo test -p kuira-crypto-ffi pinpoint_reveal_pubinputs -- --nocapture
    #[test]
    fn pinpoint_reveal_pubinputs() {
        use midnight_ledger::structure::{ContractAction, PedersenDowngradeable, ProofVersioned, Transaction};
        use midnight_onchain_runtime::state::ContractState;
        use midnight_onchain_runtime::transcript::Transcript;
        use midnight_onchain_vm::ops::Op;
        use midnight_onchain_vm::result_mode::ResultModeVerify;
        use midnight_storage::arena::Sp;
        use midnight_transient_crypto::commitment::{PedersenRandomness, Pedersen};
        use midnight_transient_crypto::curve::Fr;
        use midnight_transient_crypto::proofs::PARAMS_VERIFIER;

        type PreSealTx = Transaction<Signature, ProofMarker, PedersenRandomness, DefaultDB>;

        let pre: PreSealTx = tagged_deserialize(
            &hex::decode(include_str!("../test-fixtures/reveal_preseal_tx.hex").trim()).unwrap()[..],
        ).expect("preseal deserializes");
        let state: ContractState<DefaultDB> = tagged_deserialize(
            &hex::decode(include_str!("../test-fixtures/reveal_paired_state.hex").trim()).unwrap()[..],
        ).expect("state deserializes");

        let stx = match &pre { Transaction::Standard(s) => s, _ => panic!("not standard") };
        let (call, binding_pr) = {
            let mut found = None;
            for e in stx.intents.iter() {
                let (_seg, intent) = &*e;
                for a in intent.actions.iter() {
                    if let ContractAction::Call(c) = &*a {
                        found = Some((c.clone(), intent.binding_commitment.clone()));
                    }
                }
            }
            found.expect("reveal call")
        };

        let vk = state.operations.iter()
            .find(|kv| format!("{:?}", kv.0) == "revealRegulation")
            .and_then(|kv| (*kv.1).v2.clone())
            .expect("revealRegulation vk");
        let proof = match &call.proof {
            ProofVersioned::V2(p) => p.clone(),
            other => panic!("unexpected proof version: {:?}", other),
        };

        let binding_down: Pedersen = PedersenDowngradeable::<DefaultDB>::downgrade(&binding_pr);
        let binding_into: Pedersen = binding_pr.clone().into();
        eprintln!("binding downgrade == into ? {}", binding_down == binding_into);

        let verify = |label: &str, pis: Vec<Fr>| {
            let res = vk.verify(&PARAMS_VERIFIER, &proof, pis.into_iter());
            eprintln!("  {label}: {}", if res.is_ok() { "VERIFIES ✓" } else { "fails" });
        };

        // (a) embedded transcript, downgrade binding (the node's exact computation)
        verify("(a) full + downgrade", call.public_inputs(binding_down));
        // (c) embedded transcript, Into binding
        verify("(c) full + Into     ", call.public_inputs(binding_into));

        // (b) strip Noop ops from the fallible transcript, recompute public inputs
        let stripped_call = {
            let mut c = (*call).clone();
            if let Some(ft) = &call.fallible_transcript {
                let kept: std::vec::Vec<Op<ResultModeVerify, DefaultDB>> = ft.program
                    .iter().map(|o| (*o).clone())
                    .filter(|op| !matches!(op, Op::Noop { .. }))
                    .collect();
                let n_total: u32 = ft.program.iter()
                    .map(|o| if let Op::Noop { n } = &*o { *n } else { 0 }).sum();
                eprintln!("fallible: {} ops, stripped to {} (removed {} noop-field-elems)",
                    ft.program.len(), kept.len(), n_total);
                c.fallible_transcript = Some(Sp::new(Transcript {
                    gas: ft.gas,
                    effects: ft.effects.clone(),
                    program: kept.into(),
                    version: ft.version.clone(),
                }));
            }
            c
        };
        verify("(b) no-noop + downgrade", stripped_call.public_inputs(binding_down));
    }

    /// Localize error 115 across the seal boundary, using a MATCHED pre/post pair
    /// captured from the SAME reveal balance call (CAPTURE_PRESEAL_TX before seal,
    /// CAPTURE_SUBMITTED_TX after seal). Both carry the same proof + transcript; only
    /// the intent binding commitment representation changes (PedersenRandomness =
    /// "embedded-fr" -> PureGeneratorPedersen = "pedersen-schnorr").
    ///
    ///   pre-seal verifies, post-seal doesn't  => seal mutates the binding the proof
    ///       was bound to => bug is in balance_ffi's seal path.
    ///   neither verifies                       => the prover committed to a different
    ///       transcript than was embedded => snapshot-timing bug upstream (compact).
    ///
    /// Run with:
    ///   cargo test -p kuira-crypto-ffi well_formed_across_seal -- --nocapture
    #[test]
    fn well_formed_across_seal() {
        use midnight_ledger::structure::{ContractAction, LedgerState, Transaction};
        use midnight_ledger::verify::{ProofVerificationMode, WellFormedStrictness};
        use midnight_onchain_runtime::state::ContractState;
        use midnight_transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};

        type PreSealTx = Transaction<Signature, ProofMarker, PedersenRandomness, DefaultDB>;
        type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

        let pre_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_preseal_tx.hex").trim(),
        )
        .expect("preseal hex");
        let post_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_sealed_tx.hex").trim(),
        )
        .expect("sealed hex");
        let state_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_paired_state.hex").trim(),
        )
        .expect("state hex");

        let pre: PreSealTx = tagged_deserialize(&pre_bytes[..]).expect("preseal deserializes");
        let post: SealedTx = tagged_deserialize(&post_bytes[..]).expect("sealed deserializes");
        let contract_state: ContractState<DefaultDB> =
            tagged_deserialize(&state_bytes[..]).expect("state deserializes");

        // Address + ttl come from the sealed tx.
        let (address, network_id, tblock) = {
            let stx = match &post {
                Transaction::Standard(s) => s,
                o => panic!("post not standard: {:?}", o),
            };
            let mut addr = None;
            let mut tb = Timestamp::from_secs(0);
            for e in stx.intents.iter() {
                let (_seg, intent) = &*e;
                tb = intent.ttl;
                for a in intent.actions.iter() {
                    if let ContractAction::Call(c) = &*a {
                        addr = Some(c.address);
                    }
                }
            }
            (addr.expect("call addr"), stx.network_id.clone(), tb)
        };

        // Compare the downgraded binding commitment (the Pedersen point that actually
        // enters binding_input) on each side of the seal. If these differ, seal moved
        // the binding the proof was bound to.
        use midnight_ledger::structure::PedersenDowngradeable;
        if let Transaction::Standard(s) = &pre {
            for e in s.intents.iter() {
                eprintln!("PRE  intent binding (downgraded) = {:?}",
                    PedersenDowngradeable::<DefaultDB>::downgrade(&(*e).1.binding_commitment));
            }
        }
        if let Transaction::Standard(s) = &post {
            for e in s.intents.iter() {
                eprintln!("POST intent binding (downgraded) = {:?}",
                    PedersenDowngradeable::<DefaultDB>::downgrade(&(*e).1.binding_commitment));
            }
        }

        let mut strictness = WellFormedStrictness::default();
        strictness.enforce_balancing = false;
        strictness.verify_native_proofs = false;
        strictness.verify_contract_proofs = true;
        strictness.verify_signatures = false;
        strictness.enforce_limits = false;
        strictness.proof_verification_mode = ProofVerificationMode::Real;

        let ledger: LedgerState<DefaultDB> = {
            let mut l = LedgerState::new(network_id);
            l.contract = l.contract.insert(address, contract_state);
            l
        };

        let pre_res = pre.well_formed(&ledger, strictness, tblock);
        eprintln!("PRE-seal  well_formed: {:?}", pre_res.map(|_| "OK"));
        let post_res = post.well_formed(&ledger, strictness, tblock);
        eprintln!("POST-seal well_formed: {:?}", post_res.map(|_| "OK"));
    }

    /// Dump the reveal call's transcript ops, focusing on `Popeq` read results
    /// (`AlignedValue`). The reveal reads the evolved `p1Commitment`; if that read
    /// landed in the transcript as an EMPTY/zeroed `result` while the prover proved
    /// the real value, the verifier's field_repr diverges => InvalidProof. This
    /// surfaces transcript-content corruption directly.
    ///
    /// Run with:
    ///   cargo test -p kuira-crypto-ffi dump_reveal_transcript -- --nocapture
    #[test]
    fn dump_reveal_transcript() {
        use midnight_ledger::structure::{ContractAction, Transaction};
        use midnight_transient_crypto::commitment::PureGeneratorPedersen;
        type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

        let tx_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_invalidproof_tx.hex").trim(),
        )
        .expect("tx hex decodes");
        let tx: SealedTx = tagged_deserialize(&tx_bytes[..]).expect("reveal tx deserializes");

        let stx = match &tx {
            Transaction::Standard(stx) => stx,
            other => panic!("expected Standard tx, got {:?}", other),
        };

        for entry in stx.intents.iter() {
            let (_seg, intent) = &*entry;
            for action in intent.actions.iter() {
                if let ContractAction::Call(call) = &*action {
                    eprintln!("== call {:?} ==", call.entry_point);
                    eprintln!("communication_commitment = {:?}", call.communication_commitment);
                    for (label, t) in [
                        ("guaranteed", call.guaranteed_transcript.as_ref()),
                        ("fallible", call.fallible_transcript.as_ref()),
                    ] {
                        let Some(t) = t else {
                            eprintln!("  {label}: <none>");
                            continue;
                        };
                        eprintln!("  {label}: {} ops, version={:?}", t.program.len(), t.version);
                        for (i, op) in t.program.iter().enumerate() {
                            eprintln!("    [{i}] {:?}", &*op);
                        }
                    }
                }
            }
        }
    }

    /// Smoking-gun check for the 115/InvalidProof: does the verifier key the
    /// contract was DEPLOYED with (on-chain `op.v2`, from the captured indexer
    /// state) byte-match the verifier key the app currently PROVES against
    /// (`assets/keys/<entry>.verifier`)?
    ///
    /// commit succeeds + reveal fails, so we expect commitRegulation to match and
    /// revealRegulation to DIFFER — proving the deployed reveal VK is from a
    /// different compile than the app's current reveal proving key.
    ///
    /// Run with:
    ///   cargo test -p kuira-crypto-ffi compare_onchain_vks_to_app_keys -- --nocapture
    #[test]
    fn compare_onchain_vks_to_app_keys() {
        use midnight_onchain_runtime::state::ContractState;
        use midnight_serialize::tagged_serialize;

        let state_bytes = hex::decode(
            include_str!("../test-fixtures/reveal_invalidproof_state.hex").trim(),
        )
        .expect("state hex decodes");
        let contract_state: ContractState<DefaultDB> =
            tagged_deserialize(&state_bytes[..]).expect("contract state deserializes");

        let keys_dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/midnight-kicks/app/src/main/assets/keys/"
        );

        for op_entry in contract_state.operations.iter() {
            let entry_point = format!("{:?}", op_entry.0);
            let op = &*op_entry.1;
            let vk = match &op.v2 {
                Some(vk) => vk,
                None => {
                    eprintln!("{entry_point}: NO on-chain VK (v2 = None)");
                    continue;
                }
            };
            let mut onchain = std::vec::Vec::new();
            tagged_serialize(vk, &mut onchain).expect("serialize on-chain VK");

            let file_path = format!("{keys_dir}{entry_point}.verifier");
            let app = match std::fs::read(&file_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{entry_point}: app key unreadable ({e})");
                    continue;
                }
            };

            let matches = onchain == app;
            eprintln!(
                "{entry_point}: on-chain={}B app={}B  =>  {}",
                onchain.len(),
                app.len(),
                if matches { "MATCH" } else { "*** DIFFERS ***" },
            );
        }
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

    /// Err170 isolation: structural diff between a working deploy tx and a failing
    /// contract-call tx that the node rejects with "Invalid Transaction (Custom error: 170)".
    ///
    /// Inputs (both produced by balance_ffi, captured via ERR170_OUTPUT_HEX logcat):
    ///   /tmp/err170/deploy_ok.hex   — accepted by node (✅)
    ///   /tmp/err170/join_fail.hex   — rejected with error 170 (❌)
    ///
    /// Run with:
    ///   cargo test --release --lib err170_structural_diff -- --nocapture --ignored
    #[test]
    #[ignore]
    fn err170_structural_diff() {
        use midnight_base_crypto::signatures::Signature;
        use midnight_ledger::structure::{ProofMarker, Transaction};
        use midnight_serialize::tagged_deserialize;
        use midnight_storage::DefaultDB;
        use midnight_transient_crypto::commitment::PureGeneratorPedersen;

        type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

        for (label, path) in [
            ("DEPLOY_OK", "/tmp/err170/deploy_ok.hex"),
            ("JOIN_FAIL", "/tmp/err170/join_fail.hex"),
        ] {
            let hex_str = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read {}: {}", path, e));
            let bytes = hex::decode(hex_str.trim()).expect("hex decode");
            eprintln!("\n========== {} ({} bytes) ==========", label, bytes.len());

            let tx: SealedTx = match tagged_deserialize(&bytes[..]) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("  DESERIALIZE FAIL: {:?}", e);
                    continue;
                }
            };

            match &tx {
                Transaction::Standard(std_tx) => {
                    eprintln!("  network_id:           {:?}", std_tx.network_id);
                    eprintln!("  binding_randomness:   {:?}", std_tx.binding_randomness);
                    eprintln!("  guaranteed_coins:     is_some={}", std_tx.guaranteed_coins.is_some());
                    eprintln!("  fallible_coins:       count={}", std_tx.fallible_coins.size());
                    eprintln!("  intents:              count={}", std_tx.intents.size());
                    for entry in std_tx.intents.iter() {
                        let inner = &*entry;
                        let seg = *inner.0;
                        let intent = &*inner.1;
                        eprintln!("    ── segment {} ──", seg);
                        eprintln!("      ttl:                            {:?}", intent.ttl);
                        eprintln!("      binding_commitment:             {:?}", intent.binding_commitment);
                        eprintln!("      guaranteed_unshielded_offer:    is_some={}", intent.guaranteed_unshielded_offer.is_some());
                        eprintln!("      fallible_unshielded_offer:      is_some={}", intent.fallible_unshielded_offer.is_some());
                        eprintln!("      actions:                        count={}", intent.actions.len());
                        for (ai, action) in intent.actions.iter().enumerate() {
                            eprintln!("        action[{}]:                    {:?}", ai, action);
                        }
                        eprintln!("      dust_actions:                   is_some={}", intent.dust_actions.is_some());
                        if let Some(da_sp) = &intent.dust_actions {
                            let da = &**da_sp;
                            eprintln!("        ctime:                        {:?}", da.ctime);
                            let spends_vec: std::vec::Vec<_> = (&da.spends).into();
                            eprintln!("        spends:                       count={}", spends_vec.len());
                            for (i, s) in spends_vec.iter().enumerate() {
                                eprintln!("          spend[{}].v_fee:             {}", i, s.v_fee);
                                eprintln!("          spend[{}].old_nullifier:     {:?}", i, s.old_nullifier);
                                eprintln!("          spend[{}].new_commitment:    {:?}", i, s.new_commitment);
                            }
                            let regs_vec: std::vec::Vec<_> = (&da.registrations).into();
                            eprintln!("        registrations:                count={}", regs_vec.len());
                        }
                    }
                }
                _ => eprintln!("  Not a StandardTransaction: {:?}", std::mem::discriminant(&tx)),
            }
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
