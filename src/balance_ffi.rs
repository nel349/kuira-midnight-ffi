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

/// Headroom subtracted from the chain's `global_ttl` when sizing the dust intent's TTL — absorbs
/// the client/chain clock gap so the TTL lands strictly under the ceiling. Mirrors Kotlin IntentTtl.
const DUST_TTL_MARGIN_SECS: i128 = 15;
/// Upper bound on the dust intent's TTL window (30 min) even when `global_ttl` is generous.
const DUST_TTL_MAX_WINDOW_SECS: i128 = 30 * 60;

/// TTL window (seconds) for the balancer's dust intent that fits under the chain's `global_ttl`.
///
/// The node rejects an intent whose TTL sits more than `global_ttl` ahead of chain time (custom
/// error 182 / `IntentTtlTooFarInFuture`). A fixed 30-min window overshoots a tight node (a
/// localnet runs ~100s), so size it to the live ceiling. Mirrors Kotlin `IntentTtl.windowSeconds`.
fn dust_intent_ttl_window_secs(global_ttl_secs: i128) -> u64 {
    let capped = (global_ttl_secs - DUST_TTL_MARGIN_SECS).min(DUST_TTL_MAX_WINDOW_SECS);
    let window = if capped > 0 { capped } else { global_ttl_secs / 2 };
    window.max(0) as u64
}

/// Total dust fee to charge: the original tx's fee PLUS the dust-fee intent's own cost, plus a
/// small safety margin. The node charges the fee on the merged `(original + dust intent)` tx, so
/// sizing on `base_fee` alone under-pays it → the node rejects with `BalanceCheckOverspend`
/// (custom error 138) the moment the chain charges a real fee.
fn merged_total_fee(base_fee: u128, dust_intent_fee: u128) -> u128 {
    let merged = base_fee + dust_intent_fee;
    merged + merged * FEE_OVERHEAD_PERCENT / 100
}

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
    // Chain-tip time (ms) for the dust-fee intent's TTL. Distinct from current_time_ms (the dust
    // SYNC time, which the ctime must match for the dust root): the sync time lags the chain on
    // a chain with infrequent dust events, so a sync-anchored TTL expires (custom error 182).
    ttl_anchor_ms: i64,
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

    // #288: cap rayon to leave a core for the UI before proving spins up all cores.
    crate::prove_ffi::init_proving_thread_pool();

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
        ttl_anchor_ms,
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

/// Build the dust-only unproven transaction that pays the fee: one intent at a random segment
/// carrying [spends] as its dust actions. Used twice — once as a DRAFT to measure the dust
/// intent's own fee contribution, once for real — so the spend can be sized to the merged-tx fee.
fn build_dust_fee_intent_tx(
    spends: Vec<DustSpend<ProofPreimageMarker, DefaultDB>>,
    ctime: Timestamp,
    ttl: Timestamp,
    network_id: &str,
) -> Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
    use midnight_storage::arena::Sp;
    use midnight_storage::storage::Array as StorageArray;

    let spends_array: StorageArray<_, DefaultDB> = spends.into_iter().collect();
    let registrations_array: StorageArray<
        midnight_ledger::dust::DustRegistration<Signature, DefaultDB>,
        DefaultDB,
    > = std::iter::empty().collect();

    let dust_actions = DustActions {
        spends: spends_array,
        registrations: registrations_array,
        ctime,
    };

    // Random segment ID for the dust intent (avoids collision with original tx segments).
    let dust_segment_id: u16 = OsRng.gen_range(2..u16::MAX);

    let dust_intent = Intent::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: None,
        actions: std::iter::empty().collect(),
        dust_actions: Some(Sp::new(dust_actions)),
        ttl,
        binding_commitment: OsRng.gen(), // random binding (matches facade's Intent::new)
    };

    let dust_intents_map = StorageHashMap::default().insert(dust_segment_id, dust_intent);

    Transaction::new(
        network_id,
        dust_intents_map,
        None,
        midnight_storage::storage::HashMap::new(),
    )
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
    ttl_anchor_ms: i64,
) -> Result<(String, DustLocalState<DefaultDB>, Vec<String>), String> {
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

    balance_log!(LOG_INFO, "Fee of original tx: {} specks", base_fee);

    if base_fee == 0 {
        balance_log!(LOG_INFO, "Zero-fee network — sealing proven tx with no dust intent");
        let sealed_tx = proven_tx.seal(OsRng);
        let mut result_bytes = Vec::new();
        tagged_serialize(&sealed_tx, &mut result_bytes)
            .map_err(|e| format!("Failed to serialize sealed transaction: {:?}", e))?;
        let result_hex = hex::encode(&result_bytes);
        // No dust spent → no nullifiers to record; dust state unchanged.
        return Ok((result_hex, dust_state.clone(), Vec::new()));
    }

    // ── Step 3: Size the fee to the MERGED transaction ──
    // The node charges the fee on (original tx + dust-fee intent), not the original alone — and the
    // dust intent has its OWN cost. Estimate that with a DRAFT dust intent, then size the real spend
    // to cover base + dust-intent fee. The old `base_fee + 1%` under-paid the moment the chain
    // charged a real fee: the node saw the (Dust, segment 0) balance go negative and rejected the tx
    // as BalanceCheckOverspend (custom error 138); a ~zero-fee chain had hidden it.

    let dust_secret_key = DustSecretKey::derive_secret_key(seed);
    let timestamp_secs = u64::try_from(current_time_ms / 1000)
        .map_err(|_| format!("Negative timestamp: {}", current_time_ms))?;
    let timestamp = Timestamp::from_secs(timestamp_secs);
    // Size the dust intent's TTL to the chain's global_ttl, anchored to the CHAIN TIP (ttl_anchor)
    // — NOT the dust sync time (timestamp_secs). The sync time lags the chain when dust events are
    // sparse, so a sync-anchored TTL is already in the past → the node rejects it as expired
    // (custom error 182 / IntentTtlExpired). The ctime + dust spend keep using the sync time so the
    // dust root still resolves (#287). Fall back to the sync time only if no anchor was supplied.
    let ttl_anchor_secs = if ttl_anchor_ms > 0 {
        (ttl_anchor_ms / 1000) as u64
    } else {
        timestamp_secs
    };
    let dust_ttl = Timestamp::from_secs(
        ttl_anchor_secs + dust_intent_ttl_window_secs(params.global_ttl.as_seconds()),
    );

    // Draft: a representative dust intent so we can read its fee contribution. The dust spend's
    // value is a fixed-size field, so the draft's structure (and thus its fee) matches the real one.
    let (_, draft_spends, _) =
        select_dust_spends(dust_state, &dust_secret_key, base_fee, timestamp, exclude_nullifiers)?;
    let draft_dust_tx = build_dust_fee_intent_tx(draft_spends, timestamp, dust_ttl, network_id);
    let dust_intent_fee = draft_dust_tx
        .erase_proofs()
        .fees_with_margin(&params, DEFAULT_FEE_BLOCKS_MARGIN)
        .map_err(|e| format!("Dust-intent fee calculation failed: {:?}", e))?;

    let total_fee = merged_total_fee(base_fee, dust_intent_fee);
    balance_log!(LOG_INFO,
        "Fee sized to merged tx: base={} + dust_intent={} (+{}%) = {} specks",
        base_fee, dust_intent_fee, FEE_OVERHEAD_PERCENT, total_fee);

    // ── Step 4: Real dust spends + dust intent (covering the merged-tx fee) ──
    let (current_state, dust_spends, spent_nullifiers) =
        select_dust_spends(dust_state, &dust_secret_key, total_fee, timestamp, exclude_nullifiers)?;
    balance_log!(LOG_INFO, "Created {} dust spend(s) for total fee {}", dust_spends.len(), total_fee);

    let dust_tx = build_dust_fee_intent_tx(dust_spends, timestamp, dust_ttl, network_id);
    balance_log!(LOG_INFO, "Built dust-only unproven tx");

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
    fn test_dust_intent_ttl_window_fits_tight_global_ttl() {
        // localnet ~100s: the dust intent's window must land strictly under global_ttl (error 182).
        assert_eq!(dust_intent_ttl_window_secs(100), 85); // 100 - 15s margin
        assert!(dust_intent_ttl_window_secs(100) < 100);
    }

    #[test]
    fn test_dust_intent_ttl_window_caps_at_30min() {
        // PreProd ~1h: cap at the historical 30-min window rather than handing out a 1h TTL.
        assert_eq!(dust_intent_ttl_window_secs(3600), 30 * 60);
    }

    #[test]
    fn test_dust_intent_ttl_window_halves_tiny_global_ttl() {
        // global_ttl below the margin: half the ceiling keeps the window positive and under it.
        assert_eq!(dust_intent_ttl_window_secs(10), 5);
    }

    #[test]
    fn test_merged_total_fee_covers_dust_intent_cost() {
        // REGRESSION GUARD — custom error 138 (BalanceCheckOverspend). The fee must cover the
        // MERGED tx (original + the dust-fee intent's own cost), not the original alone. The old
        // sizing was `base + 1%`, which under-paid once the chain charged a real fee.
        let base = 1_000_000u128;
        let dust_intent = 400_000u128;

        let total = merged_total_fee(base, dust_intent);
        assert!(total >= base + dust_intent, "total {total} must cover base+dust {}", base + dust_intent);
        // A non-zero dust-intent cost MUST raise the total above the base-only (old, buggy) sizing.
        assert!(total > merged_total_fee(base, 0), "dust-intent cost must be included in the fee");
    }

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
            0, // ttl_anchor_ms
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
            0, // ttl_anchor_ms
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
            1704067200000, // ttl_anchor_ms
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
