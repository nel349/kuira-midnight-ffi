//! Local ZK Proving FFI — Phase 4C
//!
//! Proves transactions locally on the phone instead of sending to a remote proof server.
//! Uses the same Rust proving engine (`midnight-zkir`) that the proof server uses.
//!
//! Architecture: same FFI pattern as zswap_ffi.rs (ADR-001).
//! See docs/planning/LOCAL_PROVING_PLAN.md for design rationale.

use std::ffi::CString;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;
use std::io;
use std::collections::HashMap;

use midnight_serialize::{tagged_serialize, tagged_deserialize};
use midnight_transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ProvingKeyMaterial, Resolver,
};
use rand::rngs::OsRng;

// Re-use helpers from zswap_ffi
use crate::zswap_ffi::{c_str_to_rust, c_hex_to_bytes, string_to_c_ptr};

// Android logging (same pattern as zswap_ffi.rs)
#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

#[cfg(target_os = "android")]
macro_rules! prove_log {
    ($level:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        let c_tag = std::ffi::CString::new("KuiraLocalProver").unwrap();
        let c_msg = std::ffi::CString::new(msg).unwrap();
        unsafe {
            __android_log_write($level, c_tag.as_ptr(), c_msg.as_ptr());
        }
    }};
}

#[cfg(not(target_os = "android"))]
macro_rules! prove_log {
    ($level:expr, $($arg:tt)*) => {{
        eprintln!("[KuiraLocalProver] {}", format!($($arg)*));
    }};
}

const LOG_INFO: std::os::raw::c_int = 4;
const LOG_ERROR: std::os::raw::c_int = 6;

// ── Local File Resolver ──

/// Resolves proving keys from local filesystem + transaction-specific HashMap.
/// Matches the proof server's Resolver::new() pattern.
pub struct LocalFileResolver {
    keys_dir: PathBuf,
    tx_keys: HashMap<String, ProvingKeyMaterial>,
}

impl LocalFileResolver {
    pub fn new(keys_dir: PathBuf, tx_keys: HashMap<String, ProvingKeyMaterial>) -> Self {
        Self { keys_dir, tx_keys }
    }

    fn read_file(&self, path: &std::path::Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

impl Resolver for LocalFileResolver {
    async fn resolve_key(&self, key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        let key_name = key.0.as_ref();

        // 1. Check transaction-specific keys first (for contract circuits)
        if let Some(km) = self.tx_keys.get(key_name) {
            prove_log!(LOG_INFO, "Resolved key '{}' from transaction HashMap", key_name);
            return Ok(Some(km.clone()));
        }

        // 2. Map key location to file paths
        // "midnight/zswap/spend" → keys_dir/zswap/spend.{prover,verifier,bzkir}
        // "midnight/dust/spend"  → keys_dir/dust/spend.{prover,verifier,bzkir}
        let rel_path = key_name.strip_prefix("midnight/").unwrap_or(key_name);
        let base = self.keys_dir.join(rel_path);

        let prover_path = base.with_extension("prover");
        let verifier_path = base.with_extension("verifier");
        let ir_path = base.with_extension("bzkir");

        if !prover_path.exists() || !verifier_path.exists() || !ir_path.exists() {
            prove_log!(LOG_ERROR, "Key files missing for '{}': prover={}, verifier={}, ir={}",
                key_name, prover_path.exists(), verifier_path.exists(), ir_path.exists());
            return Ok(None);
        }

        prove_log!(LOG_INFO, "Loading key '{}' from {:?}", key_name, base);

        let prover_key = self.read_file(&prover_path)?;
        let verifier_key = self.read_file(&verifier_path)?;
        let ir_source = self.read_file(&ir_path)?;

        prove_log!(
            LOG_INFO,
            "Loaded key '{}': prover={}B, verifier={}B, ir={}B",
            key_name, prover_key.len(), verifier_key.len(), ir_source.len()
        );

        Ok(Some(ProvingKeyMaterial {
            prover_key,
            verifier_key,
            ir_source,
        }))
    }
}

impl ParamsProverProvider for LocalFileResolver {
    async fn get_params(&self, k: u8) -> io::Result<ParamsProver> {
        let filename = format!("bls_midnight_2p{}", k);
        let path = self.keys_dir.join(&filename);

        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("BLS params file not found: {:?}", path),
            ));
        }

        prove_log!(LOG_INFO, "Loading BLS params k={} from {:?}", k, path);
        let bytes = self.read_file(&path)?;
        prove_log!(LOG_INFO, "Loaded BLS params k={}: {}B", k, bytes.len());

        ParamsProver::read(&bytes[..])
    }
}

// ── FFI Functions ──

/// Proves all ZK preimages in a Transaction locally.
///
/// Mirrors the proof server's /prove-tx endpoint:
/// 1. Deserializes the (Transaction, HashMap) tuple
/// 2. Creates a LocalProvingProvider with keys from the given directory
/// 3. Calls tx.prove(provider, cost_model) — iterates all preimages
/// 4. Serializes the proven Transaction
///
/// # Parameters
/// - `unproven_tx_hex`: Tagged-serialized (Transaction, HashMap) tuple
/// - `keys_dir`: Path to directory containing cached proving keys
///
/// # Returns
/// Tagged-serialized proven Transaction (hex), or null on error.
/// Caller must free with `free_proven_string`.
///
/// # Safety
/// All pointers must be valid, null-terminated C strings.
#[no_mangle]
pub extern "C" fn zkir_prove_transaction_local(
    unproven_tx_hex: *const c_char,
    keys_dir: *const c_char,
) -> *const c_char {
    if unproven_tx_hex.is_null() || keys_dir.is_null() {
        prove_log!(LOG_ERROR, "Null pointer in zkir_prove_transaction_local");
        return ptr::null();
    }

    // SAFETY: Pointers validated non-null above. JNI-provided C strings.
    unsafe {
        let keys_path = match c_str_to_rust(keys_dir, "keys_dir") {
            Some(s) => PathBuf::from(s),
            None => return ptr::null(),
        };

        let tx_bytes = match c_hex_to_bytes(unproven_tx_hex, "unproven_tx") {
            Some(b) => b,
            None => return ptr::null(),
        };

        prove_log!(LOG_INFO, "Proving transaction locally: {} bytes, keys_dir={:?}", tx_bytes.len(), keys_path);

        // Deserialize (Transaction, HashMap<String, ProvingKeyMaterial>) tuple
        // Same format as proof server input
        use midnight_ledger::structure::{Transaction, ProofPreimageMarker};
        use midnight_base_crypto::signatures::Signature;
        use midnight_transient_crypto::commitment::PedersenRandomness;
        use midnight_storage::db::InMemoryDB;

        type UnprovenTx = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;
        type TxPayload = (UnprovenTx, HashMap<String, ProvingKeyMaterial>);

        let (tx, tx_keys): TxPayload = match tagged_deserialize(&mut &tx_bytes[..]) {
            Ok(payload) => payload,
            Err(e) => {
                prove_log!(LOG_ERROR, "Failed to deserialize transaction tuple: {}", e);
                return ptr::null();
            }
        };

        prove_log!(LOG_INFO, "Deserialized transaction, {} tx-specific keys", tx_keys.len());

        // Create local resolver
        let resolver = LocalFileResolver::new(keys_path, tx_keys);

        // Create local proving provider
        let provider = midnight_zkir::LocalProvingProvider {
            rng: OsRng,
            params: &resolver,
            resolver: &resolver,
        };

        // Create a tokio runtime for async proving (same pattern as proof server)
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                prove_log!(LOG_ERROR, "Failed to create tokio runtime: {}", e);
                return ptr::null();
            }
        };

        // Prove the transaction
        prove_log!(LOG_INFO, "Starting local proof generation...");
        let start = std::time::Instant::now();

        let proven_tx = match rt.block_on(async {
            // Use the initial cost model — same as proof server's /prove-tx endpoint.
            // The proof server uses INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model.
            // TODO: Accept cost_model as parameter for production use (from ledger params).
            let cost_model = &midnight_ledger::structure::INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model;
            tx.prove(provider, cost_model).await
        }) {
            Ok(proven) => proven,
            Err(e) => {
                prove_log!(LOG_ERROR, "Local proving failed: {}", e);
                return ptr::null();
            }
        };

        let elapsed = start.elapsed();
        prove_log!(LOG_INFO, "Local proving complete in {:.2}s", elapsed.as_secs_f64());

        // Serialize proven transaction (same format as proof server output)
        let mut result_bytes = Vec::new();
        if let Err(e) = tagged_serialize(&proven_tx, &mut result_bytes) {
            prove_log!(LOG_ERROR, "Failed to serialize proven transaction: {}", e);
            return ptr::null();
        }

        prove_log!(
            LOG_INFO,
            "Proven transaction: {} bytes (input was {} bytes)",
            result_bytes.len(), tx_bytes.len()
        );

        string_to_c_ptr(hex::encode(&result_bytes))
    }
}

/// Frees a string returned by prove FFI functions.
#[no_mangle]
pub extern "C" fn free_proven_string(ptr: *mut c_char) {
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
    fn test_null_safety() {
        assert!(zkir_prove_transaction_local(ptr::null(), ptr::null()).is_null());
    }

    #[test]
    fn test_invalid_hex() {
        let bad_hex = CString::new("not_hex").unwrap();
        let keys_dir = CString::new("/tmp/nonexistent").unwrap();
        assert!(zkir_prove_transaction_local(bad_hex.as_ptr(), keys_dir.as_ptr()).is_null());
    }
}
