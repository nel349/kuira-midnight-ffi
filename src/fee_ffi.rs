// This file is part of Kuira Wallet.
// Copyright (C) 2025 Kuira Wallet
// SPDX-License-Identifier: Apache-2.0

//! Fee calculation FFI for Midnight transactions.
//!
//! Wraps midnight-ledger's fee calculation with additional safety overhead.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use midnight_ledger::structure::{Transaction, LedgerParameters, ProofPreimageMarker};
use midnight_serialize::Deserializable;
use midnight_storage::DefaultDB;
use midnight_base_crypto::signatures::Signature;
use midnight_transient_crypto::commitment::PureGeneratorPedersen;

// Android logging macros (same as serialize.rs)
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

// Type alias for a sealed transaction (matches serialize.rs output)
type SealedTransaction = Transaction<Signature, ProofPreimageMarker, PureGeneratorPedersen, DefaultDB>;

/// Additional safety overhead percentage (1% of base fee).
///
/// The `feesWithMargin()` already includes margin for block-based price fluctuations,
/// but we add 1% extra as a conservative safety buffer.
const FEE_OVERHEAD_PERCENT: u128 = 1;

/// Default fee blocks margin (matches TypeScript SDK).
///
/// This is the `n` parameter in `feesWithMargin()` that accounts for
/// blockchain price fluctuations between transaction creation and confirmation.
const DEFAULT_FEE_BLOCKS_MARGIN: usize = 5;

/// Strip the tag prefix from tagged SCALE serialization.
///
/// Tagged format: "midnight:<type>[<version>](<params>):<scale-data>"
///
/// If the bytes start with ASCII "midnight:", finds the tag-data separator ':'
/// and returns everything after it. Otherwise returns the bytes unchanged.
fn strip_tag_prefix(bytes: Vec<u8>) -> Vec<u8> {
    // Check if bytes start with "midnight:" (ASCII tag)
    if bytes.len() < 9 {
        return bytes;
    }

    // Check for "midnight:" prefix
    if &bytes[0..9] == b"midnight:" {
        // Find the colon that separates tag from SCALE data
        // The tag format is: midnight:<type>[<version>](<params>): OR midnight:<type>[<version>]:
        //
        // Examples:
        //   - "midnight:transaction[v6](signature[v1],proof-preimage,embedded-fr[v1]):"
        //   - "midnight:ledger-parameters[v4]:"
        //
        // Strategy: Look for either '):' or ']:' patterns

        // Start searching after the "midnight:" prefix
        for i in 9..bytes.len()-1 {
            // Look for '):' pattern (tags with parameters)
            if bytes[i] == b')' && bytes[i + 1] == b':' {
                log_info!("[Fee FFI] Tag found with params, stripping {} bytes.", i + 2);
                return bytes[i + 2..].to_vec();
            }
            // Look for ']:' pattern (tags without parameters)
            if bytes[i] == b']' && bytes[i + 1] == b':' {
                log_info!("[Fee FFI] Tag found without params, stripping {} bytes.", i + 2);
                return bytes[i + 2..].to_vec();
            }
        }

        // If we couldn't find either pattern, assume no tag
        log_error!("[Fee FFI] Found midnight prefix but no valid tag separator ");
        return bytes;
    }

    // No tag found, return as-is
    bytes
}

/// Calculates transaction fee using midnight-ledger's fee calculation.
///
/// # Safety
///
/// - `tx_hex` must be a valid null-terminated UTF-8 string
/// - `params_hex` must be a valid null-terminated UTF-8 string
/// - Caller must call `free_c_string()` on the returned string
///
/// # Parameters
///
/// - `tx_hex`: Hex-encoded SCALE-serialized transaction
/// - `params_hex`: Hex-encoded SCALE-serialized ledger parameters
/// - `fee_blocks_margin`: Safety margin in blocks (typically 5)
///
/// # Returns
///
/// Fee in Specks as decimal string (e.g., "1000000000000"), or null on error.
///
/// # Fee Calculation
///
/// ```text
/// 1. Deserialize transaction from hex
/// 2. Deserialize ledger params from hex
/// 3. base_fee = transaction.fees_with_margin(params, margin)
/// 4. total_fee = base_fee + (base_fee * 1%)  // 1% safety overhead
/// 5. Return as string
/// ```
#[no_mangle]
pub extern "C" fn calculate_transaction_fee(
    tx_hex: *const c_char,
    params_hex: *const c_char,
    fee_blocks_margin: u32,
) -> *mut c_char {
    // Validate inputs
    if tx_hex.is_null() {
        return ptr::null_mut();
    }

    if params_hex.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // Convert C strings to Rust
        let tx_hex_str = match CStr::from_ptr(tx_hex).to_str() {
            Ok(s) => s,
            Err(e) => {
                log_error!("[Fee FFI] Invalid UTF-8 in tx_hex: {}", e);
                return ptr::null_mut();
            }
        };

        let params_hex_str = match CStr::from_ptr(params_hex).to_str() {
            Ok(s) => s,
            Err(e) => {
                log_error!("[Fee FFI] Invalid UTF-8 in params_hex: {}", e);
                return ptr::null_mut();
            }
        };

        // Decode hex to bytes
        let mut tx_bytes = match hex::decode(tx_hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                log_error!("[Fee FFI] Error decoding transaction hex: {}", e);
                return ptr::null_mut();
            }
        };

        let mut params_bytes = match hex::decode(params_hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                log_error!("[Fee FFI] Error decoding params hex: {}", e);
                return ptr::null_mut();
            }
        };

        // CRITICAL: Strip tag prefix from transaction if present
        // Tagged format: "midnight:transaction[v6](...):<scale-data>"
        // We need to find the last ':' and take everything after it
        tx_bytes = strip_tag_prefix(tx_bytes);

        // CRITICAL: Strip tag prefix from ledger params if present
        // Tagged format: "midnight:ledger-parameters[v4]:<scale-data>"
        params_bytes = strip_tag_prefix(params_bytes);

        log_info!("[Fee FFI] After stripping tags.");
        log_info!("[Fee FFI]   tx_bytes: {} bytes, prefix: {:02x?}", tx_bytes.len(), &tx_bytes[..tx_bytes.len().min(16)]);
        log_info!("[Fee FFI]   params_bytes: {} bytes, prefix: {:02x?}", params_bytes.len(), &params_bytes[..params_bytes.len().min(16)]);

        // Deserialize transaction using SCALE codec
        let transaction: SealedTransaction = match Deserializable::deserialize(&mut &tx_bytes[..], 0) {
            Ok(tx) => tx,
            Err(e) => {
                log_error!("[Fee FFI] Error deserializing transaction: {}", e);
                log_error!("[Fee FFI]   tx_bytes length: {}", tx_bytes.len());
                log_error!("[Fee FFI]   tx_bytes hex: {}", hex::encode(&tx_bytes));
                return ptr::null_mut();
            }
        };

        // Deserialize ledger parameters using SCALE codec
        let params: LedgerParameters = match Deserializable::deserialize(&mut &params_bytes[..], 0) {
            Ok(p) => p,
            Err(e) => {
                log_error!("[Fee FFI] Error deserializing ledger parameters: {}", e);
                log_error!("[Fee FFI]   params_bytes length: {}", params_bytes.len());
                log_error!("[Fee FFI]   params_bytes hex: {}", hex::encode(&params_bytes));
                return ptr::null_mut();
            }
        };

        // Calculate fee with margin
        let base_fee = match transaction.fees_with_margin(&params, fee_blocks_margin as usize) {
            Ok(fee) => fee,
            Err(e) => {
                log_error!("[Fee FFI] Fee calculation failed with {:?}", e);
                return ptr::null_mut();
            }
        };

        // Add 1% safety overhead
        let overhead = base_fee * FEE_OVERHEAD_PERCENT / 100;
        let total_fee: u128 = base_fee + overhead;

        // Convert to decimal string
        let fee_string = total_fee.to_string();

        // Return as C string
        match CString::new(fee_string) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => ptr::null_mut()
        }
    }
}

// Note: free_c_string() is defined in dust_ffi.rs and used by all modules
