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

// Type alias for a sealed transaction (matches serialize.rs output)
type SealedTransaction = Transaction<Signature, ProofPreimageMarker, PureGeneratorPedersen, DefaultDB>;

/// Additional safety overhead added to all fees (0.3 Dust = 300 trillion Specks).
///
/// This matches TypeScript SDK's `additionalFeeOverhead` parameter:
/// `/midnight-wallet/packages/dust-wallet/src/Transacting.ts:274`
const ADDITIONAL_FEE_OVERHEAD: u128 = 300_000_000_000_000;

/// Default fee blocks margin (matches TypeScript SDK).
///
/// This is the `n` parameter in `feesWithMargin()` that accounts for
/// blockchain price fluctuations between transaction creation and confirmation.
const DEFAULT_FEE_BLOCKS_MARGIN: usize = 5;

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
/// 3. fee = transaction.fees_with_margin(params, margin)
/// 4. total_fee = fee + ADDITIONAL_FEE_OVERHEAD (0.3 Dust)
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
        eprintln!("Error: tx_hex is null");
        return ptr::null_mut();
    }

    if params_hex.is_null() {
        eprintln!("Error: params_hex is null");
        return ptr::null_mut();
    }

    unsafe {
        // Convert C strings to Rust
        let tx_hex_str = match CStr::from_ptr(tx_hex).to_str() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: Invalid UTF-8 in tx_hex: {}", e);
                return ptr::null_mut();
            }
        };

        let params_hex_str = match CStr::from_ptr(params_hex).to_str() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: Invalid UTF-8 in params_hex: {}", e);
                return ptr::null_mut();
            }
        };

        // Decode hex to bytes
        let tx_bytes = match hex::decode(tx_hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Error decoding transaction hex: {}", e);
                return ptr::null_mut();
            }
        };

        let params_bytes = match hex::decode(params_hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Error decoding params hex: {}", e);
                return ptr::null_mut();
            }
        };

        // Deserialize transaction using SCALE codec
        let transaction: SealedTransaction = match Deserializable::deserialize(&mut &tx_bytes[..], 0) {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Error deserializing transaction: {}", e);
                return ptr::null_mut();
            }
        };

        // Deserialize ledger parameters using SCALE codec
        let params: LedgerParameters = match Deserializable::deserialize(&mut &params_bytes[..], 0) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error deserializing ledger parameters: {}", e);
                return ptr::null_mut();
            }
        };

        // Calculate fee with margin
        let base_fee = match transaction.fees_with_margin(&params, fee_blocks_margin as usize) {
            Ok(fee) => fee,
            Err(e) => {
                eprintln!("Error calculating fees: {:?}", e);
                return ptr::null_mut();
            }
        };

        // Add safety overhead (0.3 Dust)
        let total_fee: u128 = base_fee + ADDITIONAL_FEE_OVERHEAD;

        // Convert to decimal string
        let fee_string = total_fee.to_string();

        // Return as C string
        match CString::new(fee_string) {
            Ok(c_str) => c_str.into_raw(),
            Err(e) => {
                eprintln!("Error creating C string: {}", e);
                ptr::null_mut()
            }
        }
    }
}

// Note: free_c_string() is defined in dust_ffi.rs and used by all modules

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_calculate_fee_null_tx_hex() {
        let params_hex = CString::new("deadbeef").unwrap();

        let result = calculate_transaction_fee(ptr::null(), params_hex.as_ptr(), 5);

        assert!(result.is_null(), "Should return null for null tx_hex");
    }

    #[test]
    fn test_calculate_fee_null_params() {
        let tx_hex = CString::new("deadbeef").unwrap();

        let result = calculate_transaction_fee(tx_hex.as_ptr(), ptr::null(), 5);

        assert!(result.is_null(), "Should return null for null params_hex");
    }

    #[test]
    fn test_calculate_fee_invalid_hex() {
        let tx_hex = CString::new("not_valid_hex").unwrap();
        let params_hex = CString::new("deadbeef").unwrap();

        let result = calculate_transaction_fee(tx_hex.as_ptr(), params_hex.as_ptr(), 5);

        assert!(result.is_null(), "Should return null for invalid hex");
    }

    #[test]
    #[ignore] // TODO: Need serialized transaction hex from integration tests
    fn test_calculate_fee_success() {
        // This test requires a valid SCALE-serialized transaction hex
        // Will be implemented after we have serialize.rs creating test transactions
        todo!("Implement after getting test transaction hex from serialize module");
    }
}
