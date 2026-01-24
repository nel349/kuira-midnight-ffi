/// Test to validate which keys work with SigningKey::from_slice()
///
/// This test checks why one key works and another doesn't

#[cfg(test)]
mod key_validity_tests {
    use crate::transaction_ffi::{create_signing_key, free_signing_key};

    #[test]
    fn test_working_test_key() {
        // This key works in Android tests
        let working_key = hex::decode(
            "d319aebe08e7706091e56b1abe83f50ba6d3ceb4209dd0deca8ab22b264ff31c"
        ).unwrap();

        println!("\n🔑 Testing WORKING test key:");
        println!("   {}", hex::encode(&working_key));

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&working_key);

        let signing_key_ptr = create_signing_key(key_array.as_ptr(), 32);

        if signing_key_ptr.is_null() {
            panic!("❌ Working test key was REJECTED by create_signing_key!");
        } else {
            println!("   ✅ Key ACCEPTED");
            free_signing_key(signing_key_ptr);
        }
    }

    #[test]
    fn test_hd_wallet_key() {
        // This key fails in Android tests but is correct from HD derivation
        let hd_wallet_key = hex::decode(
            "ebf2aa00a28d02aa026f21813615b242d0dbf3f5166b659689a3b31fe98e0b5f"
        ).unwrap();

        println!("\n🔑 Testing HD wallet key:");
        println!("   {}", hex::encode(&hd_wallet_key));

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&hd_wallet_key);

        let signing_key_ptr = create_signing_key(key_array.as_ptr(), 32);

        if signing_key_ptr.is_null() {
            panic!("❌ HD wallet key was REJECTED by create_signing_key!");
        } else {
            println!("   ✅ Key ACCEPTED");
            free_signing_key(signing_key_ptr);
        }
    }

    #[test]
    fn test_both_keys_together() {
        println!("\n🔍 Testing both keys:");

        let working_key = hex::decode(
            "d319aebe08e7706091e56b1abe83f50ba6d3ceb4209dd0deca8ab22b264ff31c"
        ).unwrap();

        let hd_wallet_key = hex::decode(
            "ebf2aa00a28d02aa026f21813615b242d0dbf3f5166b659689a3b31fe98e0b5f"
        ).unwrap();

        println!("   Working:   {}", hex::encode(&working_key));
        println!("   HD Wallet: {}", hex::encode(&hd_wallet_key));

        let mut working_array = [0u8; 32];
        working_array.copy_from_slice(&working_key);

        let mut hd_array = [0u8; 32];
        hd_array.copy_from_slice(&hd_wallet_key);

        let working_ptr = create_signing_key(working_array.as_ptr(), 32);
        let hd_ptr = create_signing_key(hd_array.as_ptr(), 32);

        let working_valid = !working_ptr.is_null();
        let hd_valid = !hd_ptr.is_null();

        println!("\n   Working key:   {}", if working_valid { "✅ ACCEPTED" } else { "❌ REJECTED" });
        println!("   HD wallet key: {}", if hd_valid { "✅ ACCEPTED" } else { "❌ REJECTED" });

        if working_valid {
            free_signing_key(working_ptr);
        }

        if hd_valid {
            free_signing_key(hd_ptr);
        }

        assert!(working_valid || hd_valid, "At least one key should be valid!");
    }
}
