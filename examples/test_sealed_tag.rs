// Test program to verify sealed transaction tag

use kuira_crypto_ffi::serialize_unshielded_transaction;

fn main() {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Testing Sealed Transaction Tag");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Test data from Android logs
    let inputs_json = r#"[{
        "value": "5000000",
        "owner": "7de754a427c2723bd9e04f7e7876b70bed051aaa439966aaff1596a2c3309fe0",
        "type": "0000000000000000000000000000000000000000000000000000000000000000",
        "intent_hash": "00e28d3099efda8b36d6277c61f4ce062d52102898b1314c16bd28c9d905b59c",
        "output_no": 0
    }]"#;

    let outputs_json = r#"[{
        "value": "1000000",
        "owner": "cc88e4d1c76326a4ceea7e37108189af419e2af4c59d7295dae7745dd195a363",
        "type": "0000000000000000000000000000000000000000000000000000000000000000"
    },{
        "value": "4000000",
        "owner": "0f0a855cd404f70c87921a9f50163a808b729fe14be61ff0df50cd27780d753e",
        "type": "0000000000000000000000000000000000000000000000000000000000000000"
    }]"#;

    let signatures_json = r#"["fd5dbd86cdbf787453b6d88c350dd4fdf20d1096dc8cb7a64f5056dc2498ffeb90c12dcf98b08fc5a8567f6e1a4cd5c4297de435e87819301ebde75f95e170bc"]"#;

    let ttl = 1769298539531i64;
    let binding_commitment = "734e903096da963e1c293acc3c3f8bd0d104e83176f0ddd0e3edffd1444377fc0b";

    println!("📦 Test Parameters:");
    println!("  Inputs: 1");
    println!("  Outputs: 2");
    println!("  Signatures: 1");
    println!("  TTL: {} ms", ttl);
    println!("  Binding: {}...\n", &binding_commitment[..20]);

    match serialize_unshielded_transaction(inputs_json, outputs_json, signatures_json, ttl, binding_commitment) {
        Ok(hex) => {
            println!("✅ Transaction serialized successfully!");
            println!("   Length: {} bytes\n", hex.len() / 2);

            // Convert hex to bytes
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap())
                .collect();

            // Extract full tag (everything up to and including the final ':')
            if let Some(tag_end) = bytes.iter().position(|&b| b == b':') {
                let tag_bytes = &bytes[0..=tag_end];
                let tag = String::from_utf8_lossy(tag_bytes);

                println!("📋 FULL TRANSACTION TAG:");
                println!("   {}\n", tag);

                // Check components
                let mut checks = vec![];

                if tag.contains("pedersen-schnorr[v1]") {
                    checks.push("✅ Binding: pedersen-schnorr[v1] (PureGeneratorPedersen - SEALED!)");
                } else if tag.contains("embedded-fr[v1]") {
                    checks.push("✅ Binding: embedded-fr[v1] (PureGeneratorPedersen - SEALED!)");
                } else if tag.contains("pedersen[v1]") {
                    checks.push("❌ Binding: pedersen[v1] (Pedersen - NOT SEALED!)");
                } else {
                    checks.push("⚠️  Binding: UNKNOWN");
                }

                if tag.contains("proof-preimage") {
                    checks.push("✅ Proof: proof-preimage (ProofPreimageMarker)");
                } else if tag.contains("()") {
                    checks.push("❌ Proof: () (ProofErased - WRONG!)");
                }

                if tag.contains("signature[v1]") {
                    checks.push("✅ Signature: signature[v1]");
                }

                println!("🔍 Tag Components:");
                for check in checks {
                    println!("   {}", check);
                }
                println!();

                // Summary
                if tag.contains("pedersen-schnorr[v1]") || tag.contains("embedded-fr[v1]") {
                    println!("🎉 SUCCESS! Transaction is properly sealed with PureGeneratorPedersen!");
                    println!("   This transaction should be accepted by the Midnight node.\n");
                    std::process::exit(0);
                } else {
                    println!("❌ FAILURE! Transaction is NOT sealed (still using Pedersen).");
                    println!("   The node will likely reject this transaction.\n");
                    std::process::exit(1);
                }
            } else {
                println!("❌ ERROR: Could not find tag delimiter ':'");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("❌ Serialization failed: {}", e);
            std::process::exit(1);
        }
    }
}
