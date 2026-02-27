# kuira-crypto-ffi

**Cryptographic FFI library for the Kuira Android Wallet**

This Rust library provides C FFI bindings that bridge the Midnight blockchain's Rust-based cryptography with Android's JNI (Java Native Interface). It enables the Kuira Android Wallet to perform cryptographic operations (signing, key derivation, transaction serialization, dust fee payment) by wrapping Midnight's official Rust libraries with safe FFI interfaces.

---

## Overview

| Aspect | Details |
|--------|---------|
| **Language** | Rust (with C FFI exports) |
| **Target** | Android NDK (ARM64, ARM32, x86_64, x86) |
| **Midnight Libraries** | midnight-ledger ecosystem (see Dependencies) |
| **Output** | Static library (`libkuira_crypto_ffi.a`) → Shared library via JNI (`libkuira_crypto_ffi.so`) |

---

## Project Structure

```
kuira-crypto-ffi/
├── Cargo.toml                      # Dependencies & build config
├── Cargo.lock                      # Locked dependency versions
├── CMakeLists.txt                  # Android NDK build configuration
├── build-android.sh                # Cross-compilation script (4 ABIs)
├── src/
│   ├── lib.rs                      # Library root & key derivation FFI
│   ├── transaction_ffi.rs          # Transaction signing/verification
│   ├── serialize.rs                # SCALE codec serialization
│   ├── dust_ffi.rs                 # Dust wallet state management
│   ├── fee_ffi.rs                  # Fee calculation
│   └── test_key_validity.rs        # Key validation tests
├── jni/
│   └── kuira_crypto_jni.c          # JNI C bridge (~700 lines)
└── examples/
    └── test_sealed_tag.rs          # Test examples
```

---

## Modules

### 1. Key Derivation (`lib.rs`)

Derives shielded cryptographic keys from BIP-32 seeds.

**Functions:**
- `kuira_crypto_init()` - Initialize logging (called from JNI_OnLoad)
- `derive_shielded_keys(seed, len)` → `ShieldedKeys*` - Derives coin & encryption public keys
- `derive_dust_public_key(seed, len)` → `char*` - Derives dust wallet public key
- `free_shielded_keys(ptr)` - Memory cleanup

**Data Structures:**
```c
struct ShieldedKeys {
    char* coin_public_key;        // 64 hex chars (32 bytes)
    char* encryption_public_key;  // 64 hex chars (32 bytes)
}
```

### 2. Transaction Signing (`transaction_ffi.rs`)

Schnorr BIP-340 signature operations for transaction authorization.

**Functions:**
- `create_signing_key(private_key, len)` → `SigningKey*` - Create key from 32-byte seed
- `get_verifying_key(signing_key)` → `u8*` - Extract 32-byte public key (x-only format)
- `sign_data(signing_key, data, len)` → `SignatureBytes` - Sign with Schnorr BIP-340
- `verify_signature(pub_key, message, len, signature)` → `i32` - Verify signature
- `free_signing_key()`, `free_verifying_key()`, `free_signature()` - Memory cleanup

**Signature Format:**
- 64 bytes total (R || s)
- R: 32 bytes (public nonce)
- s: 32 bytes (signature scalar)
- Compliant with BIP-340 standard

### 3. Transaction Serialization (`serialize.rs`)

SCALE codec serialization for Midnight transactions.

**Functions:**
- `get_signing_message_for_input(inputs_json, outputs_json, input_index, ttl, binding_randomness_hex)` → JSON
  - Builds Intent and extracts signature data for specific input
  - Returns: `{"signing_message": "hex", "binding_randomness": "hex"}`

- `serialize_unshielded_transaction(inputs_json, outputs_json, signatures_json, dust_actions_hex, ttl, binding_randomness_hex)` → hex
  - Serializes complete unshielded transaction to SCALE format
  - Wraps in `Transaction::Standard` with tagged serialization

- `serialize_unshielded_transaction_with_dust(...)` → hex
  - Creates real DustSpend objects from state
  - Merges base transaction with dust fee payment

- `seal_proven_transaction(proven_tx_hex)` → hex
  - Transforms proven transaction from proof server
  - Converts binding commitment format for node submission

- `get_transaction_hash(sealed_tx_hex)` → hex
  - Computes Midnight transaction hash

### 4. Dust Wallet (`dust_ffi.rs`)

Dust token state management for fee payment (Midnight's fee mechanism).

**Functions:**
- `create_dust_local_state()` → `DustState*` - Create empty dust wallet state
- `dust_wallet_balance(state, time_millis)` → JSON - Get balance at timestamp
- `dust_replay_events(state, seed, len, events_hex)` → `DustState*` - Sync from blockchain
- `serialize_dust_state(state)` → `u8*` - Persist state to bytes
- `deserialize_dust_state(data, len)` → `DustState*` - Restore state
- `dust_get_utxo_at(state, index)` → hex - Get specific dust UTXO
- `create_dust_spend(state, seed, len, utxo_index, fee, time_ms)` → JSON - Create fee payment
- `free_dust_local_state(state)` - Memory cleanup

### 5. Fee Calculation (`fee_ffi.rs`)

Transaction fee estimation.

**Functions:**
- `calculate_transaction_fee(tx_hex, params_hex, fee_blocks_margin)` → decimal string
  - Deserializes transaction and ledger parameters
  - Returns fee in Specks (smallest unit)
  - Includes 1% safety overhead

---

## Dependencies

**Midnight Libraries (via local path to `midnight-libraries` repo):**
| Crate | Purpose |
|-------|---------|
| `midnight-zswap` | Shielded key derivation (JubJub curve) - **version-critical** |
| `midnight-ledger` | Transaction structure, Intent, dust mechanisms |
| `midnight-base-crypto` | Schnorr BIP-340 signatures |
| `midnight-serialize` | SCALE codec serialization |
| `midnight-storage` | Storage abstractions |
| `midnight-coin-structure` | Token types, addresses, UTXOs |
| `midnight-transient-crypto` | Pedersen commitments |

> **Note:** These are local path dependencies pointing to `../../../../../midnight/midnight-libraries/midnight-ledger/`. See [Version Compatibility](#version-compatibility) for critical version requirements.

**Utility Crates:**
| Crate | Version | Purpose |
|-------|---------|---------|
| `hex` | 0.4 | Hex encoding/decoding |
| `rand` | 0.8 | Random nonce generation |
| `zeroize` | 1.8 | Secure memory wiping |
| `serde` + `serde_json` | 1.0 | JSON marshalling for FFI |
| `android_logger` | 0.13 | Android logcat integration |
| `log` | 0.4 | Logging facade |

---

## Building

### Prerequisites

1. **Rust toolchain** with Android targets:
   ```bash
   rustup target add aarch64-linux-android
   rustup target add armv7-linux-androideabi
   rustup target add x86_64-linux-android
   rustup target add i686-linux-android
   ```

2. **Android NDK 26+** (LLVM toolchain)

3. **Midnight libraries** checked out at compatible version (currently v7.0.0)

### Build Commands

**Build for all Android ABIs:**
```bash
./build-android.sh
```

**Build for specific target:**
```bash
cargo build --release --target aarch64-linux-android
```

**Run tests:**
```bash
cargo test
```

### Output

Static libraries are generated in `target/<arch>/release/`:
- `aarch64-linux-android/libkuira_crypto_ffi.a` (~9 MB)
- `armv7-linux-androideabi/libkuira_crypto_ffi.a` (~7.5 MB)
- `x86_64-linux-android/libkuira_crypto_ffi.a` (~9.5 MB)
- `i686-linux-android/libkuira_crypto_ffi.a` (~6.7 MB)

After CMake linking with JNI bridge:
- `libkuira_crypto_ffi.so` (~500 KB stripped per ABI)

---

## Android Integration

### Build Flow

```
Rust Static Lib    +    JNI C Bridge    →    CMake    →    Android Shared Lib
(libkuira_crypto_ffi.a)  (kuira_crypto_jni.c)             (libkuira_crypto_ffi.so)
```

### CMake Configuration

The `CMakeLists.txt` links the Rust static library with the JNI C bridge:

```cmake
# ABI mapping
set(RUST_TARGET_aarch64-linux-android aarch64-linux-android)
set(RUST_TARGET_armeabi-v7a armv7-linux-androideabi)
set(RUST_TARGET_x86_64 x86_64-linux-android)
set(RUST_TARGET_x86 i686-linux-android)

add_library(kuira_crypto_ffi SHARED jni/kuira_crypto_jni.c)
target_link_libraries(kuira_crypto_ffi ${RUST_LIB_PATH})
```

### Kotlin Usage

```kotlin
// Load native library
System.loadLibrary("kuira_crypto_ffi")

// Derive shielded keys
val keys = ShieldedKeyDeriver.deriveKeys(seed)
// keys.coinPublicKey: "274c79e9..." (64 hex chars)
// keys.encryptionPublicKey: "f3ae706b..." (64 hex chars)

// Sign transaction data
val signature = TransactionSigner.signData(privateKey, data)
// signature: 64 bytes (Schnorr BIP-340)

// Verify signature
val valid = TransactionSigner.verifySignature(publicKey, data, signature)
```

---

## Memory Safety

### Ownership Model

| Operation | Input Ownership | Output Ownership | Cleanup |
|-----------|-----------------|------------------|---------|
| `derive_shielded_keys` | Caller | Callee | `free_shielded_keys` |
| `sign_data` | Caller | Callee | `free_signature` |
| `serialize_*` | Caller | Callee | `free_serialized_transaction` |
| `dust_replay_events` | Caller | Callee | `free_dust_local_state` |

### Security Practices

- **Key Zeroization:** Private keys zeroed immediately after use via `zeroize` crate
- **Memory Safety:** All raw pointer operations marked `unsafe` with documented contracts
- **Bounds Checking:** Maximum data size enforced (1 MB for signing)
- **No Logging Secrets:** Debug output never includes key material
- **Integer Overflow:** All arithmetic checked for overflow in JNI bridge

---

## Testing

**Test Coverage:**
- 34+ Rust unit tests (signing, verification, serialization)
- 50 Android integration tests (via Kotlin wrapper)
- BIP-340 official test vectors validated
- Memory safety stress tests (5000 operations)

**Run Rust tests:**
```bash
cargo test
```

**Run Android tests:**
```bash
# From kuira-android-wallet root
./gradlew :core:crypto:connectedAndroidTest
./gradlew :core:ledger:connectedAndroidTest
```

---

## Project Context

This library is part of the **Kuira Android Wallet** project, implementing cryptographic operations for the Midnight blockchain.

**Related Documentation:**
- `docs/PLAN.md` - Overall project implementation plan
- `docs/PROGRESS.md` - Current development progress
- `docs/PHASE_2_PROGRESS.md` - Unshielded transaction implementation details

**Phases Using This Library:**
- **Phase 1B:** Shielded key derivation (JNI FFI)
- **Phase 2D-FFI:** Transaction signing (Schnorr BIP-340)
- **Phase 2-DUST:** Dust fee payment (state management, serialization)
- **Phase 2E:** Transaction submission (SCALE serialization)

---

## Version Compatibility

### midnight-zswap (Shielded Key Derivation)

**Current version:** midnight-zswap v7.0.0 (via local path dependency).

| midnight-zswap Version | Compatibility |
|------------------------|---------------|
| v7.0.0 | ✅ Current — key derivation identical to v6, fully validated |
| v6.1.0-alpha.5 | ✅ Previous — same key derivation algorithm as v7 |

**Version-abstract FFI:** The Rust FFI layer is the abstraction boundary. Kotlin depends on stable C function signatures and JSON/blob return formats. When a new Midnight version arrives (e.g. v8), only the Rust implementation changes — not the FFI contract. Key derivation uses the same domain separators and KDF across v6/v7.

**Dependency Resolution:** This project uses local path dependencies (see `Cargo.toml`):
```toml
midnight-zswap = { path = "../../../../../midnight/midnight-libraries/midnight-ledger/zswap" }
```

The version is controlled by which commit/tag of the `midnight-libraries` repo is checked out, not by version numbers in Cargo.toml.

### Other Midnight Crates

The other midnight crates (`midnight-ledger`, `midnight-base-crypto`, `midnight-serialize`, etc.) should be kept in sync with `midnight-zswap` by using the same checkout of `midnight-libraries`.

---

## Release Build Configuration

```toml
[profile.release]
opt-level = 3          # Maximum optimization
lto = true             # Link-time optimization (smaller binaries)
codegen-units = 1      # Better optimization (slower compile)
strip = true           # Strip symbols
```

---

## License

Part of the Kuira Wallet project. See repository root for license information.
