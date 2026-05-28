#!/usr/bin/env bash
set -euo pipefail

# Kuira Crypto FFI - Android Cross-Compilation Script
#
# Builds libkuira_crypto_ffi.a for all Android architectures:
# - aarch64-linux-android (ARM64 - primary)
# - armv7-linux-androideabi (ARM32 - legacy)
# - x86_64-linux-android (x86_64 emulator)
# - i686-linux-android (x86 emulator)
#
# Requirements:
# - Rust toolchain with Android targets (installed via rustup)
# - Android NDK 26+ (installed via Android Studio SDK Manager)
#
# Usage:
#   ./build-android.sh [release|debug]
#
# Output:
#   target/<arch>/<profile>/libkuira_crypto_ffi.a (static library for CMake)

# Configuration
BUILD_PROFILE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Android NDK detection
if [ -z "${ANDROID_NDK:-}" ]; then
    if [ -n "${ANDROID_HOME:-}" ]; then
        # Use latest NDK version from Android SDK
        NDK_DIR="$ANDROID_HOME/ndk"
        if [ -d "$NDK_DIR" ]; then
            ANDROID_NDK="$(ls -1 "$NDK_DIR" | sort -V | tail -n 1)"
            ANDROID_NDK="$NDK_DIR/$ANDROID_NDK"
        fi
    fi
fi

if [ -z "${ANDROID_NDK:-}" ] || [ ! -d "$ANDROID_NDK" ]; then
    echo "ERROR: ANDROID_NDK not set and could not auto-detect"
    echo "Please set ANDROID_NDK environment variable to your NDK installation"
    echo "Example: export ANDROID_NDK=\$ANDROID_HOME/ndk/29.0.13599879"
    exit 1
fi

echo "Using Android NDK: $ANDROID_NDK"

# Android target configurations
# Format: "rust_target:android_api_level"
declare -a TARGETS=(
    "aarch64-linux-android:24"      # ARM64 (64-bit ARM, API 24+)
    "armv7-linux-androideabi:24"    # ARM32 (32-bit ARM, API 24+)
    "x86_64-linux-android:24"       # x86_64 (64-bit Intel, emulators)
    "i686-linux-android:24"         # x86 (32-bit Intel, emulators)
)

# Build flags
CARGO_FLAGS=""
if [ "$BUILD_PROFILE" = "release" ]; then
    CARGO_FLAGS="--release"
    echo "Building RELEASE profile"
else
    echo "Building DEBUG profile"
fi

# Build each target
for target_config in "${TARGETS[@]}"; do
    IFS=':' read -r RUST_TARGET API_LEVEL <<< "$target_config"

    echo ""
    echo "============================================"
    echo "Building for: $RUST_TARGET (API $API_LEVEL)"
    echo "============================================"

    # Set up Android NDK toolchain environment
    export ANDROID_NDK_HOME="$ANDROID_NDK"

    # Toolchain paths — pick the prebuilt dir matching the host OS so this
    # script works on dev Macs and Linux CI runners alike.
    case "$(uname -s)" in
        Darwin) HOST_TAG="darwin-x86_64" ;;
        Linux)  HOST_TAG="linux-x86_64"  ;;
        *) echo "ERROR: unsupported host OS: $(uname -s)"; exit 1 ;;
    esac
    TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"

    # Compiler (CC)
    export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android${API_LEVEL}-clang"
    export CC_armv7_linux_androideabi="$TOOLCHAIN/bin/armv7a-linux-androideabi${API_LEVEL}-clang"
    export CC_x86_64_linux_android="$TOOLCHAIN/bin/x86_64-linux-android${API_LEVEL}-clang"
    export CC_i686_linux_android="$TOOLCHAIN/bin/i686-linux-android${API_LEVEL}-clang"

    # Archiver (AR)
    export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
    export AR_armv7_linux_androideabi="$TOOLCHAIN/bin/llvm-ar"
    export AR_x86_64_linux_android="$TOOLCHAIN/bin/llvm-ar"
    export AR_i686_linux_android="$TOOLCHAIN/bin/llvm-ar"

    # Linker - CRITICAL: Use Android NDK linker, not macOS cc
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android${API_LEVEL}-clang"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$TOOLCHAIN/bin/armv7a-linux-androideabi${API_LEVEL}-clang"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/x86_64-linux-android${API_LEVEL}-clang"
    export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/i686-linux-android${API_LEVEL}-clang"

    # Build with cargo
    cd "$PROJECT_ROOT"
    cargo build --target "$RUST_TARGET" $CARGO_FLAGS

    # Verify output
    OUTPUT_DIR="$PROJECT_ROOT/target/$RUST_TARGET/$BUILD_PROFILE"
    if [ -f "$OUTPUT_DIR/libkuira_crypto_ffi.a" ]; then
        SIZE=$(du -h "$OUTPUT_DIR/libkuira_crypto_ffi.a" | cut -f1)
        echo "✅ Built successfully: $OUTPUT_DIR/libkuira_crypto_ffi.a ($SIZE)"
    else
        echo "❌ ERROR: Build failed for $RUST_TARGET"
        exit 1
    fi
done

echo ""
echo "============================================"
echo "✅ All targets built successfully!"
echo "============================================"
echo ""
echo "Static libraries (.a) are ready for CMake:"
for target_config in "${TARGETS[@]}"; do
    IFS=':' read -r RUST_TARGET API_LEVEL <<< "$target_config"
    echo "  - target/$RUST_TARGET/$BUILD_PROFILE/libkuira_crypto_ffi.a"
done
echo ""
echo "Next steps:"
echo "1. Run Gradle build: ./gradlew :core:crypto:assembleDebug"
echo "2. CMake will link these .a files into libkuira_crypto_ffi.so"
echo "3. Run Android tests: ./gradlew :core:crypto:connectedAndroidTest"
