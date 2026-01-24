cmake_minimum_required(VERSION 3.22.1)

project("kuira_crypto_ffi")

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Get Android ABI (arm64-v8a, armeabi-v7a, x86, x86_64)
message(STATUS "Building for Android ABI: ${ANDROID_ABI}")

# Map Android ABI to Rust target triple
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(RUST_TARGET "aarch64-linux-android")
    set(RUST_TARGET_DIR "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(RUST_TARGET "armv7-linux-androideabi")
    set(RUST_TARGET_DIR "armv7-linux-androideabi")
elseif(ANDROID_ABI STREQUAL "x86")
    set(RUST_TARGET "i686-linux-android")
    set(RUST_TARGET_DIR "i686-linux-android")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(RUST_TARGET "x86_64-linux-android")
    set(RUST_TARGET_DIR "x86_64-linux-android")
else()
    message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
endif()

# Rust library paths
set(RUST_PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
# Using release build with reduced optimizations (opt-level=2, no LTO)
set(RUST_TARGET_PATH "${RUST_PROJECT_DIR}/target/${RUST_TARGET_DIR}/release")

# Pre-built Rust static library
# NOTE: Must be built before running CMake via build-android.sh
add_library(rust_ffi STATIC IMPORTED)
set_target_properties(rust_ffi PROPERTIES
    IMPORTED_LOCATION "${RUST_TARGET_PATH}/libkuira_crypto_ffi.a"
)

# JNI C bridge
add_library(${CMAKE_PROJECT_NAME} SHARED
    jni/kuira_crypto_jni.c
)

# Include directories
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${ANDROID_NDK}/sysroot/usr/include
)

# Link libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    rust_ffi
    log      # Android logging (if needed)
    android  # Android APIs (if needed)
)

# Strip symbols in release builds (reduce .so size)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES LINK_FLAGS_RELEASE -s)
endif()

message(STATUS "CMake configured for ${ANDROID_ABI} → ${RUST_TARGET}")
message(STATUS "Rust library expected at: ${RUST_TARGET_PATH}/libkuira_crypto_ffi.a")
