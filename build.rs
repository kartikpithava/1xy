use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    
    // Configure build based on target platform
    configure_target_optimizations();
    
    // Set up feature flags
    configure_feature_flags();
    
    // Generate build information
    generate_build_info();
    
    // Configure PDF processing optimizations
    configure_pdf_optimizations();
    
    // Set up forensic compilation flags
    configure_forensic_flags();
}

fn configure_target_optimizations() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    
    // Platform-specific optimizations
    match target_os.as_str() {
        "windows" => {
            println!("cargo:rustc-link-lib=kernel32");
            println!("cargo:rustc-link-lib=user32");
            println!("cargo:rustc-cfg=windows_file_api");
            println!("cargo:rustc-cfg=feature=\"windows_acl\"");
        },
        "macos" => {
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-cfg=macos_keychain");
            println!("cargo:rustc-cfg=feature=\"apple_security\"");
        },
        "linux" => {
            println!("cargo:rustc-cfg=linux_optimizations");
            println!("cargo:rustc-cfg=feature=\"linux_capabilities\"");
            println!("cargo:rustc-link-lib=crypto");
        },
        _ => {},
    }
    
    // Architecture-specific optimizations
    match target_arch.as_str() {
        "x86_64" => {
            println!("cargo:rustc-cfg=x86_64_optimizations");
            println!("cargo:rustc-cfg=simd_support");
            println!("cargo:rustc-cfg=feature=\"sse4_2\"");
            println!("cargo:rustc-cfg=feature=\"avx2\"");
        },
        "aarch64" => {
            println!("cargo:rustc-cfg=aarch64_optimizations");
            println!("cargo:rustc-cfg=neon_support");
            println!("cargo:rustc-cfg=feature=\"neon\"");
        },
        _ => {},
    }
}

fn configure_feature_flags() {
    // Enable optimizations for release builds
    if env::var("PROFILE").unwrap_or_default() == "release" {
        println!("cargo:rustc-cfg=release_optimizations");
        println!("cargo:rustc-cfg=production_mode");
        println!("cargo:rustc-cfg=disable_debug_output");
        println!("cargo:rustc-cfg=feature=\"lto\"");
        println!("cargo:rustc-cfg=feature=\"parallel\"");
    }
    
    // Configure forensic features
    println!("cargo:rustc-cfg=forensic_mode");
    println!("cargo:rustc-cfg=metadata_sync");
    println!("cargo:rustc-cfg=trace_removal");
    println!("cargo:rustc-cfg=feature=\"secure_memory\"");
}

fn generate_build_info() {
    let build_timestamp = "2025-06-13 21:19:56";
    let git_hash = get_git_hash().unwrap_or_else(|| "unknown".to_string());
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
    let maintainer = "kartikpithava";
    
    let build_info = format!(
        r#"//! Auto-generated build information
pub const BUILD_TIMESTAMP: &str = "{}";
pub const GIT_HASH: &str = "{}";
pub const VERSION: &str = "{}";
pub const TARGET: &str = "{}";
pub const MAINTAINER: &str = "{}";
pub const BUILD_MODE: &str = "{}";
pub const FEATURES: &[&str] = &[{}];
"#,
        build_timestamp,
        git_hash,
        version,
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
        maintainer,
        if cfg!(debug_assertions) { "debug" } else { "release" },
        get_enabled_features().join(", ")
    );
    
    let out_dir = env::var("OUT_DIR").expect("Failed to get OUT_DIR");
    let dest_path = Path::new(&out_dir).join("build_info.rs");
    fs::write(&dest_path, build_info).expect("Failed to write build info");
    
    println!("cargo:rustc-env=BUILD_INFO_PATH={}", dest_path.display());
}

fn get_git_hash() -> Option<String> {
    Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
                    .map(|hash| hash.trim().to_string())
            } else {
                None
            }
        })
}

fn get_enabled_features() -> Vec<String> {
    let mut features = vec![
        "\"forensic_mode\"".to_string(),
        "\"metadata_sync\"".to_string(),
        "\"trace_removal\"".to_string(),
        "\"secure_memory\"".to_string(),
    ];
    
    if cfg!(target_os = "windows") {
        features.push("\"windows_acl\"".to_string());
    }
    if cfg!(target_os = "macos") {
        features.push("\"apple_security\"".to_string());
    }
    if cfg!(target_os = "linux") {
        features.push("\"linux_capabilities\"".to_string());
    }
    
    if cfg!(target_arch = "x86_64") {
        features.push("\"sse4_2\"".to_string());
        features.push("\"avx2\"".to_string());
    }
    if cfg!(target_arch = "aarch64") {
        features.push("\"neon\"".to_string());
    }
    
    features
}

fn configure_pdf_optimizations() {
    println!("cargo:rustc-cfg=pdf_optimization");
    println!("cargo:rustc-cfg=stream_processing");
    println!("cargo:rustc-cfg=metadata_caching");
    println!("cargo:rustc-cfg=memory_optimization");
    println!("cargo:rustc-cfg=object_pooling");
    
    // PDF processing specific flags
    println!("cargo:rustc-cfg=feature=\"incremental_parsing\"");
    println!("cargo:rustc-cfg=feature=\"lazy_loading\"");
    println!("cargo:rustc-cfg=feature=\"stream_compression\"");
}

fn configure_forensic_flags() {
    println!("cargo:rustc-cfg=forensic_invisible");
    println!("cargo:rustc-cfg=trace_elimination");
    println!("cargo:rustc-cfg=authenticity_preservation");
    println!("cargo:rustc-cfg=secure_memory");
    println!("cargo:rustc-cfg=constant_time");
    
    // Security-focused flags
    println!("cargo:rustc-cfg=feature=\"memory_protection\"");
    println!("cargo:rustc-cfg=feature=\"secure_wipe\"");
    println!("cargo:rustc-cfg=feature=\"audit_log\"");
    
    if env::var("PROFILE").unwrap_or_default() == "release" {
        println!("cargo:rustc-cfg=feature=\"obfuscation\"");
        println!("cargo:rustc-cfg=feature=\"anti_debug\"");
    }
}
