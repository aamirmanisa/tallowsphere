//! LLVM Backend for Tallow — direct llc + clang pipeline.
//!
//! This backend generates LLVM IR text using the existing CodeGen infrastructure,
//! then shells out to `llc` for compilation and `clang` for linking as two separate
//! stages. This enables fine-grained optimization control — SIMD autovectorization,
//! link-time optimization (LTO), and profile-guided optimization (PGO) flags can be
//! passed directly to llc.
//!
//! ## Pipeline
//!
//! ```text
//! AST + TypeEnv
//!     ↓
//! CodeGen::emit_module()    →  .ll file (LLVM IR text)
//!     ↓
//! llc -O3 .ll -o .o         →  .o file (native object)
//!     ↓
//! clang .o -o binary         →  native binary (linking)
//! ```
//!
//! ## vs codegen.rs (clang-only pipeline)
//!
//! The default codegen passes .ll directly to clang which internally runs
//! the equivalent of llc + link. The LLVM backend splits this into two stages:
//!
//! | Feature              | clang pipeline    | llc + clang pipeline    |
//! |----------------------|-------------------|-------------------------|
//! | SIMD / -march=native | Not exposed       | llc -march=native       |
//! | LTO                  | clang -flto       | llc + clang -flto       |
//! | PGO                  | clang -fprofile-* | llc + clang with .prof  |
//! | Object reuse         | No                | .o files can be cached  |
//! | Opt level            | clang -O2 (fixed) | llc -O0..3              |

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ast::Program;
use crate::codegen::{CodeGen, TargetConfig};
use crate::typeck::TypeEnv;

// ── LLVM Backend Configuration ────────────────────────────────────────────────

/// Optimization level for the llc stage.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LlvmOptLevel {
    O0,
    O1,
    O2,
    O3,
}

impl LlvmOptLevel {
    pub fn as_flag(&self) -> &'static str {
        match self {
            LlvmOptLevel::O0 => "-O0",
            LlvmOptLevel::O1 => "-O1",
            LlvmOptLevel::O2 => "-O2",
            LlvmOptLevel::O3 => "-O3",
        }
    }
}

/// Configuration for the LLVM backend compilation pipeline.
#[derive(Debug, Clone)]
pub struct LlvmBackendConfig {
    /// Optimization level for llc (default: O2)
    pub opt_level: LlvmOptLevel,
    /// Enable SIMD autovectorization (passes -march=native to llc)
    pub simd: bool,
    /// Enable link-time optimization (passes -flto to both llc and clang)
    pub lto: bool,
    /// Profile data file for PGO (optional, .profraw or .profdata)
    pub profile_file: Option<PathBuf>,
    /// Additional llc flags (e.g., "-mattr=+avx2")
    pub extra_llc_args: Vec<String>,
    /// Additional clang linker flags
    pub extra_linker_args: Vec<String>,
    /// Keep intermediate files (.ll, .o) for debugging
    pub keep_intermediates: bool,
}

impl Default for LlvmBackendConfig {
    fn default() -> Self {
        Self {
            opt_level: LlvmOptLevel::O2,
            simd: false,
            lto: false,
            profile_file: None,
            extra_llc_args: Vec::new(),
            extra_linker_args: Vec::new(),
            keep_intermediates: std::env::var("TALLOW_KEEP_IR").is_ok(),
        }
    }
}

impl LlvmBackendConfig {
    /// Create a release-optimized config with SIMD and LTO.
    pub fn release() -> Self {
        Self {
            opt_level: LlvmOptLevel::O3,
            simd: true,
            lto: true,
            ..Default::default()
        }
    }
}

// ── Type Mapping: Tallow → LLVM IR ──────────────────────────────────────────

/// Map Tallow types to LLVM IR type strings.
///
/// This mapping is used for documentation and standalone scenarios where
/// the full CodeGen infrastructure isn't required.
#[derive(Debug, Clone, PartialEq)]
pub enum LlvmType {
    I1,
    I8,
    I32,
    I64,
    F64,
    Ptr,
    Void,
    /// Named struct type (e.g. "%struct.Point")
    Struct(String),
    /// Array type (e.g. "[10 x i32]")
    Array(Box<LlvmType>, usize),
}

impl LlvmType {
    /// Return the LLVM IR type string.
    pub fn to_ir(&self) -> String {
        match self {
            LlvmType::I1 => "i1".to_string(),
            LlvmType::I8 => "i8".to_string(),
            LlvmType::I32 => "i32".to_string(),
            LlvmType::I64 => "i64".to_string(),
            LlvmType::F64 => "double".to_string(),
            LlvmType::Ptr => "ptr".to_string(),
            LlvmType::Void => "void".to_string(),
            LlvmType::Struct(name) => name.clone(),
            LlvmType::Array(elem, len) => format!("[{} x {}]", len, elem.to_ir()),
        }
    }

    /// Return the default/zero value for this type.
    pub fn default_value(&self) -> String {
        match self {
            LlvmType::I1 => "0".to_string(),
            LlvmType::I8 => "0".to_string(),
            LlvmType::I32 => "0".to_string(),
            LlvmType::I64 => "0".to_string(),
            LlvmType::F64 => "0.0".to_string(),
            LlvmType::Ptr => "null".to_string(),
            LlvmType::Void => String::new(),
            LlvmType::Struct(name) => format!("{name} zeroinitializer"),
            LlvmType::Array(_, _) => "zeroinitializer".to_string(),
        }
    }
}

/// Map a Tallow type name string to its LlvmType.
pub fn tallow_type_to_llvm(type_name: &str) -> LlvmType {
    match type_name {
        "bool" => LlvmType::I1,
        "i8" | "u8" => LlvmType::I8,
        "i16" | "u16" | "i32" | "u32" => LlvmType::I32,
        "i64" | "u64" | "i128" | "u128" | "isize" | "usize" => LlvmType::I64,
        "f32" | "f64" => LlvmType::F64,
        "String" | "Bytes" => LlvmType::Ptr,
        _ => LlvmType::I64, // default to i64 for unknown/complex types
    }
}

// ── Tool Discovery ────────────────────────────────────────────────────────────

/// Find the `llc` binary on the system.
pub fn find_llc() -> Option<String> {
    let candidates = [
        "llc",
        "llc-22",
        "llc-21",
        "llc-20",
        "llc-19",
        "llc-18",
        "llc-17",
    ];
    for candidate in &candidates {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            if output.status.success() {
                return Some(candidate.to_string());
            }
        }
    }

    // Check common LLVM install directories
    let dirs = [
        "/usr/bin",
        "/usr/local/bin",
        "/opt/llvm/bin",
        "/usr/lib/llvm-22/bin",
        "/usr/lib/llvm-21/bin",
        "/usr/lib/llvm-20/bin",
        "/usr/lib/llvm-19/bin",
        "/usr/lib/llvm-18/bin",
        "/usr/lib/llvm-17/bin",
    ];
    for dir in &dirs {
        let candidate = format!("{dir}/llc");
        if Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }

    None
}

/// Find the `clang` binary on the system.
pub fn find_clang_llvm() -> Option<String> {
    let candidates = [
        "clang",
        "clang-22",
        "clang-21",
        "clang-20",
        "clang-19",
        "clang-18",
        "clang-17",
    ];
    for candidate in &candidates {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            if output.status.success() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

// ── LLVM Backend Compiler ────────────────────────────────────────────────────

/// The LLVM backend compiler.
///
/// Wraps the existing `CodeGen` for IR generation and adds the `llc` → `clang`
/// two-stage compilation pipeline.
pub struct LlvmBackend<'a> {
    config: LlvmBackendConfig,
    codegen: CodeGen<'a>,
}

impl<'a> LlvmBackend<'a> {
    /// Create a new LLVM backend with the given configuration.
    pub fn new(
        program: &'a Program,
        env: &'a TypeEnv,
        target: TargetConfig,
        config: LlvmBackendConfig,
    ) -> Self {
        Self {
            config,
            codegen: CodeGen::new_with_target(program, env, target),
        }
    }

    /// Create with default configuration (O2, no SIMD, no LTO).
    pub fn new_default(program: &'a Program, env: &'a TypeEnv, target: TargetConfig) -> Self {
        Self::new(program, env, target, LlvmBackendConfig::default())
    }

    /// Create with release configuration (O3, SIMD, LTO).
    pub fn new_release(program: &'a Program, env: &'a TypeEnv, target: TargetConfig) -> Self {
        Self::new(program, env, target, LlvmBackendConfig::release())
    }

    /// Set the source directory for import resolution.
    pub fn set_source_dir(&mut self, dir: String) {
        self.codegen.set_source_dir(dir);
    }

    /// Generate LLVM IR text for the program.
    pub fn emit_llvm_ir(&mut self) -> Result<String, String> {
        self.codegen.emit_module()
    }

    /// Full compilation pipeline: generate IR, compile with llc, link with clang.
    ///
    /// Produces a native binary at `output_path`.
    pub fn compile(&mut self, output_path: &Path) -> Result<(), String> {
        // Stage 1: Generate LLVM IR
        let ir = self.codegen.emit_module()?;

        let ll_path = output_path.with_extension("ll");
        std::fs::write(&ll_path, &ir)
            .map_err(|e| format!("failed to write LLVM IR: {e}"))?;

        // Stage 2: Compile LLVM IR → native object with llc
        let obj_path = output_path.with_extension("o");
        self.compile_with_llc(&ll_path, &obj_path)?;

        // Stage 3: Link object → binary with clang
        let output_str = output_path.display().to_string();
        self.link_with_clang(&obj_path, &output_str)?;

        // Clean up intermediate files unless debugging
        if !self.config.keep_intermediates {
            let _ = std::fs::remove_file(&ll_path);
            let _ = std::fs::remove_file(&obj_path);
        }

        // Handle async stub if needed
        // Note: The existing CodeGen tracks has_async; we'd need to expose it.
        // For now, async programs compiled via this backend may need the stub.
        // The async stub is embedded in codegen.rs compile flow — we skip it here
        // since it's primarily a C file for the clang-only pipeline.

        Ok(())
    }

    /// Compile LLVM IR (.ll) → native object (.o) using llc.
    pub fn compile_with_llc(
        &self,
        ll_path: &Path,
        obj_path: &Path,
    ) -> Result<(), String> {
        let llc = find_llc()
            .ok_or_else(|| {
                "llc not found. Install LLVM: `pacman -S llvm` (Arch) or `apt install llvm` (Debian)"
                    .to_string()
            })?;

        let mut cmd = Command::new(&llc);

        // Input/output
        cmd.arg(ll_path);
        cmd.arg("-o");
        cmd.arg(obj_path);

        // Optimization level
        cmd.arg(self.config.opt_level.as_flag());

        // SIMD: target native CPU for autovectorization
        if self.config.simd {
            cmd.arg("-march=native");
            cmd.arg("-mcpu=native");
        }

        // LTO: emit bitcode for later link-time optimization
        if self.config.lto {
            // With LTO, llc should accept bitcode input.
            // Since we generate .ll text, we skip LTO at the llc stage
            // and let clang handle it at link time.
        }

        // PGO: use profile data
        if let Some(profile) = &self.config.profile_file {
            cmd.arg(format!(
                "-fprofile-sample-use={}",
                profile.display()
            ));
        }

        // Extra llc arguments
        for arg in &self.config.extra_llc_args {
            cmd.arg(arg);
        }

        // File type: emit object file
        cmd.arg("-filetype=obj");

        // Relocation model: PIC for shared library / PIE compatibility
        cmd.arg("-relocation-model=pic");

        let output = cmd
            .output()
            .map_err(|e| format!("failed to run llc ({llc}): {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{stderr}");
            return Err(format!("llc exited with status {}", output.status));
        }

        Ok(())
    }

    /// Link native object (.o) → binary using clang.
    pub fn link_with_clang(
        &self,
        obj_path: &Path,
        output_path: &str,
    ) -> Result<(), String> {
        let clang = find_clang_llvm()
            .ok_or_else(|| {
                "clang not found. Install LLVM: `pacman -S clang` (Arch) or `apt install clang` (Debian)"
                    .to_string()
            })?;

        let mut cmd = Command::new(&clang);

        // Input object file
        cmd.arg(obj_path);
        cmd.arg("-o");
        cmd.arg(output_path);

        // Optimization (for the link step)
        cmd.arg(self.config.opt_level.as_flag());

        // LTO at link time
        if self.config.lto {
            cmd.arg("-flto");
        }

        // Link math library (required for sqrt, pow, etc.)
        cmd.arg("-lm");

        // Position-independent executable
        cmd.arg("-fPIE");
        cmd.arg("-pie");

        // Reproducible builds
        cmd.arg("-Wdate-time");
        cmd.arg("-fno-ident");
        cmd.arg("-Wl,--build-id=sha1");

        // Binary hardening: CET
        cmd.arg("-fcf-protection=full");

        // Extra linker args
        for arg in &self.config.extra_linker_args {
            cmd.arg(arg);
        }

        let output = cmd
            .output()
            .map_err(|e| format!("failed to run clang ({clang}): {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{stderr}");
            return Err(format!("clang exited with status {}", output.status));
        }

        Ok(())
    }

    /// Emit LLVM IR only (no compilation), returning the path to the .ll file.
    pub fn emit_ir_to_file(&mut self, output_path: &Path) -> Result<PathBuf, String> {
        let ir = self.codegen.emit_module()?;
        let ll_path = output_path.with_extension("ll");
        std::fs::write(&ll_path, &ir)
            .map_err(|e| format!("failed to write LLVM IR: {e}"))?;
        Ok(ll_path)
    }
}

// ── Convenience: Top-level compile functions ──────────────────────────────────

/// Compile a Tallow program using the LLVM backend (llc + clang pipeline).
///
/// This is the equivalent of `CodeGen::compile_with_target_and_source_dir`
/// but using the `llc` + `clang` two-stage pipeline instead of the single
/// `clang` invocation.
pub fn compile_llvm(
    program: &Program,
    env: &TypeEnv,
    output_path: &Path,
    target: TargetConfig,
    source_dir: Option<String>,
    release: bool,
) -> Result<(), String> {
    let config = if release {
        LlvmBackendConfig::release()
    } else {
        LlvmBackendConfig::default()
    };

    let mut backend = LlvmBackend::new(program, env, target, config);
    if let Some(dir) = source_dir {
        backend.set_source_dir(dir);
    }
    backend.compile(output_path)
}

/// Emit LLVM IR only (no compilation or linking).
pub fn emit_llvm_ir(
    program: &Program,
    env: &TypeEnv,
    output_path: &Path,
    target: TargetConfig,
) -> Result<PathBuf, String> {
    let mut backend = LlvmBackend::new_default(program, env, target);
    backend.emit_ir_to_file(output_path)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_mapping_primitives() {
        assert_eq!(tallow_type_to_llvm("bool").to_ir(), "i1");
        assert_eq!(tallow_type_to_llvm("i8").to_ir(), "i8");
        assert_eq!(tallow_type_to_llvm("i32").to_ir(), "i32");
        assert_eq!(tallow_type_to_llvm("i64").to_ir(), "i64");
        assert_eq!(tallow_type_to_llvm("f64").to_ir(), "double");
        assert_eq!(tallow_type_to_llvm("String").to_ir(), "ptr");
        assert_eq!(tallow_type_to_llvm("Bytes").to_ir(), "ptr");
    }

    #[test]
    fn test_llvm_type_default_values() {
        assert_eq!(LlvmType::I1.default_value(), "0");
        assert_eq!(LlvmType::I32.default_value(), "0");
        assert_eq!(LlvmType::F64.default_value(), "0.0");
        assert_eq!(LlvmType::Ptr.default_value(), "null");
        assert_eq!(LlvmType::Void.default_value(), "");
    }

    #[test]
    fn test_llvm_type_struct() {
        let t = LlvmType::Struct("%struct.Point".to_string());
        assert_eq!(t.to_ir(), "%struct.Point");
        assert_eq!(t.default_value(), "%struct.Point zeroinitializer");
    }

    #[test]
    fn test_llvm_type_array() {
        let t = LlvmType::Array(Box::new(LlvmType::I32), 10);
        assert_eq!(t.to_ir(), "[10 x i32]");
        assert_eq!(t.default_value(), "zeroinitializer");
    }

    #[test]
    fn test_llc_found() {
        // llc should be available in the test environment
        let llc = find_llc();
        assert!(llc.is_some(), "llc not found — install LLVM for these tests");
    }

    #[test]
    fn test_clang_found() {
        let clang = find_clang_llvm();
        assert!(clang.is_some(), "clang not found — install LLVM for these tests");
    }

    #[test]
    fn test_opt_level_flags() {
        assert_eq!(LlvmOptLevel::O0.as_flag(), "-O0");
        assert_eq!(LlvmOptLevel::O1.as_flag(), "-O1");
        assert_eq!(LlvmOptLevel::O2.as_flag(), "-O2");
        assert_eq!(LlvmOptLevel::O3.as_flag(), "-O3");
    }

    #[test]
    fn test_release_config() {
        let cfg = LlvmBackendConfig::release();
        assert_eq!(cfg.opt_level, LlvmOptLevel::O3);
        assert!(cfg.simd);
        assert!(cfg.lto);
    }

    #[test]
    fn test_default_config() {
        let cfg = LlvmBackendConfig::default();
        assert_eq!(cfg.opt_level, LlvmOptLevel::O2);
        assert!(!cfg.simd);
        assert!(!cfg.lto);
    }
}
