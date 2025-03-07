//! Build script that generates Rust bindings from ASN.1 schemas.
//! Output is written to `messages.rs` in the build output directory (`OUT_DIR`).

use rasn_compiler::prelude::*;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[macro_export]
macro_rules! run {
    ($program:expr) => {
        $crate::_run(OsStr::new($program), &[])
    };
    ($program:expr, $($arg:expr),*) => {
        $crate::_run(OsStr::new($program), &[$(OsStr::new($arg)),*])
    };
}

/// Wrapper for `Command` with verbose error result
fn _run(program: &OsStr, args: &[&OsStr]) -> Result<(), std::io::Error> {
    let output = Command::new(program).args(args).output()?;

    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "{} exited with {} status ({})",
                program.to_str().unwrap_or_default(),
                output.status.code().unwrap_or_default(),
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    Ok(())
}

/// Format Rust code output by `rasn-compiler`
fn format(file_path: &Path) -> Result<(), std::io::Error> {
    // Strip gratuitous underscores in rasn-compiler output
    run!("sed", "-i.bak", "s/__/_/g", file_path)?;

    Ok(())
}

/// Apply a patch to `file_path`
fn patch(file_path: &Path, patch_path: &Path) -> Result<(), std::io::Error> {
    run!("patch", file_path, patch_path)
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Schemas to import
    let schemas = [
        Path::new("schema/ISO-8650-ACSE-1.asn"),
        Path::new("schema/ISO-8823-PRESENTATION.asn"),
        Path::new("schema/ISO-9506-MMS-1.asn"),
        Path::new("schema/ISO-9506-MMS-1A.asn"),
        Path::new("schema/ISO-9506-MMS-Environment-1.asn"),
        Path::new("schema/ISO-9506-MMS-Object-Module-1.asn"),
    ];

    // Code generator output is written to build artifacts directory
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let out_file = out_dir.join("messages.rs");

    // Patch to code generator output
    let out_patches = [Path::new("patches/10-messages-recursive-struct-fix.patch")];

    // Tell cargo to rebuild on schema changes
    schemas
        .iter()
        .for_each(|path| println!("cargo:rerun-if-changed={}", path.display()));

    // Generate Rust bindings from ASN.1 schemas
    match Compiler::<RasnBackend, _>::new()
        .add_asn_sources_by_path(schemas.iter())
        .set_output_path(&out_file)
        .compile()
    {
        Ok(warnings) => {
            for warning in warnings {
                eprintln!("warning: {warning}");
            }

            format(&out_file)?;

            for patch_file in out_patches {
                patch(&out_file, patch_file)?;
            }
        }
        Err(error) => {
            Err(format!("{error}"))?;
        }
    }

    Ok(())
}
