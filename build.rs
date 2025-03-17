//! Build script that generates Rust bindings from ASN.1 schemas.
//! Output is written to `messages.rs` in the build output directory (`OUT_DIR`).

use rasn_compiler::prelude::*;
use std::path::{Path, PathBuf};

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
        }
        Err(error) => {
            Err(format!("{error}"))?;
        }
    }

    Ok(())
}
