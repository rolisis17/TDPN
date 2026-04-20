use std::env;
use std::path::PathBuf;

#[path = "build_support/icon_scaffold.rs"]
mod icon_scaffold;

fn icon_path_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    Some(PathBuf::from(manifest_dir).join("icons").join("icon.ico"))
}

fn main() {
    if let Some(icon_path) = icon_path_from_manifest_dir() {
        match icon_scaffold::ensure_scaffold_icon(&icon_path) {
            Ok(result) => match result.status {
                icon_scaffold::IconScaffoldStatus::AlreadyValid => {
                    println!(
                        "cargo:warning=desktop icon preflight: icon is present and valid at {}",
                        result.icon_path.display()
                    );
                }
                icon_scaffold::IconScaffoldStatus::CreatedFromEmbeddedBytes
                | icon_scaffold::IconScaffoldStatus::ReplacedInvalidFile => {
                    println!(
                        "cargo:warning=desktop icon preflight: wrote deterministic fallback icon at {} ({})",
                        result.icon_path.display(),
                        result.reason
                    );
                }
            },
            Err(err) => {
                println!(
                    "cargo:warning=desktop icon preflight failed at {}: {}",
                    icon_path.display(),
                    err
                );
            }
        }

        match icon_scaffold::icon_file_is_valid(&icon_path) {
            Ok(true) => {
                println!(
                    "cargo:warning=desktop icon validation passed for {}",
                    icon_path.display()
                );
            }
            Ok(false) => {
                println!(
                    "cargo:warning=desktop icon validation failed for {} (tauri build may fail without a valid .ico)",
                    icon_path.display()
                );
            }
            Err(err) => {
                println!(
                    "cargo:warning=desktop icon validation could not read {}: {}",
                    icon_path.display(),
                    err
                );
            }
        }
    } else {
        println!(
            "cargo:warning=desktop icon preflight skipped: CARGO_MANIFEST_DIR was unavailable"
        );
    }

    tauri_build::build()
}
