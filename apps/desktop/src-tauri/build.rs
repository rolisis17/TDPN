use std::env;
use std::path::PathBuf;

#[path = "build_support/icon_scaffold.rs"]
mod icon_scaffold;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/icon_scaffold.rs");
    println!("cargo:rerun-if-changed=icons/icon.svg");
    println!("cargo:rerun-if-changed=icons/icon.ico");

    let is_windows_target = env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows");

    if is_windows_target {
        let manifest_dir = PathBuf::from(
            env::var("CARGO_MANIFEST_DIR")
                .expect("CARGO_MANIFEST_DIR should be available in build scripts"),
        );
        let icon_path = icon_scaffold::windows_icon_output_path(&manifest_dir);
        let source_icon_path = icon_scaffold::windows_icon_source_path(&manifest_dir);

        match icon_scaffold::inspect_windows_icon(&icon_path, &source_icon_path) {
            Ok(icon_scaffold::WindowsIconPreflightStatus::Ready) => {
                println!(
                    "cargo:warning=desktop icon preflight passed for {}",
                    icon_path.display()
                );
            }
            Ok(status) => {
                panic!(
                    "{}",
                    icon_scaffold::windows_icon_failure_message(
                        &icon_path,
                        &source_icon_path,
                        status
                    )
                );
            }
            Err(err) => {
                panic!(
                    "desktop icon preflight failed to read {}: {}",
                    icon_path.display(),
                    err
                );
            }
        }
    } else {
        println!("cargo:warning=desktop icon preflight skipped: target os is not windows");
    }

    tauri_build::build()
}
