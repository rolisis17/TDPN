#[path = "../build_support/icon_scaffold.rs"]
mod icon_scaffold;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("gpm_icon_scaffold_contract_{nanos}"))
}

#[test]
fn placeholder_icon_payload_is_valid_ico() {
    assert!(icon_scaffold::ico_bytes_are_valid(
        icon_scaffold::placeholder_ico_bytes()
    ));
}

#[test]
fn ensure_scaffold_icon_generates_missing_icon() {
    let temp_root = unique_temp_dir();
    let icon_path = temp_root.join("icons").join("icon.ico");

    let result =
        icon_scaffold::ensure_scaffold_icon(&icon_path).expect("missing icon should be generated");
    assert_eq!(
        result.status,
        icon_scaffold::IconScaffoldStatus::CreatedFromEmbeddedBytes
    );
    assert!(icon_path.exists());
    assert!(
        icon_scaffold::icon_file_is_valid(&icon_path).expect("generated icon should be readable")
    );

    fs::remove_dir_all(&temp_root).expect("temp root cleanup should succeed");
}

#[test]
fn ensure_scaffold_icon_replaces_invalid_icon() {
    let temp_root = unique_temp_dir();
    let icon_path = temp_root.join("icons").join("icon.ico");
    fs::create_dir_all(icon_path.parent().expect("icon path should have a parent"))
        .expect("icon directory should be creatable");
    fs::write(&icon_path, [0x00, 0x00, 0x01]).expect("should write truncated icon");

    let result =
        icon_scaffold::ensure_scaffold_icon(&icon_path).expect("invalid icon should be replaced");
    assert_eq!(
        result.status,
        icon_scaffold::IconScaffoldStatus::ReplacedInvalidFile
    );
    assert!(
        icon_scaffold::icon_file_is_valid(&icon_path).expect("replaced icon should be readable")
    );

    fs::remove_dir_all(&temp_root).expect("temp root cleanup should succeed");
}
