#![allow(dead_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const MIN_VALID_ICO_SIZE_BYTES: usize = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconScaffoldStatus {
    AlreadyValid,
    CreatedFromEmbeddedBytes,
    ReplacedInvalidFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconScaffoldResult {
    pub status: IconScaffoldStatus,
    pub reason: String,
    pub icon_path: PathBuf,
}

pub fn placeholder_ico_bytes() -> &'static [u8] {
    &[
        // ICONDIR
        0x00, 0x00, // reserved
        0x01, 0x00, // image type = icon
        0x01, 0x00, // image count = 1
        // ICONDIRENTRY
        0x01, // width = 1
        0x01, // height = 1
        0x00, // color count
        0x00, // reserved
        0x01, 0x00, // planes
        0x20, 0x00, // bit count = 32
        0x30, 0x00, 0x00, 0x00, // image bytes = 48
        0x16, 0x00, 0x00, 0x00, // image offset = 22
        // BITMAPINFOHEADER (40 bytes)
        0x28, 0x00, 0x00, 0x00, // header size
        0x01, 0x00, 0x00, 0x00, // width = 1
        0x02, 0x00, 0x00, 0x00, // height = 2 (xor + and masks)
        0x01, 0x00, // planes
        0x20, 0x00, // bpp = 32
        0x00, 0x00, 0x00, 0x00, // compression = BI_RGB
        0x04, 0x00, 0x00, 0x00, // image size = 4
        0x00, 0x00, 0x00, 0x00, // x pixels per meter
        0x00, 0x00, 0x00, 0x00, // y pixels per meter
        0x00, 0x00, 0x00, 0x00, // colors used
        0x00, 0x00, 0x00, 0x00, // important colors
        // XOR mask pixel (BGRA)
        0xFF, 0xFF, 0xFF, 0xFF, // white, opaque
        // AND mask row (padded to 4 bytes)
        0x00, 0x00, 0x00, 0x00,
    ]
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn ico_bytes_are_valid(bytes: &[u8]) -> bool {
    if bytes.len() < MIN_VALID_ICO_SIZE_BYTES {
        return false;
    }

    let reserved = match read_u16_le(bytes, 0) {
        Some(value) => value,
        None => return false,
    };
    let image_type = match read_u16_le(bytes, 2) {
        Some(value) => value,
        None => return false,
    };
    let image_count = match read_u16_le(bytes, 4) {
        Some(value) => value,
        None => return false,
    };
    if reserved != 0 || image_type != 1 || image_count == 0 {
        return false;
    }

    // Validate first icon directory entry.
    let image_size = match read_u32_le(bytes, 14) {
        Some(value) if value > 0 => value as usize,
        _ => return false,
    };
    let image_offset = match read_u32_le(bytes, 18) {
        Some(value) => value as usize,
        None => return false,
    };

    if image_offset < MIN_VALID_ICO_SIZE_BYTES {
        return false;
    }
    let image_end = match image_offset.checked_add(image_size) {
        Some(value) => value,
        None => return false,
    };
    image_end <= bytes.len()
}

pub fn icon_file_is_valid(icon_path: &Path) -> io::Result<bool> {
    let bytes = fs::read(icon_path)?;
    Ok(ico_bytes_are_valid(&bytes))
}

pub const WINDOWS_ICON_SOURCE_RELATIVE_PATH: &str = "icons/icon.svg";
pub const WINDOWS_ICON_OUTPUT_RELATIVE_PATH: &str = "icons/icon.ico";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsIconPreflightStatus {
    Ready,
    MissingIcon,
    InvalidIcon,
    MissingSourceIcon,
}

pub fn windows_icon_source_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join(WINDOWS_ICON_SOURCE_RELATIVE_PATH)
}

pub fn windows_icon_output_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join(WINDOWS_ICON_OUTPUT_RELATIVE_PATH)
}

pub fn windows_icon_prebuild_command() -> &'static str {
    "npm run generate:windows-icon"
}

pub fn inspect_windows_icon(
    icon_path: &Path,
    source_icon_path: &Path,
) -> io::Result<WindowsIconPreflightStatus> {
    let source_exists = source_icon_path.exists();
    let icon_exists = icon_path.exists();

    if !source_exists {
        return Ok(WindowsIconPreflightStatus::MissingSourceIcon);
    }

    if !icon_exists {
        return Ok(WindowsIconPreflightStatus::MissingIcon);
    }

    match icon_file_is_valid(icon_path) {
        Ok(true) => Ok(WindowsIconPreflightStatus::Ready),
        Ok(false) => Ok(WindowsIconPreflightStatus::InvalidIcon),
        Err(err) => Err(err),
    }
}

pub fn windows_icon_failure_message(
    icon_path: &Path,
    source_icon_path: &Path,
    status: WindowsIconPreflightStatus,
) -> String {
    let remediation = windows_icon_prebuild_command();
    match status {
        WindowsIconPreflightStatus::Ready => format!(
            "desktop icon guardrail is already satisfied at {}",
            icon_path.display()
        ),
        WindowsIconPreflightStatus::MissingSourceIcon => format!(
            "desktop Windows icon source is missing: {}\n\
             Restore the source asset or regenerate it before building.\n\
             Manual remediation: cd apps/desktop && {}\n\
             If the generator reports missing tooling, run `npm install` in apps/desktop first.",
            source_icon_path.display(),
            remediation
        ),
        WindowsIconPreflightStatus::MissingIcon => format!(
            "desktop Windows icon is missing: {}\n\
             Manual remediation: cd apps/desktop && {}\n\
             If the generator reports missing tooling, run `npm install` in apps/desktop first.",
            icon_path.display(),
            remediation
        ),
        WindowsIconPreflightStatus::InvalidIcon => format!(
            "desktop Windows icon is invalid: {}\n\
             Manual remediation: cd apps/desktop && {}\n\
             If the generator reports missing tooling, run `npm install` in apps/desktop first.",
            icon_path.display(),
            remediation
        ),
    }
}

pub fn ensure_scaffold_icon(icon_path: &Path) -> io::Result<IconScaffoldResult> {
    let write_reason = match fs::read(icon_path) {
        Ok(existing_bytes) => {
            if ico_bytes_are_valid(&existing_bytes) {
                return Ok(IconScaffoldResult {
                    status: IconScaffoldStatus::AlreadyValid,
                    reason: "existing icon is valid".to_string(),
                    icon_path: icon_path.to_path_buf(),
                });
            }
            "existing icon is missing/invalid ICO structure".to_string()
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => "icon file missing".to_string(),
        Err(err) => return Err(err),
    };

    if let Some(parent) = icon_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(icon_path, placeholder_ico_bytes())?;

    let status = if write_reason == "icon file missing" {
        IconScaffoldStatus::CreatedFromEmbeddedBytes
    } else {
        IconScaffoldStatus::ReplacedInvalidFile
    };

    Ok(IconScaffoldResult {
        status,
        reason: write_reason,
        icon_path: icon_path.to_path_buf(),
    })
}
