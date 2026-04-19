use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

// Minimal 1x1 RGBA ICO payload used only as a scaffold fallback when no
// project icon exists yet.
fn placeholder_ico_bytes() -> [u8; 70] {
    [
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

fn ensure_scaffold_icon() -> io::Result<()> {
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => PathBuf::from(v),
        Err(_) => return Ok(()),
    };
    let icon_dir = manifest_dir.join("icons");
    let icon_path = icon_dir.join("icon.ico");
    if icon_path.exists() {
        return Ok(());
    }

    fs::create_dir_all(&icon_dir)?;
    fs::write(&icon_path, placeholder_ico_bytes())?;
    println!(
        "cargo:warning=generated scaffold placeholder icon at {}",
        icon_path.display()
    );
    Ok(())
}

fn main() {
    if let Err(err) = ensure_scaffold_icon() {
        println!(
            "cargo:warning=failed to prepare scaffold icon (continuing): {}",
            err
        );
    }
    tauri_build::build()
}
