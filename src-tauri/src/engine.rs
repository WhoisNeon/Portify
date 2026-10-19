use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub const SINGBOX_VERSION: &str = "1.14.3";
pub const SINGBOX_SHA256_AMD64: &str =
    "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf";
pub const SINGBOX_SHA256_ARM64: &str =
    "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4";

/// The name of the file inside the release archive.
const BINARY_NAME: &str = "sing-box.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxSource {
    Bundled,
    NextToExe,
    Cached,
    Downloaded,
}

#[derive(Debug, Clone)]
pub struct ResolvedBinary {
    pub path: PathBuf,
    pub source: SingBoxSource,
}

/// The digest for the architecture this build is running on.
pub fn expected_sha256() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        SINGBOX_SHA256_ARM64
    } else {
        SINGBOX_SHA256_AMD64
    }
}

/// The architecture slug used in the release asset names.
pub fn arch_slug() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The GitHub release URL for the given architecture.
pub fn release_url(arch: &str) -> String {
    format!(
        "https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-windows-{arch}.zip"
    )
}

/// The directory the executable lives in.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

/// The cached download location.
pub fn cached_binary_path() -> PathBuf {
    crate::store::app_dir().join("sing-box").join(BINARY_NAME)
}

/// Looks for sing-box in the known locations, downloading it if needed.
///
/// The order is: the `sing-box/` folder next to the executable (the
/// self-contained ZIP layout), the executable's own folder, then the cache.
pub async fn resolve_binary() -> Result<ResolvedBinary, String> {
    if let Some(dir) = exe_dir() {
        let bundled = dir.join("sing-box").join(BINARY_NAME);
        if bundled.is_file() {
            return Ok(ResolvedBinary {
                path: bundled,
                source: SingBoxSource::Bundled,
            });
        }
        let next_to_exe = dir.join(BINARY_NAME);
        if next_to_exe.is_file() {
            return Ok(ResolvedBinary {
                path: next_to_exe,
                source: SingBoxSource::NextToExe,
            });
        }
    }

    let cached = cached_binary_path();
    if cached.is_file() {
        return Ok(ResolvedBinary {
            path: cached,
            source: SingBoxSource::Cached,
        });
    }

    let path = download_singbox().await?;
    Ok(ResolvedBinary {
        path,
        source: SingBoxSource::Downloaded,
    })
}

/// Downloads the sing-box release, extracts the binary, verifies its digest
/// and caches it.
///
/// This is **async**: Tauri's command handlers run on an async runtime, and
/// `reqwest::blocking` panics when called from inside one.
pub async fn download_singbox() -> Result<PathBuf, String> {
    let arch = arch_slug();
    let url = release_url(arch);
    let target_dir = crate::store::app_dir().join("sing-box");
    fs::create_dir_all(&target_dir)
        .map_err(|e| format!("could not create {}: {e}", target_dir.display()))?;
    let target = target_dir.join(BINARY_NAME);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("could not create the HTTP client: {e}"))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("could not download {url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "could not download {url}: the server answered {}",
            response.status()
        ));
    }
    let archive = response
        .bytes()
        .await
        .map_err(|e| format!("could not read the download: {e}"))?;

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive.as_ref()))
        .map_err(|e| format!("could not open the downloaded archive: {e}"))?;

    let mut extracted: Option<Vec<u8>> = None;
    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| format!("could not read the archive entry {i}: {e}"))?;
        if !file.is_file() {
            continue;
        }
        // The archive holds sing-box.exe at the top level, optionally inside
        // a versioned folder.
        let name = file.name().replace('\\', "/");
        if !name.ends_with(BINARY_NAME) {
            continue;
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| format!("could not extract sing-box.exe: {e}"))?;
        extracted = Some(buf);
        break;
    }

    let data =
        extracted.ok_or_else(|| format!("the downloaded archive did not contain {BINARY_NAME}"))?;

    let actual = sha256_hex(&data);
    let expected = expected_sha256();
    if actual != expected {
        return Err(format!(
            "the downloaded sing-box binary failed its checksum (expected {expected}, got {actual}); refusing to use it"
        ));
    }

    fs::write(&target, &data)
        .map_err(|e| format!("could not write {}: {e}", target.display()))?;
    Ok(target)
}

/// Runs `sing-box check` against a config file.
///
/// Returns the process's stderr verbatim when the check fails, because that
/// is the only useful description of what sing-box objected to.
pub fn check_config(singbox: &Path, config_path: &Path) -> Result<(), String> {
    let output = Command::new(singbox)
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .arg("--disable-color")
        .output()
        .map_err(|e| format!("could not run {}: {e}", singbox.display()))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    Err(if detail.is_empty() {
        format!(
            "sing-box rejected the configuration (exit status {})",
            output.status.code().unwrap_or(-1)
        )
    } else {
        format!("sing-box rejected the configuration: {detail}")
    })
}

/// A running sing-box process.
pub struct RunningGateway {
    pub child: Child,
    pub config_path: PathBuf,
}

/// Spawns `sing-box run` with stderr piped.
///
/// sing-box writes every log line to stderr and leaves stdout empty, so the
/// caller reads stderr for the log view. `--disable-color` strips the ANSI
/// escapes so the UI can render plain text.
pub fn spawn_gateway(singbox: &Path, config_path: &Path) -> Result<RunningGateway, String> {
    let child = Command::new(singbox)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .arg("--disable-color")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", singbox.display()))?;

    Ok(RunningGateway {
        child,
        config_path: config_path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_is_lowercase_hex_of_64_chars() {
        let hex = sha256_hex(b"portify");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn expected_sha256_is_a_known_digest() {
        let hex = expected_sha256();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_pinned_amd64_digest_is_the_sing_box_1_14_3_binary() {
        // The digest recorded in the spec for sing-box 1.14.3 windows-amd64.
        assert_eq!(
            SINGBOX_SHA256_AMD64,
            "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf"
        );
    }

    #[test]
    fn the_pinned_arm64_digest_is_the_sing_box_1_14_3_binary() {
        assert_eq!(
            SINGBOX_SHA256_ARM64,
            "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4"
        );
    }

    #[test]
    fn checking_a_missing_binary_fails_cleanly() {
        let err = check_config(
            Path::new("no-such-sing-box.exe"),
            Path::new("no-config.json"),
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn the_release_url_follows_the_version() {
        let url = release_url("amd64");
        assert!(url.contains(SINGBOX_VERSION), "url must carry the version: {url}");
        assert!(url.ends_with(".zip"), "url must point at the zip: {url}");
    }

    #[test]
    fn the_release_url_is_amd64_or_arm64() {
        assert!(release_url("amd64").contains("windows-amd64"));
        assert!(release_url("arm64").contains("windows-arm64"));
    }
}
