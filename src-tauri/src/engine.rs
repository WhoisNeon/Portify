use std::path::{Path, PathBuf};

pub const SINGBOX_VERSION: &str = "1.14.3";
pub const SINGBOX_SHA256_AMD64: &str =
    "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf";
pub const SINGBOX_SHA256_ARM64: &str =
    "db11afc05195e2e6484830a0a62050a22b3d488e080bfa8e21023e55ca3153d4";

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

pub fn expected_sha256() -> &'static str {
    SINGBOX_SHA256_AMD64
}

pub fn sha256_hex(_data: &[u8]) -> String {
    String::new()
}

pub async fn resolve_binary() -> Result<ResolvedBinary, String> {
    Err("not implemented".into())
}

pub async fn download_singbox() -> Result<PathBuf, String> {
    Err("not implemented".into())
}

pub fn check_config(_singbox: &Path, _config_path: &Path) -> Result<(), String> {
    Err("not implemented".into())
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
