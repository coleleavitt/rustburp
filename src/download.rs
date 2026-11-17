use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;
use sha2::{Digest, Sha256};

// ============================================================================
// PortSwigger API Response Types
// ============================================================================

/// Root response from the PortSwigger releases API
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiResponse {
    result_set: ResultSet,
}

/// Contains the list of releases
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResultSet {
    results: Vec<Release>,
}

/// A single release entry containing multiple builds
#[derive(Debug, Deserialize)]
struct Release {
    #[serde(default)]
    builds: Vec<Build>,
}

/// A specific build (platform/edition combination)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Build {
    build_category_id: String,
    build_category_platform: String,
    version: String,
    #[serde(default)]
    sha256_checksum: String,
}

impl Build {
    /// Check if this is a downloadable Burp Suite desktop JAR.
    fn is_supported_jar(&self) -> bool {
        self.build_category_platform == "Jar"
            && matches!(self.build_category_id.as_str(), "desktop" | "pro")
    }

    fn file_prefix(&self) -> &'static str {
        product_file_prefix(&self.build_category_id)
    }
}

// ============================================================================
// Public Types
// ============================================================================

/// Version info from PortSwigger API
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub product: String,
    pub file_prefix: String,
}

impl VersionInfo {
    fn target_filename(&self) -> String {
        format!("{}_v{}.jar", self.file_prefix, self.version)
    }
}

/// Download progress callback data
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub percentage: u8,
    pub speed: String,
}

/// Burp Suite downloader
pub struct BurpDownloader {
    client: reqwest::blocking::Client,
}

impl BurpDownloader {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { client })
    }

    pub fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let url = "https://portswigger.net/burp/releases/data?pageSize=20";

        let response = self
            .client
            .get(url)
            .send()
            .context("Failed to fetch version info")?;

        if !response.status().is_success() {
            anyhow::bail!("API returned status: {}", response.status());
        }

        let api_response: ApiResponse = response
            .json()
            .context("Failed to parse API response as JSON")?;

        version_info_from_api_response(api_response)
    }

    /// Get the installed Burp Suite version (if any)
    pub fn get_installed_version(&self) -> Option<(String, PathBuf)> {
        let install_dir = Self::install_dir()?;

        let entries = fs::read_dir(&install_dir).ok()?;

        #[derive(Debug)]
        struct InstalledJar {
            version: String,
            path: PathBuf,
            modified: Option<SystemTime>,
        }

        // Find the highest installed Burp version across legacy pro and current desktop jars.
        let jar = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                let version = parse_installed_jar_version(&name)?;
                let modified = e.metadata().ok().and_then(|m| m.modified().ok());

                Some(InstalledJar {
                    version,
                    path: e.path(),
                    modified,
                })
            })
            .max_by(|a, b| {
                compare_burp_versions(&a.version, &b.version)
                    .then_with(|| a.modified.cmp(&b.modified))
            })?;

        Some((jar.version, jar.path))
    }

    /// Get the installation directory
    pub fn install_dir() -> Option<PathBuf> {
        dirs::data_local_dir().map(|d| d.join("BurpSuite"))
    }

    /// Download Burp Suite with progress callback
    pub fn download<F>(&self, version_info: &VersionInfo, progress_callback: F) -> Result<PathBuf>
    where
        F: Fn(DownloadProgress),
    {
        let install_dir = Self::install_dir().context("Could not determine install directory")?;
        fs::create_dir_all(&install_dir).context("Failed to create install directory")?;

        let target_file = install_dir.join(version_info.target_filename());

        // Check if already downloaded and valid
        if target_file.exists() {
            progress_callback(DownloadProgress {
                bytes_downloaded: 0,
                total_bytes: 0,
                percentage: 0,
                speed: "Validating existing file...".to_string(),
            });

            if !version_info.sha256.is_empty() {
                let actual_sha256 = self.calculate_sha256(&target_file)?;
                if actual_sha256.eq_ignore_ascii_case(&version_info.sha256) {
                    let size = target_file.metadata()?.len();
                    progress_callback(DownloadProgress {
                        bytes_downloaded: size,
                        total_bytes: size,
                        percentage: 100,
                        speed: "File verified - already downloaded".to_string(),
                    });
                    return Ok(target_file);
                } else {
                    // Corrupted, delete and re-download
                    fs::remove_file(&target_file)?;
                }
            } else if target_file.metadata()?.len() > 100_000_000 {
                // No checksum but file is big enough, assume it's valid
                let size = target_file.metadata()?.len();
                progress_callback(DownloadProgress {
                    bytes_downloaded: size,
                    total_bytes: size,
                    percentage: 100,
                    speed: "Already downloaded".to_string(),
                });
                return Ok(target_file);
            } else {
                fs::remove_file(&target_file)?;
            }
        }

        let artifact_name = version_info.target_filename();

        // Try download URLs in order
        let urls = [
            version_info.download_url.clone(),
            format!(
                "https://portswigger-cdn.net/burp/releases/{}",
                artifact_name
            ),
            format!("https://portswigger.net/burp/releases/{}", artifact_name),
        ];

        let partial_file = target_file.with_extension("jar.part");

        for url in &urls {
            if partial_file.exists() {
                let _ = fs::remove_file(&partial_file);
            }

            match self.perform_download(
                url,
                &partial_file,
                &version_info.sha256,
                &progress_callback,
            ) {
                Ok(()) => {
                    if target_file.exists() {
                        fs::remove_file(&target_file).context("Failed to replace old JAR")?;
                    }
                    fs::rename(&partial_file, &target_file)
                        .context("Failed to install downloaded JAR")?;
                    return Ok(target_file);
                }
                Err(e) => {
                    let _ = fs::remove_file(&partial_file);
                    eprintln!(
                        "  {} Download from {} failed: {}",
                        "!".yellow(),
                        url.dimmed(),
                        e
                    );
                    continue;
                }
            }
        }

        anyhow::bail!(
            "Failed to download from all mirrors. Please check your internet connection or download manually from https://portswigger.net/burp/releases"
        )
    }

    fn perform_download<F>(
        &self,
        url: &str,
        target_file: &PathBuf,
        expected_sha256: &str,
        progress_callback: &F,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        let mut response = self.client.get(url).send().context("Failed to connect")?;

        if !response.status().is_success() {
            anyhow::bail!("HTTP {}", response.status());
        }

        let total_bytes = response.content_length().unwrap_or(0);

        // Burp Suite Pro should be > 100MB
        if total_bytes > 0 && total_bytes < 100_000_000 {
            anyhow::bail!(
                "File too small ({} bytes) - likely not the real JAR",
                total_bytes
            );
        }

        let mut file = File::create(target_file).context("Failed to create file")?;
        let mut downloaded: u64 = 0;
        let mut buffer = [0u8; 8192];
        let start_time = Instant::now();
        let mut last_update = start_time;

        progress_callback(DownloadProgress {
            bytes_downloaded: 0,
            total_bytes,
            percentage: 0,
            speed: "Starting...".to_string(),
        });

        loop {
            let bytes_read = response.read(&mut buffer).context("Failed to read")?;
            if bytes_read == 0 {
                break;
            }

            file.write_all(&buffer[..bytes_read])
                .context("Failed to write")?;
            downloaded += bytes_read as u64;

            let now = Instant::now();
            if now.duration_since(last_update).as_millis() > 200 {
                let elapsed = now.duration_since(start_time).as_secs_f64();
                let speed = if elapsed > 0.0 {
                    format_speed((downloaded as f64 / elapsed) as u64)
                } else {
                    "...".to_string()
                };

                let percentage = if total_bytes > 0 {
                    ((downloaded * 100) / total_bytes) as u8
                } else {
                    0
                };

                progress_callback(DownloadProgress {
                    bytes_downloaded: downloaded,
                    total_bytes,
                    percentage,
                    speed,
                });

                last_update = now;
            }
        }

        file.flush()?;
        drop(file);

        progress_callback(DownloadProgress {
            bytes_downloaded: downloaded,
            total_bytes: downloaded,
            percentage: 100,
            speed: "Download complete".to_string(),
        });

        // Validate checksum if provided
        if !expected_sha256.is_empty() {
            progress_callback(DownloadProgress {
                bytes_downloaded: downloaded,
                total_bytes: downloaded,
                percentage: 100,
                speed: "Validating checksum...".to_string(),
            });

            let actual_sha256 = self.calculate_sha256(target_file)?;
            if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
                fs::remove_file(target_file)?;
                anyhow::bail!(
                    "Checksum mismatch! Expected: {}, Got: {}",
                    expected_sha256,
                    actual_sha256
                );
            }

            progress_callback(DownloadProgress {
                bytes_downloaded: downloaded,
                total_bytes: downloaded,
                percentage: 100,
                speed: "Checksum verified".to_string(),
            });
        }

        Ok(())
    }

    /// Calculate SHA256 of a file
    pub fn calculate_sha256(&self, path: &PathBuf) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}

fn version_info_from_api_response(api_response: ApiResponse) -> Result<VersionInfo> {
    let build = api_response
        .result_set
        .results
        .iter()
        .flat_map(|release| &release.builds)
        .find(|b| b.is_supported_jar())
        .context("Could not find a supported Burp Suite JAR in API response")?;

    let download_url = format!(
        "https://portswigger.net/burp/releases/download?product={}&type={}&version={}",
        build.build_category_id, build.build_category_platform, build.version
    );

    Ok(VersionInfo {
        version: build.version.clone(),
        download_url,
        sha256: build.sha256_checksum.clone(),
        product: build.build_category_id.clone(),
        file_prefix: build.file_prefix().to_string(),
    })
}

fn product_file_prefix(product: &str) -> &'static str {
    match product {
        "desktop" => "burpsuite_desktop",
        "pro" => "burpsuite_pro",
        _ => "burpsuite",
    }
}

fn parse_installed_jar_version(filename: &str) -> Option<String> {
    ["burpsuite_desktop_v", "burpsuite_pro_v"]
        .iter()
        .find_map(|prefix| {
            filename
                .strip_prefix(prefix)
                .and_then(|name| name.strip_suffix(".jar"))
                .map(ToOwned::to_owned)
        })
}

fn compare_burp_versions(a: &str, b: &str) -> Ordering {
    let a_parts = numeric_version_parts(a);
    let b_parts = numeric_version_parts(b);
    let max_len = a_parts.len().max(b_parts.len());

    for i in 0..max_len {
        match a_parts
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&b_parts.get(i).copied().unwrap_or(0))
        {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    a.cmp(b)
}

fn numeric_version_parts(version: &str) -> Vec<u64> {
    version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect()
}

fn format_speed(bytes_per_second: u64) -> String {
    if bytes_per_second >= 1024 * 1024 {
        format!("{:.1} MB/s", bytes_per_second as f64 / (1024.0 * 1024.0))
    } else if bytes_per_second >= 1024 {
        format!("{:.1} KB/s", bytes_per_second as f64 / 1024.0)
    } else {
        format!("{} B/s", bytes_per_second)
    }
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_current_desktop_jar_before_legacy_pro_jar() {
        let json = r#"
        {
          "ResultSet": {
            "Results": [
              {
                "builds": [
                  {
                    "BuildCategoryId": "dast",
                    "BuildCategoryPlatform": "Linux",
                    "Version": "2026.5.1"
                  }
                ]
              },
              {
                "builds": [
                  {
                    "BuildCategoryId": "desktop",
                    "BuildCategoryPlatform": "Jar",
                    "Version": "2026.4.3",
                    "Sha256Checksum": "desktop-sha"
                  }
                ]
              },
              {
                "builds": [
                  {
                    "BuildCategoryId": "pro",
                    "BuildCategoryPlatform": "Jar",
                    "Version": "2026.3.3",
                    "Sha256Checksum": "pro-sha"
                  }
                ]
              }
            ]
          }
        }
        "#;

        let response: ApiResponse = serde_json::from_str(json).unwrap();
        let version = version_info_from_api_response(response).unwrap();

        assert_eq!(version.version, "2026.4.3");
        assert_eq!(version.product, "desktop");
        assert_eq!(version.sha256, "desktop-sha");
        assert_eq!(
            version.download_url,
            "https://portswigger.net/burp/releases/download?product=desktop&type=Jar&version=2026.4.3"
        );
        assert_eq!(version.target_filename(), "burpsuite_desktop_v2026.4.3.jar");
    }

    #[test]
    fn parses_supported_installed_jar_names() {
        assert_eq!(
            parse_installed_jar_version("burpsuite_desktop_v2026.4.3.jar").as_deref(),
            Some("2026.4.3")
        );
        assert_eq!(
            parse_installed_jar_version("burpsuite_pro_v2026.3.3.jar").as_deref(),
            Some("2026.3.3")
        );
        assert_eq!(parse_installed_jar_version("burpsuite.jar"), None);
        assert_eq!(
            parse_installed_jar_version("burpsuite_desktop_v2026.4.3.jar.part"),
            None
        );
    }

    #[test]
    fn compares_burp_versions_numerically() {
        assert_eq!(
            compare_burp_versions("2026.4.10", "2026.4.3"),
            Ordering::Greater
        );
        assert_eq!(
            compare_burp_versions("2026.4.1", "2026.4"),
            Ordering::Greater
        );
        assert_eq!(compare_burp_versions("2026.4", "2026.4.0"), Ordering::Less);
    }
}
