use anyhow::{Context, Result};
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

/// Version info from PortSwigger API
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
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

    /// Fetch the latest Burp Suite Pro version info from PortSwigger
    pub fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let url = "https://portswigger.net/burp/releases/data?pageSize=1";

        let response = self
            .client
            .get(url)
            .send()
            .context("Failed to fetch version info")?;

        if !response.status().is_success() {
            anyhow::bail!("API returned status: {}", response.status());
        }

        let json_text = response.text().context("Failed to read response")?;

        // Regex extracts Version from: {"BuildCategoryId":"pro","BuildCategoryPlatform":"Jar",...,"Version":"X.Y"}
        let version = self
            .extract_field(
                &json_text,
                r#""BuildCategoryId":"pro","BuildCategoryPlatform":"Jar"[^}]*"Version":"([^"]+)""#,
            )
            .or_else(|| {
                self.extract_field(
                    &json_text,
                    r#""BuildCategoryId":"pro"[^}]*"BuildCategoryPlatform":"Jar"[^}]*"Version":"([^"]+)""#,
                )
            })
            .context("Could not find Pro JAR version in API response")?;

        let sha256 = self
            .extract_field(
                &json_text,
                r#""BuildCategoryId":"pro","BuildCategoryPlatform":"Jar"[^}]*"Sha256Checksum":"([^"]+)""#,
            )
            .or_else(|| {
                self.extract_field(
                    &json_text,
                    r#""BuildCategoryId":"pro"[^}]*"BuildCategoryPlatform":"Jar"[^}]*"Sha256Checksum":"([^"]+)""#,
                )
            })
            .unwrap_or_default();

        let download_url = format!(
            "https://portswigger.net/burp/releases/download?product=pro&type=Jar&version={}",
            version
        );

        Ok(VersionInfo {
            version,
            download_url,
            sha256,
        })
    }

    /// Extract a regex capture group from text
    fn extract_field(&self, text: &str, pattern: &str) -> Option<String> {
        let re = regex::Regex::new(pattern).ok()?;
        re.captures(text)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Get the installed Burp Suite version (if any)
    pub fn get_installed_version(&self) -> Option<(String, PathBuf)> {
        let install_dir = Self::install_dir()?;

        let entries = fs::read_dir(&install_dir).ok()?;

        // Find the newest burpsuite_pro_v*.jar file
        let jar = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("burpsuite_pro_v") && name.ends_with(".jar")
            })
            .max_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()))?;

        let filename = jar.file_name().to_string_lossy().to_string();
        let version = filename
            .strip_prefix("burpsuite_pro_v")?
            .strip_suffix(".jar")?
            .to_string();

        Some((version, jar.path()))
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

        let target_file = install_dir.join(format!("burpsuite_pro_v{}.jar", version_info.version));

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
            }
        }

        // Try download URLs in order
        let urls = [
            version_info.download_url.clone(),
            format!(
                "https://portswigger-cdn.net/burp/releases/burpsuite_pro_v{}.jar",
                version_info.version
            ),
            format!(
                "https://portswigger.net/burp/releases/burpsuite_pro_v{}.jar",
                version_info.version
            ),
        ];

        for url in &urls {
            match self.perform_download(url, &target_file, &version_info.sha256, &progress_callback)
            {
                Ok(()) => return Ok(target_file),
                Err(e) => {
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
