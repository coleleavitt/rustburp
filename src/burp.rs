use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;
use tracing::{debug, info};
use walkdir::WalkDir;

/// Represents a detected Burp Suite installation
#[derive(Debug, Clone)]
pub struct BurpInstallation {
    /// Root installation directory
    pub path: PathBuf,

    /// Path to the main JAR file
    pub jar_path: PathBuf,

    /// Detected version (if available)
    pub version: Option<String>,
}

impl BurpInstallation {
    /// Common paths where Burp Suite might be installed
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Environment variable override
        if let Ok(burp_home) = std::env::var("BURP_HOME") {
            paths.push(PathBuf::from(burp_home));
        }

        // Home directory locations
        if let Some(home) = dirs::home_dir() {
            // Common Linux/macOS locations
            paths.push(home.join("BurpSuitePro"));
            paths.push(home.join("burpsuite_pro"));
            paths.push(home.join(".BurpSuite"));
            paths.push(home.join(".local/share/JetBrains/Toolbox/apps/burpsuite"));
        }

        // ~/.local paths
        if let Some(data_dir) = dirs::data_local_dir() {
            paths.push(data_dir.join("BurpSuitePro"));
            paths.push(data_dir.join("burpsuite"));
        }

        // System-wide locations (Linux)
        paths.push(PathBuf::from("/opt/BurpSuitePro"));
        paths.push(PathBuf::from("/opt/burpsuite"));
        paths.push(PathBuf::from("/usr/local/BurpSuitePro"));
        paths.push(PathBuf::from("/usr/share/burpsuite"));

        // macOS specific
        #[cfg(target_os = "macos")]
        {
            paths.push(PathBuf::from("/Applications/Burp Suite Professional.app"));
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join("Applications/Burp Suite Professional.app"));
            }
        }

        // Windows specific
        #[cfg(target_os = "windows")]
        {
            if let Ok(program_files) = std::env::var("ProgramFiles") {
                paths.push(PathBuf::from(program_files).join("BurpSuitePro"));
            }
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                paths.push(PathBuf::from(local_app_data).join("BurpSuitePro"));
            }
        }

        paths
    }

    /// Detect Burp Suite installation
    pub fn detect() -> Result<Option<Self>> {
        for search_path in Self::search_paths() {
            debug!("Searching in: {}", search_path.display());

            if !search_path.exists() {
                continue;
            }

            // Look for the JAR file
            if let Some(installation) = Self::check_path(&search_path)? {
                info!("Found Burp Suite at: {}", installation.path.display());
                return Ok(Some(installation));
            }
        }

        // Also check if burpsuite_pro.jar is in PATH
        if let Ok(output) = std::process::Command::new("which")
            .arg("burpsuite")
            .output()
        {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let burp_path = PathBuf::from(path_str.trim());
                if let Some(parent) = burp_path.parent() {
                    if let Some(installation) = Self::check_path(parent)? {
                        return Ok(Some(installation));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Check a specific path for Burp Suite installation
    fn check_path(path: &std::path::Path) -> Result<Option<Self>> {
        // Check for direct JAR in path
        let jar_candidates = ["burpsuite_pro.jar", "burpsuite.jar", "BurpSuitePro.jar"];

        for jar_name in jar_candidates {
            let jar_path = path.join(jar_name);
            if jar_path.exists() {
                let version = Self::detect_version(&jar_path)?;
                return Ok(Some(Self {
                    path: path.to_path_buf(),
                    jar_path,
                    version,
                }));
            }
        }

        // macOS .app bundle
        if path.extension().map(|e| e == "app").unwrap_or(false) {
            let contents_path = path.join("Contents/Resources/app");
            for jar_name in jar_candidates {
                let jar_path = contents_path.join(jar_name);
                if jar_path.exists() {
                    let version = Self::detect_version(&jar_path)?;
                    return Ok(Some(Self {
                        path: path.to_path_buf(),
                        jar_path,
                        version,
                    }));
                }
            }
        }

        // Search subdirectories (max depth 3)
        for entry in WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let name = entry.file_name().to_string_lossy();
                if name.contains("burpsuite") && name.ends_with(".jar") {
                    let jar_path = entry.path().to_path_buf();
                    let version = Self::detect_version(&jar_path)?;
                    return Ok(Some(Self {
                        path: jar_path
                            .parent()
                            .map(|p| p.to_path_buf())
                            .unwrap_or_else(|| path.to_path_buf()),
                        jar_path,
                        version,
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Try to detect Burp Suite version from the JAR
    fn detect_version(jar_path: &PathBuf) -> Result<Option<String>> {
        // Try to read version from manifest or filename
        let filename = jar_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Check if version is in filename (e.g., burpsuite_pro_v2024.1.jar)
        if let Some(version) = Self::extract_version_from_filename(&filename) {
            return Ok(Some(version));
        }

        // Try reading MANIFEST.MF from JAR
        // This would require zip reading, skipping for now
        // Could add zip crate dependency if needed

        Ok(None)
    }

    fn extract_version_from_filename(filename: &str) -> Option<String> {
        // Pattern: burpsuite_pro_v2024.1.jar or similar
        let patterns = ["_v", "-v", "_"];
        for pattern in patterns {
            if let Some(idx) = filename.find(pattern) {
                let rest = &filename[idx + pattern.len()..];
                let version: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '.')
                    .collect();
                if !version.is_empty()
                    && version
                        .chars()
                        .next()
                        .map(|c| c.is_numeric())
                        .unwrap_or(false)
                {
                    return Some(version);
                }
            }
        }
        None
    }

    /// Install the agent JAR to the specified path
    pub fn install_agent(&self, agent_path: &PathBuf) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = agent_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create agent directory")?;
        }

        // The agent JAR would be embedded in the binary or downloaded
        // For now, we'll create a placeholder that indicates where to put it
        // In production, this would contain the actual agent bytecode

        println!(
            "  {} Installing agent to {}",
            "→".blue(),
            agent_path.display().to_string().dimmed()
        );

        // TODO: Embed the actual agent JAR at compile time or download it
        // For now, copy from the build directory if available
        let source_jar = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("burp-agent.jar");

        if source_jar.exists() {
            std::fs::copy(&source_jar, agent_path).context("Failed to copy agent JAR")?;
        } else {
            // Create a marker file indicating agent needs to be built
            std::fs::write(
                agent_path.with_extension("jar.pending"),
                "Agent JAR needs to be built from Java sources",
            )?;

            println!("  {} Agent JAR not found. Build it with:", "!".yellow());
            println!("    {}", "cd agent && ./gradlew shadowJar".white());
        }

        Ok(())
    }

    /// Set up a launcher script for running Burp with the agent
    pub fn setup_launcher(&self, agent_path: &PathBuf) -> Result<()> {
        let bin_dir = dirs::home_dir()
            .context("Could not determine home directory")?
            .join(".local")
            .join("bin");

        std::fs::create_dir_all(&bin_dir).context("Failed to create bin directory")?;

        let launcher_path = bin_dir.join("rusburp-run");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let script = format!(
                r#"#!/bin/bash
# Burp Suite Pro launcher with agent
# Generated by rusburp

AGENT_JAR="{agent_jar}"
BURP_JAR="{burp_jar}"

if [ ! -f "$AGENT_JAR" ]; then
    echo "Error: Agent JAR not found at $AGENT_JAR"
    echo "Run 'rusburp install' to fix this."
    exit 1
fi

if [ ! -f "$BURP_JAR" ]; then
    echo "Error: Burp Suite JAR not found at $BURP_JAR"
    exit 1
fi

exec java -javaagent:"$AGENT_JAR" -jar "$BURP_JAR" "$@"
"#,
                agent_jar = agent_path.display(),
                burp_jar = self.jar_path.display()
            );

            std::fs::write(&launcher_path, script).context("Failed to write launcher script")?;

            // Make executable
            let mut perms = std::fs::metadata(&launcher_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&launcher_path, perms)?;
        }

        #[cfg(windows)]
        {
            let launcher_path = bin_dir.join("rusburp-run.bat");
            let script = format!(
                r#"@echo off
REM Burp Suite Pro launcher with agent
REM Generated by rusburp

set AGENT_JAR={agent_jar}
set BURP_JAR={burp_jar}

if not exist "%AGENT_JAR%" (
    echo Error: Agent JAR not found at %AGENT_JAR%
    echo Run 'rusburp install' to fix this.
    exit /b 1
)

if not exist "%BURP_JAR%" (
    echo Error: Burp Suite JAR not found at %BURP_JAR%
    exit /b 1
)

java -javaagent:"%AGENT_JAR%" -jar "%BURP_JAR%" %*
"#,
                agent_jar = agent_path.display(),
                burp_jar = self.jar_path.display()
            );

            std::fs::write(&launcher_path, script).context("Failed to write launcher script")?;
        }

        println!(
            "  {} Created launcher at {}",
            "→".blue(),
            launcher_path.display().to_string().dimmed()
        );

        // Check if ~/.local/bin is in PATH
        if let Ok(path_env) = std::env::var("PATH") {
            if !path_env.contains(".local/bin") {
                println!();
                println!(
                    "  {} Add {} to your PATH:",
                    "!".yellow(),
                    "~/.local/bin".cyan()
                );
                println!("    {}", "export PATH=\"$HOME/.local/bin:$PATH\"".white());
            }
        }

        Ok(())
    }

    /// Remove the launcher script
    pub fn remove_launcher(&self) -> Result<()> {
        let bin_dir = dirs::home_dir()
            .context("Could not determine home directory")?
            .join(".local")
            .join("bin");

        let launcher_path = bin_dir.join("rusburp-run");
        if launcher_path.exists() {
            std::fs::remove_file(&launcher_path)?;
            println!(
                "  {} Removed {}",
                "✓".green(),
                launcher_path.display().to_string().dimmed()
            );
        }

        #[cfg(windows)]
        {
            let launcher_path = bin_dir.join("rusburp-run.bat");
            if launcher_path.exists() {
                std::fs::remove_file(&launcher_path)?;
            }
        }

        Ok(())
    }
}
