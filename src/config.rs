use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::debug;

/// Embedded agent JAR (compiled into the binary)
const EMBEDDED_AGENT_JAR: &[u8] = include_bytes!("../resources/burp-agent.jar");

/// Current agent version (matches the embedded JAR)
pub const AGENT_VERSION: &str = "2.0.0";

/// Application configuration stored in user's config directory
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Version of the installed agent
    pub installed_agent_version: Option<String>,

    /// Path to Burp Suite installation
    pub burp_home: Option<PathBuf>,

    /// Whether the agent is enabled
    #[serde(default)]
    pub agent_enabled: bool,
}

impl Config {
    /// Load config from file, or create default if not exists
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content =
                std::fs::read_to_string(&config_path).context("Failed to read config file")?;
            let config: Config = toml::from_str(&content).context("Failed to parse config file")?;
            debug!("Loaded config from {}", config_path.display());
            Ok(config)
        } else {
            debug!("Config file not found, using defaults");
            Ok(Config::default())
        }
    }

    /// Save config to file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(&config_path, content).context("Failed to write config file")?;

        debug!("Saved config to {}", config_path.display());
        Ok(())
    }

    /// Get the path to the config file
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Could not determine config directory")?
            .join("rusburp");
        Ok(config_dir.join("config.toml"))
    }

    /// Get the path where the agent JAR should be installed
    pub fn agent_jar_path(&self) -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir()
            .context("Could not determine local data directory")?
            .join("rusburp");

        // Ensure directory exists
        std::fs::create_dir_all(&data_dir).context("Failed to create data directory")?;

        Ok(data_dir.join("burp-agent.jar"))
    }

    /// Check if the agent is properly enabled
    pub fn is_agent_enabled(&self) -> bool {
        self.agent_enabled && self.installed_agent_version.is_some()
    }

    /// Ensure the embedded agent JAR is extracted to disk
    /// Returns the path to the agent JAR
    pub fn ensure_agent_extracted(&self) -> Result<PathBuf> {
        let agent_path = self.agent_jar_path()?;

        // Check if we need to extract/update
        let needs_extract = if agent_path.exists() {
            // Check if the embedded version is newer
            match &self.installed_agent_version {
                Some(v) if v == AGENT_VERSION => false,
                _ => true,
            }
        } else {
            true
        };

        if needs_extract {
            debug!("Extracting embedded agent JAR to {}", agent_path.display());
            std::fs::write(&agent_path, EMBEDDED_AGENT_JAR)
                .context("Failed to extract agent JAR")?;
        }

        Ok(agent_path)
    }
}
