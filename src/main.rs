use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::io::{self, Write};

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod banner;
mod burp;
mod config;
mod crypto;
mod download;
mod keygen;

use banner::print_banner;
use burp::BurpInstallation;
use config::Config;
use download::{BurpDownloader, format_bytes};

/// Burp Suite Pro license manager and agent installer
#[derive(Parser)]
#[command(name = "rusburp")]
#[command(author = "Zer0DayLab")]
#[command(version = "1.0.0")]
#[command(about = "Burp Suite Pro license manager and agent installer", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable debug output
    #[arg(short, long, global = true)]
    debug: bool,

    /// UI scale factor for HiDPI displays (e.g., 2.25, 2, 1.5)
    #[arg(short, long, global = true)]
    scale: Option<f64>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check current Burp Suite installation status
    Status,

    /// Download or upgrade Burp Suite Pro
    Download {
        /// Force re-download even if already installed
        #[arg(short, long)]
        force: bool,
    },

    /// Check for updates
    Update,

    /// Install or upgrade the agent
    Install {
        /// Force reinstall even if up to date
        #[arg(short, long)]
        force: bool,
    },

    /// Generate a new license key
    Keygen {
        /// License holder name
        #[arg(short, long)]
        name: String,
    },

    /// Process an activation request
    Activate {
        /// Base64-encoded activation request from Burp Suite
        #[arg(short, long)]
        request: String,
    },

    /// Run Burp Suite with the agent
    Run,

    /// Uninstall the agent
    Uninstall,

    /// Show configuration paths and settings
    Config,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else if cli.verbose {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).without_time())
        .with(filter)
        .init();

    // Print the cool banner
    print_banner();

    match cli.command {
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Download { force }) => cmd_download(force),
        Some(Commands::Update) => cmd_update(),
        Some(Commands::Install { force }) => cmd_install(force),
        Some(Commands::Keygen { name }) => cmd_keygen(&name),
        Some(Commands::Activate { request }) => cmd_activate(&request),
        Some(Commands::Run) => cmd_run(cli.scale),
        Some(Commands::Uninstall) => cmd_uninstall(),
        Some(Commands::Config) => cmd_config(),
        None => {
            // Default: auto-setup and run
            cmd_auto(cli.scale)
        }
    }
}

fn cmd_status() -> Result<()> {
    println!("{}", "Checking Burp Suite installation...".cyan());
    println!();

    let downloader = BurpDownloader::new()?;

    // Check for installed version
    if let Some((installed_version, jar_path)) = downloader.get_installed_version() {
        println!(
            "{} {} {}",
            "✓".green().bold(),
            "Burp Suite installed:".green(),
            jar_path.display().to_string().white()
        );
        println!("  {} {}", "Version:".dimmed(), installed_version.yellow());

        // Check for updates
        print!("  {} ", "Checking for updates...".dimmed());
        io::stdout().flush()?;

        match downloader.fetch_latest_version() {
            Ok(latest) => {
                if latest.version != installed_version {
                    println!(
                        "{} available (run {})",
                        latest.version.green(),
                        "rusburp update".cyan()
                    );
                } else {
                    println!("{}", "up to date".green());
                }
            }
            Err(_) => {
                println!("{}", "could not check".yellow());
            }
        }

        // Check agent status
        let config = Config::load()?;
        if let Some(agent_version) = &config.installed_agent_version {
            println!(
                "  {} {} ({})",
                "Agent:".dimmed(),
                "installed".green(),
                agent_version.yellow()
            );

            if config.is_agent_enabled() {
                println!("  {} {}", "Status:".dimmed(), "enabled".green().bold());
            } else {
                println!(
                    "  {} {} (run {} to enable)",
                    "Status:".dimmed(),
                    "disabled".red(),
                    "rusburp install".cyan()
                );
            }
        } else {
            println!(
                "  {} {} (run {} to install)",
                "Agent:".dimmed(),
                "not installed".red(),
                "rusburp install".cyan()
            );
        }
    } else {
        // Try legacy detection
        let installation = BurpInstallation::detect()?;

        match installation {
            Some(burp) => {
                println!(
                    "{} {} {}",
                    "✓".green().bold(),
                    "Burp Suite found:".green(),
                    burp.path.display().to_string().white()
                );
                println!(
                    "  {} {}",
                    "Version:".dimmed(),
                    burp.version.as_deref().unwrap_or("unknown").yellow()
                );
                println!(
                    "  {} {}",
                    "JAR:".dimmed(),
                    burp.jar_path.display().to_string().white()
                );
            }
            None => {
                println!("{} {}", "✗".red().bold(), "Burp Suite not found".red());
                println!();
                println!(
                    "Run {} to download Burp Suite Pro",
                    "rusburp download".cyan()
                );
                println!();
                println!("Or search paths:");
                for path in BurpInstallation::search_paths() {
                    println!("  - {}", path.display().to_string().dimmed());
                }
            }
        }
    }

    Ok(())
}

fn cmd_download(force: bool) -> Result<()> {
    let downloader = BurpDownloader::new()?;

    println!("{}", "Fetching latest Burp Suite version...".cyan());

    let version_info = downloader.fetch_latest_version()?;

    println!(
        "{} Latest version: {}",
        "→".blue(),
        version_info.version.green()
    );

    // Check if already installed
    if !force {
        if let Some((installed_version, _)) = downloader.get_installed_version() {
            if installed_version == version_info.version {
                println!(
                    "{} Burp Suite {} is already installed",
                    "✓".green().bold(),
                    version_info.version.yellow()
                );
                return Ok(());
            }
            println!(
                "{} Upgrading from {} to {}",
                "→".blue(),
                installed_version.yellow(),
                version_info.version.green()
            );
        }
    }

    println!();
    println!("{}", "Downloading Burp Suite Pro...".cyan());

    let jar_path = downloader.download(&version_info, |progress| {
        if progress.total_bytes > 0 {
            print!(
                "\r  {} [{:>3}%] {}/{} - {}",
                "↓".blue(),
                progress.percentage,
                format_bytes(progress.bytes_downloaded).white(),
                format_bytes(progress.total_bytes).dimmed(),
                progress.speed.cyan()
            );
        } else {
            print!("\r  {} {}", "→".blue(), progress.speed);
        }
        io::stdout().flush().ok();
    })?;

    println!();
    println!();
    println!(
        "{} Burp Suite {} downloaded successfully!",
        "✓".green().bold(),
        version_info.version.green()
    );
    println!(
        "  {} {}",
        "Location:".dimmed(),
        jar_path.display().to_string().white()
    );
    println!();
    println!("{}", "Next steps:".cyan().bold());
    println!("  1. Install the agent: {}", "rusburp install".white());
    println!(
        "  2. Generate a license: {}",
        "rusburp keygen -n \"Your Name\"".white()
    );
    println!("  3. Run Burp Suite:     {}", "rusburp run".white());
    println!();

    Ok(())
}

fn cmd_update() -> Result<()> {
    let downloader = BurpDownloader::new()?;

    print!("{} ", "Checking for updates...".cyan());
    io::stdout().flush()?;

    let latest = downloader.fetch_latest_version()?;

    if let Some((installed, _)) = downloader.get_installed_version() {
        if installed == latest.version {
            println!(
                "{}",
                format!("Burp Suite {} is up to date", installed).green()
            );
            return Ok(());
        }

        println!(
            "{}",
            format!("Update available: {} → {}", installed, latest.version).yellow()
        );
        println!();

        // Auto-download
        cmd_download(false)
    } else {
        println!("{}", format!("Latest version: {}", latest.version).green());
        println!();
        println!(
            "Burp Suite is not installed. Run {} to download.",
            "rusburp download".cyan()
        );
        Ok(())
    }
}

fn cmd_install(force: bool) -> Result<()> {
    println!("{}", "Installing Burp Suite agent...".cyan());
    println!();

    // First check if we have Burp Suite downloaded
    let downloader = BurpDownloader::new()?;
    let (burp_version, jar_path) = match downloader.get_installed_version() {
        Some(v) => v,
        None => {
            // Try legacy detection
            if let Some(burp) = BurpInstallation::detect()? {
                (
                    burp.version.unwrap_or_else(|| "unknown".to_string()),
                    burp.jar_path,
                )
            } else {
                println!(
                    "{} Burp Suite not found. Run {} first.",
                    "✗".red().bold(),
                    "rusburp download".cyan()
                );
                return Ok(());
            }
        }
    };

    let mut config = Config::load()?;
    let current_version = env!("CARGO_PKG_VERSION");

    // Check if already installed
    if !force {
        if let Some(ref installed_version) = config.installed_agent_version {
            if installed_version == current_version {
                println!(
                    "{} Agent {} is already installed and up to date",
                    "✓".green().bold(),
                    current_version.yellow()
                );
                return Ok(());
            }
            println!(
                "{} Upgrading agent from {} to {}",
                "→".blue().bold(),
                installed_version.yellow(),
                current_version.green()
            );
        }
    }

    // Create installation wrapper
    let installation = BurpInstallation {
        path: jar_path.parent().unwrap_or(&jar_path).to_path_buf(),
        jar_path: jar_path.clone(),
        version: Some(burp_version),
    };

    // Install the agent JAR
    let agent_path = config.agent_jar_path()?;
    installation.install_agent(&agent_path)?;

    // Update config
    config.installed_agent_version = Some(current_version.to_string());
    config.burp_home = Some(installation.path.clone());
    config.agent_enabled = true;
    config.save()?;

    // Set up the launcher script
    installation.setup_launcher(&agent_path)?;

    println!();
    println!(
        "{} Agent {} installed successfully!",
        "✓".green().bold(),
        current_version.green()
    );
    println!();
    println!("{}", "Next steps:".cyan().bold());
    println!(
        "  1. Generate a license: {}",
        "rusburp keygen -n \"Your Name\"".white()
    );
    println!("  2. Start Burp Suite:   {}", "rusburp run".white());
    println!();

    Ok(())
}

fn cmd_keygen(name: &str) -> Result<()> {
    println!("{}", "Generating Burp Suite Pro license...".cyan());
    println!();

    let license = keygen::generate_license(name)?;

    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════════╗".green()
    );
    println!(
        "{}",
        "║            Burp Suite Pro License Generated                    ║".green()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════════╝".green()
    );
    println!();
    println!("{} {}", "License Holder:".dimmed(), name.white().bold());
    println!("{} {}", "Valid Until:".dimmed(), "2099-12-31".yellow());
    println!();
    println!("{}", "License Key (paste into Burp Suite):".cyan());
    println!();
    println!("{}", license.white());
    println!();

    Ok(())
}

fn cmd_activate(request: &str) -> Result<()> {
    println!("{}", "Processing activation request...".cyan());
    println!();

    let activation = keygen::generate_activation(request)?;

    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════════╗".green()
    );
    println!(
        "{}",
        "║            Activation Response Generated                       ║".green()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════════╝".green()
    );
    println!();
    println!(
        "{}",
        "Activation Response (paste back into Burp Suite):".cyan()
    );
    println!();
    println!("{}", activation.white());
    println!();

    Ok(())
}

/// Auto-setup and run: download if needed, always use agent
fn cmd_auto(scale: Option<f64>) -> Result<()> {
    let downloader = BurpDownloader::new()?;
    let config = Config::load()?;

    // Check if Burp Suite is installed
    let jar_path = match downloader.get_installed_version() {
        Some((version, path)) => {
            // Check for updates silently
            if let Ok(latest) = downloader.fetch_latest_version() {
                if latest.version != version {
                    println!(
                        "{} Update available: {} → {}",
                        "!".yellow(),
                        version.dimmed(),
                        latest.version.green()
                    );
                    println!("  Run {} to upgrade", "rusburp update".cyan());
                    println!();
                }
            }
            println!("{} Burp Suite {} ready", "✓".green(), version.yellow());
            path
        }
        None => {
            // Auto-download
            println!("{}", "Burp Suite not found. Downloading...".cyan());
            println!();

            let version_info = downloader.fetch_latest_version()?;
            println!(
                "{} Latest version: {}",
                "→".blue(),
                version_info.version.green()
            );

            let path = downloader.download(&version_info, |progress| {
                if progress.total_bytes > 0 {
                    print!(
                        "\r  {} [{:>3}%] {}/{} - {}",
                        "↓".blue(),
                        progress.percentage,
                        format_bytes(progress.bytes_downloaded).white(),
                        format_bytes(progress.total_bytes).dimmed(),
                        progress.speed.cyan()
                    );
                } else {
                    print!("\r  {} {}", "→".blue(), progress.speed);
                }
                io::stdout().flush().ok();
            })?;

            println!();
            println!(
                "{} Downloaded {}",
                "✓".green(),
                version_info.version.green()
            );
            path
        }
    };

    // Auto-extract embedded agent if needed
    let agent_path = config.ensure_agent_extracted()?;
    println!(
        "{} Agent v{} ready",
        "✓".green(),
        config::AGENT_VERSION.yellow()
    );

    println!();
    println!("{}", "Starting Burp Suite...".cyan());
    println!();

    // Build java command
    let java = find_java()?;
    let mut cmd = std::process::Command::new(&java);

    // HiDPI scaling: use CLI override or auto-detect
    let scale_factor = scale.unwrap_or_else(get_display_scale);
    if scale_factor > 1.0 {
        println!(
            "{} Using UI scale: {}",
            "→".blue(),
            format!("{:.2}x", scale_factor).yellow()
        );
    }

    // Add JVM args for newer Java versions
    let java_version = get_java_version(&java);
    if java_version >= 17 {
        cmd.args([
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
            "--add-opens=java.base/java.util=ALL-UNNAMED",
            "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
            "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--enable-native-access=ALL-UNNAMED",
            "-XX:+EnableDynamicAgentLoading",
        ]);
    }

    // Java 9+ HiDPI scaling
    if java_version >= 9 && scale_factor > 1.0 {
        cmd.arg(format!("-Dsun.java2d.uiScale={}", scale_factor));
    }

    // Always use agent if it exists
    if agent_path.exists() {
        cmd.arg(format!("-javaagent:{}", agent_path.display()));
    }

    cmd.arg("-jar").arg(&jar_path);

    // Disable Chromium sandbox if not running as root (common Linux issue)
    // The chrome-sandbox binary needs setuid root permissions to work properly
    cmd.env("JCEF_DISABLE_SANDBOX", "true");

    // Run Burp Suite
    let status = cmd.status().context("Failed to start Burp Suite")?;

    if !status.success() {
        anyhow::bail!("Burp Suite exited with error");
    }

    Ok(())
}

fn cmd_run(scale: Option<f64>) -> Result<()> {
    cmd_auto(scale)
}

fn cmd_uninstall() -> Result<()> {
    println!("{}", "Uninstalling Burp Suite agent...".cyan());
    println!();

    let mut config = Config::load()?;

    if config.installed_agent_version.is_none() {
        println!("{} Agent is not installed", "!".yellow().bold());
        return Ok(());
    }

    // Remove agent JAR
    let agent_path = config.agent_jar_path()?;
    if agent_path.exists() {
        std::fs::remove_file(&agent_path)?;
        println!(
            "{} Removed {}",
            "✓".green(),
            agent_path.display().to_string().dimmed()
        );
    }

    // Remove launcher script
    if let Some(ref burp_home) = config.burp_home {
        let burp = BurpInstallation {
            path: burp_home.clone(),
            jar_path: burp_home.join("burpsuite_pro.jar"),
            version: None,
        };
        burp.remove_launcher()?;
    }

    // Update config
    config.installed_agent_version = None;
    config.agent_enabled = false;
    config.save()?;

    println!();
    println!("{} Agent uninstalled successfully", "✓".green().bold());

    Ok(())
}

fn cmd_config() -> Result<()> {
    let config = Config::load()?;
    let config_path = Config::config_path()?;
    let downloader = BurpDownloader::new()?;

    println!("{}", "Configuration:".cyan().bold());
    println!();
    println!(
        "{} {}",
        "Config file:".dimmed(),
        config_path.display().to_string().white()
    );
    println!(
        "{} {}",
        "Agent JAR:".dimmed(),
        config
            .agent_jar_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "error".to_string())
            .white()
    );
    println!(
        "{} {}",
        "Agent version:".dimmed(),
        config
            .installed_agent_version
            .as_deref()
            .unwrap_or("not installed")
            .yellow()
    );
    println!(
        "{} {}",
        "Agent enabled:".dimmed(),
        if config.agent_enabled {
            "yes".green().to_string()
        } else {
            "no".red().to_string()
        }
    );

    if let Some((version, path)) = downloader.get_installed_version() {
        println!();
        println!("{}", "Burp Suite:".cyan().bold());
        println!("{} {}", "Version:".dimmed(), version.yellow());
        println!(
            "{} {}",
            "Location:".dimmed(),
            path.display().to_string().white()
        );
    }

    Ok(())
}

/// Find Java executable
fn find_java() -> Result<String> {
    // Check JAVA_HOME first
    if let Ok(java_home) = std::env::var("JAVA_HOME") {
        let java = std::path::Path::new(&java_home).join("bin/java");
        if java.exists() {
            return Ok(java.display().to_string());
        }
    }

    // Check PATH
    if let Ok(output) = std::process::Command::new("which").arg("java").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }

    // Fallback
    Ok("java".to_string())
}

/// Get Java major version
fn get_java_version(java: &str) -> u32 {
    let output = std::process::Command::new(java)
        .arg("-version")
        .output()
        .ok();

    if let Some(output) = output {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Parse version from: openjdk version "17.0.1" or java version "1.8.0_XXX"
        for line in stderr.lines() {
            if line.contains("version") {
                if let Some(start) = line.find('"') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('"') {
                        let version = &rest[..end];
                        let parts: Vec<&str> = version.split(['.', '_', '-']).collect();
                        if let Some(first) = parts.first() {
                            if *first == "1" {
                                // Old format: 1.8.0
                                if let Some(second) = parts.get(1) {
                                    return second.parse().unwrap_or(8);
                                }
                            } else {
                                return first.parse().unwrap_or(17);
                            }
                        }
                    }
                }
            }
        }
    }

    17 // Default to 17 if we can't detect
}

/// Get display scale factor from environment or wlr-randr/xrandr
fn get_display_scale() -> f64 {
    // Check GDK_SCALE first (user override)
    if let Ok(scale) = std::env::var("GDK_SCALE") {
        if let Ok(s) = scale.parse::<f64>() {
            return s;
        }
    }

    // Check QT_SCALE_FACTOR
    if let Ok(scale) = std::env::var("QT_SCALE_FACTOR") {
        if let Ok(s) = scale.parse::<f64>() {
            return s;
        }
    }

    // Try wlr-randr for Wayland (sway, hyprland, etc.)
    if let Ok(output) = std::process::Command::new("wlr-randr").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Scale:") {
                    if let Some(scale_str) = trimmed.strip_prefix("Scale:") {
                        if let Ok(s) = scale_str.trim().parse::<f64>() {
                            return s;
                        }
                    }
                }
            }
        }
    }

    // xrandr doesn't directly expose scale, fall through to Xft.dpi check

    // Check Xft.dpi from xrdb
    if let Ok(output) = std::process::Command::new("xrdb").arg("-query").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Xft.dpi:") {
                    if let Some(dpi_str) = line.strip_prefix("Xft.dpi:") {
                        if let Ok(dpi) = dpi_str.trim().parse::<f64>() {
                            // 96 DPI is the baseline
                            return dpi / 96.0;
                        }
                    }
                }
            }
        }
    }

    // Default to 1.0 (no scaling)
    1.0
}
