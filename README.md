# rusburp

A command-line tool for managing Burp Suite Pro installation, licensing, and activation.

## Features

- **Auto-download**: Automatically downloads the latest Burp Suite Pro JAR from PortSwigger
- **License generation**: Generate valid license keys for any name
- **Offline activation**: Process activation requests without internet
- **One-command setup**: Download, install agent, and run with a single command
- **HiDPI support**: Automatic scaling detection for high-resolution displays
- **Wayland compatible**: Native Wayland support on Linux (Java 21+)

## Installation

### Prerequisites

- **Java 17+** (Java 21 recommended for best experience)
  - Windows: Download from [Adoptium](https://adoptium.net/) or [Oracle](https://www.oracle.com/java/technologies/downloads/)
  - Linux: `sudo apt install openjdk-21-jdk` (Debian/Ubuntu) or `sudo dnf install java-21-openjdk` (Fedora)

### Download rusburp

#### Option 1: Pre-built Binary (Recommended)

Download the latest release for your platform from the [Releases](../../releases) page.

**Linux:**
```bash
# Download and make executable
chmod +x rusburp
sudo mv rusburp /usr/local/bin/
```

**Windows:**
1. Download `rusburp.exe`
2. Move to a folder in your PATH (e.g., `C:\Program Files\rusburp\`)
3. Or run directly from the download location

#### Option 2: Build from Source

If you want to build it yourself, follow these steps:

##### Step 1: Install Git (if you don't have it)

**Windows:**
1. Download Git from [git-scm.com](https://git-scm.com/download/win)
2. Run the installer, click Next through all the defaults
3. Restart your terminal/PowerShell after installation

**Linux:**
```bash
# Debian/Ubuntu
sudo apt install git

# Fedora
sudo dnf install git

# Arch
sudo pacman -S git
```

##### Step 2: Install Rust Toolchain

**Windows:**
1. Download the Rust installer from [rustup.rs](https://rustup.rs)
2. Run `rustup-init.exe`
3. Press Enter to accept the default installation
4. **Important:** Close and reopen your terminal/PowerShell after installation
5. Verify it worked: `rustc --version` (should show something like `rustc 1.XX.X`)

**Linux:**
```bash
# Run this command and follow the prompts (press Enter for defaults)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# After installation, reload your shell
source ~/.cargo/env

# Verify it worked
rustc --version
```

##### Step 3: Clone and Build

**Windows (PowerShell):**
```powershell
git clone https://github.com/coleleavitt/rustburp.git
cd rustburp
cargo build --release
```

**Linux:**
```bash
git clone https://github.com/coleleavitt/rustburp.git
cd rustburp
cargo build --release
```

The first build may take a few minutes as it downloads and compiles dependencies.

##### Step 4: Use the Binary

After building, your binary is at:
- **Windows:** `target\release\rusburp.exe`
- **Linux:** `target/release/rusburp`

**Windows - Add to PATH (optional):**
```powershell
# Copy to a folder in your PATH, or run from the build directory:
.\target\release\rusburp.exe
```

**Linux - Install system-wide:**
```bash
sudo cp target/release/rusburp /usr/local/bin/
rusburp --version
```

## Quick Start

The easiest way to get started - just run rusburp with no arguments:

```bash
rusburp
```

This will:
1. Download Burp Suite Pro (if not already installed)
2. Extract the embedded agent
3. Launch Burp Suite with the agent enabled

## Usage

### Generate a License Key

```bash
rusburp keygen -n "Your Name"
```

Copy the generated license key and paste it into Burp Suite when prompted.

### Activate Burp Suite (Offline)

When Burp Suite asks for activation:
1. Select **"Manual activation"**
2. Copy the activation request
3. Run:

```bash
rusburp activate -r "PASTE_ACTIVATION_REQUEST_HERE"
```

4. Copy the activation response back into Burp Suite

### Other Commands

```bash
# Check installation status
rusburp status

# Download/update Burp Suite
rusburp download

# Check for updates
rusburp update

# Install the agent manually
rusburp install

# Run Burp Suite
rusburp run

# Run with custom UI scaling (for HiDPI displays)
rusburp run -s 2.0

# Show configuration paths
rusburp config

# Uninstall the agent
rusburp uninstall
```

### Command-Line Options

```
Options:
  -v, --verbose    Enable verbose output
  -d, --debug      Enable debug output
  -s, --scale      UI scale factor for HiDPI displays (e.g., 2.0, 1.5)
  -h, --help       Print help
  -V, --version    Print version
```

### Configuring Burp Suite Memory

Burp's **Settings → Suite → Performance → Maximum memory usage** setting is greyed out when you launch Burp through rusburp. That setting only works with PortSwigger's own native launcher, which can restart the JVM with a new heap size. rusburp starts the JVM directly (`java -jar ...`), and Java locks the heap size at process start, so Burp disables the option. Set the heap through the JVM instead:

**Recommended: `JAVA_TOOL_OPTIONS`** (works with `rusburp` and `rusburp run`, keeping the agent, scaling, and Wayland flags):

```bash
JAVA_TOOL_OPTIONS="-Xmx4g" rusburp run
```

Windows (PowerShell):

```powershell
$env:JAVA_TOOL_OPTIONS = "-Xmx4g"; rusburp run
```

Notes:

- Use `JAVA_TOOL_OPTIONS`, **not** `_JAVA_OPTIONS`. rusburp deliberately clears `_JAVA_OPTIONS` so the shell can't inject UI-scale flags; `JAVA_TOOL_OPTIONS` is passed straight through to the JVM.
- Java prints `Picked up JAVA_TOOL_OPTIONS: -Xmx4g` when Burp starts — that line confirms the setting took effect.
- The minimum is `-Xmx256m`. Around 4 GB is comfortable for large scans; don't exceed your physical RAM, and leave room for the OS.
- If you set nothing, the JVM default applies (typically a quarter of physical RAM). Burp's "50% of memory" default only applies when PortSwigger's launcher starts it.
- For very large projects, also use a disk-based project (offered in Burp's startup dialog) to keep traffic on disk instead of in RAM.

**Alternative: launch Burp manually** (bypasses rusburp's flags — include them yourself on Java 17+):

Linux:
```bash
java -Xmx4g \
  --add-opens=java.desktop/javax.swing=ALL-UNNAMED \
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  --add-opens=java.base/java.lang.reflect=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.base/sun.nio.ch=ALL-UNNAMED \
  --add-opens=java.base/java.io=ALL-UNNAMED \
  --enable-native-access=ALL-UNNAMED \
  -XX:+EnableDynamicAgentLoading \
  -javaagent:~/.local/share/rusburp/burp-agent.jar \
  -jar ~/.local/share/BurpSuite/burpsuite_pro.jar
```

Windows (PowerShell), with the same `--add-opens` flags on Java 17+:
```powershell
java -Xmx4g `
  -javaagent:"$env:LOCALAPPDATA\rusburp\burp-agent.jar" `
  -jar "$env:LOCALAPPDATA\BurpSuite\burpsuite_pro.jar"
```

## File Locations

| Platform | Config File | Data Directory |
|----------|-------------|----------------|
| **Linux** | `~/.config/rusburp/config.toml` | `~/.local/share/rusburp/` |
| **Windows** | `%APPDATA%\rusburp\config.toml` | `%LOCALAPPDATA%\rusburp\` |
| **macOS** | `~/Library/Application Support/rusburp/config.toml` | `~/Library/Application Support/rusburp/` |

Burp Suite JAR is stored in:
- **Linux/macOS**: `~/.local/share/BurpSuite/`
- **Windows**: `%LOCALAPPDATA%\BurpSuite\`

## Troubleshooting

### "Java not found"

Make sure Java is installed and in your PATH:
```bash
java -version
```

If not found, install Java 17+ and ensure `JAVA_HOME` is set.

### HiDPI/Scaling Issues

Use the `-s` flag to manually set scaling:
```bash
rusburp run -s 2.0
```

Or set environment variables:
```bash
export GDK_SCALE=2
export QT_SCALE_FACTOR=2
rusburp run
```

### "Maximum Memory Usage" Is Greyed Out

That setting only works when Burp is started by PortSwigger's native launcher; rusburp starts the JVM directly, so the heap is fixed at launch. See [Configuring Burp Suite Memory](#configuring-burp-suite-memory) for how to set `-Xmx` via `JAVA_TOOL_OPTIONS` instead.

### Wayland Issues (Linux)

For best Wayland support, use Java 21+. For older Java versions, rusburp automatically falls back to XWayland.

### Download Fails

If the automatic download fails:
1. Check your internet connection
2. Download manually from [PortSwigger](https://portswigger.net/burp/releases)
3. Place the JAR in `~/.local/share/BurpSuite/` (Linux) or `%LOCALAPPDATA%\BurpSuite\` (Windows)

## License

This project is for educational purposes only. Burp Suite is a product of PortSwigger Ltd.

## Credits

Created by Zer0DayLab
