# Security Scanning Dev Tools

This directory contains development tools for running security scans locally.

## Prerequisites

### Install Trivy

**Windows (using Chocolatey):**
```powershell
choco install trivy
```

**Windows (manual):**
1. Download from https://github.com/aquasecurity/trivy/releases
2. Extract and add to PATH

**Alternative (using Scoop):**
```powershell
scoop install trivy
```

### Install OpenGrep

**Windows (manual):**
1. Download from https://github.com/opengrep/opengrep/releases (version 1.12.0 or later)
2. Extract the Windows binary (e.g., `opengrep_windows_x86.exe`)
3. Rename to `opengrep.exe` and add to PATH

**Note:** OpenGrep may not be available via package managers. Download directly from GitHub releases.

**Windows Environment Variables:**

For OpenGrep to work correctly on Windows, you need to set the following environment variables in your PowerShell session:

```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
```

These can be added to your PowerShell profile (`$PROFILE`) to persist across sessions.

## Usage

### Run All Scans

```bash
python dev-tools/scan_security.py --all
```

### Run Individual Scans

```bash
# Filesystem scan only
python dev-tools/scan_security.py --trivy-fs

# Image scan (build image first)
docker build -t credshare:build -f Dockerfile.sharepass .
python dev-tools/scan_security.py --trivy-image credshare:build

# SAST scan only (OpenGrep)
python dev-tools/scan_security.py --opengrep
```

### Export Results to Files

**Save all scan results to a directory:**
```bash
# Creates timestamped directory with all results
python dev-tools/scan_security.py --all --output-dir scan-results
```

**Save single scan to specific file:**
```bash
python dev-tools/scan_security.py --trivy-image credshare:build --output image-scan.txt
```

**Export in JSON format (better for analysis):**
```bash
# JSON format is easier to parse and analyze programmatically
python dev-tools/scan_security.py --trivy-image credshare:build --json --output-dir results
```

**Quiet mode (suppress console output, save to files only):**
```bash
python dev-tools/scan_security.py --all --output-dir results --quiet
```

### Custom Trivy Ignore File

```bash
python dev-tools/scan_security.py --trivy-fs --trivyignore .trivyignore
```

### Output File Formats

- **Table format** (default): Human-readable text output
- **JSON format** (`--json`): Machine-readable, better for analysis and filtering
  - Use JSON when you need to process results programmatically
  - JSON files are easier to search and filter for specific vulnerabilities

## Pre-commit Hooks

Install pre-commit hooks to automatically run scans before commits:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## CI/CD Integration

Security scans are automatically run in CI:
- **Security Workflow** (`.github/workflows/security.yaml`): Runs on PRs and pushes
- **Build Workflow** (`.github/workflows/build.yaml`): Runs before pushing images to GHCR

Images with high or critical vulnerabilities will **not** be pushed to GHCR.

