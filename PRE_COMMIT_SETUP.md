# Pre-commit Hooks Setup

This guide will help you set up pre-commit hooks to catch linting and security issues before they reach your pipeline.

## Installation

1. **Install pre-commit** (if not already installed):
   ```bash
   pip install pre-commit
   ```

2. **Install the git hooks**:
   ```bash
   pre-commit install
   ```

   This installs hooks that run automatically on `git commit`.

3. **Optional: Install pre-push hooks** (for Trivy scans):
   ```bash
   pre-commit install --hook-type pre-push
   ```

## Running Manually

You can run all hooks manually on all files:
```bash
pre-commit run --all-files
```

Or run a specific hook:
```bash
pre-commit run flake8 --all-files
pre-commit run black --all-files
```

## What's Included

The pre-commit hooks will check:

- **Code Quality:**
  - `flake8` - Python linting (matches pipeline configuration)
  - `black` - Python code formatting
  - Trailing whitespace, end-of-file fixes
  - YAML/JSON/TOML validation
  - Large file detection
  - Private key detection

- **Security:**
  - `bandit` - Python security linter
  - `pip-audit` - Python dependency vulnerability scanner
  - `opengrep` - SAST/Secret scanning
  - `trivy` - Filesystem scan (runs on pre-push, CRITICAL only)

## Troubleshooting

### Hooks not running?

1. **Verify installation:**
   ```bash
   pre-commit --version
   ```

2. **Reinstall hooks:**
   ```bash
   pre-commit uninstall
   pre-commit install
   ```

3. **Check if hooks are installed:**
   ```bash
   ls .git/hooks/
   ```
   You should see `pre-commit` in the list.

### Hooks running but not catching issues?

- Make sure you're committing the files (hooks only run on staged files by default)
- Run manually to test: `pre-commit run --all-files`

### Need to skip hooks temporarily?

```bash
git commit --no-verify
```

⚠️ **Warning:** Only skip hooks if absolutely necessary. The pipeline will still fail if issues exist.

## Updating Hooks

To update hook versions:
```bash
pre-commit autoupdate
```

Then commit the updated `.pre-commit-config.yaml` file.

