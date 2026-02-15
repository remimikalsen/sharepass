# Testing CredShare

## Setup

1. **Install test dependencies:**

   All test packages (pytest, playwright, flake8, black, etc.) are included in the dev requirements. If you've already set up the dev environment, you're good to go:

   ```bash
   pip-sync requirements.txt requirements-dev.txt
   ```

   See [Developer Notes](../README.md#developer-notes) for the full virtual environment setup.

   > Alternatively, you can install just the test requirements directly:
   > `pip install -r tests/requirements-tests.txt`

2. **Install Playwright browsers** (REQUIRED for e2e tests):

   ```bash
   playwright install
   ```

   On Ubuntu/Debian, Playwright also needs system-level dependencies (libs for Chromium, Firefox, WebKit). Install them with:

   ```bash
   playwright install-deps
   ```

   > **Note:** `install-deps` may require root/sudo and uses `apt` under the hood. If it fails, check the [Playwright docs](https://playwright.dev/python/docs/intro#installing-playwright) for manual dependency installation.

## Running Tests

### Unit Tests (No app required)

```bash
# From the tests directory
cd tests
pytest -m "not e2e"
```

### E2E Tests (App must be running)

**Important:** E2E tests require the app to be running on `http://127.0.0.1:8080` before running tests.

1. **Start the app** in a separate terminal (from project root):

   ```bash
   # Option 1: Run directly
   cd app
   python app.py

   # Option 2: Or use Docker Compose
   docker compose up
   ```

2. **Wait for the app to start** (check that http://127.0.0.1:8080 is accessible)

3. **Run e2e tests** in another terminal (from tests directory):

   ```bash
   cd tests
   pytest -m "e2e"
   ```

## Code Quality Tools

- **Linting**: `flake8 ../app` (from tests directory)
- **Auto-formatting**: `black ../app` (from tests directory)

## Coverage Reports

Coverage reports are automatically generated when running pytest. View them in the terminal output.
