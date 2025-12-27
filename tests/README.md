# Testing CredShare

## Setup

1. **Install test requirements** (from project root):
   ```powershell
   pip install -r tests\requirements-tests.txt
   ```

2. **Install Playwright browsers** (REQUIRED for e2e tests):
   ```powershell
   playwright install
   ```

   **Note:** This downloads browser binaries (Chromium, Firefox, WebKit) which are required for e2e tests. On Windows, this may take a few minutes.

## Running Tests

### Unit Tests (No app required)
```powershell
# From the tests directory
cd tests
pytest -m "not e2e"
```

### E2E Tests (App must be running)

**Important:** E2E tests require the app to be running on `http://127.0.0.1:8080` before running tests.

1. **Start the app** in a separate terminal (from project root):
   ```powershell
   # Option 1: Run directly
   cd app
   python app.py

   # Option 2: Or use Docker Compose
   docker compose up
   ```

2. **Wait for the app to start** (check that http://127.0.0.1:8080 is accessible)

3. **Run e2e tests** in another terminal (from tests directory):
   ```powershell
   cd tests
   pytest -m "e2e"
   ```

## Code Quality Tools

- **Linting**: `flake8 ../app` (from tests directory)
- **Auto-formatting**: `black ../app` (from tests directory)

## Coverage Reports

Coverage reports are automatically generated when running pytest. View them in the terminal output.
