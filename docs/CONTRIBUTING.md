# Contributing

Thank you for considering contributing to Zenith Passkeys!

## Development Setup

```bash
# Clone the repo
git clone https://github.com/user/zenith-passkeys.git
cd zenith-passkeys

# Install in development mode with dev dependencies
pip install -e ./cli[dev]
```

## Project Structure

```
projectwarden/
├── cli/                          # Python package
│   ├── pyproject.toml            # Package config
│   ├── src/zenith_passkeys/      # Source code
│   │   ├── main.py               # CLI entry point (Click)
│   │   ├── core/                 # Core library
│   │   │   ├── crypto.py         # Argon2id KDF + AES-256-GCM
│   │   │   ├── vault.py          # Vault file operations
│   │   │   ├── schema.py         # Data models (Credential, Settings)
│   │   │   ├── credentials.py    # Credential CRUD operations
│   │   │   ├── webauthn.py       # WebAuthn response generation
│   │   │   ├── recovery.py       # Recovery key generation/parsing
│   │   │   └── paths.py          # Platform-specific paths
│   │   ├── commands/             # CLI commands
│   │   ├── native_host/          # Native messaging host
│   │   │   ├── host.py           # Main host process
│   │   │   ├── protocol.py       # Length-prefixed JSON protocol
│   │   │   └── manifest.py       # Native host manifest registration
│   │   └── backup/               # Cloud backup providers
│   └── tests/                    # Unit tests
├── extension/                    # Browser extension (vanilla JS)
│   ├── manifest.json             # Extension manifest (MV3)
│   ├── background.js             # Service worker
│   ├── content-main.js           # WebAuthn interception (MAIN world)
│   ├── content-isolated.js       # Message relay (ISOLATED world)
│   ├── fallback-vault.js         # Browser-only vault mode
│   ├── native-client.js          # Native messaging client
│   ├── confirm.html/js           # WebAuthn confirmation dialog
│   └── popup/                    # Extension popup UI
└── docs/                         # Documentation
```

## Code Style

- **Python:** Use [ruff](https://github.com/astral-sh/ruff) for linting and formatting
- **JavaScript:** Standard JS style, no build tools, no frameworks
- **Type hints:** Required for Python public APIs, not for JS

```bash
# Lint Python
ruff check cli/src/

# Format Python
ruff format cli/src/
```

## Testing

```bash
# Run all tests
pytest cli/tests/ -v

# Run with coverage
pytest cli/tests/ -v --cov=zenith_passkeys --cov-report=term-missing

# Run specific test file
pytest cli/tests/test_vault.py -v
```

## Security Guidelines

This is a security-sensitive project. Please follow these rules:

1. **Never log private keys, MEK, or derived keys**
2. **Never make network calls** outside explicit backup commands
3. **Always use atomic file writes** (`.tmp` + `os.replace()`)
4. **Always zero-fill sensitive byte arrays** after use
5. **Validate all input** — especially from native messaging and imports
6. **Use `os.urandom()`** for all random number generation
7. **Treat extension messages as untrusted** — validate rpId against origin

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Run the test suite to ensure nothing is broken
4. Update documentation if needed
5. Submit a PR with a clear description of the changes

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
