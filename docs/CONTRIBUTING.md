# Contributing

## Development Setup

```bash
pip install -e ./cli[dev]
```

## Code Style

- Python: ruff for linting
- JavaScript: Standard JS style (no build tools)
- No type annotations for JS files

## Testing

```bash
pytest cli/tests/ -v
```

## Project Structure

- `cli/` — Python package (CLI + native host + core library)
- `extension/` — Browser extension (vanilla JS, no build step)

## Security

- Never log private keys, MEK, or derived keys
- Never make network calls outside explicit backup commands
- Always use atomic file writes (`.tmp` + `os.replace()`)
