# Contributing to ShipGuard

Thanks for your interest in contributing! Here's how to get started.

## Prerequisites

- Python 3.10+
- `pip` or `pipx`

## Setup

```bash
git clone https://github.com/artificemachine/shipguard.git
cd shipguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Development workflow

1. **Fork** the repo and create a branch from `main`.
2. Make your changes in `src/shipguard/`.
3. Run tests: `pytest`
4. Run ShipGuard on itself: `shipguard scan .`
5. Open a Pull Request against `main`.

## What to contribute

- New vulnerability detection rules
- Bug fixes (check open issues)
- Support for additional languages or file types
- Tests and documentation fixes

Issues labeled `good first issue` or `help wanted` are a great starting point.

## Code conventions

- Python with type hints
- Tests use `pytest`
- Follow existing rule pattern structure in `src/shipguard/`

## Commit messages

Keep commits focused. Use a short summary line describing what changed and why.

## Reporting bugs

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Output of `shipguard scan .` on the affected repo
- Python version (`python --version`)

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
