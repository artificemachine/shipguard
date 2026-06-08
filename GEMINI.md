# ShipGuard — Gemini Context

ShipGuard is a SAST tool implementing a unified 7-layer security framework for repositories.

## 🎯 Project Overview
- **Purpose:** Static security analysis for Python, Shell, JS/TS, GHA, and Config files.
- **Stack:** Python 3.10+, Rust (secrets scanner).

## 🛠 Building and Running

### Setup & Build
- **Install Dev:** `pip install -e ".[dev]"`
- **Build Rust:** `cd rust/shipguard-secrets && cargo build --release`
- **Build Package:** `hatch build`

### Quality & Testing
- **Test:** `pytest tests/`
- **Security Pipeline:** `make security`
- **Staged Scan:** `shipguard scan-staged`

## 📏 Operational Rules
- **Rule Dev:** Rules must return `Finding` objects and map to CWE IDs.
- **Test Fixtures:** Intentionally vulnerable code in `tests/fixtures/` must not be "fixed".
- **Decoupling:** Binary must not depend on local repo path once installed.

## 🤝 Workspace Conventions
- **CHANGELOG.md:** Append-only, required per commit.
- **Task Lifecycle:** todo → plan_proposed → plan_approved → in_progress → report_ready → review_requested → review_passed → done.
- **Task Management:** Use `shux` for all task coordination.
- **Handoffs:** Write via `shux handoff-write`.
