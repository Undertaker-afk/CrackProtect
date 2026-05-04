# Product Layer Overview

The user-facing product layer is centered around the GUI sample (`examples/ilgui.cpp`) and project-file driven automation.

## GUI capabilities

- Drag-and-drop binaries directly into the target list.
- Profile editor (`json`/`toml`/`yaml` compatible paths).
- Per-function rule list to model virtualization/obfuscation decisions.
- Batch workflow controls:
  - Save project files for repeatable runs.
  - Export CI-ready command lines.

## Report generation

The project file and command export support three report classes:

- **Protection coverage report** (virtualization/obfuscation/packing coverage).
- **Compatibility report** (OS/runtime/toolchain checks).
- **Performance delta report** (startup and runtime overhead).

## Export formats

GUI options emit command switches for:

- HTML summary (`--export-html`)
- PDF summary (`--export-pdf`)
- JSON artifacts (`--export-json`)

## Failure diagnostics

Failure diagnostics are encoded as:

- `structured-with-hints`

This is intended for machine parsing and remediation guidance in CI logs.
