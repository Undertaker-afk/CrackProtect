# Packer Fixture Matrix

Expected validation targets for `--pack` pipeline:

- `console_app.exe`: smoke test for standard console startup.
- `gui_app.exe`: WinMain and subsystem GUI startup behavior.
- `exceptions_cpp.exe`: heavy C++ exceptions / unwind metadata stress.
- `tls_init.exe`: TLS callback ordering and initialization checks.

Use this folder to store signed-off fixture binaries and expected report snapshots.
