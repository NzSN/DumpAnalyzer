# Deployment assets

Everything needed to take DumpAnalyzer from a built checkout to a supervised
user deployment: the install script, systemd units, environment templates,
and the DSH analyzer adapter. These are deployment assets, not part of the
Rust crate — `cargo` builds only `src/`.

## Contents

| Path | Purpose |
| --- | --- |
| [deploy.py](deploy.py) | Install/refresh the full layout into the user's home (or a staging root). Never overwrites user configuration; never starts or restarts services. |
| [forensicator_release.py](forensicator_release.py) | Fetch, verify and install the native Forensicator MCP binary from GitHub releases. |
| [test_deploy.py](test_deploy.py) | Offline release integrity, MCP probe, staging and configuration-preservation tests. |
| [systemd/dump-analyzer.service](systemd/dump-analyzer.service) | Daemon user unit. |
| [systemd/dump-analyzer-dsh-adapter.service](systemd/dump-analyzer-dsh-adapter.service) | DSH adapter user unit (confined; `dsh-http` provider only). |
| [systemd/environment.example](systemd/environment.example) | Daemon environment template with commented provider blocks (`cdb-ssh`, `dsh-http`). |
| [systemd/dsh-adapter.env.example](systemd/dsh-adapter.env.example) | Adapter environment template (bearer token, optional service-side key fallback). |
| [systemd/prepare-state.py](systemd/prepare-state.py) | `ExecStartPre`: private state directory and demonstrably-stale lock removal. |
| [dsh-adapter/](dsh-adapter/README.md) | `dsh-http` sidecar: the HTTP adapter (`server.mjs`), the zero-tool analyzer profile patch, and the route-table example. |

## Install

```sh
python3 deploy/deploy.py --dry-run          # plan only
python3 deploy/deploy.py                    # live user layout
python3 deploy/deploy.py --root /tmp/stage  # stage under a target directory
python3 deploy/deploy.py --forensicator-version v0.0.1  # pin the Forensicator release
python3 deploy/deploy.py --skip-forensicator           # offline/custom Forensicator
python3 deploy/deploy.py --skip-dsh                    # daemon only; skips Forensicator too
```

DSH deployments download the latest stable
[Forensicator release](https://github.com/NzSN/Forensicator/releases/latest)
by default. The published binary currently targets **Linux x86-64** and is
static; Lean and a Forensicator source checkout are not required. Pin a tag
with `--forensicator-version` to avoid automatic version upgrades. `--no-build` skips
only the Rust build; use `--skip-forensicator` to avoid the download.
`--dry-run` performs no downloads, builds, or MCP probes.

The installer resolves `latest` through GitHub's public release redirect,
then downloads the versioned archive and its `.sha256` file directly. It
does not require an API token or consume the unauthenticated REST API quota.
It verifies the checksum, archive build identity and ELF architecture, then
checks native MCP initialization, tool discovery, and `list_plugins` before
changing installed files. Missing assets, download failures, checksum errors,
unsupported platforms and failed MCP probes stop deployment with a nonzero
exit status. Use `--skip-forensicator` when supplying your own executable.

The verified executable is installed atomically at
`~/.local/libexec/dump-analyzer/forensicator`. A replaced binary is backed up
with a dated suffix. The adjacent `forensicator-release.json` records the
release tag, source commit, archive/binary SHA-256, Lean toolchain and MCP
probe result. These are managed deployment assets, separate from user config.

The environment template points at that installed executable. Existing user
configuration is preserved, and tool use stays opt-in: set
`DUMP_ANALYZER_FORENSICATOR_BIN` to its absolute path and enable the existing
authenticated DSH MCP settings. See the
[Forensicator guide](../docs/dsh-http-guide.md#forensicator-mcp-tools). Change
the analyzer version when upgrading the forensic capture profile.

## Where things land

| Kind | Location | Examples |
| --- | --- | --- |
| Binaries/scripts | `~/.local/bin`, `~/.local/libexec/dump-analyzer/` | daemon, adapter, helpers, Forensicator and its release receipt |
| Units | `~/.config/systemd/user/` | both services |
| Configuration (user-authored, 0600) | `~/.config/dump-analyzer/` | `environment`, `dsh-adapter.env`, `dsh-routes.json` |
| State (runtime-produced) | `~/.local/state/` | analyzer state store, the dedicated DSH home |

Configuration templates in this directory ship placeholders only; real
endpoints, tokens, and keys live in the config home and are never committed
to this repository.

## Verify deployment changes

```sh
python3 -B -m unittest discover -s deploy -p 'test_*.py' -v
python3 deploy/deploy.py --root /tmp/stage --forensicator-version v0.0.1
FORENSICATOR_TEST_BIN=/tmp/stage/.local/libexec/dump-analyzer/forensicator \
  cargo test --offline --locked --test forensicator native_forensicator_mcp -- --ignored
```

The Python tests use controlled downloads and subprocesses. The staged install
downloads and probes the real release; the optional Rust test uses generated
minidump/PDB files and the real binary through the MCP bridge. Neither starts
production services or sends dump evidence to an external model.

## Rules for editing these assets

- Templates carry `replace-with-…` placeholders, never real credentials or
  endpoints.
- `deploy.py` keeps existing user configuration by default; new template
  fields must land in the templates, not in deployed files.
- Changing a unit's paths or environment requires `systemctl --user
  daemon-reload` on deployed hosts; the script does this in the live layout.
- The DSH adapter and its profile patch are documented in
  [dsh-adapter/README.md](dsh-adapter/README.md); the full provider guide is
  [docs/dsh-http-guide.md](../docs/dsh-http-guide.md).
