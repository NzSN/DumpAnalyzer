# Deployment assets

Everything needed to take DumpAnalyzer from a built checkout to a supervised
user deployment: the install script, systemd units, environment templates,
and the DSH analyzer adapter. These are deployment assets, not part of the
Rust crate — `cargo` builds only `src/`.

## Contents

| Path | Purpose |
| --- | --- |
| [deploy.py](deploy.py) | Install/refresh the full layout into the user's home (or a staging root). Never overwrites user configuration; never starts or restarts services. |
| [systemd/dump-analyzer.service](systemd/dump-analyzer.service) | Daemon user unit. |
| [systemd/dump-analyzer-dsh-adapter.service](systemd/dump-analyzer-dsh-adapter.service) | DSH adapter user unit (confined; `dsh-http` provider only). |
| [systemd/environment.example](systemd/environment.example) | Daemon environment template with commented provider blocks (`cdb-ssh`, `claude-cdb`, `dsh-http`). |
| [systemd/dsh-adapter.env.example](systemd/dsh-adapter.env.example) | Adapter environment template (bearer token, optional service-side key fallback). |
| [systemd/prepare-state.py](systemd/prepare-state.py) | `ExecStartPre`: private state directory and demonstrably-stale lock removal. |
| [systemd/claude-with-settings.py](systemd/claude-with-settings.py) | `claude-cdb` adapter launching the Claude CLI with connection/model settings and tool restrictions. |
| [dsh-adapter/](dsh-adapter/README.md) | `dsh-http` sidecar: the HTTP adapter (`server.mjs`), the zero-tool analyzer profile patch, and the route-table example. |

## Install

```sh
python3 deploy/deploy.py --dry-run          # plan only
python3 deploy/deploy.py                    # live user layout
python3 deploy/deploy.py --root /tmp/stage  # stage under a target directory
```

## Where things land

| Kind | Location | Examples |
| --- | --- | --- |
| Binaries/scripts | `~/.local/bin`, `~/.local/libexec/dump-analyzer/` | daemon, adapter, helpers |
| Units | `~/.config/systemd/user/` | both services |
| Configuration (user-authored, 0600) | `~/.config/dump-analyzer/` | `environment`, `dsh-adapter.env`, `dsh-routes.json` |
| State (runtime-produced) | `~/.local/state/` | analyzer state store, the dedicated DSH home |

Configuration templates in this directory ship placeholders only; real
endpoints, tokens, and keys live in the config home and are never committed
to this repository.

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
