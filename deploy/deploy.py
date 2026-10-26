#!/usr/bin/python3
"""Deploy DumpAnalyzer (daemon + optional DSH adapter) into a target layout.

Default layout is the real user deployment; --root redirects every path
under a staging directory (e.g. --root /tmp/stage for inspection):

  <root>/.local/bin/dump-analyzer                    release binary
  <root>/.local/libexec/dump-analyzer/...            helper scripts, adapter
  <root>/.local/libexec/dump-analyzer/forensicator    verified GitHub release
  <root>/.config/systemd/user/*.service              user units
  <root>/.config/dump-analyzer/                      environment, dsh-adapter.env,
                                                     dsh-routes.json (user config)
  <root>/.local/state/dsh-analyzer/                  dedicated DSH home

User-authored configuration is never overwritten: existing environment,
dsh-adapter.env, dsh-routes.json, and an installed analyzer profile patch
are kept unless --force-config is given. The script never starts, stops,
enables, or restarts services; it prints the remaining manual steps.

Usage:
  python3 deploy/deploy.py [--root DIR] [--no-build] [--skip-dsh] [--dry-run]
                           [--force-config] [--skip-forensicator]
                           [--forensicator-version latest|TAG]
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from forensicator_release import ReleaseError, install_release, prepare_release

REPO = Path(__file__).resolve().parent.parent
SYSTEMD = REPO / "deploy" / "systemd"
ADAPTER = REPO / "deploy" / "dsh-adapter"


class Plan:
    """Collects actions; --dry-run prints without mutating."""

    def __init__(self, dry_run):
        self.dry_run = dry_run
        self.notes = []

    def note(self, message):
        print(f"  note: {message}")
        self.notes.append(message)

    def run(self, description, fn):
        print(f"  {'would ' if self.dry_run else ''}{description}")
        if not self.dry_run:
            return fn()

    def install(self, source, target, mode):
        def apply():
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, mode)

        self.run(f"install {source.name} -> {target} (mode {mode:o})", apply)

    def write(self, target, text, mode):
        def apply():
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if target.exists():
                target.write_text(text)
            else:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
                with os.fdopen(fd, "w") as handle:
                    handle.write(text)

        self.run(f"write {target} (mode {mode:o})", apply)


def load_template(path, substitutions):
    text = Path(path).read_text()
    for name, value in substitutions.items():
        text = text.replace(name, value)
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None,
                        help="staging root; default is the real user layout ($HOME)")
    parser.add_argument("--no-build", action="store_true",
                        help="reuse the existing target/release binary")
    parser.add_argument("--skip-dsh", action="store_true",
                        help="deploy only the daemon; skip the DSH adapter, its profile, and Forensicator")
    parser.add_argument("--skip-forensicator", action="store_true",
                        help="skip the GitHub release download (offline/custom executable deployment)")
    parser.add_argument("--forensicator-version", default="latest", metavar="TAG",
                        help="Forensicator release tag to pin; default is the latest stable release")
    parser.add_argument("--force-config", action="store_true",
                        help="overwrite existing user configuration (default keeps it)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the planned actions without changing anything")
    args = parser.parse_args(argv)

    if os.geteuid() == 0:
        print("refusing to run as root: the units are user services", file=sys.stderr)
        return 2
    try:
        if args.dry_run:
            return deploy(args, None)
        with tempfile.TemporaryDirectory(prefix="dump-analyzer-deploy-") as temporary:
            return deploy(args, Path(temporary))
    except (ReleaseError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def deploy(args, temporary):
    home = Path.home()
    root = args.root.expanduser().resolve() if args.root else None

    def at(relative):
        """Map a real-layout absolute path into the staging root.

        Paths under $HOME land at <root>/<home-relative>; anything else at
        <root>/<absolute-relative>.
        """
        relative = Path(relative)
        if root is None:
            return relative
        try:
            return root / relative.relative_to(home)
        except ValueError:
            return root / relative.relative_to("/")

    paths = {
        "bin": at(home / ".local/bin/dump-analyzer"),
        "libexec": at(home / ".local/libexec/dump-analyzer"),
        "units": at(home / ".config/systemd/user"),
        "config": at(home / ".config/dump-analyzer"),
        "dsh_home": at(home / ".local/state/dsh-analyzer"),
        "forensicator": at(home / ".local/libexec/dump-analyzer/forensicator"),
    }
    plan = Plan(args.dry_run)
    print(f"deploy root: {root if root else '(live user layout)'}")

    # Fetch and qualify before changing installed files. Dry runs never make
    # network requests, invoke a release binary, or create temporary files.
    with_forensicator = not args.skip_dsh and not args.skip_forensicator
    prepared = None
    if with_forensicator:
        prepared = plan.run(
            f"fetch Forensicator {args.forensicator_version} from GitHub; verify SHA-256 and probe native MCP",
            lambda: prepare_release(args.forensicator_version, temporary / "forensicator"),
        )

    # 1. Release binary -------------------------------------------------
    binary = REPO / "target/release/dump-analyzer"
    if not args.no_build:
        def build():
            subprocess.run(["cargo", "build", "--release", "--offline", "--locked"], cwd=REPO, check=True)
        plan.run("cargo build --release --offline --locked", build)
    if not binary.exists() and not args.dry_run:
        print("error: release binary missing; build first or drop --no-build", file=sys.stderr)
        return 1
    if binary.exists():
        if paths["bin"].exists():
            import hashlib
            current = hashlib.sha256(paths["bin"].read_bytes()).hexdigest()
            fresh = hashlib.sha256(binary.read_bytes()).hexdigest()
            if current != fresh:
                backup = paths["bin"].with_name(
                    paths["bin"].name + ".bak-" + __import__("time").strftime("%Y%m%d")
                )
                plan.run(f"back up existing binary -> {backup.name}",
                         lambda: shutil.copy2(paths["bin"], backup))
        plan.install(binary, paths["bin"], 0o755)

    if with_forensicator:
        tag = prepared.receipt["tag"] if prepared else args.forensicator_version
        plan.run(f"install Forensicator {tag} -> {paths['forensicator']} (mode 755) and release receipt",
                 lambda: install_release(prepared, paths["forensicator"]))

    # 2. Helper scripts and units --------------------------------------
    plan.install(SYSTEMD / "prepare-state.py", paths["libexec"] / "prepare-state.py", 0o755)
    plan.install(SYSTEMD / "dump-analyzer.service", paths["units"] / "dump-analyzer.service", 0o644)

    # 3. Daemon environment template (never clobber user config) --------
    env_target = paths["config"] / "environment"
    if env_target.exists() and not args.force_config:
        plan.note(f"kept existing {env_target}")
    else:
        plan.write(env_target, load_template(SYSTEMD / "environment.example", {
            "/home/lsz/.local/libexec/dump-analyzer/forensicator": str(paths["forensicator"]),
        }), 0o600)

    # 4. DSH adapter (optional) -----------------------------------------
    if not args.skip_dsh:
        dsh = shutil.which("dsh")
        plan.install(ADAPTER / "server.mjs", paths["libexec"] / "dsh-adapter/server.mjs", 0o644)
        plan.install(SYSTEMD / "dump-analyzer-dsh-adapter.service",
                     paths["units"] / "dump-analyzer-dsh-adapter.service", 0o644)
        for name, template in [
            ("dsh-adapter.env", SYSTEMD / "dsh-adapter.env.example"),
            ("dsh-routes.json", ADAPTER / "routes.example.json"),
        ]:
            target = paths["config"] / name
            if target.exists() and not args.force_config:
                plan.note(f"kept existing {target}")
            else:
                plan.write(target, load_template(template, {}), 0o600)

        profile_patch = paths["dsh_home"] / "profiles/analyzer/cordis.patch.yml"
        if profile_patch.exists() and not args.force_config:
            plan.note(f"kept existing analyzer profile patch {profile_patch}")
        else:
            if dsh is None:
                plan.note("dsh CLI not found in PATH; skipping profile creation "
                          "(install @deepseek-ai/dsh, then rerun)")
            else:
                def create_profile():
                    paths["dsh_home"].mkdir(mode=0o700, parents=True, exist_ok=True)
                    env = dict(os.environ, DSH_HOME=str(paths["dsh_home"]))
                    subprocess.run(
                        [dsh, "--profile", "analyzer", "--from-default-profile", "headless",
                         "--dump-config"],
                        cwd=paths["dsh_home"], env=env, check=True,
                        stdout=subprocess.DEVNULL,
                    )
                plan.run(f"create headless-derived analyzer profile in {paths['dsh_home']}",
                         create_profile)
                plan.install(ADAPTER / "analyzer-cordis.patch.yml", profile_patch, 0o600)

    # 5. systemd reload (best effort) -----------------------------------
    if root is None and shutil.which("systemctl"):
        def reload():
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        plan.run("systemctl --user daemon-reload", reload)
    else:
        plan.note("staging root or missing systemctl: skipping daemon-reload")

    # 6. Remaining manual steps ------------------------------------------
    print("\nremaining manual steps:")
    print("  1. fill secrets in ~/.config/dump-analyzer/environment and dsh-adapter.env")
    print("     (and edit dsh-routes.json: it ships placeholder gateways only)")
    if with_forensicator:
        print("     To enable Forensicator in the DSH reasoner, set in the daemon environment:")
        print("       DUMP_ANALYZER_DSH_TOOLS=on")
        print(f"       DUMP_ANALYZER_FORENSICATOR_BIN={paths['forensicator']}")
        print("     Enable DSH_ANALYZER_ALLOW_MCP=on in dsh-adapter.env with matching adapter tokens.")
        print("     Choose a distinct DUMP_ANALYZER_VERSION when changing the Forensicator build.")
    if not args.skip_dsh:
        print("  2. systemctl --user enable --now dump-analyzer-dsh-adapter")
        print("  3. systemctl --user restart dump-analyzer")
    else:
        print("  2. systemctl --user restart dump-analyzer")
    print("  verify: journalctl --user -u <unit> -n 20")
    return 0


if __name__ == "__main__":
    sys.exit(main())
