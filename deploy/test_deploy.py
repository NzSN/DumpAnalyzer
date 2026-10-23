"""Offline deployment regression tests; no GitHub or live service access.

Run: python3 -B -m unittest discover -s deploy -p 'test_*.py' -v
"""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import deploy
import forensicator_release as release


VERSION = "v0.0.1"
PACKAGE = f"forensicator-{VERSION}-linux-x86_64"
ASSET = f"{PACKAGE}.tar.gz"
ASSET_URL = f"{release.RELEASES}/download/{VERSION}/{ASSET}"
ELF = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + b"synthetic binary"


def archive_bytes(overrides=None, symlink=False, traversal=False):
    entries = {
        "forensicator": ELF,
        "BUILD.txt": f"tag={VERSION}\ncommit={'a' * 40}\n".encode(),
        "lean-toolchain": b"leanprover/lean4:v4.33.0\n",
    }
    entries.update(overrides or {})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(f"{PACKAGE}/{name}")
            if symlink and name == "forensicator":
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        if traversal:
            member = tarfile.TarInfo("../escaped")
            member.size = 6
            archive.addfile(member, io.BytesIO(b"escape"))
    return output.getvalue()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = archive_bytes()
        self.checksum_override = None
        self.requested = []
        self.probe = self.enterContext(patch.object(release, "probe_mcp"))
        self.enterContext(patch.object(release, "download", side_effect=self.fetch))
        self.enterContext(patch.object(release.platform, "system", return_value="Linux"))
        self.enterContext(patch.object(release.platform, "machine", return_value="x86_64"))

    def fetch(self, url, destination, limit):
        self.requested.append(url)
        checksum = f"{hashlib.sha256(self.archive).hexdigest()}  {ASSET}\n".encode()
        blobs = {ASSET_URL: self.archive, ASSET_URL + ".sha256": self.checksum_override or checksum}
        data = blobs[url]
        self.assertLessEqual(len(data), limit)
        destination.write_bytes(data)

    def prepare(self):
        return release.prepare_release(VERSION, self.root / "download")

    def test_pinned_release_verifies_probes_and_installs_with_receipt_and_backup(self):
        with patch.object(release.urllib.request, "urlopen", side_effect=AssertionError("pinned tags do not need the API")):
            prepared = self.prepare()
        self.assertEqual(self.requested, [ASSET_URL + ".sha256", ASSET_URL])
        self.probe.assert_called_once_with(prepared.binary)
        destination = self.root / "installed" / "forensicator"
        destination.parent.mkdir()
        destination.write_bytes(b"old binary")
        release.install_release(prepared, destination)
        self.assertEqual(destination.read_bytes(), ELF)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
        backups = list(destination.parent.glob("forensicator.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"old binary")
        receipt_path = destination.with_name("forensicator-release.json")
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["tag"], VERSION)
        self.assertEqual(receipt["commit"], "a" * 40)
        self.assertEqual(receipt["archiveSha256"], hashlib.sha256(self.archive).hexdigest())
        self.assertEqual(receipt["binarySha256"], hashlib.sha256(ELF).hexdigest())
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        release.install_release(prepared, destination)
        self.assertEqual(list(destination.parent.glob("forensicator.bak-*")), backups)

    def test_checksum_mismatch_prevents_execution(self):
        self.checksum_override = f"{'0' * 64}  {ASSET}\n".encode()
        with self.assertRaisesRegex(release.ReleaseError, "SHA-256 mismatch"):
            self.prepare()
        self.probe.assert_not_called()

    def test_checksum_must_identify_exactly_one_selected_archive(self):
        for text in [f"{'a' * 64}  other.tar.gz\n", f"{'a' * 64}  {ASSET}\n{'b' * 64}  {ASSET}\n", "not a checksum"]:
            with self.subTest(text=text):
                self.checksum_override = text.encode()
                with self.assertRaisesRegex(release.ReleaseError, "SHA-256 file"):
                    self.prepare()
        self.probe.assert_not_called()

    def test_archive_links_are_rejected_and_extra_paths_are_never_extracted(self):
        self.archive = archive_bytes(symlink=True)
        with self.assertRaisesRegex(release.ReleaseError, "regular forensicator"):
            self.prepare()
        self.probe.assert_not_called()
        self.archive = archive_bytes(traversal=True)
        self.prepare()
        self.assertFalse((self.root / "escaped").exists())

    def test_build_identity_architecture_and_archive_bounds_are_checked(self):
        for overrides, expected in [
            ({"BUILD.txt": b"tag=v9.9.9\ncommit=unknown\n"}, "build identity"),
            ({"forensicator": b"not an ELF"}, "ELF binary"),
        ]:
            with self.subTest(expected=expected):
                self.archive = archive_bytes(overrides)
                with self.assertRaisesRegex(release.ReleaseError, expected):
                    self.prepare()
        self.archive = archive_bytes()
        with patch.object(release, "MAX_BINARY_BYTES", 10):
            with self.assertRaisesRegex(release.ReleaseError, "bounded regular"):
                self.prepare()
        self.probe.assert_not_called()

    def test_unsupported_host_and_invalid_tag_fail_before_download(self):
        with patch.object(release.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(release.ReleaseError, "Linux x86-64"):
                self.prepare()
        for version in ["main", "v0/../../secret", "v0.0.1\n"]:
            with self.assertRaises(release.ReleaseError):
                release.prepare_release(version, self.root / "invalid")
        self.assertEqual(self.requested, [])

    def test_failed_mcp_probe_prevents_a_prepared_release(self):
        self.probe.side_effect = release.ReleaseError("MCP unavailable")
        with self.assertRaisesRegex(release.ReleaseError, "MCP unavailable"):
            self.prepare()


class NetworkAndProbeTests(unittest.TestCase):
    def test_latest_uses_the_public_release_redirect_and_validates_its_target(self):
        with patch.object(release.urllib.request, "urlopen") as open_url:
            response = open_url.return_value.__enter__.return_value
            response.geturl.return_value = f"{release.RELEASES}/tag/{VERSION}"
            self.assertEqual(release.resolve_version("latest"), VERSION)
            self.assertEqual(open_url.call_args.args[0].full_url, f"{release.RELEASES}/latest")
            response.read.assert_not_called()
            for location in ["https://elsewhere.example/tag/v0.0.1", f"{release.RELEASES}/tag/main"]:
                response.geturl.return_value = location
                with self.assertRaises(release.ReleaseError):
                    release.resolve_version("latest")

    def test_download_stops_at_its_size_limit_and_reports_http_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "asset"
            with patch.object(release.urllib.request, "urlopen", return_value=io.BytesIO(b"x" * 100)):
                with self.assertRaisesRegex(release.ReleaseError, "size limit"):
                    release.download(ASSET_URL, target, 32)
            self.assertLessEqual(target.stat().st_size, 32)
            with patch.object(release.urllib.request, "urlopen", side_effect=urllib.error.HTTPError(ASSET_URL, 404, "not found", {}, None)):
                with self.assertRaisesRegex(release.ReleaseError, "404"):
                    release.download(ASSET_URL, target, 32)

    def test_probe_checks_real_mcp_contract_without_dump_or_inherited_credentials(self):
        results = [
            {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}},
            {"tools": [{"name": name} for name in release.REQUIRED_TOOLS]},
            {"isError": False, "structuredContent": {"plugins": [{"name": "cause"}]}},
        ]
        def output():
            return b"".join(json.dumps({"jsonrpc": "2.0", "id": i, "result": result}).encode() + b"\n" for i, result in enumerate(results, 1))
        with patch.object(release.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, output())
            release.probe_mcp(Path("/tmp/forensicator"))
            requests = [json.loads(line) for line in run.call_args.kwargs["input"].splitlines()]
            self.assertEqual([request["method"] for request in requests], ["initialize", "notifications/initialized", "tools/list", "tools/call"])
            self.assertEqual(requests[3]["params"], {"name": "list_plugins", "arguments": {}})
            self.assertEqual(run.call_args.kwargs["env"], {"LANG": "C.UTF-8"})
            results[1] = {"tools": []}
            run.return_value = subprocess.CompletedProcess([], 0, output())
            with self.assertRaisesRegex(release.ReleaseError, "MCP initialization/discovery"):
                release.probe_mcp(Path("/tmp/forensicator"))
            run.side_effect = subprocess.TimeoutExpired("forensicator", 15)
            with self.assertRaises(release.ReleaseError):
                release.probe_mcp(Path("/tmp/forensicator"))


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        binary = self.repo / "target/release/dump-analyzer"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"test daemon")
        self.enterContext(patch.object(deploy, "REPO", self.repo))
        self.enterContext(patch.object(deploy.os, "geteuid", return_value=1000))
        self.enterContext(patch.object(deploy.shutil, "which", return_value=None))
        self.stdout = io.StringIO()
        self.enterContext(redirect_stdout(self.stdout))
        self.enterContext(redirect_stderr(io.StringIO()))
        self.stage = self.root / "stage"

    def main(self, *flags):
        return deploy.main(["--root", str(self.stage), "--no-build", *flags])

    def test_dry_run_has_no_network_build_execution_or_filesystem_writes(self):
        with patch.object(deploy, "prepare_release") as prepare, patch.object(deploy, "install_release") as install, patch.object(deploy.tempfile, "TemporaryDirectory", side_effect=AssertionError("dry run created temporary files")):
            self.assertEqual(self.main("--dry-run"), 0)
            prepare.assert_not_called()
            install.assert_not_called()
        self.assertFalse(self.stage.exists())
        self.assertIn("would fetch Forensicator latest", self.stdout.getvalue())

    def test_download_failure_keeps_existing_daemon_and_configuration(self):
        binary = self.stage / ".local/bin/dump-analyzer"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"old daemon")
        env = self.stage / ".config/dump-analyzer/environment"
        env.parent.mkdir(parents=True)
        env.write_text("operator configuration")
        with patch.object(deploy, "prepare_release", side_effect=release.ReleaseError("bad checksum")):
            self.assertEqual(self.main(), 1)
        self.assertEqual(binary.read_bytes(), b"old daemon")
        self.assertEqual(env.read_text(), "operator configuration")

    def test_staging_installs_release_and_preserves_existing_configuration(self):
        prepared_bin = self.root / "prepared-forensicator"
        prepared_bin.write_bytes(ELF)
        prepared = release.PreparedRelease(prepared_bin, {"tag": VERSION, "binarySha256": hashlib.sha256(ELF).hexdigest()})
        with patch.object(deploy, "prepare_release", return_value=prepared) as prepare:
            self.assertEqual(self.main("--forensicator-version", VERSION), 0)
            self.assertEqual(prepare.call_args.args[0], VERSION)
            installed = self.stage / ".local/libexec/dump-analyzer/forensicator"
            self.assertEqual(installed.read_bytes(), ELF)
            env = self.stage / ".config/dump-analyzer/environment"
            self.assertIn(f"# DUMP_ANALYZER_FORENSICATOR_BIN={installed}", env.read_text())
            env.write_text("operator daemon config")
            adapter = env.with_name("dsh-adapter.env")
            adapter.write_text("operator adapter config")
            self.assertEqual(self.main(), 0)
            self.assertEqual(env.read_text(), "operator daemon config")
            self.assertEqual(adapter.read_text(), "operator adapter config")

    def test_skip_flags_avoid_downloads(self):
        for flag in ["--skip-forensicator", "--skip-dsh"]:
            with self.subTest(flag=flag), patch.object(deploy, "prepare_release") as prepare:
                self.assertEqual(self.main(flag), 0)
                prepare.assert_not_called()
        self.assertFalse((self.stage / ".local/libexec/dump-analyzer/forensicator").exists())


if __name__ == "__main__":
    unittest.main()
