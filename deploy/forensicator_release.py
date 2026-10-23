"""Fetch and verify the native MCP executable from NzSN/Forensicator releases.

Only Python's standard library is required. Downloads and validation happen in
a temporary directory before an installed binary is replaced.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request


REPOSITORY = "NzSN/Forensicator"
RELEASES = f"https://github.com/{REPOSITORY}/releases"
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
REQUIRED_TOOLS = {"inspect", "analyze", "match", "list_plugins"}


class ReleaseError(Exception):
    """A release cannot be safely installed; the existing binary is retained."""


@dataclass
class PreparedRelease:
    binary: Path
    receipt: dict


def download(url, destination, limit):
    """Bound downloads, verify TLS, and never forward local credentials."""
    request = urllib.request.Request(url, headers={"User-Agent": "DumpAnalyzer-deploy"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            total = 0
            with destination.open("wb") as output:
                while chunk := response.read(min(65536, limit - total + 1)):
                    total += len(chunk)
                    if total > limit:
                        raise ReleaseError(f"download exceeds its size limit: {url}")
                    output.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        raise ReleaseError(f"could not download {url}: {error}") from error


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_version(version):
    if version != "latest":
        if not TAG.fullmatch(version):
            raise ReleaseError("--forensicator-version must be latest or a release tag such as v0.0.1")
        return version
    # The public release redirect avoids unauthenticated REST API rate limits.
    # Resolve once, then pin both asset requests to the same version tag.
    request = urllib.request.Request(f"{RELEASES}/latest", headers={"User-Agent": "DumpAnalyzer-deploy"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            location = response.geturl()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        raise ReleaseError(f"could not resolve the latest Forensicator release: {error}") from error
    prefix = f"{RELEASES}/tag/"
    if not location.startswith(prefix) or not TAG.fullmatch(location[len(prefix):]):
        raise ReleaseError("GitHub did not redirect to a supported Forensicator release tag")
    return location[len(prefix):]


def _extract(archive_path, package, directory):
    # Never extract archive paths into the filesystem: read only the three
    # known regular files and write to host-selected paths. Links are refused.
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = []
            for member in archive:
                members.append(member)
                if len(members) > 32:
                    raise ReleaseError("Forensicator archive has too many entries")
            for name, limit in [("forensicator", MAX_BINARY_BYTES), ("BUILD.txt", 4096), ("lean-toolchain", 1024)]:
                found = [member for member in members if member.name == f"{package}/{name}"]
                if len(found) != 1 or not found[0].isfile() or not 0 < found[0].size <= limit:
                    raise ReleaseError(f"Forensicator archive has no unique bounded regular {name}")
                with archive.extractfile(found[0]) as source, (directory / name).open("wb") as output:
                    shutil.copyfileobj(source, output, 65536)
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ReleaseError("Forensicator release archive could not be read") from error


def probe_mcp(binary):
    """Exercise only initialization, discovery and list_plugins; no dump input."""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "dump-analyzer-deploy", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "list_plugins", "arguments": {}}},
    ]
    try:
        completed = subprocess.run(
            [str(binary), "mcp"], input="".join(json.dumps(request) + "\n" for request in requests).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=True,
            cwd=binary.parent, env={"LANG": "C.UTF-8"},
        )
        if len(completed.stdout) > 1024 * 1024:
            raise ValueError("oversized MCP probe output")
        replies = [json.loads(line) for line in completed.stdout.splitlines()]
        if len(replies) != 3 or any(
            reply.get("jsonrpc") != "2.0" or reply.get("id") != index or "error" in reply
            for index, reply in enumerate(replies, 1)
        ):
            raise ValueError("invalid MCP replies")
        if replies[0]["result"]["protocolVersion"] not in {"2025-11-25", "2025-06-18", "2024-11-05"}:
            raise ValueError("unsupported MCP version")
        names = {tool["name"] for tool in replies[1]["result"]["tools"]}
        if not REQUIRED_TOOLS <= names:
            raise ValueError("required MCP tools are missing")
        result = replies[2]["result"]
        if result.get("isError", False):
            raise ValueError("MCP list_plugins failed")
        data = result.get("structuredContent")
        if data is None:
            data = json.loads(result["content"][0]["text"])
        if not isinstance(data["plugins"], list) or not data["plugins"]:
            raise ValueError("no Forensicator plugins")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
        raise ReleaseError("Forensicator release failed its native MCP initialization/discovery probe") from error


def prepare_release(version, directory):
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ReleaseError("Forensicator releases currently support Linux x86-64; use --skip-forensicator on this host")
    tag = resolve_version(version)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    package = f"forensicator-{tag}-linux-x86_64"
    name = f"{package}.tar.gz"
    asset_url = f"{RELEASES}/download/{tag}/{name}"
    archive = directory / name
    checksum = directory / f"{name}.sha256"
    download(f"{asset_url}.sha256", checksum, 4096)
    try:
        checksum_text = checksum.read_text().strip()
    except UnicodeError as error:
        raise ReleaseError("Forensicator checksum is not text") from error
    match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]" + re.escape(name), checksum_text)
    if match is None:
        raise ReleaseError("Forensicator SHA-256 file does not identify the selected archive")
    download(asset_url, archive, MAX_ARCHIVE_BYTES)
    archive_sha = sha256(archive)
    if archive_sha != match[1].lower():
        raise ReleaseError("Forensicator archive SHA-256 mismatch; existing binary was not replaced")
    _extract(archive, package, directory)
    try:
        build = dict(line.split("=", 1) for line in (directory / "BUILD.txt").read_text().splitlines())
        toolchain = (directory / "lean-toolchain").read_text().strip()
        if build.get("tag") != tag or not re.fullmatch(r"[0-9a-f]{40}", build.get("commit", "")) or not toolchain:
            raise ValueError("invalid build identity")
    except (ValueError, UnicodeError) as error:
        raise ReleaseError("Forensicator archive build identity is invalid") from error
    binary = directory / "forensicator"
    with binary.open("rb") as handle:
        header = handle.read(20)
    if not header.startswith(b"\x7fELF\x02\x01") or header[18:20] != b"\x3e\x00":
        raise ReleaseError("Forensicator archive does not contain a Linux x86-64 ELF binary")
    binary.chmod(0o755)
    probe_mcp(binary)
    return PreparedRelease(binary, {
        "repository": REPOSITORY, "tag": tag, "commit": build["commit"],
        "asset": name, "url": asset_url, "archiveSha256": archive_sha,
        "binarySha256": sha256(binary), "leanToolchain": toolchain,
        "mcpProbe": "initialize, tools/list, list_plugins passed",
        "installedAt": datetime.now(timezone.utc).isoformat(),
    })


def _atomic_copy(source, destination, mode):
    descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def install_release(prepared, destination):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.exists() and sha256(destination) != prepared.receipt["binarySha256"]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        shutil.copy2(destination, destination.with_name(f"{destination.name}.bak-{stamp}"))
    _atomic_copy(prepared.binary, destination, 0o755)
    receipt_source = prepared.binary.parent / "forensicator-release.json"
    receipt_source.write_text(json.dumps(prepared.receipt, indent=2) + "\n")
    _atomic_copy(receipt_source, destination.with_name("forensicator-release.json"), 0o600)
