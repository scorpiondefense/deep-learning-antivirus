"""Malware sample acquisition.

- Malware (~100): MalwareBazaar REST API (abuse.ch) - query by file type, download password-protected zips
- Benign (~100): System binaries from /usr/bin + /usr/local/bin (platform-aware collection)
- All samples stored with hash-based filenames, manifest tracking
"""

import hashlib
import io
import json
import os
import platform
import shutil
from pathlib import Path

import pyzipper
import requests

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _get_api_headers() -> dict:
    """Get API headers, including Auth-Key if set via environment variable."""
    headers = {}
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY", "")
    if api_key:
        headers["Auth-Key"] = api_key
    return headers


def download_malware_samples(
    output_dir: str,
    count: int = 100,
    file_type: str = "exe",
) -> list[dict]:
    """Download malware samples from MalwareBazaar.

    Set MALWAREBAZAAR_API_KEY env var for authenticated access.
    Falls back to unauthenticated get_recent query if no key is set.
    """
    os.makedirs(output_dir, exist_ok=True)
    manifest = []
    headers = _get_api_headers()

    print(f"[*] Querying MalwareBazaar for {count} '{file_type}' samples...")
    if not headers.get("Auth-Key"):
        print("[*] No MALWAREBAZAAR_API_KEY set, using unauthenticated get_recent endpoint")

    # Try get_recent (works without auth key)
    try:
        response = requests.post(
            MALWAREBAZAAR_API,
            data={"query": "get_recent", "selector": str(min(count, 1000))},
            headers=headers,
            timeout=60,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] API query failed: {e}")
        return manifest

    if result.get("query_status") != "ok":
        print(f"[!] Query status: {result.get('query_status', 'unknown')}")
        return manifest

    samples = result.get("data", [])
    print(f"[*] Got {len(samples)} sample metadata entries")

    downloaded = 0
    for sample in samples:
        sha256 = sample.get("sha256_hash", "")
        if not sha256:
            continue

        out_path = os.path.join(output_dir, sha256)
        if os.path.exists(out_path):
            manifest.append({"sha256": sha256, "source": "malwarebazaar", "path": out_path})
            downloaded += 1
            continue

        try:
            dl_resp = requests.post(
                MALWAREBAZAAR_API,
                data={"query": "get_file", "sha256_hash": sha256},
                headers=headers,
                timeout=120,
            )
            dl_resp.raise_for_status()

            # Response is a password-protected zip (uses AES encryption)
            zip_data = io.BytesIO(dl_resp.content)
            with pyzipper.AESZipFile(zip_data) as zf:
                names = zf.namelist()
                if not names:
                    continue
                file_data = zf.read(names[0], pwd=ZIP_PASSWORD)

            # Verify hash
            actual_hash = _sha256(file_data)
            if actual_hash != sha256:
                print(f"[!] Hash mismatch for {sha256[:16]}...")
                continue

            with open(out_path, "wb") as f:
                f.write(file_data)

            manifest.append({"sha256": sha256, "source": "malwarebazaar", "path": out_path})
            downloaded += 1
            print(f"  [{downloaded}/{count}] Downloaded {sha256[:16]}...")

        except (requests.RequestException, pyzipper.BadZipFile, KeyError) as e:
            print(f"  [!] Failed to download {sha256[:16]}: {e}")
            continue

        if downloaded >= count:
            break

    print(f"[*] Downloaded {downloaded} malware samples")
    return manifest


def collect_benign_samples(output_dir: str, count: int = 100) -> list[dict]:
    """Collect benign samples from system binaries."""
    os.makedirs(output_dir, exist_ok=True)
    manifest = []

    system = platform.system()
    search_dirs = []

    if system == "Darwin" or system == "Linux":
        search_dirs = ["/usr/bin", "/usr/local/bin", "/usr/sbin"]
    elif system == "Windows":
        windir = os.environ.get("WINDIR", r"C:\Windows")
        search_dirs = [
            os.path.join(windir, "System32"),
            os.path.join(windir, "SysWOW64"),
        ]

    print(f"[*] Collecting benign samples from {search_dirs}...")

    collected = 0
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue

        try:
            entries = sorted(os.listdir(search_dir))
        except PermissionError:
            continue

        for entry in entries:
            if collected >= count:
                break

            filepath = os.path.join(search_dir, entry)
            if not os.path.isfile(filepath):
                continue

            # Skip very small files and symlinks
            try:
                if os.path.islink(filepath):
                    continue
                size = os.path.getsize(filepath)
                if size < 1024:  # Skip files < 1KB
                    continue
            except OSError:
                continue

            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                sha256 = _sha256(data)
                out_path = os.path.join(output_dir, sha256)

                if not os.path.exists(out_path):
                    shutil.copy2(filepath, out_path)

                manifest.append({
                    "sha256": sha256,
                    "source": filepath,
                    "path": out_path,
                })
                collected += 1

            except (OSError, PermissionError):
                continue

        if collected >= count:
            break

    print(f"[*] Collected {collected} benign samples")
    return manifest


def save_manifest(manifest: list[dict], output_path: str) -> None:
    """Save download manifest to JSON."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)


def load_manifest(manifest_path: str) -> list[dict]:
    """Load download manifest from JSON."""
    with open(manifest_path, "r") as f:
        return json.load(f)
