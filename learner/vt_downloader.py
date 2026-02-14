"""VirusTotal sample downloader for augmenting the training dataset.

Supports two modes:
  - Hash lookups (free tier): verify known hashes against VT
  - Intelligence search + download (premium/enterprise): search for and
    download malware samples directly from VT

The API key is read from the VIRUSTOTAL_API_KEY environment variable.
"""

import hashlib
import os
import time
from pathlib import Path

import requests


VT_API_BASE = "https://www.virustotal.com/api/v3"

# Rate limits (requests per minute)
FREE_TIER_RPM = 4
PREMIUM_TIER_RPM = 30


class VirusTotalDownloader:
    def __init__(self, api_key=None, premium=False):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "No API key provided. Set the VIRUSTOTAL_API_KEY environment variable."
            )
        self.session = requests.Session()
        self.session.headers["x-apikey"] = self.api_key
        self.premium = premium
        self._rpm = PREMIUM_TIER_RPM if premium else FREE_TIER_RPM
        self._min_interval = 60.0 / self._rpm
        self._last_request = 0.0

    def _rate_limit(self):
        """Sleep if needed to stay under the API rate limit."""
        now = time.time()
        elapsed = now - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def get_file_report(self, sha256):
        """Look up a file hash on VirusTotal (works with free tier).

        Returns a dict with detection stats, or None if not found.
        """
        self._rate_limit()
        url = f"{VT_API_BASE}/files/{sha256}"
        resp = self.session.get(url)

        if resp.status_code == 404:
            return None
        resp.raise_for_status()

        data = resp.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        return {
            "sha256": sha256,
            "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "type_tag": data.get("type_tag", "unknown"),
            "meaningful_name": data.get("meaningful_name", ""),
        }

    def search_malware(self, limit=100, file_type="peexe", min_positives=5):
        """Search for malware samples using VT Intelligence (premium required).

        Returns a list of dicts with sha256 and metadata.
        """
        query = f"type:{file_type} positives:{min_positives}+"
        results = []
        cursor = None

        while len(results) < limit:
            self._rate_limit()
            params = {"query": query, "limit": min(limit - len(results), 40)}
            if cursor:
                params["cursor"] = cursor

            resp = self.session.get(
                f"{VT_API_BASE}/intelligence/search", params=params
            )

            if resp.status_code == 403:
                print("[VT] Intelligence search requires a premium API key.")
                break
            resp.raise_for_status()

            body = resp.json()
            for item in body.get("data", []):
                attrs = item.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results.append(
                    {
                        "sha256": item["id"],
                        "positives": stats.get("malicious", 0)
                        + stats.get("suspicious", 0),
                        "total": sum(stats.values()),
                        "type_tag": attrs.get("type_tag", "unknown"),
                        "meaningful_name": attrs.get("meaningful_name", ""),
                    }
                )

            cursor = body.get("meta", {}).get("cursor")
            if not cursor or not body.get("data"):
                break

        return results[:limit]

    def download_sample(self, sha256, output_dir):
        """Download a malware sample by SHA-256 (premium required).

        Returns the output path on success, or None on failure.
        """
        self._rate_limit()
        url = f"{VT_API_BASE}/files/{sha256}/download"
        resp = self.session.get(url)

        if resp.status_code == 403:
            print(f"[VT] Download failed for {sha256}: premium API key required.")
            return None
        resp.raise_for_status()

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / sha256
        out_path.write_bytes(resp.content)

        # Verify hash
        actual = hashlib.sha256(resp.content).hexdigest()
        if actual != sha256.lower():
            out_path.unlink()
            print(f"[VT] Hash mismatch for {sha256}: got {actual}")
            return None

        return str(out_path)

    def download_malware_samples(self, output_dir, count=100, file_type="peexe"):
        """Search for and download malware samples. Returns manifest entries.

        This is the main entry point that combines search + download.
        Gracefully handles free-tier limitations.
        """
        print(f"[VT] Searching for up to {count} malware samples...")
        search_results = self.search_malware(
            limit=count, file_type=file_type
        )

        if not search_results:
            print("[VT] No samples found (intelligence search may require premium).")
            return []

        print(f"[VT] Found {len(search_results)} samples, downloading...")
        manifest = []
        for i, entry in enumerate(search_results):
            sha256 = entry["sha256"]
            print(
                f"[VT] Downloading {i + 1}/{len(search_results)}: {sha256[:16]}..."
            )
            path = self.download_sample(sha256, output_dir)
            if path:
                manifest.append(
                    {
                        "sha256": sha256,
                        "path": path,
                        "source": "virustotal",
                        "vt_positives": entry["positives"],
                        "vt_total": entry["total"],
                    }
                )
            else:
                # Download failed (likely free tier), stop trying
                print("[VT] Download not available, stopping.")
                break

        print(f"[VT] Downloaded {len(manifest)} samples.")
        return manifest
