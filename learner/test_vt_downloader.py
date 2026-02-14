"""Tests for the VirusTotal downloader module."""

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from vt_downloader import VirusTotalDownloader, FREE_TIER_RPM, PREMIUM_TIER_RPM


class TestVirusTotalDownloaderInit(unittest.TestCase):
    def test_raises_without_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
            with self.assertRaises(ValueError) as ctx:
                VirusTotalDownloader()
            self.assertIn("VIRUSTOTAL_API_KEY", str(ctx.exception))

    def test_raises_with_empty_api_key(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}):
            with self.assertRaises(ValueError):
                VirusTotalDownloader()

    def test_accepts_explicit_api_key(self):
        dl = VirusTotalDownloader(api_key="test-key-123")
        self.assertEqual(dl.api_key, "test-key-123")
        self.assertEqual(dl.session.headers["x-apikey"], "test-key-123")

    def test_reads_from_env(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "env-key-456"}):
            dl = VirusTotalDownloader()
            self.assertEqual(dl.api_key, "env-key-456")

    def test_free_tier_rate_limit(self):
        dl = VirusTotalDownloader(api_key="key")
        self.assertEqual(dl._rpm, FREE_TIER_RPM)
        self.assertAlmostEqual(dl._min_interval, 60.0 / FREE_TIER_RPM, places=2)

    def test_premium_tier_rate_limit(self):
        dl = VirusTotalDownloader(api_key="key", premium=True)
        self.assertEqual(dl._rpm, PREMIUM_TIER_RPM)
        self.assertAlmostEqual(dl._min_interval, 60.0 / PREMIUM_TIER_RPM, places=2)


class TestGetFileReport(unittest.TestCase):
    def setUp(self):
        self.dl = VirusTotalDownloader(api_key="test-key")
        self.dl._rate_limit = MagicMock()  # Skip rate limiting in tests

    def test_returns_none_on_404(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        self.dl.session.get = MagicMock(return_value=mock_resp)

        result = self.dl.get_file_report("deadbeef" * 8)
        self.assertIsNone(result)

    def test_parses_malicious_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40,
                        "suspicious": 3,
                        "undetected": 10,
                        "harmless": 5,
                        "timeout": 2,
                        "failure": 0,
                    },
                    "type_tag": "peexe",
                    "meaningful_name": "evil.exe",
                }
            }
        }
        self.dl.session.get = MagicMock(return_value=mock_resp)

        result = self.dl.get_file_report("abc123")
        self.assertIsNotNone(result)
        self.assertEqual(result["sha256"], "abc123")
        self.assertEqual(result["positives"], 43)  # 40 + 3
        self.assertEqual(result["total"], 60)  # 40 + 3 + 10 + 5 + 2 + 0
        self.assertEqual(result["type_tag"], "peexe")
        self.assertEqual(result["meaningful_name"], "evil.exe")

    def test_parses_clean_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 5,
                        "harmless": 65,
                        "timeout": 0,
                        "failure": 0,
                    },
                    "type_tag": "peexe",
                    "meaningful_name": "clean.exe",
                }
            }
        }
        self.dl.session.get = MagicMock(return_value=mock_resp)

        result = self.dl.get_file_report("cleanfile")
        self.assertEqual(result["positives"], 0)
        self.assertEqual(result["total"], 70)


class TestSearchMalware(unittest.TestCase):
    def setUp(self):
        self.dl = VirusTotalDownloader(api_key="test-key")
        self.dl._rate_limit = MagicMock()

    def test_returns_empty_on_403(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        self.dl.session.get = MagicMock(return_value=mock_resp)

        results = self.dl.search_malware(limit=5)
        self.assertEqual(results, [])

    def test_parses_search_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {
                    "id": "sha256_sample_1",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 30,
                            "suspicious": 1,
                            "undetected": 5,
                            "harmless": 0,
                            "timeout": 0,
                            "failure": 0,
                        },
                        "type_tag": "peexe",
                        "meaningful_name": "sample1.exe",
                    },
                },
                {
                    "id": "sha256_sample_2",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 50,
                            "suspicious": 0,
                            "undetected": 10,
                            "harmless": 0,
                            "timeout": 0,
                            "failure": 0,
                        },
                        "type_tag": "peexe",
                        "meaningful_name": "sample2.exe",
                    },
                },
            ],
            "meta": {},
        }
        self.dl.session.get = MagicMock(return_value=mock_resp)

        results = self.dl.search_malware(limit=10)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["sha256"], "sha256_sample_1")
        self.assertEqual(results[0]["positives"], 31)
        self.assertEqual(results[1]["sha256"], "sha256_sample_2")
        self.assertEqual(results[1]["positives"], 50)

    def test_respects_limit(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {
                    "id": f"sha256_{i}",
                    "attributes": {
                        "last_analysis_stats": {"malicious": 10},
                        "type_tag": "peexe",
                    },
                }
                for i in range(20)
            ],
            "meta": {},
        }
        self.dl.session.get = MagicMock(return_value=mock_resp)

        results = self.dl.search_malware(limit=5)
        self.assertEqual(len(results), 5)


class TestDownloadSample(unittest.TestCase):
    def setUp(self):
        self.dl = VirusTotalDownloader(api_key="test-key")
        self.dl._rate_limit = MagicMock()

    def test_returns_none_on_403(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        self.dl.session.get = MagicMock(return_value=mock_resp)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.dl.download_sample("abc123", tmpdir)
            self.assertIsNone(result)

    def test_successful_download_with_valid_hash(self):
        content = b"this is malware content for testing"
        sha256 = hashlib.sha256(content).hexdigest()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = content
        self.dl.session.get = MagicMock(return_value=mock_resp)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.dl.download_sample(sha256, tmpdir)
            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(result))
            with open(result, "rb") as f:
                self.assertEqual(f.read(), content)

    def test_rejects_hash_mismatch(self):
        content = b"actual content"
        wrong_hash = "0" * 64  # Will not match

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = content
        self.dl.session.get = MagicMock(return_value=mock_resp)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.dl.download_sample(wrong_hash, tmpdir)
            self.assertIsNone(result)
            # File should have been cleaned up
            self.assertFalse(os.path.exists(os.path.join(tmpdir, wrong_hash)))


class TestDownloadMalwareSamples(unittest.TestCase):
    def setUp(self):
        self.dl = VirusTotalDownloader(api_key="test-key")
        self.dl._rate_limit = MagicMock()

    def test_returns_empty_when_search_finds_nothing(self):
        self.dl.search_malware = MagicMock(return_value=[])

        manifest = self.dl.download_malware_samples("/tmp/out", count=5)
        self.assertEqual(manifest, [])

    def test_stops_on_download_failure(self):
        self.dl.search_malware = MagicMock(
            return_value=[
                {"sha256": "aaa", "positives": 10, "total": 60},
                {"sha256": "bbb", "positives": 20, "total": 60},
            ]
        )
        # First download fails (free tier)
        self.dl.download_sample = MagicMock(return_value=None)

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = self.dl.download_malware_samples(tmpdir, count=5)
            self.assertEqual(manifest, [])
            # Should have stopped after first failure
            self.dl.download_sample.assert_called_once()

    def test_builds_manifest_on_success(self):
        self.dl.search_malware = MagicMock(
            return_value=[
                {"sha256": "aaa", "positives": 10, "total": 60},
                {"sha256": "bbb", "positives": 20, "total": 70},
            ]
        )
        self.dl.download_sample = MagicMock(
            side_effect=["/tmp/out/aaa", "/tmp/out/bbb"]
        )

        manifest = self.dl.download_malware_samples("/tmp/out", count=5)
        self.assertEqual(len(manifest), 2)
        self.assertEqual(manifest[0]["sha256"], "aaa")
        self.assertEqual(manifest[0]["source"], "virustotal")
        self.assertEqual(manifest[0]["vt_positives"], 10)
        self.assertEqual(manifest[1]["sha256"], "bbb")
        self.assertEqual(manifest[1]["vt_positives"], 20)


if __name__ == "__main__":
    unittest.main()
