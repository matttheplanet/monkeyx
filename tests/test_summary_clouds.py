"""Tests for the Cloud / CDN / SaaS provider inventory in the Scan Debrief.

_parse_clouds mines two signal sources — bbot STORAGE_BUCKET events and the DNS
resolve-report (CNAME/MX/CDN) — and maps hosts to providers by DNS suffix. These
lock in the provider mapping, the bbot_type selector, and the rendered section.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.summary import (
    _match_provider, _parse_clouds, _collect_stats, _write_markdown_report,
)


class TestMatchProvider:
    def test_bucket_suffixes(self):
        assert _match_provider("acmecorp.blob.core.windows.net") == ("Azure", "object-storage")
        assert _match_provider("x.s3.amazonaws.com") == ("AWS S3", "object-storage")
        assert _match_provider("app.storage.googleapis.com") == ("GCP", "object-storage")
        assert _match_provider("demoapp.firebaseio.com") == ("Firebase", "object-storage")
        assert _match_provider("x.digitaloceanspaces.com") == ("DigitalOcean Spaces", "object-storage")

    def test_cdn_suffixes(self):
        assert _match_provider("d123.cloudfront.net") == ("CloudFront", "cdn")
        assert _match_provider("x.akamaiedge.net") == ("Akamai", "cdn")
        assert _match_provider("x.fastly.net") == ("Fastly", "cdn")

    def test_mail_suffixes(self):
        assert _match_provider("mxa-00000000.gslb.pphosted.com") == ("Proofpoint", "mail")
        assert _match_provider("acmecorp.mail.protection.outlook.com") == ("Microsoft 365", "mail")
        assert _match_provider("mxb.eu.mailgun.org") == ("Mailgun", "mail")

    def test_longest_suffix_wins(self):
        # .s3.amazonaws.com (object-storage) beats .amazonaws.com (hosting)
        assert _match_provider("bucket.s3.amazonaws.com") == ("AWS S3", "object-storage")
        assert _match_provider("ec2-1-2-3-4.compute.amazonaws.com") == ("AWS", "hosting")

    def test_case_and_trailing_dot(self):
        assert _match_provider("X.S3.AMAZONAWS.COM.") == ("AWS S3", "object-storage")

    def test_unknown_returns_none(self):
        assert _match_provider("intranet.example.com") is None
        assert _match_provider("") is None
        assert _match_provider(None) is None


class TestParseClouds:
    def _write(self, data_dir, name, records):
        path = os.path.join(data_dir, name)
        with open(path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def test_buckets_and_dns(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        self._write(str(data), "scan-bbot-normalized.jsonl", [
            # provider from bbot_module (most reliable)
            {"bbot_type": "STORAGE_BUCKET", "bbot_module": "bucket_azure",
             "type": "finding", "host": "acmecorp.blob.core.windows.net"},
            # provider from host suffix (no/unknown module)
            {"bbot_type": "STORAGE_BUCKET", "bbot_module": "bbot",
             "type": "finding", "host": "app.storage.googleapis.com"},
            # a non-bucket bbot finding must be ignored
            {"bbot_type": "FINDING", "type": "finding", "host": "x.example.com",
             "title": "something else"},
        ])
        self._write(str(data), "scan-resolve-report.jsonl", [
            {"hostname": "www.example.com", "cname": ["d1.cloudfront.net"],
             "cdn-name": "cloudfront"},
            {"hostname": "example.com",
             "mx": ["mxa-00000000.gslb.pphosted.com"]},
            {"hostname": "internal.example.com", "cname": ["nothing.example.org"]},
        ])

        stats = {'clouds': []}
        _parse_clouds(str(data), stats)
        by_provider = {c['provider']: c for c in stats['clouds']}

        assert by_provider["Azure"]['category'] == "object-storage"
        assert by_provider["Azure"]['signals'] == ["bucket"]
        assert by_provider["GCP"]['host_count'] == 1
        # CloudFront cname corroborated by cdn-name -> signal upgraded to "cdn"
        assert by_provider["CloudFront"]['signals'] == ["cdn"]
        assert by_provider["Proofpoint"]['signals'] == ["mx"]
        # unmatched cname produced no provider
        assert "example.org" not in by_provider

    def test_no_files_empty(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        stats = {'clouds': []}
        _parse_clouds(str(data), stats)
        assert stats['clouds'] == []

    def test_sorted_by_host_count(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        self._write(str(data), "scan-resolve-report.jsonl", [
            {"hostname": "a", "cname": ["x.fastly.net"]},
            {"hostname": "b", "cname": ["y.cloudfront.net"]},
            {"hostname": "c", "cname": ["z.cloudfront.net"]},
        ])
        stats = {'clouds': []}
        _parse_clouds(str(data), stats)
        # CloudFront (2 hosts) sorts before Fastly (1 host)
        assert [c['provider'] for c in stats['clouds']] == ["CloudFront", "Fastly"]


class TestRender:
    def _base(self):
        return {
            'targets': {'ips': 0, 'domains': 0, 'urls': 0, 'subdomains': 0},
            'ports': {'total': 0, 'hosts_with_ports': 0},
            'findings': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0,
                         'low': 0, 'info': 0},
            'modules': {'succeeded': [], 'failed': [], 'empty_output': []},
            'module_history': [], 'clouds': [], 'coverage': [], 'warnings': [],
        }

    def test_section_rendered_when_present(self, tmp_path):
        stats = self._base()
        stats['clouds'] = [
            {'provider': 'Azure', 'category': 'object-storage',
             'signals': ['bucket'], 'host_count': 3,
             'sample_hosts': ['a.blob.core.windows.net', 'b.blob.core.windows.net']},
            {'provider': 'Proofpoint', 'category': 'mail', 'signals': ['mx'],
             'host_count': 30, 'sample_hosts': ['mx.pphosted.com']},
        ]
        md = str(tmp_path / "summary.md")
        _write_markdown_report(stats, md)
        text = open(md).read()
        assert "## Cloud / CDN / SaaS Providers" in text
        assert "| Provider | Category | Signals | Hosts | Examples |" in text
        assert "| Azure | object-storage | bucket | 3 |" in text
        assert "| Proofpoint | mail | mx | 30 |" in text

    def test_section_omitted_when_empty(self, tmp_path):
        stats = self._base()
        md = str(tmp_path / "summary.md")
        _write_markdown_report(stats, md)
        assert "Cloud / CDN / SaaS Providers" not in open(md).read()
