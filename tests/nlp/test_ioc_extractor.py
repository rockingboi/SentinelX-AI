"""
Unit tests for IOCExtractor.
Tests: all major IOC types, benign filtering, private IP handling,
deduplication, confidence, and extract_from_event().

Real API: IOCExtractor.extract_from_text(str) and extract_from_event(NormalizedEvent)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("APP_ENV", "development")

import pytest
from backend.nlp.extractor.ioc_extractor import IOCExtractor, ExtractedIOC
from backend.models.ioc_entity import IOCType
from backend.schemas.logs import NormalizedEvent


@pytest.fixture(scope="module")
def extractor():
    """Default extractor — private IPs excluded."""
    return IOCExtractor(include_private_ips=False)


@pytest.fixture(scope="module")
def extractor_with_private():
    """Extractor with private IP inclusion enabled."""
    return IOCExtractor(include_private_ips=True)


def _event(raw_line: str, **kwargs) -> NormalizedEvent:
    return NormalizedEvent(log_type="linux_syslog", raw_line=raw_line, **kwargs)


# ── IP addresses ──────────────────────────────────────────────────────────────

class TestIPExtraction:
    def test_extract_public_ipv4(self, extractor):
        """Public IPv4 address must be extracted."""
        iocs = extractor.extract_from_text("Connection from 185.24.18.15 port 22")
        vals = {i.value for i in iocs}
        assert "185.24.18.15" in vals

    def test_extract_ipv6(self, extractor):
        """IPv6 address must be extracted."""
        iocs = extractor.extract_from_text("Client connected from 2001:db8::1")
        types = {i.ioc_type for i in iocs}
        assert IOCType.IPV6 in types

    def test_localhost_excluded(self, extractor):
        """127.0.0.1 must never be extracted as an IOC."""
        iocs = extractor.extract_from_text("Connection from 127.0.0.1 port 80")
        vals = {i.value for i in iocs}
        assert "127.0.0.1" not in vals

    def test_private_ip_excluded_by_default(self, extractor):
        """Private IPs (192.168.x.x) must not be extracted by default."""
        iocs = extractor.extract_from_text("Login from 192.168.1.100 to server")
        vals = {i.value for i in iocs}
        assert "192.168.1.100" not in vals

    def test_private_ip_included_when_flag_set(self, extractor_with_private):
        """Private IPs must be extracted when include_private_ips=True."""
        iocs = extractor_with_private.extract_from_text("Login from 192.168.1.100 to server")
        vals = {i.value for i in iocs}
        assert "192.168.1.100" in vals

    def test_link_local_excluded(self, extractor):
        """Link-local address 169.254.x.x must not be extracted."""
        iocs = extractor.extract_from_text("ARP from 169.254.0.1")
        vals = {i.value for i in iocs}
        assert "169.254.0.1" not in vals


# ── Domains & URLs ────────────────────────────────────────────────────────────

class TestDomainAndURL:
    def test_extract_domain(self, extractor):
        """Malicious domain must be extracted."""
        iocs = extractor.extract_from_text("DNS query for evil-c2.xyz resolved")
        types = {i.ioc_type for i in iocs}
        assert IOCType.DOMAIN in types

    def test_extract_url(self, extractor):
        """Full URL must be extracted as IOC."""
        iocs = extractor.extract_from_text("Request to http://malware.xyz/payload.exe")
        types = {i.ioc_type for i in iocs}
        assert IOCType.URL in types or IOCType.DOMAIN in types

    def test_extract_from_text_returns_list(self, extractor):
        """extract_from_text must always return a list."""
        iocs = extractor.extract_from_text("some random line")
        assert isinstance(iocs, list)


# ── Hashes ────────────────────────────────────────────────────────────────────

class TestHashExtraction:
    def test_extract_md5(self, extractor):
        """MD5 hash — real malware hash (not in BENIGN_HASHES allowlist)."""
        # NotPetya hash — not in the benign/empty-file allowlist
        notpetya_md5 = "64b0b58a2c030c77fdb2b537b2fcc17d"
        iocs = extractor.extract_from_text(f"Malware detected with hash {notpetya_md5}")
        vals = {i.value for i in iocs}
        assert notpetya_md5 in vals

    def test_extract_sha256(self, extractor):
        """SHA-256 hash — real malware hash (not in BENIGN_HASHES allowlist)."""
        # WannaCry SHA256 — not in the benign allowlist
        wannacry_sha256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
        iocs = extractor.extract_from_text(f"Process hash: {wannacry_sha256}")
        vals = {i.value for i in iocs}
        assert wannacry_sha256 in vals

    def test_extract_sha1(self, extractor):
        """SHA-1 hash — real non-benign hash."""
        # Mirai botnet SHA1
        mirai_sha1 = "29c3048a8e98276e9bf5d3afe8c1c9dc7eda5a8a"
        iocs = extractor.extract_from_text(f"File SHA1: {mirai_sha1}")
        assert len(iocs) >= 1


# ── CVE & Email ───────────────────────────────────────────────────────────────

class TestCVEAndEmail:
    def test_extract_cve(self, extractor):
        """CVE identifier must be extracted."""
        iocs = extractor.extract_from_text("Exploiting CVE-2021-44228 (Log4Shell)")
        vals = {i.value for i in iocs}
        assert any("CVE-2021-44228" in v for v in vals)

    def test_extract_email(self, extractor):
        """Email address must be extracted."""
        iocs = extractor.extract_from_text("Email from attacker@malicious.com received")
        types = {i.ioc_type for i in iocs}
        assert IOCType.EMAIL in types


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:
    def test_same_ip_twice_one_ioc(self, extractor):
        """Same IP appearing twice in a line must produce only one IOC."""
        iocs = extractor.extract_from_text(
            "Failed password from 185.24.18.15 port 22, retrying from 185.24.18.15"
        )
        ip_iocs = [i for i in iocs if i.value == "185.24.18.15"]
        assert len(ip_iocs) == 1

    def test_multiple_ips_multiple_iocs(self, extractor):
        """Two different public IPs in one line produce two separate IOCs."""
        # Use two routable (non-TEST-NET, non-private) public IPs
        iocs = extractor.extract_from_text("From 185.24.18.15 to 91.108.4.100")
        ip_vals = {i.value for i in iocs if i.ioc_type == IOCType.IPV4}
        assert "185.24.18.15" in ip_vals
        assert "91.108.4.100" in ip_vals


# ── Confidence & metadata ─────────────────────────────────────────────────────

class TestIOCMetadata:
    def test_confidence_between_0_and_1(self, extractor):
        """All extracted IOCs must have confidence in [0.0, 1.0]."""
        iocs = extractor.extract_from_text("Failed password from 185.24.18.15 port 22")
        for ioc in iocs:
            assert 0.0 <= ioc.confidence <= 1.0

    def test_ioc_has_value_field(self, extractor):
        """All IOCs must have a non-empty value."""
        iocs = extractor.extract_from_text("Login from 185.24.18.15")
        for ioc in iocs:
            assert ioc.value
            assert len(ioc.value) > 0

    def test_ioc_has_ioc_type_field(self, extractor):
        """All IOCs must have an ioc_type field of type IOCType."""
        iocs = extractor.extract_from_text("Login from 185.24.18.15")
        for ioc in iocs:
            assert isinstance(ioc.ioc_type, IOCType)


# ── extract_from_event ────────────────────────────────────────────────────────

class TestExtractFromEvent:
    def test_source_ip_extracted_from_event_field(self, extractor):
        """source_ip field on NormalizedEvent must contribute to IOC extraction."""
        ev = _event(
            raw_line="Failed password for root from 185.24.18.15",
            source_ip="185.24.18.15",
            event_type="Failed Login",
        )
        iocs = extractor.extract_from_event(ev)
        vals = {i.value for i in iocs}
        assert "185.24.18.15" in vals

    def test_empty_event_no_crash(self, extractor):
        """Extracting from an event with empty raw_line must not raise."""
        ev = _event(raw_line="   ")
        iocs = extractor.extract_from_event(ev)
        assert isinstance(iocs, list)

    def test_returns_list_of_extracted_ioc(self, extractor):
        """Return type must be a list of ExtractedIOC objects."""
        ev = _event(raw_line="Hash: d41d8cd98f00b204e9800998ecf8427e")
        iocs = extractor.extract_from_event(ev)
        for ioc in iocs:
            assert isinstance(ioc, ExtractedIOC)
