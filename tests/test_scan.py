import pytest

from app import scanner


def test_ip_blocked_private():
    for ip in ["127.0.0.1", "10.0.0.1", "172.16.5.4", "172.31.255.1",
               "192.168.1.1", "169.254.10.20", "0.0.0.0", "::1", "fe80::1", "not-an-ip"]:
        assert scanner.ip_blocked(ip), ip


def test_ip_public_ok():
    for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"]:
        assert not scanner.ip_blocked(ip), ip


def test_validate_url_rejects():
    for bad in ["notaurl", "", "ftp://x.com/", "https://user@x.com/",
                "https://x.com:9999/", "gopher://x.com"]:
        with pytest.raises(scanner.ScanError):
            scanner.validate_url(bad)


def test_validate_url_normalises():
    s, h, p = scanner.validate_url("https://Example.COM")
    assert (s, h, p) == ("https", "example.com", 443)
    s, h, p = scanner.validate_url("http://x.com/")
    assert (s, h, p) == ("http", "x.com", 80)


def test_secret_patterns():
    hits = scanner.scan_text_for_secrets("key = 'AKIAIOSFODNN7EXAMPLE' // todo remove")
    assert any(h["check"].startswith("AWS") and h["sev"] == "critical" for h in hits)
    # synthetic fixture: parts never appear contiguously, so no real secret exists here
    stripe_fixture = "sk_live_" + "4eC39" + "HqLyjWDarjtT1zdp7dc"
    hits = scanner.scan_text_for_secrets("const s = '%s';" % stripe_fixture)
    assert any("Stripe" in h["check"] and h["sev"] == "critical" for h in hits)
    hits = scanner.scan_text_for_secrets("-----BEGIN PRIVATE KEY-----\nMIIB...")
    assert any("Private key" in h["check"] for h in hits)
    assert scanner.scan_text_for_secrets("hello world, nothing here") == []


def test_grade():
    assert scanner.grade([]) == "SOLID"
    assert scanner.grade([{"sev": "low"}, {"sev": "low"}]) == "SOLID"
    assert scanner.grade([{"sev": "low"}] * 3) == "AT RISK"
    assert scanner.grade([{"sev": "high"}]) == "AT RISK"
    assert scanner.grade([{"sev": "medium"}, {"sev": "critical"}]) == "FAIL"


def test_fingerprints():
    notes = scanner.detect_backend_and_builder("…https://abc123.supabase.co/rest/v1/…")
    assert any("Supabase" in n["check"] for n in notes)
    notes = scanner.detect_backend_and_builder("<meta name='lovable.dev'>")
    assert any("Lovable" in n["check"] for n in notes)
    assert scanner.detect_backend_and_builder("plain page") == []
