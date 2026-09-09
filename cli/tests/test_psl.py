import pytest
from zenith_passkeys.core.psl import (
    validate_rp_id,
    is_public_suffix,
    get_public_suffix,
    get_registrable_domain,
)


def test_public_suffix_identification():
    # Standard TLDs
    assert is_public_suffix("com")
    assert is_public_suffix("org")
    assert is_public_suffix("io")
    assert is_public_suffix("net")
    assert is_public_suffix("uk")

    # Two-level ccTLDs
    assert is_public_suffix("co.uk")
    assert is_public_suffix("org.uk")
    assert is_public_suffix("gov.uk")
    assert is_public_suffix("com.au")
    assert is_public_suffix("co.jp")
    assert is_public_suffix("co.in")

    # Multi-tenant private public suffixes
    assert is_public_suffix("github.io")
    assert is_public_suffix("gitlab.io")
    assert is_public_suffix("pages.dev")
    assert is_public_suffix("vercel.app")
    assert is_public_suffix("netlify.app")
    assert is_public_suffix("azurewebsites.net")
    assert is_public_suffix("herokuapp.com")
    assert is_public_suffix("web.app")

    # Registrable domains are NOT public suffixes
    assert not is_public_suffix("example.com")
    assert not is_public_suffix("github.com")
    assert not is_public_suffix("google.co.uk")
    assert not is_public_suffix("alice.github.io")
    assert not is_public_suffix("localhost")


def test_get_public_suffix():
    assert get_public_suffix("example.com") == "com"
    assert get_public_suffix("sub.example.com") == "com"
    assert get_public_suffix("example.co.uk") == "co.uk"
    assert get_public_suffix("sub.example.co.uk") == "co.uk"
    assert get_public_suffix("alice.github.io") == "github.io"
    assert get_public_suffix("localhost") is None


def test_get_registrable_domain():
    assert get_registrable_domain("example.com") == "example.com"
    assert get_registrable_domain("sub.example.com") == "example.com"
    assert get_registrable_domain("deep.sub.example.com") == "example.com"
    assert get_registrable_domain("sub.example.co.uk") == "example.co.uk"
    assert get_registrable_domain("alice.github.io") == "alice.github.io"
    assert get_registrable_domain("github.io") is None
    assert get_registrable_domain("com") is None
    assert get_registrable_domain("localhost") == "localhost"


def test_validate_rp_id_standard_domain():
    # Exact domain match
    assert validate_rp_id("example.com", "https://example.com")
    assert validate_rp_id("example.com", "https://example.com:8443")

    # Subdomain origin claiming parent domain
    assert validate_rp_id("example.com", "https://sub.example.com")
    assert validate_rp_id("example.com", "https://deep.sub.example.com")
    assert validate_rp_id("sub.example.com", "https://deep.sub.example.com")

    # Origin claiming a subdomain (invalid)
    assert not validate_rp_id("sub.example.com", "https://example.com")

    # Domain mismatch
    assert not validate_rp_id("example.com", "https://attacker-example.com")
    assert not validate_rp_id("example.com", "https://evil.com")


def test_validate_rp_id_rejects_public_suffixes():
    # Origin attempting to claim root TLD
    assert not validate_rp_id("com", "https://example.com")
    assert not validate_rp_id("org", "https://example.org")
    assert not validate_rp_id("io", "https://example.io")

    # Origin attempting to claim two-level ccTLD
    assert not validate_rp_id("co.uk", "https://example.co.uk")
    assert not validate_rp_id("co.uk", "https://sub.example.co.uk")

    # Multi-tenant hosting protection (anti-spoofing)
    # attacker.github.io claiming github.io must be REJECTED
    assert not validate_rp_id("github.io", "https://attacker.github.io")
    assert not validate_rp_id("pages.dev", "https://site.pages.dev")
    assert not validate_rp_id("vercel.app", "https://app.vercel.app")
    assert not validate_rp_id("netlify.app", "https://site.netlify.app")

    # However, each tenant can claim their OWN subdomain
    assert validate_rp_id("attacker.github.io", "https://attacker.github.io")
    assert validate_rp_id("sub.attacker.github.io", "https://sub.attacker.github.io")
    assert validate_rp_id("attacker.github.io", "https://sub.attacker.github.io")


def test_validate_rp_id_localhost():
    assert validate_rp_id("localhost", "http://localhost")
    assert validate_rp_id("localhost", "http://localhost:3000")
    assert validate_rp_id("localhost", "http://localhost:8080")
    assert validate_rp_id("127.0.0.1", "http://127.0.0.1:8000")
    assert not validate_rp_id("example.com", "http://localhost:3000")


def test_validate_rp_id_edge_cases():
    assert not validate_rp_id("", "https://example.com")
    assert not validate_rp_id("   ", "https://example.com")
    assert not validate_rp_id("example.com", "")
    assert not validate_rp_id("example.com", "not a url")
