"""Public Suffix List (PSL) validation for WebAuthn Relying Party IDs.

Conforms to W3C WebAuthn Level 3 (Section 5.1.4.1 Validating Relying Party ID):
- An RP ID must be a valid domain string.
- The origin's effective domain must equal the RP ID or end with a dot followed by the RP ID.
- The RP ID must NOT be a public suffix or eTLD (e.g. 'com', 'co.uk', 'github.io').

This prevents multi-tenant subdomain attacks (e.g. attacker.github.io claiming rp_id='github.io').
"""
from urllib.parse import urlparse

# Standard two-part ccTLDs and common public suffixes
_TWO_PART_CCTLDS = {
    # UK
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "sch.uk", "gov.uk", "nhs.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "school.nz", "geek.nz",
    # South Africa
    "co.za", "net.za", "org.za", "ac.za", "gov.za", "web.za",
    # Canada
    "gc.ca",
    # Singapore, Hong Kong, Taiwan, Korea
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr", "ac.kr",
    # Mexico, Argentina, Colombia
    "com.mx", "org.mx", "edu.mx", "gob.mx", "net.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar",
    "com.co", "net.co", "nom.co", "org.co", "edu.co", "gov.co",
    # Others
    "com.tr", "org.tr", "edu.tr", "gov.tr",
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.ng", "org.ng", "gov.ng", "edu.ng",
}

# Major multi-tenant hosting platforms and cloud providers where subdomains
# are untrusted user content and must never be claimed by sub-tenants.
_PRIVATE_PUBLIC_SUFFIXES = {
    # GitHub / GitLab / Code
    "github.io", "gitlab.io", "codeberg.page", "srht.site",
    # Cloudflare
    "pages.dev", "workers.dev",
    # Vercel / Netlify / Render / Fly / Heroku
    "vercel.app", "now.sh", "netlify.app", "onrender.com", "fly.dev", "herokuapp.com",
    "railway.app", "up.railway.app", "koyeb.app", "deno.dev",
    # AWS / Azure / GCP / Firebase
    "azurewebsites.net", "azureedge.net", "blob.core.windows.net",
    "appspot.com", "firebaseapp.com", "web.app",
    "s3.amazonaws.com", "cloudfront.net", "awsapprunner.com",
    # Others (Glitch, Surge, Replit, Shopify, etc.)
    "glitch.me", "surge.sh", "repl.co", "replit.app", "myshopify.com",
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
    "githubusercontent.com",
}

_ALL_PUBLIC_SUFFIXES = _TWO_PART_CCTLDS | _PRIVATE_PUBLIC_SUFFIXES

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def is_public_suffix(domain: str) -> bool:
    """Check if a domain is a public suffix (e.g. 'com', 'co.uk', 'github.io')."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return False
    
    # Loopback is not a public suffix
    if domain in LOOPBACK_HOSTS:
        return False
    
    # Single label (e.g. 'com', 'org', 'io', 'net', 'uk') is always a TLD / public suffix
    if "." not in domain:
        return True
    
    # Check known multi-part suffixes
    return domain in _ALL_PUBLIC_SUFFIXES


def get_public_suffix(domain: str) -> str | None:
    """Extract the public suffix from a domain name.
    
    Examples:
        'foo.example.com' -> 'com'
        'foo.example.co.uk' -> 'co.uk'
        'alice.github.io' -> 'github.io'
        'localhost' -> None
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain or domain in LOOPBACK_HOSTS:
        return None
    
    parts = domain.split(".")
    if len(parts) == 1:
        return parts[0]
    
    # Check 2-label suffix (e.g., 'co.uk', 'github.io')
    two_part = ".".join(parts[-2:])
    if two_part in _ALL_PUBLIC_SUFFIXES:
        return two_part
    
    # Default to single top-level domain label
    return parts[-1]


def get_registrable_domain(domain: str) -> str | None:
    """Extract the registrable domain (eTLD+1) from a domain name.
    
    Examples:
        'sub.example.com' -> 'example.com'
        'sub.example.co.uk' -> 'example.co.uk'
        'alice.github.io' -> 'alice.github.io'
        'github.io' -> None (public suffix, not registrable on its own)
        'localhost' -> 'localhost'
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return None
    if domain in LOOPBACK_HOSTS:
        return domain
    
    ps = get_public_suffix(domain)
    if not ps:
        return domain
    
    if domain == ps:
        return None  # The domain IS the public suffix
    
    # Domain ends with .<ps>
    prefix = domain[:-len(ps)].rstrip(".")
    prefix_parts = prefix.split(".")
    return f"{prefix_parts[-1]}.{ps}"


def validate_rp_id(rp_id: str, origin: str) -> bool:
    """Validate Relying Party ID against origin per WebAuthn Level 3 specs.
    
    Rules:
    1. rp_id must be non-empty.
    2. Origin must be valid and parseable.
    3. Loopback hosts (localhost, 127.0.0.1) are accepted for local development.
    4. Origin hostname must equal rp_id OR end with '.<rp_id>'.
    5. rp_id must NOT be a public suffix (e.g. 'com', 'co.uk', 'github.io').
    6. rp_id must have at least one registrable label before its public suffix.
    """
    if not rp_id:
        return False
    
    rp_id = rp_id.strip().lower().rstrip(".")
    if not rp_id:
        return False
    
    try:
        parsed = urlparse(origin)
        hostname = parsed.hostname
    except Exception:
        return False
    
    if not hostname:
        return False
    hostname = hostname.strip().lower().rstrip(".")
    
    # Local development allowance
    if hostname in LOOPBACK_HOSTS:
        return rp_id in LOOPBACK_HOSTS or rp_id == hostname
    
    # rp_id cannot be a public suffix / TLD
    if is_public_suffix(rp_id):
        return False
    
    # Origin hostname must equal rp_id or be a subdomain of rp_id
    if hostname != rp_id and not hostname.endswith("." + rp_id):
        return False
    
    # Ensure rp_id has a registrable domain portion
    reg_domain = get_registrable_domain(rp_id)
    if not reg_domain:
        return False
    
    return True
