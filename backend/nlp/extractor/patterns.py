"""
SentinelX AI — IOC Regex Pattern Library
==========================================
All compiled regex patterns used by the IOC extractor engine.

Design principles:
  1. All patterns are compiled ONCE at module import time (class-level constants).
  2. Patterns handle both standard and DEFANGED indicators:
       - Defanged IPs:     185[.]24[.]18[.]15  or  185(.)24(.)18(.)15
       - Defanged schemes: hxxp:// or hXXp:// or h__p://
       - Defanged domains: evil[.]com or evil(.)com
  3. Patterns err on the side of broad matching; false positives are
     filtered by the validation layer in IOCExtractor.
  4. Ordering matters: more specific patterns (SHA256) must be checked
     before less specific ones (MD5) to avoid partial matches.

IOC Types covered:
  IPV4, IPV6, URL, DOMAIN, EMAIL, FILENAME, FILE_PATH,
  MD5, SHA1, SHA256, CVE, USERNAME (partial), PORT
"""
from __future__ import annotations

import re

# ── Defang helpers ────────────────────────────────────────────────────────────
# These normalise defanged indicators before matching.
# Defanging replaces . with [.] or (.) and http with hxxp.

# Matches [.] or (.) or {.} as a literal dot
_DEFANG_DOT   = re.compile(r"\[\.?\]|\(\.?\)|\{\.?\}")
# Matches hxxp, h__p, hXXp variants
_DEFANG_SCHEME = re.compile(r"(?i)h(?:xx|XX|__)p(s?)")


def _refang(text: str) -> str:
    """Restore defanged IOCs to canonical form for matching."""
    text = _DEFANG_DOT.sub(".", text)
    text = _DEFANG_SCHEME.sub(r"http\1", text)
    return text


# ── IPv4 ─────────────────────────────────────────────────────────────────────
# Matches both standard and defanged: 185.24.18.15 or 185[.]24[.]18[.]15
# Requires word boundary to avoid matching e.g. "1.2.3.4.5"
IPV4 = re.compile(
    r"(?<![.\d])"                          # No leading digit/dot
    r"(?P<ip>"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"   # Octet
    r"(?:\[?\.\]?|\(?\.?\)?))"             # Separator (standard or defanged)
    r"{3}"                                  # Three times
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"  # Last octet
    r")"
    r"(?![.\d])",                          # No trailing digit/dot
    re.IGNORECASE,
)

# ── IPv6 ─────────────────────────────────────────────────────────────────────
# Matches full and compressed IPv6 addresses (not link-local fe80:: without context)
IPV6 = re.compile(
    r"(?<![:\w])"
    r"(?P<ip6>"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"          # Full
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                        # Trailing ::
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"                        # Leading ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"       # One :: in middle
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|::(?:[fF]{4}(?::0{1,4})?:)?"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"                    # IPv4-mapped
    r"|::1"                                                 # Loopback
    r"|::"                                                  # Unspecified
    r")"
    r"(?![:\w])",
)

# ── URL ───────────────────────────────────────────────────────────────────────
# Broad URL pattern — handles http(s)://, ftp://, defanged hxxp://
# Also matches partial paths and query strings
URL = re.compile(
    r"(?i)"
    r"(?P<url>"
    r"(?:https?|hxxps?|h__ps?|ftps?|sftp)"   # Scheme (standard + defanged)
    r"(?:://|%3A%2F%2F)"                        # :// (or URL-encoded)
    r"(?:[^\s\"'<>\[\]{}|\\^`]){3,}"           # Host + path
    r")",
)

# ── Domain ────────────────────────────────────────────────────────────────────
# Broad domain pattern — further validated with tldextract in the engine
# Excludes pure numeric strings (those are IPs) and common log artefacts
DOMAIN = re.compile(
    r"(?<![/@\w])"                              # Not part of email/path
    r"(?P<domain>"
    r"(?:[a-zA-Z0-9]"                           # First char of label
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"     # Label body
    r"\[?\.\]?"                                 # Separator (or defanged)
    r")+"
    r"(?P<tld>"
    r"(?:com|net|org|io|gov|mil|edu|co|uk|de|ru|cn|fr|nl|"
    r"info|biz|int|arpa|xyz|online|site|tech|store|app|dev|"
    r"[a-z]{2,6})"                              # 2-6 char TLD
    r")"
    r"(?::\d{2,5})?"                            # Optional port
    r"(?![.\w])"                                # Not followed by more domain chars
    r")",
    re.IGNORECASE,
)

# ── Email ─────────────────────────────────────────────────────────────────────
EMAIL = re.compile(
    r"(?P<email>"
    r"[a-zA-Z0-9._%+\-]+"                       # Local part
    r"@"
    r"[a-zA-Z0-9.\-]+"                          # Domain
    r"\.[a-zA-Z]{2,}"                           # TLD
    r")",
)

# ── File Hashes ───────────────────────────────────────────────────────────────
# Order matters: SHA256 > SHA1 > MD5 (most specific first)

SHA256 = re.compile(
    r"(?<![0-9a-fA-F])"
    r"(?P<sha256>[0-9a-fA-F]{64})"
    r"(?![0-9a-fA-F])",
)

SHA1 = re.compile(
    r"(?<![0-9a-fA-F])"
    r"(?P<sha1>[0-9a-fA-F]{40})"
    r"(?![0-9a-fA-F])",
)

MD5 = re.compile(
    r"(?<![0-9a-fA-F])"
    r"(?P<md5>[0-9a-fA-F]{32})"
    r"(?![0-9a-fA-F])",
)

# Sysmon combined hash field: "MD5=...,SHA256=...,SHA1=..."
SYSMON_HASHES = re.compile(
    r"(?:MD5=(?P<md5>[0-9a-fA-F]{32})|"
    r"SHA1=(?P<sha1>[0-9a-fA-F]{40})|"
    r"SHA256=(?P<sha256>[0-9a-fA-F]{64}))",
    re.IGNORECASE,
)

# ── CVE ───────────────────────────────────────────────────────────────────────
CVE = re.compile(
    r"(?i)\b(?P<cve>CVE-(?:19|20)\d{2}-\d{4,7})\b",
)

# ── File Paths ────────────────────────────────────────────────────────────────
# Windows absolute path: C:\Windows\... or \\UNC\path\...
# Intentionally broad — captures the full path including backslashes.
# Validation (removing trailing punctuation) is done in the extractor.
WIN_PATH = re.compile(
    r"(?P<winpath>"
    r"(?:[A-Za-z]:[\\/]|\\\\)"               # Drive letter (C:\) or UNC root (\\)
    r"[^\x00-\x1f\"'<>|?*\[\]{}]{4,512}"    # Path chars — allows backslash, colon, dot
    r")",
)

# Unix absolute path: /etc/passwd, /home/user/...
UNIX_PATH = re.compile(
    r"(?<!\w)"
    r"(?P<unixpath>"
    r"/(?:[^\x00-\x1f \t\"'<>|;`]{1,255}/)+"  # Directory components
    r"[^\x00-\x1f \t\"'<>|;`]{1,255}"          # Filename
    r")",
)

# ── Registry Keys ─────────────────────────────────────────────────────────────
REGISTRY_KEY = re.compile(
    r"(?P<regkey>"
    r"(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|"
    r"HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR|"
    r"HKEY_CURRENT_CONFIG|HKCC)"
    r"(?:\\[^\x00-\x1f\"'<>|]{1,255})+"
    r")",
    re.IGNORECASE,
)

# ── Port Numbers ──────────────────────────────────────────────────────────────
# Only interesting/non-standard ports or explicitly labelled ones
PORT = re.compile(
    r"(?:port|PORT|dport|sport)\s*[=:]\s*(?P<port>\d{1,5})"
    r"|:(?P<port2>\d{2,5})(?!\.\d)",
)

# ── Filename (basename only) ──────────────────────────────────────────────────
# Matches suspicious filenames with executable or script extensions
SUSPICIOUS_FILENAME = re.compile(
    r"(?<![/\\])"
    r"(?P<filename>"
    r"[A-Za-z0-9_\-\.]{1,128}"
    r"\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|sh|bash|py|pl|rb|"
    r"php|asp|aspx|jsp|cgi|msi|hta|scr|com|pif|lnk|iso|img)"
    r")"
    r"(?![A-Za-z0-9_\-])",
    re.IGNORECASE,
)

# ── Username heuristics ───────────────────────────────────────────────────────
# Labelled usernames from structured logs
LABELLED_USERNAME = re.compile(
    r"(?:user(?:name)?|account\s+name|logon\s+name)\s*[=:]\s*"
    r"(?P<username>[^\s,;\"'<>]{2,64})",
    re.IGNORECASE,
)

# ── Process names ─────────────────────────────────────────────────────────────
# Labelled process names from structured logs
LABELLED_PROCESS = re.compile(
    r"(?:process\s+name|image|executable)\s*[=:]\s*"
    r"(?P<process>[^\s,;\"'<>]{2,256}\.exe)",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Allowlists / Benign value filters
# Values that match patterns but should never be emitted as IOCs
# ─────────────────────────────────────────────────────────────────────────────

# Benign IPv4 addresses (internal/testing only)
BENIGN_IPS: frozenset[str] = frozenset({
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "224.0.0.0", "239.255.255.255",
})

# Benign hostnames / domains
BENIGN_DOMAINS: frozenset[str] = frozenset({
    "localhost", "localhost.localdomain", "local",
    "example.com", "example.org", "example.net",
    "test.com", "test.local", "internal",
})

# Benign hash values (all-zero, all-f, etc.)
BENIGN_HASHES: frozenset[str] = frozenset({
    "0" * 32, "f" * 32,         # MD5
    "0" * 40, "f" * 40,         # SHA1
    "0" * 64, "f" * 64,         # SHA256
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
})
