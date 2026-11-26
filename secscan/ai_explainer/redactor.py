"""PII and host-detail redaction layer for the optional AI explainer.

Before any text leaves the machine, :class:`Redactor` strips:
- MAC addresses
- IPv4 and IPv6 addresses
- Windows and POSIX file paths (preserving HTTP/HTTPS URLs)
- Windows ``DOMAIN\\user`` and ``user@host`` identifiers
- Known usernames and hostnames (auto-detected or caller-supplied)
"""

from __future__ import annotations

import getpass
import logging
import re
import socket
from collections.abc import Iterable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# MAC address: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# IPv4 address: 4 octets 0-255
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# IPv6 address (full, compressed with ::, or link-local with optional %zone)
_IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9:])"
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}"
    r"|::"
    r")(?:%[A-Za-z0-9_.-]+)?"
    r"(?![A-Za-z0-9:])"
)

# Windows paths: C:\Users\alice\file.txt or \\server\share\path
_WIN_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)[^\s\"'<>|,;]+")

# POSIX absolute paths: /home/alice/.ssh/id_rsa, /etc/ssh/sshd_config
# Negative lookbehind avoids matching inside URLs (https://example.com/foo/bar)
_POSIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9:./])/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+")

# DOMAIN\username (Windows local/domain account format)
_DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$ -]+?(?=\s|$|[,;\"'])")

# URLs — temporarily shielded so POSIX path regex doesn't strip URL paths
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


class Redactor:
    """Deterministic PII redactor for security findings."""

    def __init__(
        self,
        *,
        usernames: Iterable[str] | None = None,
        hostnames: Iterable[str] | None = None,
        include_system_identity: bool = True,
    ) -> None:
        """Initialize the redactor.

        Args:
            usernames: Additional usernames to redact.
            hostnames: Additional hostnames to redact.
            include_system_identity: If ``True``, automatically include the
                current OS username and hostname.
        """
        user_set: set[str] = {u.strip() for u in (usernames or []) if u and u.strip()}
        host_set: set[str] = {h.strip() for h in (hostnames or []) if h and h.strip()}

        if include_system_identity:
            try:
                current_user = getpass.getuser().strip()
                if current_user:
                    user_set.add(current_user)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not detect current username: %s", exc)
            try:
                current_host = socket.gethostname().strip()
                if current_host:
                    host_set.add(current_host)
                    # Also include short hostname if FQDN
                    short_host = current_host.split(".")[0]
                    if short_host:
                        host_set.add(short_host)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not detect current hostname: %s", exc)

        # Longest first so partial matches don't shadow longer names
        self.usernames: list[str] = sorted(user_set, key=len, reverse=True)
        self.hostnames: list[str] = sorted(host_set, key=len, reverse=True)

    def redact(self, text: str) -> tuple[str, dict[str, str]]:
        """Replace sensitive values in *text* with numbered placeholders.

        Returns:
            ``(redacted_text, mapping)`` where ``mapping`` maps each
            placeholder (e.g. ``"[IP-1]"``) back to the original value.
        """
        if not text:
            return text, {}

        mapping: dict[str, str] = {}
        reverse_map: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = {}

        def _placeholder(category: str, original: str) -> str:
            key = (category, original)
            if key in reverse_map:
                return reverse_map[key]
            count = counters.get(category, 0) + 1
            counters[category] = count
            token = f"[{category}-{count}]"
            reverse_map[key] = token
            mapping[token] = original
            return token

        # 1. Shield URLs so rule source links are not mangled by path regexes
        urls: list[str] = []

        def _shield_url(match: re.Match[str]) -> str:
            idx = len(urls)
            urls.append(match.group(0))
            return f"__SECSCAN_URL_{idx}__"

        result = _URL_RE.sub(_shield_url, text)

        # 2. MAC addresses (before IPv6, since both use colons)
        result = _MAC_RE.sub(lambda m: _placeholder("MAC", m.group(0)), result)

        # 3. IPv6 addresses (before IPv4, since IPv6 can contain dots/colons)
        result = _IPV6_RE.sub(lambda m: _placeholder("IP", m.group(0)), result)

        # 4. IPv4 addresses
        result = _IPV4_RE.sub(lambda m: _placeholder("IP", m.group(0)), result)

        # 5. Windows file paths (before DOMAIN\user and POSIX paths)
        result = _WIN_PATH_RE.sub(lambda m: _placeholder("PATH", m.group(0)), result)

        # 6. Windows DOMAIN\username
        result = _DOMAIN_USER_RE.sub(lambda m: _placeholder("USER", m.group(0)), result)

        # 7. POSIX file paths
        result = _POSIX_PATH_RE.sub(lambda m: _placeholder("PATH", m.group(0)), result)

        # 8. Known hostnames (case-insensitive, whole-word)
        for host in self.hostnames:
            pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(host)}(?![A-Za-z0-9_-])", re.I)
            result = pattern.sub(lambda m: _placeholder("HOST", m.group(0)), result)

        # 9. Known usernames (case-insensitive, whole-word)
        for user in self.usernames:
            pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(user)}(?![A-Za-z0-9_-])", re.I)
            result = pattern.sub(lambda m: _placeholder("USER", m.group(0)), result)

        # 10. Restore shielded URLs (redacting any hostname/IP inside them if present)
        for idx, url in enumerate(urls):
            restored = url
            for host in self.hostnames:
                pat = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(host)}(?![A-Za-z0-9_-])", re.I)
                restored = pat.sub(lambda m: _placeholder("HOST", m.group(0)), restored)
            result = result.replace(f"__SECSCAN_URL_{idx}__", restored)

        return result, mapping
