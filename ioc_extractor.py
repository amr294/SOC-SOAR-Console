import ipaddress
import re


_HEX = re.compile(r"^[0-9a-fA-F]+$")

_HASH_TYPES = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
}

# Wazuh FIM (syscheck) hash fields.
_SYSCHECK_FIELDS = (
    "sha256_after",
    "sha1_after",
    "md5_after",
)


def _public_ip(value):
    """
    Return (normalized_value, type) for a globally routable IP,
    or None for private, loopback, link-local, etc.

    Internal addresses are not useful to look up externally and
    would leak internal addressing to a third party.
    """

    if not isinstance(value, str):
        return None

    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if not ip.is_global:
        return None

    return str(ip), f"IPv{ip.version}"


def is_public_ip(value):
    """True if value is a globally routable IP address."""

    return _public_ip(value) is not None


def extract_iocs(src_ip=None, dst_ip=None, event=None):
    """
    Extract enrichable indicators from one normalized alert.

    Returns a de-duplicated list of (value, type) tuples:
        public IPv4/IPv6 addresses from src_ip / dst_ip
        file hashes from Wazuh syscheck data
    """

    found = []
    seen = set()

    def add(item):
        if item is not None and item[0] not in seen:
            seen.add(item[0])
            found.append(item)

    add(_public_ip(src_ip))
    add(_public_ip(dst_ip))

    syscheck = (
        event.get("syscheck")
        if isinstance(event, dict)
        else None
    )

    if isinstance(syscheck, dict):
        for field in _SYSCHECK_FIELDS:
            digest = syscheck.get(field)

            if (
                isinstance(digest, str)
                and _HEX.match(digest)
                and len(digest) in _HASH_TYPES
            ):
                add((digest.lower(), _HASH_TYPES[len(digest)]))

    return found
