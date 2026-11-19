"""CA bundle for networks that inspect TLS (corporate proxies such as Zscaler).

boto3 and requests trust only the bundled ``certifi`` roots. A TLS-inspecting proxy re-signs some AWS hostnames
(here: the global endpoints of Route 53, CloudFront and WAF Classic) with its own root CA, which is normally installed
in the operating system's trust store but unknown to ``certifi``: calls then fail with CERTIFICATE_VERIFY_FAILED.

``build_ca_bundle`` writes ``certifi`` plus the operating system's trusted root certificates (Windows only) to one
PEM file. Point ``AWS_CA_BUNDLE`` (boto3) and ``REQUESTS_CA_BUNDLE`` (Akamai) at it. Certificates are public; the file
holds no secrets.
"""
from __future__ import annotations

import ssl
from pathlib import Path

import certifi

SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"


def system_roots() -> list[str]:
    """PEM text of the OS-trusted root/intermediate CA certificates usable for TLS servers (empty off Windows)."""
    if not hasattr(ssl, "enum_certificates"):
        return []
    seen: set[bytes] = set()
    pems: list[str] = []
    for store in ("ROOT", "CA"):
        for der, encoding, trust in ssl.enum_certificates(store):
            if encoding != "x509_asn" or der in seen:
                continue
            if trust is not True and SERVER_AUTH_OID not in trust:
                continue  # trusted for other purposes only (code signing, ...)
            seen.add(der)
            pems.append(ssl.DER_cert_to_PEM_cert(der))
    return pems


def build_ca_bundle(out: Path) -> tuple[int, int]:
    """Write the bundle; returns ``(certifi certificates, system certificates added)``."""
    base = Path(certifi.where()).read_text(encoding="ascii")
    extra = system_roots()
    out.write_text(base.rstrip() + "\n" + "".join(extra), encoding="ascii")
    return base.count("BEGIN CERTIFICATE"), len(extra)
