"""Gateway TLS helper: fetch a gateway's certificate so the SE can review its fingerprint and
pin it (trust-on-first-use), without ever disabling TLS verification on the actual apply.

This is the policy-safe alternative to a "skip TLS verify" toggle: we retrieve the presented
certificate once for review, then the apply (in apply_runner) verifies against that pinned PEM.
"""
import hashlib
import ssl


def fetch_gateway_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Retrieve the gateway's leaf certificate (PEM) and its SHA-256 fingerprint for review."""
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest().upper()
    fingerprint = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    return {"pem": pem.strip(), "fingerprint": fingerprint}
