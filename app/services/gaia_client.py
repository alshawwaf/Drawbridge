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


def ensure_pinned(db, gw) -> bool:
    """Trust-on-first-use: if the gateway opts into auto-trust and has no cert pinned yet, fetch the
    cert it currently presents and pin it to the profile. The apply/fetch that follows then verifies
    against this pinned PEM — TLS verification is never disabled, we just decide what to trust.

    Best-effort: if the gateway is unreachable right now we leave the cert empty and try again on the
    next connect. Returns True when a cert was newly pinned. Safe to call on every connect — once a
    cert is present it's a no-op.
    """
    if not getattr(gw, "auto_trust", False) or (gw.cert_pem or "").strip():
        return False
    try:
        pem = fetch_gateway_cert(gw.host, gw.port).get("pem", "").strip()
    except Exception:
        return False
    if not pem:
        return False
    gw.cert_pem = pem
    db.commit()
    return True
