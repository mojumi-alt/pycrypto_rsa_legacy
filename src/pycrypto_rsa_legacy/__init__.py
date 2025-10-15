from .plain_rsa_key import PlainRSAKey

try:
    # Use native module if available
    from ._plain_rsa_key import PlainRSAKey  # type: ignore
except ImportError:
    pass


def import_key(key_data: str | bytes) -> PlainRSAKey:
    """
    Imports an RSA key from bytes.
    This operation requires pycryptodome.

    Args:
        key_data (str | bytes): byte representation of the key to import

    Raises:
        ValueError: If pycryptodome is not available

    Returns:
        PlainRSAKey: A new plain rsa key
    """

    try:
        from Crypto.PublicKey import RSA  # type: ignore
    except ImportError:
        raise ValueError("pycryptodome is required for this operation")

    raw = RSA.import_key(key_data)

    return PlainRSAKey(
        n=raw.n,
        e=raw.e,
        d=raw.d,
        p=raw.p,
        q=raw.q,
        u=raw.u,
    )
