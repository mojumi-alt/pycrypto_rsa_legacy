try:
    from .plain_rsa_key import PlainRSAKey as PythonRSAKey
    from ._plain_rsa_key import PlainRSAKey as NativeRSAKey

    PlainRSAKey: type[NativeRSAKey] | type[PythonRSAKey] = NativeRSAKey

except ImportError:
    PlainRSAKey = PythonRSAKey
