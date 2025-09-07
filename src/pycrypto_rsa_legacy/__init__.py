from .rsa import PlainRSAKey as PythonPlainRSAKey

try:
    from .rsa import PlainRSAKey as PythonPlainRSAKey
    from _pycrypto_rsa_legacy import PlainRSAKey as NativeRSAKey

    PlainRSAKey: type[NativeRSAKey] | type[PythonPlainRSAKey] = NativeRSAKey

except ImportError:
    PlainRSAKey = PythonPlainRSAKey
