from pycrypto_rsa_legacy import NativeRSAKey as PlainRSAKey
from base import AbstractTests


class TestNative(AbstractTests.TestRSA):

    def get_key_implementation(self):
        return PlainRSAKey
