from pycrypto_rsa_legacy._plain_rsa_key import PlainRSAKey
from base import AbstractTests


class TestNative(AbstractTests.TestRSA):

    def get_key_implementation(self):
        return PlainRSAKey
