from pycrypto_rsa_legacy.plain_rsa_key import PlainRSAKey
from base import AbstractTests


class TestPython(AbstractTests.TestRSA):

    def get_key_implementation(self):
        return PlainRSAKey
