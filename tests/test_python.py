from pycrypto_rsa_legacy import PythonRSAKey as PlainRSAKey
from base import AbstractTests


class TestPython(AbstractTests.TestRSA):

    def get_key_implementation(self):
        return PlainRSAKey
