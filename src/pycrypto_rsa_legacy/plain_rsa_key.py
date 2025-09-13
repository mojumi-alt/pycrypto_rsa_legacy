# SPDX-License-Identifier: MIT
import typing


class PlainRSAKey:
    """
    Represents a plain rsa key that offers various cryptographic functions.

    Build a new rsa key from raw parameters. Use the 'key' parameter
    to try to import from keys provided by e.g. pycryptodome

    Please note that plain rsa is _insecure_ and you should only use this
    for legacy code that does not have another choice.
    New projects should use more secure alternatives.
    """

    def __init__(
        self,
        n: int | None = None,
        e: int | None = None,
        d: int | None = None,
        p: int | None = None,
        q: int | None = None,
        u: int | None = None,
        key: typing.Any | None = None,
    ) -> None:

        if key:
            self.__n = getattr(key, "n", None)
            self.__e = getattr(key, "e", None)
            self.__d = getattr(key, "d", None)
            self.__p = getattr(key, "p", None)
            self.__q = getattr(key, "q", None)
            self.__u = getattr(key, "u", None)
        else:
            self.__n = n
            self.__e = e
            self.__d = d
            self.__p = p
            self.__q = q
            self.__u = u

    def encrypt(self, plaintext: bytes | str) -> bytes:
        """
        Apply plain rsa encryption to a string.

        Args:
            plaintext (bytes | str): The input string to encrypt

        Raises:
            ValueError: If public key is not set on this rsa key
            ValueError: If the input string it not string or bytes
            ValueError: If the plaintext is too big

        Returns:
            bytes: The encrypted string
        """

        n, e = self.__n, self.__e
        if e is None or n is None:
            raise ValueError("Public key must not be None")

        v = int.from_bytes(PlainRSAKey.__to_binary(plaintext), byteorder="big")
        if v >= n:
            raise ValueError("Plaintext too big")
        result = pow(v, e, n)
        return result.to_bytes((result.bit_length() + 7) // 8, byteorder="big")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Apply plain rsa decryption to a given string.

        Raises:
            ValueError: If the the ciphertext is too big
            ValueError: If the private key is not set on this rsa key

        Returns:
            bytes: The decrypted string as bytes. You will need to call decode() on the result if you need a string.
        """

        c = int.from_bytes(ciphertext, byteorder="big")
        n, d, p, q, u = self.__n, self.__d, self.__p, self.__q, self.__u

        if d is None or n is None:
            raise ValueError("Private key value must not be None")

        if c >= n:
            raise ValueError("Ciphertext too large")

        if p is not None and q is not None and u is not None:
            m1 = pow(c, d % (p - 1), p)
            m2 = pow(c, d % (q - 1), q)
            h = m2 - m1
            if h < 0:
                h = h + q
            h = h * u % q
            result = h * p + m1
        else:
            result = pow(c, d, n)

        return result.to_bytes((result.bit_length() + 7) // 8, byteorder="big")

    def sign(self, message: bytes | str) -> bytes:
        """
        Sign message using plain rsa

        Args:
            message (bytes | str): The message to sign

        Returns:
            bytes: The signed message as bytes
        """
        return self.decrypt(PlainRSAKey.__to_binary(message))

    def verify(self, message: bytes | str, signature: bytes) -> bool:
        """
        Use plain rsa to verify a message

        Args:
            message (bytes | str): The message to verify
            signature (bytes): The signature to check against

        Returns:
            bool: Returns true if the signature matches
        """
        return self.encrypt(signature) == PlainRSAKey.__to_binary(message)

    @property
    def is_private_key(self) -> bool:
        """
        Determines if this key can be used as a private key

        Returns:
            bool: True if 'n' and 'd' key parameters are set
        """
        return self.__n is not None and self.__d is not None

    @property
    def is_public_key(self) -> bool:
        """
        Determines if this key can be used as a public key

        Returns:
            bool: True if 'n' and 'e' key parameters are set
        """
        return self.__n is not None and self.__e is not None

    @property
    def max_message_length_bits(self) -> int:
        """
        Get the maximum length of a message in bits this key can handle

        Raises:
            ValueError: If no exponent is defined for this key

        Returns:
            int: The maximum message length in bits
        """

        n = self.__n
        if n is None:
            raise ValueError("No exponent defined for this key!")

        return n.bit_length() - 1

    @property
    def e(self) -> int | None:
        """
        Get the public key parameter for this key

        Returns:
            int | None: The parameter 'e'
        """
        return self.__e

    @e.setter
    def e(self, value: int | None) -> None:
        """
        Set the public key parameter for this key

        Args:
            value (int | None): The parameter 'e'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        if type(value) != int and value != None:
            raise TypeError("Value must either be 'None' or 'int'")
        self.__e = value

    @property
    def n(self) -> int | None:
        """
        Get the exponent for this key

        Returns:
            int | None: The parameter 'n'
        """
        return self.__n

    @n.setter
    def n(self, value: int | None) -> None:
        """
        Set the exponent for this key

        Args:
            value (int | None): The parameter 'n'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        if type(value) != int and value != None:
            raise TypeError("Value must either be 'None' or 'int'")
        self.__n = value

    @property
    def d(self) -> int | None:
        """
        Get the private key parameter for this key

        Returns:
            int | None: The parameter 'd'
        """
        return self.__d

    @d.setter
    def d(self, value: int | None) -> None:
        """
        Set the private key parameter for this key

        Args:
            value (int | None): The parameter 'd'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        if type(value) != int and value != None:
            raise TypeError("Value must either be 'None' or 'int'")
        self.__d = value

    @property
    def p(self) -> int | None:
        """
        Get the private key factor p for this key

        Returns:
            int | None: The parameter 'p'
        """
        return self.__p

    @p.setter
    def p(self, value: int | None) -> None:
        """
        Set the private key factor p for this key

        Args:
            value (int | None): The parameter 'p'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        if type(value) != int and value != None:
            raise TypeError("Value must either be 'None' or 'int'")
        self.__p = value

    @property
    def q(self) -> int | None:
        """
        Get the private key factor q for this key

        Returns:
            int | None: The parameter 'q'
        """
        return self.__q

    @q.setter
    def q(self, value: int | None) -> None:
        """
        Set the private key factor q for this key

        Args:
            value (int | None): The parameter 'q'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        if type(value) != int and value != None:
            raise TypeError("Value must either be 'None' or 'int'")
        self.__q = value

    @property
    def u(self) -> int | None:
        """
        Get the private key factor u for this key

        Returns:
            int | None: The parameter 'u'
        """
        return self.__u

    @u.setter
    def u(self, value: int | None) -> None:
        """
        Set the private key factor u for this key

        Args:
            value (int | None): The parameter 'u'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        if type(value) != int and value != None:
            raise TypeError("Value must either be 'None' or 'int'")
        self.__u = value

    @staticmethod
    def __to_binary(value: bytes | str) -> bytes:
        if type(value) == str:
            return value.encode("latin-1")
        elif type(value) == bytes:
            return value
        else:
            raise ValueError("Input must either be string or bytes")
