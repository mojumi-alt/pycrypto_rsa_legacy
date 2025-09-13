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
        n: int | None = ...,
        e: int | None = ...,
        d: int | None = ...,
        p: int | None = ...,
        q: int | None = ...,
        u: int | None = ...,
        key: typing.Any | None = ...,
    ) -> None: ...

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
        ...

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Apply plain rsa decryption to a given string.

        Raises:
            ValueError: If the the ciphertext is too big
            ValueError: If the private key is not set on this rsa key

        Returns:
            bytes: The decrypted string as bytes. You will need to call decode() on the result if you need a string.
        """
        ...

    def sign(self, message: bytes | str) -> bytes:
        """
        Sign message using plain rsa

        Args:
            message (bytes | str): The message to sign

        Returns:
            bytes: The signed message as bytes
        """
        ...

    def verify(self, message: bytes | str, signature: bytes) -> bool:
        """
        Use plain rsa to verify a message

        Args:
            message (bytes | str): The message to verify
            signature (bytes): The signature to check against

        Returns:
            bool: Returns true if the signature matches
        """
        ...

    @property
    def is_private_key(self) -> bool:
        """
        Determines if this key can be used as a private key

        Returns:
            bool: True if 'n' and 'd' key parameters are set
        """
        ...

    @property
    def is_public_key(self) -> bool:
        """
        Determines if this key can be used as a public key

        Returns:
            bool: True if 'n' and 'e' key parameters are set
        """
        ...

    @property
    def max_message_length_bits(self) -> int:
        """
        Get the maximum length of a message in bits this key can handle

        Raises:
            ValueError: If no exponent is defined for this key

        Returns:
            int: The maximum message length in bits
        """
        ...

    @property
    def e(self) -> int | None:
        """
        Get the public key parameter for this key

        Returns:
            int | None: The parameter 'e'
        """
        ...

    @e.setter
    def e(self, value: int | None) -> None:
        """
        Set the public key parameter for this key

        Args:
            value (int | None): The parameter 'e'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        ...

    @property
    def n(self) -> int | None:
        """
        Get the exponent for this key

        Returns:
            int | None: The parameter 'n'
        """
        ...

    @n.setter
    def n(self, value: int | None) -> None:
        """
        Set the exponent for this key

        Args:
            value (int | None): The parameter 'n'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        ...

    @property
    def d(self) -> int | None:
        """
        Get the private key parameter for this key

        Returns:
            int | None: The parameter 'd'
        """
        ...

    @d.setter
    def d(self, value: int | None) -> None:
        """
        Set the private key parameter for this key

        Args:
            value (int | None): The parameter 'd'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        ...

    @property
    def p(self) -> int | None:
        """
        Get the private key factor p for this key

        Returns:
            int | None: The parameter 'p'
        """
        ...

    @p.setter
    def p(self, value: int | None) -> None:
        """
        Set the private key factor p for this key

        Args:
            value (int | None): The parameter 'p'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        ...

    @property
    def q(self) -> int | None:
        """
        Get the private key factor q for this key

        Returns:
            int | None: The parameter 'q'
        """
        ...

    @q.setter
    def q(self, value: int | None) -> None:
        """
        Set the private key factor q for this key

        Args:
            value (int | None): The parameter 'q'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        ...

    @property
    def u(self) -> int | None:
        """
        Get the private key factor u for this key

        Returns:
            int | None: The parameter 'u'
        """
        ...

    @u.setter
    def u(self, value: int | None) -> None:
        """
        Set the private key factor u for this key

        Args:
            value (int | None): The parameter 'u'

        Raises:
            TypeError: Value must be either 'int' or 'None'
        """
        ...
