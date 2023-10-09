import binascii

from Crypto.PublicKey import ECC as ecc

from nizkpauth.exceptions import InvalidKeyError


class Key:
    fixed_der_starting_bytes = b"0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04"

    def __init__(self, ecc_key):
        self._ecc_key = ecc_key

    def to_hex(self):
        der_bytes = self.to_der()
        return binascii.b2a_hex(der_bytes).decode()

    @classmethod
    def from_hex(cls, hex_string):
        key_bytes = binascii.a2b_hex(hex_string)
        key = cls.from_der(key_bytes, missing_bytes=True)
        return key

    def to_b64(self):
        der_bytes = self.to_der()
        return binascii.b2a_base64(der_bytes, newline=False).decode()

    @classmethod
    def from_b64(cls, string):
        key_bytes = binascii.a2b_base64(string)
        key = cls.from_der(key_bytes, missing_bytes=True)
        return key

    def to_der(self):
        return self._ecc_key.export_key(format="DER")[
            len(self.fixed_der_starting_bytes) :
        ]

    @classmethod
    def from_der(cls, der_bytes, missing_bytes=False):
        added_part = cls.fixed_der_starting_bytes if missing_bytes else b""
        key = ecc.import_key(added_part + der_bytes)
        return cls(key)

    def to_binary(self):
        return self._ecc_key.export_key(format="raw")

    def to_file(self, path):
        ...

    @classmethod
    def from_file(cls, path):
        ...

    def to_str(self):
        return self.to_b64()

    @classmethod
    def from_str(cls, string):
        try:
            key = cls.from_b64(string)

        except ValueError as e:
            raise InvalidKeyError("Wrong key format")

        return key

    @classmethod
    def from_point_on_curve(cls, curve, x, y):
        return cls(ecc.construct(curve=curve, point_x=x, point_y=y))

    @property
    def point(self):
        return self._ecc_key.pointQ


class PrivateKey(Key):
    fixed_der_starting_bytes = b"0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 "

    def public_key(self):
        return Key(self._ecc_key.public_key())

    @staticmethod
    def generate(curve):
        return __class__(ecc.generate(curve=curve.name))

    @property
    def private_component(self):
        return self._ecc_key.d
