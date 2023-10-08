import binascii

from Crypto.PublicKey import ECC as ecc

from nizkpauth.exceptions import InvalidKeyError


class Key:
    def __init__(self, ecc_key):
        self._ecc_key = ecc_key

    def to_hex(self):
        der_bytes = self._ecc_key.export_key(format='DER')
        return binascii.b2a_hex(der_bytes).decode()
    
    def to_b64(self):
        der_bytes = self._ecc_key.export_key(format='DER')
        return binascii.b2a_base64(der_bytes).decode()
    
    def to_binary(self):
        return self._ecc_key.export_key(format='raw')
    
    def to_file(self, path):
        ...

    @classmethod
    def from_file(cls, path):
        ...
    
    @classmethod
    def from_hex(cls, hex_string):
        key_bytes = binascii.a2b_hex(hex_string)
        key = ecc.import_key(key_bytes)
        return key
    
    @classmethod
    def from_b64(cls, string):
        key_bytes = binascii.a2b_base64(string)
        key = ecc.import_key(key_bytes)
        return key

    def to_str(self):
        return self.to_b64()
    
    @classmethod
    def from_str(cls, string):
        try:
            key = cls.from_b64(string)

        except ValueError as e:
            raise InvalidKeyError('Wrong key format')

        return cls(key)
    
    
    
    @classmethod
    def from_point_on_curve(cls, curve, x, y):
        return cls(ecc.construct(curve=curve, point_x=x, point_y=y))
    
    @property
    def point(self):
        return self._ecc_key.pointQ
    
    

class PrivateKey(Key):
    def public_key(self):
        return Key(self._ecc_key.public_key())
    
    @staticmethod
    def generate(curve):
        return __class__(ecc.generate(curve=curve.name))

    @property
    def private_component(self):
        return self._ecc_key.d