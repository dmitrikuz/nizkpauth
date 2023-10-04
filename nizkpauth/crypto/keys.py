from Crypto.PublicKey import ECC as ecc
from nizkpauth.exceptions import InvalidKeyError

class Key:
    def __init__(self, ecc_key):
        self._ecc_key = ecc_key

    def to_hex(self):
        return self._ecc_key.export_key(format="DER").hex()
    
    def to_binary(self):
        return self._ecc_key.export_key(format='raw')
    
    def to_file(self, path):
        ...

    @classmethod
    def from_file(cls, path):
        ...
    
    @classmethod
    def from_hex(cls, hex_string):
        key_bytes = bytes.fromhex(hex_string)
        
        try:
            key = ecc.import_key(key_bytes)

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

