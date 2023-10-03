from Crypto.PublicKey import ECC as ecc
from .curves import Curve

class Key:
    def __init__(self, ecc_key):
        self._ecc_key = ecc_key

    def to_hex(self):
        return self._ecc_key.export_key(format="DER").hex()
    
    def to_binary(self):
        return self._ecc_key.export_key(format='raw')
    
    def to_file(self, path):
        ...

    @staticmethod
    def from_file(path):
        ...
    
    @staticmethod
    def from_hex(hex_string):
        key_bytes = bytes.fromhex(hex_string)
        key = ecc.import_key(key_bytes)
        return __class__(key)
    
    @staticmethod
    def from_point_on_curve(curve, x, y):
        return __class__(ecc.construct(curve=curve, point_x=x, point_y=y))
    
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

