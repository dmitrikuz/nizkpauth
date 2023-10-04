from Crypto.PublicKey import ECC as ecc
from nizkpauth.exceptions import InvalidCurveName
from nizkpauth.crypto.keys import Key



class Curve:
    def __init__(self, name):
        self._set_config(name)
        self._set_base_point()


    def _set_config(self, name):
        try:
            self._config = CURVE_PRESETS[name]

        except KeyError:
            raise InvalidCurveName

    def _set_base_point(self):
        self._base_point = ecc.construct(
            curve=self._config['name'],
            point_x=self._config['generator'][0],
            point_y=self._config['generator'][1]
        )

    @property
    def base_point_as_key(self):
        return Key(self._base_point)

    @property
    def order(self):
        return self._config['generator_order']
    
    @property
    def name(self):
        return self._config['name']
    
    @property
    def size(self):
        return self._base_point.pointQ.size_in_bits()

    
    
CURVE_PRESETS = {
    "p256":{
        "name": "p256",
        "generator": (
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        ),
        "generator_order": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    },
}