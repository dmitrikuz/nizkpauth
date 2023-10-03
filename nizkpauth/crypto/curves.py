from Crypto.PublicKey import ECC as ecc



class Curve:
    def __init__(self, name):
        self.__config =CURVE_PRESETS[name]
        self.__set_base_point()


    def __set_base_point(self):
        self.__base_point = ecc.construct(
            curve=self.__config['name'],
            point_x=self.__config['generator'][0],
            point_y=self.__config['generator'][1]
        )

    @property
    def base_point_as_key(self):
        return self.__base_point
    
    @property
    def order(self):
        return self.__config['generator_order']
    
    @property
    def name(self):
        return self.__config['name']
    
    
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