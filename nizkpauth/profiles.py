import json
from nizkpauth.crypto.keys import Key, PrivateKey
from nizkpauth.crypto.curves import Curve
from nizkpauth.crypto.hashes import Hash
from nizkpauth.exceptions import InvalidProfileFormat


class Profile:
    def __init__(self, user_id, curve, hash, public_key=None):
        self.user_id = user_id
        self.curve = curve
        self.hash = hash
        self.public_key = public_key

    def save_to_file(self, filename):
        with open(filename, "w") as f:
            profile_json = self.export_json()
            f.write(profile_json)

    @classmethod
    def load_from_file(cls, filename):
        with open(filename, "r") as f:
            profile_json = f.read()
        return cls.import_json(profile_json)

    def export_json(self):
        return json.dumps(self.to_dict(), indent=4)

    @classmethod
    def import_json(cls, json_string):
        profile_dict = json.loads(json_string)
        return cls.from_dict(profile_dict)

    def to_dict(self):
        return {
            attr: self.get_field_serializers()[attr](value)
            for attr, value in vars(self).items()
        }

    @classmethod
    def from_dict(cls, profile_dict):
        deserializers = cls.get_field_deserializers()
        if profile_dict.keys() != deserializers.keys():
            raise InvalidProfileFormat(f'Should be {deserializers.keys()}')
        try:
            params = {
                attr: deserializers[attr](value) for attr, value in profile_dict.items()
            }
        except KeyError as e:
            raise InvalidProfileFormat(f'Should be {deserializers.keys()}')

        return cls(**params)

    @classmethod
    def get_field_serializers(cls):
        return {
            "user_id": lambda x: x,
            "curve": lambda curve: curve.name,
            "hash": lambda hash: hash.name,
            "public_key": Key.to_hex,
        }

    @classmethod
    def get_field_deserializers(cls):
        return {
            "user_id": lambda x: x,
            "curve": lambda name: Curve(name),
            "hash": lambda name: Hash(name),
            "public_key": Key.from_hex,
        }


class ProverProfile(Profile):
    def __init__(self, user_id, curve, hash, public_key=None, private_key=None):
        super().__init__(user_id, curve, hash, public_key)
        self.private_key = private_key

    def generate_keys(self):
        private_key = PrivateKey.generate(self.curve)
        self.public_key, self.private_key = private_key.public_key(), private_key

    @classmethod
    def get_field_serializers(cls):
        return {**super().get_field_serializers(), **{"private_key": PrivateKey.to_hex}}

    @classmethod
    def get_field_deserializers(cls):
        return {**super().get_field_deserializers(),**{"private_key": PrivateKey.from_hex}}
