

from dataclasses import fields, dataclass
from datetime import datetime

from dataclasses_json import dataclass_json

from nizkpauth.crypto.keys import PrivateKey
from nizkpauth.crypto.utils import compute_challenge
from nizkpauth.exceptions import InvalidProofFormat
from nizkpauth.profiles import ProverProfile
from nizkpauth.utils import encode_string, decode_string


class Prover:
    def __init__(self, profile: ProverProfile):
        self._profile = profile

    def create_proof(self):
        other_info = self._other_info()
        proof_value_private, proof_value_public = self._proof_values_pair()
        challenge = self._challenge(proof_value_public, other_info)
        residue = self._residue(proof_value_private, challenge)

        proof = Proof(
            self._profile.user_id, 
            other_info, 
            residue, 
            challenge
        )

        return proof

    def _other_info(self):
        return datetime.strftime(datetime.now(), "%H:%M:%S %d/%m/%Y")

    def _proof_values_pair(self):
        proof_value_private = PrivateKey.generate(self._profile.curve)
        proof_value_public = proof_value_private.public_key()
        return proof_value_private, proof_value_public

    def _challenge(self, proof_value_public, other_info):
        challenge = compute_challenge(
            curve_generator_point=self._profile.curve.base_point_as_key,
            proof_value=proof_value_public,
            public_key=self._profile.public_key,
            user_id=self._profile.user_id,
            other_info=other_info,
            hash_name=self._profile.hash.name,
        )
        return challenge

    def _residue(self, proof_value_private, challenge):
        residue = (
            proof_value_private.private_component - self._profile.private_key.private_component * challenge
        ) % self._profile.curve.order
        residue = int(residue)
        return residue


@dataclass_json
@dataclass
class Proof:
    user_id: str
    other_info: str
    residue: int
    challenge: int

    def to_encoded(self):
        return encode_string(self.to_json())
    
    @classmethod
    def from_encoded(cls, string):
        try:
            return cls.from_json(decode_string(string))
        except (KeyError, UnicodeDecodeError):
            raise InvalidProofFormat
    
    def __post_init__(self):
        for field in fields(self):
            if not isinstance(getattr(self, field.name), field.type):
                raise InvalidProofFormat