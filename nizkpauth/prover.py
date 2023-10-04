

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
        self._set_other_info()
        self._set_proof_value()
        self._set_challenge()
        self._set_residue()

        proof = Proof(
            self._profile.user_id, 
            self.other_info, 
            self.residue, 
            self.challenge
        )

        return proof

    def _set_other_info(self):
        self.other_info = datetime.strftime(datetime.now(), "%H:%M:%S %d/%m/%Y")

    def _set_proof_value(self):
        self.proof_value_private = PrivateKey.generate(self._profile.curve)
        self.proof_value = self.proof_value_private.public_key()

    def _set_residue(self):
        residue = (
            self.proof_value_private.private_component - self._profile.private_key.private_component * self.challenge
        ) % self._profile.curve.order
        self.residue = int(residue)

    def _set_challenge(self):
        self.challenge = compute_challenge(
            curve_generator_point=self._profile.curve.base_point_as_key,
            proof_value=self.proof_value,
            public_key=self._profile.public_key,
            user_id=self._profile.user_id,
            other_info=self.other_info,
            hash_name=self._profile.hash.name,
        )



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
        return cls.from_json(decode_string(string))
    
    def __post_init__(self):
        for field in fields(self):
            if not isinstance(getattr(self, field.name), field.type):
                raise InvalidProofFormat

