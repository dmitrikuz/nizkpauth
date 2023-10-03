from crypto import utils as crypto_utils
from crypto.keys import Key
from profiles import Profile


class Verifier:
    def __init__(self, profile: Profile):
        self._public_key = profile.public_key
        self._curve_generator_point = profile.curve.base_point_as_key
        self._hash_name = profile.hash.name
        self._curve_name = profile.curve.name

    def verify_proof(self, proof):
        self._set_proof_value(proof)
        self._set_challenge(proof)

        if self._challenge == proof.challenge:
            return True

        return False

    def _set_proof_value(self, proof):
        proof_value_point = (
            self._curve_generator_point.point * proof.residue
            + self._public_key.point * proof.challenge
        )

        proof_value = Key.from_point_on_curve(self._curve_name, *proof_value_point.xy)
        self._proof_value = proof_value

    def _set_challenge(self, proof):
        self._challenge = crypto_utils.compute_challenge(
            public_key=self._public_key,
            curve_generator_point=self._curve_generator_point,
            hash_name=self._hash_name,
            user_id=proof.user_id,
            other_info=proof.other_info,
            proof_value=self._proof_value,
        )
