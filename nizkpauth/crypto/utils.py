import hashlib

from Crypto.PublicKey import ECC as ecc
from nizkpauth import utils

from .keys import Key


def compute_challenge(
    *,
    curve_generator_point: Key,
    proof_value: Key,
    public_key: Key,
    user_id: str,
    other_info: str,
    hash_name: str
):
    challenge = hashlib.new(hash_name)
    challenge.update(curve_generator_point.to_binary())
    challenge.update(proof_value.to_binary())
    challenge.update(public_key.to_binary())
    challenge.update(utils.from_string_to_binary(user_id))
    challenge.update(utils.from_string_to_binary(other_info))
    challenge = int(challenge.hexdigest(), 16)

    return challenge