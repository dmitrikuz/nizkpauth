from nizkpauth.prover import Prover, Proof
from nizkpauth.profiles import ProverProfile
from nizkpauth.exceptions import InvalidProofFormat

import json
import re
import pytest

USER_ID = 'user@email'
FILEPATH = f"profiles/{USER_ID}.json"

class TestProverWithValidInput:
    def test_prover_creation(self):
        profile = ProverProfile.load_from_file(FILEPATH)
        try:
            prover = Prover(profile)

        except Exception as e:
            assert False, f'Exception {e} hash occured'

    def test_prover_proof_creation(self):
        profile = ProverProfile.load_from_file(FILEPATH)
        prover = Prover(profile)

        try:
            proof = prover.create_proof()

        except Exception as e:
            assert False, f'Exception {e} has occured'


    def test_proof_export(self):
        b64_regex = r'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$'

        profile = ProverProfile.load_from_file(FILEPATH)
        prover = Prover(profile)
        proof = prover.create_proof()

        try:
            json_proof = proof.to_json()
            encoded_proof = proof.to_encoded()

        except Exception as e:
            assert False, f'Exception {e} has occured'

        assert json.dumps(vars(proof)) == json_proof
        assert re.match(b64_regex, encoded_proof)


    def test_proof_json_import(self):
        params = dict(user_id='user', other_info='0', residue=15, challenge=123)
        proof = Proof(**params)
        proof_json = json.dumps(params)
        
        try:
            proof_from_json = Proof.from_json(proof_json)

        except Exception as e:
            assert False, f'Exception {e} has occured'

        assert proof == proof_from_json


    def test_proof_decoding(self):
        params = dict(user_id='user', other_info='0', residue=15, challenge=123)
        proof = Proof(**params)
        b64str = proof.to_encoded()

        try:
            proof_from_encoded = Proof.from_encoded(b64str)

        except Exception as e:
            assert False, f'Exception {e} has occured'

        assert proof == proof_from_encoded

    
    def test_proof_import_with_invalid_parameters_type(self):
        params = dict(user_id='user', other_info=12, residue='a', challenge='string')
        with pytest.raises(InvalidProofFormat):
            proof = Proof(**params)


