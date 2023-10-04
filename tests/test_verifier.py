from nizkpauth.profiles import Profile, ProverProfile
from nizkpauth.prover import Prover
from nizkpauth.verifier import Verifier
from nizkpauth.crypto.hashes import Hash
from nizkpauth.crypto.curves import Curve

USER_ID = 'verification_test_user@email.com'
FILEPATH_PUBLIC = f'profiles/{USER_ID}_public.json'
FILEPATH_PRIVATE = f'profiles/{USER_ID}_private.json'

class TestVerifier:

    def test_verifier_creation(self):
        verifier_profile = Profile.load_from_file(FILEPATH_PUBLIC)
        try:
            verifier = Verifier(verifier_profile)
        except Exception as e:
            assert False, f'Exception {e} has occured'

    def test_valid_proof_verification(self):
        prover_profile = ProverProfile.load_from_file(FILEPATH_PRIVATE)
        prover = Prover(prover_profile)
        proof = prover.create_proof()

        verifier_profile = Profile.load_from_file(FILEPATH_PUBLIC)
        verifier = Verifier(verifier_profile)
        verification_result = verifier.verify_proof(proof)

        assert verification_result == True


    def test_invalid_proof_verification(self):
        prover_profile = ProverProfile.load_from_file(FILEPATH_PRIVATE)
        prover = Prover(prover_profile)
        proof = prover.create_proof()
        proof.challenge += 1

        verifier_profile = Profile.load_from_file(FILEPATH_PUBLIC)
        verifier = Verifier(verifier_profile)
        verification_result = verifier.verify_proof(proof)

        assert verification_result == False


