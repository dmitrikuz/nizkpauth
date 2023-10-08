from nizkpauth.profiles import Profile, ProverProfile
from nizkpauth.prover import Prover
from nizkpauth.verifier import Verifier
from nizkpauth.crypto.hashes import Hash
from nizkpauth.crypto.curves import Curve

USER_ID = 'test_verification'

class TestVerifier:

    prover_profile = ProverProfile(user_id=USER_ID, curve=Curve('p256'), hash=Hash('sha256'))
    prover_profile.generate_keys()
    verifier_profile = prover_profile.to_public()

    def test_verifier_creation(self):
        try:
            verifier = Verifier(self.verifier_profile)
        except Exception as e:
            assert False, f'Exception {e} has occured'

    def test_valid_proof_verification(self):
        prover = Prover(self.prover_profile)
        proof = prover.create_proof()

        verifier = Verifier(self.verifier_profile)
        verification_result = verifier.verify_proof(proof)

        assert verification_result == True


    def test_invalid_proof_verification(self):
        prover = Prover(self.prover_profile)
        proof = prover.create_proof()

        proof.challenge += 1

        verifier = Verifier(self.verifier_profile)
        verification_result = verifier.verify_proof(proof)

        assert verification_result == False


