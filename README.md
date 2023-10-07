# nizkpauth
The program and python package used for creating and verifying non-interactive zero-knowledge proofs

Based on [RFC-8235](https://datatracker.ietf.org/doc/html/rfc8235#ref-FIPS186-4)

## Installation
```
git clone https://github.com/dmitrikuz/nizkpauth.git
pip install .
```

## Usage
### Profile creation
  `nizkpauth profile -u username -f filename`
### Proof creation
  `nizkpauth proof -f filename`
### Additional info
  `nizkpauth --help`

### Package
```python
from nizkpauth.profile import Profile, ProverProfile
from nizkpauth.prover import Prover
from nizkpauth.verifier import Verifier

# proof creation
profile = ProverProfile.load_from_file(prover_filename)
prover = Prover(profile)
proof = prover.create_proof()

# proof verification
profile = Profile.load_from_file(verifier_filename)
verifier = Verifier(profile)
verification_result = verifier.verify_proof(proof)
```
