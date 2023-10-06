import argparse
from nizkpauth.profiles import ProverProfile
from nizkpauth.prover import Prover
from nizkpauth.crypto.curves import Curve
from nizkpauth.crypto.hashes import Hash

def main():
    parser = argparse.ArgumentParser(
        prog="NIZKP Client",
        description="Generates profile and proof for authentication based on NIZKP",
    )
    parser.add_argument("action", choices=["profile", "proof"])
    parser.add_argument("-f", "--filename", required=False)
    parser.add_argument("-u", "--user", required=False)
    parser.add_argument("-c", "--curve", required=False, default='p256')
    parser.add_argument("-a", "--hash", required=False, default='sha256')
    parser.add_argument(
        "-e", "--encoded", required=False, default=0, type=int, choices=[0, 1]
    )

    args = parser.parse_args()

    if args.action == "profile":
        user = args.user
        curve_name = Curve(args.curve)
        hash_name = Hash(args.hash)
        
        p = ProverProfile(user_id=user, curve=curve_name, hash=hash_name)
        p.generate_keys()

        if args.filename is not None:
            p.save_to_file(args.filename)

    else:
        if args.filename is not None:
            profile = ProverProfile.load_from_file(args.filename)
            prover = Prover(profile)
            proof = prover.create_proof()

            if args.encoded:
                proof = proof.to_encoded()
            else:
                proof = proof.to_json()

            print(proof)


if __name__ == "__main__":
    main()