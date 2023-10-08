import json
import os

import pytest

from nizkpauth.crypto.curves import Curve
from nizkpauth.crypto.hashes import Hash
from nizkpauth.crypto.keys import PrivateKey
from nizkpauth.exceptions import (InvalidCurveError,
                                  InvalidHashCurveCombinationError,
                                  InvalidHashError, InvalidProfileFormat)
from nizkpauth.profiles import Profile, ProverProfile


class TestProverProfileWithValidInput:
    curve = Curve("p256")
    hash = Hash("sha256")
    private_key = PrivateKey.generate(curve)
    public_key = private_key.public_key()
    user_id = "user@email"
    filepath = f"profiles/{user_id}.json"

    def test_creation_with_valid_parameters(self):
        try:
            profile = ProverProfile(user_id=self.user_id, curve=self.curve, hash=self.hash)
            profile.generate_keys()
            self.profile = profile

        except Exception as e:
            assert False, f"Exception {e} was raised"

    def test_from_dict_creation(self):
        profile_data = {'user_id': self.user_id, 'curve': self.curve.name, 'hash': self.hash.name, 'public_key': self.public_key.to_hex(), 'private_key': self.private_key.to_hex()}

        try:
            loaded_profile = ProverProfile.from_dict(profile_data)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )

    def test_to_dict_conversion(self):
        profile = ProverProfile(user_id=self.user_id, curve=self.curve, hash=self.hash, private_key=self.private_key, public_key=self.public_key)
        try:
            profile_dict = profile.to_dict()

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert profile_dict.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )

    def test_json_export(self):
        profile = ProverProfile(user_id=self.user_id, curve=self.curve, hash=self.hash)
        profile.generate_keys()
        profile_data = {'user_id': self.user_id, 'curve': self.curve.name, 'hash': self.hash.name, 'public_key': profile.public_key.to_hex(), 'private_key': profile.private_key.to_hex()}
        profile_data_json = json.dumps(profile_data, indent=4)
        

        try:
            loaded_profile_json = profile.export_json()

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert profile_data_json == loaded_profile_json


    def test_json_import(self):
        profile_data = {'user_id': self.user_id, 'curve': self.curve.name, 'hash': self.hash.name, 'public_key': self.public_key.to_hex(), 'private_key': self.private_key.to_hex()}
        profile_data_json = json.dumps(profile_data)

        try:
            loaded_profile = ProverProfile.import_json(profile_data_json)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )

    def test_save_in_file(self):
        test_path = 'profiles/test_private.json'
        try:
            profile = ProverProfile(user_id=self.user_id, curve=self.curve, hash=self.hash)
            profile.generate_keys()
            profile.save_to_file(test_path)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert os.path.isfile(test_path)

    def test_load_from_file(self):
        test_path = 'profiles/test_private.json'
        try:
            loaded_profile = ProverProfile.load_from_file(test_path)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )



class TestPublicProfileWithValidInput:
    filepath = 'profiles/test_public.json'

    def test_save_to_file(self):
        
        profile = ProverProfile(user_id='test_public', curve=Curve('p256'), hash=Hash('sha256'))
        profile.generate_keys()
        profile = profile.to_public()
        profile.save_to_file(self.filepath)

    def test_load_from_file(self):
        try:
            loaded_profile = Profile.load_from_file(self.filepath)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key")
        )


class TestProfileWithInvalidInput:
    filepath_private = f"profiles/test_private.json"
    filepath_public = f"profiles/test_public.json"

    def test_load_public_from_private_format(self):
        with pytest.raises(InvalidProfileFormat):
            profile = Profile.load_from_file(self.filepath_private)

    def test_load_private_from_public_format(self):
        with pytest.raises(InvalidProfileFormat):
            profile = ProverProfile.load_from_file(self.filepath_public)

    def test_invalid_hash(self):

        with pytest.raises(InvalidHashError):
            curve = Curve("p256")
            hash = Hash("Non existing hash")
            profile = ProverProfile(user_id='user', curve=curve, hash=hash)

    def test_invalid_curve(self):
        with pytest.raises(InvalidCurveError):
            curve = Curve("Non existing curve")
            hash = Hash("sha256")
            profile = ProverProfile(user_id='user', curve=curve, hash=hash)


    def test_invalid_hash_curve_combination(self):
        curve = Curve("p256")
        hash = Hash("sha224")
        with pytest.raises(InvalidHashCurveCombinationError):
            profile = ProverProfile(user_id='user', curve=curve, hash=hash)