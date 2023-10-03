from nizkpauth.profiles import Profile, ProverProfile
from nizkpauth.crypto.curves import Curve
from nizkpauth.crypto.hashes import Hash
from nizkpauth.exceptions import InvalidProfileFormat

import os
import json
import pytest


class TestProverProfileWithValidInput:
    curve = Curve("p256")
    hash = Hash("sha256")
    user_id = "user@email"
    filepath = f"profiles/{user_id}.json"

    def test_creation_with_valid_parameters(self):
        try:
            profile = ProverProfile(self.user_id, self.curve, self.hash)
            profile.generate_keys()

        except Exception as e:
            assert False, f"Exception {e} was raised"

    def test_from_dict_creation(self):
        with open(self.filepath, "r") as f:
            profile_data = json.load(f)

        try:
            loaded_profile = ProverProfile.from_dict(profile_data)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )

    def test_to_dict_conversion(self):
        try:
            profile = ProverProfile(self.user_id, self.curve, self.hash)
            profile.generate_keys()
            profile_dict = profile.to_dict()

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert profile_dict.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )

    def test_json_export(self):
        loaded_profile = ProverProfile.load_from_file(self.filepath)

        with open(self.filepath, "r") as f:
            json_string = f.read()

        try:
            loaded_profile_json = loaded_profile.export_json()

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert json_string == loaded_profile_json

    def test_json_import(self):
        with open(self.filepath, "r") as f:
            json_string = f.read()

        try:
            loaded_profile = ProverProfile.import_json(json_string)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )

    def test_save_in_file(self):
        test_path = 'profiles/test.json'
        try:
            profile = ProverProfile(self.user_id, self.curve, self.hash)
            profile.generate_keys()
            profile.save_to_file(test_path)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert os.path.isfile(test_path)

    def test_load_from_file(self):

        try:
            loaded_profile = ProverProfile.load_from_file(self.filepath)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key", "private_key")
        )



class TestPublicProfileWithValidInput:
    user_id = "user@email"
    filepath = f"profiles/{user_id}_public.json"

    def test_load_from_file(self):
        try:
            loaded_profile = Profile.load_from_file(self.filepath)

        except Exception as e:
            assert False, f"Exception {e} was raised"

        assert loaded_profile.__dict__.keys() == set(
            ("user_id", "curve", "hash", "public_key")
        )


class TestProfileWithInvalidInput:
    user_id = "user@email"
    filepath_private = f"profiles/{user_id}.json"
    filepath_public = f"profiles/{user_id}_public.json"

    def test_load_public_from_private_format(self):
        with pytest.raises(InvalidProfileFormat):
            profile = Profile.load_from_file(self.filepath_private)

    def test_load_private_from_public_format(self):
        with pytest.raises(InvalidProfileFormat):
            profile = ProverProfile.load_from_file(self.filepath_public)

    ...