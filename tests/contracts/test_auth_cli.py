import copy
import unittest

from jsonschema import Draft202012Validator
from test_protocol_storage import REGISTRY, load


class AuthCLIContractTests(unittest.TestCase):
    def test_public_session_result_contains_no_credential(self):
        schema = load("contracts/api/v1/local-response.schema.json")
        validator = Draft202012Validator(
            {"$ref": schema["$id"] + "#/$defs/authSessionCLI"}, registry=REGISTRY
        )
        result = {
            "schema_version": "1.0",
            "status": "signed_in",
            "session_file": "/private/session.json",
            "expires_ms": 1800000000000,
            "user": {
                "id": "00000000-0000-4000-8000-000000000001",
                "revision": 1, "name": "owner", "role": "admin",
                "disabled": False, "historical_restored": False,
                "trust_generation": "00000000-0000-4000-8000-000000000002",
            },
        }
        validator.validate(result)
        result["status"] = "signed_out"
        validator.validate(result)
        for field in ("cookie", "csrf_token", "password", "token"):
            leaked = copy.deepcopy(result)
            leaked[field] = "secret"
            with self.assertRaises(Exception):
                validator.validate(leaked)


if __name__ == "__main__":
    unittest.main()
