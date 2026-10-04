"""Unit tests only; they never run cPanel or mark fixtures observed."""
import hashlib
import unittest

import capture


class CaptureTests(unittest.TestCase):
    def test_canonical_exact_envelope_integers(self):
        self.assertEqual(capture.canonical({"b": -1200, "a": [0, True, 255]}),
                         '{"a":[0,true,2.55e2],"b":-1.2e3}')
        self.assertEqual(capture.canonical("<>&\u2028"), '"\\u003c\\u003e\\u0026\\u2028"')
        with self.assertRaises(ValueError):
            capture.canonical(1.5)

    def test_digest_excludes_only_sha256(self):
        value = {"id": "fixture", "sha256": "old"}
        sealed = capture.seal(value)
        expected = hashlib.sha256(b'{"id":"fixture"}').hexdigest()
        self.assertEqual(sealed["sha256"], expected)
        self.assertNotEqual(capture.seal({"id": "altered"})["sha256"], expected)

    def test_arbitrary_commands_rejected_without_execution(self):
        for argv in [("/bin/sh", "-c", "true"), (capture.WHMAPI1, "createacct"),
                     (capture.WHMAPI1, "--output=jsonpretty", "version", "token=secret")]:
            with self.assertRaises(ValueError):
                capture.capture(argv)

    def test_strict_response_json(self):
        self.assertEqual(capture.strict_json('{"metadata":{"result":0}}')["metadata"]["result"], 0)
        for text in ['{"a":1,"a":2}', '{"x":NaN}', '{}{}']:
            with self.assertRaises(ValueError):
                capture.strict_json(text)


if __name__ == "__main__":
    unittest.main()
