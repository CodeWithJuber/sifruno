import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from restore_files import restore


class RestoreTests(unittest.TestCase):
    def snapshot(self, directory, path='artifacts/example.txt', corrupt=False):
        data = b'preserved artifact\n'
        sha = hashlib.sha256(data).hexdigest()
        archive = Path(directory) / 'snapshot.zip'
        manifest = {
            'format': 'sifruno-file-snapshot-v1',
            'files': [{'path': path, 'size': len(data), 'sha256': sha}],
            'unique_objects': {sha: len(data)},
        }
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('manifest.json', json.dumps(manifest))
            output.writestr('objects/' + sha, b'changed' if corrupt else data)
        return archive, data

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, expected = self.snapshot(tmp)
            target = Path(tmp) / 'restored'
            self.assertEqual(restore(archive, target)['restored_files'], 1)
            self.assertEqual((target / 'artifacts/example.txt').read_bytes(), expected)

    def test_unsafe_paths_rejected_before_writing(self):
        for path in ('../escape', '/absolute', 'C:/drive', 'a\\b', '.git/config'):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                archive, _ = self.snapshot(tmp, path)
                target = Path(tmp) / 'restored'
                with self.assertRaises(ValueError):
                    restore(archive, target)
                self.assertFalse(target.exists())

    def test_corruption_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, _ = self.snapshot(tmp, corrupt=True)
            target = Path(tmp) / 'restored'
            with self.assertRaises(ValueError):
                restore(archive, target)
            self.assertFalse(target.exists())

    def test_existing_directory_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, _ = self.snapshot(tmp)
            with self.assertRaises(ValueError):
                restore(archive, tmp)


if __name__ == '__main__':
    unittest.main()
