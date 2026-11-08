"""Pure bundle-path checks; never run the live host acceptance runner."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validation.bundle_path import resolve_bundle_path


class BundlePathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cheesetrap-path-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def directory(self, name):
        path = self.root / name
        path.mkdir()
        return path

    def test_accepts_caller_selected_parent(self):
        path = self.directory('cheesetrap-f0102-test')
        self.assertNotEqual(path.parent, Path('/home/ubuntu'))
        self.assertEqual(resolve_bundle_path(str(path)), path)

    def test_accepts_existing_name_boundaries(self):
        for name in ('cheesetrap-f0102-', 'cheesetrap-f0102-' + 'a' * 31):
            with self.subTest(name=name):
                path = self.directory(name)
                self.assertEqual(resolve_bundle_path(path), path)

    def test_rejects_invalid_project_names(self):
        for name in ('cheesetrap-other', 'cheesetrap-f0102-BAD',
                     'cheesetrap-f0102-a b', 'cheesetrap-f0102-' + 'a' * 32):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    resolve_bundle_path(self.directory(name))

    def test_rejects_missing_directory(self):
        with self.assertRaises(ValueError):
            resolve_bundle_path(self.root / 'cheesetrap-f0102-missing')

    def test_rejects_regular_file(self):
        path = self.root / 'cheesetrap-f0102-file'
        path.write_text('fixture')
        with self.assertRaises(ValueError):
            resolve_bundle_path(path)

    def test_rejects_filesystem_root(self):
        with self.assertRaises(ValueError):
            resolve_bundle_path(Path(self.root.anchor))

    def test_resolves_relative_path(self):
        path = self.directory('cheesetrap-f0102-relative')
        self.assertEqual(resolve_bundle_path(os.path.relpath(path)), path)

    def test_accepts_alias_to_valid_target(self):
        target = self.directory('cheesetrap-f0102-target')
        alias = self.root / 'alias'
        alias.symlink_to(target, target_is_directory=True)
        self.assertEqual(resolve_bundle_path(alias), target)

    def test_rejects_valid_alias_to_invalid_target(self):
        target = self.directory('wrong-prefix')
        alias = self.root / 'cheesetrap-f0102-alias'
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            resolve_bundle_path(alias)

    def test_rejects_dangling_symlink(self):
        alias = self.root / 'cheesetrap-f0102-dangling'
        alias.symlink_to(self.root / 'cheesetrap-f0102-missing')
        with self.assertRaises(ValueError):
            resolve_bundle_path(alias)


if __name__ == '__main__':
    unittest.main()
