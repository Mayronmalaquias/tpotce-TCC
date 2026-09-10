import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('host_integrity.py')

class IntegrityTests(unittest.TestCase):
    def test_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, state = base / 'files', base / 'state'
            root.mkdir()
            (root / 'binary').write_bytes(b'original')
            (root / 'library').write_bytes(b'library')
            def run(action, expected, *extra):
                result = subprocess.run([sys.executable, str(SCRIPT), action,
                    '--state-dir', str(state), *extra], capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            run('check', 2)
            run('init', 0, '--root', str(root))
            original = (state / 'baseline.json').read_bytes()
            run('init', 2, '--root', str(root))
            run('check', 0)
            (root / 'binary').write_bytes(b'tampered')
            (root / 'library').unlink()
            (root / 'persistence').write_bytes(b'new')
            run('check', 1)
            changes = json.loads((state / 'latest.json').read_text())['changes']
            self.assertIn(str(root / 'binary'), changes['modified'])
            self.assertIn(str(root / 'library'), changes['removed'])
            self.assertIn(str(root / 'persistence'), changes['added'])
            self.assertEqual(original, (state / 'baseline.json').read_bytes())
            run('check', 1)
            (state / 'baseline.json').write_text('{}')
            run('check', 2)

    @unittest.skipIf(sys.platform == 'win32', 'Linux metadata and symlinks')
    def test_metadata_symlink_and_read_failure(self):
        from host_integrity import inventory
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_text('x')
            binary.chmod(0o600)
            link = root / 'link'
            link.symlink_to('binary')
            first, errors = inventory([directory])
            self.assertFalse(errors)
            binary.chmod(0o700)
            link.unlink()
            link.symlink_to('missing')
            second, errors = inventory([directory])
            self.assertFalse(errors)
            self.assertNotEqual(first[str(binary)], second[str(binary)])
            self.assertNotEqual(first[str(link)], second[str(link)])
            with patch('host_integrity.os.open', side_effect=PermissionError('denied')):
                _, errors = inventory([directory])
            self.assertTrue(errors)

if __name__ == '__main__':
    unittest.main()
