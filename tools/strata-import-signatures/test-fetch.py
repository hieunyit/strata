#!/usr/bin/env python3
"""Pinned-source cache regression tests; isolated files, no network requests."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tool = self.root / 'tools' / 'strata-import-signatures'
        self.tool.mkdir(parents=True)
        shutil.copyfile(Path(__file__).with_name('fetch.sh'), self.tool / 'fetch.sh')
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.content = b'[{"pattern":"example-bot"}]\n'
        self.digest = hashlib.sha256(self.content).hexdigest()
        (self.cache / self.digest).write_bytes(self.content)
        (self.tool / 'sources.lock').write_text(
            f'bots_url=file://{self.root}/missing-upstream\nbots_sha256={self.digest}\n')
        self.env = dict(os.environ, STRATA_SIGNATURE_CACHE=str(self.cache))

    def fetch(self):
        return subprocess.run(['bash', str(self.tool / 'fetch.sh'), 'bots'],
                              env=self.env, capture_output=True, text=True)

    def test_pinned_cache_works_when_upstream_disappears(self):
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()).read_bytes(), self.content)
        self.assertEqual((self.cache / self.digest).read_bytes(), self.content)
        # A poisoned extraction is regenerated from the verified original bytes.
        Path(result.stdout.strip()).write_bytes(b'poisoned extraction')
        self.assertEqual(self.fetch().returncode, 0)
        self.assertEqual(Path(result.stdout.strip()).read_bytes(), self.content)

    def test_bad_archive_is_rejected_even_with_verified_marker(self):
        self.assertEqual(self.fetch().returncode, 0)
        (self.cache / self.digest).write_bytes(b'wrong archive')
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('corrupt pinned archive', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_download_wrong_hash_does_not_install(self):
        (self.cache / self.digest).unlink()
        upstream = self.root / 'upstream'
        upstream.write_bytes(b'new mutable upstream contents')
        lock = self.tool / 'sources.lock'
        lock.write_text(lock.read_text().replace('missing-upstream', 'upstream'))
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertFalse((self.cache / self.digest).exists())

    def test_successful_download_preserves_original_bytes(self):
        (self.cache / self.digest).unlink()
        upstream = self.root / 'missing-upstream'
        upstream.write_bytes(self.content)
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        upstream.unlink()
        self.assertEqual(self.fetch().returncode, 0)
        self.assertEqual((self.cache / self.digest).read_bytes(), self.content)

    @unittest.skipUnless(shutil.which('make'), 'make is supplied by the dev image')
    def test_make_does_not_invoke_importer_when_fetch_fails(self):
        makefile = Path(__file__).resolve().parents[2] / 'Makefile'
        shutil.copyfile(makefile, self.root / 'Makefile')
        # Stub only the build command; any importer invocation records a failure.
        commands = self.root / 'bin'
        commands.mkdir()
        go = commands / 'go'
        go.write_text('#!/bin/sh\nexit 0\n')
        go.chmod(0o755)
        build = self.root / 'build'
        build.mkdir()
        importer = build / 'strata-import-signatures'
        marker = self.root / 'importer-was-called'
        importer.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 0\n')
        importer.chmod(0o755)
        (self.cache / self.digest).unlink()
        env = dict(self.env, PATH=str(commands)+os.pathsep+os.environ['PATH'])
        result = subprocess.run(['make', 'signatures-import'], cwd=self.root, env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists(), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
