#!/usr/bin/env python3
"""Negative controls for bounded measurement, including HTTP 200 fail-open."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import activation_load_probe as probe


class ActivationEvidenceTests(unittest.TestCase):
    def test_hostile_limits_fail_before_process_or_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'output'
            base = [sys.executable, str(Path(probe.__file__)), *[
                value for name in ('nginx', 'module', 'bundle', 'hot-bundle', 'pubkey', 'mkbundle')
                for value in ('--' + name, str(Path(temp) / 'must-not-open'))], '--out', str(output)]
            for name, value in [('rate', '0'), ('rate', '501'), ('seconds', '31'), ('clients', '17'), ('cpu', '1024')]:
                result = subprocess.run(base + ['--' + name, value], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn('bounded rate/seconds/clients/cpu required', result.stderr)
                self.assertFalse(output.exists())

    def test_200_error_and_unsent_work_are_never_successful_inspections(self):
        rows = [{'status': 200, 'action': 'allow', 'wall_ns': 10},
                {'status': 200, 'action': 'error', 'wall_ns': 15},
                {'error': 'driver_queue_full'}, {'status': 403, 'action': 'block', 'wall_ns': 20}]
        summary = probe.percentiles(rows)
        self.assertEqual(summary['requests'], 4)
        self.assertEqual(summary['errors'], 3)
        self.assertEqual(summary['wall_ns']['p100'], 20)
        self.assertIsNone(probe.percentiles([])['wall_ns']['p99'])

    def test_nonincreasing_version_fails_before_launching_nginx(self):
        with tempfile.TemporaryDirectory() as temp:
            header = Path(temp) / 'header-only'
            raw = bytearray(40); struct.pack_into('<Q', raw, 16, 1); header.write_bytes(raw)
            args = argparse.Namespace(out=str(Path(temp) / 'output'), **{
                name: str(header) for name in ('nginx', 'module', 'bundle', 'hot_bundle', 'pubkey', 'mkbundle')})
            with patch.object(probe.subprocess, 'run') as run, patch.object(probe.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'version must increase'):
                    probe.run(args)
                run.assert_not_called(); launch.assert_not_called()
            self.assertFalse((Path(args.out) / 'summary.json').exists())


if __name__ == '__main__':
    unittest.main()
