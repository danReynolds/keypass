#!/usr/bin/env python3
"""Unit tests for the bundler's dependency allowlist. No native build runs."""
import importlib.util
from pathlib import Path
import re
import sys
import unittest

# Keep hook/__pycache__ out of the published package.
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location(
    'bundle', Path(__file__).resolve().parent.parent / 'hook' / 'bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class AllowlistTest(unittest.TestCase):
    def test_accepts_openssl_3_or_4(self):
        for crypto in ('libcrypto.3.dylib', 'libcrypto.4.dylib'):
            bundle.check_closure({'libkeypass_hardware.dylib', 'libfido2.1.dylib',
                                  crypto, 'libcbor.0.14.dylib'}, bundle.MAC)
        for crypto in ('libcrypto.so.3', 'libcrypto.so.4'):
            bundle.check_closure({'libkeypass_hardware.so', 'libfido2.so.1',
                                  crypto, 'libcbor.so.0.11'}, bundle.LINUX)

    def test_refuses_two_openssl_versions(self):
        with self.assertRaisesRegex(ValueError, 'different OpenSSL libraries'):
            bundle.check_closure({'libkeypass_hardware.dylib', 'libfido2.1.dylib',
                                  'libcrypto.3.dylib', 'libcrypto.4.dylib',
                                  'libcbor.0.14.dylib'}, bundle.MAC)
        with self.assertRaisesRegex(ValueError, 'different OpenSSL libraries'):
            bundle.check_closure({'libkeypass_hardware.so', 'libfido2.so.1',
                                  'libcrypto.so.3', 'libcrypto.so.4',
                                  'libcbor.so.0.11'}, bundle.LINUX)

    def test_refuses_near_miss_versions(self):
        for name, patterns in (('libcrypto.3.4.dylib', bundle.MAC),
                               ('libcrypto.40.dylib', bundle.MAC),
                               ('libcrypto.so.40', bundle.LINUX),
                               ('libcrypto.so.3.4', bundle.LINUX),
                               ('libcrypto.so.1.1', bundle.LINUX)):
            self.assertFalse(any(re.fullmatch(p, name) for p in patterns), name)

    def test_refuses_unknown_or_missing_libraries(self):
        with self.assertRaisesRegex(ValueError, 'expected exactly'):
            bundle.check_closure({'libkeypass_hardware.dylib', 'libfido2.1.dylib',
                                  'libcbor.0.14.dylib'}, bundle.MAC)
        for crypto in ('libcrypto.5.dylib', 'libcrypto.1.1.dylib'):
            self.assertFalse(any(re.fullmatch(p, crypto) for p in bundle.MAC))


if __name__ == '__main__':
    unittest.main()
