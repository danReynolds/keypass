#!/usr/bin/env python3
"""Unit tests for the bundler's dependency allowlist. No native build runs."""
import importlib.util
from pathlib import Path
import unittest

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

    def test_refuses_unknown_or_missing_libraries(self):
        with self.assertRaisesRegex(ValueError, 'expected exactly'):
            bundle.check_closure({'libkeypass_hardware.dylib', 'libfido2.1.dylib',
                                  'libcbor.0.14.dylib'}, bundle.MAC)
        for crypto in ('libcrypto.5.dylib', 'libcrypto.1.1.dylib'):
            self.assertFalse(any(__import__('re').fullmatch(p, crypto) for p in bundle.MAC))


if __name__ == '__main__':
    unittest.main()
