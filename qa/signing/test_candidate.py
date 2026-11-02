"""Offline checks against the actual compiled Windows PE candidate."""
import os
from pathlib import Path
import struct
import unittest

DLL = Path(os.environ.get('DLL_PATH', 'windows/build/PushGateWin.dll'))

class Candidate(unittest.TestCase):
    def setUp(self):
        self.data = DLL.read_bytes()

    def test_amd64_dll(self):
        self.assertEqual(self.data[:2], b'MZ')
        pe = struct.unpack_from('<I', self.data, 0x3c)[0]
        self.assertEqual(self.data[pe:pe + 4], b'PE\0\0')
        self.assertEqual(struct.unpack_from('<H', self.data, pe + 4)[0], 0x8664)
        self.assertTrue(struct.unpack_from('<H', self.data, pe + 22)[0] & 0x2000)

    def test_version_resource_directory(self):
        pe = struct.unpack_from('<I', self.data, 0x3c)[0]
        opt = pe + 24
        self.assertEqual(struct.unpack_from('<H', self.data, opt)[0], 0x20b)
        resource_rva, resource_size = struct.unpack_from('<II', self.data, opt + 112 + 16)
        self.assertGreater(resource_rva, 0)
        self.assertGreater(resource_size, 0)
        for value in ('VS_VERSION_INFO', 'ProductName', 'PushGate', 'ProductVersion', '0.1.0.0'):
            self.assertIn((value + '\0').encode('utf-16le'), self.data)

if __name__ == '__main__':
    unittest.main()
