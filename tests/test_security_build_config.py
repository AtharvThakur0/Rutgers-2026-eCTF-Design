import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware"))

from security_build_config import (  # noqa: E402
    MAX_PERMISSION_ENTRIES,
    PermissionParseError,
    PermissionTable,
)


class PermissionTableParseTests(unittest.TestCase):
    def test_valid_permission_strings(self):
        table = PermissionTable.parse("1234=RW-:aabb=--C:4321=RWC")

        self.assertEqual(len(table), 3)
        self.assertEqual(table[0].group_id, 0x1234)
        self.assertTrue(table[0].read)
        self.assertTrue(table[0].write)
        self.assertFalse(table[0].receive)
        self.assertEqual(table[1].group_id, 0xAABB)
        self.assertFalse(table[1].read)
        self.assertFalse(table[1].write)
        self.assertTrue(table[1].receive)
        self.assertEqual(table[2].group_id, 0x4321)
        self.assertEqual(table.serialize(), "1234=RW-:aabb=--C:4321=RWC")

    def test_invalid_permission_width(self):
        with self.assertRaises(PermissionParseError):
            PermissionTable.parse("1234=RW")

        with self.assertRaises(PermissionParseError):
            PermissionTable.parse("1234=RWC-")

    def test_invalid_group_id_format(self):
        with self.assertRaises(PermissionParseError):
            PermissionTable.parse("123=RWC")

        with self.assertRaises(PermissionParseError):
            PermissionTable.parse("0x12=RWC")

        with self.assertRaises(PermissionParseError):
            PermissionTable.parse("zzzz=RWC")

    def test_duplicate_group_handling(self):
        with self.assertRaises(PermissionParseError):
            PermissionTable.parse("1234=R--:1234=--C")

    def test_min_max_supported_group_ids(self):
        table = PermissionTable.parse("0000=R--:ffff=--C")

        self.assertEqual(table[0].group_id, 0x0000)
        self.assertEqual(table[1].group_id, 0xFFFF)

    def test_max_entries_supported(self):
        spec = ":".join(f"{index:04x}=R--" for index in range(MAX_PERMISSION_ENTRIES))
        table = PermissionTable.parse(spec)

        self.assertEqual(len(table), MAX_PERMISSION_ENTRIES)

    def test_too_many_entries_rejected(self):
        spec = ":".join(f"{index:04x}=R--" for index in range(MAX_PERMISSION_ENTRIES + 1))
        with self.assertRaises(PermissionParseError):
            PermissionTable.parse(spec)


if __name__ == "__main__":
    unittest.main()
