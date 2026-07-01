import unittest
import tempfile
import os
import json

from utils import (
    normalize_ip, parse_spamhaus_txt, parse_spamhaus_json,
    parse_netset, parse_plain_ip_list, parse_dshield_block,
    merge_networks, save_networks, load_networks,
)
from ip_manager import IPManager
from config import load_config


class TestNormalize(unittest.TestCase):
    def test_ipv4_full(self):
        self.assertEqual(normalize_ip("10.0.0.1"), "10.0.0.1/32")

    def test_ipv4_cidr(self):
        self.assertEqual(normalize_ip("10.0.0.0/24"), "10.0.0.0/24")

    def test_ipv6_full(self):
        self.assertEqual(normalize_ip("::1"), "::1/128")

    def test_ipv6_cidr(self):
        self.assertEqual(normalize_ip("2001:db8::/32"), "2001:db8::/32")

    def test_comment(self):
        self.assertIsNone(normalize_ip("# comment"))
        self.assertIsNone(normalize_ip("; comment"))

    def test_empty(self):
        self.assertIsNone(normalize_ip(""))
        self.assertIsNone(normalize_ip("   "))

    def test_inline_comment(self):
        self.assertEqual(normalize_ip("10.0.0.0/24 # comment"), "10.0.0.0/24")

    def test_whitespace(self):
        self.assertEqual(normalize_ip("  10.0.0.0/24  "), "10.0.0.0/24")


class TestParsers(unittest.TestCase):
    def test_spamhaus_txt(self):
        text = "10.0.0.0/24 ; SBL12345\n10.0.1.0/24 ; SBL12346\n"
        result = parse_spamhaus_txt(text)
        self.assertIn("10.0.0.0/24", result)
        self.assertIn("10.0.1.0/24", result)
        self.assertEqual(len(result), 2)

    def test_spamhaus_txt_ignore_no_semicolon(self):
        text = "10.0.0.0/24\n# comment\n"
        result = parse_spamhaus_txt(text)
        self.assertEqual(len(result), 0)

    def test_spamhaus_json(self):
        text = json.dumps([
            {"cidr": "10.0.0.0/24"},
            {"cidr": "10.0.1.0/24"},
        ])
        result = parse_spamhaus_json(text)
        self.assertIn("10.0.0.0/24", result)
        self.assertEqual(len(result), 2)

    def test_netset(self):
        text = "10.0.0.0/24\n10.0.1.0/24\n192.168.1.1\n"
        result = parse_netset(text)
        self.assertEqual(len(result), 3)

    def test_plain_ip_list(self):
        text = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
        result = parse_plain_ip_list(text)
        self.assertEqual(len(result), 3)

    def test_dshield_block(self):
        text = (
            "Start   End     \n"
            "1.0.0.0 1.0.0.255\n"
            "2.0.0.0 2.0.0.255\n"
        )
        result = parse_dshield_block(text)
        self.assertGreater(len(result), 0)

    def test_dshield_with_comment(self):
        text = "# comment\n1.2.3.4 1.2.3.4\n"
        result = parse_dshield_block(text)
        self.assertEqual(len(result), 1)


class TestMerge(unittest.TestCase):
    def test_merge_v4(self):
        result = merge_networks([
            "10.0.0.0/24",
            "10.0.0.128/25",
            "10.0.1.0/24",
        ])
        self.assertIn("10.0.0.0/23", result)
        self.assertEqual(len(result), 1)

    def test_merge_v6(self):
        result = merge_networks([
            "2001:db8::/32",
            "2001:db8:1::/48",
        ])
        self.assertIn("2001:db8::/32", result)

    def test_merge_empty(self):
        result = merge_networks([])
        self.assertEqual(result, [])

    def test_merge_v4_v6_separate(self):
        result = merge_networks([
            "10.0.0.0/24",
            "2001:db8::/32",
        ])
        self.assertEqual(len(result), 2)


class TestIPManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ipm = IPManager(self.tmpdir)

    def test_add_and_count(self):
        self.ipm.add_networks(["10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual(self.ipm.count_v4, 2)
        self.assertEqual(self.ipm.total_count, 2)

    def test_add_v6(self):
        self.ipm.add_networks(["2001:db8::/32"])
        self.assertEqual(self.ipm.count_v6, 1)

    def test_merge(self):
        self.ipm.add_networks(["10.0.0.0/24", "10.0.0.128/25"])
        merged = self.ipm.merge()
        self.assertEqual(len(merged), 1)

    def test_save_load_merged(self):
        self.ipm.add_networks(["10.0.0.0/24"])
        self.ipm.save_merged()
        ipm2 = IPManager(self.tmpdir)
        ipm2.load_merged()
        self.assertEqual(ipm2.total_count, 1)

    def test_clear(self):
        self.ipm.add_networks(["10.0.0.0/24"])
        self.ipm.clear()
        self.assertEqual(self.ipm.total_count, 0)


class TestConfig(unittest.TestCase):
    def test_load_config(self):
        tmpdir = tempfile.mkdtemp()
        cfg_path = os.path.join(tmpdir, "config.json")
        cfg = {"general": {"data_dir": "/tmp"}}
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        loaded = load_config(cfg_path)
        self.assertEqual(loaded["general"]["data_dir"], "/tmp")


class TestFileIO(unittest.TestCase):
    def test_save_load_networks(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "test.txt")
        networks = {"10.0.0.0/24", "10.0.1.0/24"}
        save_networks(networks, path)
        loaded = load_networks(path)
        self.assertEqual(loaded, networks)

    def test_load_nonexistent(self):
        loaded = load_networks("/nonexistent/path.txt")
        self.assertEqual(loaded, set())


if __name__ == "__main__":
    unittest.main()
