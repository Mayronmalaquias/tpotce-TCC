import copy
import unittest

from honeypot_firewall import render, rules_fingerprint


class FirewallTests(unittest.TestCase):
    def test_no_interpolation_or_wildcard_in_trusted_networks(self):
        for name in ['br-*', 'eth0', 'br-123456789012"; flush ruleset', 'docker0']:
            with self.assertRaises(ValueError):
                render({'trusted_bridges': [name]})

    def test_fingerprint_detects_policy_tampering_but_not_traffic(self):
        original = {'nftables': [
            {'metainfo': {'version': '1'}},
            {'rule': {'handle': 4, 'expr': [{'counter': {'packets': 1, 'bytes': 10}}, {'drop': None}]}}
        ]}
        traffic = copy.deepcopy(original)
        traffic['nftables'][1]['rule']['handle'] = 8
        traffic['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 500
        self.assertEqual(rules_fingerprint(original), rules_fingerprint(traffic))
        traffic['nftables'][1]['rule']['expr'][1] = {'accept': None}
        self.assertNotEqual(rules_fingerprint(original), rules_fingerprint(traffic))


if __name__ == '__main__':
    unittest.main()
