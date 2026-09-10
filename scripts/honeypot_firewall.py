#!/usr/bin/env python3
"""Fail-closed Docker bridge containment in a separate, atomic nftables table.

Only reply-direction established/related traffic is allowed from untrusted
bridges. Host-originated traffic and the explicitly trusted nginx bridge retain
their existing rules. New Docker bridges are quarantined automatically.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

TABLE = 'beeia_containment'


def render(config):
    trusted = config.get('trusted_bridges', [])
    if not isinstance(trusted, list) or any(
            not isinstance(name, str) or not re.fullmatch(r'br-[0-9a-f]{12}', name)
            for name in trusted):
        raise ValueError('trusted_bridges must contain explicit Docker bridge names')
    members = ', '.join(json.dumps(name) for name in sorted(set(trusted)))
    elements = f'elements = {{ {members} }};' if trusted else ''
    return f'''table inet {TABLE} {{
  set trusted_bridges {{ type ifname; {elements} }}
  chain from_container {{
    iifname @trusted_bridges return
    ct direction reply ct state established,related counter return
    limit rate 3/minute burst 5 packets log prefix "BEEIA_DENY "
    counter drop
  }}
  chain host_input {{
    type filter hook input priority -10; policy accept;
    iifname "br-*" jump from_container
    iifname "docker0" jump from_container
  }}
  chain container_forward {{
    type filter hook forward priority -10; policy accept;
    iifname "br-*" jump from_container
    iifname "docker0" jump from_container
  }}
}}
'''


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def rules_fingerprint(document):
    """Ignore counters/handles but include every rule, set, chain and policy."""
    def clean(value):
        if isinstance(value, list):
            return [clean(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes')}
        return value
    canonical = json.dumps(clean(document), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['render', 'apply', 'check'])
    parser.add_argument('--config', type=Path, default=Path('/etc/beeia-security/containment.json'))
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    desired = render(config)
    digest_path = args.config.with_name('firewall.sha256')
    if args.action == 'render':
        print(desired)
        return
    if args.action == 'apply':
        exists = subprocess.run(['nft', 'list', 'table', 'inet', TABLE],
                                capture_output=True).returncode == 0
        transaction = (f'delete table inet {TABLE}\n' if exists else '') + desired
        run(['nft', '--check', '-f', '-'], input=transaction)
        run(['nft', '-f', '-'], input=transaction)
        state = json.loads(run(['nft', '-j', 'list', 'table', 'inet', TABLE]).stdout)
        digest_path.write_text(rules_fingerprint(state) + '\n')
        digest_path.chmod(0o600)
        print('Containment applied atomically; Docker tables preserved')
    else:
        state = json.loads(run(['nft', '-j', 'list', 'table', 'inet', TABLE]).stdout)
        if rules_fingerprint(state) != digest_path.read_text().strip():
            raise ValueError('Containment rules differ from the applied configuration')
        # Reject network arrangements that would bypass the bridge policy.
        containers = json.loads(run(['docker', 'inspect', 'cowrie', 'dionaea']).stdout)
        for container in containers:
            networks = container['NetworkSettings']['Networks']
            if not networks or container['HostConfig']['NetworkMode'] == 'host':
                raise ValueError('Honeypot has no isolated bridge network')
            for details in networks.values():
                bridge = 'br-' + details['NetworkID'][:12]
                if bridge in config.get('trusted_bridges', []):
                    raise ValueError('Honeypot joined trusted proxy network')
                network = json.loads(run(['docker', 'network', 'inspect', details['NetworkID']]).stdout)[0]
                override = network.get('Options', {}).get('com.docker.network.bridge.name')
                if network['Driver'] != 'bridge' or (override and override != bridge and override != 'docker0'):
                    raise ValueError('Unsupported honeypot network; containment requires review')
        print('Containment rules and honeypot network topology verified')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f'CONTAINMENT ERROR: {exc}', file=sys.stderr)
        sys.exit(2)
