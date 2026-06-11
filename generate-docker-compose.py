# Generator for docker-compose.yml — the YAML is GENERATED; hand edits to
# docker-compose.yml are lost on the next run of this script. Change things
# here, then run `python3 generate-docker-compose.py` from the repo root.
#
# RANGES below is the single place to declare client subnets, per-subnet
# client counts, and request intervals. Each subnet gets ONE traffic-generator
# service (clients_netN) that simulates `count` clients via secondary IPs
# (.32 and up) on its interface; see client/entrypoint.sh.
#
# Each network's IPAM `ip_range` is pinned to the first /27 of the subnet so
# docker's auto-assigned addresses (proxy/cidrx/filebeat) stay below .32 and
# never collide with the static/secondary client IPs.
#
# The cidrx service publishes its stats endpoints to the host. While the
# stack runs:
#   curl http://localhost:8666/stats   # JSON live stats
#   curl http://localhost:8666/bans    # plain-text ban list
import yaml

# Hardcoded network definitions: list of (subnet, client count, interval)
RANGES = [
    ('172.16.1.0/24', 4, 0.1),
    ('172.16.2.0/24', 2, 0.1),
    ('172.16.3.0/24', 5, 0.1),
    ('172.16.16.0/24', 33, 0.07),
]

# Build contexts and Dockerfile names for services
PROXY_BUILD    = {'context': './proxy',    'dockerfile': 'Dockerfile'}
CLIENT_BUILD   = {'context': './client',   'dockerfile': 'Dockerfile'}
FILEBEAT_BUILD = {'context': './filebeat', 'dockerfile': 'Dockerfile'}
CIDRX_BUILD    = {'context': './cidrx',    'dockerfile': 'Dockerfile'}

TARGET_URL  = 'http://proxy:80/'
OUTPUT_FILE = 'docker-compose.yml'

# First client IP's last octet; secondary IPs continue upward from here.
IP_START = 32


def generate_compose():
    services = {}
    networks = {}
    volumes  = {
        'filebeat_data': {},
        'cidrx_data': {},
    }

    # ── proxy ──
    proxy_nets = {f'net{i+1}': {} for i in range(len(RANGES))}
    services['proxy'] = {
        'build':          PROXY_BUILD,
        'container_name': 'proxy',
        'restart':        'unless-stopped',
        'ports':          ['80'],
        'volumes':        [
            '/tmp:/var/log/nginx:rw',
        ],
        'networks':       proxy_nets,
    }

    # ── cidrx ──
    services['cidrx'] = {
        'build':          CIDRX_BUILD,
        'container_name': 'cidrx',
        'restart':        'unless-stopped',
        'ports':          ['9000:9000', '8666:8666'],
        'volumes':        [
            './docker-test-config.toml:/config/cidrx.toml:ro',
            'cidrx_data:/data',
        ],
        'healthcheck': {
            'test':         ['CMD', 'wget', '-q', '-O', '/dev/null',
                             'http://127.0.0.1:8666/stats'],
            'interval':     '10s',
            'timeout':      '3s',
            'retries':      3,
            'start_period': '30s',
        },
        'networks':       proxy_nets,
    }

    # ── filebeat ──
    services['filebeat'] = {
        'build':          FILEBEAT_BUILD,
        'container_name': 'filebeat',
        'user':           'root',
        'depends_on':     ['proxy', 'cidrx'],
        'restart':        'unless-stopped',
        'networks':       proxy_nets,
        'volumes': [
            '/tmp:/var/log/nginx:ro',
            'filebeat_data:/usr/share/filebeat/data',
        ],
        'environment': {
            'INGESTOR_HOST':       'cidrx:9000',
            'PROXY_CONTAINER_NAME': 'proxy',
        },
    }

    # ── traffic generators (one per subnet) ──
    for i, (subnet, count, interval) in enumerate(RANGES):
        net_name = f'net{i+1}'
        base = subnet.rsplit('.', 1)[0]
        networks[net_name] = {
            'driver': 'bridge',
            'ipam': {
                'driver': 'default',
                'config': [{
                    'subnet':   subnet,
                    # Keep docker-assigned addresses below .32 so they never
                    # collide with the static/secondary client IPs.
                    'ip_range': f'{base}.0/27',
                }],
            }
        }

        name = f'clients_{net_name}'
        services[name] = {
            'build':          CLIENT_BUILD,
            'container_name': name,
            'depends_on':     ['proxy'],
            'cap_add':        ['NET_ADMIN'],
            'networks':       {net_name: {'ipv4_address': f'{base}.{IP_START}'}},
            'environment': {
                'TARGET_URL': TARGET_URL,
                'INTERVAL':   interval,
                'IP_BASE':    base,
                'IP_START':   IP_START,
                'COUNT':      count,
            }
        }

    compose = {
        'services': services,
        'networks': networks,
        'volumes':  volumes,
    }

    with open(OUTPUT_FILE, 'w') as f:
        yaml.dump(compose, f, sort_keys=False)
    print(f"Generated {OUTPUT_FILE} with {len(RANGES)} traffic-gen services on {len(networks)} networks.")


if __name__ == '__main__':
    generate_compose()
