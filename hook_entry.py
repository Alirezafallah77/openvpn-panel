"""Root-owned OpenVPN script entry point."""
import os
import sys
from vpn.hook import run, DATABASE
from quota import Quotas

if __name__ == '__main__':
    os.umask(0o007)
    try:
        run(sys.argv[1], os.environ, Quotas(DATABASE))
    except Exception:
        print('VPN hook rejected operation; inspect accounting service', file=sys.stderr)
        sys.exit(1)
