import os
from vpn.maintenance import run_backup

if __name__ == '__main__':
    os.umask(0o077)
    run_backup()
