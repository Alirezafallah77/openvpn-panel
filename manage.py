"""Local administrative utilities; never prints a plaintext password."""
import argparse
import getpass
from werkzeug.security import generate_password_hash

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['password-hash'])
    parser.parse_args()
    password = getpass.getpass('Admin password (at least 12 characters): ')
    if len(password) < 12:
        parser.error('Password must have at least 12 characters')
    if password != getpass.getpass('Repeat password: '):
        parser.error('Passwords do not match')
    print(generate_password_hash(password))
