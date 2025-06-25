"""
Prexl: A local, open-source 2FA CLI tool for TOTP code generation.
Secrets are stored encrypted using a password, never sent online.
"""
import os
import json
import base64
import getpass
import click
import pyotp
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import time
import sys
import threading
import platform

SECRETS_PATH = os.path.expanduser('~/.prexl/secrets.json')
SALT_PATH = os.path.expanduser('~/.prexl/salt')

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_salt():
    if not os.path.exists(SALT_PATH):
        os.makedirs(os.path.dirname(SALT_PATH), exist_ok=True)
        salt = os.urandom(16)
        with open(SALT_PATH, 'wb') as f:
            f.write(salt)
        return salt
    with open(SALT_PATH, 'rb') as f:
        return f.read()

def load_secrets(password):
    salt = get_salt()
    key = derive_key(password, salt)
    f = Fernet(key)
    if not os.path.exists(SECRETS_PATH):
        return {}, f
    with open(SECRETS_PATH, 'rb') as file:
        data = file.read()
    try:
        decrypted = f.decrypt(data)
        return json.loads(decrypted.decode()), f
    except InvalidToken:
        raise click.ClickException('Invalid password or corrupted secrets file.')

def save_secrets(secrets, f):
    os.makedirs(os.path.dirname(SECRETS_PATH), exist_ok=True)
    data = json.dumps(secrets).encode()
    encrypted = f.encrypt(data)
    with open(SECRETS_PATH, 'wb') as file:
        file.write(encrypted)

def getpass_with_timeout(prompt, timeout=90):
    """
    Password prompt with asterisks and timeout on Windows (cmd.exe, some terminals).
    Falls back to getpass.getpass (no asterisks, no timeout) on non-Windows or unsupported terminals.
    """
    if platform.system() != 'Windows':
        # Fallback for Linux/macOS
        import getpass
        return getpass.getpass(prompt)
    try:
        import msvcrt
    except ImportError:
        import getpass
        return getpass.getpass(prompt)
    import time as _time
    print(prompt, end='', flush=True)
    pw = ''
    start = _time.time()
    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            if ch in (b'\r', b'\n'):
                print()
                break
            elif ch == b'\x03':  # Ctrl+C
                print('\nExiting.')
                sys.exit(0)
            elif ch == b'\x08':  # Backspace
                if len(pw) > 0:
                    pw = pw[:-1]
                    print('\b \b', end='', flush=True)
            else:
                try:
                    c = ch.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                pw += c
                print('*', end='', flush=True)
        if _time.time() - start > timeout:
            print('\n(Inactivity timeout reached. Exiting.)')
            sys.exit(0)
        _time.sleep(0.05)
    return pw

@click.group()
def cli():
    """Prexl: Local 2FA CLI (TOTP)"""
    pass

@cli.command()
@click.argument('name')
@click.argument('secret')
def add(name, secret):
    """Add a new TOTP secret."""
    import base64
    try:
        # Validate Base32 secret
        base64.b32decode(secret, casefold=True)
    except Exception:
        click.echo('Error: Secret must be a valid Base32 string (A-Z, 2-7, no spaces).')
        return
    password = getpass_with_timeout('Master password: ', 90)
    secrets, f = load_secrets(password)
    if name in secrets:
        click.echo(f'Entry "{name}" already exists.')
        return
    secrets[name] = secret
    save_secrets(secrets, f)
    click.echo(f'Added entry "{name}".')

@cli.command()
@click.argument('name')
def gen(name):
    """Generate a TOTP code for NAME, show live timer, allow 2 codes per password entry, then re-authenticate. Exit after 90s of inactivity."""
    import time
    import sys
    import threading
    max_tries = 2
    timeout = 90

    def input_with_timeout(prompt, timeout):
        result = [None]
        def inner():
            try:
                result[0] = input(prompt)
            except EOFError:
                pass
        t = threading.Thread(target=inner)
        t.daemon = True
        t.start()
        t.join(timeout)
        if t.is_alive():
            print('\n(Inactivity timeout reached. Exiting.)')
            sys.exit(0)
        return result[0]

    try:
        while True:
            password = getpass_with_timeout('Master password: ', timeout)
            try:
                secrets, _ = load_secrets(password)
            except click.ClickException as e:
                click.echo(str(e))
                return
            if name not in secrets:
                click.echo(f'No entry for "{name}".')
                return
            secret = secrets[name]
            totp = pyotp.TOTP(secret)
            for attempt in range(max_tries):
                code = totp.now()
                interval = totp.interval if hasattr(totp, 'interval') else 30
                now = int(time.time())
                remaining = interval - (now % interval)
                click.echo(f'TOTP for {name}: {code}')
                # Live countdown
                for sec in range(remaining, 0, -1):
                    print(f'Code valid for: {sec:2d}s', end='\r', flush=True)
                    time.sleep(1)
                print(' ' * 30, end='\r')  # Clear line
                try:
                    input_with_timeout('Press Enter for next code, or Ctrl+C to exit...', timeout)
                except KeyboardInterrupt:
                    click.echo('\nExiting.')
                    return
                if attempt == max_tries - 1:
                    click.echo('(Max tries reached. Exiting.)')
    except KeyboardInterrupt:
        click.echo('\nExiting.')
        return

@cli.command()
def list():
    """List all stored account names."""
    password = getpass_with_timeout('Master password: ', 90)
    secrets, _ = load_secrets(password)
    if not secrets:
        click.echo('No entries found.')
        return
    click.echo('Stored entries:')
    for name in secrets:
        click.echo(f'- {name}')

@cli.command()
@click.argument('name')
def remove(name):
    """Remove a stored TOTP secret by NAME."""
    password = getpass_with_timeout('Master password: ', 90)
    secrets, f = load_secrets(password)
    if name not in secrets:
        click.echo(f'No entry for "{name}".')
        return
    confirm = input(f'Are you sure you want to remove "{name}"? (y/N): ')
    if confirm.lower() == 'y':
        del secrets[name]
        save_secrets(secrets, f)
        click.echo(f'Removed entry "{name}".')
    else:
        click.echo('Aborted.') 