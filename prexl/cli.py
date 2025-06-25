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
from rich.console import Console
from rich.text import Text

SECRETS_PATH = os.path.expanduser('~/.prexl/secrets.json')
SALT_PATH = os.path.expanduser('~/.prexl/salt')

console = Console()

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

def print_gradient_logo():
    console.print()
    console.print()
    console.print()
    logo = [
        "░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ",
        "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ",
        "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ",
        "░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓█▓▒░        ",
        "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ",
        "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ",
        "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░ ",
    ]
    color1 = "#00BFFF"  # DeepSkyBlue
    color2 = "#FF69B4"  # HotPink
    for i, line in enumerate(logo):
        blend = i / (len(logo) - 1)
        r = int(int(color1[1:3], 16) * (1 - blend) + int(color2[1:3], 16) * blend)
        g = int(int(color1[3:5], 16) * (1 - blend) + int(color2[3:5], 16) * blend)
        b = int(int(color1[5:7], 16) * (1 - blend) + int(color2[5:7], 16) * blend)
        hex_color = f"#{r:02x}{g:02x}{b:02x}"
        console.print(Text(line, style=f"bold {hex_color}"))
    console.print()
    console.print()
    console.print()

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Prexl: Local 2FA CLI (TOTP)"""
    # First-run detection
    first_run_flag = os.path.expanduser('~/.prexl/.first_run_complete')
    is_first_run = not os.path.exists(first_run_flag)

    if ctx.invoked_subcommand is None:
        print_gradient_logo()
        if is_first_run:
            click.secho("Welcome to Prexl!", fg="blue")
            click.echo() 
            click.secho("Prexl is a local, open-source CLI tool for generating TOTP (2FA) codes.", fg="blue")
            click.echo("Your secrets are stored securely and never leave your device." , fg="blue")
            # Mark first run complete
            os.makedirs(os.path.dirname(first_run_flag), exist_ok=True)
            with open(first_run_flag, 'w') as f:
                f.write('1')
        console.print()
        console.print()
        click.echo("Quick start:\n")
        click.echo("  prexl add <name> <secret>   # Add a new TOTP secret")
        click.echo("  prexl gen <name>            # Generate a TOTP code")
        click.echo("  prexl list                  # List all stored entries")
        click.echo("  prexl remove <name>         # Remove a stored secret\n")
        click.echo("For help, run: prexl --help or see the README.md\n")
    # If a subcommand is invoked, do nothing special

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

@cli.command()
def welcome():
    """Show the PREXL welcome and quick start message."""
    print_gradient_logo()
    click.secho("Welcome to Prexl!", fg="blue")
    click.echo() 
    click.secho("Prexl is a local, open-source CLI tool for generating TOTP (2FA) codes.", fg="blue")
    click.secho("Your secrets are stored securely and never leave your device.", fg="blue")
    console.print()
    console.print()
    click.echo("Quick start:\n")
    click.echo("  prexl add <name> <secret>   # Add a new TOTP secret")
    click.echo("  prexl gen <name>            # Generate a TOTP code")
    click.echo("  prexl list                  # List all stored entries")
    click.echo("  prexl remove <name>         # Remove a stored secret\n")
    click.echo("For help, run: prexl --help or see the README.md\n") 