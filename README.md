# Prexl: Local 2FA CLI Tool

Prexl is a fully local, open-source CLI tool for generating TOTP (2FA) codes. Secrets are stored securely, encrypted with a password, and never leave your device.

## How to install and use locally from GitHub

If you find this project on GitHub and want to use it locally:

1. **Clone the repository:**
   ```sh
   git clone https://github.com/kinvenho/prexl.git
   cd prexl
   ```
2. **Install the requirements:**
   ```sh
   pip install -r requirements.txt
   ```
   Or, to install as a CLI tool globally:
   ```sh
   pip install .
   ```
3. **Usage:**
   After installation, use the CLI as described below.

## Features
- Offline TOTP code generation (pyotp)
- Secrets encrypted with a password (cryptography)
- Simple CLI (click)
- Password input is masked with asterisks (`*`) on Windows (cmd.exe); standard hidden input elsewhere
- 90-second inactivity timeout on all password prompts (Windows only)
- Secret validation: only valid Base32 secrets are accepted
- MIT licensed, open-source

## Installation

Install globally as a CLI tool:

```
pip install .
```

## Usage

After installation, use the `prexl` command from anywhere:

```
prexl add <name> <secret>
prexl gen <name>
prexl list
prexl remove <name>
prexl welcome
```

### Example

```
prexl add github JBSWY3DPEHPK3PXP
prexl gen github
prexl list
prexl remove github
prexl welcome
```

You will be prompted for your master password to unlock your secrets. On Windows (cmd.exe), you will see asterisks (`*`) as you type your password. On other platforms or terminals, password input will be hidden (no asterisks).

### TOTP Generation Flow
- Each time you generate a code, you can press Enter for the next code (up to 2 codes per password entry).
- After 2 codes, you will be prompted for your password again.
- If you do not respond to a password or code prompt within 90 seconds, the process will exit automatically.

### Secret Validation
- Only valid Base32 secrets (A-Z, 2-7, no spaces) are accepted. If you enter an invalid secret, you will see an error message.

## Security
- All secrets are encrypted with a password you choose.
- No data is sent online.
- If you forget your password, secrets cannot be recovered.
- For best security, use a strong, unique master password.

## Platform Notes
- Password masking with asterisks and inactivity timeout is supported on Windows (cmd.exe, some terminals).
- On other platforms or unsupported terminals, password input will be hidden but not masked, and there is no inactivity timeout.

## License
MIT 