import os
import sys
import json
import base64
import logging
import subprocess

log = logging.getLogger("patroni_launcher")
logging.basicConfig(level=logging.INFO)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(SCRIPT_DIR, "secrets.enc")
ENTROPY_FILE = os.path.join(SCRIPT_DIR, "secrets.key")
YAML_FILE = os.path.join(SCRIPT_DIR, "patroni.yaml")

REQUIRED_KEYS = [
    "PATRONI_SUPERUSER_PASSWORD",
    "PATRONI_REPLICATION_PASSWORD",
]


def ensure_pywin32():
    """Verify pywin32 is available — should be installed by install.ps1."""
    try:
        import win32crypt  # noqa: F401
    except ImportError:
        log.error(
            "pywin32 is not installed. "
            "Re-run install.ps1 or: pip install --no-index "
            "--find-links .patroni-packages pywin32"
        )
        sys.exit(1)


def load_secrets():
    """Read secrets.key + secrets.enc, decrypt each DPAPI blob, set as env vars."""
    try:
        import win32crypt
    except ImportError:
        log.error(
            "pywin32 is still not available after install attempt. "
            "Manual install required: pip install pywin32"
        )
        sys.exit(1)

    if not os.path.exists(SECRETS_FILE):
        log.error("Secrets file not found: %s", SECRETS_FILE)
        sys.exit(1)

    if not os.path.exists(ENTROPY_FILE):
        log.error("Entropy file not found: %s", ENTROPY_FILE)
        sys.exit(1)

    # load entropy
    with open(ENTROPY_FILE, "rb") as f:
        raw = f.read().strip()
        # Strip UTF-8 BOM if present
        if raw.startswith(b'\xef\xbb\xbf'):
            raw = raw[3:]
        entropy = base64.b64decode(raw)    

    # load encrypted secrets
    with open(SECRETS_FILE, "r") as f:
        encrypted = json.load(f)

    # Validate all required keys are present
    missing = [k for k in REQUIRED_KEYS if k not in encrypted]
    if missing:
        log.error("Missing keys in secrets.enc: %s", ", ".join(missing))
        sys.exit(1)

    for key, blob_b64 in encrypted.items():
        try:
            blob = base64.b64decode(blob_b64)
            _, plain_bytes = win32crypt.CryptUnprotectData(
                blob,
                entropy,
                None,
                None,
                0
            )
            os.environ[key] = plain_bytes.decode("utf-8")
        except Exception as e:
            log.error("Failed to decrypt key '%s': %s", key, e)
            sys.exit(1)

    log.info("Decrypted %d secret(s) into environment", len(encrypted))


def verify_yaml_has_no_plaintext():
    """
    Safety check — scan the YAML for password fields that
    don't use {{}} placeholders. Catches accidental misconfigs.
    """
    with open(YAML_FILE, "r") as f:
        content = f.read()

    import re
    pattern = r'password:\s*(?!.*\{\{)(.+)'
    matches = re.findall(pattern, content)

    if matches:
        log.warning(
            "SECURITY: patroni.yaml contains password values "
            "that are not env var placeholders. "
            "Ensure all passwords use {{ENV_VAR}} syntax."
        )


def main():
    log.info("Starting Patroni launcher...")

    # ensure check
    ensure_pywin32()

    # decrypt and populate
    load_secrets()

    # safety check
    verify_yaml_has_no_plaintext()

    # launch patroni in process
    sys.argv = ["patroni", YAML_FILE]

    try:
        from patroni.__main__ import main as patroni_main
        patroni_main()
    except Exception as e:
        log.error("Patroni failed to start: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()