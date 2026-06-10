import json
import secrets
import string

from argon2 import PasswordHasher

ph = PasswordHasher()


def hash_password(password):
    return ph.hash(password)


def verify_password(hash_value, password):
    try:
        return ph.verify(hash_value, password)
    except Exception:
        return False


def generate_backup_codes(count=8):
    alphabet = string.ascii_uppercase + string.digits
    return [f"RECOVERY-{''.join(secrets.choice(alphabet) for _ in range(6))}" for _ in range(count)]


def consume_backup_code(stored_backup_codes, candidate_code):
    if not stored_backup_codes:
        return stored_backup_codes, False

    try:
        codes = json.loads(stored_backup_codes)
    except (TypeError, ValueError):
        return stored_backup_codes, False

    normalized_code = candidate_code.strip().upper()
    remaining_codes = []
    used = False

    for code_hash in codes:
        if not used and verify_password(code_hash, normalized_code):
            used = True
            continue
        remaining_codes.append(code_hash)

    return json.dumps(remaining_codes), used