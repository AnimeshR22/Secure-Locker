# src/authentication/password_auth.py

import re
import time
import platform
import uuid
import hashlib
import hmac
from typing import Tuple, List
from argon2 import PasswordHasher, exceptions as argon2_excs

# ------------------------------------------------------------
# 1. Password Strength Validation
# ------------------------------------------------------------
def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Checks password against policy:
      - At least 12 chars
      - At least one uppercase, one lowercase, one digit, one special char
    Returns (is_valid, [list_of_issues]).
    """
    issues = []
    if len(password) < 12:
        issues.append("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        issues.append("Password must include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        issues.append("Password must include at least one lowercase letter.")
    if not re.search(r"\d", password):
        issues.append("Password must include at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        issues.append("Password must include at least one special character.")
    return (len(issues) == 0, issues)

# ------------------------------------------------------------
# 2. Password Hashing & Verification (Argon2)
# ------------------------------------------------------------
_ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)

def hash_password(password: str) -> str:
    """
    Hash the password using Argon2.
    Returns the Argon2 hash string.
    """
    return _ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    """
    Verify a plaintext password against an Argon2 hash.
    """
    try:
        return _ph.verify(hash, password)
    except argon2_excs.VerifyMismatchError:
        return False

# ------------------------------------------------------------
# 3. Password Generation Helpers
# ------------------------------------------------------------
def generate_password_biometric(biometric_data: bytes) -> str:
    """
    Derive a password string by hashing raw biometric data (e.g. face/fingerprint template).
    """
    return hashlib.sha256(biometric_data).hexdigest()

def generate_password_device_fingerprint() -> str:
    """
    Derive a device‐unique password by hashing together:
      - OS/platform info
      - Hostname
      - Machine type
      - MAC address
    """
    components = [
        platform.system(),
        platform.release(),
        platform.machine(),
        platform.node(),
        str(uuid.getnode())
    ]
    fingerprint = "|".join(components)
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

def generate_password_time_based(seed: str) -> str:
    """
    Generate a time‐based password using HMAC-SHA256:
      - seed: a user‐provided secret string
      - current UNIX timestamp (in seconds)
    """
    timestamp = str(int(time.time()))
    hm = hmac.new(seed.encode("utf-8"), timestamp.encode("utf-8"), hashlib.sha256)
    return hm.hexdigest()

# ------------------------------------------------------------
# Example Usage
# ------------------------------------------------------------
if __name__ == "__main__":
    # 1. Validate
    pw = "My$ecureP@ssw0rd"
    ok, issues = validate_password_strength(pw)
    if not ok:
        print("Password issues:", issues)
        exit(1)

    # 2. Hash & Verify
    h = hash_password(pw)
    print("Argon2 hash:", h)
    print("Verify ok:", verify_password(h, pw))

    # 3. Generate from biometric (example)
    print("Biometric‐derived:", generate_password_biometric(b"fake_biometrics"))

    # 4. Device fingerprint
    print("Device fingerprint:", generate_password_device_fingerprint())

    # 5. Time‐based
    print("Time‐based token:", generate_password_time_based("userSeed123"))
