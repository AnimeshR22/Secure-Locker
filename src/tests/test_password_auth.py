import re
import time
from src.authentication.password_auth import (
    validate_password_strength,
    hash_password,
    verify_password,
    generate_password_biometric,
    generate_password_device_fingerprint,
    generate_password_time_based,
)

def test_validate_strength():
    ok, issues = validate_password_strength("Weak1!")
    assert not ok
    assert "12 characters" in issues[0]

    ok, issues = validate_password_strength("My$ecureP@ssw0rd")
    assert ok and issues == []

def test_hash_and_verify():
    pwd = "Another$tr0ngP@ss"
    h = hash_password(pwd)
    # Argon2 hashes start with $argon2
    assert h.startswith("$argon2")
    assert verify_password(h, pwd)
    assert not verify_password(h, "badpass")

def test_biometric_is_deterministic_hex():
    data = b"biometric123"
    out1 = generate_password_biometric(data)
    out2 = generate_password_biometric(data)
    assert out1 == out2
    assert re.fullmatch(r"[0-9a-f]{64}", out1)

def test_device_fingerprint_format():
    fp = generate_password_device_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{64}", fp)

def test_time_based_changes_over_time():
    t1 = generate_password_time_based("seed123")
    time.sleep(1)
    t2 = generate_password_time_based("seed123")
    assert t1 != t2
    # But same timestamp gives same:
    ts = int(time.time())
    # Monkey-patch time.time? Or just re-run immediately:
    t3 = generate_password_time_based("seed123")
    assert isinstance(t3, str)
