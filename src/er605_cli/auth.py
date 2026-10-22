"""RSA password encryption and login helpers for ER605.

Implements the exact raw zero-padded RSA encryption from
`www/webpages/js/libs/encrypt.js` (`$.su.encrypt` / `nopadding`).
"""

from typing import Sequence
from .exceptions import ValidationError


def rsa_encrypt_nopadding(plaintext: str, modulus_hex: str, exponent_hex: str) -> str:
    """Encrypt `plaintext` using TP-Link's custom zero-padded textbook RSA.

    Corresponds to `$.su.encrypt(val, [n, e])` in `www/webpages/js/libs/encrypt.js`:
    1. Encode `plaintext` as UTF-8 bytes.
    2. Right-pad with `0x00` bytes to the byte length of modulus `n`:
       `key_bytes = (n.bit_length() + 7) >> 3`.
    3. Interpret the byte array as a big-endian integer `m`.
    4. Compute `c = pow(m, e, n)`.
    5. Format `c` as a lower-case hex string padded with leading zeros to 256 chars.
    """
    if not modulus_hex or not exponent_hex:
        raise ValidationError("Invalid RSA public key parameters (modulus or exponent empty).")

    try:
        n = int(modulus_hex.strip(), 16)
        e = int(exponent_hex.strip(), 16)
    except ValueError as exc:
        raise ValidationError("Invalid hexadecimal RSA public key parameters.") from exc

    if n <= 0 or e <= 0:
        raise ValidationError("RSA modulus and exponent must be positive integers.")

    key_bytes = (n.bit_length() + 7) >> 3
    raw_bytes = plaintext.encode("utf-8")
    if len(raw_bytes) > key_bytes:
        raise ValidationError(
            f"Message too long for RSA encryption ({len(raw_bytes)} bytes > {key_bytes} bytes)."
        )

    padded = raw_bytes + b"\x00" * (key_bytes - len(raw_bytes))
    m = int.from_bytes(padded, byteorder="big", signed=False)
    c = pow(m, e, n)
    hex_str = format(c, "x")
    if len(hex_str) & 1:
        hex_str = "0" + hex_str
    if len(hex_str) < 256:
        hex_str = hex_str.zfill(256)
    return hex_str


def extract_rsa_key_pair(login_get_result: dict) -> Sequence[str]:
    """Extract `[n, e]` from `/login?form=login` `method: get` result."""
    if not isinstance(login_get_result, dict):
        raise ValidationError("Unexpected response format when reading RSA login keys.")
    pwd_field = login_get_result.get("password")
    if (
        not isinstance(pwd_field, (list, tuple))
        or len(pwd_field) < 2
        or not isinstance(pwd_field[0], str)
        or not isinstance(pwd_field[1], str)
    ):
        raise ValidationError("Router did not return valid RSA public key parameters [n, e].")
    return pwd_field[0], pwd_field[1]
