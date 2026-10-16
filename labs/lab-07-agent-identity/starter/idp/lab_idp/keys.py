"""The IdP's signing key.

An OIDC provider signs tokens with a private key and publishes the matching
public key at a JWKS URL, so any client can verify a token without ever
holding a secret. That is the structural difference from lab 01, where the
same HS256 secret both signed and verified.

LAB ONLY (ADR-0008): the key lives in a file next to the code and is created
on first start. A real IdP keeps it in an HSM or a managed key service and
rotates it.
"""

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_PATH = Path(os.environ.get("LAB_IDP_KEY", Path(__file__).resolve().parent.parent / "lab07-idp-signing-key.pem"))


def _b64u_int(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class SigningKey:
    def __init__(self, private_key: rsa.RSAPrivateKey):
        self.private_key = private_key
        pub = private_key.public_key()
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = hashlib.sha256(der).hexdigest()[:16]
        self.private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def jwks(self) -> dict:
        nums = self.private_key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": _b64u_int(nums.n),
                    "e": _b64u_int(nums.e),
                }
            ]
        }


def load_or_create(path: Path = KEY_PATH) -> SigningKey:
    if path.exists():
        return SigningKey(serialization.load_pem_private_key(path.read_bytes(), password=None))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sk = SigningKey(key)
    path.write_bytes(sk.private_pem)
    return sk
