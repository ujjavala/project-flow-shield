"""Generate a persistent local-only RSA OIDC key pair when none exists."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    key_dir = Path(os.getenv("OIDC_KEY_DIRECTORY", "/run/oidc"))
    private_path = key_dir / "signing-key.pem"
    public_path = key_dir / "signing-public.pem"
    key_dir.mkdir(parents=True, exist_ok=True)

    if private_path.exists():
        private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            raise RuntimeError("Existing local OIDC key is not an RSA key of at least 2048 bits")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private_path.chmod(0o600)

    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o644)
    print(f"Local OIDC keys are ready in {key_dir}")


if __name__ == "__main__":
    main()