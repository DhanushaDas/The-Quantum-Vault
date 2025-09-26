# app/pqc_crypto.py
import oqs
import base64

# Use the Dilithium3 algorithm, as specified in your plan
_SIG_ALGORITHM = "Dilithium3"

def generate_keypair():
    """
    Generates a new PQC public and private key pair.
    """
    with oqs.Signature(_SIG_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return base64.b64encode(public_key).decode(), base64.b64encode(secret_key).decode()

def sign_message(message_bytes, secret_key_b64):
    """
    Signs a message using the PQC private key.
    """
    secret_key = base64.b64decode(secret_key_b64)
    with oqs.Signature(_SIG_ALGORITHM, secret_key) as signer:
        signature = signer.sign(message_bytes)
        return base64.b64encode(signature).decode()

def verify_signature(message_bytes, signature_b64, public_key_b64):
    """
    Verifies a signature using the PQC public key.
    """
    public_key = base64.b64decode(public_key_b64)
    signature = base64.b64decode(signature_b64)
    with oqs.Signature(_SIG_ALGORITHM) as verifier:
        try:
            return verifier.verify(message_bytes, signature, public_key)
        except Exception:
            return False