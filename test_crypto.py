# test_crypto.py
from app.pqc_crypto import generate_keypair, sign_message, verify_signature

def run_test():
    print("--- Testing PQC Engine ---")

    print("1. Generating new Dilithium3 key pair...")
    public_key, secret_key = generate_keypair()
    print("   ... SUCCESS!")
    print()

    message = b"This is a test message for our hackathon project!"
    print("2. Signing a message...")
    signature = sign_message(message, secret_key)
    print("   ... SUCCESS!")
    print()

    print("3. Verifying the signature...")
    is_valid = verify_signature(message, signature, public_key)
    if is_valid:
        print("   ... SUCCESS: Signature verified correctly!")
    else:
        print("   ... FAILED: Signature did not verify!")
    print()

    print("4. Testing a failed verification with wrong message...")
    wrong_message = b"This is the wrong message!"
    is_valid_fail = verify_signature(wrong_message, signature, public_key)
    if not is_valid_fail:
        print("   ... SUCCESS: Invalid signature was correctly rejected!")
    else:
        print("   ... FAILED: Invalid signature was accepted!")

if __name__ == "__main__":
    run_test()