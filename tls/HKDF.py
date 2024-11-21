from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

HASH_FUNC = hashes.SHA256() # Use SHA256
KEY_LEN = 32 # 32 bytes

# HKDF.Extract
def hkdf_extract(salt, input_key_material, length=KEY_LEN):
    # Extract: Derive the PRK (pseudorandom key)
    hkdf_extract = HKDF(
        algorithm=HASH_FUNC,
        length=length,             # Length of the PRK (match SHA-256 output: 32 bytes)
        salt=salt,             # Salt can be any value or None
        info=None,             # No info for Extract phase
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk

# HKDF.Expand
def hkdf_expand(prk, info, length=KEY_LEN):
    # Expand: Derive the final key from the PRK
    hkdf_expand = HKDF(
        algorithm=HASH_FUNC,
        length=length,         # Desired output length of the final derived key
        salt=None,             # No salt in the Expand phase (PRK is used directly as key)
        info=info,             # Context-specific info parameter
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key

# HMAC_Sign
def hmac_sign(key, message): # compute tag = HMAC(key, message)
    # Create an HMAC object using SHA-256
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    tag = h.finalize()
    # Generate the HMAC code (digest)
    return tag

# HMAC_Verify
def hmac_verify(key, message, tag): # Verify tag =? HMAC(key, message)
    # Create a new HMAC object with the same message and key
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    try:
        # Verify by comparing with the provided signature
        h.verify(tag)
        return True
    except Exception:
        return False


# Example usage
def main():
    # Define the initial input keying material (IKM) and optional salt and info
    ikm = b"This is a key material"  # Input secret
    salt = b"This is a salt value"           # Salt

    # Extract a pseudorandom key
    prk = hkdf_extract(salt, ikm)
    print("PRK (pseudorandom key):", prk.hex())

    # Perform the Expand phase to get the final derived key
    info_A = b"This key is for Alice"
    info_B = b"This key is for Bob"
    info_C = b"This key is for Charlie"
    info_D = b"This key is for Denise"

    derived_key_A = hkdf_expand(prk, info_A)  
    derived_key_B = hkdf_expand(prk, info_B)  
    derived_key_C = hkdf_expand(prk, info_C)  
    derived_key_D = hkdf_expand(prk, info_D)  

    print("Derived Key for Alice:", derived_key_A.hex())
    print("Derived Key for Bob:", derived_key_B.hex())
    print("Derived Key for Charlie:", derived_key_C.hex())
    print("Derived Key for Denise:", derived_key_D.hex())

    # Example of HMAC
    message_A = b"This is Alice's tag"
    tag_A = hmac_sign(derived_key_A, message_A)
    print("Alice's tag:", tag_A.hex())
    assert hmac_verify(derived_key_A, message_A, tag_A) == True
    assert hmac_verify(derived_key_A, info_A, tag_A) == False # Wrong message
    assert hmac_verify(derived_key_B, message_A, tag_A) == False # Wrong key
    assert hmac_verify(derived_key_A, message_A, b"TryTryTryTry") == False # Wrong tag

    # Example of concatenating two bytes
    byte_var1 = b'\x01\x02'
    byte_var2 = b'\x03\x04'
    byte_string1 = b'This is Alice and '
    byte_string2 = b'this is Bob.'

    concatenated_bytes = byte_var1 + byte_var2
    concatenated_bytes_string = byte_string1 + byte_string2
    print(concatenated_bytes)
    print(concatenated_bytes_string.decode()) # decode to string

if __name__ == "__main__":
    main()