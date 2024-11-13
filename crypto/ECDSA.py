from ecdsa import SigningKey, util # pip install ecdsa

# Use the curve P256, also known as SECP256R1, see https://neuromancer.sk/std/nist/P-256
from ecdsa import NIST256p as CURVE  

# Use SHA256 as the hash function used in DSA
from hashlib import sha256 as HASH_FUNC

# Or one can try P521 + SHA512 
# Note that the length of the HASH_FUNC must be shorter than the order of CURVE
# from ecdsa import NIST521p as CURVE  #Use the curve P521
# from hashlib import sha512 as HASH_FUNC


# Function to sign a message using ECDSA
def ecdsa_sign(message, private_key, nonce = None):
    signature = None
    if nonce: # If the nonce is explicitly specified
        signature = private_key.sign(
            message,
            k=nonce, 
            hashfunc=HASH_FUNC, 
            sigencode=util.sigencode_der
        )
    else:
        signature = private_key.sign(
            message,
            hashfunc=HASH_FUNC, 
            sigencode=util.sigencode_der
        )
    return signature


# Function to verify ECDSA signature
def ecdsa_verify(signature, message, public_key):
    try:
        is_valid = public_key.verify(
            signature,
            message,
            hashfunc=HASH_FUNC,
            sigdecode=util.sigdecode_der
        )
        return is_valid
    except:
        return False

# Compute the inverse of a number w.r.t modulus
def invert(number, modulus): # GCD(number, modulus) should be 1 (i.e., they are co-prime)
    inverse = None
    try:
        inverse = pow(number, -1, modulus)
    except:
        print("Non-invertible element.")
    return inverse

def main():

    # Generate ECDSA key pair
    private_key = SigningKey.generate(CURVE)
    public_key = private_key.get_verifying_key()
    order_CURVE = CURVE.order

    # Print the sk and pk
    private_key_int = private_key.privkey.secret_multiplier
    print("\nPrivate Key (decimal):", private_key_int)
    public_key_point = public_key.pubkey.point
    public_key_x = public_key_point.x()
    public_key_y = public_key_point.y()

    print("Public Key X (decimal):", public_key_x)
    print("Public Key Y (decimal):", public_key_y)

    # Message to be signed
    message = b"Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!Hello, Alice!"
    hashed_message = HASH_FUNC(message).digest()
    print("\nThe hash of the message is:", hashed_message.hex())
    h1 = int.from_bytes(HASH_FUNC(message).digest(), byteorder='big')
    print("The integer of the hash is:", h1)


    # Example of generating DSA signature with random nonce
    signature_random_nonce = ecdsa_sign(message, private_key)
    r_random, s_random = util.sigdecode_der(signature_random_nonce, order_CURVE)
    print("\nSignature (r, s) with random nonce:")
    print("r =", r_random)
    print("s =", s_random)

    # Verify the signature    
    is_valid_sigma_random_nonce = ecdsa_verify(signature_random_nonce, message, public_key)
    if is_valid_sigma_random_nonce:
        print("Signature with random nonce is valid")

    ## Example of generating DSA signature with fixed nonce
    nonce = 34119 % order_CURVE
    signature_fixed_nonce = ecdsa_sign(message, private_key, nonce)
    r_fixed, s_fixed = util.sigdecode_der(signature_fixed_nonce, order_CURVE)
    print("\nSignature (r_1, s_1) with fixed nonce:") # Here r is always the same, but s may be varied because of the internal randomness of padding message
    print("r_1 =", r_fixed)
    print("s_1 =", s_fixed)

    # Verify the signatures
    is_valid_sigma_fixed_nonce = ecdsa_verify(signature_fixed_nonce, message, public_key)
    if is_valid_sigma_fixed_nonce: 
        print("Signature with fixed nonce is valid")

    modulus = order_CURVE
    inverse_r_fixed = invert(r_fixed, modulus) % modulus
    print(f"\nThe inverse of r_1 is: {inverse_r_fixed}")

    # Example of Nonce-reuse attack
    # TODO

if __name__ == "__main__":
    main()