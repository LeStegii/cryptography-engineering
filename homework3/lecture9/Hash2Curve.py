from ecdsa import ellipticcurve, curves  # pip install ecdsa
from hashlib import sha256
from ecdsa.numbertheory import square_root_mod_prime
from os import urandom

# Information about P256
P256 = curves.NIST256p
a = P256.curve.a()
b = P256.curve.b()
p = P256.curve.p()
n = P256.order
g = P256.generator
q = n
HASH = sha256


def Create_P256_point(x, y):
    P = ellipticcurve.Point(P256.curve, x, y)
    return P


def Is_P256_point(x, y):
    # Since the cofactor is 1, so: is_EC_point = is_group_member
    try:
        ellipticcurve.Point(P256.curve, x, y)
        return True
    except:
        return False


def printable_P256_point(point):
    x = point.x()
    if x != None:
        y = point.y()
        str = f"({x}, {y})"
    else:
        str = "(0, 0)"
    return str


def GetY(x):
    # Given x, compute y such that (x,y) is a point in P256. 
    # If such y does not exist, return None
    p = P256.curve.p()
    rhs = (pow(x, 3, p) + (a * x) + b) % p
    try:
        y = square_root_mod_prime(rhs, p)
        # Two solutions: y0 and p-y0
        return (y, (p - y) % p)
    except:
        # No solution, (x,y) does not exist
        return None


def hash_to_curve(msg_bytes):
    """Warning: This is not a secure implementation (or at least not "uniform") for hash_to_curve. This method is just for illustrating how the DH-OPRF works."""
    """For a secure implementation, please refer to https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html"""
    # Input: msg, an arbitrary-length byte string.
    # Output: P = (x,y), a point in P256.
    h_pw = sha256(msg_bytes)
    h_pw_digest = h_pw.digest()
    first_byte = h_pw_digest[0]
    msb_left = (first_byte & 0x80) != 0
    msb_right = (first_byte & 0x80) != 1

    h_pw_int = int.from_bytes(h_pw_digest) % p

    x = p - h_pw_int
    while True:
        y_int = GetY(x)
        if y_int != None:
            break
        else:
            x = x - 1 % p
    y = y_int[msb_left]
    P_left = Create_P256_point(x, y)

    x = h_pw_int
    while True:
        y_int = GetY(x)
        if y_int != None:
            break
        else:
            x = x + 1 % p
    y = y_int[msb_right]
    P_right = Create_P256_point(x, y)

    P = P_left + P_right

    if x == h_pw_int:
        return P_left
    else:
        return P


def gen_random_point() -> ellipticcurve.Point:
    x = None
    y_int = None
    while y_int is None:
        x = int.from_bytes(urandom(32))
        y_int = GetY(x)
    y0, y1 = y_int
    return Create_P256_point(x, y0)


def test():
    # Example usage
    x = None
    y_int = None
    # Try to find a random point (x,y) in P256
    # To do this, just keep picking random x and trying until GetY(x) does not output None
    while True:
        x_rand = urandom(32)
        x = int.from_bytes(x_rand)
        y_int = GetY(x)
        if y_int != None:
            break
    y0, y1 = y_int

    # Create two points
    P0 = Create_P256_point(x, y0)
    P1 = Create_P256_point(x, y1)
    print("P0:", printable_P256_point(P0))
    print("P1:", printable_P256_point(P1))

    # Calculate Q = P0 + P1, should be the "zero" point of P256 (we normally call it "infinity")
    Q = P0 + P1
    Q_str = printable_P256_point(Q)
    print("P0 + P1 = ", Q_str)

    # Calculate r * P0 (if we use group description, then this is P0^r)
    r = int.from_bytes(urandom(32))
    Q = r * P0
    Q_str = printable_P256_point(Q)
    print("r: ", r)
    print("r * P0 = \n", Q_str)

    # Usage sample of hash_to_P256
    password = urandom(32)  # random password
    hpw_point = hash_to_curve(password)  # Get h(pw)
    hpw_point_str = printable_P256_point(hpw_point)
    print("pw = ", password)
    print("h(pw) = ", hpw_point_str)

    # # Test
    # for i in range(100000):
    #     password = urandom(32)
    #     hpw_point = hash_to_curve(password) 
    #     hpw_point_str = printable_P256_point(hpw_point)


if __name__ == "__main__":
    test()
