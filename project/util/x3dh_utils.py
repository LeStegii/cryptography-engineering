from ecdsa import VerifyingKey, SigningKey

from project.util import crypto_utils


def x3dh_key(ik: SigningKey, ek: SigningKey, IPK_B: VerifyingKey, SPK_B: VerifyingKey, OPK_B: VerifyingKey):
    DH1 = crypto_utils.power_sk_vk(ik, SPK_B)
    DH2 = crypto_utils.power_sk_vk(ek, IPK_B)
    DH3 = crypto_utils.power_sk_vk(ek, SPK_B)
    DH4 = crypto_utils.power_sk_vk(ek, OPK_B)
    return crypto_utils.hkdf_extract(salt=None, input_key_material=DH1 + DH2 + DH3 + DH4)


def x3dh_key_reaction(IPK_A: VerifyingKey, EPK_A: VerifyingKey, ik: SigningKey, sk: SigningKey, ok: SigningKey):
    DH1 = crypto_utils.power_sk_vk(sk, IPK_A)
    DH2 = crypto_utils.power_sk_vk(ik, EPK_A)
    DH3 = crypto_utils.power_sk_vk(sk, EPK_A)
    DH4 = crypto_utils.power_sk_vk(ok, EPK_A)
    return crypto_utils.hkdf_extract(salt=None, input_key_material=DH1 + DH2 + DH3 + DH4)

def generate_initial_x3dh_keys():
    ik, IPK = crypto_utils.generate_signature_key_pair()
    sk, SPK = crypto_utils.generate_signature_key_pair()
    one_time_prekeys = crypto_utils.generate_one_time_pre_keys(5)

    return {
        "ik": ik,
        "IPK": IPK,
        "sk": sk,
        "SPK": SPK,
        "sigma": crypto_utils.ecdsa_sign(SPK.to_pem(), ik),
        "oks": [ok for ok, _ in one_time_prekeys],
        "OPKs": [OPK for _, OPK in one_time_prekeys]
    }