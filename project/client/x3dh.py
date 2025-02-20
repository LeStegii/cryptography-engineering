from ecdsa import VerifyingKey, SigningKey

import utils


def x3dh_key(ik: SigningKey, ek: SigningKey, IPK_B: VerifyingKey, SPK_B: VerifyingKey, OPK_B: VerifyingKey):
    DH1 = utils.power_sk_vk(ik, SPK_B)
    DH2 = utils.power_sk_vk(ek, IPK_B)
    DH3 = utils.power_sk_vk(ek, SPK_B)
    DH4 = utils.power_sk_vk(ek, OPK_B)
    return utils.hkdf_extract(salt=None, input_key_material=DH1 + DH2 + DH3 + DH4)


def x3dh_key_reaction(IPK_A: VerifyingKey, EPK_A: VerifyingKey, ik: SigningKey, sk: SigningKey, ok: SigningKey):
    DH1 = utils.power_sk_vk(sk, IPK_A)
    DH2 = utils.power_sk_vk(ik, EPK_A)
    DH3 = utils.power_sk_vk(sk, EPK_A)
    DH4 = utils.power_sk_vk(ok, EPK_A)
    return utils.hkdf_extract(salt=None, input_key_material=DH1 + DH2 + DH3 + DH4)

