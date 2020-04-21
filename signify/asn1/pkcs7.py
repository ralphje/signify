from pyasn1.type import univ
from pyasn1_modules import rfc2315


class Data(univ.OctetString):
    pass


class Countersignature(rfc2315.SignerInfo):
    pass
