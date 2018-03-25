from . import pkcs7, spc, x509, oids


def guarded_ber_decode(data, asn1_spec=None):
    from pyasn1.codec.ber import decoder as ber_decoder
    from signify.exceptions import ParseError
    from signify import _print_type

    result, rest = ber_decoder.decode(data, asn1Spec=asn1_spec)
    if rest:
        raise ParseError("Extra information after parsing %s BER" % _print_type(asn1_spec))
    return result
