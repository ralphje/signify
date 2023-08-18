from __future__ import annotations

from typing import Any, TypeVar, overload

from pyasn1.type.base import Asn1Type

from . import pkcs7, spc, oids, ctl

__all__ = ["pkcs7", "spc", "oids", "ctl", "guarded_ber_decode", "guarded_der_decode"]


_T = TypeVar("_T", bound=Asn1Type)


@overload
def guarded_ber_decode(data: Any, asn1_spec: _T) -> _T:
    ...


@overload
def guarded_ber_decode(data: Any, asn1_spec: None = None) -> Asn1Type:
    ...


def guarded_ber_decode(data: Any, asn1_spec: _T | None = None) -> Asn1Type | _T:
    from pyasn1.codec.ber import decoder as ber_decoder
    from signify.exceptions import ParseError
    from signify import _print_type

    try:
        result, rest = ber_decoder.decode(data, asn1Spec=asn1_spec)
    except Exception as e:
        raise ParseError("Error while parsing %s BER: %s" % (_print_type(asn1_spec), e))
    if rest:
        raise ParseError("Extra information after parsing %s BER" % _print_type(asn1_spec))
    return result


@overload
def guarded_der_decode(data: Any, asn1_spec: _T) -> _T:
    ...


@overload
def guarded_der_decode(data: Any, asn1_spec: None = None) -> Asn1Type:
    ...


def guarded_der_decode(data: Any, asn1_spec: _T | None = None) -> Asn1Type | _T:
    from pyasn1.codec.der import decoder as der_decoder
    from signify.exceptions import ParseError
    from signify import _print_type

    try:
        result, rest = der_decoder.decode(data, asn1Spec=asn1_spec)
    except Exception as e:
        raise ParseError("Error while parsing %s DER: %s" % (_print_type(asn1_spec), e))
    if rest:
        raise ParseError("Extra information after parsing %s DER" % _print_type(asn1_spec))
    return result
