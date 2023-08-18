from __future__ import annotations

import hashlib
from typing import Iterable, cast

from pyasn1.type import univ
from pyasn1_modules import rfc5280

from signify import asn1, _print_type
from signify._typing import HashFunction
from signify.asn1 import guarded_ber_decode
from signify.exceptions import ParseError

# this list must be in the order of worst to best
ACCEPTED_DIGEST_ALGORITHMS = (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha384, hashlib.sha512)


def _verify_empty_algorithm_parameters(algorithm: rfc5280.AlgorithmIdentifier, location: str) -> None:
    if "parameters" in algorithm and algorithm["parameters"].isValue:
        parameters = guarded_ber_decode(algorithm["parameters"])
        if not isinstance(parameters, univ.Null):
            raise ParseError("%s has parameters set, which is unexpected" % (location,))


def _get_digest_algorithm(
    algorithm: rfc5280.AlgorithmIdentifier,
    location: str,
    acceptable: Iterable[HashFunction] = ACCEPTED_DIGEST_ALGORITHMS,
) -> HashFunction:
    result = asn1.oids.get(algorithm["algorithm"], asn1.oids.OID_TO_HASH)
    if isinstance(result, tuple) or result not in acceptable:
        raise ParseError(
            "%s must be one of %s, not %s" % (location, [x().name for x in acceptable], _print_type(result))
        )

    _verify_empty_algorithm_parameters(algorithm, location)

    return cast(HashFunction, result)


def _get_encryption_algorithm(algorithm: univ.Sequence, location: str) -> str:
    result = asn1.oids.OID_TO_PUBKEY.get(algorithm["algorithm"])
    if result is None:
        raise ParseError("%s: %s is not acceptable as encryption algorithm" % (location, algorithm["algorithm"]))

    _verify_empty_algorithm_parameters(algorithm, location)
    return result
