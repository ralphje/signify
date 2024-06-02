from __future__ import annotations

import hashlib
from typing import Iterable, cast

from asn1crypto import algos

from signify._typing import HashFunction
from signify.exceptions import ParseError

# this list must be in the order of worst to best
ACCEPTED_DIGEST_ALGORITHMS = ("md5", "sha1", "sha256", "sha384", "sha512")


def _get_digest_algorithm(
    algorithm: algos.DigestAlgorithm,
    location: str,
    acceptable: Iterable[str] = ACCEPTED_DIGEST_ALGORITHMS,
) -> HashFunction:
    alg = algorithm["algorithm"].native
    if alg not in acceptable:
        raise ParseError(f"{location} must be one of {list(acceptable)}, not {alg}")
    if algorithm["parameters"].native:
        raise ParseError(f"{location} has parameters set, which is unexpected")
    return cast(HashFunction, getattr(hashlib, alg))
