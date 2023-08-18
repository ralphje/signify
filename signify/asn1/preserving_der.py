from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import encoder
from pyasn1.compat.octets import null, str2octs
from pyasn1.type import univ

__all__ = ["encode"]


class SetOfEncoder(cer_encoder.SetOfEncoder):  # type: ignore[misc]
    """This class is identical to the one of the CER encoder, except that the sorting
    has been removed.
    """

    def encodeValue(  # type: ignore[no-untyped-def]  # noqa: N802
        self,
        value,
        asn1Spec,  # noqa: N803
        encodeFun,  # noqa: N803
        **options,
    ):
        chunks = self._encodeComponents(value, asn1Spec, encodeFun, **options)

        if len(chunks) > 1:
            zero = str2octs("\x00")
            max_len = max(map(len, chunks))
            padded_chunks = [(x.ljust(max_len, zero), x) for x in chunks]

            chunks = [x[1] for x in padded_chunks]

        return null.join(chunks), True, True


tagMap = encoder.tagMap.copy()  # noqa: N816
tagMap.update({univ.SetOf.tagSet: SetOfEncoder()})

typeMap = encoder.typeMap.copy()  # noqa: N816
typeMap.update({univ.SetOf.typeId: SetOfEncoder()})


class Encoder(encoder.Encoder):  # type: ignore[misc]
    fixedDefLengthMode = True  # noqa: N815
    fixedChunkSize = 0  # noqa: N815


encode = Encoder(tagMap, typeMap)
