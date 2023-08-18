from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import encoder
from pyasn1.compat.octets import null, str2octs
from pyasn1.type import univ

__all__ = ["encode"]


class SetOfEncoder(cer_encoder.SetOfEncoder):  # type: ignore[misc]
    """This class is identical to the one of the CER encoder, except that the sorting
    has been removed.
    """

    def encodeValue(self, value, asn1Spec, encodeFun, **options):  # type: ignore[no-untyped-def]
        chunks = self._encodeComponents(value, asn1Spec, encodeFun, **options)

        if len(chunks) > 1:
            zero = str2octs("\x00")
            maxLen = max(map(len, chunks))
            paddedChunks = [(x.ljust(maxLen, zero), x) for x in chunks]

            chunks = [x[1] for x in paddedChunks]

        return null.join(chunks), True, True


tagMap = encoder.tagMap.copy()
tagMap.update({univ.SetOf.tagSet: SetOfEncoder()})

typeMap = encoder.typeMap.copy()
typeMap.update({univ.SetOf.typeId: SetOfEncoder()})


class Encoder(encoder.Encoder):  # type: ignore[misc]
    fixedDefLengthMode = True
    fixedChunkSize = 0


encode = Encoder(tagMap, typeMap)
