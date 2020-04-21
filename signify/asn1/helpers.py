import re


def rdn_to_string(rdn_sequence):
    """Returns an (almost) rfc2253 compatible string given a RDNSequence"""

    from . import oids
    from pyasn1.codec.ber import decoder

    result = []
    for n in rdn_sequence[::-1]:
        type_value = n[0]  # get the AttributeTypeAndValue object

        #   If the AttributeType is in a published table of attribute types
        #   associated with LDAP [4], then the type name string from that table
        #   is used, otherwise it is encoded as the dotted-decimal encoding of
        #   the AttributeType's OBJECT IDENTIFIER.
        type = oids.OID_TO_RDN.get(type_value['type'], ".".join(map(str, type_value['type'])))
        value = str(decoder.decode(type_value['value'])[0])

        # Escaping according to RFC2253
        value = re.sub("([,+\"<>;\\\\])", r"\\\1", value)
        if value.startswith("#"):
            value = "\\" + value
        if value.endswith(" "):
            value = value[:-1] + "\\ "
        result.append("{type}={value}".format(type=type, value=value))
    return ", ".join(result)


def rdn_get_components(rdn, component_type=None):
    """Get individual components of this RDNSequence

    :param component_type: if provided, yields only values of this type,
        if not provided, yields tuples of (type, value)
    """

    from . import oids
    from pyasn1.codec.ber import decoder

    for n in rdn[::-1]:
        type_value = n[0]  # get the AttributeTypeAndValue object
        type = oids.OID_TO_RDN.get(type_value['type'], ".".join(map(str, type_value['type'])))
        value = str(decoder.decode(type_value['value'])[0])

        if component_type is not None:
            if component_type in (type_value['type'], ".".join(map(str, type_value['type'])), type):
                yield value
        else:
            yield (type, value)


def time_to_python(time):
    if 'utcTime' in time:
        return time['utcTime'].asDateTime
    else:
        return time['generalTime'].asDateTime
