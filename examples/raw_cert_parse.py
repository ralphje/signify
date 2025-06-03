from __future__ import annotations

import logging
import re
import pathlib
import sys
import textwrap
from typing import Any


from signify.authenticode import (
    RawCertificateFile,
    AuthenticodeSignedData,
    AuthenticodeSignerInfo,
    RFC3161SignedData,
)
from signify.pkcs7 import SignerInfo, SignedData
from signify.x509 import Certificate


def indent_text(*items: str, indent: int = 4) -> str:
    return "\n".join(textwrap.indent(item, " " * indent) for item in items)


def list_item(*items: str, indent: int = 4) -> str:
    return re.sub(r"^( *) {2}", r"\1- ", indent_text(*items, indent=indent))


def format_certificate(cert: Certificate, indent: int = 4) -> str:
    return list_item(
        f"Subject: {cert.subject.dn}",
        f"Issuer: {cert.issuer.dn}",
        f"Serial: {cert.serial_number}",
        f"Valid from: {cert.valid_from}",
        f"Valid to: {cert.valid_to}",
        indent=indent,
    )


def describe_attribute(name: str, values: list[Any]) -> list[str]:
    if name in (
        "microsoft_time_stamp_token",
        "microsoft_spc_sp_opus_info",
        "counter_signature",
    ):
        return [f"{name}: (elided)"]
    if name == "message_digest":
        return [f"{name}: {values[0].native.hex()}"]
    if len(values) == 1:
        return [f"{name}: {values[0].native}"]
    return [f"{name}:", *[list_item(str(value.native)) for value in values]]


def describe_signer_info(signer_info: SignerInfo) -> list[str]:
    result = [
        f"Issuer: {signer_info.issuer.dn}",
        f"Serial: {signer_info.serial_number}",
        f"Digest algorithm: {signer_info.digest_algorithm.__name__}",
        f"Digest encryption algorithm: {signer_info.digest_encryption_algorithm}",
        f"Encrypted digest: {signer_info.encrypted_digest.hex()}",
    ]

    if signer_info.authenticated_attributes:
        result += [
            "",
            "Authenticated attributes:",
            *[
                list_item(*describe_attribute(*attribute))
                for attribute in signer_info.authenticated_attributes.items()
            ],
        ]
    if signer_info.unauthenticated_attributes:
        result += [
            "",
            "Unauthenticated attributes:",
            *[
                list_item(*describe_attribute(*attribute))
                for attribute in signer_info.unauthenticated_attributes.items()
            ],
        ]

    if isinstance(signer_info, AuthenticodeSignerInfo):
        result += [
            "",
            "Opus Info:",
            indent_text(
                f"Program name: {signer_info.program_name}",
                f"More info: {signer_info.more_info}",
                f"Publisher info: {signer_info.publisher_info}",
                indent=4,
            ),
        ]

    if signer_info.countersigner:
        result += [""]
        if hasattr(signer_info.countersigner, "issuer"):
            result += [
                "Countersigner:",
                indent_text(
                    f"Signing time: {signer_info.countersigner.signing_time}",
                    *describe_signer_info(signer_info.countersigner),
                    indent=4,
                ),
            ]
        if hasattr(signer_info.countersigner, "signer_info"):
            result += [
                "Countersigner (nested RFC3161):",
                indent_text(
                    *describe_signed_data(signer_info.countersigner),
                    indent=4,
                ),
            ]

    return result


def describe_signed_data(signed_data: SignedData):
    result = [
        "Included certificates:",
        *[format_certificate(cert) for cert in signed_data.certificates],
        "",
        "Signer:",
        indent_text(*describe_signer_info(signed_data.signer_info), indent=4),
        "",
        f"Digest algorithm: {signed_data.digest_algorithm.__name__}",
        f"Content type: {signed_data.content_type}",
    ]

    if isinstance(signed_data, AuthenticodeSignedData) and signed_data.indirect_data:
        result += [
            "",
            "Indirect Data:",
            indent_text(
                f"Digest algorithm: {signed_data.indirect_data.digest_algorithm.__name__}",
                f"Digest: {signed_data.indirect_data.digest.hex()}",
                f"Content type: {signed_data.indirect_data.content_type}",
            ),
        ]
        if signed_data.indirect_data.content_type == "microsoft_spc_pe_image_data":
            pe_image_data = signed_data.indirect_data.content
            result += [
                "",
                indent_text("PE Image Data:", indent=4),
                indent_text(
                    f"Flags: {pe_image_data.flags}",
                    f"File Link Type: {pe_image_data.file_link_type}",
                    indent=8,
                ),
            ]
            if pe_image_data.file_link_type == "moniker":
                result += [
                    indent_text(
                        f"Class ID: {pe_image_data.class_id}",
                        f"Content Type: {','.join(pe_image_data.content_types)}",
                        indent=8,
                    )
                ]
            else:
                result += [
                    indent_text(
                        f"Publisher: {pe_image_data.publisher}",
                        indent=8,
                    )
                ]

    if isinstance(signed_data, RFC3161SignedData) and signed_data.tst_info:
        result += [
            "",
            "TST Info:",
            indent_text(
                f"Hash algorithm: {signed_data.tst_info.hash_algorithm.__name__}",
                f"Digest: {signed_data.tst_info.message_digest.hex()}",
                f"Serial number: {signed_data.tst_info.serial_number}",
                f"Signing time: {signed_data.tst_info.signing_time}",
                f"Signing time acc: {signed_data.tst_info.signing_time_accuracy}",
                f"Signing authority: {signed_data.tst_info.signing_authority}",
            ),
        ]

    if isinstance(signed_data, AuthenticodeSignedData):
        verify_result, e = signed_data.explain_verify()
        result += ["", str(verify_result)]
        if e:
            result += [f"{e}"]

    return result


def main(*filenames: str):
    logging.basicConfig(level=logging.DEBUG)

    for filename in filenames:
        print(f"{filename}:")
        with pathlib.Path(filename).open("rb") as file_obj:
            try:
                pe = RawCertificateFile(file_obj)
                for signed_data in pe.signed_datas:
                    print(indent_text(*describe_signed_data(signed_data), indent=4))
                    print("--------")

                result, e = pe.explain_verify()
                print(result)
                if e:
                    print(e)

            except Exception as e:
                raise
                print("    Error while parsing: " + str(e))


if __name__ == "__main__":
    main(*sys.argv[1:])
