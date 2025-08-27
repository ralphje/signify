from __future__ import annotations

import argparse
import logging
import pathlib
import re
import textwrap
from typing import Any, cast

from signify.authenticode import AuthenticodeFile, CertificateTrustList
from signify.authenticode.indirect_data import IndirectData, PeImageData, SigInfo
from signify.authenticode.signed_data import AuthenticodeSignature
from signify.authenticode.signer_info import AuthenticodeSignerInfo
from signify.authenticode.tsp import RFC3161SignedData
from signify.pkcs7 import SignedData, SignerInfo
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
    if name in (
        "message_digest",
        "microsoft_ctl_subject_name_md5_hash",
        "microsoft_ctl_key_identifier",
        "microsoft_ctl_auth_root_sha256_hash",
    ):
        return [f"{name}: {values[0].native.hex()}"]
    if len(values) == 1:
        value = values[0]
        if name == "microsoft_spc_indirect_data_content":
            return [
                f"{name}:",
                indent_text(*describe_indirect_data(IndirectData(value))),
            ]
        if isinstance(value.native, dict):
            return [
                f"{name}:",
                indent_text(*[f"{k}: {v}" for k, v in value.native.items()]),
            ]
        return [f"{name}: {value.native}"]
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
                    *describe_signed_data(
                        cast(RFC3161SignedData, signer_info.countersigner)
                    ),
                    indent=4,
                ),
            ]

    return result


def describe_indirect_data(indirect_data: IndirectData) -> list[str]:
    result = [
        f"Digest algorithm: {indirect_data.digest_algorithm.__name__}",
        f"Digest: {indirect_data.digest.hex()}",
        f"Content type: {indirect_data.content_type}",
    ]
    if indirect_data.content_type == "microsoft_spc_pe_image_data" and isinstance(
        indirect_data.content, PeImageData
    ):
        pe_image_data = indirect_data.content
        result += [
            "",
            "PE Image Data:",
            indent_text(
                f"Flags: {pe_image_data.flags}",
                f"File Link Type: {pe_image_data.file_link_type}",
            ),
        ]
        if pe_image_data.file_link_type == "moniker":
            result += [
                indent_text(
                    f"Class ID: {pe_image_data.class_id}",
                    f"Content Type: {','.join(pe_image_data.content_types)}",
                )
            ]
        else:
            result += [
                indent_text(
                    f"Publisher: {pe_image_data.publisher}",
                )
            ]

    if indirect_data.content_type == "microsoft_spc_siginfo" and isinstance(
        indirect_data.content, SigInfo
    ):
        siginfo = indirect_data.content
        result += [
            "",
            "SigInfo:",
            indent_text(
                f"SIP Version: {siginfo.sip_version}",
                f"SIP GUID: {siginfo.sip_guid}",
            ),
        ]

    return result


def describe_signed_data(signed_data: SignedData) -> list[str]:
    result = []

    if len(signed_data.signer_infos) == 1:
        result += [
            "Included certificates:",
            *[format_certificate(cert) for cert in signed_data.certificates],
            "",
            "Signer:",
            indent_text(*describe_signer_info(signed_data.signer_info), indent=4),
            "",
            f"Digest algorithm: {signed_data.digest_algorithm.__name__}",
            f"Content type: {signed_data.content_type}",
        ]

    if isinstance(signed_data, AuthenticodeSignature) and signed_data.indirect_data:
        result += [
            "",
            "Indirect Data:",
            indent_text(*describe_indirect_data(signed_data.indirect_data)),
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

    if isinstance(signed_data, CertificateTrustList):
        result += [
            "",
            "Certificate Trust List:",
            indent_text(
                f"Subject usage: {signed_data.subject_usage}",
                (
                    f"List identifier: {signed_data.list_identifier.hex()}"
                    if signed_data.list_identifier
                    else "List identifier: None"
                ),
                f"Sequence number: {signed_data.sequence_number}",
                f"This update: {signed_data.this_update}",
                f"Next update: {signed_data.next_update}",
                f"Subject algorithm: "
                + (
                    signed_data.subject_algorithm
                    if isinstance(signed_data.subject_algorithm, str)
                    else signed_data.subject_algorithm.__name__
                ),
                "",
                f"Subjects:",
                *[
                    list_item(
                        f"Identifier: {s.identifier_str}",
                        "Attributes:",
                        *(
                            list_item(*describe_attribute(*attribute))
                            for attribute in s.attributes_asn1.items()
                        ),
                    )
                    for s in signed_data.subjects
                ],
            ),
        ]

    if isinstance(signed_data, (AuthenticodeSignature, CertificateTrustList)):
        verify_result, e = signed_data.explain_verify()
        result += ["", str(verify_result)]
        if e:
            result += [f"{e!r}"]

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Authenticode signature")
    parser.add_argument(
        "filenames", nargs="*", help="Filenames to verify", type=pathlib.Path
    )
    parser.add_argument(
        "--catalog",
        action="append",
        help="Catalog files to use in verification",
        type=pathlib.Path,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Provide full details on the signatures.",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    for filename in args.filenames:
        print(f"{filename}:")
        try:
            with filename.open("rb") as file_obj:
                signed_file = AuthenticodeFile.from_stream(file_obj, allow_flat=True)

                # Add catalogs
                for catalog in args.catalog or ():
                    with catalog.open("rb") as catalog_obj:
                        signed_file.add_catalog(catalog_obj)

                # When verbose, print the full signatures
                if args.verbose:
                    for signed_data in signed_file.signatures:
                        print(indent_text(*describe_signed_data(signed_data), indent=4))
                        print("--------")

                # Get the result
                result, e = signed_file.explain_verify()

                # When verbose, print the full result, or print the summary when not
                # verbose.
                if args.verbose:
                    print(result)
                    if e:
                        print(repr(e))
                else:
                    print(f"    Status: {result.name}")

        except Exception as e:
            if args.verbose:
                print("    Error while parsing: " + str(e))
            else:
                print("    Status: ERROR")


if __name__ == "__main__":
    main()
