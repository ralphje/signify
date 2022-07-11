import logging
import sys

from authenticode import SignedPEFile


def main(*filenames):
    logging.basicConfig(level=logging.DEBUG)

    for filename in filenames:
        print("{}:".format(filename))
        with open(filename, "rb") as file_obj:
            try:
                pe = SignedPEFile(file_obj)
                for signed_data in pe.signed_datas:
                    print("    Included certificates:")
                    for cert in signed_data.certificates:
                        print("      - Subject: {}".format(cert.subject.dn))
                        print("        Issuer: {}".format(cert.issuer.dn))
                        print("        Serial: {}".format(cert.serial_number))
                        print("        Valid from: {}".format(cert.valid_from))
                        print("        Valid to: {}".format(cert.valid_to))

                    print()
                    print("    Signer:")
                    print("        Issuer: {}".format(signed_data.signer_info.issuer.dn))
                    print("        Serial: {}".format(signed_data.signer_info.serial_number))
                    print("        Program name: {}".format(signed_data.signer_info.program_name))
                    print("        More info: {}".format(signed_data.signer_info.more_info))

                    if signed_data.signer_info.countersigner:
                        print()
                        if hasattr(signed_data.signer_info.countersigner, 'issuer'):
                            print("    Countersigner:")
                            print("        Issuer: {}".format(signed_data.signer_info.countersigner.issuer.dn))
                            print("        Serial: {}".format(signed_data.signer_info.countersigner.serial_number))
                        if hasattr(signed_data.signer_info.countersigner, 'signer_info'):
                            print("    Countersigner (nested RFC3161):")
                            print("        Issuer: {}".format(
                                signed_data.signer_info.countersigner.signer_info.issuer.dn
                            ))
                            print("        Serial: {}".format(
                                signed_data.signer_info.countersigner.signer_info.serial_number
                            ))
                        print("        Signing time: {}".format(signed_data.signer_info.countersigner.signing_time))

                        if hasattr(signed_data.signer_info.countersigner, 'certificates'):
                            print("        Included certificates:")
                            for cert in signed_data.signer_info.countersigner.certificates:
                                print("          - Subject: {}".format(cert.subject.dn))
                                print("            Issuer: {}".format(cert.issuer.dn))
                                print("            Serial: {}".format(cert.serial_number))
                                print("            Valid from: {}".format(cert.valid_from))
                                print("            Valid to: {}".format(cert.valid_to))

                    print()
                    print("    Digest algorithm: {}".format(signed_data.digest_algorithm.__name__))
                    print("    Digest: {}".format(signed_data.spc_info.digest.hex()))

                    print()

                    result, e = signed_data.explain_verify()
                    print("    {}".format(result))
                    if e:
                        print("    {}".format(e))
                    print("--------")

                result, e = pe.explain_verify()
                print(result)
                if e:
                    print(e)

            except Exception as e:
                print("    Error while parsing: " + str(e))


if __name__ == '__main__':
    main(*sys.argv[1:])
