from cryptography.hazmat.backends.openssl.rsa import _rsa_sig_determine_padding


def rsa_public_decrypt(key, signature, padding, algorithm):
    """Implementation of RSA_public_decrypt using cryptography-based modules. This hooks directly into the CFFI part
    of cryptography, so it probably breaks at some point.

    :param RSAPublicKey key: The RSAPublicKey that is used for decryption
    :param bytes signature: The signature bytes
    :param padding: The padding method
    :param algorithm: The hashing algorithm (only used for determining the signature)
    :return: The contents of the buffer
    """

    # This method calls raw C methods. This may fail, but shouldn't.
    backend = key._backend
    padding_enum = _rsa_sig_determine_padding(backend, key, padding, algorithm)

    buflen = backend._lib.RSA_size(key._rsa_cdata)
    backend.openssl_assert(buflen > 0)
    buf = backend._ffi.new("unsigned char[]", buflen - 11)
    res = backend._lib.RSA_public_decrypt(len(signature), signature, buf, key._rsa_cdata, padding_enum)
    backend.openssl_assert(res > 0)

    return backend._ffi.buffer(buf)[:res]
