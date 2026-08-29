"""Native Windows SystemCertificates registry record construction."""

def certificate_store_patch(certificate, store = "ROOT"):
    """Builds one machine SystemCertificates patch from a certificate record."""
    fingerprint = certificate.sha1.upper()
    digest = binary.decode(fingerprint, encoding = "hex")
    if len(digest) != 20:
        fail("certificate fingerprint is not SHA-1")
    blob = binary.builder(capacity = 44 + len(certificate.der))
    blob.u32le(3)
    blob.u32le(1)
    blob.u32le(len(digest))
    blob.append(digest)
    blob.u32le(32)
    blob.u32le(1)
    blob.u32le(len(certificate.der))
    blob.append(certificate.der)
    return {
        "hive": "SOFTWARE",
        "key": "/Microsoft/SystemCertificates/%s/Certificates/%s" % (store.upper(), fingerprint),
        "name": "Blob",
        "type": "REG_BINARY",
        "value": blob.bytes(),
    }
