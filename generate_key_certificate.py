import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generate_RSA_PK():
    private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,)

    # Escribimos la PK serializada en el fichero
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'elbicho64')
        )

    file = open("JsonFiles/private_key.json", "w")
    b64_bytes_key = base64.urlsafe_b64encode(pem)
    b64_string_key = b64_bytes_key.decode("ascii")
    file.write(b64_string_key)


def generate_CSR(private_key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CryptoBank"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CryptoBank"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"CryptoBank.com"),
            x509.DNSName(u"www.CryptoBank.com"),
            x509.DNSName(u"subdomain.CryptoBank.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256())
    # Write our CSR out to disk.
    f = open("certificates/csr.pem", "wb")
    f.write(csr.public_bytes(serialization.Encoding.PEM))


