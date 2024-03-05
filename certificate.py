import win32crypt
import win32cryptcon

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from ipaddress import ip_address

import configparser
config = configparser.ConfigParser()
config.read('settings.ini')

key_path = config.get('Paths', 'key_path')
cert_path = config.get('Paths', 'cert_path')


def generate_self_signed_certificate(ip_address_str: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ip_address_str)
    ])

    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=365)

    ip = ip_address(ip_address_str)
    ip_constraint = x509.IPAddress(ip)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.SubjectAlternativeName([ip_constraint]),
            critical=False
        )
    )

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return private_key, certificate


def save_key(private_key) -> None:
    with open(key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


def save_certificate(certificate) -> None:
    with open(cert_path, "wb") as cert_file:
        cert_file.write(
            certificate.public_bytes(encoding=serialization.Encoding.PEM)
        )


def install_ssl_certificate(certificate_path) -> None:
    with open(certificate_path, 'r') as cert_file:
        cert_str = cert_file.read()

    # decoding certificate
    cert_byte = win32crypt.CryptStringToBinary(cert_str, win32cryptcon.CRYPT_STRING_BASE64HEADER)[0]

    # opening root store
    store = win32crypt.CertOpenStore(
        win32cryptcon.CERT_STORE_PROV_SYSTEM,
        0,
        None,
        win32cryptcon.CERT_SYSTEM_STORE_LOCAL_MACHINE,
        "ROOT"
    )

    try:
        # installing certificate
        store.CertAddEncodedCertificateToStore(
            win32cryptcon.X509_ASN_ENCODING,
            cert_byte,
            win32cryptcon.CERT_STORE_ADD_REPLACE_EXISTING)
    finally:
        # closing opened store
        store.CertCloseStore(win32cryptcon.CERT_CLOSE_STORE_FORCE_FLAG)
