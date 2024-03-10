from typing import Tuple
from pathlib import Path

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


def generate_self_signed_certificate(ip_address_str: str | Path) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Generate a self-signed SSL certificate for the given IP address

    Args:
        ip_address_str (str): The IP address for which the certificate is being generated

    Returns:
        tuple: A tuple containing the private key and the generated SSL certificate

    The function generates a self-signed SSL certificate using the RSA algorithm with a
    2048-bit key size. The certificate is valid for one year starting from the current
    UTC time. The IP address provided is included as the common name and subject alternative
    name in the certificate.

    Example:
        private_key, certificate = generate_self_signed_certificate('192.168.1.1')
    """
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
