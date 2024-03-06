import sys
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from ipaddress import ip_address

import configparser
import platform

config = configparser.ConfigParser()
config.read('settings.ini')

key_path = config.get('Paths', 'key_path')
cert_path = config.get('Paths', 'cert_path')


def generate_self_signed_certificate(ip_address_str: str) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
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


def install_ssl_certificate(certificate_path: str) -> None:
    os = platform.system()
    match os:
        case 'Windows':
            install_ssl_certificate_win(certificate_path)
        case 'Linux':
            install_ssl_certificate_linux(certificate_path)
        case default:
            print("Unknown operating system")
            sys.exit()


def install_ssl_certificate_linux(certificate_path: str) -> None:
    """
    Install an SSL certificate to the root store on Linux.

    Args:
        certificate_path (str): Path to the SSL certificate file.

    This function reads the contents of the certificate file and installs it to the
    root certificate store on a Linux system.

    Note:
        This function assumes the use of the `update-ca-certificates` command, which is
        commonly available on Debian-based distributions. This may need adjustments
        for other Linux distributions.

    Example:
        install_ssl_certificate_linux('/path/to/certificate.crt')
    """
    import shutil
    import subprocess

    # copy the certificate to the appropriate directory
    cert_fir = '/usr/local/share/ca-certificates/'
    shutil.copy(certificate_path, cert_fir)

    # update the CA certificates store
    subprocess.run(['update-ca-certificates'], check=True)


def install_ssl_certificate_win(certificate_path) -> None:
    """
    Install an SSL certificate to the root store on Windows.

    Args:
        certificate_path (str): Path to the SSL certificate file.

    This function reads the contents of the certificate file, decodes it, and installs
    it to the root certificate store on a Windows system.

    Note:
        This function is specific to Windows and relies on the `win32crypt` library.

    Example:
        install_ssl_certificate('path/to/certificate.crt')
    """
    import win32crypt
    import win32cryptcon

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
