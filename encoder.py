import sys

import click
import hashlib

from lxml import etree

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils, padding


@click.command()
@click.option("--pk", help="private key pem")
@click.option("--xml", help="xml soap message")
def sign(pk, xml):
    pk_bytes = None
    request: etree.Element = None
    soap_body = None

    try:
        with open(pk, "r") as pk_file:
            pk_bytes = pk_file.read()
            if "-----BEGIN PRIVATE KEY-----" not in pk_bytes:
                raise RuntimeError("invalid pk file")
    except FileNotFoundError:
        print("pk file not found")
        sys.exit(1)
    else:
        print("pk ok")
        pk_bytes = bytes(pk_bytes.encode("utf-8"))

    try:
        with open(xml, "r") as xml_file:
            request = xml_file.read()
    except FileNotFoundError:
        print("request file not found")
        sys.exit(1)
    else:
        print("request ok")
        request = etree.XML(request)
        soap_body = request.find(
            "soap:Body", namespaces={"soap": "http://schemas.xmlsoap.org/soap/envelope/"}
        )

    hasher = hashlib.sha256()
    hasher.update(etree.tostring(soap_body))
    soap_raw_digest = hasher.digest()

    key = serialization.load_pem_private_key(pk_bytes, password=None)

    signature = key.sign(
        soap_raw_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.MGF1.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("--- HEX DIGEST ---")
    print(hasher.hexdigest())
    print("--- SIGNATURE ---")
    print(signature.hex())


if __name__ == "__main__":
    sign()
