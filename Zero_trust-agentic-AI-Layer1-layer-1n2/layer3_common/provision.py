"""Create persistent local CA, service credentials, and isolated database roles."""
import hashlib
import ipaddress
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVICES = {"pap": "policy_administration_service", "pip": "policy_information_service",
            "pdp": "policy_decision_service", "pep": "access_control_service", "sales": "protected_sales_service",
            "database": "layer3_postgres", "risk_agent": "risk_analyzer"}


def write(path, data, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("ascii"))
    if private:
        path.chmod(0o600)


def provision(root):
    root.mkdir(parents=True, exist_ok=True)
    # Never rotate existing credentials implicitly: that could orphan database data.
    ca_key_path = root / "ca.key"
    if ca_key_path.exists():
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca = x509.load_pem_x509_certificate((root / "ca.crt").read_bytes())
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = None
    if ca is None or ca.not_valid_after_utc < datetime.now(timezone.utc) + timedelta(days=30) or not has_extension(ca, x509.SubjectKeyIdentifier):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local Layer 3 Development CA")])
        now = datetime.now(timezone.utc)
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
              .not_valid_after(now + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
              .sign(ca_key, hashes.SHA256()))
        write(ca_key_path, ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()), True)
        write(root / "ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    tokens = {}
    for service in [*SERVICES, "operator"]:
        path = root / service / "client.key"
        if not path.exists():
            write(path, secrets.token_urlsafe(48), True)
        tokens[service] = path.read_text().strip()
    for service, host in SERVICES.items():
        target = root / service
        write(target / "ca.crt", ca.public_bytes(serialization.Encoding.PEM))
        existing = x509.load_pem_x509_certificate((target / "tls.crt").read_bytes()) if (target / "tls.crt").exists() else None
        if existing is None or existing.not_valid_after_utc < datetime.now(timezone.utc) + timedelta(days=14) or not has_extension(existing, x509.AuthorityKeyIdentifier):
            key = (serialization.load_pem_private_key((target / "tls.key").read_bytes(), password=None)
                   if (target / "tls.key").exists() else ec.generate_private_key(ec.SECP256R1()))
            now = datetime.now(timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                           .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
                           .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                           .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                           .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                           .add_extension(x509.SubjectAlternativeName([x509.DNSName(host), x509.DNSName("localhost"),
                                                                     x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                           .sign(ca_key, hashes.SHA256()))
            write(target / "tls.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()), True)
            write(target / "tls.crt", certificate.public_bytes(serialization.Encoding.PEM))
        write(target / "inbound.json", json.dumps({k: hashlib.sha256(v.encode()).hexdigest() for k, v in tokens.items()}))
        if not (target / "database.key").exists():
            write(target / "database.key", secrets.token_urlsafe(48), True)
    if not (root / "pep" / "evidence.key").exists():
        write(root / "pep" / "evidence.key", Fernet.generate_key(), True)
    sql = []
    for service in ("pap", "pep", "sales"):
        password = (root / service / "database.key").read_text().strip()
        sql.append(f"CREATE ROLE {service} LOGIN PASSWORD '{password}'; CREATE SCHEMA AUTHORIZATION {service};")
        sql.append(f"ALTER ROLE {service} IN DATABASE layer3 SET search_path TO {service}, public;")
        sql.append(f"GRANT CONNECT ON DATABASE layer3 TO {service};")
    sql.append("REVOKE CREATE ON SCHEMA public FROM PUBLIC;")
    write(root / "database" / "init.sql", "\n".join(sql), True)
    write(root / "database" / "pg_hba.conf",
          "local all all trust\nhostnossl all all all reject\nhostssl all all all scram-sha-256\n")
    write(root / "ready", "Layer 3 local security initialized\n")


def has_extension(certificate, extension):
    try:
        certificate.extensions.get_extension_for_class(extension)
        return True
    except x509.ExtensionNotFound:
        return False


if __name__ == "__main__":
    provision(Path(os.getenv("OUTPUT_DIR", "/state")))
