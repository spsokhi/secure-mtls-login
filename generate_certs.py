from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def save_key(key, filename, password=None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        ))

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# === Step 1: Create Certificate Authority (CA) ===
ca_key = generate_private_key()
ca_subject = ca_issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "My CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureOrg"),
])

ca_cert = x509.CertificateBuilder() \
    .subject_name(ca_subject) \
    .issuer_name(ca_issuer) \
    .public_key(ca_key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc)) \
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)) \
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True) \
    .add_extension(x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False
    ), critical=True) \
    .sign(ca_key, hashes.SHA256())

save_key(ca_key, "ca.key")
save_cert(ca_cert, "ca.crt")
print("✅ CA Key and Certificate generated: ca.key, ca.crt")

# === Step 2: Generate Client Certificate ===
client_key = generate_private_key()
client_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "client1"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Users"),
])

client_cert = x509.CertificateBuilder() \
    .subject_name(client_subject) \
    .issuer_name(ca_subject) \
    .public_key(client_key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc)) \
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=180)) \
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=True,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False
    ), critical=True) \
    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False) \
    .sign(ca_key, hashes.SHA256())

save_key(client_key, "client.key")
save_cert(client_cert, "client.crt")
print("✅ Client Key and Certificate generated: client.key, client.crt")

# === Export Client Certificate as PKCS#12 ===
from cryptography.hazmat.primitives.serialization import pkcs12
import datetime

pkcs12_data = pkcs12.serialize_key_and_certificates(
    name=b"client1",
    key=client_key,
    cert=client_cert,
    cas=[ca_cert],
    encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
)

with open("client.p12", "wb") as f:
    f.write(pkcs12_data)

print("✅ Client PKCS#12 file created: client.p12 (password: mypassword)")
