from flask import Flask, request, render_template_string
import ssl
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head><title>Secure Login</title></head>
<body>
    <h2>🔐 Secure Dashboard</h2>
    <p>Hello <strong>{{ cn }}</strong>, you are authenticated via certificate!</p>
    <p><em>Organization: {{ org }}</em></p>
    <form action="/logout" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
'''

@app.before_request
def require_client_cert():
    cert_pem = request.environ.get('SSL_CLIENT_CERT')
    if not cert_pem:
        return "❌ No client certificate provided.", 401
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        now = datetime.datetime.now(datetime.timezone.utc)
        if cert.not_valid_after_utc < now:
            return "❌ Certificate expired.", 403
        subject = cert.subject
        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        request.user_info = {'cn': cn, 'org': org}
    except Exception as e:
        return f"❌ Certificate validation failed: {str(e)}", 403

@app.route('/')
def index():
    user = request.user_info
    return render_template_string(LOGIN_PAGE, cn=user['cn'], org=user['org'])

@app.route('/logout', methods=['POST'])
def logout():
    return "👋 Logged out. Close browser to end session.", 200


def load_ca_private_key():
    with open('ca.key', 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


if __name__ == '__main__':
    ca_cert = 'ca.crt'
    server_crt = 'server.crt'
    server_key = 'server.key'

    if not (os.path.exists(server_crt) and os.path.exists(server_key)):
        print("⚙️ Generating server certificate...")
        ca_private_key = load_ca_private_key()
        now = datetime.datetime.now(datetime.timezone.utc)
        server_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_cert = x509.CertificateBuilder() \
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])) \
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "My CA")])) \
            .public_key(server_key_obj.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(now + datetime.timedelta(days=180)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("127.0.0.1")]), critical=False) \
            .sign(ca_private_key, hashes.SHA256())
        with open(server_crt, "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))
        with open(server_key, "wb") as f:
            f.write(server_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("✅ Server certificate generated.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_cert)
    context.load_cert_chain(certfile=server_crt, keyfile=server_key)

    print("🚀 Visit https://127.0.0.1:5000")
    app.run(ssl_context=context, host='127.0.0.1', port=5000, debug=False)
