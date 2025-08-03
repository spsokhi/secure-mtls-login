# 🔐 Secure Certificate-Based Login (mTLS)

A secure, passwordless login system using **mutual TLS (mTLS)** and **client certificate authentication** in Python with Flask.

No passwords. No databases. Just cryptography.

---

## 🛠️ How It Works

- Uses a **private Certificate Authority (CA)** to issue client certificates.
- Clients authenticate by presenting a certificate signed by the CA.
- Server verifies the client cert **before allowing access**.
- Built with `Flask`, `cryptography`, and native TLS — no external auth providers.

Perfect for high-security internal tools, zero-trust systems, or learning PKI.

---

## 📦 Features

✅ Certificate-based authentication  
✅ Mutual TLS (mTLS)  
✅ Strong encryption (RSA 2048, SHA-256, TLS 1.3)  
✅ Client `.p12` file for easy browser import  
✅ No passwords, no sessions, no cookies  
✅ Full Python automation

---

## 🚀 Quick Start

### 1. Clone the repo
```
git clone https://github.com/spsokhi/secure-mtls-login.git
cd secure-mtls-login
```
### 2. Install dependencies
```
pip install cryptography flask
```
### 3. Generate certificates
```
python generate_certs.py
```
This creates: 

- ca.crt, ca.key — your Certificate Authority
- client.p12 — import this into your browser
- client.crt, client.key — for CLI testing
  
##  Import Certificates into Browser
- Import the CA Certificate (ca.crt) to Trust the Server:
- Press Win + R, type certmgr.msc, and hit Enter.
- Go to: Trusted Root Certification Authorities > Certificates
- Right-click → All Tasks → Import → Browse to ca.crt
- Finish the wizard (place in Trusted Root Certification Authorities)

## Import the Client Certificate (client.p12):
- Right-click client.p12 → Install PFX
- Choose Local Machine
- Enter password: mypassword
- Store in: Personal (Your Certificates)

### 4. Run the server
```
python app.py
```

### 5. Access the app
Open browser and go to: https://localhost:5000
Import client.p12 (password: mypassword)
When prompted, select the client1 certificate
You're in! 🔐
🔒 Note: Browsers will warn about "Not Secure" — that’s because the CA is self-signed. Proceed anyway or trust ca.crt . 


## 🔐 Trust the CA (Remove Browser Warnings)
- Chrome / Edge (Windows)
  - Open certmgr.msc
  - Go to Trusted Root Certification Authorities > Certificates
  - Import ca.crt
- Firefox
  - Firefox → Settings → Privacy & Security
  - Scroll to Certificates → View Certificates
  - Authorities → Import → Select ca.crt
  - Check: "Trust this CA to identify websites"

 ## 🧪 Test with curl
```
curl -k --cert client.crt --key client.key https://127.0.0.1:5000
```

## 🗂️ Project Structure
```
secure-mtls-login/
│
├── generate_certs.py    # Generates CA and client certs
├── app.py               # Flask server with mTLS
├── client.p12           # Client certificate (import into browser)
├── ca.crt               # CA cert (trust this)
├── server.crt/key       # Server certificate (auto-generated)
└── README.md

```

⚠️ Security Notes
🔐 Never expose ca.key — it can sign new client certificates.
🔄 Use short-lived certs in production.
🛑 This is for education or internal use — not a full IAM solution.
🔒 Run only over HTTPS with CERT_REQUIRED.
