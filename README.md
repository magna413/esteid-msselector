# esteid-msselector

Fetch Estonian eID certificates from SK's public LDAPS directory and render **Microsoft X509 selector strings**.

Example output:

```
X509:<I>C=EE,O=SK ID Solutions AS,OID.2.5.4.97=NTREE-10747013,CN=ESTEID2018<SR>928cc5...
```

---

## 🚀 Installation

### From source

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Directly from GitHub

```bash
pip install git+https://github.com/magna413/esteid-msselector.git
```

---

## 🔧 Usage

### CLI

```bash
esteid-msselector 38001085718
```

### Python Library

```python
from esteid_msselector import EsteidLDAP

client = EsteidLDAP()
try:
    selectors = client.get_ms_strings("38001085718")
    for s in selectors:
        print(s)
finally:
    client.close()
```

---

## 📝 How it works

- Connects to **ldaps://esteid.ldap.sk.ee:636** (SK ID Solutions LDAP directory)  
- Performs anonymous simple bind (`-x`)  
- Searches `c=EE` base with `serialNumber=PNOEE-<idcode>`  
- Prefers `ou=Authentication` entries (ignores `o=Mobile-ID`)  
- Extracts `userCertificate;binary`  
- Parses with `cryptography` to get issuer DN and serial  
- Renders Microsoft selector string with:
  - Issuer DN (OpenSSL-style, raw OIDs preserved)
  - Reversed-hex serial number (`<SR>`)

---

## 📄 License

MIT
