import os
import ldap
import certifi
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .errors import CertificateNotFoundError
from cryptography.hazmat.primitives import hashes, serialization
from .errors import LdapConnectionError
from asn1crypto import keys



class EsteidLDAP:
    """Fetch Estonian eID certs and render Microsoft X509 selector strings."""

    LDAP_URI = "ldaps://esteid.ldap.sk.ee:636"
    BASE_DN = "c=EE"
    ATTRS = ["userCertificate;binary"]

    def __init__(self):
        os.environ.setdefault("LDAPTLS_CACERT", certifi.where())
        self.conn = ldap.initialize(self.LDAP_URI)
        self.conn.protocol_version = 3
        self.conn.set_option(ldap.OPT_REFERRALS, 0)
        try:
            self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            self.conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        except ValueError:
            pass
        self.conn.simple_bind_s("", "")

    @staticmethod
    def _reverse_hex_bytes(h: str) -> str:
        h = h.lower().lstrip("0x")
        if len(h) % 2: h = "0" + h
        return "".join([h[i:i+2] for i in range(0, len(h), 2)][::-1])

    @staticmethod
    def _issuer_dn_with_oids(cert: x509.Certificate) -> str:
        parts = []
        for rdn in cert.issuer.rdns:
            for attr in rdn:
                oid = attr.oid.dotted_string
                val = attr.value
                if oid == "2.5.4.6":
                    parts.append(f"C={val}")
                elif oid == "2.5.4.10":
                    parts.append(f"O={val}")
                elif oid == "2.5.4.3":
                    parts.append(f"CN={val}")
                else:
                    parts.append(f"OID.{oid}={val}")
        return ",".join(parts)

    @staticmethod
    def _prefer_auth(results):
        auth, rest = [], []
        for dn, entry in results:
            if not entry: continue
            dl = dn.lower()
            (auth if ("ou=authentication" in dl and "o=mobile-id" not in dl) else rest).append((dn, entry))
        return auth if auth else results
    
    def _IssuerAndSubject(self, cert: x509.Certificate) -> str:
        issuer = self._issuer_dn_with_oids(cert)
        serial_rev = self._reverse_hex_bytes(f"{cert.serial_number:x}")
        return f"X509:<I>{issuer}<SR>{serial_rev}"

    def _SHA1PublicKey(self, cert: x509.Certificate) -> str:
        """SHA1 of SubjectPublicKeyInfo (DER)."""
        spki = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        h = hashes.Hash(hashes.SHA1())
        h.update(spki)
        return f"X509:<SHA1-PUKEY>{h.finalize().hex()}"
    
    """SKI"""
    def _SubjectKeyIdentifier(self, cert: x509.Certificate) -> str:
        """SKI from extension if present; else SHA1 of subjectPublicKey BIT STRING."""
        try:
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            return f"X509:<SKI>{ski.value.digest.hex()}"
        except x509.ExtensionNotFound:
            # Compute RFC 5280 Method 1: SHA1 over the subjectPublicKey BIT STRING (not whole SPKI)
            spki = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Parse out the BIT STRING: simple approach—load as public key and re-encode the raw key bits where available.
            # cryptography doesn’t expose the bit string directly, but RFC method is equivalent for most CAs to SKI extension.
            # Practical fallback: hash the BIT STRING by stripping the SPKI header.
            # Minimal DER walk:
              # if you prefer no extra dep, keep extension-first approach above
            spki_parsed = keys.PublicKeyInfo.load(spki)
            key_bytes = spki_parsed["public_key"].native  # bytes of the BIT STRING
            h = hashes.Hash(hashes.SHA1())
            h.update(key_bytes)
            return f"X509:<SKI>{h.finalize().hex()}"

    def get_ms_strings(self, id_code: str) -> List[str]:
        search_filter = f"(serialNumber=PNOEE-{id_code})"
        results = self.conn.search_s(self.BASE_DN, ldap.SCOPE_SUBTREE, search_filter, self.ATTRS)
        if not results:
            raise CertificateNotFoundError(f"No certificates found for ID code {id_code}")

        dn, entry = self._prefer_auth(results)[0]
        certs = entry.get("userCertificate;binary", [])
        if not certs:
            raise CertificateNotFoundError(f"No userCertificate;binary in LDAP entry for {id_code}")

        out: List[str] = []
        for der in certs:
            cert = x509.load_der_x509_certificate(der, default_backend())
            issuer_and_subject = self._IssuerAndSubject(cert)
            sha1_pubkey = self._SHA1PublicKey(cert)
            subject_key_id = self._SubjectKeyIdentifier(cert)
            out.append(f"{'SHA1PublicKey':<22}{sha1_pubkey}")
            out.append(f"{'SubjectKeyIdentifier':<22}{subject_key_id}")
            out.append(f"{'IssuerAndSubject':<22}{issuer_and_subject}")

        return out

    def close(self):
        try: self.conn.unbind_s()
        except Exception: pass

