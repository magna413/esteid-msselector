import os
import ldap
import certifi
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .errors import CertificateNotFoundError


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
            issuer = self._issuer_dn_with_oids(cert)
            serial_rev = self._reverse_hex_bytes(f"{cert.serial_number:x}")
            out.append(f"X509:<I>{issuer}<SR>{serial_rev}")
        return out

    def close(self):
        try: self.conn.unbind_s()
        except Exception: pass

