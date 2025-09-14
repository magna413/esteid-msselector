class EsteidError(Exception):
    """Base class for all esteid-msselector errors."""
    pass


class CertificateNotFoundError(EsteidError):
    """Raised when no certificates are found for a given ID code."""
    pass


class LdapConnectionError(EsteidError):
    """Raised when the LDAP server cannot be reached or queried."""
    pass

