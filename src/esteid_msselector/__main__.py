# src/esteid_msselector/__main__.py
import sys
from .client import EsteidLDAP
from .errors import CertificateNotFoundError, LdapConnectionError

def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print("Usage: esteid-msselector <ESTONIAN_ID_CODE>", file=sys.stderr)
        return 2  # usage error

    id_code = argv[0].strip()
    client = EsteidLDAP()
    try:
        results = client.get_ms_strings(id_code)
        if not results:
            # Shouldn’t happen if client raises, but keep as guard
            print(f"Error: No certificates found for ID code {id_code}", file=sys.stderr)
            return 1
        for s in results:
            print(s)
        return 0
    except CertificateNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except LdapConnectionError as e:
        print(f"LDAP error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        # last-ditch fallback without a scary traceback
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()

if __name__ == "__main__":
    sys.exit(main())
