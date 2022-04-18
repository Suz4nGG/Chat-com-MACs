from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


def devolver_mac(mensaje, llave_mac):
    hm = hmac.HMAC(llave_mac,
                   hashes.SHA256(),
                   backend=default_backend()
                   )
    hm.update(mensaje)
    return hm.finalize()
