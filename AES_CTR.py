from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def cifrar(mensaje, llave_aes, iv):
    AES_CIPHER = Cipher(algorithms.AES(llave_aes),
                        modes.CTR(iv),
                        backend=default_backend())
    cifrador = AES_CIPHER.encryptor()
    cifrado = cifrador.update(mensaje)
    cifrador.finalize()
    return cifrado


def descifrar(mensaje_cifrado, llave_aes, iv):
    AES_CIPHER = Cipher(algorithms.AES(llave_aes),
                        modes.CTR(iv),
                        backend=default_backend())
    AES_DECRYPTOR = AES_CIPHER.decryptor()
    mensaje_descifrado = AES_DECRYPTOR.update(mensaje_cifrado)
    AES_DECRYPTOR.finalize()
    return mensaje_descifrado
