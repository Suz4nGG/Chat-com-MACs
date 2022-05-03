from time import sleep
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
import socket
import threading
import AES_CTR
import sys
import os
import mensajes
import base64
import recupera_hmac


def obtener_llaves(llave_aes, llave_mac):
    return llave_aes, llave_mac


def conectar_servidor(host, puerto):
    """
        // Definiendo el socket del cliente
        * Parámetros:
        & host = dirección IP STR
        & puerto = puerto valido INT
    """
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()


# def cifrar_mensaje_cliente(mensaje, llave_aes, llave_mac, iv):
#     """
#         //Se cifran los mensajes que el usuario desee mandar
#         * Parámetros:
#         & mensaje = texto a enviar STR
#         & llave_aes = llave generada aleatoriamente BYTES
#         & llave_mac = llve generada aleatoriamente BYTES
#     """
#     mensaje = base64.b64encode(mensaje.encode("utf-8"))
#     mensaje_cifrado = AES_CTR.cifrar(mensaje, llave_aes, iv)
#     # print("SOLO EL MENSAJE EN CIFRADO", mensaje_cifrado, "\n")
#     # * Calculando la MAC...
#     mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
#     # print("MAC QUE SE MANDA", mac, "\n")
#     mensaje_cifrado = mensaje_cifrado+mac
#     print("\n")
#     print("TODOOOOOO EL MENSAJE CIFRADO", mensaje_cifrado, "\n")
#     return mensaje_cifrado

def cifrar_mensaje(mensaje, llave_aes, llave_mac):
    """
        //Se cifran los mensajes que el usuario desee mandar
        * Parámetros:
        & mensaje = texto a enviar STR
        & llave_aes = llave generada aleatoriamente BYTES
        & llave_mac = llve generada aleatoriamente BYTES
    """
    mensaje = base64.b64encode(mensaje.encode("utf-8"))
    mensaje_cifrado = AES_CTR.cifrar(mensaje, llave_aes, iv)
    # * Calculando la MAC...
    mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
    mensaje_cifrado = mensaje_cifrado+mac
    return mensaje_cifrado

# def descifrar_mensaje(mensaje_cifrado, llave_aes, llave_mac, iv):
#     """
#         // Descifrado de mensajes de los clientes en el servidor
#         * Parámetros:
#         & mensaje_cifrado = BYTES
#         & llave_aes = BYTES
#         & llave_mac = BYTES
#     """
#     print("LLAVE MAC", llave_mac)
#     print("TODO EL MENSAJE CIFRADO", mensaje_cifrado, "\n")
#     mac_recibida = mensaje_cifrado[-32:]
#     print("MAC RECIBIDA", mac_recibida, "\n")
#     mensaje_cifrado = mensaje_cifrado[:-32]
#     print("FUNCIÓN DESCIFRADO", mensaje_cifrado, "\n")
#     # * Recalculando la MAC...
#     # print("******LLVEMAC", llave_mac)
#     mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
#     print("MAC DEL CLIENTE:::", mac, "\n")
#     if mac != mac_recibida:
#         print("[Warning]: El contenido del mensaje posiblemente fue alterado...")
#         return
#     mensaje = AES_CTR.descifrar(mensaje_cifrado, llave_aes, iv)
#     # mensaje = base64.b64decode(mensaje.decode("utf-8"))
#     return mensaje


def descifrar_mensaje(mensaje_cifrado, llave_aes, llave_mac, iv):
    """
        // Descifrado de mensajes de los clientes en el servidor
        * Parámetros:
        & mensaje_cifrado = BYTES
        & llave_aes = BYTES
        & llave_mac = BYTES
    """
    mac_recibida = mensaje_cifrado[-32:]
    mensaje_cifrado = mensaje_cifrado[:-32]
    # * Recalculando la MAC...
    mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
    print( b'----->MAC:' + mac )
    print( b'----->MAC RECIBIDA:' + mac_recibida )
    if mac == mac_recibida:
        mensaje = AES_CTR.descifrar(mensaje_cifrado, llave_aes, iv)
        print( b'MENSAJE:' + mensaje )
        # mensaje = base64.b64decode(mensaje.decode("utf-8"))
        return mensaje
    print("[Warning]: El contenido del mensaje posiblemente fue alterado...")
    exit(1)


def deserealizar_llave(llave):
    llave_deserealizada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    return llave_deserealizada


def crear_secreto(dh_servidor_pub, dh_cliente_priv):
    secreto_emisor = dh_cliente_priv.exchange(ec.ECDH(), dh_servidor_pub)
    return secreto_emisor


def derivar_llave(secreto_emisor):
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=16,
                       salt=None,
                       info=b'handshake data',  # tiene que ser lo mismo de los dos lados
                       backend=default_backend()).derive(secreto_emisor)
    return derived_key


def verificar_firma(ec_servidor_pub, signature, dh_servidor_pub_S):
    try:
        ec_servidor_pub.verify(signature,
                               dh_servidor_pub_S,
                               ec.ECDSA(hashes.SHA256()))
        print('**LA FIRMA ES VALIDA**', "\n")
    except:
        print('**LA FIRMA NO ES VALIDA**', "\n")
        exit()


# todo: obteniendo las llaves aes y mac que nos mando el servidor
def leer_mensajes(cliente, llave_dh_cliente_privada):
    """
        //Lectura de mensajes enviados de cliente a cliente
        * Parámetros:
        & cliente = socket SOCKET
    """
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        mensaje = mensaje.split(b': ')[1]
        if mensaje.startswith(b'firmas'):
            firmas = mensaje[6:]
            llave_dh_servidor_publica_serializada = firmas[:215]
            llave_ec_servidor_publica_serializada = firmas[215:430]
            firma = firmas[430:]
            llave_ec_servidor_publica = deserealizar_llave(
                llave_ec_servidor_publica_serializada)
            # * Verificamos la FIRMA
            verificar_firma(llave_ec_servidor_publica,
                            firma,
                            llave_dh_servidor_publica_serializada)
            llave_dh_servidor_publica = deserealizar_llave(
                llave_dh_servidor_publica_serializada)
            secreto_cliente = crear_secreto(llave_dh_servidor_publica,
                                            llave_dh_cliente_privada)
            llaves.append(derivar_llave(secreto_cliente[:24]))  # * aes
            llaves.append(derivar_llave(secreto_cliente[24:]))  # * mac
        else:
            if llaves:
                mensaje = descifrar_mensaje(mensaje,
                                            llaves[0],
                                            llaves[1],
                                            iv)
                print(">::", mensaje, "\n")


def enviar_mensaje_loop(cliente, usuario, llave_dh_cliente_publica):
    """
        // Ciclo de envio de mensajes  de un cliente a los clientes del servidor
        * Parámetros:
        & cliente = socket SOCKET
        & usuario = nombre usuario STR
    """
    # * Envio de datos al servidor para el registro del cliente
    print("*****Los datos del cliente han sido enviados al servidor")
    cliente.send(b'%b::%b' %
                 (usuario.encode('utf-8'),
                  iv))
    # // Serializando la llave DH del cliente
    llave_serializada = serializar_llave(llave_dh_cliente_publica)
    llave_dh_cliente_publica_serializada = b'DHPUBCLIENTE' + llave_serializada
    # ! Mandamos la llave DH pública del cliente al servidor
    mensajes.mandar_mensaje(cliente,
                            llave_dh_cliente_publica_serializada,
                            usuario.encode('utf-8'))
    # // Inicia el loop de envio de mensajes
    mensaje = b''
    while mensaje.strip() != b'exit':
        mensaje = input(f'{usuario}: ')
        # * Se cifra el mensaje del cliente
        mensaje = cifrar_mensaje(mensaje, llaves[0], llaves[1])
        # * Se manda el mensaje ya con la MAC
        mensajes.mandar_mensaje(cliente, mensaje, usuario.encode('utf-8'))


# todo: LLAVES DH
def generar_diffie_hellman():
    llave_dh_cliente_privada = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend())
    # ! Esta es la que se tiene que intercambiar
    llave_dh_cliente_publica = llave_dh_cliente_privada.public_key()
    return llave_dh_cliente_privada, llave_dh_cliente_publica


# todo: Serialización de las llaves
def serializar_llave(llave_cliente):
    llave_cliente_serializada = llave_cliente.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return llave_cliente_serializada


if __name__ == '__main__':
    # * Pasando parámetros
    host = sys.argv[1]
    puerto = sys.argv[2]
    usuario = sys.argv[3]
    llaves = []
    # * Generando iv
    iv = os.urandom(16)
    # * Iniciando conexión con el servidor
    cliente = conectar_servidor(host, puerto)
    # // Generando la llave DF
    llave_dh_cliente_privada, llave_dh_cliente_publica = generar_diffie_hellman()
    # ? Ejecución del hilo principal
    hilo = threading.Thread(target=leer_mensajes,
                            args=(cliente,
                                  llave_dh_cliente_privada))
    hilo.start()
    # * Ciclo de envio de mensajes
    enviar_mensaje_loop(cliente,
                        usuario,
                        llave_dh_cliente_publica)
