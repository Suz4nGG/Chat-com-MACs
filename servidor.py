"""
Servidor.

Servidor de un chat. Es una implementación incompleta:
- Falta manejo de exclusión mutua
- Falta poder desconectar de forma limpia clientes
- Falta poder identificar clientes
"""
from time import sleep
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend

import socket
import threading
import base64
import sys
import AES_CTR
import mensajes
import recupera_hmac
from collections import namedtuple

# ! Almacen de las credenciales que el usuario envía al servidor
Datos_Usuario = namedtuple('Datos_Usuario', 'socket iv')


def crear_socket_servidor(puerto):
    """
        //Creación del socket del servidor
        * Parámetros:
        & puerto = INT
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # hace el bind en cualquier interfaz disponible
    servidor.bind(('127.0.0.1', int(puerto)))
    return servidor


def broadcast(mensaje, clientes, usuario, aes, mac, iv):
    """
        //Envio de mensajes de un cliente a todos los clientes del servidor
        * Parámetros:
        & mensaje = BYTES
        & clientes = DICC
        & usuario = BYTES
    """
    print("AES DEL CLIENTE", aes)
    print("MAC DEL CLIENTE", mac)
    print("IV DEL CLIENTE", iv)
    for cliente in clientes.keys():
        mensaje_cifrado = cifrar_mensaje(mensaje,
                                         aes,
                                         mac,
                                         iv)
        mensajes.mandar_mensaje(clientes[cliente].socket,
                                mensaje_cifrado,
                                usuario)


def eliminar_usuario(usuario, clientes, mutex):
    """
        // Elimina de la lista de clientes al CLIENTE que desee salir del servidor
        * Parámetros:
        & usuario = STR
        & clientes = DICC
        & mutex = MUTEX
    """
    mutex.acquire()
    del clientes[usuario]
    mutex.release()


# todo: Atención de los usuarios en el servidor
def registrar_usuario(cliente, clientes, mutex, datos_usuario):
    """
        //Registro de nuevos usuarios al servidor
        * Parámetros:
        & cliente = STR
        & clientes = BYTES
        & mutex = MUTEX
        & datos_usuario = TUPLE
    """
    datos = datos_usuario.split(b'::')
    usuario = datos[0]
    iv = datos[1]
    # * Verificación de usuario existente en el servidor
    if usuario in clientes.keys():
        print("*****Usuario ya registrado: -", usuario)
        mensajes.mandar_mensaje(cliente,
                                mensaje=b'exit',
                                serv=b'servidor')

    # * Si el usuario no existe se agrega
    print("*****Usuario registrado correctamente en el servidor")
    mensajes.mandar_mensaje(cliente,
                            mensaje=b'Bienvenido (a) ',
                            usuario=usuario)
    # * Añadiendo las llaves al diccionario, para manejar el intercambio de las llaves almacenadas
    mutex.acquire()
    clientes[usuario] = Datos_Usuario(socket=cliente,
                                      iv=iv,
                                      )
    # * Liberando...
    mutex.release()
    return usuario


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
    if mac == mac_recibida:
        mensaje = AES_CTR.descifrar(mensaje_cifrado, llave_aes, iv)
        mensaje = base64.b64decode(mensaje.decode("utf-8"))
        return mensaje
    print("[Warning]: El contenido del mensaje posiblemente fue alterado...")
    exit(1)


def cifrar_mensaje(mensaje, llave_aes, llave_mac, iv):
    """
        //Se cifran los mensajes que el usuario desee mandar
        * Parámetros:
        & mensaje = texto a enviar STR
        & llave_aes = llave generada aleatoriamente BYTES
        & llave_mac = llve generada aleatoriamente BYTES
    """
    print("llave mac", llave_mac)
    mensaje_cifrado = AES_CTR.cifrar(mensaje, llave_aes, iv)
    print("desde el servidor", mensaje_cifrado, "\n")
    # * Calculando la MAC...
    mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
    print("mac desde el sercidor", mac)
    mensaje_cifrado = mensaje_cifrado+mac
    return mensaje_cifrado


# todo: Generando el secreto del servidor
def crear_secreto(dh_cliente_pub, dh_servidor_priv):
    secreto_servidor = dh_servidor_priv.exchange(ec.ECDH(), dh_cliente_pub)
    return secreto_servidor


def derivar_llave(secreto_servidor):
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=16,
                       salt=None,
                       info=b'handshake data',  # tiene que ser lo mismo de los dos lados
                       backend=default_backend()).derive(secreto_servidor)
    return derived_key


# todo: obteniendo las llaves aes y mac que nos mando el servidor
def obtener_llaves(llave_aes, llave_mac):
    return llave_aes, llave_mac


def administrar_clientes(cliente, clientes, mutex):
    """
        //Control de los mensajes y datos de clientes en el servidor
        * Parámetros:
        & cliente = STR
        & clientes = DICC
        & mutex = MUTEX
    """
    # * Recuperando los datos del usuario para su registro
    datos_usuario = cliente.recv(4096)
    try:
        # * Registrando al usuario...
        print("*****Recibiendo datos del usuario...")
        usuario = registrar_usuario(cliente, clientes, mutex, datos_usuario)
        print("*****Enviando llaves y firmas al cliente...")
        llaves_firmas = enviar_llaves_y_firma()
        mensajes.mandar_mensaje(cliente, llaves_firmas, usuario)
    except:
        cliente.close()
        return
    mensaje = b''
    flag = 0
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        llaves.append(mensaje.split(b': ')[0])
        mensaje = mensaje.split(b': ')[1]

        if mensaje.startswith(b'DHPUBCLIENTE'):
            llave_dh_cliente_publica_serializada = mensaje[12:]
            llave_dh_cliente_publica = deserializar_llave(
                llave_dh_cliente_publica_serializada)
            secreto_servidor = crear_secreto(llave_dh_cliente_publica,
                                             llave_dh_servidor_privada)

            llaves.append(derivar_llave(secreto_servidor[:24]))  # * aes
            llaves.append(derivar_llave(secreto_servidor[24:]))  # * mac

        else:
            iv = clientes[usuario].iv
            for llave in llaves:
                if llave == usuario:
                    indice = llaves.index(llave)
                    aes = indice + 1
                    mac = indice + 2
            mensaje_descifrado = descifrar_mensaje(mensaje,
                                                   llaves[aes],
                                                   llaves[mac],
                                                   iv)
            if mensaje_descifrado == b'exit':
                cliente.close()
                print("Byeee")
                return
            print("*************************************")
            print("MENSAJE A MANDAR A TODOS:", mensaje_descifrado)
            broadcast(mensaje_descifrado,
                      clientes,
                      usuario,
                      llaves[aes],
                      llaves[mac],
                      iv)


# todo: Revertir la llave serializada que el cliente mando
def deserializar_llave(llave):
    llave_deserealizada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    return llave_deserealizada


# todo: Serializando las llaves publicas del servidor
def serializar_llaves_publicas(llave_dh_servidor_publica,
                               llave_ec_servidor_publica):
    llave_dh_servidor_publica_serializada = serializar_llave(
        llave_dh_servidor_publica)
    llave_ec_servidor_publica_serializada = serializar_llave(
        llave_ec_servidor_publica)
    return llave_dh_servidor_publica_serializada, llave_ec_servidor_publica_serializada


# todo: Firmando las llaves del servidor
# // Firmando las llaves EC privada y DH pública serializada del servidor
def firmando_llaves_ec_dh_servidor(llave_ec_servidor_privada,
                                   llave_dh_servidor_publica,
                                   llave_ec_servidor_publica):
    # // Serializando las llaves generadas
    llave_dh_servidor_publica_serializada, llave_ec_servidor_publica_serializada = serializar_llaves_publicas(
        llave_dh_servidor_publica,
        llave_ec_servidor_publica)
    firma = llave_ec_servidor_privada.sign(
        llave_dh_servidor_publica_serializada,
        ec.ECDSA(hashes.SHA256()))
    return firma, llave_dh_servidor_publica_serializada, llave_ec_servidor_publica_serializada


# todo: Enviando las llaves y la firma
def enviar_llaves_y_firma():
    firma, llave_dh_servidor_publica_serializada, llave_ec_servidor_publica_serializada = firmando_llaves_ec_dh_servidor(
        llave_ec_servidor_privada,
        llave_dh_servidor_publica,
        llave_ec_servidor_publica)
    llaves_y_firmas = (b'firmas' + llave_dh_servidor_publica_serializada +
                       llave_ec_servidor_publica_serializada + firma)
    return llaves_y_firmas


def escuchar(servidor, clientes, mutex):
    servidor.listen(5)
    while True:
        conn, addr = servidor.accept()
        hiloAtencion = threading.Thread(target=administrar_clientes,
                                        args=(conn, clientes, mutex))
        hiloAtencion.start()


def serializar_llave(llave_servidor):
    llave_servidor_serializada = llave_servidor.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return llave_servidor_serializada


# todo: Generandor de las llaves EC para el servidor
def generar_llaves_ec():
    llave_ec_servidor_privada = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend())
    llave_ec_servidor_publica = llave_ec_servidor_privada.public_key()
    return llave_ec_servidor_privada, llave_ec_servidor_publica


# todo: Generador de las llaves DH para el servidor
def generar_llaves_dh():
    llave_dh_servidor_privada = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend())
    llave_dh_servidor_publica = llave_dh_servidor_privada.public_key()
    return llave_dh_servidor_privada, llave_dh_servidor_publica


if __name__ == '__main__':
    # * Inicializando el servidor...
    servidor = crear_socket_servidor(sys.argv[1])
    print('*****Iniciando el servidor...')
    # * Diccionario para la atención de clientes...
    clientes = {}
    llaves = []
    keys = {'aes': b'', 'mac': b'', 'usuario': b''}
    # * Iniciando mutex...
    mutex = threading.Lock()
    # * Generando llaves DH del servidor
    llave_dh_servidor_privada, llave_dh_servidor_publica = generar_llaves_dh()
    # * Generando llaves EC del servidor
    llave_ec_servidor_privada, llave_ec_servidor_publica = generar_llaves_ec()

    print("*****Escuchando...")
    escuchar(servidor,
             clientes,
             mutex)
