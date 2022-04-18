"""
Servidor.

Servidor de un chat. Es una implementación incompleta:
- Falta manejo de exclusión mutua
- Falta poder desconectar de forma limpia clientes
- Falta poder identificar clientes
"""


import socket
import threading
import base64
import sys
import AES_CTR
import mensajes
import recupera_hmac
from collections import namedtuple

Datos_Usuario = namedtuple('Datos_Usuario', 'socket llave_aes llave_mac iv')


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


def broadcast(mensaje, clientes, usuario):
    """
        //Envio de mensajes de un cliente a todos los clientes del servidor
        * Parámetros:
        & mensaje = BYTES
        & clientes = DICC
        & usuario = BYTES
    """
    for cliente in clientes.keys():
        mensajes.mandar_mensaje(clientes[cliente].socket,
                                mensaje,
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


def registrar_usuario(cliente, clientes, mutex, datos_usuario):
    """
        //Registro de nuevos usuarios al servidor
        * Parámetros:
        & cliente = STR
        & clientes = BYTES
        & mutex = MUTEX
        & datos_usuario = TUPLE
    """
    datos = datos_usuario.split(b'-')
    iv = 0
    usuario = datos[0]
    llave_aes = datos[1]
    llave_mac = datos[2]
    # * Verificación de usuario existente en el servidor
    if usuario in clientes.keys():
        print("Usuario ya registrado...", usuario)
        mensajes.mandar_mensaje(cliente, mensaje=b'exit', serv=b'servidor')
    mensajes.mandar_mensaje(
        cliente, mensaje=b'Bienvenido(a) ', usuario=usuario)
    # * Añadiendo las llaves al diccionario, para manejar el intercambio de las llaves almacenadas
    mutex.acquire()
    clientes[usuario] = Datos_Usuario(socket=cliente,
                                      llave_aes=llave_aes,
                                      llave_mac=llave_mac,
                                      iv=iv)
    # * Liberando...
    mutex.release()
    return usuario


def descifrar_mensaje(mensaje_cifrado, llave_aes, llave_mac):
    """
        // Descifrado de mensajes de los clientes en el servidor
        * Parámetros:
        & mensaje_cifrado = BYTES
        & llave_aes = BYTES
        & llave_mac = BYTES
    """
    iv = mensaje_cifrado[-16:]
    mac_recibida = mensaje_cifrado[-48:-16]
    mensaje_cifrado = mensaje_cifrado[:-48]
    # * Recalculando la MAC...
    mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
    if mac != mac_recibida:
        print("[Warning]: El contenido del mensaje posiblemente fue alterado...")
        exit(1)
    mensaje = AES_CTR.descifrar(mensaje_cifrado, llave_aes, iv)
    mensaje = base64.b64decode(mensaje.decode("utf-8"))
    return mensaje


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
        usuario = registrar_usuario(cliente, clientes, mutex, datos_usuario)
    except:
        cliente.close()
        return
    mensaje = b''
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        mensaje = mensaje.split(b': ')[1]
        # * Obtenemos las credenciales almacenadas
        llave_aes_usuario = clientes[usuario].llave_aes
        llave_mac_usuario = clientes[usuario].llave_mac
        # * Desciframos el mensaje
        mensaje_cifrado = descifrar_mensaje(mensaje,
                                            llave_aes_usuario,
                                            llave_mac_usuario)
        if mensaje_cifrado == b'exit':
            eliminar_usuario(usuario, clientes, mutex)
            cliente.close()
        broadcast(mensaje_cifrado, clientes, usuario)


def escuchar(servidor, clientes, mutex):
    servidor.listen(5)
    while True:
        conn, addr = servidor.accept()
        hiloAtencion = threading.Thread(target=administrar_clientes, args=(conn,
                                                                           clientes,
                                                                           mutex))
        hiloAtencion.start()


if __name__ == '__main__':
    servidor = crear_socket_servidor(sys.argv[1])
    print('Escuchando...')
    mutex = threading.Lock()
    clientes = {}
    escuchar(servidor, clientes, mutex)
