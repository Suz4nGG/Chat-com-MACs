import socket
import threading
import AES_CTR
import sys
import os
import mensajes
import base64
import recupera_hmac


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


def cifrar_mensaje_cliente(mensaje, llave_aes, llave_mac):
    """
        //Se cifran los mensajes que el usuario desee mandar
        * Parámetros:
        & mensaje = texto a enviar STR
        & llave_aes = llave generada aleatoriamente BYTES
        & llave_mac = llve generada aleatoriamente BYTES
    """
    iv = os.urandom(16)
    mensaje = base64.b64encode(mensaje.encode("utf-8"))
    mensaje_cifrado = AES_CTR.cifrar(mensaje, llave_aes, iv)
    # * Calculando la MAC...
    mac = recupera_hmac.devolver_mac(mensaje_cifrado, llave_mac)
    mensaje_cifrado = mensaje_cifrado+mac+iv
    return mensaje_cifrado


def leer_mensajes(cliente):
    """
        //Lectura de mensajes enviados de cliente a cliente
        * Parámetros:
        & cliente = socket SOCKET
    """
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        print(mensaje.decode('utf-8'))


def enviar_mensaje_loop(cliente, usuario):
    """
        // Ciclo de envio de mensajes  de un cliente a los clientes del servidor
        * Parámetros:
        & cliente = socket SOCKET
        & usuario = nombre usuario STR
    """
    # * Generando llaves
    llave_aes = os.urandom(16)
    llave_mac = os.urandom(16)
    # * Envio de datos al servidor para el registro del cliente en cuestión
    cliente.send(b'%b-%b-%b' %
                 (usuario.encode('utf-8'),
                  llave_aes,
                  llave_mac))
    # * Se controlan los mensajes de error del servidor
    mensaje_control = mensajes.leer_mensaje(cliente)
    print(mensaje_control)
    if mensaje_control.startswith(b'exit'):
        print("El usuario ya esta registrado...")
        return
    mensaje = b''
    while True:
        mensaje = input(f'{usuario}: ')
        mensaje = cifrar_mensaje_cliente(mensaje, llave_aes, llave_mac)
        mensajes.mandar_mensaje(cliente, mensaje, usuario.encode('utf-8'))


if __name__ == '__main__':
    host = sys.argv[1]
    puerto = sys.argv[2]
    usuario = sys.argv[3]
    cliente = conectar_servidor(host, puerto)
    hilo = threading.Thread(target=leer_mensajes, args=(cliente,))
    hilo.start()
    enviar_mensaje_loop(cliente, usuario)
