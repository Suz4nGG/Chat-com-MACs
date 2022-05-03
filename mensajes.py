DELIMITADOR = b'\r\n'

"""
mensajes.

Módulo utileria para manejo de mensajes de chat
"""


def quitar_delimitador(mensaje):
    """
    Limpia un mensaje para que no tenga delemitador.

    Keyword Arguments:
    mensaje --
    returns: bytes
    """
    if not mensaje.endswith(DELIMITADOR):
        return mensaje
    return mensaje[:-len(DELIMITADOR)]


def leer_mensaje(socket):
    """
    Permite leer un mensaje de longitud arbitraria, utilizando delimitadores de mensaje.

    Keyword Arguments:
    socket de cliente
    returns: bytes
    """
    chunk = socket.recv(6096)
    mensaje = b''
    while not chunk.endswith(DELIMITADOR):
        mensaje += chunk
        chunk = socket.recv(6096)
    mensaje += chunk
    return quitar_delimitador(mensaje)


def mandar_mensaje(cliente, mensaje, usuario):
    separador = b': '
    mensaje = usuario+separador+mensaje+DELIMITADOR
    cliente.send(mensaje)
