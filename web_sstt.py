# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors    #https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging
from urllib import request, response      # Para imprimir logs


BUFSIZE = 8192 # Tamaño máximo del buffer que se puede utilizar -> No tocar
TIMEOUT_CONNECTION = 20 # Timout para la conexión persistente 
MAX_ACCESOS = 10

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
            "html":"text/html", "css":"text/css", "js":"text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    n = cs.send(data)
    print('Bytes enviados:', n)
    return n

def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    mensaje = cs.recv(BUFSIZE)
    d = mensaje.decode()
    return d


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()


def process_cookies(headers):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    if 'Cookie' in headers:
        patron_cookie = r'cookie_counter=(\d{1})'
        er_cookie = re.compile(patron_cookie)
        result = er_cookie.fullmatch(headers['Cookie'])
        if result:
            a = result.group(1)
            n = int(a)
            if n == MAX_ACCESOS:
                return MAX_ACCESOS
            elif n <= MAX_ACCESOS and n >=1:
                return n+1
    return 1

# libreria ospath 
def process_web_request(cs, webroot):
    running = True
    inputs = [cs]
    cookie = ''

    while running:

        print('waiting for the next event')
        rsublist, wsublist, xsublist = select.select(inputs, [], [], TIMEOUT_CONNECTION)

        # Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
        if (rsublist):
            
            # Leer los datos con recv
            request_i = recibir_mensaje(cs)

            http_lines = request_i.split('\r\n')
            
            if ' ' in http_lines[0]:
                print('ENTRA')
                try:
                    method, resource, version = http_lines[0].split(' ', 2)

                    request = {'method': method,
                            'resource': resource,
                            'version': version}

                    # Devuelve el resto de parámetros de las cabeceras
                    headers = {}
                    for line in http_lines[1:-4]:
                        key, value = line.split(': ', 2)
                        headers[key] = value
                                
                    # Comprueba versión de HTTP
                        
                    if (request['version'] != 'HTTP/1.1'):
                        state_line = 'HTTP/1.1 505 HTTP Version Not Supported'
                        resource = '/505.html'
                        # Comprobar si es un método GET. Si no devolver un error  # ? Error 405 "Method Not Allowed".
                    else:
                        if (request['method'] != 'GET'):
                            state_line = "HTTP/1.1 405 METHOD NOT ALLOWED \r\n"
                            resource = '/405.html'
                            print('Metodo desconocido')
                        else:
                            # Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                            if (request['resource'] == '/'):
                                resource = '/index.html'
                            else:
                                resource = request['resource']

                            # Leer URL y eliminar parámetros si los hubiera
                            print(resource)

                            # Comprobar que el recurso (fichero) existe, si no devolver # ? Error 404 "Not found"
                            if not (os.path.isfile(webroot+resource)):
                                state_line = "HTTP/1.1 404 NOT FOUND \r\n"
                                resource = '/404.html'
                                        
                            # Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                            #   el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                            #   Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                                    
                            else:
                                cookie_value = process_cookies(headers)

                                if cookie_value < MAX_ACCESOS:
                                    state_line = "HTTP/1.1 200 OK\r\n"
                                    cookie = "Set-Cookie: cookie_counter={0}; Max-Age=120\r\n".format(cookie_value)
                                else:
                                    state_line = "HTTP/1.1 403 FORBIDDEN\r\n"
                                    resource = '/403.html'
                except:
                    state_line = "HTTP/1.1 400 Bad Request"
                    resource = '/400.html'
                    
                    
                # Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                absolute_path = webroot + resource
                print('Ruta absoluta: ' + absolute_path)

                # Obtener el tamaño del recurso en bytes.
                size = os.stat(absolute_path).st_size

                # Extraer extensión para obtener el tipo de archivo. -> Se extrae mediante una er
                patron_extension = r'.+\.(.+)'
                er_extension = re.compile(patron_extension)

                result = er_extension.fullmatch(os.path.basename(absolute_path))
                extension = filetypes[result.group(1)]

                # Respuesta
                response_msg = \
                    "{0}" \
                    "Server: Mi Servidor\r\n"\
                    "Content-Type: {1}\r\n"\
                    "Content-Length: {2}\r\n"\
                    "Date: {3}\r\n"\
                    "Connection: Keep-Alive\r\n"\
                    "Keep-Alive: timeout=10\r\n"\
                    "{4}"\
                    "\r\n"\
                    .format(state_line, extension, size, datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'), cookie)

                print(response_msg)

                a = response_msg.encode()
                enviar_mensaje(cs, a)

                # Se lee y se envía el fichero
                with open(absolute_path, 'rb') as f:
                    msg = f.read(BUFSIZE)
                    while (msg):
                        if msg != '':
                            enviar_mensaje(cs, msg)
                        msg = f.read(BUFSIZE)

            else:
                running = False
            
        else:
            print('Time Out')
            running = False
            cerrar_conexion(cs)



def main():
    """ Función principal del servidor
    """

    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()

        # Activa mensajes de loggin con -v
        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        # webroot -> directorio raiz de la maquina servidor -> PATH respecto al webroot
        logger.info("Serving files from {}".format(args.webroot))

        # Funcionalidad a realizar
        # Crea un socket TCP (SOCK_STREAM)
        server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)

        # Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Vinculamos el socket a una IP y puerto elegidos
        server.bind((args.host, args.port))

        # Escucha conexiones entrantes
        server.listen()

        # Bucle infinito para mantener el servidor activo indefinidamente
        while True:
            # - Aceptamos la conexión
            cs, addr = server.accept()
            print('Conexion aceptada')

            # - Creamos un proceso hijo
            pid = os.fork()

            if pid == 0:
                print('Proceso hijo')
                server.close()
                process_web_request(cs, args.webroot)
                print('Proceso hijo termina')
                sys.exit()

            else:
                cs.close()                

    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
