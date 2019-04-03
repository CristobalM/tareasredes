
import sys
import socket as libsock

if len(sys.argv) < 2:
    print('Ingrese puerto')
    exit(1)

addr = '127.0.0.1'
port = int(sys.argv[1])

RECEIVE_BUF_SIZE = 1024

def run_client():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket.connect((addr, port))

    socket.send('hola\n'.encode())


run_client()