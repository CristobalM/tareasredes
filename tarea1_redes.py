import sys
import socket as libsock
import io
import struct

if len(sys.argv) < 2:
    print('Ingrese puerto')
    exit(1)

hostname = '127.0.0.1'
port = int(sys.argv[1])

RECEIVE_BUF_SIZE = 65500

ASK_DNS_SERVER_HOSTNAME = '8.8.8.8'
ASK_DNS_SERVER_PORT = 53

LOGGING = True


def cond_print(s_msg):
    global LOGGING
    if LOGGING:
        print(s_msg)


def make_dns_query(hostname, port, query):
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    socket.connect((hostname, port))
    cond_print("Emitiendo query a DNS {}:{}...".format(hostname, port))
    socket.send(query)

    return socket


def respond_dns_query_to_user(socket, addr, ans):
    host, port = addr
    cond_print("Respondiendo query a usuario {}:{}...".format(host, port))
    socket.sendto(ans, addr)


def run_server():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket.bind((hostname, port))

    while True:
        cond_print("\n\nEn espera de queries DNS...\n")

        data, address = socket.recvfrom(RECEIVE_BUF_SIZE)

        cond_print("Recibiendo: \n---------------")
        cond_print(data)
        cond_print("---------------\n Recibido OK\n")

        asking_socket = make_dns_query(ASK_DNS_SERVER_HOSTNAME, ASK_DNS_SERVER_PORT, data)
        external_resp_data, external_resp_addr = asking_socket.recvfrom(RECEIVE_BUF_SIZE)

        cond_print("Esperando respuesta de google: \n---------------")
        cond_print("---------------\n Recibida respuesta:\n")
        cond_print(external_resp_data)

        respond_dns_query_to_user(socket, address, external_resp_data)


run_server()