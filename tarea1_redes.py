import sys
import socket as libsock

from console_logging import cond_print

from cache_tarea1 import Cache
from dns_parser import DnsParser

if len(sys.argv) < 2:
    print('Ingrese puerto')
    exit(1)

hostname = '127.0.0.1'
port = int(sys.argv[1])

RECEIVE_BUF_SIZE = 65500

ASK_DNS_SERVER_HOSTNAME = '8.8.8.8'
ASK_DNS_SERVER_PORT = 53

LOGGING = True


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


def bin_to_text(bin_inp, m='08b'):
    return format(bin_inp, m)


def run_server():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket.bind((hostname, port))

    cache = Cache.get()

    while True:
        cond_print("\n\nEn espera de queries DNS...\n")

        data, address = socket.recvfrom(RECEIVE_BUF_SIZE)

        dns_parser_input = DnsParser(data)
        process_msg_state = dns_parser_input.process_msg()
        cond_print("Process Msg State: %s" % str(process_msg_state))
        dns_id = bin_to_text(dns_parser_input.dns_id, '016b')
        dns_flags = bin_to_text(dns_parser_input.dns_flags)
        dns_qdcount = bin_to_text(dns_parser_input.dns_qdcount)
        dns_ancount = bin_to_text(dns_parser_input.dns_ancount)
        dns_nscount = bin_to_text(dns_parser_input.dns_nscount)
        dns_arcount = bin_to_text(dns_parser_input.dns_arcount)

        cond_print("id: %s\nflags: %s\nqdcount: %s\nancount: %s\nnscount: %s\narcount: %s" %
                   (dns_id, dns_flags, dns_qdcount, dns_ancount, dns_nscount, dns_arcount))

        cond_print("---------------\n Recibido OK\n")

        dns_id_int = dns_parser_input.dns_id
        user_query = '-'.join([';'.join([qr.question, qr.dns_qtype, qr.dns_qclass])
                               for qr in dns_parser_input.questions_records]) + '|' + \
                     '-'.join([dns_flags, dns_qdcount, dns_ancount, dns_nscount,dns_arcount])

        if cache.is_saved(user_query):
            cond_print("Respondiendo del cache: \n---------------")

            processed_msg = cache.retrieve_data_with_id(dns_id_int, user_query)
            respond_dns_query_to_user(socket, address, processed_msg)
            cond_print("OK: \n---------------")

        else:
            cond_print("Esperando respuesta de google: \n---------------")
            asking_socket = make_dns_query(ASK_DNS_SERVER_HOSTNAME, ASK_DNS_SERVER_PORT, data)
            external_resp_data, external_resp_addr = asking_socket.recvfrom(RECEIVE_BUF_SIZE)

            cond_print("---------------\n Recibida respuesta:\n")
            cond_print(external_resp_data)

            dns_response = DnsParser(external_resp_data)
            dns_response.process_msg()
            processed_msg = dns_response.pack()

            cache.save_data(user_query, dns_response)
            cond_print("Respondiendo de google: \n---------------")
            # respond_dns_query_to_user(socket, address, external_resp_data)
            respond_dns_query_to_user(socket, address, processed_msg)
            cond_print("OK: \n---------------")




run_server()
