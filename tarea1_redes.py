import sys
import socket as libsock
import copy
import json
import binascii

from console_logging import cond_print

from cache_tarea1 import Cache
from dns_parser import DnsParser
from redirect import Redirect

from server_log import Log

with open('config.json') as json_file:
    config_file = json.load(json_file)
    hostname = config_file['hostname']
    ASK_DNS_SERVER_HOSTNAME = config_file['resolver']
    ASK_DNS_SERVER_PORT = config_file['port']

with open('filtros.json') as json_file:
    filtros_file = json.load(json_file)
    Ban_List = filtros_file['ban']
    Redireccion = filtros_file['redireccion']  # tiene tuplas dentro, hay que iterar

if len(sys.argv) < 2:
    print('Ingrese puerto')
    exit(1)

# hostname = '127.0.0.1'
port = int(sys.argv[1])

RECEIVE_BUF_SIZE = 65500

# ASK_DNS_SERVER_HOSTNAME = '8.8.8.8'
# ASK_DNS_SERVER_PORT = 53

LOGGING = True

tipos_permitidos = ["000f", "0001", "001c"]


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


def url_formatter(string):
    question = string.get_question()
    host_name_nob = question.replace("b", "")  # hostname sin b
    format_host_name = host_name_nob.translate(str.maketrans({"'": None}))
    return format_host_name


def binary_to_hex(data):  # transformar input binario en hexadecimal
    aux = binascii.hexlify(data)
    return aux.decode('utf-8')  # transformar input hexadecimal en binario


def run_server():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket.bind((hostname, port))

    cache = Cache.get()

    while True:
        check = 0  # 0 si se manda respuesta, 1 no manda respuesta
        cond_print("\n\nEn espera de queries DNS...\n")

        data, address = socket.recvfrom(RECEIVE_BUF_SIZE)
        dns_parser_input = DnsParser(data)

        origin_addres = address

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
        user_query = '-'.join([';'.join(map(lambda x: str(x), [qr.question, qr.dns_qtype, qr.dns_qclass]))
                               for qr in dns_parser_input.questions_records]) + '|' + \
                     '-'.join([dns_flags, dns_qdcount, dns_ancount, dns_nscount, dns_arcount])

        host_name = copy.deepcopy(dns_parser_input.questions_records[0])  # variable copiada para trabajar con ella
        string_nombre = url_formatter(host_name)

        # Aqui esta el ciclo para matar a los del filtro
        for baneado in Ban_List:
            if string_nombre == baneado:
                check = 1
            else:
                continue

        # Aqui limitar solo a A, AAAA, MX
        question_type = copy.deepcopy(dns_parser_input.questions_records[0].dns_qtype)
        holi = binary_to_hex(question_type)

        # Aqui van ciclo para cambiar ip


        # aqui hay que ver como manejar la salida
        if check == 0:  #
            if cache.is_saved(user_query):
                cond_print("Respondiendo del cache: \n---------------")

                processed_msg = cache.retrieve_data_with_id(dns_id_int, user_query)
                respond_dns_query_to_user(socket, address, processed_msg)
                cond_print("OK: \n---------------")

                # LOG
                para_procesar = processed_msg
                dns_parser_cache = DnsParser(para_procesar)
                dns_parser_cache.process_msg()
                ip_name = dns_parser_cache.answers_records
                host_name = copy.deepcopy(dns_parser_input.questions_records)
                log_con_cache = Log(host_name, ip_name, address)
                log_con_cache.server_log()
                print("Log con info de cache guardado")

            else:
                raw_question = dns_parser_input.questions_records[0].raw_question if len(dns_parser_input.questions_records) > 0 else ''
                raw_question = '.'.join(map(lambda x: x.decode('utf-8'), raw_question))
                if raw_question in Redireccion:
                    cond_print('redirect question: %s to %s' % (raw_question, Redireccion[raw_question]))
                    redirect = Redirect(dns_parser_input, Redireccion[raw_question])
                    redirect.process()
                    dns_response = redirect.get_dns_parser()
                else:
                    cond_print('Not to redirect question: %s' % raw_question)

                    cond_print("Esperando respuesta de google: \n---------------")
                    asking_socket = make_dns_query(ASK_DNS_SERVER_HOSTNAME, ASK_DNS_SERVER_PORT, data)
                    external_resp_data, external_resp_addr = asking_socket.recvfrom(RECEIVE_BUF_SIZE)
                    cond_print("---------------\n Recibida respuesta:\n")
                    cond_print(external_resp_data)
                    dns_response = DnsParser(external_resp_data)
                    dns_response.process_msg()
                    cond_print("Respondiendo de google: \n---------------")
                processed_msg = dns_response.pack()

                cache.save_data(user_query, dns_response)

                # respond_dns_query_to_user(socket, address, external_resp_data)
                respond_dns_query_to_user(socket, address, processed_msg)
                cond_print("OK: \n---------------")

                # -----------------------------------------------------------------------------------
                # LOG

                host_name = copy.deepcopy(dns_parser_input.questions_records)
                ip_name = copy.deepcopy(dns_response.answers_records)
                log_sin_cache = Log(host_name, ip_name, address[0])
                log_sin_cache.server_log()
                print("Log guardado")


run_server()
