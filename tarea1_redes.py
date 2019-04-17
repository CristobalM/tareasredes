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


class QuestionParser:
    def __init__(self, reader):
        self.reader = reader
        self.dns_qname = None
        self.dns_qtype = None
        self.dns_qclass = None
        self.sections = []
        self.question = None

    def process(self):
        question = []
        while True:
            try:
                length_oct = self.reader.read(1)
            except Exception:
                return False
            if length_oct == 0:
                break

            try:
                section = self.reader.read(length_oct)
            except Exception:
                return False
            self.sections.append(length_oct)
            self.sections.append(section)
            question.append(section)

        self.dns_qname = ''.join(self.sections)
        self.question = '.'.join(question)

        try:
            self.dns_qtype = self.reader.read(2)
            self.dns_qclass = self.reader.read(2)
        except Exception:
            return False

        return True

    def get_question(self):
        return self.question


class RRParser:
    def __init__(self, reader):
        self.reader = reader
        self.dns_name = None
        self.dns_type = None
        self.dns_class = None
        self.dns_ttl = None
        self.dns_rdlength = None

    def process(self):
        pass


class DnsParser:
    def __init__(self, dnsmsg):
        self.dnsmsg = dnsmsg
        self.dns_id = None
        self.dns_flags = None
        self.dns_qdcount = None
        self.dns_ancount = None
        self.dns_nscount = None
        self.dns_arcount = None

    def process_msg(self):
        reader = io.StringIO(self.dnsmsg)
        header = reader.read(12)

        try:
            self.dns_id, self.dns_flags, self.dns_qdcount,\
            self.dns_ancount, self.dns_nscount, self.dns_arcount = struct.unpack('!HHHHHH', header)



        except Exception:
            return False

        return True


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