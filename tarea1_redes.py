import sys
import socket as libsock
import io
import struct
import binascii

# A= 1
# MX=15
# AAAA=28
# mx rdata format
# preference= 16 bits
# exchange= domain name/answer
# 2 char es un byte
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

    def process(self):
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

        # self.dns_qname = '.'.join(self.sections)
        self.dns_qname = ''.join(self.sections)

        try:
            self.dns_qtype = self.reader.read(2)

            self.dns_qclass = self.reader.read(2)
        except Exception:
            return False

        return True


class RRParser:
    def __init__(self, reader):
        self.hqParser = DnsParser(reader)  # instancia de la otra clase

        self.dns_name = None
        self.dns_type = None
        self.dns_class = None
        self.dns_ttl = None
        self.dns_rdlength = None
        self.dns_answer = None
        self.dns_preference = None
        self.dns_exchange = None

    def process_msg(self, send_data):
        respuestas = []  # almacenar las tuplas de respuestas

        i = 0  # posicion desde donde comienza pregunta
        k = 0
        cnt = 0  # contador de bytes para moverse en los ciclos
        (self.hqParser.process_msg_send())
        countAnsw = self.hqParser.dns_ancount  # cantidad de respuestas en str
        countAnsw_num = int(countAnsw, 16)
        solo_preguntas = self.hqParser.Rest
        self.dns_name = solo_preguntas[0:4]

        # aqui deberia empezar el ciclo, hay que diferenciar si son A, AAAA o MX

        check = binary_to_hex(send_data)  # data recibida en binario

        if self.dns_name[:2] == "c0":  # checkeo offset
            decimal = int(self.dns_name[2:4], 16)
            i = decimal * 2  # contador para data original
            k = i - 24  # contador para data recibida
            if self.hqParser.Qname[k] == check[i] and self.hqParser.Qname[k + 1] == check[i + 1]:
                print("")
                # continue
            else:  # en caso de que las cosas no funquen
                print("no concuerdan las cosas")
                pass

        self.dns_type = solo_preguntas[4:8]
        print(self.dns_type)
        self.dns_class = solo_preguntas[8:12]
        self.dns_ttl = solo_preguntas[12:20]
        self.dns_rdlength = solo_preguntas[20:24]  # muestra tambien el largo total de preference + exchange in mx
        largo_respuesta = int(self.dns_rdlength, 16)

        if self.dns_type == "0001" or self.dns_type == "001c":  # para analizar ipv4, ipv6
            self.dns_answer = solo_preguntas[24:24 + largo_respuesta]
            respuestas.append(
                [self.dns_name, self.dns_type, self.dns_class, self.dns_ttl, self.dns_rdlength, self.dns_answer])
        if self.dns_type == "000f":  # si es mail
            self.dns_preference = solo_preguntas[24:28]
            self.dns_exchange = solo_preguntas[28:28 + largo_respuesta - 4]
            respuestas.append(
                [self.dns_name, self.dns_type, self.dns_class, self.dns_ttl, self.dns_rdlength, self.dns_preference,
                 self.dns_exchange])
            self.dns_answer = self.dns_preference + self.dns_exchange  # en caso de ser necesario se concatenan en un solo string
        print(respuestas)


        # verificar cantidad de respuestas, para ver el ciclo
        # maybe guardar cada respuesta como un arreglo



        # verificar que el offset esta apuntando a la posicion correcta
        # verificar el tipo de mensaje pedido, A=0001, AAAA=001c MX=000f, si no se pasa


class DnsParser:
    def __init__(self, dnsmsg):
        self.dnsmsg = dnsmsg  # mensaje en binario
        self.dns_id = None  # id del mensaje
        self.dns_flags = None  # flags
        self.dns_qdcount = None  # cantidad de preguntas
        self.dns_ancount = None  # cantidad de respuestas
        self.dns_nscount = None  # authority records
        self.dns_arcount = None  # aditional records
        self.Qname = None  # nombre del dominio a preguntar
        self.Qtype = None  # tipo del dominio preguntado
        self.Qclass = None
        self.Rest = None
        self.Query_pos = None

    def process_msg_send(self):
        dnsmessage = (binary_to_hex(self.dnsmsg))  # convierte binary data a octetos
        print(dnsmessage)
        # header
        self.dns_id = dnsmessage[:4]
        self.dns_flags = dnsmessage[4:8]
        self.dns_qdcount = dnsmessage[8:12]
        self.dns_ancount = dnsmessage[12:16]
        self.dns_nscount = dnsmessage[16:20]
        self.dns_arcount = dnsmessage[20:24]
        header = self.dns_id + self.dns_flags + self.dns_qdcount + self.dns_ancount + self.dns_nscount + self.dns_arcount  # junta todo el heder
        # question
        i = 24
        question = []
        while True:
            par = dnsmessage[i] + dnsmessage[i + 1]

            question.append(par)
            if par == "00":
                break
            i += 2
        self.Qname = ''.join(question)

        self.Qtype = dnsmessage[i + 2:i + 6]
        self.Qclass = dnsmessage[i + 6:i + 10]
        Question = self.Qname + self.Qtype + self.Qclass  # junta toda la question

        # todo lo que viene despues de las dos primeras partes
        # la idea es usar esta misma funcion para parsear la primera parte de la respuesta
        self.Rest = dnsmessage[i + 10:]


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


def binary_to_hex(data):  # transformar input binario en hexadecimal
    aux = binascii.hexlify(data)
    return aux.decode('utf-8')  # transformar input hexadecimal en binario


def hex_to_binary(data):
    aux = binascii.unhexlify(data)
    return aux


def run_server():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket.bind((hostname, port))

    while True:
        cond_print("\n\nEn espera de queries DNS...\n")

        data, address = socket.recvfrom(RECEIVE_BUF_SIZE)
        parserSend = DnsParser(data)
        parserSend.process_msg_send()
        cond_print("Recibiendo: \n---------------")

        cond_print(data)

        cond_print("---------------\n Recibido OK\n")

        asking_socket = make_dns_query(ASK_DNS_SERVER_HOSTNAME, ASK_DNS_SERVER_PORT, data)
        external_resp_data, external_resp_addr = asking_socket.recvfrom(RECEIVE_BUF_SIZE)
        parserRCV = RRParser(external_resp_data)

        parserRCV.process_msg(data)

        cond_print("Esperando respuesta de google: \n---------------")
        cond_print("---------------\n Recibida respuesta:\n")
        cond_print(external_resp_data)

        respond_dns_query_to_user(socket, address, external_resp_data)


run_server()
