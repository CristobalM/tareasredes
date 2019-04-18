import sys
import socket as libsock
import io
import struct
import binascii


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
        self.dns_qname = ''
        while True:
            try:
                (length_oct,) = struct.unpack('B', self.reader.read(1))
            except Exception:
                return False
            if length_oct == 0:
                break

            try:
                section = self.reader.read(length_oct)
            except Exception:
                return False
            self.dns_qname += struct.pack('B', length_oct)
            self.dns_qname += struct.pack('s', section)
            question.append(section)

        self.question = '.'.join(question)
        cond_print("Question size: %d" % len(self.question))

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
        self.answer = None
        self.sections = None
        self.unpacked_answer = None

    def process_name(self, root=True):
        dns_name = ''
        pointer_mask = 0b11000000
        sections = []

        while True:
            try:
                (length_oct,) = struct.unpack('B', self.reader.read(1))
            except Exception:
                return False
            if length_oct == 0:
                break

            try:
                if length_oct & pointer_mask:
                    other_byte = self.reader.read(1)
                    other_byte_u = struct.unpack('B', other_byte)
                    dns_name += struct.pack('B', length_oct) + other_byte
                    offset = ((length_oct & ~pointer_mask) << 8) + other_byte
                    position = self.reader.tell()
                    self.reader.seek(offset)
                    pointer_resolved_result, sections_children = self.process_name(root=False)
                    self.reader.seek(position)
                    sections = sections + sections_children
                    dns_name += pointer_resolved_result

                else:
                    section = self.reader.read(length_oct)
                    dns_name += struct.pack('B', length_oct)
                    dns_name += struct.pack('s', section)
                    sections.append(section)
            except Exception:
                return False

        if root:
            self.dns_name = dns_name
            self.sections = sections
        else:
            return dns_name, sections

    def process_inner(self):
        self.dns_type, self.dns_class, self.dns_ttl, self.dns_rdlength = struct.unpack('!HHIH', self.reader.read(10))

    def process_rdata(self):
        self.answer = self.reader.read(self.dns_rdlength)
        self.unpacked_answer = struct.unpack('B'*self.dns_rdlength, self.answer)

    def process(self):
        cond_print("Processing Name in RR Record")
        self.process_name()
        cond_print("Processing Inner in RR Record")
        self.process_inner()
        cond_print("Processing RDATA in RR Record")
        self.process_rdata()
        cond_print("NAME in RR : %s " % str(self.sections))
        cond_print("NAME in RR ugly: %s " % self.dns_name)
        cond_print("dns_class in RR : %s " % self.dns_class)
        cond_print("dns_ttl in RR : %s " % self.dns_ttl)
        cond_print("dns_rdlength in RR : %s " % self.dns_rdlength)

        cond_print("RData: %s " % self.answer)
        cond_print("unpacked rdata: %s " % str(self.unpacked_answer))



class DnsParser:
    def __init__(self, dnsmsg):
        self.dnsmsg = dnsmsg # dnsmsg.encode(encoding='UTF-8') if isinstance(dnsmsg, str) else dnsmsg

        self.dns_id = None
        self.dns_flags = None
        self.dns_qdcount = None
        self.dns_ancount = None
        self.dns_nscount = None
        self.dns_arcount = None

    def process_msg(self):
        reader = io.BytesIO(self.dnsmsg)
        header = reader.read(12)

        self.dns_id, self.dns_flags, self.dns_qdcount,\
        self.dns_ancount, self.dns_nscount, self.dns_arcount = struct.unpack('!HHHHHH', header)

        questions_records = []
        answers_records = []
        authority_records = []
        additional_records = []

        cond_print("Questions:")
        for i in range(self.dns_qdcount):
            qrecord = QuestionParser(reader)
            questions_records.append(qrecord)
            worked_question = qrecord.process()
            cond_print(qrecord.get_question() if worked_question else 'Question Failed')

        for i in range(self.dns_ancount):
            anrecord = RRParser(reader)
            answers_records.append(anrecord)
            anrecord.process()

        for i in range(self.dns_nscount):
            aurecord = RRParser(reader)
            authority_records.append(aurecord)
            aurecord.process()

        for i in range(self.dns_arcount):
            addirecord = RRParser(reader)
            additional_records.append(addirecord)
            addirecord.process()

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


def bin_to_text(bin_inp, m='08b'):
    return format(bin_inp, m)


def run_server():
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket.bind((hostname, port))

    while True:
        cond_print("\n\nEn espera de queries DNS...\n")

        data, address = socket.recvfrom(RECEIVE_BUF_SIZE)

        dns_parser_input = DnsParser(data)
        process_msg_state = dns_parser_input.process_msg()
        cond_print("Process Msg State: %s" % str(process_msg_state))
        dns_id = bin_to_text(dns_parser_input.dns_id, '016b')
        dns_flags = bin_to_text(dns_parser_input.dns_flags)
        dns_qdcount = dns_parser_input.dns_qdcount
        dns_ancount = dns_parser_input.dns_ancount
        dns_nscount = dns_parser_input.dns_nscount
        dns_arcount = dns_parser_input.dns_arcount

        cond_print("id: %s\nflags: %s\nqdcount: %s\nancount: %s\nnscount: %s\narcount: %s" %
                   (dns_id, dns_flags, dns_qdcount, dns_ancount, dns_nscount, dns_arcount) )

        cond_print("Recibiendo: \n---------------")
        cond_print(data)
        cond_print("---------------\n Recibido OK\n")

        asking_socket = make_dns_query(ASK_DNS_SERVER_HOSTNAME, ASK_DNS_SERVER_PORT, data)
        external_resp_data, external_resp_addr = asking_socket.recvfrom(RECEIVE_BUF_SIZE)

        cond_print("Esperando respuesta de google: \n---------------")
        cond_print("---------------\n Recibida respuesta:\n")
        cond_print(external_resp_data)

        dns_response = DnsParser(external_resp_data)
        dns_response.process_msg()

        respond_dns_query_to_user(socket, address, external_resp_data)



run_server()