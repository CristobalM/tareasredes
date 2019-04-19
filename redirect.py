import copy
import struct
import binascii

from dns_parser import DnsParser
from rr_parser import RRParser
from console_logging import cond_print

class Redirect:
    def __init__(self, dnsparser, redirect_to):
        self.dnsparser = copy.deepcopy(dnsparser)
        self.redirect_to = redirect_to

    def process(self):
        self.dnsparser.dns_qdcount = 0
        cond_print('DNS FLAGS:')
        cond_print(type(self.dnsparser.dns_flags))
        cond_print(bin(self.dnsparser.dns_flags))
        self.dnsparser.dns_flags = self.dnsparser.dns_flags + (1<<15)
        cond_print(bin(self.dnsparser.dns_flags))


        name_q = self.dnsparser.questions_records[0].dns_qname
        type_q = self.dnsparser.questions_records[0].dns_qtype
        class_q = self.dnsparser.questions_records[0].dns_qclass
        self.dnsparser.questions_records.clear()
        self.dnsparser.dns_ancount = 1
        self.dnsparser.answers_records.clear()
        arec = RRParser()
        self.dnsparser.answers_records.append(arec)
        arec.dns_name = name_q
        arec.dns_type = type_q
        arec.dns_class = class_q
        arec.dns_ttl = 123
        #arec.dns_ttl = 123
        arec.set_answer_from_string(self.redirect_to)
        arec.build_metadata()

    def pack(self):
        #return self.dnsparser.pack()

        packed_a = self.dnsparser.pack()
        self.dnsparser = DnsParser(packed_a)
        self.dnsparser.process_msg()
        return self.dnsparser.pack()

    def get_dns_parser(self):
        return self.dnsparser
