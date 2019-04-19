import io
import itertools
import struct

from console_logging import cond_print
from question_parser import QuestionParser
from rr_parser import RRParser


class DnsParser:
    def __init__(self, dnsmsg):
        self.dnsmsg = dnsmsg  # dnsmsg.encode(encoding='UTF-8') if isinstance(dnsmsg, str) else dnsmsg

        self.header = None
        self.dns_id = None
        self.dns_flags = None
        self.dns_qdcount = None
        self.dns_ancount = None
        self.dns_nscount = None
        self.dns_arcount = None

        self.questions_records = []
        self.answers_records = []
        self.authority_records = []
        self.additional_records = []
        self.record_lists = [self.questions_records, self.answers_records, self.authority_records, self.additional_records]

    def process_msg(self):
        reader = io.BytesIO(self.dnsmsg)
        self.header = reader.read(12)

        self.dns_id, self.dns_flags, self.dns_qdcount, \
        self.dns_ancount, self.dns_nscount, self.dns_arcount = struct.unpack('!HHHHHH',  self.header)


        cond_print("Questions:")
        for i in range(self.dns_qdcount):
            qrecord = QuestionParser(reader)
            self.questions_records.append(qrecord)
            worked_question = qrecord.process()
            cond_print(qrecord.get_question() if worked_question else 'Question Failed')

        for i in range(self.dns_ancount):
            anrecord = RRParser(reader)
            self.answers_records.append(anrecord)
            anrecord.process()

        for i in range(self.dns_nscount):
            aurecord = RRParser(reader)
            self.authority_records.append(aurecord)
            aurecord.process()

        for i in range(self.dns_arcount):
            addirecord = RRParser(reader)
            self.additional_records.append(addirecord)
            addirecord.process()

        return True

    def get_header_with_id(self, dns_id=None):
        if dns_id is None:
            dns_id = self.dns_id
        header = struct.pack('!HHHHHH',
                             dns_id, self.dns_flags,
                             self.dns_qdcount, self.dns_ancount,
                             self.dns_nscount, self.dns_arcount)
        return header
        if False:
            reader = io.BytesIO(self.dnsmsg)
            reader.seek(2)
            rest_of_header = reader.read(10)
            return struct.pack('!H', dns_id) + rest_of_header

    def pack(self, _id=None):
        if _id is None:
            _id = self.dns_id
        body = b''
        for item in itertools.chain(*self.record_lists):
            body += item.pack()

        return self.get_header_with_id(_id) + body
