from console_logging import cond_print
import struct


class QuestionParser:
    def __init__(self, reader):
        self.reader = reader
        self.dns_qname = None
        self.dns_qtype = None
        self.dns_qclass = None
        self.sections = []
        self.question = None
        self.raw_question = None

    def process(self):
        question = []
        self.raw_question = []
        self.dns_qname = b''
        while True:
            try:
                first_read = self.reader.read(1)
                self.dns_qname += first_read
                (length_oct,) = struct.unpack('!B', first_read)
            except Exception:
                print("There was an EXCEPTION in QuestionParser")
                return False
            if length_oct == 0:
                break

            try:
                section = self.reader.read(length_oct)
                self.dns_qname += section
            except Exception:
                print("There was an EXCEPTION in QuestionParser")
                return False
            question.append(section)

        self.raw_question = question
        self.question = '.'.join(map(lambda x: str(x),question))
        cond_print("Question size: %d" % len(self.question))

        try:
            self.dns_qtype = self.reader.read(2)
            self.dns_qclass = self.reader.read(2)
        except Exception:
            print("There was an EXCEPTION in QuestionParser")
            return False

        return True

    def get_question(self):
        return self.question

    def pack(self):
        return self.dns_qname + self.dns_qtype + self.dns_qclass
