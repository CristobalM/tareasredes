import struct

from console_logging import cond_print


def convert_to_int(x):
    return int.from_bytes(x, byteorder='big')

class RRParser:
    def __init__(self, reader=None):
        self.reader = reader
        self.dns_name = None
        self.dns_type = None
        self.dns_class = None
        self.dns_ttl = None
        self.dns_rdlength = None
        self.answer = None
        self.sections = None
        self.unpacked_answer = None
        self.metadata = None

    def pack(self):
        if self.reader is None:
            self.build_metadata()
        return self.dns_name + self.metadata + self.answer



    def build_metadata(self):
        cond_print('MetadataBuild')
        cond_print(int.from_bytes(self.dns_type, byteorder='big'))
        #cond_print(int(self.dns_class))
        #cond_print(int(self.dns_ttl))
        #cond_print(int(self.dns_rdlength))
        cond_print('MetadataBuildEnd')

        ptype = convert_to_int(self.dns_type)
        pclass = convert_to_int(self.dns_class)
        pttl = self.dns_ttl
        prdl = self.dns_rdlength #convert_to_int(self.dns_rdlength)

        self.metadata = struct.pack('!HHIH',
                                    ptype,
                                    pclass,
                                    pttl,
                                    prdl)




    def set_answer_from_string(self, str_answer):
        numbers_as_str = str_answer.split('.')
        numbers = [int(x) for x in numbers_as_str]
        packed_ip = struct.pack('!' + 'B'*len(numbers), *numbers)

        cond_print('rd_l')
        cond_print(numbers)

        cond_print('"Numbers: "')

        cond_print(numbers)

        cond_print('"Packed IP:"')
        cond_print(packed_ip)
        self.answer = packed_ip
        self.dns_rdlength = len(numbers)
        self.unpack_answer()

    def process_name(self, root=True):
        if not root:
            cond_print("Not in ROOT")
        else:
            self.dns_name = b''
        pointer_mask = 0b11000000
        sections = []

        while True:
            first_read = self.reader.read(1)
            if root:
                self.dns_name += first_read
            if len(first_read) == 0:
                cond_print('ZERO SIZE READ')
                break

            (length_oct,) = struct.unpack('!B', first_read)

            cond_print("LENGTH OCT: " + str(length_oct))

            if length_oct == 0:
                break

            if length_oct & pointer_mask:
                other_byte = self.reader.read(1)
                if root:
                    self.dns_name += other_byte
                (other_byte_u,) = struct.unpack('!B', other_byte)
                #dns_name += first_read + other_byte
                offset = ((length_oct & ~pointer_mask) << 8) | other_byte_u
                position = self.reader.tell()
                self.reader.seek(offset)
                self.process_name(root=False)
                self.reader.seek(position)
                break
            else:
                section = self.reader.read(length_oct)
                if root:
                    self.dns_name += section
                sections.append(section)

        if root:
            self.sections = sections
        else:
            cond_print("Getting out of child")
            return True

    def process_inner(self):
        self.metadata = self.reader.read(10)
        cond_print('Metadata is')
        cond_print(self.metadata)
        self.dns_type, self.dns_class, self.dns_ttl, self.dns_rdlength = struct.unpack('!HHIH', self.metadata)

    def unpack_answer(self):
        self.unpacked_answer = struct.unpack('B' * self.dns_rdlength, self.answer)

    def process_rdata(self):
        self.answer = self.reader.read(self.dns_rdlength)
        self.unpack_answer()

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

