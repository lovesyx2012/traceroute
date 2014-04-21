import struct


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        hi = ord(msg[i])
        lo = ord(msg[i+1]) if i+1 < len(msg) else 0
        addend = lo + (hi << 8)
        s += addend
        s = (s >> 16) + (s & 0xFFFF)
    return ~s & 0xffff

class IPDatagram(object):
    def __init__(
            self, 
            ip_vhl, 
            ip_tos, 
            ip_len, 
            ip_id, 
            ip_off, 
            ip_ttl, 
            ip_p, 
            ip_sum, 
            ip_src, 
            ip_dst, 
            ip_data):
        self.ip_vhl = ip_vhl
        self.ip_tos = ip_tos
        self.ip_len = ip_len
        self.ip_id = ip_id
        self.ip_off = ip_off
        self.ip_ttl = ip_ttl
        self.ip_p = ip_p
        self.ip_sum = ip_sum
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_data = ip_data

    def pack_header(self):
        fields = (
            self.ip_vhl,
            self.ip_tos,
            self.ip_len,
            self.ip_id,
            self.ip_off,
            self.ip_ttl,
            self.ip_p,
            self.ip_sum,
            self.ip_src,
            self.ip_dst,
        )
        return struct.pack("!BBHHHBBH4s4s", *(fields))
     
    def pack(self):
        ip_header = self.pack_header()
        return ip_header + self.ip_data

    def checksum(self):
        datagram = self.pack_header()
        return checksum(datagram)

    def length(self):
        return 20 + len(self.ip_data)

    @classmethod
    def unpack(cls, ip_datagram):
        ip_header = ip_datagram[:20]
        ip_data = ip_datagram[20:]

        fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
        ip_vhl = fields[0]
        ip_tos = fields[1]
        ip_len = fields[2]
        ip_id = fields[3]
        ip_off = fields[4]
        ip_ttl = fields[5]
        ip_p = fields[6]
        ip_sum = fields[7]
        ip_src = fields[8]
        ip_dst = fields[9]

        return cls(
            ip_vhl, 
            ip_tos, 
            ip_len, 
            ip_id, 
            ip_off, 
            ip_ttl, 
            ip_p, 
            ip_sum, 
            ip_src, 
            ip_dst, 
            ip_data)
