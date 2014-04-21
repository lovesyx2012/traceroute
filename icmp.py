import struct

import ip

class ICMPMessage(object):
    def __init__(self, type, code, cksum=0):
        self.icmp_type = type
        self.icmp_code = code
        self.icmp_cksum = cksum

    def pack(self):
        fields = (
            self.icmp_type,
            self.icmp_code,
            self.icmp_cksum
        )
        return struct.pack("!BBH", fields)

    def checksum(self):
        message = self.pack()
        return ip.checksum(message)

    @classmethod
    def unpack(cls, icmp_message_raw):
        type = ord(icmp_message_raw[0])

        if type == 0:
            return ICMPMessage_EchoReply.unpack(icmp_message_raw)
        if type == 3:
            return ICMPMessage_Unreachable.unpack(icmp_message_raw)
        if type == 8:
            return ICMPMessage_EchoRequest.unpack(icmp_message_raw)
        if type == 11:
            return ICMPMessage_TimeExceeded.unpack(icmp_message_raw)
        raise Exception("unknown icmp message type")


class ICMPMessage_EchoReply(ICMPMessage):
    def __init__(self, id, seq, data, code=0, cksum=0):
        super(self.__class__, self).__init__(0, code, cksum)
        self.echo_id = id
        self.echo_seq = seq
        self.echo_data = data

    def pack(self):
        fields = (
            self.icmp_type,
            self.icmp_code,
            self.icmp_cksum,
            self.echo_id,
            self.echo_seq,
        )
        return struct.pack("!BBHHH", *fields) + self.echo_data

    @classmethod
    def unpack(cls, icmp_message):
        fields = struct.unpack("!BBHHH", icmp_message[:8])
        echo_data = icmp_message[8:]
        if fields[0] != 0 or fields[1] != 0:
            raise Exception("invalid type/code for echo request")
        return cls(fields[3], fields[4], echo_data, cksum=fields[2])


class ICMPMessage_EchoRequest(ICMPMessage):
    def __init__(self, id, seq, data, code=0, cksum=0):
        super(self.__class__, self).__init__(8, code, cksum)
        self.echo_id = id
        self.echo_seq = seq
        self.echo_data = data

    def pack(self):
        fields = (
            self.icmp_type,
            self.icmp_code,
            self.icmp_cksum,
            self.echo_id,
            self.echo_seq,
        )
        return struct.pack("!BBHHH", *fields) + self.echo_data

    @classmethod
    def unpack(cls, icmp_message):
        fields = struct.unpack("!BBHHH", icmp_message[:8])
        echo_data = icmp_message[8:]
        if fields[0] != 8 or fields[1] != 0:
            raise Exception("invalid type/code for echo request")
        return cls(fields[3], fields[4], echo_data, cksum=fields[2])




class ICMPMessage_TimeExceeded(ICMPMessage):
    def __init__(self, ip_datagram, code=0, cksum=0, unused=0):
        super(self.__class__, self).__init__(11, code, cksum)
        self.te_unused = unused
        self.te_datagram = ip_datagram

    def pack(self):
        fields = (
            self.icmp_type,
            self.icmp_code,
            self.icmp_cksum,
            self.te_unused,
        )
        return struct.pack("!BBHI", *fields) + self.te_datagram

    @classmethod
    def unpack(cls, icmp_message):
        fields = struct.unpack("!BBHI", icmp_message[:8])
        ip_datagram = icmp_message[8:]
        if fields[0] != 11:
            raise Exception("invalid type for time exceeded message")
        return cls(ip_datagram, fields[1], fields[2], fields[3])

class ICMPMessage_Unreachable(ICMPMessage):
    def __init__(self, ip_datagram, code=0, cksum=0, unused=0):
        super(self.__class__, self).__init__(3, code, cksum)
        self.un_unused = unused
        self.un_datagram = ip_datagram

    def pack(self):
        fields = (
            self.icmp_type,
            self.icmp_code,
            self.icmp_cksum,
            self.un_unused,
        )
        return struct.pack("!BBHI", *fields) + self.un_datagram

    @classmethod
    def unpack(cls, icmp_message):
        fields = struct.unpack("!BBHI", icmp_message[:8])
        ip_datagram = icmp_message[8:]
        if fields[0] != 3:
            raise Exception("invalid type for time exceeded message")
        return cls(ip_datagram, fields[1], fields[2], fields[3])


