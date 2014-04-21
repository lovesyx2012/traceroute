import unittest

import ip


ip_datagram = {
    "ip_vhl": 0x45,
    "ip_tos": 0x00,
    "ip_len": 0x0038,
    "ip_id": 0x76f5,
    "ip_off": 0x0000,
    "ip_ttl": 64,
    "ip_p": 17,
    "ip_sum": 0xcdff,
    "ip_src": "\xc0\xa8\x5a\x6e",
    "ip_dst": "\xc0\xa8\x5a\x01",
    "ip_data": \
        "\xfd\x84\x00\x35\x00\x24\x76\xa4" \
        "\x41\xce\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f" \
        "\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
    
    "raw": \
        "\x45\x00\x00\x38\x76\xf5\x00\x00\x40\x11\xcd\xff\xc0\xa8\x5a\x6e" \
        "\xc0\xa8\x5a\x01" \
        "\xfd\x84\x00\x35\x00\x24\x76\xa4" \
        "\x41\xce\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f" \
        "\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
}


class IPDatagramTestCase(unittest.TestCase):
    def setUp(self):
        pass


    def test_init(self):
        datagram = ip.IPDatagram(
            ip_datagram["ip_vhl"],
            ip_datagram["ip_tos"],
            ip_datagram["ip_len"],
            ip_datagram["ip_id"],
            ip_datagram["ip_off"],
            ip_datagram["ip_ttl"],
            ip_datagram["ip_p"],
            ip_datagram["ip_sum"],
            ip_datagram["ip_src"],
            ip_datagram["ip_dst"],
            ip_datagram["ip_data"])

        self.assertEqual(datagram.ip_vhl, ip_datagram["ip_vhl"])
        self.assertEqual(datagram.ip_tos, ip_datagram["ip_tos"])
        self.assertEqual(datagram.ip_len, ip_datagram["ip_len"])
        self.assertEqual(datagram.ip_id, ip_datagram["ip_id"])
        self.assertEqual(datagram.ip_off, ip_datagram["ip_off"])
        self.assertEqual(datagram.ip_ttl, ip_datagram["ip_ttl"])
        self.assertEqual(datagram.ip_p, ip_datagram["ip_p"])
        self.assertEqual(datagram.ip_sum, ip_datagram["ip_sum"])
        self.assertEqual(datagram.ip_src, ip_datagram["ip_src"])
        self.assertEqual(datagram.ip_dst, ip_datagram["ip_dst"])
        self.assertEqual(datagram.ip_data, ip_datagram["ip_data"])

    def test_unpack(self):
        datagram = ip.IPDatagram.unpack(ip_datagram["raw"])
        
        self.assertEqual(datagram.ip_vhl, ip_datagram["ip_vhl"])
        self.assertEqual(datagram.ip_tos, ip_datagram["ip_tos"])
        self.assertEqual(datagram.ip_len, ip_datagram["ip_len"])
        self.assertEqual(datagram.ip_id, ip_datagram["ip_id"])
        self.assertEqual(datagram.ip_off, ip_datagram["ip_off"])
        self.assertEqual(datagram.ip_ttl, ip_datagram["ip_ttl"])
        self.assertEqual(datagram.ip_p, ip_datagram["ip_p"])
        self.assertEqual(datagram.ip_sum, ip_datagram["ip_sum"])
        self.assertEqual(datagram.ip_src, ip_datagram["ip_src"])
        self.assertEqual(datagram.ip_dst, ip_datagram["ip_dst"])
        self.assertEqual(datagram.ip_data, ip_datagram["ip_data"])

    def test_pack(self):
        datagram = ip.IPDatagram.unpack(ip_datagram["raw"])
        self.assertEqual(datagram.pack(), ip_datagram["raw"])

    def test_checksum(self):
        datagram = ip.IPDatagram.unpack(ip_datagram["raw"])
        datagram.ip_sum = 0;
        self.assertEqual(datagram.checksum(), ip_datagram["ip_sum"])

    def tearDown(self):
        pass


udp_datagram = \
    "\xfd\x84\x00\x35\x00\x24\x00\x00" \
    "\x41\xce\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f" \
    "\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

class ChecksumTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_checksum(self):
        cksum = ip.checksum(udp_datagram)
        

    def tearDown(self):
        pass


