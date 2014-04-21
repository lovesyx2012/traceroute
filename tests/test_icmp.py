import unittest

import icmp


echo_request = {
    "icmp_type": 8,
    "icmp_code": 0,
    "icmp_cksum": 0x89dd,
    "echo_id": 0x1e09,
    "echo_seq": 0,
    "echo_data": \
        "\x53\x54\x04\x23\x00\x0b\x0d\x94" \
        "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15" \
        "\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23" \
        "\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31" \
        "\x32\x33\x34\x35\x36\x37",
    "raw": \
        "\x08\x00\x89\xdd\x1e\x09\x00\x00\x53\x54\x04\x23\x00\x0b\x0d" \
        "\x94\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15" \
        "\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24" \
        "\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33" \
        "\x34\x35\x36\x37",
}

class ICMPMessage_EchoRequest_TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_init(self):
        message = icmp.ICMPMessage_EchoRequest(
            echo_request["echo_id"],
            echo_request["echo_seq"],
            echo_request["echo_data"],
            cksum=echo_request["icmp_cksum"])

        self.assertEqual(message.icmp_type, echo_request["icmp_type"])
        self.assertEqual(message.icmp_code, echo_request["icmp_code"])
        self.assertEqual(message.icmp_cksum, echo_request["icmp_cksum"])
        self.assertEqual(message.echo_id, echo_request["echo_id"])
        self.assertEqual(message.echo_seq, echo_request["echo_seq"])
        self.assertEqual(message.echo_data, echo_request["echo_data"])

    def test_unpack(self):
        message = icmp.ICMPMessage_EchoRequest.unpack(echo_request["raw"])
        self.assertEqual(message.icmp_type, echo_request["icmp_type"])
        self.assertEqual(message.icmp_code, echo_request["icmp_code"])
        self.assertEqual(message.icmp_cksum, echo_request["icmp_cksum"])
        self.assertEqual(message.echo_id, echo_request["echo_id"])
        self.assertEqual(message.echo_seq, echo_request["echo_seq"])
        self.assertEqual(message.echo_data, echo_request["echo_data"])

    def test_pack(self):
        message = icmp.ICMPMessage_EchoRequest(
            echo_request["echo_id"],
            echo_request["echo_seq"],
            echo_request["echo_data"],
            cksum=echo_request["icmp_cksum"])

        self.assertEqual(message.pack(), echo_request["raw"])
        

    def tearDown(self):
        pass


echo_reply = {
    "icmp_type": 0,
    "icmp_code": 0,
    "icmp_cksum": 0x91dd,
    "echo_id": 0x1e09,
    "echo_seq": 0,
    "echo_data": \
        "\x53\x54\x04\x23\x00\x0b\x0d\x94\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" \
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" \
        "\x30\x31\x32\x33\x34\x35\x36\x37",
    "raw": \
        "\x00\x00\x91\xdd\x1e\x09\x00\x00\x53\x54\x04\x23\x00\x0b\x0d" \
        "\x94\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15" \
        "\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24" \
        "\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33" \
        "\x34\x35\x36\x37",
}


class ICMPMessage_EchoReply_TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_unpack(self):
        message = icmp.ICMPMessage_EchoReply.unpack(echo_reply["raw"])
        self.assertEqual(message.icmp_type, echo_reply["icmp_type"])
        self.assertEqual(message.icmp_code, echo_reply["icmp_code"])
        self.assertEqual(message.icmp_cksum, echo_reply["icmp_cksum"])
        self.assertEqual(message.echo_id, echo_reply["echo_id"])
        self.assertEqual(message.echo_seq, echo_reply["echo_seq"])
        self.assertEqual(message.echo_data, echo_reply["echo_data"])

    def test_pack(self):
        message = icmp.ICMPMessage_EchoReply(
            echo_reply["echo_id"],
            echo_reply["echo_seq"],
            echo_reply["echo_data"],
            cksum=echo_reply["icmp_cksum"])

        self.assertEqual(message.icmp_type, echo_reply["icmp_type"])
        self.assertEqual(message.icmp_code, echo_reply["icmp_code"])
        self.assertEqual(message.icmp_cksum, echo_reply["icmp_cksum"])
        self.assertEqual(message.echo_id, echo_reply["echo_id"])
        self.assertEqual(message.echo_seq, echo_reply["echo_seq"])
        self.assertEqual(message.echo_data, echo_reply["echo_data"])

    def tearDown(self):
        pass


time_exceeded = {
    "icmp_type": 11,
    "icmp_code": 0,
    "icmp_cksum": 0x3b2f,
    "te_unused": 0,
    "te_datagram": \
        "\x45\x00\x00\x34\x95\x80\x00\x00" \
        "\x01\x11\xde\x3b\xc0\xa8\x5a\x6e\x4a\x7d\xe0\x69\x95\x7f\x82\x9b" \
        "\x00\x20\xa1\x95\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "raw": \
        "\x0b\x00\x3b\x2f\x00\x00\x00\x00\x45\x00\x00\x34\x95\x80\x00\x00" \
        "\x01\x11\xde\x3b\xc0\xa8\x5a\x6e\x4a\x7d\xe0\x69\x95\x7f\x82\x9b" \
        "\x00\x20\xa1\x95\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}


class ICMPMessage_TimeExceeded_TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_init(self):
        message = icmp.ICMPMessage_TimeExceeded(
            time_exceeded["te_datagram"],
            time_exceeded["icmp_code"],
            time_exceeded["icmp_cksum"],
            time_exceeded["te_unused"])

        self.assertEqual(message.icmp_type, time_exceeded["icmp_type"])
        self.assertEqual(message.icmp_code, time_exceeded["icmp_code"])
        self.assertEqual(message.icmp_cksum, time_exceeded["icmp_cksum"])
        self.assertEqual(message.te_unused, time_exceeded["te_unused"])
        self.assertEqual(message.te_datagram, time_exceeded["te_datagram"])

    def test_unpack(self):
        message = icmp.ICMPMessage_TimeExceeded.unpack(time_exceeded["raw"])

        self.assertEqual(message.icmp_type, time_exceeded["icmp_type"])
        self.assertEqual(message.icmp_code, time_exceeded["icmp_code"])
        self.assertEqual(message.icmp_cksum, time_exceeded["icmp_cksum"])
        self.assertEqual(message.te_unused, time_exceeded["te_unused"])
        self.assertEqual(message.te_datagram, time_exceeded["te_datagram"])

    def test_pack(self):
        message = icmp.ICMPMessage_TimeExceeded.unpack(time_exceeded["raw"])
        message_raw = message.pack()
        self.assertEqual(message_raw, time_exceeded["raw"])

    def tearDown(self):
        pass


unreachable = {
    "icmp_type": 3,
    "icmp_code": 3,
    "icmp_cksum": 0x1e34,
    "un_unused": 0,
    "un_datagram": \
        "\x45\x00\x00\x20\xe8\x1e\x00\x00" \
        "\x01\x11\xb0\x95\xc0\xa8\x5a\x6e\x04\x02\x02\x01\xe9\xcf\x82\x9a" \
        "\x00\x0c\xc1\xa1\x58\x58\x58\x58",
    "raw": \
        "\x03\x03\x1e\x34\x00\x00\x00\x00\x45\x00\x00\x20\xe8\x1e\x00\x00" \
        "\x01\x11\xb0\x95\xc0\xa8\x5a\x6e\x04\x02\x02\x01\xe9\xcf\x82\x9a" \
        "\x00\x0c\xc1\xa1\x58\x58\x58\x58",
}


class ICMPMessage_Unreachable_TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_init(self):
        message = icmp.ICMPMessage_Unreachable(
            unreachable["un_datagram"],
            unreachable["icmp_code"],
            unreachable["icmp_cksum"],
            unreachable["un_unused"])

        self.assertEqual(message.icmp_type, unreachable["icmp_type"])
        self.assertEqual(message.icmp_code, unreachable["icmp_code"])
        self.assertEqual(message.icmp_cksum, unreachable["icmp_cksum"])
        self.assertEqual(message.un_unused, unreachable["un_unused"])
        self.assertEqual(message.un_datagram, unreachable["un_datagram"])

    def test_unpack(self):
        message = icmp.ICMPMessage_Unreachable.unpack(unreachable["raw"])

        self.assertEqual(message.icmp_type, unreachable["icmp_type"])
        self.assertEqual(message.icmp_code, unreachable["icmp_code"])
        self.assertEqual(message.icmp_cksum, unreachable["icmp_cksum"])
        self.assertEqual(message.un_unused, unreachable["un_unused"])
        self.assertEqual(message.un_datagram, unreachable["un_datagram"])

    def test_pack(self):
        message = icmp.ICMPMessage_Unreachable.unpack(unreachable["raw"])
        message_raw = message.pack()
        self.assertEqual(message_raw, unreachable["raw"])

    def tearDown(self):
        pass





class ICMPTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_unpack(self):
        message = icmp.ICMPMessage.unpack(echo_request["raw"])
        self.assertIsInstance(message, icmp.ICMPMessage_EchoRequest)

        message = icmp.ICMPMessage.unpack(echo_reply["raw"])
        self.assertIsInstance(message, icmp.ICMPMessage_EchoReply)

        message = icmp.ICMPMessage.unpack(time_exceeded["raw"])
        self.assertIsInstance(message, icmp.ICMPMessage_TimeExceeded)

        message = icmp.ICMPMessage.unpack(unreachable["raw"])
        self.assertIsInstance(message, icmp.ICMPMessage_Unreachable)


    def test_checksum(self):
        message = icmp.ICMPMessage.unpack(echo_request["raw"])
        cksum = message.icmp_cksum
        message.icmp_cksum = 0
        self.assertEqual(message.checksum(), cksum)

    def tearDown(self):
        pass