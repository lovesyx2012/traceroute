#!/usr/bin/python

import time
import socket
import select
import struct
import sys
import os

import ip
import icmp



def ping(dst_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    echo_id = os.getpid() & 0xFFFF
    echo_seq = 0

    while True:
        send_echo_request(sock, dst_addr, echo_id, echo_seq)
        if not wait_for_reply(sock, dst_addr, echo_id, echo_seq):
            print "Request timeout for echo_seq", echo_seq

        echo_seq += 1
        if echo_seq > 0xFFFF:
            echo_seq = 0


def send_echo_request(sock, dst, id, seq):
    data = struct.pack("!d", time.time())
    data = data.ljust(64, "X")
    icmp_message = icmp.ICMPMessage_EchoRequest(id, seq, data)
    icmp_message.icmp_cksum = icmp_message.checksum()
    icmp_message_raw = icmp_message.pack()
    sock.sendto(icmp_message_raw, (dst, 0))


def wait_for_reply(sock, dst, id, seq):
    time_out = time.time() + 1
    time_left = 1
    reply = False

    while time_left > 0:
        input_ready, write_ready, except_ready = select.select([sock], [], [], time_left)

        if sock in input_ready:
            ip_datagram_raw, address = sock.recvfrom(0xFFFF)
            reply |= check_reply(ip_datagram_raw, address[0], id, seq)

        time_left = time_out - time.time()

    return reply


def check_reply(ip_datagram_raw, ip_src, echo_id, echo_seq):
    try:
        ip_datagram = ip.IPDatagram.unpack(ip_datagram_raw)

        if ip_datagram.ip_p != socket.IPPROTO_ICMP:
            return False

        icmp_message = icmp.ICMPMessage.unpack(ip_datagram.ip_data)

        if type(icmp_message) is not icmp.ICMPMessage_EchoReply:
            return False

        if icmp_message.echo_id != echo_id:
            # 'tis not our packet
            return False

        if len(icmp_message.echo_data) >= 8:
            send_time = struct.unpack("!d", icmp_message.echo_data[:8])[0]
            delay = int((time.time() - send_time) * 1000)
            print "Reply from %s echo_seq=%d time=%dms" % (ip_src, icmp_message.echo_seq, delay)
        else:
            print "Reply from %s echo_seq=%d" % (ip_src, icmp_message.echo_seq)

        if icmp_message.echo_seq == echo_seq:
            return True

    except Exception as e:
        print "Error:", e

    return False



if __name__ == '__main__':
    host = "4.2.2.1"
    if len(sys.argv) > 1:
        host = sys.argv[1]
    ping(host)
