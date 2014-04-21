#!/usr/bin/python

import socket
import ip
import icmp
import select
import time
import sys

import ip
import icmp


def traceroute(host):
    ip_addr = socket.inet_aton(host)
    ttl = 0
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    for ttl in xrange(1, 30):
        # set ttl
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl);

        #send probe
        send_sock.sendto("XXXX", (host, 32768 + 666))

        # wait for response
        reply_from = wait_for_reply(recv_sock, ip_addr)
        print ttl, ": ",  reply_from

        if reply_from == host:
            break;


def wait_for_reply(sock, dst_addr):
    time_out = time.time() + 5;
    time_left = 5

    while time_left > 0:
        input_ready, write_ready, except_ready = select.select([sock], [], [], time_left)

        if sock in input_ready:
            buff, addr = sock.recvfrom(0xFFFF)            
            if check_reply(buff, dst_addr):
                return addr[0]

        time_left = time_out - time.time()

    return None

def check_reply(reply, dst_addr):
    try:
        if len(reply) == 0:
            return False

        ip_datagram = ip.IPDatagram.unpack(reply)

        if ip_datagram.ip_p != socket.IPPROTO_ICMP:
            return False

        icmp_message = icmp.ICMPMessage.unpack(ip_datagram.ip_data)

        if type(icmp_message) is icmp.ICMPMessage_TimeExceeded:
            dropped_datagram = ip.IPDatagram.unpack(icmp_message.te_datagram)
            if dropped_datagram.ip_dst == dst_addr:
                return True

        if type(icmp_message) is icmp.ICMPMessage_Unreachable:
            dropped_datagram = ip.IPDatagram.unpack(icmp_message.un_datagram)
            if dropped_datagram.ip_dst == dst_addr:
                return True

    except Exception as e:
        print "Error:", e

    return False


if __name__ == '__main__':
    host = "4.2.2.1"
    if len(sys.argv) > 1:
        host = sys.argv[1]
    traceroute(host)
