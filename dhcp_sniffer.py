import socket
import ctypes
import binascii
import struct
import argparse

from common import Ethernet, IPv4, UDP, DHCP, Host, \
    PACKETS_WITHOUT_DHCP
from utils import convert_hex_str_to_mac, get_time, convert_hex_str_to_int_str, \
    get_ip_address, get_netmask, get_subnet, check_port_open, open_browser


class BPF(object):
    def __init__(self):
        self.SO_ATTACH_FILTER = 26

        # instruction classes
        self.BPF_LD = 0x00
        self.BPF_JMP = 0x05
        self.BPF_RET = 0x06

        # ld/ldx fields
        self.BPF_W = 0x00  # word(4 byte)
        self.BPF_H = 0x08  # helf word(2 byte)
        self.BPF_B = 0x10  # byte(1 byte)
        self.BPF_ABS = 0x20  # absolute address

        # alu/jmp fields
        self.BPF_JEQ = 0x10
        self.BPF_K = 0x00

    def fill_sock_filter(self, code, jt, jf, k):
        return struct.pack('HBBI', code, jt, jf, k)

    def statement(self, code, k):
        return self.fill_sock_filter(code, 0, 0, k)

    def jump(self, code, jt, jf, k):
        return self.fill_sock_filter(code, jt, jf, k)


class BPF_DHCP(BPF):
    def __init__(self):
        super(BPF_DHCP, self).__init__()

    def set_dhcp_filter(self, sock, addr=None):
        addr = struct.unpack('!L', addr)[0]
        command_list = [
            # filter IPv4
            self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_H, 12),
            self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 1, 0x0800),

            # # filter UDP
            # self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_B, 23),
            # self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 3, 0x11),
            #
            # # filter destination port 67
            # self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_H, 36),
            # self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 1, 67),

            # self.statement(0x20, 0x0000001a),
            # self.jump(0x15, 2, 0, addr),
            # self.jump(0x20, 0, 0, 0x0000001e),
            # self.jump(0x15, 0, 1, addr),

            # return
            self.statement(self.BPF_RET | self.BPF_K, 0x00040000),  # pass
            self.statement(self.BPF_RET | self.BPF_K, 0x00000000)  # reject
        ]
        self.print_commands(command_list)
        commands = b''.join(command_list)
        buffers = ctypes.create_string_buffer(commands)
        fprog = struct.pack('HL', len(command_list), ctypes.addressof(buffers))
        sock.setsockopt(socket.SOL_SOCKET, self.SO_ATTACH_FILTER, fprog)

    def print_commands(self, command_list):
        print("like <tcpdump -dd ...>")
        for i in list(map(lambda x: binascii.hexlify(x).decode('ascii'),
                          command_list)):
            print(i)


simple_dhcp_type = ['DHCPREQUEST']

if __name__ == '__main__':

    # argument parse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default='eth0',
                        help='sniffer interface to get DHCP packets. default is eth0')
    parser.add_argument('-d', '--detail', action='store_true',
                        help='show more detail packet information. if not set, only {} show.'.format(
                            ' '.join(simple_dhcp_type)))
    args = parser.parse_args()

    # iface ip addr and mask
    iface_ip = get_ip_address(args.interface.encode('utf-8'))
    iface_mask = get_netmask(args.interface.encode('utf-8'))
    subnet_addr = get_subnet(socket.inet_ntoa(iface_ip),
                             socket.inet_ntoa(iface_mask))
    print('iface ip: {}\niface mask: {}\niface subnet: {}'.format(
        socket.inet_ntoa(iface_ip), socket.inet_ntoa(iface_mask), subnet_addr))

    # bind raw_socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0800)

    # use BPF to filter DHCP packet
    BPF_DHCP().set_dhcp_filter(sock, socket.inet_aton(subnet_addr))

    sock.bind((args.interface, 0x0800))

    # print setting
    print('bind interface: {}'.format(args.interface))
    if args.detail:
        print('capture type: all DHCP broadcast packets')
    # else:
    #     print('capture type: {}'.format(' '.join(simple_dhcp_type)))
    #     print("{:30}{:20}{:20}{:20}{:20}{:20}".format('Local Time',
    #                                                   'Message Type',
    #                                                   'Host Name', 'MAC',
    #                                                   'IPv4', 'Option 55'))
    #     print('-' * 130)

    # only get DHCP packets:
    #     format: IPv4(EtherType: 0x0800) + UDP(port: 67, 68)

    known_hosts = {}

    while True:
        packet = sock.recv(2048)

        # get Ethernet Frame
        ethernet_frame = Ethernet(packet)
        source_mac = ethernet_frame.get_source_mac()
        dest_mac = ethernet_frame.get_dest_mac()
        ether_type = ethernet_frame.get_ether_type()

        # get IPv4 packet
        ip_packet = IPv4(packet)
        protocol = ip_packet.get_protocol()
        source_ip = ip_packet.get_source_ip()
        dest_ip = ip_packet.get_dest_ip()

        # get UDP datagram
        udp = UDP(packet)
        source_port = udp.get_source_port()
        dest_port = udp.get_dest_port()
        udp_length = udp.get_length()

        # get DHCP
        # if it is not DHCP packet fields like:
        # - message_type
        # - host_name
        # would be empty
        dhcp = DHCP(packet, udp_length - 8)
        dhcp.parse_options()
        try:
            # could be errors if it happens to be not DHCP packet
            dhcp.parse_payload()
        except struct.error:
            dhcp._chaddr = ''
            dhcp._ciaddr = ''
        chaddr = dhcp.chaddr
        ciaddr = dhcp.ciaddr
        message_type = dhcp.option_53
        request_list = dhcp.option_55
        host_name = dhcp.option_12
        # there is no option50 (request IP) when DHCP client rebinds lease. Should use ciaddr as IP address in this condition.
        request_ip = dhcp.option_50 if '' != dhcp.option_50 else ciaddr
        server_id = dhcp.option_54

        host = Host(convert_hex_str_to_mac(source_mac))
        if source_ip:
            host.set_ip(source_ip)

        #  Continue if packet is from our interface
        if host.ip == socket.inet_ntoa(iface_ip):
            continue

        host = known_hosts.setdefault(host.mac, host)
        host.increase_packet_num()

        if message_type and host_name:
            host.set_dhcp_seen()

        # get now
        now = get_time()

        possible_to_open_browser = False

        if args.detail:
            print("message type  : {}".format(message_type))
            print("local time    : {}".format(now))
            print("host name     : {}".format(host_name))
            print("request ip    : {}".format(request_ip))
            print("server id     : {}".format(server_id))
            print("source MAC    : {}".format(convert_hex_str_to_mac(chaddr)))
            print(
                "dest   MAC    : {}".format(convert_hex_str_to_mac(dest_mac)))
            print("source IP     : {}:{}".format(source_ip, source_port))
            print("dest   IP     : {}:{}".format(dest_ip, dest_port))
            print("UDP length    : {}".format(udp_length))
            print("option 55     : {}".format(
                convert_hex_str_to_int_str(request_list)))
            print("")
        else:
            if message_type in simple_dhcp_type:
                possible_to_open_browser = True
                host.set_dhcp_seen()
                print(
                    "DYNAMIC {:30}{:20}{:20}{:20}{:20}{:20}".format(now,
                                                                    message_type,
                                                                    host_name,
                                                                    convert_hex_str_to_mac(
                                                                        chaddr),
                                                                    request_ip,
                                                                    convert_hex_str_to_int_str(
                                                                        request_list)))

            if host.num_packets > PACKETS_WITHOUT_DHCP and (
                    not host.broadcasted_dhcp and not host.seen):
                host.set_seen()
                print("STATIC {:30}{:20}{:20}".format(now, host.mac, host.ip))
                possible_to_open_browser = True

            if possible_to_open_browser and check_port_open(host.ip, 80):
                print('Can open browser at: http://{}'.format(host.ip))
