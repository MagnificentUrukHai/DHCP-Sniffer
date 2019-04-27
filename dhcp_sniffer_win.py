import socket
import argparse
import struct

from common import UDP, DHCP, IPv4, Host, PACKETS_WITHOUT_DHCP, DHCP_Protocol
from utils import convert_hex_str_to_mac, convert_hex_str_to_int_str, get_time, \
    check_port_open

simple_dhcp_type = ['DHCPREQUEST']

if __name__ == '__main__':

    # argument parse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--detail', action='store_true',
                        help='show more detail packet information. if not set, only {} show.'.format(
                            ' '.join(simple_dhcp_type)))
    args = parser.parse_args()

    # bind raw_socket
    host_ip = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((host_ip, 0))

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # print setting
    print('listen IP: {}'.format(host_ip))
    if args.detail:
        print('capture type: all DHCP broadcast packets')
    else:
        print('capture type: {}'.format(','.join(simple_dhcp_type)))
        print("{:30}{:20}{:20}{:20}{:20}{:20}".format('Local Time',
                                                      'Message Type',
                                                      'Host Name', 'MAC',
                                                      'IPv4', 'Option 55'))
        print('-' * 130)

    # only get DHCP packets:
    #     format: IPv4(EtherType: 0x0800) + UDP(port: 67, 68)

    known_hosts = {}

    while True:
        packet = sock.recv(2048)

        # get IPv4 packet
        ip_packet = IPv4(packet)
        protocol = ip_packet.get_protocol()

        # if protocol != IPv4.protocol_UDP:
        #     continue;

        source_ip = ip_packet.get_source_ip()
        dest_ip = ip_packet.get_dest_ip()

        # get UDP datagram
        udp = UDP(packet)
        source_port = udp.get_source_port()
        dest_port = udp.get_dest_port()
        udp_length = udp.get_length()

        # if ((
        #         source_port != DHCP_Protocol.client_port and source_port != DHCP_Protocol.server_port) or
        #         (
        #                 dest_port != DHCP_Protocol.client_port and dest_port != DHCP_Protocol.server_port)):
        #     continue

        # get DHCP
        dhcp = DHCP(packet, udp_length - 8)
        dhcp.parse_options()
        try:
            # could be errors if it happens to be not DHCP packet
            dhcp.parse_payload()
        except struct.error:
            pass
        chaddr = dhcp.chaddr
        ciaddr = dhcp.ciaddr
        message_type = dhcp.option_53
        request_list = dhcp.option_55
        host_name = dhcp.option_12
        # there is no option50 (request IP) when DHCP client rebinds lease. Should use ciaddr as IP address in this condition.
        request_ip = dhcp.option_50 if '' != dhcp.option_50 else ciaddr
        server_id = dhcp.option_54

        host = Host(chaddr if chaddr else '')
        if source_ip:
            host.set_ip(source_ip or request_ip)

        host = known_hosts.setdefault(host.ip, host)
        host.increase_packet_num()

        now = get_time()

        if args.detail:
            print("message type  : {}".format(message_type))
            print("local time    : {}".format(now))
            print("host name     : {}".format(host_name))
            print("request ip    : {}".format(request_ip))
            print("server id     : {}".format(server_id))
            print("source MAC    : {}".format(convert_hex_str_to_mac(chaddr)))
            print("source IP     : {}:{}".format(source_ip, source_port))
            print("dest   IP     : {}:{}".format(dest_ip, dest_port))
            print("UDP length    : {}".format(udp_length))
            print("option 55     : {}".format(
                convert_hex_str_to_int_str(request_list)))
            print("")
        else:
            if message_type in simple_dhcp_type:
                host.set_dhcp_seen()
                print(
                    "{:30}{:20}{:20}{:20}{:20}{:20}".format(now, message_type,
                                                            host_name,
                                                            convert_hex_str_to_mac(
                                                                chaddr),
                                                            request_ip,
                                                            convert_hex_str_to_int_str(
                                                                request_list)))
            if host.num_packets > PACKETS_WITHOUT_DHCP and (
                    not host.broadcasted_dhcp and not host.seen):
                host.set_seen()
                print("STATIC {:30}{:20}".format(now, host.ip))
            if check_port_open(host.ip, 80):
                print('Can open browser at: http://{}'.format(
                    source_ip or host.ip))
