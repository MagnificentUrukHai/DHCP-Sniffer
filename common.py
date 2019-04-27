import binascii
import socket
import struct
import os

PACKETS_WITHOUT_DHCP = 10

if os.name == 'posix':

    class Ethernet(object):
        # ethertype
        ETH_P_ALL = 0x0003
        ETH_P_IP = 0x0800

        def __init__(self, packet):
            self._frame_header = packet[0:14]

        def get_source_mac(self):
            return binascii.hexlify(self._frame_header[6:12]).decode()

        def get_dest_mac(self):
            return binascii.hexlify(self._frame_header[0:6]).decode()

        def get_ether_type(self):
            return binascii.hexlify(self._frame_header[12:14]).decode()


    class IPv4(object):
        # protocol
        protocol_UDP = 17

        def __init__(self, packet):
            self._ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])

        def get_source_ip(self):
            return socket.inet_ntoa(self._ip_header[8])

        def get_dest_ip(self):
            return socket.inet_ntoa(self._ip_header[9])

        def get_protocol(self):
            return self._ip_header[6]


    class UDP(object):
        def __init__(self, packet):
            self._udp_header = struct.unpack('!HHHH', packet[34:42])

        def get_source_port(self):
            return self._udp_header[0]

        def get_dest_port(self):
            return self._udp_header[1]

        def get_length(self):
            return self._udp_header[2]


    class DHCP_Protocol(object):
        server_port = 67
        client_port = 68

        # DHCP options
        magic_cookie = '63825363'
        option_pad = 0
        option_host_name = 12
        option_request_ip = 50
        option_message_type = 53
        option_server_id = 54
        option_request_list = 55
        option_end = 255

        @staticmethod
        def get_message_type(value):
            message_type = {
                1: 'DHCPDISCOVER',
                2: 'DHCPOFFER',
                3: 'DHCPREQUEST',
                4: 'DHCPDECLINE',
                5: 'DHCPACK',
                6: 'DHCPNAK',
                7: 'DHCPRELEASE',
                8: 'DHCPINFORM'
            }
            return message_type.get(value, 'None')


    # length: number of bytes
    class DHCP(object):
        def __init__(self, packet, length):
            self._payload = packet[42:]
            self._length = length
            self._ciaddr = ''
            self._chaddr = ''
            self._option_55 = ''
            self._option_53 = ''
            self._option_12 = ''
            self._option_50 = ''
            self._option_54 = ''

        def parse_payload(self):
            # parse DHCP payload [0:44]
            #    ciaddr [Client IP Address]      : [12:16]
            #    yiaddr [Your IP Address]        : [16:20]
            #    siaddr [Server IP Address]      : [20:24]
            #    giaddr [Gateway IP Address]     : [24:28]
            #    chaddr [Client Hardware address]: [28:44]
            tmp = struct.unpack('!4s', self._payload[12:16])
            self._ciaddr = socket.inet_ntoa(tmp[0])
            self._chaddr = binascii.hexlify(self._payload[28:34]).decode()

        # DHCP options format:
        #     Magic Cookie + DHCP options + FF(end option)
        #     DHCP option format:
        #         code(1 byte) + length(1 byte) + value
        #     Pad and End option format:
        #         code(1 byte)
        def parse_options(self):
            find = False
            payload = binascii.hexlify(self._payload).decode()

            index = payload.find(DHCP_Protocol.magic_cookie)
            if -1 == index:
                return

            index += len(DHCP_Protocol.magic_cookie)
            hex_count = self._length * 2;
            while True:
                code = int(payload[index:index + 2], 16)
                if DHCP_Protocol.option_pad == code:
                    index += 2
                    continue
                if DHCP_Protocol.option_end == code:
                    return
                length = int(payload[index + 2:index + 4], 16)
                value = payload[index + 4:index + 4 + length * 2]

                # set DHCP options
                if DHCP_Protocol.option_request_list == code:
                    self._option_55 = value
                elif DHCP_Protocol.option_message_type == code:
                    self._option_53 = DHCP_Protocol.get_message_type(
                        int(value))
                elif DHCP_Protocol.option_host_name == code:
                    self._option_12 = bytes.fromhex(value).decode()
                elif DHCP_Protocol.option_request_ip == code:
                    b = bytes.fromhex(value)
                    self._option_50 = socket.inet_ntoa(b)
                elif DHCP_Protocol.option_server_id == code:
                    b = bytes.fromhex(value)
                    self._option_54 = socket.inet_ntoa(b)

                index = index + 4 + length * 2

                if index + 4 > hex_count:
                    break

        @property
        def ciaddr(self):
            return self._ciaddr

        @property
        def chaddr(self):
            return self._chaddr

        @property
        def option_55(self):
            return self._option_55

        @property
        def option_53(self):
            return self._option_53

        @property
        def option_12(self):
            return self._option_12

        @property
        def option_50(self):
            return self._option_50

        @property
        def option_54(self):
            return self._option_54

if os.name == 'nt':
    class IPv4:
        # protocol
        protocol_UDP = 17

        def __init__(self, packet):
            self._ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0:20])

        def get_source_ip(self):
            return socket.inet_ntoa(self._ip_header[8])

        def get_dest_ip(self):
            return socket.inet_ntoa(self._ip_header[9])

        def get_protocol(self):
            return self._ip_header[6]


    class UDP():
        def __init__(self, packet):
            self._udp_header = struct.unpack('!HHHH', packet[20:28])

        def get_source_port(self):
            return self._udp_header[0]

        def get_dest_port(self):
            return self._udp_header[1]

        def get_length(self):
            return self._udp_header[2]


    class DHCP_Protocol(object):
        server_port = 67
        client_port = 68

        # DHCP options
        magic_cookie = '63825363'
        option_pad = 0
        option_host_name = 12
        option_request_ip = 50
        option_message_type = 53
        option_server_id = 54
        option_request_list = 55
        option_end = 255

        @staticmethod
        def get_message_type(value):
            message_type = {
                1: 'DHCPDISCOVER',
                2: 'DHCPOFFER',
                3: 'DHCPREQUEST',
                4: 'DHCPDECLINE',
                5: 'DHCPACK',
                6: 'DHCPNAK',
                7: 'DHCPRELEASE',
                8: 'DHCPINFORM'
            }
            return message_type.get(value, 'None')


    # length: number of bytes
    class DHCP():
        def __init__(self, packet, length):
            self._payload = packet[28:]
            self._length = length
            self._ciaddr = ''
            self._chaddr = ''
            self._option_55 = ''
            self._option_53 = ''
            self._option_12 = ''
            self._option_50 = ''
            self._option_54 = ''

        def parse_payload(self):
            # parse DHCP payload [0:44]
            #    ciaddr [Client IP Address]      : [12:16]
            #    yiaddr [Your IP Address]        : [16:20]
            #    siaddr [Server IP Address]      : [20:24]
            #    giaddr [Gateway IP Address]     : [24:28]
            #    chaddr [Client Hardware address]: [28:44]
            tmp = struct.unpack('!4s', self._payload[12:16])
            self._ciaddr = socket.inet_ntoa(tmp[0])
            self._chaddr = binascii.hexlify(self._payload[28:34]).decode()

        # DHCP options format:
        #     Magic Cookie + DHCP options + FF(end option)
        #     DHCP option format:
        #         code(1 byte) + length(1 byte) + value
        #     Pad and End option format:
        #         code(1 byte)
        def parse_options(self):
            find = False
            payload = binascii.hexlify(self._payload).decode()

            index = payload.find(DHCP_Protocol.magic_cookie)
            if -1 == index:
                return

            index += len(DHCP_Protocol.magic_cookie)
            hex_count = self._length * 2;
            while True:
                code = int(payload[index:index + 2], 16)
                if DHCP_Protocol.option_pad == code:
                    index += 2
                    continue
                if DHCP_Protocol.option_end == code:
                    return
                length = int(payload[index + 2:index + 4], 16)
                value = payload[index + 4:index + 4 + length * 2]

                # set DHCP options
                if DHCP_Protocol.option_request_list == code:
                    self._option_55 = value
                elif DHCP_Protocol.option_message_type == code:
                    self._option_53 = DHCP_Protocol.get_message_type(
                        int(value))
                elif DHCP_Protocol.option_host_name == code:
                    self._option_12 = bytes.fromhex(value).decode()
                elif DHCP_Protocol.option_request_ip == code:
                    b = bytes.fromhex(value)
                    self._option_50 = socket.inet_ntoa(b)
                elif DHCP_Protocol.option_server_id == code:
                    b = bytes.fromhex(value)
                    self._option_54 = socket.inet_ntoa(b)

                index = index + 4 + length * 2
                byte_count = index / 2

                if index + 4 > hex_count:
                    break

        @property
        def ciaddr(self):
            return self._ciaddr

        @property
        def chaddr(self):
            return self._chaddr

        @property
        def option_55(self):
            return self._option_55

        @property
        def option_53(self):
            return self._option_53

        @property
        def option_12(self):
            return self._option_12

        @property
        def option_50(self):
            return self._option_50

        @property
        def option_54(self):
            return self._option_54


class Host:
    def __init__(self, mac: str):
        self._mac = mac
        self._ip = None
        self._broadcasted_dhcp = False
        self._num_packets = 0
        self._seen = False

    def increase_packet_num(self) -> None:
        self._num_packets += 1

    def set_seen(self) -> None:
        self._seen = True

    def set_dhcp_seen(self) -> None:
        self._broadcasted_dhcp = True

    @property
    def mac(self) -> str:
        return self._mac

    @property
    def ip(self):
        return self._ip

    def set_ip(self, ip) -> None:
        self._ip = ip

    @property
    def broadcasted_dhcp(self) -> bool:
        return self._broadcasted_dhcp

    @property
    def num_packets(self):
        return self._num_packets

    @property
    def seen(self):
        return self._seen

    def __repr__(self):
        return '{} @ {} | DHCP seen: '.format(self.mac, self.ip,
                                              self.broadcasted_dhcp)
