from scapy.all import *

PACKETS_WITHOUT_DHCP = 5

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


# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


def get_requested_address(packet):
    if packet.options[0][1] != 3:
        raise ValueError('Packet {} is not DHCPREQUEST'.format(packet))

    requested_address = get_option(packet.options, 'requested_addr')
    return requested_address
