import os
import argparse

from scapy.all import sniff, conf, get_if_hwaddr, get_if_list, get_if_addr

if os.name == 'nt':
    from scapy.all import get_windows_if_list as _get_if_list
elif os.name == 'posix':
    from scapy.all import get_if_list as _get_if_list

from scapy import layers

from common import Host, PACKETS_WITHOUT_DHCP, get_requested_address
from utils import get_time, check_port_open

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--detail', action='store_true',
                        help='show all packets to specified iface')
    parser.add_argument('-i', '--interface',
                        help='specify interface to work with')
    parser.add_argument('--show-interfaces', action='store_true',
                        help='get list of all available ifaces')
    args = parser.parse_args()

    interface = args.interface or conf.iface
    interface_hwaddr = get_if_hwaddr(interface)

    known_hosts = {}

    if args.show_interfaces:
        print('{:20} {:20} {:20}'.format('NAME', 'MAC', 'IP'))
        if os.name == 'posix':
            for iface in _get_if_list():
                print('{:20} {:20} {:20}'.format(iface, get_if_hwaddr(iface),
                                                 get_if_addr(iface)))
        elif os.name == 'nt':
            for iface in _get_if_list():
                name = iface.get('name')
                print('{:20} {:20}'.format(name, iface.get('mac')))
        exit(0)

    if args.detail:
        print('Capturing all packets to interface {}'.format(interface))
    else:
        print('{:10} {:30} {:20} {:20}'.format('Type', 'Time', 'MAC', 'IP'))

    while True:
        packet = sniff(count=1, iface=args.interface,
                       lfilter=lambda d: d.src != interface_hwaddr)[0]

        source_mac = packet.getlayer(layers.l2.Ether).src
        dest_mac = packet.getlayer(layers.l2.Ether).dst

        ip_layer = packet.getlayer(layers.inet.IP)

        if not ip_layer:
            continue

        source_ip = ip_layer.src
        dest_ip = ip_layer.dst

        host = Host(source_mac)
        host.set_ip(source_ip)

        # more unique identifier
        host = known_hosts.setdefault(host.mac + host.ip, host)
        host.increase_packet_num()

        dhcp_layer = packet.getlayer(layers.dhcp.DHCP)

        if dhcp_layer:
            try:
                requested_address = get_requested_address(dhcp_layer)
            except ValueError:
                print('Caught non-DCHPREQUEST packet')
                continue

            host.set_ip(requested_address)
            host.set_dhcp_seen()

        now = get_time()

        if args.detail:
            print(packet.summary())
        else:
            if host.num_packets > PACKETS_WITHOUT_DHCP and (
                    not host.broadcasted_dhcp and not host.seen):
                print('STATIC {:30} {:20} {:20}'.format(
                    now, host.mac, host.ip
                ))
                host.set_seen()
                if check_port_open(host.ip, 80):
                    print('Can open browser at http://{}'.format(host.ip))

            if host.broadcasted_dhcp and not host.seen:
                print(
                    'DYNAMIC {:30} {:20} {:20}'.format(now, host.mac, host.ip))
                host.set_seen()
                if check_port_open(host.ip, 80):
                    print('Can open browser at http://{}'.format(host.ip))
