import webbrowser
import socket
import time
import struct
import os

if os.name != 'nt':
    import fcntl


def open_browser(ip: str) -> None:
    return webbrowser.open_new_tab('http://{}'.format(ip))


def check_port_open(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0


def convert_hex_str_to_int_str(hexstr):
    pool = []
    for x, y in zip(hexstr[0::2], hexstr[1::2]):
        pool.append(str(int(x + y, 16)))
    return ','.join(pool)


def convert_hex_str_to_mac(hexstr):
    pool = []
    for x, y in zip(hexstr[0::2], hexstr[1::2]):
        pool.append(x + y)
    return ':'.join(pool)


def get_time():
    return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime())


def get_netmask(ifname: bytes) -> bytes:
    return fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099,
                       struct.pack('256s', ifname))[20:24]


def get_ip_address(ifname: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24]


def get_subnet(addr: str, mask: str) -> str:
    msplit = mask.split('.')
    asplit = addr.split('.')
    res = []
    for i in range(4):
        res.append(str(int(asplit[i]) & int(msplit[i])))
    return '.'.join(res)
