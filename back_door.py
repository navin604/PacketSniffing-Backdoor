from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import libpcap as pcap


class BackDoor:
    def __init__(self):
        print("Backdoor has been initiated")
        self.key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
        self.iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'
        self.flag = [('flag', b'\x60\x60\x60')]
        self.port = 53

    def start(self):
        print("Starting")
        self.sniff_init()


    def sniff_init(self):
        pass

    def process_packets(self, header, packet):
        print(header, packet)

    def filter_packets(self):
        pass

    def decrypt_data(self):
        pass


