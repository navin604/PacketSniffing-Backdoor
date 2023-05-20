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

    def start(self):
        self.create_process()
        self.get_input()

    def get_input(self):
        while True:
            name = input("Enter command:")
            print(name)

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



