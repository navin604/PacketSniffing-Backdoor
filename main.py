from client import Client
from back_door import BackDoor
import sys


def shutdown():
    print("You must specify one argument -> CLIENT or SERVER")
    sys.exit()


def process_arg(arg):
    if len(arg) != 1:
        shutdown()
    elif arg[0] == "SERVER":
        return True
    elif arg[0] == "CLIENT":
        return False
    else:
        shutdown()


def run_server():
    B = BackDoor()


def run_client():
    C = Client()


def main():
    mode = process_arg(sys.argv[1:])
    if mode:
        run_server()
    else:
        run_client()


if __name__ == "__main__":
    main()
