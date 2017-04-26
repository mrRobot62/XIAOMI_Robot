#!/usr/bin/python

# X... Pocket Knife

# TODO:
# Verschluesselung
# Ergebnis vom Command ausgeben

import sys
import socket
import struct
import hashlib
import argparse

# https://cryptography.io/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
_backend = default_backend()

TARGET_IP = ""
TARGET_PORT = 54321

parser = argparse.ArgumentParser(description=("Control Xiaomi Mi Home Wifi devices"))
parser.add_argument("-ip", type=str, help="IP or DNS-Name of the device")
parser.add_argument("-info", help="get info of the device", action="store_true")
parser.add_argument("-power", type=str, choices=["on", "off"], help="turn Air Purifier 'on' or 'off'")
parser.add_argument("-mode", type=str, choices=["auto", "silent","favorite"], help="set mode of Air Purifier to 'auto','silent' or 'favorite'")
parser.add_argument("-token", type=str, help="set token for cryption/encryption (only for experts)")
parser.add_argument("-cmd", type=str, help="encrypt given command and send to device (only for experts)")
parser.add_argument("-decode", type=str, help="decipher a given cipher with given token (only for experts)")

#parser.add_argument("--print-raw", action='store_true')
args = parser.parse_args()

class XiaomiPacket():
    def __init__(self):
        self.magic =      "2131".decode('hex')
        self.length =     "0020".decode('hex')
        self.unknown1 =   "FFFFFFFF".decode('hex')
        self.devicetype = "FFFF".decode('hex')
	self.serial   =   "FFFF".decode('hex')
        self.stamp =      "FFFFFFFF".decode('hex')
        self.checksum =   "ffffffffffffffffffffffffffffffff".decode('hex')
	self.data = ""
	self.token = ""

    def setRaw(self, raw):
        self.magic =      raw[ 0: 2]
        self.length =     raw[ 2: 4]
	self.unknown1 =   raw[ 4: 8]
	self.devicetype = raw[ 8:10]
        self.serial =     raw[10:12]
      	self.stamp =      raw[12:16]
	self.checksum =   raw[16:32]
        self.data =       raw[32:]

	if self.length=="0020".decode('hex'):
	    self.token=self.checksum
	return

    def updateChecksum(self):
        self.checksum = md5(self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.token+self.data)
        return

    def getRaw(self):
        if len(self.data)>0:
            self.updateChecksum()
	    raw = self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.checksum+self.data
            return raw
        else:
	    raw = self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.checksum
            return raw

    def getPlainData(self):
	plain = decrypt(self.token, self.data)
 	return plain

    def setPlainData(self,plain):
	self.data = encrypt(self.token, plain)
        length = len(self.data)+32
	self.length = format(length, '04x').decode('hex')

	self.updateChecksum()
	return

    def setHelo(self):
        self.magic =      "2131".decode('hex')
        self.length =     "0020".decode('hex')
        self.unknown1 =   "FFFFFFFF".decode('hex')
        self.devicetype = "FFFF".decode('hex')
        self.serial =     "FFFF".decode('hex')
        self.stamp =      "FFFFFFFF".decode('hex')
        self.checksum =   "ffffffffffffffffffffffffffffffff".decode('hex')
        self.data = ""
        self.token = ""
	return

    def findXiaomi(self):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(('', 0))
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	Packet  = XiaomiPacket()
	Packet.setHelo()

	sock.sendto(Packet.getRaw(), ('<broadcast>', TARGET_PORT))

	d = sock.recvfrom(1024)
	print d[1][0]
	return d[1][0]

    def printPacket(self,txt):
        txt=(txt[0:11]+"            ")[0:12]

	txt=txt+self.getRaw().encode('hex') 
	txt=txt[:160]
	print txt
        return

def md5(data):
    checksum = hashlib.md5()
    checksum.update(data)
    return checksum.digest()

def key_iv(token):
    key = md5(token)
    iv = md5(key+token)
    return (key, iv)

def encrypt(token, plaintext):
    key, iv=key_iv(token)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext)+padder.finalize()
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=_backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext)+encryptor.finalize()

def decrypt(token, ciphertext):
    key, iv = key_iv(token)
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=_backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(bytes(ciphertext))+decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_plaintext = unpadder.update(padded_plaintext)+unpadder.finalize()
    return unpadded_plaintext

def GetSessionInfo():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print('Failed to create socket')
        sys.exit()    

    try:
	PACKET  = XiaomiPacket()
	PACKET.setHelo()	
	#PACKET.printPacket('HELO')

	sock.sendto(PACKET.getRaw(), (TARGET_IP, TARGET_PORT))
	sock.settimeout(1.0)
	try:
	    d = sock.recvfrom(1024)
	except socket.timeout:
	    print "Timeout"
	    sys.exit()

	PACKET.setRaw(d[0])
	if args.token:
     	    PACKET.token=args.token.decode('hex')
	#PACKET.printPacket('HELO answer')
	if PACKET.devicetype.encode('hex')=="034c":
	    print "Device Type: Xiaomi Mi Robot Vacuum"
        elif PACKET.devicetype.encode('hex')=="00c4":
            print "Device Type: Xiaomi Smart Mi Air Purifier"
	else:
	    print "Device Type: "+PACKET.devicetype.encode('hex')
	print "Token:       "+PACKET.token.encode('hex')
	return PACKET
    except socket.error, msg:
	print('Error Code: '+str(msg[0])+' Messge: '+msg[1])
	sys.exit()

def SendRcv(PACKET):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print('Failed to create socket')
        sys.exit()

    try:
	#PACKET.printPacket('Send')
	#print PACKET.getPlainData()

        sock.sendto(PACKET.getRaw(), (TARGET_IP, TARGET_PORT))
	sock.settimeout(1.0)
        d = sock.recvfrom(1024)
	PACKET.setRaw(d[0])
	#print PACKET.getPlainData()
	#print PACKET.data.encode('hex')
        return
    except socket.error, msg:
        print('Error Code: '+str(msg[0])+' Messge: '+msg[1])
        sys.exit()
    return

#Packet.setPlainData('{"id":6148,"method":"get_prop","params":["aqi","led","mode","filter1_life","buzzer","favorite_level","temp_dec","humidity","motor1_speed","led_b","child_lock"]}')


if args.ip:
    TARGET_IP = args.ip
else:
    Packet  = XiaomiPacket()
    TARGET_IP = Packet.findXiaomi()


if args.decode:
    if not args.token:
	print "For this option the token argument is needed!"
	sys.exit()
    Packet  = XiaomiPacket()
    if args.decode.decode('hex')[0:2]=='!1':
        Packet.data=args.decode.decode('hex')[32:]
    else:
        Packet.data=args.decode.decode('hex')
    Packet.token=args.token.decode('hex')
    print Packet.getPlainData()

if args.info:
    Packet = GetSessionInfo()
    k = key_iv(Packet.token)

if args.power:
    Packet = GetSessionInfo()
    if Packet.devicetype.encode('hex')!="00c4": 
        print "ERROR: Air Purifier not recognized!"
	sys.exit()
    print args.power
    if args.power=="on":
        Packet.setPlainData('{"id":6149,"method":"set_power","params":["on"]}')
        SendRcv(Packet)
    else:
        Packet.setPlainData('{"id":6149,"method":"set_power","params":["off"]}')
        SendRcv(Packet)

if args.mode:
    Packet = GetSessionInfo()
    if Packet.devicetype.encode('hex')!="00c4": 
        print "ERROR: Air Purifier not recognized!"
        sys.exit()

    print args.mode
    if args.mode=="auto":
        Packet.setPlainData('{"id":6149,"method":"set_mode","params":["auto"]}')
        SendRcv(Packet)
    elif args.mode=="silent":
        Packet.setPlainData('{"id":6149,"method":"set_mode","params":["silent"]}')
        SendRcv(Packet)
    else:
        Packet.setPlainData('{"id":6149,"method":"set_mode","params":["favorite"]}')
        SendRcv(Packet)

if args.cmd:
    Packet = GetSessionInfo()
    Packet.setPlainData(args.cmd)
    SendRcv(Packet)
    print Packet.getPlainData()
