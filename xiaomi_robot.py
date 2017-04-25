#!/usr/bin/python

# X... Pocket Knife
################################################################
# XIAOMI vaccum cleaner script
#
# based on X... Pocket Knife from ioBroker forum
# adapted and with more functionality

# Version 0.1
#
# (c) LunaX
# History
# 25-APR-17   -power parameter implemented
# 20-MAR-17   initial
#
# Copyright 2017 Lunax
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is furnished
# to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
################################################################

import sys
import socket
import struct
import hashlib
import argparse
import logging

# https://cryptography.io/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
_backend = default_backend()

TARGET_PORT = 54321
TOKEN="<insert your 16Bytes token here"

parser = argparse.ArgumentParser(description=("Control Xiaomi Mi Home Wifi devices"))
grp0 = parser.add_mutually_exclusive_group()
grp1 = parser.add_mutually_exclusive_group()

parser.add_argument("-ip", type=str, help="IP or DNS-Name of the device")
parser.add_argument("-token", type=str, help="set token for cryption/encryption (only for experts)")
parser.add_argument("-decode", type=str, help="decipher a given cipher with given token (only for experts)")
#parser.add_argument("-power", type=int,  help="set fan-power in a range of 0...100. If 0 then MIN-Power, 1=Standard, 2=Max. All values above 2 are real values for fan-power")
#parser.add_argument("-powerX", type=int, choices=xrange(10,100), help="set fan-power to an individual value {10...100}")

grp0.add_argument("-info", help="get info of the device", action="store_true")
grp0.add_argument("-cmd", type=str, help="set a command from table => start, pause, charge, get_status, fan_power1, fan_power2, fan_power3, find")
grp0.add_argument("-raw_cmd", type=str, help="encrypt given command and send to device (only for experts)")
grp0.add_argument("-list", help="list all available xiaomi commands",action="store_true")
grp0.add_argument("-power", default=1, type=int, help="set fan-power in a range of 0...100. If 0 then MIN-Power, 1=Standard, 2=Max. All values above 2 are real values for fan-power")

grp1.add_argument("-v","--verbose", action="store_true", help="verbose output. If not set loglevel = INOF -v (DEBUG)" )
grp1.add_argument("-q","--quiet", action="store_true", help="no output, need for ALEXA functionality")

log = logging.getLogger("xiaomi")
logging.basicConfig()

COMMANDS = {
    "start":'{"id":%1,"method":"app_start"}',
    "pause":'{"id":%1,"method":"app_pause"}',
    "stop":'{"id":%1,"method":"app_pause"}',
    "charge":'{"id":%1,"method":"app_charge"}',
    "home":'{"id":%1,"method":"app_charge"}',
    "status":'{"id":%1,"method":"get_status"}',
    "fan_power0":'{"id":%1,"method":"set_custom_mode","params":[35]}',
    "fan_power1":'{"id":%1,"method":"set_custom_mode","params":[60]}',
    "fan_power2":'{"id":%1,"method":"set_custom_mode","params":[100]}',
    "fan_powerX":'{"id":%1,"method":"set_custom_mode","params":[%2]}',
    "power":'{"id":%1,"method":"set_custom_mode","params":[%2]}',
    "find":'{"id":%1,"method":"find_me","params":[""]}',
}


silent_mode = False

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

    def md5(self, data):
        '''
        create a MD5 checksum from data.
        Return checksum
        '''
        checksum = hashlib.md5()
        checksum.update(data)
        return checksum.digest()

    def key_iv(self, token):
        '''
        create a key
        '''
        key = self.md5(token)
        iv = self.md5(key+token)
        return (key, iv)

    def updateChecksum(self):
        self.checksum = self.md5(self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.token+self.data)
        return

    def encrypt(self, token, plaintext):
        '''
        encrypt plaintext with token and return encrypted message
        '''
        key, iv=self.key_iv(token)
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext)+padder.finalize()
        cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=_backend)
        encryptor = cipher.encryptor()
        return encryptor.update(padded_plaintext)+encryptor.finalize()

    def decrypt(self, token, ciphertext):
        '''
        decrypt an encrypted data sequence with the token key/iv pair
        '''
        key, iv = self.key_iv(token)
        cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=_backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(bytes(ciphertext))+decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_plaintext = unpadder.update(padded_plaintext)+unpadder.finalize()
        return unpadded_plaintext

    def getRaw(self):
        if len(self.data)>0:
            self.updateChecksum()
            raw = self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.checksum+self.data
            return raw
        else:
            raw = self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.checksum
            return raw

    def getPlainData(self):
        '''
        return human readable data (JSON)
        '''
        plain = self.decrypt(self.token, self.data)
        return plain

    def setPlainData(self,plain):
        '''
        encrypt the given plain JSON format data
        '''
        self.data = self.encrypt(self.token, plain)
        self.length = len(self.data)+32
        self.length = format(self.length, '04x').decode('hex')
        self.updateChecksum()
        return

    def setHelo(self):
        '''
        configure a HELO (Hello) message
        '''
        self.magic =      "2131".decode('hex')
        self.length =     "0020".decode('hex')
        self.unknown1 =   "FFFFFFFF".decode('hex')
        self.devicetype = "FFFF".decode('hex')
        self.serial =     "FFFF".decode('hex')
        self.stamp =      "FFFFFFFF".decode('hex')
        self.checksum =   "ffffffffffffffffffffffffffffffff".decode('hex')
        self.data = ""
        self.token = ""
        self.raw_token = ""
        return

    def getHelo(self):
        return self.magic+self.length+self.unknown1+self.devicetype+self.serial+self.stamp+self.checksum

#------------------------------------------------------------------------------
class Xiaomi():
    def __init__(self, ip=None):
        self.PACKET = XiaomiPacket()
        self.token = ""
        self.raw_token = TOKEN
        self.IP = ip
        self.counter = 1000

    def getXiaomiPacket(self):
        if self.PACKET == None:
            self.PACKET = XiaomiPacket()
        return self.PACKET

    def setToken(self, token):
        self.PACKET.token=args.token.decode('hex')
        #self.PACKET.token=token.decode('hex')
        self.token = token
        self.raw_token = token
        log.debug("setToken: {}".format(token))

    def setIP(self, ip):
        '''
        set an ip address for the xiaomi device. If parameter IP is none,
        system search in local network a device.
        '''
        if ip:
            log.debug("Set IP \t ({})".format(ip))
            self.IP = ip
        else:
            log.debug("search a xiaomi device...")
            self.IP = self.findXiaomiDevice()
            #log.info("{:15}: ({})".format("device found at" ,self.IP))

    def listCommandSet(self):
        for c in COMMANDS.keys():
            log.info("Command: {} => {}".format(c,COMMANDS[c]))

    def findXiaomiDevice(self):
        '''
        try to find a xiaomi device in the local network.
        If several devices are available this method return the first found
        '''
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            log.setLevel(logging.ERROR)
            log.error("Failed to create upd socket")
            sys.exit(1)

        try:
            sock.bind(('', 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            self.PACKET.setHelo()
            sock.sendto(self.PACKET.getRaw(), ('<broadcast>', TARGET_PORT))
            sock.settimeout(5.0)
            #
            #
            d = sock.recvfrom(1024)
        except socket.error:
            log.setLevel(logging.ERROR)
            log.error("Timeout for findXiaomiDevice. Try it again")
            sys.exit(2)

        return d[1][0]


    def getSessionInfo(self):
        '''
        open a udp session with the xiaomi device on given IP address

        1)  first send a HALO-message
        2)  wait for resonse
        3)
        '''
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            log.setLevel(logging.ERROR)
            log.error('Failed to create socket')
            sys.exit(1)

        try:
            self.PACKET=self.getXiaomiPacket()
            log.debug("XiaomiPacket initialized {}".format(self.PACKET))
            if self.IP == "" or self.IP == None:
                self.IP = self.findXiaomiDevice()
                log.info("Found device at IP ({})".format(self.IP))
            self.PACKET.setHelo()
            sock.sendto(self.PACKET.getRaw(), (self.IP, TARGET_PORT))
            sock.settimeout(1.0)
            try:
                d = sock.recvfrom(1024)
                log.debug ("Xiaomi => Host : \t ({})".format(d[0]))
                #print "Receive ({}) IP/Port ({})".format(d[0], d[1] )
            except socket.timeout:
                log.setLevel(logging.ERROR)
                log.error("Timeout in getSessionInfo()")
                sys.exit(2)

            self.PACKET.setRaw(d[0])
            if args.token:
                self.PACKET.token=args.token.decode('hex')

            log.info("*********************************************************************************")
            if self.PACKET.devicetype.encode('hex')=="034c":
                log.info("{:15}: {:25} ID({})".format("Device Type","Xiaomi Mi Robot Vacuum", self.PACKET.devicetype.encode('hex')))
            #
            elif self.PACKET.devicetype.encode('hex')=="00c4":
                log.info("{:15}: {:25} ID({})".format("Device Type", "Xiaomi Mi Air Purifier", self.PACKET.devicetype.encode('hex')))
            else:
                log.info("{:15}: {:25} ID({})".format("Device Type","unknown", self.PACKET.devicetype.encode('hex')))
            #
            log.info("{:15}: {:25} ID({})".format("IP-Address", "", self.IP))
            log.info("{:15}: {:25} ID({})".format("Token", "", self.token))
            log.info("{:15}: {:25} ID({})".format("encoded token", "", self.PACKET.token))
            log.info("*********************************************************************************")
            log.info("")
            if (args.verbose):
                self.listCommandSet()
            return self.PACKET

        except socket.error, msg:
            log.setLevel(logging.ERROR)
            log.error('Receive error {}'.format(socket.error))
            sys.exit(1)

    def SetPower(self, value):
        value = self.constrain(value,0,100)
        if (value == 0):
            command = self._getCommand("fan_power0")
        elif (value == 1):
            command = self._getCommand("fan_power1")
        elif (value == 2):
            command = self._getCommand("fan_power2")
        #
        if (value > 2):
            command = self._getCommand("fan_powerX")
            command = command.replace("%2",str(value))
        #
        log.debug("{:25}: CMD({})".format("HOST => XIAOMI", command))
        self.PACKET.setPlainData(command)
        log.debug("send power command to {}".format(self.IP))
        self.SendRcv(command)
        pass

    def SendCmd(self, cmd, info=False):
        if info:
            self.getSessionInfo()
        if cmd:
            log.debug("prepare command...")
            command = self._getCommand(cmd)
            log.debug("raw command ({})".format(command))
            if command:
                #log.info("prepare and send HELO message...")
                #self._sendHELO()
                log.debug("set data command...")
                self.PACKET.setPlainData(command)
                log.debug("send command to {}".format(self.IP))
                self.SendRcv(command)
            else:
                log.setLevel(logging.ERROR)
                log.error("Command not found ({})".format(cmd))
                sys.exit(1)
        else:
            log.setLevel(logging.ERROR)
            log.error("you have to set a command value if you use -cmd param")
            sys.exit(1)

    def _sendHELO(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            log.setLevel(logging.ERROR)
            log.error('Failed to create socket')
            sys.exit(1)
        try:
            # create a HELO message
            log.debug("prepare HELO-Message")
            # create helo message
            self.PACKET.setHelo()
            # send this message via udp
            log.debug("send HELO-Message to {}".format(self.IP))
            log.debug("{:25}: CMD({})".format("HOST => XIAOMI", ""))
            sock.sendto(self.PACKET.getRaw(), (self.IP, TARGET_PORT))
            # if after one second no response go into timeout
            sock.settimeout(1.0)
            try:
                d = sock.recvfrom(1024)
                # save data to structure
                self.PACKET.setRaw(d[0])
                log.info("XIAOMI => HOST : RECV ({})".format(self.PACKET.getPlainData()))
            except socket.timeout:
                log.setLevel(logging.ERROR)
                log.error("timeout for HELO message")
                sys.exit(2)

        except socket.error, msg:
            log.setLevel(logging.ERROR)
            log.error("Socket error: {} / {}".format(str(msg[0], msg[1])))

    def _getCommand(self,cmd):
        '''
        search the real xiaomi command in our list. If user command not found
        return the stop command (for safty issues)

        set the internal counter number
        '''
        try:
            command = COMMANDS[cmd]
        except Exception:
            log.setLevel(logging.ERROR)
            log.error("seems you used an unknown command => -cmd {}".format(cmd))
            sys.exit(1)

        if command == None:
            command = COMMANDS["stop"]

        command = command.replace("%1",str(self.counter))
        log.debug ("raw {} -> {}".format(COMMANDS[cmd],command))
        self.counter = self.counter + 1
        return command

    def SendRcv(self,cmd=None):
        #print "--> (1)"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            log.setLevel(logging.ERROR)
            log.error('Failed to create socket')
            sys.exit(1)

        try:
            # if a command is set by parameter, use it
            # if not use last command
            #if cmd:
            #    self.PACKET.setPlainData(cmd)
#            log.debug("{:25}: CMD: {:80}".format("SendRcv", self.PACKET.getPlainData()))
            # send data to xiaomi
#            log.debug("send packet and wait for receive...")
            #print "Token: " + self.PACKET.token
            sock.sendto(self.PACKET.getRaw(), (self.IP, TARGET_PORT))
            sock.settimeout(2.0)
            d = sock.recvfrom(1024)
            # read received data from xiaomi
            # save data into structure
            self.PACKET.setRaw(d[0])
            log.info ("SendRcv Xiaomi => Host :\nData:({})".format(self.PACKET.getPlainData()))
            #print "--> " + self.PACKET.getPlainData()
            return

        except socket.error:
            log.setLevel(logging.ERROR)
            log.error("Timeout error during sending the command {}".format(self.PACKET.getPlainData()))
            #print "--> timeout"
            sys.exit(2)
        return

    def constrain(self, value, min, max):
        if value < min:
            return min
        if value > max:
            return max
        return value

#Packet.setPlainData('{"id":6148,"method":"get_prop","params":["aqi","led","mode","filter1_life","buzzer","favorite_level","temp_dec","humidity","motor1_speed","led_b","child_lock"]}')
if __name__ == '__main__':
    xiaomi = Xiaomi()
    log.setLevel(logging.INFO)
    log.propagate=True

    if args.quiet:
        #print "-quiet"
        log.setLevel(logging.CRITICAL)
        #log.propagate = False

    if args.verbose:
        print "-verbose"
        log.setLevel(logging.DEBUG)
        log.propagate = True

    if args.ip:
        xiaomi.setIP(args.ip)
    else:
        # search a device
        xiaomi.setIP(None)

    if args.token:
        xiaomi.setToken(args.token)
    else:
        # use default TOKEN
        xiaomi.setToken(TOKEN)

    if args.info:
        xiaomi.getSessionInfo()
        sys.exit(0)

    if args.list:
        xiaomi.listCommandSet()
        sys.exit(0)

    if args.power:
        xiaomi.SetPower(args.power)

    if args.cmd:
        #if args.quiet == False :
            #
            # only if something is send to console, than show SessionInfo
        xiaomi.getSessionInfo()
        #
        #print xiaomi.token
        xiaomi.SendCmd(args.cmd)
