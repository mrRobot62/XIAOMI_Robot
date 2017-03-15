#!/usr/bin/python

import socket
import sys
import codecs

UDP_IP = '192.168.0.107'
UDP_PORT = 54321
INET_ADDR = (UDP_IP,UDP_PORT)

action = str(sys.argv[1])
#header = "213100500000000002f2c97b5872"
header =  "2131005000000000034c941d58c48232"
#          "21 31 00 50 00 00 00 00 03 4c 94 1d 58 c4 82 32 0c 0a ea 1c d6 13 64 4b 1a 02 92 75 b0 53 18 bc a7 2f fc 75 8f 77 67 60 3c e0 14 ba 87 1a bc 67 ac 9d 4f b8 3b e5 ac 27 37 58 fe 3b ed f5 bd 62 97 cf 95 07 30 f2 c7 59 b4 b6 34 da 4d 3b 21 05"
if action == "start":
   #message_to_send = header + "2fd096c280746dc2091bad1d30c49ce74da6c88492a5c0e7c427ad0b4ca98c3b08ea35e67b29dddd8624dd1f2ea46ced68fce3c5b7fef8e89eef60b3c777f43a5622"
   message_to_send = header + "0c0aea1cd613644b1a029275b05318bca72ffc758f7767603ce014ba871abc67ac9d4fb83be5ac273758fe3bedf5bd6297cf950730f2c759b4b634da4d3b2105"
if action == "pause":
   message_to_send = header + "3080fdc4d67fe6fd048b63eb6d2cee5f285f8fec54c2e3bc5486641ec620bae160e9717af4d17ce3c0265bcb807644dae475bcaaf089391f6f76fa85b31396af3e26"

if action == "home":
   message_to_send = header + "30e4006525a8e0420c337fbc2bfc1741369bb9760685aafe250790ee4ea8bda3aafbdfaa47ae0e8518503530fb72579fe8cf334c6a6fcd4cbc94bfb310f64163a80a"

if action == "find":
   message_to_send = header + "29d24b61f9c826221c4c7a68be606ff324f81fcc282e18fa679d0506e3e805cbfe56323f2dc292f5d609d20782cb6df1abe3b4a9ce062da42e3371126048c2213b3e"

message_to_send = codecs.decode(message_to_send, "hex_codec")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(message_to_send, INET_ADDR)
