#!/usr/bin/python
################################################################
# XIAOMI vaccum cleaner script
#
#
# (c) LunaX
# History
# 15-MAR-17   commands: "silent, standard, power, find"
# 13-MAR-17   initial
################################################################

import socket
import sys,os,time
import codecs
import argparse

UDP_IP = '192.168.0.107'
UDP_PORT = 54321
INET_ADDR = (UDP_IP,UDP_PORT)

verbose = 0
xiaomi_cmd = {
#    "header":"2131005000000000034c941d58",
# --- alter Stand vor der WLAN Umstellung - funktioniert aber einwandfrei
#    "start": "2131005000000000034c941d58c482320c0aea1cd613644b1a029275b05318bca72ffc758f7767603ce014ba871abc67ac9d4fb83be5ac273758fe3bedf5bd6297cf950730f2c759b4b634da4d3b2105",
#    "stop":  "2131005000000000034c941d58c5b4778eaae116bf0551a500b4b297ddb092d5ecb7c9b4ae005c46a99525aa3420e245975bc44e4eb6b8d277cbd3eebd85ccce377ab9a75593940eb702f3fb486609e6",
#    "home":  "2131005000000000034c941d58c671bb02bfbec414f6fdc9a065be48f7ba1430e4d6d057041ac1c24917bfa39049734f521e4eb577dca735f18fec74e2ed02850fbbae786b355016f2ef0c1d1c6f3aad",
#    "reset": "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

    "start": "2131005000000000034c941d58c84f96f10159e5416ab7edb2bcba98dbb72dfc5473f997f04e1c575ccc5d794ff6576072df487b6a7602b15f3087f743f82a2651c61ebf84b9c63b9a41671291bfc51b",
    "stop":  "2131005000000000034c941d58c84f9dac99c1569b214d7a24fb5137c5763aed32eaff27e4f0b9d8dbb50a7794f08d91b9b8110d24324e49800739476828486ed396df5131cca625843b540c5c76ab9f",
    "home":  "2131005000000000034c941d58c8564af356c1ab5fc4c811b241955b8b7401db7a214d0e6aea7c39508b375202f6d77eaa28ae62e91596a52f4e59e074932f6f188a407736eb89de2c365c546cde7556",
    "reset": "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

    "pause":   "",
    "find":    "2131005000000000034c941d58c8e5028ce6fbad550f7f197abef3b9704b32558becadc58cfd1fe65dc2f85dc243a3077130dc9a3310e82c73ea904d617c49dac9955233109737e311654b78e25ec449",
    "silent":  "2131006000000000034c941d58c85f0a64098a6d9f1a7398735a74cba679dfc2edb7606024080b88868e11e93cc3413425615901d96a8b69754563dd706bb772fe7357c392fd79c919da61a3f9078cb56490663b351ad704d750dd59e7978960",
    "standard":"2131006000000000034c941d58c85c915e90fba8b113f76721d9479c2a453c2eddb1bc068cd65ee899fd3ccda3ed00d3fb88a59e7c8ac82840e4d6f53b3e9c9db3e3820d14987decef98de2c26105e2fc0d02eb36e1b7350456f107b473d0fb9",
    "power":   "2131006000000000034c941d58c85dd2cf7e6464b0b7a0af63978e5d695498aadaeb8666ca0b47290ee5c6ac7cfde4c5760ddf82196016e484bd22137ed47b8121d5a79b19f364a62a363c253bfa5af895f94e1be81e952e965d7aea937a2b55",
}

def send_udp(udp_msg):
    '''
        send an udp message to ip and port address
    '''
    global verbose
    message_to_send = codecs.decode(udp_msg, "hex_codec")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message_to_send, INET_ADDR)
    except:
        print "ERROR: UDP send failure - can't establish udp connection"
        os._exit(1);
    finally:
        if verbose > 1:
            print ("UDP-Dest: \t{0}".format(INET_ADDR))
            print ("UDP-Message:\t{0}".format(udp_msg))
        if verbose > 0:
            print ("send UDP message")
    pass

def receive_udp():
    global verbose
    pass

def Do_Command(cmd, wait):
    '''
        create an UDP command for XIAOMI robot

        a command is a combination of a header and a command sequence
    '''
    global xiaomi_cmd, verbose
#    msg = xiaomi_cmd['header']
    msg = ""
    if cmd == "start":
        msg = xiaomi_cmd['start']
    if cmd == "stop":
        msg = xiaomi_cmd['stop']
    if cmd == "home":
        msg = xiaomi_cmd['home']
    if cmd == "pause":
        msg = xiaomi_cmd['pause']
    if cmd == "siltent":
        msg = xiaomi_cmd['silent']
    if cmd == "standard":
        msg = xiaomi_cmd['standard']
    if cmd == "power":
        msg = xiaomi_cmd['power']
    if cmd == "find":
        msg = xiaomi_cmd['find']
    if cmd == "reset":
        reset = xiaomi_cmd['reset']

    if verbose > 1:
        print ("Do_Command ({})".format(cmd))

    # -- sometimes a command will not be accepted
    # -- to avoid this a reset command at beginning
    if wait < 1:
        wait = 0
    if wait > 60:       # maximum 60 secs wait between a command
        wait = 60
    send_udp(xiaomi_cmd['reset'])
    time.sleep(1)
    send_udp(msg)
    if wait > 0:
        time.sleep(wait)
    pass

def main():
    global UDP_IP, UDP_PORT, INET_ADDR, verbose
    parser = argparse.ArgumentParser(description='XIAOMI vaccum cleaner')
    parser.add_argument('-i','--ip',
        action='store_true',
        help='UDP destination ip' )

    parser.add_argument('-p','--port',
         action='store_true',
         help='UDP destination port' )
    parser.add_argument('-w','--wait',
         type=int,
         help='wait in seconds between two commands' )

    parser.add_argument('-c', '--cmd',
         required=True,
         nargs='*',
#         choices=['stop','start','pause','silent','standard','power','home'],
         choices=['stop','start','home','silent','standard','power','find'],
         )
    parser.add_argument('-v', '--verbose',
         action='count',
         help='verbose output' )

    args = parser.parse_args()

    verbose = 0
    command = ""
    wait = 0;
    if args.verbose:
        verbose=args.verbose
    if args.ip:
        UDP_IP = args.ip
    if args.port:
        UDP_PORT = args.port
    if args.wait:
        wait = args.wait
    command = args.cmd

    msg = "UDP_IP:\t\t{}".format(UDP_IP)
    msg = msg + "\nUDP_PORT:\t{}".format(UDP_PORT)
    msg = msg + "\nCOMMAND:\t{}".format(command)
    msg = msg + "\nVerbose:\t{}".format(verbose)
    if (verbose > 1):
        print (msg)

    #-------------------------------------------
    # handle multiple command list
    #-------------------------------------------
    for cmd in command:
        Do_Command(cmd, wait)
        time.sleep(2)

    if verbose > 0:
        print "finish"

#------------------------------------------------------
if __name__ == '__main__':
    main()

os._exit(0)



'''
XIAOMI UDP Packets

----------------------------------------
Topic JOYSTICK      in work
----------------------------------------
T
Stop-Condition: HOME than STOP

after first JOY-START command only every second 144-Bytes JOY-MOVE command
do something


Start-Sequence
S: 80, R: 64 - brush on, hoover on, no movement
2131005000000000034c941d58c862458e80867f678cc917fde09b0942fe56ff842ad329ab6c2a936618dbfd35cc0b08b188fb05cc0b349465fe4ce8ad89f9288dfb914bb6bd5c42fbd2642344507e73
S: 144 - nothing
21 31 00 90 00 00 00 00 03 4c 94 1d 58 c8 63 2e 4b e6 e9 7d 8a 2d 14 4c ca fc 8d 43 b7 52 98 8f 4a e7 9e 4c cb 6f 0b 7e bc 78 fb db 31 2b ce 22 74 72 d4 a8 c1 b8 0c 39 00 c3 27 af 48 df e7 04 91 f4 57 cc 7b 82 cc cf 83 bc 3d 23 15 3a 42 c7 b1 2d 60 02 fe d0 be 01 f2 24 5e 95 f4 1c 7e 32 b0 68 90 b8 c3 26 5c d9 72 41 63 4e 98 73 ed 96 ba 88 5d d6 e6 e0 9e 41 29 24 60 87 cc 23 af ae e7 a6 b2 d9 0c dd d1 5b 6e 3d 85 57 26 fd 8c e0
S: 144 - 1. forward ca. 30cm (fast)
21 31 00 90 00 00 00 00 03 4c 94 1d 58 c8 63 39 c2 2d 87 94 c1 bb 0f 39 76 62 e9 97 9e 24 48 f0 35 9c 41 6a 4a e3 41 22 e5 90 ec 6b 7b 55 65 23 bf ee 98 82 21 49 f2 65 4f 9e e5 e3 27 bf ae 1f 17 4d 5c 78 e6 5e d0 97 2a 7f 00 03 87 c8 2a 1f cf c2 99 cc 78 89 d6 c2 7c 4a e3 27 0c f3 f1 75 76 f9 06 49 ed e2 8f 9a 19 28 5d 83 dc 69 a4 35 bc 7c 1a 1f a0 61 e2 50 92 42 fd ce 73 f4 e7 36 f5 67 c0 aa 19 26 ad 99 a6 ca 91 4e fc e9 4f b9
S: 144 - nothing
21 31 00 90 00 00 00 00 03 4c 94 1d 58 c8 63 39 8d f8 06 46 53 db d7 3a f6 44 e5 f2 7b 3d e0 bf e2 9f db 1e 64 ef 8b e3 85 c1 09 67 ba cf ca fc 0a 05 7a 4f b5 5c 13 b8 be af 56 2c 45 47 ee 6e 21 97 d7 e7 f4 ad dd d4 a5 fd 88 39 96 34 84 23 09 68 a5 d9 ea 9d 94 ee cd 1f 70 84 ab 4c f3 8e a6 ae 8c f3 a1 89 2e 7e 66 44 7e b6 a7 67 6e c2 40 8a b2 04 0e 42 cd 89 11 f7 3b b4 17 41 76 bc 4d f0 3a fc 92 fe 8a 18 d8 66 a6 7a d5 5a d4 33
S: 144 - 2. forward ca. 30cm (fast)




'''
