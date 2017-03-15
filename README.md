XIAOMI Vaccum cleaner robot

Python script to use this robot

--------------------------------------------------------------------------
Important notes:
--------------------------------------------------------------------------
1)  all commands must be sniffed via Wireshark for you own
2)  if you work with wireshark use this filter to find you own commands
    (data.len == 80 || data.len == 64 || data.len == 96  || data.len == 144) && (ip.proto == 17)


Using this tool:  

it is possible to send several commands in a sequence to the bot
examples:  
./xiaomi_vaccum_cleaner_script.py --cmd find start standard
First send FIND-command, than start robot cleaning and set hoover to standard

./xiaomi_vaccum_cleaner_script.py -vv --cmd find start standard
same as above but with verbose-verbose output

./xiaomi_vaccum_cleaner_script.py -vv -w 10 --cmd find start standard
same as above but wait 10secs between every command

./xiaomi_vaccum_cleaner_script.py -i 192.189.8.100 -vv --cmd find start standard
same as above but use new IP-Addrress as in script

-------------------------------------------------------------------------------

usage: xiaomi_vaccum_cleaner_script.py [-h] [-i] [-p] [-w WAIT] -c
                                       [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]]
                                       [-v]

XIAOMI vaccum cleaner

optional arguments:
  -h, --help            show this help message and exit
  -i, --ip              UDP destination ip
  -p, --port            UDP destination port
  -w WAIT, --wait WAIT  wait in seconds between two commands
  -c [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]], --cmd [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]]
  -v, --verbose         verbose output

  -------------------------------------------------------------------------------

############################################################################
HowTo sniff you XIAOMI robot
############################################################################
Preconditions:
1)  download and install "WireShark" on your pc
2)  download and install "PaketSender" on your pc
3)  install an ANDROID emulator on your pc (MAC OS => BlueStack)
    3.1) install XIAOMI MI application
    3.2) configure the application
    3.3) test application if robot works - IMPORTANT !!!!!
4)  Start Wireshark
5)  setup network card to sniff (e.g. WiFI)
6)  insert into filter text field this filter criteria
(data.len == 80 || data.len == 64 || data.len == 96  || data.len == 144) && (ip.proto == 17)
7)  Start sniffing (icon upper left blue shark fin)
8)  go to android app and go to main screen (MAP is shown) - do nothing
9)  you should see packets in Wireshark
10) click middle button (CLEAN) 1x time - wait until robot moves
11) click middle button again (STOP) - robot should stop
12) go to wireshark and stop recording (red square)
13) now you should see all packetes from app to robot and answer from robot

Short introduction into UDP Packets
PING/CARD command:  Host send every second 80Bytes, Robot return 256 Bytes
(this packets can be ignored)

Normal commands:  host sends 80Bytes, robot answer: 64Bytes
(start,stop,find,home)

Power commands: Host: 96 Bytes, Robot: 64Bytes
(silent, standard, power)

Joystick commands: Host: 144 Bytes, Robot: 64Bytes
(not implemented yet)  

14) to find YOUR START-Command, find a 80/64 Byte sequence.
    Wireshark combine both (send & receive with a bracket (left side)).
15) copy only DATA-Packet (80 Bytes)
    these packets start every time with HEX: 213100xx
    xx = Number of Bytes, for 80Bytes = 50, 96Bytes = 60, ...

16) start PaketSender
17) insert 80Byte packet in HEX-Field
18) click SAVE-Button
19) click SEND-Button
20) IMPORTANT:
    in below log table you must see:
    first:    your SEND udp package
    second:   a 64 Byte response from both
    If you do not see this response than the bot didn't recognize the command


Use RESET-Command - sometimes this avoid the "not responding"
21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff

Good luck and enjoy your XIAOMI Robot
March 2017, LunaX
