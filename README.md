<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="Content-Style-Type" content="text/css">
  <title></title>
  <meta name="Generator" content="Cocoa HTML Writer">
  <meta name="CocoaVersion" content="1504.81">
</head>
<body>
<p>&lt;h1&gt;XIAOMI Vaccum cleaner robot&lt;/h1&gt;</p>
<p><br></p>
<p>Python script to use this robot</p>
<p><br></p>
<p>--------------------------------------------------------------------------&lt;br&gt;</p>
<p>Important notes:&lt;br&gt;</p>
<p>--------------------------------------------------------------------------&lt;br&gt;</p>
<p>1)  all commands must be sniffed via Wireshark for you own</p>
<p>2)  if you work with wireshark use this filter to find you own commands</p>
<p>    (data.len == 80 || data.len == 64 || data.len == 96  || data.len == 144) &amp;&amp; (ip.proto == 17)</p>
<p><br></p>
<p><br></p>
<p>Using this tool:  </p>
<p><br></p>
<p>it is possible to send several commands in a sequence to the bot</p>
<p>examples:  </p>
<p>./xiaomi_vaccum_cleaner_script.py --cmd find start standard</p>
<p>First send FIND-command, than start robot cleaning and set hoover to standard</p>
<p><br></p>
<p>./xiaomi_vaccum_cleaner_script.py -vv --cmd find start standard</p>
<p>same as above but with verbose-verbose output</p>
<p><br></p>
<p>./xiaomi_vaccum_cleaner_script.py -vv -w 10 --cmd find start standard</p>
<p>same as above but wait 10secs between every command</p>
<p><br></p>
<p>./xiaomi_vaccum_cleaner_script.py -i 192.189.8.100 -vv --cmd find start standard</p>
<p>same as above but use new IP-Addrress as in script</p>
<p><br></p>
<p>-------------------------------------------------------------------------------</p>
<p><br></p>
<p>usage: xiaomi_vaccum_cleaner_script.py [-h] [-i] [-p] [-w WAIT] -c</p>
<p>                                       [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]]</p>
<p>                                       [-v]</p>
<p><br></p>
<p>XIAOMI vaccum cleaner</p>
<p><br></p>
<p>optional arguments:</p>
<p>  -h, --help            show this help message and exit</p>
<p>  -i, --ip              UDP destination ip</p>
<p>  -p, --port            UDP destination port</p>
<p>  -w WAIT, --wait WAIT  wait in seconds between two commands</p>
<p>  -c [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]], --cmd [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]]</p>
<p>  -v, --verbose         verbose output</p>
<p><br></p>
<p>  -------------------------------------------------------------------------------</p>
<p><br></p>
<p>############################################################################&lt;br&gt;</p>
<p>&lt;h2&gt;HowTo sniff you XIAOMI robot&lt;/h2&gt;</p>
<p>############################################################################&lt;br&gt;</p>
<p>Preconditions:</p>
<p>1)  download and install "WireShark" on your pc</p>
<p>2)  download and install "PaketSender" on your pc</p>
<p>3)  install an ANDROID emulator on your pc (MAC OS =&gt; BlueStack)</p>
<p>    3.1) install XIAOMI MI application</p>
<p>    3.2) configure the application</p>
<p>    3.3) test application if robot works - IMPORTANT !!!!!</p>
<p>4)  Start Wireshark</p>
<p>5)  setup network card to sniff (e.g. WiFI)</p>
<p>6)  insert into filter text field this filter criteria</p>
<p>(data.len == 80 || data.len == 64 || data.len == 96  || data.len == 144) &amp;&amp; (ip.proto == 17)</p>
<p>7)  Start sniffing (icon upper left blue shark fin)</p>
<p>8)  go to android app and go to main screen (MAP is shown) - do nothing</p>
<p>9)  you should see packets in Wireshark</p>
<p>10) click middle button (CLEAN) 1x time - wait until robot moves</p>
<p>11) click middle button again (STOP) - robot should stop</p>
<p>12) go to wireshark and stop recording (red square)</p>
<p>13) now you should see all packetes from app to robot and answer from robot</p>
<p><br></p>
<p>Short introduction into UDP Packets</p>
<p>PING/CARD command:  Host send every second 80Bytes, Robot return 256 Bytes</p>
<p>(this packets can be ignored)</p>
<p><br></p>
<p>Normal commands:  host sends 80Bytes, robot answer: 64Bytes</p>
<p>(start,stop,find,home)</p>
<p><br></p>
<p>Power commands: Host: 96 Bytes, Robot: 64Bytes</p>
<p>(silent, standard, power)</p>
<p><br></p>
<p>Joystick commands: Host: 144 Bytes, Robot: 64Bytes</p>
<p>(not implemented yet)  </p>
<p><br></p>
<p>14) to find YOUR START-Command, find a 80/64 Byte sequence.</p>
<p>    Wireshark combine both (send &amp; receive with a bracket (left side)).</p>
<p>15) copy only DATA-Packet (80 Bytes)</p>
<p>    these packets start every time with HEX: 213100xx</p>
<p>    xx = Number of Bytes, for 80Bytes = 50, 96Bytes = 60, ...</p>
<p><br></p>
<p>16) start PaketSender</p>
<p>17) insert 80Byte packet in HEX-Field</p>
<p>18) click SAVE-Button</p>
<p>19) click SEND-Button</p>
<p>20) IMPORTANT:</p>
<p>    in below log table you must see:</p>
<p>    first:    your SEND udp package</p>
<p>    second:   a 64 Byte response from both</p>
<p>    If you do not see this response than the bot didn't recognize the command</p>
<p><br></p>
<p><br></p>
<p>Use RESET-Command - sometimes this avoid the "not responding"</p>
<p>21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff</p>
<p><br></p>
<p>Good luck and enjoy your XIAOMI Robot</p>
<p>March 2017, LunaX</p>
</body>
</html>
