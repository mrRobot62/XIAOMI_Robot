<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="Content-Style-Type" content="text/css">
  <title><h1>XIAOMI Vaccum cleaner robot</h1></title>
  <meta name="Generator" content="Cocoa HTML Writer">
  <meta name="CocoaVersion" content="1504.81">
</head>
<body>
<p></p>
<p>--------------------------------------------------------------------------</p>
<p><h3>Update: xiaomi_robot.py works with TOKEN - no sniffing needed    </h3></p>
<p>--------------------------------------------------------------------------</p>
Please refere to "Ermittlung_TOKEN_DE.pdf" to see, how you can check which token-id your
robot use

Quick & dirty description:
<ol>
<li> reset WLAN from you robot
<li> robot establish a new AdHoc network "rockrobo....."
<li> remove robot device in your App on your smartphone
<li> Alternative 1:
<li> install python script
<li> python xiaomi_robot.py -info
<li> robot answer with a status and the current token (16 Bytes)
<li> save YOUR token
<li> if this way didn't work for you go to alternative 2
<li> Alternative 2:
<li> open PacketSender
<li> insert in field Hex: 21 31 00 20 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
<li> insert a name
<li> save
<li> send
<li> Robot should answer immediately with a status and his token
<li> Robot answer with : 21 31 00 20 00 00 00 00 03 4C 94 1D 58 FE 4B F2 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF<br>
but the FF FF... is exchanged with YOUR Token (16 Bytes)
<li> copy this 16 bytes and save them - you need it later
<li> Install python script (works only with Python 2.7)
<li> maybe you have to install python cryptography library with pip install cryptography
<li> test if script run without error messages
<li> python xiaomi_robot.py -h
<li> you should see a help screen - if yes you won :-)
<li> Start: python xiaomi_robot.py -ip "ip from your robot" -cmd "start" -token "your token"
<li> Pause: python xiaomi_robot.py -ip "ip from your robot" -cmd "pause" -token "your token"
<li> Home: python xiaomi_robot.py -ip "ip from your robot" -cmd "home" -token "your token"
<li> Good luck and have fun
</ol>

LunaX 25-MAR-17

<p><br></p>
<p>Python script to use this robot</p>
<p><br></p>
<p>--------------------------------------------------------------------------</p>
<p><h3>Important notes:</h3></p>
<p>--------------------------------------------------------------------------</p>
<ol>
  <li>all commands must be sniffed via Wireshark for you own environment</li>
  <li>if you work with wireshark use this filter to find you own commands</li>
  <ul>
    <li>(data.len == 80 || data.len == 64 || data.len == 96  || data.len == 144) &amp;&amp; (ip.proto == 17)</li>
  </ul>
</ol>
<p><br></p>
<p><br></p>
<p>Using this tool:  </p>
<p><br></p>
<p>it is possible to send several commands in a sequence to the bot</p>
<p>examples:  </p>
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
<p>                                       [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]]</p>
<p>                                       [-v]</p>
<p><br></p>
<p>XIAOMI vaccum cleaner</p>
<p><br></p>
<p>optional arguments:</p>
<p>  -h, --help            show this help message and exit</p>
<p>  -i, --ip              UDP destination ip</p>
<p>  -p, --port            UDP destination port</p>
<p>  -w WAIT, --wait WAIT  wait in seconds between two commands</p>
<p>  -c [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]], --cmd [{stop,start,home,silent,standard,power,find} [{stop,start,home,silent,standard,power,find} ...]]</p>
<p>  -v, --verbose         verbose output</p>
<p><br></p>
<p>  -------------------------------------------------------------------------------</p>
<p><br></p>
<p>############################################################################</p>
<h1>HowTo sniff your XIAOMI robot</h1>
<p>############################################################################</p>
<p><b>Preconditions:</b></p>
<ol>
  <li>download and install "WireShark" on your pc</li>
  <li>download and install "PaketSender" on your pc</li>
  <li>install an ANDROID emulator on your pc (MAC OS =&gt; BlueStack)</li>
  <ul>
    <li>install XIAOMI MI application</li>
    <li>configure the application</li>
    <li>test application if robot works - IMPORTANT !!!!!</li>
  </ul>
  <li>Start Wireshark</li>
  <li>setup network card to sniff (e.g. WiFI)</li>
  <li>insert into filter text field this filter criteria</li>
  <ul>
    <li>(data.len == 80 || data.len == 64 || data.len == 96  || data.len == 144) &amp;&amp; (ip.proto == 17)</li>
  </ul>
  <li>Start sniffing (icon upper left blue shark fin)</li>
  <li>go to android app and go to main screen (MAP is shown) - do nothing</li>
  <li>you should see packets in Wireshark</li>
  <li>click middle button (CLEAN) 1x time - wait until robot moves</li>
  <li>click middle button again (STOP) - robot should stop</li>
  <li>go to wireshark and stop recording (red square)</li>
  <li>now you should see all packetes from app to robot and answer from robot</li>
  <ul>
    <li><b>Short introduction into UDP Packets</b></li>
  </ul>
</ol>
<p>			PING/CARD command:  Host send every second 80Bytes, Robot return 256 Bytes</p>
<p>			(this packets can be ignored)</p>
<p><br></p>
<p>			Normal commands:  host sends 80Bytes, robot answer: 64Bytes</p>
<p>			(start,stop,find,home)</p>
<p><br></p>
<p>			Power commands: Host: 96 Bytes, Robot: 64Bytes</p>
<p>			(silent, standard, power)</p>
<p><br></p>
<p>			Joystick commands: Host: 144 Bytes, Robot: 64Bytes</p>
<p>			(not implemented yet)  </p>
<ol>
  <li>to find YOUR START-Command, find a 80/64 Byte sequence.</li>
  <ul>
    <li>Wireshark combine both (send &amp; receive with a bracket (left side)).</li>
  </ul>
  <li>copy only DATA-Packet (80 Bytes)</li>
  <ul>
    <li>these packets start every time with HEX: 213100xx</li>
    <li>xx = Number of Bytes, for 80Bytes = 50, 96Bytes = 60, ...</li>
  </ul>
  <li>start PaketSender</li>
  <li>insert 80Byte packet in HEX-Field</li>
  <li>click SAVE-Button</li>
  <li>click SEND-Button</li>
  <li>IMPORTANT:</li>
  <ul>
    <li>in below log table you must see</li>
    <li>first:    your SEND udp package</li>
    <li>second:   a 64 Byte response from both</li>
    <li><b>If you do not see this response than the bot didn't recognize the command</b></li>
  </ul>
</ol>
<p><br></p>
<p><br></p>
<p>Use RESET-Command - sometimes this avoid the "not responding"</p>
<p>21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff</p>
<p><br></p>
<p>Good luck and enjoy your XIAOMI Robot</p>
<p>March 2017, LunaX</p>
</body>
</html>
