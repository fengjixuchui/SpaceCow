# SpaceCow - Python Rootkit

Follow me on [Twitter](https://twitter.com/__SPX__) 

In the past days i spent a lot of time watching some RedTeam ops and I saw all these little tools making some awsome stuff... and in the 90% of the cases RedTeams don't share their tricks and softwares with others.

So i thought I could create something open source. And after some days i crawled up with something...
![SpaceCow-c2c](http://zetabay.net/wp-content/uploads/2019/06/Cattura-1024x556.png)

## Why do you need SpaceCow?

This software is a minimal Rootkit written in pure __Python3__ and does some little tricks to make itself stealthy, so let's listing all its capabilities :

- __Socket Server MultiPort__ : I saw that a lot of reverse shells listen only on one port so i thought 'Why i can't listen on 100?'.
- __Socket Server MultiClient__ : Yep, botnet ... are you happy SKs?
- __CrossPlatform__: theoretically it can be run only both Windows and Linux platform, just require Python3.
- __Encrypted Communication__ : The network comm is completly encrypted using RSA encryption.
- __Custom TCP Protocol__: You can have multiple theories on what does it mean, but in my opinion sending packets following a specific set of rules is a custom protocol already, infact the sending and the receiving methods between client and server is optimized. Each packet is being splitted in more piecies in order to allow the RSA algorithm to encrypt everything and then each packet is sent following a ACK - SYNC kind of style, so both the client and server are sure that the other received the last packet correctly.
- __Runtime Payload Execution__ : this is cool, so id order to make the stub less FUD i decided to execute the '_critical payloads_' such as command shell execution, ... in runtime. So in the python script is not written a backdoor functionality for command exec. But the client once triggered will download from remote the custom payload to execute : __SHELL__ commands and __POWERSHELL__ commands. 

    (P.S. The commands sent using this payloads should be encoded in base64 to avoid F* unicode decoding errors but I didn't done this. )

- __Traffic Obfuscation__ : So this is fun because WireShark uses a specific Windows API to intercept the traffic so there's a Library created for C++ that allows the same kind of manipulation at the same level. Cool and someone decided to make it for python (PyDivert). So using this lib you can take each packet on a specific port, modifing it by your need and re-inject it into the network (Pit-Stop style). So thanks to this i managed to modify the source IP address of each packet incoming from the C&C with the destination one, so basically if you intercept the traffic you'll se in the incoming packets that the infected ones are coming from the loopback or from the LAN ... so less noise.

- __Sandbox Aggressive Detection__ : I've taken some scripts around the network to perform an aggressive Sandbox detection to try to avoid analysis. This is not tested yet ! You can implement it if you want.

- __Persistence via Windows Services__ : What is the best way to gain persistence without using the same REGKEYs? Windows Services... In the repo you have a file called '_ServiceCreator.py_' using that you can create a custom service that will execute the file at the startup. Be sure to install the service setting it : 

    ```--startup=auto install```

    This is tested but for some reasons the service is set on startup auto but is not being executed. Don't know why it needs some work but you can create a service using the ```sc.exe``` native Windows program to create a new one.


## How to use it and stuff

Basically install Python3 and install the requirements using pip:


```pip.exe -r install requirements.txt```

Inside you have a custom library that i have written called '__TrueColors__' (color.py) you can grab it and using it in other projects, is based on Colorama.

Once you're ready start the file 'spacecow.py':

```python spacecow.py -h

           __n__n__
    .------`-\00/-'
   /  ##  ## (oo)
  / \## __   ./ SpaceCow
     |//YY \|/ Windows Rootkit
     |||   |||

usage: spacecow.py [-h] [-p PORTS] [--version]

optional arguments:
  -h, --help  show this help message and exit
  -p PORTS    Define the ports for the socket server (ex. 2000,2001,...).
  --version   show program's version number and exit

```

To listen on ports just enter the following syntax :

```python spacecow.py -p 2000,2001```

Enter the ports separated just with a comma.

To enable the persistence you have to run the file '_ServiceCreator.py_', you can add it as module in the client.py. Remember to change '_exepath_' in the file with the final path of the .exe malware and you can modify the 3 class init variables defining the Service Name, Description and DisplayName. In the end to create a new service you can run the following syntax:

```python ServiceCreator.py --startup=auto install```

To start the service :

```python ServiceCreator.py start```

To uninstall the service :

```python ServiceCreator.py remove```

Then reboot the system.

## C2 Commands

I didn't set a help menu so the commands are the following :

### Command Line
- ```list```: list all the implants
- ```notify connection true/false```: this will inform you each time a new implant gets connected but this will break the current input and you need to press enter.
- ```drop */1,2,3,...```: you can broadcast a close connection to all implants using * or sending to specific indexes separating them with comma.
- ```jump (index)``` : select the index and you can spawn a interactive shell with the selected implant.

### Interactive shell
- ```exit/background``` : to close the shell and drop the connection (yep need work to handle it).
- ```EXEC::command``` : execute a cmd command.
- ```PSEXEC::command``` : execute a powershell command.

## Conclusions

This is a PoC it needs some work ( download, upload, broadcast, handling, ...) but it's all optional the basic functions are full working. So feel free to implement it and if you want to help me creating stuff pm me.

## Disclaimer

Meant for study only purposes not for illegal.

## License

You can use this code even for commercial purposes but please give credit, I've spent hours on it.
