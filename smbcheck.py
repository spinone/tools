#!/usr/bin/env python
# -*- coding: utf-8 -*-

#python 2.7 Linux

# Requires pysmb-1.1.27 from https://pypi.org/project/pysmb/#files
# Unzip, cd to the unzipped folder and use "sudo python setup.py install"
# Requires nmap to be installed and on the path

__author__ = 'Chris Rundle (crundle@blackberry.com)'
__version__ = '1.0.0'
__last_modification__ = '2019.03.12'

# Import modules #

import sys
import os
import subprocess
import socket
import time

try:
    from smb.SMBConnection import *
except:
    print "[***] Requires pysmb-1.1.27 from https://pypi.org/project/pysmb/#files\n[!] Cannot continue.\n"
    sys.exit()

def basics():
# check args
    if len(sys.argv)<4:
        print "\n[!] Incorrect arguments...\n"
        usage()
        sys.exit()

# check nmap
    isx = subprocess.call("type " + "nmap", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0
    if not isx:
         sys.exit("\n[***] Can't find nmap - is it in your PATH?\n")


def usage():
        print "SMBCHECK v" + __version__ + "\nUsage:\n       Please provide the credentials to use to connect (username, password and domain)\n       and a filename containing the list of machines to connect to (IP addresses or FQDNs):\n       smbcheck.py -u:USERNAME -p:PASSWORD -d:DOMAIN -L:FILENAME [AND/OR] HOST\n       e.g. python smbcheck.py -u:chris -p:Password123 -d:WALES -L:hostlist.txt 192.168.5.207 10.2.3.0/24\n       (-v = verbose output)"

def chkport(IP): # Check if port 445 is open
    open445=False
    open137=False
    cmd="nmap -Pn -sS -p 445" + IP 
    cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in cmd.stdout: # Loop through Nmap output looking for open port 445
        if " open " in line: # not open|filtered
            if "445" in line:
                open445=True
    return open445

def smbscan(target):
# Check that TCP 445 is open
    print "\n[+] Checking shares on %s using %s\\%s" % (target, udom, uname)
    if chkport(target):
        print "[+] Port 445 is open..."
    else:
        print "[!] Port 445 is not open on %s." % target
        return

    conn = SMBConnection(uname, passwd, "pentest", target, domain=udom, use_ntlm_v2=True, is_direct_tcp=True)
    try:
        conn.connect(target, 445)
    except Exception as e:
        print "[!] Unable to connect to %s (%s)" % (target, str(e))
        return

    FA=False # Found ADMIN$ Share

    try:
        shares = conn.listShares()
        eko("SMB connection established.")
        slist=""
        for share in shares:
            slist=slist + share.name + ", "
        print "[+] The following shares were found: %s" % slist[:-2]

        for share in shares:
            #if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
            if share.name in ['ADMIN$']:
                FA=True            
                try:
                    sharedfiles = conn.listPath(share.name, '/')
                    if len(sharedfiles)>=1:
                        print "[+] The ADMIN$ share can be accessed using the credentials supplied and contains %s Shared files." % len(sharedfiles)
                    else:
                        print "[!] No shared files found."
                except:
                     "[!] Found the ADMIN$ share, but could not open it - check your credentials."
    except Exception as e:
        print "[!] Unable to list shares (%s)" % str(e)

    if not FA:
        print "[!] ADMIN$ share not found for this server - further checks needed."

    conn.close()

def chkVal(x): # checks if a value is a number between 0 and 255
    try:
        float(x)
    except ValueError:
        return False
    if not 0 <= int(x) <= 255:
        return False
    return True

def validIP(address): # checks if the target is a valid IP address
    rval=True
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not chkVal(item):
            return False
    return True

def IPlist(addressrange): # checks if target is a valid IP range
    parts = addressrange.split(".")
    if len(parts) != 4:
        return False
    for i in range(0,3):
        if not chkVal(parts[i]):
            return False
    listparts=parts.pop().split("-")
    if len(listparts) != 2:
        return False
    for item in listparts:
        if not chkVal(item):
            return False
    return True       

def iprange(addressrange): # converts an IP range into a list
    list=[]
    first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
    for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
        list.append(first3octets+str(i))
    return list

def ip2bin(ip): # Required for CIDR
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "": b += dec2bin(int(q),8); outQuads -= 1
    while outQuads > 0: b += "00000000"; outQuads -= 1
    return b

def dec2bin(n,d=None): # Required for CIDR
    s = ""
    while n>0:
        if n&1: s = "1"+s
        else: s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d: s = "0"+s
    if s == "": s = "0"
    return s

def bin2ip(b): # Required for CIDR
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def returnCIDR(c): # returns a list from a CIDR range
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    ips=[]
    if subnet == 32: #return list(bin2ip(baseIP))
        ips.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return ips

def chkport(IP): # Check if port 445/tcp is open
    open445=False
    cmd="nmap -Pn -sT -p445 " + IP 
    cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in cmd.stdout: # Loop through Nmap output looking for open port 445
        if " open " in line: # not open|filtered
            open445=True
    return open445

def eko(aradia):
    global verbose
    if verbose:
        print "[v:] " + aradia

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def main():
    global uname, passwd, udom, verbose
    verbose = False
    basics()

    # HEADING
    lh = "*** SMBCHECK v" + __version__ + " ***"
    lhl =  "*"* len(lh)
    print "\n" + lhl +"\n" + lh + "\n" + lhl 
    print

    # MAIN LOOP
    targets=[]
    targs=sys.argv[1:]

    # check calls for usage/help
    for target in targs:
        if target.lower() in ("-h", "--h", "-help", "--help"):
            usage()
            sys.exit()

        elif target[:2] == '-v':
            verbose = True
            eko("Verbose = " + str(verbose))

    for target in targs:
        if target[:3] == '-u:':
            uname = target[3:]
            #print uname

        elif target[:3] == '-p:':
            passwd = target[3:]
            #print passwd

        elif target[:3] == '-d:':
            udom = target[3:]
            #print udom

        elif target[:2] == '-v':
            verbose = True

        elif target[:3] == '-L:': # found a list
            filename = target[3:]
            # check file exists & can be opened
            validfile=True
            try:
                lines = [line.strip('\n') for line in open(filename)]
            except:
                print "[!] Cannot open file '%s'..." % (filename) 
                validfile=False
            if validfile:
                eko("Appending the contents of '%s' to the target list..." % filename)
                for target in lines:
                    # check each list entry is a valid IP address
                    if validIP(target):
                        targets.append(target)
                    elif '/' in target: # found cidr target
                        cidrlist=returnCIDR(target)
                        for item in cidrlist:
                            if validIP(item):
                                targets.append(item)
                    else: # Not a valid IP address in list
                        x="It"
                        #print "%s is not a valid IP - trying to resolve...." % target
                        try:
                            x=(socket.gethostbyname(target)) # get IP from FQDN
                        except Exception as e:
                            eko("Target: " + target + " (" + str(e) + ")")
                        if validIP(x):
                            targets.append(x)
                            eko(target + " resolved to " + x)
                        else:
                            print "[!] Invalid list entry '%s' was discarded." % target
                            eko("(" + x + " isn\'t a valid or resolvable IP address.)")

        elif target[0] == "-":
            print "[!] Invalid command line argument (%r) was ignored..." % target

        elif '/' in target: # found cidr target
            cidrlist=returnCIDR(target)
            for item in cidrlist:
                targets.append(item)

        elif IPlist(target):
            addresslist=iprange(target)
            for item in addresslist:
                targets.append(item)

        elif validIP(target):
            targets.append(target)

        else:
             try: 
                x=(socket.gethostbyname(target)) # get IP from FQDN
                if x == '92.242.132.15':
                    raise Exception('BT Internet maps non-existent hosts to 92.242.132.15')
                    eko("FQDN '%s' resolves to %s" % (target, x))
                targets.append(x)
             except Exception as e: 
                print "[!] Ignoring %s as it does not appear to be a valid target..." % (target)
                print "    (%s)" % e
                print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
  
    if len(targets)>0:
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        for target in targets: 
            smbscan(target)
            print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    else:
        print "\n" + "="*40 + "\n" + "[!] No valid targets provided.\n"


# --- Allow import without running the code --- #

if __name__ == "__main__":
    main()

# ------END------- #

