#/bin/python
# -*- coding: utf-8 -*- 

import os
import sys
import argparse
import socket
from urlparse import urlparse

sys.path.append("./module")
from M_ccsinjection import *
from M_heartbleed import *

def mainScreen():
    os.system('cls' if os.name=='nt' else 'clear')
    print "         █████╗ ██████╗ ███████╗██╗   ██╗"
    print "        ██╔══██╗╚════██╗██╔════╝██║   ██║"
    print "        ███████║ █████╔╝███████╗██║   ██║"
    print "        ██╔══██║██╔═══╝ ╚════██║╚██╗ ██╔╝"
    print "        ██║  ██║███████╗███████║ ╚████╔╝ "
    print "        ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═══╝ "
    print "      [Auto Scanning to SSL Vulnerability]"
    print "          [By Hahwul / www.hahwul.com]"
    print "________________________________________________"

###MAIN##
mainScreen()
parser = argparse.ArgumentParser()
parser.add_argument("-t", help="Target URL/IP Address")
parser.add_argument("-p", help="Custom Port / Default: 443")
parser.add_argument("-m", help="Check Module")

args = parser.parse_args()
if args.t:
    target = args.t
    print "[SET] target      ::  "+args.t
    targetIP = socket.gethostbyname(target)
    print "[SET] IP Address  ::  "+targetIP
else:
    print "Please Input Target Argument / -h --help"
    exit()
if args.p:
    port = args.p
    print "[SET] target port ::  "+args.p
else:
    port = 443
    print "[SET] target port ::  443"
if args.m:
    checkVun = args.m
    print "[SET] include     ::  "+args.m+" Module"
else:
    checkVun = "all"
    print "[SET] include     ::  All Module"
print "________________________________________________"
print "                    [LOG]                       "
print ""


# css_result = m_ccsinjection_run("127.0.0.1",443)

print "________________________________________________"
print "                   [REPORT]                     "
print ""











