#/bin/python
# -*- coding: utf-8 -*- 
#==============================================
#    A2SV(Auto Scanning to SSL Vulnerability  |
#     by HaHwul(www.hahwul.com)               |
#     https://github.com/hahwul/a2sv          |
#==============================================
import os
import sys
import argparse
import socket
import datetime
from urlparse import urlparse

sys.path.append(os.path.dirname( os.path.abspath( __file__ ))+"/module")
from M_ccsinjection import *
from M_heartbleed import *
from M_poodle import *
from M_freak import *

global ccs_result
global heartbleed_result
global poodle_result
global freak_result
global targetIP
global port

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


def runScan(s_type):
    global ccs_result
    global heartbleed_result
    global poodle_result
    global freak_result
    print ""
    print "[INF] Scan CCS Injection.."
    ccs_result = m_ccsinjection_run(targetIP,port)
    print "[RES] CCS Injection Result :: "+ccs_result
    print "[INF] Scan HeartBleed.."
    heartbleed_result = m_heartbleed_run(targetIP,port)
    print "[RES] HeartBleed :: "+heartbleed_result
    print "[INF] Scan SSLv3 POODLE.."
    poodle_result = m_poodle_run(targetIP,port)
    print "[RES] SSLv3 POODLE :: "+poodle_result
    print "[INF] Scan FREAK.."
    freak_result = m_freak_run(targetIP,port)
    print "[RES] FREAK :: "+freak_result



def outReport():
    global ccs_result
    global heartbleed_result
    global poodle_result
    global freak_result

    if ccs_result == "0x01":
        ccs_result = "Vulnerable! (0x01)"
    else:
        ccs_result = "Not Vulnerable. (0x00)"

    if heartbleed_result == "0x01":
        heartbleed_result = "Vulnerable! (0x01)"
    else:
        heartbleed_result = "Not Vulnerable. (0x00)"

    if poodle_result == "0x01":
        poodle_result = "Vulnerable! (0x01)"
    else:
        poodle_result = "Not Vulnerable. (0x00)"
    if freak_result == "0x01":
        freak_result = "Vulnerable! (0x01)"
    else:
        freak_result = "Not Vulnerable. (0x00)"

    print "  [TARGET]: "+targetIP
    print "  [PORT]: "+str(port)
    print "  [SCAN TIME]: "+str(datetime.datetime.now())
    print "  [VULNERABILITY]"
    print "   - CCS Injection: "+ccs_result
    print "   - HeartBleed: "+heartbleed_result
    print "   - SSLv3 POODLE: "+poodle_result
    print "   - FREAK: "+freak_result

###MAIN##
mainScreen()
parser = argparse.ArgumentParser()
parser.add_argument("-t", help="Target URL/IP Address")
parser.add_argument("-p", help="Custom Port / Default: 443")
parser.add_argument("-m", help="Check Module")

args = parser.parse_args()
if args.t:
    target = args.t
    print "[SET] target =>"+args.t
    targetIP = socket.gethostbyname(target)
    print "[SET] IP Address =>"+targetIP
else:
    print "Please Input Target Argument / -h --help"
    exit()
if args.p:
    port = args.p
    print "[SET] target port =>"+args.p
else:
    port = 443
    print "[SET] target port =>443"
if args.m:
    checkVun = args.m
    print "[SET] include =>"+args.m+" Module"
else:
    checkVun = "all"
    print "[SET] include => All Module"
runScan(checkVun)
print "________________________________________________"
print "                   [REPORT]                     "
outReport()
print "________________________________________________"
#print "               [SSL INFOMATION]                 "
#result = subprocess.Popen(['timeout','4','openssl','s_client','-showcerts','-connect',targetIP+":"+str(port)], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
#print result    ## Next Step

