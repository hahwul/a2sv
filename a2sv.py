#/bin/python
# -*- coding: utf-8 -*- 
#==============================================
#    A2SV(Auto Scanning to SSL Vulnerability  |
#     by HaHwul(www.hahwul.com)               |
#     https://github.com/hahwul/a2sv          |
#==============================================
# Version 
a2sv_version = "1.2.1"
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

## Report Table
class TablePrinter(object):
    "Print a list of dicts as a table"
    def __init__(self, fmt, sep=' ', ul=None):
        """        
        @param fmt: list of tuple(heading, key, width)
                        heading: str, column label
                        key: dictionary key to value to print
                        width: int, column width in chars
        @param sep: string, separation between columns
        @param ul: string, character to underline column label, or None for no underlining
        """
        super(TablePrinter,self).__init__()
        self.fmt   = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width, lb='{', rb='}') for heading,key,width in fmt)
        self.head  = {key:heading for heading,key,width in fmt}
        self.ul    = {key:str(ul)*width for heading,key,width in fmt} if ul else None
        self.width = {key:width for heading,key,width in fmt}

    def row(self, data):
        return self.fmt.format(**{ k:str(data.get(k,''))[:w] for k,w in self.width.iteritems() })

    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return '\n'.join(res)
########################


def mainScreen():
    os.system('cls' if os.name=='nt' else 'clear')
    print "                █████╗ ██████╗ ███████╗██╗   ██╗"
    print "               ██╔══██╗╚════██╗██╔════╝██║   ██║"
    print "               ███████║ █████╔╝███████╗██║   ██║"
    print "               ██╔══██║██╔═══╝ ╚════██║╚██╗ ██╔╝"
    print "               ██║  ██║███████╗███████║ ╚████╔╝ "
    print "               ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═══╝ "
    print "             [Auto Scanning to SSL Vulnerability]"
    print "                 [By Hahwul / www.hahwul.com]"
    print "_________________________________________________________________"

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

def outVersion():
    print "A2SV v"+a2sv_version

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


    data = [
    {'v_vuln':'CCS Injection', 'v_cve':'CVE-2014-0224', 'v_state':ccs_result, 'cvss':'C:P/I:N/A:N'},
    {'v_vuln':'HeartBleed', 'v_cve':'CVE-2014-0160', 'v_state':heartbleed_result, 'cvss':'C:P/I:N/A:N'},
    {'v_vuln':'SSLv3 POODLE', 'v_cve':'CVE-2014-3566', 'v_state':poodle_result, 'cvss':'C:P/I:N/A:N'},
    {'v_vuln':'OpenSSL FREAK', 'v_cve':'CVE-2015-0204'*9, 'v_state':freak_result, 'cvss':'C:P/I:N/A:N'}
]
    fmt = [
    ('Vulnerability',       'v_vuln',   14),
    ('CVE',          'v_cve',       13),
    ('State', 'v_state', 23),
    ('CVSS',          'cvss',       12)
]
    print "[TARGET]: "+targetIP
    print "[PORT]: "+str(port)
    print "[SCAN TIME]: "+str(datetime.datetime.now())
    print "[VULNERABILITY]"
    print( TablePrinter(fmt, ul='=')(data) )

###MAIN##
mainScreen()
parser = argparse.ArgumentParser()
parser.add_argument("-t", help="Target URL/IP Address")
parser.add_argument("-p", help="Custom Port / Default: 443")
parser.add_argument("-m", help="Check Module")
parser.add_argument("-v", help="Show Version",action='store_true')

args = parser.parse_args()
if args.v:
    outVersion()
    exit()
if args.t:
    target = args.t
    print "[SET] target =>"+args.t
    targetIP = socket.gethostbyname(target)
    print "[SET] IP Address =>"+targetIP
else:
    print "Please Input Target Argument / -h --help"
    exit()
if args.p:
    port = int(args.p)
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
print "[FIN] Scan Finish!"
print "_________________________________________________________________"
print "                             [REPORT]                            "
outReport()
print "_________________________________________________________________"
#print "               [SSL INFOMATION]                 "
#result = subprocess.Popen(['timeout','4','openssl','s_client','-showcerts','-connect',targetIP+":"+str(port)], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
#print result    ## Next Step

