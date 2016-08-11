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
from M_logjam import *
from M_drown import *
#==============================================

# Version 
myPath=os.path.dirname( os.path.abspath( __file__ ))
vfp = open(myPath+"/version","r")  #Version File Pointer
a2sv_version = vfp.read()
a2sv_version = a2sv_version.rstrip()
#==============================================

global targetIP
global port
global ccs_result
global heartbleed_result
global poodle_result
global freak_result
global logjam_result
global drown_result


#===========================
# Set Result Val
# -1: Not Scan
# 0x00: Not Vuln
# 0x01: Vuln
ccs_result = "-1"
heartbleed_result = "-1"
poodle_result = "-1"
freak_result = "-1"
logjam_result = "-1"
#===========================
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
VIOLET = '\033[0;35m'
END = '\033[0m'

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
    print "                    █████╗ ██████╗ ███████╗██╗   ██╗"
    print "                   ██╔══██╗╚════██╗██╔════╝██║   ██║"
    print "                   ███████║ █████╔╝███████╗██║   ██║"
    print "    .o oOOOOOOOo   ██╔══██║██╔═══╝ ╚════██║╚██╗ ██╔╝        OOOo"
    print "    Ob.OOOOOOOo O  ██║  ██║███████╗███████║ ╚████╔╝   .adOOOOOOO"
    print "    OboO'''''''''' ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═══╝  ''''''''''OO" 
    print "    OOP.oOOOOOOOOOOO 'POOOOOOOOOOOo.   `'OOOOOOOOOP,OOOOOOOOOOOB'"
    print "    `O'OOOO'     `OOOOo'OOOOOOOOOOO` .adOOOOOOOOO'oOOO'    `OOOOo"
    print "    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO"
    print "    OOOOO                 ''OOOOOOOOOOOOOOOO'`                oOO"
    print "   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo."
    print "  oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO"
    print " OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO'`  ''OOOOOOOOOOOOO.OOOOOOOOOOOOOO"
    print " 'OOOO'       'YOoOOOOMOIONODOO'`  .   ''OOROAOPOEOOOoOY'     'OOO'"
    print "    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`"
    print "    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         ."
    print "    .            oOOP'%OOOOOOOOoOOOOOOO?oOOOOO?OOOO'OOo"
    print "                 '%o  OOOO'%OOOO%'%OOOOO'OOOOOO'OOO':"
    print "                      `$'  `OOOO' `O'Y ' `OOOO'  o             ."
    print "    .                  .     OP'          : o     ."
    print "                              :"
    print BLUE+"                [Auto Scanning to SSL Vulnerability "+a2sv_version+"]"+END
    print VIOLET+"                       [By Hahwul / www.hahwul.com]"+END
    print "________________________________________________________________________"
def runScan(s_type):
    global ccs_result
    global heartbleed_result
    global poodle_result
    global freak_result
    global logjam_result
    global drown_result
    print ""
    if s_type == "c":
        print GREEN+"[INF] Scan CCS Injection.."+END
        ccs_result = m_ccsinjection_run(targetIP,port)
        print GREEN+"[RES] CCS Injection Result :: "+ccs_result+END
    elif s_type == "h":
        print GREEN+"[INF] Scan HeartBleed.."+END
        heartbleed_result = m_heartbleed_run(targetIP,port)
        print GREEN+"[RES] HeartBleed :: "+heartbleed_result+END
    elif s_type == "p":
        print GREEN+"[INF] Scan SSLv3 POODLE.."+END
        poodle_result = m_poodle_run(targetIP,port)
        print GREEN+"[RES] SSLv3 POODLE :: "+poodle_result+END
    elif s_type == "f":
        print GREEN+"[INF] Scan OpenSSL FREAK.."+END
        freak_result = m_freak_run(targetIP,port)
        print GREEN+"[RES] OpenSSL FREAK :: "+freak_result+END
    elif s_type == "l":
        print GREEN+"[INF] Scan OpenSSL LOGJAM.."+END
        logjam_result = m_logjam_run(targetIP,port)
        print GREEN+"[RES] OpenSSL LOGJAM :: "+logjam_result+END
    elif s_type == "d":
        print GREEN+"[INF] Scan SSLv2 DROWN.."+END
        logjam_result = m_drown_run(targetIP,port)
        print GREEN+"[RES] SSLv2 DROWN :: "+drown_result+END
    else:
        print GREEN+"[INF] Scan CCS Injection.."+END
        ccs_result = m_ccsinjection_run(targetIP,port)
        print GREEN+"[RES] CCS Injection Result :: "+ccs_result+END
        print GREEN+"[INF] Scan HeartBleed.."+END
        heartbleed_result = m_heartbleed_run(targetIP,port)
        print GREEN+"[RES] HeartBleed :: "+heartbleed_result+END
        print GREEN+"[INF] Scan SSLv3 POODLE.."+END
        poodle_result = m_poodle_run(targetIP,port)
        print GREEN+"[RES] SSLv3 POODLE :: "+poodle_result+END
        print GREEN+"[INF] Scan OpenSSL FREAK.."+END
        freak_result = m_freak_run(targetIP,port)
        print GREEN+"[RES] OpenSSL FREAK :: "+freak_result+END
        print GREEN+"[INF] Scan OpenSSL LOGJAM.."+END
        logjam_result = m_logjam_run(targetIP,port)
        print GREEN+"[RES] OpenSSL LOGJAM :: "+logjam_result+END
        print GREEN+"[INF] Scan SSLv2 DROWN.."+END
        drown_result = m_drown_run(targetIP,port)
        print GREEN+"[RES] SSLv2 DROWN :: "+drown_result+END

def outVersion():
    print "A2SV v"+a2sv_version

def updateVersion():
    print GREEN+"[INF] Update A2SV"+END
    print GREEN+"[INF] This A2SV version is .. v"+a2sv_version+END
    os.chdir(os.path.dirname( os.path.abspath( __file__ )))
    os.system("git pull -v")
    print GREEN+"\n[INF] This A2SV version is .. v"+a2sv_version+END
    print RED+"[FIN] Updated A2SV"+END

def outReport():
    global ccs_result
    global heartbleed_result
    global poodle_result
    global freak_result
    global logjam_result
    global drown_result
    if ccs_result == "0x01":
        ccs_result = "Vulnerable!"
    elif ccs_result == "0x00":
        ccs_result = "Not Vulnerable."
    else:
        ccs_result = "Not Scan."
    if heartbleed_result == "0x01":
        heartbleed_result = "Vulnerable!"
    elif heartbleed_result == "0x00":
        heartbleed_result = "Not Vulnerable."
    else:
        heartbleed_result = "Not Scan."
    if poodle_result == "0x01":
        poodle_result = "Vulnerable!"
    elif poodle_result == "0x00":
        poodle_result = "Not Vulnerable."
    else:
        poodle_result = "Not Scan."
    if freak_result == "0x01":
        freak_result = "Vulnerable!"
    elif freak_result == "0x00":
        freak_result = "Not Vulnerable."
    else:
        freak_result = "Not Scan."
    if logjam_result == "0x01":
        logjam_result = "Vulnerable!"
    elif logjam_result == "0x00":
        logjam_result = "Not Vulnerable."
    else:
        logjam_result = "Not Scan."
    if drown_result == "0x01":
        drown_result = "Vulnerable!"
    elif drown_result == "0x00":
        drown_result = "Not Vulnerable."
    else:
        drown_result = "Not Scan."

#----------- Template -----------
#    if logjam_result == "0x01":
#        logjam_result = "Vulnerable!"
#    elif logjam_result == "0x00":
#        logjam_result = "Not Vulnerable."
#    else:
#        logjam_result = "Not Scan."
#----------- -------- -----------


    data = [
    {'v_vuln':'HeartBleed', 'v_cve':'CVE-2014-0160', 'cvss':'AV:N/AC:L/Au:N/C:P/I:N/A:N', 'v_state':heartbleed_result},
    {'v_vuln':'CCS Injection', 'v_cve':'CVE-2014-0224', 'cvss':'AV:N/AC:M/Au:N/C:P/I:P/A:P', 'v_state':ccs_result},
    {'v_vuln':'SSLv3 POODLE', 'v_cve':'CVE-2014-3566', 'cvss':'AV:N/AC:M/Au:N/C:P/I:N/A:N', 'v_state':poodle_result},    
    {'v_vuln':'OpenSSL FREAK', 'v_cve':'CVE-2015-0204', 'cvss':'AV:N/AC:M/Au:N/C:N/I:P/A:N', 'v_state':freak_result},
    {'v_vuln':'OpenSSL LOGJAM', 'v_cve':'CVE-2015-4000', 'cvss':'AV:N/AC:M/Au:N/C:N/I:P/A:N', 'v_state':logjam_result},
    {'v_vuln':'SSLv2 DROWN', 'v_cve':'CVE-2016-0800', 'cvss':'AV:N/AC:M/Au:N/C:P/I:N/A:N', 'v_state':drown_result}
]
    fmt = [
    ('Vulnerability',       'v_vuln',   14),
    ('CVE',          'v_cve',       13),
    ('CVSS v2 Base Score',          'cvss',       26),
    ('State', 'v_state', 16)
]
    print BLUE+" [TARGET]: "+targetIP+END
    print BLUE+" [PORT]: "+str(port)+END
    print BLUE+" [SCAN TIME]: "+str(datetime.datetime.now())+END
    print RED+" [VULNERABILITY]"+END
    print( TablePrinter(fmt, ul='=')(data) )

###MAIN##
mainScreen()
parser = argparse.ArgumentParser("a2sv",formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-t","--target", help="Target URL/IP Address")
parser.add_argument("-p","--port", help="Custom Port / Default: 443")
parser.add_argument("-m","--module", help="Check SSL Vuln with one module\n[h]: HeartBleed\n[c]: CCS Injection\n[p]: SSLv3 POODLE\n[f]: OpenSSL FREAK\n[l]: OpenSSL LOGJAM\n[d]: SSLv2 DROWN")
parser.add_argument("-u","--update", help="Update A2SV (GIT)",action='store_true')
parser.add_argument("-v","--version", help="Show Version",action='store_true')
args = parser.parse_args()

if args.version:
    outVersion()
    exit()
if args.update:
    updateVersion()
    exit()
if args.target:
    target = args.target
    print BLUE+"[SET] target => "+args.target+END
    targetIP = socket.gethostbyname(target)
    print BLUE+"[SET] IP Address => "+targetIP+END
else:
    print "Please Input Target Argument / -h --help"
    exit()
if args.port:
    port = int(args.port)
    print BLUE+"[SET] target port => "+args.port+END
else:
    port = 443
    print BLUE+"[SET] target port => 443"+END
if args.module:
    checkVun = args.module
    ModuleName = args.module
    if ModuleName == "c":
        ModuleName = "CCS Injection"
    elif ModuleName == "h":
        ModuleName = "HeartBleed"
    elif ModuleName == "p":
        ModuleName = "SSLv3 POODLE Attack"
    elif ModuleName == "f":
        ModuleName = "OpenSSL FREAK Attack"
    elif ModuleName == "l":
        ModuleName = "OpenSSL LOGJAM Attack"
    elif ModuleName == "d":
        ModuleName = "SSLv2 DROWN Attack"
    print BLUE+"[SET] include => "+ModuleName+" Module"+END
else:
    checkVun = "all"
    print BLUE+"[SET] include => All Module"+END
runScan(checkVun)
print RED+"[FIN] Scan Finish!"+END
print "________________________________________________________________________"
print "                              [A2SV REPORT]                             "
outReport()
print "________________________________________________________________________"
#print "               [SSL INFOMATION]                 "
#result = subprocess.Popen(['timeout','4','openssl','s_client','-showcerts','-connect',targetIP+":"+str(port)], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
#print result    ## Next Step

