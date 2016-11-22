import Queue
import threading
import getopt
import sys
import urllib2
import hashlib
import socket
import time
import os
import re
import netaddr
import subprocess
from C_display import *

#Module
def m_freak_run(ip_address,iPort,displayMode):
	#Identifier is not used
	IP = ip_address.strip()##
	try:
		socket.inet_aton(IP)
		showDisplay(displayMode, " - [LOG] IP Check Ok.")
	except:
		showDisplay(displayMode, "%s,invalid IP" % IP)
		return "0x02"
	try:
		showDisplay(displayMode, " - [LOG] Start SSL Connection / Gathering Information")
		result = subprocess.Popen(['timeout','4','openssl','s_client','-connect',ip_address+":"+str(iPort),"-cipher","EXPORT"], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
		showDisplay(displayMode, " - [LOG] Ending Get Information")
		#showDisplay(displayMode, result
		if "Cipher is EXP" in result:
			showDisplay(displayMode, " - [LOG] 'Cipher is EXP' in Response")
			return "0x01"
		else:
			showDisplay(displayMode, " - [LOG] 'Cipher is EXP' not in Response")
			return "0x00"
	except:
		showDisplay(displayMode, "[INF] Error FREAK Module")
		return "0x02"


