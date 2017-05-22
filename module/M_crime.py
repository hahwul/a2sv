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

def m_crime_run(ip_address,iPort,displayMode):
	#Identifier is not used
	IP = ip_address.strip()##
	try:
		socket.inet_aton(IP)
		showDisplay(displayMode," - [LOG] IP Check Ok.")
	except:
		showDisplay(displayMode,"%s,invalid IP" % IP)
		return "0x02"
	try:
		showDisplay(displayMode," - [LOG] Start SSL Connection")
		result = subprocess.Popen(['timeout','4','openssl','s_client','-connect',ip_address+":"+str(iPort),"-nextprotoneg","NULL"], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
		showDisplay(displayMode," - [LOG] Analysis SSL Information")
		#showDisplay(displayMode,result)
		if "Protocols advertised by server" in result:
			showDisplay(displayMode," - [LOG] 'Protocols advertised by server'")
			return "0x00"
		else:
			showDisplay(displayMode," - [LOG] 'Includes SPDY version <4'")
			return "0x01"
	except:
		showDisplay(displayMode,"[INF] Error CRIME Module")
		return "0x02"


