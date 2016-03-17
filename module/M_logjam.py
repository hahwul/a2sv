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
#Module

def m_logjam_run(ip_address,iPort):
	#Identifier is not used
	IP = ip_address.strip()##
	try:
		socket.inet_aton(IP)
		print " - [LOG] IP Check Ok."
	except:
		print "%s,invalid IP" % IP
		return "0x00"
	try:
		print " - [LOG] Start SSL Connection / Gathering Information"
		result = subprocess.Popen(['timeout','4','openssl','s_client','-connect',ip_address+":"+str(iPort),"-cipher","EDH"], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
		print " - [LOG] Ending Get Information"
		#print result
		if "Cipher is DEH" in result:
			print " - [LOG] 'Cipher is DEH' in Response"
			return "0x01"
		else:
			print " - [LOG] 'Cipher is DEH' not in Response"
			return "0x00"
	except:
		print "[INF] Error LOGJAM Module"
		return


