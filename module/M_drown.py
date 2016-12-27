import socket
from C_display import *

#Module

def check_tls(hostname,port):
    client_hello = '16030100d8010000d403037d408377c8e5204623867604ab0ee4a140043a4e383f770a1e6b66c2d45d34e820de8656a211d79fa9809e9ae6404bb7bcc372afcdd6f51882e39ac2241a8535090016c02bc02fc00ac009c013c01400330039002f0035000a0100007500000014001200000f7777772e65746973616c61742e6567ff01000100000a00080006001700180019000b00020100002300003374000000100017001502683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202'

    s = socket.socket()
    s.settimeout(5)
    s.connect((hostname,int(port)))
    s.send(client_hello.decode('hex'))
    try:
        data = s.recv(1024*1024)
    except socket.timeout:
        data = ''

    if data:
        server_hello_len = int(data[3:5].encode('hex'),16)
        index = 5
        index += server_hello_len
        cert_msg = data[index:]

        return cert_msg
    
def m_drown_run(hostname,port,displayMode):
	client_hello_payload = '803e0100020015001000100100800200800600400400800700c00800800500806161616161616161616161616161616161616161616161616161616161616161'
	s = socket.socket()
	
	s.settimeout(5)
	s.connect((hostname,int(port)))
	s.sendall(client_hello_payload.decode('hex'))
	try:
		server_hello = s.recv(10*1024)		
	except socket.timeout:
		server_hello = ''
        
	except socket.error:
		showDisplay(displayMode," - [LOG] Execption")
		return "0x02"

	if server_hello:
		try:
			#parse incoming packet to extract the certificate
			index = 0
			length = server_hello[index:index+2].encode('hex')
			index +=2
			msg_type = server_hello[index].encode('hex')
			index +=1
			session_id = server_hello[index].encode('hex')
			index +=1
			cert_type = server_hello[index].encode('hex')
			index +=1
			ssl_version = server_hello[index:index+2]
			index +=2
			cert_len = int(server_hello[index:index+2].encode('hex'),16)
			#showDisplay(displayMode,'cert_len',cert_len)
			index +=2
			cipher_spec_len = server_hello[index:index+2]
			index +=2
			conn_id = server_hello[index:index+2]
			index +=2
			cert = server_hello[index:cert_len+1]
			data = check_tls(hostname,port)
			if data:
				showDisplay(displayMode," - [LOG] Check the TLS CERT")
				showDisplay(displayMode," - [LOG] Check the SSLv2 CERT")
				if cert.encode('hex') in data.encode('hex'):
					showDisplay(displayMode," - [LOG] SSLv2 Enable - Same cert")
					return "0x01"
				else:
					showDisplay(displayMode," - [LOG] SSLv2 Enable - Not same cert")
					return "0x01"
		except Exception as e:
			showDisplay(displayMode,str(e))
			return "0x02"
	else:
		showDisplay(displayMode," - [LOG] Not connected SSLv2")
		return "0x00"
	
	s.close()

