import socket, ssl, sys, argparse
#Module
class Responses:
    ACCEPT, REJECT, NOT_AVAILABLE = range(3)

def test_server(hostname, port, ssl_version, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl_version)
        ssl_sock.connect((hostname, port))
        return Responses.ACCEPT
    except ssl.SSLError:
        return Responses.REJECT
    except socket.error:
        return Responses.NOT_AVAILABLE
    finally:
        ssl_sock.close()

def m_poodle_run(hostname,port):
    quiet = 1
    timeout = 1
    result = test_server(hostname, port, ssl.PROTOCOL_SSLv3, timeout)
    if result == Responses.ACCEPT:
        print " - [LOG] SSLv3 CONNECTION ACCEPTED"
        return "0x01"
    elif result == Responses.REJECT:
        print " - [LOG] SSLv3 Rejected"
        return "0x00"
    else:
        print " - [LOG] SSLv3 No Answer"
        return "0x00"

