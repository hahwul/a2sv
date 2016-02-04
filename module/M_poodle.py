import socket, ssl, sys, argparse

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

common_ports = {
    'https': 443
}

message_ports = {
    'imaps': 993,
    'pops': 995,
    'smtps': 465,
    'submission': 587,
    'nntp': 563,
    'xmpp': 5223,
    'irc': 6679,
    'irc': 6697
}

web_ports = {
    'cpanel': 2083,
    'whm': 2087,
    'cpanel webmail': 2096,
    'plesk': 8443
}

file_transfer_ports = {
    'ssh': 22,
    'ftps': 989,
    'ftps': 990,
    'ldap': 636,
    'ms-ldap': 3269
}

database_ports = {
    'oracle': 2484,
    'mysql': 3307,
    'mssql': 1433
}

def get_services(group):
    services = dict()
    if group == "https":
        services.update(common_ports)
    elif group == "msg":
        services.update(message_ports)
    elif group == "web":
        services.update(web_ports)
    elif group == "file":
        services.update(file_transfer_ports)
    elif group == "db":
        services.update(database_ports)
    elif group == "all":
        services.update(common_ports)
        services.update(message_ports)
        services.update(web_ports)
        services.update(file_transfer_ports)
        services.update(database_ports)
    return services

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="The address to scan.")
    parser.add_argument("-q", "--quiet", default=False, action="store_true", help="Hide output for services that the server doesn't support.")
    parser.add_argument("-t", "--timeout", default=1, type=float, help="Number of seconds to wait before giving up on a port.")
    parser.add_argument("-p", "--ports", default="https", help="Group of protocols to test. Valid values are: all, https, db, file, web, msg.")
    args = parser.parse_args()
    return args

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

