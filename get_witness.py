import socket
import ssl
import pprint
ssl.SSLContext

hostname = 'finance.yahoo.com'
context = ssl.create_default_context()

with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())
        cert = ssock.getpeercert()
        print(cert)
