import random
import os
from datetime import datetime
from OpenSSL import crypto
import ssl
import time
import socket

def main():
    # print("s")
    # Retrieving a certificate from TTP
    server_key = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA,4096)
    # server_key.generate_key(crypto.TYPE_DSA,4096)
    if not os.path.exists('PubKeys'):
        # print ("Creating CA driectory")
        os.makedirs('PubKeys')
    with open('PubKeys/server.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
    if not os.path.exists('Server'):
        # print ("Creating CA driectory")
        os.makedirs('Server')
    with open('Server/server.key', "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))

    HOST = '127.0.0.1'
    PORT_TTP = 54433

    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.connect((HOST,PORT_TTP))
    ttp_socket.sendall(b'server')
    # d = ttp_socket.recv(1024)
    # print ("Certificate Recieved", d.decode())
    ttp_socket.close()

    time.sleep(3)
    # Loading server certificate
    with open("CA/server.crt", "r") as f:
        server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    # print (server_cert)
    # Connecting to Client
    HOST = '127.0.0.1'
    PORT_S = 54432
    serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_client_sock.bind((HOST,PORT_S))
    serv_client_sock.listen()
    client_conn,client_addr=serv_client_sock.accept()
    ## Secure socket
    secure_serv_client_sock = ssl.wrap_socket(client_conn,server_side=True,cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLSv1_2,ca_certs="./CA/ca.crt",certfile="./CA/server.crt",keyfile="./Server/server.key")
    # Get certificate from the client
    client_cert = secure_serv_client_sock.getpeercert();
    # print (client_cert)
    print (secure_serv_client_sock.cipher())
    # print (secure_serv_client_sock.shared_ciphers())

    clt_subject    = dict(item[0] for item in client_cert['subject']);
    clt_commonName = clt_subject['commonName'];

    # Check the client certificate bears the expected name as per server's policy
    if not client_cert:
        raise Exception("Unable to get the certificate from the client");

    if clt_commonName != 'client':
        raise Exception("Incorrect common name in client certificate");
    with client_conn:
        print ("Connected by", client_addr)
        while True:
            data = secure_serv_client_sock.recv(1024)
            if not data:
                break
            secure_serv_client_sock.send(data)
    secure_serv_client_sock.close()

if __name__=="__main__":
    main()
