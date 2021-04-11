import random
import os
from datetime import datetime
from OpenSSL import crypto
import ssl
import time
import socket

def main():
    # print("c")
    #Creating Key
    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA,4096)
    if not os.path.exists('PubKeys'):
        # print ("Creating CA driectory")
        os.makedirs('PubKeys')
    with open('PubKeys/client.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))
    if not os.path.exists('Client'):
        # print ("Creating CA driectory")
        os.makedirs('Client')
    with open('Client/client.key', "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))

    HOST = '127.0.0.1'
    PORT_TTP = 54434

    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.connect((HOST,PORT_TTP))
    ttp_socket.sendall(b'client')
    # d = ttp_socket.recv(1024)
    # print ("Certificate Recieved", d.decode())
    ttp_socket.close()

    time.sleep(3)

    HOST = '127.0.0.1'
    PORT_S = 54432

    serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_client_sock.connect((HOST,PORT_S))
    serv_client_sock.sendall(b'Hello World')
    data = serv_client_sock.recv(1024)

    print ("Recieved", data.decode())
    serv_client_sock.close()

if __name__=="__main__":
    main()
