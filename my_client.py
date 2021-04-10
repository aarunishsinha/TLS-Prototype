import random
import os
from datetime import datetime
from OpenSSL import crypto
import socket

def main():
    # print("c")
    HOST = '127.0.0.1'
    PORT_TTP = 65433

    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.connect((HOST,PORT_TTP))
    ttp_socket.sendall(b'alice')
    ttp_socket.close()

    HOST = '127.0.0.1'
    PORT_S = 65432

    serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_client_sock.connect((HOST,PORT_S))
    serv_client_sock.sendall(b'Hello World')
    data = serv_client_sock.recv(1024)

    print ("Recieved", data.decode())
    serv_client_sock.close()

if __name__=="__main__":
    main()
