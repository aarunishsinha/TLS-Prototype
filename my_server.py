import random
import os
from datetime import datetime
from OpenSSL import crypto
import socket

def main():
    # print("s")
    HOST = '127.0.0.1'
    PORT_TTP = 65433

    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.connect((HOST,PORT_TTP))
    ttp_socket.sendall(b'bob')
    ttp_socket.close()

    HOST = '127.0.0.1'
    PORT_S = 65432
    serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_client_sock.bind((HOST,PORT_S))
    serv_client_sock.listen()
    client_conn,client_addr=serv_client_sock.accept()
    with client_conn:
        print ("Connected by", client_addr)
        while True:
            data = client_conn.recv(1024)
            if not data:
                break
            client_conn.sendall(data)
    serv_client_sock.close()

if __name__=="__main__":
    main()
