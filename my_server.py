import random
import os
from datetime import datetime
from OpenSSL import crypto
import ssl
import time
import socket
import hmac
import hashlib
import string

def encrypt_record(message, key):
    signature = hmac.new(key.encode(), message.encode(), hashlib.sha1).digest()
    m = "sendrecieve" + str(signature) + message
    return m
def decrypt_record(data, key):
    if not data.startswith("sendrecieve"):
        raise Exception("Message recieved from the wrong host or port")
    m1 = data.split("'")
    signature = "b'" + m1[1] + "'"
    message = m1[2]
    good_signature = hmac.new(key.encode(),message.encode(),hashlib.sha1).digest()
    if signature!=str(good_signature):
        raise Exception("Different keys on sender and reciever")
    obj = message
    return obj
def main():
    # Retrieving a certificate from TTP
    server_key = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA,4096)
    print ("Key pair generated")
    if not os.path.exists('PubKeys'):
        os.makedirs('PubKeys')
    with open('PubKeys/server.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
    if not os.path.exists('Server'):
        os.makedirs('Server')
    with open('Server/server.key', "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))

    HOST = '127.0.0.1'
    PORT_TTP = 54433
    print ("Connecting to the TTP")
    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.connect((HOST,PORT_TTP))
    ttp_socket.sendall(b'server')
    print ("Certificate recieved")
    ttp_socket.close()

    time.sleep(3)
    # Loading server certificate
    with open("CA/server.crt", "r") as f:
        server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
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
    print ("Requested Client Certificate")
    client_cert = secure_serv_client_sock.getpeercert();
    print (secure_serv_client_sock.cipher())

    # Check the client certificate bears the expected name as per server's policy
    if not client_cert:
        raise Exception("Unable to get the certificate from the client");
    clt_subject    = dict(item[0] for item in client_cert['subject']);
    clt_commonName = clt_subject['commonName'];
    if clt_commonName != 'client':
        raise Exception("Incorrect common name in client certificate");
    ## Check dates
    after = str(client_cert['notAfter'])
    after = after[:-4]
    n=datetime.strptime(after,"%b %d %H:%M:%S %Y")
    t1 = time.time()
    tc = datetime.timestamp(n)
    if tc-t1 < 0:
        raise Exception ("Certificate has expired")
        
    print ("Certificate Verified")

    m = "The OTP for transferring Rs 1,00,000 to your friend’s account is 256345."
    with client_conn:
        print ("Connected to Client")
        while True:
            record_key = secure_serv_client_sock.recv(1024)
            if not record_key:
                break
            time.sleep(1)
            data = encrypt_record(m,record_key.decode())
            time.sleep(1)
            secure_serv_client_sock.send(data.encode())
    secure_serv_client_sock.close()

if __name__=="__main__":
    main()
