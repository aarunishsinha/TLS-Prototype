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
    # client_key.generate_key(crypto.TYPE_DSA,4096)
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
    # Create an SSL context
    context = ssl.SSLContext();
    context.verify_mode = ssl.CERT_REQUIRED;
    # cipher_suite = 'ECDHE-ECDSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384'
    ## SETTING THE CHIPHER SUITE RANDOMLY
    cipher_suite = ['ECDHE-RSA-AES128-SHA256','ECDHE-RSA-AES256-SHA384']
    cipher_s = random.choice(cipher_suite)
    # print(cipher_s)
    context.set_ciphers(cipher_s)
    # Load CA certificate with which the client will validate the server certificate
    context.load_verify_locations("./CA/ca.crt");
    context.load_cert_chain(certfile="./CA/client.crt", keyfile="./Client/client.key");
    HOST = '127.0.0.1'
    PORT_S = 54432

    serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secureClientSocket  = context.wrap_socket(serv_client_sock);
    secureClientSocket.connect((HOST,PORT_S))
    server_cert = secureClientSocket.getpeercert();
    # print (server_cert)
    print (secureClientSocket.cipher())
    print (secureClientSocket.compression())
    # print (secureClientSocket.shared_ciphers())
    # Validate whether the Certificate is indeed issued to the server
    subject = dict(item[0] for item in server_cert['subject']);
    commonName = subject['commonName'];
    if not server_cert:
        raise Exception("Unable to retrieve server certificate");

    if commonName != 'server':
        raise Exception("Incorrect common name in server certificate");
    secureClientSocket.send(b'Hello World')
    data = secureClientSocket.recv(1024)

    print ("Recieved", data.decode())
    secureClientSocket.close()

if __name__=="__main__":
    main()
