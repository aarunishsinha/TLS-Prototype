import random
import os
from datetime import datetime
from OpenSSL import crypto
import ssl
import time
import socket
import hashlib
import hmac
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
    #Creating Key
    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA,4096)
    print ("Key pair generated")
    if not os.path.exists('PubKeys'):
        os.makedirs('PubKeys')
    with open('PubKeys/client.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))
    if not os.path.exists('Client'):
        os.makedirs('Client')
    with open('Client/client.key', "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))

    HOST = '127.0.0.1'
    PORT_TTP = 54434
    print ("Connecting to the TTP")
    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.connect((HOST,PORT_TTP))
    ttp_socket.sendall(b'client')
    print ("Certificate recieved")
    ttp_socket.close()

    time.sleep(3)
    # Create an SSL context
    context = ssl.SSLContext();
    context.verify_mode = ssl.CERT_REQUIRED;
    ## SETTING THE CHIPHER SUITE RANDOMLY
    cipher_suite = ['ECDHE-RSA-AES128-SHA256','ECDHE-RSA-AES256-SHA384']
    cipher_s = random.choice(cipher_suite)
    context.set_ciphers(cipher_s)
    # Load CA certificate with which the client will validate the server certificate
    context.load_verify_locations("./CA/ca.crt");
    context.load_cert_chain(certfile="./CA/client.crt", keyfile="./Client/client.key");
    HOST = '127.0.0.1'
    PORT_S = 54432

    serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secureClientSocket  = context.wrap_socket(serv_client_sock);
    secureClientSocket.connect((HOST,PORT_S))
    print ("Requested Server Certificate")
    server_cert = secureClientSocket.getpeercert();

    ## VERIFY SERVER'S Certificate
    ### Validate whether the Certificate is indeed issued to the server
    if not server_cert:
        raise Exception("Unable to retrieve server certificate");
    subject = dict(item[0] for item in server_cert['subject']);
    commonName = subject['commonName'];
    if commonName != 'server':
        raise Exception("Incorrect common name in server certificate");
    ### Check dates
    after = str(server_cert['notAfter'])
    after = after[:-4]
    n=datetime.strptime(after,"%b %d %H:%M:%S %Y")
    t1 = time.time()
    tc = datetime.timestamp(n)
    if tc-t1 < 0:
        raise Exception ("Certificate has expired")
    print ("Certificate verified")

    record_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 20))
    time.sleep(1)
    secureClientSocket.send(record_key.encode())
    data = secureClientSocket.recv(4096)
    time.sleep(1)
    mes = decrypt_record(data.decode(),record_key)

    print ("Message Recieved:",mes)
    secureClientSocket.close()

if __name__=="__main__":
    main()
