import random
import os
from datetime import datetime
from OpenSSL import crypto
import socket
import ssl

def create_CA(root_ca_path, key_path):
    ''' Create CA and Key'''

    ca_key = crypto.PKey()                              # (RSA public key) OR (key pair)
    ca_key.generate_key(crypto.TYPE_RSA, 4096)
    # ca_key.generate_key(crypto.TYPE_DSA, 4096)
    # print (ca_key.p)
    # ca_key = RSA.generate(1024, random_generator)


    ca_cert = crypto.X509()
    ca_cert.set_version(2)                              # X509v3 (version value is zero-based i.e. 0 is for V1, 1 for V2 and 2 for V3)
    ca_cert.set_serial_number(random.randint(50000000, 100000000))


    ca_subj = crypto.X509Name(ca_cert.get_subject())
    ca_subj.__setattr__('C', "IN")
    ca_subj.__setattr__('ST', "New Delhi")
    ca_subj.__setattr__('L', "Hauz Khas")
    ca_subj.__setattr__('O', "IITD")
    ca_subj.__setattr__('OU', "CSE IITD")
    ca_subj.__setattr__('CN', "CSE IITD TTP")

    ca_cert.set_subject(ca_subj)
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        #crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyCertSign, cRLSign"),
    ])


    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(365*24*60*60)

    ca_cert.sign(ca_key, 'sha256')

    # Save certificate
    with open(root_ca_path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))

    # Save private key
    with open(key_path, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))

    # Save public key
    with open('Pubkeys/ca.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))


def load_CA(root_ca_path, key_path):
    ''' Load CA and Key'''

    with open(root_ca_path, "r") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(key_path, "r") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    return ca_cert, ca_key

def load_pubkey(path):
    with open(path, "r") as f:
        ca_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
    return ca_key

def CA_varification(ca_cert):
    ''' Verify the CA certificate '''

    ca_expiry = datetime.strptime(str(ca_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
    now = datetime.now()
    validity = (ca_expiry - now).days
    print ("CA Certificate valid for {} days".format(validity))


def create_cert(ca_cert, ca_subj, ca_key, client_cn,user_key):
    ''' Create Client certificate '''

    # client_key = crypto.PKey()
    # client_key.generate_key(crypto.TYPE_RSA, 4096)

    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(random.randint(50000000, 100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = client_cn

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(user_key)

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),
        #crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])

    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(365*24*60*60)

    client_cert.sign(ca_key, 'sha384')


    with open("CA/"+client_cn + ".crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))


def client_varification():
    pass



def main():

    '''Create self signed certificates'''

    key_path = "CA/ca.key"
    root_ca_path = "CA/ca.crt"

    if not os.path.exists('PubKeys'):
        # print ("Creating CA driectory")
        os.makedirs('PubKeys')
    if not os.path.exists('CA'):
        print ("Creating CA driectory")
        os.makedirs('CA')

    if not os.path.exists(root_ca_path):
        print ("Creating CA Certificate, Please provide the values")
        create_CA(root_ca_path, key_path)
        print ("Created CA Certificate")
        ca_cert, ca_key = load_CA(root_ca_path, key_path)
        CA_varification(ca_cert)
    else:
        print ("CA certificate has been found as {}".format(root_ca_path))
        ca_cert, ca_key = load_CA(root_ca_path, key_path)
        CA_varification(ca_cert)

        # SERVER INTERACTION
    HOST = '127.0.0.1'
    PORT_TTP = 54433

    server_cn = ''
    subject = ca_cert.get_subject()

    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.bind((HOST,PORT_TTP))
    ttp_socket.listen()
    server_conn,server_addr = ttp_socket.accept()
    print ("Connecting to server")
    while True:
        data = server_conn.recv(1024)
        if not data:
            break
        server_cn = data.decode()
    server_key=load_pubkey("PubKeys/server.key")
    create_cert(ca_cert, subject, ca_key, server_cn, server_key)
    print ("Server Digital Certificate issued")
    # server_conn.sendall(server_cn.encode())
    ttp_socket.close()


        # CLIENT INTERATION
    PORT_TTP = 54434

    client_cn = ''

    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.bind((HOST,PORT_TTP))
    ttp_socket.listen()
    client_conn,client_addr = ttp_socket.accept()
    # with client_conn:
    print ("Connecting to Client")
    while True:
        data = client_conn.recv(1024)
        if not data:
            break
        client_cn = data.decode()
        # client_conn.sendall(data)
    client_key=load_pubkey("PubKeys/client.key")
    create_cert(ca_cert, subject, ca_key, client_cn, client_key)
    print ("Client Digital Certificate issued")
    # client_conn.sendall(client_cn.encode())
    ttp_socket.close()



if __name__ == "__main__":
    main()
