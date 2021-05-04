# TLS-Prototype
A prototype for the Transport Layer Security(TLS) protocol.

## Message
```
The OTP for transferring Rs 1,00,000 to your friend’s account is 256345.
```

## Entities
### Trusted Third Party
The TTP issues digital certificates to both the client and the server.

### Server
The server generates a public/private key pair, obtains a digital certificate from the TTP, performs the TLS handshake protocol with the client (including the protocol negotiation, authenticated key exchange and key transcript confirmation), and finally performs the TLS record protocol to securely send the message to the client.

### Client
The client generates a public/private key pair, obtains a digital certificate from the TTP, performs the TLS handshake protocol with the server (including the protocol negotiation, authenticated key exchange and key transcript confirmation), and finally performs the TLS record protocol to securely receive the message sent from the server.

## Constraints
The TTP, the server and the client have access to the following cipher suite. 
- Asymmetric key algorithm: ECDSA or RSA,
- Symmetric key algorithm: AES or CHACHA20, and
- Hashing algorithm: SHA256 or SHA384

## Execution
Open 3 separate terminal windows/tabs.\
Terminal-1:
```
$ python3 my_ttp.py
```
Terminal-2:
```
$ python3 my_server.py
```
Terminal-3:
```
$ python3 my_client.py
```

*Note*: For more details, check [Report](https://github.com/aarunishsinha/TLS-Prototype/readme.pdf)
