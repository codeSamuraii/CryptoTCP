# CryptoTCP
This module was created to easily implement a secure communication tunnel using Python 3.
###### This software was a personnal proof-of-concept and is not suitable for production use.

## Introduction
The CryptoTCP class provides a simple way to set-up a TCP server/client with hybrid encryption, handling cryptographic and network operations such as: socket management, data transmission, key generation, encryption/decryption, encapsulation etc.

#### Examples

##### Server
```python
# This function is called each time nw data is received
def my_process_func(data):
    print("\n* * * * CALLING FUNC * * * *")
    print(str(data), "\n")

my_tcp_server = CryptoTCP()
my_tcp_server.listen_auto(8978, my_process_func, block=True)
```
The server will listen on port 8978 and automatically set-up a secure communication with the client. Every incoming message is then deciphered and passed to our processing function. The last instruction will block until handler is closed.

##### Client
```python
my_tcp_client = CryptoTCP()
my_tcp_client.connect_auto("127.0.0.1", 8978)

my_tcp_client.send_secure("(1) Hello, world!")
my_tcp_client.send_secure("(2) This exchange is secure.")

my_tcp_client.stop_remote_handler()
```
The client will connect to the server, set-up encryption and send two encrypted messages. After that, it will notify the server to stop waiting for data.

## API documentation
#### Introduction
All *private* methods and attributes - those which start with a single underscore, e.g. ```_sig_post()``` - are generally not supposed to be called, they are meant for internal use only.

#### CryptoEngine
All cryptographic operations are handled by the *CryptoEngine* class, from which CryptoTCP inherits.

CryptoEngine can be used on it's own but does not provide generic encryption methods, it was designed to be used in conjonction with CryptoTCP.

###### Initialization
Arguments (all optional):
* ```aes_byte_strenght``` (defaults to 16) : size in byte of the AES session key.
* ```rsa_bit_strenght``` (default to 2048) : size in bits of the RSA keychain.

_**To be continued...**_
