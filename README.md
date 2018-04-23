# CryptoTCP
This class was created to easily implement a secure communication tunnel in Python 3.

The CryptoTCP class provides a simple way to set-up a TCP server and client with hybrid (RSA + AES) encryption, handling both cryptographic and network operations such as socket listening and connection, key generation, data encryption and decryption etc.

Simple server example:
```python
from cryptotcp import CryptoTCP


# This function is called each time new data is received
def my_processing_func(data):
    print("\n* * * * CALLING FUNC * * * *")
    print(str(data) + "\n")


my_tcp_server = CryptoTCP()
my_tcp_server.listen_auto(8978, my_processing_func, block=True, close_after=True)
```

Corresponding client:
```python
from cryptotcp import CryptoTCP

my_tcp_client = CryptoTCP()
my_tcp_client.connect_auto("127.0.0.1", 8978)

my_tcp_client.send_secure("(1) Hello, world!")
my_tcp_client.send_secure("(2) This exchange is secure.")

my_tcp_client.stop_remote_handler()
my_tcp_client.disconnect()
```

Will produce the following output server-side:
```
INFO   RSA 2048 bits - AES 16 bytes
INFO   Listening on 8978...
INFO   Inbound connection from 127.0.0.1
INFO   Starting communication handler on Thread-1
INFO   T1: 102 bytes received. Final size: 17 bytes

* * * * CALLING FUNC * * * *
b'(1) Hello, world!'

INFO   T1: 113 bytes received. Final size: 28 bytes

* * * * CALLING FUNC * * * *
b'(2) This exchange is secure.'

INFO   T1: Closing handler.
```
