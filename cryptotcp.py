# -*- coding: utf-8 -*-

"""
CryptoTCP v0.1
© Rémi Héneault 2018
"""
import time
import socket
import pickle
import logging
import threading
from sys import getsizeof
from threading import Thread

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES as AesCipher
from Crypto.Cipher import PKCS1_OAEP as RsaCipher

# Logging and verbose-printing functions
log = logging.getLogger()
logging.basicConfig(format="%(levelname)-6s %(message)s")
dbg, nfo, wrn, err = log.debug, log.info, log.warning, log.error


class CryptoEngine(object):
    """Class that handles cryptographic operations.

    Contains methods to encrypt and decrypt using AES and RSA.
    Before using such methods, you need to import the other's party RSA
    public key and the AES session key using corresponding functions.

    Args:
        aes_byte_strenght (int, optional): Size of the AES session key in
            bytes, defaults to 16.
        rsa_bit_strenght (int, optional): Size of the RSA private key in bits,
            defaults to 2048.
        logging_level (int, optional): Logging level, can be set either using
            'logging' module presets or corresponding integer.

    Methods:
        import_peer_rsa: import the other party's public key.
        set_session_aes: generate or import the AES session key.
        rsa_encrypt - rsa_decrypt - aes_encrypt - aes_decrypt: self-explanatory.
    """

    def __init__(self, aes_byte_strenght=16, rsa_bit_strenght=2048,
                 logging_level=logging.INFO):
        log.setLevel(logging_level)
        dbg("Debugging active.")

        self._aes_size = aes_byte_strenght
        self._rsa_size = rsa_bit_strenght
        self._rsa_byte_size = int(rsa_bit_strenght / 8)
        nfo("RSA {} bits - AES {} bytes".format(
            rsa_bit_strenght,
            aes_byte_strenght))

        dbg("Generating RSA keys...")
        rsa_private = RSA.generate(rsa_bit_strenght)
        rsa_public = rsa_private.publickey()
        rsa_public_ssh = rsa_public.exportKey('OpenSSH')
        dbg("Generating complete.")

        self._rsa_keychain = {
            "private": rsa_private,
            "public": rsa_public,
            "ssh": rsa_public_ssh,
            "peer": None}

    def import_peer_rsa(self, key):
        """Imports the other party's RSA public key.

        The public key can be transmitted in plain text using it's ssh-exported
        version.

        Args:
            key (bytes): The public key to use for encryption.

        Returns:
            bool: True in case of success, False otherwise.

        """
        dbg("Importing peer key...")
        try:
            peerKey = RSA.importKey(key)
        except Exception:
            err("Error while importing peer key!")
            return False

        self._rsa_keychain["peer"] = peerKey
        dbg("Peer key imported.")
        return True

    def rsa_encrypt(self, data):
        """Encrypts data using other party's public key.

        Args:
            data (bytes or str): Data to encrypt.

        Returns:
            bytes: Ciphered data in case of success, empty byte otherwise.

        """
        try:
            peerKey = self._rsa_keychain["peer"]
        except KeyError:
            err("No peer key to encrypt with.")
            return bytes(False)

        if isinstance(data, str):
            data = data.encode('utf-8')

        sendCipher = RsaCipher.new(peerKey)
        try:
            ciphered_data = sendCipher.encrypt(data)
            return ciphered_data
        except ValueError:
            err("Message is too long.")
            return bytes(False)

    def rsa_decrypt(self, data):
        """Decrypt data using own RSA private key.

        Args:
            data (bytes): Ciphered data.

        Returns:
            bytes: Deciphered data in case of success, empty byte otherwise.

        """
        persKey = self._rsa_keychain["private"]
        recvCipher = RsaCipher.new(persKey)

        try:
            deciphered_data = recvCipher.decrypt(data)
            return deciphered_data
        except ValueError:
            err("Wrong length or failed integrity check.")
            return bytes(False)

    def set_session_aes(self, key=None):
        """Imports specified AES key or generates one.

        Args:
            key (bytes, optional): AES key to import.

        Returns:
            bytes: AES session key to be used for communication.

        """
        if key is None:
            dbg("Generating session key... ")
            sessionKey = Random.get_random_bytes(self._aes_size)
        else:
            sessionKey = key

        self._session_key = sessionKey
        return sessionKey

    def aes_encrypt(self, data):
        """Encrypt data with AES.

        Args:
            data (bytes or str): Data to encrypt.

        Returns:
            bytes: a pickle bytes buffer containing the encrypted data, the
                nonce and the tag in case of success, an empty byte otherwise.

        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            comm_cipher = AesCipher.new(self._session_key, AesCipher.MODE_EAX)
        except Exception:
            err("Error while creating the cipher, key must be incorrect.")
            return bytes(False)

        try:
            ciphered_data, tag = comm_cipher.encrypt_and_digest(data)
        except Exception:
            err("Error while decrypting, data must be inconsistent or key is "
                "wrong.")
            return bytes(False)

        nonce = comm_cipher.nonce
        packet = pickle.dumps([nonce, tag, ciphered_data])
        return packet

    def aes_decrypt(self, data):
        """Decrypts AES-encrypted data.

        This is not a generic decryption function, data input must be a byte
        buffer made by previous method.

        Args:
            data (bytes): Byte buffer containing the necessary for decryption.

        Returns:
            bytes: Bytes representation of decrypted data in case of success,
                empty byte otherwise.

        """
        try:
            data = pickle.loads(data)
            nonce, tag, ciphered = data[0], data[1], data[2]
        except pickle.UnpicklingError:
            err("Error while unpacking data.")
            return bytes(False)
        except Exception:
            err("Packed data doesn't match necessary pattern.")
            return bytes(False)

        try:
            comm_cipher = AesCipher.new(self._session_key,
                                        AesCipher.MODE_EAX,
                                        nonce)
        except Exception:
            err("Error while creating the cipher, key must be incorrect.")
            return bytes(False)

        try:
            deciphered_data = comm_cipher.decrypt_and_verify(ciphered, tag)
            return deciphered_data
        except Exception:
            err("Error during decryption. Nonce or tag may be inconsistent.")
            return bytes(False)


class CryptoTCP(CryptoEngine):
    """Class that provides a simple encrypted TCP client or server.

    This class relies on CryptoEngine for cryptographic operations.
    Provided methods are non-generic and should be used with another instance
    of this class.

    Args:
        **engine_params (optional): arguments for CryptoEngine initialization.
    """

    MODE_CLIENT = 1
    MODE_SERVER = 2

    def __init__(self, **engine_params):
        self._mode = 0
        self._current_sock = None
        self._current_thread = None
        self._continue_thread = False

        CryptoEngine.__init__(self, **engine_params)

    def connect(self, ip, port):
        """Connect to distant server.

        Args:
            ip (str): Distant IP.
            port (int): Distant port.

        Returns:
            bool: True in case of success, False otherwise.

        """
        if self._current_sock:
            err("Already connected.")
            return False

        self._mode = self.MODE_CLIENT
        nfo("Connecting to {}:{}... ".format(ip, port))
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            new_sock.connect((ip, port))
        except socket.error as e:
            err("Error #{}: {}".format(e.errno, e.strerror))
            return False

        self._current_sock = new_sock
        nfo("Connected. ")
        return True

    def listen(self, port):
        """Listen for incoming connection.

        Args:
            port (int): Local port to listen on.

        Returns:
            bool: True in case of success, False otherwise.

        """
        if self._current_sock:
            err("Already connected.")
            return False

        self._mode = self.MODE_SERVER
        nfo("Listening on {}...".format(port))
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            new_sock.bind(("127.0.0.1", port))
            new_sock.listen(1)
            new_sock, _distIP = new_sock.accept()
            nfo("Inbound connection from {}".format(_distIP[0]))
        except socket.error as e:
            err("Error #{}: {}".format(e.errno, e.strerror))
            return False

        self._current_sock = new_sock
        return True

    def _exchange_keys_client(self):
        # TODO: Exception handling, return value
        clientRsa = self._rsa_keychain['ssh']
        sessionKey = self.set_session_aes()
        current_sock = self._current_sock

        current_sock.sendall(clientRsa)
        peerKey = current_sock.recv(self._rsa_size)
        self.import_peer_rsa(peerKey)

        ciphKey = self.rsa_encrypt(sessionKey)
        current_sock.sendall(ciphKey)

    def _exchange_keys_server(self):
        # TODO: Exception handling, return value
        serverRsa = self._rsa_keychain['ssh']
        current_sock = self._current_sock

        peerKey = current_sock.recv(self._rsa_size)
        self.import_peer_rsa(peerKey)
        current_sock.sendall(serverRsa)

        sessionKey = self.rsa_decrypt(current_sock.recv(self._rsa_byte_size))
        self.set_session_aes(sessionKey)

    def exchange_keys(self):
        """Exchange RSA and AES keys.

        First each party's public key is transmitted to the other. Then, using
        that key, the client generates and encrypts the AES session key before
        sending it to the server.
        """
        dbg("Exchanging keys... ")
        if self._mode == self.MODE_CLIENT:
            self._exchange_keys_client()
        elif self._mode == self.MODE_SERVER:
            self._exchange_keys_server()
        nfo("Secure connection established.")

    def send_secure(self, data):
        """Send encrypted data to peer.

        Args:
            data (bytes): Data to send.

        Returns:
            bool: True if data is successfully sent and confirmed by peer,
                False if peer fails validation or if a problem occurs.

        """
        current_sock = self._current_sock

        packet = self.aes_encrypt(data)
        size = getsizeof(packet)
        dbg("Sending data (packet size: {})... ".format(size))

        dbg("Forging and sending header...")
        tab = (5 - len(str(size))) * "-"
        header = self.aes_encrypt("INCOMING:{}{}".format(size, tab))
        current_sock.sendall(header)
        dbg("Header sent.")

        current_sock.sendall(packet)
        nfo("Data sent.")

        confirmation = current_sock.recv(4).decode('utf-8')
        if confirmation == "/OK/":
            dbg("Peer confirmation received.")
            return True
        else:
            err("Peer encountered an error.")
            return False

    def _sig_error(self):
        """Notify peer that there was an issue while handling received data."""
        self._current_sock.sendall("/KO/".encode('utf-8'))
        dbg("Error notification sent.")

    def _sig_confirm(self):
        """Notify peer that data was received and decrypted."""
        self._current_sock.sendall("/OK/".encode('utf-8'))
        dbg("Confirmation sent.")

    def _sig_stop(self):
        """Notify peer to stop his communication handler."""
        current_sock = self._current_sock
        header = self.aes_encrypt("INCOMING:STOP-")
        current_sock.sendall(header)

    def _sig_post(self):
        """Ask peer to send back a STOP signal to close local handler."""
        current_sock = self._current_sock
        header = self.aes_encrypt("INCOMING:POST-")
        current_sock.sendall(header)

    def _stop_handler_loop(self):
        self._continue_thread = False

    def _comm_handler(self):
        """Method that waits for data and decrypts it."""
        current_sock = self._current_sock
        id = "T" + threading.current_thread().name[-1] + ": "

        while self._continue_thread:
            header, clear = b'', b''
            dbg(id + "Waiting for communication...")
            try:
                header = current_sock.recv(100)
            except KeyboardInterrupt:
                self._stop_handler_loop()
                self.disconnect()
                break

            if not header:
                self._stop_handler_loop()
                nfo("Connection shut down.")
                break

            header = self.aes_decrypt(header)
            size = header.decode('utf-8')[9:13]

            if size == "STOP":
                dbg(id + "STOP signal received.")
                self._stop_handler_loop()
                break
            if size == "POST":
                dbg(id + "Sending STOP signal to peer.")
                self._sig_stop()
                continue

            size = int(size.replace("-", "", 4))
            dbg(id + "Incoming data ({} bytes)...".format(size))

            data = current_sock.recv(size)
            dbg(id + "Packet received. Decrypting...")

            clear = self.aes_decrypt(data)
            if not clear:
                self._sig_error()
                continue
            else:
                nfo(id + "{} bytes received. Final size: {} bytes".format(size, len(clear)))
                self._sig_confirm()
                yield clear

        nfo(id + "Closing handler.")

    def data_reader(self, process_fnc):
        for data in self._comm_handler():
            process_fnc(data)

    def disconnect(self):
        """Disconnect and close connection."""
        if self._continue_thread:
            err("Handler is still running.")
            return

        try:
            self._current_sock.shutdown(socket.SHUT_RDWR)
        except socket.error:
            dbg("Socket already shutdown.")

        self._current_sock.close()
        self._current_sock = None
        nfo("Socket closed.")

    def process_data(self, process_fnc, block=True, close_after=True):
        """Starts a new thread to handle incoming data.

        Args:
            process_fnc (function): Function to call when data is available.
            block (bool): Wether the current func return immediately or wait
                for the thread to close.
            close_after (bool): Wether the socket should be closed when the
                thread finishes.
        """
        self._continue_thread = True
        newThread = Thread(target=self.data_reader, args=(process_fnc,))
        nfo("Starting communication handler on {}".format(newThread.name))
        newThread.setDaemon(True)
        newThread.start()
        self._current_thread = newThread
        if block:
            newThread.join()
        else:
            newThread.join(0)
        if block and close_after:
            self.disconnect()

    # TODO: Tidy up args
    def listen_auto(self, port, process_fnc=None, **process_args):
        """Listen for incoming connections and automatically exchange keys."""
        self.listen(port)
        self._exchange_keys_server()
        if process_fnc:
            self.process_data(process_fnc, **process_args)
            time.sleep(1)
        else:
            nfo("Waiting for client to be ready...")
            time.sleep(3)  # Wait for distant handler to start

    def connect_auto(self, ip, port, process_fnc=None, **process_args):
        """Same as above."""
        self.connect(ip, port)
        self._exchange_keys_client()
        if process_fnc:
            self.process_data(process_fnc, **process_args)
            time.sleep(1)
        else:
            nfo("Waiting for server to be ready...")
            time.sleep(3)

    def stop_handlers(self):
        """Stop local and remote handlers."""
        self._sig_post()
        self._sig_stop()
        time.sleep(2)

    def stop_local_handler(self):
        """Stop local handler."""
        self._sig_post()

    def stop_remote_handler(self):
        """Stop remote handler."""
        self._sig_stop()
