# -*- coding: utf-8 -*-

"""
CryptoTCP v0.2
© Rémi Héneault (@codeSamuraii)
https://github.com/codeSamuraii
"""
import sys
import time
import socket
import pickle
import logging
import threading

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES as AesCipher
from Crypto.Cipher import PKCS1_OAEP as RsaCipher


class InvalidParameterError(ValueError, TypeError):
    def __init__(self, message):
        super().__init__("unexpected exception.\n" + message +
                         "\nUse provided methods to avoid data inconsistency.")

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

    Methods:
        import_peer_rsa: import the other party's public key.
        set_session_aes: generate or import the AES session key.
        rsa_encrypt - rsa_decrypt - aes_encrypt - aes_decrypt: self-explanatory.
    """

    def __init__(self, aes_byte_strenght=16, rsa_bit_strenght=2048):
        # Arguments verification
        if aes_byte_strenght not in {16, 24, 32}:
            raise ValueError("AES strenght must be of [16, 24, 32]")
        if rsa_bit_strenght not in {1024, 2048, 3072}:
            raise ValueError("RSA strenght must be of [1024, 2048, 3072]")

        self._aes_size = aes_byte_strenght
        self._rsa_size = rsa_bit_strenght
        self._rsa_byte_size = int(rsa_bit_strenght / 8)

        # Generate RSA keychain
        rsa_private = RSA.generate(rsa_bit_strenght)
        rsa_public = rsa_private.publickey()
        rsa_public_ssh = rsa_public.exportKey('OpenSSH')

        self._rsa_keychain = {
            "private": rsa_private,
            "public": rsa_public,
            "ssh": rsa_public_ssh,
            "peer": None}

        self._session_key = None

    def import_peer_rsa(self, key):
        """Imports the other party's RSA public key.

        The public key can be transmitted in plain text using it's ssh-exported
        version.

        Args:
            key (bytes): The public key to use for encryption.
        """
        try:
            peerKey = RSA.importKey(key)
        except (ValueError, IndexError, TypeError):
            raise ValueError("Error during import. Key must be invalid.") \
                from None

        self._rsa_keychain["peer"] = peerKey

    def rsa_encrypt(self, data):
        """Encrypts data using other party's public key.

        Args:
            data (bytes or str): Data to encrypt.

        Returns:
            bytes: Ciphered data.
        """
        peerKey = self._rsa_keychain["peer"]
        if peerKey is None:
            raise KeyError("Peer key not found. Have you imported it ?")

        if isinstance(data, str):
            data = data.encode('utf-8')

        sendCipher = RsaCipher.new(peerKey)

        try:
            ciphered_data = sendCipher.encrypt(data)
        except ValueError:
            raise ValueError("Incorrect data length.") from None
        except Exception as unknown_e:
            raise InvalidParameterError("Encryption error. Peer key must be invalid.") \
                from unknown_e

        return ciphered_data

    def rsa_decrypt(self, data):
        """Decrypt data using own RSA private key.

        Args:
            data (bytes): Ciphered data.

        Returns:
            bytes: Deciphered data.
        """
        persKey = self._rsa_keychain["private"]
        recvCipher = RsaCipher.new(persKey)

        try:
            deciphered_data = recvCipher.decrypt(data)
        except ValueError:
            raise ValueError("Incorrect length or failed integrity check.")
        except Exception as unknown_e:
            raise InvalidParameterError("Decryption error.") from unknown_e

        return deciphered_data

    def set_session_aes(self, key=None):
        """Imports specified AES key or generates one.

        Args:
            key (bytes, optional): AES key to import.

        Returns:
            bytes: AES session key to be used for communication.

        """
        if key is None:
            sessionKey = Random.get_random_bytes(self._aes_size)
        else:
            if not isinstance(key, bytes):
                raise TypeError("Session key must be a byte string or array.")
            elif len(key) not in {16, 24, 32}:
                raise ValueError("Session key length must be of [16, 24, 32].")
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
                nonce and the tagA.

        """
        if not isinstance(data, (str, bytes)):
            raise TypeError("Input data type must be string or bytes.")
        if self._session_key is None:
            raise KeyError("No session key found. Import or generate one.")

        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            comm_cipher = AesCipher.new(self._session_key, AesCipher.MODE_EAX)
        except Exception as unknown_e:
            raise InvalidParameterError("Error while creating cipher.") \
                from unknown_e
# FIXME: HERE
        try:
            ciphered_data, tag = comm_cipher.encrypt_and_digest(data)
        except Exception:
            pass

        nonce = comm_cipher.nonce
        packet = pickle.dumps([nonce, tag, ciphered_data])
        return packet
