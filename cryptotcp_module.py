# -*- coding: utf-8 -*-

"""
CryptoTCP v0.2
© Rémi Héneault (@codeSamuraii)
https://github.com/codeSamuraii
"""
import logging
import pickle
import socket
import sys
import threading
import time

from Crypto import Random
from Crypto.Cipher import AES as AesCipher
from Crypto.Cipher import PKCS1_OAEP as RsaCipher
from Crypto.PublicKey import RSA


class UnexpectedError(ValueError, TypeError):
    def __init__(self, cause):
        display = "\nUnexpected error. {}".format(cause)
        super().__init__(display)


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
            peer_key = RSA.importKey(key)
        except (ValueError, IndexError, TypeError) as original_ex:
            raise ValueError("Error during import. Key must be invalid.") \
                from original_ex
        else:
            self._rsa_keychain["peer"] = peer_key

    def rsa_encrypt(self, data):
        """Encrypts data using other party's public key.

        Args:
            data (bytes or str): Data to encrypt.

        Returns:
            bytes: Ciphered data.
        """
        peer_key = self._rsa_keychain["peer"]
        if peer_key is None:
            raise KeyError("Peer key not found. Have you imported it ?")

        try:
            send_rsa_cipher = RsaCipher.new(peer_key)
        except Exception as unknown_e:
            raise UnexpectedError("Can't initialize RSA cipher.") \
                from unknown_e

        try:
            ciphered_data = send_rsa_cipher.encrypt(data)
        except ValueError:
            raise ValueError("Incorrect data length.") from None
        except Exception as unknown_e:
            raise UnexpectedError("Exception during RSA encrption.") \
                from unknown_e

        return ciphered_data

    def rsa_decrypt(self, data):
        """Decrypt data using own RSA private key.

        Args:
            data (bytes): Ciphered data.

        Returns:
            bytes: Deciphered data.
        """
        personnal_rsa_key = self._rsa_keychain["private"]
        recv_rsa_cipher = RsaCipher.new(personnal_rsa_key)

        try:
            deciphered_data = recv_rsa_cipher.decrypt(data)
        except ValueError:
            raise ValueError("Incorrect length or failed integrity check.") \
                from None
        except Exception as unknown_e:
            raise UnexpectedError("Exception during RSA decryption.") \
                from unknown_e

        return deciphered_data

    def set_session_aes(self, custom_key=None):
        """Imports specified AES key or generates one.

        Args:
            key (bytes, optional): AES key to import.

        Returns:
            bytes: AES session key to be used for communication.

        """
        if custom_key is None:
            aes_session_key = Random.get_random_bytes(self._aes_size)
        else:
            if not isinstance(custom_key, bytes):
                raise TypeError(
                    "Session custom_key must be a byte string or array.")
            elif len(custom_key) not in {16, 24, 32}:
                raise ValueError(
                    "Session custom_key length must be of [16, 24, 32].")
            else:
                aes_session_key = custom_key

        self._session_key = aes_session_key
        return aes_session_key

    def aes_encrypt(self, data):
        """Encrypt data with AES.

        Args:
            data (bytes or str): Data to encrypt.

        Returns:
            bytes: a pickle bytes buffer containing the encrypted data, the
                nonce and the tag.

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
            raise UnexpectedError("Can't initialize cipher. Session key "
                                  "must be invalid.") from unknown_e

        try:
            ciphered_data, tag = comm_cipher.encrypt_and_digest(data)
        except Exception as unknown_e:
            raise UnexpectedError("Failed AES encryption.") from unknown_e
        else:
            nonce = comm_cipher.nonce
            packet = pickle.dumps([nonce, tag, ciphered_data])

        return packet

    def aes_decrypt(self, data):
        """Decrypts AES-encrypted data.

        This is not a generic decryption function, data input must be a byte
        pickle buffer made by previous method.

        Args:
            data (bytes): Byte buffer containing the necessary for decryption.

        Returns:
            bytes: Bytes representation of decrypted data.

        """
        try:
            data = pickle.loads(data)
            nonce, tag, ciphered = data[0], data[1], data[2]
        except Exception as unknown_e:
            raise UnexpectedError("Corrupted data packet.") from unknown_e

        try:
            comm_cipher = AesCipher.new(self._session_key,
                                        AesCipher.MODE_EAX,
                                        nonce)
        except Exception as unknown_e:
            raise UnexpectedError("Can't initialize AES cipher. "
                                  "Session key must be invalid.") \
                from unknown_e

        try:
            deciphered_data = comm_cipher.decrypt_and_verify(ciphered, tag)
        except Exception as unknown_e:
            raise UnexpectedError("Error during AES decryption.")

        return deciphered_data
