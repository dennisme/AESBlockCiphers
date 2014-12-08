#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData


class ECBMode(object):
    '''
    This class is used to implement ECB mode using python cryptography. The
    chunkData and padData are custom classes that are used to build
    functionality that python cryptography would normally handle in the
    backend. Educational purposes only.
    '''
    def __init__(self, key):
        '''
        This constructor initilizes the key to be used for encryption and
        decryption. The key can be 16, 24 or 32 bytes long.
        '''
        self.key = key

    # Input validation for the key
    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if (len(key) not in [16, 24, 32]):
            raise Exception('The key must be 16, 24, or 32 bytes long.')
        self._key = key

    def pad(self, data):
        '''
        This constructor takes in the string that needs to be padded.
        Calls the custom pad class in the block/padding.py and returns the
        padded string.
        '''
        padding = padData(data)
        paddedData = padding.padString()
        return paddedData

    def unPad(self, data):
        '''
        This constructor takes in the padded string that needs to be unpadded
        by the receiver of the message.
        '''
        try:
            unPadding = padData(data)
            unPaddedData = unPadding.unPadString()
            return unPaddedData
        except ValueError:
            return data

    def preProcess(self, data):
        '''
        The preProcess constructor takes the plaintext. Then pads and chunks if
        needed. Returns a list.
        '''
        if (len(data) == 0):
            raise ValueError('Plaintext string can not be empty.')
        elif (len(data) < 16):
            paddedList = [self.pad(data)]
            return paddedList
        elif (len(data) == 16):
            dataList = [data]
            return dataList
        elif (len(data) % 16 == 0):
            divList = chunkData(data)
            return divList.getChunk()
        else:
            chunk = chunkData(data)
            chunkedData = chunk.getChunk()
            shortBlock = self.pad(chunkedData.pop(-1))
            chunkedData.append(shortBlock)
            return chunkedData

    def postProcess(self, data):
        '''
        The postProcess constructor is used to validate and chunk the
        ciphertext. Returns a list.
        '''
        if (len(data) == 0 or len(data) < 16):
            raise ValueError('Invalid ciphertext byte length.')
        else:
            chunk = chunkData(data)
            return chunk.getChunk()

    def encrypt(self, plaintext):
        '''
        The encrypt constructor takes the plaintext string, sends it to the
        preProcess class to be padded and chunked. The blocks are then
        encrypted using the python cryptography library. Returns a ciphertext
        string.
        '''
        # Send the plaintext string to be padded and chunked
        plaintext = self.preProcess(plaintext)
        
        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()
        
        # Loop through and encrypt the plaintext list
        ciphertextList = []
        for i in range(0, len(plaintext)):
            ciphertext = encryptor.update(plaintext[i])
            ciphertextList.append(ciphertext)
        return ''.join(ciphertextList)
    
    def decrypt(self, ciphertext):
        '''
        The decrypt constructor takes the ciphertext string, sends it to
        the postProcess class to be chunked. The blocks are then decrypted
        and unpadded using the python cryptography library. Returns a
        ciphertext string.
        '''
        # Send the ciphertext string to be chunked
        ciphertext = self.postProcess(ciphertext)
        
        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        decryptor = cipher.decryptor()

        # Loop through decrypt the ciphertext and then unpad.
        plaintextList = []
        for i in range(0, len(ciphertext)):
            plaintext = decryptor.update(ciphertext[i])
            plaintextList.append(plaintext)
        paddedElement = self.unPad(plaintextList.pop(-1))
        plaintextList.append(paddedElement)
        return ''.join(plaintextList)
