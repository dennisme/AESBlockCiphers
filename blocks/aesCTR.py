#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData
from xor import xorData


class CTRMode(object):
    '''
    This class is used to implment CTR mode using python cryptography. The
    chunkData, padData, and xorData are custom classes that are used to build
    functionality that python cryptography would normally handle in the
    backend. Educational purposes only.
    '''
    def __init__(self, key, iv):
        '''
        This constructor initilizes the key and initialization vector. The key
        and the IV should be the same length, either 16, 24, or 32 bytes long.
        '''
        self.key = key
        self.iv = iv

    # Input validation for the key
    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if (len(key) not in [16, 24, 32]):
            raise Exception('The key must be 16, 24, or 32 bytes long.')
        self._key = key

    # Input validation for the IV
    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, iv):
        if (len(iv) not in [16, 24, 32]):
            raise Exception('The iv must be 16, 24, or 32 bytes long.')
        self._iv = iv

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
        by the reciever of the message.
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
            raise ValueError('Plaintext string can not be empty')
        elif (len(data) < 16):
            paddedList = [self.pad(data)]
            return paddedList
        elif (len(data) == 16):
            dataList = [data]
            return dataList
        elif(len(data) % 16 == 0):
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
        This encrypt constructor takes the plaintext string, sends it to the
        preProcess class to be padded and chunked. The blocks are then
        encrypted using python cryptography library ECB mode.
        Note: CTR does not normally use padding. See issue related to #12.
        '''
        # Send the plaintext string to be padded and chunked
        plaintext = self.preProcess(plaintext)

        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()

        ciphertextList = []
        # Loop through the plaintext elements, return ciphertext string
        # NIST 800-38A first block does not get incremented with the counter
        for i in range(0, len(plaintext)):
            if (i == 0):
                firstBlock = encryptor.update(self.iv)
                xor = xorData(firstBlock, plaintext[i])
                firstElement = xor.getXor()
                ciphertextList.append(firstElement)
            elif (i >= 1):
                # There will be an error here if ord(preCount) > 256 
                # Need to come up with a fix
                preCount = self.iv[-1]
                countElement = chr(ord(preCount) + i) 
                count = self.iv[:-1] + str(countElement)
                nBlock = encryptor.update(count)
                xor = xorData(nBlock, plaintext[i])
                nElement = xor.getXor()
                ciphertextList.append(nElement)
        return ''.join(ciphertextList)

    def decrypt(self, ciphertext):
        '''
        This decrypt constructor takes the plantext string, sends it to the
        postProcess class to be chunked. The blocks are sent to the python
        cryptography ECB mode for encryption. In CTR, the decryption of the
        blocks uses the encryption of the IV + counter and the key, xored with the
        ciphertext to get the plaintext.
        Note: CTR does not normally use padding. See issue related to #12.
        '''
        # Send the ciphertext string to be chunked
        ciphertext = self.postProcess(ciphertext)

        # Initilize the python cryptography ECB mode
        # CTR uses encryption algorithm
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()

        plaintextList = []
        # Loop through the ciphertext list, return plaintext string
        for i in range(0, len(ciphertext)):
            if (i == 0):
                firstBlock = encryptor.update(self.iv)
                xor = xorData(firstBlock, ciphertext[i])
                firstElement = xor.getXor()
                plaintextList.append(firstElement)
            elif (i >= 1):
                # There will be an error here if ord(preCount) > 256 
                # Need to come up with a fix
                preCount = self.iv[-1]
                countElement = chr(ord(preCount) + i) 
                count = self.iv[:-1] + str(countElement)
                nBlock = encryptor.update(count)
                xor = xorData(nBlock, ciphertext[i])
                nElement = xor.getXor()
                plaintextList.append(nElement)
        paddedElement = self.unPad(plaintextList.pop(-1))
        plaintextList.append(paddedElement)
        return ''.join(plaintextList)
