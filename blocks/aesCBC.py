#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData
from xor import xorData


class CBCMode(object):
    '''
    This class is used to implment CBC mode using python cryptography. The
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
        if (len(iv) != 16):
            raise Exception('Initialization vector (IV) must be 16 bytes.')
        self._iv = iv

    def pad(self, data):
        '''
        This constructor takes in the string that needs to be padded.
        Calls the custom pad class in the block/padding.py and returns the
        pdded string.
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
            divList = [chunkData(data)]
            return divList
        else:
            chunk = chunkData(data)
            chunkedData = chunk.getChunk()
            for i in range(0, len(chunkedData)):
                if (len(chunkedData[i]) < 16):
                        paddedChunk = self.pad(chunkedData.pop(i))
                        chunkedData.append(paddedChunk)
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
        encrypted using python cryptography library ECB mode. The chaining
        of ciphertexts is done manually.
        '''
        # Send the plaintext string to be padded and chunked
        plaintext = self.preProcess(plaintext)
        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()
        
        # Loop through the elements, special treatment for block 1
        # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
        ciphertextList = []
        for i in range(0, len(plaintext)):
            if (i == 0):
                xor = xorData(self.iv, plaintext[i])
                initialXor = xor.getXor()
                firstElement = encryptor.update(initialXor)
                ciphertextList.append(firstElement)
            elif (i >= 1):
                return ciphertextList[i-1]
                xor = xorData(ciphertextList[i-1], plaintext[i])
                nElementXor = xor.getXor()
                nEncryption = encryptor.update(nElementXor)
                ciphertextList.append(nEncryption)
        return ''.join(ciphertextList)

    def decrypt(self, ciphertext):
        '''
        This decrypt constructor takes the plantext string, sends it to the
        postProcess class to be chunked. The blocks are sent to the python
        cryptography ECB mode for decryption. The first block is tehn xored
        with the IV. The remaining blocks are xored with the previous
        ciphertext in the list. The last element in the plaintextList is
        then unpadded.
        '''
        # Send the ciphertext string to be chunked
        ciphertext = self.postProcess(ciphertext)
        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        decryptor = cipher.decryptor()
        
        # Loop through the ciphertext list, special treatment for block 1
        plaintextList = []
        for i in range(0, len(ciphertext)):
            if (i == 0):
                firstElement = decryptor.update(ciphertext[i])
                xor = xorData(self.iv, firstElement)
                firstPlaintext = xor.getXor()
                plaintextList.append(firstPlaintext)
            elif (i >= 1):
                nElement = decryptor.update(ciphertext[i])
                xor = xorData(ciphertext[i-1], nElement)
                nPlaintext = xor.getXor()
                plaintextList.append(nPlaintext)
        paddedElement = self.unPad(plaintextList.pop(-1))
        plaintextList.append(paddedElement)
        return ''.join(plaintextList)
