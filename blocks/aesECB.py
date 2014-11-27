#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData

class ECBMode:
    '''
    This class is used to implment ECB mode using python cryptography. The
    chunkData and padData are custom classes that are used to build 
    functionality that python cryptography would normally handle in the
    backend. Educational purposes only. 
    '''
    def __init__(self, key, bits):
        '''
        This constructor initilizes the key to be used for encryption and 
        decryption. The key must be 16 bytes long.
        '''
        self.key = key
        self.bits = bits
    
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
        The backend constructor takes the plaintext. Then pads and chunks if
        needed. Returns a list. 
        '''
        if (data == ''):
            raise ValueError('Plaintext string can not be empty')
        elif (len(data) < 16):
            paddedList = [self.pad(data)]
            return paddedList
        elif (len(data) == 16):
            dataList = [data]
            return dataList
        elif (len(data) % 16 == 0):
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
        //todo
        '''
        if (len(data) == '' or len(data) < 16):
            raise ValueError('Invalid ciphertext byte length')
        else:
            chunk = chunkData(data)
            return chunk.getChunk()

    def encrypt(self, plaintext):
        '''
        //todo
        '''
        plaintext = self.preProcess(plaintext)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key),modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()
        ciphertextList = []
        for i in range(0, len(plaintext)):
            ciphertext = encryptor.update(plaintext[i])
            ciphertextList.append(ciphertext)
        return ''.join(ciphertextList)
                    
    def decrypt(self, ciphertext):
        '''
        //todo
        '''
        ciphertext = self.postProcess(ciphertext)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key),modes.ECB(),
                backend = backend)
        decryptor = cipher.decryptor()
        plaintextList = []
        plaintextList2 = []
        if (len(ciphertext) == 1):
            plaintext = decryptor.update(ciphertext[0])
            unPaddedPt = self.unPad(plaintext)
            return unPaddedPt
        else:
            for i in range(0, len(ciphertext)):
                plaintext = decryptor.update(ciphertext[i])
                plaintextList.append(plaintext)
            paddedElement = self.unPad(plaintextList.pop(-1))
            plaintextList.append(paddedElement)
            return ''.join(plaintextList)
