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
        if (len(key) not in [16,24,32]):
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
        //todo xor should happen here
        '''
        if (len(data) == ''):
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
            for i in range (0, len(chunkedData)):
                if (len(chunkedData[i]) < 16):
                        paddedChunk = self.pad(chunkedData.pop(i))
                        chunkedData.append(paddedChunk)
            return chunkedData

    def postProcess(self, data):
        '''
        //todo xor should happen here
        '''
        if (len(data) == '' or len(data) < 16):
            raise ValueError('Invalid ciphertext byte length.')
        else:
            chunk = chunkData(data)
            return chunk.getChunk()
    
    def encrypt(self, plaintext):
        '''
        //todo
        '''
        # Send the plaintext string to be padded and chunked 
        plaintext = self.postProcess(plaintext)
       
        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key),modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()
        
        ciphertextList = []
        xor = xorData(self.iv, plaintext[0])
        initialXor = xor.getXor()
        firstElement = encryptor.update(initialXor)
        ciphertextList.append(firstElement)
        
        #Add the second element to the list. 
#        getSecondXor = xorData(ciphertextList[0], plaintext[1])
#        secondXor = getSecondXor.getXor() 

        if (len(plaintext) == 1):
            return ''.join(ciphertextList)
        if (len(plaintext) >= 2):
            xorx = xorData(ciphertextList[0], plaintext[1])
            secondXor = xorx.getXor() 
            return ''.join(ciphertextList) 
        if (len(plaintext) >= 3):
            for i in range(2, len(plaintext)):
                return ciphertextList

                 
#        for i in range(0, len(plaintext)):
        # if 1 just return the ciphertextList
        #if 2 retrun cipherext list
        # more than 2 loop and return
        #idea was to xor the first element then encrypt add to the new list
        #if plaintext len > 1 loop and encrypt 
#        startElement = xorData(plaintext[0],self.IV)
#        for i in range(0, len(plaintext)):
            
#        return ''.join(ciphertextList)

    def decrypt(self, ciphertext):
        '''
        //todo
        '''
        ciphertext = self.postProcess(ciphertext)
        backed = default_backend()
        cipher = Cipher(algorithms.AES(self.key),modes.ECB(),
                backend = backend)
        decryptor = cipher.decryptor()
        plaintextList = []
        #//todo         
