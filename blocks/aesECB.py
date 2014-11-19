#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData
from xor import xorData

class aesECB:
    '''
    This class is used to implment ECB mode using python cryptography. The
    chunkData, padData, and xorData are custom classes that are used to build 
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
        pading = padData(self.bits, data)
        paddedData = pading.padString()
        return paddedData

    def unPad(self, data):
        '''
        This constructor takes in the padded string that need to be unpadded 
        by the receiver of the message. 
        '''
        unPadding = padData(self.bits, data)
        unPaddedData = unPadding.unPadString()
        return unPaddedData
    
    def encrypt(self, plaintext):
        '''
        This constructor takes the plaintext, after being padded and encrypts
        it with the key.
        '''
        if (plantext == ''):
            raise ValueError('Plaintext can not be empty')
        elif (len(plaintext < 16):
            #TODO Sent to padding
            #encrypt
    
    def decrypt(self, ciphertext):
        #TODO take cipher text and decrypt it using python cryptography
        


