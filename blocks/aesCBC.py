#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData
from xor import xorData

class aesCBC:
    '''
    This class is used to implment CBC mode using python cryptography. The
    chunkData, padData, and xorData are custom classes that are used to build 
    functionality that python cryptography would normally handle in the 
    backend. Educational purposes only.
    '''
    def __init__(self, key):
        self.key = key
        return self.key
        
