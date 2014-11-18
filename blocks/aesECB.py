#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from chunk import chunkData
from padding import padData
from xor import xorData

class aesECB:
    
    def __init__(self, key):
#todo
