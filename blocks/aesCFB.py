#!/usr/bin/python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from xor import xorData


class CFBMode(object):
    '''
    This class is used to implment CFB8 mode using python cryptography. The
    base encryption library function used is ECB mode. Specific block function
    is done manually. Educational purposes only.
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

    def encrypt(self, plaintext):
        '''
        This encrypt constructor takes the plaintext string, and loops through
        it encrypting using a 8 bit shift register.
        Note: CFB does not use padding.
        '''
        # Initilize the python cryptography ECB mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()

        ciphertextList = []
        # Loop through the plaintext elements, return ciphertext string
        for i in range(0, len(plaintext)):
            if (i == 0):
                outputBlock = encryptor.update(self.iv)
                xor = xorData(outputBlock[0], plaintext[i])
                firstCiphertextByte = xor.getXor()
                ciphertextList.append(firstCiphertextByte)
                sbitShift = self.iv[1:] + ciphertextList[i]
            elif (i >= 1):
                nBlock = encryptor.update(sbitShift)
                xor = xorData(nBlock[0], plaintext[i])
                nCiphertextByte = xor.getXor()
                ciphertextList.append(nCiphertextByte)
                sbitShift = sbitShift[1:] + ciphertextList[i]
        return ''.join(ciphertextList)

    def decrypt(self, ciphertext):
        '''
        This decrypt constructor takes the ciphertext string, loops through
        decrypting using a 8 bit shift register.
        Note: CFB does not use padding.
        '''
        # Initilize the python cryptography ECB mode
        # CFB uses encryption algorithm for decryption
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(),
                backend = backend)
        encryptor = cipher.encryptor()

        plaintextList = []
        # Loop through the ciphertext list, return plaintext string
        for i in range(0, len(ciphertext)):
            if (i == 0):
                outputBlock = encryptor.update(self.iv)
                xor = xorData(outputBlock[0], ciphertext[i])
                firstPlaintextByte = xor.getXor()
                plaintextList.append(firstPlaintextByte)
                sbitShift = self.iv[1:] + ciphertext[i]
            elif (i >= 1):
                nBlock = encryptor.update(sbitShift)
                xor = xorData(nBlock[0], ciphertext[i])
                nPlaintextByte = xor.getXor()
                plaintextList.append(nPlaintextByte)
                sbitShift = sbitShift[1:] + ciphertext[i]
        return ''.join(plaintextList)
