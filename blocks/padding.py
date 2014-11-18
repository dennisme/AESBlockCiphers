#!/usr/bin/python
# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives import padding
'''
Pads a given string with PKCS#7 padding algorithm provided by python 
cryptography padding function.
https://cryptography.io/en/latest/hazmat/primitives/padding/
https://tools.ietf.org/html/rfc5652#section-6.3

Note: if the data passed is over 16 bytes python cryptograpy will try to step
it up and treat it like multiple blocks. It tries to do the work for you. 
Bounds checking should be handled in the specific block program. 
'''
class padData:
    '''
    This class is used to pad the messages that are not 16 bytes in length.
    It takes the AES bit size (128, 192, 256) and the string to be padded 
    and returns the string.
    '''
    def __init__(self, aesBits, paddedStr):
        '''
        This constructor initializes the variables to be used in the padString
        function. 
        '''
        self.aesBits = aesBits
        self.paddedStr = paddedStr

    def padString(self):
        '''
        This padString constructor takes the aesBits and paddedStr passed to 
        it and calls the python cryptograpy library function to implement
        PKC#7 padding. The padded string is retunred. 
        '''
        padder = padding.PKCS7(self.aesBits).padder()
        paddedData = padder.update(self.paddedStr)
        paddedData += padder.finalize()
        return paddedData 


