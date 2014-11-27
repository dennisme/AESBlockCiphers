#!/usr/bin/python
# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives import padding
'''
Pads a given string with PKCS#7 padding algorithm provided by python 
cryptography padding function.
https://cryptography.io/en/latest/hazmat/primitives/padding/
https://tools.ietf.org/html/rfc5652#section-6.3

Note: If the data passed is over 16 bytes python cryptograpy will try to step
it up and treat it like multiple blocks. It tries to do the work for you. 
Bounds checking is needed to make sure my functions do the work. 
'''
class padData:
    '''
    This class is used to pad the messages that are not 16 bytes in length.
    AES supports a block size of 16 bytes or 128 bits.
    '''
    def __init__(self, inputString):
        '''
        This constructor initializes the variables to be used in the padString
        function. 
        '''
        self.aesBits = 128
        self.inputString = inputString

    def padString(self):
        '''
        This padString constructor takes the aesBits and paddedStr passed to 
        it and calls the python cryptograpy library function to implement
        PKC#7 padding. The padded string is returned. 
        '''
        if (len(self.inputString) > 16 or len(self.inputString) == 0):
            raise ValueError('The input can not be null or greater than 16 bytes.')
        elif len(self.inputString) < 16:
            padder = padding.PKCS7(self.aesBits).padder()
            paddedData = padder.update(self.inputString)
            paddedData += padder.finalize()
            return paddedData 
        else:
            return self.inputString 

    def unPadString(self):
        '''
        This unPadString constructor takes the aesBits and paddedStr passed to 
        it and calls the python cryptograpy library function to remove PKC#7
        padding. The unpadded string is returned.
        '''
        if (len(self.inputString) != 16):
            raise ValueError('Invalid padding bytes.')
        unpadder = padding.PKCS7(self.aesBits).unpadder()
        unPaddedData = unpadder.update(self.inputString)
        returnData = unPaddedData + unpadder.finalize()
        return returnData

