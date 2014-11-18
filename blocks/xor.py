#!/usr/bin/python
# -*- coding: utf-8 -*-
import binascii 

class xorData:
    '''
    This class is used to xor two strings of equal length, and return the 
    result. Often the result is a byte object (\x17\x04\x01\x18\x00) which
    is represented as a str in python. To debug the result it is helpful to
    print the representation (print repr(someString)). 
    '''

    def __init__(self, stringOne, stringTwo):
        '''
        This constructor initializes the variables to be used in the getXor
        function. 
        '''
        self.stringOne = stringOne
        self.stringTwo = stringTwo

    def getXor(self):
        '''
        This getXor constructor takes the stringOne and stringTwo and converts
        them to ints to be xored together. Once xored, the resulting int is
        converted to binary and then to a string using binascii.
        '''
        stringOneToInt = int(binascii.hexlify(self.stringOne), 16)
        stringTwoToInt = int(binascii.hexlify(self.stringTwo), 16)
        # converts the strong to an int
        xorString = bin(stringOneToInt ^ stringTwoToInt)
        #takes the ints xors them and converts to binary
        stringResult = binascii.unhexlify('%x' % int(xorString, 2))
        #returns the bin to int, then using binascii unhexlify to a byte object
        return stringResult


