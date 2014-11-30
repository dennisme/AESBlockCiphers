#!/usr/bin/python
# -*- coding: utf-8 -*-
from itertools import cycle, izip


class xorData(object):
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
    
    @property
    def stringOne(self):
        return self._stringOne

    @stringOne.setter
    def stringOne(self, stringOne):
        if (len(stringOne) == 0):
            raise ValueError('String one cant not be empty')
        self._stringOne = stringOne
    
    @property
    def stringTwo(self):
        return self._stringTwo

    @stringTwo.setter
    def stringTwo(self, stringTwo):
        if (len(stringTwo) == 0):
            raise ValueError('String two cant not be empty')
        self._stringTwo = stringTwo
    
    def getXor(self):
        '''
        //redo
        '''
        xorString = ''.join(chr(ord(c)^ord(k)) for c,k in izip(self.stringOne, cycle(self.stringTwo)))
        return xorString


            
