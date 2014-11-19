#/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
from blocks.xor import xorData  
from blocks.padding import padData
from blocks.chunk import chunkData
class blockTestCase(unittest.TestCase):
    '''
    This class is used to test the functionality of various functions that are
    used throughout the library. The testing can be called using the command
    'nose test/test.py' from the AESBlockCipher directory. When code is pushed
    to the 'develop' branch in github, the test files are run with TravisCI. 
    The project and tests can be viewed at:
    https://travis-ci.org/dennisme/AESBlockCiphers
    '''
    def testXorData(self):
        '''
        Testing blocks/xor.py
        '''
        xorTest1 = xorData('tested', 'crypto')  
        assert xorTest1.getXor() == '\x17\x17\n\x04\x11\x0b' 
        xorTest2 = xorData('tested', '\x17\x17\n\x04\x11\x0b')  
        assert xorTest2.getXor() == 'crypto'
    
    def testPad(self):
        '''
        Testing the pad function of strings <= 16 bytes in length.
        '''
        padTest1 = padData(128, 'secret message')
        assert padTest1.padString() == 'secret message\x02\x02'
        assert len(padTest1.padString()) == 16

    def testUnPad(self):
        '''
        Testing the unpad function of strings exactly 16 bytes in lenght.
        '''
        unPadTest2 = padData(128, 'secret message\x02\x02')
        assert unPadTest2.unPadString() == 'secret message'

    def testChunk(self):
        '''
        Testing the chunk function to see if it properly splits up large data
        sets
        '''
        testString = 'This is an example of a large string greater than 16 bytes'
        expectedResult = [
                'This is an examp', 
                'le of a large st', 
                'ring greater tha', 
                'n 16 bytes']
        testChunk1 = chunkData(testString)
        assert testChunk1.getChunk() == expectedResult

        
        
        
