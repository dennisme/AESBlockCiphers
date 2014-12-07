#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
from blocks.aesCFB import CFBMode

class cfbTestCase(unittest.TestCase):
    '''
    This class is used to test the blocks/aesCFB.py class. When the code is
    pushed to the 'develop' branch on github, the test files are run with
    TravisCI. The project can be view at:
    https://travis-ci.org/dennisme/AESBlockCiphers
    Note: Test cases use a static IV. CFB does not need padding.
    '''
    def testSmallString(self):
        '''
        Testing blocks/aesCFB.py for a small string of information < 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CFBMode(key, IV)
        ciphertext = test.encrypt('small string')
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == 'F5\xbcp\x06\x9c{\xc2\x91\xbf\x83Y'
        assert plaintext == 'small string'

    def testEvenBlockString(self):
        '''
        Testing blocks/aesCFB.py with a string that is 16 bytes in length.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = '1111111111111111'
        test = CFBMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 16
        assert ciphertext == (
                '\x04\xc9\xfd\xff\xe3\xfc\xa2\xa5\xaan\x80w\x91J\x94\xa6')
        assert plaintext == '1111111111111111'
    
    def testEvenTwoBlockString(self):
        '''
        Testing blocks/aesCFB.py with a string that is 32 bytes in length.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = '1' * 32
        test = CFBMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 32 
        assert ciphertext == (
                '\x04\xc9\xfd\xff\xe3\xfc\xa2\xa5\xaan\x80w\x91J\x94\xa6\x96n'
                '\x18\xf4\x005d\xc0\x0bxN!\x01g3P')
        
    def testLargeString(self):
        '''
        Testing blocks/aesCFB.py with a large string greater than 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = (
                'This is another example of a message that would be over 16'
                ' bytes in length. Cool stuff.')
        returnedCiphertext = (
                'aW\xe5C\xa6\x19r\x85\x8a\x92\x0bU7b-\xb7\xfe\t\xe3\xda \x03K'
                '\x94^gj\xaf"q\xa8\xd3\x96r\xcd\x95\x8a\xa2\x19\xa4\xe8\x01'
                '\xb5\xa1\xfcP\x02z[\x8e=\x98b\x17J\xf1\x12Y\xb3\xc1\x19j?'
                '\x82R\x82\xb7g9\x8e\xc9\x9c\t\xe7,\x94\xd5)\xccF/<\xa9vv\xb2'
                '\xf3')
        test = CFBMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testVeryLargeData(self):
        '''
        Testing blocks/aesCFB.py with a very large string of data.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = (
                'This is a super secret message that just happens to'
                ' be very long as well. I hope there is not a charlie'
                ' sniffing data from the wire. Hopefully Alice and Bob'
                ' move to a better block mode')
        returnedCiphertext = (
                'aW\xe5C\xa6\x19r\x85\x8a\xdc\x90\xa8\xbb\xf8\xd8aD_\x92\xf3'
                '\x8c\x8c\xa0E\xee\x13\t\xda\xce\x9c\xcc\xac\xfcq@?\xac1r\x94'
                '\xc9\xd1\xd5lS\x1b\x97TX\xde\xff\x08\xa3"|\x86\xdc\x19B\x9dh'
                '\x93\xf0\xe8\x15cN\xa1\xd2\xd0\xa2\xb4|A\xf1d\x86T\xba\xc4.'
                '\xd7\xb4\x12\x8c\xe7\x9a\x15\x16\x91\xd8\x9b\x06K-#@B\xd3\xe0'
                '\x14J,\x91*Sc\xe8\xd19\x81\xc5\x1c;\x11\xcf\x83\xf3\xc3\x11'
                '\xd6=\x1aQ\x18\x8e\xf8\xddW5w\x03\xd9|(\xa7\xa9\xbb0\xe6\x0fr'
                '\x01d\xe5\x16U\xe3\x8fA~Gz\xf1B=x\xa3\xc6\xe9\x8f\xe7cS\xa3'
                '\x88rV\xaa\x16\x8c\xe9 `\xaf-}\x1e33c\x9b0+')
        test = CFBMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(returnedCiphertext)
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

