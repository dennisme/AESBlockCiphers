#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
from blocks.aesCTR import CTRMode

class ctrTestCase(unittest.TestCase):
    '''
    This class is used to test the blocks/aesCTR.py class. When the code is
    pushed to the 'develop' branch on github, the test files are run with
    TravisCI. The project can be view at:
    https://travis-ci.org/dennisme/AESBlockCiphers
    Note: Test cases use a static IV.
    '''
    def testSmallString(self):
        '''
        Testing blocks/aesCTR.py for a small string of information < 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CTRMode(key, IV)
        ciphertext = test.encrypt('small string')
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == 'F\x89\xe5n~J\x88\xdbS\xa3\x94Z\x1f\x90=\x8b'
        assert plaintext == 'small string'

    def testEvenBlockString(self):
        '''
        Testing blocks/aesCTR.py with a string that is 16 bytes in length.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = '1111111111111111'
        test = CTRMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 16
        assert ciphertext == (
                '\x04\xd5\xb53#[\xca\x9e\x10\xfb\xcb\x0c*\xa5\x08\xbe')
        assert plaintext == '1111111111111111'
    
    def testEvenTwoBlockString(self):
        '''
        Testing blocks/aesCTR.py with a string that is 32 bytes in length.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = '1' * 32
        test = CTRMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 32 
        assert ciphertext == (
                '\x04\xd5\xb53#[\xca\x9e\x10\xfb\xcb\x0c*\xa5\x08\xbe\x8bB:hc'
                '\xb25\x9ezQ\x16x\x16\xfa\x1c\xb2')
        
    def testLargeString(self):
        '''
        Testing blocks/aesCTR.py with a large string greater than 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = (
                'This is another example of a message that would be over 16'
                ' bytes in length. Cool stuff.')
        returnedCiphertext = (
                'a\x8c\xedq2\x03\x88\x8f@\xa4\x95Is\xf1K\xaf\xdf\x0bj4"\xefa'
                '\x8f$\x06\x07(\x07\xa6H\xf0\xab\x07v\x85\xcd\xadyT\x00E\x90'
                '\x9e\xefE\xc1\xf7\xb7\xac:\xf0\x14\x95\xbb\xa0\t\x87\x8aG>'
                '\x1b%\xd5\x9b\xdc\x9e\x98&*\xca.\xc0\xf2\x0bR)\xfa\x82\x04'
                '\xd8dQ\'\xd1,\xbd\xa4\xa4q\xda\xe1\x82\xfa\xc1\xd9')
        test = CTRMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testVeryLargeData(self):
        '''
        Testing blocks/aesCTR.py with a very large string of data.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = (
                'This is a super secret message that just happens to'
                ' be very long as well. I hope there is not a charlie'
                ' sniffing data from the wire. Hopefully Alice and Bob'
                ' move to a better block mode')
        returnedCiphertext = (
                'a\x8c\xedq2\x03\x88\x8f@\xea\x89Hk\xf1K\xaf\xc9\x16h+7\xf7$'
                '\xc2.\x13T(@\xae\r\xf7\xb0\x07e\xc0\x87\xacbAT\r\x86\x81\xeaL'
                '\xcb\xa4\xf5\xbdu\xbf\x00\x95\xe9\xf6]\xc3\xd3\x05+\x00.\xc1'
                '\x9b\xd4\x83\x98=*\xc8%\x9a\xbalR\x02\xfa\x9d\r\xd8cM7\xc5/'
                '\xb3\xc4\xdeX\xbd\x87\xff\xd3\xa9\xf0\x1dx\x88\xbb\x13\xb7'
                '\xb1\x83\x13H\xf7N\x16\xd0\x17\xec\xcb\xe9\xe7[K<\xf4y\x9e'
                '\xa5Xp\x9c\x1b-\xfaW\xa7V\x16k\xc2\x19\xa9H(\xda\xab\xb6\xdd'
                '\x843\x02\xb9d\xca\x01\xe1\xd9\x02\x98\x942\x11)E\xa7-Kd(;'
                '\x81G\xc5\xc4\xed\xa0>n\xb1S\x92\xfe\xa5\x97h\xb8\xf6180u\xff'
                '\xff\xa4\xbf\x19t\xe0')
        test = CTRMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(returnedCiphertext)
        assert (len(ciphertext) % 16) == 0
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testPreProcess(self):
        '''
        Testing the preProcess function in blocks/aesCTR.py with a large
        string. If the string is multiple of the block size then the last item
        will not contain padding.
        Note: This test is repetitive and will be trimmed out once issue #9
        is addressed. This would also be removed once issue #12 is addressed.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CTRMode(key, IV)
        preProcessedData = test.preProcess(
                'This data should be split into a list with 16 byte'
                ' elements. The element that is not 16 bytes gets sent'
                ' to the padding function and then appended to the list')
        returnedList = [
                'This data should',
                ' be split into a',
                ' list with 16 by',
                'te elements. The',
                ' element that is',
                ' not 16 bytes ge',
                'ts sent to the p',
                'adding function ',
                'and then appende',
                'd to the list\x03\x03\x03']
        # Loop through the list, making sure each element is 16 bytes
        for i in range(0, len(returnedList)):
            assert len(returnedList[i]) == 16
        assert preProcessedData == returnedList

    def testPostProcess(self):
        '''
        Testing the postProcess function in blocks/aesCTR.py with a large
        ciphertext.
        Note: This test is repetitive and will be trimmed out once issue #9
        is addressed. This would also be removed once issue #12 is addressed.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CTRMode(key, IV)
        postProcessData = test.postProcess(
                'x\xf5\xf8\xa8-\x99\xd4\x84\xc2\x94\xd09\x16\xe5\t\x96\xde\xe0'
                '\xb4o~\x17)\xb1\x86:\xef\xc4\xbc:n\xb0\xe0K1^\x1cPA\x89\xc2'
                '\xdfr(lZ&\xd4\x15U\xc0\xd3\xfb\xb7\x18\xb1e\xdd\xe9\x84<w'
                "\xf9(\xe7\xa6\xd6\x17\\\xb4[x\xbc'Be\x10\x16\xac\xf2\x81S"
                '\x05{\x04\xc8tkN\xc4ON\xb7\t\xcaA')
        returnedList = [
                'x\xf5\xf8\xa8-\x99\xd4\x84\xc2\x94\xd09\x16\xe5\t\x96',
                '\xde\xe0\xb4o~\x17)\xb1\x86:\xef\xc4\xbc:n\xb0',
                '\xe0K1^\x1cPA\x89\xc2\xdfr(lZ&\xd4',
                '\x15U\xc0\xd3\xfb\xb7\x18\xb1e\xdd\xe9\x84<w\xf9(',
                "\xe7\xa6\xd6\x17\\\xb4[x\xbc'Be\x10\x16\xac\xf2",
                '\x81S\x05{\x04\xc8tkN\xc4ON\xb7\t\xcaA']
        # Loop through the list, making sure each element is 16 bytes
        for i in range(0, len(returnedList)):
            assert len(returnedList[i]) == 16
        assert postProcessData == returnedList
