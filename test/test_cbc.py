#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
from blocks.aesCBC import CBCMode


class cbcTestCase(unittest.TestCase):
    '''
    This class is used to test the blocks/aesCBC.py class. When the code is
    pushed to the 'develop' branch on github, the test files are run with
    TravisCI. The project can be view at:
    https://travis-ci.org/dennisme/AESBlockCiphers
    Note: Test cases use a static IV.
    '''
    def testSmallString(self):
        '''
        Testing blocks/aesCBC.py for a small string of information < 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CBCMode(key, IV)
        ciphertext = test.encrypt('small string')
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == ('\x1aUe\xc72\xa9\x04\xed\xb5\x1b\xfe\xa6\xdd'
                              '\xbb\xdb\x19')
        assert plaintext == 'small string'

    def testEvenBlockString(self):
        '''
        Testing blocks/aesCBC.py with a string that is 16 bytes in length.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = '1111111111111111'
        test = CBCMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 16
        assert ciphertext == '\xd6\xdc\xd3\xbc9\x88\xdfz\x9e1l+Q\n\x18\xc3'
        assert plaintext == '1111111111111111'

    def testLargeString(self):
        '''
        Testing blocks/aesCBC.py with a large string greater than 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = (
                'This is another example of a message that would be over 16'
                ' bytes in length. Cool stuff.')
        returnedCiphertext = (
                'x\xc8S`\xb1\xa8V\xf9^\xf9\x12\xcb\xc2\x96\xb2\xdd\xe8\xabF'
                "\xd77.\xb4\xa8\x9d\xd5\xd7\x1b\xc9y'\xa4\xa5\xb7K\xd9:\xba"
                '\x89\x9a\x03x*\xc0\x08\x93L\xe1q#\xdeQ\x01\xc9\xe2\x9e\xa9'
                '\xcb*C\xfdX\x12\x88\xd9\x859w\xbd\xed\x94\xa7h\x8b\x86\x17'
                '\x11G\x8e\xcf\xa2\x9c\x0e\x0b\xdb0\x9e\r\xa5\xd8\xda[{\xfe'
                '\xb7\xc8')
        test = CBCMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testVeryLargeData(self):
        '''
        Testing blocks/aesOFB.py with a very large string of data.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = ('This is a super secret message that just happens to'
                      ' be very long as well. I hope there is not a charlie'
                      ' sniffing data from the wire. Hopefully Alice and Bob'
                      ' move to a better block mode')
        returnedCiphertext = (
                '{\xc9\xd3\x98\xb7\x92\x9at\x9f\x9a\xf8\xe3\xee\x8a\xa1f\xdc'
                '\x90\x8f;\x1bGQ0\x89\xb9\xf7\xbbO<\t\xd4Y\x86S4>_\xbd0d=\r0'
                '\x89\xa85d1\x13\xc4\xcb\xeb\x81\x8b\xb9~\x12\x0c\xc6\xbdhH.^'
                '\xed\xb7\x84 a:\x05-)\x98\tZ\xd9\xc2\xef\x0f\xa3\x9c#u\xb5'
                '\x0e_\x06\xc1\xf6\xf3y\x95\xbfx\xa1\x84T\xc2\xc2\xb4>\x88'
                '\xa6Mp\xc2\'\x12\xfbSt\x0fM\xe9>\xaa\xc1\xd24t\x99\xfa\xe0'
                '\xf7\x1d\x7f\x92=\xc0\x7f\x0f\xd8\xf4P\x07aB\xbf\xfaK'
                '\x80ma"sS\x91\xa3\xed5,\xc7\xf0\x01\xd86\xba\x955\x16\xe9'
                '\xc9\x04\xaau\x80rQ!\x1f\x92\xf2\xc4\x15\xc1\x8fT\xa0v\x83j'
                '\tg\xd4\xe9\x9e$\x87\x11\xf6')
        test = CBCMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(returnedCiphertext)
        assert (len(ciphertext) % 16) == 0
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testPreProcess(self):
        '''
        Testing the preProcess function in blocks/aesCBC.py with a large
        string. If the string is multiple of the block size then the last item
        will not contain padding.
        Note: This test is repetitive and will be trimmed out once issue #9
        is addressed.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CBCMode(key, IV)
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
        Testing the postProcess function in blocks/aesCBC.py with a large
        ciphertext.
        Note: This test is repetitive and will be trimmed out once issue #9
        is addressed.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = CBCMode(key, IV)
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
