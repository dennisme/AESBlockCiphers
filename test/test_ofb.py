#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
from blocks.aesOFB import OFBMode


class ofbTestCase(unittest.TestCase):
    '''
    This class is used to test the blocks/aesOFB.py class. When the code is
    pushed to the 'develop' branch on github, the test files are run with
    TravisCI. The project can be view at:
    https://travis-ci.org/dennisme/AESBlockCiphers
    Note: Test cases use a static IV.
    '''
    def testSmallString(self):
        '''
        Testing blocks/aesOFB.py for a small string of information < 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = OFBMode(key, IV)
        ciphertext = test.encrypt('small string')
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == 'F\x89\xe5n~J\x88\xdbS\xa3\x94Z\x1f\x90=\x8b'
        assert plaintext == 'small string'

    def testEvenBlockString(self):
        '''
        Testing blocks/aesOFB.py with a string that is 16 bytes in length.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = '1111111111111111'
        test = OFBMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 16
        assert ciphertext == (
                '\x04\xd5\xb53#[\xca\x9e\x10\xfb\xcb\x0c*\xa5\x08\xbe')
        assert plaintext == '1111111111111111'

    def testLargeString(self):
        '''
        Testing blocks/aesOFB.py with a large string greater than 16 bytes.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        testString = (
                'This is another example of a message that would be over 16'
                ' bytes in length. Cool stuff.')
        returnedCiphertext = (
                'a\x8c\xedq2\x03\x88\x8f@\xa4\x95Is\xf1K\xaf8\xe0P\xed7\xab'
                "\x1b\x0eb\x88}\xff\xbf\x18+\x86CMtt\x15\xff{l'\xc9u\xacv\x8f"
                '\x8e%&\x1cc\x11s\xc0\xf4\x05)\xa4\xee\xbf\xe3\x98\xca\xe5.'
                '\x81\xeb\x01\xec\xf1^\x15\x8c\xadX6\xd2\xd3\x93d\xdf!\xf77'
                '\xceN\xfe\xba\x12\xb26\xae\xf2\x10\xdd=')
        test = OFBMode(key, IV)
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
        testString = (
                'This is a super secret message that just happens to'
                ' be very long as well. I hope there is not a charlie'
                ' sniffing data from the wire. Hopefully Alice and Bob'
                ' move to a better block mode')
        returnedCiphertext = (
                'a\x8c\xedq2\x03\x88\x8f@\xea\x89Hk\xf1K\xaf.\xfdR\xf2"\xb3^Ch'
                '\x9d.\xff\xf8\x10n\x81XMg1_\xfe`ys\x81c\xb3s\x86\x84vd\r,^g'
                '\xc0\xa6S}\xe0\xb7\xfd\xf6\x83\xc1\xf1.\x89\xf6\x01\xf7\xf1'
                "\\\x1e\xd6\xe5?6\xf9\xd3\x8cm\xdf&\xeb\'\xdaM\xf0\xdah\x9bQ"
                '\xc8\x8f9\xb5\x146}{\x14\xd0\x98r(\xd6\xe8\x8b0\xdf\xd5$qK'
                '\x1a\xb2\x8b\xed\x0c:\x0e\xb6uy\xb9\xb3]P+\xc4\x14\x05\xce'
                '\x1c3\xa0\xe6[\x94\xdc\x8b\n~\x89\x85\x86\xc2\x035\xf8\xf4'
                '\x91!\xe7\xeb\x12\x91\xc6\xe2\x91yo\x11\xdd\xa8\xfdYZ\x99'
                '\x17\x99\xf5\xf6\xce\x1f\x14$\xf0\x1b\xb2e\xb8\x91\x8a\xc9'
                '\xaai<^\xa3P\xa7\x0c')
        test = OFBMode(key, IV)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(returnedCiphertext)
        assert (len(ciphertext) % 16) == 0
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testPreProcess(self):
        '''
        Testing the preProcess function in blocks/aesOFB.py with a large
        string. If the string is multiple of the block size then the last item
        will not contain padding.
        Note: This test is repetitive and will be trimmed out once issue #9
        is addressed. This would also be removed once issue #12 is addressed.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = OFBMode(key, IV)
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
        Testing the postProcess function in blocks/aesOFB.py with a large
        ciphertext.
        Note: This test is repetitive and will be trimmed out once issue #9
        is addressed. This would also be removed once issue #12 is addressed.
        '''
        IV = '\xb0\xc8\xbc\xa6\xf2Z\x85~\xe5\x9f\xa3m\x17C\xc9\x7f'
        key = '\x00' * 16
        test = OFBMode(key, IV)
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
