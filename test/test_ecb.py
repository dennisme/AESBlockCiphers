#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
from blocks.aesECB import ECBMode

class ecbTestCase(unittest.TestCase):
    '''
    This class is used to test the blocks/aesECB.py class. When the code is
    pushed to the 'develop' branch on github, the test files are run with
    TravisCI. The project can be view at:
    https://travis-ci.org/dennisme/AESBlockCiphers
    '''
    def testSmallString(self):
        '''
        Testing blocks/aesECB.py for a small string of information < 16 bytes.
        '''
        key = '\x00' * 16
        test = ECBMode(key)
        ciphertext = test.encrypt('small string')
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == '\xa6\xfe8\xec/\xf9\x123\x8e\xc5-T$\xd8x\xe4' 
        assert plaintext == 'small string'

    def testEvenBlockString(self):
        '''
        Testing blocks/aesECB.py with a string that is 16 bytes in length.
        '''
        key = '\x00' * 16
        testString = '1111111111111111'
        test = ECBMode(key)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert len(testString) == 16
        assert ciphertext == '\xb6\xdeT\xf9\xa7\x867\xd1\xebR<\xa7 \x15\x89\xf4'
        assert plaintext == '1111111111111111'

    def testLargeString(self):
        '''
        Testing blocks/aesECB.py with a large string greater than 16 bytes.
        '''
        key = '\x00' * 16
        testString = ('This is an example of a message that would be over 16,'
                      ' bytes in length. Super secret information.')
        returnedCiphertext = (
                'X>\xc1\xeag\x86=9\x06\x8b\xfd\x15t\x08\x19\xe7\x15\x8d\xed'
                '\x89\x16\xd1R\xee\xd5\xeb\xcd\xc7\xc8\xec\\-\xc3\xd7+m\xe8'
                '\xc4N_b\xc3Y\x02\xfb\xcb\xd9\xbc\xf1HCo^\xc9G\xb5\x1b\x12Oa8'
                '\x1b\x94\xa5\xa6\xa7\x1fy\xf1\xef\xea\xba\xe0D\t5tAdZ~\x13'
                '\xe8D\xcf\x04,\x04t\x1d\xf3CW\xc0\xbf@\xf5\xee\xde\xe7\xf6'
                '\xb9\xb6o\x89q`_\xbf\xddQ\x07')
        test = ECBMode(key)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(ciphertext)
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testVeryLargeData(self):
        '''
        Testing blocks/aesECB.py with a very large string of data.
        '''
        key = '\x00' * 16
        testString = ('This is a super secret message that just happens to'
                      ' be very long as well. I hope there is not a charlie'
                      ' sniffing data from the wire. Hopefully Alice and Bob'
                      ' move to a better block mode')
        returnedCiphertext = (
                ';\x13p\xd5gF\xaa\x7f3\xdc[Rw\xf74\t2\xbb\xa6b\x8b\x9f\x1e@'
                '\xd23[R%\xb5\x0e#M\xd7p\xe2\x81 \t\xa2\xe2Z\xee\xaa\n\x8b8'
                '\xe2\xe8\xc6\xbf\xc5?\xb2\x17\xb7\xa2\x9e\xda\xc7\xc1N\x97'
                '\xb8\xa8\x84\xce<_S,\x9a\xf4v\xb9\xe0\x9fl-\xbf_^s\xf6S\xd6'
                '\x93\xedh\x08\xbe\xe7\xce\xf1\xcb\x14M\xce\x93(\xbd\r\xd3'
                '\xa92\xd0\x81\xc7\xacA\x9b\xe6C\x91P\xef\xed\xf7g\x9e\r\xaehu'
                '\xbe\xef\x9aKU\x98\xdd\xb5>\xc0gK\x05&b7\x86s/\x88\xdb\xe4t'
                '\xc8\xd8\x82t\x9c\xddp\xbc6\xdf\x16m\xcd:wL\xa7\x1b#\xe5'
                '\xd0Ot,\x0b\xa1\x87\x11A\x06A2\x86\xcbE\xf9\x9aI2K\x03^\x02'
                '\x8c$')
        test = ECBMode(key)
        ciphertext = test.encrypt(testString)
        plaintext = test.decrypt(returnedCiphertext)
        assert (len(ciphertext) % 16) == 0
        assert ciphertext == returnedCiphertext
        assert plaintext == testString

    def testPreProcess(self):
        '''
        Testing the preProcess function in blocks/aesECB.py with a large 
        string. If the string is multiple of the block size then the last item
        will not contain padding.
        '''
        key = '\x00' * 16
        test = ECBMode(key)
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
        #Loop through the list, making sure each element is 16 bytes
        for i in range(0, len(returnedList)):
            assert len(returnedList[i]) == 16
        assert preProcessedData == returnedList

    def testPostProcess(self):
        key = '\x00' * 16
        test = ECBMode(key)
        postProcessData = test.postProcess(
                'D_\x04gF\x19\xd7\x9a\x91\xc3\x05ub\x03\xbf\x0f\xa8\r\n%$}'
                '\xa20c\xbbw\nJa2\x8d\xd3\x00\xb7`I\x1ce\xf6*\xd6bf\xa8\x94'
                '\xb7\x89\xd5)\x07\xb5\x8b\x14\xc5A\xa5\xf5Z\xb0\xc3\xa6\xac0')
        returnedList = [
                'D_\x04gF\x19\xd7\x9a\x91\xc3\x05ub\x03\xbf\x0f', 
                '\xa8\r\n%$}\xa20c\xbbw\nJa2\x8d', 
                '\xd3\x00\xb7`I\x1ce\xf6*\xd6bf\xa8\x94\xb7\x89', 
                '\xd5)\x07\xb5\x8b\x14\xc5A\xa5\xf5Z\xb0\xc3\xa6\xac0']
        #Loop through the list, making sure each element is 16 bytes
        for i in range(0, len(returnedList)):
            assert len(returnedList[i]) == 16
        assert postProcessData == returnedList    
