#!/usr/bin/python
# -*- coding: utf-8 -*-

class chunkData():
    '''
    This class is used to break large input strings into 16 byte blocks. 
    AES uses 16 byte blocks. The last element in the list returned may 
    need to be padded.
    '''
    def __init__(self, rawStr):
        '''
        This constructor takes the plaintext string to be used in the class.
        The default blocksize it initialized here.
        '''
        self.blockSize = 16
        self.rawStr = rawStr

    def getChunk(self):
        '''
        The getChunk constructor takes the rawStr variable passed to it,
        and breaks it up into chunks of 16 bytes. To be sent to encryption
        algorithm. 
        '''
        self.chunkRaw = [self.rawStr[i:i+self.blockSize] 
                for i in range (0, len(self.rawStr), self.blockSize)]
        return self.chunkRaw
