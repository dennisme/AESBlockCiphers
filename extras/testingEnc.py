#!usr/bin/python
# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

print "IV"
iv = os.urandom(12)
print iv
print repr(iv)
print type(iv)

print "-----"
padder = padding.PKCS7(192).padder()
padded_data = padder.update("1111111111112222222222222")
print len(padded_data)
print type(padded_data)
print repr(padded_data)
padded_data += padder.finalize()
print padded_data
print type(padded_data)
print repr(padded_data)
print len(padded_data)

print "----------------"
print "starting encryption"
backend = default_backend()
cipher = Cipher(algorithms.AES("\x00" * 24), modes.ECB(), backend = backend)
encryptor = cipher.encryptor()

ct = encryptor.update(padded_data) + encryptor.finalize()
print type(ct)
print repr(ct)
print len(ct)
print "finished encryption"

print "-----------"
print "testing this one"
decryptor = cipher.decryptor()
pt = decryptor.update(ct) 
print "-------------"
pt = pt  + "\x16\x16"
print repr(pt)
print type(pt)
print len(pt)
print "end test"

print "-----------"
unpadder = padding.PKCS7(192).unpadder()
uppt = unpadder.update(pt)
print uppt
print repr(uppt)
print type(uppt)
