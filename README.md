AESBlockCiphers
=========

Personal project using AES to implement ECB, CBC, CFB, OFB, CTR. For educational 
purposes only. 

To download and run the program simply unzip the file and run 'pip install -r
requirements.txt'

Once in the AESBlockCiphers/ directory the test files can be run using the 
command 'nosetests test/test.py'


=========
As this project sits now it is not completed. 
TODO list:
-Fix errors caused by a plaintext of exactly 16 bytes being sent to block/padding.py
-Finish creating the interface for ECB, CBC, CFB, OFB, CTR
-Write test cases for the main modes in a seperate test file under test/
-Write basic template files for using the library
-Error handeling with padding, chunking, and xor
-Run tests on functions for timing
-Report info in graph form
-Write final report


=========
Note: 

I have spent a great deal of time turning this code into a library function
that can easily be imported and used by anyone. I could have just used functiong
and passed data. But I felt this would be more extendaby and practical. I feel
that I can complete the project before the end of the semester.


=========
Extra:

I have provided the small test scripts I used to test the code before putting 
into the library form in the extras/ directory.

<a href='https://travis-ci.org/sebdah/git-pylint-commit-hook'><img src='https://travis-ci.org/dennisme/AESBlockCiphers.svg?branch=develop'></a>
