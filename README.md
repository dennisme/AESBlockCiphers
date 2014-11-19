AESBlockCiphers
=========

<a href='https://travis-ci.org/sebdah/git-pylint-commit-hook'><img src='https://travis-ci.org/dennisme/AESBlockCiphers.svg?branch=develop'></a>

Personal project using AES to implement ECB, CBC, CFB, OFB, CTR. For educational 
purposes only. 

To run the program simply unzip the file and run 'pip install -r
requirements.txt' 

Once in the AESBlockCiphers/ directory the test files can be run using the 
command 'nosetests test/test.py'

To make the scripts executable simply use 'chmod u+x script.py'

Directory Info:
=========

blocks/ - contains block cipher and common modules. 
test/ - contains test code for the working modules in block/ 
extras/ - contains a small test script for proof on concept
requirements.txt - used for tracking dependencies
LICENSE.md - licensing purposes 
README.md - used for readme on github
template.py - will be used to test all block modes by importing blocks/

Info:
=========
I have completed all functions that I will need to complete the modes, with
the exception for the shift register logic and pre computation of the count.


**As this project sits now it is not completed** 
TODO list:
=========

-Fix errors caused by a plaintext of exactly 16 bytes being sent to block/padding.py
-Finish creating the interface for ECB, CBC, CFB, OFB, CTR
-Write test cases for the main modes in a seperate test file under test/
-Write basic template files for using the library
-Error handeling with padding, chunking, and xor
-Run tests on functions for timing
-Report info in graph form
-Write final report


Note: 
=========

I have spent a great deal of time turning this code into a library 
that can easily be imported and used by anyone. I could have just used functiong
and passed data. But I felt this would be more extendaby and practical. I feel
that I can complete the project before the end of the semester.



