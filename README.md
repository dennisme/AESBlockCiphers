AESBlockCiphers
=========

**As this project sits now it is not completed** 

<a href='https://travis-ci.org/sebdah/git-pylint-commit-hook'><img src='https://travis-ci.org/dennisme/AESBlockCiphers.svg?branch=develop'></a>

Personal project using python cryptography to implement ECB, CBC, CFB, OFB
and CTR. The base encryption in all the files is ECB.I have written the code
for the specific block opertion. Educational purposes only.

###Installation:

Note: setup.py coming soon.

'''bash
pip install -r requiremnts.txt
'''

###Testing

'''python
nosetest test/test_ecb.py
'''

'''python 
nosetests -vv test/test_*
'''

###Directory Info:

- blocks - contains block cipher and common modules. 
- test - contains test code for the working modules in block/ 
- requirements.txt - used for tracking dependencies
- LICENSE.md - licensing purposes 
- README.md - used for readme on github

###TODO list:

- Write basic template files for using the library
- Run tests on functions for timing
- Report info in graph form
- Fix issues


