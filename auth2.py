#!/usr/bin/python3

import sys
import os
import time
import subprocess
import base64
import hashlib
import hmac
import struct
import math
import logging
import ConfigParser
import getpass

        cf = ConfigParser.ConfigParser()
        cf.read(sProperties)

        LOG_FILENAME = cf.get('LOG_DETAILS', 'LOG_FILENAME')

        secret = cf.get('AUTH2', 'secret')
        key_len = cf.get('AUTH2', 'KEY_LENGTH')
        timeWindow = cf.get('AUTH2', 'TIME_WINDOW')
        shell = cf.get('COMMAND', 'LOGIN_SHELL')

except ConfigParser.Error:
        sys.exit('Failed while parsing %s', sProperties)

try:
        log = logging.getLogger(LOG_FILENAME)
        logging.basicConfig(filename=LOG_FILENAME,
                            level=logging.INFO,
                            format=FORMAT)
        timeWindow = int(time.time()) / int(timeWindow)
        key_len = float(key_len)
except TypeError:
        exception_info = "Failed in setting logs, or incorrect parameters were set in properties file."
        print(exception_info)
        sys.exit(2)


# if len(sys.argv)<2:
#    print get_hotp_token(secret, timeWindow, key_len)
# else:
#    user_pin = sys.argv[1]
shell_list = shell.split(' ')

user_pin = getpass.getpass('Please enter 2 step authentication token : ')
if test_user_pin(secret, timeWindow, key_len, user_pin):
    log.info('Login successful.')
    subprocess.call(shell_list, shell=False,)
else:
    log.info('Login unsuccessful. OTP Entered : ' + user_pin)
    print("ACCESS DENIED")
    time.sleep(2)
    sys.exit(1)
