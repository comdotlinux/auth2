#!/usr/bin/python3

import sys
import time
import subprocess
import base64
import hashlib
import hmac
import struct
import math
import logging
import configparser
import getpass

FORMAT = '%(asctime)-15s %(message)s '
sProperties = 'ssh.properties'
curTime = time.strftime("%d-%m-%Y.%H%MHrs")


def get_hotp_token(secret, time_window, key_len):
    key = base64.b32decode(secret)
    msg = struct.pack(">Q", time_window)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    otp = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff)
    return otp % int(math.pow(10, key_len))


def test_user_pin(secret, time_window, key_len, user_pin):
    for offset in [0, -1, -2, 1]:
        cur_pin = get_hotp_token(secret, time_window + offset, key_len)
        if str(cur_pin) == str(user_pin):
            return True
    return False

try:
    cf = configparser.ConfigParser()
    cf.read(sProperties)

    LOG_FILENAME = cf.get('LOG_DETAILS', 'LOG_FILENAME')

    secret = cf.get('AUTH2', 'secret')
    key_len = cf.get('AUTH2', 'KEY_LENGTH')
    timeWindow = cf.get('AUTH2', 'TIME_WINDOW')
    shell = cf.get('COMMAND', 'LOGIN_SHELL')

except configparser.Error:
        sys.exit('Failed while parsing %s', sProperties)

try:
    log = logging.getLogger(LOG_FILENAME)
    logging.basicConfig(filename=LOG_FILENAME,
                        level=logging.INFO,
                        format=FORMAT)
    timeWindow = int(int(time.time()) / int(timeWindow))
    key_len = float(key_len)
except TypeError:
    exception_info = "Failed in setting logs, " + \
        "or incorrect parameters were set in properties file."
    print(exception_info)
    sys.exit(2)


try:
    shell_list = shell.split(' ')
    user_pin = getpass.getpass('Please enter 2 step authentication token : ')

    if user_pin and test_user_pin(secret, timeWindow, key_len, user_pin):
        log.info('Login successful.')
        subprocess.call(shell_list, shell=False,)
    else:
        if not user_pin:
            log.info('Login unsuccessful.Blank / Null / Empty OTP Entered.')
        else:
            log.info('Login unsuccessful. OTP Entered : ' + user_pin)

        print("ACCESS DENIED")
        time.sleep(2)
        sys.exit(1)
except Exception:
    exception_info = 'Failed in getting userinput... Exiting as failed Login'
    print(exception_info)
    log.error(exception_info)
    sys.exit(3)
