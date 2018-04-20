import os
import operator
import codecs
import sys
import getopt
from datetime import datetime, timedelta, tzinfo
from calendar import timegm

CONST_DEFAULT = ["AppName",
                 "FriendlyEventName", "EventTime", "AppPath"]
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


def extract_default_keys(pathToFile):
    try:
        f = codecs.open(pathToFile, 'r', encoding='utf-16le')
        lines = f.readlines()
        f.close()
    except IOError:
        return {'Error': 'unable to open file'}

    myDict = {}
    try:
        for line in lines:
            sLines = line.split("=")
            myDict[sLines[0]] = str(sLines[1]).encode("utf-8")
    except:
        return{'Error': 'unable to parse file'}

    res = {}

    try:
        for key in CONST_DEFAULT:
            if(key == "EventTime"):
                res[key] = datetime.utcfromtimestamp(
                    (long(myDict[key]) - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
            else:
                res[key] = ''.join(myDict[key])
    except:
        return{'Error': 'key does not exist in file'}

    return res


def extract_specific_key(pathToFile, key):
    try:
        f = codecs.open(pathToFile, 'r', encoding='utf-16le')
        lines = f.readlines()
        f.close()
    except IOError:
        return [-1]
    for line in lines:
        sLines = line.split("=")
        if(sLines[0] == key):
            return sLines[1]
    return ""
