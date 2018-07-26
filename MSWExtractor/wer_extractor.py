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


def is_file_wer(pathToFile):
    try:
        f = codecs.open(os.path.join(pathToFile),
                        'r', encoding='utf-16le')
        line_one = f.readline()
        line_two = f.readline()
        f.close()
        if('Version=' in line_one or 'EventType=' in line_two):
            return True
    except:
        return False
    return False
        


def extract_default_keys(pathToFile):
    lines = _read_file_lines(pathToFile)

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

    res['WindowsVersion'] = extract_windows_key(pathToFile)
    return res

def extract_windows_key(pathToFile):
    return extract_specific_array_key(pathToFile, "OsInfo", "osver")

def extract_specific_key(pathToFile, key):
    lines = _read_file_lines(pathToFile)
    try:
        for line in lines:
            sLines = line.split("=")
            if sLines[0] == key:
                return sLines[1]
        return {'Error': 'key does not exist in file'}
    except:
        return {'Error': 'unable to parse file'}

def extract_specific_array_key(pathToFile, array, key):
    lines = _read_file_lines(pathToFile)
    try:
        for i in xrange(0,len(lines)):
            splited_line = lines[i].split("=")
            if array in splited_line[0] and ".Key" in splited_line[0]:
                if splited_line[1] == key:
                    value_splited_line = lines[i+1].split("=")
                    return value_splited_line[1]
        return {'Error': 'key does not exist in file'}
    except:
        return {'Error': 'unable to parse file'}


def find_dmp_files(pathToFile):
    lines = _read_file_lines(pathToFile)
    res = []
    try:
        for line in lines:
            sLines = line.split("=")
            if sLines[1].endswith(".dmp") and "\\" not in sLines[1] and sLines[1] not in res:
                res.append(sLines[1])
        return res
    except:
        return {'Error': 'unable to parse file'}


def _read_file_lines(pathToFile):
    try:
        f = codecs.open(pathToFile, 'r', encoding='utf-16le')
        lines = f.readlines()
        clean_lines = []
        for line in lines:
            clean_line = line.replace('\n', '').replace(
                '\t', '').replace('\r', '')
            clean_lines.append(clean_line)
        f.close()
        return clean_lines
    except IOError:
        return {'Error': 'unable to open file'}
