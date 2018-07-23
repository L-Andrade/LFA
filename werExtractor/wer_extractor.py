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


def is_file_wer(path_to_file):
    try:
        f = codecs.open(os.path.join(path_to_file),
                        'r', encoding='utf-16le')
        line_one = f.readline()
        line_two = f.readline()
        f.close()
        if('Version=' in line_one or 'EventType=' in line_two):
            return True
    except:
        return False
    return False
        


def extract_default_keys(path_to_file):
    res = {}

    try:
        lines = _read_file_lines(path_to_file)
    except:
        raise

    dict_wer_keys = {}
    try:
        for line in lines:
            split_line = line.split("=")
            dict_wer_keys[split_line[0]] = str(split_line[1]).encode("utf-8")

        res['WindowsVersion'] = extract_windows_key(path_to_file)
    except:
        raise


    for key in CONST_DEFAULT:
        try:
            if(key == "EventTime"):
                res[key] = datetime.utcfromtimestamp(
                    (long(dict_wer_keys[key]) - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
            else:
                res[key] = ''.join(dict_wer_keys[key])
        except:
            raise

    return res

def extract_windows_key(path_to_file):
    return extract_specific_array_key(path_to_file, "OsInfo", "osver")

def extract_specific_key(path_to_file, key):
    lines = _read_file_lines(path_to_file)
    try:
        for line in lines:
            sLines = line.split("=")
            if sLines[0] == key:
                return sLines[1]
        raise KeyError('Could not find key "'+key+'"')
    except:
        raise

def extract_specific_array_key(path_to_file, array, key):
    lines = _read_file_lines(path_to_file)
    try:
        for i in xrange(0,len(lines)):
            splited_line = lines[i].split("=")
            if array in splited_line[0] and ".Key" in splited_line[0]:
                if splited_line[1] == key:
                    value_splited_line = lines[i+1].split("=")
                    return value_splited_line[1]
        raise KeyError('Could not find key "'+key+'"" in the array "'+array+'"')
    except:
        raise


def find_dmp_files(path_to_file):
    lines = _read_file_lines(path_to_file)
    res = []
    try:
        for line in lines:
            sLines = line.split("=")
            if sLines[1].endswith(".dmp") and "\\" not in sLines[1] and sLines[1] not in res:
                res.append(sLines[1])
    except:
        raise
    return res


def _read_file_lines(path_to_file):
    clean_lines = []
    try:
        f = codecs.open(path_to_file, 'r', encoding='utf-16le')
        lines = f.readlines()
        for line in lines:
            clean_line = line.replace('\n', '').replace('\t', '').replace('\r', '')
            clean_lines.append(clean_line)
        f.close()
    except IOError:
        raise
    return clean_lines
