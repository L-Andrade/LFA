import os
import operator
import codecs
import sys
import getopt

CONST_DEFAULT = ["UploadTime", "AppName",
                 "FriendlyEventName", "EventTime", "AppPath"]


def extract_default_keys(pathToFile):
    try:
        f = codecs.open(pathToFile, 'r', encoding='utf-16le')
        lines = f.readlines()
        f.close()
    except IOError:
        return [-1]
    myDict = {}
    for line in lines:
        sLines = line.split("=")
        myDict[sLines[0]] = sLines[1]
    res = {}
    for key in CONST_DEFAULT:
        res[key] = myDict[key]
    return res
