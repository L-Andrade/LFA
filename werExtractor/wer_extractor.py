import os
import operator
import codecs
import sys
import getopt


def extract(pathToFile):
    try:
        f = codecs.open(pathToFile,
                        'r', encoding='utf-16le')
        lines = f.readlines()
        f.close()
    except IOError:
        return {-1}
    myDict = {}
    for line in lines:
        sLines = line.split("=")
        myDict[sLines[0]] = sLines[1]
    return myDict["AppName"]
