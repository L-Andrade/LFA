import os
import sys
import codecs
import socket
import re

# Only for IPv4
IP_REGEX_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"


def extract_ip_addresses(path_to_file):
    lines = _read_file_lines(path_to_file)

    p = re.compile(IP_REGEX_PATTERN)

    my_dict = {}
    try:
        for line in lines:
            occurences = p.findall(line)
            for ip in occurences:
                if my_dict.get(ip):
                    my_dict[ip] += 1
                elif is_valid_ip(ip):
                    my_dict[ip] = 1
    except:
        return {'Error': 'unable to parse file'}

    return my_dict

def is_valid_ipv4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
    except socket.error:
        return False
    return True

def is_valid_ipv6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True

def is_valid_ip(address):
    return is_valid_ipv4(address) or is_valid_ipv6(address)

def _read_file_lines(path_to_file):
    try:
        f = open(path_to_file, 'r')
        lines = f.readlines()
        f.close()
        return lines
    except IOError:
        return {'Error': 'unable to open file'}
