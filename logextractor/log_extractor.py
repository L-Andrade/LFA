import os
import sys
import codecs
import socket
import re

# Only for IPv4
IP_REGEX_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
# For IPv6
IPV6_REGEX_PATTERN = r"(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)"

# Protocols
PROTOCOLS = ["TCP",  "UDP", "ICMP", "HTTP",
             "FTP", "POP", "SSH", "TLS", "SSL"]


def extract_ip_addresses(path_to_file):
    lines = _read_file_lines(path_to_file)

    p_ipv4 = re.compile(IP_REGEX_PATTERN)
    p_ipv6 = re.compile(IPV6_REGEX_PATTERN)

    # this is what will be returned, the formart is a bi-dimentional array
    # eg: [[192.168.1.1, "HTTP",2],[192.168.1.10, "POP",3]]
    # format is [[ip,protocol,number of occurrences ]]
    my_list = []
    try:
        for line in lines:
            occurrences = p_ipv4.findall(line)
            occurrences.extend(p_ipv6.findall(line))

            for ip in occurrences:
                if is_valid_ip(ip):
                    ip = ip.lower()

                    # Needs optimization...
                    protocol = "N/A" # default val
                    for p in PROTOCOLS:
                        if p in line:
                            protocol = p

                    # Search for the ip protocol combination in the list, if found incrase the counter else create one
                    found_entry = False
                    for entry in my_list:
                        if entry[0] == ip and entry[1] == protocol:
                            entry[2] +=1
                            found_entry = True
                            break 
                    if not found_entry:
                        my_list.append([ip,protocol,1])

    except Exception as e:
        return ['Log Extractor Error : ' + str(e)]

    return my_list


def extract_custom_regex(path_to_file, regex):
    lines = _read_file_lines(path_to_file)

    pattern = re.compile(regex)
    my_dict = {}
    try:
        for line in lines:
            occurrences = pattern.findall(line)
            for match in occurrences:
                match = match.lower()
                if my_dict.get(match):
                    my_dict[match] += 1
                else:
                    my_dict[match] = 1
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
