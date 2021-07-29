# Version 1.0 (November 2020)
#
# Created by:
# John Althouse
# Andrew Smart
# RJ Nunaly
# Mike Brady
#
# Converted to Python by:
# Caleb Yu
#
# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#

# -----------------------------------------

# Forked Version 2.0 (Juli 2021)
#
# 2021-07 - Forked by James D, wallparse@gmail.com
# - Fixed a minor bug and added matching function.
# - Refactored to simplify new features, trying to keep as much of the original structure as possible.
# - Added Elasticsearch output feature
# - Added Elasticsearch input feature
# - Added multithreading
# -> This fork can fetch the hosts to test from one elasticsearch index and output to another elasticsearch index.

from __future__ import print_function
import codecs
import socket
import struct
import os
import sys
import random
import argparse
import hashlib
import ipaddress
import json # James added this to be able to use json objects instead of string concats.
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.connection import create_ssl_context
import re
from multiprocessing import Process, Queue
import threading
import socks
import time


# Returns the result from the elasticsearch-query
# Note that the lstAvoidHosts and strInputField parameter is injected in es-query (thus validate this input field before this func)
def fetchInputFromElastic(args, esInput, strInputField,  maxSize, lstAvoidHosts):
    strFinishedQuery = args.elasticinputquery
    strMinutesBack = "now-" + str(args.fetchminutes) + "m"


    if strFinishedQuery == None:
        print("[-] Warning: no --elasticinputquery defined. Reverting to ", strInputField, ":*")
        strFinishedQuery = strInputField + ":*"

    if len(lstAvoidHosts) > 0:
        for ahost in lstAvoidHosts:
            if(len(ahost) > 2):
                if args.avoiddomaininquery:
                    ahost = ahost.replace("-", "\\-")
                    strFinishedQuery += " AND NOT " + strInputField + ":*" + ahost + ""
                else:
                    strFinishedQuery += " AND NOT " + strInputField + ":\"" + ahost + "\""

    # We return 1 result from the query just for debugging and the rest will be for the aggregation.
    esquery_agg =  {
        "size" : 1,
        #"terminate_after":500,
        "aggs": {
            "thefields": {
                "terms": { 
                    "field": strInputField,
                    "size": maxSize,
                }
            }
        },        
        "query": 
            {
                "bool": {                
                    "must": [
                        {                
                            "query_string": {
                                "query": strFinishedQuery,                    
                                "default_field": strInputField
                            }                        
                        },
                        {
                            "range": {
                                args.elastictimefield: {
                                    "format": "strict_date_optional_time",
                                    "gte": strMinutesBack
                                }
                            }
                        }                            
                    ]
                }
            }
        }

    result = esInput.search(index=args.elasticinputindex, body=esquery_agg, request_timeout=args.elasticfindtimeout)
    
    if result != None:
        print("[+] Got result back from elasticsearch")

        thefields = result["aggregations"]["thefields"]["buckets"]
        
        lstToReturn = []
        beginBucket = 0
        flen = len(thefields)

        if(flen < 1):
            print("[-] Warning: got no results from elastic. The result is ", json.dumps(result))

        while beginBucket < flen:
            strJarmCandidate = thefields[beginBucket]["key"]

            # We really only want valid domains like... ^([A-z0-9\-.]{2,})$
            mValidDomain = re.search(args.validdomains, strJarmCandidate)

            if mValidDomain != None:
                strJarmCandidate = mValidDomain[1]    
                lstToReturn.append(strJarmCandidate) 
            else:
                print("[-] Avoiding domain since not matching pattern ", strJarmCandidate)

            beginBucket = beginBucket +1        
        return lstToReturn
    else:
        print("[-] Warning: The elastic query returned no result.")

    return None

def ingestElasticsearch(esConnection, esIndex, esDocument, strTimefield):
    print("[+] shipping to elasticsearch index", esIndex)
    dtNow = datetime.now()

    # For simpler handling of elasticsearch indexes we enable index-names by date-time
    strFinalIndex = esIndex.replace("#yyyy#", str(dtNow.year))
    strFinalIndex = strFinalIndex.replace("#mm#", str(dtNow.month))
    strFinalIndex = strFinalIndex.replace("#dd#", str(dtNow.day))

    esDocument[strTimefield] = dtNow    # Set the timefield

    # Adjust to be more compatible with ECS https://www.elastic.co/guide/en/ecs/current/ecs-destination.html
    if "ip" in esDocument :        
        strIP = esDocument["ip"]
        del esDocument["ip"]
        
        # If host and ip has the same value we only store the ip.
        if "host" in esDocument and esDocument["host"] != strIP:
            strDomain = esDocument["host"]            

            # To store the registered domain may be useful
            m = re.search("([^.]{1,}[.]{1,}[^.]{1,})$", strDomain)
            if m != None:
                strRegDomain = m[1]          
                        
            esDocument["destination"] = { "ip":strIP, "domain":strDomain}

            if(strRegDomain != None):
                esDocument["destination"]["registered_domain"] = strRegDomain

        else:
            esDocument["destination"] = { "ip":strIP}

        if "host" in esDocument:
            del esDocument["host"]

    esDocument["ecs"]  = {"version":"1.0.0"} # Mandatory for all ECS documents

    # Ship the log to elasticsearch
    try:
        res = esConnection.index(index=strFinalIndex, body=esDocument)
    except:
        print("[-] Error on ingest of ", json.dumps(esDocument, default=str), " this may happen when ip is redirected to domain when resolving. Skipping this")      
        

#Randomly choose a grease value
def choose_grease():
    grease_list = [b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a", b"\x4a\x4a", b"\x5a\x5a", b"\x6a\x6a", b"\x7a\x7a", b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba", b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa"]
    return random.choice(grease_list)

def packet_building(jarm_details):
    payload = b"\x16"
    #Version Check
    if jarm_details[2] == "TLS_1.3":
        payload += b"\x03\x01"
        client_hello = b"\x03\x03"
    elif jarm_details[2] == "SSLv3":
        payload += b"\x03\x00"
        client_hello =  b"\x03\x00"
    elif jarm_details[2] == "TLS_1":
        payload += b"\x03\x01"
        client_hello = b"\x03\x01"
    elif jarm_details[2] == "TLS_1.1":
        payload += b"\x03\x02"
        client_hello = b"\x03\x02"
    elif jarm_details[2] == "TLS_1.2":
        payload += b"\x03\x03"
        client_hello = b"\x03\x03"
    
    #Random values in client hello
    client_hello += os.urandom(32)
    session_id = os.urandom(32)
    session_id_length = struct.pack(">B", len(session_id))
    client_hello += session_id_length
    client_hello += session_id
    
    #Get ciphers
    cipher_choice = get_ciphers(jarm_details)
    client_suites_length = struct.pack(">H", len(cipher_choice))
    client_hello += client_suites_length
    client_hello += cipher_choice
    client_hello += b"\x01" #cipher methods
    client_hello += b"\x00" #compression_methods
    #Add extensions to client hello
    extensions = get_extensions(jarm_details)
    client_hello += extensions
    #Finish packet assembly
    inner_length = b"\x00"
    inner_length += struct.pack(">H", len(client_hello))
    handshake_protocol = b"\x01"
    handshake_protocol += inner_length
    handshake_protocol += client_hello
    outer_length = struct.pack(">H", len(handshake_protocol))
    payload += outer_length
    payload += handshake_protocol
    return payload

def get_ciphers(jarm_details):
    selected_ciphers = b""
    #Two cipher lists: NO1.3 and ALL
    if jarm_details[3] == "ALL":
        list = [b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9", b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04", b"\x13\x03", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"]
    elif jarm_details[3] == "NO1.3":
        list = [b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"]
    #Change cipher order
    if jarm_details[4] != "FORWARD":
        list = cipher_mung(list, jarm_details[4])
    #Add GREASE to beginning of cipher list (if applicable)
    if jarm_details[5] == "GREASE":
        list.insert(0,choose_grease())
    #Generate cipher list
    for cipher in list:
        selected_ciphers += cipher
    return selected_ciphers

def cipher_mung(ciphers, request):
    output = []
    cipher_len = len(ciphers)
    #Ciphers backward
    if (request == "REVERSE"):
        output = ciphers[::-1]
    #Bottom half of ciphers
    elif (request == "BOTTOM_HALF"):
        if (cipher_len % 2 == 1):
            output = ciphers[int(cipher_len/2)+1:]
        else:
            output = ciphers[int(cipher_len/2):]
    #Top half of ciphers in reverse order
    elif (request == "TOP_HALF"):
        if (cipher_len % 2 == 1):
            output.append(ciphers[int(cipher_len/2)])
            #Top half gets the middle cipher
        output += cipher_mung(cipher_mung(ciphers, "REVERSE"),"BOTTOM_HALF")
    #Middle-out cipher order
    elif (request == "MIDDLE_OUT"):
        middle = int(cipher_len/2)
        # if ciphers are uneven, start with the center.  Second half before first half
        if (cipher_len % 2 == 1):
            output.append(ciphers[middle])
            for i in range(1, middle+1):
                output.append(ciphers[middle + i])
                output.append(ciphers[middle - i])
        else:
            for i in range(1, middle+1):
                output.append(ciphers[middle-1 + i])
                output.append(ciphers[middle - i])
    return output

def get_extensions(jarm_details):
    extension_bytes = b""
    all_extensions = b""
    grease = False
    #GREASE
    if jarm_details[5] == "GREASE":
        all_extensions += choose_grease()
        all_extensions += b"\x00\x00"
        grease = True
    #Server name
    all_extensions += extension_server_name(jarm_details[0])
    #Other extensions
    extended_master_secret = b"\x00\x17\x00\x00"
    all_extensions += extended_master_secret
    max_fragment_length = b"\x00\x01\x00\x01\x01"
    all_extensions += max_fragment_length
    renegotiation_info = b"\xff\x01\x00\x01\x00"
    all_extensions += renegotiation_info
    supported_groups = b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
    all_extensions += supported_groups
    ec_point_formats = b"\x00\x0b\x00\x02\x01\x00"
    all_extensions += ec_point_formats
    session_ticket = b"\x00\x23\x00\x00"
    all_extensions += session_ticket
    #Application Layer Protocol Negotiation extension
    all_extensions += app_layer_proto_negotiation(jarm_details)
    signature_algorithms = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    all_extensions += signature_algorithms
    #Key share extension
    all_extensions += key_share(grease)
    psk_key_exchange_modes = b"\x00\x2d\x00\x02\x01\x01"
    all_extensions += psk_key_exchange_modes
    #Supported versions extension
    if (jarm_details[2] == "TLS_1.3") or (jarm_details[7] == "1.2_SUPPORT"):
        all_extensions += supported_versions(jarm_details, grease)
    #Finish assembling extensions
    extension_length = len(all_extensions)
    extension_bytes += struct.pack(">H", extension_length)
    extension_bytes += all_extensions
    return extension_bytes

#Client hello server name extension
def extension_server_name(host):
    ext_sni = b"\x00\x00"
    ext_sni_length = len(host)+5
    ext_sni += struct.pack(">H", ext_sni_length)
    ext_sni_length2 = len(host)+3
    ext_sni += struct.pack(">H", ext_sni_length2)
    ext_sni += b"\x00"
    ext_sni_length3 = len(host)
    ext_sni += struct.pack(">H", ext_sni_length3)
    ext_sni += host.encode()
    return ext_sni

#Client hello apln extension
def app_layer_proto_negotiation(jarm_details):
    ext = b"\x00\x10"
    if (jarm_details[6] == "RARE_APLN"):
        #Removes h2 and http/1.1
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30", b"\x06\x73\x70\x64\x79\x2f\x31", b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33", b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    else:
        #All apln extensions in order from weakest to strongest
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", b"\x06\x73\x70\x64\x79\x2f\x31", b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33", b"\x02\x68\x32", b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    #apln extensions can be reordered
    if jarm_details[8] != "FORWARD":
        alpns = cipher_mung(alpns, jarm_details[8])
    all_alpns = b""
    for alpn in alpns:
        all_alpns += alpn
    second_length = len(all_alpns)
    first_length = second_length+2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += all_alpns
    return ext

#Generate key share extension for client hello
def key_share(grease):
    ext = b"\x00\x33"
    #Add grease value if necessary
    if grease == True:
        share_ext = choose_grease()
        share_ext += b"\x00\x01\x00"
    else:
        share_ext = b""
    group = b"\x00\x1d"
    share_ext += group
    key_exchange_length = b"\x00\x20"
    share_ext += key_exchange_length
    share_ext += os.urandom(32)
    second_length = len(share_ext)
    first_length = second_length+2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += share_ext
    return ext

#Supported version extension for client hello
def supported_versions(jarm_details, grease):
    if (jarm_details[7] == "1.2_SUPPORT"):
        #TLS 1.3 is not supported
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    else:
        #TLS 1.3 is supported
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    #Change supported version order, by default, the versions are from oldest to newest
    if jarm_details[8] != "FORWARD":
        tls = cipher_mung(tls, jarm_details[8])
    #Assemble the extension
    ext = b"\x00\x2b"
    #Add GREASE if applicable
    if grease == True:
        versions = choose_grease()
    else:
        versions = b""
    for version in tls:
        versions += version
    second_length = len(versions)
    first_length = second_length+1
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">B", second_length)
    ext += versions
    return ext

#Send the assembled client hello using a socket
def send_packet(packet, destination_host, destination_port, proxyhost, proxyport, socktimeout):
    ip = None
    ipAddr = None

    try:
        #Connect the socket
        if ":" in destination_host:
            if proxyhost != None:
                sock = socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.set_proxy(socks.SOCKS5, proxyhost, proxyport)
            else:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            #Timeout of 20 seconds
            sock.settimeout(socktimeout)
            sock.connect((destination_host, destination_port, 0, 0))
        else:
            if proxyhost != None:
                sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                sock.set_proxy(socks.SOCKS5, proxyhost, proxyport)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            #Timeout of 10 seconds
            sock.settimeout(socktimeout)
            sock.connect((destination_host, destination_port))

        # Determine if the input is an IP or domain name
        ip = None
        try:
            if (type(ipaddress.ip_address(destination_host)) == ipaddress.IPv4Address) or (type(ipaddress.ip_address(destination_host)) == ipaddress.IPv6Address):
                ip = (destination_host, destination_port)
                ipAddr = destination_host
        except ValueError as e:
            ip = None

        if ip == None:
            ip = sock.getpeername()

        if ipAddr == None:
            try:
                ipAddr = socket.gethostbyname(destination_host)                                       
            except:
                ipAddr = None
                         
        sock.sendall(packet)       
        data = sock.recv(1484)  #Receive server hello
        
        sock.shutdown(socket.SHUT_RDWR) #Close socket
        sock.close()

        return bytearray(data), ip[0], ipAddr

    #Timeout errors result in an empty hash
    except socket.timeout as e:
        sock.close()
        return "TIMEOUT", ip[0], ipAddr
    except Exception as e:
        sock.close()
        return None, ip[0], ipAddr

#If a packet is received, decipher the details
def read_packet(data):
    try:
        if data == None:
            return "|||"
        jarm = ""
        #Server hello error
        if data[0] == 21:
            selected_cipher = b""
            return "|||"
        #Check for server hello
        elif (data[0] == 22) and (data[5] == 2):
            server_hello_length = int.from_bytes(data[3:5], "big")
            counter = data[43]
            #Find server's selected cipher
            selected_cipher = data[counter+44:counter+46]
            #Find server's selected version
            version = data[9:11]
            #Format
            jarm += codecs.encode(selected_cipher, 'hex').decode('ascii')
            jarm += "|"
            jarm += codecs.encode(version, 'hex').decode('ascii')
            jarm += "|"
            #Extract extensions
            extensions = (extract_extension_info(data, counter, server_hello_length))
            jarm += extensions
            return jarm
        else:
            return "|||"

    except Exception as e:
        return "|||"

#Deciphering the extensions in the server hello
def extract_extension_info(data, counter, server_hello_length):
    try:
        #Error handling
        if (data[counter+47] == 11):
            return "|"
        elif (data[counter+50:counter+53] == b"\x0e\xac\x0b") or (data[82:85] == b"\x0f\xf0\x0b"):
            return "|"
        elif counter+42 >= server_hello_length:
            return "|"
        count = 49+counter
        length = int(codecs.encode(data[counter+47:counter+49], 'hex'), 16)
        maximum = length+(count-1)
        types = []
        values = []
        #Collect all extension types and values for later reference
        while count < maximum:
            types.append(data[count:count+2])
            ext_length = int(codecs.encode(data[count+2:count+4], 'hex'), 16)
            if ext_length == 0:
                count += 4
                values.append("")
            else:
                values.append(data[count+4:count+4+ext_length])
                count += ext_length+4
        result = ""
        #Read application_layer_protocol_negotiation
        alpn = find_extension(b"\x00\x10", types, values)
        result += str(alpn)
        result += "|"
        #Add formating hyphens
        add_hyphen = 0
        while add_hyphen < len(types):
            result += codecs.encode(types[add_hyphen], 'hex').decode('ascii')
            add_hyphen += 1
            if add_hyphen == len(types):
                break
            else:
                result += "-"
        return result
    #Error handling
    except IndexError as e:
        result = "|"
        return result

#Matching cipher extensions to values
def find_extension(ext_type, types, values):
    iter = 0
    #For the APLN extension, grab the value in ASCII
    if ext_type == b"\x00\x10":
        while iter < len(types):
            if types[iter] == ext_type:
                return ((values[iter][3:]).decode())
            iter += 1
    else:
        while iter < len(types):
            if types[iter] == ext_type:
                return values[iter].hex()
            iter += 1
    return ""

#Custom fuzzy hash
def jarm_hash(jarm_raw):
    #If jarm is empty, 62 zeros for the hash
    if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
        return "0"*62
    fuzzy_hash = ""
    handshakes = jarm_raw.split(",")
    alpns_and_ext = ""
    for handshake in handshakes:
        components = handshake.split("|")
        #Custom jarm hash includes a fuzzy hash of the ciphers and versions
        fuzzy_hash += cipher_bytes(components[0])
        fuzzy_hash += version_byte(components[1])
        alpns_and_ext += components[2]
        alpns_and_ext += components[3]
    #Custom jarm hash has the sha256 of alpns and extensions added to the end
    sha256 = (hashlib.sha256(alpns_and_ext.encode())).hexdigest()
    fuzzy_hash += sha256[0:32]
    return fuzzy_hash

#Fuzzy hash for ciphers is the index number (in hex) of the cipher in the list
def cipher_bytes(cipher):
    if cipher == "":
        return "00"
    list = [b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f", b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d", b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a", b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23", b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c", b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2", b"\xc0\xa3",  b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf", b'\xcc\x13', b'\xcc\x14', b'\xcc\xa8', b'\xcc\xa9', b'\x13\x01', b'\x13\x02', b'\x13\x03', b'\x13\x04', b'\x13\x05']
    count = 1
    for bytes in list:
        strtype_bytes = codecs.encode(bytes, 'hex').decode('ascii')
        if cipher == strtype_bytes:
            break
        count += 1
    hexvalue = str(hex(count))[2:]
    #This part must always be two bytes
    if len(hexvalue) < 2:
        return_bytes = "0" + hexvalue
    else:
        return_bytes = hexvalue
    return return_bytes

#This captures a single version byte based on version
def version_byte(version):
    if version == "":
        return "0"
    options = "abcdef"
    count = int(version[3:4])
    byte = options[count]
    return byte

def ParseNumber(number):
    if number.startswith('0x'):
        return int(number[2:], 16)
    else:
        return int(number)

def checkJarmForHost(dctFingerprints, args, destination_host, destination_port, file, proxyhost, proxyport, esConnection, strElasticTimestamp, threadqueue):
    ipaddr2 = None
    ip = None 
    
    #Select the packets and formats to send
    #Array format = [destination_host,destination_port,version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]
    tls1_2_forward = [destination_host, destination_port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"]
    tls1_2_reverse = [destination_host, destination_port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"]
    tls1_2_top_half = [destination_host, destination_port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    tls1_2_bottom_half = [destination_host, destination_port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"]
    tls1_2_middle_out = [destination_host, destination_port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"]
    tls1_1_middle_out = [destination_host, destination_port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    tls1_3_forward = [destination_host, destination_port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    tls1_3_reverse = [destination_host, destination_port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    tls1_3_invalid = [destination_host, destination_port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    tls1_3_middle_out = [destination_host, destination_port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    #Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
    #Possible cipher lists: ALL, NO1.3
    #GREASE: either NO_GREASE or GREASE
    #APLN: either APLN or RARE_APLN
    #Supported Verisons extension: 1.2_SUPPPORT, NO_SUPPORT, or 1.3_SUPPORT
    #Possible Extension order: FORWARD, REVERSE
    queue = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]
    jarm = ""

    socktimeout = 10 # Default timeout for sockets
    if(args.socktimeout):
        socktimeout = args.socktimeout

    #Assemble, send, and decipher each packet
    iterate = 0
    while iterate < len(queue):
        payload = packet_building(queue[iterate])
        try:
            server_hello, ip, ipaddr2 = send_packet(payload, destination_host, destination_port, proxyhost, proxyport, socktimeout)
        except:
            print("[-] Error on connect to ", destination_host, " interrupting tests")
            jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
            break
        #Deal with timeout error
        if server_hello == "TIMEOUT":
            jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
            break
        ans = read_packet(server_hello)
        jarm += ans
        iterate += 1
        if iterate == len(queue):
            break
        else:
            jarm += ","
    #Fuzzy hash
    result = jarm_hash(jarm)
    objMatch = None
    strBestGuess = ""

    # Find a match if we have a fingerprint-list
    if dctFingerprints != None:
        if(result.lower() in dctFingerprints):
            objMatch = dctFingerprints[result.lower()]
            strBestGuess = objMatch["guess"]

    # Replacing string concats
    jsonOutput = { "host":destination_host, "ip":ipaddr2, "result":result, "fuzzy":jarm, "guess":strBestGuess}
    strOutput = json.dumps(jsonOutput)
    
    # If requested, write to elasticsearch
    if esConnection != None:
        ingestElasticsearch(esConnection, args.elasticindex, jsonOutput, strElasticTimestamp)

    # If requested write to thread queue
    if threadqueue != None:
        threadqueue.put(jsonOutput)

    # Write to file    
    if args.output and file != None:
        if ip != None:
            if args.json:
                file.write(strOutput)
            else:
                file.write(destination_host + "," + ipaddr2 + "," + result)
        else:
            file.write(destination_host + ",Failed to resolve IP," + result)
            
        #Verbose mode adds pre-fuzzy-hashed JARM
        if args.verbose:
            if  args.json != True:
                file.write("," + jarm)
        file.write("\n")        
    # Print to STDOUT
    else:
        if ip != None:
            if args.json:
                sys.stdout.write(strOutput)
            else:
                print("Domain: " + destination_host)
                print("Resolved IP: " + ip)
                print("JARM: " + result)
        else:
            if args.json:
                sys.stdout.write(strOutput)
            else:
                print("Domain: " + destination_host)
                print("Resolved IP: IP failed to resolve.")
                print("JARM: " + result)
        #Verbose mode adds pre-fuzzy-hashed JARM
        if args.verbose:
            if args.json != True:
                scan_count = 1
                for round in jarm.split(","):
                    print("Scan " + str(scan_count) + ": " + round, end="")
                    if scan_count == len(jarm.split(",")):
                        print("\n",end="")
                    else:
                        print(",")
                    scan_count += 1
        if args.json:
            sys.stdout.write("\n")

# Creates a connection object for es. TODO: Yes, bad cohesion
def createElasticConnection(args, strElasticHost):
    # If requested write to elasticsearch index
    if strElasticHost != None :
        if(args.elastictls):
            bVerifyCerts = True
            elasticport = 9200

            if args.elastictimefield == None:
                args.elastictimefield="@timestamp"

            if args.elasticport:
                elasticport = ParseNumber(args.elasticport)

            if args.elasticskipcert :
                bVerifyCerts = False

            esConnection = Elasticsearch(strElasticHost, verify_certs=bVerifyCerts, http_auth=(args.elasticuser, args.elasticpassword), scheme="https",port=elasticport)
        else:
            esConnection = Elasticsearch(strElasticHost)  

        return esConnection

    return None   
   

# Thread safe if mtxHistoryFile contains lock, write-to-history file
def writeHistory(historyFile, destination_host, dtNow):       
    if historyFile != None: 
        if(destination_host.find(",")>= 0):
            destination_host = destination_host.split(",")[0]

        strDateTime = dtNow.strftime("%Y-%m-%d %H:%M:%S") 
        historyFile.write(destination_host.strip() + "," + strDateTime + "\n")
        historyFile.flush()            
   


def checkForJarmInBulk(dctFingerprints, 
                                args, 
                                lstAllDestinations, 
                                destination_port, 
                                proxyhost, 
                                proxyport,                                  
                                strElasticTimestamp, 
                                lstHistory,
                                lstAvoid,
                                threadq,
                                threadname):

    ipos = 0
    esConnection2 = createElasticConnection(args, args.elastichost)

    while ipos < len(lstAllDestinations):            
        destination_host = lstAllDestinations[ipos]
        port_check = lstAllDestinations[ipos].split(",")

        # checking if we have destination,port format.
        if len(port_check) == 2:
            destination_port = int(port_check[1][:-1])
            destination_host = port_check[0]
        else:
            destination_host = port_check[0].strip() 

        # Extract the registered domain part
        strRegDomain = destination_host
        m = re.search("([^.]{1,}[.]{1,}[^.]{1,})$", destination_host)
        if m != None:
            strRegDomain = m[1]

        if destination_host in lstAvoid :
            print("[+] Avoiding from list ", destination_host)
        elif destination_host in lstHistory:
            print("[+] Avoiding since already tested ", destination_host)
        elif args.avoiddomain and strRegDomain != destination_host and strRegDomain in lstAvoid :
            print("[+] Avoiding from list due to registered domain option", destination_host)           
        else:  
            print("[+] Testing: ", destination_host)
            checkJarmForHost(dctFingerprints, args, destination_host, destination_port, None, proxyhost, proxyport, esConnection2, strElasticTimestamp, threadq)
            print("[+] Finished tests of: ", destination_host)

        ipos+=1

    print("[+] Bulk complete thread ", str(threadname))

    return True    

# Consumer thread for the output file queues
def queueConsumer(args, threadq, commandqueue):
    outFile = createOutputFileFromArgs(args) 

    if threadq != None :
        while commandqueue.qsize() < 1:
            while threadq.qsize():
                objJson = threadq.get()
                outFile.write(json.dumps(objJson, default=str) + "\n")
                outFile.flush()
            time.sleep(1.0)
        
    if outFile != None:
        outFile.close()

    

# The slowness of https, python, networks and whatnot made me do this....
def checkWithThreads( lstAllDestinations, 
                    threadCount,
                    dctFingerprints, 
                    args, 
                    destination_port, 
                    proxyhost, 
                    proxyport, 
                    strElasticTimestamp, 
                    dtNow,
                    lstHistory,
                    lstAvoid):
    # Init queue and process list
    #queue = Queue()
    processes = []

    itemsPerThread = int(len(lstAllDestinations) / threadCount) # Number of items per thread
    remainders = int(len(lstAllDestinations) % threadCount)     # Yes, we'll potentially need one more thread for the remainders        
    processPos = 0

    if(len(lstAllDestinations) < 1):
        print("[-] Warning: the list is empty. No further tests")
        return 

    # If the user requests to write to an output file we create the queue here.
    threadq = None    
    if(args.output != None):
        threadq = Queue()

    if(len(lstAllDestinations) < threadCount):
        threadCount = len(lstAllDestinations)
        print("[-] Warning: The number of items to test is less than the requested threads. Hence one item per thread will be executed")

    while processPos < threadCount:        
        endPos = ((processPos+1) * itemsPerThread)
        startPos = processPos*itemsPerThread

        if(endPos > len(lstAllDestinations)):
            break

        lstThreadDestinations = lstAllDestinations[startPos:endPos]
        
        pProc = Process(target=checkForJarmInBulk, args=(dctFingerprints, 
                                    args, 
                                    lstThreadDestinations, 
                                    destination_port, 
                                    proxyhost, 
                                    proxyport,                                      
                                    strElasticTimestamp, 
                                    lstHistory,
                                    lstAvoid,
                                    threadq,
                                    processPos))

        processes.append(pProc)
        pProc.start()
        processPos += 1

    # Add the remainders if any to a single process
    if remainders > 0:
        startPos = (threadCount*itemsPerThread)
        lstThreadDestinations = lstAllDestinations[startPos:]
        pProc = Process(target=checkForJarmInBulk, args=(dctFingerprints, 
                                    args, 
                                    lstThreadDestinations, 
                                    destination_port, 
                                    proxyhost, 
                                    proxyport, 
                                    strElasticTimestamp, 
                                    lstHistory,
                                    lstAvoid,
                                    threadq,
                                    "remainders"))
        pProc.start()
        processes.append(pProc)        

    print("[+] Joining ", str(len(processes)), " threads...")
    
    pcounter=0
    consumerProc = None
    consumerQueue = Queue()
    if threadq != None:           
        consumerProc = Process(target=queueConsumer, args=(args, threadq, consumerQueue))
        consumerProc.start()


    for p in processes: # Now we join the threads
        if threadq != None:
            print("[+] Queue length ", str(threadq.qsize()))

        pcounter +=1
        print("[+] Joining thread ", pcounter)

        p.join()                
        print("[+] Thread ", pcounter, " joined.")
                   

    #if outFile != None:
    #    outFile.close()         
    print("[+] Threads all collected")

    # Terminate the consumer queue
    if consumerProc != None:
        consumerQueue.put("terminate")
        consumerProc.join()


# Open a file handle (removed the extension creation code from original implementation)
def createOutputFileFromArgs(args):
    if args.output:
        file = open(args.output, "a+")
        return file

    return None

# Add the items to the history file if they dont already exist.
def addToHistory(historyFile, lstAllDestinations, dtNow, lstHistory):
    for lst in lstAllDestinations:
        if not lst in lstHistory:
            writeHistory(historyFile, lst, dtNow)

def appendWithoutCR(lstAll, lstToAdd):
    lstResult = lstAll
    for str in lstToAdd:
        if(str.find(",")>= 0):
            str = str.split(",")[0]

        if not (str.strip() in lstAll):
            lstResult.append(str.strip())        
    return lstResult

def isWorldWritable(strFile):
    stFileCheck = os.stat(strFile)
    writeWorldWritable = (stFileCheck.st_mode & 0o2)
    return (writeWorldWritable == 2)

def assertDangerousInput(strFile):
    if strFile and isWorldWritable(strFile):
        print("[-] Error: it would be bad practice to use input from this file:", strFile, " since it is writable for all") 
        exit(-1)
                
def writeListToFile(elasticoutfile, lstElasticInput):
    if os.path.exists(elasticoutfile):
        print("[-] Error: the chosen output path exists: ", elasticoutfile)
        return False
    fout = open(elasticoutfile, "w")

    for strLine in lstElasticInput:
        fout.write(strLine + "\n")
    
    fout.flush()
    fout.close()

    return True
    
# Ingests a text file with previously created json results into elasticsearch.
def ingestFinishedResultInElastic(esConnection, dctFingerprints, args, destination_port,  proxyhost, proxyport,  strElasticTimestamp, dtNow, lstHistory, lstAvoid):
    finput = open(args.jsoninput, "r")
    strLines = finput.readlines()
    finput.close()

    for jsonOutput in strLines:
        jObj = json.loads(jsonOutput.strip())
        ingestElasticsearch(esConnection, args.elasticindex, jObj, strElasticTimestamp)

# Main function, gotta have one don't we
def main():    
    parser = argparse.ArgumentParser(description="Enter an IP address and port to scan.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("scan", nargs='?', help="Enter an IP or domain to scan.")
    group.add_argument("-i", "--input", help="Provide a list of IP addresses or domains to scan, one domain or IP address per line.  Optional: Specify port to scan with comma separation (e.g. 8.8.4.4,853).", type=str)
    parser.add_argument("-p", "--port", help="Enter a port to scan (default 443).", type=int)
    parser.add_argument("-v", "--verbose", help="Verbose mode: displays the JARM results before being hashed.", action="store_true")
    parser.add_argument("-V", "--version", help="Print out version and exit.", action="store_true")
    parser.add_argument("-o", "--output", help="Provide a filename to output/append results to a CSV file.", type=str)
    parser.add_argument("-j", "--json", help="Output ndjson (either to file or stdout; overrides --output defaults to CSV)", action="store_true")
    parser.add_argument("-P", "--proxy", help="To use a SOCKS5 proxy, provide address:port.", type=str)
    parser.add_argument("-m", "--match", help="Try to match the fingerprint signature in fingerprint.txt", action="store_true")
    parser.add_argument("--socktimeout", help="Timeout in seconds for socket connect attempts. (default=10)", type=int)

    # Tests are already made, just reformat them and output to elastic
    parser.add_argument("--jsoninput", help="Tests are already made, just read the json file line-by-line and output to elastic. Specify the filename to read from.", type=str)

    # Elastic output
    parser.add_argument("-e", "--elastichost", help="Use this elasticsearch host for output (default=127.0.0.1)", type=str)
    parser.add_argument("--elasticindex", help="Use this elasticsearch index for output. Example: jarm-#yyyy#", type=str)

    # Elastic input
    parser.add_argument("--elasticinputhost", help="Use this elasticsearch host for input (default=127.0.0.1)", type=str)
    parser.add_argument("--elasticinputindex", help="Use this elasticsearch index for input.", type=str)
    parser.add_argument("--elasticinputquery", help="Use this elasticsearch query to fetch the hosts", type=str)
    #parser.add_argument("--elasticinputregex", help="Use this regular expression to carve out the hostnames/ip-addresses for each result from the elastic query", type=str)
    parser.add_argument("--elasticinputfield", help="Use this elasticsearch input field where the hosts are stored (default=destination.domain)", type=str)
    parser.add_argument("--elasticinputtimespan", help="Use this elasticsearch timespan for input (default=1h)", type=str)
    parser.add_argument("--elasticinputmax", help="Use this to limit search result from elasticsearch (default=1000)", type=int)

    # Elastic common for input/output
    parser.add_argument("--elasticuser", help="Use this elasticsearch user (if required by the elastic server)", type=str)
    parser.add_argument("--elasticpassword", help="Use this elasticsearch password (if required by the elastic server)", type=str)
    parser.add_argument("--elastictls", help="Use if elasticsearch requires https (more common these days)", action="store_true")
    parser.add_argument("--elasticskipcert", help="If specified no certificate validation occurs when connecting to elasticsearch (using this is NOT recommended of course)", action="store_true")
    parser.add_argument("--elasticport", help="If you have another port than 9200 for your elasticsearch then specify it here", type=int)
    parser.add_argument("--elastictimefield", help="Set the timefield for elasticsearch (default=@timestamp)", type=str)
    parser.add_argument("--elasticoutfile", help="If this is specified then the result from the elastic query will be written to this textfile.", type=str)

    # Avoid lists
    parser.add_argument("--avoid", help="Use this file for avoiding specific domains/ips", type=str)
    parser.add_argument("--avoidinquery", help="Use this file for avoiding specific domains/ips directly in the elastic query", type=str)
    parser.add_argument("--history", help="Use this file for avoid checking each host more than once (if none, then no history)", type=str)
    parser.add_argument("--avoiddomain", help="If set then the registered domain part of the fqdn is compared", action="store_true")
    parser.add_argument("--avoiddomaininquery", help="If set then the registered domain part of the fqdn is compared direct in elastic query", action="store_true")

    # Filter by times
    parser.add_argument("--elasticfindtimeout", help="Find timeout in seconds for elastic (default=40)", type=int)
    parser.add_argument("--fetchminutes", help="Search this number of minutes back in time for elastic (default=10)", type=int)

    # Misc
    parser.add_argument("--validdomains", help="Regular expression to determine valid domains to test for jarm. Default=^([A-z0-9\\-.])$", type=str)
        
    # Multithreading added for ... speed
    parser.add_argument("--threads", help="If set to a value > 0 this number of threads will be used for the JARM-tests", type=int)    
    args = parser.parse_args()    

    # Init variables
    file =              None
    destination_host =  args.scan
    destination_port =  443
    dctFingerprints =   {}    
    proxyhost =         None
    proxyport =         None 
    esConnection =      None
    strElasticTimestamp = "@timestamp"
    lstElasticInput =   None
    strElasticInputField = "destination.domain.keyword"
    elasticInputMax =   1000                        # The maximum number of hosts to fetch from elasticsearch
    lstAvoid =          []                          # Will receive the static avoid list    
    lstHistory =        []                          # Will receive the history list
    dtNow =             datetime.now()              # Timestamp used for history-file

    if args.version:
        print("JARMxy - Yet another JARM Fork - 2021... started: ", str(dtNow))
        exit()

    # Checking privileges since we are connecting to uncontrolled hosts
    if os.name != 'nt' and os.getuid() == 0:
        exit('[-] Error: This command shall not be run with sudo or as root user')           

    # Set the valid domains regexp
    if args.validdomains == None:
        args.validdomains = "^([A-z0-9\-.]{2,})$"

    if not (args.scan or args.input or args.elasticinputhost or args.jsoninput):
        parser.error("[-] Error: A domain/IP to scan or an input file is required.")    

    if args.elasticinputhost and args.elasticinputindex == None:
        exit("[-] Error: If you want elasticsearch input you also needs to specify the index for input.")   

    # Elasticsearch settings
    if args.elastichost and args.elasticindex == None:
        exit("[-] Error: If you want elasticsearch output you also needs to specify the index for output.")    

    if args.elasticinputhost == None and args.elasticoutfile != None:
        exit("[-] Error: If you want to store the elastic result into an output file then please specify the elastic input host (--elasticinputhost <hostname>)")

    # If we want to query an elasticsearch cluster for the hosts to do the Jarm-check on.
    if args.elasticinputhost and args.elasticinputindex != None:
        if args.elasticinputfield != None:
            strElasticInputField = args.elasticinputfield

        if args.elasticinputmax != None:
            elasticInputMax = args.elasticinputmax    

        # For security, check the permissions of the files used for queries of elasticsearch 
        # Windows, is ..hmm...  windows, nevermind.       
        if os.name != 'nt': 
            assertDangerousInput(args.avoiddomaininquery)
            assertDangerousInput(args.avoidinquery)                   

        # Get the avoid-list for queries
        lstAvoidInQuery =   []
        if args.avoidinquery != None and (os.path.exists(args.avoidinquery)):
            with open(args.avoidinquery,'r') as avoidInqueryFile:
                for strHost in avoidInqueryFile.readlines():
                    lstAvoidInQuery.append(strHost.strip())            
                      
        print("[+] Fetching from elasticsearch...")
        esInput = createElasticConnection(args, args.elasticinputhost)
        lstElasticInput = fetchInputFromElastic(args, esInput, strElasticInputField, elasticInputMax, lstAvoidInQuery)

        if lstElasticInput != None:
            print("[+] Retrieved ", str(len(lstElasticInput)), " entries from elasticsearch")
        else:
            print("[-] Warning... the elasticsearch query did not result in any hits.") 

        if args.elasticoutfile != None:
            print("[+] Ok. You chose to just output to a text file. Hence we'll do that and exit")
            writeListToFile(args.elasticoutfile, lstElasticInput)
            print("[+] Done! since output to file", args.elasticoutfile)
            exit()

    # If requested write to elasticsearch index
    esConnection = createElasticConnection(args, args.elastichost)

    #set proxy
    if args.proxy:
        proxyhost, proxyport = args.proxy.split(':')
        proxyport = ParseNumber(proxyport)

    if args.port:
        destination_port = int(args.port)

    # Get the avoid-list
    if args.avoid != None and (os.path.exists(args.avoid)):
        avoidFile = open(args.avoid, "r")
        lstAvoid = avoidFile.readlines()
        avoidFile.close()

    
    # Get the history-list
    if args.history != None and (os.path.exists(args.history)):
        historyFile = open(args.history, "r")
        lstTemp = historyFile.readlines()

        # Read line by line and remove the timestamp
        for line in lstTemp:
            lstHistory.append(line.split(",")[0].strip())

        historyFile.close()
        historyFile = None
        
    if args.history != None : 
        print("[+] using history file")   
        historyFile = open(args.history, "a")


    # Fill the fingerprint dictionary    
    if args.match:
        strFingerpath = os.path.dirname( os.path.abspath(__file__)) + os.path.sep + "fingerprints.txt"
        if(os.path.exists(strFingerpath)):
            print("[+] Reading fingerprints from ", strFingerpath)
            match_file = open(strFingerpath, "r")
            strMatchLines = match_file.readlines()
            match_file.close()

            for strLine in strMatchLines:
                strClean = strLine.strip()
                strSplitted = strClean.split(',')
                strKey = strSplitted[0].lower()

                if(strKey in dctFingerprints):
                    dctFingerprints[strKey]["guess"] = dctFingerprints[strKey]["guess"] + "," + strSplitted[1]
                else:
                    objVal = {"guess":strSplitted[1], "added":strSplitted[2]}
                    dctFingerprints[strKey] = objVal
        else:
            print("[-] Error: The fingerprint file requested does not exist (", strFingerpath, ")")

    # If we want file output option then the file is created here (threads handle file output differently)
    if(args.threads == None or args.threads < 1):
        file = createOutputFileFromArgs(args)

    if args.jsoninput != None:
        print("[+] Reading input from ", args.jsoninput, " and sending to elastic:", args.elastichost)
        if esConnection == None:
            print("[-] Error: no elastic connection for ingest")
        else:
            ingestFinishedResultInElastic(esConnection,dctFingerprints, args, destination_port,  proxyhost, proxyport,  strElasticTimestamp, dtNow, lstHistory, lstAvoid)

    # Input the hosts to test from file if requested
    if args.input:
        input_file = open(args.input, "r")
        entries = input_file.readlines()
        lstToAddForHistory = []

        if(args.threads != None and args.threads > 0):
            checkWithThreads(entries, args.threads, dctFingerprints, args, destination_port,  proxyhost, proxyport,  strElasticTimestamp, dtNow, lstHistory, lstAvoid)
        else:        
            for entry in entries:
                port_check = entry.split(",")
                if len(port_check) == 2:
                    destination_port = int(port_check[1][:-1])
                    destination_host = port_check[0]
                else:
                    destination_host = port_check[0].strip() # James - 2021-07-21 - Fixing this bug - previously: entry[:-1]

                if destination_host in lstAvoid or destination_host in lstHistory:
                    print("[+] Avoiding ", destination_host)
                else:
                    checkJarmForHost(  dctFingerprints, args, destination_host, destination_port, file, proxyhost, proxyport, esConnection, strElasticTimestamp, None)   
                    lstToAddForHistory.append(destination_host)   

        # Write to history
        addToHistory(historyFile, lstToAddForHistory, dtNow, lstHistory)
        lstHistory = appendWithoutCR(lstHistory, lstToAddForHistory) # note that we have already added these.        

    # The Elasticsearch input
    if args.elasticinputhost:
        lstToAddForHistory = []
        if(args.threads != None and args.threads > 0):
            checkWithThreads(lstElasticInput, args.threads, dctFingerprints, args, destination_port,  proxyhost, proxyport,  strElasticTimestamp, dtNow,lstHistory,lstAvoid)
        else:          
            for destination_host in lstElasticInput:
                if destination_host in lstAvoid or destination_host in lstHistory:
                    print("[+] Avoiding ", destination_host)
                else:            
                    checkJarmForHost(  dctFingerprints, args, destination_host, destination_port, file, proxyhost, proxyport, esConnection, strElasticTimestamp, None)
                    lstToAddForHistory.append(destination_host)  

        addToHistory(historyFile, lstToAddForHistory, dtNow,lstHistory)
        lstHistory = appendWithoutCR(lstHistory, lstToAddForHistory) # note that we have already added these.          


    # The default, only one specific test (no avoid-lists here)
    if args.jsoninput == None and args.input == None and args.elasticinputhost == None:
        checkJarmForHost(dctFingerprints, args, destination_host, destination_port, file, proxyhost, proxyport, esConnection, strElasticTimestamp, None)  

    #Close files
    if file != None:
        file.close()
    
    if historyFile != None:
        historyFile.close()

    print("[+] Done!")

# Old fashioned python syntax
if __name__ == "__main__":    
    main()
