#!/usr/bin/python3

import sys
import binascii
import random
import argparse

#for timestamping
import time
import re
import os #for playing around with set input path

# ----- ===== Configurable parameteres ==== ----
# DO NOT TOUCH OTHER VARIABLES
# default necessary values if there is nothing provided
# default_src_mac = "00:00:00:00:00:01"
# default_dst_mac = "00:00:00:00:00:02"
# default_src_ip = "10.0.0.1"
# default_dst_ip = "192.168.88.8"
# default_src_port = 1234
# default_dst_port = 808
# default_vlan = None
# default_ttl = 64
# default_ether_type = 'ipv4'
# default_src_ipv6 = '2603:c022:1:52dd:dead:beef:abba:edda'
# default_dst_ipv6 = '2405:0800:9030:1bd2:dead:beef:dead:beef'
# default_protocol = 'udp'
#DEFINE HERE THE DIFFERENT PACKETS SIZE YOU WANT - ALL HEADER INFORMATION WILL BE THE SAME FOR ALL PACKET SIZES
#This needs to be list object: if you want to use one packet size must be a list with two elements, where the latter is
#empty, i.e., packet_size=(64,)
# packet_sizes = (64,) #,  # PCAP file will be generated for these
                # 128,  # packet sizes - we always generate all packets with these packet sizes
                # 256,
                # 512,
                # 1024,
                # 1280,
                # 1500)

# COLORIZING
none = '\033[0m'
bold = '\033[01m'
disable = '\033[02m'
underline = '\033[04m'
reverse = '\033[07m'
strikethrough = '\033[09m'
invisible = '\033[08m'

black = '\033[30m'
red = '\033[31m'
green = '\033[32m'
orange = '\033[33m'
blue = '\033[34m'
purple = '\033[35m'
cyan = '\033[36m'
lightgrey = '\033[37m'
darkgrey = '\033[90m'
lightred = '\033[91m'
lightgreen = '\033[92m'
yellow = '\033[93m'
lightblue = '\033[94m'
pink = '\033[95m'
lightcyan = '\033[96m'
CBLINK = '\33[5m'
CBLINK2 = '\33[6m'
# ------ =================================== -----

### CONSTANT LETTERS USED TO BE REPLACED ###
# to ease adding new ones without messing up already used ones
# |--- pcap packet header
# T1 T1 T1 T1 - time in seconds 
# T2 T2 T2 T2 - time in microseconds 
# XX XX XX XX - Frame size 
# YY YY YY YY - Frame size 
#
# |--- eth header
# TY PE - Ethernet type #TODO
#
# |--- ip_header
# XX XX - Length 
# TT - ttl
# PP - protocol (udp/tcp ~ 11/6) #TODO
# YY YY - checksum
# SS SS SS SS - soure IP (ipv4)
# DD DD DD DD - dest IP (ipv4)
#
# |--- ipv6_header
# XX XX - length
# SS SS SS ... - source IP
# DD DD DD ... - dest IP
#
# |--- udp_header
# ZZ ZZ - source port
# XX XX - dest port
# YY YY - length
#
# |-- gtp_header
# FF - type
# LL LL - length
# TE ID TE ID - TEID
#
# |--- tcp_syn_header
# ZZ ZZ - source port
# XX XX - destination port
# NN NN NN NN - SEQ number
# CC CC - checksum
# TT TT TT TT - timestamp

#sec and microsec
TIME_FORMAT = '4D 3C B2 A1' 
#sec and nanosec
# TIME_FORMAT= 'D4 C3 B2 A1'

# Global header for pcap 2.4

pcap_global_header = ( f'{TIME_FORMAT}' #this magic number dictates if time is second+micro, or seconds+nano
                        '02 00'  # File format major revision (i.e. pcap <2>.4)
                        '04 00'  # File format minor revision (i.e. pcap 2.<4>)
                        '00 00 00 00'
                        '00 00 00 00'
                        'FF FF 00 00'
                        '01 00 00 00')

# pcap packet header that must preface every packet
pcap_packet_header = ('T1 T1 T1 T1'  # time in seconds (little endian)
                      'T2 T2 T2 T2'  # time in microseconds (little endian)
                      'XX XX XX XX'  # Frame Size (little endian)
                      'YY YY YY YY')  # Frame Size (little endian)

eth_header = ('00 E0 4C 00 00 01'  # Dest Mac
              '00 04 0B 00 00 02'  # Src Mac
              'TY PE')  # Protocol (0x0800 = IP)

ip_header = ('45'  # IP version and header length (multiples of 4 bytes) (4+4 bits)
             '00'  #DSCP + ECN (6 + 2 bits)
             'XX XX'  # Length (16 bits) - will be calculated and replaced later
             '00 00' # Identification (16 bits)
             '40 00' # Flags + frag_Offset (3 + 13 bits)
             'TT PP'  # TTL + Protocol (11-UDP, 6-TCP) (8 + 8 bits)
             'YY YY'  # Checksum - will be calculated and replaced later (16 bits)
             'SS SS SS SS'  # Source IP (Default: 10.1.0.1) (32 bits)
             'DD DD DD DD')  # Dest IP (Default: 10.0.0.1) (32 bits)

ipv6_header = ( '6' # IP version
                '00' # Traffic class, DSCP, ECN
                '3F B7 7' # Flow label <- randomly set to this 3fb77, it does not have any specific meaning now
                'XX XX' # Length (16 bits) in bytes including extension headers if there is any + PDU- will be calucalted and replaced later
                'PP' # Next header (protocol set to TCP here as only TCP SYNs are supported for now) 
                'FF' # Hop limit - set to max 255
                'SS SS SS SS SS SS SS SS SS SS SS SS SS SS SS SS' # Source IP (128 bits) - will be replaced later
                'DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD' # Dest IP (128 bits) - will be replaced later
)

tcp_syn_header= ('ZZ ZZ' # Source port - will be replaced later
                 'XX XX' # Destination port - will be replaced later
                 'NN NN NN NN' # SEQ number - will be replaced later
                 '00 00 00 00' # ACK number - set to 0 as being SYN packet
                 'L' # header length - calculated later (in 32-bit words) 
                 '00' # reserved (3bit), nonce (1bit), flags (CWR,ECE,URG,ACK) (4bit)
                 '2' # flags (4bit) (ACK,PSH,SYN,FIN -> hex(0b0010) -> 2)  - it's set to 2 to indicate SYN packet
                 '20 00' # window - set randomly
                 'CC CC' # checksum - will be replaced later
                 '00 00' # urgent pointer - 00 00 by default
                 '02 04 05 78' #TCP option - Max Segment Size - set to 1400 bytes
            ### IF YOU WANT MORE TCP OPTIONS HERE, DO IT BELOW ####
                '04 02' # TCP option - SACK permitted
                '08 0A TT TT TT TT 00 00 00 00' # TCP option timestamp - 08 timestamp, 0a (length - 10), TT... timestamp, 00... timestamp echo reply=0 by default
                '01' #TCP option - No-Operation
                '03 03 07' #TCP window scale (03), length (03), set multiplier to 7 (multiply by 128)' 
)

udp_header = ('ZZ ZZ'  # Source port - will be replaced later
              'XX XX'  # Destination Port - will be replaced later
              'YY YY'  # Length - will be calculated and replaced later
              'CC CC') # UDP checksum - it is optional in IPv4 but MANDATORY in IPv6 - so we calculate it to be sure

gtp_header = ('30'              # Version(3), Proto type(1) and other zero fields
              'FF'              # Type: T-PDU
              'LL LL'           # Length - will be calculated later
              'TE ID TE ID')    # TEID - will be added later

ETHER_TYPES_ALLOWED = ['ipv4', 'ipv6']
PROTOS_ALLOWED = ['udp', 'tcp_syn'] #currently, we do not support more protos than pure UDP or TCP_SYN


def _reverseEndian(hexstring):
    #create a list of 2-characters of the input
    big_endian = re.findall('..', hexstring)
    little_endian=""
    for i in reversed(big_endian):
        little_endian+=i

    return little_endian

import struct
def createTimestamp(**kwargs):
    # this is a timestamp in seconds.microseconds, e.g., 1570435931.7557144
    _time = kwargs.get('time', time.time())
    reverse = kwargs.get('reverse', False)

    #check for float type
    if isinstance(_time,float):
        _time="%.8f" % _time # str(time) is not working well below python3 as floats become reduced to two decimals only
    #split it to seconds and microseconds
    _time=_time.split('.')
    # time is a list now
    sec  = format(int(_time[0]), '08x')
    usec = format(int(_time[1]), '08x')
    # convert the to hex
    # sec = ("%08x" % int(sec))   # now, we have sec in hex (big endian)
    # usec = ("%08x" % int(usec)) # now, we have usec in hex (big endian)

    # little_endian_hex = (struct.pack('<f', sec).hex(),struct.pack('<f', usec).hex())
    
    if(reverse):
        # big_endian_hex = (struct.pack('>f', sec).hex(), struct.pack('>f', usec).hex())
        sec  = _reverseEndian(sec)
        usec = _reverseEndian(usec)
        # return big_endian_hex
    
    # return little_endian_hex
    
    return (sec,usec)

def getByteLength(str1):
    return int(len(''.join(str1.split())) / 2)



first_byte_to_write = True

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'ab')
    bitout.write(bytes)


def backspace(n):
    # print((b'\x08' * n).decode(), end='') # use \x08 char to go back
    sys.stdout.write('\r' * n)  # use '\r' to go back

def rawcount(filename):
    '''
    Ultrafast way to count number of lines in a file. Comes pretty handy when parsing the csv file and we want to show its progress.
    comes from here: https://stackoverflow.com/questions/845058/how-to-get-line-count-of-a-large-file-cheaply-in-python
    Works with python3! python2 might not be sufficient for the raw interface
    '''
    f = open(filename, 'rb')
    lines = 0
    buf_size = 1024 * 1024
    read_f = f.raw.read

    buf = read_f(buf_size)
    while buf:
        lines += buf.count(b'\n')
        buf = read_f(buf_size)

    return lines


def calculateRemainingPercentage(message, current, n):
    percent = str(message + ": %d%%" % (int((current / float(n)) * 100)))
    if(current < n):
        #coloring - does not seem to work, though
        percent.replace(": ", str(": {}".format(orange)) )
        
        print(percent, end="\r")
    else:
        #coloring - does not seem to work, though
        percent.replace(": ", str(": {}{}".format(bold,green)) ) 
        
        print(percent, end="")
        print("\t{}{}[DONE]{}".format(bold,green,none))

    # sys.stdout.write(percent)

#    backspace(len(percent))  # back for n chars


def readFile(input):
    #get the number of lines in the file
    num_lines = rawcount(input)
    headers = list() # list of dictionaries
    print("\n### PROCESSING INPUT FILE ###")
    with open(input, 'r') as lines:
        line_num = 1
        for line in lines:
            #progress status
            calculateRemainingPercentage(f"|-- Parsing input file: {input}", line_num, num_lines)
            #remove blank spaces
            line = line.strip()
            #removed blank lines
            if line:
                #omit commented lines
                packet_counter=1
                if not (line.startswith("#", 0, 1)):
                    #assume that the desctiption file is a CSV file and look like this:
                    ##timestamp=123123124.123123, src_mac=<SRC_MAC>,dst_mac=<DST_MAC>, src_ip=<SRC_IP>, dst_ip<DST_IP>, src_port=<SRC_PORT>,dst_port=<DST_PORT>,gtp=<GTP_TEID>, ?? - unimplemented
                    #let us further assume that order is not important
                    one_line = line.split(',')
                    # this dictionary will store eventually one complete header
                    header = {
                            'timestamp':"",
                            'src_mac':"",
                            'dst_mac':"",
                            'src_ip':"",
                            'dst_ip':"",
                            'src_port':"",
                            'dst_port':"",
                            'gtp':"",
                            'ext_src_ip':"",
                            'ext_dst_ip':"",
                            'vlan':"",
                            'ttl':"",
                            'ether_type':"",
                            'src_ipv6':"",
                            'dst_ipv6':"",
                            'protocol':"",
                            'payload_needed':""
                            # NOTE: add more header fields here
                    }
                    for i in one_line:
                        #remove white spaces
                        i=i.strip()
                        #check whether there is a remaining comma at the end (strip above already makes it a zero-length
                        #white space, so we only need to check that

                        if i != "":
                            #OK, everything is prepared, let's start to parse the relevant data
                            header_row=i.split('=')
                            #now, we only will have key=value pairs, let's see whether they are meaningful
                            #note we need to iterate the whole line first, as it should not be ordered.
                            for h in header.keys():
                                if header_row[0] == h:
                                    if h.endswith("mac"):
                                        header[h] = parseMAC(header_row[1])
                                    elif h.endswith('ip'):
                                        header[h] = parseIP(header_row[1])
                                    elif h.endswith('ipv6'):
                                        header[h] = parseIPv6(header_row[1])
                                    elif h.endswith('payload_needed'):
                                        if (header_row[1].lower() == "false"): #we only have to handle false, rest are true by default
                                            header[h] = False
                                        elif (header_row[1].lower() == "true"): #any string converted to bool is considered as True
                                            header[h] = True
                                        else:
                                            print("payload_needed cannot be parsed properly -> reverting to default True")
                                            header[h] = True
                                    
                                    #TODO: below could be OR-ed together, but easier to follow this way
                                    #we basically do some quick conversion here, whether we need values as Int or String
                                    elif h.endswith('timestamp'):
                                        header[h] = header_row[1] #it is a string, but it can remain a string
                                    elif h.endswith('ether_type'):
                                        header[h] = header_row[1] #it is a string, but it can remain a string
                                    elif h.endswith('protocol'):
                                        header[h] = header_row[1] #it is a string, but it can remain a string
                                    else: #all other header fields that are represented as INTEGER
                                    #e.g., ***port,***vlan, ***gtp, ***ttl
                                        header[h] = int(header_row[1])
                                    # NOTE: handle here futher header fields that are different from the above
                                    # or update the above ones to parse the new header fields accordingly
                    headers.append(header)
            
            #update line_num to update progress bar
            line_num+=1

    #Set necessary header fields (e.g., source MAC) data to default values if csv file did contain them
    for h in headers:
        #inside the list
        for hh in h:
            #inside one header
            if hh == 'timestamp' and h[hh]=="":
                h[hh] = default_timestamp

            if hh == 'src_mac' and h[hh]=="":
                h[hh]=parseMAC(default_src_mac)

            if hh == 'dst_mac' and h[hh]=="":
                h[hh] = parseMAC(default_dst_mac)

            if hh == 'src_ip' and h[hh] =="":
                h[hh]=parseIP(default_src_ip)

            if hh == 'dst_ip' and h[hh] == "":
                h[hh] = parseIP(default_dst_ip)

            if hh == 'src_port' and h[hh] == "":
                h[hh] = default_src_port

            if hh == 'dst_port' and h[hh] == "":
                h[hh] = default_dst_port

            if hh == 'vlan' and h[hh] == "":
                h[hh] = default_vlan

            if hh == 'gtp' and h[hh] == "":
                h[hh] = None
            
            if hh == "ttl" and h[hh] == "":
                h[hh] = default_ttl
            
            if hh == "protocol" and h[hh] == "":
                h[hh] = default_protocol            

            if hh == 'src_ipv6' and h[hh] =="":
                h[hh]=parseIPv6(default_src_ipv6)

            if hh == 'dst_ipv6' and h[hh] =="":
                h[hh]=parseIPv6(default_dst_ipv6)

            if hh == 'payload_needed' and h[hh] =="":
                h[hh]=True

            if hh == 'ether_type' and h[hh]=="":
                h[hh] = default_ether_type

            
            #NOTE: Add here new header type


    return headers

def setDefaults(**kwargs):
    '''
    This function will set default headers.
    :param kwargs:
        packet_sizes = list of packetsizes required
        payload_needed = default payload_needed 
        src_mac = default src_mac
        dst_mac = default dst_mac
        src_ip = default src_ip
        dst_ip = default dst_ip
        ttl = default_ttl
        src_port = default src_port
        dst_port = default dst_port
        vlan = default vlan
        gtp_teid = default gtp_teid
        timestamp = default timestamp
        ether_type = default ether_type
        src_ipv6 = default src_ipv6
        dst_ipv6 = default dst_ipv6
        protocol = default protocol
    :return: None
    '''
    global default_src_mac, default_dst_mac
    global default_src_ip, default_dst_ip
    global default_src_port, default_dst_port
    global default_vlan
    global default_ttl
    global packet_sizes
    global verbose
    global default_timestamp
    global default_ether_type
    global default_src_ipv6
    global default_dst_ipv6
    global default_protocol
    #NOTE: add here your new header type

    packet_sizes = []
    default_src_mac = kwargs.get('src_mac')
    default_dst_mac = kwargs.get('dst_mac')
    default_src_ip = kwargs.get('src_ip')
    default_dst_ip = kwargs.get('dst_ip')
    default_src_port = int(kwargs.get('src_port')) #CONVERT TO INT
    default_dst_port = int(kwargs.get('dst_port')) #CONVERT TO INT
    default_vlan = kwargs.get('vlan') #IS NOT CONVERTED TO INT as default is None
    gtp_teid = kwargs.get('gtp_teid') #IS NOT CONVERTED TO INT as default is None
    verbose = kwargs.get('verbose')
    default_timestamp = kwargs.get('timestamp')
    default_ttl = int(kwargs.get('ttl')) #CONVERT TO INT
    default_ether_type = kwargs.get('ether_type')
    default_src_ipv6 = kwargs.get('src_ipv6')
    default_dst_ipv6 = kwargs.get('dst_ipv6')
    default_protocol = kwargs.get('protocol')
    #NOTE: add here your new header type

    if default_vlan is not None:
        default_vlan = int(default_vlan)

    ps = kwargs.get('packet_sizes')
    for i in ps:
        packet_sizes.append(int(i))

def generateRandomHeaders(num_packets):
    '''
    This function generates random packets, as an alternative to reading from a csv file.
    :param num_packets: number of packets to generate
    :return: the generated headers in a list
    '''
    headers = []
    for i in range(num_packets):
        calculateRemainingPercentage("|-- Generating random headers", i, num_packets-1)
        header = {
            'timestamp': default_timestamp,
            'src_mac': getRandomMAC(),
            'dst_mac': getRandomMAC(),
            'src_ip': getRandomIP(),
            'dst_ip': getRandomIP(),
            'src_port': default_src_port,
            'dst_port': default_dst_port,
            'gtp': None,
            'ext_src_ip':"",
            'ext_dst_ip':"",
            'vlan': default_vlan,
            'ttl': default_ttl,
            'ether_type': "ipv4",
            'src_ipv6': parseIPv6(default_src_ipv6),
            'dst_ipv6': parseIPv6(default_dst_ipv6),
            'protocol': default_protocol,
            'payload_needed': True
        }

        headers.append(header)

    return headers

def generateFromHeaders(headers, pcapfile, **kwargs):
    '''
    This function will read the input file and creates a pcap from its content
    :param inputfile: input file to read
    :param pcapfile: pcap output file
    :return: None
    '''

    n=len(headers)

    print("\n### PCAP GENERATION ###")
    # write out header information to file - 5-tuples will be printed in an .nfo files as well
    for i in range(1, int(n) + 1):
        # print out the remaining percentage to know when the generate will finish
        calculateRemainingPercentage("|-- Generating packets in all packet sizes required", i, int(n))

        # set here the header variables
        timestamp = headers[i-1]['timestamp']
        #Get/calculate timestamp
        if timestamp is None: #timestamp was not set, use current time
            time = createTimestamp(reverse=True)
        else:
            time = createTimestamp(time=timestamp, reverse=True)
        #recall, time is a tuple (sec, usec)

        #L2 addresses
        src_mac = headers[i-1]['src_mac']
        dst_mac = headers[i-1]['dst_mac']
        
        #L2 vlan
        vlan = headers[i-1]['vlan']

        #L3 - IPv4 addresses + TTL
        src_ip = headers[i-1]['src_ip']
        dst_ip = headers[i-1]['dst_ip']
        ttl = headers[i-1]['ttl']

        #L3 - IPv6 addresses
        src_ipv6 = headers[i-1]['src_ipv6']
        dst_ipv6 = headers[i-1]['dst_ipv6']
        # TODO: add IPv6 TTL field if needed
        
        # L4 ports and protocol
        sport = headers[i-1]['src_port']
        dport = headers[i-1]['dst_port']
        protocol = headers[i-1]['protocol']

        #PAYLOAD NEEDED?
        payload_needed = headers[i-1]['payload_needed']

        #Let's keep track of the full header size to later generate padding if needed w.r.t. the required packet size
        full_header_length = 0

        #ETHER_TYPE
        ether_type = headers[i-1]['ether_type']
        if ether_type == "ipv4": 
            eth_type = "08 00" #we need the ether_type variable later, so create a new one  to be used below only (from line 484)
            IPv6 = False #indicator for easier handling later
        else: # ipv6
            eth_type = "86 DD"
            IPv6 = True #indicator for easier handling later

        # GTP layer (if any)
        gtp_teid = headers[i-1]['gtp']
        ext_src_ip = headers[i-1]['ext_src_ip']
        ext_dst_ip = headers[i-1]['ext_dst_ip']

        #VLAN HANDLING - it requires other eth_type and additional headers
        if vlan is None:
            # update ethernet header for each packet
            eth_header = dst_mac + ' ' + src_mac + eth_type  # append ether_type to indicate ipv4/6
        else:
            eth_header = dst_mac + ' ' + src_mac + \
                         '81 00' + \
                         '0V VV' + \
                         eth_type # append ether_type to indicate ipv4/6 - #TODO: not sure about VLAN + IPv6
            # update vlan header
            eth_header = eth_header.replace('0V VV', "0%03x" % vlan)
        
        #update full header length
        full_header_length += getByteLength(eth_header)
        
        # +----------------+
        # |   IPv4 packet  |
        # +----------------+
        if not IPv6:
            # +----------------+
            # |   GTP packet   |  # NOTE: GTP only available for IPv4
            # +----------------+
            # GTP tunneling: it requires additional headers
            if gtp_teid is not None:
                gtp = gtp_header
                gtp = gtp.replace('TE ID TE ID', "%08x" % gtp_teid)
                #update full header length
                full_header_length += getByteLength(gtp)
                # generate the external headers
                gtp_dport = 2152
                gtp_sport = 2152
                ext_udp = udp_header.replace('XX XX', "%04x" % gtp_dport)
                ext_udp = ext_udp.replace('ZZ ZZ', "%04x" % gtp_sport)
                ext_ip = ip_header
                ext_ip = ext_ip.replace('SS SS SS SS', ext_src_ip)
                ext_ip = ext_ip.replace('DD DD DD DD', ext_dst_ip)
                ext_ip = ext_ip.replace('TT',"%02x" % ttl)
                ext_ip = ext_ip.replace('PP', '11')
                #update full header length
                full_header_length += getByteLength(ext_ip)
            # +-------------------------+
            # |   IPv4 header assembly  |
            # +-------------------------+
            # update ip header - see on top how it looks like (the last bytes are encoding the IP address)
            ip = ip_header
            #update source IP
            ip = ip.replace('SS SS SS SS', src_ip)
            #update destination IP
            ip = ip.replace('DD DD DD DD', dst_ip)
            #update ttl
            ip = ip.replace('TT', "%02x" % ttl)
            #update protocol
            if protocol == "udp":
                ip = ip.replace('PP', '11') #17 for UDP
            else:
                ip = ip.replace('PP', '06') #6 for TCP

            #update full header length
            full_header_length += getByteLength(ip)

        # +----------------+
        # |   IPv6 packet  |
        # +----------------+
        else:
            # +-------------------------+
            # |   IPv6 header assembly  |
            # +-------------------------+
            # update ipv6 header - see on top how it looks like (the last bytes are encoding the IP address)
            ipv6 = ipv6_header
            ipv6 = ipv6.replace('SS SS SS SS SS SS SS SS SS SS SS SS SS SS SS SS', src_ipv6)
            ipv6 = ipv6.replace('DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD', dst_ipv6)
            if protocol == "udp":
                ipv6 = ipv6.replace('PP', '11')
            else:
                ipv6 = ipv6.replace('PP', '06')
            #ipv6.replace('XX XX', header_length)

            #update full header length
            full_header_length += getByteLength(ipv6)

        # +----------------+
        # |   UDP proto    |
        # +----------------+
        if protocol == "udp":
            # update ports
            udp = udp_header.replace('XX XX', "%04x" % dport)
            udp = udp.replace('ZZ ZZ', "%04x" % sport)

            #update full header length
            full_header_length += getByteLength(udp)
       
        # +----------------+
        # | TCP_SYN proto  |
        # +----------------+
        elif protocol == "tcp_syn":
            tcp_syn = tcp_syn_header.replace('XX XX', "%04x" % dport)
            tcp_syn = tcp_syn.replace('ZZ ZZ', "%04x" % sport)
            tcp_syn = tcp_syn.replace('NN NN NN NN', "%08x" % random.randint(1,65535))

            #tcp_syn_length requires length in the number of 32-bit words, hence we divide by 4
            tcp_syn_len = int(getByteLength(tcp_syn) / 4) 
            tcp_syn = tcp_syn.replace('L', "%01x" % tcp_syn_len)
            
            #timestamp in the TCP header - we use our time tuple, which is (sec, usec)
            #we only need sec here, no usec
            tcp_syn = tcp_syn.replace('TT TT TT TT', time[0])
            # tcp_syn = tcp_syn.replace('CC CC', checksum)

            #update full header length
            full_header_length += getByteLength(tcp_syn)
        
        #TODO: else other protocols/subprotocols, e.g., TCP SYN-ACK, TCP ACK

        # create packets with the different packet sizes but with the same 5-tuple
        for pktSize in packet_sizes:

            #TODO: would make more sense to not have the for loop at all if no payload is needed
            # but would require too much of refactoring :(
            if payload_needed:
                # generate the packet payload (random) w.r.t. the full_header_length kept track on before
                message = getMessage(pktSize, full_header_length)
            else:
                message = ''

            message_len = getByteLength(message)
            

            ip_len = 0 #initialize IP length with 0
            #### ONCE we get the packet payload, we can calculate payload length, protocol length, checksum, etc. ####
            if protocol == "udp":
                # generate the headers (in case of tunneling: internal headers)
                udp_len = message_len + getByteLength(udp_header)
                udp = udp.replace('YY YY', "%04x" % udp_len)
                ip_len = udp_len #add UDP + payload length to IP length
                

            elif protocol == "tcp_syn":
                # print("tcp header length: {}".format(getByteLength(tcp_syn_header)))
                ip_len = message_len + getByteLength(tcp_syn_header) #add tcp syn length + payload to ip len
                #we don't use TCP protocol length as it is in the TCP header, but will use this info in the IP length and PCAP length later on
                
                

            # print(ether_type)
            if ether_type == "ipv4":
                # +----------------+
                # |   IPv4 packet  |
                # +----------------+
                # update ip_len with IPv4 header size
                ip_len += getByteLength(ip_header) 

                ip = ip.replace('XX XX', "%04x" % ip_len)
                # print(ip)
                checksum = ip_checksum(ip.replace('YY YY', '00 00')) # we have to temporarily overwrite the field to 0000 to make it sense as YYYY is not hex
                ip = ip.replace('YY YY', "%04x" % checksum)
                tot_len = ip_len
                
                #UDP checksum calculation
                if protocol == "udp": 
                    #+-----------------------+
                    #|  UDPv4 CHECKSUM CALC  |
                    #+-----------------------+
                    udp_checksum = ip_checksum(
                                                src_ip + #src ip
                                                dst_ip + #dst ip
                                                '00 11' + #8w0 + protocol
                                                str("%04x" % udp_len) + #udp length in 16 bit                                
                                                udp.replace('CC CC', '') + #udp header without checksum, so we remove it from the header when calculating it, replacing it with 00 00 would work, too
                                                message
                                            )
                    udp = udp.replace('CC CC', "%04x" % udp_checksum)

                #TCP checksum calculation
                if protocol == "tcp_syn":
                    #+-----------------------+
                    #|  TCPv4 CHECKSUM CALC  |
                    #+-----------------------+
                    tcp_checksum = (ip_checksum(
                                                src_ip  + #src IP
                                                dst_ip  + #dst IP 
                                                '00 06' + #8w0 + protocol
                                                str("%04x" % (tot_len - getByteLength(ip_header))) + #tcp header+data length -> ip_total_length - ip_header_length
                                                tcp_syn.replace('CC CC','') + #tcp header without the checksum, so we remove it from the header when calculating it, replacing it with 00 00 would work, too
                                                message
                                                )
                                    )
                    tcp_syn = tcp_syn.replace('CC CC', "%04x" % tcp_checksum)
                # encapsulation (external header) #TODO: FIX GTP
                if gtp_teid is not None: # GTP is only supported for IPv4 and UDP packets
                    gtp_len = ip_len
                    gtp = gtp.replace('LL LL', "%04x" % gtp_len)
                    # print(gtp)
                    # generate the external headers
                    ext_udp_len = gtp_len + getByteLength(gtp) + getByteLength(udp_header)
                    ext_udp = ext_udp.replace('YY YY', "%04x" % ext_udp_len)

                    #GTP UTP IPv4 packets have checksum of 00 00 
                    #TODO: calculate it properly
                    ext_udp = ext_udp.replace('CC CC', '00 00')
                    # print(ext_udp)

                    ext_ip_len = ext_udp_len + getByteLength(ip_header)
                    if ext_ip_len > 1500:
                        print("WARNING! Generating >MTU size packets: {}".format(ext_ip_len))
                    ext_ip = ext_ip.replace('XX XX', "%04x" % ext_ip_len)
                    checksum = ip_checksum(ext_ip.replace('YY YY', '00 00'))
                    ext_ip = ext_ip.replace('YY YY', "%04x" % checksum)

                    tot_len = ext_ip_len

            else:
                # +----------------+
                # |   IPv6 packet  |
                # +----------------+
                ipv6 = ipv6.replace('XX XX', "%04x" % ip_len)
                checksum = ip_checksum(ipv6.replace('YY YY', '00 00'))
                ipv6 = ipv6.replace('YY YY', "%04x" % checksum)

                # update ip_len with IPv6 header size
                ip_len += getByteLength(ipv6_header)
                tot_len = ip_len

                #UDP checksum calculation
                if protocol == "udp": 
                    #+-----------------------+
                    #|  UDPv6 CHECKSUM CALC  |
                    #+-----------------------+
                    udp_checksum = ip_checksum(
                                                src_ipv6 + #src ipv6
                                                dst_ipv6 + #dst ipv6
                                                str("%08x" % udp_len) + #udp length in 16 bit     
                                                '00 00 00 11' + #24w0 + protocol/next header
                                                udp.replace('CC CC', '') + #udp header without checksum, so we remove it from the header when calculating it (replacing it with 00 00 would work, too)
                                                message
                                            )
                    udp = udp.replace('CC CC', "%04x" % udp_checksum)

                #TCP checksum calculation
                if protocol == "tcp_syn":
                    #+-----------------------+
                    #|  TCPv4 CHECKSUM CALC  |
                    #+-----------------------+
                    tcp_checksum = (ip_checksum(
                                                src_ipv6  + #src IPv6
                                                dst_ipv6  + #dst IPv6
                                                str("%08x" % (tot_len - getByteLength(ipv6_header))) + #tcp header+data length -> ip_total_length - ip_header_length                                                 
                                                '00 00 00 06' + #24w0 + protocol/next header
                                                tcp_syn.replace('CC CC','') + #tcp header without the checksum, so we remove it from the header when calculating it, replacing it with 00 00 would work, too
                                                message
                                                )
                                    )
                    tcp_syn = tcp_syn.replace('CC CC', "%04x" % tcp_checksum)
            
            # print(tot_len)
            pcap_len = tot_len + getByteLength(eth_header)
            hex_str = "%08x" % pcap_len
            reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]

            pcaph = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
            pcaph = pcaph.replace('YY YY YY YY', reverse_hex_str)

            #using the timestamp values stored in time, we append it to the PCAP header
            pcaph = pcaph.replace('T1 T1 T1 T1', time[0]) # time[0] is seonds
            pcaph = pcaph.replace('T2 T2 T2 T2', time[1]) # time[1] is useonds

            # at the first packet we need the global pcap header
            if i == 1:
                pcap_init = pcap_global_header + pcaph
            # otherwise, we do not need the pcap global header
            else:
                pcap_init = pcaph

            if ether_type == "ipv4":
                # +----------------+
                # |   IPv4 packet  |
                # +----------------+
                if protocol == "udp":    
                    # +----------------+
                    # |   UDP packet   |
                    # +----------------+
                    if gtp_teid is not None:
                        # +----------------+
                        # |   GTP packet   |
                        # +----------------+
                        bytestring = pcap_init + eth_header + ext_ip + ext_udp + gtp + ip + udp + message
                    else:
                        bytestring = pcap_init + eth_header + ip + udp + message
                
                elif protocol == "tcp_syn":
                    # +----------------+
                    # |   TCP packet   |
                    # +----------------+
                    if gtp_teid is not None:
                        # +----------------+
                        # |   GTP packet   |
                        # +----------------+
                        bytestring = pcap_init + eth_header + ext_ip + ext_udp + gtp + ip + tcp_syn + message
                    else:
                        bytestring = pcap_init + eth_header + ip + tcp_syn + message
                #NOTE: implement further protocol here
            else:
                # +----------------+
                # |   IPv6 packet  |
                # +----------------+
                if protocol == "udp":    
                    # +----------------+
                    # |   UDP packet   |
                    # +----------------+
                    bytestring = pcap_init + eth_header + ipv6 + udp + message
                elif protocol == "tcp_syn":
                    # +----------------+
                    # |   TCP packet   |
                    # +----------------+
                    bytestring = pcap_init + eth_header + ipv6 + tcp_syn + message

    
            # this function is writing out pcap file per se
            if verbose:
                print("Packet to be written out:\n{}".format(headers[i-1]))

            writeByteStringToFile(bytestring, pcapfile + str(".%dbytes.pcap" % pktSize))


def getRandomMAC():
    return "1a" + str("%0.10X" % random.randint(1,0xffffffffff))

def getRandomIP():
    # to avoid multicast addresses (range is between 0.0.0.0/8 and 223.255.255.255)
    ip = str("%0.8X" % random.randint(0x01000000,0xdfffffff))

    #avoid others 127.0.0.0/8 - hex(127)=7F
    while ip.startswith("7F"):
        #print "Ooops, accidentally a 127.0.0.0/8 IP was generated...REGENERATING!"
        ip = str("%0.8X" % random.randint(0x01000000, 0xdfffffff))

    return ip

def getRandomPort(**args):
    '''
    Use 'exlude=[XXX]' to exlude a list of ports (even 1 port has to be defined as a list)
    '''
    port = random.randint(1,65535)
    exlude = args.get("exclude", [4305])
    if(port in exlude):
        getRandomPort()
    return int(port)

def parseMAC(mac):
    ret_val=mac.replace(":","").upper()
    if len(ret_val) != 12: #check mac address length
        print("ERROR during parsing mac address - not long enough!: {}".format(mac))
        exit(-1)
    return  ret_val

def parseIPv6(ip):
    ret_val=ip.replace(":","").upper()
    if len(ret_val) != 32: #check ipv6 address length
        #TODO: implement compressed ipv6 addresses, i.e., omitted zeros and :: 
        print("ERROR during parsing ipv6 address - not long enough, please DO NOT OMIT 0s!: {}".format(ip))
        exit(-1)
    return  ret_val

def parseIP(ip):
    ret_val = ""
    #split IP address into 4 8-bit values
    ip_segments=ip.split(".")
    for i in ip_segments:
        ret_val+=str("%0.2X" % int(i))
    if len(ret_val) != 8: #check length of IP
        print("ERROR during parsing IP address - not long enough!: {}".format(ip))
        exit(-1)
    return ret_val

def splitN(str1, n):
    return [str1[start:start + n] for start in range(0, len(str1), n)]


# Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):
    # print("---- CHECKSUM CALC ----")
    # print(iph)
    # split into bytes
    words = splitN(''.join(iph.split()), 4)

    csum = 0
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


def getMessage(packetsize, header_length):
    '''
    This function creates random message to pad the packet as payload w.r.t. the header_length and the required packet size
    If header size is already bigger than the required packetsize, null-char is returned as message
    For instance, if packet size is 64B and protocol is TCP, then no message will be appended as TCP header already makes the packet size to go beyond 64
    @params
    int packetsize = required final packet size
    int header_length = the size of the already used headers
    '''
    message = ''
    header_length = header_length + 4 #we have to calculate with the checksum appended by the interface itself when sent out (offloaded to the hardware on modern systems)
    #check if header_length is already enough for the required packet size
    if header_length > packetsize:
        return message

    #otherwise fill the message with random numbers as HEX chars
    for i in range(0, int(packetsize) - header_length):  
        message += "%0.2X " % random.randint(0, 255)

    return message


def showHelp():
    print("{}usage: pcap_generator_from_csv.py <input_csv_file> <desired_output_pcapfile_prefix>{}".format(bold,none))
    print('Example: ./pcap_generator_from_csv.py input.csv output')
    print("{}Note: Existing files with the given <desired_output_pcapfile_prefix>.[PacketSize].pcap will be overwritten!{}".format(yellow,none))

    print("This python script generates pcap files according to the header information stored in a CSV file")
    print("See 'input.csv' file for CSV details")
    print("")
    print("Supported header fields: {}\n" \
                                               "  VLAN \n" \
                                               "  L2 (src and dst MAC, ethertype) \n" \
                                               "  L3 (src and dst IPv4/IPv6, TTL) \n" \
                                               "  L4 (src and dst PORT) \n" \
                                               "  GTP_TEID\n " \
                                               "  PROTOCOL (UDP/TCP_SYN)"
                                               "  TIMESTAMP for each packet\n ".format(bold,none))
    print("Any further header definition in the file is sleemlessly ignored!")
    print("")
    print("In case of missing L2, L3, L4 information in the inputfile, default values will be used!")
    print("To change the default values, modify the source code (first couple of lines after imports)")
    print("")
    print("Default packet size is 64-byte! It is defined as a list in the source code! " \
          "Extend it if necessary!\n")
    print("{}WARNING: THE SCRIPT IS NOT BULLET-PROOF! \nPAY ATTENTION TO YOUR HEADER DATA\n For instance, supply IPv4 addresses when ether_type=0x0800 and IPv6 addresses when ether_type=0x86dd and vice versa!{}\n",red,none)
    print("")
    print("{}Alternatively, you may wish to generate random packets.{}".format(yellow,none))
    print("{}usage: pcap_generator_from_csv.py --generate-random <number_of_packets> -o <desired_output_pcapfile_prefix>{}".format(bold,none))
    print('Example: ./pcap_generator_from_csv.py --generate-random 128 -o output')
    exit(0)


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Usage of PCAP generator from CSV file")
    parser.add_argument('-i','--input',nargs=1, dest="input",
                        help="Specify the name of the input CSV file. "
                             "For syntax, see input.csv.example! "
                             "If not provided, the provided example file input.csv will be used by default!",
                        required=False,
                        default=["input.csv"])
    parser.add_argument('-R','--generate-random', nargs=1, dest="generate_random",
                        help="Generate a certain number of random packets (provided as the param of this) instead " 
                        "of giving a CSV file input. If specified, input CSV file is ignored.",
                        required=False,
                        default=[False])
    parser.add_argument('-o','--output',nargs=1, dest="output",
                        help="Specify the output PCAP file's basename! "
                             "Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!",
                        required=True)
    parser.add_argument('-p','--packetsizes',nargs=1, dest="packetsizes",
                        help="Specify here the required packetsize! "
                        "In case of more than one, just create a comma separated list "
                        "such as 64,112,42. Default: 64",
                        required=False,
                        default=['64'])    
    parser.add_argument('-P','--payload-needed', action='store_true', dest='payload_needed',
                        help="Specifiy if you want the packets to be padded to the packetsize at all! "
                        "For instance, if you want normal TCP SYN, you don't need payload - " 
                        "although, using TCP protocol already makes your packet bigger than the min. of 64B",
                        required=False)

    parser.add_argument('-a','--src-mac',nargs=1, dest="src_mac",
                        help="Specify default source MAC address if it is not present "
                        "in the input.csv. Default: 00:00:00:00:00:01",
                        required=False,
                        default=["00:00:00:00:00:01"])
    parser.add_argument('-b', '--dst-mac', nargs=1, dest="dst_mac",
                        help="Specify default destination MAC address if it is not present "
                             "in the input.csv. Default: 00:00:00:00:00:02",
                        required=False,
                        default=["00:00:00:00:00:02"])
    parser.add_argument('-c', '--vlan', nargs=1, dest="vlan",
                        help="Specify default VLAN tag if it is not present "
                             "in the input.csv. Default: No VLAN",
                        required=False,
                        default=[None])
    parser.add_argument('-d', '--src-ip', nargs=1, dest="src_ip",
                        help="Specify default source IP address if it is not present "
                             "in the input.csv. Default: 10.0.0.1",
                        required=False,
                        default=["10.0.0.1"])

    parser.add_argument('-e', '--dst-ip', nargs=1, dest="dst_ip",
                        help="Specify default destination IP address if it is not present "
                             "in the input.csv. Default: 10.0.0.2",
                        required=False,
                        default=["10.0.0.2"])

    parser.add_argument('-f', '--ttl', nargs=1, dest="ttl",
                        help="Specify default TTL if it is not present "
                             "in the input.csv. Default: 10",
                        required=False,
                        default=["64"])

    parser.add_argument('-g', '--src-port', nargs=1, dest="src_port",
                        help="Specify default source port if it is not present "
                             "in the input.csv. Default: 1234",
                        required=False,
                        default=["1234"])
    parser.add_argument('-j', '--dst-port', nargs=1, dest="dst_port",
                        help="Specify default destination port if it is not present "
                             "in the input.csv. Default: 80",
                        required=False,
                        default=["80"])
    parser.add_argument('-k', '--gtp-teid', nargs=1, dest="gtp_teid",
                        help="Specify default GTP_TEID if it is not present "
                             "in the input.csv. Default: NO GTP TEID",
                        default=[None])
    parser.add_argument('-l', '--timestamp', nargs=1, dest="timestamp",
                        help="Specify the default timestamp for each packet if it is not present "
                             "in the input.csv. Default: Use current time",
                        required=False,
                        default=[None])
    parser.add_argument('-m', '--ether-type', nargs=1, dest="ether_type",
                        help="Sepcify the default ether type for each packet if is not present (ipv4/ipv6) "
                             "in the input.csv. Default: ipv4",
                        required=False,
                        default="ipv4")
    parser.add_argument('-n','--src-ipv6', nargs=1, dest="src_ipv6",
                        help="Specify the default source IPv6 address if IPv6 is desired and the value is not present"
                             "in the input.csv. Default: 2603:c022:0001:52dd:dead:beef:abba:edda (0s are not OMITTED!)",
                        required=False,
                        default=['2603:c022:0001:52dd:dead:beef:abba:edda']
                        )
    parser.add_argument('-u','--dst-ipv6', nargs=1, dest="dst_ipv6",
                        help="Specify the default destination IPv6 address if IPv6 is desired and the value is not present"
                             "in the input.csv. Default: 2405:0800:9030:1bd2:dead:beef:dead:beef (0s are not OMITTED!)",
                        required=False,
                        default=['2405:0800:9030:1bd2:dead:beef:dead:beef']
                        )
    parser.add_argument('-w','--protocol', nargs=1, dest="protocol",
                        help="Specify the default protocol if not present (udp/tcp_syn) "
                        "Default: udp",
                        required=False,
                        default=['udp']
                        )
    parser.add_argument('-v','--verbose', action='store_true', required=False, dest='verbose',
                        help="Enabling verbose mode")

    # NOTE: Add more parsable arguments here if needed

    parser.set_defaults(verbose=False)
    parser.set_defaults(payload_needed=True)
    

    args = parser.parse_args()

    

    input = args.input[0]
    generate_random = int(args.generate_random[0])


    output = args.output[0]
    packet_sizes = (args.packetsizes[0]).split(',')
    payload_needed = args.payload_needed
    src_mac = args.src_mac[0]
    dst_mac = args.dst_mac[0]
    src_ip = args.src_ip[0]
    dst_ip = args.dst_ip[0]
    src_port = args.src_port[0]
    dst_port = args.dst_port[0]
    vlan = args.vlan[0]
    gtp_teid = args.gtp_teid[0]
    timestamp = args.timestamp[0]
    ttl = args.ttl[0]
    ether_type = (args.ether_type).lower()
    if ether_type not in ETHER_TYPES_ALLOWED:
        print("Ethertype {} is not known! Only IPv4 and IPv6 are allowed!".format(ether_type))
        print("")
        exit(-1)
    
    src_ipv6 = args.src_ipv6[0]
    dst_ipv6 = args.dst_ipv6[0]

    protocol = args.protocol[0]
    if protocol not in PROTOS_ALLOWED:
        print("Protocol {} is not known! Only IPv4 and IPv6 are allowed!".format(protocol))
        print("")
        exit(-1)

    ## NOTE: Add here more input args to parse
    
    verbose=args.verbose

    print("{}The following arguments were set:{}".format(bold,none))
    print("{}Input file:            {}{}{}".format(bold,green,input,none))
    print("{}Generate random?       {}{}{}".format(bold,green,generate_random,none))
    print("{}Output file:           {}{}{}".format(bold,green,output,none))
    print("{}Packetsizes:           {}{}{}".format(bold,green,packet_sizes,none))
    print("{}PAYLOAD needed:        {}{}{}".format(bold,green,payload_needed,none))
    print("{}Eth_type if undefined: {}{}{}".format(bold,green,ether_type,none))
    print("{}SRC MAC if undefined:  {}{}{}".format(bold,green,src_mac,none))
    print("{}DST MAC if undefined:  {}{}{}".format(bold,green,dst_mac,none))
    print("{}SRC IP if undefined:   {}{}{}".format(bold,green,src_ip,none))
    print("{}DST IP if undefined:   {}{}{}".format(bold,green,dst_ip,none))
    print("{}TTL if undefined:      {}{}{}".format(bold,green,ttl,none))
    print("{}SRC PORT if undefined: {}{}{}".format(bold,green,src_port,none))
    print("{}DST PORT if undefined: {}{}{}".format(bold,green,dst_port,none))
    print("{}VLAN if undefined:     {}{}{}".format(bold,green,vlan,none))
    print("{}GTP_TEID if undefined  {}{}{}".format(bold,green,gtp_teid,none))
    print("{}TIMESTAMP if undefined:{}{}{}".format(bold,green,timestamp,none))
    print("{}SRC IPv6 if undefined: {}{}{}".format(bold,green,src_ipv6,none))
    print("{}DST IPv6 if undefined: {}{}{}".format(bold,green,dst_ipv6,none))
    print("{}Protocol if undefined: {}{}{}".format(bold,green,protocol,none))
    


    ## NOTE: Add here more parsed input args to display



    for i in packet_sizes:
        open(str("{}.{}bytes.pcap".format(output,i)),'w') # delete contents

    setDefaults(
        packet_sizes=packet_sizes,
        payload_needed=payload_needed,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        vlan=vlan,
        verbose=verbose,
        gtp_teid=gtp_teid,
        timestamp=timestamp,
        ttl=ttl,
        ether_type=ether_type,
        protocol=protocol,
        src_ipv6=src_ipv6,
        dst_ipv6=dst_ipv6
        # NOTE: add here extra header to be configured from input
    )

    # print(generate_random)
    if generate_random != 0:
        headers = generateRandomHeaders(generate_random)
    else:
        headers = readFile(input)

    generateFromHeaders(headers,output)
