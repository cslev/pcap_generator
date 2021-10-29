# PCAP Generator
This application generates PCAP files from CSV files using low-level Python tools

## CSV file should look like this:
```
#this is a comment
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, dst_port=22
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, dst_port=8192,vlan=10
src_mac=20:00:00:00:00:01,dst_mac=20:00:00:00:00:02, vlan=1000
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, dst_port=22
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, src_port=12312, dst_port=514, ether_type=ipv4, protocol=tcp_syn
#ext_src_ip=192.168.1.20, ext_dst_ip=192.168.1.1, gtp=255, src_ip=10.0.0.1, dst_ip=10.0.0.2, src_port=2048, dst_port=4096
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ipv6=2603:abba:abba:acdc:dead:beef:dead:beef, dst_ipv6=2400:abba:edda:acdc:dbf3:52a8:2cb7:b38e, src_port=11771, dst_port=123,ether_type=ipv6,protocol=tcp_syn
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ipv6=2603:abba:abba:acdc:dead:beef:dead:beef, dst_ipv6=2400:abba:edda:acdc:dbf3:52a8:2cb7:b38e,dst_port=534,ether_type=ipv6,protocol=udp

```
 If a necessary L2/L3/L4/GTP/etc. header field is missing default values will be used, which can be changed by input arguments.
 
## Supported protocol and ether types
- Ethernet
  - IPv4
    - UDP
    - TCP SYN
    - GTP
  - IPv6
    - UDP
    - TCP SYN

## Checksum
In all cases, even in IPv4/UDP where checksum are optional, checksum are always calculated properly.
Hence, you can use the generated pcap to replay it over muliple links as routers will not drop the packets (due to checksum errors)

## Payload
There is an optional setting for each packet about the payload. The new "protocol_header" you can define for each packet is `payload_needed` and by default it is set to `True`. 
So, if you omit it works as before and uses the packet size as an indicator.
Otherwise, you can set for some packets to not generate a payload. For instance, you might generate different types of packets with 128B packet size, but you don't want the TCP_SYN packets to have a payload at all. Then, you can disable it by adding `payload_needed=false` to the particular line in your .csv file.

## Requirements
 - Python 3
 
## Quick walkthrough
###### First, download the source
```
$ git clone https://github.com/cslev/pcap_generator
$ cd pcap_generator
```

###### Create your own CSV file, then execute the following command:
```
$ python3 pcap_generator_from_csv.py -i YOUR_INPUT.CSV -o YOUR_DESIRED_PCAPFILENAME
```

###### For additional arguments, see help
```
$ python3 pcap_generator_from_csv.py -h

usage: pcap_generator_from_csv.py [-h] -i INPUT -o OUTPUT [-p PACKETSIZES] [-P] [-a SRC_MAC] [-b DST_MAC] [-c VLAN] [-d SRC_IP] [-e DST_IP] [-f TTL] [-g SRC_PORT] [-j DST_PORT] [-k GTP_TEID] [-l TIMESTAMP]
                                  [-m ETHER_TYPE] [-n SRC_IPV6] [-u DST_IPV6] [-w PROTOCOL] [-v]

Usage of PCAP generator from CSV file

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Specify the name of the input CSV file. For syntax, see input.csv.example!
  -o OUTPUT, --output OUTPUT
                        Specify the output PCAP file's basename! Output will be [output].[PACKETSIZE]bytes.pcap extension is not needed!
  -p PACKETSIZES, --packetsizes PACKETSIZES
                        Specify here the required packetsize! In case of more than one, just create a comma separated list such as 64,112,42. Default: 64
  -P, --payload-needed  Specifiy if you want the packets to be padded to the packetsize at all! For instance, if you want normal TCP SYN, you don't need payload - although, using TCP protocol already makes
                        your packet bigger than the min. of 64B
  -a SRC_MAC, --src-mac SRC_MAC
                        Specify default source MAC address if it is not present in the input.csv. Default: 00:00:00:00:00:01
  -b DST_MAC, --dst-mac DST_MAC
                        Specify default destination MAC address if it is not present in the input.csv. Default: 00:00:00:00:00:02
  -c VLAN, --vlan VLAN  Specify default VLAN tag if it is not present in the input.csv. Default: No VLAN
  -d SRC_IP, --src-ip SRC_IP
                        Specify default source IP address if it is not present in the input.csv. Default: 10.0.0.1
  -e DST_IP, --dst-ip DST_IP
                        Specify default destination IP address if it is not present in the input.csv. Default: 10.0.0.2
  -f TTL, --ttl TTL     Specify default TTL if it is not present in the input.csv. Default: 10
  -g SRC_PORT, --src-port SRC_PORT
                        Specify default source port if it is not present in the input.csv. Default: 1234
  -j DST_PORT, --dst-port DST_PORT
                        Specify default destination port if it is not present in the input.csv. Default: 80
  -k GTP_TEID, --gtp-teid GTP_TEID
                        Specify default GTP_TEID if it is not present in the input.csv. Default: NO GTP TEID
  -l TIMESTAMP, --timestamp TIMESTAMP
                        Specify the default timestamp for each packet if it is not present in the input.csv. Default: Use current time
  -m ETHER_TYPE, --ether-type ETHER_TYPE
                        Sepcify the default ether type for each packet if is not present (ipv4/ipv6) in the input.csv. Default: ipv4
  -n SRC_IPV6, --src-ipv6 SRC_IPV6
                        Specify the default source IPv6 address if IPv6 is desired and the value is not presentin the input.csv. Default: 2603:c022:0001:52dd:dead:beef:abba:edda (0s are not OMITTED!)
  -u DST_IPV6, --dst-ipv6 DST_IPV6
                        Specify the default destination IPv6 address if IPv6 is desired and the value is not presentin the input.csv. Default: 2405:0800:9030:1bd2:dead:beef:dead:beef (0s are not OMITTED!)
  -w PROTOCOL, --protocol PROTOCOL
                        Specify the default protocol if not present (udp/tcp_syn) Default: udp
  -v, --verbose         Enabling verbose mode
```

## Example
In order to create a PCAP from CSV file called 'input.csv', desired output file called 'output.pcap' with packet sizes of 64,128, and 512 assuming that if there is no VLAN header specified in the CSV file for a given header then apply VLAN tag: 505, the following command will do the job:
```
$ python3 pcap_generator_from_csv.py -i input.csv -o output -p 64,128,512 --vlan 505
```
Your PCAP files will be 'output.64bytes.pcap', 'output.128bytes.pcap', and 'output.512bytes.pcap' all consisting of the same header fields but in different packet sizes.

**NOTE**: if you set `payload_needed=false` for some specific packets, they won't be padded to the requested packet size obviously.

## WARNING
**THE SCRIPT IS NOT BULLET-PROOF!**

PAY ATTENTION TO YOUR HEADER DATA

For instance, supply IPv4 addresses when *ether_type=ipv4*, and IPv6 addresses when *ether_type=ipv6* and vice versa!
Otherwise, you might end up using default values or run into errors!

## GTP feature 
Thanks to @egerpon for adding GTP feature
### UPDATE: seems to be broken

## Want to quickly create a pcap with random packets?
I am always having this issue. There is a software-based network function and I would like to measure its performance with an RSS-enabling pcap file, i.e., to quickly send some random "rubbish" towards it but the trace is diverse enough to enforce the network function to scale and use more queues and/or CPU cores for packet processing.

Below, is a simple BASH loop to create an input file for `pcap_generator_from_csv.py` than consist of **100** random packets:
```
for i in {1..100}; 
do 
  ip=$(printf "%d.%d.%d.%d\n" "$((RANDOM % 256))" "$((RANDOM % 256))" "$((RANDOM % 256))" "$((RANDOM % 256))"); 
  src_port=$(printf "%d\n" "$((RANDOM % 65535))");
  dst_port=$(printf "%d\n" "$((RANDOM % 65535))"); 
  echo "src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=${ip}, src_port=${src_port}, dst_port=${dst_port}" >> rss_capable.txt;
done
```
Once ready, you can use the freshly made `rss_capable.txt` to generate the actual pcap file accordingly.
