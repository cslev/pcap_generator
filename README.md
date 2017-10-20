# PCAP Generator
This application generates PCAP files from CSV files using low-level Python tools

## CSV file should look like this:
```
#this is a comment
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, src_port=12345, dst_port=22
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, dst_port=22
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, dst_port=2222,vlan=10
src_mac=20:00:00:00:00:01,dst_mac=20:00:00:00:00:02, vlan=1000
src_mac=00:00:00:00:00:01,dst_mac=00:00:00:00:00:02, src_ip=10.0.0.1, dst_ip=10.0.0.2, dst_port=22
```
 If a necessary L2/L3/L4 header field is missing  default values will be used, which can be changed by input arguments.
 
## Requirements
 - Python
 
## Quick walkthrough
###### First, download the source
```
$ git clone https://github.com/cslev/pcap_generator
$ cd pcap_generator
```

###### Create your own CSV file, then execute the following command:
```
$ python pcap_generator_from_csv.py -i YOUR_INPUT.CSV -o YOUR_DESIRED_PCAPFILENAME
```

###### For additional arguments, see help
```
$ python pcap_generator_from_csv.py -h

usage: pcap_generator_from_csv.py [-h] -i INPUT -o OUTPUT [-p PACKETSIZES]
                                  [-a SRC_MAC] [-b DST_MAC] [-c VLAN]
                                  [-d SRC_IP] [-e DST_IP] [-f SRC_PORT]
                                  [-g DST_PORT]

Usage of PCAP generator from CSV file

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Specify the name of the input CSV file. For syntax,
                        see input.csv.example!
  -o OUTPUT, --output OUTPUT
                        Specify the output PCAP file's name! .pcap extension
                        is not needed!
  -p PACKETSIZES, --packetsizes PACKETSIZES
                        Specify here the required packetsize! In case of more
                        than one, just create a comma separated list such as
                        64,112,42. Default: 64
  -a SRC_MAC, --src_mac SRC_MAC
                        Specify default source MAC address if it is not
                        present in the input.csv. Default: 00:00:00:00:00:01
  -b DST_MAC, --dst_mac DST_MAC
                        Specify default destination MAC address if it is not
                        present in the input.csv. Default: 00:00:00:00:00:02
  -c VLAN, --vlan VLAN  Specify default VLAN tag if it is not present in the
                        input.csv. Default: No VLAN
  -d SRC_IP, --src_ip SRC_IP
                        Specify default source IP address if it is not present
                        in the input.csv. Default: 10.0.0.1
  -e DST_IP, --dst_ip DST_IP
                        Specify default destination IP address if it is not
                        present in the input.csv. Default: 192.168.88.8
  -f SRC_PORT, --src_port SRC_PORT
                        Specify default source port if it is not present in
                        the input.csv. Default: 1234
  -g DST_PORT, --dst_port DST_PORT
                        Specify default destination port if it is not present
                        in the input.csv. Default: 808

```


