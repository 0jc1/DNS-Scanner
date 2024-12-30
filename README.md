# DNS Scanner and Listener

>Disclaimer - This code was written for educational purposes. 

>**dns_listen must be run with sudo priviledes**


## What Is Scanning ?

Scanning is often done to find DNS resolvers which readily respond to queries, so that they can be used in 
DNS Amplification Attacks.

## What is EDNS ?

EDNS is Extended DNS. The significance of this is previously DNS had a limit of 512 bytes per packet. EDNS modified this allowing users to include information about the size of packets they can handle. This in and of itself made DNS amplification attacks feasible.

## Sample Output: 

```
sudo ./dns_scan -h 8.8.8.8 
Host was specified: 8.8.8.8
Using default domain
Starting listener to file: dns_outfile...
Listening on port 53535

DNS Query packet:
Header: DD 24 01 00 00 01 00 00 00 00 00 01 
Payload: 
Total size: 12 bytes

Built DNS query packet for ..
Using port 53535
Sending: 28 bytes to 8.8.8.8:53

DNS Query Details:
Server: 8.8.8.8:53
Query Type: 255 (ANY)
Domain: ..
Hex Dump:

0000: DD 24 01 00 00 01 00 00 00 00 00 01 00 00 01 00 
0010: 01 00 00 29 10 00 00 00 00 00 00 00 

Received packet from 8.8.8.8:53, size: 103
DNS packet: DD 24 81 80 00 01 00 00 00 01 00 01 00 00 01 00 01 00 00 06 
DNS Response received - RCODE: 0
Response flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, RCODE=0

```
