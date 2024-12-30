# DNS Scanner and Listener (with Spoof Scanning)

>Disclaimer - This code was written for educational purposes. 

>**dns_listen must be run with sudo priviledes**


## What Is Scanning ?

Scanning is often done to find DNS resolvers which readily respond to queries, so that they can be used in 
DNS Amplification Attacks.

## What is EDNS ?

EDNS is Extended DNS. The significance of this is previously DNS had a limit of 512 bytes per packet. EDNS modified this allowing users to include information about the size of packets they can handle. This in and of itself made DNS amplification attacks feasible.

## Sample Output: 

```
./dns_scan -h 8.8.8.8
Host was specified: 8.8.8.8
Using default domain
Sending: 29 bytes

66 34 01 00 00 01 00 00 
00 00 00 01 00 00 FF 00 
01 00 00 29 FF FF 00 00 
00 00 00 00 00 

sudo ./dns_list
Server: 8.8.8.8 Responded with: 2043 bytes with 5376 records

```
