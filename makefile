CC = gcc

all: dns.o dns_listen dns_scan

dns_scan: dns.o dns_scan.c
	$(CC) dns_scan.c -lpthread obj/dns.o -o bin/dns_scan

dns_listen: dns.h dns.o dns_listen.c
	$(CC) dns_listen.c obj/dns.o -o bin/dns_listen

dns.o: dns.h dns.c
	$(CC) dns.c -c -o obj/dns.o