#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <time.h>
#include "dns.h"

typedef struct range {
    unsigned long start;
    unsigned long amount;
    in_addr_t spoof_ip;
    unsigned char *host;
} Thread_Data;

unsigned short checksum(const void *buffer, int numWords) {
    //Store sum in long, so that carry bits are not lost.
    unsigned long sum = 0;
    const unsigned short *data = buffer;

    for(int i = 0; i < numWords; i++) 
        sum += *data++;
    
    //Adding the carry digits from the csum may produce more carry bits.
    while(sum > 0xFFFF) 
        sum = (sum >> 16) + (sum & 0xFFFF);
    //return the compliment of the sum
    return (unsigned short) ~sum;
}

unsigned char *encapsulateUDP(unsigned char *buffer, int *payloadSize, int dst_port) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, *payloadSize + sizeof(struct udphdr));

    if(!tmp) {
        perror("encapsulateUDP :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(tmp + sizeof(struct udphdr), buffer, *payloadSize);

    struct udphdr *udph = (struct udphdr *) tmp;
    udph->uh_sport = htons(53535);  // Always use our fixed port
    udph->uh_dport = htons(dst_port);
    udph->uh_ulen = htons(sizeof(struct udphdr) + *payloadSize);
    udph->uh_sum = 0;  // UDP checksum is optional, set to 0
    *payloadSize += sizeof(struct udphdr);

    return tmp;
}

unsigned char *encapsulateIP(unsigned char *buffer, int *payloadSize, in_addr_t sourceIP, in_addr_t destIP) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, *payloadSize + sizeof(struct ip));

    if(!tmp) {
        perror("encapsulateUDP :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(tmp + sizeof(struct ip), buffer, *payloadSize);

    struct ip *iph = (struct ip *) tmp;
    iph -> ip_v = 4;
    iph -> ip_hl = 5; //minimum number of octets
    iph -> ip_tos = 0;
    iph -> ip_len = htons(*payloadSize + sizeof(struct ip)); //len = data + header
    iph -> ip_id = htons(4321);
    iph -> ip_off = 0;
    iph -> ip_ttl = MAXTTL;
    iph -> ip_p = IPPROTO_UDP;
    iph -> ip_sum = 0;
    iph -> ip_src.s_addr = sourceIP;
    iph -> ip_dst.s_addr = destIP;

    iph -> ip_sum = checksum(tmp, iph -> ip_hl * 2); //ip header length is the number of 32-bit words, but csum uses 16 bit words

    *payloadSize += sizeof(struct ip);

    return tmp;
}

void *scan_thread(void *args) {

    // TODO Remove scanning special purpose IP ranges (private IPs)
    //as per https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    
    Thread_Data *td = (Thread_Data *) args;

    unsigned char *buff = NULL;
    int payloadSize = 0;

    int socket_type = SOCK_DGRAM;
    int socket_protocol = IPPROTO_UDP;

    // Build DNS packet in correct order:
    // 1. Start with DNS header
    buff = encapsulateDNS(NULL, &payloadSize);
    
    // 2. Add query name
    buff = addRecord(buff, td->host, &payloadSize);
    
    // 3. Add question section (type and class)
    buff = addQuestion(buff, &payloadSize);
    
    // 4. Add EDNS record
    buff = addEDNS(buff, &payloadSize);
    
    printf("\nThread built DNS query packet for %s\n", td->host);

    // Read the port that the listener is using first
    int listen_port = 0;
    FILE *port_file = fopen("/tmp/dns_scanner_port", "r");
    if (port_file) {
        fscanf(port_file, "%d", &listen_port);
        fclose(port_file);
        printf("Thread using listener port: %d\n", listen_port);
    } else {
        printf("Warning: Could not read listener port\n");
    }

    // if(td->spoof_ip) {
    //     socket_type = SOCK_RAW;
    //     socket_protocol = IPPROTO_RAW;
        
    //     //add UDP header with our listening port as source
    //     buff = encapsulateUDP(buff, &payloadSize, 53); //port 53 default dns
    //     struct udphdr *udph = (struct udphdr *)buff;
    //     udph->uh_sport = htons(listen_port ? listen_port : rand());
    //     buff = encapsulateIP(buff, &payloadSize, td->spoof_ip, 0);
    // }

    int sockfd = socket(AF_INET, socket_type, socket_protocol);
    if(sockfd < 0) {
        perror("Couldn't create socket");
        return NULL;
    }

    // Set socket options
    int option = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(sockfd);
        return NULL;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(option)) < 0) {
        perror("setsockopt SO_REUSEPORT failed");
        close(sockfd);
        return NULL;
    }

    // Bind socket if not spoofing
    if (!td->spoof_ip && listen_port > 0) {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = htons(listen_port);

        if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            perror("Couldn't bind socket");
            close(sockfd);
            return NULL;
        }
    }

    struct sockaddr_in server_addr;
    for(uint32_t ip = td->start; ip < td->start + td->amount + 1; ip++) {
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(ip);
        server_addr.sin_port = htons(53);  // DNS port

        // if(td->spoof_ip) {
        //     struct ip *iph = (struct ip *)buff;
        //     iph->ip_dst.s_addr = htonl(ip);
        //     iph->ip_sum = checksum(iph, iph->ip_hl * 2);
        //     server_addr.sin_port = htons(0);
        // }

        int sent = sendto(sockfd, (char *) buff, payloadSize, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
        if (sent < 0) {
            perror("Error sending packet");
        } else {
            printf("Thread sent: %d bytes from port %d to %s:%d\n", 
                   sent, 
                   listen_port,
                   inet_ntoa(server_addr.sin_addr), 
                   ntohs(server_addr.sin_port));
        }
    }

    if(buff) free(buff);
    close(sockfd);
    return NULL;
}

int start_scanning(int numThreads, in_addr_t start_ip, in_addr_t end_ip, unsigned char *spoof_ip, unsigned char *host) {
    unsigned long ips_per_thread = (ntohl(end_ip) - ntohl(start_ip))/numThreads;
    pthread_t *threads = malloc(numThreads * sizeof(pthread_t));
    Thread_Data **thread_data = malloc(numThreads * sizeof(Thread_Data*));
    printf("IPs per thread: %ld\n", ips_per_thread);

    for(int i = 0; i < numThreads; i++) {
        thread_data[i] = (Thread_Data *) malloc(sizeof(Thread_Data));
        thread_data[i]->host = malloc(strlen(host) + 1);
        strcpy(thread_data[i]->host, host);
        thread_data[i]->start = (ntohl(start_ip) + i*ips_per_thread);
        thread_data[i]->amount = ips_per_thread;
        // if(spoof_ip)
        //     thread_data[i]->spoof_ip = inet_addr(spoof_ip);
        // else
        thread_data[i]->spoof_ip = 0;

        pthread_create(&threads[i], NULL, &scan_thread, thread_data[i]);
    }

    // Wait for all threads and cleanup
    for(int j = 0; j < numThreads; j++) {
        pthread_join(threads[j], NULL);
        if(thread_data[j]->host) free(thread_data[j]->host);
        free(thread_data[j]);
    }
    free(thread_data);
    free(threads);
    return 0;
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Error: Invalid argument length\n");
        printf("Options:\n");
        printf("\t-h DNS Server IP (single scan)\n");
        printf("\t-d Domain to resolve\n");
        printf("\t-S IP of server with DNS Listener (spoof scan)\n");
        printf("\t-s Start IP (DNS scan range)\n");
        printf("\t-e End IP (DNS scan range)\n");
        printf("\t-t Thread count (optional, default = 1)\n");
        printf("\t-l Listener output file (optional, default = 'dns_outfile')\n");
        printf("\t   (Not for spoof scanning)\n");
        
        printf("\nUsage:\n");
        printf("\t%s -h <DNS Server> \t\t- Test single server\n", argv[0]);
        printf("\t%s -h <DNS Server> -d <Domain> \t- Test single domain on single server\n", argv[0]);
        printf("\t%s -h <DNS Server> -d <Domain> -S <Server IP> \t- Test single domain on spoofed listener\n", argv[0]);
        printf("\t%s -s <Start IP> -e <End IP> (-S <Server IP>) \t- Scan range of IPs (can also be spoofed)\n", argv[0]);

        return -1;
    }

    int opt;
    int payloadSize = 0;
    int thread_count = 1;

    int socket_type = SOCK_DGRAM;
    int socket_protocol = IPPROTO_UDP;

    char *dns_server = NULL, *listen_file = "dns_outfile";
    unsigned char *host = NULL, 
    *req_ip = NULL, 
    *start_ip = NULL, 
    *end_ip = NULL,
    *buff = NULL;

    while((opt = getopt(argc, argv,"h:S:s:e:d:t:l:")) > 0) {

        switch (opt)
        {
        case 'h': //specifies DNS server
            printf("Host was specified: %s\n", optarg);
            dns_server = (char *) malloc(strlen(optarg) + 1);
            strcpy((char *) dns_server, optarg);
            break;
        
        case 'S':
            // printf("Spoofing enabled. Responses will go to: %s\n", optarg);
            // req_ip = (unsigned char *) malloc(strlen(optarg) + 1);
            // strcpy((char *) req_ip, optarg);
            // break;
        case 's':
            printf("Start IP: %s\n", optarg);
            start_ip = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) start_ip, optarg);
            break;
        case 'e':
            printf("End IP: %s\n", optarg);
            end_ip = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) end_ip, optarg);
            break;
        case 'd':
            printf("Domain name: %s\n", optarg);
            host = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) host, optarg);
            break;
        case 't':
            printf("Using %d Threads\n", atoi(optarg));
            thread_count = atoi(optarg);
            break;
        case 'l':
            listen_file = malloc(strlen(optarg) + 1);
            strcpy(listen_file, optarg);
        default:
            break;
        }
    }

    srand(time(NULL));

    if(host == NULL) {
        printf("Using default domain\n");
        host = (unsigned char *) malloc(50);
        strcpy((char *) host, "..");
    }    

    if(host == NULL) {
        perror("Couldn't allocate host");
        return -1; 
    }

    if(req_ip == NULL) { //spoofing scanning was not selected
        pthread_t listen_id;
        pthread_create(&listen_id, NULL, &dns_listen_thread, (void *) listen_file);
        sleep(2); //wait for thread to init
    }
    
    if(start_ip && end_ip) {
        in_addr_t start, end;
        inet_pton(AF_INET, start_ip, &start);
        inet_pton(AF_INET, end_ip, &end); //for ip 255.255.255.255 this returns -1
        start_scanning(thread_count, start, end, req_ip, host);
    } else {
        if(!dns_server) {
            perror("Invalid DNS server!");
            return -1;
        }
        // Build DNS packet in correct order:
        // 1. Start with DNS header
        buff = encapsulateDNS(NULL, &payloadSize);
        
        // 2. Add query name
        buff = addRecord(buff, host, &payloadSize);
        
        // 3. Add question section (type and class)
        buff = addQuestion(buff, &payloadSize);
        
        // 4. Add EDNS record
        buff = addEDNS(buff, &payloadSize);
        
        printf("\nBuilt DNS query packet for %s\n", host);

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(53);
        if (inet_pton(AF_INET, dns_server, &server_addr.sin_addr) == -1) { 
            perror("inet_pton failed");
            return -1;
        }

        if(req_ip) {
            socket_type = SOCK_RAW;
            socket_protocol = IPPROTO_RAW;

            //add UDP header
            buff = encapsulateUDP(buff, &payloadSize, 53); //port 53 default dns
            //add IP header with spoofed source IP
            buff = encapsulateIP(buff, &payloadSize, inet_addr((const char *) req_ip), inet_addr((const char *) dns_server));
            server_addr.sin_port = htons(0);
        }

        int sockfd = socket(AF_INET, socket_type, socket_protocol);
        if(sockfd < 0) {
            perror("Couldn't create socket");
            return -1;
        }

        // Set socket options
        int option = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
            perror("setsockopt SO_REUSEADDR failed");
            close(sockfd);
            return -1;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(option)) < 0) {
            perror("setsockopt SO_REUSEPORT failed");
            close(sockfd);
            return -1;
        }

        struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0) {
            perror("setsockopt SO_LINGER failed");
            close(sockfd);
            return -1;
        }

        // For non-spoofed queries, bind to port 53535
        if (!req_ip) {
            struct sockaddr_in bind_addr;
            memset(&bind_addr, 0, sizeof(bind_addr));
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_addr.s_addr = INADDR_ANY;
            bind_addr.sin_port = htons(53535);

            if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
                perror("Couldn't bind to port 53535");
                close(sockfd);
                return -1;
            }
            printf("Using port 53535\n");
        }

        int sent = sendto(sockfd, (char *) buff, payloadSize, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
        printf("Sending: %d bytes to %s:%d\n", sent, dns_server, ntohs(server_addr.sin_port));

        if(sent < 0) {
            perror("Error sending packet");
            return -1;
        }

        printf("\nDNS Query Details:\n");
        printf("Server: %s:%d\n", dns_server, ntohs(server_addr.sin_port));
        printf("Query Type: 255 (ANY)\n");
        printf("Domain: %s\n", host);
        printf("Hex Dump:\n");
        for(int i = 0; i < payloadSize; i++) {
            if(i%16 == 0) printf("\n%04x: ", i);
            printf("%02X ", buff[i]);
        }
        printf("\n");

        // Don't close the socket immediately - wait for response
        sleep(1);  
        close(sockfd);
    }
    sleep(2); //let the last couple of responses roll in

    if(host) free(host); 
    if(dns_server) free(dns_server);
    if(req_ip) free(req_ip);
    if(buff) free(buff);
    if(start_ip) free(start_ip);
    if(end_ip) free(end_ip);

    return 0;
}
