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
#include <signal.h>
#include <errno.h>
#include "dns.h"

// Signal handler for clean shutdown
static volatile int keep_running = 1;
void handle_signal(int signum) {
    keep_running = 0;
}

void formatDNSName(unsigned char* dns,unsigned char* host)
{
    if(strncmp((const char *) host, ".", 1) == 0) 
        *dns++ = '\0';
    
        
    else {
        char *token = strtok((char *) host, ".");
        do {

            *dns++ = strlen((char *) token);
            for(int i = 0; i < strlen((const char *) token) ; i++)  
                *dns++ = token[i];

        } while((token = strtok(NULL, ".")) != NULL);
    }
    
    *dns++ = '\0';
}

unsigned char *addEDNS(unsigned char *buffer, int *payloadSize) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + 11);

    if(!tmp) {
        perror("addEDNS :: Couldn't reallocate buffer");
    }

    // EDNS0 OPT record format:
    // - Root domain name (1 byte: 0)
    // - Type (2 bytes: 41 = OPT)
    // - UDP payload size (2 bytes: 4096)
    // - Extended RCODE (1 byte: 0)
    // - EDNS version (1 byte: 0)
    // - Z field (2 bytes: 0)
    // - Data length (2 bytes: 0)
    unsigned char *edns = &tmp[*payloadSize];
    
    // Root domain name
    edns[0] = 0;
    
    // Type OPT (41 = 0x0029)
    edns[1] = 0x00;
    edns[2] = 0x29;
    
    // UDP payload size (4096 = 0x1000)
    edns[3] = 0x10;
    edns[4] = 0x00;
    
    // Extended RCODE & Version
    edns[5] = 0x00;  // Extended RCODE
    edns[6] = 0x00;  // Version
    
    // Z field
    edns[7] = 0x00;
    edns[8] = 0x00;
    
    // Data length
    edns[9] = 0x00;
    edns[10] = 0x00;

    *payloadSize += 11;  // Size of OPT record

    return tmp;
}

unsigned char *addQuestion(unsigned char *buffer, int *payloadSize) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + sizeof(struct QUES));

    if(!tmp) {
        perror("addQuestion :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    // Add question section:
    // - QTYPE: A record (1)
    // - QCLASS: IN (1)
    unsigned char *question = &tmp[*payloadSize];
    question[0] = 0x00;  // QTYPE high byte
    question[1] = 0x01;  // QTYPE low byte (1 = A record)
    question[2] = 0x00;  // QCLASS high byte
    question[3] = 0x01;  // QCLASS low byte (1 = IN)

    *payloadSize += 4;  // Size of QTYPE (2) + QCLASS (2)
    return tmp;
}

unsigned char *addRecord(unsigned char *buffer, unsigned char *query_name, int *payloadSize) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + strlen((const char *) query_name) + 1);

    if(!tmp) {
        perror("addRecord :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    unsigned char *qname = &tmp[*payloadSize];
    formatDNSName(qname, query_name);
    *payloadSize += strlen( (const char *) qname) + 1;

    return tmp;
}

unsigned char *encapsulateDNS(unsigned char *buffer, int *payloadSize) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + sizeof(struct DNS_HDR));

    if(!tmp) {
        perror("encapsulateDNS :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    // First 12 bytes are DNS header, then copy existing data after it
    unsigned char *header = tmp;
    if (buffer && *payloadSize > 0) {
        memcpy(tmp + 12, buffer, *payloadSize);
    }
    
    // Set DNS ID in network byte order
    unsigned short id = (unsigned short)rand();
    unsigned short dns_id = htons(id);
    header[0] = (dns_id >> 8) & 0xFF;  // High byte
    header[1] = dns_id & 0xFF;         // Low byte
    
    // Byte 2: Flags (QR=0, OPCODE=0, AA=0, TC=0, RD=1)
    header[2] = 0x01;  // Only RD (recursion desired) bit set
    
    // Byte 3: Flags (RA=0, Z=0, AD=0, CD=0, RCODE=0)
    header[3] = 0x00;
    
    // Question count: 1
    header[4] = 0x00;
    header[5] = 0x01;
    
    // Answer count: 0
    header[6] = 0x00;
    header[7] = 0x00;
    
    // Authority count: 0
    header[8] = 0x00;
    header[9] = 0x00;
    
    // Additional count: 1 (for EDNS)
    header[10] = 0x00;
    header[11] = 0x01;

    *payloadSize += 12;  // DNS header is always 12 bytes
    
    // Debug output
    printf("\nDNS Query packet:\n");
    printf("Header: ");
    for(int i = 0; i < 12; i++) {
        printf("%02X ", header[i]);
    }
    printf("\nPayload: ");
    for(int i = 12; i < *payloadSize; i++) {
        printf("%02X ", tmp[i]);
    }
    printf("\nTotal size: %d bytes\n", *payloadSize);

    return tmp;
}


void *dns_listen_thread(void *args) {
    // Set up signal handler
    //signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    char * file_name = args;
    FILE *outfile = fopen(file_name, "w");
    
    if(outfile == NULL) {
        printf("Error opening outfile!\n");
        exit(-1);
    }
    else {
        printf("Starting listener to file: %s...\n", file_name);
    }

    // Remove old port file if it exists
    unlink("/tmp/dns_scanner_port");

    unsigned char *rcv_buff = malloc(65536);
    struct sockaddr_in any;
    socklen_t len = sizeof(any);
    
    // Create socket with raw UDP to match sender
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0) {
        perror("Couldn't create socket");
        exit(-1);
    }

    // Set socket options
    int option = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(sockfd);
        exit(-1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(option)) < 0) {
        perror("setsockopt SO_REUSEPORT failed");
        close(sockfd);
        exit(-1);
    }

    // Allow binding to an address that is already in use
    struct linger sl;
    sl.l_onoff = 1;
    sl.l_linger = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0) {
        perror("setsockopt SO_LINGER failed");
        close(sockfd);
        exit(-1);
    }

    // Try to bind to port 53535
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(53535);

    if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("Couldn't bind to port 53535");
        close(sockfd);
        exit(-1);
    }

    printf("Listening on port 53535\n");
    FILE *port_file = fopen("/tmp/dns_scanner_port", "w");
    if (port_file) {
        fprintf(port_file, "53535");
        fclose(port_file);
    }

    while(keep_running) {
        int resp_size = recvfrom(sockfd, rcv_buff, 65536, 0, (struct sockaddr *) &any, &len);

        if(resp_size < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, check if we should exit
                continue;
            }
            perror("Error getting response");
            continue;  // Don't exit on receive error, just try again
        }

        printf("\nReceived packet from %s:%d, size: %d\n", 
               inet_ntoa(any.sin_addr),
               ntohs(any.sin_port), 
               resp_size);

        // Print first 20 bytes of received data
        printf("DNS packet: ");
        for(int i = 0; i < 20 && i < resp_size; i++) {
            printf("%02X ", rcv_buff[i]);
        }
        printf("\n");

        // Check if this is from DNS port 53
        if (ntohs(any.sin_port) == 53) {
            // DNS header starts at beginning of buffer for UDP socket
            unsigned char *dns_payload = rcv_buff;
                    
            // Check if this is a response by examining the flags
            // In DNS header, QR bit is the highest bit of byte 2
            if (dns_payload[2] & 0x80) {  // Check QR bit directly from the byte
                unsigned char rcode = dns_payload[3] & 0x0F;
                printf("DNS Response received - RCODE: %d\n", rcode);
                
                // Print more details about the response
                printf("Response flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, RCODE=%d\n",
                       (dns_payload[2] & 0x80) >> 7,  // QR
                       (dns_payload[2] & 0x78) >> 3,  // OPCODE
                       (dns_payload[2] & 0x04) >> 2,  // AA
                       (dns_payload[2] & 0x02) >> 1,  // TC
                       (dns_payload[2] & 0x01),       // RD
                       (dns_payload[3] & 0x80) >> 7,  // RA
                       rcode);                        // RCODE
                
                fprintf(outfile, "%s %d\n", inet_ntoa(any.sin_addr), resp_size);
                fflush(outfile);
            }
        }
    }

    printf("\nShutting down listener...\n");
    if(rcv_buff) free(rcv_buff);
    fclose(outfile);
    close(sockfd);
    unlink("/tmp/dns_scanner_port");
    return NULL;
}
