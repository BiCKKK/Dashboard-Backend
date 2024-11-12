#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string.h>
#include <sqlite3.h>

struct sensorInfos{
    char* IOA;
    char* value;

}SensorInfos;

char dbPath[64] = "../PHPserver/dbHandler/test.db";

void updateSensorInfo(struct sensorInfos **si,int size,char* tableName){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    char *sqlIOA = malloc(128);
    char *sqlvalue = malloc(128);
    for(int i=0;i<size;i++){

        sprintf(sqlIOA,"UPDATE \"%s\" SET IOA=\"%s\" WHERE id=%d",tableName,si[i]->IOA,i+1);
        rc = sqlite3_exec(db, sqlIOA, 0, 0, &err_msg);
        
        if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

        sprintf(sqlvalue,"UPDATE \"%s\" SET value=\"%s\" WHERE id=%d",tableName,si[i]->value,i+1);
        rc = sqlite3_exec(db, sqlvalue, 0, 0, &err_msg);

        if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }
    }

    sqlite3_close(db);
    
}



void delSensorInfo(struct sensorInfos *si){
    free(si->IOA);
    free(si->value);
    free(si);
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}



void packet_handler(const u_char *packet,struct pcap_pkthdr *header,char* tableName){
    struct ether_header *eth_header; 
    eth_header = (struct ether_header *) packet; 
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { 
        printf("Not an IP packet. Skipping...\n\n"); 
        return; 
    } 

    // printf("Total packet available: %d bytes\n", header->caplen); 
    // printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */ 
    const u_char *ip_header; 
    const u_char *tcp_header; 
    const u_char *payload; 
 
    /* Header lengths in bytes */ 
    int ethernet_header_length = 14; /* Doesn't change */ 
    int ip_header_length; 
    int tcp_header_length; 
    int payload_length; 


    /* Find start of IP header */ 
    ip_header = packet + ethernet_header_length; 
    /* The second-half of the first byte in ip_header 
       contains the IP header length (IHL). */ 
    ip_header_length = ((*ip_header) & 0x0F); 
    /* The IHL is number of 32-bit segments. Multiply 
       by four to get a byte count for pointer arithmetic */ 
    ip_header_length = ip_header_length * 4; 
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length); 

        /* Now that we know where the IP header is, we can  
       inspect the IP header for a protocol number to  
       make sure it is TCP before going any further.  
       Protocol is always the 10th byte of the IP header */ 
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) { 
        printf("Not a TCP packet. Skipping...\n\n"); 
        return; 
    } 

    const u_char *ip_source = ip_header + 12;
    char* sourceIP = malloc(64);
    char* tmp = malloc(64);
    sprintf(sourceIP,"%x.%x.%x.%x",*(ip_source),*(ip_source+1),*(ip_source+2),*(ip_source+3));
    printf("IP from %s: %s\n",tableName,sourceIP);
    
        /* Add the ethernet and ip header length to the start of the packet 
       to find the beginning of the TCP header */ 
    tcp_header = packet + ethernet_header_length + ip_header_length; 
    /* TCP header length is stored in the first half  
       of the 12th byte in the TCP header. Because we only want 
       the value of the top half of the byte, we have to shift it 
       down to the bottom half otherwise it is using the most  
       significant bits instead of the least significant bits */ 
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4; 
    /* The TCP header length stored in those 4 bits represents 
       how many 32-bit words there are in the header, just like 
       the IP header length. We multiply by four again to get a 
       byte count. */ 
    tcp_header_length = tcp_header_length * 4; 
    // printf("TCP header length in bytes: %d\n", tcp_header_length); 

        /* Add up all the header sizes to find the payload offset */ 
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length; 
    // printf("Size of all headers combined: %d bytes\n", total_headers_size); 
    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length); 
    // printf("Payload size: %d bytes\n", payload_length); 
    payload = packet + total_headers_size; 
    // printf("Memory address where payload begins: %p\n\n", payload); 
 
    /* Print payload in ASCII */ 
    if (payload_length > 0) { 
        const u_char *temp_pointer = payload; 
        int byte_count = 0;
        struct SensorInfos *allSensors[5];
        if(payload_length==87){
            temp_pointer+=12;
            int IOA_length = 3;
            int value_length = 4;
            struct sensorInfos **allSensors = malloc(5*sizeof(*allSensors));
            for(int i=0;i<5;i++){
                allSensors[i] = malloc(sizeof(allSensors[i]));
                allSensors[i]->IOA = malloc(IOA_length);
                allSensors[i]->value = malloc(value_length);
                char* tmp = malloc(2);
                sprintf(allSensors[i]->IOA,"");
                sprintf(allSensors[i]->value,"");
                for(int IOA_index=0;IOA_index<IOA_length;IOA_index++){
                    sprintf(tmp,"%02X",*temp_pointer);
                    strcat(allSensors[i]->IOA,tmp);
                    temp_pointer++;
                }
                for(int value_index=0;value_index<value_length;value_index++){
                    sprintf(tmp,"%02X",*temp_pointer);
                    strcat(allSensors[i]->value,tmp);
                    temp_pointer++;
                }
                temp_pointer+=8;
                // printf("IOA %d: %s\n",i,allSensors[i]->IOA);
                // printf("Value %d: %s\n",i,allSensors[i]->value);
            }

            updateSensorInfo(allSensors,5,tableName);

            for(int i=0;i<5;i++){
                delSensorInfo(allSensors[i]);
            }
            free(allSensors);
        }
        
        

        // while (byte_count++ < payload_length) { 
        //     printf("%02X", *temp_pointer); 
        //     temp_pointer++; 
        // } 
        //printf("\n"); 
    } 
 
    return; 

}

int main(int argc,char *argv[])
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    char* DSS1device = "WANR1-eth1";
    char* DSS2device = "WANR2-eth1";
    pcap_t* DSS1descr;
    pcap_t* DSS2descr;
    const u_char *DSS1packet;
    const u_char *DSS2packet;
    struct pcap_pkthdr DSS1hdr;
    struct pcap_pkthdr DSS2hdr;     /* pcap.h */


    while(1){
        DSS1descr = pcap_open_live(DSS1device,BUFSIZ,0,100,error);
        if(DSS1descr == NULL)
        {
            printf("pcap_open_live(): %s\n",error);
            exit(1);
        }

        DSS1packet = pcap_next(DSS1descr,&DSS1hdr);
        if(DSS1packet == NULL)
        {
            printf("Didn't grab packet\n");
            exit(1);
        }

        DSS2descr = pcap_open_live(DSS2device,BUFSIZ,0,100,error);
        if(DSS2descr == NULL)
        {
            printf("pcap_open_live(): %s\n",error);
            exit(1);
        }

        DSS2packet = pcap_next(DSS2descr,&DSS2hdr);
        if(DSS2packet == NULL)
        {
            printf("Didn't grab packet\n");
            exit(1);
        }

        packet_handler(DSS1packet,&DSS1hdr,"DSS1SENSORS");
        sleep(1);
        packet_handler(DSS2packet,&DSS2hdr,"DSS2SENSORS");
        sleep(1);
    }
    

    return 0;

}

