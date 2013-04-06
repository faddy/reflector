/***********************
*     Reflector     *
***********************/

/*
Written by: Fahad Ghani, fahadghanidgp@gmail.com
*/

/*
(you need to be root user to run this application) 
The reflector is a tool which reflects against an attacker's host the attacker's traffic. It is able to simulate two non-existent hosts: 'victim' and 'relayer', at both the Ethernet and IP levels. Whenever an attacker sends a packet to victim, the packet is intercepted by the reflector application and re-sent as a packet from relayer to the attacker's host. The reply that is sent by the attacker's host to relayer is then sent back as a packet from victim (in reply to the original packet) to the attacker's host.

The program can be compiled using gcc, using libpcap and libnet libraries:
% gcc -Wall reflector.c -o reflector -lpcap -lnet

The application can be invoked with the following syntax:
# reflector --victim-ip [IP Addr] --victim-ethernet [Ethernet Addr] \
            --relayer-ip [IP Addr] --relayer-ethernet [Ethernet Addr]

A non-default interface can be specified using the --interface command-line option.

E.g.:
# reflector --victim-ip 192.168.1.11 --victim-ethernet 00:0A:0B:0C:11:37 \
            --relayer-ip 192.168.1.9 --relayer-ethernet 00:0A:06:1B:AB:B0
 
*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header*/
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst;  /* source and dest address */
};

/*ARP header*/
struct sniff_arp {
    u_short arp_htype;
    u_short arp_ptype;
    u_char arp_hlen;
    u_char arp_plen;
    u_short arp_oper;
    u_char arp_sha[ETHER_ADDR_LEN];
    u_char arp_spa[4];
    u_char arp_tha[ETHER_ADDR_LEN];
    u_char arp_tpa[4];
};


/*TCP header*/
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;	 /* source port */
    u_short th_dport;    /* destination port */
    tcp_seq th_seq;      /* sequence number */
    tcp_seq th_ack;      /* acknowledgement number */
    u_char th_offx2;     /* data offset, rsvd */
    u_char th_flags;
    u_short th_win;      /* window */
    u_short th_sum;      /* checksum */
    u_short th_urp;      /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short udp_sport;  
    u_short udp_dport;  
    u_short udp_len;    
    u_short udp_sum;  
};

char* ghost_ip;                      // = "192.168.1.70";
char* relayer_ip;                    // = "192.168.1.80";
u_char ghost_eth[ETHER_ADDR_LEN];    // = {0x0c, 0x60, 0x76, 0x07, 0xbc, 0x15};
u_char relayer_eth[ETHER_ADDR_LEN];  // = {0x0c, 0x60, 0x76, 0x07, 0xbc, 0x16};
char* dev;                           //="eth0";

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_arp *arp;			/* The ARP header */
    const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
    u_char *payload;                    /* Packet payload */

    int size_tcp;
    int size_ip;
    int size_payload;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    switch(ethernet->ether_type){
    case 0x0008:
        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;	/* IP header length in integer */

        /* the libnet context */
            libnet_t* l; 
            int bytes_written;
            char errbuf[LIBNET_ERRBUF_SIZE];
            l = libnet_init(LIBNET_LINK, dev, errbuf);
            if ( l == NULL ) {
                fprintf(stderr, "\nlibnet_init() failed: %s\n", errbuf);
                exit(EXIT_FAILURE);
            }

            if( (strcmp(inet_ntoa(ip->ip_dst), ghost_ip)==0) || (memcmp(ethernet->ether_dhost, ghost_eth, 6)==0) ){
                printf("\naddressed to ghost ip!----------");
                switch(ip->ip_p) {
                    case IPPROTO_TCP:
                        printf("   Protocol: TCP\n");

                        /******************************
                         * BUILD TCP STUFF HERE
                        *******************************/

                        /* define/compute tcp header offset */
                        printf("\nsize_ip = %d", size_ip);
                        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                        size_tcp = TH_OFF(tcp)*4;
                        printf("\nsize_tcp= %d", size_tcp);
                        if (size_tcp < 20) {
                            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                            return;
                        }

                        /* define/compute tcp payload (segment) offset */
                        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

                        /* compute tcp payload (segment) size */
                        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

                        /* build TCP options*/
                        u_int8_t *tcp_options = (u_int8_t* )(packet + SIZE_ETHERNET + size_ip + 20); printf("\ntcp options = %d", *tcp_options); 
                        u_int32_t tcp_options_s = (u_int32_t)(size_tcp - 20); printf("\ntcp options length = %d", tcp_options_s);
                        libnet_build_tcp_options(tcp_options, tcp_options_s, l, 0);

                        /* build TCP header*/					
                        u_int16_t sp = ntohs(tcp->th_sport);
                        u_int16_t dp = ntohs(tcp->th_dport);
                        u_int32_t seq = ntohl(tcp->th_seq);
                        u_int32_t ack = ntohl(tcp->th_ack);
                        u_int8_t control = tcp->th_flags;
                        u_int16_t win = ntohs(tcp->th_win);
                        u_int16_t sum = 0;
                        u_int16_t urg = ntohs(tcp->th_urp);
                        u_int16_t len = ntohs(ip->ip_len) - size_ip;
                        u_int32_t payload_s = size_payload;
                        printf("\n payload = %d\n", payload_s);
                        if(size_payload==0) 
                            libnet_build_tcp(sp, dp, seq, ack, control, win, sum, urg, len, NULL, 0, l, 0);
                        else
                            libnet_build_tcp(sp, dp, seq, ack, control, win, sum, urg, len, payload, payload_s, l, 0);

                        /*******************************/

                        break;

                    case IPPROTO_UDP:
                        printf("   Protocol: UDP\n");

                        /******************************
                         * BUILD UDP STUFF HERE
                        *******************************/
                        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);				

                        /* build UDP header */
                        u_int16_t sport = ntohs(udp->udp_sport);
                        u_int16_t dport = ntohs(udp->udp_dport);
                        u_int16_t length = ntohs(udp->udp_len);
                        u_int16_t udp_sum = 0;
                        u_int8_t *udp_payload = (u_int8_t *)(packet + SIZE_ETHERNET + size_ip + 8); 
                        u_int32_t udp_payload_s = ntohs(udp->udp_len) - 8;

                        libnet_build_udp(sport, dport, length, udp_sum, udp_payload, udp_payload_s, l, 0);

                        /*******************************/			
                }
            
                /* build IP options */
                u_int8_t* ip_options = (u_int8_t*)(packet + SIZE_ETHERNET + 20); 
                u_int32_t ip_options_s = (u_int32_t)(size_ip - 20);
                libnet_build_ipv4_options(ip_options, ip_options_s, l, 0);
                
                /* build IP header */
                u_int32_t relayer_ip_addr = libnet_name2addr4(l, relayer_ip, LIBNET_DONT_RESOLVE);	        
                u_int16_t len = ntohs(ip->ip_len); 
                u_int8_t tos = ip->ip_tos;
                u_int16_t id = ntohs(ip->ip_id);
                u_int16_t frag = ntohs(ip->ip_off);
                u_int8_t ttl = ip->ip_ttl;
                u_int8_t prot = ip->ip_p;
                u_int16_t sum = 0;
                u_int32_t src = relayer_ip_addr;            // new src IP = relayer's IP 
                u_int32_t dst = (ip->ip_src).s_addr;        // new dst IP = packet's src IP
                u_int8_t *ip_payload;
                u_int32_t ip_payload_s;
            
                // ip_payload = null if TCP/UDP
                if( (ip->ip_p==IPPROTO_TCP) || (ip->ip_p==IPPROTO_UDP) ){
                    ip_payload = NULL; 
                    ip_payload_s = 0;
                }
                else {
                    ip_payload = (u_int8_t*) (packet + SIZE_ETHERNET + size_ip);
                    ip_payload_s = ntohs(ip->ip_len) - (size_ip);
                }
            
                libnet_build_ipv4(len, tos, id, frag, ttl, prot, sum, src, dst, ip_payload, ip_payload_s, l, 0);
                
                // new src ETH = relayer's ETH 
                // new dst ETH = packet's dst ETH 
                if ( libnet_build_ethernet ((u_int8_t*) (ethernet->ether_shost), (u_int8_t*) (relayer_eth), ETHERTYPE_IP, NULL, 0, l, 0) == -1 )
                    {
                        fprintf(stderr, "\nError building Ethernet header: %s\n",libnet_geterror(l));
                        libnet_destroy(l);
                        exit(EXIT_FAILURE);
                    }
                
                // call the send function on packet
                bytes_written = libnet_write(l);
                if ( bytes_written != -1 )
                    printf("\n%d bytes written.", bytes_written);
                else
                    fprintf(stderr, "\nError writing packet: %s\n",libnet_geterror(l));
    
                printf("\n----------------------");
            }
            
            else {
                if( (strcmp(inet_ntoa(ip->ip_dst), relayer_ip)==0) || (memcmp(ethernet->ether_dhost, relayer_eth, 6)==0)){
                    printf("\naddressed to relayer ip!---------");
                                    
                    switch(ip->ip_p) {
                        case IPPROTO_TCP:
                            printf("   Protocol: TCP\n");
                                            
                            /******************************
                             * BUILD TCP STUFF HERE
                             *******************************/
                            /* define/compute tcp header offset */
                            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                            size_tcp = TH_OFF(tcp)*4;
                            if (size_tcp < 20) {
                                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                                return;
                            }
    
                            /* define/compute tcp payload (segment) offset */
                            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
                            
                            /* compute tcp payload (segment) size */
                            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
                        
                            /* build TCP options*/
                            u_int8_t *tcp_options = (u_int8_t* )(packet + SIZE_ETHERNET + size_ip + 20); 
                            u_int32_t tcp_options_s = (u_int32_t) (size_tcp - 20);
                            libnet_build_tcp_options(tcp_options, tcp_options_s, l, 0);
                            
                            /* build TCP header*/                        
                            u_int16_t sp = ntohs(tcp->th_sport);
                            u_int16_t dp = ntohs(tcp->th_dport);
                            u_int32_t seq = ntohl(tcp->th_seq);
                            u_int32_t ack = ntohl(tcp->th_ack);
                            u_int8_t control = tcp->th_flags;
                            u_int16_t win = ntohs(tcp->th_win);
                            u_int16_t sum = 0;
                            u_int16_t urg = ntohs(tcp->th_urp);
                            u_int16_t len = size_tcp + size_payload;
                            u_int32_t payload_s = size_payload;
                            if(size_payload==0) 
                                libnet_build_tcp(sp, dp, seq, ack, control, win, sum, urg, len, NULL, 0, l, 0);
                            else
                                libnet_build_tcp(sp, dp, seq, ack, control, win, sum, urg, len, payload, payload_s, l, 0);
                            
                            /*******************************/
                            break;
                        case IPPROTO_UDP:
                            printf("   Protocol: UDP\n");
    
                            /******************************
                             * BUILD UDP STUFF HERE
                             *******************************/
                            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);                
                            
                            /* build UDP header */
                            u_int16_t sport = ntohs(udp->udp_sport);
                            u_int16_t dport = ntohs(udp->udp_dport);
                            u_int16_t length = ntohs(udp->udp_len);
                            u_int16_t udp_sum = 0;
                            u_int8_t *udp_payload = (u_int8_t *)(packet + SIZE_ETHERNET + size_ip + 8); 
                            u_int32_t udp_payload_s = ntohs(udp->udp_len) - 8;
                            
                            libnet_build_udp(sport, dport, length, udp_sum, udp_payload, udp_payload_s, l, 0);
                            
                            /*******************************/
                                
                    }            
                                    
                    /* build IP options */
                    u_int8_t* options = (u_int8_t*)(packet + SIZE_ETHERNET + 20); 
                    u_int32_t options_s = (u_int32_t)(size_ip - 20);
                    libnet_build_ipv4_options(options, options_s, l, 0);
                                
                    /* build IP header */
                    u_int32_t ghost_ip_addr = libnet_name2addr4(l, ghost_ip, LIBNET_DONT_RESOLVE);
                    u_int16_t len = ntohs(ip->ip_len); 
                    u_int8_t tos = ip->ip_tos;
                    u_int16_t id = ntohs(ip->ip_id);
                    u_int16_t frag = ntohs(ip->ip_off);
                    u_int8_t ttl = ip->ip_ttl;
                    u_int8_t prot = ip->ip_p;
                    u_int16_t sum = 0;
                    u_int32_t src = ghost_ip_addr;                // new src IP = ghost's IP 
                    u_int32_t dst = (ip->ip_src).s_addr;        // new dst IP = packet's src IP
                    
                    u_int8_t *ip_payload; 
                    u_int32_t ip_payload_s;
                    
                    // ip_payload = null if TCP/UDP
           	    if( (ip->ip_p==IPPROTO_TCP) || (ip->ip_p==IPPROTO_UDP) ){
           	        ip_payload = NULL; 
           	        ip_payload_s = 0;
           	    }
           	    else {
           	        ip_payload = (u_int8_t*) (packet + SIZE_ETHERNET + size_ip);
           	        ip_payload_s = ntohs(ip->ip_len) - (size_ip);
           	    }
                    
                    libnet_build_ipv4(len, tos, id, frag, ttl, prot, sum, src, dst, ip_payload, ip_payload_s, l, 0);
                    
                    // new src ETH = ghost's ETH
                    // new dst ETH = packet's src ETH 
                    if ( libnet_build_ethernet ((u_int8_t*) (ethernet->ether_shost), (u_int8_t*) (ghost_eth), ETHERTYPE_IP, NULL, 0, l, 0) == -1 ){
                        fprintf(stderr, "\nError building Ethernet header: %s\n",libnet_geterror(l));
                        libnet_destroy(l);
                        exit(EXIT_FAILURE);
                    }				
    
                    // call the send function on packet
                    bytes_written = libnet_write(l);
                    if ( bytes_written != -1 )
                        printf("\n%d bytes written.", bytes_written);
                    else
                        fprintf(stderr, "\nError writing packet: %s\n", libnet_geterror(l));
    
                    printf("\n----------------------");
                }                
            }
            
            libnet_destroy(l);
            break;
        
        case 0x0608:
            // ARP packet
            arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
            
            if ( ntohs(arp->arp_oper)==1 ){
            
                libnet_t* l; /* the libnet context */
                u_int32_t src_ip_addr;
                int bytes_written;
                char errbuf[LIBNET_ERRBUF_SIZE];
                l = libnet_init(LIBNET_LINK, dev, errbuf);
                if ( l == NULL ) {
                    fprintf(stderr, "\nlibnet_init() failed: %s\n", errbuf);
                    exit(EXIT_FAILURE);
                }
                u_int32_t ghost_ip_addr = libnet_name2addr4(l, ghost_ip, LIBNET_DONT_RESOLVE);
                u_int32_t relayer_ip_addr = libnet_name2addr4(l, relayer_ip, LIBNET_DONT_RESOLVE);
                
                // if its looking for ghost ip, send ghost's ETH address
                if( memcmp( arp->arp_tpa, (char*) &ghost_ip_addr, 4 )==0 ){
                    printf("\nARP packet looking for Ghost's MAC address!!");
                    
                    // build ARP packet
                    // arp reply with src eth = ghost eth, src ip = ghost ip, dst eth = attacker's eth, dst ip = attacker's ip
                    src_ip_addr = ghost_ip_addr;
                    
                    if ( libnet_autobuild_arp (ARPOP_REPLY,\
                                            (u_int8_t*) ghost_eth,\
                                            (u_int8_t*)(&src_ip_addr),\
                                            (u_int8_t*) arp->arp_sha,\
                                            (u_int8_t*)(arp->arp_spa), l) == -1)
                    {
                        fprintf(stderr, "\nError building ARP header: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(EXIT_FAILURE);
                    }
                    
                    // src addr = ghost eth, dst addr = attacker's eth, ethernet type = ETHERTYPE_ARP
                    if ( libnet_build_ethernet ((u_int8_t*) (ethernet->ether_shost), (u_int8_t*) (ghost_eth), ETHERTYPE_ARP, NULL, 0, l, 0) == -1 )
                    {
                        fprintf(stderr, "\nError building Ethernet header: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(EXIT_FAILURE);
                    }
                    
                    bytes_written = libnet_write(l);
                    if ( bytes_written != -1 )
                        printf("\n%d bytes written.", bytes_written);
                    else
                        fprintf(stderr, "\nError writing packet: %s\n", libnet_geterror(l));
    
                    printf("\n----------------------");                
                }                
                
                if ( memcmp( arp->arp_tpa, (u_char*) &relayer_ip_addr, 4 )==0 ) {
                    printf("\nARP packet looking for the Relayers MAC address!!");
                    // build ARP packet, with ans = relayers eth
                    // arp reply with src eth = relayer eth, src ip = relayer ip, dst eth = attacker's eth, dst ip = attacker's ip
                    src_ip_addr = relayer_ip_addr;
                                                    
                    if ( libnet_autobuild_arp (ARPOP_REPLY,\
                                            (u_int8_t*) relayer_eth,\
                                            (u_int8_t*)(&src_ip_addr),\
                                            (u_int8_t*) arp->arp_sha,\
                                            (u_int8_t*)(arp->arp_spa), l) == -1)
                    {
                        fprintf(stderr, "\nError building ARP header: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(EXIT_FAILURE);
                    }
    
                    // src addr = relayer eth, dst addr = attacker's eth, ethernet type = ETHERTYPE_ARP
                    if ( libnet_build_ethernet ((u_int8_t*) (ethernet->ether_shost), (u_int8_t*) (relayer_eth), ETHERTYPE_ARP, NULL, 0, l, 0) == -1 )
                    {
                        fprintf(stderr, "\nError building Ethernet header: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(EXIT_FAILURE);
                    }
                    
                    bytes_written = libnet_write(l);
                    if ( bytes_written != -1 )
                        printf("\n%d bytes written.", bytes_written);
                    else
                        fprintf(stderr, "\nError writing packet: %s\n", libnet_geterror(l));
                }
                libnet_destroy(l);
            break;        
        
        default:
            printf("\nunknown packet");
        }
        
    }
    
}
    
    
    
int main(int argc, const char *argv[]){
        
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                        /* packet capture handle */
        
    bpf_u_int32 mask;                    /* subnet mask */
    bpf_u_int32 net;                    /* ip */
    u_int8_t* victim_mac_addr; 
    u_int8_t* relayer_mac_addr;
    u_char* victim_mac_addr_str;
    u_char* relayer_mac_addr_str;
    int length;
        
    if(argc<9){
        printf("incorrect syntax\n");
        exit(EXIT_FAILURE);
    }
    else {
        // set default value for interface
        dev = NULL;
        int i = 1;
        while(i<argc){
                
            if (strcmp("--victim-ip", argv[i])==0) { 
                ghost_ip = (char*) argv[i+1]; 
            }
            if (strcmp("--relayer-ip", argv[i])==0){ 
                relayer_ip = (char*) argv[i+1];
            }
            if (strcmp("--victim-ethernet", argv[i])==0) {
                victim_mac_addr_str = (u_char*) argv[i+1];
            }
            if (strcmp("--relayer-ethernet", argv[i])==0) {
                relayer_mac_addr_str = (u_char*) argv[i+1];
            }
            if (strcmp("--interface", argv[i])==0){
                dev = (char*) argv[i+1];
            }
            i++;
        }                  
    }
        
    printf("\nVictim: %s", ghost_ip);
    printf("\nRelayer: %s", relayer_ip);
      
    if (dev == NULL) dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "\nCouldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
        
    /* convert into a u_char array for ethernet address*/
    victim_mac_addr = libnet_hex_aton((int8_t*)victim_mac_addr_str, &length);
    if(victim_mac_addr != NULL){
        printf("\nGhost Address read: ");
        int i;
        for ( i=0; i < length; i++) {
            ghost_eth[i] = victim_mac_addr[i];
            printf("%02X", victim_mac_addr[i]);
            if ( i < length-1 )
                printf(":");
        }
        printf("\n");
    }
        
    relayer_mac_addr = libnet_hex_aton((int8_t*)relayer_mac_addr_str, &length);
    if(relayer_mac_addr != NULL){
        printf("\nRelayer Address read: ");
        int i;
        for ( i=0; i < length; i++) {
            relayer_eth[i] = relayer_mac_addr[i];
            printf("%02X", relayer_mac_addr[i]);
            if ( i < length-1 )
                printf(":");
            }
            printf("\n");
        }
        
        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "\nCouldn't get netmask for device %s: %s\n",
                dev, errbuf);
            net = 0;
            mask = 0;
        }
        printf("\nDevice: %s\n", dev);
        
        /*Open the device for capture*/
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "\nCouldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    
        /*the callback function*/
        pcap_loop(handle, -1, got_packet, NULL);
    
        /* cleanup */
        pcap_close(handle);
                
        return(0);
}
