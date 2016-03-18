#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "read_conf.h"



	typedef struct {
		const char *dev_name;
		pcap_if_t *alldevs,*d; 
		pcap_t *handle;

		char *net_n;
		char *mask_n;
	}types;

	struct ip_hdr{
		unsigned char ip_version_and_header_length;
		unsigned char ip_tos;
		unsigned short ip_len;
		unsigned short ip_id;
		unsigned short ip_frag_offset;
		unsigned char ip_ttl;
		unsigned char ip_type;
		unsigned short ip_checksum;
		unsigned int src_addr;
		unsigned int dst_addr;
	};

	

	struct tcp_hdr {
		unsigned short tcp_src_port;
		unsigned short tcp_dest_port;
		unsigned int tcp_seq;
		unsigned int tcp_ack;
		unsigned char reserved:4;
		unsigned char tcp_offset:4;
		unsigned char tcp_flags;

		#define TCP_FIN  0x01
		#define TCP_SYN  0x02
		#define TCP_RST  0x04
		#define TCP_PUSH 0x08
		#define TCP_ACK  0x10
		#define TCP_URG  0x20

		unsigned short tcp_window;
		unsigned short tcp_checksum;
		unsigned short tcp_urgent;
	};

