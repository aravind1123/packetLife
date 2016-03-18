
#include "packet.h"
	

	using namespace std;

 class radar 

	{

	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	struct in_addr addr;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *filter_exp;
	struct bpf_program fp;
	struct pcap_pkthdr header;
	const u_char *packet;

	
	types basic;

	public:
		radar();
		int radar_engine();
		static void caught_packet(u_char*,const struct pcap_pkthdr*,const u_char*);
		static void decode_ethernet(const u_char*);
		static void decode_ip(const u_char*);
		static void decode_tcp(const u_char*);
	

	};

	radar::radar()
	{
	
	data data_out;
	data_out=read_info();
	basic.dev_name=data_out.interface.c_str();
	filter_exp=new char[20];
	filter_exp=data_out.exp.c_str();

	}	

	int radar::radar_engine()
	{
	const char *name=basic.dev_name;
	
	if(pcap_findalldevs(&(basic.alldevs),errbuf)==-1){
		cout<<"Error in pcap:"<<errbuf<<endl;
		exit(1);
	}	
		basic.dev_name=name;
	cout<<"\n\tBefore callling name:"<<name;
	printf("\nThe list all devs:\n");
	cout<<"\n\tBefore callling name:"<<basic.dev_name;


	for(basic.d=basic.alldevs;basic.d;basic.d=(basic.d)->next){
		cout<<(basic.d)->name<<"\t";
			if((basic.d)->description)
				cout<<(basic.d)->description<<endl;
			else
				cout<<"\n";

	}		
	
	basic.dev_name=name;
	if( pcap_lookupnet(basic.dev_name, &net,&mask,errbuf)==-1 ){	
		cout<<"Cant get net and mask\n";
		net=0;
		mask=0;
	}else{
		printf("\n\nThe details of %s:\n",basic.dev_name);
		addr.s_addr=net;	
		basic.net_n=inet_ntoa(addr);
		printf("The ip address is %s\n",basic.net_n);

		addr.s_addr=mask;
		basic.mask_n=inet_ntoa(addr);
		printf("The net mask is:%s\n",basic.mask_n);
	}

	basic.handle=pcap_open_live(basic.dev_name,BUFSIZ,1,1000,errbuf);

	if(basic.handle==NULL){
		printf("Error cant open:%s\n",basic.dev_name);
		return 1;
	}

	if(pcap_compile(basic.handle,&fp,filter_exp,0,net)==-1){
		printf("Couldn parse filter %s: %s\n",filter_exp,pcap_geterr(basic.handle));
		return (2);
	}

	if(pcap_setfilter(basic.handle,&fp)==-1){
		printf("Couldn't install filter %s: %s\n",filter_exp,pcap_geterr(basic.handle));
		return (2);
	}


	pcap_loop(basic.handle,20,caught_packet,NULL);


	pcap_close(basic.handle);

	
	}

	void radar::caught_packet(u_char *user_args,const struct pcap_pkthdr *cap_header,const u_char *packet)
	{
		printf("\n-----------------------BEG---------------------------------\n");
		printf("\n===Got a %d byte packet===\n",cap_header->len);
		decode_ethernet(packet);
		decode_ip(packet+ETH_HLEN);
		decode_tcp(packet+ETH_HLEN+sizeof(struct ip_hdr));
		printf("\n-----------------------END--------------------------------\n");

	}

	void radar::decode_ethernet(const u_char *packet)
	{

		int i;
		const struct ethhdr *ethernet_header;
		ethernet_header=(const struct ethhdr*)packet;
		printf("[[ Layer 2 :: Ethernet Header ]]\n");
		printf("Destination MAC:%02x",ethernet_header->h_dest[0]);
		for(i=1; i<ETH_ALEN ; i++)
			printf(":%02x",ethernet_header->h_dest[i]);

			printf("\nSource MAC:%02x",ethernet_header->h_source[0]);
			for(i=1;i<ETH_ALEN;i++)
				printf(":%02x",ethernet_header->h_source[i]);
				printf("\n");

	}

	void radar::decode_ip(const u_char *packet)
	{

		const struct ip_hdr *ip_header;
		struct in_addr src,dst;
		ip_header=(const struct ip_hdr*)packet;


		src.s_addr=ip_header->src_addr;
		dst.s_addr=ip_header->dst_addr;

		printf("[[ Layer 3:: Ip header ]]\n");
		printf("Source:%s\n",inet_ntoa(src));
		printf("Destination:%s\n",inet_ntoa(dst));

	}

	void radar::decode_tcp(const u_char *packet)
	{

		const struct tcp_hdr *tcp_header;
		u_int header_size;

		tcp_header=(const struct tcp_hdr*)packet;
		header_size=4*tcp_header->tcp_offset;

		printf("\n[[ Layer 4 :: Tcp header ]] \n");
		printf("Source port: %hu \n",ntohs(tcp_header->tcp_src_port));
		printf("Destination port: %hu \n",ntohs(tcp_header->tcp_dest_port));
		printf("Seq #: %u \n",ntohl(tcp_header->tcp_seq));
		printf("Ack #: %u \n",ntohl(tcp_header->tcp_ack));
		printf("\nHeader size: %u \n===Flags===\n",header_size);

		if(tcp_header->tcp_flags & TCP_FIN )
			printf("FIN\t");
		if(tcp_header->tcp_flags & TCP_SYN )
			printf("SYN\t");
		if(tcp_header->tcp_flags & TCP_RST )
			printf("RST\t");
		if(tcp_header->tcp_flags & TCP_PUSH )
			printf("PUSH\t");
		if(tcp_header->tcp_flags & TCP_ACK )
			printf("ACK\t");
		if(tcp_header->tcp_flags & TCP_URG )
			printf("URG\t");
	}


	int main()
	{
	
	radar r_obj;
	r_obj.radar_engine();
	return 0;
	}
