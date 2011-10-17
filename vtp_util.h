#ifndef __VTP_UTIL_H
#define __VTP_UTIL_H 1


#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "raw_ethernet_packet.h"
#include "debug.h"
#include "vtp.h"
#include "config.h"
#include "socks.h"

#define DNS_PORT 53

#define ETH_HDR_LEN 14
#define IP_HDR_LEN(pkt) ((*(pkt + ETH_HDR_LEN) & 0x0f) << 2)

/*
  struct IPADDRESS {
  unsigned char a1,a2,a3,a4;
  };
  
  
  void do_binary_to_ipaddress(unsigned char* ip,IPADDRESS& ipaddress);
  void do_ipaddress_to_string(IPADDRESS ipaddress,char* buffer);
  void do_binary_to_string(unsigned char* ip,char* buffer);
*/

void dbg_print_pkt_info(RawEthernetPacket * pkt);
void dbg_print_pkt(RawEthernetPacket * pkt);
void dbg_print_buf(unsigned char * buf, unsigned int len);

int is_ip_pkt(RawEthernetPacket * pkt);


/* Packet Field Utility Functions */
int is_tcp_pkt(RawEthernetPacket * pkt);
int is_arp_pkt(RawEthernetPacket * pkt);
int is_udp_pkt(RawEthernetPacket * pkt);

int is_dns_pkt(RawEthernetPacket * pkt);

int is_syn_pkt(RawEthernetPacket * pkt);
int is_ack_pkt(RawEthernetPacket * pkt);
int is_fin_pkt(RawEthernetPacket * pkt);

void swap_eth_addrs(RawEthernetPacket * pkt);
void swap_ip_addrs(RawEthernetPacket * pkt);
void swap_ports(RawEthernetPacket * pkt);

int pkt_has_timestamp(RawEthernetPacket * pkt);

char* return_ip_protocol(unsigned char protocol);
unsigned long get_tcp_timestamp(char *opts, int len);
unsigned short OnesComplementSum(unsigned short *buf, int len);
unsigned short get_tcp_checksum(RawEthernetPacket * pkt, unsigned short tcp_len);
unsigned short get_ip_checksum(RawEthernetPacket * pkt);
unsigned short get_udp_checksum(RawEthernetPacket * pkt, unsigned short udp_len);

int get_mss(RawEthernetPacket * pkt);


void set_tcp_timestamp(char * ts_opt, unsigned long local_ts, unsigned long remote_ts);


int vsend(int fd, char * buf, int length);
int vrecv(int fd, char * buf, int length);


#endif 
