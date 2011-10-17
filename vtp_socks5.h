#ifndef __VTP_SOCKS5_H
#define __VTP_SOCKS5_H 1


#include "raw_ethernet_packet.h"
#include "debug.h"
#include "vtp.h"

#include <sys/socket.h>
#include <sys/types.h>

#define SOCKS_PORT 9050
#define MAX_CONS 10000
#define MAX_PKTS 750


#define VTP_MAC_ADDR {0x00, 0x50, 0x56, 0x00, 0x99, 0x99}

#define SOCKS_VERSION 0x05

#define SOCKS_RSVD 0x00

#define SOCKS_AUTH_NONE 0x00
#define SOCKS_AUTH_GSSAPI 0x01
#define SOCKS_AUTH_USER_PASS 0x02
#define SOCKS_AUTH_ERROR 0xff

#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_CMD_BIND 0x02
#define SOCKS_CMD_UDP_ASSOC 0x03

#define SOCKS_ADDR_IPV4 0x01
#define SOCKS_ADDR_FQDN 0x02
#define SOCKS_ADDR_IPV6 0x03

#define SOCKS_REPLY_SUCCESS 0x00
#define SOCKS_REPLY_FAILURE 0x01
#define SOCKS_REPLY_NOT_ALLOWED 0x02
#define SOCKS_REPLY_NET_UNREACHABLE 0x03
#define SOCKS_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS_REPLY_REFUSED 0x05
#define SOCKS_REPLY_TTL_EXP 0x06
#define SOCKS_REPLY_ILL_CMD 0x07
#define SOCKS_REPLY_ILL_ADDR 0x08

#define CLOSED 0
#define FIN_WAIT 1
#define ESTABLISHED 2



struct socks_cons {
  unsigned long dest_addr;
  unsigned long src_addr;
  unsigned short dest_port;
  unsigned short src_port;

  RawEthernetPacket pkt_template;

  unsigned int tcp_state;

  unsigned long seq_num;
  unsigned long ack_num;
  unsigned short ip_id;
  unsigned long local_timestamp;
  unsigned long remote_timestamp;
  unsigned short mss;

  int rem_socket;
  int local_socket;

  int in_use;

  int prev;
  int next;
};



int socks_connect(struct in_addr socks_ip, unsigned short socks_port);

int proxy_connect(unsigned long proxy_ip, unsigned short proxy_port);
int handle_socks_reply(int socks_fd);

int handle_arp_request(RawEthernetPacket * pkt);
int handle_syn_pkt(RawEthernetPacket * pkt);
int handle_data_pkt(RawEthernetPacket * pkt);
int handle_fin_pkt(RawEthernetPacket * pkt);
int handle_proxy_close(int index);

int handle_con_error(int index);



int do_syn_ack(RawEthernetPacket * pkt, int index);
int do_last_ack(RawEthernetPacket * pkt, int index);
int do_fin_ack(RawEthernetPacket * pkt, int index);

int make_fin_pkt(int con_index);
int make_rst_pkt(int con_index);
int make_data_pkt(int con_index, char * data, int data_len);



/* DNS FUNCTIONS
   Implemented int vtp_dns.cc
*/


#define MAX_QUERIES 100

struct dns_answer {
  char * data;
  int len;
  int pkt_offset;
  int num_answers;

};

struct dns_queries {
 
  int socket;

  char * name;
  int name_len;
  unsigned char opcode;
  unsigned long ttl;
  struct dns_answer answer;
  unsigned long ip;

  RawEthernetPacket pkt;

  int in_use;
  int next;
  int prev;
};



int make_dns_reply_pkt(RawEthernetPacket * pkt, struct dns_answer answers);
int socks4_connect(struct in_addr socks_ip, unsigned short socks_port);


#define FOREACH_QUERY(iter, queries) for (iter = g_first_query; iter != -1; iter = g_queries[iter].next)

int add_query(char * name, int name_len, unsigned char opcode, int socket, RawEthernetPacket * pkt);
int find_query(int socket);
int delete_query(int index);


int handle_dns_request(RawEthernetPacket * pkt, struct in_addr dns_addr, unsigned short dns_port);
int handle_dns_reply(int query_index);




/**/



#define FOREACH_CON(iter,cons)  for (iter = g_first_con; iter != -1; iter = cons[iter].next)

int add_con(unsigned long dest_addr, unsigned short dest_port, unsigned long src_addr, unsigned short src_port, int rem_socket);
int delete_con(unsigned long dest_addr, unsigned short dest_port, unsigned long src_addr, unsigned short src_port);
int delete_con(int index);
int find_con(unsigned long dest_addr, unsigned short dest_port, unsigned long src_addr, unsigned short src_port);
int find_con(int rem_socket, int local_socket);

#define FOREACH_PKT(iter, pkts) for (iter = g_first_pkt; iter != -1; iter = pkts[iter].next)

int add_pkt(RawEthernetPacket * pkt);
RawEthernetPacket *  get_pkt();


#endif
