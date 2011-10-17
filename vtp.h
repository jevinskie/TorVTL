#ifndef __VTP_H
#define __VTP_H

#include "vtp_util.h"


#define POLL_TIMEOUT 0
#define MAX_VTP_CONS 100



struct VTP_CON {
  unsigned long rem_seq_num;
  unsigned long dest_ip;
  unsigned long src_ip;
  unsigned short src_port;
  unsigned short dest_port;
  RawEthernetPacket ack_template;
  unsigned short ip_id;
  unsigned long tcp_timestamp;
  bool in_use;
  int next;
  int prev;
};

#define FOREACH_VTP_CON(iter, cons) for (iter = g_first_vtp; iter != -1; iter = cons[iter].next) 




/* Sending Layers Need to implement these */
int vtp_init();
int vtp_send(RawEthernetPacket * p, struct in_addr serv_addr);
int vtp_recv(RawEthernetPacket ** p);
int vtp_connect(struct in_addr  serv_addr, unsigned short serv_port);
int vtp_close(struct in_addr  serv_addr);


int register_fd(int fd);
int unregister_fd(int fd);


#endif
