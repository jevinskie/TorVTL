#ifndef __NET_UTIL_H
#define __NET_UTIL_H 1

#include <sys/socket.h>
#include <sys/types.h> 
#include <netinet/in.h>

// 14 (ethernet frame) + 20 bytes
struct HEADERS {
  char ethernetdest[6];
  char ethernetsrc[6];
  unsigned char ethernettype[2]; // indicates layer 3 protocol type
  char ip[20];
};

struct IPHEADER {
  unsigned char junk[9];
  unsigned char protocol[1];
  unsigned char checksum[2];

  union {
    // for getting the address information both in binary format and long format
    unsigned char src[4];
    unsigned long srcl;
  };

  union {
    unsigned char dest[4];
    unsigned long destl;
  };

};

// this is used to extract the IP address from the IP header in conventional form
struct IPADDRESS {
  unsigned char a1,a2,a3,a4;
};


void do_binary_to_string(unsigned char* ip,char* buffer);
void do_ipaddress_to_string(IPADDRESS ipaddress,char* buffer);
void do_binary_to_ipaddress(unsigned char* ip,IPADDRESS& ipaddress);
//char* return_ip_protocol(unsigned char protocol);

int get_local_sock_addr(int sock, struct sockaddr * addr);


#endif
