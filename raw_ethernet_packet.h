#ifndef _raw_ethernet_packet
#define _raw_ethernet_packet
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "config.h"
extern "C" {
#define OPENSSL_NO_KRB5
#include <openssl/ssl.h>
}

class Packet;

using namespace std;

#define SERIALIZATION_CLOSED -1
#define SERIALIZATION_ERROR -2

struct RawEthernetPacket {
  
  char pkt[2 + 4 + ETHERNET_PACKET_LEN];
  char * type;
  size_t * size;
  char * data;

  size_t get_size() const;
  void set_size(size_t new_size);
  
  char * get_type();
  void set_type(const char * new_type);

  char * get_data();
  
  int length() const { return sizeof(pkt);}


  RawEthernetPacket();
  RawEthernetPacket(const RawEthernetPacket &rhs);
  RawEthernetPacket(const char *data, const size_t size);
  const RawEthernetPacket & operator= (const RawEthernetPacket &rhs);
  virtual ~RawEthernetPacket();

  int SerializeToBuf(char ** buf) const;
  void UnserializeFromBuf(char * buf);

  int Serialize(const int fd, SSL *ssl) const;
  int Unserialize(const int fd, SSL *ssl);

  int UdpSerialize(const int fd,SSL *ssl,struct sockaddr *serveraddr) const;
  int UdpUnserialize(const int fd, SSL *ssl);
  
  int VtpSerialize(const int fd, SSL *ssl, struct in_addr * serveraddr) const;
  int VtpUnserialize(const int fd, SSL *ssl, struct in_addr * serveraddr);

  void Print(unsigned size=ETHERNET_PACKET_LEN, FILE *out=stdout) const;
  ostream & Print(ostream &os) const;
};

inline ostream & operator<<(ostream &os, const RawEthernetPacket &p) {
  return p.Print(os);
}
#endif
