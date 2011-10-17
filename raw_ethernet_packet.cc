#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "raw_ethernet_packet.h"
#include "util.h"
#include "debug.h"




RawEthernetPacket::RawEthernetPacket(){
  type = pkt;
  size = (size_t*)(pkt + (sizeof(char) * 2));
  data = pkt + (sizeof(char) * 2) + sizeof(size_t);
}


RawEthernetPacket::RawEthernetPacket(const RawEthernetPacket &rhs) 
{
  this->type = pkt;
  this->size = (size_t*)(pkt + (sizeof(char) * 2));
  this->data = pkt + (sizeof(char) * 2) + sizeof(size_t);
  //  *(this->size)=*(rhs.size);
  this->set_size(rhs.get_size());
  memcpy(this->type, rhs.type, sizeof(char) * 2);
  memcpy(this->data,rhs.data,*(this->size));
}

RawEthernetPacket::RawEthernetPacket(const char *data, const size_t size)
{
  this->type = pkt;
  this->size = (size_t*)(pkt + (sizeof(char) * 2));
  this->data = pkt + (sizeof(char) * 2) + sizeof(size_t);
  this->set_size(size);
  memcpy(this->data,data,size);
}
  

const RawEthernetPacket & RawEthernetPacket::operator= (const RawEthernetPacket &rhs)
{
  this->type = pkt;
  this->size = (size_t*)(pkt + (sizeof(char) * 2));
  this->data = pkt + (sizeof(char) * 2) + sizeof(size_t);
  this->set_size(rhs.get_size());
  memcpy(data, rhs.data, *(size_t*)(this->size));

  return *this;
}


RawEthernetPacket::~RawEthernetPacket() 
{} 


size_t RawEthernetPacket::get_size() const {
  size_t t_size;
  memcpy(&t_size, pkt+2, sizeof(size_t));
  return t_size;
}

void RawEthernetPacket::set_size(size_t new_size) {
  memcpy(this->pkt + (sizeof(char) * 2), &new_size, sizeof(size_t));
}

char * RawEthernetPacket::get_type() {
  return pkt;
}

void RawEthernetPacket::set_type (const char * new_type)  {
  memcpy(this->pkt, new_type, sizeof(char) * 2);
}

char * RawEthernetPacket::get_data() {
  return this->pkt + (sizeof(char) * 2) + sizeof(size_t);
}



int RawEthernetPacket::Serialize(const int fd, SSL * ssl) const {
  int length = (sizeof(char)*2) + this->get_size() + sizeof(size_t); 
  int ret = 0;

  ret = writeall(fd, pkt, length, 0, 1, ssl);
  if (ret != (int)length) {
    return -1;
  }
  return ret;
}


int RawEthernetPacket::Unserialize(const int fd, SSL * ssl) {
  int ret;
  
  ret = readall(fd, pkt, sizeof(char) * 2 + sizeof(size_t), 0, 1, ssl);
  if (ret == 0) {
    JRLDBG("TCP socket closed\n");
    return 0;
  } else if (ret != (sizeof(char) * 2 + sizeof(size_t))) {
    JRLDBG("Error unserializing packet header from tcp socket\n");
    return -1;
  }

  JRLDBG("Receiving TCP data. size=%d, offset=%d\n", this->get_size(), *(pkt + 2));

  ret = readall(fd, data, this->get_size(), 0, 1, ssl);
  if (ret == 0) {
    JRLDBG("TCP Socket closed\n");
    return 0;
  } else if (ret != (int)this->get_size()) {
    JRLDBG("Error unserializing packet from tcp socket\n");
    return -1;
  }

  return ret;
}

/* SRC_ROUTING: We need to add a long * to the arguments that we will
   write the client address (int form) into */
int RawEthernetPacket::UdpUnserialize(const int fd, SSL * ssl) {
  struct sockaddr_in clientaddr; /*the client  address strcuture */
  int clientlen = sizeof(clientaddr);

  int length = 2 + sizeof(size_t)+ ETHERNET_PACKET_LEN;
  int rcvd = 0;
  
  rcvd = recvfrom(fd, pkt,length,0,(struct sockaddr *)&clientaddr,(socklen_t *)&clientlen);
  
  return rcvd;
}

int RawEthernetPacket::UdpSerialize(const int fd, SSL * ssl, struct sockaddr * serveraddr) const {
  int len = sizeof(*serveraddr); 
  int length;

  int sent = 0;
  length = sizeof(char)* 2 + this->get_size() + sizeof(size_t);

  sent = sendto(fd,pkt,length,0,serveraddr,len);

  return sent;
}

// JRL VTP
int RawEthernetPacket::VtpUnserialize(const int fd, SSL * ssl, struct in_addr * serveraddr) {
  int ret;
  this->set_size((unsigned int)(-1));

  ret = readall(fd, pkt, sizeof(char) * 2, 0, 1, ssl);
  if (ret == 0) {
    JRLDBG("VTP connection has Closed\n");
    return 0;
  } else if (ret != (int)sizeof(char) * 2) {
    JRLDBG("Could not read type from VTP packet\n");
    return -1;
  }

  ret = readall(fd, (char *)serveraddr, sizeof(struct in_addr), 0, 1, ssl);
  if (ret == 0) {
    JRLDBG("VTP connection has closed\n");
    return 0;
  } else if (ret != (int)sizeof(struct in_addr))  {
    JRLDBG("Could not read VTP address info\n");
    return -1;
  }

  ret = readall(fd, (char *)size, sizeof(size_t), 0, 1, ssl);
  if (ret == 0) {
    JRLDBG("VTP connection has closed\n");
    return 0;
  } else if (ret != sizeof(size_t)) {
    JRLDBG("Could not read VTP size\n");
    return -1;
  }
  
  ret = readall(fd, data, this->get_size(), 0, 1, ssl);
  if (ret == 0) {
    JRLDBG("VTP connection has closed\n");
    return 0;
  } else if (ret != (int)this->get_size()) {
    JRLDBG("Could not read VTP packet data\n");
    return -1;
  }

  return ret;
}

int RawEthernetPacket::VtpSerialize(const int fd, SSL * ssl, struct in_addr * serveraddr ) const {
  int length;
  int ret;

  ret = writeall(fd, type, sizeof(char) * 2, 0, 1, ssl);  
  if (ret != sizeof(char) * 2) {
    JRLDBG("Error writing type to VTP socket\n");
    return -1;
  }

  ret = writeall(fd, (char *)serveraddr, sizeof(struct in_addr), 0, 1, ssl);
  if (ret != sizeof(struct in_addr)) {
    JRLDBG("Error writing dest addr to VTP socket\n");
    return -1;
  }

  length = this->get_size() + sizeof(size_t);

  ret = writeall(fd, pkt + (sizeof(char) * 2), length, 0, 1, ssl);
  if (ret != (int)length) {
    JRLDBG("ERROR writing packet length and data to VTP socket\n");
    return -1;
  }
  
  return ret;
}

// END JRL

#define MIN(x,y) ((x)<(y) ? (x) : (y))

void RawEthernetPacket::Print(unsigned size, FILE *out) const
{
  fprintf(out,"raw_ethernet_packet: size %-4u first %u bytes: ", *(this->size), MIN(*(this->size),size));
  printhexbuffer(out, data, MIN(*(this->size),size));
  fprintf(out,"\n");
}

ostream & RawEthernetPacket::Print(ostream &os) const
{
  char buf[10240];
  unsigned n;
  unsigned i;

  snprintf(buf,2048,"RawEthernetPacket(size=%u, bytes=",  this->get_size());
  n=strlen(buf);
  for (i=0;i<this->get_size();i++) { 
    bytetohexbyte(data[i],&(buf[n+2*i]));
  }
  buf[n+2*i]=0;
  os<<(char*)buf;
  os<<", text=\"";
  for (i=0;i<this->get_size();i++) {
    char c= data[i];
    if (c>=32 && c<=126) { 
      os<<c;
    } else {
      os<<'.';
    }
  }
  os << "\")";

  return os;
}

