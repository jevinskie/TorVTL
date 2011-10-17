#include "vtp_util.h"



void dbg_print_pkt_info(RawEthernetPacket * pkt) {
  unsigned long src_addr;
  unsigned long dest_addr;
  unsigned short src_port;
  unsigned short dest_port;
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  string dest_str;
  string src_str;
  struct in_addr dest;
  struct in_addr src;

  unsigned long seq_num = ntohl(*(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4));
  unsigned long ack_num = ntohl(*(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8));

  src_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dest_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 16);
  src_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len);
  dest_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2);

  dest.s_addr = dest_addr;
  dest_str = inet_ntoa(dest);

  src.s_addr = src_addr;
  src_str = inet_ntoa(src);

  JRLDBG("Packet: %s:%d-%s:%d seq: %lu, ack: %lu\n", src_str.c_str(), ntohs(src_port), dest_str.c_str(), ntohs(dest_port), 
	 seq_num, ack_num);
	 

  return;

}

void dbg_print_pkt(RawEthernetPacket * pkt) {
  unsigned int x; 
  int i;
  char pkt_line[128];

  JRLDBG("Packet Dump: (pkt_size=%d) \n", pkt->get_size());

  for (x = 0; x < pkt->get_size();) {
    sprintf(pkt_line, "\t%.4x:  ", x);

    for (i = 0; i < 16; i += 2) {
      if (pkt->get_size() < x + i) {
	break;
      } 

      if (pkt->get_size() == x + i + 1) {
	sprintf(pkt_line, "%s%.2x ", pkt_line, *(unsigned char *)(pkt->data + i + x));
      } else {

	sprintf(pkt_line, "%s%.4x  ", pkt_line, ntohs(*(unsigned short *)(pkt->data + i + x)));
      }
    }

    JRLDBG("%s\n", pkt_line);

    x += 16;
  }
}

void dbg_print_buf(unsigned char * buf, unsigned int len) {
  unsigned int x; 
  int i;
  char pkt_line[128];

  JRLDBG("Buf Dump: (len=%d) \n", len);

  for (x = 0; x < len;) {
    sprintf(pkt_line, "\t%.4x:  ", x);

    for (i = 0; i < 16; i += 2) {
      if (len < x + i) {
	break;
      } 

      if (len == x + i + 1) {
	sprintf(pkt_line, "%s%.2x ", pkt_line, *(unsigned char *)(buf + i + x));
      } else {

	sprintf(pkt_line, "%s%.4x  ", pkt_line, ntohs(*(unsigned short *)(buf + i + x)));
      }
    }

    JRLDBG("%s\n", pkt_line);

    x += 16;
  }

}
/*
  void do_binary_to_ipaddress(unsigned char* ip,IPADDRESS& ipaddress)
  {
  ipaddress.a1=ip[0];
  ipaddress.a2=ip[1];
  ipaddress.a3=ip[2];
  ipaddress.a4=ip[3];
  }
  
  void do_ipaddress_to_string(IPADDRESS ipaddress,char* buffer)
  {
  sprintf(buffer,"%d.%d.%d.%d",ipaddress.a1,ipaddress.a2,ipaddress.a3,ipaddress.a4);
  }
  
  void do_binary_to_string(unsigned char* ip,char* buffer)
  {
  IPADDRESS ipaddress;
  do_binary_to_ipaddress(ip,ipaddress);
  do_ipaddress_to_string(ipaddress,buffer);
  }
*/

int get_mss(RawEthernetPacket * pkt) {
  unsigned long ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  int offset = 0;
  int len = tcp_hdr_len - 20;
  unsigned short mss;

  char * opts = (pkt->data + ETH_HDR_LEN + ip_hdr_len + 20);

  if (len <= 0) {
    return -1;
  }

  while (offset < len) {
    if (*(opts + offset) == 0x00) {
      break;
    } else if (*(opts + offset) == 0x01) {
      offset++;
    } else if (*(opts + offset) == 0x02) {
      mss = (*(unsigned short *)(opts + offset + 2));
      offset += *(opts + offset + 1);
      return (int)ntohs(mss);
    } else {
      offset += *(opts + offset + 1);
    }
  }
  return -1;


}

unsigned long get_tcp_timestamp(char *opts, int len) {
  int offset = 0;
  unsigned long timestamp = 0;
  unsigned long * ts_ptr; 

  while (offset < len) {
    if (*(opts + offset) == 0x00) {
      break;
    } else if (*(opts + offset) == 0x01) {
      offset++;
    } else if (*(opts + offset) == 0x08) {
      offset += 2;
      ts_ptr = (unsigned long *)(opts + offset);
      timestamp = (*ts_ptr);
      break;
    } else if (*(opts + offset) == 0x02) {
      offset += *(opts + offset + 1);
    } else if (*(opts + offset) == 0x03) {
      offset += *(opts + offset + 1);
    } else if (*(opts + offset) == 0x04) {
      // SACK OK
      offset += 2;
    } else if (*(opts + offset) == 0x05) {
      offset += *(opts + offset + 1);
    } else {
      offset += *(opts + offset + 1);
      //JRLDBG("Could not find timestamp\n");
      //break;
    }
  }
  return timestamp;
}

void set_tcp_timestamp(char * ts_opt, unsigned long local_ts, unsigned long remote_ts) {
  int offset = 0;

  //  *(ts_opt + offset) = 0x01;
  //offset++;
  //*(ts_opt + offset) = 0x01;
  //offset++;
  *(ts_opt + offset) = 0x08;
  offset++;
  *(ts_opt + offset) = 0x0a;
  offset++;
  
  *(unsigned long *)(ts_opt + offset) = local_ts;
  offset += sizeof(unsigned long);

  *(unsigned long *)(ts_opt + offset) = remote_ts;
  
  return;
}



int pkt_has_timestamp(RawEthernetPacket * pkt) {
  unsigned short ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  int offset = 0;
  int len = tcp_hdr_len - 20;

  char * opts = (pkt->data + ETH_HDR_LEN + ip_hdr_len + 20);

  if (len <= 0) {
    return -1;
  }
		       
  

  while (offset < len) {
    if (*(opts + offset) == 0x00) {
      break;
    } else if (*(opts + offset) == 0x01) {
      offset++;
    } else if (*(opts + offset) == 0x08) {
      return offset;
    } else {
      offset += *(opts + offset + 1);
      //JRLDBG("Could not find timestamp\n");
      //break;
    }
  }
  return -1;

}

void swap_eth_addrs(RawEthernetPacket * pkt) {
  char mac_addr[6];
 
  memcpy(mac_addr, pkt->data, 6);

  // copy the source mac to dest mac
  memcpy(pkt->data, pkt->data + 6, 6);
  
  // set the dest mac to our taken address
  memcpy(pkt->data + 6, mac_addr, 6);
}

void swap_ip_addrs(RawEthernetPacket * pkt) {
  unsigned long src_ip;
  unsigned long dst_ip;

  src_ip = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dst_ip = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 16);

  *(unsigned long *)(pkt->data + ETH_HDR_LEN + 12) = dst_ip;
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + 16) = src_ip;
}

void swap_ports(RawEthernetPacket * pkt) {
  unsigned short src_port;
  unsigned short dst_port;
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);

  src_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len);
  dst_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2);

  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len) = dst_port;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2) = src_port;  
}


int is_syn_pkt(RawEthernetPacket * pkt) {
  //unsigned char ip_hdr_len = (*(pkt->data + ETH_HDR_LEN) & 0x0f) << 2;
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);

  if ((*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 13) & 0x02) == 0x02) 
    return 1;
  return 0;
}

int is_fin_pkt(RawEthernetPacket * pkt) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);

  if ((*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 13) & 0x01) == 0x01) 
    return 1;
  return 0;
}


 int is_ack_pkt(RawEthernetPacket * pkt) {
   unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);

   if ((*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 13) & 0x10) == 0x10)
     return 1;
   return 0;
 }

int is_dns_pkt(RawEthernetPacket * pkt) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);

  // Right now we just look at the destination port address
  // there is probably a better way though....
  if (*(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2) == htons(DNS_PORT)) {
    return 1;
  }
  return 0;
}

int is_tcp_pkt(RawEthernetPacket * pkt) {
  //int eth_hdr_len = 14;
  if ((*(pkt->data + 12) == 0x08) && (*(pkt->data + 13) == 0x00)) {
    // IP packet
    if (*(pkt->data + ETH_HDR_LEN + 9) == 0x6) {
      // TCP packet
      return 1;
    }
  }
  return 0;
}

int is_udp_pkt(RawEthernetPacket * pkt) {
  if ((*(pkt->data + 12) == 0x08) && (*(pkt->data + 13) == 0x00)) {
    if (*(pkt->data + ETH_HDR_LEN + 9) == 17) {
      return 1;
    }
  }
  return 0;
}

int is_arp_pkt(RawEthernetPacket * pkt) {
  if ((*(pkt->data + 12) == 0x08) && (*(pkt->data + 13) == 0x06)) {
    return 1;
  } 
  return 0;
}

int is_ip_pkt(RawEthernetPacket * pkt) {
  if ((*(pkt->data + 12) == 0x08) && (*(pkt->data + 13) == 0x00)) {
    return 1;
  }
  return 0;
}




char* return_ip_protocol(unsigned char protocol)
{
  if(protocol==0x1)
    {
      return "ICMP";
    }
  else if(protocol==0x6)
    {
      return "TCP";
    }
  else if(protocol==17)
    {
      return "UDP";
    }
  else if(protocol==121)
    {
      return "SMP";
    }
  else
    {
      return "Unknown";
    }

  return 0;
}


unsigned short get_tcp_checksum(RawEthernetPacket * pkt, unsigned short tcp_len) {
  unsigned short buf[1600];
  unsigned long * src_addr;
  unsigned long * dest_addr;
  unsigned short len;
  unsigned short proto;

  len = tcp_len;
  len += (len % 2) ? 1 : 0;

  
  src_addr = (unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dest_addr = (unsigned long *)(pkt->data + ETH_HDR_LEN + 16);
  proto = *(pkt->data + ETH_HDR_LEN + 9);

  *((unsigned long *)(buf)) = *src_addr;
  *((unsigned long *)(buf + 2)) = *dest_addr;
  
  buf[4]=htons(proto);
  buf[5]=htons(tcp_len);
  // return 0;

  memcpy(buf + 6, (pkt->data + ETH_HDR_LEN + IP_HDR_LEN(pkt->data)), tcp_len);
  if (tcp_len % 2) {
    JRLDBG("Odd tcp_len: %hu\n", tcp_len);
    *(((char*)buf) + 2 * 6 + tcp_len) = 0;
  }

  return htons(~(OnesComplementSum(buf, len/2+6)));
}

unsigned short get_udp_checksum(RawEthernetPacket * pkt, unsigned short udp_len) {
  unsigned short buf[1600];
  unsigned long * src_addr;
  unsigned long * dest_addr;
  unsigned short len;
  unsigned short proto;

  len = udp_len;
  len += (len % 2) ? 1 : 0;

  
  src_addr = (unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dest_addr = (unsigned long *)(pkt->data + ETH_HDR_LEN + 16);
  proto = *(pkt->data + ETH_HDR_LEN + 9);

  *((unsigned long *)(buf)) = *src_addr;
  *((unsigned long *)(buf + 2)) = *dest_addr;
  
  buf[4]=htons(proto);
  buf[5]=htons(udp_len);
  // return 0;

  memcpy(buf + 6, (pkt->data + ETH_HDR_LEN + IP_HDR_LEN(pkt->data)), udp_len);
  if (udp_len % 2) {
    JRLDBG("Odd tcp_len: %hu\n", udp_len);
    *(((char*)buf) + 2 * 6 + udp_len) = 0;
  }

  return htons(~(OnesComplementSum(buf, len/2+6)));
}

unsigned short get_ip_checksum(RawEthernetPacket * pkt) {
  unsigned short buf[10];
  memset(buf, 0, 10);
  memcpy((char*)buf, pkt->data + ETH_HDR_LEN, 20);
  return htons(~(OnesComplementSum(buf, 10)));

}

unsigned short OnesComplementSum(unsigned short *buf, int len) {
  unsigned long sum, sum2, sum3;
  unsigned short realsum;
  int i;

  sum=0;
  for (i=0;i<len;i++) {
    sum+=ntohs(buf[i]);
  }
  // assume there is no carry out, so now...

  sum2 = (sum&0x0000ffff) + ((sum&0xffff0000)>>16);

  sum3 = (sum2&0x0000ffff) +((sum2&0xffff0000)>>16);

  realsum=sum3;

  return realsum;
}  


int vsend(int fd, char * buf, int length) {
  int sent = 0;;
  int amt_left = length;
  int total_sent = 0;

  //  JRLDBG("UDT sendall: size=%d\n", size);
  while (amt_left > 0) {
    sent = send(fd, buf + total_sent, amt_left, 0);
    if (sent == -1) {
      JRLDBG("Error could not send packet in vsend\n");
      // error
      return -1;
    }
    total_sent += sent;
    amt_left -= sent;
  }

  return 0;
}

int vrecv(int fd, char * buf, int length) {
  int recvd = 0;
  int amt_left = length;
  int total_recvd = 0;

  //  JRLDBG("UDT recvall: size=%d\n", size);
  while (amt_left > 0) {
//    recvd = recv(fd, buf + total_recvd, amt_left, 0);
    recvd = read(fd, buf + total_recvd, amt_left);
    JRLDBG("Received %d bytes\n", recvd);

    if (recvd == 0) {
      JRLDBG("Connection has unexpectedly closed (fd=%d)\n", fd);
      return -1;
    } else if (recvd == -1) {
      if (errno == EWOULDBLOCK) {
	JRLDBG("Tried to read an empty socket\n");
	return -2;
      }
      
      JRLDBG("Error could not recv packet in vrecv\n");
      return -1;
    }
    
    total_recvd += recvd;
    amt_left -= recvd;
  }

  return 0;

}
