#include "vtp_socks5.h"
#include <fcntl.h>


struct socks_cons g_cons[MAX_CONS];
int g_first_con;
int g_last_con;
int g_num_cons;

RawEthernetPacket g_pkts[MAX_PKTS];
int g_num_pkts;

struct in_addr g_socks_addr;
unsigned short g_socks_port;

struct in_addr g_dns_addr;
unsigned short g_dns_port;


struct dns_queries g_queries[MAX_QUERIES];
int g_first_query;
int g_last_query;
int g_num_queries;


int vtp_init() {
  int i;

  for(i = 0; i < MAX_CONS; i++) {
    g_cons[i].next = -1;
    g_cons[i].prev = -1;
    g_cons[i].in_use = 0;
    g_cons[i].tcp_state = CLOSED;
  }
  
  g_first_con = -1;
  g_last_con = -1;
  g_num_cons = -1;

  g_num_pkts = 0;

  /*** DNS INITIALIZATION ***/
  for(i = 0; i < MAX_QUERIES; i++) {
    g_queries[i].next = -1;
    g_queries[i].prev = -1;
    g_queries[i].in_use = 0;
    
  }
  
  g_first_query = -1;
  g_last_query = -1;
  g_num_queries = -1;

  return 0;
}

int vtp_connect(struct in_addr serv_addr, unsigned short serv_port) {
  if (serv_port == 0) {
    serv_port = SOCKS_PORT;
  }

  JRLDBG("VTP_Connect: addr: %lu, port: %hu\n", (unsigned long)serv_addr.s_addr, serv_port);


  g_socks_addr = serv_addr;
  g_socks_port = serv_port;

  // This needs to be set differently
  g_dns_addr = serv_addr;
  g_dns_port = serv_port;

  return 0;

}

int vtp_send(RawEthernetPacket * pkt, struct in_addr serv_addr) {
  char mac_addr[6] = VTP_MAC_ADDR;



  if (memcmp(pkt->data + 6, mac_addr, 6) == 0) {
    JRLDBG("We received our own packet...dropping\n");
    return 0;
  }

  if (is_arp_pkt(pkt)) {
    handle_arp_request(pkt);
  } else if (is_tcp_pkt(pkt)) {
    if (is_syn_pkt(pkt)) {

      //      dbg_print_pkt(pkt);
      
      if (handle_syn_pkt(pkt) == -1) {
	JRLDBG("Error with SYN packet\n");
	return -1;
      }
    } else if (is_fin_pkt(pkt) ) {
      if (handle_fin_pkt(pkt) == -1) {
	JRLDBG("Error with FIN packet\n");
	return -1;
      }
    } else {
      JRLDBG("Data Pkt:\n");
      // Data Packet
      if (handle_data_pkt(pkt) == -1) {
	JRLDBG("Error with Data packet\n");
	return -1;
      }

    }
  } else if (is_udp_pkt(pkt)) {
    if (is_dns_pkt(pkt)) {
      int dns_ret = handle_dns_request(pkt, g_dns_addr, g_dns_port);

      if (dns_ret == -1) {
	JRLDBG("Error with DNS packet\n");
	return -1;
      } else if (dns_ret == 1) {
	//add_pkt(pkt);
      }
    }
  } else {
    return 0;
  }
  
  return 0;
}

  
int vtp_recv(RawEthernetPacket ** p) {
  int num_pkts;
  int i;
  extern fd_set g_vtp_read_set;

  FOREACH_CON(i, g_cons) {
    if (g_cons[i].tcp_state != ESTABLISHED) {
      continue;
    }

    if (FD_ISSET(g_cons[i].rem_socket, &g_vtp_read_set)) {
      char data[g_cons[i].mss];
      int data_len = 0;
      JRLDBG("Triggered by con %d (fd=%d)\n", i, g_cons[i].rem_socket);
      //      data_len = recv(g_cons[i].rem_socket, data, g_cons[i].mss, 0);
      data_len = read(g_cons[i].rem_socket, data, g_cons[i].mss);
      
      JRLDBG("Received Proxy data (%d bytes) from con (%d)\n", data_len, i);
      if (data_len == -1) {
	if (errno == EWOULDBLOCK) {
	  cerr << "Select tried to tell us an empty socket was ready..." << endl;
	  JRLDBG("Select tried to tell us an empty socket (%d) was ready...\n", g_cons[i].rem_socket);
	  continue;
	}

	JRLDBG("Recv Error\n");
	handle_proxy_close(i);

	return -1;
      } else if (data_len == 0) {
	handle_proxy_close(i);
	continue;
      }
      
      if (g_cons[i].tcp_state != ESTABLISHED) {
	JRLDBG("Error: Connection %d Not established (state=%d)\n", i, g_cons[i].tcp_state);
	continue;
      }
      
      make_data_pkt(i, data, data_len);
      
      //	dbg_print_pkt(&(g_cons[i].pkt_template));
      
      add_pkt(&(g_cons[i].pkt_template));
    }
  }

  FOREACH_QUERY(i, g_queries) {
    if (FD_ISSET(g_queries[i].socket, &g_vtp_read_set)) {
      JRLDBG("Handling DNS REply %d\n", i);
      handle_dns_reply(i);
    }
  }


  num_pkts = g_num_pkts;
  *p = g_pkts;
  
  g_num_pkts = 0;

  return num_pkts;
}

int vtp_close(struct in_addr serv_addr) {

  return 0;
}




int socks_connect(struct in_addr socks_addr, unsigned short socks_port) {
  char conf_buf[3];
  char conf_response[2];
  struct sockaddr_in socks_server;
  int socks_fd;
  
  // connect to the socks server and negotiate the method
  if ((socks_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    JRLDBG("Error creating socket\n");
    return -1;
  }

  

  socks_server.sin_family = AF_INET;
  socks_server.sin_port = htons(socks_port);
  socks_server.sin_addr.s_addr = socks_addr.s_addr;
  memset(&(socks_server.sin_zero), '\0', 8);

  if (connect(socks_fd, (struct sockaddr *)&socks_server, sizeof(struct sockaddr)) == -1) {
    JRLDBG("Error: could not connect to socks proxy\n");
    return -2;
  }

  // socks version
  conf_buf[0] = SOCKS_VERSION;

  // number of auth methods
  conf_buf[1] = 0x01;

  // not-auth required method
  conf_buf[2] = SOCKS_AUTH_NONE;

  JRLDBG("Sending Connect request to socks server\n");
  if (vsend(socks_fd, conf_buf, 3) == -1) {
    // error
    JRLDBG("Error: Could not send configuration request\n");
    return -1;
  }

  JRLDBG("Receiving Configuration response from socks server\n");
  if (vrecv(socks_fd, conf_response, 2) == -1) {
    JRLDBG("Error: Could not receive socks response\n");
    // error
    return -1;
  }
  
  if (conf_response[1] == (char)SOCKS_AUTH_ERROR) {
    JRLDBG("Error: Proxy returned Auth error\n");
    close(socks_fd);
    return -1;
  }
  //fcntl(socks_fd, F_SETFL, O_NONBLOCK);

  return socks_fd;
}


int proxy_connect(unsigned long proxy_ip, unsigned short proxy_port) {
  struct sockaddr_in proxy_addr;
  int proxy_sock;

  JRLDBG("Connecting to given proxy (addr: %lu, port: %hu\n", proxy_ip, proxy_port);
  if ((proxy_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    JRLDBG("Error: Could not create proxy socket\n");
    return -1;
  }
  
  proxy_addr.sin_family = AF_INET;
  proxy_addr.sin_port = proxy_port;
  proxy_addr.sin_addr.s_addr = proxy_ip;
  memset(proxy_addr.sin_zero, 0, 8);
  
  if (connect(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(struct sockaddr)) == -1) {
    JRLDBG("Error: Could not connect to given proxy\n");
    return -1;
  }
  
  return proxy_sock;
}

int handle_proxy_close(int index) {
  extern fd_set g_vtp_all_set;

  JRLDBG("Socks connection %d has closed\n", index);

  FD_CLR(g_cons[index].rem_socket, &g_vtp_all_set); 
  close(g_cons[index].rem_socket);

  make_fin_pkt(index);

  add_pkt(&(g_cons[index].pkt_template));
  
  g_cons[index].tcp_state = FIN_WAIT;

  return 0;
}

int handle_con_error(int index) {
  JRLDBG("SOCKS connection %d died with error\n", index);

  make_rst_pkt(index);

  add_pkt(&(g_cons[index].pkt_template));

  delete_con(index);

  return 0;
}


int handle_socks_reply(int socks_fd) {
  char sock_reply[4];
  char sock_addr[32];
  unsigned long proxy_ip;
  unsigned short proxy_port;
  int proxy_sock;
  
  if (vrecv(socks_fd, sock_reply, 4) == -1) {
    JRLDBG("Could not receive socks reply\n");
    return -1;
  }
  
  if (sock_reply[1] != 0) {
    JRLDBG("Socks reply indicates error: %d\n", sock_reply[1]);
    // SOCKS error
    return -1;
  }
  
  JRLDBG("Socks reply indicates address type: %d\n", sock_reply[3]);

  if (sock_reply[3] == SOCKS_ADDR_IPV4) {
    JRLDBG("Handling ipv4 address type\n");

    if (vrecv(socks_fd, sock_addr, 6) == -1) {
      JRLDBG("Error: Could not receive socks proxy info\n");
      return -1;
    }

    proxy_ip = *(unsigned long *)(sock_addr);
    proxy_port = *(unsigned short *)(sock_addr + 4);
  } else if (sock_reply[3] == SOCKS_ADDR_FQDN) {
    
  } else if (sock_reply[3] == SOCKS_ADDR_IPV6) {
    
  }
  
  JRLDBG("proxyID: %lu, proxy_port: %hu\n", proxy_ip, proxy_port);

  if ((proxy_ip != 0) && (proxy_port != 0)) {
    JRLDBG("Connecting to proxy socket, addr: %lu, port: %hu\n", proxy_ip, proxy_port);
    /* For some reason implementations branch from the RFC with this.
     * They return the addr/port that you are connecting to, instead
     * of the new proxy addr/port....
     
     proxy_sock = proxy_connect(proxy_ip, proxy_port);
     
     */

    // We should check if the ip and port are same, else do proxy_connect
    proxy_sock = socks_fd;

  } else {
    proxy_sock = socks_fd;
  }

  if (proxy_sock == -1) {
    JRLDBG("Error: Could not connect to proxy socket\n");
    return -1;
  }

  return proxy_sock;
}


/* Packet Routines */

int handle_syn_pkt(RawEthernetPacket * pkt) {
  char sock_cmd[10];
  int proxy_sock;
  unsigned long src_addr;
  unsigned long dest_addr;
  unsigned short dest_port;
  unsigned short src_port;
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  int index;
  int socks_fd;
  
  src_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dest_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 16);
  src_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len);
  dest_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2);
  
  JRLDBG("Received a syn Packet\n");
  if (find_con(dest_addr, dest_port, src_addr, src_port) != -1) {
    // huh....
    JRLDBG("Connection already exists\n");
    return -1;
  }
  
  socks_fd = socks_connect(g_socks_addr, g_socks_port);
  


  sock_cmd[0] = SOCKS_VERSION;
  sock_cmd[1] = SOCKS_CMD_CONNECT;
  sock_cmd[2] = SOCKS_RSVD;
  sock_cmd[3] = SOCKS_ADDR_IPV4;
  *(unsigned long *)(sock_cmd + 4) = dest_addr;
  *(unsigned short *)(sock_cmd + 8) = dest_port;
  
  
  if (vsend(socks_fd, sock_cmd, 10) == -1) {
    JRLDBG("Error sending socks command\n");
    return -1;
  } 
  
  if ((proxy_sock = handle_socks_reply(socks_fd)) == -1) {
    //error
    JRLDBG("Error in sock Reply\n");
    return -1;
  }
  
  
  if ((index = add_con(dest_addr, dest_port, src_addr, src_port, proxy_sock)) == -1) {
    JRLDBG("Could not add connection to the list\n");
    return -1;
  }
  
  JRLDBG("Connection added (fd: %d, index: %d)\n", socks_fd, index);

  g_cons[index].mss = get_mss(pkt);
  
  JRLDBG("SynACK to VM\n");
  do_syn_ack(pkt, index);

  g_cons[index].tcp_state = ESTABLISHED;
  
  return 0;
}

int handle_data_pkt(RawEthernetPacket * pkt) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ntohs(*(unsigned short *)(pkt->data + ETH_HDR_LEN + 2));
  unsigned long src_addr;
  unsigned long dest_addr;
  unsigned short dest_port;
  unsigned short src_port;
  int con_index;
  int offset = 0;
  int data_len = ip_pkt_len - (ip_hdr_len + tcp_hdr_len);
  char * data = pkt->data + ETH_HDR_LEN + ip_hdr_len + tcp_hdr_len;


  JRLDBG("Data Packet from VM(%d bytes)\n", data_len);
  dbg_print_pkt_info(pkt);

  src_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dest_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 16);
  src_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len);
  dest_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2);
  
  con_index = find_con(dest_addr, dest_port, src_addr, src_port);
  
  if (con_index == -1) {
    JRLDBG("Could not find connection of packet\n");
    return -1;
  }
  
  if (g_cons[con_index].tcp_state != ESTABLISHED) {
    JRLDBG("Connection is not established\n");
    return 0;
  }

  // Retrieve seq_num
  g_cons[con_index].ack_num = ntohl(*(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4)) + data_len;
  
  // retrieve timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    g_cons[con_index].remote_timestamp = get_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20, tcp_hdr_len - 20);
  }
  

#ifdef DEBUG
  if (is_ack_pkt(pkt)) {
    JRLDBG("ACK from VM: (%lu)\n", *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8));
  }

  //  dbg_print_pkt(pkt);

#endif

  if (data_len == 0) {
    JRLDBG("Returning from zero length data pkt\n");
    return 0;
  }

  JRLDBG("Sending %d bytes to proxy con (fd: %d, index: %d)\n", data_len, g_cons[con_index].rem_socket, con_index);

  if (vsend(g_cons[con_index].rem_socket, data, data_len) == -1) {
    JRLDBG("Error: Could not send data to the proxy (%d)\n", errno);
    handle_con_error(con_index);
    return -1;
  }

  make_data_pkt(con_index, NULL, 0);
  
  JRLDBG("ACKing packet\n");
  dbg_print_pkt_info(&(g_cons[con_index].pkt_template));
  
  add_pkt(&(g_cons[con_index].pkt_template));
  
  return 0;
}

int handle_fin_pkt(RawEthernetPacket * pkt) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned long src_addr;
  unsigned long dest_addr;
  unsigned short dest_port;
  unsigned short src_port;
  int con_index;


  src_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 12);
  dest_addr = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 16);
  src_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len);
  dest_port = *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 2);

  con_index = find_con(dest_addr, dest_port, src_addr, src_port);

  if (con_index == -1) {
    JRLDBG("Could not find connection\n");
    dbg_print_pkt_info(pkt);
    return -1;
  }

  if (g_cons[con_index].tcp_state == ESTABLISHED) {
    do_fin_ack(pkt, con_index);
    g_cons[con_index].tcp_state = CLOSED;
  } else if (g_cons[con_index].tcp_state == FIN_WAIT) {
    do_last_ack(pkt, con_index);
  }

  delete_con(con_index);

  return 0;
}




int do_fin_ack(RawEthernetPacket * pkt, int index) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned long rcv_seq_num;
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ntohs(*(unsigned short *)(pkt->data + ETH_HDR_LEN + 2));
  int offset = 0;
  unsigned short tcp_cksum;
  
  // Switch the various address fields
  swap_eth_addrs(pkt);
  swap_ip_addrs(pkt);


  // Set The IP Header ID
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 4) = g_cons[index].ip_id;
  g_cons[index].ip_id++;

  // Compute the IP Header checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);
  
  // Switch the tcp port fields
  swap_ports(pkt);
  
  // Set ack to seqnum+1
  rcv_seq_num =  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4);
  rcv_seq_num = ntohl(rcv_seq_num) + 1;
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8) = htonl(rcv_seq_num);
  g_cons[index].ack_num = rcv_seq_num;
  
  // set our seqnum to 1
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htonl(g_cons[index].seq_num);

  // Timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    g_cons[index].remote_timestamp = get_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20, tcp_hdr_len - 20);

    set_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20 + offset, g_cons[index].local_timestamp, g_cons[index].remote_timestamp);
  }

  // Set FIN-ACk flags
  offset = ETH_HDR_LEN + ip_hdr_len + 13;
  *(pkt->data + offset) |= 0x11;
  *(pkt->data + offset) &= 0xd1;

  //Set the TCP checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = 0;
  tcp_cksum = get_tcp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = tcp_cksum;


  //dbg_print_pkt(pkt);

  JRLDBG("Adding FIN-ACK to the receive queue\n");
  if (add_pkt(pkt) == -1) {
    JRLDBG("Error adding packet the the receive queue\n");
    return -1;
  }

  return 0;

}


int do_syn_ack(RawEthernetPacket * pkt, int index) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned long rcv_seq_num;
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ntohs(*(unsigned short *)(pkt->data + ETH_HDR_LEN + 2));
  int offset = 0;
  unsigned short tcp_cksum;
  
  // Switch the various address fields
  swap_eth_addrs(pkt);
  swap_ip_addrs(pkt);


  // Set The IP Header ID
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 4) = g_cons[index].ip_id;
  g_cons[index].ip_id++;

  // Compute the IP Header checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);
  
  // Switch the tcp port fields
  swap_ports(pkt);
  
  // Set ack to seqnum+1
  rcv_seq_num =  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4);
  rcv_seq_num = ntohl(rcv_seq_num) + 1;
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8) = htonl(rcv_seq_num);
  g_cons[index].ack_num = rcv_seq_num;
  
  // set our seqnum to 1
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htonl(g_cons[index].seq_num);
  g_cons[index].seq_num++;
  
  // Timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    g_cons[index].remote_timestamp = get_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20, tcp_hdr_len - 20);

    set_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20 + offset, g_cons[index].local_timestamp, g_cons[index].remote_timestamp);
  }

  // Set SYN-ACk flags
  offset = ETH_HDR_LEN + ip_hdr_len + 13;
  *(pkt->data + offset) |= 0x12;
  *(pkt->data + offset) &= 0xd2;

  //Set the TCP checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = 0;
  tcp_cksum = get_tcp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = tcp_cksum;

  // Setup the connection entries packet template
  g_cons[index].pkt_template = *pkt;
  g_cons[index].mss -= tcp_hdr_len - 20;
  g_cons[index].mss -= ip_hdr_len - 20;
  

  //  dbg_print_pkt(pkt);

  JRLDBG("Adding SYN-ACK to the receive queue\n");
  if (add_pkt(pkt) == -1) {
    JRLDBG("Error adding packet the the receive queue\n");
    return -1;
  }

  return 0;
}

int do_last_ack(RawEthernetPacket * pkt, int index) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned long rcv_seq_num;
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ntohs(*(unsigned short *)(pkt->data + ETH_HDR_LEN + 2));
  int offset = 0;
  unsigned short tcp_cksum;
  
  // Switch the various address fields
  swap_eth_addrs(pkt);
  swap_ip_addrs(pkt);


  // Set The IP Header ID
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 4) = g_cons[index].ip_id;
  g_cons[index].ip_id++;

  // Compute the IP Header checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);
  
  // Switch the tcp port fields
  swap_ports(pkt);
  
  // Set ack to seqnum+1
  rcv_seq_num =  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4);
  rcv_seq_num = ntohl(rcv_seq_num) + 1;
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8) = htonl(rcv_seq_num);
  g_cons[index].ack_num = rcv_seq_num;
  
  // set our seqnum to +1
  g_cons[index].seq_num++;
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htonl(g_cons[index].seq_num);

  // Timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    g_cons[index].remote_timestamp = get_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20, tcp_hdr_len - 20);

    set_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20 + offset, g_cons[index].local_timestamp, g_cons[index].remote_timestamp);
  }

  // Set FIN-ACk flags
  offset = ETH_HDR_LEN + ip_hdr_len + 13;
  *(pkt->data + offset) |= 0x10;
  *(pkt->data + offset) &= 0xd0;

  //Set the TCP checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = 0;
  tcp_cksum = get_tcp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = tcp_cksum;


  //  dbg_print_pkt(pkt);

  JRLDBG("Adding LAST-ACK to the receive queue\n");
  if (add_pkt(pkt) == -1) {
    JRLDBG("Error adding packet the the receive queue\n");
    return -1;
  }

  return 0;
}
 


int handle_arp_request(RawEthernetPacket * pkt) {
  char mac_addr[6] = VTP_MAC_ADDR;
  unsigned long temp_ip;
  int index;

  JRLDBG("Handling ARP Request\n");

  // set the ether headers
  // copy the source mac to dest mac
  memcpy(pkt->data, pkt->data + 6, 6);
  
  // set the dest mac to our taken address
  memcpy(pkt->data + 6, mac_addr, 6);

  // set the op field to reply (0x02)
  *(pkt->data + ETH_HDR_LEN + 6) = 0x00;
  *(pkt->data + ETH_HDR_LEN + 7) = 0x02;

  // store the target IP address for use as sender
  temp_ip = *(unsigned long *)(pkt->data + ETH_HDR_LEN + 24);
  
  // copy the arp target address from sender
  memcpy(pkt->data + ETH_HDR_LEN + 18, pkt->data + ETH_HDR_LEN + 8, 10);
  
  // copy the sender information into the packet
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + 14) = temp_ip;
  memcpy(pkt->data + ETH_HDR_LEN + 8, mac_addr, 6);

  // put packet onto send queue
  index = add_pkt(pkt);

  return 0;
}


int make_rst_pkt(int con_index) {
  RawEthernetPacket * pkt = &(g_cons[con_index].pkt_template);
  int ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ip_hdr_len + tcp_hdr_len;
  unsigned long tcp_cksum;
  int offset;
  // assume that address/ports are ok
  /* fix:
   *    ip_total_len
   *    ip_id
   *    ip_cksum
   *    tcp_flags
   *    tcp seq_num
   *    tcp_ack_num
   *    tcp_timestamp
   *    tcp_cksum
   */


  // ip_total_len
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 2) = htons(ip_pkt_len);

  // ip_id
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 4) = htons(g_cons[con_index].ip_id);
  g_cons[con_index].ip_id++;

  //ip_cksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);

  //tcp_flags
  offset = ETH_HDR_LEN + ip_hdr_len + 13;
  *(pkt->data + offset) |= 0x04;
  *(pkt->data + offset) &= 0xd4;

  //tcp_seq_num
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htonl(g_cons[con_index].seq_num);

  // tcp_ack_num
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8) = htonl(g_cons[con_index].ack_num);


  // Timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    set_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20 + offset, g_cons[con_index].local_timestamp, g_cons[con_index].remote_timestamp);
  }


  //tcp_cksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = 0;
  tcp_cksum = get_tcp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = tcp_cksum;

  JRLDBG("Making RST Pkt\n");
  dbg_print_pkt_info(pkt);
  pkt->set_size(ETH_HDR_LEN + ip_pkt_len);

  return 0;

}



int make_fin_pkt(int con_index) {
  RawEthernetPacket * pkt = &(g_cons[con_index].pkt_template);
  int ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ip_hdr_len + tcp_hdr_len;
  unsigned long tcp_cksum;
  int offset;
  // assume that address/ports are ok
  /* fix:
   *    ip_total_len
   *    ip_id
   *    ip_cksum
   *    tcp_flags
   *    tcp seq_num
   *    tcp_ack_num
   *    tcp_timestamp
   *    tcp_cksum
   */


  // ip_total_len
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 2) = htons(ip_pkt_len);

  // ip_id
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 4) = htons(g_cons[con_index].ip_id);
  g_cons[con_index].ip_id++;

  //ip_cksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);

  //tcp_flags
  offset = ETH_HDR_LEN + ip_hdr_len + 13;
  *(pkt->data + offset) |= 0x11;
  *(pkt->data + offset) &= 0xd1;

  //tcp_seq_num
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htonl(g_cons[con_index].seq_num);

  // tcp_ack_num
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8) = htonl(g_cons[con_index].ack_num);


  // Timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    set_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20 + offset, g_cons[con_index].local_timestamp, g_cons[con_index].remote_timestamp);
  }


  //tcp_cksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = 0;
  tcp_cksum = get_tcp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = tcp_cksum;

  JRLDBG("Making FIN Pkt\n");
  dbg_print_pkt_info(pkt);
  pkt->set_size(ETH_HDR_LEN + ip_pkt_len);

  return 0;

}


int make_data_pkt(int con_index, char * data, int data_len) {
  RawEthernetPacket * pkt = &(g_cons[con_index].pkt_template);
  int ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short tcp_hdr_len = (*(pkt->data + ETH_HDR_LEN + ip_hdr_len + 12) & 0xf0) >> 2;
  unsigned short ip_pkt_len = ip_hdr_len + tcp_hdr_len + data_len;
  unsigned long tcp_cksum;
  int offset;
  // assume that address/ports are ok
  /* fix:
   *    data
   *    ip_total_len
   *    ip_id
   *    ip_cksum
   *    tcp_flags
   *    tcp seq_num
   *    tcp_ack_num
   *    tcp_timestamp
   *    tcp_cksum
   */

  if (data_len == 0) {
    JRLDBG("No Data: This is an ACK Packet\n");
  }

  // data
  if (data_len > 0) {
    memcpy(pkt->data + ETH_HDR_LEN + ip_hdr_len + tcp_hdr_len, data, data_len);
  }

  // ip_total_len
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 2) = htons(ip_pkt_len);

  // ip_id
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 4) = htons(g_cons[con_index].ip_id);
  g_cons[con_index].ip_id++;

  //ip_cksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);

  //tcp_flags
  offset = ETH_HDR_LEN + ip_hdr_len + 13;
  *(pkt->data + offset) |= 0x10;
  *(pkt->data + offset) &= 0xd0;

  //tcp_seq_num

  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htonl(g_cons[con_index].seq_num);
  g_cons[con_index].seq_num += data_len;

  // tcp_ack_num
  *(unsigned long *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 8) = htonl(g_cons[con_index].ack_num);


  // Timestamp
  if ((offset = pkt_has_timestamp(pkt)) != -1) {
    g_cons[con_index].local_timestamp = htonl(ntohl(g_cons[con_index].local_timestamp) + 1);
    set_tcp_timestamp(pkt->data + ETH_HDR_LEN + ip_hdr_len + 20 + offset, g_cons[con_index].local_timestamp, g_cons[con_index].remote_timestamp);
  }


  //tcp_cksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = 0;
  tcp_cksum = get_tcp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 16) = tcp_cksum;

  JRLDBG("Making Data Packet (size: %d, len: %d)\n", ETH_HDR_LEN + ip_pkt_len, data_len);
  dbg_print_pkt_info(pkt);

  //  dbg_print_pkt(pkt);

  pkt->set_size(ETH_HDR_LEN + ip_pkt_len);

  return 0;
}






/* List processing */

int add_con(unsigned long dest_addr, unsigned short dest_port, unsigned long src_addr, unsigned short src_port, int rem_socket) {
  int i;

  extern fd_set g_vtp_all_set;
  extern int g_vtp_max_fd;

  for(i = 0; i < MAX_CONS; i++) {
    if (g_cons[i].in_use == 0) {
      g_cons[i].src_addr = src_addr;
      g_cons[i].dest_addr = dest_addr;
      g_cons[i].dest_port = dest_port;
      g_cons[i].src_port = src_port;

      g_cons[i].rem_socket = rem_socket;
      FD_SET(rem_socket, &g_vtp_all_set);
      if (rem_socket > g_vtp_max_fd) {
	g_vtp_max_fd = rem_socket;
      }

      g_cons[i].tcp_state = CLOSED;

      g_cons[i].in_use = 1;

      g_cons[i].ip_id = 1;
      g_cons[i].seq_num = 1;
      g_cons[i].local_timestamp = htonl(1);

      if (g_first_con == -1) 
	g_first_con = i;

      g_cons[i].prev = g_last_con;
      g_cons[i].next = -1;
      
      if (g_last_con != -1) {
	g_cons[g_last_con].next = i;
      }

      g_last_con = i;

      g_num_cons++;
      return i;
    }
  }
  return -1;

}


int delete_con(int index) {
  int next_i;
  int prev_i;

  extern fd_set g_vtp_all_set;

  JRLDBG("Deleting Connection %d\n", index);

  g_cons[index].src_addr = 0;
  g_cons[index].dest_addr = 0;
  g_cons[index].tcp_state = CLOSED;

  FD_CLR(g_cons[index].rem_socket, &g_vtp_all_set);
  close(g_cons[index].rem_socket);
  g_cons[index].rem_socket = 0;

  //close(g_cons[index].local_socket);
  //g_cons[index].local_socket = 0;
  g_cons[index].in_use = 0;

  prev_i = g_cons[index].prev;
  next_i = g_cons[index].next;

  if (prev_i != -1)
    g_cons[prev_i].next = g_cons[index].next;


  if (next_i != -1) 
    g_cons[next_i].prev = g_cons[index].prev;

  if (g_first_con == index)
    g_first_con = g_cons[index].next;

  if (g_last_con == index) 
    g_last_con = g_cons[index].prev;

  g_cons[index].next = -1;
  g_cons[index].prev = -1;

  g_num_cons--;

  return 0;
}


int find_con(unsigned long dest_addr, unsigned short dest_port, unsigned long src_addr, unsigned short src_port) {
  int i;

  FOREACH_CON(i, g_cons) {
    if ( (g_cons[i].dest_addr == dest_addr) && (g_cons[i].dest_port == dest_port) &&
	 (g_cons[i].src_addr == src_addr) && (g_cons[i].src_port == src_port) ) {
      return i;
    }
  }
  return -1;
}

int find_con(int rem_socket, int local_socket) {
  int i;

  FOREACH_CON(i, g_cons) {
    if ( ((g_cons[i].rem_socket == rem_socket) || (rem_socket == -1)) && 
	 ((g_cons[i].local_socket == local_socket) || (local_socket == -1)) &&
	 ((local_socket != -1) || (rem_socket != -1))) {
      return i;
    }
  }
  return -1;
}



/* Packet Queue Processing */


int add_pkt(RawEthernetPacket * pkt) {
  if (g_num_pkts >= MAX_PKTS) {
    return -1;
  }

  g_pkts[g_num_pkts] = *pkt;
  g_num_pkts++;
  
  return 0;
}


RawEthernetPacket * get_pkt() {
  RawEthernetPacket * pkt;

  pkt = &(g_pkts[g_num_pkts - 1]);
  g_num_pkts++;

  return pkt;
}



/*** DNS FUNCTIONS ***/


int handle_dns_request(RawEthernetPacket * pkt, struct in_addr dns_addr, unsigned short dns_port) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short udp_hdr_len = 8; 
  unsigned char opcode;
  int name_len = 0;
  char * dns_msg = pkt->data + ETH_HDR_LEN + ip_hdr_len + udp_hdr_len;
  char * hostname;
  int i = 0;
  int j = 0;
  unsigned short  num_queries;
  int q_offset = 12;
  int query_index;
  char * dns_req;
  int req_len;
  int socks_fd;

  if ((*(dns_msg + 2) & 0x80) == 0x80) {
    // dns message is not a query
    JRLDBG("DNS packet is not a query\n");
    return 0;
  }

  opcode = *(dns_msg + 2);
  opcode = opcode >> 3;
  opcode &= 0x0f;

  if (opcode != 0) {
    // not a standard query
    JRLDBG("DNS Request not a standard Query\n");
    return 0;
  }

  num_queries = ntohs(*(unsigned short *)(dns_msg + 4));
  JRLDBG("Number of queries: %hu\n", num_queries);

  for (j = 0; j < num_queries; j++) {
    name_len = *(dns_msg + q_offset) + 1;
    while (*(dns_msg + q_offset + name_len) != 0) {
      name_len += *(dns_msg + q_offset + name_len) + 1;
    }
    
    JRLDBG("Name query length: %d\n", name_len);
    
    if (ntohs(*(unsigned short *)(dns_msg + q_offset + name_len + 1)) != 1) {
      // Not an IN A query
      JRLDBG("Not an IN A query\n");
      return 0;
    }
    
    if (ntohs(*(unsigned short *)(dns_msg + q_offset + name_len + 3)) != 1) {
      // Not an IN A query
      JRLDBG("Not an Internet class query\n");
      return 0;
    }
    
    hostname = (char *)malloc(sizeof(char) * name_len);
    snprintf(hostname, name_len, "%s", dns_msg + 12 + 1);
    
    i = *(dns_msg + q_offset) + 1;
    while (*(dns_msg + q_offset + i) != 0) {
      *(hostname + i - 1) = '.';
      i += *(dns_msg + q_offset + i) + 1;
    }
    
    JRLDBG("Query for hostname: %s\n", hostname);
    

    socks_fd = socks4_connect(dns_addr, dns_port);

    //fcntl(socks_fd, F_SETFL, O_NONBLOCK);    

    if (socks_fd < 0) {
      // error;
      JRLDBG("could not connect to socks server for dns request (ret=%d)\n", socks_fd);
      return -1;
    }

    query_index = add_query(hostname, name_len, opcode, socks_fd, pkt);

    if (query_index == -1) {
      JRLDBG("could not add query");
      close(socks_fd);
      return -1;
    }

    req_len = 8 + 1 + strlen(hostname) + 1;
    dns_req = (char *)malloc(req_len);
    memset(dns_req, 0, req_len);
    
    dns_req[0] = 0x04;
    dns_req[1] = 0xf0;
    *(unsigned short *)(dns_req + 2) = htons(0);
    *(unsigned long *)(dns_req + 4) = htonl(1);
    strcpy(dns_req + 8 + 1, hostname);
    

    if (vsend(socks_fd, dns_req, req_len) == -1) {
      JRLDBG("Error sending dns request\n");
      close(socks_fd);
      delete_query(query_index);
      return -1;
    } 

    free(dns_req);
  }


  return 1;
}

int handle_dns_reply(int query_index) {
  char dns_ans[8];
  unsigned long ip_addr;
  unsigned char reply_code;
  struct dns_answer answers;
  unsigned long ttl = 0xffffffff;
  unsigned char ip_hdr_len = IP_HDR_LEN(g_queries[query_index].pkt.data);
  unsigned short udp_hdr_len = 8; 
  char * dns_msg = g_queries[query_index].pkt.data + ETH_HDR_LEN + ip_hdr_len + udp_hdr_len;
  int q_offset = 12;

  answers.len = 0;
  answers.pkt_offset = 0;
  answers.num_answers = 1;
  answers.data = NULL;

  JRLDBG("Receiving DNS packet on socket %d\n", g_queries[query_index].socket);
  if (vrecv(g_queries[query_index].socket, dns_ans, 8) == -1) {
    JRLDBG("Error receiving DNS reply\n");
    delete_query(query_index);
    return -1;
  }
  JRLDBG("Received DNS reply\n");

  if (dns_ans[0] != 0) {
    // bad version
    JRLDBG("Socks returned bad version for dns request\n");
    delete_query(query_index);
    return -1;
  }

  reply_code = dns_ans[1];

  if (reply_code != 90) {
    // error
    JRLDBG("Socks returned error for dns request: %d\n", reply_code);
    delete_query(query_index);
    return -1;
  }

  ip_addr = ntohl(*(unsigned long *)(dns_ans + 4));



  answers.data = (char *)malloc(g_queries[query_index].name_len + 14 + 1);
  
  memcpy(answers.data + answers.len, dns_msg + q_offset, g_queries[query_index].name_len + 1 + 4);
  *(unsigned long *)(answers.data + answers.len + g_queries[query_index].name_len + 1 + 4) = ttl;
  *(unsigned short *)(answers.data + answers.len + g_queries[query_index].name_len + 1 + 8) = htons(4);
  *(unsigned long *)(answers.data + answers.len + g_queries[query_index].name_len + 1 + 10) = htonl(ip_addr); 
  
  q_offset += g_queries[query_index].name_len + 4 + 1;
  answers.len += g_queries[query_index].name_len + 14 + 1;
  answers.pkt_offset = q_offset;
  

  make_dns_reply_pkt(&(g_queries[query_index].pkt), answers);

  add_pkt(&(g_queries[query_index].pkt));

  free(answers.data);
  delete_query(query_index);

  return 0;
}


int make_dns_reply_pkt(RawEthernetPacket * pkt, struct dns_answer answers) {
  unsigned char ip_hdr_len = IP_HDR_LEN(pkt->data);
  unsigned short ip_pkt_len = ntohs(*(unsigned short *)(pkt->data + ETH_HDR_LEN + 2));
  unsigned short udp_pkt_len = ntohs(*(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4));
  unsigned short udp_hdr_len = 8; 
  char * dns_msg = pkt->data + ETH_HDR_LEN + ip_hdr_len + udp_hdr_len;
  unsigned short udp_checksum;
  
  swap_eth_addrs(pkt);
  swap_ip_addrs(pkt);


  // ip_pkt_len
  ip_pkt_len += answers.len;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 2) = htons(ip_pkt_len);

  // Compute the IP Header checksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = 0;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + 10) = get_ip_checksum(pkt);

  swap_ports(pkt);
  
  // set the udp packet length
  udp_pkt_len += answers.len;
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 4) = htons(udp_pkt_len);

  // copy the answer field into the packet
  memcpy(dns_msg + answers.pkt_offset, answers.data, answers.len);

  *(unsigned short *)(dns_msg + 6) = htons(answers.num_answers);

  // set the response flag
  *(dns_msg + 2) |= 0x80;




  // udp_chksum
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 6) = 0;
  udp_checksum = get_udp_checksum(pkt, ip_pkt_len - ip_hdr_len);
  *(unsigned short *)(pkt->data + ETH_HDR_LEN + ip_hdr_len + 6) = udp_checksum;

  pkt->set_size(ETH_HDR_LEN + ip_pkt_len);

  return 0;
}




int socks4_connect(struct in_addr socks_addr, unsigned short socks_port) {
  int socks_fd;
  struct sockaddr_in socks_server;
  
  // connect to the socks server and negotiate the method
  if ((socks_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    JRLDBG("Error creating socket\n");
    return -1;
  }


  socks_server.sin_family = AF_INET;
  socks_server.sin_port = htons(socks_port);
  socks_server.sin_addr.s_addr = socks_addr.s_addr;
  memset(&(socks_server.sin_zero), '\0', 8);

  if (connect(socks_fd, (struct sockaddr *)&socks_server, sizeof(struct sockaddr)) == -1) {
#ifdef DEBUG
    JRLDBG("Error: could not connect to socks proxy\n");
    JRLDBG("Socks address: %s, port: %d\n", inet_ntoa(socks_addr), socks_port);
#endif
    return -2;
  }

  return socks_fd;
}


int add_query(char * name, int name_len, unsigned char opcode, int socket, RawEthernetPacket * pkt) {
  int i;

  extern fd_set g_vtp_all_set;
  extern int g_vtp_max_fd;

  for(i = 0; i < MAX_QUERIES; i++) {
    if (g_queries[i].in_use == 0) {


      g_queries[i].name_len = name_len;
      g_queries[i].name = (char *)malloc(sizeof(char) * name_len);
      g_queries[i].opcode = opcode;
      g_queries[i].pkt = *pkt;

      g_queries[i].socket = socket;
      FD_SET(socket, &g_vtp_all_set);
      if (socket > g_vtp_max_fd) {
	g_vtp_max_fd = socket;
      }


      g_queries[i].in_use = 1;


      if (g_first_query == -1) 
	g_first_query = i;

      g_queries[i].prev = g_last_query;
      g_queries[i].next = -1;
      
      if (g_last_query != -1) {
	g_queries[g_last_query].next = i;
      }

      g_last_query = i;

      g_num_queries++;
      return i;
    }
  }
  return -1;
}






int delete_query(int index) {
  int next_i;
  int prev_i;

  extern fd_set g_vtp_all_set;

  JRLDBG("Deleting DNS Query %d\n", index);

  FD_CLR(g_queries[index].socket, &g_vtp_all_set);
  close(g_queries[index].socket);
  g_queries[index].socket = 0;

  free(g_queries[index].name);
  g_queries[index].name = NULL;
  g_queries[index].name_len = 0;

  g_queries[index].in_use = 0;

  prev_i = g_queries[index].prev;
  next_i = g_queries[index].next;

  if (prev_i != -1)
    g_queries[prev_i].next = g_queries[index].next;


  if (next_i != -1) 
    g_queries[next_i].prev = g_queries[index].prev;

  if (g_first_query == index)
    g_first_query = g_queries[index].next;

  if (g_last_query == index) 
    g_last_query = g_queries[index].prev;

  g_queries[index].next = -1;
  g_queries[index].prev = -1;

  g_num_queries--;

  return 0;
}


int find_query(int socket) {
  int i;

  FOREACH_QUERY(i, g_queries) {
    if (g_queries[i].socket == socket) {
      return i;
    }
  }
  return -1;
}
