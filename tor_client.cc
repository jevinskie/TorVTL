/* This is the standalone tor client 
   Jack Lange, 2006
*/
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <getopt.h>
#include <signal.h>

extern "C"{
  #include <libnet.h>
  #include <pcap.h>
}

#include "raw_ethernet_packet.h"
#include "config.h"
#include "util.h"
#include "vtp_util.h"
#include "vtp_util.h"
#include "net_util.h"
#include "vtp.h"
#include "vtp_socks5.h"


#include "debug.h"

DEBUG_DECLARE();

using namespace std;

fd_set g_vtp_read_set;
fd_set g_vtp_all_set;
int g_vtp_max_fd = 0;

void usage(char * progname);
void recv_pcap_pkt(pcap_t * device);

void handle_sig(int signum) {
  exit(0);
}

int main(int argc, char ** argv) {
  int opt;
  extern char *optarg;
  //  extern int optind;

  string address;
  int tor_port = 0;
  string tx_device_name;
  string rx_device_name;
  int unified_dev = 0;

  struct in_addr tor_addr;
  hostent * tor_he;

  pcap_t * rx_device = NULL;
  int rx_dev_fd = 0;
  libnet_t * tx_device = NULL;

  char net_errbuf[LIBNET_ERRORBUF_SIZE];
  char pcap_errbuf[PCAP_ERRBUF_SIZE];

  RawEthernetPacket * recv_pkts;

  debug_init("./tor.log");

  if (argc < 4) {
    usage(argv[0]);
    exit(0);
  }

  while ((opt = getopt(argc, argv, "d:r:t:a:p:h")) != -1) {
    switch(opt){
    case 'd':
      if (unified_dev == 2) {
	usage(argv[0]);
	exit(0);
      }

      tx_device_name = string(optarg);
      rx_device_name = string(optarg);
      unified_dev = 1;
      break;
    case 't': 
      if (unified_dev == 1) {
	usage(argv[0]);
	exit(0);
      }
      unified_dev = 2;
      tx_device_name = string(optarg);
      break;
    case 'r':
      if (unified_dev == 1) {
	usage(argv[0]);
	exit(0);
      }
      unified_dev = 2;
      rx_device_name = string(optarg);
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
    case 'p':
      tor_port = atoi(optarg);
      break;
    case 'a':
      address = string(optarg);
      break;
    default:
      usage(argv[0]);
      exit(0);
    }
  }

  if ((address.empty()) || (tor_port == 0) || 
       (rx_device_name.empty()) || 
       (tx_device_name.empty()) ){
    usage(argv[0]);
    exit(0);
  }

  signal(SIGINT, handle_sig);


  tx_device = libnet_init(LIBNET_LINK_ADV, (char*)tx_device_name.c_str(), net_errbuf);

  if (tx_device == NULL) {
    cerr << "libnet can't open tx device(" << tx_device_name.c_str() << "): " << net_errbuf << endl;
    exit(-1);
  } 

  cerr << "libnet attached to tx device: " << tx_device_name.c_str() << endl;

  rx_device = pcap_open_live((char*)(rx_device_name.c_str()), ETHERNET_PACKET_LEN, 1, 0, pcap_errbuf);

  if (rx_device == NULL) {
    cerr << "pcap can't open rx_device(" << rx_device_name.c_str() << "): " << pcap_errbuf << endl;
    exit(-1);
  }

  rx_dev_fd = pcap_fileno(rx_device);

  cerr << "pcap attached to rx device: " << rx_device_name.c_str() << endl;

  vtp_init();

  if ((tor_he = gethostbyname(address.c_str())) == NULL) {
    cerr << "Could not lookup address for " << address.c_str() << endl;
    exit(-1);
  }

  tor_addr = *((struct in_addr *)tor_he->h_addr);

  vtp_connect(tor_addr, tor_port);

  FD_ZERO(&g_vtp_read_set);
  FD_ZERO(&g_vtp_all_set);
  FD_SET(rx_dev_fd, &g_vtp_all_set);

  g_vtp_max_fd = rx_dev_fd;

  while (1) {
    int n_cons = 0;
    int n_pkts_recvd = 0;
    g_vtp_read_set = g_vtp_all_set;
    
    JRLDBG("Loop set (set size=%d)\n", g_vtp_max_fd);
    n_cons = select(g_vtp_max_fd + 1, &g_vtp_read_set, NULL, NULL, NULL);
    JRLDBG("Loop mark\n");

    if (n_cons == -1) {
      JRLDBG("Select returned error %d\n", errno);
      perror("Select returned an error");
      continue;
    } 

    if ((n_cons > 0) && (FD_ISSET(rx_dev_fd, &g_vtp_read_set))) {
      JRLDBG("Triggered by PCAP\n");
      recv_pcap_pkt(rx_device);
    }

    if ((n_pkts_recvd = vtp_recv(&recv_pkts)) > 0) {
      int i;

      for (i = 0; i < n_pkts_recvd; i++) {
	if (libnet_adv_write_link(tx_device, (u_char *)(recv_pkts[i].get_data()), recv_pkts[i].get_size()) < 0) {
	  cerr << "Can't write packet to tx device" << endl;
	}
      }
    }
  }
}


void usage(char * progname) {
  cerr << "usage: " << progname;
  cerr << " <-d <device> | -r <rx_dev> -t <tx_dev>> -a <address> -p [port] " << endl;
}


void recv_pcap_pkt(pcap_t * device) {
  struct pcap_pkthdr header;
  const u_char * packet;
  struct HEADERS headers;
  struct in_addr serv_addr;

  packet = pcap_next(device, &header);

  if (packet == NULL) {
    cerr << "pcap_next returned a null pointer\n";
    return;
  }

  RawEthernetPacket pkt((const char *)packet, (unsigned)(header.len));

  //  pkt.set_type("et");

  memcpy((void *)&headers, (void *)pkt.get_data(), sizeof(headers));

  if (vtp_send(&pkt, serv_addr) == -1) {
    JRLDBG("Error processing packet\n");
    cerr << "Error Processing packet" << endl;
  }

  return;
}
