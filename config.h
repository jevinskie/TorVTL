#ifndef _config
#define _config

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

#define ETHERNET_HEADER_LEN 14
#define ETHERNET_DATA_MIN   46
#define ETHERNET_DATA_MAX   1500

#define ETHERNET_PACKET_LEN (ETHERNET_HEADER_LEN+ETHERNET_DATA_MAX)

#define LIBNET_ERRORBUF_SIZE 256

// JRL VTP FIFO
#define HOME "./"
#define VTP_FIFO_SENDFILE HOME "vtp_fifo_send"
#define VTP_FIFO_RECVFILE HOME "vtp_fifo_recv"

#endif
