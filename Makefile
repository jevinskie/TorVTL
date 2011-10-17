UTIL_OBJS = raw_ethernet_packet.o vtp_util.o util.o net_util.o
TORCLIENT_OBJS =  $(UTIL_OBJS) vtp_socks5.o  tor_client.o

LIBNETLDFLAGS =  -lnet
SSLFLAGS	= -lssl
PCAPCFLAGS  = 
PCAPLDFLAGS =  -lpcap

CXX=g++
CC=/usr/bin/gcc 
AR=ar
RANLAB=ranlib

CXXFLAGS =  -g -gstabs+ -Wall $(PCAPCFLAGS) -I/usr/kerberos/include
LDFLAGS  =  $(PCAPLDFLAGS) $(LIBNETLDFLAGS) $(SSLFLAGS) 

all:	torclient


torclient: $(TORCLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(TORCLIENT_OBJS) $(LDFLAGS) -o torclient

tap1: tap_create.o
	$(CXX) $(CXXFLAGS) tap_create.o -o tap_create
	./tap_create tap1
	/sbin/ifconfig tap1 up

%.o : %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $(@F)

clean: 
	rm -f $(TORCLIENT_OBJS) torclient
