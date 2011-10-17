#ifndef _socks
#define _socks

#if defined(WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <winsock.h>
#else
extern "C" {
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#define OPENSSL_NO_KRB5
#include <openssl/ssl.h>
#include <stdio.h>
#include <errno.h>
}
#endif

#include <string>

using namespace std;

#define SND_RCV_SOCKET_BUF_SIZE 65536
#ifndef INADDR_NONE
#define INADDR_NONE             0xffffffff
#endif


#if defined(WIN32) && !defined(__CYGWIN__)
#include <io.h>
#define WRITE(fd,buf,len) send(fd,buf,len,0)
#define READ(fd,buf,len) recv(fd,buf,len,0)
#define CLOSE(x) closesocket(x)
#define IOCTL(x,y,z) ioctlsocket((SOCKET)x,(long)y,(unsigned long *)z)
#else
#define WRITE(ssl,buf,len) write(ssl,buf,len)
#define READ(fd,buf,len) read(fd,buf,len)
#define CLOSE(x) close(x)
#define IOCTL(x,y,z) ioctl(x,y,z)
#endif


int CreateAndSetupTcpSocket(const int bufsize=SND_RCV_SOCKET_BUF_SIZE, 
                            const bool nodelay=true,
                            const bool nonblocking=false);

int CreateAndSetupUdpSocket(const int bufsize=SND_RCV_SOCKET_BUF_SIZE, 
                            const bool nonblocking=false);

int CreateAndSetupUnixDomainSocket(const int bufsize=SND_RCV_SOCKET_BUF_SIZE,
                                   const bool nonblocking=false);

int SetNoDelaySocket(const int fd, const bool nodelay=true);

int IsSocket(const int fd);
int IsStreamSocket(const int fd);
int IsDatagramSocket(const int fd);
int IsVirtualSocket(const int fd);

int BindSocket(const int mysocket, const int myport);
int BindSocket(const int mysocket, const unsigned adx, const int myport);
int BindSocket(const int mysocket, const char *host_or_ip, const int myport);
int BindSocket(const int mysocket, const char *pathname);

int ListenSocket(const int mysocket, const int max=SOMAXCONN);

int ConnectToHost(const int mysocket, const int hostip, const int port);
int ConnectToHost(const int mysocket, const char *host, const int port);
int ConnectToPath(const int mysocket, const char *pathname);

int Send(const int fd, SSL *ssl, const char *buf, const int len, bool sendall=true);
int Receive(const int fd, SSL *ssl, char *buf, const int len, bool recvall=true);

int SendTo(const int mysocket, 
           const unsigned ip, const int port, 
           const char *buf, const int len, bool sendall=true);
int ReceiveFrom(const int mysocket, 
                const unsigned ip, const int port, 
                char *buf, const int len, const bool recvall=true);
int SendTo(const int mysocket, 
           const char *host_or_ip, const int port, 
           const char *buf, const int len, const bool sendall=true);
int ReceiveFrom(const int mysocket, 
                const char *host_or_ip, const int port, 
                char *buf, const int len, const bool recvall=true);


int JoinMulticastGroup(const int mysocket, const char *IP);
int JoinMulticastGroup(const int mysocket, const unsigned adx);
int LeaveMulticastGroup(const int mysocket, const char *IP);
int LeaveMulticastGroup(const int mysocket, const unsigned adx);
int SetMulticastTimeToLive(const int mysocket, const unsigned char ttl);


unsigned GetMyIPAddress();
unsigned ToIPAddress(const char *hostname);
void     PrintIPAddress(const unsigned adx, FILE *out=stderr);
void     IPToHostname(const unsigned ip, char *name, const int namesize);
int      IsValidIPMulticastAddress(const unsigned ipadx);


int SetSignalHandler(const int signum, void (*handler)(int), const bool oneshot=false);
int IgnoreSignal(const int signum);
int ListenToSignal(const int signum);

int GetLine(int fd, SSL *ssl, string &s);
int PutLine(int fd, SSL *ssl, const string &s);

#endif
