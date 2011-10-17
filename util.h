#ifndef _util
#define _util


#include <stdio.h>
#include <iostream>
#include <string>
extern "C" {
#define OPENSSL_NO_KRB5
#include <openssl/ssl.h>
}

using namespace std;

int readall(const int fd, char *buf, const int len, const int oneshot=0, const int awaitblock=1,SSL *ssl=0);
int writeall(const int fd, const char *buf, const int len, const int oneshot=0, const int awaitblock=1,SSL *ssl=0);

int compare_nocase(const string& s1, const string& s2);

struct SerializationException {};

void printhexnybble(FILE *out,const char lower);
void printhexbyte(FILE *out,const char h);
void printhexshort(FILE *out,const short h);
void printhexint(FILE *out,const int h);
void printhexbuffer(FILE *out, const char *buf, const int len);

void hexbytetobyte(const char hexbyte[2], char *byte);
void bytetohexbyte(const char byte, char hexbyte[2]);

void ConvertHexEthernetAddressToBinary(const char* string,char address[6]);

void ConvertBinaryEthernetAddressToHex(char address[6],char* string);


typedef char EthernetAddrString[2*6+6];

using namespace std;

struct EthernetAddr {
  char addr[6];

  EthernetAddr();
  EthernetAddr(const EthernetAddr &rhs);
  EthernetAddr(const EthernetAddrString rhs);
  const EthernetAddr & operator=(const EthernetAddr &rhs);

  bool operator==(const EthernetAddr &rhs) const;
 
  void SetToString(const EthernetAddrString s);
  void GetAsString(EthernetAddrString s) const;
  
  void Serialize(const int fd, SSL *ssl) const;
  void Unserialize(const int fd,SSL *ssl);

  ostream & Print(ostream &os) const;
};

inline ostream & operator<<(ostream &os, const EthernetAddr &e)
{
  return e.Print(os);
}

#endif
