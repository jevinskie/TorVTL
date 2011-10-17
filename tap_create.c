#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int tun_alloc(char*);

int main (int argc, char **  argv) {
  int fd;
  if (argv[1]) {
    if ((fd = tun_alloc(argv[1])) < 0) {
      printf("Error\n");
    }
  }
  close(fd);

}

int tun_alloc(char *dev) {
  struct ifreq ifr;
  int fd, err;
  
  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
    return -1;
  
  memset(&ifr, 0, sizeof(struct ifreq));
  
  /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
   *        IFF_TAP   - TAP device  
   *
   *        IFF_NO_PI - Do not provide packet information  
   */ 
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
  if( *dev )
    strncpy(ifr.ifr_name, dev, strlen(dev));
  
  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
         close(fd);
         return err;
  }

  if ((err = ioctl(fd, TUNSETPERSIST, 1)) < 0) {
    close(fd);
    return err;
  }
  strcpy(dev, ifr.ifr_name);
  return fd;
}              
