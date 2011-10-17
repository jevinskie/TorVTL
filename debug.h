#ifndef __DEBUG_H
#define __DEBUG_H 1


#define DEBUG 0

extern FILE * logfile;
extern time_t dbgt;
extern char dmsg[1024];

#define DEBUG_DECLARE() FILE * logfile; time_t dbgt; char dmsg[1024];




#ifdef DEBUG
#define JRLDBG( ...) time(&dbgt); sprintf(dmsg,"%s: ",ctime(&dbgt)); *(dmsg + strlen(dmsg) -3) = ' '; fprintf(logfile, dmsg); sprintf(dmsg,__VA_ARGS__); fprintf(logfile,dmsg); fflush(logfile);
#define debug_init(logfilename) logfile = fopen(logfilename,"w+");
#else 
#define JRLDBG( ...)
#define debug_init(logfilename)
#endif

#endif
