#ifndef _UNIX
#define _UNIX
/* Stuff from unix header files used by OLSR and not found in Windows */


// from <netinet/in.h>
/* Internet address.  */
typedef unsigned long in_addr_t;

#define	IN_EXPERIMENTAL(a)	((((in_addr_t)(a)) & 0xe0000000) == 0xe0000000)
#define	IN_BADCLASS(a)		((((in_addr_t)(a)) & 0xf0000000) == 0xf0000000)


// from <bits/sigset.h>
# define _SIGSET_NWORDS	(1024 / (8 * sizeof (unsigned long int)))
typedef struct
  {
    unsigned long int __val[_SIGSET_NWORDS];
  } __sigset_t;


// from <signal.h>
typedef __sigset_t sigset_t;



// from <sys/time.h>
/* Type of the second argument to `getitimer' and
   the second and third arguments `setitimer'.  */
struct itimerval
  {
    /* Value to put into `it_value' when the timer expires.  */
    struct timeval it_interval;
    /* Time to the next timer expiration.  */
    struct timeval it_value;
  };



// from <net/route.h>
#define	RTF_UP		0x0001		/* Route usable.  */
#define	RTF_GATEWAY	0x0002		/* Destination is a gateway.  */
#define	RTF_HOST	0x0004		/* Host entry (net otherwise).  */

#endif // _UNIX
        
