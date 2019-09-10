#ifndef _MPRSEL
#define _MPRSEL

#include <sys/time.h>

#ifdef __cplusplus
extern "C" 
{
#endif /* __cplusplus */

#ifndef NULL
#define NULL 0
#endif // !NULL

typedef const void* MPRSELHandle;

typedef struct MPRSELPosition
{
    unsigned long addrs[256];
} MPRSELPosition;


char* MPRSELMemoryInit(const char* keyFile, unsigned int size);

inline MPRSELHandle MPRSELPublishInit(const char* keyFile)
    {return (MPRSELHandle)MPRSELMemoryInit(keyFile, sizeof(MPRSELPosition));}
void MPRSELPublishUpdate(MPRSELHandle mprHandle, const MPRSELPosition* currentPosition);
void MPRSELPublishShutdown(MPRSELHandle mprHandle, const char* keyFile);

MPRSELHandle MPRSELSubscribe(const char* keyFile);
void MPRSELGetCurrentPosition(MPRSELHandle mprHandle, MPRSELPosition* currentPosition);
void MPRSELUnsubscribe(MPRSELHandle mprHandle);

// Generic data publishing
unsigned int MPRSELSetMemory(MPRSELHandle mprHandle, unsigned int offset, 
                          const char* buffer, unsigned int len);
unsigned int MPRSELGetMemorySize(MPRSELHandle mprHandle);
unsigned int MPRSELGetMemory(MPRSELHandle mprHandle, unsigned int offset, 
                          char* buffer, unsigned int len);


#ifdef __cplusplus
}
#endif /* __cplusplus */ 
    
#endif // _MPRSEL
