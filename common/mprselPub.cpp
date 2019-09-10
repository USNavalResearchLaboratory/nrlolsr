/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: 
 *
 * (1) source code distributions retain this paragraph in its entirety, 
 *  
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided 
 *     with the distribution, and 
 *
 * (3) all advertising materials mentioning features or use of this 
 *     software display the following acknowledgment:
 * 
 *      "This product includes software written and developed 
 *       by Brian Adamson , Joe Macker 
 *       and William Chao, Justin Dean
 *       of the Naval Research Laboratory (NRL)." 
 *         
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the 
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/
#ifdef UNIX

#include "mprselPub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h> // for permissions flags

#include <unistd.h>  // for unlink()

static const char* MPRSEL_DEFAULT_KEY_FILE = "/tmp/mprsel";

// Upon success, this returns a pointer for
// storage of published MPRSEL position
extern "C" char* MPRSELMemoryInit(const char* keyFile, unsigned int size)
{
    if (!keyFile) keyFile = MPRSEL_DEFAULT_KEY_FILE;
    char* posPtr = ((char*)-1);
    int id = -1;
    
    // First read file to see if shared memory already active
    // If active, try to use it
    FILE* filePtr = fopen(keyFile, "r");
    if (filePtr)
    {
        if (1 == fscanf(filePtr, "%d", &id))
        {
            if (((char*)-1) != (posPtr = (char*)shmat(id, 0, 0)))
            {
                // Make sure pre-existing shared memory is right size
                if (size != *((unsigned int*)posPtr))
                {
                    MPRSELPublishShutdown((MPRSELHandle)posPtr, keyFile);
                    posPtr = (char*)-1;   
                }
            }
            else
            {
               perror("MPRSELPublishInit(): shmat() warning");       
            }
        }
        fclose(filePtr);
    }
    
    if (((char*)-1) == posPtr)
    {
        // Create new shared memory segment
        // and advertise its "id" in the keyFile
        id = shmget(0, (int)(size+sizeof(unsigned int)), IPC_CREAT | 
                    SHM_R| S_IRGRP | S_IROTH | SHM_W);
        if (-1 == id)
        {
            perror("MPRSELPublishInit(): shmget() error");
            return NULL;
        }
        if (((char*)-1) ==(posPtr = (char*)shmat(id, 0, 0)))
        {
            perror("MPRSELPublishInit(): shmat() error");
            struct shmid_ds ds;
            if (-1 == shmctl(id, IPC_RMID, &ds))
            {  
                perror("MPRSELPublishInit(): shmctl(IPC_RMID) error");
            }
            return NULL;
        }
        // Write "id" to "keyFile"
        if ((filePtr = fopen(keyFile, "w+")))
        {
            if (fprintf(filePtr, "%d", id) <= 0)
                perror("MPRSELPublishInit() fprintf() error");
            fclose(filePtr);
            memset(posPtr+sizeof(unsigned int), 0, size);
            *((unsigned int*)posPtr) = size;
            return (posPtr + sizeof(unsigned int));
        }
        else
        {
            perror("MPRSELPublishInit() fopen() error");
        }
        if (-1 == shmdt(posPtr)) 
            perror("MPRSELPublishInit() shmdt() error");
        struct shmid_ds ds;
        if (-1 == shmctl(id, IPC_RMID, &ds))
            perror("MPRSELPublishInit(): shmctl(IPC_RMID) error");
        return NULL;
    }
      
    if (((char*)-1) == posPtr) 
        return NULL;
    else
        return (posPtr + sizeof(unsigned int));
}  // end MPRSELPublishInit()

extern "C" void MPRSELPublishShutdown(MPRSELHandle mprHandle, const char* keyFile)
{
    char* ptr = (char*)mprHandle - sizeof(unsigned int);
    if (!keyFile) keyFile = MPRSEL_DEFAULT_KEY_FILE;
    if (-1 == shmdt((void*)ptr)) 
        perror("MPRSELPublishShutdown() shmdt() error");
    FILE* filePtr = fopen(keyFile, "r");
    if (filePtr)
    {
        int id;
        if (1 == fscanf(filePtr, "%d", &id))
        {
            struct shmid_ds ds;
            if (-1 == shmctl(id, IPC_RMID, &ds))
                perror("MPRSELPublishShutdown(): shmctl(IPC_RMID) error");
        }
        fclose(filePtr);
        if (unlink(keyFile)) 
            perror("MPRSELPublishShutdown(): unlink() error");
    }
    else
    {
        perror("MPRSELPublishShutdown(): fopen() error");
    }   
}  // end MPRSELPublishShutdown();


// Upon success, this returns a pointer for
// storage of published MPRSEL position
extern "C" MPRSELHandle MPRSELSubscribe(const char* keyFile)
{
   if (!keyFile) keyFile = MPRSEL_DEFAULT_KEY_FILE;
    char* posPtr = ((char*)-1);
    int id = -1;
    // First read file to see if shared memory already active
    // If active, try to use it
    FILE* filePtr = fopen(keyFile, "r");
    if (filePtr)
    {
        if (1 == fscanf(filePtr, "%d", &id))
        {
            if (((char*)-1) == (posPtr = (char*)shmat(id, 0, SHM_RDONLY)))
            {
               perror("MPRSELSubscribe(): shmat() error"); 
               fclose(filePtr);
               return NULL;      
            }
            else
            {
                fclose(filePtr);
                return (posPtr + sizeof(unsigned int));   
            }
        }
        else
        {
            perror("MPRSELSubscribe(): fscanf() error");  
            fclose(filePtr);
            return NULL; 
        }
    }
    else
    {
        perror("MPRSELSubscribe(): fopen() error"); 
        return NULL;      
    }
}  // end MPRSELSubscribe()

extern "C" void MPRSELUnsubscribe(MPRSELHandle mprHandle)
{
    char* ptr = (char*)mprHandle - sizeof(unsigned int);
    if (-1 == shmdt((void*)ptr)) 
        perror("MPRSELUnsubscribe() shmdt() error");
}  // end MPRSELUnsubscribe()

extern "C" void MPRSELPublishUpdate(MPRSELHandle mprHandle, const MPRSELPosition* currentPosition)
{
    memcpy((char*)mprHandle, (char*)currentPosition, sizeof(MPRSELPosition));   
}  // end MPRSELPublishUpdate()

extern "C" void MPRSELGetCurrentPosition(MPRSELHandle mprHandle, MPRSELPosition* currentPosition)
{
    memcpy((char*)currentPosition, (char*)mprHandle, sizeof(MPRSELPosition));
}  // end MPRSELGetCurrentPosition()

extern "C" unsigned int MPRSELSetMemory(MPRSELHandle mprHandle, unsigned int offset, 
                            const char* buffer, unsigned int len)
{
    char* ptr = (char*)mprHandle - sizeof(unsigned int);
    unsigned int size = (*((unsigned int*)ptr));
    
    // Make sure request fits into available shared memory
    if ((offset+len) > size)
    {
        fprintf(stderr, "MPRSELSetMemory() Request exceeds allocated shared memory!\n");
        unsigned int delta = offset + len - size;
        if (delta > len)
            return 0;
        else
            len -= delta;        
    }
    ptr = (char*)mprHandle + offset;
    memcpy(ptr, buffer, len);
    return len;
}  // end MPRSELSetMemory()

extern "C" unsigned int MPRSELGetMemorySize(MPRSELHandle mprHandle)
{
    char* ptr = (char*)mprHandle - sizeof(unsigned int);
    unsigned int size = *((unsigned int*)ptr);
    return size;   
}

extern "C" unsigned int MPRSELGetMemory(MPRSELHandle mprHandle, unsigned int offset, 
                            char* buffer, unsigned int len)
{
    char* ptr = (char*)mprHandle - sizeof(unsigned int);
    unsigned int size = *((unsigned int*)ptr);
    if (size < (offset+len))
    {
        unsigned int delta = offset + len - size;
        if (delta > len)
        {
            fprintf(stderr, "MPRSELGetMemory() Invalid request!\n");
             return 0;
        }
        else
        {
            len -= delta;
        }   
    }
    ptr = (char*)mprHandle + offset;
    memcpy(buffer, ptr, len);
    return len;
}  // end MPRSELGetMemory()
#endif //unix
