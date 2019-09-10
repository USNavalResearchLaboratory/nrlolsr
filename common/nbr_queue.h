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
 *       by Brian Adamson, Joe Macker and Justin Dean of the 
 *       Naval Research Laboratory (NRL)." 
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

#ifndef _NBR_QUEUE
#define _NBR_QUEUE
 
#include "protokit.h"
#include "stdlib.h"
inline double InlineGetCurrentTime()
{
  struct timeval tv;
  ProtoSystemTime(tv);
  double current_time = (double)(tv.tv_sec&0x00ffffff) + ((double)tv.tv_usec)/1.0e06;
  return current_time;
}  


struct linknode {
  struct linknode *next;
  struct linknode *prev;
  class NbrTuple *object;
  double N_time;  //semi hack for double hop neighbors
};
// Prioritized FIFO queue
class NBRQueue
{
    // Members
    private:
        linknode *head, *tail;
	linknode *peek_ptr,*temp_ptr, *print_peek_ptr,*backup_peek;
	static int numlinks; // was used for debugging
	double holdTime;
    // Methods
    public:
	static const double         Default_Neighb_Hold_Time; 
        NBRQueue();
	NBRQueue(double holdtime);
        bool IsEmpty() {return (head == NULL);}
        void QueueObject(NbrTuple *theObject); //sorts on timeout value
        void QueueObject(NbrTuple *theObject,double sortvalue); //sorts on sortvalue
        void QueueObjectAddressSort(NbrTuple *theObject); //sorts based on N_addr
        NbrTuple *FindObject(ProtoAddress id1,ProtoAddress id2);
	NbrTuple *FindObject(ProtoAddress id);
	NbrTuple *FindNextObject(ProtoAddress id);
	//NbrTuple *FindObject2(nsaddr_t id);
	//NbrTuple *GetNextObject();
        NbrTuple *Head() {return head->object;}
        void RemoveCurrent();
	void Clear();
	int checkCurrent();
	void printpeek();
	void RestoreBackupPeek();
	void SetBackupPeek();
	NbrTuple * PeekInit();
	NbrTuple * PeekNext();
	NbrTuple * PrintPeekInit();
	NbrTuple * PrintPeekNext();
	bool SetHoldTime(double hold);
};   



class NbrTuple
{  
    friend class NBRQueue;
    // Members
    public:
        NbrTuple();
        NbrTuple(double holdtime);
	bool SetHoldTime(double hold);
        // (TBD) Compress type/version fields? 
        ProtoAddress                N_addr;
        ProtoAddress                N_2hop_addr; //address for neighbor
	ProtoAddress                subnetMask; //this really needs to be cleaned up
	UINT32                      N_spf;  //used in routing shortest path first
	bool                        N_spf_link_set; //set to true when outside app sets the link metric
	UINT32                      N_minmax; //used in min max routing
	bool                        N_minmax_link_set; //set to true when an outside app sets the link metric
	bool                       was_used; //used in routing caluclation for spf and minmax
	int                         N_status;  // ASYM_LINK SYM_LINK or MRP_LINK possible LOST_LINK only used in 1 hop list
	int                         N_macstatus; //LINK_UP LINK_DOWN LINK_DEFAULT
	UINT8                    N_willingness; //used to describe willingness;
	double                      N_sort;      // planed to be used in SOME list sorting
	double		            N_time;    // Node id of message source (list sorted by this value)
	double                      N_time2;
	int                         hop;       // number of hop neighbor
	int                         cdegree;    // used to find mprs current 
	int                         tdegree;   // used to find mprs total
	unsigned long               node_degree; //used by only by OPSF manet ext. 
	int                         seq_num;  // used by dupicate and topology tables
	double                      konectivity;  //used by historisis function
	int                         recievedHello; //set to 0 on sending hello 1 on recieving


	NBRQueue                    parents;  //queue of links
	NBRQueue                    children; //queue of links
	NBRQueue                    stepparents; //queue of links
    private:
	struct linknode *parent;
};

#endif // _NBR_QUEUE
