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
 
#define __nbr_queue__
#include <string.h>
#include <math.h>

#include "nbr_queue.h"


const double NBRQueue::Default_Neighb_Hold_Time = 6.0;

int NBRQueue::numlinks=0;


NBRQueue::NBRQueue()
  : head(NULL), tail(NULL), peek_ptr(NULL)
{
  holdTime=Default_Neighb_Hold_Time;
  head=NULL;
  tail=NULL;
  peek_ptr=NULL;
  backup_peek=NULL;
  print_peek_ptr=NULL;
  temp_ptr=NULL;
}

NBRQueue::NBRQueue(double holdtime)
  : head(NULL), tail(NULL), peek_ptr(NULL)
{
  holdTime=holdtime;
  head=NULL;
  tail=NULL;
  peek_ptr=NULL;
  backup_peek=NULL;
  print_peek_ptr=NULL;
  temp_ptr=NULL;
}
bool
NBRQueue::SetHoldTime(double hold){
  if(hold>0){
    holdTime=hold;
    return true;
  }
  return false;
}
int number_of_queues=0;
int number_of_ups=0;
int avg_number=0;
void NBRQueue::QueueObject(NbrTuple *theObject)
{
  number_of_queues++;
  number_of_ups++;
  avg_number=number_of_ups/number_of_queues;
  //fprintf(stdout,"%d is average entry of QueueObject\n",avg_number);
  //  DMSG(8,"%f is HOLLLLLLLLLLLLLLLLLLD time\n",holdTime);
    struct linknode *prev = tail;
    struct linknode *newnode=new struct linknode;
    //fprintf(stdout,"  %d \n",numlinks++);
    newnode->object=theObject;
    newnode->N_time=InlineGetCurrentTime() + holdTime;
    theObject->parent=newnode;
    //    fprintf(stdout,"time in queueobject %f\n",theObject->N_time);
    while (prev)
    {
        if (theObject->N_time < prev->object->N_time)
        {
	  number_of_ups++;
            prev = prev->prev;  // Go up the queue
        }
        else
        {
	  newnode->prev=prev;
            if ((newnode->next = prev->next))
                newnode->next->prev = newnode;
            else
                tail = newnode;
            prev->next = newnode;
            return;
        }
    }
    
    // theObject goes to top of the queue
    if ((newnode->next = head))
        head->prev = newnode;
    else
        tail = newnode;
    newnode->prev = NULL;
    head = newnode;
}  // end NBRQueue::QueueObject() 

//added later to sort by network address instead of time value
void NBRQueue::QueueObjectAddressSort(NbrTuple *theObject){
  struct linknode *prev = tail;
  struct linknode *newnode=new struct linknode;
  //fprintf(stdout,"  %d \n",numlinks++);
  newnode->object=theObject;
  newnode->N_time=InlineGetCurrentTime() + holdTime;
  theObject->parent=newnode;
  while (prev)
    {
      if (theObject->N_addr.CompareHostAddr(prev->object->N_addr)>0)
        {
	  prev = prev->prev;  // Go up the queue
        }
      else
        {
	  newnode->prev=prev;
	  if ((newnode->next = prev->next))
	    newnode->next->prev = newnode;
	  else
	    tail = newnode;
	  prev->next = newnode;
	  return;
        }
    }
  
  // theObject goes to top of the queue
  if ((newnode->next = head))
    head->prev = newnode;
  else
    tail = newnode;
  newnode->prev = NULL;
  head = newnode;
}  // end NBRQueue::QueueObjectAddressSort()  


//added later to sort by sort value instead of time value
void NBRQueue::QueueObject(NbrTuple *theObject,double sortvalue)
{
  struct linknode *prev = tail;
  struct linknode *newnode=new struct linknode;
  //fprintf(stdout,"  %d \n",numlinks++);
  newnode->object=theObject;
  newnode->N_time=InlineGetCurrentTime() + holdTime;
  theObject->parent=newnode;
  while (prev)
    {
      if (theObject->N_sort < prev->object->N_sort)
        {
	  prev = prev->prev;  // Go up the queue
        }
      else
        {
	  newnode->prev=prev;
	  if ((newnode->next = prev->next))
	    newnode->next->prev = newnode;
	  else
	    tail = newnode;
	  prev->next = newnode;
	  return;
        }
    }
  
  // theObject goes to top of the queue
  if ((newnode->next = head))
    head->prev = newnode;
  else
    tail = newnode;
  newnode->prev = NULL;
  head = newnode;
}  // end NBRQueue::QueueObject() 

NbrTuple* NBRQueue::FindObject(ProtoAddress id1, ProtoAddress id2)
{
  peek_ptr=head;
  while (peek_ptr) {
    if ((peek_ptr->object->N_addr).HostIsEqual(id2)){
      //    if (peek_ptr->object->N_2hop_addr==id2){
      //      DMSG(8,"found first id\n");
      if(((peek_ptr->object)->parents).FindObject(id1)){
	return peek_ptr->object;
      }
      if(((peek_ptr->object)->stepparents).FindObject(id1)){
	return peek_ptr->object;
      }
    }
    peek_ptr=peek_ptr->next;
  }
  return NULL;
}
//NbrTuple* NBRQueue::FindObject2(nsaddr_t id)
//{
//  peek_ptr=head;
//  while (peek_ptr) {
//    if (peek_ptr->object->N_2hop_addr==id) 
//      return peek_ptr->object;
//    peek_ptr=peek_ptr->next;
//  }
//  return NULL;
//}

NbrTuple* NBRQueue::FindObject(ProtoAddress id)
{
  peek_ptr=head;
  //DMSG(12,"NBRQueue::FindObject looking for %s\n",id.HostAddressString());
  while (peek_ptr) {
    //DMSG(8,"%d ",peek_ptr->object->N_addr);
    // this next line will cause crash if object was erased in the wrong way
    // added this line to check for empty objects and skip them and then fix it
    if(peek_ptr->object!=NULL) { // shouldn't need this at all remove me
      //  DMSG(12," checking %s |",(peek_ptr->object->N_addr).HostAddressString());
      if ((peek_ptr->object->N_addr).HostIsEqual(id)){ 
	//	DMSG(12," found\n");
	return peek_ptr->object;
      } else {
	//	DMSG(12,"%s is not equal to ",id.HostAddressString());
	//DMSG(12,"%s \n",(peek_ptr->object->N_addr).HostAddressString());
      }    
    }
    else {
      DMSG(0,"mysterious null object still around! I am the ginnger bread man you can't catch me! LOSER");
    //  errorfix=1;
    //  fprintf(stdout,"removing mysterious null object /n");
    //  if(peek_ptr->prev) 
    //	peek_ptr->prev->next=peek_ptr->next;
    //  else
    //	head=peek_ptr->next;
    //  if(peek_ptr->next) 
    //	peek_ptr->next->prev=peek_ptr->prev;
    //  else
    //	tail=peek_ptr->prev;
    }
    //DMSG(8,"-");
    //DMSG(8,"%p/",peek_ptr->next);
    temp_ptr=peek_ptr;
    peek_ptr=peek_ptr->next;
    //if(errorfix){
    //  free(temp_ptr);
    //  errorfix=0;
    //}
  }
  //DMSG(8,"returning null \n");
  return NULL;
}

NbrTuple* NBRQueue::FindNextObject(ProtoAddress id)
{
  if(peek_ptr)
    peek_ptr=peek_ptr->next;
  while(peek_ptr) {
    if ((peek_ptr->object->N_addr).HostIsEqual(id)) {
      return peek_ptr->object;
    }
    peek_ptr=peek_ptr->next;
  }
  return NULL;
}
    
//NbrTuple* NBRQueue::GetNextObject()
//{
//    NbrTuple *theObject = head;
//    if (theObject)
//    {
//        if((head = head->next))
//            head->prev = NULL;
//        else
//            tail = NULL;
//    }
//    return theObject;
//}  // end NBRQueue::GetNextObject()
void NBRQueue::printpeek()
{
  //DMSG(8,"%p is peek ptr \n",peek_ptr);
}
void NBRQueue::RestoreBackupPeek()
{
  peek_ptr=backup_peek;
}
void NBRQueue::SetBackupPeek()
{
  backup_peek=peek_ptr;
}
int NBRQueue::checkCurrent()
{
  if(peek_ptr!=NULL)
    //DMSG(8,"time is %f and %f is experiation time \n",InlineGetCurrentTime(),peek_ptr->N_time);
    if(peek_ptr->N_time<InlineGetCurrentTime()){
      //      DMSG(8,"time is %f and %f is experiation time",CURRENT_TIME,peek_ptr->N_time);
      temp_ptr=peek_ptr;
      //RemoveCurrent();
      return 1;
    }
  return 0;
}
void NBRQueue::Clear()
{
  peek_ptr=head;
  while(peek_ptr!=NULL){
    temp_ptr=peek_ptr->next;
    //DMSG(8,"removing %d's pointer ",peek_ptr->object->N_addr);
    //fflush(stdout);
    //fprintf(stdout,"  %d \n",numlinks--);
    free(peek_ptr);
    peek_ptr=temp_ptr;
  }
  head=NULL;
  tail=NULL;
}
    
void NBRQueue::RemoveCurrent()
{
  if(peek_ptr==NULL){
    peek_ptr=head;
  }
  temp_ptr=NULL;
  //DMSG(8,"%p peek pointer in RemoveCurrent\n",peek_ptr->next);
  if(peek_ptr){
    if (peek_ptr->prev){
      temp_ptr=peek_ptr->prev;
      peek_ptr->prev->next = peek_ptr->next;
    }
    else {
      head = peek_ptr->next;
      temp_ptr = NULL;
    }
    if (peek_ptr->next)
      peek_ptr->next->prev = peek_ptr->prev;
    else
      tail = peek_ptr->prev;
    //fprintf(stdout,"  %d \n",numlinks--);
    free(peek_ptr);
    peek_ptr=temp_ptr;
  }
}  // end NBRQueue::Remove()
NbrTuple* NBRQueue::PeekInit()
{
  peek_ptr=head;
  if(peek_ptr!=NULL)
    return peek_ptr->object;
  return NULL;
}

NbrTuple* NBRQueue::PeekNext()
{
  if (peek_ptr!=NULL){
    peek_ptr=peek_ptr->next;
    if(peek_ptr!=NULL)
      return peek_ptr->object;
    return NULL;   // list has been traversed
  }
  else { 
    peek_ptr=head;
    if(peek_ptr!=NULL)  //object was removed and peek_ptr was pointing at null
      return peek_ptr->object;
    else
      return NULL;     //last object was removed  
  }
}

NbrTuple* NBRQueue::PrintPeekInit()
{
  print_peek_ptr=head;
  if(print_peek_ptr!=NULL)
    return print_peek_ptr->object;
  return NULL;
}

NbrTuple* NBRQueue::PrintPeekNext()
{
  if (print_peek_ptr!=NULL){
    print_peek_ptr=print_peek_ptr->next;
    if(print_peek_ptr!=NULL)
      return print_peek_ptr->object;
    return NULL;   // list has been traversed
  }
  else { 
    return NULL; 
  }
}

/***********************************************************************/
NbrTuple::NbrTuple(){
  N_spf = 128;//middle of the road value for default 0-255 for one link
  N_minmax = 128;//middle of the road value for default 0-255 for one link
  N_status = 0;
  N_old_status = 1;
  N_macstatus = 0;
  N_willingness = 0;
  N_sort = 0;
  N_time = 0;
  N_time2 = 0;
  hop = 0;
  cdegree = 0;
  tdegree = 0;
  node_degree = 0; //thanks brian!
  seq_num = 0;
  konectivity = 0;
  recievedHello = 0;
}
NbrTuple::NbrTuple(double hold){
  was_used = 0;
  N_spf = 128;//middle of the road value for default when 0-255 for one link
  N_spf_link_set = false; //this is set to true when an outside app sets the link metric
  N_minmax = 128;//middle of the road value for default 0-255 for one link
  N_minmax_link_set = false; //this is set to true when an outside app sets the link metric
  N_status = 0;
  N_willingness = 0;
  N_sort = 0;
  N_time = 0;
  N_time2 = 0;
  hop = 0;
  cdegree = 0;
  tdegree = 0;
  seq_num = 0;
  konectivity = 0;
  recievedHello = 0;
  parents.SetHoldTime(hold);
  children.SetHoldTime(hold);
  stepparents.SetHoldTime(hold);
}

bool
NbrTuple::SetHoldTime(double hold){
  bool returnvalue = true;
  returnvalue &= parents.SetHoldTime(hold);
  returnvalue &= children.SetHoldTime(hold);
  returnvalue &= stepparents.SetHoldTime(hold);
  return returnvalue;
}
/***********************************************************************/
