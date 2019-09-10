#include "nrlolsrAgent.h"

NrlolsrAgent::NrlolsrAgent() : nrlolsrObject(GetSocketNotifier(),GetTimerMgr())
{
  smfDelayForwardTimer.SetListener(this,&NrlolsrAgent::OnSmfDelayForwardTimeout);
  numberOfStoredPackets=0;
  smfDelayForward = 0;
}

bool 
NrlolsrAgent::OnStartup(int argc, const char*const* argv)
{
  routingTable=ProtoRouteMgr::Create(); 
  if(routingTable){
    if(!routingTable->Open((void*)&here_.addr_)){
      DMSG(0,"NrlolsrAgent::OnStartup: Error Opening routing table\n");
      return false;
    }
  } else {
    DMSG(0,"NrlolsrAgent::OnStartup: Error creating routing table\n");
    return false;
  }
  nrlolsrObject.SetOlsrRouteTable(routingTable);
  if(ProcessCommands(argc,argv)){
    nrlolsrObject.Start();
  } else {
    DMSG(0,"Error parsing commands in NrlolsrAgent::OnStartup()\n");
    return false;
  }
  int statefulWindowSize = 32768;  // 2^15, or 32 kilobits wide
  int thePast = 1048576;           // 2^20, or 1 megabits wide
  if(!duptable.Init(statefulWindowSize,thePast)){
    DMSG(0,"Error setting up duptable with window size of %d and timeout value of %d\n",statefulWindowSize,thePast);
    return false;
  }
  for (int i = 0; i < SMF_MAX_BUFFER_SIZE;i++)
  {
    forwardPacketArray[i] = NULL;
  }
  return true;
}

bool
NrlolsrAgent::ProcessCommands(int argc, const char*const* argv)
{
  bool printusage = false;
  char localinterfacename[256];
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"attach-protolibmk")){
      i++;
      protolibManetKernelPointer = (ProtolibMK*)TclObject::lookup(argv[i]);
    } else if (!strcmp(argv[i],"-smfdelayforward")){
      i++;
      smfDelayForward = atof(argv[i]);
    } else {
      //couldn't process it send it off to nrlolsrObject to be processed
      int startindex=i;//position of first option
      int endindex=i;
      if(startindex==argc-1){
	nrlolsrObject.ProcessCommands(endindex-startindex+2,&argv[startindex-1]);//the minus one because we start at 1 with processCommands
      } else { //find the end
	endindex++;
	while(strncmp(argv[endindex],"-",1)) {
	  endindex++;
	  if(endindex==argc) break;
	}
	endindex--;
	printusage = !nrlolsrObject.ProcessCommands(endindex-startindex+2,&argv[startindex-1]);//the minus one because we start at 1 with processCommands
      }
      i=endindex;
    }
  }
  if(printusage){
    return false;
  }    
  return true;
}

void 
NrlolsrAgent::OnShutdown()
{
  if(smfDelayForwardTimer.IsActive()) smfDelayForwardTimer.Deactivate();
  nrlolsrObject.Stop();
  routingTable->Close();
  delete routingTable;
  routingTable=NULL;
  return;
}
nsaddr_t
NrlolsrAgent::GetRoute(SIMADDR dest)
{
  nsaddr_t returnvalue=INVALID;
  ProtoAddress dst,gw;
  unsigned int ifIndex, prefixLen = 32;
  int metric;
  dst.SimSetAddress(dest);
  if(routingTable){
    if(routingTable->GetRoute(dst,prefixLen,gw,ifIndex,metric)){
      returnvalue=gw.SimGetAddress();
      if(!gw.IsValid()){
		returnvalue=dst.SimGetAddress();
      }
    } else {
	  DMSG(4,"NrlolsrAgent::GetRoute %s has no route to %d destination\n",nrlolsrObject.GetMyAddress().GetHostString(),dest);
	}
  } else {
    DMSG(0,"NrlolsrAgent::GetRoute no attached routing table!\n");
  }
  return returnvalue;
}

void
NrlolsrAgent::recv(Packet *p,Handler *handle) //this can be called to recv either olsr packets or packets to be forwarded
{
  //DMSG(0,"bunny here in recv\n");
  //  fprintf(stdout,"entering NrloslrAgent::recv\n");
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  
  if(ch->ptype() == PT_PROTOLIBMK) { // send on up to Agent
    //    fprintf(stdout,"NrlolsrAgetn::recv is an olsr packet\n");
    //should only recv olsr packets all other packets are filtered out by port number in protolibMK
    ProtoSocket::Proxy* proxy = nrlolsrObject.GetSocket().GetHandle();
    NsProtoSimAgent::UdpSocketAgent* udpSocketAgent = static_cast<NsProtoSimAgent::UdpSocketAgent*>(proxy);
    //(dynamic_cast<Agent*>(nrlolsrObject.GetSocket().GetHandle()))->recv(p,0);
    Agent* theAgent = static_cast<Agent*>(udpSocketAgent);
    if(theAgent){
      theAgent->recv(p,0);
    } else {
      Packet::free(p);
      DMSG(0,"NrlolsrAgent::recv theAgent is NULL!\n");
    }
    //DMSG(0,"bunny here was an olsr packet\n");
    return;
  } else { // send packet back out interface
    /* check ttl */
    //DMSG(0,"sending back out interface bunny\n");
    if (ih->ttl_ == 0){
      //      fprintf(stdout,"nrlolsrAgent is dropping packet because of ttl\n");
      drop(p, DROP_RTR_TTL);
      return;
    }
    //check to see if its a udp packet or a broadcast packet 
    if(ih->daddr()==IP_BROADCAST && ih->dport()!=-1){//it's broadcast send to mcastForward
	//DMSG(0,"bunny here its a bcast packet!\n");  
        mcastForward(p); //its a broadcast packet so we forward under certain conditions      
    } else { //its has single destination find and send on way
      if(ch->num_forwards_==0) {
		ih->saddr() = here_.addr_;
      }
      nsaddr_t nextHop=GetRoute(ih->daddr());
      if(nextHop!=INVALID && (nextHop!=ch->prev_hop_ || ch->num_forwards_==0)){ //make sure we don't send it back up 
		DMSG(6,"%d is sending packet to %d back to protoManetKernel to forward to the next hop %d\n",here_.addr_,ih->daddr(),nextHop);
		//      fprintf(stdout,"nrlolsrAgent sending back to protoManetKernel and trying to foward it to %d\n",nextHop);
		protolibManetKernelPointer->forward(p,nextHop);
		return;
      }
      if(nextHop==INVALID){
		ProtoAddress dst,gw;
		unsigned int ifIndex, prefixLen = 32;
		int metric;
		dst.SimSetAddress(ih->daddr());
		if(nrlolsrObject.localHnaRouteTable.FindRoute(dst,prefixLen,gw,ifIndex,metric)) {
		  //packet is for the local node so lets modify it and send it up to a listening agent
		  ih->dst_.addr_=here_.addr_;
		  nextHop=here_.addr_;
		  protolibManetKernelPointer->forward(p,nextHop);
		  return;
		} else {
		  DMSG(0,"nrlolsrAgent dropping packet because nextHop is INVALID couldn't find route to %d\n",ih->daddr());
		}
		//      fprintf(stdout,"nrlolsrAgent dropping packet because nextHop is INVALID couldn't find route to %d\n",ih->daddr());
	  } else if(nextHop==ch->prev_hop_) {
		//      fprintf(stdout,"nrlolsrAgent dropping packet because nextHop is the same as the last hop which is %d\n",ih->daddr());
      } else {
		//      fprintf(stdout,"nrlolsrAgent dropping packet becasue ch->num_forwards!= 0\n");
      }
      drop(p,DROP_RTR_NO_ROUTE);
    } //end else of isbroadcast
  }
}
void
NrlolsrAgent::delayedMcastForward(Packet *p)
{
    DMSG(0,"NrlolsrAgent::delayedMcastForward(*p) with delay =%f\n",smfDelayForward);
    if(smfDelayForward == 0) //no delay in forwarding
    {
        DMSG(0,"NrlolsrAgent::delayedMcastForward: Forwarding with no delay\n");
        protolibManetKernelPointer->bcastforward(p);
    }
    else // there is some delay
    {
         //set delay to a random number between 0 and max delay
        double delay = UniformRand(smfDelayForward);
        if(smfDelayForwardTimer.IsActive())//timer is already set just add the packet to the queue if its not full
        {
            numberOfStoredPackets++;
            if(numberOfStoredPackets == SMF_MAX_BUFFER_SIZE)
            {
                DMSG(0,"NrlolsrAgent::delayedMcastForward: buffer full at time\n");
                OnSmfDelayForwardTimeout(smfDelayForwardTimer);//fire off the buffer as its full
                //reset the buffer and reinstall the timer
                numberOfStoredPackets = 0;
                forwardPacketArray[numberOfStoredPackets] = p;
                smfDelayForwardTimer.SetInterval(delay);
                smfDelayForwardTimer.SetRepeat(0);
                GetTimerMgr().ActivateTimer(smfDelayForwardTimer);
            } 
            else
            {
                DMSG(0,"NrlolsrAgent::delayedMcastForward: timer active just adding to buffer at %d\n",numberOfStoredPackets);
                forwardPacketArray[numberOfStoredPackets] = p;
            }
        }
        else
        { //timer is not active so set a random interval and install the timer
            DMSG(0,"NrlolsrAgent::delayedMcastForward: Timer not active. Adding with delay of %f\n",delay);
            if(numberOfStoredPackets != 0)
            {
                DMSG(0,"NrlolsrAgent::DelayedMcastForward: WARNING! numberOfStoredPackets != 0 when it should be");
                exit(0);
            }
            forwardPacketArray[numberOfStoredPackets] = p; //numberOfStoredPackets should always be 0 here
            smfDelayForwardTimer.SetInterval(delay);
            smfDelayForwardTimer.SetRepeat(0);
            GetTimerMgr().ActivateTimer(smfDelayForwardTimer);
        }
    }
    return;
}
bool
NrlolsrAgent::OnSmfDelayForwardTimeout(ProtoTimer &theTimer)
{
    DMSG(0,"NrlolsrAgent::OnSmfDelayForwardTimeout: Timeout sending %d packets now\n",numberOfStoredPackets);
    numberOfStoredPackets = 0;
    if(smfDelayForwardTimer.IsActive())
    {
        smfDelayForwardTimer.Deactivate();
    }
    //go through the packets and send them off
    Packet *p;
    p = forwardPacketArray[0];
    int index = 0;
    while(p)
    {
        protolibManetKernelPointer->bcastforward(p);
        forwardPacketArray[index] = NULL;
        index++;
        if(index == SMF_MAX_BUFFER_SIZE)
        {
            p = NULL;
        }
        else
        {
            p = forwardPacketArray[index];
        }
    }
    return false;
}

void
NrlolsrAgent::mcastForward(Packet *p){ //this is used to forward multicast and returns true if packet was forwarded

  //DMSG(0,"here bunny in forwarding multicast packet!\n");
  if(nrlolsrObject.FloodingIsOn()){
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    int  seqno=ch->uid_;
	//int seqno=ih->fid_;
    int saddr = (int)ih->src_.addr_; 
    int prevaddr = (int)ch->prev_hop_; 
    
    ProtoAddress proto_source_addr;
    proto_source_addr.SetRawHostAddress(ProtoAddress::SIM,(char*)&saddr,4);
    
    ProtoAddress proto_prev_hop_addr;
    proto_prev_hop_addr.SetRawHostAddress(ProtoAddress::SIM,(char*)&prevaddr,4);
    //check to see if were are originator node.
    if(nrlolsrObject.GetMyAddress().HostIsEqual(proto_source_addr)){
      protolibManetKernelPointer->bcastforward(p);
      return; //we are done no more checking needed
    }
    DMSG(2,"Node %s is calling isdup with ",nrlolsrObject.GetMyAddress().GetHostString());
    DMSG(2,"source=%s seqno=%d, last hop = Node %d\n",proto_source_addr.GetHostString(),seqno, prevaddr);
    
    bool wasdup = duptable.IsDuplicate((unsigned int)Scheduler::instance().clock(), 
                                       seqno, sizeof(seqno) << 3,
                                       proto_source_addr.GetRawHostAddress(),proto_source_addr.GetLength() << 3);
    if(wasdup){
      DMSG(2, "IsDuplicate returned true\n");
      Packet::free(p);
      return;
    } else { //packet was not a duplicate forward packet back out and return;
      //smart/mpr flooding logic here.
      DMSG(2, "IsDuplicate returned false\n");
      NbrTuple* tuple;
      switch(nrlolsrObject.GetFloodingType()){
      case Nrlolsr::SIMPLE:
        delayedMcastForward(p);
	//protolibManetKernelPointer->bcastforward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	break;
      case Nrlolsr::SMPR:
	
	if(nrlolsrObject.GetMprSelectorList().FindObject(proto_prev_hop_addr)){ //returns a pointer to a tuple but we only need to know if it exists
	  //fprintf(stdout,"forwarding because %d is last hop who selected me %s as mpr\n",prevaddr,nrlolsrObject.GetMyAddress().GetHostString());
	  //protolibManetKernelPointer->bcastforward(p);      
          delayedMcastForward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	} else { //this node does not forward the packet
	  Packet::free(p);
	  //fprintf(stdout,"not forwarding because %d did not select me %s as mpr\n",prevaddr,nrlolsrObject.GetMyAddress().GetHostString());
	}
	break;
      case Nrlolsr::NSMPR:
	if(!nrlolsrObject.GetMprSelectorList().IsEmpty()){ //if list is not empty forward on the packet
	  //current nod is an mpr of someone
	  //protolibManetKernelPointer->bcastforward(p);
          delayedMcastForward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	} else { //this node is not an mpr so it does not forward packets
	  Packet::free(p);
	}
	break;
      case Nrlolsr::NOTSYM:
	tuple = nrlolsrObject.GetNbrList().FindObject(proto_prev_hop_addr);
	if(tuple){ //entry exists check to see if its symetric
	  if(tuple->N_status==ASYM_LINK || tuple->N_status==LOST_LINK){ //link does not exists so forward packet on just in case
	    //protolibManetKernelPointer->bcastforward(p);
            delayedMcastForward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	  } else { //we know about nbr see if they selected us as mpr 
	    if(nrlolsrObject.GetMprSelectorList().FindObject(proto_prev_hop_addr)){ //returns a pointer to a tuple but we only need to know if it exists
	      //protolibManetKernelPointer->bcastforward(p);//nbr selected us as mpr
              delayedMcastForward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	    } else { //neighbor is sym and did not select us as mpr so don't forward
	      Packet::free(p);
	    }
	  }
	} else {//we don't know neighbor so we forward it
	  //protolibManetKernelPointer->bcastforward(p);
          delayedMcastForward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	}
	break;
      case Nrlolsr::MPRCDS:
      case Nrlolsr::ECDS:
	if(nrlolsrObject.IsForwarder()){
	  //node is part of the forwarding tree
	  //fprintf(stderr,"%s is a forwarder!\n",nrlolsrObject.GetMyAddress().GetHostString());
	  //protolibManetKernelPointer->bcastforward(p);
          delayedMcastForward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	} else {
	  //node is not part of the tree and doesn't need to forward
	  Packet::free(p);
	}
	break;
      default:
	fprintf(stderr,"NrlolsrAgent::mcastForward(p): Error trying to forward broadcast pack because floodingType %d is not defined\n",nrlolsrObject.GetFloodingType());
      }
    }
  } else { //flooding is not on
    struct hdr_ip *ih = HDR_IP(p);
    int saddr = (int)ih->src_.addr_; 
    ProtoAddress proto_source_addr;
    proto_source_addr.SetRawHostAddress(ProtoAddress::SIM,(char*)&saddr,4);
    //check to see if were are originator node.
    if(nrlolsrObject.GetMyAddress().HostIsEqual(proto_source_addr)){
      protolibManetKernelPointer->bcastforward(p);
      return; //we are done no more checking needed
    }
    else
        Packet::free(p);
  }
  return;
}


static class NsNrlolsrAgentClass : public TclClass
{
public:
  NsNrlolsrAgentClass() : TclClass("Agent/NrlolsrAgent") {}
  TclObject *create(int argc, const char*const* argv)
  {return (new NrlolsrAgent());}
} class_nrlolsragent;
