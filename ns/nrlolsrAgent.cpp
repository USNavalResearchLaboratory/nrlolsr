#include "nrlolsrAgent.h"

NrlolsrAgent::NrlolsrAgent() : nrlolsrObject(GetSocketNotifier(),GetTimerMgr())
{
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
  return true;
}

bool
NrlolsrAgent::ProcessCommands(int argc, const char*const* argv)
{
  bool printusage = false;
  char localinterfacename[256];
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"attach-protolibManetKernel")){
      i++;
      protolibManetKernelPointer = (ProtolibManetKernel*)TclObject::lookup(argv[i]);
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
    } 
  } else {
    DMSG(0,"NrlolsrAgent::GetRoute no attached routing table!\n");
  }
  return returnvalue;
}

void
NrlolsrAgent::recv(Packet *p,Handler *handle) //this can be called to recv either olsr packets or packets to be forwarded
{
  //  fprintf(stdout,"entering NrloslrAgent::recv\n");
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  
  if(ch->ptype() == PT_ProtolibManetKernel) { // send on up to Agent
    //    fprintf(stdout,"NrlolsrAgetn::recv is an olsr packet\n");
    //should only recv olsr packets all other packets are filtered out by port number in protolibManetKernel
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
    return;
  } else { // send packet back out interface
    /* check ttl */
    if (ih->ttl_ == 0){
      //      fprintf(stdout,"nrlolsrAgent is dropping packet because of ttl\n");
      drop(p, DROP_RTR_TTL);
      return;
    }
    //check to see if its a udp packet or a broadcast packet 
    if(ih->daddr()==IP_BROADCAST && ih->dport()!=-1){//it's broadcast send to mcastForward
        mcastForward(p); //its a broadcast packet so we forward under certain conditions      
    } else { //its has single destination find and send on way
      if(ch->num_forwards_==0) {
	ih->saddr() = here_.addr_;
      }
      nsaddr_t nextHop=GetRoute(ih->daddr());
      if(nextHop!=INVALID && (nextHop!=ch->prev_hop_ || ch->num_forwards_==0)){ //make sure we don't send it back up 
	//      fprintf(stdout,"nrlolsrAgent sending back to protoManetKernel and trying to foward it to %d\n",nextHop);
	protolibManetKernelPointer->forward(p,nextHop);
	return;
      }
      if(nextHop==INVALID){
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
NrlolsrAgent::mcastForward(Packet *p){ //this is used to forward multicast and returns true if packet was forwarded
  if(nrlolsrObject.FloodingIsOn()){
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    int  seqno=ch->uid_;
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
	protolibManetKernelPointer->bcastforward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	break;
      case Nrlolsr::SMPR:
	
	if(nrlolsrObject.GetMprSelectorList().FindObject(proto_prev_hop_addr)){ //returns a pointer to a tuple but we only need to know if it exists
	  //fprintf(stdout,"forwarding because %d is last hop who selected me %s as mpr\n",prevaddr,nrlolsrObject.GetMyAddress().GetHostString());
	  protolibManetKernelPointer->bcastforward(p);      
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	} else { //this node does not forward the packet
	  Packet::free(p);
	  //fprintf(stdout,"not forwarding because %d did not select me %s as mpr\n",prevaddr,nrlolsrObject.GetMyAddress().GetHostString());
	}
	break;
      case Nrlolsr::NSMPR:
	if(!nrlolsrObject.GetMprSelectorList().IsEmpty()){ //if list is not empty forward on the packet
	  //current nod is an mpr of someone
	  protolibManetKernelPointer->bcastforward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	} else { //this node is not an mpr so it does not forward packets
	  Packet::free(p);
	}
	break;
      case Nrlolsr::NOTSYM:
	tuple = nrlolsrObject.GetNbrList().FindObject(proto_prev_hop_addr);
	if(tuple){ //entry exists check to see if its symetric
	  if(tuple->N_status==ASYM_LINK || tuple->N_status==LOST_LINK){ //link does not exists so forward packet on just in case
	    protolibManetKernelPointer->bcastforward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	  } else { //we know about nbr see if they selected us as mpr 
	    if(nrlolsrObject.GetMprSelectorList().FindObject(proto_prev_hop_addr)){ //returns a pointer to a tuple but we only need to know if it exists
	      protolibManetKernelPointer->bcastforward(p);//nbr selected us as mpr
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	    } else { //neighbor is sym and did not select us as mpr so don't forward
	      Packet::free(p);
	    }
	  }
	} else {//we don't know neighbor so we forward it
	  protolibManetKernelPointer->bcastforward(p);
    DMSG(2,"Node %s is forwarding broadcast packet\n",nrlolsrObject.GetMyAddress().GetHostString());
	}
	break;
      case Nrlolsr::MPRCDS:
      case Nrlolsr::ECDS:
	if(nrlolsrObject.IsForwarder()){
	  //node is part of the forwarding tree
	  //fprintf(stderr,"%s is a forwarder!\n",nrlolsrObject.GetMyAddress().GetHostString());
	  protolibManetKernelPointer->bcastforward(p);
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
