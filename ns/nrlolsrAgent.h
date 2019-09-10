#include <nrlolsr.h>
#include <protokit.h>
#include <smfDupTree.h>


#include <nsProtoManetKernel.h>
//#include <protolib/ns/nsProtoManetKernel.h> //this uses the older cvs directory structure
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>
#include <cmu-trace.h>
#include <priqueue.h>
#include <red.h>

#define SMF_MAX_BUFFER_SIZE 50
class NrlolsrAgent : public NsProtoSimAgent 
{
 public:
  NrlolsrAgent();
  bool OnStartup(int argc, const char*const* argv);
  bool ProcessCommands(int argc, const char*const* argv);
  void OnShutdown();
  nsaddr_t GetRoute(SIMADDR dest);
  //the next function is a hack for sure but it mantians seperation between protoManetKernel and the nrlolsrAgent
  void recv(Packet *p,Handler *);//used for udp packet forwarding when handle=NULL and used for multicast forwarding when handler does not equal null
  void mcastForward(Packet *p); //called by recv when handler is not null
  Nrlolsr nrlolsrObject;
 private:
  ProtolibMK* protolibManetKernelPointer;
  ProtoRouteMgr* routingTable;
  SmfDuplicateTree duptable;
 
  double smfDelayForward;
  ProtoTimer smfDelayForwardTimer;
  Packet* forwardPacketArray[SMF_MAX_BUFFER_SIZE]; //stores the packets for delayed forwarding
  int numberOfStoredPackets; //used to keep track of the number of stored packets in the buffer
  void delayedMcastForward(Packet *p); //called by mcastForward to take care of any delayed forwarding attempting to avoid collisions
  bool OnSmfDelayForwardTimeout(ProtoTimer &theTimer); //send all packets in the forwardPacketArray when it fires off.
};



