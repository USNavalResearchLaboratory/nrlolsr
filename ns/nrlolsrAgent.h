#include "nrlolsr.h"
#include "protokit.h"
#include "smfDupTree.h"


#include <nrlolsr/ns/protolibManetKernel.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>
#include <cmu-trace.h>
#include <priqueue.h>
#include <red.h>

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
  ProtolibManetKernel* protolibManetKernelPointer;
  ProtoRouteMgr* routingTable;
  SmfDuplicateTree duptable;
};



