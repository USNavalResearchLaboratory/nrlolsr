#include "nrlolsr.h"
#include "protokit.h"


class NrlolsrApp : public ProtoApp 
{
 public:
  NrlolsrApp();
  bool OnStartup(int argc, const char*const* argv);
  bool ProcessCommands(int argc, const char*const* argv);
  void OnShutdown();

  //void recv(Packet *p,Handler *);//not quite sure how this works with protolib?
  Nrlolsr nrlolsrObject;
 private:
  ProtoRouteMgr* routingTable;
};



