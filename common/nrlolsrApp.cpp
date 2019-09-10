#include "nrlolsrApp.h"

NrlolsrApp::NrlolsrApp() 
 : nrlolsrObject(GetDispatcher(), GetSocketNotifier(), GetTimerMgr())
{
}

bool NrlolsrApp::OnStartup(int argc, const char*const* argv)
{
  routingTable=ProtoRouteMgr::Create(); 
  if(routingTable)
  {
    if(!routingTable->Open())
    {
      DMSG(0,"NrlolsrApp::OnStartup: Error Opening routing table\n");
      return false;
    }
  } 
  else 
  {
    DMSG(0,"NrlolsrApp::OnStartup: Error creating routing table\n");
    return false;
  }
  nrlolsrObject.SetOlsrRouteTable(routingTable);
  if(ProcessCommands(argc,argv))
  {
    nrlolsrObject.Start();
  } 
  else 
  {
    DMSG(0,"Error parsing commands in NrlolsrApp::OnStartup()\n");
    return false;
  }
  return true;
}  // end NrlolsrApp::OnStartup()

bool NrlolsrApp::ProcessCommands(int argc, const char*const* argv)
{
  return  nrlolsrObject.ProcessCommands(argc,argv);
}

void NrlolsrApp::OnShutdown()
{
  nrlolsrObject.Stop();
  routingTable->Close();
  delete routingTable;
  routingTable=NULL;
  return;
}

PROTO_INSTANTIATE_APP(NrlolsrApp)

