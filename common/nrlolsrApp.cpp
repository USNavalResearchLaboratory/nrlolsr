#include "nrlolsrApp.h"

NrlolsrApp::NrlolsrApp() 
 : nrlolsrObject(GetDispatcher(), GetSocketNotifier(), GetTimerMgr())
{
}

bool NrlolsrApp::OnStartup(int argc, const char*const* argv)
{
  //This will create a route table pass it to the nrlolsr object process commands and start
  //running the nrlolsr object


  //I remember creating the route table before processing the commands for a reason....
  //So we will go through the argvs, looking for the -z option which creates a zebraRouteMgr
  //instead of a system one before doing processCommands
  bool dozebra=false;
  for(int i = 1; i<argc;i++){
    if(!strcmp(argv[i],"-z")){
      dozebra = true;
    }
  }
  if(dozebra){
    routingTable = ProtoRouteMgr::Create(ProtoRouteMgr::ZEBRA);
  } else {
    routingTable=ProtoRouteMgr::Create(); 
  }
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

  //done with the routing table stuff now to process the rest of the commands
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

