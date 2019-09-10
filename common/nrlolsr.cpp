 #include "nrlolsr.h"

#ifndef SIMULATE //real world code requires more things which all of which are not included in protolib simulation code
Nrlolsr::Nrlolsr(ProtoDispatcher& theDispatcher, ProtoSocket::Notifier& theNotifier, ProtoTimerMgr& theTimer)
 : socket(ProtoSocket::UDP), mac_control_socket(ProtoSocket::UDP),
   recvPipe(ProtoPipe::MESSAGE) , smf_pipe(ProtoPipe::MESSAGE) , gui_pipe(ProtoPipe::MESSAGE) , sdt_pipe(ProtoPipe::MESSAGE)
#ifdef SMF_SUPPORT
   , cap_rcvr(NULL)
#endif // SMF_SUPPORT
#else
Nrlolsr::Nrlolsr(ProtoSocket::Notifier& theNotifier, ProtoTimerMgr& theTimer)
 : socket(ProtoSocket::UDP), mac_control_socket(ProtoSocket::UDP)
#endif //if not else SIMULATE
{ 
#ifndef SIMULATE //simulation does not have dispatcher
	dispatcher = &theDispatcher;
#endif
  isRunning = false;
  isSleeping = false;
  timerMgrPtr = &theTimer;
  socket.SetNotifier(&theNotifier); 
  socket.SetListener(this,&Nrlolsr::OnSocketEvent);

  mac_control_socket.SetNotifier(&theNotifier);
  mac_control_socket.SetListener(this,&Nrlolsr::OnMacControlSocketEvent);
  mac_control_port = 6005; //default mac control port

  //pipe setup
#ifndef SIMULATE //simulations do not support pipes
  recvPipe.SetNotifier(&theNotifier);
  recvPipe.SetListener(this,&Nrlolsr::OnRecvPipeMessage);
  strncpy(recvPipeName,"nrlolsr", 256); // default control pipe name for nrlolsr
#endif // !SIMULATE 
  
  updateSmfForwardingInfo = false; //set to true when mpr selector list changes and send at end of parcing hello message which changed mpr selector list
  floodingType = SMPR;  //default forwarding engine is set to source based mpr flooding.
  localNodeIsForwarder=false;
  localNodeIsForwarder_old=false; //don't need to print anything out till the local node is a forwarder.  This variable is only used with sdt messaging
  floodingOn = true;//set to true when flooding command is used
  fastreroute = true;
  unicastRouting = true;
  SDTOn = false;
  //DMSG(6,"Enter: Nrlolsr::Nrlolsr()\n");

  Neighb_Hold_Time = 6.0; //is default value changed on Start();
  qosvalue=0;
  userDefBroadcast = false;

  ipvMode = ProtoAddress::IPv4;
  hostMaskLength = 32;
#ifdef SIMULATE
  ipvMode = ProtoAddress::SIM;
#endif //SIMULATE
  
  // hello timer stuff
  Hello_Interval = .5 ; //in seconds
  Hello_Timeout_Factor = 6.0; 
  Hello_Jitter =.5; //% of Hello_Interval
  helloPadding=0;

  //TC timer stuff
  dotcextra = false; //if true non standard tc messages will be sent
  TC_Interval=2.0;
  TC_Timeout_Factor=5.0;
  TC_Jitter =.5; //% of TC_Interval 

  //HNA timer stuff
  dohna = true;
  hnaFromFile =  false;
  HNA_Interval=15.0;
  HNA_Timeout_Factor=90;
  HNA_Jitter=.1;
  localHnaRouteTable.Init();

  //forwarding delay
  fdelay = 0;

  //set class variables
  D_Hold_Time=15.0; //in seconds

  // init hysteris values
  T_up = .4;
  T_down = .15;
  alpha = .7; //weight given to past 


  //default state
  olsr_port_number = 698;
  noerrors = 1;
  allLinks=false;
  
  helloUseUnicast=false;
  helloUseUnicastOpt=false;
  helloSentBcastOnly=0;
  
  tcSlowDown=false;
  tcSlowDownFactor=1; //factor of how much slower tcs are being sent
  tcSlowDownState=0; //4 valid states 0-1-2-3
  

  dospf=false;
  dominmax=false;
  dorobust=false;
  fuzzyflooding=false;
	recordhellohistory=false;
  
  localNodeDegree = 0;
  localWillingness = WILL_DEFAULT;

  pseqno = 0;
  seqno = 0;
  mssn = 0;

  //init default debug values
  olsrDebugValue = 0;
  SetDebugLevel(olsrDebugValue);

  //create a routing table
  //realRouteTable=ProtoRouteMgr::Create(); // this is now passed to us via SetOlsrRouteTable
  
  //timer stuff
  hello_timer.SetListener(this,&Nrlolsr::OnHelloTimeout);
  hello_jitter_timer.SetListener(this,&Nrlolsr::OnHelloTimeout);
  sendHelloTimerOn=true;

  tc_timer.SetListener(this,&Nrlolsr::OnTcTimeout);
  tc_jitter_timer.SetListener(this,&Nrlolsr::OnTcTimeout);
  sendTcTimerOn=true;

  hna_timer.SetListener(this,&Nrlolsr::OnHnaTimeout);
  hna_jitter_timer.SetListener(this,&Nrlolsr::OnHnaTimeout);
  sendHnaTimerOn=true;
    //DMSG(6,"Exit: Nrlolsr::Nrlolsr()\n");
  delayed_forward_timer.SetListener(this,&Nrlolsr::OnDelayedForwardTimeout);
  
  delay_smf_off_timer.SetListener(this,&Nrlolsr::OnDelaySmfOffTimeout);
 
  static_run_timer.SetListener(this,&Nrlolsr::OnStaticRunTimeout); 
  static_run_timer.SetInterval(0);
  // LP 8-30-05 - added
#ifdef OPNET
  total_Hello_sent =  total_Hello_rcv = total_TC_sent = total_TC_rcv = 0;
  Hello_sent_changed_flag = TC_sent_changed_flag = Hello_rcv_changed_flag = OPNET_FALSE;
  TC_rcv_changed_flag = MPR_increased_flag = MPR_decreased_flag = OPNET_FALSE;
#endif
  // end LP 

}

bool 
Nrlolsr::SetOlsrBroadcastAddress(const char* addrname,const char* netmask){
  bool returnvalue = true;
  userDefBroadcast = true;
  returnvalue &= userDefNetBroadAddr.ResolveFromString(addrname);
  userDefBroadMaskLength=atoi(netmask);
  return returnvalue;
}

bool
Nrlolsr::SetOlsrInterfaceAddress(const char* name){
  //DMSG(6,"Enter: Nrlolsr::SetInterfaceAddress(name %s)\n", name);
  strncpy(interfaceName,name,256);
  if(realRouteTable){
    interfaceIndex = realRouteTable->GetInterfaceIndex(interfaceName);
	if(!realRouteTable->GetInterfaceName(interfaceIndex,interfaceName,256)){
		DMSG(0,"Nrlolsr::SetOlsrInterfaceAddress: Error finding interfaceName from index %d\n",interfaceIndex);
		return false;
	}
    return interfaceIndex > 0; 
  }
  DMSG(0,"Nrlolsr::SetInterfaceAddress Error SetOlsrRouteTable must be called before this function!\n");
  return false;
  //DMSG(6,"Exit: Nrlolsr::SetInterfaceAddress(name %s)\n", name); 
}
bool
Nrlolsr::SetOlsrIPv4(bool ipv4mode){
  if(ipv4mode){
    ipvMode = ProtoAddress::IPv4;
    hostMaskLength = 32;
  } else {
    ipvMode = ProtoAddress::IPv6;
    hostMaskLength = 128;
  }
  return true;
}   

bool
Nrlolsr::SetOlsrPort(int portnumber){
  if(socket.IsOpen()){
    broadAddr.SetPort(portnumber);
    olsr_port_number=portnumber;
    if(!(socket.Bind(olsr_port_number))){
      DMSG(0,"Nrlolsr::SetOlsrPort error setting socket to port %d\n",portnumber);
      return false;
    }
  } else {
    olsr_port_number = portnumber;
  }
  return true;
}//end Nrlolsr::SetOlsrMacControlPort
bool
Nrlolsr::SetOlsrMacControlPort(int portnumber){
  mac_control_port=portnumber;
  if(mac_control_socket.IsOpen()){
    if(!(mac_control_socket.Bind(mac_control_port))){
      DMSG(0,"Nrlolsr::SetOlsrMacControlPort error setting mac_control_socket to port %d\n",portnumber);
      return false;
    }
  }
  return true;
}//end Nrlolsr::SetOlsrMacControlPort

bool
Nrlolsr::SetOlsrDebugLevel(int debuglvl){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrDebugLevell(debuglvl %d)\n", debuglvl);
  if(debuglvl>=0){
    olsrDebugValue = debuglvl;
    SetDebugLevel(olsrDebugValue);
    //DMSG(6,"Exit: Nrlolsr::SetOlsrDebugLevel(debuglvl %d)\n", debuglvl);
    return true;
  }
//DMSG(6,"Exit: Nrlolsr::SetOlsrDebugLevel(debuglvl %d)\n", debuglvl);
  return false;
}
bool 
Nrlolsr::SetOlsrDebugLog(const char* logfilename){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrDebugLog(logfilename %s)\n", logfilename);
  CloseDebugLog();
  //DMSG(6,"Exit: Nrlolsr::SetOlsrDebugLog(logfilename %s)\n", logfilename);
  return OpenDebugLog(logfilename);
}
bool
Nrlolsr::SetOlsrStatic(double runtime){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrStatic(runtime %f\n",runtime);
  if(runtime > 0) {
    if(isRunning){//called after startup we need to install the timer ourselves
      if(static_run_timer.IsActive()) static_run_timer.Deactivate();
      static_run_timer.SetInterval(runtime);
      static_run_timer.SetRepeat(0);
      if(!timerMgrPtr) {
        timerMgrPtr->ActivateTimer(static_run_timer);
      } else {
        DMSG(0,"Nrlolsr::SetOlsrStatic: Error. timerMgrPtr is NULL!\n");
      }
    } else { //called on command line or after we shut it down so just set the interval and let startup take care of things
      static_run_timer.SetInterval(runtime);
      static_run_timer.SetRepeat(0);
    }
  } else if (runtime == -1) { //a turn back on command
    if(static_run_timer.IsActive()) static_run_timer.Deactivate();
    if(!isRunning){
      Restart();
    } else {
      DMSG(0,"Nrlolsr::SetOlsrStatic: Warning. Calling this function with a runtime of -1 when nrlolsr has already started will only reset the static_run_timer\n");
    }
  } else if (runtime == 0){ //basiclly a shutdown command (if this is called on the command line startup will turn timers back on)
    if(isRunning){
      if(static_run_timer.IsActive()) static_run_timer.Deactivate();
      Sleep();
    } else {
      DMSG(0,"Nrlolsr::SetOlsrStatic: Warning a runtime of 0 is a noop when nrlolsr has not yet started\n");
    }
  } else {
    DMSG(0,"Nrlolsr::SetOlsrStatic: Error.  runtime \"%f\" is not -1 or between 1-MAX_DOUBLE.",runtime);
    return false;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrStatic(runtime %f\n",runtime);
  return true;  
}
bool
Nrlolsr::SetOlsrHelloInterval(double interval){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHelloInterval(interval %f)\n",interval);
  if(interval>0){
    Hello_Interval = interval;
    Neighb_Hold_Time = Hello_Timeout_Factor*Hello_Interval;     
    Mantissa_Hello_Hold_Interval = doubletomantissa(Neighb_Hold_Time);
    Mantissa_Hello_Interval = doubletomantissa(Hello_Interval);
		hello_timer.SetInterval(Hello_Interval);
	} else {
    DMSG(0,"-hi(Hello Interval in seconds) value not positive\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloInterval(interval %d)\n",interval);
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloInterval(interval %d)\n",interval);
  return 1;
}
bool
Nrlolsr::SetOlsrHelloJitter(double jitter){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHelloJitter(jitter %f)\n",jitter);
  if(jitter>=0 && jitter < 1) {
    Hello_Jitter = jitter;
  } else {
    DMSG(0,"hj(Hello Jitter in percent of hello interval) value must be <=0 and <1\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloJitter(jitter %f)\n",jitter);
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloJitter(jitter %f)\n",jitter);
  return 1;
}
bool
Nrlolsr::SetOlsrHelloTimeout(double timeout){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHelloTimeout(timeout %f)\n",timeout);
  if(timeout > 1){
    Hello_Timeout_Factor = timeout;
    Neighb_Hold_Time = Hello_Timeout_Factor*Hello_Interval;
    Mantissa_Hello_Hold_Interval = doubletomantissa(Neighb_Hold_Time);
  } else {
    DMSG(0,"ht(Hello Timeout factor of hello interval) value only valid if greater than one\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloTimeout(timeout %f)\n",timeout);
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloTimeout(timeout %f)\n",timeout);
  return 1;
}
bool
Nrlolsr::SetOlsrHelloPadding(unsigned int padding){
  padding -= padding % 4;
  helloPadding = (padding>1500 ? 1500 : padding);
  return 1;
}
bool
Nrlolsr::SetOlsrTCInterval(double interval){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrTCInterval(interval %f)\n",interval);
  if(interval>0){
    TC_Interval = interval;
    Top_Hold_Time = TC_Timeout_Factor*TC_Interval;     
		tc_timer.SetInterval(TC_Interval);
	} else {
    DMSG(0,"-tci(TC Interval in seconds) value not positive\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrTCInterval(interval %f)\n",interval);
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrTCInterval(interval %f)\n",interval);
  return 1;
}
bool
Nrlolsr::SetOlsrTCJitter(double jitter){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrTCJitter(jitter %f)\n",jitter);
  if(jitter>=0 && jitter < 1) {
    TC_Jitter = jitter;
  } else {
    DMSG(0,"tcj(TC Jitter in percent of TC Interval) value must be <=0 and <1\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrTCJitter(jitter %f)\n",jitter);
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrTCJitter(jitter %f)\n",jitter);
  return 1;
}
bool
Nrlolsr::SetOlsrTCTimeout(double timeout){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrTCTimeout(timeout %f)\n",timeout);
  if(timeout > 1){
    TC_Timeout_Factor = timeout;
    Top_Hold_Time = TC_Timeout_Factor*TC_Interval;
  } else {
    DMSG(0,"tct(TC Timeout factor of TC Interval) value only valid if greater than one\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrTCTimeout(timeout %f)\n",timeout);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrTCTimeout(timeout %f)\n",timeout);    
  return 1;
}

bool
Nrlolsr::SetOlsrHNAInterval(double interval){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHNAInterval(interval %f)\n",interval);    
  if(interval>0){
    HNA_Interval = interval;
    HNA_Hold_Time = HNA_Timeout_Factor*HNA_Interval;     
		hna_timer.SetInterval(HNA_Interval);
	} else {
    DMSG(0,"-hnai(HNA Interval in seconds) value not positive\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAInterval(interval %f)\n",interval);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAInterval(interval %f)\n",interval);    
  return 1;
}
bool
Nrlolsr::SetOlsrHNAJitter(double jitter){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHNAJitter(jitter %f)\n",jitter);    
  if(jitter>=0 && jitter < 1) {
    HNA_Jitter = jitter;
  } else {
    DMSG(0,"hnaj(HNA Jitter in percent of HNA Interval) value must be <=0 and <1\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAJitter(jitter %f)\n",jitter);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAJitter(jitter %f)\n",jitter);    
  return 1;
}
bool
Nrlolsr::SetOlsrHNATimeout(double timeout){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHNATimeout(timeout %f)\n",timeout);    
  if(timeout > 1){
    HNA_Timeout_Factor = timeout;
    HNA_Hold_Time = HNA_Timeout_Factor*HNA_Interval;
  } else {
    DMSG(0,"hnat(HNA Timeout factor of HNA Interval) value only valid if greater than one\n");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHNATimeout(timeout %f)\n",timeout);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHNATimeout(timeout %f)\n",timeout);    
  return 1;
}
bool
Nrlolsr::SetOlsrDelaySmfOff(double delay){
  if(delay<0){
    DMSG(0,"Nrlolsr::SetOlsrDelaySmfOff has to be positive and in seconds.  Setting to 0)\n");
    Delay_Smf_Off_Time = 0;
  } else {
    Delay_Smf_Off_Time = delay;
  }
  return true;
}
bool
Nrlolsr::SetOlsrForwardingDelay(double delay){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrForwardingDelay(delay = %f)\n",delay)
  if(delay<0){
    DMSG(0,"Nrlolsr::SetOlsrForwardingDelay has to be positive and in seconds. Setting to 0)\n");
    fdelay=0;
  } else {
    fdelay=delay;
  }
  return true;
}
bool
Nrlolsr::SetOlsrAllLinks(bool on){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrAllLinks(on %d)\n",on);    
  allLinks = on;
  //DMSG(6,"Exit: Nrlolsr::SetOlsrAllLinks(on %d)\n",on);    
  return true;
}
bool
Nrlolsr::SetOlsrHelloUseUnicast(int mode){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHelloUseUnicast(on %d)\n",on);    
  switch (mode) {
    case 0:
      helloUseUnicast = false;
      helloUseUnicastOpt = false;
      break;
    case 1:
      helloUseUnicast = true;
      helloUseUnicastOpt = true;
      break;
    case 2:
      helloUseUnicast = true;
      helloUseUnicastOpt = false;
      break;
    default:
      DMSG(0,"Nrlolsr::SetOlsrHelloUseUnicast value of %d is invalid only values 0-2 are valid\n");
      return false;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHelloUseUnicast(on %d)\n",on);    
  return true;

}
bool
Nrlolsr::SetOlsrFastReRoute(bool on){
  fastreroute = on;
  return true;
}
bool
Nrlolsr::SetOlsrTCSlowDown(bool on){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrTCSlowDown(on %d)\n",on);
  tcSlowDown = on;
  //DMSG(6,"Exit: Nrlolsr::SetOlsrTCSlowDown(on %d)\n",on);
  return true;
}
bool
Nrlolsr::SetOlsrWillingness(int willingness){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrWillingness(willingness %d)\n",willingness);    
  if((willingness >= 0) & (willingness < 8)){ 
    localWillingness = willingness;
    //    DMSG(6,"Enter: Nrlolsr::SetOlsrWillingness(willingness %d)\n",willingness);    
    return true;
  }
  DMSG(0,"-w(willingness factor) value only valid for integers from 0-7 0 = never 7 = always\n"); 
  //DMSG(6,"Enter: Nrlolsr::SetOlsrWillingness(willingness %d)\n",willingness);    
  return false;
}
bool
Nrlolsr::SetOlsrRecordHelloHistory(bool on){
	//DMSG(6,"Enter: Nrlolsr::SetOlsrRecordHelloHistory(on %d)\n",on);
	recordhellohistory=on;
	//DMSG(6,"Exit: Nrlolsr::SetOlsrRecordHelloHistory(on %d\n",on);
	return true;
}
bool 
Nrlolsr::SetOlsrHysUp(double up){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHysUp(up %f)\n",up);    
  if(up>=0 && up<1){
    T_up = up;
  } else {
    DMSG(0,"-hys up value must be >=0 and <1");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHysUp(up %f)\n",up);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHysUp(up %f)\n",up);    
  return 1;
}
bool 
Nrlolsr::SetOlsrHysDown(double down){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHysDown(down %f)\n",down);    
  if(down>=0 && down<1){
    T_down = down;
  } else {
    DMSG(0,"-hys down value must be >=0 and <1");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHysDown(down %f)\n",down);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHysDown(down %f)\n",down);    
  return 1;
}
bool 
Nrlolsr::SetOlsrHysAlpha(double a){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHysAlpha(alpha %f)\n",a);    
  if(a>=0 &&  a<1){
    alpha = a;
  } else {
    DMSG(0,"-hys alpha value must be >=0 and <1");
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHysAlpha(alpha %f)\n",a);    
    return 0;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHysAlpha(alpha %f)\n",a);    
  return 1;
}   
bool 
Nrlolsr::SetOlsrHysOff(bool off){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHysOff(off %d)\n",off);    
  if(off){
    T_up = .00000001;
    T_down = .00000001;
    alpha = .5;
  } else {
    //6 missing hellos will break link of perfect link
    T_up = .4;
    T_down = .15;
    alpha = .7; //weight given to past
    //2 missing hellos break link of perfect link
    /*    T_up = .8;
    T_down = .3;
    alpha = .5;*/
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHysOff(off %d)\n",off);    
  return 1;
}
bool 
Nrlolsr::SetOlsrHNAOff(bool off){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHNAOff(off %d)\n",off);    
  if(off){
    dohna = false;
  } else {
    dohna = true;
  }
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAOff(off %d)\n",off);    
  return true;
}
bool 
Nrlolsr::SetOlsrHNAFile(const char* filename){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrHNAFile(filename %s)\n",filename);    
  char tag[8], subnetaddress[256], buff[1024];
  char allones[128];
  memset(allones,0xffff,128);
  int masklength=0;
  ProtoAddress subnetAddress, subnetMask;
  FILE *fid= fopen(filename,"r");
  hnaFromFile = true;
  if(fid){
    //read in hna information
    while(fgets(buff, 1023,fid)){ //parse line   
      sscanf(buff,"%s %s %d",tag,subnetaddress,&masklength);
      if(!strcmp(tag,"HNA")){
		if(subnetAddress.ResolveFromString(subnetaddress)){
		  //if(subnetAddress.GetType()==ProtoAddress::IPv4){
		  //	subnetMask.ResolveFromString("255.255.255.255");
		  //} else if (subnetAddress.GetType()==ProtoAddress::IPv6){
		  //	subnetMask.ResolveFromString("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		  //}
		  subnetMask.SetRawHostAddress(subnetAddress.GetType(),allones,subnetAddress.GetLength());
		  subnetMask.ApplyPrefixMask(masklength);
		  NbrTuple* newhnaroute = new NbrTuple; // yes yes I know lots of wasted space but its only done every once in a while so......
		  newhnaroute->N_addr = subnetAddress;
		  newhnaroute->N_2hop_addr = subnetMask;
		  hnaAddresses.QueueObject(newhnaroute);
		  localHnaRouteTable.SetRoute(subnetAddress,masklength,subnetAddress);//this list is only currently only used by ns2 for "anycasting"
		  DMSG(4,"%s is adding the network route ",myaddress.GetHostString());
		  DMSG(4,"%s/",newhnaroute->N_addr.GetHostString());
		  DMSG(4,"%s to the local hna route table\n",newhnaroute->N_2hop_addr.GetHostString());
		} else {
		  DMSG(0,"Invalid address string %s in %s file\n",subnetaddress,filename);
		  fclose(fid);
		  //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAFile(filename %s)\n",filename);    
		  return 0;
		}
      } else {
		DMSG(0,"invalid option %s in hna setup file %s\n",tag,filename);
		//DMSG(6,"Exit: Nrlolsr::SetOlsrHNAFile(filename %s)\n",filename);
		return 0;
      }
    }
  } else {
    DMSG(0,"-hna %s could not be opened\n",filename);
    //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAFile(filename %s)\n",filename);    
    return 0;
  }
  fclose(fid);
  //DMSG(6,"Exit: Nrlolsr::SetOlsrHNAFile(filename %s)\n",filename);    
  return 1;
}
bool
Nrlolsr::SetOlsrFuzzyFlooding(bool fuzzyfloodingon){
  fuzzyflooding=fuzzyfloodingon;
  if(fuzzyflooding){
    tcloopcounter=0;
    hnaloopcounter=0;
    floodingdistance[0]=32;
    floodingdistance[1]=2;
    floodingdistance[2]=4;
    floodingdistance[3]=2;
    floodingdistance[4]=8;
    floodingdistance[5]=2;
    floodingdistance[6]=4;
    floodingdistance[7]=2;
    floodingdistance[8]=16;
    floodingdistance[9]=2;
    floodingdistance[10]=4;
    floodingdistance[11]=2;
    floodingdistance[12]=8;
    floodingdistance[13]=2;
    floodingdistance[14]=4;
    floodingdistance[15]=2;
  }
  return true;
}
bool 
Nrlolsr::SetOlsrQos(const char* setQosValue){
  //DMSG(6,"Enter: Nrlolsr::SetOlsrQos(setQosValue %s)\n",setQosValue);    
  qosvalue=atoi(setQosValue);
  //DMSG(6,"Exit: Nrlolsr::SetOlsrQos(setQosValue %s)\n",setQosValue);    
  return true;
}
bool
Nrlolsr::SetOlsrRouteTable(ProtoRouteMgr *theRouteMgr){
  if(theRouteMgr!=NULL){
    realRouteTable = theRouteMgr;
	realRouteTable->SetForwarding(true);
    return true;
  }
  DMSG(0,"Nrlolsr::SetOlsrRouteTable:  theRouteMgr pointer is NULL can not set realRouteTable\n");
  return false;
}

bool
Nrlolsr::Start()
{
  isRunning = true;
  //DMSG(6,"Enter: Nrlolsr::Start()\n");
  //set up timers with correct values.
  Neighb_Hold_Time = Hello_Timeout_Factor*Hello_Interval; 
  Mantissa_Hello_Hold_Interval = doubletomantissa(Neighb_Hold_Time);
  Mantissa_Hello_Interval = doubletomantissa(Hello_Interval);
  Top_Hold_Time=TC_Timeout_Factor*TC_Interval;
  HNA_Hold_Time=HNA_Interval*HNA_Timeout_Factor;

  nbr_list.SetHoldTime(Neighb_Hold_Time);         //list of neighbors
  nbr_list_old_for_tc.SetHoldTime(Neighb_Hold_Time);     //copy of list of neighbors only used when tcSlowDown is turned on used between sending tc messages
  nbr_list_old_for_hello.SetHoldTime(Neighb_Hold_Time);  //copy of list of neighbors only used when tcSlowDown is turned on used between recieved hello messages

  nbr_2hop_list.SetHoldTime(Neighb_Hold_Time);    //list of 2 hop neighbors
  duplicateTable.SetHoldTime(D_Hold_Time);        //list of duplicates default 15 sec
  forwardTable.SetHoldTime(D_Hold_Time);          //list of forwared packets default 15 sec
  topologySet.SetHoldTime(Top_Hold_Time);         //list of topology 
  hnaSet.SetHoldTime(HNA_Hold_Time);              //list of hna associations

  if(userDefBroadcast){
    netBroadAddr=userDefNetBroadAddr;
    broadMaskLength=userDefBroadMaskLength;
  } else if (ipvMode==ProtoAddress::IPv6) {
    netBroadAddr.ResolveFromString("ff02::705");
    broadMaskLength = 128;
  } else if (ipvMode==ProtoAddress::IPv4) {
    netBroadAddr.ResolveFromString("224.0.0.57");
    broadMaskLength = 32; 
#ifdef SIMULATE
  } else if(ipvMode==ProtoAddress::SIM) {
    SIMADDR tempbaddr = 0xffffffff;
    netBroadAddr.SimSetAddress(tempbaddr);
    broadMaskLength = 32;
    DMSG(8,"%s is address\n",netBroadAddr.GetHostString());
#endif //SIMULATE
  }

  // "Fix" the interface name in case it was
  netBroadAddr.GetBroadcastAddress(broadMaskLength,broadAddr); 
  broadAddr.SetPort(olsr_port_number);
  // route table and hna stuff
  //the below line should be called by the controling/App/Agent/etc classes.
  //realRouteTable->Open();
  initialRouteTable.Init();
  realRouteTable->GetAllRoutes(ipvMode,initialRouteTable);
  if(!hnaFromFile && dohna){ // check to see if hna info set from file
    dohna &= discoverAndSetHNAs(interfaceName);
  } 
  // set local address
  if(!realRouteTable->GetInterfaceAddress(interfaceIndex,ipvMode,myaddress)){
    //if(!ProtoSocket::GetInterfaceAddress(interfaceName,ipvMode,myaddress)){ 
    DMSG(0,"Nrlolsr:: error finding ip address of dev %s\n",interfaceName);
    //DMSG(6,"Exit: Nrlolsr::Start()\n");
    return 0;
  }
  /* broadcast addresses have to be set manually or multicast address used
  //add broadcast address or multicast address  
  if(!netBroadAddr.IsMulticast()){ //add route if not a multicast address
    ProtoAddress gwAddr;
    if(!realRouteTable->SetRoute(netBroadAddr,broadMaskLength,gwAddr,interfaceIndex,-1)){ 
      perror(NULL);
    }
  }
  */
  //install udp sockets
  if (!socket.Open(olsr_port_number,ipvMode,false)){
    DMSG(0, "Nrlolsr::Start() Error opening udp socket! \n");
    //DMSG(6,"Exit: Nrlolsr::Start()\n");
    return false;
  }
  if(!mac_control_socket.Open(mac_control_port,ipvMode,false)) {
    DMSG(0,"Nrlolsr::Start() Error opening mac control upd socket on port %d\n",mac_control_port);
    return false;
  }
#ifndef SIMULATE
  //install pipes
  if(recvPipe.IsOpen()) recvPipe.Close();
  if(!recvPipe.Listen(recvPipeName))
  {
        DMSG(0, "Nrloslr::Start() Error opening recvPipe with name %s\n",recvPipeName);
  }
#endif //SIMULATE
  
  if(qosvalue!=0){
    if(ipvMode==ProtoAddress::IPv4){
      if (!socket.SetTOS(qosvalue)){
	DMSG(0,"nrlolsr: Error setting tos of socket\n");
        //DMSG(6,"Exit: Nrlolsr::Start()\n");
	return false;
      }
    }
#ifdef IPV6
    else {
      if(!socket.SetFlowLabel(qosvalue<<20)){ //shifting bits because IPv6 has different packet format for qos than IPv4
	DMSG(0,"nrlolsr: Error setting flow of socket\n");
        //DMSG(6,"Exit: Nrlolsr::Start\n");
	return false;
      } 
    }
#endif
  }
  if(!socket.SetReuse(true)){ //this was required for use in certain emulated systems
    DMSG(0,"Nrlolsr::Start() ERROR SetReuse(true) returned false\n");
  }
  if(!socket.Bind(olsr_port_number)){
    DMSG(0,"nrlolsr: Error binding port number olsr_port_number to udp socket \n");    
    //DMSG(6,"Exit: Nrlolsr::Start()\n");
    return false;
  }
  
  //project specific mac layer control functions not needed for core functionality
  if(!mac_control_socket.Bind(mac_control_port)){
    DMSG(0,"Nrlolsr::Start(): Error binding port number %d to mac control udp socket\n",mac_control_port);
    return false;
  }
  llToGlobal.Init(); //used with ipv6 to translate ll address to global addres
#ifdef SMF_SUPPORT
  // (TBD) error check the init here!
  ipToMacTable.Init(); //only used if spipe is used
#ifndef OPNET  // JPH SMF  
  if (NULL == (cap_rcvr = ProtoCap::Create()))
    {
      DMSG(0, "Nrlolsr::Start() ProtoCap::Create() error: %s\n", GetErrorString());    
      return false;
    }
  cap_rcvr->SetListener(this, &Nrlolsr ::OnPktCapture); 
  cap_rcvr->SetNotifier(static_cast<ProtoChannel::Notifier*>(dispatcher));

  // 1) "fix" interfaceName in case it's really an IP address
  if (!ProtoSocket::GetInterfaceName(interfaceIndex, interfaceName, 256))
    {
      DMSG(0, "Nrlolsr::Start() error getting interface name\n");
      delete cap_rcvr;
      return false;
    }
  
  // 2) Open cap_rcvr
  if (!cap_rcvr->Open(interfaceName))    {
      DMSG(0, "Nrlolsr::Start() error opening cap_rcvr\n");
      delete cap_rcvr;
      return false;
    }
#endif // OPNET   
#endif // SMF_SUPPORT
#ifndef SIMULATE
  if (!smf_pipe.IsOpen())
    {
      // Try to connect to "nrlsmf" by default
      if (smf_pipe.Connect("nrlsmf"))
	{
	  char cmd[256];
	  cmd[255] = '\0';
	  strcpy(cmd,"smfServerStart ");
	  strncat(cmd,recvPipeName,255 - strlen(cmd));
	  unsigned int len = strlen(cmd);
	  if (!smf_pipe.Send(cmd, len))
	    {
	      DMSG(0, "Nrloslr::Start(): smf_pipe.Send() Not connected.\n");
	    }
	  
	}
      else
	{
	  DMSG(0, "Nrloslr::Start(): smf_pipe.Connect(nrlsmf) Not connected.\n");
	}
    }
    if (SDTOn && (!sdt_pipe.IsOpen()))
    {
        // Try and connect to the smf pipe "sdt" by default
        if(sdt_pipe.Connect("sdt"))
        {
            //send any initial state here    
        } 
        else
        {
            DMSG(0, "Nrlolsr::Start(): sdt_pipe.Connect(sdt) Not Connected.\n");
        }
    }
  if (!gui_pipe.IsOpen())
    {
      //Try to connect to "nrlolsrgui" by default
      if (gui_pipe.Connect("nrlolsrgui"))
	{
	  char cmdstr[256];
	  memset(cmdstr,0,256);
	  unsigned int cmdlen =0;
	  strcpy(cmdstr,"guiServerStart ");
	  strcat(cmdstr,recvPipeName);
	  cmdlen=strlen(cmdstr);
	  if (!gui_pipe.Send(cmdstr, cmdlen))
	    {
	      DMSG(0, "Nrlolsr::Start(): gui_pipe.Connect(nrlolsrgui) Not connected.\n");
	    }
	}
      else 
	{
	  DMSG(0, "Nrlolsr::Start(): gui_pipe.Connect(nrlolsrgui) Not connected.\n");
	}
    }
#endif //SIMULATE
  if(netBroadAddr.IsMulticast()){ //do multicast stuff
    DMSG(8,"%s is netBroadAddr\n",netBroadAddr.GetHostString());
    if(!socket.JoinGroup(netBroadAddr,interfaceName)){
      DMSG(0,"Nrlolsr: Error joining group %s\n",netBroadAddr.GetHostString());
      //DMSG(6,"Exit: Nrlolsr::Start()\n");
      return false;
    }
    if(!socket.SetMulticastInterface(interfaceName)){
      DMSG(0,"Nrlolsr::Start Error calling SetMulticastInterface with interfaceName=%s\n",interfaceName);
      //DMSG(6,"Exit: Nrlolsr::Start()\n");
      return false;
    }
  } else { //address should be broadcast and will add route later
    if (!socket.SetBroadcast(true)){
      DMSG(0, "Nrlolsr: Error setting broadcast udp socket! \n");
      //DMSG(6,"Exit: Nrlolsr::Start()\n");
      return false;
    }
  }
  //set and install timers
  //hello timer stuff
  hello_timer.SetInterval(Hello_Interval);
  hello_timer.SetRepeat(-1);
  double randValue = UniformRand(Hello_Interval)*Hello_Jitter;
  hello_jitter_timer.SetInterval(randValue);
  hello_jitter_timer.SetRepeat(0);
  //end hello timer stuff

  //tc timer stuff
  tc_timer.SetInterval(TC_Interval);
  tc_timer.SetRepeat(-1);
  randValue = UniformRand(TC_Interval)*TC_Jitter;
  tc_jitter_timer.SetInterval(randValue);
  tc_jitter_timer.SetRepeat(0);
  //end tc timer stuff

  //hna timer stuff
  hna_timer.SetInterval(HNA_Interval);
  hna_timer.SetRepeat(-1);
  randValue = UniformRand(HNA_Interval)*HNA_Jitter;
  hna_jitter_timer.SetInterval(randValue);
  hna_jitter_timer.SetRepeat(0);
  //end hna timer stuff

  //delayed timer stuff

  //install timers
  if(timerMgrPtr){
    if(!hello_timer.IsActive()) timerMgrPtr->ActivateTimer(hello_timer);
    if(!hello_jitter_timer.IsActive()) timerMgrPtr->ActivateTimer(hello_jitter_timer);
    if(!tc_timer.IsActive()) timerMgrPtr->ActivateTimer(tc_timer);
    if(!tc_jitter_timer.IsActive()) timerMgrPtr->ActivateTimer(tc_jitter_timer);
    if(!hna_timer.IsActive()) timerMgrPtr->ActivateTimer(hna_timer);
    if(!hna_jitter_timer.IsActive()) timerMgrPtr->ActivateTimer(hna_jitter_timer);
    if(!static_run_timer.IsActive()){
      if(static_run_timer.GetInterval()!=0){
        timerMgrPtr->ActivateTimer(static_run_timer);
      }
    }
  } else {
    DMSG(0,"Nrlolsr::Start() Error timerMgrPtr is NULL!\n");
    return false;
  }
  
  //send any smf info that might need to be sent.  This has to be done near the end as 
  //local address and pipes have to be set up.  Also smf pipe handshaking has to happen.
  if(updateSmfForwardingInfo){
    SendForwardingInfo();
  }

  //DMSG(6,"Exit: Nrlolsr::Start()\n");
  return true;
} // end Nrlolsr::Start(argc %s, argv %d)

bool
Nrlolsr::discoverAndSetHNAs(char* ignoreDev){ // function onwly works with ipv4 in unix
  //DMSG(6,"Enter: Nrlolsr::discoverAndSetHNAs(ignoreDev %s)\n",ignoreDev);
  bool returnvalue = false;
#ifdef UNIX
#ifndef SIMULATE
  if(ipvMode==ProtoAddress::IPv4){ //ipv6 does not yet have auto setup for hna use the file option to set the hna for v6
    char *trashCharPtr = NULL;
    char buff[1024],word[256];//currentDev[256];
    ProtoAddress currentMask, currentNetwork;
    FILE *fid = popen("netstat -rn","r");
    trashCharPtr = fgets(buff,1023,fid);// getting rid of first line
    trashCharPtr = fgets(buff,1023,fid);// getting rid of first line
    while(fgets(buff, 1023,fid)){ //parse line
      int index=0;
      int wordnumber=0;
      while(isspace(buff[index])) index++; //eat whitespace
      while(buff[index]!='\0'){ // parse word
	wordnumber++;
	sscanf(&buff[index],"%s",word);
	if(wordnumber==1) currentNetwork.ResolveFromString(word);
	if(wordnumber==3) currentMask.ResolveFromString(word);
	if(wordnumber==8) {
	  if(strcmp(word,ignoreDev) && strcmp(word,"lo")){
	    NbrTuple* newhnaroute = new NbrTuple; // yes yes I know lots of wasted space but its only done every once in a while so shut your hole.
	    newhnaroute->N_addr = currentNetwork;
	    newhnaroute->N_2hop_addr = currentMask;
	    hnaAddresses.QueueObject(newhnaroute);
	    returnvalue = true;
	  }
	}
	index+=strlen(word);
	while(isspace(buff[index])) index++; //eat whitespace
      }
    }
    pclose(fid);
  }  else {
    returnvalue = false;
  }
#endif//ifndef SIMULATE
#endif//ifdef UNIX
  //DMSG(6,"Exit: Nrlolsr::discoverAndSetHNAs(ignoreDev %s)\n",ignoreDev);
  return returnvalue;
}
bool
Nrlolsr::ConfigProcessCommands(const char* theFileName)
{
    FILE *configFile;
    char commands[500];
    configFile = fopen(theFileName,"r");
    if(NULL != configFile)
    {
        while(fgets(commands,500,configFile))
        {
            if(!StringProcessCommands(commands))
            {
                DMSG(0,"Nrlolsr::ConfigProcessCommads(%s\n): Error processing commands in file\n",configFile);
                return false;
            }
        }
        fclose(configFile);
    }
    else
    {
        DMSG(0,"Nrlolsr::ConfigProcessCommands(%s\n): Error opening file.",theFileName);
        return false;
    }
    return true;
}

bool
Nrlolsr::StringProcessCommands(const char* theString){
  DMSG(3,"\"%s\" is the stirng I am processing\n",theString);
  const char *stringPtrStart=theString;
  const char *stringPtrEnd=theString;
  char space = ' ';
  char *argv[256]; 
  int argc=1;
  int wordsize;
  while(stringPtrStart){
    stringPtrEnd = strchr(stringPtrStart,space);
    if(stringPtrEnd!=NULL){
      wordsize = stringPtrEnd-stringPtrStart;
      argv[argc]=new char[wordsize+1];
      memset(argv[argc],0,wordsize+1);
      strncpy(argv[argc],stringPtrStart,wordsize);
      argc++;
      stringPtrStart=stringPtrEnd+1;
    } else {//last word
      wordsize = strlen(stringPtrStart);
      argv[argc]=new char[wordsize+1];
      memset(argv[argc],0,wordsize+1);
      //      fprintf(stderr,"%d is strlen\n",wordsize);
      strncpy(argv[argc],stringPtrStart,wordsize);
      argc++;
      stringPtrStart=stringPtrEnd; //or NULL
    }
  }
  bool returnvalue = ProcessCommands(argc,argv);
  for(int i=1;i<argc;i++){
    delete[] argv[i];
  }
  return returnvalue;
}

bool 
Nrlolsr::ProcessCommands(int argc, const char*const* argv){
  //DMSG(6,"Enter: Nrlolsr::ProcessCommands(argc,argv)\n");
  bool printusage = false;
  char localinterfacename[256];
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"-b")){
      i++;
      if(!SetOlsrBroadcastAddress(argv[i],argv[i+1])){
	DMSG(0,"Nrlolsr: Error setting broadcast address to:\n          Address: %s netmask %s\n",argv[i],argv[i+1]);
	printusage = true;
      }
      i++;
    }
    else if(!strcmp(argv[i],"-z")){
      //this is handled by the App code and this is just here so that usage isn't printed
    }
    else if(!strcmp(argv[i],"-nrlopt")){
      StringProcessCommands("-robustroute -fdelay .05 -tci 2.0 -tct 8 -tcj .99 -hys down .01 -hi .25 -hj .99 -ht 12");
    }
    else if(!strcmp(argv[i],"-ipv6")){
      SetOlsrIPv4(false);
    }
    else if(!strcmp(argv[i],"-ipv4")){
      SetOlsrIPv4(true);
    }
    else if(!strcmp(argv[i],"-i")){
      i++;
      strncpy(localinterfacename,argv[i],256);
      if(!SetOlsrInterfaceAddress(localinterfacename)){
	DMSG(0,"error setting InterfaceAddress to %s\n",localinterfacename);
	printusage = true;
      }
    } 
    else if(!strcmp(argv[i],"-d")){
      i++;
      if(!SetOlsrDebugLevel(atoi(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting debug level to %d\n",atoi(argv[i]));
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-l")){
      i++;
      if(!SetOlsrDebugLog(argv[i])){
	DMSG(0,"Nrlolsr: Error opening log file %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-config")){
      i++;
      if(!ConfigProcessCommands(argv[i])){
        DMSG(0,"Nrlolsr: Error opening config file %s\n",argv[i]);
        printusage = true;
      }
    }
#ifndef SIMULATE //protolib does not support pipes in simulation
    else if(!strcmp(argv[i], "-sdtClient")) { //set up and open sdt_pipe (used to update sdt)
      i++;
      if(sdt_pipe.IsOpen()) sdt_pipe.Close();
      if(sdt_pipe.Connect(argv[i])) {
        SDTOn = true;
      } else {
        DMSG(0,"Nrlolsr::ProcessCommands(): sdt_pipe.Connect() error can't connect to %s\n",argv[i]);
      }
    }
    else if(!strcmp(argv[i], "-guiClient")) { //set up gui sendPipeName and open gui_pipe (used to update the gui)
      i++;
      if(gui_pipe.IsOpen()) gui_pipe.Close();
      if(gui_pipe.Connect(argv[i])) {
	char cmdstr[256];
	memset(cmdstr,0,256);
	unsigned int cmdlen =0;
	strcpy(cmdstr,"guiServerStart ");
	strcat(cmdstr,recvPipeName);
	cmdlen=strlen(cmdstr);
	if (!gui_pipe.Send(cmdstr, cmdlen)) {
	  DMSG(0, "Nrlolsr::ProcessCommands(): gui_pipe.Send() error\n");
	}
      }	else {
	DMSG(0,"Nrlolsr::ProcessCommands(): Error connecting to gui_pipe of name %s\n",argv[i]);
	printusage = true;
      }
    } else if(!strcmp(argv[i],"guiClientStart")) { // respond by connecting to indicated pipe
      i++;
      if(gui_pipe.IsOpen()) gui_pipe.Close();
      if(!gui_pipe.Connect(argv[i])){
	DMSG(0,"Nrlolsr::ProcessCommands(): Error connecting to gui_pipe of name %s\n",argv[i]);
	printusage = true;
      }
    } else if(!strcmp(argv[i], "-sendGuiRoutes")) { 
      if(gui_pipe.IsOpen()){
	SendGuiRoutes();
      } else {
	DMSG(0,"Nrlolsr::ProcessCommands(): Cannont send gui route information as gui_pipe is not open!\n");
      }
    } else if(!strcmp(argv[i], "-sendGuiNeighbors")){
      if(gui_pipe.IsOpen()){
	SendGuiNeighbors();
      } else {
	DMSG(0,"Nrlolsr::ProcessCommands(): Cannont send gui neighbor information as gui_pipe is not open!\n");
      }
    } else if(!strcmp(argv[i], "-sendGuiSettings")){
      if(gui_pipe.IsOpen()){
	SendGuiSettings();
      } else {
	DMSG(0,"Nrlolsr::ProcessCommands(): Cannont send gui settings information as gui_pipe is not open!\n");
      }
    } else if(!strcmp(argv[i],"-rpipe")) { //set recvPipeName and open pipe to receive commands
      i++;
      strncpy(recvPipeName, argv[i], 256);
      if(recvPipe.IsOpen()) recvPipe.Close();
      if(!recvPipe.Listen(recvPipeName)) {
	DMSG(0, "Nrloslr::ProcessCommands(): Error opening recvPipe with name %s\n",recvPipeName);
	printusage = true;
      } else {
	if(gui_pipe.IsOpen()) {
	  char cmd[256];
	  //cmd[255] = '\0';
	  memset((void*)cmd,0,255);
	  strcpy(cmd,"guiServerStart ");
	  strncat(cmd,recvPipeName,255 - strlen(cmd));
	  unsigned int len = strlen(cmd);
	  if (!gui_pipe.Send(cmd, len)) {
	    DMSG(0, "Nrloslr::ProcessCommands(): gui_pipe.Send() error\n");
	  }
	} 
      }
#ifndef SMF_SUPPORT
    }
#else
      if(smf_pipe.IsOpen())
	{
	  char cmd[256];
	  cmd[255] = '\0';
	  strcpy(cmd,"smfServerStart ");
	  strncat(cmd,recvPipeName,255 - strlen(cmd));
	  unsigned int len = strlen(cmd);
	  if (!smf_pipe.Send(cmd, len))
	    {
	      DMSG(0, "Nrloslr::ProcessCommands(): smf_pipe.Send() error\n");
	    }
	}
    } else if((!strcmp(argv[i], "smfClient")) ||
              (!strcmp(argv[i],"-smfClient"))) { //set up sendPipeName and open smf_pipe (used to send mac layer mpr info to smfClient)
      i++;
      if(smf_pipe.IsOpen()) smf_pipe.Close();
      if(smf_pipe.Connect(argv[i]))
	{
	  char cmd[256];
	  cmd[255] = '\0';
	  strcpy(cmd,"smfServerStart ");
	  strncat(cmd, recvPipeName, 255-strlen(cmd));
	  unsigned int len = strlen(cmd);
	  if (smf_pipe.Send(cmd, len))
	    {
	      floodingOn = true;
	      SendForwardingInfo(); //default floodyingType = SMPR
	      //SendMacMprInfo();
	    }
	  else
	    {
	      DMSG(0, "Nrlolsr::ProcessCommands(): smf_pipe.Send() error\n");
	    }
	}
      else
	{
	  DMSG(0,"Nrlolsr::ProcessCommands(): Error connecting to smf_pipe of name %s\n",argv[i]);
	  printusage = true;
	}
    } else if(!strcmp(argv[i],"smfClientStart")) { // respond by connecting to indicated pipe
      i++;
      if(smf_pipe.IsOpen()) smf_pipe.Close();
      if(smf_pipe.Connect(argv[i]))
	{
	  SendForwardingInfo();
	  //SendMacMprInfo();
	  //SendMacSymInfo();
	}
      else
	{
	  DMSG(0,"Nrlolsr::ProcessCommands(): Error connecting to smf_pipe of name %s\n",argv[i]);
	  printusage = true;
	} 
    }
#endif // SMF_SUPPORT
#endif // NOT_SIMULATE
    else if (!strcmp(argv[i],"-flooding")){//default is off flooding method to use for broadcast packets in ns
      i++;
      updateSmfForwardingInfo=true;
      if(!strcmp(argv[i],"off")){
	floodingOn = false;
	localNodeIsForwarder=false;
      } else if(!strcmp(argv[i],"s-mpr")){ //source specific mpr flooding (tree for each source)
	floodingOn = true;
	floodingType = SMPR;
	localNodeIsForwarder=false;
      } else if(!strcmp(argv[i],"smpr")){ //source specific mpr flooding (s-mpr alias)
	floodingOn = true;
	floodingType = SMPR;
	localNodeIsForwarder=false;
      } else if(!strcmp(argv[i],"ns-mpr")){ //non-source specific mpr flooding (one shared tree) using all mpr nodes
	floodingOn = true;
	floodingType = NSMPR;
	localNodeIsForwarder=false;
      } else if(!strcmp(argv[i],"not-sym")){ //forward packets from all except symetric non mpr nodes
	floodingOn = true;
	floodingType = NOTSYM;
	localNodeIsForwarder=false;
      } else if(!strcmp(argv[i],"simple")){ //simplified flooding
	floodingOn = true;
	floodingType = SIMPLE;
	localNodeIsForwarder=true;
      } else if(!strcmp(argv[i],"cf")){ //classical flooding (simplified flooding alias)
	floodingOn = true;
	floodingType = SIMPLE;
	localNodeIsForwarder=true;
      } else if(!strcmp(argv[i],"ecds")){ //ospfs essential cds algrothim
	floodingOn = true;
	floodingType = ECDS;
	localNodeIsForwarder=false;
      } else if(!strcmp(argv[i],"mpr-cds")){ //algorithm described in inria report "On the robustness and stability of connected dominating sets
	floodingOn = true;
	floodingType = MPRCDS;
	localNodeIsForwarder=false;
      } else {
	floodingOn = false;
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-unicast")){ //used for turning off unicast routing (hello smf only mode)
      i++;
      if(!strcmp(argv[i],"off")){
	unicastRouting=false;
      } else {
	unicastRouting=true;
      }
    }
    else if(!strcmp(argv[i],"-static")){//used to set up static routes will turn olsr "off" after the given amout of seconds
      i++;
      if(!SetOlsrStatic(atof(argv[i]))){
        DMSG(0,"Nrlolsr: Error setting static with a run time of %s\n",argv[i]);
        printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-hi")){
      i++;
      if(!SetOlsrHelloInterval(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting Hello Interval to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-hj")){
      i++;
      if(!SetOlsrHelloJitter(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting Hello Jitter to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-ht")){
      i++;
      if(!SetOlsrHelloTimeout(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting Hello Timeout factor to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-hp")){
      i++;
      if(!SetOlsrHelloPadding((unsigned int)atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting Hello Padding value to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-tci")){
      i++;
      if(!SetOlsrTCInterval(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting TC Interval to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-tcj")){
      i++;
      if(!SetOlsrTCJitter(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting TC Jitter to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-tct")){
      i++;
      if(!SetOlsrTCTimeout(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting TC Timeout factor to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-fdelay")){
      i++;
      if(!SetOlsrForwardingDelay(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting fdelay to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-smfoffdelay")){
      i++;
      if(!SetOlsrDelaySmfOff(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting smfoffdelay to %s\n",argv[i]);
	printusage = true;
      }
      
    }
    else if(!strcmp(argv[i],"-spf")){
      dotcextra=true;
      dospf=true;
      dominmax=false;
      dorobust=false;
    }
    else if(!strcmp(argv[i],"-minmax")){
      dotcextra=true;
      dospf=false;
      dominmax=true;
      dorobust=false;
    }
    else if(!strcmp(argv[i],"-shortesthop")){
      dotcextra=false;
      dospf=false;
      dominmax=false;
      dorobust=false;
    }
    else if(!strcmp(argv[i],"-robustroute")){
      dotcextra=false;
      dospf=false;
      dominmax=false;
      dorobust=true;
    }
    else if(!strcmp(argv[i],"-port")){
      i++;
      if(!SetOlsrPort(atoi(argv[i]))){
	DMSG(0,"Nrlolsr::ProcessCommands Error setting port %s\n",argv[i]);
      }
    }
    else if(!strcmp(argv[i],"-mcport")){
      i++;
      if(!SetOlsrMacControlPort(atoi(argv[i]))){
	DMSG(0,"Nrlolsr::ProcessCommands Error setting mac_control_port %s\n",argv[i]);
      }
    }
    else if(!strcmp(argv[i],"-hnai")){
      i++;
      if(!SetOlsrHNAInterval(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting HNA Interval to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-hnaj")){
      i++;
      if(!SetOlsrHNAJitter(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting HNA Jitter to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-hnat")){
      i++;
      if(!SetOlsrHNATimeout(atof(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting HNA Timeout factor to %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-unicasthellos")){
      i++;
      if(!strcmp(argv[i],"on")){
	if(!SetOlsrHelloUseUnicast(2)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -unicasthellos section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else if(!strcmp(argv[i],"opt")){
	if(!SetOlsrHelloUseUnicast(1)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -unicasthellos section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else if(!strcmp(argv[i],"off")){
	if(!SetOlsrHelloUseUnicast(0)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -unicasthellos section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else {
	DMSG(0,"Nrlolsr::ProcessCommands in -unicasthellos section.  \"%s\"!=on or off\n");
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-al")){
      i++;
      if(i==argc){ //-al was only and last option 
	i--;
	if(!SetOlsrAllLinks(true)){
	  DMSG(0,"Nrlolsr: odd Error SetOlsrAllLinks(true) failed please send command line text to jdean@itd.nrl.navy.mil\n");
	  printusage = true;
	}
      } else if(!strcmp(argv[i],"on")){
	if(!SetOlsrAllLinks(true)){
	  DMSG(0,"Nrlolsr:odd Error SetOlsrAllLinks(true) failed please send command line text to jdean@itd.nrl.navy.mil\n");
	  printusage = true;
	}
      } else if(!strcmp(argv[i],"off")){
	if(!SetOlsrAllLinks(false)){
	  DMSG(0,"Nrlolsr: odd Error SetOlsrAllLinks(false) failed please send command line text to jdean@itd.nrl.navy.mil\n");
	  printusage = true;
	}
      } else { //for backwards compatability a simple "-al" is the same as "-al on"
	i--;
	if(!SetOlsrAllLinks(true)){
	  DMSG(0,"Nrlolsr: odd Error SetOlsrAllLinks(true) failed please send command line text to jdean@itd.nrl.navy.mil\n");
	  printusage = true;
	}
      }
    }
    else if(!strcmp(argv[i],"-fastreroute")){
      i++;
      if(!strcmp(argv[i],"on")){
	if(!SetOlsrFastReRoute(true)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -fastreroute section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else if(!strcmp(argv[i],"off")){
	if(!SetOlsrFastReRoute(false)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -fastreroute section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else {
	DMSG(0,"Nrlolsr::ProcessCommands in -fastreroute section.  \"%s\"!=on or off\n");
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-slowdown")){
      i++;
      if(!strcmp(argv[i],"on")){
	if(!SetOlsrTCSlowDown(true)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -slowdown section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else if(!strcmp(argv[i],"off")){
	if(!SetOlsrTCSlowDown(false)){
	  DMSG(0,"Nrlolsr::ProcessCommands in -slowdown section.  Should not EVER return false\n");
	  printusage = true;
	}
      } else {
	DMSG(0,"Nrlolsr::ProcessCommands in -slowdown section.  \"%s\"!=on or off\n");
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-w")){
      i++;
      if(!SetOlsrWillingness(atoi(argv[i]))){
	DMSG(0,"Nrlolsr: Error setting willingness value to %s\n",argv[i]);
	printusage = true;
      }
    }
		else if(!strcmp(argv[i],"-recordhellohistory")){
			i++;
			if(!strcmp(argv[i],"on")){
				if(!SetOlsrRecordHelloHistory(true)){
					DMSG(0,"Nrlolsr::ProcessCommands in -recordhellohistory on section.  Should not EVER return false\n");
					printusage = true;
				} 
			} else if(!strcmp(argv[i],"off")){
				if(!SetOlsrRecordHelloHistory(false)){
					DMSG(0,"Nrlolsr::ProcessCommands in -recordhellohistory off section.  Should not EVER return false\n");
					printusage = true;
				} 
			} else {
				DMSG(0,"Nrlolsr::ProcessCommands in recordhellohistory section. \"%s\"!=on or off\n");
			}
		} 
		else if(!strcmp(argv[i],"-hys")){
      int j;
      i++;
      if(!strcmp(argv[i],"up")){
	if(!SetOlsrHysUp(atof(argv[i+1]))){
	  DMSG(0,"Nrlolsr: Error %s is invalid -hys up value\n",argv[i+1]);
	  printusage = true;
	}
	j=i+1;
      } 
      else if (!strcmp(argv[i],"down")){
      	if(!SetOlsrHysDown(atof(argv[i+1]))){
	  DMSG(0,"Nrlolsr: Error %s is invalid -hys down value\n",argv[i+1]);
	  printusage = true;
	}
	j=i+1;
      } 
      else if (!strcmp(argv[i],"alpha")){
	if(!SetOlsrHysAlpha(atof(argv[i+1]))){
	  DMSG(0,"Nrlolsr: Error %s is invalid -hys alpha value\n",argv[i+1]);
	  printusage = true;
	}
	j=i+1;
      }
      else if (!strcmp(argv[i],"off")){
	if(!SetOlsrHysOff(true)){
	  DMSG(0,"Nrlolsr: Error that shouldn't ever happen email jdean@itd.nrl.navy.mil with command line\n");
	  printusage = true;
	}
	j=i;
      }
      else if (!strcmp(argv[i],"on")){
	if(!SetOlsrHysOff(false)){
	  DMSG(0,"Nrlolsr: Error that shouldn't ever happen email jdean@itd.nrl.navy.mil with command line\n");
	  printusage = true;
	}
	j=i;
      }
      else {
	DMSG(0,"Nrlolsr: Error %s is invalid -hys option\n",argv[i]);
	printusage = true;
	j=i;
      }
      i=j;
    } 
    else if(!strcmp(argv[i],"-hna")){
      i++;
      if(!strcmp(argv[i],"auto")){
	if(!SetOlsrHNAOff(false)){
	  DMSG(0,"Nrlolsr: Error that should never happen email jdean@itd.nrl.navy.mil with command line\n");
	  printusage = true;
	}
      } 
      else if(!strcmp(argv[i],"off")){
	if(!SetOlsrHNAOff(true)){
	  DMSG(0,"Nrlolsr: Error that should never happen email jdean@itd.nrl.navy.mil with command line\n");
	  printusage = true;
	}
      }
      else {
	if(!SetOlsrHNAFile(argv[i])){
	  DMSG(0,"Nrlolsr: Error opening %s for -hna option\n",argv[i]);
	  printusage = true;
	}
      }
    }
    else if(!strcmp(argv[i],"-qos")){
      i++;
      if(!SetOlsrQos(argv[i])){
	DMSG(0,"Nrlolsr: Error setting qos to value of %s\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-fuzzy")){
      i++;
      if(i==argc){//-fuzzy was last option 
      	i--;
	if(!SetOlsrFuzzyFlooding(true)){
	  DMSG(0,"Nrlolsr::ProcessCommands Error turning on fuzzy flooding\n");
	  printusage = true;
	}
      } else {
        if(!strcmp(argv[i],"on")){
	  if(!SetOlsrFuzzyFlooding(true)){
	    DMSG(0,"Nrlolsr::ProcessCommands Error turning on fuzzy flooding\n");
	    printusage = true;
  	  }
        } else if(!strcmp(argv[i],"off")){
	  if(!SetOlsrFuzzyFlooding(false)){
	    DMSG(0,"Nrlolsr::ProcessCommands Error turning off fuzzy flooding\n");
	    printusage = true;
	  }
        } else {//default turn on fuzzy flooding without following on/off
	  i--;
	  if(!SetOlsrFuzzyFlooding(true)){
	    DMSG(0,"Nrlolsr::ProcessCommands Error turning off fuzzy flooding\n");
	    printusage = true;
	  }
        }
      }
    }
    else if(!strcmp(argv[i],"-link")){
      i++;
      ProtoAddress temp_link_address;
      NbrTuple *temp_nbr_ptr=NULL;
      int temp_weight=0;
      if(temp_link_address.ResolveFromString(argv[i])){
	i++;
	if(!strcmp(argv[i],"up")){ //set link to up state 
	  SetLinkState(LINK_UP,temp_link_address);
	} else {
	  if((temp_nbr_ptr=nbr_list.FindObject(temp_link_address))){
	    if(!strcmp(argv[i],"down")){
	      //bring node down cleanly
	      SetLinkState(LINK_DOWN,temp_link_address);
	    } else if(!strcmp(argv[i],"default")){
	      //revert to normal operation
	      SetLinkState(LINK_DEFAULT,temp_link_address);
		  temp_nbr_ptr->N_minmax_link_set=false;
		  temp_nbr_ptr->N_spf_link_set=false;
		} else if(!strcmp(argv[i],"spf")){
	      i++;
	      temp_weight = atoi(argv[i]);
	      temp_nbr_ptr->N_spf=temp_weight;//set spf value of link
		  temp_nbr_ptr->N_spf_link_set=true;
	    } else if(!strcmp(argv[i],"minmax")){
	      i++;
	      temp_weight = atoi(argv[i]);
	      temp_nbr_ptr->N_minmax=temp_weight; //set minmax value of link
		  temp_nbr_ptr->N_minmax_link_set=true;
		} else if(!strcmp(argv[i],"promisc")){
	      i++;
	      temp_weight = atoi(argv[i]);
	      //set promisc value of link 
	      //this is empty for now
	    }
	  } else {
	    DMSG(0,"Nrlolsr: %s is not currently a neighbor\n",temp_link_address.GetHostString());
	    printusage = true;
	  }
	}
      } else { //neighbor doesn't exist
	DMSG(0,"Nrlolsr: %s is not a valid address\n",argv[i]);
	printusage = true;
      }
    }
    else if(!strcmp(argv[i],"-v")){	
		DMSG(0,"Nrlolsr::version 7.9.2\n");
      //DMSG(6,"Exit: Nrlolsr::ProcessCommands(argc,argv)\n");
      return false;
    }
#ifdef SIMULATE
    else if(!strcmp(argv[i],"target")){
      return true;
    }
#endif //SIMULATE
    else {
      printusage = true;
      if(strcmp(argv[i],"-h")){
	DMSG(0,"%s is invalid option\n",argv[i]);
      }
    }
  }
  if(printusage){
#ifndef SIMULATE
    DMSG(0,"Nrlolsr:options [-i <interfacename>][-d <debuglvl>][-l <debuglogfile>][nrlopt][-al on | off][-h][-v][-z]\n");
    DMSG(0,"                 [-config <configfile>][-w <willingness>][-hna auto|<filename>|off][-b <broadaddr> <masklength>]\n");
    DMSG(0,"                 [-hi <HelloInterval>][-hj <HelloJitter>][-ht <HelloTimeoutfactor>][-hp <HelloPadding>]\n");
    DMSG(0,"                 [-tci <TCInterval>][-tcj <TCJitter>][-tct <TCTimeoutfactor>][-ipv6][-ipv4]\n");
    DMSG(0,"                 [-hnai <HNAInterval>][-hnaj <HNAJitter>][-hnat <HNATimeoutfactor>][-port <number]\n");
    DMSG(0,"                 [-hys up <upvalue> | down <downvalue> | alpha <alphavalue> | on | off][-slowdown on | off]\n");
    DMSG(0,"                 [-qos <qosvalue>][-fuzzy on | off][-shortesthop][-robustroute][-spf][-minmax][-mcport <portnumber>]\n");
    DMSG(0,"                 [-link <address> up | down | default | spf <weight> | minmax <weight> | promisc <weight>]\n");
    DMSG(0,"                 [-flooding off | s-mpr | ns-mpr | not-sym | simple | ecds | mpr-cds][-smfoffdelay <delay>]\n");
    DMSG(0,"                 [-unicast on | off][-static <time>][-fdelay <MaxForwardDelay>][-unicasthellos on | opt | off\n");
    DMSG(0,"                 [-rpipe <pipename>][-smfClient <pipename>][-sdtClient <pipename>][-guiClient <pipename>]\n");
    DMSG(0,"see readme.help for more info\n");
#endif
    //DMSG(6,"Exit: Nrlolsr::ProcessCommands(argc,argv)\n");
    return false;
  }
  //DMSG(6,"Exit: Nrlolsr::ProcessCommands(argc,argv)\n");
  return true;
} //end Nrlolsr::ProcessCommands(argc,argv)

bool 
Nrlolsr::ParseMacControlMessage(MacControlMsg& msg)
{
    // 1) Get the IP address (Ethernet addresses not handled)
    ProtoAddress::Type addrType;
    switch (msg.GetAddressType())
    {
        case MacControlMsg::ADDR_IPV4:
            addrType = ProtoAddress::IPv4;
            break;
        case MacControlMsg::ADDR_IPV6:
            addrType = ProtoAddress::IPv6;
break;
        default:
            DMSG(0, "Nrlolsr::ParseMacControlMessage() invalid address type\n");
            return false;   
    }
    ProtoAddress addr;
    if (!addr.SetRawHostAddress(addrType, msg.GetAddress(), msg.GetAddressLength()))
    {
        DMSG(0, "Nrlolsr::ParseMacControlMessage() error translating address\n");
        return false;   
    }
    
    // 2) Generate an NRL-OLSR command for each "param" in message
    MacControlMsg::Param param;
    while (msg.GetNextParam(param))
    {
        char *cmd[4];
	cmd[0]=new char[256];
	cmd[1]=new char[256];
	cmd[2]=new char[256];
	cmd[3]=new char[256];

	int local_argc=0;
	sprintf(cmd[0],"-link");
	sprintf(cmd[1],"%s",addr.GetHostString());
        switch (param.GetType())
	  {
	  case MacControlMsg::Param::METRICS_SPF_COST:
	    sprintf(cmd[2],"spf");
	    sprintf(cmd[3],"%d",param.GetValue());
	    local_argc=4;
	    break;
	  case MacControlMsg::Param::METRICS_MINMAX_COST:
	    sprintf(cmd[2],"minmax");
	    sprintf(cmd[3],"%d",param.GetValue());
	    local_argc=4;
	    break;
	  case MacControlMsg::Param::METRICS_PROMISC_COUNT:
	    sprintf(cmd[2],"promisc");
	    sprintf(cmd[3],"%d",param.GetValue());
	    local_argc=4;
	    break;
	  case MacControlMsg::Param::METRICS_NBR_QUALITY:
                switch (param.GetValue())
                {
                    case MacControlMsg::Param::NBR_GOOD:
                      sprintf(cmd[2],"up");
		      local_argc=3;
		      break;
                    case MacControlMsg::Param::NBR_BAD:
                      sprintf(cmd[2],"down");
		      local_argc=3;
		      break;
                    case MacControlMsg::Param::NBR_UNKNOWN:
		      sprintf(cmd[2],"default");
		      local_argc=3;
		      break;
                    default:
                        DMSG(0, "Nrlolsr::ParseMacControlMessage() invalid nbr quality\n");
                        break;
                }     
                break;
            default:
                DMSG(0, "Nrlolsr::ParseMacControlMessage() invalid param type\n");
                return false;
        }
        ProcessCommands(local_argc,cmd);
	delete[] cmd[0];
	delete[] cmd[1];
	delete[] cmd[2];
	delete[] cmd[3];
    }
    return true;
}  // end Nrlolsr::ParseMacControlMessage()



bool
Nrlolsr::OnHelloTimeout(ProtoTimer& theTimer)
{
  DMSG(6,"Enter: Nrlolsr::OnHelloTimeout(theTimer)\n");

  //do hello timer stuff
  if(sendHelloTimerOn){
    if(hello_jitter_timer.IsActive()){
      hello_jitter_timer.Deactivate();
    }   
    sendHelloTimerOn=false;
    SendHello();
  } else {
    printCurrentTable(3);
    printTopology(3);
    printRoutingTable(3);
    // do periodic checking here
    // instead of using the packet numbers to see if a packet was lost durring a hello interval to update the historisis
    // I decided thatt it would be easier and more active if it checked for lost packets every hello interval but given the
    // nature of the jitter in the hello interavl the konectivity value for a node is only started to be reduced after 2 of its
    // hello intervals with no recieved message from that node.  the way the jitter is implimented in this code at most 3 hello's 
    // can be recieved in any given interval (and that rarely) so that the one sending hellos faster can fake at most 2 lost
    // hello messages.  if a hello is percieved as no being there a flag is rasied if then the next hello interval there is still 
    // no reply for the missing neighbor its konectivity value is decreased with the factor alpha
    if(recordhellohistory){
			DMSG(0,"==========Hello history at time %f===========\n",InlineGetCurrentTime());
		}
		NbrTuple *nb;
    for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
      if(nb!=NULL){
				if(nb->recievedHello>0){
					if(recordhellohistory){
						DMSG(0,"%s ",myaddress.GetHostString());
						DMSG(0,"recieved a hello from %s resetting status\n",nb->N_addr.GetHostString());
					}
					nb->recievedHello=0;
				} else if(nb->recievedHello==0) {
					if(recordhellohistory){
						DMSG(0,"%s ",myaddress.GetHostString());
						DMSG(0,"did not recieve a hello from %s flagging it\n",nb->N_addr.GetHostString());
					}
					nb->recievedHello=-1;
				} else if(nb->recievedHello==-1) {
					if(recordhellohistory){
						DMSG(0,"%s ",myaddress.GetHostString());
						DMSG(0,"did not recieve a hello from %s reducting konectivity to %f; its type is %d\n",nb->N_addr.GetHostString(),nb->konectivity,nb->N_status);
					}
					nb->konectivity=nb->konectivity*alpha; // reduce value
				}
      }
    }
		if(recordhellohistory){
			DMSG(0,"==========End Hello History=========\n");
		}
    //end periodic checking
    
    //set up next timer to send packet out
    sendHelloTimerOn=true;
    double randValue = UniformRand(Hello_Interval)*Hello_Jitter;
    hello_jitter_timer.SetInterval(randValue);
    timerMgrPtr->ActivateTimer(hello_jitter_timer);
  }
  DMSG(6,"Exit: Nrlolsr::OnHelloTimeout(theTimer)\n");
  return true;
} // end Nrlolsr::OnHellotimeout()

bool 
Nrlolsr::SendHello()
{
  DMSG(6,"Enter: %s's Nrlolsr::SendHello() at time %f\n",myaddress.GetHostString(),InlineGetCurrentTime());
  //this method will build and send a hello packet when called it uses methods defined in the olsr_packet_types.h file

  //clean up tables
  nb_purge();
  for_purge();
  dup_purge();
  top_purge();
  hna_purge();
  makeRoutingTable();

  printLinks();
  printRouteLinks();
  printNbrs();
  selectmpr(); //make sure mprs are up to date before building packet
  if(floodingType==ECDS){
    calculateOspfEcds(); //this could be done more often but it would take up more cpu time.
  }
  if(floodingType==MPRCDS){
    calculateMprCds(); //this could be done more often but it would take up more cpu time.
  }
  if(floodingType==NSMPR){
    calculateNsMpr(); //this could be done more often but it would take up more cpu time.
  }
  //DMSG(1,"sending hello packet at time %f\n",InlineGetCurrentTime());
  //DMSG(6,"Enter: SendHello()\n");
  //DMSG(6,"Enter: \n");
  seqno++;  

  //build up parts for adding to hello message
  LinkMessage asymlinks, symlinks, mprlinks, lostlinks;
  asymlinks.linkCode=ASYM_LINKv4;
  asymlinks.reserved=0; 
  
  symlinks.linkCode=SYM_LINKv4;
  symlinks.reserved=0; 

  mprlinks.linkCode=MPR_LINKv4;
  mprlinks.reserved=0; 

  lostlinks.linkCode=LOST_LINKv4;
  lostlinks.reserved=0;

  //actually add the links to their type lists
  NbrTuple *nb;
  localNodeDegree=0;
  for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
    if(nb!=NULL){
      if(nb->N_macstatus==LINK_DEFAULT) { //olsr state of neighbors is used
	if(nb->N_time>InlineGetCurrentTime()){
	  if(nb->N_status==ASYM_LINKv4){
	    asymlinks.addNeighbor(&nb->N_addr);
	  }
	  if(nb->N_status==SYM_LINKv4){
	    if(floodingType==ECDS){
	      localNodeDegree++;
	      symlinks.addNeighborExtra(&nb->N_addr,nb->node_degree);
	    } else {
	      symlinks.addNeighbor(&nb->N_addr); 
	    }
	  }
	  if(nb->N_status==MPR_LINKv4){
	    if(floodingType==ECDS){
	      localNodeDegree++;
	      mprlinks.addNeighborExtra(&nb->N_addr,nb->node_degree);
	    } else {
	      mprlinks.addNeighbor(&nb->N_addr); 
	    }
	  }
	  if(nb->N_status==LOST_LINKv4){
	    nb->N_status=PENDING_LINK; //move back to pending link type
	    lostlinks.addNeighbor(&nb->N_addr);
	  }
	}
      } else if (nb->N_macstatus==LINK_UP) {
       	if(nb->N_status==MPR_LINKv4){ //link is always up no matter the olsr state either mpr or sym
	  if(floodingType==ECDS){
	    localNodeDegree++;
	    mprlinks.addNeighborExtra(&nb->N_addr,nb->node_degree);
	  } else {
	    mprlinks.addNeighbor(&nb->N_addr);
	  }
	} else {
	  if(floodingType==ECDS){
	    localNodeDegree++;
	    symlinks.addNeighborExtra(&nb->N_addr,nb->node_degree);
	  } else {
	    symlinks.addNeighbor(&nb->N_addr);
	  }
	}
      } else if (nb->N_macstatus==LINK_DOWN) {
	lostlinks.addNeighbor(&nb->N_addr); //keep sending that the link is lost
      }
    }
  }    
  //  DMSG(4,"size of link messages ASYM=%d | SYM=%d | MPR=%d LOST=%d\n",asymlinks.size,symlinks.size,mprlinks.size,lostlinks.size);

  // build up whole hello message
  HelloMessage hellomessage;
  hellomessage.htime = Mantissa_Hello_Interval; //this value is not currently processed upon being recieved.
  hellomessage.willingness = localWillingness;
  if (!symlinks.neighbors.IsEmpty())
    hellomessage.addLinkMessage(&symlinks);
  if (!mprlinks.neighbors.IsEmpty())
    hellomessage.addLinkMessage(&mprlinks);
  if (!lostlinks.neighbors.IsEmpty())
    hellomessage.addLinkMessage(&lostlinks);
  if (!asymlinks.neighbors.IsEmpty())
    hellomessage.addLinkMessage(&asymlinks);
  //DMSG(4,"%d is size of hello message\n",hellomessage.size);

  // build up Olsr message
  OlsrMessage olsrmessage;
  olsrmessage.type=NRLOLSR_HELLO;  
  olsrmessage.Vtime = doubletomantissa(Neighb_Hold_Time);
  olsrmessage.SetO_addr(myaddress);
  olsrmessage.ttl=1;
  olsrmessage.D_seq_num=seqno;
  olsrmessage.setHelloMessage(&hellomessage);

  DelayedForward(&olsrmessage,0);//will add hello to packet and send out right away
//  DelayedForward(&olsrmessage,0);//will add hello to packet and send out right away
  
  if(helloUseUnicast){
      //we may want to do something similar to minimize the amount of unicast messages sent when not needed
      //if(Hello_Timeout_Factor/2<++helloSentBcastOnly){
          helloSentBcastOnly=0;
          for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext())
          {
              if(nb!=NULL)
              {
                  if(helloUseUnicastOpt){
                      if(nb->konectivity<.99){
                          DMSG(6,"Sending unicast hellos at time %f\n",InlineGetCurrentTime());
                          SendUnicastHello(&olsrmessage,nb->N_addr);
                      }
                  } else {
                      DMSG(6,"Sending unicast hellos at time %f\n",InlineGetCurrentTime());
                      SendUnicastHello(&olsrmessage,nb->N_addr);
                  }
              }
          }
      //} else {
      //    DMSG(8,"Not sending unicast hellos at time %f\n",InlineGetCurrentTime());
     // }
  }
  //  DMSG(4,"%d is size of olsrmessage\n",olsrmessage.size);

  //switched to use the common packet for greater efficencies
  //OlsrPacket olsrpacket;
  //olsrpacket.addOlsrMessage(&olsrmessage);  

  //DMSG(4,"%d is size of packet being sent\n",olsrpacket.size);
  //finished building hello

  // print out hello 
  // HINT: try using ethereal parser for olsr from pf.itd.nrl.navy.mil before using code below
  /*
  int j=0;
  DMSG(1,"*********SENDING HELLO********* at time %f \n",InlineGetCurrentTime());
  for(int i=0;i<buffersize;i++){
    if(i % 4 == 0)
      DMSG(1,"line %d: ",j++);
    DMSG(1,"%02X ",(unsigned char)buffer[i]);
    if(i % 4 == 3)
      DMSG(1,"\n");
  }  
  DMSG(1,"*********HELLO END*********\n");
  */ 
  //end printing

  //sending hello out
  //  olsrpacket2forward.addOlsrMessage(&olsrmessage);
  //char buffer[1500];
  //int buffersize=olsrpacket2forward.pack(buffer,1500);
  //unsigned int len = buffersize; 
  //if(len<helloPadding){ //added for "larger hello packets"
  //  len=helloPadding;
  //  memset((void*)(buffer+buffersize),helloPadding-buffersize,0);
  //}
  //socket.SetTTL(1);
  //turn off the delayed forward timer as the packet is being sent on the hello timer
  //if(delayed_forward_timer.IsActive()){
  //  delayed_forward_timer.Deactivate();
  //}
  //socket.SendTo(buffer, len, broadAddr);
  //clear the packet2forward
  //olsrpacket2forward.clear();
  //  DMSG(6,"Exit: Nrlolsr::SendHello()\n");
  
  // LP 8-30-05 - added
#ifdef OPNET
  total_Hello_sent ++;
  Hello_sent_changed_flag = OPNET_TRUE;
#endif
  // end LP
  
  return true;
}// end Nrlolsr::SendHello()
void
Nrlolsr::SendUnicastHello(OlsrMessage *forwardmessage,ProtoAddress uniAddr){
    uniAddr.SetPort(olsr_port_number);
    if(olsrpacket2forward.size!=4)
    {
        DMSG(1,"Nrlolsr::SendUnicastHello WARNING this was called while messages waiting...sending both messages now\n");
        DelayedForward(forwardmessage,0);//will add hello to packet and send out right away and clear the buffer of waiting messages
    }
    olsrpacket2forward.addOlsrMessage(forwardmessage);
    char forwardbuffer[1500];
    int forwardbuffersize=olsrpacket2forward.pack(forwardbuffer,1500);
    unsigned int forwardlen = forwardbuffersize;
    if(forwardlen<helloPadding){ 
      //last message added to the packet was a hello and padding level is greater than then buffer length.
      forwardlen=helloPadding;
      memset((void*)(forwardbuffer+forwardbuffersize),0,helloPadding-forwardbuffersize);
    }
    socket.SetTTL(1);
    socket.SendTo(forwardbuffer,forwardlen,uniAddr);
    olsrpacket2forward.clear();
    olsrpacket2forward.seqno=pseqno++;
}

bool
Nrlolsr::OnTcTimeout(ProtoTimer& theTimer)
{
  //DMSG(6,"Enter: Nrlolsr::OnTcTimeout(theTimer)\n");
  if(unicastRouting){
    //do tc timer stuff
    if(sendTcTimerOn){
      if(tc_jitter_timer.IsActive()){
	tc_jitter_timer.Deactivate();
      }
      sendTcTimerOn=false;
      //clean up tables
      nb_purge();
      for_purge();
      dup_purge();
      top_purge();
      if(fastreroute){
	makeRoutingTable();
      }
      if(tcSlowDown){ //checking to see if slowdown option is used.
	if(NeighborsStableForTC()){ //checking to see if neighbor table is stable so we can slow down tcs
	  if(tcSlowDownState!=3){ //not at last state of 4 states
	    tcSlowDownState++;
	  } else if(fuzzyflooding && tcloopcounter!=0){ //if fuzzy flooding is on and its in a state other than 0 do nothing
	    //fuzzy flooding has to slow down slower only once per loop so that all nodes get Vtimes which will not be to short
	    //do nothing
	  } else {//double the factor and set the state to 0;
	    tcSlowDownState=0;
	    tcSlowDownFactor=tcSlowDownFactor*2;
	    if(tcSlowDownFactor*TC_Interval>3600) { //just capping the tc interval to one hour
	      tcSlowDownFactor=tcSlowDownFactor/2;
	    }
	    tc_timer.SetInterval(TC_Interval*tcSlowDownFactor);
	    DMSG(8,"%s's tcslowdownfactor is up to %d\n",myaddress.GetHostString(),tcSlowDownFactor);
	  }
	} else { //neighbor table is not stable reset everything
	  tcSlowDownState=0;
	  tcSlowDownFactor=1;
	  DMSG(8,"%s's tcslowdownfactor is reset to %d\n",myaddress.GetHostString(),tcSlowDownFactor);
	}
      }
      if(dotcextra){
	SendTcExtra();
      } else {
	SendTc();
      }
    } else {
      sendTcTimerOn=true;
      double randValue = UniformRand(TC_Interval)*TC_Jitter;
      if(tcSlowDown){
	randValue= UniformRand(TC_Interval*tcSlowDownFactor)*TC_Jitter;
      }
      tc_jitter_timer.SetInterval(randValue);
      timerMgrPtr->ActivateTimer(tc_jitter_timer);
    }
  }
  //DMSG(6,"Exit: Nrlolsr::OnTcTimeout(theTimer)\n");
  return true;
} // end Nrlolsr::OnTcTimeout()

bool
Nrlolsr::OnHnaTimeout(ProtoTimer& theTimer)
{
  //DMSG(6,"Enter: Nrlolsr::OnHnaTimeout(theTimer)\n");
  if(unicastRouting){
    //do hna timer stuff
    if(sendHnaTimerOn){
      if(hna_jitter_timer.IsActive()){
	hna_jitter_timer.Deactivate();
      }    
      sendHnaTimerOn=false;
      SendHna();
    } else {
      sendHnaTimerOn=true;
      printHnaLinks();
      double randValue = UniformRand(HNA_Interval)*HNA_Jitter;
      hna_jitter_timer.SetInterval(randValue);
      timerMgrPtr->ActivateTimer(hna_jitter_timer);
    }
  }
  //DMSG(6,"Exit: Nrlolsr::OnHnaTimeout(theTimer)\n");
  return true;
} // end Nrlolsr::OnHnaTimeout()

bool
Nrlolsr::SendHna(){
  //DMSG(6,"Enter: Nrlolsr::SendHna()\n");
  if(dohna){
    //DMSG(2,"sending thehna \n");

    seqno++;
    NbrTuple* hna;
    HNAMessage hnamessage;
    for(hna=hnaAddresses.PrintPeekInit();hna!=NULL;hna=hnaAddresses.PrintPeekNext()){
      //      DMSG(2,"adding %s with mask ",hna->N_addr.GetHostString());
      //DMSG(2,"%s\n",hna->N_2hop_addr.GetHostString());
      hnamessage.addNetwork(&hna->N_addr,&hna->N_2hop_addr);
    }
    OlsrMessage olsrmessage;
    olsrmessage.type=NRLOLSR_HNA_MESSAGE;
    olsrmessage.Vtime=doubletomantissa(HNA_Hold_Time);
    olsrmessage.SetO_addr(myaddress);
    if(fuzzyflooding){
      olsrmessage.ttl=floodingdistance[hnaloopcounter++];
      hnaloopcounter=hnaloopcounter % 16;
      olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*olsrmessage.ttl/2);//set Vtime based upon how often far away nodes will hear tc
    } else {
      olsrmessage.ttl=NETWORK_DIAMETER;
    }
    olsrmessage.D_seq_num=seqno;
    olsrmessage.setHNAMessage(&hnamessage);

    DelayedForward(&olsrmessage,0);//this will append the message to packet2forward and send it out

    //OlsrPacket olsrpacket;
    //olsrpacket.addOlsrMessage(&olsrmessage);
    //char buffer[1500];
    //int buffersize=olsrpacket.pack(buffer,1500);
    //unsigned int len = buffersize;

    //socket.SetTTL(1);
    //socket.SendTo(buffer, len, broadAddr);
    
    //DMSG(2,"sent thehna \n");
  }
  //DMSG(6,"Exit: Nrlolsr::SendHna()\n");
  return true;
}
bool 
Nrlolsr::SendTc()
{
  DMSG(6,"Enter: Nrlolsr::SendTC()\n");
  if((!mprSelectorList.IsEmpty() && !allLinks) || //send tc message with mpr selector set info
     (!nbr_list.IsEmpty() && allLinks && localWillingness!=0)){          //send tc message with full link info
    DMSG(8,"sending tc from %s at time %f \n",myaddress.GetHostString(),InlineGetCurrentTime());

    seqno++;
    TCMessage tcmessage;
    tcmessage.mssn=mssn;
    tcmessage.reserved=0;
    NbrTuple *nb;
    int numberOfAddr=0;
    // adding the address into the packet to be sent off
    if(!allLinks){ //fill in mpr info
      for(nb=mprSelectorList.PeekInit();nb!=NULL;nb=mprSelectorList.PeekNext()){
	if(nb!=NULL){
	  //DMSG(10,"Adding %s to the tc message\n",nb->N_addr.GetHostString());
	  numberOfAddr++;
	  tcmessage.addMprSelector(&nb->N_addr);
	}
      }
    } else { //fill in full link info
      for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
	if(nb!=NULL){
	  if((nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && nb->N_macstatus!=LINK_DOWN){ // check to make sure is symetric link
	    //DMSG(10,"%s is the link address\n",nb->N_addr.GetHostString());
	    numberOfAddr++;
	    tcmessage.addMprSelector(&nb->N_addr);
	  }
	}
      }
    }
    if(numberOfAddr==0) {//can happen in alllinks mode when only asymetric neighbors are in neighbor table
      return true;
    }
    // build up Olsr message
    OlsrMessage olsrmessage;
    olsrmessage.type=NRLOLSR_TC_MESSAGE;
    olsrmessage.Vtime=doubletomantissa(Top_Hold_Time);
    if(tcSlowDown && (tcSlowDownState>0 || tcSlowDownFactor!=1)){
      olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*(double)tcSlowDownFactor/2);
    }
    olsrmessage.SetO_addr(myaddress);
    if(fuzzyflooding){
      olsrmessage.ttl=floodingdistance[tcloopcounter++];
      tcloopcounter = tcloopcounter % 16;
      olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*olsrmessage.ttl/2);//set Vtime based upon how often far away nodes will hear tc
      if(tcSlowDown && (tcSlowDownState>0 || tcSlowDownFactor!=1)){
	olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*olsrmessage.ttl/2*(double)tcSlowDownFactor/2); //this prob doesn't currently v7.5 work
      }
    } else {
      olsrmessage.ttl=NETWORK_DIAMETER;
    }
    olsrmessage.D_seq_num=seqno;
    olsrmessage.setTCMessage(&tcmessage);

    DelayedForward(&olsrmessage,0);//this will append the tc message to the packet2forward and send it right out

    //OlsrPacket olsrpacket;
    //olsrpacket.addOlsrMessage(&olsrmessage);
    //char buffer[1500];
    //int buffersize=olsrpacket.pack(buffer,1500);

    // printing tc only use this code after trying to use ethereal parser found at pf.itd.nrl.navy.mil its much easier to use that    
    //if(ipvMode==ProtoAddress::SIM){
    //  int j=0;
    //  DMSG(1,"***********TC MESSAGE from %s***********\n",myaddress.GetHostString());
    //  for(int i=0;i<buffersize;i++){
    //	if(i % 4 == 0)
    //	  DMSG(1,"line %d: ",j++);
    //	DMSG(1,"%02X ",(unsigned char)(buffer[i]));
    //	if(i % 4 == 3)
    //	  DMSG(1,"\n");
    // }  
    // DMSG(1,"***********END TC ************\n");
    //} //end printing tc

    //finished building tc
    //sending tc out
    //unsigned int len = buffersize;
    //socket.SetTTL(1);
    //socket.SendTo(buffer, len, broadAddr);
		
	// LP 8-30-05 - added
#ifdef OPNET
    total_TC_sent ++;
    TC_sent_changed_flag = OPNET_TRUE;
#endif
    // end LP

  }
  //DMSG(6,"Exit: Nrlolsr::SendTC()\n");
  return true;
} // end Nrlolsr::SendTc()

bool 
Nrlolsr::SendTcExtra()
{
  //DMSG(6,"Enter: Nrlolsr::SendTCExtra()\n");
  if((!mprSelectorList.IsEmpty() && !allLinks) || //send tc message with mpr selector set info
     (!nbr_list.IsEmpty() && allLinks)){          //send tc message with full link info
    //DMSG(9,"sending tc from %s at time %f \n",myaddress.GetHostString(),InlineGetCurrentTime());
    seqno++;
    TCMessageExtra tcmessageextra;
    tcmessageextra.mssn=mssn;
    tcmessageextra.reserved=0;
    NbrTuple *nb;
    int numberOfAddr=0;
    // adding the address into the packet to be sent off
    if(!allLinks){ //fill in mpr info
      //below commented section was replaced with above less efficent section to get the konectivity value
      for(nb=mprSelectorList.PeekInit();nb!=NULL;nb=mprSelectorList.PeekNext()){
      	if(nb!=NULL){
      	  //DMSG(10,"Adding %s to the tc message\n",nb->N_addr.GetHostString());
      	  numberOfAddr++;
		  //tcmessageextra.addMprSelector(&nb->N_addr,(UINT8)nb->N_minmax,(UINT8)nb->N_spf);
		  //find link metric values if they were not set by the -link command	
		  if(!(nb->N_spf_link_set)){//link is not set so we need to find a reasonable link metric
			  nb->N_spf=(UINT32)(255-(UINT8)(nbr_list.FindObject(nb->N_addr)->konectivity*255));
		  }
		  if(!(nb->N_minmax_link_set)){//link is not set so we need to find a reasonable link metric
			  nb->N_minmax=(UINT32)(nbr_list.FindObject(nb->N_addr)->konectivity*255);
		  }	
		  tcmessageextra.addMprSelector(&nb->N_addr,(UINT8)nb->N_minmax,(UINT8)nb->N_spf);
      	}
      }
    } else { //fill in full link info
      for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
	if(nb!=NULL){
	  if((nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && (nb->N_macstatus!=LINK_DOWN)){ // check to make sure is symetric link
	    //DMSG(10,"%s is the link address\n",nb->N_addr.GetHostString());
	    numberOfAddr++;
		//find link metric values if they were not set by the -link command
		if(!(nb->N_spf_link_set)){//link is not set so we need to find a reasonable link metric
		  nb->N_spf=(UINT32)(255-(UINT8)(nbr_list.FindObject(nb->N_addr)->konectivity*255));
		}
		if(!(nb->N_minmax_link_set)){//link is not set so we need to find a reasonable link metric
		  nb->N_minmax=(UINT32)(nbr_list.FindObject(nb->N_addr)->konectivity*255);
		}
		tcmessageextra.addMprSelector(&nb->N_addr,(UINT8)nb->N_minmax,(UINT8)nb->N_spf);//using hysterisis value for min max routing
	  }
	}
      }
    }
    // build up Olsr message
    OlsrMessage olsrmessage;
    olsrmessage.type=NRLOLSR_TC_MESSAGE_EXTRA;
    olsrmessage.Vtime=doubletomantissa(Top_Hold_Time);
    if(tcSlowDown && (tcSlowDownState>0 || tcSlowDownFactor!=1)){
      olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*(double)tcSlowDownFactor/2);
    }
    olsrmessage.SetO_addr(myaddress);
    if(fuzzyflooding){
      olsrmessage.ttl=floodingdistance[tcloopcounter++];
      tcloopcounter=tcloopcounter % 16;
      olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*olsrmessage.ttl/2);//set Vtime based upon how often far away nodes will hear tc
      if(tcSlowDown && (tcSlowDownState>0 || tcSlowDownFactor!=1)){
	olsrmessage.Vtime=doubletomantissa(Top_Hold_Time*olsrmessage.ttl/2*(double)tcSlowDownFactor/2); //this may not currntly work v7.5
      }
    } else {
      olsrmessage.ttl=NETWORK_DIAMETER;
    }
    olsrmessage.D_seq_num=seqno;
    olsrmessage.setTCMessageExtra(&tcmessageextra);

    DelayedForward(&olsrmessage,0);//this will append the tc extra message and send it out 

    //OlsrPacket olsrpacket;
    //olsrpacket.addOlsrMessage(&olsrmessage);
    //char buffer[1500];
    //int buffersize=olsrpacket.pack(buffer,1500);

    // printing tc only use this code after trying to use ethereal parser found at pf.itd.nrl.navy.mil its much easier to use that    

    //    if(ipvMode==ProtoAddress::SIM){
    //  int j=0;
    //  DMSG(3,"***********TC MESSAGE EXTRA %s***********\n",myaddress.GetHostString());
    //  for(int i=0;i<buffersize;i++){
    //	if(3 % 4 == 0)
    //	  DMSG(3,"line %d: ",j++);
    //	DMSG(3,"%02X ",(unsigned char)(buffer[i]));
    //	if(i % 4 == 3)
    //	  DMSG(3,"\n");
    // }  
    // DMSG(3,"***********END TC EXTRA ************\n");
    //} //end printing tc
    
    //finished building tc
    //sending tc out
    //unsigned int len = buffersize;
    //socket.SetTTL(1);
    //socket.SendTo(buffer, len, broadAddr);
  }
  //DMSG(6,"Exit: Nrlolsr::SendTCExtra()\n");
    
  // LP 8-30-05 - added
#ifdef OPNET
  total_TC_sent ++;
  TC_sent_changed_flag = OPNET_TRUE;
#endif
  // end LP

  return true;
} // end Nrlolsr::SendTcExtra()

void
Nrlolsr::OnSocketEvent(ProtoSocket &thesocket,ProtoSocket::Event theEvent)
{
  DMSG(6,"Enter: Nrlolsr::OnSocketEvent(thesocket,theEvent)\n");
  //  printRoutingTable(2);
  switch (theEvent)
    {
    case ProtoSocket::INVALID_EVENT:
    case ProtoSocket::ERROR_:
      TRACE("ERROR) ...\n");
      break;
    case ProtoSocket::CONNECT:
      TRACE("CONNECT) ...\n");
      break;  
    case ProtoSocket::ACCEPT:
      TRACE("ACCEPT) ...\n");
      break; 
    case ProtoSocket::SEND:
      {
	TRACE("SEND) ...\n");
	break; 
      }
    case ProtoSocket::RECV:
      {
	bool redoroutingtable = false;
	char buffer[1500];
	unsigned int len = 1500;
	ProtoAddress addr;
	if(!thesocket.RecvFrom(buffer, len, addr)){
	  DMSG(0,"OnSocketEvent: error with RecvFrom\n");
	  //  DMSG(6,"Exit: Nrlolsr::OnSocketEvent(thesocket,theEvent)\n");
	  return;
	}
	if((len % 4) != 0){
	  DMSG(0,"Exit: onSocketEvent() invalid packet size %d value \n",len);
	  //DMSG(6,"Exit: Nrlolsr::OnSocketEvent(thesocket,theEvent)\n");
	  return;
	}
	
	// print recieved message yet again please try and use ethereal parser but you can fall back to this code if something is wrong
	int j=0;
	  DMSG(1,"***********RECV MESSAGE*********** at time %f from %s \n",InlineGetCurrentTime(),addr.GetHostString());
	  for(int i=0;i<(int)len;i++){
	  if(i % 4 == 0)
	  DMSG(1,"line %d: ",j++);
	  DMSG(1,"%02X ",(unsigned char)buffer[i]);
	  if(i % 4 == 3)
	  DMSG(1,"\n");
	  }  
	  DMSG(1,"***********END RECV ************\n");
	//end printing recieved message
	OlsrPacket olsrpacket;
	olsrpacket.unpack(buffer,len,ipvMode);
	//cleaning up tables and preparing to parse messages
	nb_purge();
	for_purge();
	dup_purge();
	top_purge();
	hna_purge();
	// go though the messages
	char* littlebuffer;
	int olsrmessagesize = 0;
	int messagenumberindex=0;
	while((littlebuffer = (char*)olsrpacket.messages.peekNext(&olsrmessagesize))){
	  messagenumberindex++;
	  OlsrMessage olsrmessage;
	  DMSG(6,"unpacking  olsrmessage\n");
	  olsrmessage.unpack(littlebuffer,olsrmessagesize,ipvMode);
	  DMSG(6,"%s is processing %d message number %d of the packet\n",myaddress.GetHostString(),olsrmessage.type,messagenumberindex);

	  if(IsDuplicate(olsrmessage.O_addr,olsrmessage.D_seq_num)){ // checking to see if message has already been processed.
	    printDuplicateTable(4);
	    //DMSG(7,"recieved duplicate dropping \n");
	  } else { //first time recieving message process it
	    
	    printDuplicateTable(4);
	    //this line has to be moved below and only done for symetric links or it breaks the algorithm
	    //addDuplicate(olsrmessage.O_addr,olsrmessage.D_seq_num);
	    int olsrmessageheadersize = 8;
	    
	    if(ipvMode==ProtoAddress::IPv4 || ipvMode==ProtoAddress::SIM)
	      olsrmessageheadersize +=4;
	    else
	      olsrmessageheadersize +=16;
	    
	    if(olsrmessage.type==NRLOLSR_HELLO){
	      DMSG(8,"%s recieving the hello from ",myaddress.GetHostString());
	      DMSG(8,"%s loud and clear at time %f\n",olsrmessage.O_addr.GetHostString(),InlineGetCurrentTime());
	      redoroutingtable = true;
	      if(ipvMode==ProtoAddress::IPv6 && addr.IsValid()){
		ProtoAddress temp_addr;
		unsigned int temp_ifIndex;
		int temp_metric;
		if(!llToGlobal.GetRoute(addr,8*addr.GetLength(),temp_addr,temp_ifIndex,temp_metric)){
		  llToGlobal.SetRoute(addr,8*addr.GetLength(),olsrmessage.O_addr); //this mapping is used to check to see if we should forward tc packets later when all we have is the ll address of the previous hop.
		}
	      }

	      //its a hello message parse the interface messages lists
	      //printCurrentTable(3);
	      //process the originator address
	      HelloMessage hellomessage;
	      hellomessage.unpack(olsrmessage.message,olsrmessage.size-olsrmessageheadersize,ipvMode);
	      UINT8 spfValue=0;
	      UINT8 minmaxValue=0;
	      update_nbr(olsrmessage.O_addr,ASYM_LINKv4,spfValue,minmaxValue,olsrmessage.Vtime,hellomessage.willingness);
	      
	      // for printing again use ethereal parser if possible
	      /*
		int buffersize=hellomessage.pack(buffer,1500);
		DMSG(8,"***********RECV HELLO***********\n");
		for(int i=0;i<(int)buffersize;i++){
		if(i % 4 == 0)
		DMSG(8,"line %d: ",j++);
		DMSG(8,"%02X ",(unsigned char)buffer[i]);
		if(i % 4 == 3)
		DMSG(8,"\n");
		}  
		DMSG(8,"***********END HELLO RECV************\n");
	      */
	      //end printing
		  
		  	      // LP 8-30-05- added
#ifdef OPNET
		  total_Hello_rcv ++;
		  Hello_rcv_changed_flag = OPNET_TRUE;
#endif
		  // end LP
	      	      
	      //go though neighbor different link types
	      hellomessage.messages.peekInit();
	      int linkmessagesize=0;
	      unsigned long onehopnodedegree=0;
	      while((littlebuffer = (char*)hellomessage.messages.peekNext(&linkmessagesize))){ //loop to process link messages
		LinkMessage linkmessage;
		//the next 2 variable are only used for manet ospf extensions used in conjunction with smf code.
		unsigned long twohopnodedegree = 0; //this is only used for manet ospf extensions
		int degreesize=0; //this isn't really needed because degree size is always 4
		//end ospf variables;

		linkmessage.unpack(littlebuffer,linkmessagesize,ipvMode);
		linkmessage.neighbors.peekInit();
		int neighboraddresssize=0;
		switch(linkmessage.linkCode) {
		case ASYM_LINKv4:
		  //DMSG(8,"in the asymlink area \n");
		  while((littlebuffer = (char*)linkmessage.neighbors.peekNext(&neighboraddresssize))){ //sets littlebuffer to next object size in addresssize
		    //UINT32 neighboraddress = ntohl(((UINT32*)littlebuffer)[0]); 
		    //if(neighboraddress==myaddress.IPv4HostAddr()){
		    ProtoAddress nbr_addr;
		    nbr_addr.SetRawHostAddress(ipvMode,littlebuffer,neighboraddresssize);
		    if(nbr_addr.HostIsEqual(myaddress)){
		      UINT8 spfValue=0;
		      UINT8 minmaxValue=0;
		      update_nbr(olsrmessage.O_addr,SYM_LINKv4,spfValue,minmaxValue);
		    }
		  }
		  //DMSG(8,"returned from update in asym area \n");
		  break;
		case SYM_LINKv4:
		case MPR_LINKv4:
		  if(linkmessage.reserved==1) { //message has degree information
		    linkmessage.degrees.peekInit();
		  }
		  //DMSG(8,"in the sym/mpr link area \n");
		  while((littlebuffer = (char*)linkmessage.neighbors.peekNext(&neighboraddresssize))){
		    onehopnodedegree++;
		    if(linkmessage.reserved==1){
		      twohopnodedegree = (unsigned long)(*(UINT32*)linkmessage.degrees.peekNext(&degreesize));
		    }
		    //	      UINT32 neighboraddress = ntohl(((UINT32*)littlebuffer)[0]); 
		    ProtoAddress nbr_addr;
		    nbr_addr.SetRawHostAddress(ipvMode,littlebuffer,neighboraddresssize);
		    //DMSG(9,"in while loop of sym/mpr link area %s ",nbr_addr.GetHostString());
		    //DMSG(9,"<- is %s's nbr address\n",olsrmessage.O_addr.GetHostString());
		    
		    if(nbr_addr.HostIsEqual(myaddress)){	      //if(neighboraddress==myaddress.IPv4HostAddr()){
		      update_mprselector(olsrmessage.O_addr,linkmessage.linkCode); //add/remove from mpr selector set depending on type
		      UINT8 spfValue=0;
		      UINT8 minmaxValue=0;
		      update_nbr(olsrmessage.O_addr,SYM_LINKv4,spfValue,minmaxValue); // will update the time this doesn't mean its not an mpr
		    } else {
		      //DMSG(9,"updating 2 hop neighbor table\n");
		      if(linkmessage.reserved ==0){
			update_2hop_nbr(olsrmessage.O_addr,nbr_addr);
		      } else {
			update_2hop_nbrExtra(olsrmessage.O_addr,nbr_addr,twohopnodedegree);
		      }
		      
		    }
		  }
		  //DMSG(8,"returned from update in sym/mpr \n");
		  break;
		case LOST_LINKv4:
		  //DMSG(8,"in the lostlink area \n");
		  while((littlebuffer = (char*)linkmessage.neighbors.peekNext(&neighboraddresssize))){
		    //UINT32 neighboraddress = ntohl(((UINT32*)littlebuffer)[0]);
		    ProtoAddress nbr_addr;
		    nbr_addr.SetRawHostAddress(ipvMode,littlebuffer,neighboraddresssize);
		    //DMSG(9,"in while loop of lost link area %s <= is ",nbr_addr.GetHostString());
		    //DMSG(9,"%s's nbr address\n",olsrmessage.O_addr.GetHostString());
		    if(nbr_addr.HostIsEqual(myaddress)){  // if(neighboraddress==myaddress.IPv4HostAddr()){
		      //make asym link and lose all of its 2 hop neighbors		
		      UINT8 spfValue=0;
		      UINT8 minmaxValue=0;
		      update_nbr(olsrmessage.O_addr,LOST_LINKv4,spfValue,minmaxValue);
		    } else {
		      remove_2hop_link(olsrmessage.O_addr,nbr_addr);
		    }
		  }
		  //DMSG(8,"returned from updating in lost area \n");
		  break;
		}
	      }
	      if(floodingType==ECDS){
		NbrTuple *one_hop_tuple_pt=nbr_list.FindObject(olsrmessage.O_addr);
		if(one_hop_tuple_pt){ 
		  one_hop_tuple_pt->node_degree = onehopnodedegree;
		} else {
		  fprintf(stderr, "in socket recv of nrlolsr coudn't find %s in one hop list and it should ALWAYS be there\n",one_hop_tuple_pt->N_addr.GetHostString());
		}
	      }
	      if(NeighborsStableForHello()){
		redoroutingtable=false;
	      } else { //not stable
		if(tcSlowDown && (tcSlowDownState!=0 || tcSlowDownFactor!=1)){ //send out tc message and reset the tc slowdown factors
		  sendTcTimerOn=true; //so ontctimeout sends tc and resets timers
		  ProtoTimer emptytimer;
		  OnTcTimeout(emptytimer); //send out tc message because neighbors have changed
		}
	      }
	      //	DMSG(8,"finished parsing hello message\n");
	      //printCurrentTable(3); 


	      if(updateSmfForwardingInfo){
		SendForwardingInfo();
	      }

	    } else if(olsrmessage.type==NRLOLSR_TC_MESSAGE) {
	      //DMSG(8,"%s recieving the tc from ",myaddress.GetHostString());
	      //DMSG(8,"%s loud and clear\n",olsrmessage.O_addr.GetHostString());
	      redoroutingtable = true;
	      //printTopology(3);
		  		  
		  // LP 8-30-05- added
#ifdef OPNET
		  total_TC_rcv ++;
		  TC_rcv_changed_flag = OPNET_TRUE;
#endif
		  // end LP
		  
	      TCMessage tc;
	      tc.unpack(olsrmessage.message,olsrmessage.size-olsrmessageheadersize,ipvMode);
	      //    if(strcmp(olsrmessage.O_addr.GetHostString(),"46")==0){
	      //	DMSG(3,"%s is processing TC message from 46 with mssn number %d\n",myaddress.GetHostString(),tc.mssn);
	      //
	      if(updateTopology(olsrmessage.O_addr,tc.mssn)){  // check to see if mssn is most current
		int mprselectorsize=0; //not really used but holds value of size of object returned
		tc.mprselectors.peekInit();
		while((littlebuffer = (char*)tc.mprselectors.peekNext(&mprselectorsize))){
		  ProtoAddress nbr_addr;
		  nbr_addr.SetRawHostAddress(ipvMode,littlebuffer,mprselectorsize);	   
		  //DMSG(9,"in while of tc %s",nbr_addr.GetHostString());
		  //DMSG(9,"<- is mprselector address of %s",olsrmessage.O_addr.GetHostString());
		  //DMSG(9," %s <- is my address\n",myaddress.GetHostString());
		  UINT8 spfValue=0;
		  UINT8 minmaxValue=0;
		  addTopologyInfo(olsrmessage.O_addr,nbr_addr,tc.mssn,spfValue,minmaxValue,olsrmessage.Vtime);
		}
		// update tables and then forward tc message if it was sent by a node that selected this node as its mpr
		//printTopology(3);
		//will check for to see if should forward packet later in this function and forward if needed
	      } else { //not the most up to date mssn number
		redoroutingtable = false;
	      } 
	    } else if(olsrmessage.type==NRLOLSR_TC_MESSAGE_EXTRA) {
	      //DMSG(8,"%s recieving the tc from ",myaddress.GetHostString());
	      //DMSG(8,"%s loud and clear\n",olsrmessage.O_addr.GetHostString());
	      redoroutingtable = true;
	      //printTopology(3);
		  		  
		  // LP 8-30-05- added
#ifdef OPNET
		  total_TC_rcv ++;
		  TC_rcv_changed_flag = OPNET_TRUE;
#endif
		  // end LP

	      TCMessageExtra tc;
	      UINT8* spf_value_ptr=NULL;
	      UINT8* minmax_value_ptr=NULL;
	      tc.unpack(olsrmessage.message,olsrmessage.size-olsrmessageheadersize,ipvMode);
	      if(updateTopology(olsrmessage.O_addr,tc.mssn)){  // check to see if mssn is most current
		int mprselectorsize=0; //not really used but holds value of size of object returned
		int spfsize=0; 
		int minmaxsize=0; //same as mprelectorsize in that it isn't used.
		tc.mprselectors.peekInit();
		tc.spf.peekInit();
		tc.minmax.peekInit();
		while((littlebuffer = (char*)tc.mprselectors.peekNext(&mprselectorsize))){
		  ProtoAddress nbr_addr;
		  nbr_addr.SetRawHostAddress(ipvMode,littlebuffer,mprselectorsize);	   
		  spf_value_ptr=(UINT8*)tc.spf.peekNext(&spfsize);
		  minmax_value_ptr=(UINT8*)tc.minmax.peekNext(&minmaxsize);
		  
		  //DMSG(8,"in while of tc %s",nbr_addr.GetHostString());
		  //DMSG(8,"<- is mprselector address of %s with minmax value of %d",olsrmessage.O_addr.GetHostString(),*minmax_value_ptr);
		  //DMSG(8," %s <- is my address\n",myaddress.GetHostString());
		 
		  if(minmax_value_ptr==NULL || spf_value_ptr==NULL) {
		    DMSG(0,"Nrlolsr::OnSocketEvent: NRLOLSR_TC_MESSAGE_EXTRA area: minmax or spf pointer is equal to null when links are still present\n");
		  }
		  addTopologyInfo(olsrmessage.O_addr,nbr_addr,tc.mssn,*spf_value_ptr,*minmax_value_ptr,olsrmessage.Vtime);
		}
		// update tables and then forward tc message if it was sent by a node that selected this node as its mpr
		//printTopology(3);
		//will check for to see if should forward packet later in this function and forward if needed
	      } 
	    } else if(olsrmessage.type==NRLOLSR_HNA_MESSAGE) {
	      int hnasize=0; //not really used but holds value of size of object returned
	      HNAMessage hna;
	      hna.unpack(olsrmessage.message,olsrmessage.size-olsrmessageheadersize,ipvMode);
	      ProtoAddress hna_addr,hna_mask;
	      bool addrturn = true;
	      hna.networksandmasks.peekInit();
	      //DMSG(4,"size of hna message %s\n",hna.size)
#ifndef SIMULATE
#ifdef UNIX
		  if(olsrDebugValue>=2){ //this if block prints out all hna info of a neighbor as they get parsed.  going to be used by cmap for display
			FILE *fid = popen("date -u +%T","r");
			char dateBuffer[10];
			char *trashCharPtr = NULL;
                        trashCharPtr = fgets(dateBuffer,9,fid);
			pclose(fid);
			fprintf(stdout,"Hna-Networks List for %s: %s.%06d\n",olsrmessage.O_addr.GetHostString(),dateBuffer,GetLittleTime());
		  }
#endif //UNIX
#endif //SIMULATE      
	      while((littlebuffer = (char*)hna.networksandmasks.peekNext(&hnasize))){
			if(addrturn) {
			  hna_addr.SetRawHostAddress(ipvMode,littlebuffer,hnasize);
			} else {
			  hna_mask.SetRawHostAddress(ipvMode,littlebuffer,hnasize);
			  addHnaInfo(olsrmessage.O_addr,hna_addr,hna_mask,olsrmessage.Vtime);
#ifndef SIMULATE
#ifdef UNIX
			  if(olsrDebugValue>=2){
				fprintf(stdout,"%s -> ",olsrmessage.O_addr.GetHostString());//fixme
				fprintf(stdout,"%s/%d\n",hna_addr.GetHostString(),hna_mask.GetPrefixLength());
			  }
#endif //UNIX
#endif //SIMULATE      
			}
			addrturn=!addrturn;
	      }
#ifndef SIMULATE
#ifdef UNIX
	      if(olsrDebugValue>=2){
			fprintf(stdout,"End of Hna-Networks List for %s\n",olsrmessage.O_addr.GetHostString());
			fflush(stdout);	  
	      }
#endif //UNIX
#endif //SIMULATE      
	      // moved forwarding out of processing area so forwarding is checked after each message is fully processed or ignored
	    } //finished processing message check for forwarding and duplicate entry
	    //we need to check for symetry before continuing to forwarding section
	    NbrTuple* sym_check_ptr;
	    ProtoAddress globalAddr; //this address is only used for ipv6
	    if(ipvMode!=ProtoAddress::IPv6){ //check to see if packet was reieved from symetric neighbor
	      sym_check_ptr = nbr_list.FindObject(addr);
	      globalAddr.SetRawHostAddress(ipvMode,addr.GetRawHostAddress(),addr.GetLength());
	    } else {
	      unsigned int ifIndex;
	      int metric;
	      llToGlobal.GetRoute(addr,addr.GetLength()*8,globalAddr,ifIndex,metric);
	      sym_check_ptr = nbr_list.FindObject(globalAddr);
	    }
	    if(sym_check_ptr){
	      if((sym_check_ptr->N_status == SYM_LINKv4) || (sym_check_ptr->N_status == MPR_LINKv4)){ //neighbor is symetric and packet can be added to dup table.
		

		//if(!WasForwarded(olsrmessage.O_addr,olsrmessage.D_seq_num) && !mprSelectorList.IsEmpty()){ //message hasn't been forwared yet and I am mpr
		// (forwarding table is redundant and is meant to be used only with multiple interfaces)
		if(!WasForwarded(olsrmessage.O_addr,olsrmessage.D_seq_num) && (NULL!=mprSelectorList.FindObject(globalAddr))){//message hasn't been forwared yet and I am mpr  
		  if(olsrmessage.ttl!=0 && ((olsrmessage.type==NRLOLSR_TC_MESSAGE) || (olsrmessage.type==NRLOLSR_HNA_MESSAGE) || (olsrmessage.type==NRLOLSR_TC_MESSAGE_EXTRA))){
		    //		if(strcmp(olsrmessage.O_addr.GetHostString(),"46")==0 && olsrmessage.type==NRLOLSR_TC_MESSAGE){
		    //TCMessage tc;
		    //tc.unpack(olsrmessage.message,olsrmessage.size-12,ipvMode);
		    //DMSG(3,"%s is forwarding ",myaddress.GetHostString());
		    //DMSG(3,"TC message originated from ");
		    //DMSG(3,"%s with mssn number %d ttl of %d and hopc of %d\n",olsrmessage.O_addr.GetHostString(),tc.mssn,olsrmessage.ttl,olsrmessage.hopc);
		    //
		    addForwarded(olsrmessage.O_addr,olsrmessage.D_seq_num);
		    double delay = UniformRand(fdelay);
		    DelayedForward(&olsrmessage,delay);
		    //thesocket.SendTo(forwardbuffer, forwardlen, broadAddr);
		  }
		}//finished forwarding 	    
		//check to see if neighbor is semetric
		addDuplicate(olsrmessage.O_addr,olsrmessage.D_seq_num);
	      }
	    }	  
	  } 
	}
	//printRoutingTable(3);
	//redoroutingtable = true; // theres a problem currently with timed out neighbors not setting flag. but this was using too much cpu time so redoing routes on hellos
	if(redoroutingtable && fastreroute) {
	  makeRoutingTable();
	  //makeNewRoutingTable();
	  addHnaRoutes();
	  //printRoutingTable(3);
	}
	//DMSG(6,"Exit: Nrlolsr::OnSocketEvent(thesocket,theEvent)\n");
	return;
      }
    case ProtoSocket::DISCONNECT:
      TRACE("DISCONNECT) ...\n");
      break;  
      //    case ProtoSocket::ERROR_:
      // TRACE("Error) invalid event in Nrlolsr::OnSocketEvent() ...\n");
      //break;
    case ProtoSocket::EXCEPTION:
      TRACE("EXCEPTION) event in Nrlolsr::OnSocketEvent() ...\n");
      break;
    }
  //DMSG(6,"Exit: Nrlolsr::OnSocketEvent(thesocket,theEvent)\n");
  return;
}//end Nrlolsr::OnSocketEvent(thesocket,theEvent)}
void
Nrlolsr::DelayedForward(OlsrMessage *forwardmessage, double delay){
  DMSG(6,"Enter: Nrlolsr::DelayedForward(OlsrMessage *forwardmessage,double delay)\n");
  if(!forwardmessage->O_addr.HostIsEqual(myaddress)){ //only decrement ttl and hopc if messages was not originated by myaddress
	forwardmessage->ttl--;
	forwardmessage->hopc++;
  }
  //OlsrPacket olsrpacket2forward;
  olsrpacket2forward.addOlsrMessage(forwardmessage);
  
  if(delay>0){
    if(delayed_forward_timer.IsActive()){
      //do nothing timer is already active
      a8packedmessages++;
      DMSG(8,"node %s is adding message number %d to packet2forward\n",myaddress.GetHostString(),a8packedmessages);
    } else {
      DMSG(8,"node %s adding first message to packet2foward\n",myaddress.GetHostString());
      a8packedmessages=1;
      delayed_forward_timer.SetInterval(delay);
      delayed_forward_timer.SetRepeat(0);
      timerMgrPtr->ActivateTimer(delayed_forward_timer);
   }
  } else {
    DMSG(4,"node %s is forwarding message right away\n",myaddress.GetHostString());
    if(delayed_forward_timer.IsActive()){
      delayed_forward_timer.Deactivate();//we will be sending the packet right away so we are going to turn the timer off
    }
    char forwardbuffer[1500];
    int forwardbuffersize=olsrpacket2forward.pack(forwardbuffer,1500);
    unsigned int forwardlen = forwardbuffersize;

    if(forwardlen<helloPadding && forwardmessage->type==NRLOLSR_HELLO){ 
      //last message added to the packet was a hello and padding level is greater than then buffer length.
      forwardlen=helloPadding;
      memset((void*)(forwardbuffer+forwardbuffersize),0,helloPadding-forwardbuffersize);
    }
    socket.SetTTL(1);
    socket.SendTo(forwardbuffer,forwardlen,broadAddr);
    olsrpacket2forward.clear();
    olsrpacket2forward.seqno=pseqno++;
  }
}
bool
Nrlolsr::OnDelayedForwardTimeout(ProtoTimer &theTimer){
  DMSG(4,"forwarding packet from %s at time %f\n",myaddress.GetHostString(),InlineGetCurrentTime());
  char forwardbuffer[1500];
  int forwardbuffersize=olsrpacket2forward.pack(forwardbuffer,1500);
  unsigned int forwardlen = forwardbuffersize;
  socket.SetTTL(1);
  if(socket.SendTo(forwardbuffer,forwardlen,broadAddr)){
    olsrpacket2forward.clear();
    olsrpacket2forward.seqno=pseqno++;
	return true;
  } else {
    olsrpacket2forward.clear();
    olsrpacket2forward.seqno=pseqno++;
	return false;
  }
}
bool
Nrlolsr::OnDelaySmfOffTimeout(ProtoTimer &theTimer){
  DMSG(4,"Really turning off smf forwarding\n");
  localNodeIsForwarder=false;
  SendForwardingInfo();
  return true;
}
bool
Nrlolsr::OnStaticRunTimeout(ProtoTimer &theTimer){
  DMSG(4,"OnStaticRunTimeout putting olsr to sleep\n");
  Sleep();
  return true;
}
void
Nrlolsr::SetLocalNodeIsForwarder(bool isRelay){
  if(isRelay){
    if(delay_smf_off_timer.IsActive()){
      delay_smf_off_timer.Deactivate();
    }
    localNodeIsForwarder=true;
  } else {
    if(Delay_Smf_Off_Time==0)
    {
      localNodeIsForwarder=false;
      if(delay_smf_off_timer.IsActive()) delay_smf_off_timer.Deactivate();
    } else {
      if(delay_smf_off_timer.IsActive()) return; //timer is already active do not install new timer
      delay_smf_off_timer.SetInterval(Delay_Smf_Off_Time);
      delay_smf_off_timer.SetRepeat(0);
      timerMgrPtr->ActivateTimer(delay_smf_off_timer);
    }
  }
  return;
}
void 
Nrlolsr::OnMacControlSocketEvent(ProtoSocket& theSocket, ProtoSocket::Event theEvent){
    MacControlMsg msg;
    unsigned int len = MacControlMsg::MAX_SIZE;
    switch (theEvent)
    {
        case ProtoSocket::RECV:
            while (theSocket.Recv(msg.AccessBuffer(), len))
            {
                msg.InitFromBuffer(len);
                ParseMacControlMessage(msg);
                len = MacControlMsg::MAX_SIZE;
            }
            break;
        default:
            // ignore other events
            break;   
    }
}  // end Nrlolsr::OnMacControlSocketEvent()

#ifdef SMF_SUPPORT
void Nrlolsr::OnPktCapture(ProtoChannel& /*theChannel*/, ProtoChannel::Notification theNotification)
{
    if (ProtoChannel::NOTIFY_INPUT != theNotification) 
        return;
    while (1)
    {
        unsigned char buffer[2048];
        unsigned int numBytes = 2048;
        ProtoCap::Direction direction;
        if (!cap_rcvr->Recv((char*)buffer, numBytes, &direction))
        {
            DMSG(0, "Nrlolsr::OnPktCapture() error receiving packet\n");
            return ;
        }
        if (0 == numBytes) break;
        if (ProtoCap::INBOUND != direction) continue;
        // Only pay attention to UDP/IP packets for our OLSR port
        UINT16 type;
        memcpy(&type, buffer+12, 2);
        type = ntohs(type);
        if ((type != 0x0800) && (type != 0x86dd)) continue;  // not IPv4 or IPv6
        // 1) Get IP protocol version
        const unsigned int ETH_HDR_LEN = 14;         // Ethernet MAC header is 14 bytes
        const unsigned int UDP_OFFSET_PORT_DST = 2;  
        const unsigned int UDP_HDR_LEN = 8;
        const unsigned int OLSR_OFFSET_TYPE = 4;    // OLSR packet type is 5th byte of OLSR msg
	const unsigned int OLSR_OFFSET_SRC = 8;     // OLSR Originator Address starts at 9th byte of OLSR msg  Originator is last hop with hello messages

	//these values are taken from rfc 1700 and rfc 2460
        const unsigned char HOP_BY_HOP_OH = 0; // '0' is hop by hop option header
	//const unsigned char IP_TCP_TYPE = 6; 
	const unsigned char IP_UDP_TYPE = 17;        // '17' is UDP packet type for IP
	const unsigned char ROUTE_OH = 43;
	const unsigned char FRAGMENT_OH = 44;
	const unsigned char ENCAPULATION_OH = 50;
	const unsigned char AUTHENTICATION_OH = 51;
	const unsigned char NO_NEXT_HEADER_OH = 59;
	const unsigned char DESTINATION_OH = 60;

	
        unsigned char ipVersion = buffer[ETH_HDR_LEN]  >> 4;
        ProtoAddress ipSrc;
        if (4 == ipVersion)
        {
            const unsigned int IPV4_OFFSET_TYPE = 9;
            if (IP_UDP_TYPE != buffer[ETH_HDR_LEN+IPV4_OFFSET_TYPE])
                continue;  // it's not a UDP packet
            const unsigned int IPV4_HDR_LEN = 20;
            UINT16 dstPort = htons(olsr_port_number);  // check for OLSR port number
            if (memcmp(&dstPort, buffer+ETH_HDR_LEN+IPV4_HDR_LEN+UDP_OFFSET_PORT_DST, 2))
                continue;  // it's not an OLSR (port olsr_port_number) packet
            if (1 != buffer[ETH_HDR_LEN+IPV4_HDR_LEN+UDP_HDR_LEN+OLSR_OFFSET_TYPE])
	      continue;  // it's not an OLSR "hello" message
	    const unsigned int IPV4_OFFSET_SRC = 12;
            ipSrc.SetRawHostAddress(ProtoAddress::IPv4, (char*)buffer+ETH_HDR_LEN+IPV4_OFFSET_SRC, 4);//this works for ipv4 because there is only one address type
        }
        else if (6 == ipVersion)
        {
            // (TBD) we need to do a real parse, looking thru possible extended IPv6 headers (i.e. option headers)
            const unsigned int IPV6_OFFSET_NEXT_HEADER = 6;
            unsigned char next_header_=buffer[ETH_HDR_LEN+IPV6_OFFSET_NEXT_HEADER];
	    unsigned char header_offsets = 0;  //size of all the options headers
            unsigned int IPV6_HDR_LEN = 40; //header options increase this length

	    bool isudppacket=false;
	    switch (next_header_){
	    case HOP_BY_HOP_OH:
	    case ROUTE_OH:
	    case FRAGMENT_OH:
	      //encapulation and auth are broken and need their own case
	    case ENCAPULATION_OH:
      	    case AUTHENTICATION_OH:
       	    case DESTINATION_OH:
		    //option header is being used go to next header
	      if(buffer[ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets]==NO_NEXT_HEADER_OH){
		//this is the last header and there is no more
		isudppacket=false;
		break;
	      } else {
		//go to the next header
		header_offsets+=buffer[ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets+1]+8;
		next_header_=buffer[ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets];
		continue;
	      }
	    case IP_UDP_TYPE:
		    //packet contains udp information check it
		    isudppacket=true;
		    break;
	    default: 
	      break;
	    }
	    if(!isudppacket){
	      continue; //jump to next packet 
	    }

            UINT16 dstPort = htons(olsr_port_number);  // check for OLSR port number
            if (memcmp(&dstPort, buffer+ETH_HDR_LEN+IPV6_HDR_LEN+UDP_OFFSET_PORT_DST+header_offsets, 2))
                continue;  // it's not an OLSR (port olsr_port_number) packet
            if (1 != buffer[ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets+UDP_HDR_LEN+OLSR_OFFSET_TYPE])
                continue;  // it's not an OLSR "hello" message so we can't verify that last hop is originator
	    ipSrc.SetRawHostAddress(ProtoAddress::IPv6, (char*)buffer+ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets+UDP_HDR_LEN+OLSR_OFFSET_SRC, 16);
        }
        else
        {
            DMSG(0, "Nrlolsr::OnPktCapture() recv'd packet of unsupported IP version: %d\n", ipVersion);
            continue;
        }   

        ProtoAddress macSrc;
        const unsigned int ETH_OFFSET_SRC = 6;
        macSrc.SetRawHostAddress(ProtoAddress::ETH, (char*)buffer+ETH_OFFSET_SRC, 6);
        // Add the entry to our "ip to mac" table
        ipToMacTable.SetRoute(ipSrc, 8*ipSrc.GetLength(), macSrc);
    }  // end while(1)
}  // end Nrlolsr::OnPktCapture()
#endif // SMF_SUPPORT

#ifndef SIMULATE //pipe and ProtoCap capability is not included in simulation protolib code

void Nrlolsr::OnRecvPipeMessage(ProtoSocket& /*theSocket*/, ProtoSocket::Event theEvent)
{
  //fprintf(stderr,"getting a new message\n");
    if (ProtoSocket::RECV == theEvent)
    {
        char buffer[8192];
        memset(buffer,0,8192);
        unsigned int len = 8191;
        if (recvPipe.Recv(buffer, len))
        {
            if (len)
            {
                DMSG(0, "Nrlolsr::OnRecvPipeMessage: recvd \"%s\"\n", buffer);
                StringProcessCommands(buffer);
            }
        } 
        else 
        {
            DMSG(0, "Nrlolsr::OnRecvPipemessage recvPipe.Recv() error\n");
        }   
    }  // end if(ProtoSocket::RECV == theEvent)
}  // end Nrlolsr::OnRecvPipeMessage()

#endif //not SIMULATE

int
Nrlolsr::update_nbr(ProtoAddress id,int status,UINT8 spfValue,UINT8 minmaxValue) {
  //DMSG(6,"Enter: Nrlolsr::update_nbr(id %s,status %d,spfValue %d, minmaxValue)\n",id.GetHostString(),status,spfValue,minmaxValue);
  NbrTuple *tuple_pt, *children, *parents;
  int updateMprs=0;
  tuple_pt = nbr_list.FindObject(id);
  switch(status) {
    case ASYM_LINKv4: 
      DMSG(0,"error in Nrlolsr::update_nbr(short call function) in ASYM_LINKv4 area should never happen\n");
      break;
  case SYM_LINKv4:  // can be mpr link as well 
    if(tuple_pt) { //should always pass if done correctly
      // update link time
      if(tuple_pt->N_status==ASYM_LINKv4){ //link was asym before now its a symetric link
	tuple_pt->hop=1;
	tuple_pt->N_status=SYM_LINKv4;
	//link up known children
	for(children=(tuple_pt->children).PeekInit();children!=NULL;children=(tuple_pt->children).PeekNext()){
	  if(children!=NULL){
	    if((children->stepparents).FindObject(tuple_pt->N_addr)){ //remove stepparent status
	      (children->stepparents).RemoveCurrent();
	    } else {
	      DMSG(0,"didn't find stepparents in SYM_LINKv4 area!!!  updated node %s with child ",tuple_pt->N_addr.GetHostString());
	      DMSG(0,"%s who doesn't know about ",children->N_addr.GetHostString());
	      DMSG(0,"%s\n",tuple_pt->N_addr.GetHostString());
	    }
	    (children->parents).QueueObject(tuple_pt); // link the child to parent node
	    if(nbr_2hop_list.FindObject(children->N_addr)){//need to take out if its there already to update time
	      nbr_2hop_list.RemoveCurrent(); 
	    } else {
	      // is okay cause could have been only a 1 hop neighbor
	    }
	    nbr_2hop_list.QueueObject(children); // add to two hop list 
	  }
	}	    
	updateMprs=1;
      }
      //DMSG(7,"Moving %s to the sym neighbor table \n",id.GetHostString());
      nbr_list.RemoveCurrent();
      tuple_pt->N_time=InlineGetCurrentTime() + Neighb_Hold_Time;
      //tuple_pt->N_spf=spfValue;
      //tuple_pt->N_minmax=minmaxValue;
      nbr_list.QueueObjectAddressSort(tuple_pt); //sorts neighbors by address to avoid route flapping
      //checkCurrentTable(2);      
    } else {
      DMSG(0,"Error: didn't pass for some reason Nrlolsr::nbr_update,sym_link");}
    break;
  case LOST_LINKv4:  //recieved a lost link from a neighbor you can still hear
    if(tuple_pt) { //should always pass
      //DMSG(7,"changing nb %s to asym list at time %f \n",tuple_pt->N_addr.GetHostString(),InlineGetCurrentTime());
      // check and remove nodes children
      nbr_list.RemoveCurrent();
      for(children=(tuple_pt->children).PeekInit();children!=NULL;children=(tuple_pt->children).PeekNext()){
	if(children!=NULL){
	  //abandon children
	  if((children->parents).FindObject(tuple_pt->N_addr))
	    (children->parents).RemoveCurrent();
	  else if((children->stepparents).FindObject(tuple_pt->N_addr))
	    (children->stepparents).RemoveCurrent();
	  if((children->parents).IsEmpty()){
	    //child lost last parent, child runs free	      
	    //DMSG(7,"removing 2 hop %s ",children->N_addr.GetHostString());
	    //DMSG(7,"cause %s deleated (lost link)\n",tuple_pt->N_addr.GetHostString());
	    fflush(stdout);
	    nbr_2hop_list.FindObject(children->N_addr);
	    nbr_2hop_list.RemoveCurrent();
	    if(!nbr_list.FindObject(children->N_addr)){ //check to see if it was exclusivly a 2 hop neighbor
	      //get rid of step children
	      for(parents=(children->children).PeekInit();parents!=NULL;parents=(children->children).PeekNext()){
		if(parents!=NULL){
		  if((parents->stepparents).FindObject(children->N_addr)){
		    (parents->stepparents).RemoveCurrent();
		  } else {
		    //error statements shouldn't enter here
		    if((parents->parents).FindObject(children->N_addr)){
		      DMSG(0,"missing stepparents link for node %s to stepparent ",parents->N_addr.GetHostString());
		      DMSG(0,"%s in LOST_LINKv4 area:\n",children->N_addr.GetHostString());
		      DMSG(0,"did find parent link! wasn't moved to stepparent correctly someplace in past!\n");
		    } else {
		      DMSG(0,"missing stepparents link for node %s to stepparents ",parents->N_addr.GetHostString());
		      DMSG(0,"%s in LOST_LINKv4 area: no parent link found\n",children->N_addr.GetHostString());
		    }
		    //end error stantments 
		  }
		}
	      }
	      (children->children).Clear();
	      //get rid of step parents
	      for(parents=(children->stepparents).PeekInit();parents!=NULL;parents=(children->stepparents).PeekNext()){
		if(parents!=NULL){
		  //if(parents->N_addr.IPv4HostAddr()!=tuple_pt->N_addr.IPv4HostAddr()){
		  if(!parents->N_addr.HostIsEqual(tuple_pt->N_addr)){
		    if((parents->children).FindObject(children->N_addr)){
		      (parents->children).RemoveCurrent();
		    } else {
		      DMSG(0,"missing childlink for node %s to child ",parents->N_addr.GetHostString());
		      DMSG(0,"%s in LOST_LINKv4 area: ",children->N_addr.GetHostString());
		      DMSG(0,"%s stepparents was ",children->N_addr.GetHostString());
		      DMSG(0,"%s\n",parents->N_addr.GetHostString());
		    }
		  }
		}
	      }
	      (children->stepparents).Clear();
	      
	      //	    if(children->hop==2){
	      //DMSG(10,"freeing it \n");
	      delete children;
	      //free(children);
	    } 
	  }
	}
      }
      (tuple_pt->children).Clear();
      NbrTuple *mprtuple;
      if((mprtuple = mprSelectorList.FindObject(tuple_pt->N_addr))){
	mprSelectorList.RemoveCurrent();
	delete mprtuple;

	updateSmfForwardingInfo = true;  //send updated mpr selector list to send pipe if open

	//free(mprtuple);
		  		  
		  // LP 8-30-05- added
#ifdef OPNET
		  total_TC_rcv ++;
		  TC_rcv_changed_flag = OPNET_TRUE;
#endif
		  // end LP

      }
      //update current node
      if((tuple_pt->parents).IsEmpty()){ // has no parents can remain a 1 hop
	tuple_pt->hop=1;
      }
      else
	tuple_pt->hop=2;             // is now a 2 hop neighbor
      tuple_pt->N_time=InlineGetCurrentTime() + Neighb_Hold_Time;
      tuple_pt->N_status=ASYM_LINKv4;
      //tuple_pt->N_spf=spfValue;
      //tuple_pt->N_minmax=minmaxValue;
      nbr_list.QueueObjectAddressSort(tuple_pt);
      //nbr_list.QueueObject(tuple_pt);
    }
  }
  //DMSG(6,"Exit: Nrlolsr::update_nbr(id %s,status %d,spfValue %d, minmaxValue)\n",id.GetHostString(),status,spfValue,minmaxValue);
  return 1;
}

int
Nrlolsr::update_nbr(ProtoAddress id,int status,UINT8 spfValue, UINT8 minmaxValue, UINT8 Vtime, UINT8 willingness) {
  //DMSG(6,"Enter: Nrlolsr::update_nbr(id %s,status %d,spfValue %d,minmaxvalue %d)\n",id.GetHostString(),status,spfValue,minmaxValue);
  NbrTuple *tuple_pt, *children, *parents;
  int updateMprs=0;
  tuple_pt = nbr_list.FindObject(id);
  if(tuple_pt==NULL){
    //DMSG(8," neighbor %s not found in list\n",id.GetHostString());
  }
  switch(status) {
  case ASYM_LINKv4:
    //if(id.IPv4HostAddr()!=myaddress.IPv4HostAddr()) { // shouldn't ever happen
    if(!id.HostIsEqual(myaddress)){ // shouldn't ever happen
      if(tuple_pt) {
		DMSG(8,"hello message reieved konectivity %f is improving\n",tuple_pt->konectivity);
		tuple_pt->konectivity=alpha*tuple_pt->konectivity+(1-alpha);			
		  if(tuple_pt->N_status!=SYM_LINKv4 && tuple_pt->N_status!=MPR_LINKv4){
					//if link is asym then update the object and move it to the back keeping asym status
					//DMSG(8,"in asylink areas \n");
					nbr_list.RemoveCurrent();
					//printCurrentTable(3);
					if(tuple_pt->konectivity>T_up && tuple_pt->N_status==PENDING_LINK){
						tuple_pt->N_status=ASYM_LINKv4;
					}
					tuple_pt->N_time=InlineGetCurrentTime() + mantissatodouble(Vtime); 
					tuple_pt->N_willingness = willingness;
					//tuple_pt->N_spf=spfValue;
					//tuple_pt->N_minmax=minmaxValue;
					nbr_list.QueueObjectAddressSort(tuple_pt);
					//nbr_list.QueueObject(tuple_pt);
					//DMSG(7,"refreshed one hop neighbor with timeout time %f\n",tuple_pt->N_time);
				}
			} else {
				// check to see if its a two hop neighbor
				tuple_pt = nbr_2hop_list.FindObject(id);
				if(tuple_pt) {
					//set queue up for being one hop neighbor (handling timeouts of children)
					tuple_pt->SetHoldTime(mantissatodouble(Vtime));
					//add to 1 hop list but don't erase 2 hop list entry
					tuple_pt->N_time=InlineGetCurrentTime() + mantissatodouble(Vtime);
					//tuple_pt->konectivity=(1-alpha); //set initial konectivity value  //I think the below initial value works better
					tuple_pt->konectivity=(T_up+T_down)/2;
			
					DMSG(8,"hello message reieved from known 2 hop neighbor setting konectivity to %f\n",tuple_pt->konectivity);
					if(tuple_pt->konectivity>T_up){
						tuple_pt->N_status=ASYM_LINKv4;
						//tuple_pt->hop=1; //don't make it a one hop neighbor till its sym
					} else {
						//DMSG(7,"Adding %s nbr to pending \n",tuple_pt->N_addr.GetHostString());
						tuple_pt->N_status=PENDING_LINK;
					}
					//tuple_pt->N_spf=spfValue;
					//tuple_pt->N_minmax=minmaxValue;
					tuple_pt->N_willingness = willingness;
					nbr_list.QueueObjectAddressSort(tuple_pt);
					//nbr_list.QueueObject(tuple_pt);
				} else {
					//DMSG(2,"Adding %s asym neighbor table \n",id.GetHostString());
					//not in current table add new tuple
					tuple_pt = new NbrTuple;
					tuple_pt->SetHoldTime(mantissatodouble(Vtime)); //set the queue up for the Vtime value
					tuple_pt->N_addr=id;
					//tuple_pt->konectivity=(1-alpha); //set initial konectivity value  //I think the below initial value works better
					tuple_pt->konectivity=(T_up+T_down)/2;
			
					DMSG(8,"hello message reieved from new neighbor setting konectivity to %f\n",tuple_pt->konectivity);
					if(tuple_pt->konectivity>T_up){
						tuple_pt->N_status=ASYM_LINKv4;
						tuple_pt->hop=1; //ok to do this here cause its a new neighbor
					} else {
						tuple_pt->N_status=PENDING_LINK;
						tuple_pt->hop=1;  //ok to do this here cause its a new neighbor
					}
					tuple_pt->N_time=InlineGetCurrentTime() + Neighb_Hold_Time;
					//tuple_pt->N_spf=spfValue;
					//tuple_pt->N_minmax=minmaxValue;
					tuple_pt->N_willingness = willingness;
					nbr_list.QueueObjectAddressSort(tuple_pt);
					//nbr_list.QueueObject(tuple_pt);
				}
			}
    }
    tuple_pt->recievedHello=1; //used for historisis
    if(tuple_pt->N_status==PENDING_LINK){
      //DMSG(6,"Exit: Nrlolsr::update_nbr(id %s,status %d,spfValue %d,minmaxValue)\n",id.GetHostString(),status,spfValue,minmaxValue);
      return 0;
    } else {
      //DMSG(6,"Exit: Nrlolsr::update_nbr(id %s,status %d,spfValue %d,minmaxValue)\n",id.GetHostString(),status,spfValue,minmaxValue);
      return 1;
    }
    break;
  case SYM_LINKv4:  // can be mpr link as well 
    if(tuple_pt) { //should always pass if done correctly
      // update link time
      if(tuple_pt->N_status==ASYM_LINKv4){
				tuple_pt->hop=1;
				tuple_pt->N_status=SYM_LINKv4;
				//link up known children
				for(children=(tuple_pt->children).PeekInit();children!=NULL;children=(tuple_pt->children).PeekNext()){
					if(children!=NULL){
						if((children->stepparents).FindObject(tuple_pt->N_addr)){ //remove stepparent status
							(children->stepparents).RemoveCurrent();
						} else {
							DMSG(0,"didn't find stepparents in SYM_LINKv4 area!!!  updated node %s with child ",tuple_pt->N_addr.GetHostString());
							DMSG(0,"%s who doesn't know about ",children->N_addr.GetHostString());
							DMSG(0,"%s\n",tuple_pt->N_addr.GetHostString());
						}
						(children->parents).QueueObject(tuple_pt); // link the child to parent node
						if(nbr_2hop_list.FindObject(children->N_addr)){//need to take out if its there already to update time
							nbr_2hop_list.RemoveCurrent(); 
						} else {
							// is okay cause could have been only a 1 hop neighbor
						}
						nbr_2hop_list.QueueObject(children); // add to two hop list 
					}
				}	    
				updateMprs=1;
      }
      //DMSG(7,"Moving %s to the sym neighbor table \n",id.GetHostString());
      nbr_list.RemoveCurrent();
      tuple_pt->N_time=InlineGetCurrentTime() + Neighb_Hold_Time;
      //tuple_pt->N_spf=spfValue;
      //tuple_pt->N_minmax=minmaxValue;      
      tuple_pt->N_willingness = willingness;
      nbr_list.QueueObjectAddressSort(tuple_pt);
      //nbr_list.QueueObject(tuple_pt);
      //checkCurrentTable(2);
      
      //this call is made only in send hello
      //if(updateMprs)
      //	selectmpr();
    }
    else {
      DMSG(0,"didn't pass for some reason nrouter/nbr_update,sym_link");}
    break;
  case LOST_LINKv4:  //recieved a lost link from a neighbor you can still hear
    if(tuple_pt) { //should always pass
      //DMSG(7,"changing nb %s to asym list at time %f \n",tuple_pt->N_addr.GetHostString(),InlineGetCurrentTime());
      // check and remove nodes children
      nbr_list.RemoveCurrent();
      for(children=(tuple_pt->children).PeekInit();children!=NULL;children=(tuple_pt->children).PeekNext()){
	if(children!=NULL){
	  //abandon children
	  if((children->parents).FindObject(tuple_pt->N_addr))
	    (children->parents).RemoveCurrent();
	  else if((children->stepparents).FindObject(tuple_pt->N_addr))
	    (children->stepparents).RemoveCurrent();
	  if((children->parents).IsEmpty()){
	    //child lost last parent, child runs free	      
	    //DMSG(7,"removing 2 hop %s ",children->N_addr.GetHostString());
	    //DMSG(7,"cause %s deleated (lost link)\n",tuple_pt->N_addr.GetHostString());
	    fflush(stdout);
	    nbr_2hop_list.FindObject(children->N_addr);
	    nbr_2hop_list.RemoveCurrent();
	    if(!nbr_list.FindObject(children->N_addr)){ //check to see if it was exclusivly a 2 hop neighbor
	      //get rid of step children
	      for(parents=(children->children).PeekInit();parents!=NULL;parents=(children->children).PeekNext()){
		if(parents!=NULL){
		  if((parents->stepparents).FindObject(children->N_addr)){
		    (parents->stepparents).RemoveCurrent();
		  } else {
		    //error statements shouldn't enter here
		    if((parents->parents).FindObject(children->N_addr)){
		      DMSG(0,"missing stepparents link for node %s to stepparent ",parents->N_addr.GetHostString());
		      DMSG(0,"%s in LOST_LINKv4 area: /n",children->N_addr.GetHostString());
		      DMSG(0,"but did find parent link! wasn't moved to stepparent correctly someplace in past!");
		    } else {
		      DMSG(0,"missing stepparents link for node %s to stepparent ",parents->N_addr.GetHostString());
		      DMSG(0,"%s in LOST_LINKv4 area: no parent link found",children->N_addr.GetHostString());
		    }
		    //end error stantments 
		  }
		}
	      }
	      (children->children).Clear();
	      //get rid of step parents
	      for(parents=(children->stepparents).PeekInit();parents!=NULL;parents=(children->stepparents).PeekNext()){
		if(parents!=NULL){
		  //if(parents->N_addr.IPv4HostAddr()!=tuple_pt->N_addr.IPv4HostAddr()){
		  if(!parents->N_addr.HostIsEqual(tuple_pt->N_addr)){
		    if((parents->children).FindObject(children->N_addr)){
		      (parents->children).RemoveCurrent();
		    } else {
		      DMSG(0,"missing childlink for node %s to child ",parents->N_addr.GetHostString());
		      DMSG(0,"%s in LOST_LINKv4 area: ",children->N_addr.GetHostString());
		      DMSG(0,"%s stepparent was ",children->N_addr.GetHostString());
		      DMSG(0,"%s\n",parents->N_addr.GetHostString());
		    }
		  }
		}
	      }
	      (children->stepparents).Clear();
	      delete children;
	      //free(children);
	    } 
	  }
	}
      }
      (tuple_pt->children).Clear();
      NbrTuple *mprtuple;
      if((mprtuple = mprSelectorList.FindObject(tuple_pt->N_addr))){
	mprSelectorList.RemoveCurrent();
	delete mprtuple;
	updateSmfForwardingInfo = true;  //send updated mpr selector list to send pipe if open
	//free(mprtuple);
		
	// LP 9-16-05 - added for Opnet statistic
#ifdef OPNET
	if (mprSelectorList.IsEmpty()){
		MPR_decreased_flag = OPNET_TRUE;
		// printf("\t\t DECREASED MPR\n");
		}
#endif
	// end LP

      }
      //update current node
      if((tuple_pt->parents).IsEmpty()){ // has no parents can remain a 1 hop
	tuple_pt->hop=1;
      }
      else
	tuple_pt->hop=2;             // is now a 2 hop neighbor
      tuple_pt->N_time=InlineGetCurrentTime() + Neighb_Hold_Time;
      tuple_pt->N_status=ASYM_LINKv4;
      //tuple_pt->N_spf=spfValue;
      //tuple_pt->N_minmax=minmaxValue;
      tuple_pt->N_willingness = willingness;
      nbr_list.QueueObjectAddressSort(tuple_pt);
      //nbr_list.QueueObject(tuple_pt);
    }
  }
  //DMSG(6,"Exit: Nrlolsr::update_nbr(id %s,status %d,spfValue %d,minmaxValue %d)\n",id.GetHostString(),status,spfValue, minmaxValue);
  return 1;
}

void 
Nrlolsr::update_2hop_nbr(ProtoAddress onehop_addr,ProtoAddress twohop_addr){
  //DMSG(6,"Enter: Nrlolsr::update_2hop_nbr(onehop %s,twohop",onehop_addr.GetHostString());
  //DMSG(6," %s\n",twohop_addr.GetHostString());
  
  NbrTuple *tuple_pt,*parent_tuple_pt,*other_tuple_pt;
  int updateMprs=0;
  int parentcheck=0;
  int errortype=0;
  parent_tuple_pt=nbr_list.FindObject(onehop_addr);
  parentcheck=parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4;
  //printCurrentTable(3);
  //DMSG(10,"parent check %d \n",parentcheck);
  
  if((tuple_pt=nbr_2hop_list.FindObject(onehop_addr,twohop_addr))){ //returns two hop guy
    if(parentcheck){
      //DMSG(7,"found in correct link \n");
      fflush(stdout);
      //update time 
      if((parent_tuple_pt=(tuple_pt->parents).FindObject(onehop_addr))){ 
				//	if(parent_tuple_pt=(tuple_pt->stepparents).FindObject(onehop_addr))
				//  DMSG(0,"both step parent and parent present how did it get this way?");
				errortype=4;
				//DMSG(9,"real child \n",parent_tuple_pt);
				(tuple_pt->parents).RemoveCurrent(); // removes the pointer pointing to the parent so it can be updated
				//printCurrentTable(3);
				(tuple_pt->parents).QueueObject(parent_tuple_pt); 
				//printCurrentTable(3);
				nbr_2hop_list.RemoveCurrent();
				nbr_2hop_list.QueueObject(tuple_pt);
      } else {
				// was a step child check to see if neighbor is true one hop
				errortype=5;
				parent_tuple_pt=(tuple_pt->stepparents).FindObject(onehop_addr);
				//DMSG(9,"step child \n");
				(tuple_pt->stepparents).RemoveCurrent(); // removes the pointer pointing to the parent so it can be updated
				if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) {
					updateMprs=1;
					(tuple_pt->parents).QueueObject(parent_tuple_pt);
					nbr_2hop_list.RemoveCurrent();
					nbr_2hop_list.QueueObject(tuple_pt);
				}	else {
					(tuple_pt->stepparents).QueueObject(parent_tuple_pt);
				}
      }
      other_tuple_pt=(parent_tuple_pt->children).FindObject(twohop_addr);
      //DMSG(11,"%p %p should be the same \n",tuple_pt,other_tuple_pt);
      fflush(stdout);
      (parent_tuple_pt->children).RemoveCurrent(); // removes the pointer pointing to the child so it can be updated
      (parent_tuple_pt->children).QueueObject(other_tuple_pt);  // updating the time again
    }
  } else if((tuple_pt=nbr_2hop_list.FindObject(twohop_addr))){
    //is already someones two hop neighbor just link them together
    //DMSG(8,"is an existing 2 hop neighbor \n");
    if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) { //make sure neighbor is true one hop
      errortype=6;
      updateMprs=1;
      (tuple_pt->parents).QueueObject(parent_tuple_pt); // link child to parent node   
      nbr_2hop_list.RemoveCurrent();  // next two lines update the timeout value of the 2 hop neighbor
      nbr_2hop_list.QueueObject(tuple_pt);
    } else {
      errortype=7;
      (tuple_pt->stepparents).QueueObject(parent_tuple_pt); //link child to node which isn't a real one hop node yet
    }
    (parent_tuple_pt->children).QueueObject(tuple_pt); // link parent to child node    
  } else if((tuple_pt=nbr_list.FindObject(twohop_addr))){
    //is already a one hop neighbor just link them together
    //DMSG(7,"is an existing 1 hop neighbor \n");    
    //DMSG(7,"parent_tuple_pt->N_status=%d mpr=%d sym=%d\n",parent_tuple_pt->N_status,MPR_LINKv4,SYM_LINKv4);
    if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) { //make sure neighbor is true one hop
      errortype=8;
      updateMprs=1;
      (tuple_pt->parents).QueueObject(parent_tuple_pt); // link the child to parent node
      //DMSG(7,"Adding 2hop neighbor %s to ",parent_tuple_pt->N_addr.GetHostString()); 
      //DMSG(7,"%s to neighbor table now\n",tuple_pt->N_addr.GetHostString());
      nbr_2hop_list.QueueObject(tuple_pt); // add to two hop list 
      (parent_tuple_pt->children).QueueObject(tuple_pt); // link the parent to the child node
    } else {
      //do nothing not a real neighbor yet
	  errortype=9;
    }
  } 
  else {
    //DMSG(8,"should be true one hop neighbor \n");
    //DMSG(8,"parent_tuple_pt->N_status = %d MPR_linkv4 = %d SYM_LINKv4 = %d\n",parent_tuple_pt->N_status,MPR_LINKv4,SYM_LINKv4);
    if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) { //make sure neighbor is true one hop
      errortype=10;
      //no existing 2 hop neighbor with given twohop_addr
      // make and link them together
      //DMSG(7,"Adding and making two hop neighbor %s to ",twohop_addr.GetHostString());
      //DMSG(7,"%s\n",parent_tuple_pt->N_addr.GetHostString());
            
      updateMprs=1;
      tuple_pt=new NbrTuple; // make new neighbor
      tuple_pt->N_addr=twohop_addr;
      tuple_pt->hop=2;
      (tuple_pt->parents).QueueObject(parent_tuple_pt);// link child to parent node
      (parent_tuple_pt->children).QueueObject(tuple_pt); // link parent to child node
      nbr_2hop_list.QueueObject(tuple_pt);  // add to two hop list
      //tuple_pt is only valid for use as a 2 hop right now the queue time is not set up properly as Vtime for it is not known
    }
    else{
      errortype=11;
      // may make node and add to stepparents in the future
      //DMSG(8,"ignroing 2 link cause 1 hop is pending \n");
    }

  }
  //checkCurrentTable(errortype);
  //printCurrentTable(3);
  
  //DMSG(6,"Exit: Nrlolsr::update_2hop_nbr(onehop %s,twohop",onehop_addr.GetHostString());
  //DMSG(6," %s\n",twohop_addr.GetHostString());
}//end Nrlolsr::update_2hop_nbr(onehop,twohop)

void 
Nrlolsr::update_2hop_nbrExtra(ProtoAddress onehop_addr,ProtoAddress twohop_addr,unsigned long nodedegree){
  //DMSG(6,"Enter: Nrlolsr::update_2hop_nbr(onehop %s,twohop",onehop_addr.GetHostString());
  //DMSG(6," %s\n",twohop_addr.GetHostString());
  
  NbrTuple *tuple_pt,*parent_tuple_pt,*other_tuple_pt;
  int updateMprs=0;
  int parentcheck=0;
  int errortype=0;
  parent_tuple_pt=nbr_list.FindObject(onehop_addr);
  parentcheck=parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4;
  //printCurrentTable(3);
  //DMSG(10,"parent check %d \n",parentcheck);
  
  if((tuple_pt=nbr_2hop_list.FindObject(onehop_addr,twohop_addr))){ //returns two hop guy
    tuple_pt->node_degree=nodedegree;
    if(parentcheck){
      //DMSG(8,"found in correct link \n");
      fflush(stdout);
      //update time 
      if((parent_tuple_pt=(tuple_pt->parents).FindObject(onehop_addr))){ 
	//	if(parent_tuple_pt=(tuple_pt->stepparents).FindObject(onehop_addr))
	//  DMSG(0,"both step parent and parent present how did it get this way?");
	errortype=4;
	//DMSG(9,"real child \n",parent_tuple_pt);
	(tuple_pt->parents).RemoveCurrent(); // removes the pointer pointing to the parent so it can be updated
	//printCurrentTable(3);
	(tuple_pt->parents).QueueObject(parent_tuple_pt); 
	//printCurrentTable(3);
	nbr_2hop_list.RemoveCurrent();
	nbr_2hop_list.QueueObject(tuple_pt);
      }
      else {
	// was a step child check to see if neighbor is true one hop
	errortype=5;
	parent_tuple_pt=(tuple_pt->stepparents).FindObject(onehop_addr);
	//DMSG(9,"step child \n");
	(tuple_pt->stepparents).RemoveCurrent(); // removes the pointer pointing to the parent so it can be updated
	if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) {
	  updateMprs=1;
	  (tuple_pt->parents).QueueObject(parent_tuple_pt);
	  nbr_2hop_list.RemoveCurrent();
	  nbr_2hop_list.QueueObject(tuple_pt);
	}
	else {
	  (tuple_pt->stepparents).QueueObject(parent_tuple_pt);
	}
      }
      other_tuple_pt=(parent_tuple_pt->children).FindObject(twohop_addr);
      //DMSG(11,"%p %p should be the same \n",tuple_pt,other_tuple_pt);
      fflush(stdout);
      (parent_tuple_pt->children).RemoveCurrent(); // removes the pointer pointing to the child so it can be updated
      (parent_tuple_pt->children).QueueObject(other_tuple_pt);  // updating the time again
    }
  }
  else if((tuple_pt=nbr_2hop_list.FindObject(twohop_addr))){
    //is already someones two hop neighbor just link them together
    //DMSG(8,"is an existing 2 hop neighbor \n");
    if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) { //make sure neighbor is true one hop
      errortype=6;
      updateMprs=1;
      (tuple_pt->parents).QueueObject(parent_tuple_pt); // link child to parent node   
      nbr_2hop_list.RemoveCurrent();  // next two lines update the timeout value of the 2 hop neighbor
      nbr_2hop_list.QueueObject(tuple_pt);
    } else {
      errortype=7;
      (tuple_pt->stepparents).QueueObject(parent_tuple_pt); //link child to node which isn't a real one hop node yet
    }
    (parent_tuple_pt->children).QueueObject(tuple_pt); // link parent to child node    
  } 
  else if((tuple_pt=nbr_list.FindObject(twohop_addr))){
    //is already a one hop neighbor just link them together
    //DMSG(8,"is an existing 1 hop neighbor \n");    
    //DMSG(8,"parent_tuple_pt->N_status=%d mpr=%d sym=%d\n",parent_tuple_pt->N_status,MPR_LINKv4,SYM_LINKv4);
    if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) { //make sure neighbor is true one hop
      errortype=8;
      updateMprs=1;
      (tuple_pt->parents).QueueObject(parent_tuple_pt); // link the child to parent node
      //DMSG(7,"Adding 2hop neighbor %s to ",parent_tuple_pt->N_addr.GetHostString()); 
      //DMSG(7,"%s to neighbor table now\n",tuple_pt->N_addr.GetHostString());
      nbr_2hop_list.QueueObject(tuple_pt); // add to two hop list 
      (parent_tuple_pt->children).QueueObject(tuple_pt); // link the parent to the child node
    } else {
      //do nothing not a real neighbor yet
      errortype=9;
    }
  } 
  else {
    //DMSG(8,"should be true one hop neighbor \n");
    //DMSG(8,"parent_tuple_pt->N_status = %d MPR_linkv4 = %d SYM_LINKv4 = %d\n",parent_tuple_pt->N_status,MPR_LINKv4,SYM_LINKv4);
    if(parent_tuple_pt->N_status==MPR_LINKv4 || parent_tuple_pt->N_status==SYM_LINKv4) { //make sure neighbor is true one hop
      errortype=10;
      //no existing 2 hop neighbor with given twohop_addr
      // make and link them together
      //DMSG(7,"Adding and making two hop neighbor %s to ",twohop_addr.GetHostString());
      //DMSG(7,"%s\n",parent_tuple_pt->N_addr.GetHostString());
            
      updateMprs=1;
      tuple_pt=new NbrTuple; // make new neighbor
      tuple_pt->N_addr=twohop_addr;
      tuple_pt->hop=2;
      tuple_pt->node_degree=nodedegree; 
      (tuple_pt->parents).QueueObject(parent_tuple_pt);// link child to parent node
      (parent_tuple_pt->children).QueueObject(tuple_pt); // link parent to child node
      nbr_2hop_list.QueueObject(tuple_pt);  // add to two hop list
      //tuple_pt is only valid for use as a 2 hop right now the queue time is not set up properly as Vtime for it is not known
    }
    else{
      errortype=11;
      // may make node and add to stepparents in the future
      //DMSG(8,"ignroing 2 link cause 1 hop is pending \n");
    }

  }
  //checkCurrentTable(errortype);
  //printCurrentTable(3);
  
  //DMSG(6,"Exit: Nrlolsr::update_2hop_nbr(onehop %s,twohop",onehop_addr.GetHostString());
  //DMSG(6," %s\n",twohop_addr.GetHostString());
}//end Nrlolsr::update_2hop_nbr(onehop,twohop)

void
Nrlolsr::remove_2hop_link(ProtoAddress oneaddr,ProtoAddress twoaddr){
  //DMSG(6,"Enter: Nrlolsr::remove_2hop_link(oneaddr %s,twoaddr ",oneaddr.GetHostString());
  //DMSG(6,"%s)\n",twoaddr.GetHostString());

  NbrTuple *tuple_pt, *child_pt, *parents;
  tuple_pt=nbr_list.FindObject(oneaddr);
  if(tuple_pt){ //should always pass
    child_pt=tuple_pt->children.FindObject(twoaddr);
    if(child_pt){ // should pass most of the time
      //DMSG(7,"Removing: 2 hop neighbor %s ",twoaddr.GetHostString()); 
      //DMSG(7,"two %s\n",oneaddr.GetHostString());
      // remove the link
      if((tuple_pt=child_pt->parents.FindObject(oneaddr))){ // check if its a parent or step parent 
	child_pt->parents.RemoveCurrent();
      }
      else if((tuple_pt=child_pt->stepparents.FindObject(oneaddr))){
	child_pt->stepparents.RemoveCurrent();
      } else {
	DMSG(0,"parent checking failed in remove_2hop_link! %s to %s at time %f \n",oneaddr.GetHostString(),twoaddr.GetHostString(),InlineGetCurrentTime());
      }
      tuple_pt->children.RemoveCurrent();
      // check to see if child lost last parent
      if(child_pt->parents.IsEmpty()){
	// lost last parent remove the node
	if(nbr_2hop_list.FindObject(twoaddr)) // may have been a stepparent removed
	  nbr_2hop_list.RemoveCurrent();
	if(!nbr_list.FindObject(twoaddr)){ //check to see if it was exclusivly a 2 hop neighbor
	  //get rid of step parents of removed node
	  for(parents=((child_pt->stepparents).PeekInit());parents!=NULL;parents=(child_pt->stepparents).PeekNext()){
	    if(parents!=NULL){
	      if(!parents->N_addr.HostIsEqual(tuple_pt->N_addr)){
		//if(parents->N_addr.IPv4HostAddr()!=tuple_pt->N_addr.IPv4HostAddr()){ //will neverhappen removed above
		if((parents->children).FindObject(child_pt->N_addr)) {
		  (parents->children).RemoveCurrent();
		} else {
		  DMSG(0,"missing childlink for node %s to child ",parents->N_addr.GetHostString());
		  DMSG(0,"%s in remove_2hop_link area: ",child_pt->N_addr.GetHostString());
		  DMSG(0,"%s stepparent was ",child_pt->N_addr.GetHostString());
		  DMSG(0,"%s\n",parents->N_addr.GetHostString());
		}
	      }
	    }
	  }
	  (child_pt->stepparents).Clear();
	  //get rid of step children of removed node
	  for(parents=((child_pt->children).PeekInit());parents!=NULL;parents=(child_pt->children).PeekNext()){
	    if(parents!=NULL){
	      if((parents->stepparents).FindObject(child_pt->N_addr)){
		(parents->stepparents).RemoveCurrent();
	      } else {
		//error statments shouldn't enter here
		if((parents->parents).FindObject(child_pt->N_addr)){
		  DMSG(0,"missing stepparents link for node %s to stepparent ",parents->N_addr.GetHostString());
		  DMSG(0,"%s in remove_2hop_link area: /n ",child_pt->N_addr.GetHostString());
		  DMSG(0,"but did find parent link! wasn't moved to stepparent correctly someplace in the past!");
		} else {
		  DMSG(0,"missing stepparents link for the node %s to stepparents ",parents->N_addr.GetHostString());
		  DMSG(0,"%s in remove_2hop_link area: no parent link found",child_pt->N_addr.GetHostString());
		}
		// end error statements
	      }
	    }
	  }
	  (child_pt->children).Clear();
	  delete child_pt;
	  //free(child_pt);
	}        
      }
    } else {
      // DMSG(0,"child_pt %d not found in tuple_pt %d's child list whild trying to remove in remove_2hop_link at time %f for node %d",twoaddr,oneaddr,InlineGetCurrentTime(),here_.addr_);  
    }
  } else {
    DMSG(0,"tuple_pt not found in nbr_list, trying to remove two hop %s to ",oneaddr.GetHostString());
    DMSG(0,"%s at time %f link doesn't exist!",twoaddr.GetHostString(),InlineGetCurrentTime());
  }
  //checkCurrentTable(40);
  //DMSG(6,"Exit: Nrlolsr::remove_2hop_link(oneaddr %s,twoaddr ",oneaddr.GetHostString());
  //DMSG(6,"%s)\n",twoaddr.GetHostString());
} //end remove_2hop_link(oneaddr,twoaddr)

bool
Nrlolsr::SetLinkState(NodeLinkState state, ProtoAddress node){
  NbrTuple *tuple = NULL;
  switch(state)
    {
    case LINK_UP: //seting link state to up make new node if neccary
      if(!(tuple = nbr_list.FindObject(node))){ //node isn't a one hop and needs to be added as one
	update_nbr(tuple->N_addr, ASYM_LINKv4, 0,0, doubletomantissa(Neighb_Hold_Time), WILL_DEFAULT); //add to neighbor table (faking recieving a hello) 
      } 
      tuple->N_macstatus=LINK_UP;//set state to keep it a one hop neighbor
      tuple->konectivity=1;//fake "good" history
      update_nbr(tuple->N_addr, SYM_LINKv4, 0,0, doubletomantissa(Neighb_Hold_Time), WILL_DEFAULT); //make it a symetric neighbor
      // add to state table 
      break;
    case LINK_DOWN://bring link down if up 
      if((tuple = nbr_list.FindObject(node))){//node is one hop
	//set state to down and add to state list clean up 2 hop table;
	//HysFailure(tuple);//will fake a hystersis failure
	tuple->N_macstatus=LINK_DOWN;
	//makeNewRoutingTable();
        makeRoutingTable();
      } else if((tuple = nbr_2hop_list.FindObject(node))){ //is currently a 2 hop neighbor
	tuple->N_macstatus=LINK_DOWN;
      } 
      //add to state list
      
      break;
    case LINK_DEFAULT://restoring state to default olsr state
      if((tuple = nbr_list.FindObject(node))){ //node is a one hop
	tuple->N_macstatus=LINK_DEFAULT;
	if(tuple->konectivity>T_up){ //bring it back out of a lost stat if its down
	  tuple->N_status=SYM_LINK;
	} else {
	  tuple->N_status=PENDING_LINK; //assuming that its a pending link now
	}
	nb_purge();//will clean up the neighbor table checking this entry
	//makeNewRoutingTable();
	makeRoutingTable();
      } else if((tuple = nbr_2hop_list.FindObject(node))) { //node is currently a 2 hop neighbor
	tuple->N_macstatus=LINK_DEFAULT;
      } 
      // remove from state table if there
      break;
    default:
      return false;
    }
  return true;
}

void
Nrlolsr::HysFailure(NbrTuple* nb){ //code modified version of nb purge (maybe can clean up nb_purge now that this is here
  NbrTuple* children=NULL;
  NbrTuple* parents=NULL;
  NbrTuple* nb_top=NULL;

  nb->N_status=LOST_LINKv4;
  // must manually take out the topology tuple as they only time out based on timeout values
  nb_top=topologySet.FindObject(nb->N_addr,myaddress); // remove the forward link if in the topology table
  if(nb_top){
    ////DMSG(1,"removing from %d topology tuple %d list at time %f due to historisis 1\n",myaddress.IPv4HostAddr(),nb_top->N_addr,CURRENT_TIME);
    //DMSG(7,"Removing from %s topology tuple ",myaddress.GetHostString()); 
    //DMSG(7,"%s list at time %f due to historisis 1\n",nb_top->N_addr.GetHostString(),InlineGetCurrentTime());
    topologySet.RemoveCurrent();
    delete nb_top;
  }
  nb_top=topologySet.FindObject(myaddress,nb->N_addr); // remove the reverse link if there
  if(nb_top){
    //DMSG(7,"Removing from %s topology tuple ",myaddress.GetHostString());
    //DMSG(7,"%s list at time %f due to historisis 2\n",nb_top->N_addr.GetHostString(),InlineGetCurrentTime());
    ////DMSG(1,"removing from %d topology tuple %d list at time %f due to historisis 2\n",myaddress.IPv4HostAddr(),nb_top->N_addr,InlineGetCurrentTime());
    topologySet.RemoveCurrent();
    delete nb_top;
  }
  //removing children from parent/stepparent node that is being deleated
  for(children=(nb->children).PeekInit();children!=NULL;children=(nb->children).PeekNext()){
    if(children!=NULL){
      //abandon children
      if((children->parents).FindObject(nb->N_addr)){
	(children->parents).RemoveCurrent();
      } else if((children->stepparents).FindObject(nb->N_addr)){
	(children->stepparents).RemoveCurrent();
      } else {
	DMSG(0,"child without parent or stepparent pointer in nb_purge | ");
      }
      if((children->parents).IsEmpty()){
	//child lost last parent, child runs free	      
	////DMSG(1,"removing 2 hop %d cause %d deleated from %d's 1 hop list (purge)\n",children->N_addr,nb->N_addr,myaddress.IPv4HostAddr());
	// DMSG(7,"Removing 2 hop %s ",children->N_addr.GetHostString());
	//DMSG(7,"cause %s deleated from ",nb->N_addr.GetHostString());
	//DMSG(7,"%s's 1 hop list (purge)\n",myaddress.GetHostString());
	if(nbr_2hop_list.FindObject(children->N_addr))
	  nbr_2hop_list.RemoveCurrent();
	if(!nbr_list.FindObject(children->N_addr)){ //check to see if it was exclusivly a 2 hop neighbor
	  ////DMSG(1,"testline 0 \n");
	  //DMSG(12,"testline 0 \n");
	  //get rid of step children
	  for(parents=(children->children).PeekInit();parents!=NULL;parents=(children->children).PeekNext()){
	    if(parents!=NULL){
	      if((parents->stepparents).FindObject(children->N_addr)){
		(parents->stepparents).RemoveCurrent();
	      } else if((parents->parents).FindObject(children->N_addr)){
		DMSG(0,"parent pointer instead of stepparent pointer in nb_purge function | ");
	      } else {
		DMSG(0,"missing stepparent pointer in nb_purge function | ");
	      }
	    }
	  }
	  (children->children).Clear();
	  //get rid of step parents
	  for(parents=(children->stepparents).PeekInit();parents!=NULL;parents=(children->stepparents).PeekNext()){
	    if(parents!=NULL){
	      //  //DMSG(8,"testline 3 \n");
	      //if(parents->N_addr!=nb->N_addr){
	      if(!(parents->N_addr.HostIsEqual((nb->N_addr)))){
		//if(parents->children!=nb->children){
		if((parents->children).FindObject(children->N_addr)){
		  (parents->children).RemoveCurrent();
		} else {
		  DMSG(0,"missing child link in nb_purge function | ");
		}
		// }
	      }
	    }
	  }
	  (children->stepparents).Clear();
	  delete children;
	  //free(children);
	} 	
      }
    }
  }
  (nb->children).Clear();		
  if(!(nb->parents).IsEmpty()){ // checking to see if node has parents
    nb->hop=2; // is now a two hop neighbor 
  }
  NbrTuple *mprtuple;
  if((mprtuple = mprSelectorList.FindObject(nb->N_addr))){
    mprSelectorList.RemoveCurrent();
    delete mprtuple;

    updateSmfForwardingInfo = true;  //send updated mpr selector list to send pipe if open
    //free(mprtuple);
	
	// LP 9-16-05 - added for Opnet statistic
#ifdef OPNET
	if (mprSelectorList.IsEmpty()){
		MPR_decreased_flag = OPNET_TRUE;
		// printf("\t\t DECREASED MPR\n");
		}
#endif
	// end LP
	
  }
}



void
Nrlolsr::addHnaInfo(ProtoAddress gwaddr,ProtoAddress subnetaddr,ProtoAddress subnetmask,UINT8 Vtime){
  //DMSG(6,"Enter: %s's ",myaddress.GetHostString());
  //DMSG(6,"Nrlolsr::addHnaInfo(gwaddr %s, ",gwaddr.GetHostString());
  //DMSG(6,"subnetaddr %s, ",subnetaddr.GetHostString());
  //DMSG(6,"subnetmask %s, Vtime %d)\n",subnetmask.GetHostString(),Vtime);
  
  NbrTuple *tuple = NULL;
  bool notfound = true;
  //check to see if subnet address and mask is same as one that is directly used
  for(tuple=hnaAddresses.PeekInit();tuple!=NULL;tuple=hnaAddresses.PeekNext()){
	//DMSG(6,"checking to see if local hna route %s/",tuple->N_addr.GetHostString());
	//DMSG(6,"%s is the same as remote ",tuple->N_2hop_addr.GetHostString());
	//DMSG(6,"%s/",subnetaddr.GetHostString());
	//DMSG(6,"%s\n",subnetmask.GetHostString());
    if(subnetaddr.HostIsEqual((tuple->N_addr)) && subnetmask.HostIsEqual((tuple->N_2hop_addr))){
      DMSG(6,"found match to local hna networks\n");
      fflush(stdout);
      //match found don't add hna 
      notfound = false;
    }
  }
  if(notfound) {
    //check for existing hna tuple and refresh if there
    tuple = hnaSet.FindObject(gwaddr);
    if(tuple){
      if(tuple->subnetMask.HostIsEqual(subnetmask) && tuple->N_2hop_addr.HostIsEqual(subnetaddr)){
		//DMSG(5,"found match with first entry\n");
		notfound = false;
		hnaSet.RemoveCurrent();
		tuple->N_time = InlineGetCurrentTime() + mantissatodouble(Vtime);
		hnaSet.QueueObject(tuple);
      }
      while((tuple = hnaSet.FindNextObject(gwaddr)) && notfound){
		if(tuple->N_2hop_addr.HostIsEqual(subnetaddr) && tuple->subnetMask.HostIsEqual(subnetmask)){
		  // found match remove and replace
		  notfound = false;
		  hnaSet.RemoveCurrent();
		  tuple->N_time = InlineGetCurrentTime() + mantissatodouble(Vtime);
		  hnaSet.QueueObject(tuple);
		}
      }
    }
    if(notfound){
      // add new hna to list
      tuple = new NbrTuple;
      tuple->N_addr=gwaddr;
      tuple->N_2hop_addr=subnetaddr;
      tuple->subnetMask=subnetmask;
      tuple->N_time = InlineGetCurrentTime() + mantissatodouble(Vtime);
      hnaSet.QueueObject(tuple);
    }
  }
  //DMSG(6,"Exit: Nrlolsr::addHnaInfo(gwaddr %s, ",gwaddr.GetHostString());
  //DMSG(6,"subnetaddr %s, ",subnetaddr.GetHostString());
  //DMSG(6,"subnetmask %s, Vtime %d)\n",subnetmask.GetHostString(),Vtime);
} //end Exit: Nrlolsr::addHnaInfo(gwaddr,subnetaddr,subnetmask,Vtime)

void
Nrlolsr::addTopologyInfo(ProtoAddress T_last, ProtoAddress T_dest, UINT16 T_seq, UINT8 spfValue, UINT8 minmaxValue, UINT8 Vtime){
  //DMSG(6,"Enter: Nrlolsr::addTopologyInfo(T_last %s, T_dest ",T_last.GetHostString());
  //DMSG(6,"%s, T_seq %d, spfValue %d, minmaxValue %d, Vtime %d)\n",T_dest.GetHostString(),T_seq,spfValue,minmaxValue, Vtime);
  //DMSG(7,"Adding T_last=%s ",T_last.GetHostString());
  //DMSG(7,"T_dest=%s ",T_dest.GetHostString());
  //DMSG(7,"mssn=%d to %s's table \n",T_seq,myaddress.GetHostString());
  NbrTuple *tuple = new NbrTuple;
  tuple->N_addr=T_last;
  tuple->N_2hop_addr=T_dest;
  tuple->seq_num=T_seq;
  tuple->N_time2=InlineGetCurrentTime()+mantissatodouble(Vtime); // wanted to make list out of order
  //tuple->N_time=CURRENT_TIME+Top_Hold_Time;
  //tuple->N_time=T_last;
  tuple->N_time=0;
  tuple->N_spf=spfValue;
  tuple->N_minmax=minmaxValue;
  tuple->N_status=0;  //used for finding disjoint paths in makeRoutingTable
  topologySet.QueueObjectAddressSort(tuple); //sorts by address
  //topologySet.QueueObject(tuple); //sorts by timeout value
  //DMSG(6,"Exit: Nrlolsr::addTopologyInfo(T_last %s, T_dest ",T_last.GetHostString());
  //DMSG(6,"%s, T_seq %d, spfValue %d, minmaxValue %d, Vtime %d)\n",T_dest.GetHostString(),T_seq,spfValue,minmaxValue, Vtime);
}

// int
// Nrlolsr::updateTopology(ProtoAddress T_last, UINT16 T_seq){
//   //DMSG(6,"Enter: Nrlolsr::updateTopology(T_last %s,T_seq %d)\n",T_last.GetHostString(),T_seq);
//   //clear and delete old entries of the oldtopologyset so we can move the entries into it
//   topologySet.Init();
//   while(tuple){
//     topologySet.RemoveCurrent();
//     delete tuple;
//     tuple=topologySet.Init();
//   }

//   NbrTuple *tuple = topologySet.FindObject(T_last);
//   if(tuple){
//     //DMSG(9,"getting addr %s mssn %d \n",T_last.GetHostString(),T_seq);
//     // checking to see if seq_num<T_seq number if so update
//     // note that compiler says this statement is always true for some reason.  Look at it later.  May need to be fixed.
//     if(T_seq-tuple->seq_num<=MAXMSSN/2 && T_seq-tuple->seq_num>0 || (T_seq < tuple->seq_num && tuple->seq_num > T_seq + MAXMSSN/2)){ // is new data update
//       //remove all old entries and prepare for updated ones
//       while(tuple){
// 	//DMSG(7,"Removing from %s topology tuple %d in updateTopology \n",myaddress.GetHostString(),T_last);
// 	topologySet.RemoveCurrent();
// 	//delete tuple; //we are now moving entries over to the oldtopology set so we can check to see if we need to redo routes
// 	oldTopologySet.QueueObject(tuple); //these entries will be deleted next updateTopology fucntion call or in the addTopologyInfo call
// 	tuple=topologySet.FindObject(T_last);
	
//       }
//       //printTopology(3);
//       return 1;
//     } else {
//       //DMSG(9,"mssn duplicate entry \n");
//       return 0;
//     }
//   }
//   //DMSG(6,"Exit: Nrlolsr::updateTopology(T_last %s,T_seq %d)\n",T_last.GetHostString(),T_seq);
//   return 1;
// }

int
Nrlolsr::updateTopology(ProtoAddress T_last, UINT16 T_seq){
  //DMSG(6,"Enter: Nrlolsr::updateTopology(T_last %s,T_seq %d)\n",T_last.GetHostString(),T_seq);
  NbrTuple *tuple = topologySet.FindObject(T_last);
  if(tuple){
    //DMSG(9,"getting addr %s mssn %d \n",T_last.GetHostString(),T_seq);
    // checking to see if seq_num<T_seq number if so update
    // note that compiler says this statement is always true for some reason.  Look at it later.  May need to be fixed.
    if((T_seq-tuple->seq_num<=MAXMSSN/2) && ((T_seq-tuple->seq_num>0) || ((T_seq < tuple->seq_num) && (tuple->seq_num > T_seq + MAXMSSN/2)))){ // is new data update
      //remove all old entries and prepare for updated ones
      while(tuple){
	//DMSG(7,"Removing from %s topology tuple %d in updateTopology \n",myaddress.GetHostString(),T_last);
	topologySet.RemoveCurrent();
	delete tuple;
	//free(tuple);
	tuple=topologySet.FindObject(T_last);
	
      }
      //printTopology(3);
      return 1;
    } else {
      //DMSG(9,"mssn duplicate entry \n");
      return 0;
    }
  }
  //DMSG(6,"Exit: Nrlolsr::updateTopology(T_last %s,T_seq %d)\n",T_last.GetHostString(),T_seq);
  return 1;
}

void
Nrlolsr::update_mprselector(ProtoAddress id,int status) {
  //DMSG(6,"Enter: Nrlolsr::update_mprselector(id %s,int %d)\n",id.GetHostString(),status);
  //using the slighly bloated NBRQueue list for simple list
  NbrTuple *tuple_pt;
  switch(status){
  case SYM_LINKv4: // remove from list if there
    //DMSG(9,"in update_mprselector with SYM status for neighbor %s\n",id.GetHostString());
    tuple_pt=mprSelectorList.FindObject(id);
    if(tuple_pt){

      mprSelectorList.RemoveCurrent();
      delete tuple_pt;

      updateSmfForwardingInfo = true;  //send updated mpr selector list to send pipe if open
 	  
	  // LP 9-9-05 - added for Opnet statistic
#ifdef OPNET
	  if (mprSelectorList.IsEmpty()){
		  MPR_decreased_flag = OPNET_TRUE;
		  // printf("\t\t DECREASED MPR\n");
		  }
#endif
	  // end LP

      //free(tuple_pt);
    }
    break;
  case MPR_LINKv4: // add to list if not there
    //DMSG(9,"in update_mprselector with MPR status for neighbor %s\n",id.GetHostString());
    tuple_pt=mprSelectorList.FindObject(id);
    if(!tuple_pt){
		
	// LP 9-9-05 - added for Opnet statistic
#ifdef OPNET
		if (mprSelectorList.IsEmpty()) {
			MPR_increased_flag = OPNET_TRUE;
			// printf("\t\t INCREASED MPR\n");
			}
#endif
	// end LP
		
      //DMSG(7,"Adding neighbor %s to my mpr selctor list\n",id.GetHostString());
      tuple_pt=new NbrTuple;
      tuple_pt->N_addr=id;
      mprSelectorList.QueueObject(tuple_pt);

      updateSmfForwardingInfo = true;  //send updated mpr selector list to send pipe if open
    }
    break;
  }
  //DMSG(6,"Exit: Nrlolsr::update_mprselector(id %s,int %d)\n",id.GetHostString(),status);
}

//this method will turn forwarding on for smf if a node is an mpr of ANY other node.  It is a simple algorithm and does not scale well
void
Nrlolsr::calculateNsMpr() {
  NbrTuple *tuple_pt=NULL;
  //localNodeIsForwarder=false;
  SetLocalNodeIsForwarder(false);
  for(tuple_pt=nbr_list.PeekInit();tuple_pt!=NULL;tuple_pt=nbr_list.PeekNext()){//loop checking to see if ANY neighbors selected this node as mpr
    if(tuple_pt->N_status==MPR_LINKv4){
      SetLocalNodeIsForwarder(true);
      //localNodeIsForwarder=true;
	  return;
	}
  }
  return;
}//end Nrlolsr::calculateNsMpr
//this method will decide based upon node address and mpr status if it should forward using. algorithm described in
//inria paper "On the robustness and stability of Connected Dominating Sets"
void
Nrlolsr::calculateMprCds() { 
  NbrTuple *tuple_pt=NULL;
  ProtoAddress *lowest_address=&myaddress;
  bool smallestid=true;
  for(tuple_pt=nbr_list.PeekInit();tuple_pt!=NULL;tuple_pt=nbr_list.PeekNext()){//loop to check to see if node has lowest address in one hop neighborhood
    if(tuple_pt!=NULL){
      if(lowest_address->CompareHostAddr(tuple_pt->N_addr)>0){//current node is not the smallest in 1 hop neighborhood
	smallestid=false;
	lowest_address=&(tuple_pt->N_addr);//so after this loop we have a pointer to the lowest address tuple;
      }
    }
  }
  if(smallestid){ //current node is automaticly a forwarder
    SetLocalNodeIsForwarder(true);
    //localNodeIsForwarder=true;
    return;
  }
  //do second check to see if current node is a forwarder did the lowest address node in the mpr selector list?
  if(mprSelectorList.FindObject(*lowest_address)){
    SetLocalNodeIsForwarder(true);
    //localNodeIsForwarder=true;
  } else {
    SetLocalNodeIsForwarder(false);
    //localNodeIsForwarder=false;
  }
  return;
}

//this method will figure out if this node should forward by using the manet extensions for OPSF.
void
Nrlolsr::calculateOspfEcds() {
  //step one do I have a higher degree than all of my neighbors
  NbrTuple *tuple_pt,*biggest_tuple_pt=NULL;
  bool oldfstate = localNodeIsForwarder;
  bool highestdegreenode = true;
  SetLocalNodeIsForwarder(false);
  //localNodeIsForwarder=false;
  printCurrentTable(5); 
  DMSG(5,"%d is local node degree\n",localNodeDegree);
  //go though one hop neighbors first
  for(tuple_pt=nbr_list.PeekInit();tuple_pt!=NULL;tuple_pt=nbr_list.PeekNext()){
    if(tuple_pt!=NULL){
      tuple_pt->was_used=false; //setting up for second check
      if(TupleLinkIsUp(tuple_pt)){
	if((tuple_pt->node_degree>localNodeDegree) || 
	   ((tuple_pt->node_degree == localNodeDegree) && (tuple_pt->N_addr.CompareHostAddr(myaddress)>0))){
	  highestdegreenode = false;
	  //check to see if node is bigger than all previous nodes (used later on)
	  //if((tuple_pt->node_degree)>localNodeDegree){
	//	DMSG(3,"broken 1st part%d is > than %d?\n",tuple_pt->node_degree,localNodeDegree);
         // }
	  // if((tuple_pt->node_degree == localNodeDegree) && (tuple_pt->N_addr.CompareHostAddr(myaddress)>0)){
//		DMSG(3,"broken 2nd part\n");
//	}
	  DMSG(5,"%s has a higher degree of %d\n",tuple_pt->N_addr.GetHostString(),tuple_pt->node_degree);
	  if(biggest_tuple_pt){
	    if((tuple_pt->node_degree>biggest_tuple_pt->node_degree) || 
	       ((tuple_pt->node_degree == biggest_tuple_pt->node_degree) && (tuple_pt->N_addr.CompareHostAddr(biggest_tuple_pt->N_addr)>0))){
	      biggest_tuple_pt=tuple_pt;
	    }
	  } else { //no previous biggest to current is biggest
	    biggest_tuple_pt=tuple_pt;
	  }
	}
      }
    }
  }
  
  //go though two hop neighbors
  for(tuple_pt=nbr_2hop_list.PeekInit();tuple_pt!=NULL;tuple_pt=nbr_2hop_list.PeekNext()){
    if(tuple_pt!=NULL){
      tuple_pt->was_used=false; //setting up for second check
      DMSG(3,"tuple_pt->node dgree is %lu localnodedegree is %lu\n",tuple_pt->node_degree,localNodeDegree);
      if((tuple_pt->node_degree>localNodeDegree) || 
	 ((tuple_pt->node_degree == localNodeDegree) && (tuple_pt->N_addr.CompareHostAddr(myaddress)>0))){
	if(tuple_pt->node_degree>localNodeDegree){
	  DMSG(3,"first part is true\n");
        }
        DMSG(3,"tuple_pt->node dgree is %lu localnodedegree is %lu\n",tuple_pt->node_degree,localNodeDegree);
		highestdegreenode = false;
		//check to see if node is bigger than all previous nodes (used later on)
		if(biggest_tuple_pt){
		  if((tuple_pt->node_degree>biggest_tuple_pt->node_degree) || 
		     ((tuple_pt->node_degree == biggest_tuple_pt->node_degree) && (tuple_pt->N_addr.CompareHostAddr(biggest_tuple_pt->N_addr)>0))){
		    biggest_tuple_pt=tuple_pt;
		  }
	} else { //no previous biggest to current is biggest
	  biggest_tuple_pt=tuple_pt;
	}
      }
    }
  }
  if(highestdegreenode){
	  DMSG(5,"%s is a forwarder with degree %d at time %f\n",myaddress.GetHostString(),localNodeDegree,InlineGetCurrentTime());
          SetLocalNodeIsForwarder(true);
	  //localNodeIsForwarder = true;
	  if(oldfstate!=localNodeIsForwarder){
	    SendForwardingInfo();
	  }
	  return;
	  //fprintf(stderr,"%s is a forwarder with degree %d\n",myaddress.GetHostString(),localNodeDegree);
  } else { //do second more complex check made easy with recursion :)
    coverNodeOspfEcds(biggest_tuple_pt);
    //check to see if all one and two hop nodes are now covered
    for(tuple_pt=nbr_list.PeekInit();tuple_pt!=NULL;tuple_pt=nbr_list.PeekNext()){
      if(tuple_pt!=NULL){
	    if(TupleLinkIsUp(tuple_pt) && !(tuple_pt->was_used)){//node is a one hop and isn't covered
                  SetLocalNodeIsForwarder(true);
		  //localNodeIsForwarder = true;
		  if(oldfstate!=localNodeIsForwarder){
		    SendForwardingInfo();
	      }
		DMSG(5,"%s is a forwarder of the second order with degree %d at time %f\n",myaddress.GetHostString(),localNodeDegree,InlineGetCurrentTime());
		  //fprintf(stderr,"%s is a forwarder of the second order with degree %d\n",myaddress.GetHostString(),localNodeDegree);	    
		  return;	  
		}
      }
    }
  }
  //  for(tuple_pt=nbr_2hop_list.PeekInit();tuple_pt!=NULL;tuple_pt=nbr_2hop_list.PeekNext()){    
  //  if(tuple_pt!=NULL){
  //    if(!tuple_pt->was_used){//node was not covered so I have to select myself as forwarder
  //	localNodeIsForwarder = true;
  //	fprintf(stderr,"%s is a forwarder of the second order with degree %d\n",myaddress.GetHostString(),localNodeDegree);
  //    }
  //  }
  //}
  if(oldfstate!=localNodeIsForwarder){
    DMSG(3,"%s is changing forwarding state from %d to %d at time %f\n",myaddress.GetHostString(),oldfstate,localNodeIsForwarder,InlineGetCurrentTime());
	SendForwardingInfo();
  }
  //DMSG(3,"%s didn't change its forwarding state from %d at time %f\n",myaddress.GetHostString(),oldfstate,InlineGetCurrentTime());
  return;
}
  
void
Nrlolsr::coverNodeOspfEcds(NbrTuple* node_tuple_pt){
  NbrTuple *tuple_pt;
  if(node_tuple_pt->was_used){ //node has been account for already so just return
    return;
  } 
  node_tuple_pt->was_used = true; //cover this node and then cover its children or parents depending on hop count
  if((node_tuple_pt->node_degree>localNodeDegree) ||
     ((node_tuple_pt->node_degree==localNodeDegree) && (node_tuple_pt->N_addr.CompareHostAddr(myaddress)>0))){//node can only cover its other neighbors if it has higher degree
    if(TupleLinkIsUp(node_tuple_pt)){ //node is one hop neighbor just check his children
      //for(tuple_pt=nbr_2hop_list.PeekInit();tuple_pt!=NULL && highestdegreenode;tuple_pt=nbr_2hop_list.PeekNext()){
      for(tuple_pt=node_tuple_pt->children.PeekInit();tuple_pt!=NULL;tuple_pt=node_tuple_pt->children.PeekNext()){
	if(tuple_pt!=NULL){
	  coverNodeOspfEcds(tuple_pt);
	}
      } 
    } else { //node is a two hop neighbor just check his parents off
      for(tuple_pt=node_tuple_pt->parents.PeekInit();tuple_pt!=NULL;tuple_pt=node_tuple_pt->parents.PeekNext()){
	if(tuple_pt!=NULL){
	  coverNodeOspfEcds(tuple_pt);
	}
      }
    } 
  }
  return;
}


// seleect mprs as outlined in the spec v8
// I recomend that you read and understand the spec and not just my poor explination of what its doing
// the way mprs are seleced: first pick the neighbors which are the only route to some nodes
// they have to be picked unless one hop neighbor has a willingness factor of never in which case the 2 hop 
// neighbor should not be in the list.  Then add in all neighbors with a willingness of ALWAYS.  Procede to 
// step though the williness factors starting from the most willing picking the node that connects to the most 
// uncovered 2 hop neighbors and repeat breaking ties by picking the node connected to the most nodes(covered included).
// If 2 hop neighbors are still uncovered go down and check the next willingness group.
// thats what this code does
void
Nrlolsr::selectmpr() {
  DMSG(6,"Enter: Nrlolsr::selectmpr of node %s with mssn of %d()\n",myaddress.GetHostString(),mssn);
  printCurrentTable(10);
  int numberOfParents;
  NbrTuple *child, *parent, *newmpr=NULL;
  //printCurrentTable(3);
  //DMSG(8," initializing mpr and incrimenting %s's mssn number which is now %d \n",myaddress.GetHostString(),mssn+1);
  mssn++;
  mssn=mssn % MAXMSSN;
  for(parent=nbr_list.PeekInit();parent!=NULL;parent=nbr_list.PeekNext()){
    if(parent!=NULL){
      if(parent->N_status==MPR_LINKv4)
	    parent->N_status=SYM_LINKv4;
      parent->tdegree=0;
      parent->cdegree=0;
    }
  }
  //  DMSG(11," assigining degrees \n");
  //  fflush(stdout);
  for(child=nbr_list.PeekInit();child!=NULL;child=nbr_list.PeekNext()){
    if(child!=NULL){
      if(child->N_status!=SYM_LINKv4 && child->N_status!=MPR_LINKv4){
				numberOfParents=0;
    		//DMSG(11,"%s is adding to - ",child->N_addr.GetHostString());
    		//fflush(stdout);
				for(parent=(child->parents).PeekInit();parent!=NULL;parent=(child->parents).PeekNext()){
				  if(parent!=NULL){
						if(TupleLinkIsUp(parent)){
						  //if((parent->N_status==MPR_LINKv4 || parent->N_status==SYM_LINKv4) && parent->N_willingness!=WILL_NEVER && parent->N_macstatus!=LINK_DOWN){
						  //DMSG(11,"%s %d:",parent->N_addr.GetHostString(),parent->cdegree+1);
						  //fflush(stdout);
						  numberOfParents++;
						  parent->tdegree++;
						  parent->cdegree++;
						}
				  }
				}
				//DMSG(11,"\n");
				if(numberOfParents==1){// parent node must be selected at mpr
				  parent=(child->parents).PeekInit();
				  if(parent->N_willingness!=WILL_NEVER){
						//DMSG(8,"parent node %s must be selected as mpr\n",parent->N_addr.GetHostString());
						makempr(parent);
				  }
				}
		  }
		}
	    //DMSG(11 ,"\n");
	    //fflush(stdout);
  }
  
  //assigining degrees for 2 hop neighbors
  for(child=nbr_2hop_list.PeekInit();child!=NULL;child=nbr_2hop_list.PeekNext()){
    if(child!=NULL){
      if(child->hop==2){
				if(!nbr_list.FindObject(child->N_addr)){
					numberOfParents=0;
					//DMSG(11,"%s is adding to - ",child->N_addr.GetHostString());
					//fflush(stdout);
					for(parent=(child->parents).PeekInit();parent!=NULL;parent=(child->parents).PeekNext()){
						if(parent!=NULL){
							if(TupleLinkIsUp(parent)){
								//if((parent->N_status==MPR_LINKv4 || parent->N_status==SYM_LINKv4) && parent->N_willingness!=WILL_NEVER && parent->N_macstatus!=LINK_DOWN){
								//DMSG(11,"%s %d:",parent->N_addr.GetHostString(),parent->cdegree+1);
								//fflush(stdout);
								numberOfParents++;
								parent->tdegree++;
								parent->cdegree++;
							}
						}
					}
					//DMSG(11,"\n");
					if(numberOfParents==1){// parent node must be selected at mpr
						parent=(child->parents).PeekInit();
						if(parent->N_willingness!=WILL_NEVER){
							makempr(parent);
						}
					}
        }
			}
		}
    //DMSG(11 ,"\n");
    //fflush(stdout);
  }
  //DMSG(9,"selecting biggest degrees \n");
  //fflush(stdout);
//for printing out degrees
	if(olsrDebugValue>=10){
		for(parent=nbr_list.PeekInit();parent!=NULL;parent=nbr_list.PeekNext()){
			DMSG(10,"%s has degree %d\n",parent->N_addr.GetHostString(),parent->cdegree);
		}
	}

  for(parent=nbr_list.PeekInit();parent!=NULL;parent=nbr_list.PeekNext()){
    if(parent->N_willingness == WILL_ALWAYS && parent->N_status!=LINK_DOWN){
      makempr(parent);
    }
  }
  // go through and select highest willingness nodes with the biggest degree
  for(int currentwillingness = 6;currentwillingness>0;currentwillingness--){
    int highestdegree=1;
    while(highestdegree){
      highestdegree=0;
      for(parent=nbr_list.PeekInit();parent!=NULL;parent=nbr_list.PeekNext()){
				if(parent->N_willingness == currentwillingness){
					if((int)(parent->cdegree)>(int)highestdegree){
						DMSG(10,"%s is new highest at %d count \n",parent->N_addr.GetHostString(),parent->cdegree);
						highestdegree=parent->cdegree;
						newmpr=parent;
					}
				}
      }
      DMSG(10,"%d is highest degree",highestdegree);
      if(highestdegree)
				makempr(newmpr);
    }
  }
  //DMSG(6,"Enter: Nrlolsr::selectmpr()\n");
}

// this makes a node an mpr and updates the current nodal degree of all the other one hop nodes
void
Nrlolsr::makempr(NbrTuple *parent) { // updates the current degrees with the parent node selected
  //DMSG(6,"Enter: Nrlolsr::makempr(*parent %s)\n",parent->N_addr.GetHostString());
  NbrTuple *child, *stepparent;
  if(parent->N_status!=MPR_LINKv4){ // check to see if its an mpr already
    parent->N_status=MPR_LINKv4;
    //DMSG(8,"%s is new mpr of ",parent->N_addr.GetHostString());
    //DMSG(8,"%s \n",myaddress.GetHostString());
    for(child=(parent->children).PeekInit();child!=NULL;child=(parent->children).PeekNext()){
      if(child!=NULL){
	//DMSG(9,"%d hop of %s :",child->hop,child->N_addr.GetHostString());
	if((child->hop==2) || (child->N_status!=SYM_LINKv4 && child->N_status!=MPR_LINKv4)){
	  for(stepparent=(child->parents).PeekInit();stepparent!=NULL;stepparent=(child->parents).PeekNext()){
	    if(stepparent!=NULL){
	      stepparent->cdegree--;
	    }
	  }
	}
      } 
    }
  }
  //DMSG(6,"Exit: Nrlolsr::makempr(*parent %s)\n",parent->N_addr.GetHostString());
}

void
Nrlolsr::makeRoutingTable(){ //function which selects which routing algorithm to use
  if(unicastRouting){
    if(dospf){
      makeSpfRoutingTable();
    } else if(dominmax){
      makeMinmaxRoutingTable();
    } else if(dorobust){
      makeNewRoutingTableRobust();
    } else {
      makeNewRoutingTable();
    }
  }
}

void
Nrlolsr::makeSpfRoutingTable() {
  DMSG(6,"Enter: Nrlolsr::makeSpfRoutingTable()\n");
  NbrTuple *nb, *nb2=NULL, *top_tuple, *old_tuple, *tuple = routeTable.PeekInit();
  NbrTuple *storage_tuple_ptr=NULL;
  
  int queueIndex=0;
  bool was_new_entry=true;
  bool entry_was_one_hop=true;
  unsigned int current_shortest_path=0 ;
  //  printRoutingTable(2);
  //clearing old routing table
  oldRouteTable.Clear();
  while(tuple){
    routeTable.RemoveCurrent();
    //DMSG(10,"copying entry in routing table to extra queue \n");
    oldRouteTable.QueueObject(tuple);
    tuple=routeTable.PeekInit();
  }
  //clean up routing sets which are used only for printing/output purposes
  routeTopologySet.Clear();
  routeNeighborSet.Clear();

  // making new queue to use 
  extraQueue.Clear();
  for(top_tuple=topologySet.PeekInit();top_tuple!=NULL;top_tuple=topologySet.PeekNext()){
    extraQueue.QueueObject(top_tuple);
  }
  //resetting status bits
  for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
    nb->was_used=false;
	if(!nb->N_spf_link_set){ //link wasn't set so find a sutable value for the spf value
		nb->N_spf=(UINT8)(255-(nb->konectivity*255));
	}
  }
  //add links with smallest spf values
  while(was_new_entry){
    was_new_entry=false;
    entry_was_one_hop=false;
    current_shortest_path=60000;
    for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
      if(nb!=NULL){
	if(!nb->was_used && (nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && nb->N_macstatus!=LINK_DOWN && nb->N_spf<current_shortest_path){
	  current_shortest_path=nb->N_spf;
	  was_new_entry=true;
	  entry_was_one_hop=true;
	  storage_tuple_ptr=nb;
	}
      }
    }
    //since 2 hop may have better spf value than one hop test link state as well
    for(top_tuple=extraQueue.PeekInit();(top_tuple!=NULL);top_tuple=extraQueue.PeekNext()){
      for(tuple=routeTable.PeekInit();(tuple!=NULL);tuple=routeTable.PeekNext()){
	if(top_tuple->N_addr.HostIsEqual(tuple->N_addr) && !(top_tuple->N_2hop_addr).HostIsEqual(myaddress)){ //T_last==R_dest | doesn't point back to here 
	  if(tuple->N_spf+top_tuple->N_spf<current_shortest_path){//found new shortest path node
	    current_shortest_path=tuple->N_spf+top_tuple->N_spf;
	    nb=tuple;
	    nb2=top_tuple;
	    was_new_entry=true;
	    entry_was_one_hop=false;
	  }
	}
      }
    }
    if(was_new_entry){
      tuple = new NbrTuple;
      if(entry_was_one_hop){
		tuple->N_time=queueIndex--; //used queue object at head (which is faster way)
		tuple->N_addr=storage_tuple_ptr->N_addr;  // really R_dest
		tuple->N_2hop_addr=storage_tuple_ptr->N_addr; // really R_next
		tuple->hop=1;                    // really R_dist
		tuple->N_spf=storage_tuple_ptr->N_spf;
		tuple->N_status=-1;
		routeTable.QueueObject(tuple);
	//	realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);
       	
	//mark one hop as used already.
		storage_tuple_ptr->was_used=true;
	// removing links pointing to this node 
		for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
			if(top_tuple->N_2hop_addr.HostIsEqual(tuple->N_addr)){
				extraQueue.RemoveCurrent();
			}
		}
		routeNeighborSet.QueueObject(storage_tuple_ptr);
	} else { //entry was not a 1 hop
	// add the link nb to routing table and do over again
	//printRoutingTable(3);
	tuple->N_time=queueIndex--;
	tuple->N_addr=nb2->N_2hop_addr;  //is R_dest=T_dest
	tuple->N_2hop_addr=nb->N_2hop_addr;       //is R_next=R_next
	tuple->N_spf=nb->N_spf+nb2->N_spf;
	tuple->hop=nb->hop+1;
	tuple->N_status=0;
	routeTable.QueueObject(tuple); 
	//realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);

	//mark one hop if its there;
	for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
	  if(!nb->was_used && nb->N_addr.HostIsEqual(tuple->N_addr)){//if direct route is present mark as used
	    nb->was_used=true;
	  }
	}
	//have to remove from extraQueue tuples point at node just added
	for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
	  if(top_tuple->N_2hop_addr.HostIsEqual(nb2->N_2hop_addr)){
	    extraQueue.RemoveCurrent();
	  }
	}
	routeTopologySet.QueueObject(nb2);
      } // if(entry_was_one_hop){
    } // if(was_new_entry)
  }// while(was_new_entry)

  //print out the links which were selected as routing links
  //printRouteLinks(); //this was moved to update less often

  // go though and cleanly update the real routing table  
  
  //add direct routes first
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //only do direct routes in the section
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//old host route existed check to see if current choice is different
  	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route (old one was host route)
	  //DMSG(6,"Setting direct route %s\n",tuple->N_addr.GetHostString());
	  //DMSG(6,"metric before call %d\n",tuple->hop);
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	} else {     
	  //DMSG(6,"Not changing direct route to %s\n",tuple->N_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	//DMSG(6,"Adding new direct route %s\n",tuple->N_addr.GetHostString());
	//DMSG(8,"metric before call %d\n",tuple->hop);
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	//realRouteTable->SetDirectHostRoute(tuple->N_addr,interfaceIndex);
      }
    }
  }
  //add host routes second
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(!tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //check to make sure is a host route 
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//DMSG(6,"old route existed for current host route\n");
	//old route existed for current host route
	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route
	  //DMSG(6,"Setting host route %s to ",tuple->N_addr.GetHostString());
	  //DMSG(6,"%s\n",tuple->N_2hop_addr.GetHostString());
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop); 
	  if(false) {//ipvMode==IPv6){ // this is cause set route functions differently in v4 mode than v6 fix this brian
	    if(old_tuple->N_2hop_addr.HostIsEqual((old_tuple->N_addr))){ //used to be a direct route delete direct route
	      //DMSG(6,"Removing old direct route to %s\n",old_tuple->N_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){//,invalidAddr)){
		DMSG(0,"Nrlolsr::makeSpfRoutingTable() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
	      }
	    } else { // used to be a host route delete host route
	      //DMSG(6,"Removing old host route %s ",old_tuple->N_addr.GetHostString());
	      //DMSG(6,"via %s\n",old_tuple->N_2hop_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){//,old_tuple->N_2hop_addr)){
		DMSG(0,"Nrlolsr::makeSpfRoutingTable() Error removing host route %s via ",old_tuple->N_addr.GetHostString());
		DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
	      }
	    }
	  }
	} else {
	  //DMSG(6,"Not changing host route to %s via",tuple->N_addr.GetHostString());
	  //DMSG(6," %s\n",tuple->N_2hop_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	//DMSG(6,"Adding new host route dest=%s route=",tuple->N_addr.GetHostString());
	//DMSG(6,"%s\n",tuple->N_2hop_addr.GetHostString());
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop);
      }
    }
  }
  old_tuple=oldRouteTable.PeekInit();
  while(old_tuple){ //loop to clean extraQueue and remove old routes
    oldRouteTable.RemoveCurrent();
    if(old_tuple->N_addr.HostIsEqual((old_tuple->N_2hop_addr))){
      //DMSG(6,"Removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      //ProtoAddress invalidAddress;
      //invalidAddress.Init();
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeSpfRoutingTable() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      }
    } else {
      //DMSG(6,"Removing route to %s via ",old_tuple->N_addr.GetHostString());
      //DMSG(6,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeSpfRoutingTable() Error removing host route to %s via",old_tuple->N_addr.GetHostString());
	DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      }
    }
    delete old_tuple;
    //free(old_tuple); 
    old_tuple=oldRouteTable.PeekInit();
  }
  //DMSG(6,"Finished updating route table\n");

  
  //printCurrentTable(7);
  //DMSG(6,"Exit: Nrlolsr::makeSpfRoutingTable()\n");
} //end Nrlolsr::makeSpfRoutingTable()

void
Nrlolsr::makeMinmaxRoutingTable() {
  //DMSG(6,"Enter: Nrlolsr::makeMinmaxRoutingTable()\n");
  NbrTuple *nb, *nb2=NULL, *top_tuple, *old_tuple, *tuple = routeTable.PeekInit();
  NbrTuple *storage_tuple_ptr=NULL;
  //DMSG(0,"redoing %s route table\n",myaddress.GetHostString());
  int queueIndex=0;
  bool was_new_entry=true;
  bool entry_was_one_hop=true;
  unsigned int current_biggest_pipe_path=0 ;
  int current_hop_count=0;
  //  printRoutingTable(2);
  //clearing old routing table
  oldRouteTable.Clear();
  while(tuple){
    routeTable.RemoveCurrent();
    //DMSG(10,"copying entry in routing table to extra queue \n");
    oldRouteTable.QueueObject(tuple);
    tuple=routeTable.PeekInit();
  }
  // clear out old route set information queues used only for printing/output purposes.
  routeTopologySet.Clear();
  routeNeighborSet.Clear();

  // making new queue to use 
  extraQueue.Clear();
  for(top_tuple=topologySet.PeekInit();top_tuple!=NULL;top_tuple=topologySet.PeekNext()){
    extraQueue.QueueObject(top_tuple);
  }
  
  //resetting status bits
  for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
    nb->was_used=false;
  }

  //add links with smallest biggest min values
  while(was_new_entry){
    was_new_entry=false;
    entry_was_one_hop=false;
    current_hop_count=5000;
    current_biggest_pipe_path=0;
    for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
      if(nb!=NULL){
	//if(!nb->was_used && (nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && nb->N_macstatus!=LINK_DOWN && nb->N_minmax>current_biggest_pipe_path){
	if(!nb->was_used && (nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && nb->N_macstatus!=LINK_DOWN && nb->konectivity>current_biggest_pipe_path){
 	  //current_biggest_pipe_path=nb->N_minmax;
	  current_biggest_pipe_path=(unsigned int)(255*nb->konectivity);
	  current_hop_count=1;
 	  was_new_entry=true;
 	  entry_was_one_hop=true;
 	  storage_tuple_ptr=nb;
	}
      }
    }
    //since 2 hop may have bigger path value than one hop test link state as well
    for(top_tuple=extraQueue.PeekInit();(top_tuple!=NULL);top_tuple=extraQueue.PeekNext()){
      for(tuple=routeTable.PeekInit();(tuple!=NULL);tuple=routeTable.PeekNext()){
 	if(top_tuple->N_addr.HostIsEqual(tuple->N_addr) && !(top_tuple->N_2hop_addr).HostIsEqual(myaddress)){ //T_last==R_dest | doesn't point back to here 
 	  if(tuple->N_minmax>current_biggest_pipe_path && top_tuple->N_minmax>current_biggest_pipe_path){//found new biggest pipe path node
	    if(tuple->N_minmax>top_tuple->N_minmax){//set biggest path to min link
	      current_biggest_pipe_path = top_tuple->N_minmax;
	    } else {
	      current_biggest_pipe_path = tuple->N_minmax;
	    }
	    current_hop_count=tuple->hop+1;
 	    nb=tuple;
 	    nb2=top_tuple;
 	    was_new_entry=true;
	    DMSG(6,"was new %d hop entry \n");
 	    entry_was_one_hop=false;
 	  } else if(tuple->N_minmax>current_biggest_pipe_path && top_tuple->N_minmax>current_biggest_pipe_path){//tie use hop count to break tie
	    if(tuple->hop<current_hop_count-1){ //new shorest path bigger pipe found
	      if(tuple->N_minmax>top_tuple->N_minmax){//set biggest path to min link
		current_biggest_pipe_path = top_tuple->N_minmax;
	      } else {
		current_biggest_pipe_path = tuple->N_minmax;
	      }
	      DMSG(6,"was new %d hop entry which is better than old %d\n",tuple->hop+1, current_hop_count);
	      current_hop_count=tuple->hop+1;
	      nb=tuple;
	      nb2=top_tuple;
	      was_new_entry=true;
	      entry_was_one_hop=false;	      
	    }
	  }
 	}  
      }
    }

    if(was_new_entry){
      tuple = new NbrTuple;
      if(entry_was_one_hop){
	tuple->N_time=queueIndex--; //used queue object at head (which is faster way)
	tuple->N_addr=storage_tuple_ptr->N_addr;  // really R_dest
	tuple->N_2hop_addr=storage_tuple_ptr->N_addr; // really R_next
	tuple->hop=1;                    // really R_dist
	tuple->N_minmax=current_biggest_pipe_path;
	tuple->N_status=-1;
	routeTable.QueueObject(tuple);
	//	realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);
	DMSG(6,"adding direct%s %d\n",tuple->N_addr.GetHostString(),tuple->N_minmax);       	
	//mark one hop as used already.
	storage_tuple_ptr->was_used=true;
	// removing links pointing to this node 
	for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
	  if(top_tuple->N_2hop_addr.HostIsEqual(tuple->N_addr)){
	    extraQueue.RemoveCurrent();
	  }
	}
	routeNeighborSet.QueueObject(storage_tuple_ptr);
      } else {
	// add the link nb to routing table and do over again
	//printRoutingTable(3);
	tuple->N_time=queueIndex--;
	tuple->N_addr=nb2->N_2hop_addr;  //is R_dest=T_dest
	tuple->N_2hop_addr=nb->N_2hop_addr;       //is R_next=R_next
	tuple->N_minmax=current_biggest_pipe_path;
	tuple->hop=nb->hop+1;
	tuple->N_status=0;
	routeTable.QueueObject(tuple); 
	DMSG(6,"adding %s via ",tuple->N_addr.GetHostString()); 
	DMSG(6,"%s to ",tuple->N_2hop_addr.GetHostString());
	DMSG(6,"%s %d\n",nb2->N_addr.GetHostString(),tuple->N_minmax);       	
	//realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);

	//mark one hop if its there;
	for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
	  if(!nb->was_used && nb->N_addr.HostIsEqual(tuple->N_addr)){//if direct route is present mark as used
	    nb->was_used=true;
	  }
	}
	//have to remove from extraQueue tuples point at node just added
	for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
	  if(top_tuple->N_2hop_addr.HostIsEqual(nb2->N_2hop_addr)){
	    extraQueue.RemoveCurrent();
	  }
	}
	routeTopologySet.QueueObject(nb2);
      } // if(entry_was_one_hop){
    } // if(was_new_entry)
  }// while(was_new_entry)
  //print out links which were selected as for route use
  //printRouteLinks();//this was moved to print less often

  // go though and cleanly update the real routing table  
  
  //add direct routes first
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //only do direct routes in the section
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//old host route existed check to see if current choice is different
  	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route (old one was host route)
	  //DMSG(6,"Setting direct route %s\n",tuple->N_addr.GetHostString());
	  //DMSG(6,"metric before call %d\n",tuple->hop);
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	} else {     
	  //DMSG(6,"Not changing direct route to %s\n",tuple->N_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	//DMSG(6,"Adding new direct route %s\n",tuple->N_addr.GetHostString());
	//DMSG(8,"metric before call %d\n",tuple->hop);
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	//realRouteTable->SetDirectHostRoute(tuple->N_addr,interfaceIndex);
      }
    }
  }
  //add host routes second
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(!tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //check to make sure is a host route 
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//DMSG(6,"old route existed for current host route\n");
	//old route existed for current host route
	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route
	  //DMSG(6,"Setting host route %s to ",tuple->N_addr.GetHostString());
	  //DMSG(6,"%s\n",tuple->N_2hop_addr.GetHostString());
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop); 
	  if(false) {//ipvMode==IPv6){ // this is cause set route functions differently in v4 mode than v6 fix this brian
	    if(old_tuple->N_2hop_addr.HostIsEqual((old_tuple->N_addr))){ //used to be a direct route delete direct route
	      //DMSG(6,"Removing old direct route to %s\n",old_tuple->N_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){//,invalidAddr)){
		DMSG(0,"Nrlolsr::makeSpfRoutingTable() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
	      }
	    } else { // used to be a host route delete host route
	      //DMSG(6,"Removing old host route %s ",old_tuple->N_addr.GetHostString());
	      //DMSG(6,"via %s\n",old_tuple->N_2hop_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){//,old_tuple->N_2hop_addr)){
		DMSG(0,"Nrlolsr::makeMinMaxRoutingTable() Error removing host route %s via ",old_tuple->N_addr.GetHostString());
		DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
	      }
	    }
	  }
	} else {
	  //DMSG(6,"Not changing host route to %s via",tuple->N_addr.GetHostString());
	  //DMSG(6," %s\n",tuple->N_2hop_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	//DMSG(6,"Adding new host route dest=%s route=",tuple->N_addr.GetHostString());
	//DMSG(6,"%s\n",tuple->N_2hop_addr.GetHostString());
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop);
      }
    }
  }
  old_tuple=oldRouteTable.PeekInit();
  while(old_tuple){ //loop to clean extraQueue and remove old routes
    oldRouteTable.RemoveCurrent();
    if(old_tuple->N_addr.HostIsEqual((old_tuple->N_2hop_addr))){
      //DMSG(6,"Removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      //ProtAddress invalidAddress;
      //invalidAddress.Init();
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeMinMaxRoutingTable() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      }
    } else {
      //DMSG(6,"Removing route to %s via ",old_tuple->N_addr.GetHostString());
      //DMSG(6,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeMinMaxRoutingTable() Error removing host route to %s via",old_tuple->N_addr.GetHostString());
	DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      }
    }
    delete old_tuple;
    //free(old_tuple); 
    old_tuple=oldRouteTable.PeekInit();
  }
  //DMSG(6,"Finished updating route table\n");

  
  //printCurrentTable(7);
  //DMSG(6,"Exit: Nrlolsr::makeMinmaxRoutingTable()\n");
} //end Nrlolsr::makeMinmaxRoutingTable()


// when making a new routing table first the old table is stored.  Then the new one is made all new from the valid topology, 
// and neighbor tables.  Then routes are added or changed depending on if they are new or not.  Then entries in the old
// routing table which are not coverd yet are removed.  The method on how to create a routing table is covered in the OLSR 
// specification.  One interteresting point to mention is that the way the lists of the tables are ordered makes a difference
// in the outcome of the resulting routing table. 
void 
Nrlolsr::makeNewRoutingTable(){ 
  DMSG(6,"Enter: Nrlolsr::makeNewRoutingTable()\n");
  printCurrentTable(3);
  printTopology(3);
  
  NbrTuple *nb, *nb2=NULL, *best_nb2=NULL, *top_tuple, *old_tuple, *tuple = routeTable.PeekInit();
  NbrTuple *top_tuple_extra;
  int wasnewentry=0, queueIndex=0,foundnewlink=0;
  double smallestSpf=0 ;
  //  printRoutingTable(2);
  //clearing old routing table
  oldRouteTable.Clear();
  while(tuple){
    routeTable.RemoveCurrent();
    //DMSG(10,"copying entry in routing table to extra queue \n");
    oldRouteTable.QueueObject(tuple);
    tuple=routeTable.PeekInit();
  }

  //fix up lists which are used for output/printing purposes
  routeTopologySet.Clear();
  routeNeighborSet.Clear();

  // making new queue to use 
  extraQueue.Clear();
  for(top_tuple=topologySet.PeekInit();top_tuple!=NULL;top_tuple=topologySet.PeekNext()){
    extraQueue.QueueObject(top_tuple);
  }
  //adding one hops
  for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
    if(nb!=NULL){
      if((nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && nb->N_macstatus!=LINK_DOWN){
		tuple=new NbrTuple;
		tuple->N_time=queueIndex--; //used queue object at head (which is faster way)
		tuple->N_addr=nb->N_addr;  // really R_dest
		tuple->N_2hop_addr=nb->N_addr; // really R_next
		tuple->hop=1;                    // really R_dist
		tuple->N_status=-1;
		routeTable.QueueObject(tuple);
		DMSG(8,"%s is adding direct neighbor ",myaddress.GetHostString());
		DMSG(8,"%s to the routing table\n",tuple->N_2hop_addr.GetHostString());
		//	realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);
		wasnewentry=1;
		// removing links pointing to this node
		for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
		  if(top_tuple->N_2hop_addr.HostIsEqual(tuple->N_addr)){
			extraQueue.RemoveCurrent();
		  }
		}
		routeNeighborSet.QueueObject(nb);
      }
    }
  }
  //adding two hop neighbors
  for(nb=nbr_2hop_list.PeekInit();nb!=NULL;nb=nbr_2hop_list.PeekNext()){
    if(nb!=NULL){
      nb2=NULL;
      if((nb->hop)==2){
	if((nb2=(nb->parents).PeekInit())){
          top_tuple=new NbrTuple;
	  tuple->N_time=queueIndex--;
	  top_tuple->N_2hop_addr=nb->N_addr;  // really T_dest
	  top_tuple->hop=2;
	  top_tuple->N_status=INVALID;
	  //loop to find most stable link that has highest willingness and preferrably an MPR selector
          best_nb2=nb2;
	  while((nb2=(nb->parents).PeekNext())){
	    if ( nb2->N_willingness > best_nb2->N_willingness ||
		 (nb2->N_status == MPR_LINKv4 && best_nb2->N_status != MPR_LINKv4) ||
		 nb2->konectivity>best_nb2->konectivity) {
              best_nb2=nb2;
            }
          }
	  //don't use if willingnes is WILL_NEVER
	  if (best_nb2->N_willingness == WILL_NEVER) {
	    delete top_tuple;
	    continue;
	  }
          top_tuple->N_addr=best_nb2->N_addr; // really T_last
	  wasnewentry=1;
          //remove all topology tuples pointing to this 2 hop node as we will manually add it back in.
	  for(top_tuple_extra=extraQueue.PeekInit();top_tuple_extra!=NULL;top_tuple_extra=extraQueue.PeekNext()){
	    if(top_tuple_extra->N_2hop_addr.HostIsEqual(top_tuple->N_2hop_addr)){
	      extraQueue.RemoveCurrent();
	    }
          }
          extraQueue.QueueObject(top_tuple);
        }
      }
    }
  }
  int shortesthop=5000;
  while(wasnewentry){
    //add on smallest value nodes
    wasnewentry=0;
    foundnewlink=0;
    /* this is broken cuase it won't always add shortest hop next
	   for(top_tuple=extraQueue.PeekInit();(top_tuple!=NULL) && (foundnewlink==0);top_tuple=extraQueue.PeekNext()){
	   for(tuple=routeTable.PeekInit();(tuple!=NULL) && (foundnewlink==0);tuple=routeTable.PeekNext()){
	   if(top_tuple->N_addr.HostIsEqual(tuple->N_addr) && !(top_tuple->N_2hop_addr).HostIsEqual(myaddress)){ //T_last==R_dest | doesn't point back to here | delay is smaller
	   nb=tuple;
	   nb2=top_tuple;
	   foundnewlink=1;
	   }  
	   }
	   }*/
    shortesthop=5000; 
    for(top_tuple=extraQueue.PeekInit();(top_tuple!=NULL);top_tuple=extraQueue.PeekNext()){
      for(tuple=routeTable.PeekInit();(tuple!=NULL);tuple=routeTable.PeekNext()){
		if(top_tuple->N_addr.HostIsEqual(tuple->N_addr) && !(top_tuple->N_2hop_addr).HostIsEqual(myaddress)){ //T_last==R_dest | doesn't point back to here | delay is smaller
		  if((tuple->hop+1)<shortesthop){//found new shortest hop node
			shortesthop=tuple->hop+1;
			nb=tuple;
			nb2=top_tuple;
			foundnewlink=1;
		  }
		}  
      }
    }
    if(foundnewlink){
      // add the link nb to routing table and do over again
      //printRoutingTable(3);
      wasnewentry=1;
      tuple = new NbrTuple;
      tuple->N_time=queueIndex--;
      tuple->N_addr=nb2->N_2hop_addr;  //is R_dest=T_dest
      tuple->N_2hop_addr=nb->N_2hop_addr;       //is R_next=R_next
      tuple->N_spf=(UINT8)(smallestSpf*(double)OLSRMAXSPF);
      tuple->hop=nb->hop+1;
      tuple->N_status=0;
      routeTable.QueueObject(tuple); 
	  DMSG(8,"%s is adding, %d hop, node ",myaddress.GetHostString(),tuple->hop);
	  DMSG(8,"%s to the routing table via node ",tuple->N_addr.GetHostString());
	  DMSG(8,"%s at time %f\n",nb2->N_addr.GetHostString(),InlineGetCurrentTime());
      //realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);
      //have to remove from extraQueue tuples point at node just added
      for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
	if(top_tuple->N_2hop_addr.HostIsEqual(nb2->N_2hop_addr)){
	  extraQueue.RemoveCurrent();
	}
      }
      routeTopologySet.QueueObject(nb2); //add topolgy tuple which was used for this route to the list of links used in route calculation
    }
  }
  //print links which were selected for routes
  //printRouteLinks(); //this was moved to print less often


  // go though and cleanly update the real routing table  
  DMSG(4,"Updating %s's routing table\n",myaddress.GetHostString());
  //add direct routes first
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //only do direct routes in the section
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//old host route existed check to see if current choice is different
  	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route (old one was host route)
	  DMSG(4,"Setting direct route %s\n",tuple->N_addr.GetHostString());
	  DMSG(4,"metric before call %d\n",tuple->hop);
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	} else {     
	  DMSG(4,"Not changing direct route to %s\n",tuple->N_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	DMSG(4,"Adding new direct route %s\n",tuple->N_addr.GetHostString());
	//DMSG(8,"metric before call %d\n",tuple->hop);
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	//realRouteTable->SetDirectHostRoute(tuple->N_addr,interfaceIndex);
      }
    }
  }
  //add host routes second
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(!tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //check to make sure is a host route 
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	DMSG(4,"old route existed for current host route\n");
	//old route existed for current host route
	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route
	  DMSG(4,"Setting host route %s to ",tuple->N_addr.GetHostString());
	  DMSG(4,"%s\n",tuple->N_2hop_addr.GetHostString());
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop); 
	  if(false) {//ipvMode==IPv6){ // this is cause set route functions differently in v4 mode than v6 fix this brian
	    if(old_tuple->N_2hop_addr.HostIsEqual((old_tuple->N_addr))){ //used to be a direct route delete direct route
	      DMSG(4,"Removing old direct route to %s\n",old_tuple->N_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){//,invalidAddr)){
		DMSG(0,"Nrlolsr::makeNewRoutingTable() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
	      }
	    } else { // used to be a host route delete host route
	      DMSG(4,"Removing old host route %s ",old_tuple->N_addr.GetHostString());
	      DMSG(4,"via %s\n",old_tuple->N_2hop_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){//,old_tuple->N_2hop_addr)){
		DMSG(0,"Nrlolsr::makeNewRoutingTable() Error removing host route %s via ",old_tuple->N_addr.GetHostString());
		DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
	      }
	    }
	  }
	} else {
	  DMSG(4,"Not changing host route to %s via",tuple->N_addr.GetHostString());
	  DMSG(4," %s\n",tuple->N_2hop_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	DMSG(4,"Adding new host route dest=%s route=",tuple->N_addr.GetHostString());
	DMSG(4,"%s\n",tuple->N_2hop_addr.GetHostString());
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop);
      }
    }
  }
  old_tuple=oldRouteTable.PeekInit();
  while(old_tuple){ //loop to clean extraQueue and remove old routes
    oldRouteTable.RemoveCurrent();
    if(old_tuple->N_addr.HostIsEqual((old_tuple->N_2hop_addr))){
      DMSG(4,"Removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      //ProtoAddress invalidAddress;
      //invalidAddress.Init();
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeNewRoutingTable() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      }
    } else {
      DMSG(4,"Removing route to %s via ",old_tuple->N_addr.GetHostString());
      DMSG(4,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeNewRoutingTable() Error removing host route to %s via",old_tuple->N_addr.GetHostString());
	DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      }
    }
    delete old_tuple;
    //free(old_tuple); 
    old_tuple=oldRouteTable.PeekInit();
  }
  DMSG(4,"Finished updating %s's route table\n",myaddress.GetHostString());

  
  //printCurrentTable(7);
  DMSG(6,"Exit: Nrlolsr::makeNewRoutingTable()\n");
} //end Nrlolsr::makeNewRoutingTable()

//this is a modified non-spec routing table calculation which takes into consideration bi-directionality of links
//and two hop neighbor information when calcluating routes.  Using this information is not spec compliant and will
//NOT perform correctly when using willingness 0 on ANY nodes in the network.  That being said it should provide 
//quicker reroutes when neighbors time out and be more robust than standard routing calcutation without the added
//overhead of using the -al links option.
//REMINDER: Not spec compliant
//          Will NOT work when ANY node in the MANET is using a willingness of 0 
//          There may be other unknown issues

void 
Nrlolsr::makeNewRoutingTableRobust(){ 
  DMSG(6,"Enter: Nrlolsr::makeNewRoutingTableRobust()\n");
  printCurrentTable(3);
  printTopology(3);
  
  NbrTuple *nb, *nb2=NULL, *best_nb2=NULL, *top_tuple, *old_tuple, *tuple = routeTable.PeekInit();
  NbrTuple *top_tuple_extra;
  int wasnewentry=0, queueIndex=0,foundnewlink=0;
  double smallestSpf=0 ;
  printRoutingTable(2);
  //clearing old routing table
  oldRouteTable.Clear();
  while(tuple){
    routeTable.RemoveCurrent();
    //DMSG(10,"copying entry in routing table to extra queue \n");
    oldRouteTable.QueueObject(tuple);
    tuple=routeTable.PeekInit();
  }

  //fix up lists which are used for output/printing purposes
  routeTopologySet.Clear();
  routeNeighborSet.Clear();

  // making new queue to use 
  extraQueue.Clear();
  NbrTuple * top_tuple_inverse;
  for(top_tuple=topologySet.PeekInit();top_tuple!=NULL;top_tuple=topologySet.PeekNext()){
    extraQueue.QueueObject(top_tuple);
    //this section is adding inverse links to the extra queue (making links bi-directional)
    top_tuple_inverse=new NbrTuple;
    top_tuple_inverse->N_addr=top_tuple->N_2hop_addr;
    top_tuple_inverse->N_2hop_addr=top_tuple->N_addr;
    top_tuple_inverse->N_status=INVALID;//flag for clearing memory when this tc is removed from the extraQueue
    extraQueue.QueueObject(top_tuple_inverse);
  }
  DMSG(9,"%s's Initial extra Topo Table\n",myaddress.GetHostString());
  for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
    DMSG(9," %s-> ",top_tuple->N_addr.GetHostString());
    DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
  }
  //adding one hops
  for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
    if(nb!=NULL){
      if((nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4) && (nb->N_macstatus!=LINK_DOWN)){
	tuple=new NbrTuple;
	tuple->N_time=queueIndex--; //used queue object at head (which is faster way)
  	tuple->N_addr=nb->N_addr;  // really R_dest
  	tuple->N_2hop_addr=nb->N_addr; // really R_next
  	tuple->hop=1;                    // really R_dist
	tuple->N_status=-1;
	routeTable.QueueObject(tuple);
	DMSG(8,"%s is adding direct neighbor ",myaddress.GetHostString());
	DMSG(8,"%s to the routing table\n",tuple->N_2hop_addr.GetHostString());
	//	realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);
	wasnewentry=1;
	// removing links pointing to this node
	for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
	  DMSG(9,"%s is checking the tuple ",myaddress.GetHostString());
	  DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
	  DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
	  if(top_tuple->N_2hop_addr.HostIsEqual(tuple->N_addr)){
	    DMSG(9,"%s is removing the inverse tuple ",myaddress.GetHostString());
	    DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
	    DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
	    extraQueue.RemoveCurrent();
	    if(top_tuple->N_status==INVALID){//have to delete only the inverse tuples made in this function;
	      DMSG(8,"%s is deleting the inverse tuple ",myaddress.GetHostString());
	      DMSG(8,"%s -> ",top_tuple->N_addr.GetHostString());
	      DMSG(8,"%s\n",top_tuple->N_2hop_addr.GetHostString());
	      delete top_tuple;
	    }
	  }
          // also remove all outgoing links as we will add back in only the "best link" using more up to date neighbor info
          else if(top_tuple->N_addr.HostIsEqual(tuple->N_addr)){
	    DMSG(9,"%s is removing the two hop tuple ",myaddress.GetHostString());
	    DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
	    DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
	    extraQueue.RemoveCurrent();
	    if(top_tuple->N_status==INVALID){//have to delete only the inverse tuples made in this function;
	      DMSG(9,"%s is deleting the two hop tuple ",myaddress.GetHostString());
	      DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
	      DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
	      delete top_tuple;
	    }
	  }
	}
	routeNeighborSet.QueueObject(nb);
      }
    }
  }
  //loop for going "fixing" the entries in the working topology extraqueue using 2 hop information (we deleted all the top entries above!
  for(nb=nbr_2hop_list.PeekInit();nb!=NULL;nb=nbr_2hop_list.PeekNext()){
    if(nb!=NULL){
      nb2=NULL;
      if((nb->hop)==2){
	if((nb2=(nb->parents).PeekInit())){
          top_tuple=new NbrTuple;
	  top_tuple->N_2hop_addr=nb->N_addr;  // really T_dest
	  top_tuple->N_status=INVALID;
	  //loop to find most stable link
          best_nb2=nb2;
	  while((nb2=(nb->parents).PeekNext())){
            if(nb2->konectivity>best_nb2->konectivity){ //we found a better first hop
              best_nb2=nb2;
            }
          }
          top_tuple->N_addr=best_nb2->N_addr; // really T_last
          //remove all topology tuples pointing to this 2 hop node as we will manually add it back in.
	  for(top_tuple_extra=extraQueue.PeekInit();top_tuple_extra!=NULL;top_tuple_extra=extraQueue.PeekNext()){
	    DMSG(9,"%s is checking the tuple ",myaddress.GetHostString());
	    DMSG(9,"%s -> ",top_tuple_extra->N_addr.GetHostString());
	    DMSG(9,"%s\n",top_tuple_extra->N_2hop_addr.GetHostString());
	    if(top_tuple_extra->N_2hop_addr.HostIsEqual(top_tuple->N_2hop_addr)){
	      DMSG(9,"%s is removing the inverse tuple ",myaddress.GetHostString());
  	      DMSG(9,"%s -> ",top_tuple_extra->N_addr.GetHostString());
	      DMSG(9,"%s\n",top_tuple_extra->N_2hop_addr.GetHostString());
	      extraQueue.RemoveCurrent();
	      if(top_tuple_extra->N_status==INVALID){//have to delete only the inverse tuples made in this function;
	        DMSG(8,"%s is deleting the inverse tuple ",myaddress.GetHostString());
	        DMSG(8,"%s -> ",top_tuple_extra->N_addr.GetHostString());
	        DMSG(8,"%s\n",top_tuple_extra->N_2hop_addr.GetHostString());
	        delete top_tuple;
	      }
	    }
          }
	  DMSG(9,"%s is adding two hop neighbor tuple ",myaddress.GetHostString());
	  DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
          DMSG(9," %s at time %f\n",top_tuple->N_2hop_addr.GetHostString(),InlineGetCurrentTime());
          extraQueue.QueueObject(top_tuple);
        }
      }
    }
  }
  //extraQueue should be fixed here

  DMSG(9,"%s's extra Topo Table after fixing queue\n",myaddress.GetHostString());
  for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
    DMSG(9," %s-> ",top_tuple->N_addr.GetHostString());
    DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
  }
  int shortesthop=5000;
  while(wasnewentry){
    //add on smallest value nodes
    wasnewentry=0;
    foundnewlink=0;
    /* this is broken cuase it won't always add shortest hop next
    for(top_tuple=extraQueue.PeekInit();(top_tuple!=NULL) && (foundnewlink==0);top_tuple=extraQueue.PeekNext()){
      for(tuple=routeTable.PeekInit();(tuple!=NULL) && (foundnewlink==0);tuple=routeTable.PeekNext()){
	if(top_tuple->N_addr.HostIsEqual(tuple->N_addr) && !(top_tuple->N_2hop_addr).HostIsEqual(myaddress)){ //T_last==R_dest | doesn't point back to here | delay is smaller
	  nb=tuple;
	  nb2=top_tuple;
	  foundnewlink=1;
	}  
      }
      }*/
    shortesthop=5000; 
    for(top_tuple=extraQueue.PeekInit();(top_tuple!=NULL);top_tuple=extraQueue.PeekNext()){
      for(tuple=routeTable.PeekInit();(tuple!=NULL);tuple=routeTable.PeekNext()){
	if(top_tuple->N_addr.HostIsEqual(tuple->N_addr) && !(top_tuple->N_2hop_addr).HostIsEqual(myaddress)){ //T_last==R_dest | doesn't point back to here | delay is smaller
	  if((tuple->hop+1)<shortesthop){//found new shortest hop node
	      DMSG(8,"%s found new shorter hop %d (%d was old) to ",myaddress.GetHostString(),tuple->hop+1,shortesthop);
              DMSG(8," R_dest=%s R_Last=",top_tuple->N_2hop_addr.GetHostString());
              DMSG(8,"%s",top_tuple->N_addr.GetHostString());
              DMSG(8," R_next=%s\n",tuple->N_2hop_addr.GetHostString());
	    shortesthop=tuple->hop+1;
	    nb=tuple;
	    nb2=top_tuple;
	    foundnewlink=1;
	  }
	}  
      }
    }
    if(foundnewlink){
      // add the link nb to routing table and do over again
      //printRoutingTable(3);
      wasnewentry=1;
      tuple = new NbrTuple;
      tuple->N_time=queueIndex--;
      tuple->N_addr=nb2->N_2hop_addr;  //is R_dest=T_dest
      tuple->N_2hop_addr=nb->N_2hop_addr;       //is R_next=R_next
      tuple->N_spf=(UINT8)(smallestSpf*(double)OLSRMAXSPF);
      tuple->hop=nb->hop+1;
      tuple->N_status=0;
      routeTable.QueueObject(tuple); 
	DMSG(8,"%s is adding, %d hop, node ",myaddress.GetHostString(),tuple->hop);
	DMSG(8,"%s to the routing table via node ",tuple->N_addr.GetHostString());
	DMSG(8,"%s at time\n",nb2->N_addr.GetHostString(),InlineGetCurrentTime());
      //realRouteTable->addHostRoute(tuple->N_addr,tuple->N_2hop_addr);
      //have to remove from extraQueue tuples point at node just added
      for(top_tuple=extraQueue.PeekInit();top_tuple!=NULL;top_tuple=extraQueue.PeekNext()){
        DMSG(9,"%s is checking tuple with ",myaddress.GetHostString());
        DMSG(9,"%s ->",top_tuple->N_addr.GetHostString());
        DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());

  //	if(top_tuple->N_2hop_addr.HostIsEqual(nb2->N_2hop_addr)){ //DON'T use this as we may delete the tuple nb2 points to!!!!
        if(top_tuple->N_2hop_addr.HostIsEqual(tuple->N_addr)){

	  extraQueue.RemoveCurrent();
          DMSG(9,"%s is removing the inverse tuple ",myaddress.GetHostString());
          DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
          DMSG(9,"%s from the extraQueue at time %f\n",top_tuple->N_2hop_addr.GetHostString(),InlineGetCurrentTime());
	  
	  if(top_tuple->N_status==INVALID){//only delete the ones which were made new in this function as the others are still in the top_table queue and still valid
            DMSG(9,"%s is deleting the inverse tuple ",myaddress.GetHostString());
            DMSG(9,"%s -> ",top_tuple->N_addr.GetHostString());
	    DMSG(9,"%s\n",top_tuple->N_2hop_addr.GetHostString());
	    delete top_tuple;
          }
	}
      }
      //this route set can't be easily updated and because its only for printing is being disabled.  The "links" being used can sometimes be inverse routes which are deleted
      //finding the "correct" link in the topology table takes too much time as the whole list needs to be searched
      //routeTopologySet.QueueObject(nb2); //add topolgy tuple which was used for this route to the list of links used in route calculation
    }
  }
  //print links which were selected for routes
  //printRouteLinks(); //this was moved to print less often


  // go though and cleanly update the real routing table  
  
  //add direct routes first
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //only do direct routes in the section
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//old host route existed check to see if current choice is different
  	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route (old one was host route)
	  //DMSG(6,"Setting direct route %s\n",tuple->N_addr.GetHostString());
	  //DMSG(6,"metric before call %d\n",tuple->hop);
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	} else {     
	  //DMSG(6,"Not changing direct route to %s\n",tuple->N_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	//DMSG(6,"Adding new direct route %s\n",tuple->N_addr.GetHostString());
	//DMSG(8,"metric before call %d\n",tuple->hop);
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex,tuple->hop);
	//realRouteTable->SetDirectHostRoute(tuple->N_addr,interfaceIndex);
      }
    }
  }
  //add host routes second
  for(tuple=routeTable.PeekInit();tuple!=NULL;tuple=routeTable.PeekNext()){
    if(!tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){ //check to make sure is a host route 
      if((old_tuple = oldRouteTable.FindObject(tuple->N_addr))){
	//DMSG(6,"old route existed for current host route\n");
	//old route existed for current host route
	if(!old_tuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr))){// if the gateways are differnet change the route
	  //DMSG(6,"Setting host route %s to ",tuple->N_addr.GetHostString());
	  //DMSG(6,"%s\n",tuple->N_2hop_addr.GetHostString());
	  realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop); 
	  if(false) {//ipvMode==IPv6){ // this is cause set route functions differently in v4 mode than v6 fix this brian
	    if(old_tuple->N_2hop_addr.HostIsEqual((old_tuple->N_addr))){ //used to be a direct route delete direct route
	      //DMSG(6,"Removing old direct route to %s\n",old_tuple->N_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){//,invalidAddr)){
		DMSG(0,"Nrlolsr::makeNewRoutingTableRobust() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
	      }
	    } else { // used to be a host route delete host route
	      //DMSG(6,"Removing old host route %s ",old_tuple->N_addr.GetHostString());
	      //DMSG(6,"via %s\n",old_tuple->N_2hop_addr.GetHostString());
	      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){//,old_tuple->N_2hop_addr)){
		DMSG(0,"Nrlolsr::makeNewRoutingTableRobust() Error removing host route %s via ",old_tuple->N_addr.GetHostString());
		DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
	      }
	    }
	  }
	} else {
	  //DMSG(6,"Not changing host route to %s via",tuple->N_addr.GetHostString());
	  //DMSG(6," %s\n",tuple->N_2hop_addr.GetHostString());
	}
	oldRouteTable.RemoveCurrent();
	delete old_tuple;
	//free(old_tuple);
      } else {
	//old host route did not exist just add to real table
	//DMSG(6,"Adding new host route dest=%s route=",tuple->N_addr.GetHostString());
	//DMSG(6,"%s\n",tuple->N_2hop_addr.GetHostString());
	realRouteTable->SetRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex,tuple->hop);
      }
    }
  }
  old_tuple=oldRouteTable.PeekInit();
  while(old_tuple){ //loop to clean extraQueue and remove old routes
    oldRouteTable.RemoveCurrent();
    if(old_tuple->N_addr.HostIsEqual((old_tuple->N_2hop_addr))){
      //DMSG(6,"Removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      //ProtoAddress invalidAddress;
      //invalidAddress.Init();
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeNewRoutingTableRobust() Error removing direct route to %s\n",old_tuple->N_addr.GetHostString());
      }
    } else {
      //DMSG(6,"Removing route to %s via ",old_tuple->N_addr.GetHostString());
      //DMSG(6,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      if(!realRouteTable->DeleteRoute(old_tuple->N_addr,hostMaskLength,old_tuple->N_2hop_addr,interfaceIndex)){
	DMSG(0,"Nrlolsr::makeNewRoutingTableRobust() Error removing host route to %s via",old_tuple->N_addr.GetHostString());
	DMSG(0,"%s\n",old_tuple->N_2hop_addr.GetHostString());
      }
    }
    delete old_tuple;
    //free(old_tuple); 
    old_tuple=oldRouteTable.PeekInit();
  }
  //DMSG(6,"Finished updating route table\n");

  
  //printCurrentTable(7);
  DMSG(6,"Exit: Nrlolsr::makeNewRoutingTableRobust()\n");
} //end Nrlolsr::makeNewRoutingTableRobust()

void
Nrlolsr::addHnaRoutes(){
  //DMSG(6,"Enter: Nrlolsr::addHnaRoutes() %s\n",myaddress.GetHostString());
  NbrTuple *routeTuple, *hnaTuple, *addedHnaTuple, *tuple = hnaRoutes.PeekInit();
  bool nomatch, foundhnamatch;
  int addedwithhopcount=0;
  // save old hna route table to oldRoutetable
  oldRouteTable.Clear();
  while(tuple){
    hnaRoutes.RemoveCurrent();
    DMSG(6,"copying entry in routing table to extra queue \n");
    oldRouteTable.QueueObject(tuple);
    tuple=hnaRoutes.PeekInit();
  }
  // next for loop is for updating hnaRoutes
  for(hnaTuple = hnaSet.PeekInit();hnaTuple!=NULL;hnaTuple=hnaSet.PeekNext()){
    nomatch = true;
    addedwithhopcount = 0;
    for(addedHnaTuple = hnaRoutes.PeekInit();addedHnaTuple!=NULL && nomatch;addedHnaTuple=hnaRoutes.PeekNext()){
	  //DMSG(6,"HNA %s is checking new hna route ",myaddress.GetHostString());
	  //DMSG(6,"%s/%d against current route ",hnaTuple->N_2hop_addr.GetHostString(),hnaTuple->subnetMask.GetPrefixLength());
	  //DMSG(6,"%s/%d\n",addedHnaTuple->N_2hop_addr.GetHostString(),addedHnaTuple->subnetMask.GetPrefixLength());

      if(hnaTuple->N_2hop_addr.HostIsEqual((addedHnaTuple->N_2hop_addr)) && 
		 hnaTuple->subnetMask.HostIsEqual((addedHnaTuple->subnetMask))) { //checking for matching subnet address
		addedwithhopcount=addedHnaTuple->hop;
		nomatch = false;
		break; //I hate using breaks! and I hate how for loops do the last statement even when its conditinal is false making me use breaks!
      }    
    }
    for(routeTuple=routeTable.PeekInit();routeTuple!=NULL;routeTuple=routeTable.PeekNext()){
      if(routeTuple->N_addr.HostIsEqual((hnaTuple->N_addr))){ //checking R_dest against hna gateway address
		if(nomatch) {
		  //add new hna info to hna routing table 
		  tuple = new NbrTuple;
		  tuple->N_addr=routeTuple->N_2hop_addr; //R_next
		  tuple->N_2hop_addr=hnaTuple->N_2hop_addr; //sbna
		  tuple->subnetMask=hnaTuple->subnetMask; //mask
		  tuple->hop=routeTuple->hop;
		  hnaRoutes.QueueObject(tuple);
		} else if (routeTuple->hop<addedwithhopcount) { // check to see if current match is better than old
		  //fprintf(stdout,"removing duplicate hna with longer hop count ");
		  //remove and free old
		  hnaRoutes.RemoveCurrent();//its one step back! grrr stupid for loop
		  delete addedHnaTuple;
		  //free(addedHnaTuple);
		  //add new hna info to hna routing table
		  tuple = new NbrTuple;
		  tuple->N_addr=routeTuple->N_2hop_addr; //R_next
		  tuple->N_2hop_addr=hnaTuple->N_2hop_addr; //sbna
		  tuple->subnetMask=hnaTuple->subnetMask; //mask
		  tuple->hop=routeTuple->hop;
		  hnaRoutes.QueueObject(tuple);
		} else {
		  // do nothing already added better route
		}
      }
    } 
  }
  /*fprintf(stdout,"             old table \n");
  for(tuple = oldRouteTable.PeekInit();tuple!=NULL;tuple = oldRouteTable.PeekNext()){
  fprintf(stdout,"R_dest %s ",tuple->N_addr.GetHostString());
  fprintf(stdout,"sbna %s ",tuple->N_2hop_addr.GetHostString());
  fprintf(stdout,"mask %s\n",tuple->subnetMask.GetHostString());
  }
  fprintf(stdout,"           new table \n");
  for(tuple = hnaRoutes.PeekInit();tuple!=NULL;tuple = hnaRoutes.PeekNext()){
  fprintf(stdout,"R_dest %s ",tuple->N_addr.GetHostString());
  fprintf(stdout,"sbna %s ",tuple->N_2hop_addr.GetHostString());
  fprintf(stdout,"mask %s\n",tuple->subnetMask.GetHostString());
  }*/
  //hnaRoutes are up to date add to real routing table
  for(routeTuple = hnaRoutes.PeekInit();routeTuple!=NULL;routeTuple = hnaRoutes.PeekNext()){
    foundhnamatch = false;
    for(tuple = oldRouteTable.PeekInit();tuple!=NULL;tuple = oldRouteTable.PeekNext()){ 
      if(routeTuple->N_2hop_addr.HostIsEqual((tuple->N_2hop_addr)) &&
		 routeTuple->subnetMask.HostIsEqual((tuple->subnetMask))){	
		foundhnamatch = true;
		if(!(routeTuple->N_addr.HostIsEqual((tuple->N_addr)))) {
		  //found existing differet route change it
		  //DMSG(6,"HNA %s is setting net route to ",myaddress.GetHostString());
		  //DMSG(6,"%s / %d via",routeTuple->N_2hop_addr.GetHostString(),routeTuple->subnetMask.GetPrefixLength());
		  //DMSG(6," %s\n",routeTuple->N_addr.GetHostString());
		  realRouteTable->SetRoute(routeTuple->N_2hop_addr,routeTuple->subnetMask.GetPrefixLength(),routeTuple->N_addr,interfaceIndex,routeTuple->hop);
		  if(false){//ipvMode==IPv6){
			//DMSG(6,"HNA Delete net route %s / %d via",tuple->N_2hop_addr.GetHostString(),tuple->subnetMask.GetPrefixLength());
			//DMSG(6," %s\n",tuple->N_addr.GetHostString());
			if(!realRouteTable->DeleteRoute(tuple->N_2hop_addr,tuple->subnetMask.GetPrefixLength(),tuple->N_addr,interfaceIndex)){//,tuple->N_addr,interfaceIndex)){
			  DMSG(0,"Nrlolsr::addHnaRoutes() Error removing net route\n");
			}
		  }
		  // don't need next three lines
		  //if(!realRouteTable->DeleteRoute(tuple->N_2hop_addr,tuple->subnetMask,tuple->N_addr,interfaceIndex)){
		  //  DMSG(0,"removing net route error\n");
		  //}
		  
		} else {
		  //DMSG(6,"HNA Found matching hna entry in current route table for %s leaving alone\n",routeTuple->N_addr.GetHostString());
		  //found same route leave alone
		}
		//free up oldroutetable entry
		oldRouteTable.RemoveCurrent();
		delete tuple;
		//free(tuple);
      } 
    }
    if (!foundhnamatch) {
      //DMSG(6,"HNA %s is adding new route to ",myaddress.GetHostString());
	  //DMSG(6,"%s / %d via ",routeTuple->N_2hop_addr.GetHostString(),routeTuple->subnetMask.GetPrefixLength());
      //DMSG(6,"%s\n",routeTuple->N_addr.GetHostString());
      //found new route and adding it here
      realRouteTable->SetRoute(routeTuple->N_2hop_addr,routeTuple->subnetMask.GetPrefixLength(),routeTuple->N_addr,interfaceIndex,routeTuple->hop);
    }
  }
  // clean up oldRouteTable
  tuple=oldRouteTable.PeekInit();
  while(tuple){ //loop to clean extraQueue and remove old routes
    oldRouteTable.RemoveCurrent();
    //remove old route
	//DMSG(6,"HNA %s is removing old route to ",myaddress.GetHostString());
    //DMSG(6,"%s / %d via ",tuple->N_2hop_addr.GetHostString(),tuple->subnetMask.GetPrefixLength());
    //DMSG(6," %s\n",tuple->N_addr.GetHostString());
    if(!realRouteTable->DeleteRoute(tuple->N_2hop_addr,tuple->subnetMask.GetPrefixLength(),tuple->N_addr,interfaceIndex)){//,tuple->N_addr)){
      DMSG(0,"error removing net route\n");
    }
    delete tuple;
    //free(tuple); 
	
    tuple=oldRouteTable.PeekInit();
  }
  //DMSG(6,"Exit: Nrlolsr::addHnaRoutes()\n");
} // end Nrlolsr::addHnaRoutes()

int 
Nrlolsr::WasForwarded(ProtoAddress addr,UINT16 dseqno){
  //DMSG(6,"Enter: Nrlolsr::WasForwarded(addr %s,dseqno %d\n",addr.GetHostString(),dseqno);
  NbrTuple *tuple = forwardTable.FindObject(addr);
  if(addr.HostIsEqual(myaddress)){
    return 1;
  }
  while(tuple){
    if(tuple->seq_num==dseqno){
      //DMSG(6,"Exit: Nrlolsr::WasForwarded(addr %s,dseqno %d\n",addr.GetHostString(),dseqno);
      return 1;
    }
    tuple = forwardTable.FindNextObject(addr);
  }
  //DMSG(6,"Exit: Nrlolsr::WasForwarded(addr %s,dseqno %d\n",addr.GetHostString(),dseqno);
  return 0;
}// end Nrlolsr::WasForwarded

void
Nrlolsr::addForwarded(ProtoAddress forwardaddr,UINT16 dseqno){
  //DMSG(6,"Enter: Nrlolsr::addForwarded(forwardaddr %s,dseqno %d\n",forwardaddr.GetHostString(),dseqno);
  NbrTuple *tuple = forwardTable.FindObject(forwardaddr);
  while(tuple){
    if(tuple->seq_num==dseqno){ 
      tuple->N_time = InlineGetCurrentTime()+D_Hold_Time;
      //DMSG(6,"Exit: Nrlolsr::addForwarded(forwardaddr %s,dseqno %d\n",forwardaddr.GetHostString(),dseqno);
      return;
    }
    tuple = forwardTable.FindNextObject(forwardaddr);
  }  
  tuple = new NbrTuple;
  tuple->seq_num = dseqno;
  tuple->N_addr = forwardaddr;
  tuple->N_time = InlineGetCurrentTime()+D_Hold_Time;
  forwardTable.QueueObject(tuple);
  //DMSG(6,"Exit: Nrlolsr::addForwarded(forwardaddr %s,dseqno %d\n",forwardaddr.GetHostString(),dseqno);
}

int
Nrlolsr::IsDuplicate(ProtoAddress addr,UINT16 dseqno){
  //DMSG(6,"Enter: Nrlolsr::IsDuplicate(addr %s,dseqno %d)\n",addr.GetHostString(),dseqno);
  NbrTuple *tuple = duplicateTable.FindObject(addr);
  printDuplicateTable(8);
  if(addr.HostIsEqual(myaddress)){
    //DMSG(6,"Exit: Nrlolsr::IsDuplicate(addr %s,dseqno %d)\n",addr.GetHostString(),dseqno);
    return 1;
  }
  while(tuple){
    if(tuple->seq_num==dseqno){ 
      //DMSG(1,"%s with seq num %d is DUP!",addr.GetHostString(),dseqno);
      //DMSG(6,"Exit: Nrlolsr::IsDuplicate(addr %s,dseqno %d)\n",addr.GetHostString(),dseqno);
      return 1;
    }
    tuple = duplicateTable.FindNextObject(addr);
  }
  //DMSG(6,"Exit: Nrlolsr::IsDuplicate(addr %s,dseqno %d)\n",addr.GetHostString(),dseqno);
  return 0;
}

// add entry addr and dseqno to duplicate table
void
Nrlolsr::addDuplicate(ProtoAddress dupaddr,UINT16 dseqno){
  //DMSG(6,"Enter: Nrlolsr::addDuplicate(dupaddr %s,dseqno %d)\n",dupaddr.GetHostString(),dseqno);
  NbrTuple *tuple = duplicateTable.FindObject(dupaddr);
  while(tuple){
    if(tuple->seq_num==dseqno){ 
      tuple->N_time = InlineGetCurrentTime()+D_Hold_Time;
      //DMSG(6,"Exit: Nrlolsr::addDuplicate(dupaddr %s,dseqno %d)\n",dupaddr.GetHostString(),dseqno);
      return;
    }
    tuple = duplicateTable.FindNextObject(dupaddr);
  }  
  tuple = new NbrTuple;
  tuple->seq_num = dseqno;
  tuple->N_addr = dupaddr;
  tuple->N_time = InlineGetCurrentTime()+D_Hold_Time;
  duplicateTable.QueueObject(tuple);
  printDuplicateTable(4);
  //DMSG(6,"Exit: Nrlolsr::addDuplicate(dupaddr %s,dseqno %d)\n",dupaddr.GetHostString(),dseqno);
}


// printing functions for debuging code
void 
Nrlolsr::printDuplicateTable(int debuglvl){
  if(olsrDebugValue>=debuglvl){
    NbrTuple *tuple;
    //DMSG(debuglvl,"------- %s's duplicate table --------\n",myaddress.GetHostString());
    for(tuple=duplicateTable.PrintPeekInit();tuple!=NULL;tuple=duplicateTable.PrintPeekNext()){
      if(tuple!=NULL){
	//DMSG(debuglvl," D_Addr= %s D_Seqn= %d D_time= %f \n",tuple->N_addr.GetHostString(), tuple->seq_num, tuple->N_time);
      }
    }
    //DMSG(debuglvl,"------- end duplicate table -------- \n");
  }  
}
void 
Nrlolsr::printHnaTables(int debuglvl){
  if(olsrDebugValue>=debuglvl){
    NbrTuple *tuple;
    //print out to  debug file
    DMSG(debuglvl,"***************%s's local hna list **************\n",myaddress.GetHostString());
    for(tuple=hnaAddresses.PrintPeekInit();tuple!=NULL;tuple=hnaAddresses.PrintPeekNext()){
      DMSG(debuglvl,"Subnetaddress %s ",tuple->N_addr.GetHostString());
      DMSG(debuglvl,"subnetmask %s\n",tuple->N_2hop_addr.GetHostString());
    }
    DMSG(debuglvl,"***************end local hna list  **************\n\n");
    DMSG(debuglvl,"***************%s's hnaSet list ***************\n",myaddress.GetHostString());
    for(tuple=hnaSet.PrintPeekInit();tuple!=NULL;tuple=hnaSet.PrintPeekNext()){
      DMSG(debuglvl,"R_dest %s ",tuple->N_addr.GetHostString());
      DMSG(debuglvl,"subnetaddr %s ",tuple->N_2hop_addr.GetHostString());
      DMSG(debuglvl,"subnetmask %s time %f\n",tuple->subnetMask.GetHostString(),tuple->N_time);
    }
    DMSG(debuglvl,"***************end hna set list  **************\n\n");
    DMSG(debuglvl,"***************%s's hnaRoutes list ***************\n",myaddress.GetHostString());
    for(tuple=hnaRoutes.PrintPeekInit();tuple!=NULL;tuple=hnaRoutes.PrintPeekNext()){
      DMSG(debuglvl,"R_next %s ",tuple->N_addr.GetHostString());
      DMSG(debuglvl,"subnetaddr %s ",tuple->N_2hop_addr.GetHostString());
      DMSG(debuglvl,"subnetmask %s\n",tuple->subnetMask.GetHostString());
    }
    DMSG(debuglvl,"***************end hna set list  **************\n\n");
  }
}

void
Nrlolsr::printRoutingTable(int debuglvl){
  if(olsrDebugValue>=debuglvl){
    int numberofroutes=0;
    NbrTuple *tuple;
    DMSG(debuglvl,"------- %s's routing table at time %f --------\n",myaddress.GetHostString(),InlineGetCurrentTime());
    for(tuple=routeTable.PrintPeekInit();tuple!=NULL;tuple=routeTable.PrintPeekNext()){
      if(tuple!=NULL){
	numberofroutes++;
	DMSG(debuglvl," R_dest= %s ",tuple->N_addr.GetHostString());
	DMSG(debuglvl,"R_next=%s R_dist=%d iteration=%d spf=%d minmax=%d\n",tuple->N_2hop_addr.GetHostString(),tuple->hop,tuple->N_status,tuple->N_spf,tuple->N_minmax);
      }
    }
    DMSG(debuglvl,"------- end %s's routing table with %d entries at time %f-------- \n",myaddress.GetHostString(),numberofroutes,InlineGetCurrentTime());
  }
}

void
Nrlolsr::printHnaLinks(){
    //print out stdout for use with cmap
#ifndef SIMULATE
#ifdef UNIX
  NbrTuple *tuple;
  if(olsrDebugValue>=2){
    FILE *fid = popen("date -u +%T","r");
    char dateBuffer[10];
    char* trashCharPtr = NULL;
    trashCharPtr = fgets(dateBuffer,9,fid);
    pclose(fid);
    fprintf(stdout,"Hna-Networks List: %s.%06d\n",dateBuffer,GetLittleTime());
    for(tuple=hnaAddresses.PrintPeekInit();tuple!=NULL;tuple=hnaAddresses.PrintPeekNext()){
      fprintf(stdout,"%s -> ",myaddress.GetHostString());
      fprintf(stdout,"%s/%d\n",tuple->N_addr.GetHostString(),tuple->N_2hop_addr.GetPrefixLength());
    } 
    for(tuple=hnaSet.PrintPeekInit();tuple!=NULL;tuple=hnaSet.PrintPeekNext()){
      fprintf(stdout,"%s -> ",tuple->N_addr.GetHostString());
      fprintf(stdout,"%s/%d\n",tuple->N_2hop_addr.GetHostString(),tuple->subnetMask.GetPrefixLength());
    }
    fprintf(stdout,"End of Hna-Networks List.\n");
    fflush(stdout);
  }   
#endif //UNIX
#endif //SIMULATE
}

#ifdef SIMULATE  // If we're in NS-2, make SendForwardingInfo() a noop function
#ifndef OPNET 
void Nrlolsr::SendForwardingInfo(){}
#endif //OPNET
#endif //SIMULATE


#ifdef OPNET
void Nrlolsr::SendForwardingInfo(){
  char buffer[512];
  unsigned int len = 0;    
  if (floodingOn){
    switch(floodingType){
      case SMPR:
#ifdef SMF_SUPPORT
      if(!ipToMacTable.IsEmpty())
	  { //do I have any ip to mac mappings so I can send mac address?
	    SendMacMprInfo(); 
	    SendMacSymInfo();
	    updateSmfForwardingInfo=false; //reset update state
	  }
      break;
#endif // SMF_SUPPORT
    case NOTSYM:
      break;
    case SIMPLE:
    case NSMPR:
    case MPRCDS:
    case ECDS: 
      if(localNodeIsForwarder){
	  	strcpy(buffer,"defaultForward on");
      } else {
	  	strcpy(buffer,"defaultForward off");
      }
      len = strlen(buffer);
	  {
	  Ici* cmd_ici = op_ici_create("smfControlMsg");
	  op_ici_attr_set_ptr(cmd_ici,"cmdbuf",buffer);
	  op_ici_attr_set_int32(cmd_ici,"len",len);
	  op_ici_install(cmd_ici);
	  op_intrpt_force_remote(0,smf_objid);
	  }	  
      break;
    default:
      fprintf(stderr,"NrlolsrAgent::mcastForward(p): Error trying to forward broadcast pack because floodingType %d is not defined\n",floodingType);
    }  // switch
  } else { //flooding is off so make sure default is off
	strcpy(buffer,"defaultForward off");
    len = strlen(buffer);
	{
	Ici* cmd_ici = op_ici_create("smfControlMsg");
	op_ici_attr_set_ptr(cmd_ici,"cmdbuf",buffer);
	op_ici_attr_set_int32(cmd_ici,"len",len);
	op_ici_install(cmd_ici);
	op_intrpt_force_remote(0,smf_objid);
	}	
  }
}
#endif //OPNET

#ifndef SIMULATE
void Nrlolsr::SendSDTInfo()
{
//    DMSG(6,"Nrlolsr::SendSDTInfo: Enter\n");
    char buffer[512];
    unsigned int len = 0;
    NbrTuple *nb;
    if (sdt_pipe.IsOpen() && SDTOn)
    {
        //currently only supports non source based forwarding for the spheres
        if(localNodeIsForwarder != localNodeIsForwarder_old)
        {
            if(localNodeIsForwarder)
            {
                sprintf(buffer,"node %s symbol sphere,blue,X,X,X,0.15\n",myaddress.GetHostString());
            } 
            else 
            {
                sprintf(buffer,"node %s symbol none",myaddress.GetHostString());
                //sprintf(buffer,"node %s symbol sphere, X,X,X,X,0.0\n",myaddress.GetHostString());
            }
            len = strlen(buffer);
            if(!sdt_pipe.Send(buffer,len))
            {
                DMSG(0,"Nrlolsr::SendSDTInfo() error sending to sdt_pipe!\n");
            }
            localNodeIsForwarder_old = localNodeIsForwarder;
        }
        memset(buffer,0,512);
        //currently only outputs one hop link information.  We will want to expand this too include information from TC link state as well

        for(nb=nbr_list.PrintPeekInit();nb!=NULL;nb=nbr_list.PrintPeekNext())
        {
            switch(nb->N_status)
            {
                case LOST_LINKv4:
                case ASYM_LINKv4:
                case PENDING_LINK:
                    if ((nb->N_old_status == SYM_LINKv4) ||
                        (nb->N_old_status == MPR_LINKv4))
                    { 
                        sprintf(buffer,"delete link,%s,",myaddress.GetHostString());
                        len = strlen(buffer);
                        sprintf(buffer+len,"%s,olsr:nbr",nb->N_addr.GetHostString());
                        len = strlen(buffer);
                        if(!sdt_pipe.Send(buffer,len))
                        {
                            DMSG(0,"Nrlolsr::SendSDTInfo() error sending to sdt_pipe!\n");
                        }
                        memset(buffer,0,512);
                    }
                    break;
                case SYM_LINKv4:
                case MPR_LINKv4:
                    if ((nb->N_old_status == LOST_LINKv4) ||
                        (nb->N_old_status == ASYM_LINKv4) ||
                        (nb->N_old_status == PENDING_LINK))
                    { 
                        sprintf(buffer,"link %s,",myaddress.GetHostString());
                        len = strlen(buffer);
                        sprintf(buffer+len,"%s,olsr:nbr",nb->N_addr.GetHostString());
                        len = strlen(buffer);
                        if(!sdt_pipe.Send(buffer,len))
                        {
                            DMSG(0,"Nrlolsr::SendSDTInfo() error sending to sdt_pipe!\n");
                        }
                        memset(buffer,0,512);
                    }
                    break;
                default:
                    ;//fprintf(stdout,"INVALID, ");
            }
            nb->N_old_status = nb->N_status; //update the old value as we have just sent anything we needed too.
        }
    } 
}
void Nrlolsr::SendForwardingInfo(){
    //DMSG(6,"Nrlolsr::SendForwardingInfo: Enter\n");
    if(SDTOn)
    {
        SendSDTInfo();
    }
  char buffer[512];
  unsigned int len = 0;    
  if (smf_pipe.IsOpen() && floodingOn){
    switch(floodingType){
      case SMPR:
#ifdef SMF_SUPPORT
      if(!ipToMacTable.IsEmpty())
	  { //do I have any ip to mac mappings so I can send mac address?
	  SendMacMprInfo();
	  SendMacSymInfo();
	  updateSmfForwardingInfo=false; //reset update state
	  }
      break;
#endif // SMF_SUPPORT
    case NOTSYM:
      break;
    case SIMPLE:
    case NSMPR:
    case MPRCDS:
    case ECDS:
      if(localNodeIsForwarder){
                DMSG(4,"turning on forwarding for all interfaces\n");
	  	strcpy(buffer,"defaultForward on");
      } else {
                DMSG(5,"turning off forwarding for all interfaces\n");
	  	strcpy(buffer,"defaultForward off");
      }
      len = strlen(buffer);
      if(!smf_pipe.Send(buffer,len)){
	  	DMSG(0,"Nrlolsr::SendForwardingInfo MPRCDS case error sending info to smf pipe\n");
      } else {
	  	updateSmfForwardingInfo=false; //reset update state
      }
      break;
    default:
      fprintf(stderr,"NrlolsrAgent::mcastForward(p): Error trying to forward broadcast pack because floodingType %d is not defined\n",floodingType);
    }  // switch
  } else { //flooding is off so make sure default is off
	if(smf_pipe.IsOpen()){
	  strcpy(buffer,"defaultForward off");
      len = strlen(buffer);
      if(!smf_pipe.Send(buffer,len)){
        DMSG(0,"Nrlolsr::SendForwardingInfo OFF area error sending info to smf pipe\n");
	  } else {
        updateSmfForwardingInfo=false; //reset update state
	  }
    }
  }
}
#endif // SIMULATE


void
Nrlolsr::SendGuiRoutes(){
#ifndef SIMULATE
  if(!gui_pipe.IsOpen()){
    DMSG(0,"Nrlolsr::SendGuiRoutes(); gui_pipe is not open!\n");
    return;
  }
  char buffer[8192];
  unsigned int len = 0;
  strcpy(buffer, "routes ");
  for(NbrTuple* routePtr=routeTable.PrintPeekInit(); routePtr!=NULL;routePtr=routeTable.PrintPeekNext()){ //adds a line to the buffer
    if(strlen(buffer)+100>8192){
      DMSG(0,"Nrlolsr::SendGuiRoutes(): insufficent buffer space\n");
      return;
    }
    strcat(buffer,routePtr->N_addr.GetHostString());
    strcat(buffer," ");
    strcat(buffer,routePtr->N_2hop_addr.GetHostString());
    strcat(buffer," ");
    if(dominmax){
      sprintf(buffer+strlen(buffer),"%f",(double)routePtr->N_minmax);
    } else if(dospf){
      sprintf(buffer+strlen(buffer),"%f",(double)routePtr->N_spf);
    } else {
      sprintf(buffer+strlen(buffer),"%d",routePtr->hop);
    }
    strcat(buffer," ");
    strcat(buffer,interfaceName);
    strcat(buffer," ");
  }
  strcat(buffer,"end-routes\0");
  len = strlen(buffer);
  if(!gui_pipe.Send(buffer,len)){
    DMSG(0,"Nrlolsr::SendGuiRoutes(): gui_pipe.Send() error\n");
  }
#endif //SIMULATE
}

void
Nrlolsr::SendGuiNeighbors(){
#ifndef SIMULATE
  if(!gui_pipe.IsOpen()){
    DMSG(0,"Nrlolsr::SendGuiNeighbors(): gui_pipe is not open!\n");
    return;
  }
  char buffer[8192];
  strcpy(buffer,"neighbors ");
  for(NbrTuple* nb=nbr_list.PrintPeekInit();nb!=NULL;nb=nbr_list.PrintPeekNext()){ //adds a line to the buffer
    if(strlen(buffer)+100>8192){
      DMSG(0,"Nrlolsr::SendGuiNeighbors(): insufficent buffer space.\n");
      return;
    }
    strcat(buffer,nb->N_addr.GetHostString());
    strcat(buffer," ");
    switch(nb->N_status){
    case LOST_LINKv4:
      strcat(buffer,"LOST ");
      break;
    case ASYM_LINKv4:
      strcat(buffer,"ASYM ");
      break;
    case SYM_LINKv4:
      strcat(buffer,"SYM ");
      break;
    case MPR_LINKv4:
      strcat(buffer,"MPR ");
      break;
    case PENDING_LINK:
      strcat(buffer,"PENDING ");
      break;
    default:
      strcat(buffer,"INVALID ");
    }
    sprintf(buffer+strlen(buffer),"%f ",nb->konectivity);
    if(mprSelectorList.FindObject(nb->N_addr)){
      strcat(buffer,"TRUE ");
    } else {
      strcat(buffer,"FALSE ");
    }
  }
  strcat(buffer,"end-neighbors\0");
  unsigned int len = strlen(buffer);
  if(!gui_pipe.Send(buffer,len)){
    DMSG(0,"Nrlolsr::SendGuiNeighbors(): gui_pipe.Send() error\n");
  }
#endif //NOT SIMULATE
}
void 
Nrlolsr::SendGuiSettings(){
#ifndef SIMULATE
  if(!gui_pipe.IsOpen()){
    DMSG(0,"Nrlolsr::SendGuiNeighbors(): gui_pipe is not open!\n");
    return;
  }
  char buffer[8192];
  sprintf(buffer,"settings %d %d %d %f %f %f %f %f %f %f %f %f %f %f %f %d",
	  allLinks,fuzzyflooding,tcSlowDown,
	  Hello_Interval,Hello_Jitter,Hello_Timeout_Factor,
	  TC_Interval,TC_Jitter,TC_Timeout_Factor,
	  HNA_Interval,HNA_Jitter,HNA_Timeout_Factor,
	  T_up,T_down,alpha,localWillingness);
  unsigned int len = strlen(buffer);
  if(!gui_pipe.Send(buffer,len)){
    DMSG(0,"Nrlolsr::SendGuiNeighbors(): gui_pipe.Send() error\n");
  }
#endif //NOT SIMULATE
} 



#ifdef SMF_SUPPORT
void Nrlolsr::SendMacMprInfo()
{ 
    char buffer[8192];
    strcpy(buffer, "selectorMac ");
    unsigned int len = strlen(buffer);
    for(NbrTuple* nb=mprSelectorList.PrintPeekInit(); nb!=NULL; nb=mprSelectorList.PrintPeekNext())
    {
        ProtoAddress macAddr;
        unsigned int ifIndex;
        int metric;
        if (ipToMacTable.GetRoute(nb->N_addr, hostMaskLength, macAddr, ifIndex, metric))
        {
			unsigned int macLen = macAddr.GetLength();	// JPH SMF - Opnet uses an int (len=4) for mac addrs
            memcpy(buffer+len, macAddr.GetRawHostAddress(), macLen);
            len += macLen;
            if (len >= (8192 - macLen))
            {
                DMSG(0, "Nrlolsr::SendMacMprInfo() selector list exceeded max message length!\n");
                break;
            }
        }
    }
#ifndef OPNET  // JPH SMF
    if(!smf_pipe.Send(buffer, len))
        DMSG(0,"Nrlolsr::SendMacMprInfo(): smf_pipe.Send() error\n");
#else
	Ici* cmd_ici = op_ici_create("smfControlMsg");
	op_ici_attr_set_ptr(cmd_ici,"cmdbuf",buffer);
	op_ici_attr_set_int32(cmd_ici,"len",len);
	op_ici_install(cmd_ici);
	op_intrpt_force_remote(0,smf_objid);
#endif  // OPNET
} //end SendMacMprInfo()

void Nrlolsr::SendMacSymInfo()
{ 
    char buffer[8192];
    strcpy(buffer, "neighborMac ");
    unsigned int len = strlen(buffer);
    for(NbrTuple* nb=nbr_list.PrintPeekInit(); nb!=NULL; nb=nbr_list.PrintPeekNext())
    {
      if((nb->N_status==SYM_LINKv4) || (nb->N_status==MPR_LINKv4)){
        ProtoAddress macAddr;
	unsigned int ifIndex;
        int metric;
        if (ipToMacTable.GetRoute(nb->N_addr, hostMaskLength, macAddr, ifIndex, metric))
	  {
            memcpy(buffer+len, macAddr.GetRawHostAddress(), 6);
            len += 6;
            if (len >= (8192 - 6))
	      {
                DMSG(0, "Nrlolsr::SendMacSymInfo() list exceeded max message length!\n");
                break;
	      }
	  }
      }    
    }
#ifndef OPNET  // JPH SMF
    if(!smf_pipe.Send(buffer, len))
        DMSG(0,"Nrlolsr::SendMacSymInfo(): smf_pipe.Send() error\n");
#else
	Ici* cmd_ici = op_ici_create("smfControlMsg");
	op_ici_attr_set_ptr(cmd_ici,"cmdbuf",buffer);
	op_ici_attr_set_int32(cmd_ici,"len",len);
	op_ici_install(cmd_ici);
	op_intrpt_force_remote(0,smf_objid);
#endif  // OPNET
} //end SendMacSymInfo()
#endif // SMF_SUPPORT

void
Nrlolsr::printNbrs(){
#ifndef SIMULATE
#ifdef UNIX
  NbrTuple *nb;
  if(olsrDebugValue>=1){
    FILE *fid = popen("date -u +%T","r");
    char dateBuffer[10];
    char *trashCharPtr = NULL;
    trashCharPtr = fgets(dateBuffer,9,fid);
    pclose(fid);
    fprintf(stdout,"Nbr List: %s.%06d\n",dateBuffer,GetLittleTime());
    for(nb=nbr_list.PrintPeekInit();nb!=NULL;nb=nbr_list.PrintPeekNext()){
      fprintf(stdout,"%s -> ",myaddress.GetHostString());
      fprintf(stdout,"%s, Type: ",nb->N_addr.GetHostString());
      switch(nb->N_status){
      case LOST_LINKv4:
	fprintf(stdout,"LOST, ");
	break;
      case ASYM_LINKv4:
	fprintf(stdout,"ASYM, ");
	break;
      case SYM_LINKv4:
	fprintf(stdout,"SYM, ");
	break;
      case MPR_LINKv4:
	fprintf(stdout,"MPR, ");
	break;
      case PENDING_LINK:
	fprintf(stdout,"PENDING, ");
	break;
      default:
	fprintf(stdout,"INVALID, ");
      }
      fprintf(stdout,"Hystersis: %f, Mac status: ",nb->konectivity);
      switch(nb->N_macstatus){
      case LINK_UP:
	fprintf(stdout,"UP, ");
	break;
      case LINK_DOWN:
	fprintf(stdout,"DOWN, ");
	break;
      case LINK_DEFAULT:
	fprintf(stdout,"DEFAULT, ");
	break;
      default:
	fprintf(stdout,"INVALID, ");
	break;
      }
      fprintf(stdout,"MinMax: %d, SPF %d.\n",(int)nb->N_minmax,(int)nb->N_spf);
    }
    fprintf(stdout,"End of Nbr List.\n");
    fflush(stdout);
  }
  return;
#endif //UNIX
#endif //SIMULATE
}


void
Nrlolsr::printLinks(){
#ifndef SIMULATE
#ifdef UNIX
  NbrTuple *tuple,*nb;
  if(olsrDebugValue>=1){
    FILE *fid = popen("date -u +%T","r");
    char dateBuffer[10];
    char *trashCharPtr = NULL;
    trashCharPtr = fgets(dateBuffer,9,fid);
    pclose(fid);
    fprintf(stdout,"Routing-Links List: %s.%06d\n",dateBuffer,GetLittleTime());
    for(nb=nbr_list.PrintPeekInit();nb!=NULL;nb=nbr_list.PrintPeekNext()){
      if(nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4){
	fprintf(stdout,"%s -> ",myaddress.GetHostString());
	fprintf(stdout,"%s",nb->N_addr.GetHostString());      
	if(dominmax || dospf){ //I have extra information to send out
	  fprintf(stdout,",%d",(int)(nb->konectivity*100));
	}
	fprintf(stdout,"\n");
      }
    }
    for(tuple=topologySet.PrintPeekInit();tuple!=NULL;tuple=topologySet.PrintPeekNext()){
      if(tuple!=NULL){
	fprintf(stdout,"%s -> ",tuple->N_addr.GetHostString());
	fprintf(stdout,"%s",tuple->N_2hop_addr.GetHostString());
	if(dominmax){ //I have extra information to send out
	  fprintf(stdout,",%d",(int)(((float)tuple->N_minmax)/2.55));
	} else if(dospf){
	  fprintf(stdout,",%d",(int)(((float)tuple->N_spf)/2.55));
	}
	fprintf(stdout,"\n");
      }
    }
    fprintf(stdout,"End of Routing-Links List.\n");
    fflush(stdout);
  }
#endif //UNIX
#endif //SIMULATE
}
void 
Nrlolsr::printRouteLinks(){
#ifndef SIMULATE
#ifdef UNIX
  NbrTuple *tuple, *nb;
  if(olsrDebugValue>=1){
    FILE *fid = popen("date -u +%T","r");
    char dateBuffer[10];
    char *trashCharPtr = NULL;
    trashCharPtr = fgets(dateBuffer,9,fid);
    pclose(fid);
    fprintf(stdout,"Used-Routing-Links List: %s.%06d\n",dateBuffer,GetLittleTime());
    for(nb=routeNeighborSet.PrintPeekInit();nb!=NULL;nb=routeNeighborSet.PrintPeekNext()){
      fprintf(stdout,"%s -> ",myaddress.GetHostString());
      fprintf(stdout,"%s\n",nb->N_addr.GetHostString());
    }
    for(tuple=routeTopologySet.PrintPeekInit();tuple!=NULL;tuple=routeTopologySet.PrintPeekNext()){
      fprintf(stdout,"%s -> ",tuple->N_addr.GetHostString());
      fprintf(stdout,"%s\n",tuple->N_2hop_addr.GetHostString());
    }
    fprintf(stdout,"End of Used-Routing-Links List.\n");
    fflush(stdout);
  }   
#endif//UNIX
#endif//SIMULATE
}

void 
Nrlolsr::printTopology(int debuglvl){
  NbrTuple *tuple;
  if(olsrDebugValue>=debuglvl){
    int numberoflinks=0;
    DMSG(debuglvl,"== %s's topology table at time %f== \n",myaddress.GetHostString(),InlineGetCurrentTime());
    for(tuple=topologySet.PrintPeekInit();tuple!=NULL;tuple=topologySet.PrintPeekNext()){
      if(tuple!=NULL){
	numberoflinks++;
	DMSG(debuglvl,"T_Last=%s ",tuple->N_addr.GetHostString());
	DMSG(debuglvl,"T_dest=%s mssn=%d spf=%d minmax=%d\n",tuple->N_2hop_addr.GetHostString(), tuple->seq_num,tuple->N_spf,tuple->N_minmax);
      }
    }
    DMSG(debuglvl,"== end %s's topo table with %d links ==\n",myaddress.GetHostString(),numberoflinks);
  }
}

int 
Nrlolsr::checkCurrentTable(int callvalue){
  NbrTuple *nb,*nb2;
  int isgood;
  if(noerrors){
    for(nb=nbr_list.PrintPeekInit();nb!=NULL;nb=nbr_list.PrintPeekNext()){
      if(nb!=NULL){
	for(nb2=(nb->children).PrintPeekInit();nb2!=NULL;nb2=(nb->children).PrintPeekNext()){
	  if(nb2!=NULL){
	    isgood=0;
	    //check to see that this child points back up only once to parent
	    if((nb2->parents).FindObject(nb->N_addr)){
	      isgood++;
	    }
	    if((nb2->stepparents).FindObject(nb->N_addr)){
	      isgood++;
	    }
	    if(isgood==0){
	      DMSG(0,"table error from %d, child pointer with no return parents or stepparents pointer, step/parent is %s child is ",callvalue,nb->N_addr.GetHostString());
	      DMSG(0,"%s | ",nb2->N_addr.GetHostString());
	      noerrors=0;
	    }
	    if(isgood==2){
	      DMSG(0,"table error from %d, child pointer with stepparent and parent, step/parent is %s child is ",callvalue,nb->N_addr.GetHostString());
	      DMSG(0,"%s | ",nb2->N_addr.GetHostString());
	      noerrors=0;
	    }
	  }
	}
	for(nb2=(nb->parents).PrintPeekInit();nb2!=NULL;nb2=(nb->parents).PrintPeekNext()){
	  if(nb2!=NULL){
	    //check to see that parent points to child once
	    isgood=0;
	    if((nb2->children).FindObject(nb->N_addr)){
	      isgood++;
	    }
	    if(!isgood){
	      DMSG(0,"table error from %d, parent pointer with no return child pointer, parent %s child ",callvalue,nb2->N_addr.GetHostString());
	      DMSG(0,"%s found in checking table | ",nb->N_addr.GetHostString());
	      noerrors=0;
	    }
	  }
	}
	for(nb2=(nb->stepparents).PrintPeekInit();nb2!=NULL;nb2=(nb->stepparents).PrintPeekNext()){
	  if(nb2!=NULL){
	    //check to see that stepparents points to child once
	    isgood=0;
	    if((nb2->children).FindObject(nb->N_addr)){
	      isgood++;
	    }
	    if(!isgood){
	      DMSG(0,"table error from %d, stepparent pointer with no return child pointer, parent %s child ",callvalue,nb2->N_addr.GetHostString());
	      DMSG(0,"%s found in checking table | ",nb->N_addr.GetHostString());
	      noerrors=0;
	    }
	  }
	}
      }
    }
  }
  return 1;
}

void
Nrlolsr::printCurrentTable(int debuglvl){
  if(olsrDebugValue>=debuglvl){
    int number_of_nbrs=0;
    int number_of_2hop_nbrs=0;
    NbrTuple *nb,*nb2;
    DMSG(debuglvl," === %s nbr table at time %f === \n",myaddress.GetHostString(),InlineGetCurrentTime());
    for(nb=nbr_list.PrintPeekInit();nb!=NULL;nb=nbr_list.PrintPeekNext()){
      if(nb!=NULL){
				number_of_nbrs++;
				DMSG(debuglvl,":%dd %dh %dt %.2fk %s c(c",nb->N_spf,nb->hop,nb->N_status,nb->konectivity,nb->N_addr.GetHostString());
				for(nb2=(nb->children).PrintPeekInit();nb2!=NULL;nb2=(nb->children).PrintPeekNext()){
					if(nb2!=NULL){
						DMSG(debuglvl,"%s ",nb2->N_addr.GetHostString());
					}
				}
				DMSG(debuglvl,")(p");
				for(nb2=(nb->parents).PrintPeekInit();nb2!=NULL;nb2=(nb->parents).PrintPeekNext()){
					if(nb2!=NULL){
						DMSG(debuglvl,"%s ",nb2->N_addr.GetHostString());
					}
				}
				DMSG(debuglvl,")(d");
				for(nb2=(nb->stepparents).PrintPeekInit();nb2!=NULL;nb2=(nb->stepparents).PrintPeekNext()){
					if(nb2!=NULL){
						DMSG(debuglvl,"%s ",nb2->N_addr.GetHostString());
					}
				}
				DMSG(debuglvl,")");
			}
		}
		DMSG(debuglvl,"\n");
    for(nb=nbr_2hop_list.PrintPeekInit();nb!=NULL;nb=nbr_2hop_list.PrintPeekNext()){
      if(nb!=NULL){
	if(nb->hop==2){
	  number_of_2hop_nbrs++;
	  DMSG(debuglvl," %s(c",nb->N_addr.GetHostString());
	  for(nb2=(nb->children).PrintPeekInit();nb2!=NULL;nb2=(nb->children).PrintPeekNext()){
	    if(nb2!=NULL){
	      DMSG(debuglvl,"error%s ",nb2->N_addr.GetHostString());
	    }
	  }
	  DMSG(debuglvl,")(p");
	  for(nb2=(nb->parents).PrintPeekInit();nb2!=NULL;nb2=(nb->parents).PrintPeekNext()){
	    if(nb2!=NULL){
	      DMSG(debuglvl,"%s ",nb2->N_addr.GetHostString());
	    }
	  }
	  DMSG(debuglvl,")(s");
	  for(nb2=(nb->stepparents).PrintPeekInit();nb2!=NULL;nb2=(nb->stepparents).PrintPeekNext()){
	    if(nb2!=NULL){
	      DMSG(debuglvl,"%s ",nb2->N_addr.GetHostString());
	    }
	  }
	  DMSG(debuglvl,")");
	}
      }
    }
    DMSG(debuglvl,"\n ==== end %s nbr table === #nbrs = %d #2hopnbrs = %d ====\n",myaddress.GetHostString(),number_of_nbrs,number_of_2hop_nbrs);
  }
}

// a bit convoluted because of the historisis  there are 2 checks in some areas to see
// which type of timeout is occuring historisis or complete timeout and removal
// if a historisis disconnect occurs it deleats 2 hop neighbors and makes it a lost neighbor
// the node will switch the lost_link to pending_link after sending out lost link message.
// checks each one hop neighbor and then checks all of there childrens timeout values
// if a one hop neighbor is removed all of its 2 hop links are also removed and it may be 
// deleated or moved to the 2 hop list if a valid link is still up
void
Nrlolsr::nb_purge() {
  //DMSG(6,"Enter: Nrlolsr::nb_purge()\n");
  NbrTuple *nb,*nbold=NULL, *children, *parents, *nb_top;
  int nbfree=0;
  int mprupdate=0;
  //int redoRoutes=0;// used when manually taking out topology tuples due to historisis 
  DMSG(6,"Enter: nb_purge() for %s \n",myaddress.GetHostString());
  
  //printCurrentTable(3);
  for(nb=nbr_list.PeekInit();nb!=NULL;nb=nbr_list.PeekNext()){
    if(nb!=NULL){ // is a valid pointer
      DMSG(8,"%f is hystersis value of %s. upvalue=%f downvalue=%f at time %f time\n",nb->konectivity,nb->N_addr.GetHostString(),T_up,T_down,nb->N_time);
      if(nb->N_macstatus!=LINK_UP && nb->konectivity<T_down && (nb->N_status==SYM_LINKv4 || nb->N_status==MPR_LINKv4 || nb->N_status==ASYM_LINKv4)){ // check to see if historisis link failure occured
	DMSG(4,"local link %s to ",myaddress.GetHostString());
	DMSG(4,"%s is broken\n",nb->N_addr.GetHostString());
	nb->N_status=LOST_LINKv4;
	// must manually take out the topology tuple as they only time out based on timeout values
	nb_top=topologySet.FindObject(nb->N_addr,myaddress); // remove the forward link if in the topology table
	if(nb_top){
	  //DMSG(1,"removing from %d topology tuple %d list at time %f due to historisis 1\n",myaddress.IPv4HostAddr(),nb_top->N_addr,CURRENT_TIME);
	  //DMSG(7,"Removing from %s topology tuple ",myaddress.GetHostString()); 
	  //DMSG(7,"%s list at time %f due to historisis 1\n",nb_top->N_addr.GetHostString(),InlineGetCurrentTime());
	  topologySet.RemoveCurrent();
	  delete nb_top;
	  //free(nb_top);
	  //redoRoutes=1;
	}
	nb_top=topologySet.FindObject(myaddress,nb->N_addr); // remove the reverse link if there
	if(nb_top){
	  //DMSG(7,"Removing from %s topology tuple ",myaddress.GetHostString());
	  //DMSG(7,"%s list at time %f due to historisis 2\n",nb_top->N_addr.GetHostString(),InlineGetCurrentTime());
	  ////DMSG(1,"removing from %d topology tuple %d list at time %f due to historisis 2\n",myaddress.IPv4HostAddr(),nb_top->N_addr,InlineGetCurrentTime());
	  topologySet.RemoveCurrent();
	  delete nb_top;
	  //free(nb_top);
	  //redoRoutes=1;
	}
      }
      if(nb->N_macstatus!=LINK_UP && (nb->N_time<InlineGetCurrentTime() || nb->N_status==LOST_LINKv4)){ //check to see if link expired b/c normal timeout
	mprupdate=1;
	fflush(stdout);
	if(nb->N_time<InlineGetCurrentTime()){ //get rid of one hop neighbor as well
	  DMSG(7,"Removing nb %s ",nb->N_addr.GetHostString());
	  DMSG(7,"from %s's list at time %f cause %f timeout\n",myaddress.GetHostString(),InlineGetCurrentTime(),nb->N_time);
	  nbr_list.RemoveCurrent();
	}
	//removing children from parent/stepparent node that is being deleated
	for(children=(nb->children).PeekInit();children!=NULL;children=(nb->children).PeekNext()){
	  if(children!=NULL){
	    //abandon children
	    if((children->parents).FindObject(nb->N_addr)){
	      (children->parents).RemoveCurrent();
	    } else if((children->stepparents).FindObject(nb->N_addr)){
	      (children->stepparents).RemoveCurrent();
	    } else {
	      DMSG(0,"child without parent or stepparent pointer in nb_purge | ");
	    }
	    if((children->parents).IsEmpty()){
	      //child lost last parent, child runs free	      
	      ////DMSG(1,"removing 2 hop %d cause %d deleated from %d's 1 hop list (purge)\n",children->N_addr,nb->N_addr,myaddress.IPv4HostAddr());
	      // DMSG(7,"Removing 2 hop %s ",children->N_addr.GetHostString());
	      //DMSG(7,"cause %s deleated from ",nb->N_addr.GetHostString());
	      //DMSG(7,"%s's 1 hop list (purge)\n",myaddress.GetHostString());
	      if(nbr_2hop_list.FindObject(children->N_addr))
		nbr_2hop_list.RemoveCurrent();
	      if(!nbr_list.FindObject(children->N_addr)){ //check to see if it was exclusivly a 2 hop neighbor
		////DMSG(1,"testline 0 \n");
		//DMSG(12,"testline 0 \n");
		//get rid of step children
		for(parents=(children->children).PeekInit();parents!=NULL;parents=(children->children).PeekNext()){
		  if(parents!=NULL){
		    if((parents->stepparents).FindObject(children->N_addr)){
		      (parents->stepparents).RemoveCurrent();
		    } else if((parents->parents).FindObject(children->N_addr)){
		      DMSG(0,"parent pointer instead of stepparent pointer in nb_purge function | ");
		    } else {
		      DMSG(0,"missing stepparent pointer in nb_purge function | ");
		    }
		  }
		}
		(children->children).Clear();
		//get rid of step parents
		for(parents=(children->stepparents).PeekInit();parents!=NULL;parents=(children->stepparents).PeekNext()){
		  if(parents!=NULL){
		    //  //DMSG(8,"testline 3 \n");
		    //if(parents->N_addr!=nb->N_addr){
		    if(!(parents->N_addr.HostIsEqual((nb->N_addr)))){
		      //if(parents->children!=nb->children){
		      if((parents->children).FindObject(children->N_addr)){
			(parents->children).RemoveCurrent();
		      } else {
			DMSG(0,"missing child link in nb_purge function | ");
		      }
		      // }
		    }
		  }
		}
		(children->stepparents).Clear();
		delete children;
		//free(children);
	      } 	
	    }
  	  }
	}
	(nb->children).Clear();		
	if((nb->parents).IsEmpty()){ // checking to see if node has parents
	  if(nb->N_status!=LOST_LINKv4){ // if is not a lost link hold it for a bit then will remove later
	    nbold=nb;
	    nbfree=1;
	  }
	}
	else{
	  nb->hop=2; // is now a two hop neighbor 
	}
	NbrTuple *mprtuple;
	if((mprtuple = mprSelectorList.FindObject(nb->N_addr))){
	  mprSelectorList.RemoveCurrent();
	  delete mprtuple;

	  updateSmfForwardingInfo = true;  //send updated mpr selector list to send pipe if open
	  //free(mprtuple);
	  
	  // LP 9-16-05 - added for Opnet statistic
#ifdef OPNET
		if (mprSelectorList.IsEmpty()){
			MPR_decreased_flag = OPNET_TRUE;
			//printf("\t\t DECREASED MPR\n");
			}
#endif
	// end LP

	}
      }
      else { // is a valid one hop neighbor check its children
	//check to see if children are missing
  	for(children=(nb->children).PeekInit();children!=NULL;children=(nb->children).PeekNext()){
  	  if(children!=NULL){
  	    if((nb->children).checkCurrent()){ // check to see if link expired child lost
  	      mprupdate=1;
	      //printCurrentTable(3);
	      ////DMSG(1,"%d's perspective deleating link %d from %d's table \n",myaddress.IPv4HostAddr(),children->N_addr,nb->N_addr);
	      //DMSG(7,"Removing: %s's perspective deleating link ",myaddress.GetHostString());
	      //DMSG(7,"%s ",children->N_addr.GetHostString());
	      //DMSG(7,"from %s's table \n",nb->N_addr.GetHostString());
	      (nb->children).RemoveCurrent();
	      if((children->parents).FindObject(nb->N_addr)) // child is lost
  		(children->parents).RemoveCurrent();
	      if((children->stepparents).FindObject(nb->N_addr)) 
		(children->stepparents).RemoveCurrent(); // (ah ha found you vindication!)
	      ////DMSG(1,"is empty? %d hop value %d",children->parents.IsEmpty(),children->hop);
	      //DMSG(9,"is empty? %d hop value %d",children->parents.IsEmpty(),children->hop);
	      if((children->parents).IsEmpty()){
  		//child is lost only parent
  		if(nbr_2hop_list.FindObject(children->N_addr)){ // may have not been added to two hop table????
		  nbr_2hop_list.RemoveCurrent();
		} else { 
		  //DMSG(8,"Warning: while removing two hop link %s which was not in 2 hop neighbor table\n",children->N_addr.GetHostString());
		}
		// remove all stepparent links 
		if(!nbr_list.FindObject(children->N_addr)){ //check to see if it was exclusivly a 2 hop neighbor
		  for(parents=((children->stepparents).PeekInit());parents!=NULL;parents=(children->stepparents).PeekNext()){
		    if(parents!=NULL){
		      if(!(parents->N_addr.HostIsEqual((nb->N_addr)))){ //don't remove current parent will be done later
			//if(parents->N_addr!=nb->N_addr){ //don't remove current parent will be done later
			if((parents->children).FindObject(children->N_addr))
			  (parents->children).RemoveCurrent();
		      }
		    }
		  }
		  (children->stepparents).Clear();		  
		  delete children;
		  //free(children);
		}
  	      }
  	    }
  	  }
  	}
      }
    }
    if(nbfree){
      //remove last of pointers to this object
      for(parents=(nbold->stepparents).PeekInit();parents!=NULL;parents=(nbold->stepparents).PeekNext()){
	if(parents!=NULL){
	  if((parents->children).FindObject(nbold->N_addr))
	    (parents->children).RemoveCurrent();
	}
      }
      (nbold->stepparents).Clear();
      delete nbold;
      //free(nbold);
      nbfree=0;
    }
  }
  if(nbfree){
    //remove last of pointers to this object
    for(parents=(nbold->stepparents).PeekInit();parents!=NULL;parents=(nbold->stepparents).PeekNext()){
      if(parents!=NULL){
	if((parents->children).FindObject(nbold->N_addr))
	  (parents->children).RemoveCurrent();
      }
    }
    (nbold->stepparents).Clear();
    delete nbold;
    //free(nbold);
  }

  // this is only done on the send hello function
  //  if(mprupdate)
  //  selectmpr();
  //printCurrentTable(3);
  //DMSG(6,"Exit: Nrlolsr::nb_purge()\n");
} //end nb_purge

void 
Nrlolsr::for_purge() {
  //DMSG(6,"Enter: Nrlolsr::for_purge()\n");
  NbrTuple *tuple;
  bool removedfor=true;
  for(tuple=forwardTable.PeekInit();tuple!=NULL && removedfor;tuple=forwardTable.PeekNext()) {
    if((tuple->N_time<InlineGetCurrentTime())){
       forwardTable.RemoveCurrent();
       delete tuple;
       //free(tuple);
    }
    else{
      removedfor=false;
    }
  }
  //DMSG(6,"Exit: Nrlolsr::for_purge()\n");
} // end for_purge

void 
Nrlolsr::dup_purge() {
  //DMSG(6,"Enter: Nrlolsr::dup_purge()\n");
  NbrTuple *tuple;
  bool removeddup=true;
  for(tuple=duplicateTable.PeekInit();tuple!=NULL && removeddup;tuple=duplicateTable.PeekNext()) {
    if((tuple->N_time<InlineGetCurrentTime())){
      //DMSG(7,"Removing duplicate tuple %s from ",tuple->N_addr.GetHostString());
      //DMSG(7,"%s's list at time %f \n",myaddress.IPv4HostAddr(),InlineGetCurrentTime());
      duplicateTable.RemoveCurrent();
      delete tuple;
      //free(tuple);
    }
    else{
      removeddup=false;
    }
  }
  //DMSG(6,"Exit: Nrlolsr::dup_purge()\n");
} // end dup_purge

void
Nrlolsr::hna_purge() {
  //DMSG(6,"Enter: Nrlolsr::hna_purge()\n");
  NbrTuple *tuple;
  bool removedhna = true;
  for(tuple=hnaSet.PeekInit();tuple!=NULL && removedhna;tuple=hnaSet.PeekNext()) {
    if((tuple->N_time<InlineGetCurrentTime())){
      hnaSet.RemoveCurrent();
      delete tuple;
      //free(tuple);
    } else {
      removedhna = false;
    }
  }
  //DMSG(6,"Exit: Nrlolsr::hna_purge()\n");
} // end hna_purge

// removes expired topology tuples if their timeout value is past the current time      
void
Nrlolsr::top_purge() {
  //DMSG(6,"Enter: Nrlolsr::top_purge()\n");
  // list is sorted by address not timeout value so have to check them all.
  NbrTuple *tuple;
  int one=1;
  int printtop=0;
  for(tuple=topologySet.PeekInit();tuple!=NULL;tuple=topologySet.PeekNext()) {
    if(tuple!=NULL){
      if((tuple->N_time2<InlineGetCurrentTime())){
	if(printtop){
	  one=0;
	  printtop=0;
	  //printTopology(3);
	}
	//DMSG(2,"removing from %s topology tuple ",myaddress.GetHostString());
	//DMSG(2,"%s at time %f %f was experation time\n",tuple->N_addr.GetHostString(),InlineGetCurrentTime(),tuple->N_time2);
	topologySet.RemoveCurrent();
	delete tuple;
	//free(tuple);
      } else {
	//DMSG(2,"not removing \n");
      }
    }
  }
  //DMSG(6,"Exit: Nrlolsr::top_purge()\n);
} // end top_purge

//mantissa time functions
UINT8 
Nrlolsr::doubletomantissa(double timeinseconds){
  //DMSG(6,"Enter: Nrlolsr::doubletomantissa(timeinseconds %d)\n",tieminseconds);
  int a, b;
  UINT8 mantissatime=0;
  for(b = 0;(double)timeinseconds/TIME_CONSTANT >= (double)pow(2,b);b++);//  fprintf(stdout,"%f first %f second\n",(double)timeinseconds/TIME_CONSTANT,(double)pow(2,b));
  b--;
  if(b<0){ //number was too small make smallest number possible
    a = 1;
    b = 0;
  } else if (b>15){ //number was too large make largest number possible
    a = 15;
    b = 15;
  } else { //everything is fine 
    a = (int)(16*((double)timeinseconds/(TIME_CONSTANT*(double)pow(2,b))-1));
    while(a>=16){
      a-=16;
      b++;
    }
  }
  mantissatime = a*16+b;
  //DMSG(6,"Exit: Nrlolsr::doubletomantissa(timeinseconds %d)\n",tieminseconds);
  return mantissatime;
}
  
double
Nrlolsr::mantissatodouble(UINT8 mantissatime){
  //DMSG(6,"Enter: Nrlolsr::mantissatodouble(mantissatime %d)\n",mantissatime);
  int a = mantissatime>>4;
  int b = mantissatime - a*16;
  double returntime = (double)(TIME_CONSTANT*(1+(double)a/16)*(double)pow(2,b));
  //DMSG(6,"Exit: Nrlolsr::mantissatodouble(mantissatime %d)\n",mantissatime);
  return returntime;
}


bool
Nrlolsr::NeighborsStableForTC(){
  DMSG(6,"Enter: Nrlolsr::NeighborsStableForTC()\n");
  //check old neighbor table against current table
  bool returnvalue=true;
  NbrTuple *nb=NULL;
  NbrTuple *nbold=nbr_list_old_for_tc.PeekInit();
  if (!nbold){
    returnvalue=false;
  }
  DMSG(6,"%p\n",nbold);
  for(nb=nbr_list.PrintPeekInit();(nb!=NULL) && returnvalue;nb=nbr_list.PrintPeekNext()){
    if(nbold && nb){//entries still exist in both tables
      DMSG(8,"%s,%d?=",nb->N_addr.GetHostString(),nb->N_status);
      DMSG(8,"%s,%d\n",nbold->N_addr.GetHostString(),nbold->N_status);
      if(!nbold->N_addr.HostIsEqual(nb->N_addr) || nbold->N_status!=nb->N_status){//entries are not the same
	returnvalue = false;
      } else {
	nbr_list_old_for_tc.RemoveCurrent();
	delete nbold;
	nbold=nbr_list_old_for_tc.PeekInit();
      }
    } else if ( nbold || nb) { //one table still has an entry and the other does not so they are not the same
      returnvalue=false; 
    }
  }
  //make sure the old list is completly cleaned up
  nbold=nbr_list_old_for_tc.PeekInit();
  while(nbold){
    nbr_list_old_for_tc.RemoveCurrent();
    delete nbold;
    nbold=nbr_list_old_for_tc.PeekInit();
  }
  //copy current table into old neighbor table
  for(nb=nbr_list.PrintPeekInit();(nb!=NULL);nb=nbr_list.PrintPeekNext()){
    if(nb){
      nbold=new NbrTuple;
      nbold->N_addr=nb->N_addr;
      nbold->N_status=nb->N_status;
      nbr_list_old_for_tc.QueueObjectAddressSort(nbold);
    }
  }
  return returnvalue;
}

bool
Nrlolsr::NeighborsStableForHello(){
  DMSG(6,"Enter: Nrlolsr::NeighborsStableForHello()\n");
  //check old neighbor table against current table
  bool returnvalue=true;
  NbrTuple *nb=NULL;
  NbrTuple *nbold=nbr_list_old_for_hello.PeekInit();
  if (!nbold){
    returnvalue=false;
  }
  //DMSG(6,"%p\n",nbold);
  for(nb=nbr_list.PrintPeekInit();(nb!=NULL) && returnvalue;nb=nbr_list.PrintPeekNext()){
    if(nbold && nb){//entries still exist in both tables
      DMSG(8,"%s,%d?=",nb->N_addr.GetHostString(),nb->N_status);
      DMSG(8,"%s,%d\n",nbold->N_addr.GetHostString(),nbold->N_status);
      if(!nbold->N_addr.HostIsEqual(nb->N_addr) || nbold->N_status!=nb->N_status){//entries are not the same
	returnvalue = false;
      } else {
	nbr_list_old_for_hello.RemoveCurrent();
	delete nbold;
	nbold=nbr_list_old_for_hello.PeekInit();
      }
    } else if ( nbold || nb) { //one table still has an entry and the other does not so they are not the same
      returnvalue=false; 
    }
  }
  //make sure the old list is completly cleaned up
  nbold=nbr_list_old_for_hello.PeekInit();
  while(nbold){
    nbr_list_old_for_hello.RemoveCurrent();
    delete nbold;
    nbold=nbr_list_old_for_hello.PeekInit();
  }
  //copy current table into old neighbor table
  for(nb=nbr_list.PrintPeekInit();(nb!=NULL);nb=nbr_list.PrintPeekNext()){
    if(nb){
      nbold=new NbrTuple;
      nbold->N_addr=nb->N_addr;
      nbold->N_status=nb->N_status;
      nbr_list_old_for_hello.QueueObjectAddressSort(nbold);
    }
  }
  return returnvalue;
}

bool 
Nrlolsr::TupleLinkIsUp(NbrTuple* tuple){ //returns true if tuple state indicates its a true one hop neighbor which can forward
  return ((tuple->N_status==MPR_LINKv4 || tuple->N_status==SYM_LINKv4) && tuple->N_willingness!=WILL_NEVER && tuple->N_macstatus!=LINK_DOWN && tuple->hop==1);
}
bool
Nrlolsr::Restart()
{
  if(!isSleeping){
    DMSG(0,"Nrloslr::Restart() Warning. Restart was called while nrlolsr was not sleeping!");
    return false;
  }
  isSleeping = false;
  isRunning = true;
  //DMSG(6,"Enter: Nrlolsr::Restart()\n");
  //install udp sockets
  if (!socket.Open(olsr_port_number,ipvMode,false)){
    DMSG(0, "Nrlolsr::Restart() Error opening udp socket! \n");
    //DMSG(6,"Exit: Nrlolsr::Start()\n");
    return false;
  }
  if(!mac_control_socket.Open(mac_control_port,ipvMode,false)) {
    DMSG(0,"Nrlolsr::Restart() Error opening mac control upd socket on port %d\n",mac_control_port);
    return false;
  }
  if(qosvalue!=0){
    if(ipvMode==ProtoAddress::IPv4){
      if (!socket.SetTOS(qosvalue)){
	DMSG(0,"nrlolsr: Error setting tos of socket\n");
        //DMSG(6,"Exit: Nrlolsr::Start()\n");
	return false;
      }
    }
#ifdef IPV6
    else {
      if(!socket.SetFlowLabel(qosvalue<<20)){ //shifting bits because IPv6 has different packet format for qos than IPv4
	DMSG(0,"nrlolsr: Error setting flow of socket\n");
        //DMSG(6,"Exit: Nrlolsr::Start\n");
	return false;
      } 
    }
#endif
  }
  if(!socket.Bind(olsr_port_number)){
    DMSG(0,"nrlolsr: Error binding port number olsr_port_number to udp socket \n");    
    //DMSG(6,"Exit: Nrlolsr::Start()\n");
    return false;
  }
  
  //project specific mac layer control functions not needed for core functionality
  if(!mac_control_socket.Bind(mac_control_port)){
    DMSG(0,"Nrlolsr::Start(): Error binding port number %d to mac control udp socket\n",mac_control_port);
    return false;
  }
  if(netBroadAddr.IsMulticast()){ //do multicast stuff
    DMSG(8,"%s is netBroadAddr\n",netBroadAddr.GetHostString());
    if(!socket.JoinGroup(netBroadAddr,interfaceName)){
      DMSG(0,"Nrlolsr: Error joining group %s\n",netBroadAddr.GetHostString());
      //DMSG(6,"Exit: Nrlolsr::Start()\n");
      return false;
    }
    if(!socket.SetMulticastInterface(interfaceName)){
      DMSG(0,"Nrlolsr::Start Error calling SetMulticastInterface with interfaceName=%s\n",interfaceName);
      //DMSG(6,"Exit: Nrlolsr::Start()\n");
      return false;
    }
  } else { //address should be broadcast and will add route later
    if (!socket.SetBroadcast(true)){
      DMSG(0, "Nrlolsr: Error setting broadcast udp socket! \n");
      //DMSG(6,"Exit: Nrlolsr::Start()\n");
      return false;
    }
  }
  //reinstall timers
  if(timerMgrPtr){
    if(!hello_timer.IsActive()) timerMgrPtr->ActivateTimer(hello_timer);
    if(!hello_jitter_timer.IsActive()) timerMgrPtr->ActivateTimer(hello_jitter_timer);
    if(!tc_timer.IsActive()) timerMgrPtr->ActivateTimer(tc_timer);
    if(!tc_jitter_timer.IsActive()) timerMgrPtr->ActivateTimer(tc_jitter_timer);
    if(!hna_timer.IsActive()) timerMgrPtr->ActivateTimer(hna_timer);
    if(!hna_jitter_timer.IsActive()) timerMgrPtr->ActivateTimer(hna_jitter_timer);
    if(!static_run_timer.IsActive()){
      if(static_run_timer.GetInterval()!=0){
        timerMgrPtr->ActivateTimer(static_run_timer);
      }
    }
  } else {
    DMSG(0,"Nrlolsr::restart() Error timerMgrPtr is NULL!\n");
    return false;
  }
  //send forwarding info it applicable
  if(updateSmfForwardingInfo){
    SendForwardingInfo();
  }
  //DMSG(6,"Exit: Nrlolsr::restart()\n");
  return true;
} // end Nrlolsr::restart(argc %s, argv %d)

void
Nrlolsr::Sleep()//turns off timers and sets the isRunning variable to false;
{
  isSleeping = true;
  isRunning = false;
  //DMSG(6,"Enter: Nrlolsr::Sleep()\n");
  if(hello_timer.IsActive())  hello_timer.Deactivate();
  if(hello_jitter_timer.IsActive()) hello_jitter_timer.Deactivate();
  if(tc_timer.IsActive()) tc_timer.Deactivate();
  if(tc_jitter_timer.IsActive()) tc_jitter_timer.Deactivate();
  if(hna_timer.IsActive()) hna_timer.Deactivate();
  if(hna_jitter_timer.IsActive()) hna_jitter_timer.Deactivate();
  if(delayed_forward_timer.IsActive()) delayed_forward_timer.Deactivate();
  if(netBroadAddr.IsMulticast()){
    if(!socket.LeaveGroup(netBroadAddr,interfaceName)){
      DMSG(0,"Nrlolsr::Stop() Error leaving multicast group %s\n",netBroadAddr.GetHostString());
    }
  }
  if(socket.IsOpen()) socket.Close();
  if(mac_control_socket.IsOpen()) mac_control_socket.Close();
}
void 
Nrlolsr::Stop() 
{
  isRunning = false;
  //DMSG(6,"Enter: Nrlolsr::Stop()\n");
  if(hello_timer.IsActive())  hello_timer.Deactivate();
  if(hello_jitter_timer.IsActive()) hello_jitter_timer.Deactivate();
  if(tc_timer.IsActive()) tc_timer.Deactivate();
  if(tc_jitter_timer.IsActive()) tc_jitter_timer.Deactivate();
  if(hna_timer.IsActive()) hna_timer.Deactivate();
  if(hna_jitter_timer.IsActive()) hna_jitter_timer.Deactivate();
  if(delayed_forward_timer.IsActive()) delayed_forward_timer.Deactivate();
  if(netBroadAddr.IsMulticast()){
    if(!socket.LeaveGroup(netBroadAddr,interfaceName)){
      DMSG(0,"Nrlolsr::Stop() Error leaving multicast group %s\n",netBroadAddr.GetHostString());
    }
  }
  if(socket.IsOpen()) socket.Close();
  if(mac_control_socket.IsOpen()) mac_control_socket.Close();
#ifndef SIMULATE //pipes are not used in simulation and not supported by protolib simulation code
  if(gui_pipe.IsOpen()) gui_pipe.Close();
  if(smf_pipe.IsOpen()) smf_pipe.Close();
  if(recvPipe.IsOpen()) recvPipe.Close();
#endif // !SIMULATE
  // restore old routing table
  NbrTuple *tuple=routeTable.PeekInit();
  while(tuple){ //loop to clean extraQueue and remove old routes
    routeTable.RemoveCurrent();
    if(tuple->N_addr.HostIsEqual((tuple->N_2hop_addr))){
      //DMSG(7,"Removing direct route to %s\n",tuple->N_addr.GetHostString());
      if(!realRouteTable->DeleteRoute(tuple->N_addr,hostMaskLength,invalidAddress,interfaceIndex)){//,invalidAddress)){
	DMSG(0,"Nrlolsr::Stop() Error removing direct route to %s\n",tuple->N_addr.GetHostString());
      }
    } else {
      //DMSG(7,"Removing route to %s via ",tuple->N_addr.GetHostString());
      //DMSG(7,"%s\n",tuple->N_2hop_addr.GetHostString());
      if(!realRouteTable->DeleteRoute(tuple->N_addr,hostMaskLength,tuple->N_2hop_addr,interfaceIndex)){//,tuple->N_2hop_addr)){
	DMSG(0,"Nrlolsr::Stop() Error removing host route %s via ",tuple->N_addr.GetHostString());
	DMSG(0,"%s\n",tuple->N_2hop_addr.GetHostString());
      }
    }
    delete tuple;
    //free(tuple); 
    tuple=routeTable.PeekInit();
  }
  /* broadcast address no longer added or removed
  if(!netBroadAddr.IsMulticast()){
    //ProtoAddress gwAddr;
    //gwAddr.Init();
    if(!realRouteTable->DeleteRoute(netBroadAddr,broadMaskLength,invalidAddress,interfaceIndex)){//,gwAddr)){ 
      DMSG(0,"Nrlolsr::Stop() error deleting %s from routing table",netBroadAddr.GetHostString());
    }
  }
  */
  //  realRouteTable->SetRoutes(initialRouteTable);
  realRouteTable->Close();
  CloseDebugLog();
  //DMSG(6,"Enter: Nrlolsr::Stop()\n");
} // end Nrlolsr::Stop()



