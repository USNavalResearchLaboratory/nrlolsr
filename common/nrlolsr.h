// nrlolsr.cpp - application to run nrlolsr 


#include "protokit.h"
#include "protoCap.h"  // for raw packet reception to get MAC addrs
#include "olsr_packet_types.h"
#include "nbr_queue.h"

#include <ctype.h>
#include <math.h>

#define NETWORK_DIAMETER 32
#define MAXMSSN 65535
#define OLSRMAXSPF 255.0 //8 bits
#define OLSRMAXMINMAX 255.0 //8 bits
#define LOADMAXROUTES 3 //max number of routes to a single destination only used in loadBalancing

// LP 8-31-05 - added
#ifdef OPNET
#include "smf_ipc.h"  //  JPH SMF
#define OPNET_TRUE 1
#define OPNET_FALSE 0
#endif

// end LP

inline double UniformRand(double max){
  return (max * ((double)rand() / (double)RAND_MAX));
}

inline int GetLittleTime()
{
  struct timeval tv;
  ProtoSystemTime(tv);
  double current_time = ((double)tv.tv_usec)/1.0e06; 
  int hacknumber=(int)current_time;
  current_time-=(double)hacknumber;
  current_time=1.0e06*current_time;
  return (int)current_time;
}

class Nrlolsr 
{
 public:
#ifdef SIMULATE  //messy but simulation does not have a real dispatcher because things are taken care of by simulation model
  Nrlolsr(ProtoSocket::Notifier& theNotifier, ProtoTimerMgr& theTimer); //SetOlsrRouteMgr must be called before Start!
#else
  Nrlolsr(ProtoDispatcher& theDispatcher, ProtoSocket::Notifier& theNotifier, ProtoTimerMgr& theTimer); //SetOlsrRouteMgr must be called before Start!
#endif //if/else SIMULATE
  bool Start();
  bool Restart();
  bool StringProcessCommands(const char* theString);
  bool ConfigProcessCommands(const char* theFileName);
  bool ProcessCommands(int argc, const char*const* argv);
  bool ParseMacControlMessage(MacControlMsg& msg); //parses mac control messages and sends corrosponding messages to processCommands
  void Stop();
  void Sleep();

  bool SetOlsrBroadcastAddress(const char* addrname,const char* netmask);
  bool SetOlsrInterfaceAddress(const char* addrname);
  bool SetOlsrPort(int theport);
  bool SetOlsrIPv4(bool ipv4mode);
  bool SetOlsrMacControlPort(int portnumber);
  bool SetOlsrDebugLevel(int debuglvl);
  bool SetOlsrDebugLog(const char* logfilename);
  bool SetOlsrHelloInterval(double interval);
  bool SetOlsrHelloJitter(double jitter);
  bool SetOlsrHelloTimeout(double timeout);
  bool SetOlsrHelloPadding(unsigned int padding);
  bool SetOlsrTCInterval(double interval);
  bool SetOlsrTCJitter(double jitter);
  bool SetOlsrTCTimeout(double timeout);
  bool SetOlsrHNAInterval(double interval);
  bool SetOlsrHNAJitter(double jitter);
  bool SetOlsrHNATimeout(double timeout);
  bool SetOlsrDelaySmfOff(double delay);
  bool SetOlsrForwardingDelay(double delay);
  bool SetOlsrAllLinks(bool on);
  bool SetOlsrHelloUseUnicast(int mode);//0=off 1=opt 2=on
  bool SetOlsrStatic(double runtime);//-1=inf 0=stop n=run for n seconds then stop timers and close sockets
  bool SetOlsrFastReRoute(bool on);
  bool SetOlsrTCSlowDown(bool on);
  bool SetOlsrWillingness(int willingness);
  bool SetOlsrRecordHelloHistory(bool on);
  bool SetOlsrHysUp(double up);
  bool SetOlsrHysDown(double down);
  bool SetOlsrHysAlpha(double a);
  bool SetOlsrHysOff(bool off);
  bool SetOlsrHNAOff(bool off);
  bool SetOlsrHNAFile(const char* filename);
  bool SetOlsrQos(const char* qosvalue);
  bool SetOlsrFuzzyFlooding(bool fuzzyfloodingon); 
  bool SetOlsrRouteTable(ProtoRouteMgr *theRouteMgr);

  ProtoSocket& GetSocket() {return socket;}
  ProtoAddress& GetMyAddress() {return myaddress;}
  NBRQueue& GetMprSelectorList() {return mprSelectorList;}
  NBRQueue& GetNbrList() {return nbr_list;}

 // LP 8-29-05 - added for displaying statistic in OPNET
#ifdef OPNET
 int total_Hello_Sent_get() { return total_Hello_sent;}
 int total_Hello_Rcv_get(){ return total_Hello_rcv;}
 int total_TC_Sent_get(){ return total_TC_sent;}
 int total_TC_Rcv_get(){ return total_TC_rcv;}
 Boolean MPR_increase_status_get(){ return MPR_increased_flag;}
 Boolean MPR_decrease_status_get(){ return MPR_decreased_flag;}
 Boolean Hello_sent_stat_status_get(){ return Hello_sent_changed_flag;}
 Boolean TC_sent_stat_status_get(){  return TC_sent_changed_flag;}
 Boolean Hello_rcv_stat_status_get(){ return Hello_rcv_changed_flag;}
 Boolean TC_rcv_stat_status_get(){ return TC_rcv_changed_flag;}
 void			reset_MPR_increased_flag () {MPR_increased_flag = OPNET_FALSE; }
 void			reset_MPR_decreased_flag () {MPR_decreased_flag = OPNET_FALSE;}
 void			reset_Hello_sent_changed_flag () {Hello_sent_changed_flag = OPNET_FALSE; }
 void			reset_TC_sent_changed_flag () {TC_sent_changed_flag = OPNET_FALSE; }
 void			reset_Hello_rcv_changed_flag () {Hello_rcv_changed_flag = OPNET_FALSE; }
 void			reset_TC_rcv_changed_flag () {TC_rcv_changed_flag = OPNET_FALSE; }
 int getNumRoutes(){return numberofroutes;} /* JPH animation 10-26-06 */
 void linkDown(ProtoAddress addr); /* JPH animation 11-01-06 */
#endif

 // end LP

  enum FloodingType {SIMPLE, SMPR, NSMPR, NOTSYM, ECDS, MPRCDS};
  bool FloodingIsOn() {return floodingOn;}
  FloodingType GetFloodingType() {return floodingType;}
  bool IsForwarder() {return localNodeIsForwarder;}

#ifdef OPNET  // JPH SMF
  void SetSmfProcessId(Objid smfProcessId) /* JPH SMF */
      {smf_objid = smfProcessId;}
  void OnPktCapture(smfT_olsr_ipc* ipc);  
#endif

  ProtoRouteTable localHnaRouteTable; //this is currently only used in ns2 for checking for "anycast" type routes

protected:
  //important needed referances
  ProtoTimerMgr *timerMgrPtr;
#ifndef SIMULATE //dispatcher is not included/used in simulation model
  ProtoDispatcher *dispatcher;
#endif //!simulate
  ProtoRouteMgr *realRouteTable;
  ProtoRouteTable initialRouteTable;

  ProtoAddress invalidAddress;
  // options
  int            olsrDebugValue;
  int            noerrors;
  bool           allLinks;
  bool           fastreroute;
  bool           helloUseUnicast; //set to false by default.  Will send unicast hellos to all known one hop neighbors once each timeout interval.
  bool           helloUseUnicastOpt; //set to false by default.  When helloUseUnicast is true will only send to nbrs with less than .99 konectivity values.
  int            helloSentBcastOnly; //keeps track of how many bcasts have been sent in a row.  when this is greater than Hello_Interval_Factor it will send unicast hellos out

  bool isRunning; //set to false in constructor, true in Start, true in Restart, false in Stop, false in Sleep
  bool isSleeping; //set to false in constructor, false in Restart, true in Sleep

  bool           tcSlowDown;
  bool           tcSlowDownNeighborsStable; //bool value which is true if neighbors are stable between tcs
  int            tcSlowDownFactor; //how much slower tcs are being sent out
  int            tcSlowDownState;  //set to one of 4 intermediate states untill slowdown factor is doubled.

  void           SetLocalNodeIsForwarder(bool isRelay); //function to set localNodeIsForwarder ALWAYS use this function when setting this variable
  bool           localNodeIsForwarder; //set to true if node should forward for smf when using manet OPSF extensions method
  bool           localNodeIsForwarder_old; //used for repressing information sent to udate sdt directly....only used for updating sdt
  unsigned long  localNodeDegree;  //vairable used in OPSF manet extensions cds algorithm
  int            localWillingness;
  int            mac_control_port; //port number that mac control option packets are sent default is 4999

  enum NodeLinkState {LINK_DEFAULT, LINK_UP, LINK_DOWN};

  //olsr class variables
  ProtoAddress myaddress;  //IP Address of this node 
  

  bool           userDefBroadcast;
  ProtoAddress   userDefNetBroadAddr; //address to use for adding network 
  unsigned int   userDefBroadMaskLength; //user defined subnet mask length

  ProtoAddress   netBroadAddr; //address to use for adding network 
  unsigned int   broadMaskLength; //subnet mask length
  ProtoAddress   broadAddr; //broadcast address actually broadcast address

  char           interfaceName[256]; //eth0 eth1 etc....
  char           recvPipeName[256];

  unsigned int   interfaceIndex;
  UINT16         seqno;  //Message Sequence Number
  UINT16         pseqno; //Packet Sequence Number
  int            bid;    //Broadcast ID 
  int            mssn;   //mpr selector list number

  double         Hello_Interval;
  UINT8          Mantissa_Hello_Interval;
  UINT8          Mantissa_Hello_Hold_Interval;
  double         Hello_Timeout_Factor;
  double         Hello_Jitter; //% of Hello_Interval
  double         Neighb_Hold_Time;
  double         D_Hold_Time;
  unsigned int   helloPadding; //number of bytes hello message will be padded out to when using the -hp option

  double         TC_Interval;
  double         TC_Timeout_Factor;
  double         TC_Jitter; //% of TC_Interval
  double         Top_Hold_Time;

  double         HNA_Interval;
  double         HNA_Timeout_Factor;
  double         HNA_Jitter; //% of HNA_Interval
  double         HNA_Hold_Time;

  double         fdelay;//forwarding delay value in seconds default is 0

  double         Delay_Smf_Off_Time; //amount of time to delay turning off forwarding with regards to smf.  default is 0
  ProtoAddress::Type    ipvMode;
  unsigned int          hostMaskLength;

  unsigned int          qosvalue;

  //do nonstandard route calculations based upon link metrics
  bool           dotcextra;  //set to true for non-standard operation
  bool           dospf;
  bool           dominmax;
  bool           dorobust;

  int a8packedmessages;
  //variables for fuzzy link state routing
  bool           fuzzyflooding;
  int            tcloopcounter; //counter to keep track of how far to send the next tc message 
  int            hnaloopcounter; //counter to keep track of how far to send the next hna message 
  int            floodingdistance[16]; //array which has ttl values which counters set though 2/4/2/8/2/4/2/16/2/4/2/8/2/4/2/32

  //hna setup variables
  bool           dohna;
  bool           hnaFromFile;
  
  
	int olsr_port_number;

  //historisis variables
	bool recordhellohistory; //when set to true print out of hello history for every neighbor being tracted will be writen to logfilename
  double T_up;          //neighbor threshold 0-1
  double T_down;        //neighbor threshold used with time outs and time out timer 0-1 less than T_up
  double alpha;         //decides rate of change smaller number allow for faster rates of neighbor chages between 0-1

  // lists
  NBRQueue       mprSelectorList;  //list of mpr selector nodes
  NBRQueue       nbr_list;         //list of neighbors
  NBRQueue       nbr_list_old_for_tc;        //only used for when tcSlowDown is set to true stores old neighbor table when last tc was sent;
  NBRQueue       nbr_list_old_for_hello;     //only used for when tcSlowDown is set to true stores old neighbor table when last hello was recieved;
  NBRQueue       nbr_2hop_list;    //list of 2 hop neighbors
  NBRQueue       duplicateTable;   //list of recently recieved packets
  NBRQueue       forwardTable;     //list of recently forwared packets
  NBRQueue       topologySet;      //list of topology tuples 
  NBRQueue       routeTable;       //list of routes
  NBRQueue       extraQueue;       //extra queue to use
  NBRQueue       oldRouteTable;    //temp list of routes

  //next two lists are used for printing output only
  NBRQueue       routeTopologySet; //list used to temporary store the topology tuples (links) which  were used in the route calculation
  NBRQueue       routeNeighborSet; //list used to temporary store the topology tuples (links) which  were used in the route calculation


  NBRQueue       hnaAddresses;     //list of local hna info
  NBRQueue       hnaSet;           //list of hna tuples
  NBRQueue       hnaRoutes;        //list of hna routes

  ProtoRouteTable llToGlobal;      //mapping of link local ipv6 addresses to global ipv6 addresses

// LP 8-29-05 - added for displaying statisc in OPNET
#ifdef OPNET
 int 			 total_Hello_sent;
 int			 total_Hello_rcv;
 int			 total_TC_sent;
 int			 total_TC_rcv;
 Boolean		 Hello_sent_changed_flag;
 Boolean		 TC_sent_changed_flag;
 Boolean		 Hello_rcv_changed_flag;
 Boolean		 TC_rcv_changed_flag;
 Boolean		 MPR_increased_flag;
 Boolean		 MPR_decreased_flag;
 Objid			 smf_objid;  // JPH SMF
 #endif // OPNET
 int             numberofroutes;  // JPH animation 10-26-06

 // end LP
  
private:

  //  static void SignalHandler(int sigNum);
  // timed functions
  bool OnHelloTimeout(ProtoTimer &theTimer);
  bool SendHello();
  void SendUnicastHello(OlsrMessage *forwardmessage, ProtoAddress uniAddr);
  bool sendHelloTimerOn;

  bool OnTcTimeout(ProtoTimer &theTimer);
  bool SendTc();
  bool SendTcExtra();
  bool sendTcTimerOn;

  bool OnHnaTimeout(ProtoTimer &theTimer);
  bool SendHna();
  bool sendHnaTimerOn;
  // recieving functions
  void OnSocketEvent(ProtoSocket &thesocket,ProtoSocket::Event theEvent);

  void DelayedForward(OlsrMessage *forwardmessage, double delay);//used to jitter forwarding of messages
  OlsrPacket olsrpacket2forward;
  bool OnDelayedForwardTimeout(ProtoTimer &theTimer);//event which sends out messages saved for forwarding

  bool OnDelaySmfOffTimeout(ProtoTimer &theTimer);//event which sets smf forwarding off and then sends information to smf_pipe
  bool OnStaticRunTimeout(ProtoTimer &theTimer);//calls Sleep() when the timer goes off
  void OnMacControlSocketEvent(ProtoSocket &thesocket,ProtoSocket::Event theEvent);
  //pcap mac address snooping
#ifndef SIMULATE
  void OnRecvPipeMessage(ProtoSocket & theSocket,ProtoSocket::Event theEvent);
#endif //SIMULATE
  

  // object variables
  //ProtoDispatcher dispatcher;
  ProtoSocket socket;
  ProtoSocket mac_control_socket;
#ifndef SIMULATE
  ProtoPipe     recvPipe;
  ProtoPipe     smf_pipe;              // pipe to smfClient
  ProtoPipe     gui_pipe;              // pipe to gui interface
  ProtoPipe     sdt_pipe;              // pipe to sdt interface
#endif //SIMULATE
  ProtoTimer hello_timer;
  ProtoTimer hello_jitter_timer;
  ProtoTimer tc_timer;
  ProtoTimer tc_jitter_timer;
  ProtoTimer hna_timer;
  ProtoTimer hna_jitter_timer;
  ProtoTimer delayed_forward_timer;
  ProtoTimer delay_smf_off_timer;
  ProtoTimer static_run_timer; //will turn off olsr when it goes off.  will only be turned on with -static command.
#ifdef SMF_SUPPORT
  // This stuff supports operation with a Simplified Multicast Forwarding (smf) client app (e.g. "nrlsmf")
  void OnPktCapture(ProtoChannel& theChannel, ProtoChannel::Notification theNotification);  
  void SendMacSymInfo(); //function to write to send pipe mac address of sym neighbors
  void SendMacMprInfo(); //function to write to send pipe mac address of mpr neighbors

  ProtoCap*         cap_rcvr;
  ProtoRouteTable   ipToMacTable;
  //deprecated use updateSmfForwardingInfo instead;
  //bool              updateSendMacMprInfo; // set to true if mprselector list is changed
#endif // SMF_SUPPORT
  void SendGuiRoutes(); //sends routing info to the gui pipe
  void SendGuiNeighbors(); //sends neighbor info to the gui pipe
  void SendGuiSettings(); //sends the setting info to the gui pipe

  void SendSDTInfo();
  void SendForwardingInfo(); //generic function which sends forwarding info dependant on which forwarding mode olsris in
  bool updateSmfForwardingInfo; //set to true if the forwarding information needs to be changed
  bool floodingOn;//set to true when flooding command is used
  FloodingType floodingType;
  bool unicastRouting;//set to true when routing is turned on; off is used for smf hello type situtations
  bool SDTOn; //set to true when attempting to send SDT commands directly using protopipes off by default

  // helper functions  
  int update_nbr(ProtoAddress id,int status,UINT8 spfValue,UINT8 minmaxValue);
  int update_nbr(ProtoAddress id,int status,UINT8 spfValue, UINT8 minmaxValue, UINT8 Vtime,UINT8 willingness);
  void update_2hop_nbr(ProtoAddress onehop_addr,ProtoAddress twohop_addr);
  void update_2hop_nbrExtra(ProtoAddress onehop_addr,ProtoAddress twohop_addr,unsigned long nodedegree);// only use for manet ospf extisions
  void remove_2hop_link(ProtoAddress oneaddr,ProtoAddress twoaddr);
  
  bool SetLinkState(NodeLinkState state,ProtoAddress node);

  void addHnaInfo(ProtoAddress gwaddr,ProtoAddress subnetaddr,ProtoAddress subnetmask,UINT8 Vtime);

  void addTopologyInfo(ProtoAddress T_last,ProtoAddress T_dest, UINT16 T_seq, UINT8 spfvalue, UINT8 minmaxValue, UINT8 Vtime);
  int updateTopology(ProtoAddress T_last, UINT16 T_seq);
  
  void update_mprselector(ProtoAddress id, int status);
  void selectmpr();
  void makempr(NbrTuple *parent);

  void calculateNsMpr();  //function to calculate smf forwarding tree if node is mpr for ANY neighbor.
  void calculateMprCds(); //fucntion to calculate smf forwarding tree based upon inria paper "On the robustness and stability of Connected Dominating Sets"
  void calculateOspfEcds(); //function to calculate proposed OSPF cds algrothim determining if node should forward or not described in richard ogiers slides
  void coverNodeOspfEcds(NbrTuple* node); //function to recurisvly cover tuples

  void makeRoutingTable(); //function which selects one of the three following routing algrothims.
  void makeNewRoutingTable();
  void makeSpfRoutingTable();
  void makeMinmaxRoutingTable();
  void makeNewRoutingTableRobust();

  void addHnaRoutes();

  int WasForwarded(ProtoAddress addr,UINT16 dseqno);
  void addForwarded(ProtoAddress addr,UINT16 dseqno);

  int IsDuplicate(ProtoAddress addr,UINT16 dseqno);
  void addDuplicate(ProtoAddress addr,UINT16 dseqno);

  //printing and debuging functions
  void printDuplicateTable(int debuglvl); //prints duplicate table
  void printRoutingTable(int debuglvl); //prints routing table
  void printTopology(int debuglvl); //prints topology links
  void printNbrs(); //prints the neighbors and their state when debuglvl >=1
  void printLinks(); //prints the known links in the network debuglvl >=1
  void printRouteLinks(); //prints the links which it selected for routing debuglvl >=1
  int checkCurrentTable(int callvalue); // does some validity checking on internal tables to make sure everything is ok
  void printCurrentTable(int debuglvl); //prints neighbor table with interconnections and neighbor status
  void printHnaTables(int debuglvl); // prints hna tables 
  void printHnaLinks();//prints the known hna associations in the network debuglvl >=2
  
  //purging functions
  void nb_purge();  //cleans up the neighbor table
  void for_purge(); //cleans up the was forwarded table
  void dup_purge(); //cleans up the duplicate table
  void hna_purge(); //cleans up the hna table
  void top_purge(); //cleans up the topology table made from tc messages.

  void HysFailure(NbrTuple* nb); //removes connections to neighbor cleanly sets state to lost link;

  //other helper functions
  bool discoverAndSetHNAs(char* ignoreDev); //discovers hnas to broadcast (only currently working in UNIX and only in IPv4 mode)
  UINT8 doubletomantissa(double timeinseconds);
  double mantissatodouble(UINT8 mantissatime);
  bool NeighborsStableForTC(); //returns true if neighbor table has not changed since last time tc message was sent
  bool NeighborsStableForHello(); //returns true if neighbor table has not changed since last time hello message was recieved
  bool TupleLinkIsUp(NbrTuple* tuple); //returns true if tuple state indicates its a true one hop neighbor which can forward

};
