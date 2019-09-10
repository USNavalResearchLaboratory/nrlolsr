#ifndef _OPNET_OLSR_PROCESS
#define _OPNET_OLSR_PROCESS

#include "opnet.h"
#include "opnetProtoSimProcess.h"
#include "nrlolsr.h" // this includes protokit.h

// LP 7-16-04 - replaced for Solaris
// #include "OpnetProtoRouteMgr.h"
#include "opnetProtoRouteMgr.h"
// end LP

#define MAX_NUM_NODES	100  // JPH - moved here from animInfo.h

// LP 8-31-05 - added for displaying statistic in OPNET
int 	global_num_hello_pk_sent =0;
int 	global_num_hello_pk_rcv =0;
int 	global_num_TC_pk_sent =0;
int 	global_num_TC_pk_rcv =0;
int		global_MRP_count = 0;
int 	global_MRP_increase = 0;
int 	global_MRP_decrease = 0;
Boolean already_process_flag = OPNET_FALSE;
Stathandle 	g_num_hello_pk_sent_stathandle;
Stathandle 	g_num_TC_pk_sent_stathandle;
Stathandle 	g_MPR_count_stathandle;
Stathandle 	g_num_hello_sent_bit_sec_stathandle;
Stathandle 	g_num_TC_sent_bit_sec_stathandle;
int	global_MPR_increase_[MAX_NUM_NODES];
int global_MPR_decrease_[MAX_NUM_NODES];


// end LP

class OpnetOlsrProcess : public OpnetProtoSimProcess, public Nrlolsr
{
    public:
    // Construction
        // LP 6-17-04 - replaced to test
		// OpnetOlsrProcess()  : Nrlolsr(GetSocketNotifier(),GetTimerMgr()) {}; 
		OpnetOlsrProcess()  : Nrlolsr(GetSocketNotifier(),GetTimerMgr()) {
			  printf("OpnetOlsrProcess.h - OpnetOlsrProcess() - this = %ld\n", this);
			  }

		~OpnetOlsrProcess();
	
	unsigned long GetAgentId() 
		{return ((unsigned long) node_id);} //  virtual MDPSimAgent function  

	
	// OpnetProtoSimProcess's virtual functions
	bool OnStartup(int argc, const char*const* argv);
	bool ProcessCommands(int argc, const char*const* argv);
	void OnShutdown(); 
	void SetOlsrNodeId (int nodeId) {node_id = nodeId;}  
	int GetOlsrNodeId () {return node_id;}  // LP 6-17-04 - added

	IpT_Address GetRoute(SIMADDR dest);
	bool GetLocalAddress(ProtoAddress& localAddr); 
	void OnReceive(Packet * rcv_pkt); 
	bool InitializeRoutingTable();
	
	private:
    // Members
		double        client_start_time;
		int			  node_id;  
		bool			logging;
	
		friend class OpnetProtoRouteMgr;
		OpnetProtoRouteMgr* routingTable_mgr;

};  // end class OpnetOlsrProcess

#ifdef PROTO_DEBUG
// This routine produces a timestamped trace of MDP messages
// void MessageTrace(bool send, unsigned long node_id, MdpMessage *msg, int len, const ProtoAddress *src);

void SetOlsrMessageTrace(bool state);
#endif // PROTO_DEBUG


#endif // _OPNET_OLSR_PROCESS


