/* Process model C++ form file: olsr_protolib_smf.pr.cpp */
/* Portions of this file copyright 1992-2006 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char olsr_protolib_smf_pr_cpp [] = "MIL_3_Tfile_Hdr_ 115A 30A op_runsim 7 4540BC93 4540BC93 1 apocalypse Jim@Hauser 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 d50 3                                                                                                                                                                                                                                                                                                                                                                                                   ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

/* LP 7-16-04 - commented out for Solaris */
/* #define WIN32 1 */
/* end LP */

#define SIMULATE 1 
#define PROTO_DEBUG 1
#define OPNET 1

  
#include "opnet.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <socket.h>
#endif

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <oms_pr.h>
#include <ip_addr_v4.h>
#include <ip_cmn_rte_table.h>
#include <udp_api.h>


#include "ip_rte_support.h"
#include "ip_rte_v4.h"
#include "ip_higher_layer_proto_reg_sup.h"
#include <ip_sim_attr_cache.h>

#include "OpnetOlsrProcess.h"
#include <smf_ipc.h>  // JPH - define ici structure for communication with SMF


/* LP 7-16-04 - replaced for Solaris */
/* #include "OpnetProtoRouteMgr.h" */
#include "opnetProtoRouteMgr.h"
/* end LP */

/* unix.h replaces the following includes for Win system */  /* JPH */
/*
#include <sys/ioctl.h>
#include <sys/file.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <inttypes.h>
#include <paths.h>
*/

/* intrpt codes */
#define TIMER_INTRPT					10
#define STARTUP_INTRPT					20
#define SELF_INTRT_CODE_PRINT_RT_EVENT	30

/***** Transition Macros *****/
#define	MESSAGE_RECEIVED	op_intrpt_type () == OPC_INTRPT_STRM
#define IP_NOTIFICATION		(op_intrpt_type () == OPC_INTRPT_REMOTE && (op_intrpt_code() != PACKET_CAPTURE_EVENT))
#define TIMEOUT_EVENT		((op_intrpt_type () == OPC_INTRPT_SELF) && (op_intrpt_code() == SELF_INTRT_CODE_TIMEOUT_EVENT))
#define PRINT_RT_EVENT		((op_intrpt_type () == OPC_INTRPT_SELF) && (op_intrpt_code() == SELF_INTRT_CODE_PRINT_RT_EVENT))
#define	END_SIM		op_intrpt_type () == OPC_INTRPT_ENDSIM
//  JPH - added proc_pcap state entered via PACKET_CAPTURE condition
#define PACKET_CAPTURE		(op_intrpt_type () == OPC_INTRPT_REMOTE && (op_intrpt_code() == PACKET_CAPTURE_EVENT))


/* Globals */
Stathandle		bits_rcvd_gstathandle;
Stathandle		bitssec_rcvd_gstathandle;
Stathandle		pkts_rcvd_gstathandle;
Stathandle		pktssec_rcvd_gstathandle;
Stathandle		ete_delay_gstathandle;
Stathandle		bits_sent_gstathandle;
Stathandle		bitssec_sent_gstathandle;
Stathandle		pkts_sent_gstathandle;
Stathandle		pktssec_sent_gstathandle;

bool olsr_trace = OPC_FALSE;
int trace_min_debug_level = 8;

double print_rt_interval = 60;  /* in seconds */

// LP 8-30-05 - added
extern int 	global_num_hello_pk_sent ;
extern int 	global_num_hello_pk_rcv ;
extern int 	global_num_TC_pk_sent ;
extern int 	global_num_TC_pk_rcv ;


/* Function declaration */

void SetOlsrMessageTrace(bool);
/*void olsr_rte_route_table_to_file_export (void* , int );*/ /* JPH 11.0 eliminated olsr_rte_route_table_to_file_export */
char* ip_cmn_rte_table_olsr_file_create (void);
void printUsage(void);

// LP 9-16-05 - added
void olsr_rte_route_table_to_file_export (void* , int ); 
char* ip_cmn_rte_table_olsr_file_create (void);
int  ip_cmn_rte_table_export_num_subinterfaces_get (struct IpT_Rte_Module_Data* , IpT_Rte_Protocol );
void ip_cmn_rte_table_export_file_header_print (FILE* );
void ip_cmn_rte_table_export_iface_addr_print (struct IpT_Rte_Module_Data* , int , FILE* , IpT_Rte_Protocol );

// end LP


/* End of Header Block */

#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
class olsr_protolib_smf_state
	{
	public:
		olsr_protolib_smf_state (void);

		/* Destructor contains Termination Block */
		~olsr_protolib_smf_state (void);

		/* State Variables */
		Stathandle	             		bits_rcvd_stathandle                            ;	/* Opnet default */
		                        		                                                	/*               */
		                        		                                                	/*               */
		Stathandle	             		bitssec_rcvd_stathandle                         ;
		Stathandle	             		pkts_rcvd_stathandle                            ;
		Stathandle	             		pktssec_rcvd_stathandle                         ;
		Stathandle	             		ete_delay_stathandle                            ;
		Stathandle	             		bits_sent_stathandle                            ;
		Stathandle	             		bitssec_sent_stathandle                         ;
		Stathandle	             		pkts_sent_stathandle                            ;
		Stathandle	             		pktssec_sent_stathandle                         ;
		Stathandle	             		mpr_list_sent_stathandle                        ;
		Stathandle	             		num_hello_pk_sent_stathandle                    ;
		Stathandle	             		num_TC_pk_sent_stathandle                       ;
		Stathandle	             		MPR_status_stathandle                           ;
		int	                    		NODE_ID                                         ;
		OpnetOlsrProcess	       		own_olsr_process                                ;	/* My olsr process */
		IpT_Rte_Proc_Id	        		olsr_protocol_id                                ;	/* OLSR_NRL protocol id */
		Objid	                  		own_module_objid                                ;
		Objid	                  		own_node_objid                                  ;
		Prohandle	              		own_prohandle                                   ;
		OmsT_Pr_Handle	         		own_process_record_handle                       ;
		IpT_Interface_Info*	    		interface_info_pnt                              ;	/* IpT_INterface_Info from "interface information"->ip_iface_table_ptr_list */
		IpT_Cmn_Rte_Table *	    		common_routing_table                            ;	/* Common Routing Table */
		IpT_Port_Info	          		olsr_port_info                                  ;	/* contains the addr_index of the interface used to reach the next hop */
		Ici *	                  		udp_command_ici_ptr                             ;
		Objid	                  		my_udp_objid                                    ;
		Objid	                  		my_smf_objid                                    ;	/* JPH SMF - Objid of Wlan SMF child process */
		IpT_Rte_Module_Data *	  		my_rte_module_data                              ;
		Prohandle	              		move_process_hndl                               ;	/* handle to the "olsr_node_movement" process */
		int	                    		smf_support                                     ;	/* JPH SMF - set true for enabling SMF */
		int	                    		num_hello_pk_sent                               ;	/* LP 8-30-05 - added */
		int	                    		num_hello_pk_rcv                                ;	/* LP 8-30-05 - added */
		int	                    		num_TC_pk_sent                                  ;	/* LP 8-30-05 - added */
		int	                    		num_TC_pk_rcv                                   ;	/* LP 8-30-05 - added */

		/* FSM code */
		void olsr_protolib_smf (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_olsr_protolib_smf_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;

	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE
	};

VosT_Obtype olsr_protolib_smf_state::obtype = (VosT_Obtype)OPC_NIL;

#define pr_state_ptr            		((olsr_protolib_smf_state*) (OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))
#define bits_rcvd_stathandle    		pr_state_ptr->bits_rcvd_stathandle
#define bitssec_rcvd_stathandle 		pr_state_ptr->bitssec_rcvd_stathandle
#define pkts_rcvd_stathandle    		pr_state_ptr->pkts_rcvd_stathandle
#define pktssec_rcvd_stathandle 		pr_state_ptr->pktssec_rcvd_stathandle
#define ete_delay_stathandle    		pr_state_ptr->ete_delay_stathandle
#define bits_sent_stathandle    		pr_state_ptr->bits_sent_stathandle
#define bitssec_sent_stathandle 		pr_state_ptr->bitssec_sent_stathandle
#define pkts_sent_stathandle    		pr_state_ptr->pkts_sent_stathandle
#define pktssec_sent_stathandle 		pr_state_ptr->pktssec_sent_stathandle
#define mpr_list_sent_stathandle		pr_state_ptr->mpr_list_sent_stathandle
#define num_hello_pk_sent_stathandle		pr_state_ptr->num_hello_pk_sent_stathandle
#define num_TC_pk_sent_stathandle		pr_state_ptr->num_TC_pk_sent_stathandle
#define MPR_status_stathandle   		pr_state_ptr->MPR_status_stathandle
#define NODE_ID                 		pr_state_ptr->NODE_ID
#define own_olsr_process        		pr_state_ptr->own_olsr_process
#define olsr_protocol_id        		pr_state_ptr->olsr_protocol_id
#define own_module_objid        		pr_state_ptr->own_module_objid
#define own_node_objid          		pr_state_ptr->own_node_objid
#define own_prohandle           		pr_state_ptr->own_prohandle
#define own_process_record_handle		pr_state_ptr->own_process_record_handle
#define interface_info_pnt      		pr_state_ptr->interface_info_pnt
#define common_routing_table    		pr_state_ptr->common_routing_table
#define olsr_port_info          		pr_state_ptr->olsr_port_info
#define udp_command_ici_ptr     		pr_state_ptr->udp_command_ici_ptr
#define my_udp_objid            		pr_state_ptr->my_udp_objid
#define my_smf_objid            		pr_state_ptr->my_smf_objid
#define my_rte_module_data      		pr_state_ptr->my_rte_module_data
#define move_process_hndl       		pr_state_ptr->move_process_hndl
#define smf_support             		pr_state_ptr->smf_support
#define num_hello_pk_sent       		pr_state_ptr->num_hello_pk_sent
#define num_hello_pk_rcv        		pr_state_ptr->num_hello_pk_rcv
#define num_TC_pk_sent          		pr_state_ptr->num_TC_pk_sent
#define num_TC_pk_rcv           		pr_state_ptr->num_TC_pk_rcv

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#  define FIN_PREAMBLE_DEC	olsr_protolib_smf_state *op_sv_ptr;
#if defined (OPD_PARALLEL)
#  define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((olsr_protolib_smf_state *)(sim_context_ptr->_op_mod_state_ptr));
#else
#  define FIN_PREAMBLE_CODE	op_sv_ptr = pr_state_ptr;
#endif


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

void olsr_sv_init()
{   
    FIN (olsr_sv_init());

    /* Obtain the object id of the Opnet OLSR module. */
    own_module_objid = op_id_self();

    /* Obtain the surrounding node's objid. */
    own_node_objid = op_topo_parent(own_module_objid);

	/* Obtain user_id */
	op_ima_obj_attr_get (own_node_objid, "user id", &NODE_ID);
	own_olsr_process.SetOlsrNodeId(NODE_ID);
	
    /* Obtain the Opnet OLSR process's prohandle. */
    own_prohandle = op_pro_self();

    /* Obtain the name of the Opnet OLSR process. */
    char proc_model_name[20];
    op_ima_obj_attr_get(own_module_objid, "process model", proc_model_name);

    /* Register the Opnet OLSR process in the model-wide process registry. */
   own_process_record_handle = (OmsT_Pr_Handle) oms_pr_process_register(own_node_objid, 
        own_module_objid, own_prohandle, proc_model_name);

    /* Register the protocol attribute in the registry. */
    oms_pr_attr_set(own_process_record_handle,
		"protocol", OMSC_PR_STRING, "OLSR_NRL",
		OPC_NIL);
	

	/** Assigns a protocol id to the custom routing protocol and	**/
	/** returns the id. If this protocol is already assigned an id,	**/
	/** this function returns that id.								**/
	olsr_protocol_id = Ip_Cmn_Rte_Table_Custom_Rte_Protocol_Register ("OLSR_NRL");
#ifdef OP_DEBUG1
	printf("Node_%d - olsr_protolib.pr.c - olsr_sv_init() - olsr_protocol_id = %I64d\n", NODE_ID, olsr_protocol_id);
#endif
	/* olsr_protocol_id = IpC_Rte_Custom; */ /* hacked by JH for OPnet 10.0 but commented by LP on 2-27-04 to test */

	#ifdef OP_DEBUG1
	/* printf("Node_%d - olsr_protolib.pr.c - olsr_sv_init() - After changing - olsr_protocol_id = %ld\n", NODE_ID, olsr_protocol_id); */
#endif
	
  	/* Get value of toggle which indicates if this OLSR process supports SMF */  /* JPH SMF */
	op_ima_obj_attr_get_toggle(own_module_objid,"SMF Support",&smf_support);
	
    /* Register the statistics that will be saved by this model. */
	bits_rcvd_stathandle 		= op_stat_reg ("OLSR.Traffic Received (bits)",			OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	bitssec_rcvd_stathandle 	= op_stat_reg ("OLSR.Traffic Received (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	pkts_rcvd_stathandle 		= op_stat_reg ("OLSR.Traffic Received (packets)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	pktssec_rcvd_stathandle 	= op_stat_reg ("OLSR.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	ete_delay_stathandle		= op_stat_reg ("OLSR.End-to-End Delay (seconds)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	bits_sent_stathandle 		= op_stat_reg ("OLSR.Traffic Sent (bits)",			OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	bitssec_sent_stathandle 	= op_stat_reg ("OLSR.Traffic Sent (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	pkts_sent_stathandle 		= op_stat_reg ("OLSR.Traffic Sent (packets)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	pktssec_sent_stathandle 	= op_stat_reg ("OLSR.Traffic Sent (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	mpr_list_sent_stathandle	= op_stat_reg ("OLSR.MPR List to SMF",			OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
// JPH SMF
	
	// LP 9-6-05 - added
	num_hello_pk_sent_stathandle = op_stat_reg ("OLSR.Total Hello Messages Sent", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	num_TC_pk_sent_stathandle 	= op_stat_reg ("OLSR.Total TC Messages Sent", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	MPR_status_stathandle = op_stat_reg ("OLSR.MPR Status", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	// end LP
	
	// LP 9-14-05 - added
	if (already_process_flag == OPNET_FALSE)
		{
		g_num_hello_pk_sent_stathandle = op_stat_reg ("OLSR.Total Hello Messages Sent", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
		g_num_TC_pk_sent_stathandle = op_stat_reg ("OLSR.Total TC Messages Sent", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
		g_MPR_count_stathandle = op_stat_reg ("OLSR.MPR Count", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
		g_num_hello_sent_bit_sec_stathandle = op_stat_reg ("OLSR.Hello Traffic Sent (bits/sec)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
		g_num_TC_sent_bit_sec_stathandle = op_stat_reg ("OLSR.TC Traffic Sent (bits/sec)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
		
		// 9-15-05
		int i;
		for (i = 0; i < 40; i++)
			  global_MPR_increase_[i] = global_MPR_decrease_[i] = 0;
		// end LP
		already_process_flag = OPNET_TRUE;
		}
	
	// end LP

    FOUT;
}  /* end mdp_sv_init() */


void OLSR_startup()
{
    FIN (OLSR_startup());
	
	/* This function is used to obtain simulation attributes for
	   the NRL_OLSR program.  After getting the necessary attributes,
	   it will kick off the Start() of theNRL_OLSR program.
	*/
	
#if OP_DEBUG1
	printf("Node %d - OLSR_protolib.pr.m - Olsr_startup()\n", NODE_ID);
#endif

    /* Obtain a pointer to the process record handle list of any
       neighboring udp processes.
	*/
    List* proc_record_handle_list_ptr = op_prg_list_create();
    oms_pr_process_discover(own_module_objid, proc_record_handle_list_ptr,
	                        "protocol", OMSC_PR_STRING, "udp", OPC_NIL);

    /* An error should be created if there are zero or more than
       one UDP processes connected to the OLSR module.
	*/
    int record_handle_list_size = op_prg_list_size(proc_record_handle_list_ptr);
    if (1 != record_handle_list_size)
	{
	    /* Generate an error and end simulation. */
	    op_sim_end("Error: either zero or more than one udp processes connected to OLSR.", "", "", "");
	}
    else
	{
        /* Obtain the process record handle of the neighboring UDP process. */
	    OmsT_Pr_Handle process_record_handle = (OmsT_Pr_Handle) op_prg_list_access(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
	    /* Obtain the object id of the UDP module. */
        oms_pr_attr_get(process_record_handle, "module objid", OMSC_PR_OBJID, &my_udp_objid);
		/* printf("Node %d - udp_objid = %ld\n", NODE_ID, my_udp_objid); */
        own_olsr_process.SetUdpProcessId(my_udp_objid);  /*  - OpnetProtoSimProcess.h */
	}

    /* Deallocate the list pointer. */
    while (op_prg_list_size(proc_record_handle_list_ptr) > 0)
	    op_prg_list_remove(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
    op_prg_mem_free(proc_record_handle_list_ptr);
   
    if (smf_support)  /* JPH SMF */
	{
		/* Obtain a pointer to the process record handle list of any
        neighboring smf processes. */
		List* proc_record_handle_list_ptr = op_prg_list_create();
		oms_pr_process_discover(own_module_objid, proc_record_handle_list_ptr,
	                        "protocol", OMSC_PR_STRING, "smf", OPC_NIL);

		/* An error should be created if there are zero or more than
		one SMF process connected to the OLSR module. */
		int record_handle_list_size = op_prg_list_size(proc_record_handle_list_ptr);
		if (1 != record_handle_list_size)
		{
			/* Generate an error and end simulation. */
			op_sim_end("Error: either zero or more than one smf process connected to OLSR.", "", "", "");
		}
		else
		{
			/* Obtain the process record handle of the neighboring SMF process. */
			OmsT_Pr_Handle process_record_handle = (OmsT_Pr_Handle) op_prg_list_access(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
			/* Obtain the object id of the SMF module. */
			oms_pr_attr_get(process_record_handle, "module objid", OMSC_PR_OBJID, &my_smf_objid);
			/* printf("Node %d - udp_objid = %ld\n", NODE_ID, my_udp_objid); */
			own_olsr_process.SetSmfProcessId(my_smf_objid);  /*  - OpnetProtoSimProcess.h */
		}

		/* Deallocate the list pointer. */
		while (op_prg_list_size(proc_record_handle_list_ptr) > 0)
	    op_prg_list_remove(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
		op_prg_mem_free(proc_record_handle_list_ptr);
		
		if (op_ima_sim_attr_exists("OLSR Flooding Type")==OPC_TRUE)
		{
			char fldtype[8];
			char cmdline[20];
			op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR Flooding Type",fldtype);
			sprintf(cmdline,"-flooding %s",fldtype);
			printf("     Flooding cmd =  %s\n",cmdline);
			own_olsr_process.Nrlolsr::StringProcessCommands(cmdline); 
		}

	}
	else
	{
		//char* argv[] = {"-flooding","off"};
		//own_olsr_process.ProcessCommands(2,argv);
		own_olsr_process.Nrlolsr::StringProcessCommands("-flooding off");
	}/* end JPH SMF */

    /* The following code is used to obtain the IP broadcast address
       for the subnet connected to the interface.
	*/

    /* Obtain a pointer to the process record handle list of any 
       IP processes residing in the local node.
	*/
    proc_record_handle_list_ptr = op_prg_list_create();
    oms_pr_process_discover(OPC_OBJID_INVALID, proc_record_handle_list_ptr,
	                        "protocol", OMSC_PR_STRING, "ip",
	                        "node objid", OMSC_PR_OBJID, own_node_objid, 
	                        OPC_NIL);

    /* An error should be created if there are zero or more than     
       one IP processes in the local node.
	*/
    record_handle_list_size = op_prg_list_size (proc_record_handle_list_ptr);
    IpT_Info* ip_info_ptr;
    if (1 != record_handle_list_size)
	{
	    /* Generate an error and end simulation. */
	    op_sim_end("Error: either zero or more than one ip processes in local node.", "", "", "");
	}
    else
	{
        /* Obtain the process record handle of the IP process. */
	    OmsT_Pr_Handle process_record_handle = (OmsT_Pr_Handle) op_prg_list_access(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
	    /* Obtain the pointer to the interface info structure. */
	    oms_pr_attr_get(process_record_handle, "interface information", OMSC_PR_ADDRESS, &ip_info_ptr);
	    oms_pr_attr_get(process_record_handle, "module data", OMSC_PR_ADDRESS, &my_rte_module_data); /* LP 3-15-04 - added */
	}

    /* Deallocate the list pointer. */
    while (op_prg_list_size(proc_record_handle_list_ptr) > 0)
	    op_prg_list_remove(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
    op_prg_mem_free(proc_record_handle_list_ptr);

    /* Obtain the pointer to the IP interface table.
	   Note that the ip_info_ptr->ip_iface_table_ptr is the same list
	     as module_data->interface_table_ptr as shown in ip_dispatch.pr.c->ip_dispatch_do_int()
	*/
    List* ip_iface_table_ptr = ip_info_ptr->ip_iface_table_ptr;

    /* Obtain the size of the IP interface table. */
    int ip_iface_table_size = op_prg_list_size(ip_iface_table_ptr);

	int interface_info_index = 0;  /* LP */
	
    /* For now, an error should be created if there are zero or more than 
       one IP interface attached to this node.  Loopback interfaces
	   and Tunnel interfaces are OK.
	*/
	
	/* In the future, we should allow more than 1 IP interface for the
	   case of IP routers. LP 3-4-04
	*/
	
    if (1 != ip_iface_table_size)
	{
#if OP_DEBUG1
		printf("OLSR_startup - ip_iface_table_size = %d\n", ip_iface_table_size);
#endif		
	
	/* check to see if there is any loopback interface or tunnel interface.  (LP 3-1-04 - added) */
		int i, ip_intf_count = 0;
		bool dumb_intf = OPC_FALSE;
		for (i = 0; i < ip_iface_table_size; i++)
			{
   			IpT_Interface_Info* intf_ptr = (IpT_Interface_Info*) op_prg_list_access(ip_iface_table_ptr, OPC_LISTPOS_HEAD + i);
			if ((intf_ptr->phys_intf_info_ptr->intf_status == IpC_Intf_Status_Tunnel) ||
				(intf_ptr->phys_intf_info_ptr->intf_status == IpC_Intf_Status_Loopback))
				{
				dumb_intf = OPC_TRUE;
				break;
				} /* end if tunnel || loop back */
			else
				{
				interface_info_index = i;
				ip_intf_count ++;
				}
			} /* end for i */

	    /* Generate an error and end simulation. */
	    if ((dumb_intf == OPC_FALSE) || (ip_intf_count > 1))  /* end LP */
			op_sim_end("Error: either zero or more than one ip interface on this node.", "", "", "");
	}  /* end if ip_iface_table-size != 1 */
	
    /* Obtain a pointer to the IP interface data structure. */
	
	
	/* added this state variable to keep track of the Interface Info */
	interface_info_pnt = (IpT_Interface_Info*) op_prg_list_access(ip_iface_table_ptr, OPC_LISTPOS_HEAD + interface_info_index);

		/* Set the destination address for OLSR messages to the interface broadcast address.  However, at this
		   time, this variable is not used at all since the OLSR program has its own bradcast address
		*/
    IpT_Address broadcastAddr = 
        ip_address_node_broadcast_create(interface_info_pnt->addr_range_ptr->address, interface_info_pnt->addr_range_ptr->subnet_mask);

#ifdef OP_DEBUG1
	printf("Node %d - olsr_protolib.pr.c - olsr_startup() - broadcastAddr = %u\n", NODE_ID, broadcastAddr);
	printf("Node %d - olsr_protolib.pr.c - olsr_startup() - address = %u, subnetmask = %u\n", 
		NODE_ID, interface_info_pnt->addr_range_ptr->address, interface_info_pnt->addr_range_ptr->subnet_mask);
#endif

	/* Obtain the common routing table from the IP module */

	common_routing_table = 	my_rte_module_data->ip_route_table; 
#ifdef OP_DEBUG1
	printf(" Node %d - olsr_protolib.pr.c - olsr_startup()  - rt = %ld \n", NODE_ID, common_routing_table);
#endif
		

	/* 5-3-04 - LP - move here since Get Interface Name required initializing routing table first */
	
	own_olsr_process.InitializeRoutingTable();	

	/* end LP */
	
    /* Obtain and Initialize OLSR program attributes. */

	/* Get interface name */
	char localIntfName[256]; 
	if (op_ima_sim_attr_exists("OLSR Interface name")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR Interface name",localIntfName);
		
		/* LP 5-3-04 - replaced 		
		if (!own_olsr_process.SetOlsrInterfaceAddress(localIntfName))
			DMSG(0,"error setting InterfaceAddress to %s\n",localIntfName);	
		printf("     InterfaceName =  %s\n",localIntfName);
		*/
		
		printf("      ***OLSR Interface Name simulation attribute is not supported as \n");
		printf("      ***  a command line option in OPNET.  To set the OLSR Interface Name, \n");
		printf("      ***   do it at the Network layer, via: \n");
		printf("               IP/IP router parameters/Interface Information/row nnn\n");

		}	
	else
		printf("      ***OLSR Interface Name simulation attribute not set - use default\n");

	/* Get Log File Name */
    char logFileName[PATH_MAX] = "OLSR_Log";
	if (op_ima_sim_attr_exists("OLSR Log File Name")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR Log File Name",logFileName);
		printf("     LogFileName =  %s\n",logFileName);
		/* own_olsr_process.StartLogging(logFileName); */ 
		own_olsr_process.SetOlsrDebugLog(logFileName); 
		}

	/* Get Debug Level */
	int debugLevel = 0;
	if (op_ima_sim_attr_exists("OLSR Debug Level")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_INTEGER,"OLSR Debug Level",&debugLevel);
		printf("     Debug Level =  %d\n",debugLevel);
		}	
	else
		op_ima_obj_attr_get(own_module_objid, "Debug Level", &debugLevel);
	
    ::SetDebugLevel(debugLevel); /* function from ProtoDebug.c - */
	own_olsr_process.SetOlsrDebugLevel(debugLevel); 

	
	/* Get setOLSR_all_link mode - */
	bool olsr_setOLSR_all_link_mode = OPC_FALSE;  
	if (op_ima_sim_attr_exists("OLSR Set OLSR All Links mode")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR Set OLSR All Links mode",&olsr_setOLSR_all_link_mode);
		if (olsr_setOLSR_all_link_mode == OPC_TRUE)
			if (!own_olsr_process.SetOlsrAllLinks(OPC_TRUE)) 
				DMSG(0,"Nrlolsr: odd Error in SetOlsrAllLinks(). Please send command line text to jdean@itd.nrl.navy.mil\n");
		}
	else
		printf("      ***OLSR Set OLSR All Links Mode attribute not set - use default\n");
	

	/* Get -h option to print NRLOLSR usage when running without OPnet - */
	bool olsr_h_option = OPC_FALSE;
	if (op_ima_sim_attr_exists("OLSR h")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR h",&olsr_h_option);
		if (olsr_h_option == OPC_BOOLINT_ENABLED)
			printUsage();
		}
	else
		printf("      ***OLSR help Mode attribute not set \n");

	/* Get -v option */
	bool olsr_v_option = OPC_FALSE;
	if (op_ima_sim_attr_exists("OLSR v")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR v",&olsr_v_option);
		if (olsr_v_option == OPC_BOOLINT_ENABLED)
			printf("Nrlolsr::version 6.1\n");
		}
	else
		printf("      ***OLSR -v Mode attribute not set - use default\n");
	

	double hello_int = 0.5, hello_jitter = 0.5, tc_int = 2.0, tc_jitter = 0.5;
	double hello_timeout = 6.0, tc_timeout = 5.0, hna_timeout = 90.0, hna_int = 15.0, hna_jitter = 0.1;
	int  willingness = 3;
	
	/* Get -w <willingness> option */
	if (op_ima_sim_attr_exists("OLSR Willingness")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_INTEGER,"OLSR Willingness",&willingness);
		own_olsr_process.SetOlsrWillingness(willingness);
		}	
	else
		printf("      ***OLSR Willingness simulation attribute not set - use default\n");
	
	/* Get -hna auto option - LP 3-22-04 */
	bool hna_auto_option = OPC_TRUE;
	if (op_ima_sim_attr_exists("OLSR HNA Auto")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR HNA Auto",&hna_auto_option);
		if (hna_auto_option == OPC_BOOLINT_ENABLED)
			own_olsr_process.SetOlsrHNAOff(OPC_FALSE);			
		}	
	else
		printf("      ***OLSR HNA Auto simulation attribute not set - use default\n");
	
	/* Get -hna off option - */
		bool hna_off_option = OPC_FALSE;
	if (op_ima_sim_attr_exists("OLSR HNA Off")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR HNA Off",&hna_off_option);
		if (hna_off_option == OPC_BOOLINT_ENABLED)
			own_olsr_process.SetOlsrHNAOff(OPC_TRUE);
		}	
	else
		printf("      ***OLSR HNA Off simulation attribute not set - use default\n");

	/* Get -hna file option - */
		char hna_file_name[256] = "hna_file";
	if (op_ima_sim_attr_exists("OLSR HNA File")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR HNA File",hna_file_name);
		op_ima_sim_attr_get_str("OLSR HNA File",256,hna_file_name);
		if (!own_olsr_process.SetOlsrHNAFile(hna_file_name))
			printf("Nrlolsr: Error opening %s for -OLSR HNA File option\n",hna_file_name);
		}	
	else
		printf("      ***OLSR HNA File simulation attribute not set - use default\n");
	
	/* Get Setting Broadcast Address Option -  -  */
	bool olsr_broadcast_mode = OPC_FALSE;
	char olsr_broadcast_addr_string[20], olsr_broadcast_netmask_string[20];
	if (op_ima_sim_attr_exists("OLSR Setting Broadcast Address")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR Setting Broadcast Address",&olsr_broadcast_mode);
		if (olsr_broadcast_mode == OPC_BOOLINT_ENABLED)
			{
			op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR Broadcast Address",olsr_broadcast_addr_string);
			op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR Broadcast Subnet Mask",olsr_broadcast_netmask_string);
#ifdef OP_DEBUG1
			printf("\t Broadcast Address = %s, Broadcast SubnetMask = %s\n", 
					olsr_broadcast_addr_string, olsr_broadcast_netmask_string);
#endif
			if (!own_olsr_process.SetOlsrBroadcastAddress(olsr_broadcast_addr_string,olsr_broadcast_netmask_string))
				DMSG(0,"Nrlolsr: Error setting broadcast address to:\n          Address: %s netmask %s\n",
					olsr_broadcast_addr_string,olsr_broadcast_netmask_string);	
			} /* end if broadcast mode = true */
		}
	else
		printf("      ***OLSR Broadcast Mode attribute not set - use default\n");

	/* Get Hello options */
	if (op_ima_sim_attr_exists("OLSR hello_intvl")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR hello_intvl",&hello_int);
		own_olsr_process.SetOlsrHelloInterval(hello_int);
		}	
	else
		printf("      ***OLSR hello_int simulation attribute not set - use default\n");
	
	if (op_ima_sim_attr_exists("OLSR hello_jitter")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR hello_jitter",&hello_jitter);
		own_olsr_process.SetOlsrHelloJitter(hello_jitter);
		}
	else
		printf("      ***OLSR hello_jitter simulation attribute not set - use default\n");
	
	if (op_ima_sim_attr_exists("OLSR hello_timeout_factor")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR hello_timeout_factor",&hello_timeout);
		own_olsr_process.SetOlsrHelloTimeout(hello_timeout);
		}
	else
		printf("      ***OLSR hello_timeout_factor simulation attribute not set - use default\n");

		/* Get TC options */

	if (op_ima_sim_attr_exists("OLSR tc_intvl")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR tc_intvl",&tc_int);
		own_olsr_process.SetOlsrTCInterval(tc_int);
		}	
	else
		printf("      ***OLSR tc_int simulation attribute not set - use default\n");
	
	if (op_ima_sim_attr_exists("OLSR tc_jitter")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR tc_jitter",&tc_jitter);
		own_olsr_process.SetOlsrTCJitter(tc_jitter);
		}
	else
		printf("      ***OLSR tc_jitter simulation attribute not set - use default\n");
	
	if (op_ima_sim_attr_exists("OLSR tc_timeout_factor")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR tc_timeout_factor",&tc_timeout);
		own_olsr_process.SetOlsrTCTimeout(tc_timeout);
		}
	else
		printf("      ***OLSR tc_timetout_factor simulation attribute not set - use default\n");
	
	/* Get IP-v6 option */
	int olsr_ipV6_mode = 0;
	if (op_ima_sim_attr_exists("OLSR IPv6 mode")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_INTEGER,"OLSR IPv6 mode",&olsr_ipV6_mode);
		printf("WARNING: OPNET Simulation does not activate either IPv4 or IPv6 mode of the OLSR program.  It uses SIM mode\n");
		}
	else
		printf("      ***OLSR IPv6 Mode attribute not set - use SIM mode\n");


	/* Get HNA options */
	
	if (op_ima_sim_attr_exists("OLSR HNA_intvl")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR HNA_intvl",&hna_int);
		own_olsr_process.SetOlsrHNAInterval(hna_int);
		}	
	else
		printf("      ***OLSR HNA_int simulation attribute not set - use default\n");
	
	if (op_ima_sim_attr_exists("OLSR HNA_jitter")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR HNA_jitter",&hna_jitter);
		own_olsr_process.SetOlsrHNAJitter(hna_jitter);
		}
	else
		printf("      ***OLSR HNA_jitter simulation attribute not set - use default\n");
	
	if (op_ima_sim_attr_exists("OLSR HNA_timeout_factor")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR HNA_timeout_factor",&hna_timeout);
		own_olsr_process.SetOlsrHNATimeout(hna_timeout);
		}
	else
		printf("      ***OLSR HNA_timeout_factor simulation attribute not set - use default\n");

	/* Get Hys options */
	double hys_up = 0.4, hys_down = 0.15, hys_alpha = 0.7;
	bool hys_off = OPC_FALSE, hys_on = OPC_TRUE;
	op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR Hys Up",&hys_up);
	op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR Hys Down",&hys_down);
	op_ima_sim_attr_get(OPC_IMA_DOUBLE,"OLSR Hys Alpha",&hys_alpha);
	op_ima_sim_attr_get(OPC_IMA_TOGGLE,"OLSR Hys ON",&hys_on);
	own_olsr_process.SetOlsrHysUp(hys_up);
	own_olsr_process.SetOlsrHysDown(hys_down);
	own_olsr_process.SetOlsrHysAlpha(hys_alpha);
	if (hys_on == OPC_BOOLINT_DISABLED) 
		own_olsr_process.SetOlsrHysOff(OPC_TRUE);
	else 
		own_olsr_process.SetOlsrHysOff(OPC_FALSE);

	printf(" hys_up = %lf, hys_down = %lf, hys_alpha = %lf, hys_on = %d\n",
		hys_up, hys_down, hys_alpha, hys_on); 
	
	/* Get QOS option */
	char  olsr_qos[20] = "0";
	if (op_ima_sim_attr_exists("OLSR QOS")==OPC_TRUE)
		{
		op_ima_sim_attr_get(OPC_IMA_STRING,"OLSR QOS", olsr_qos);
		own_olsr_process.SetOlsrQos(olsr_qos);
		}

	
	printf("     hello_int =     %lf\n",hello_int);
	printf("     hello_jitter =  %lf\n",hello_jitter);
	printf("     hello_timeout =  %lf\n",hello_timeout);
	printf("     tc_int =        %lf\n",tc_int);
	printf("     tc_jitter =     %lf\n",tc_jitter);
	printf("     tc_timeout =  %lf\n",tc_timeout);
	printf("     hna_int =        %lf\n",hna_int);
	printf("     hna_jitter =     %lf\n",hna_jitter);
	printf("     hna_timeout =  %lf\n",hna_timeout);
	printf("     willingness =  %d\n",willingness);
	printf("     set OLSR all link =  %d\n",olsr_setOLSR_all_link_mode);

 
    /* turn on message trace if debugLevel >= 8 */	
	if (debugLevel >= trace_min_debug_level) SetOlsrMessageTrace(OPC_TRUE);

	/* 5-3-04 - LP - move to the beginning of this function	*/
	/*
	own_olsr_process.InitializeRoutingTable();	
	*/ 
	/* end LP */
	
	/* Schedule interrupt for end of simulation.	LP 3-15-04*/
    /* op_intrpt_schedule_call (OPC_INTRPT_SCHED_CALL_ENDSIM, OPC_INT_UNDEF, olsr_rte_route_table_to_file_export, OPC_NIL);*/ /* JPH eliminated olsr_rte_route_table_to_file_export */
	op_intrpt_schedule_self (op_sim_time() + print_rt_interval, SELF_INTRT_CODE_PRINT_RT_EVENT); /* LP 3-17-04 */
	/* end LP */
	  
	
	/* trigger olsr_node_movement process is there is -move_file simulation attribute */
	// LP 10-7-05 - replaced	
	// if (op_ima_sim_attr_exists("OLSR_move_file")==OPC_TRUE)
	
	char mov_file_name[256];
	op_ima_sim_attr_get_str("OLSR_move_file", 256, (char *) mov_file_name);	
	if (strcmp (mov_file_name, "NULL") != 0)
	
	// end LP
		{
		move_process_hndl = op_pro_create ("olsr_node_movement", OPC_NIL);
		if (op_pro_invoke (move_process_hndl, OPC_NIL) == OPC_COMPCODE_FAILURE)
			printf("Node - %d - ERROR in invoking olsr_node_movement process\n", NODE_ID);
		}	
	else
		printf("      ***OLSR_move_file attribute not set - No need to read movement file\n");
	/* end LP */
	
	own_olsr_process.Start();
	
    FOUT;
}  /* end olsr_startup() */



OpnetOlsrProcess::~OpnetOlsrProcess()
	{
	/* virtual functions of the OpnetProtosimProcess class */
	}


bool OpnetOlsrProcess::OnStartup(int argc, const char*const* argv)
	{
	/* virtual functions of the OpnetProtosimProcess class */
	bool t_val = OPC_FALSE;
	return t_val;

	}

bool OpnetOlsrProcess::ProcessCommands(int argc, const char*const* argv)
	{
	/* virtual functions of the OpnetProtosimProcess class */
	return Nrlolsr::ProcessCommands(argc,argv);

	}

void OpnetOlsrProcess::OnShutdown()
	{
	/* virtual functions of the OpnetProtosimProcess class */
	}

IpT_Address OpnetOlsrProcess::GetRoute(SIMADDR dest)
	{
	/* virtual functions of the ProtoRouter class */
	IpT_Address  t_val;
	return t_val;
	}

void SetOlsrMessageTrace(bool state)
	{
	olsr_trace = state;
	}

bool OpnetOlsrProcess::InitializeRoutingTable()
	{
	FIN (OpnetOlsrProcess::InitializeRoutingTable());
	
#ifdef OP_DEBUG1
	printf("Node %d - OLSR_protolib.pr.m - OpnetOlsrProcess::IntializeRoutingTable()\n", NODE_ID);
#endif

	bool return_val = OPC_FALSE;
	/* creating routeing table  */
	routingTable_mgr = (OpnetProtoRouteMgr *) OpnetProtoRouteMgr::Create();	
	if(routingTable_mgr)
		{
		if(!routingTable_mgr->Open(common_routing_table, NODE_ID, olsr_protocol_id, interface_info_pnt))  
			{
			DMSG(0,"Node_%d - OLSR_startup(): Error Opening routing table\n", NODE_ID);
			FRET (return_val);
			}
		} 
	else 
		{
		DMSG(0,"Node_%d - OLSR_startup():  Error creating routing table\n", NODE_ID);
		FRET (return_val);
		}
	SetOlsrRouteTable((ProtoRouteMgr *) routingTable_mgr);
	FRET (return_val = OPC_TRUE);
	}

bool OpnetOlsrProcess::GetLocalAddress(ProtoAddress& localAddr) 
	{
	FIN (OpnetOlsrProcess::GetLocalAddress());
	IpT_Interface_Info * ip_intf_pnt;
	ip_intf_pnt = routingTable_mgr->GetIntfInfoPnt();
 	IpT_Address IpAddr = ip_intf_pnt->addr_range_ptr->address;
	IpT_Address IPSubnetMask = ip_intf_pnt->addr_range_ptr->subnet_mask;
	localAddr.SimSetAddress((SIMADDR)IpAddr);
#ifdef OP_DEBUG1
	printf("OpnetOlsrProcess::GetLocalAddress(my_Ip_Addr = %u)\n", IpAddr);
#endif
			
    FRET ( true);

	}

void OpnetOlsrProcess::OnReceive(Packet * pkt)
{
    FIN (OpnetOlsrProcess::OnReceive( Packet *pkt));

#ifdef OP_DEBUG1
	printf("\tNode %d olsr_protlib.pr.c - OpnetOlsrProcess::OnReceive(Packet *)\n", this->GetOlsrNodeId());
#endif
    /* Get packet from stream ZERO */
    Ici* cmd = op_intrpt_ici();
    if (OPC_NIL != cmd)
    {
        /* 1) Get packet dest port and find which local socket it goes to */
        int localPort;
        op_ici_attr_get(cmd, "local_port", &localPort);
        SocketProxy* socketProxy = socket_proxy_list.FindProxyByPort(localPort);
        if (socketProxy)
            {
            /* Get recv packet payload */
            char* recvData;
            op_pk_fd_get(pkt, 0, &recvData);
            /* Get recv packet length */
            int recvLen  = op_pk_bulk_size_get(pkt) / 8;
            /* Get source addr/port */
            IpT_Address remoteAddr;
            op_ici_attr_get(cmd, "rem_addr", &remoteAddr);
            int remotePort;
            op_ici_attr_get(cmd, "rem_port", &remotePort);

            IpT_Address localAddr;			
			op_ici_attr_get(cmd, "src_addr", &localAddr);
#ifdef OP_DEBUG1
			printf("\tolsr_protlib.pr.c - OpnetOlsrProcess::s::OnReceive() - remoteAdd - %u, localAdrr = %u\n",
				remoteAddr, localAddr);
#endif				
            ProtoAddress srcAddr;
            srcAddr.SimSetAddress(remoteAddr);
            srcAddr.SetPort(remotePort);
            ProtoAddress dstAddr;
            dstAddr.SimSetAddress(localAddr);
            dstAddr.SetPort(localPort);
            /* Pass packet content/info to socket proxy */
            static_cast<UdpSocketProxy*>(socketProxy)->OnReceive(recvData, recvLen, srcAddr, dstAddr);
			op_prg_mem_free(recvData);
            op_pk_destroy(pkt);
			
			// LP 8-30-05 - added
			if (own_olsr_process.Hello_rcv_stat_status_get() == OPNET_TRUE)
				{
//	num_hello_pk_rcv ++;
				global_num_hello_pk_rcv ++;
				num_hello_pk_rcv = own_olsr_process.total_Hello_Rcv_get();
				own_olsr_process.reset_Hello_rcv_changed_flag();
				}
			else if (own_olsr_process.TC_rcv_stat_status_get() == OPNET_TRUE)
				{
//	num_TC_pk_rcv ++;
				global_num_TC_pk_rcv ++;
				num_TC_pk_rcv = own_olsr_process.total_TC_Rcv_get();	
				own_olsr_process.reset_TC_rcv_changed_flag();
				}

			// LP 9-9-05
			if (own_olsr_process.MPR_increase_status_get() == OPNET_TRUE)
				{
				global_MRP_count ++;
				global_MRP_increase ++;
				op_stat_write (MPR_status_stathandle, 1.0);
				op_stat_write (g_MPR_count_stathandle, (double) global_MRP_count);
				own_olsr_process.reset_MPR_increased_flag();
#ifdef OP_DEBUG2
				printf("Node %d - INCREASE MPR_increase to %d at %lf\n", NODE_ID, global_MRP_increase, op_sim_time());
#endif
				global_MPR_increase_[NODE_ID] ++;  // LP 9-15-05
				}
			else if (own_olsr_process.MPR_decrease_status_get() == OPNET_TRUE)
				{
//	num_TC_pk_rcv ++;
				global_MRP_count --;
				global_MRP_decrease ++;
				op_stat_write (MPR_status_stathandle, 0.0);
				op_stat_write (g_MPR_count_stathandle, (double) global_MRP_count);
				own_olsr_process.reset_MPR_decreased_flag();
#ifdef OP_DEBUG2
				printf("Node %d - INCREASE MPR_decrease to %d at %lf\n", NODE_ID, global_MRP_decrease, op_sim_time());
#endif
				global_MPR_decrease_[NODE_ID] ++;  // LP 9-15-05
				}

// end LP

			}
		else
			op_pk_destroy(pkt); 

    }
    else
    {
        /* Generate an error and end simulation. */
	    op_sim_end ("Error: DoReceive() OPC_NIL cmd", "", "", "");
    }
	FOUT;
}  /* end OpnetOlsrProcess::OnReceive() */



/* JPH ip_cmn_rte_table_olsr_file_create removed because of use of function */
/*     ip_cmn_rte_table_export_file_header_print eliminated from            */
/*     11.0 version of ip_cmn_rte_table.ex.c                                */

/*********************************************************************/
/*                                                                   */
/*   Functions to export OLSR Routing Entry in the Common Routing    */
/*  table.                                                           */
/*                                                                   */
/*********************************************************************/

/*char*
  ip_cmn_rte_table_olsr_file_create (void)
*/


/* JPH olsr_rte_route_table_to_file_export removed because of use of function */
/*     ip_cmn_rte_table_export_num_subinterfaces_get eliminated from          */
/*     11.0 version of ip_cmn_rte_table.ex.c                                  */

/*void olsr_rte_route_table_to_file_export (void* PRG_ARG_UNUSED(state_ptr), int PRG_ARG_UNUSED(intrpt_code)) */

void printUsage()
	{
	printf("The following usage is for the Nrlolsr program that is run without OPnet\n\n");
	printf("Nrlolsr:options [-i <interfacename>][-d <debuglvl>][-l <debuglogfile>][-al][-h][-v]\n");
    printf("                 [-w <willingness>][-hna auto|<filename>|off][-b <broadaddr> <masklength>]\n");
    printf("                 [-hi <HelloInterval>][-hj <HelloJitter>][-ht <HelloTimeoutfactor>]\n");
    printf("                 [-tci <TCInterval>][-tcj <TCJitter>][-tct <TCTimeoutfactor>][-ipv6][-ipv4]\n");
    printf("                 [-hnai <HNAInterval>][-hnaj <HNAJitter>][-hnat <HNATimeoutfactor>]\n");
    printf("                 [-hys up <upvalue> | down <downvalue> | alpha <alphavalue> | on | off]\n");
    printf("                 [-qos <qosvalue>]\n\n");
    
	}


// JPH SMF - Opnet version of Nrlolsr::OnPktCapture member function extracted from nrlolsr.ex.cpp and overloaded
void Nrlolsr::OnPktCapture(smfT_olsr_ipc* ipc)
{
    if (ProtoCap::INBOUND != ipc->direction) return;
	
    // Only pay attention to UDP/IP packets for our OLSR port
	if (ipc->version != 4 && ipc->version != 6) return;
	
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

	
	
    ProtoAddress ipSrc;
    if (4 == ipc->version)
    {
        //const unsigned int IPV4_OFFSET_TYPE = 9;
        //if (IP_UDP_TYPE != buffer[ETH_HDR_LEN+IPV4_OFFSET_TYPE])
        //    continue;  // it's not a UDP packet
		
        //t unsigned int IPV4_HDR_LEN = 20;
        //    UINT16 dstPort = htons(698);  // check for OLSR port number
        //if (memcmp(&dstPort, buffer+ETH_HDR_LEN+IPV4_HDR_LEN+UDP_OFFSET_PORT_DST, 2))
        //    continue;  // it's not an OLSR (port 698) packet
				
        //if (1 != buffer[ETH_HDR_LEN+IPV4_HDR_LEN+UDP_HDR_LEN+OLSR_OFFSET_TYPE])
        //    continue;  // it's not an OLSR "hello" message
		
        //const unsigned int IPV4_OFFSET_SRC = 12;
        //ipSrc.SetRawHostAddress(ProtoAddress::IPv4, (char*)buffer+ETH_HDR_LEN+IPV4_OFFSET_SRC, 4);//this works for ipv4 because there is only one address type
		ipSrc.SetRawHostAddress(ProtoAddress::SIM, (char*)&ipc->src_ip4addr, 4);
	}
    else if (6 == ipc->version)
    {
		char* buffer;
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
					return;
				}
			case IP_UDP_TYPE:
		    	//packet contains udp information check it
				isudppacket=true;
		    	break;
			default: 
				break;
	    }
	    if(!isudppacket){
			return; //jump to next packet 
	    }

        UINT16 dstPort = htons(698);  // check for OLSR port number
        if (memcmp(&dstPort, buffer+ETH_HDR_LEN+IPV6_HDR_LEN+UDP_OFFSET_PORT_DST+header_offsets, 2))
            return;  // it's not an OLSR (port 698) packet
        if (1 != buffer[ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets+UDP_HDR_LEN+OLSR_OFFSET_TYPE])
            return;  // it's not an OLSR "hello" message so we can't verify that last hop is originator
	    ipSrc.SetRawHostAddress(ProtoAddress::IPv6, (char*)buffer+ETH_HDR_LEN+IPV6_HDR_LEN+header_offsets+UDP_HDR_LEN+OLSR_OFFSET_SRC, 16);
    }
    else
    {
        DMSG(0, "Nrlolsr::OnPktCapture() recv'd packet of unsupported IP version: %d\n", ipc->version);
        return;
    }   

    ProtoAddress macSrc;
    const unsigned int ETH_OFFSET_SRC = 6;
    macSrc.SetRawHostAddress(ProtoAddress::SIM, (char*)&ipc->tx_addr, 4);
    // Add the entry to our "ip to mac" table
    ipToMacTable.SetRoute(ipSrc, 8*ipSrc.GetLength(), macSrc);
}


// LP 9-19-05 - added

/*********************************************************************/
/*                                                                   */
/*   Functions to export OLSR Routing Entry in the Common Routing    */
/*  table.                                                           */
/*                                                                   */
/*********************************************************************/

int                                     
ip_cmn_rte_table_export_num_subinterfaces_get (struct IpT_Rte_Module_Data* ip_rmd_ptr, IpT_Rte_Protocol rt_protocol)
	{
	IpT_Interface_Info              *ip_iface_elem_ptr;
	int                             ip_rte_table_index, ip_iface_table_size;
	int                             num_interfaces = 0;     


	//** This function finds out the total number of subinterfaces on        **/
	//** this router that run the specified routing protocol. The value      **/
	//** returned would be printed out in the routing table export file      **/

	FIN (ip_cmn_rte_table_export_num_subinterfaces_get (ip_rmd_ptr, rt_protocol));

	//* Get the number of physical interfaces                                 */
	ip_iface_table_size = ip_rte_num_interfaces_get (ip_rmd_ptr);


	//* Loop over each element in the IP interface list published by         */
	//* by IP and if this interface has been assigned the process that       */
	//* invoked this function to be its routing protocol, increment           */
	for (ip_rte_table_index = 0; ip_rte_table_index < ip_iface_table_size; ip_rte_table_index++)
		{
		//* Obtain a handle on the i_th interface.                                               */
		ip_iface_elem_ptr = ip_rte_intf_tbl_access (ip_rmd_ptr, ip_rte_table_index);
		if (ip_interface_routing_protocols_contains (ip_rte_intf_routing_prot_get(ip_iface_elem_ptr) , rt_protocol) == OPC_TRUE)
				{
				++num_interfaces;
				}
		}
	FRET (num_interfaces);
	}


void
ip_cmn_rte_table_export_file_header_print (FILE* route_table_file_ptr)
	{
	/** This function prints a header into the ext. file 	**/
	/** containing routing tables. This header is printed	**/
	/** only once - when the file is created.				**/
	FIN (ip_cmn_rte_table_export_file_header_print (route_table_file_ptr));

	fprintf (route_table_file_ptr,
		"# This file contains the IP routing tables built by various routing protocols in\n");
		
	fprintf (route_table_file_ptr,
		"# the network model.\n\n");

	fprintf (route_table_file_ptr,
		"# It is intended to be used as a mechanism whereby dynamic routing information\n");

	fprintf (route_table_file_ptr,
		"# is recorded and reused to avoid running IP routing protocols in multiple\n");

	fprintf (route_table_file_ptr,
		"# simulations of the same network. This feature should be used only when router\n");

	fprintf (route_table_file_ptr,
		"# connectivities in the network (and hence their routing tables) do not change\n");

	fprintf (route_table_file_ptr,
		"# during the course of the simulation.\n\n");

	fprintf (route_table_file_ptr,
		"# This file is produced each time a simulation is run with the simulation\n");

	fprintf (route_table_file_ptr,
		"# attribute \"Routing Table Export/Import\"  set to \"Export\". Multiple runs for\n");

	fprintf (route_table_file_ptr,
		"# the same network model will successively overwrite this file.\n\n");

	fprintf (route_table_file_ptr,
		"# The contents of this file can be imported into the network model by running a\n");

	fprintf (route_table_file_ptr,
		"# simulation with the simulation attribute \"Routing Table Export/Import\" to \n");

	fprintf (route_table_file_ptr,
		"# \"Import\".\n\n");

	fprintf (route_table_file_ptr,
		"# In order for this to work correctly, there should be no change in the network\n");

	fprintf (route_table_file_ptr,
		"# whose simulation produced this file, and the network that is importing it\n");

	fprintf (route_table_file_ptr,
		"# contents. In other words, the \"Export\" scenario and the \"Import\" scenario\n");

	fprintf (route_table_file_ptr,
		"# should be the same.\n\n");

	fprintf (route_table_file_ptr,
		"# Warning: Modification of this file by the user can lead to unexpected simulation\n");

	fprintf (route_table_file_ptr,
		"# results.\n\n");

	FOUT;
	}


void
ip_cmn_rte_table_export_iface_addr_print (struct IpT_Rte_Module_Data* ip_rmd_ptr, int ip_iface_table_size, 
	FILE* routing_table_file_ptr, IpT_Rte_Protocol rt_protocol)
	{
	IpT_Interface_Info		*ip_intf_elem_ptr;
	char					addr_str [IPC_ADDR_STR_LEN];
	char					subnet_mask_str [IPC_ADDR_STR_LEN];
	int				        ip_rte_table_index;
                                 
	/** This function prints out interface information. This info will	**/
	/** be used for routing tables import to check whether the network	**/
	/** has been changed since the last routing tables export.			**/
	FIN (ip_cmn_rte_table_iface_addr_print (ip_rmd_ptr, ip_iface_table_size, 
			routing_table_file_ptr, rt_protocol));
	
	/* Loop over each element in the IP interface list published by	   */
	/* by IP and if this interface has been assigned the process that  */
	/* invoked this function to be its routing protocol, create a      */
	/* corresponding entry in the routing table	                   	   */
	for (ip_rte_table_index = 0; ip_rte_table_index < ip_iface_table_size; ip_rte_table_index++)
		{
		/* Obtain a handle on the i_th physiscal interface.				*/
		ip_intf_elem_ptr = ip_rte_intf_tbl_access (ip_rmd_ptr, ip_rte_table_index);
				
		if (ip_interface_routing_protocols_contains (ip_intf_elem_ptr->routing_protocols_lptr, rt_protocol) == OPC_TRUE)
			{
			ip_address_print (addr_str, ip_intf_elem_ptr->addr_range_ptr->address);
			ip_address_print (subnet_mask_str, 
				ip_intf_elem_ptr->addr_range_ptr->subnet_mask);
		
			fprintf (routing_table_file_ptr, "%d,%d,%s,%s\n",
				ip_intf_elem_ptr->phys_intf_info_ptr->ip_addr_index, 
				ip_intf_elem_ptr->subintf_addr_index, addr_str, subnet_mask_str);
			}
		}

	FOUT;
	}

char*
ip_cmn_rte_table_olsr_file_create (void)
	{
	static Boolean	file_created = OPC_FALSE;
	FILE*			rte_table_file_ptr;
	char			scenario_name [256];
	static char*	dir_name = OPC_NIL;
	Boolean			dir_name_obtained;
	char*			model_name;
	 
	/** This function creates a file in a user primary model **/
	/** directory. It also writes a header into the file.	 **/
	FIN (ip_cmn_rte_table_olsr_file_create  ());

	if (file_created ==  OPC_FALSE)
	    {
		/*  Get project and scenario name. Routing tables	*/
		/* will be saved in a file whose name is			*/
		/*  <project_name>-<scenario_name>-ip_routes.gdf.   */
	
		/* Get the network model name from the net_name simulation attribute */
		model_name = ip_net_name_sim_attr_get (OPC_TRUE);

		if (model_name != OPC_NIL)
			{
			/*  Add "ip_routes.gdf" to the file name 					*/
			strcpy (scenario_name, model_name);
			strcat (scenario_name, "-ip_routes_olsr.gdf");

			/* Free the memoery associated with model_name */
			op_prg_mem_free (model_name);
			
			dir_name = (char*) op_prg_mem_alloc (512 * sizeof (char));

			/* Check if memory has been allocated. */ 
			if (dir_name == OPC_NIL)
				{
				/* Report an error message and terminate the simulation	*/
				op_sim_end ("Error in IP common route table support code: ", "Could not allocate memory for dir_name variable", OPC_NIL, OPC_NIL);
				}

			/* Obtain the primary model directory so that a file could	*/
			/* be opened there.											*/
			dir_name_obtained = oms_tan_primary_model_dir_name_get (dir_name);
		
			if (dir_name_obtained != OPC_TRUE)
			    op_sim_end ("Cannot obtain the user's primary directory ", " "," ", " ");

			/* Append the file to be opened to the directory where	*/
			/* it should be created.								*/
			strcat (dir_name, "/");
			strcat (dir_name, scenario_name);
		
			/* If this is the first process that open the file, */
			/* write a header into it.							*/
			rte_table_file_ptr = fopen (dir_name, "w");
			ip_cmn_rte_table_export_file_header_print (rte_table_file_ptr);
			fclose (rte_table_file_ptr); 

			/* Mark that the file has been created and header	*/
			/* written.											*/
			file_created = OPC_TRUE;	
			}
	    }

	FRET(dir_name);
	}


void olsr_rte_route_table_to_file_export (void* PRG_ARG_UNUSED(state_ptr), int PRG_ARG_UNUSED(intrpt_code))
	{
	int							i;
	char*						file_name;
	char						dest_address_str [IPC_ADDR_STR_LEN];
	char						next_address_str [IPC_ADDR_STR_LEN];
	char						dest_smask_str [IPC_ADDR_STR_LEN];
	int							temp_list_size;
	IpT_Cmn_Rte_Table_Entry*	temp_route_ptr;
	IpT_Interface_Info*			olsr_route_ptr;
	Boolean						header_print_flag = OPC_FALSE;
	int							number_of_interfaces = 0;
    Boolean                     is_static = OPC_FALSE;
	FILE*						routing_table_file_ptr;

	/** This function prints out the contents of the OLSR routing table into an external file. **/
	/** Only entries that were also inserted into IP common routing table are printed.		  **/
	FIN (olsr_rte_route_table_to_file_export (void* state_ptr, int intrpt_code));

	/* Get project and scenario name. Routing tables will be saved in a user's  	*/
	/* primary model directory using the name "<project_name>-<scenario_name>.gdf"	*/
	file_name = ip_cmn_rte_table_olsr_file_create ();

	/* Write the contents of the table into the file (note that this is	*/
	/* done by each process.)											*/
	routing_table_file_ptr = fopen (file_name, "a");

	/* How many routing table entries do we have?	*/
	temp_list_size = ip_cmn_rte_table_num_entries_get (common_routing_table, InetC_Addr_Family_v4);
#ifdef OP_DEBUG1
	printf ("Node%d - olsr_rte_route_table_to_file_export() - temp_list_size = %d, filename = %s\n",
			NODE_ID, temp_list_size, file_name);
#endif	

	/* Loop through the routing table entries and print information on each.	*/
	for (i = 0; i < temp_list_size; i++)
		{
		/* Access the i'th routing table entry.	*/
		temp_route_ptr = ip_cmn_rte_table_access (common_routing_table, i, InetC_Addr_Family_v4);

		/* Is this an entry that was sourced by OLSR?	*/
		if (ip_cmn_rte_table_entry_src_proto_get (temp_route_ptr) != olsr_protocol_id)
			continue;

		/* Obtain a reference to the entry in OLSR's routing table that resulted	*/
		/* in the creation of this entry in the common routing table.			*/
		olsr_route_ptr = (IpT_Interface_Info*) ip_cmn_rte_table_entry_src_obj_ptr_get (temp_route_ptr);

		/* Insert the entry into the list that will be printed out.				*/
		
		if (header_print_flag == OPC_FALSE)
			{
			/* Change the flag - we do not want to print the 	*/
			/* header for each single entry.					*/
			header_print_flag = OPC_TRUE;

			/* Print the header:                                    	*/
			/* Get own hierarchical name - it will be printed out 		*/
			/* Append .ip to the node name to get the module name		*/
			char						module_name [256];
			strcpy (module_name, my_rte_module_data->node_name);
			strcat (module_name, ".olsr_protolib");
			
			/* Each routing table starts with Routing table marker	*/										
			fprintf (routing_table_file_ptr, "\nSTART_ROUTING_TABLE at %lf\n", op_sim_time());
				
			fprintf (routing_table_file_ptr, "#Module Object ID,Table Size,Number of Interfaces,Is static\n");

			/* Find the number of interfaces on which OLSR is running.						*/
			number_of_interfaces = ip_cmn_rte_table_export_num_subinterfaces_get (my_rte_module_data, IpC_Rte_OLSR_NRL);


			/* Print the number of entries in the table	and module object ID*/
			fprintf (routing_table_file_ptr, "%d,%d,%d,%d\n", own_module_objid, 
						temp_list_size, number_of_interfaces, is_static);
			fprintf (routing_table_file_ptr, "#Module Hierarchical Name:\n");
			fprintf (routing_table_file_ptr,  "%s\n", module_name);
			fprintf (routing_table_file_ptr, "#Interface Information: Interface,IP Address,Mask\n");
			
			char	addr_str [IPC_ADDR_STR_LEN];
			char	subnet_mask_str [IPC_ADDR_STR_LEN];

			ip_address_print (addr_str, olsr_route_ptr->addr_range_ptr->address);
			ip_address_print (subnet_mask_str, olsr_route_ptr->addr_range_ptr->subnet_mask);

#ifdef OP_DEBUG1
			// LP 9-20-05 - replaced since the name "addr_index" is changed in Opnet 11.0
			// printf ("\taddr_index_%u,subintef_addr_index_%u,%s,%s\n",
			//	olsr_route_ptr->phys_intf_info_ptr->addr_index, 
			//	olsr_route_ptr->subintf_addr_index, addr_str, subnet_mask_str);
			
			printf ("\taddr_index_%u,subintef_addr_index_%u,%s,%s\n",
				olsr_route_ptr->phys_intf_info_ptr->ip_addr_index, 
				olsr_route_ptr->subintf_addr_index, addr_str, subnet_mask_str);
			// end LP

#endif		
			// LP 9-20-05 - replaced since the name "addr_index" is changed in Opnet 11.0
			// fprintf (routing_table_file_ptr, "%d,%d,%s,%s\n",
			//	olsr_route_ptr->phys_intf_info_ptr->addr_index, 
			//	olsr_route_ptr->subintf_addr_index, addr_str, subnet_mask_str);
			
			fprintf (routing_table_file_ptr, "%d,%d,%s,%s\n",
				olsr_route_ptr->phys_intf_info_ptr->ip_addr_index, 
				olsr_route_ptr->subintf_addr_index, addr_str, subnet_mask_str);
			
			// end LP


			/* Print interface information. This information will be used when	*/
			/* importing routing table from an external file to check  			*/
			/* whether network has been changed.								*/
#ifdef OP_DEBUG1
			printf ("\tip_rte_num_interfaces_get = %d\n", ip_rte_num_interfaces_get (my_rte_module_data));
#endif
			ip_cmn_rte_table_export_iface_addr_print (my_rte_module_data, ip_rte_num_interfaces_get (my_rte_module_data), 
				routing_table_file_ptr, IpC_Rte_OLSR_NRL);

			fprintf (routing_table_file_ptr, "#OLSR Routing Table Contents:\n");
			fprintf (routing_table_file_ptr, "#-----------------------------------------------------------------\n");
			fprintf (routing_table_file_ptr, "# Dest Network,Dest Net Mask, Metric, Next Hop Addr, \n");
			fprintf (routing_table_file_ptr, "#-----------------------------------------------------------------\n");
			}  // end if header floag = False
		
				/* Change addresses to printable form (x.x.x.x).	*/
		ip_address_print (dest_address_str, ip_cmn_rte_table_entry_dest_get(temp_route_ptr));
		ip_address_print (dest_smask_str, ip_cmn_rte_table_entry_mask_get(temp_route_ptr)); 
		
			// Assume that we only have 1 hop per routing table entry
		IpT_Next_Hop_Entry * next_hop_entry_;
		next_hop_entry_ = (IpT_Next_Hop_Entry * ) op_prg_list_access(temp_route_ptr->next_hop_list, OPC_LISTPOS_HEAD);
		ip_address_print (next_address_str, inet_ipv4_address_get(next_hop_entry_->next_hop));
		
		// LP 9-20-05 - replaced
		// fprintf (routing_table_file_ptr, "%s,%s,%d,%s\n", 
		//	dest_address_str, dest_smask_str, temp_route_ptr->route_metric, next_address_str);

			fprintf (routing_table_file_ptr, "%s,%s,%d,%s\n", 
				dest_address_str, dest_smask_str, next_hop_entry_->route_metric, next_address_str);
		// end LP

		} // end for i

				
	/* Print the end marker for the table.	*/	
	if (header_print_flag == OPC_TRUE)
		fprintf (routing_table_file_ptr, "END_ROUTING_TABLE\n\n"); 


	/*  Close the file							*/ 			 
	fclose (routing_table_file_ptr);
	FOUT;
	}


/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

/* Undefine shortcuts to state variables because the */
/* following functions are part of the state class */
#undef bits_rcvd_stathandle
#undef bitssec_rcvd_stathandle
#undef pkts_rcvd_stathandle
#undef pktssec_rcvd_stathandle
#undef ete_delay_stathandle
#undef bits_sent_stathandle
#undef bitssec_sent_stathandle
#undef pkts_sent_stathandle
#undef pktssec_sent_stathandle
#undef mpr_list_sent_stathandle
#undef num_hello_pk_sent_stathandle
#undef num_TC_pk_sent_stathandle
#undef MPR_status_stathandle
#undef NODE_ID
#undef own_olsr_process
#undef olsr_protocol_id
#undef own_module_objid
#undef own_node_objid
#undef own_prohandle
#undef own_process_record_handle
#undef interface_info_pnt
#undef common_routing_table
#undef olsr_port_info
#undef udp_command_ici_ptr
#undef my_udp_objid
#undef my_smf_objid
#undef my_rte_module_data
#undef move_process_hndl
#undef smf_support
#undef num_hello_pk_sent
#undef num_hello_pk_rcv
#undef num_TC_pk_sent
#undef num_TC_pk_rcv

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_olsr_protolib_smf_init (int * init_block_ptr);
	VosT_Address _op_olsr_protolib_smf_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int);
	void olsr_protolib_smf (OP_SIM_CONTEXT_ARG_OPT)
		{
		((olsr_protolib_smf_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->olsr_protolib_smf (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_olsr_protolib_smf_svar (void *, const char *, void **);

	void _op_olsr_protolib_smf_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((olsr_protolib_smf_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_olsr_protolib_smf_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_olsr_protolib_smf_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (olsr_protolib_smf_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


	VosT_Obtype Vos_Define_Object_Prstate (const char * _op_name, unsigned int _op_size);
	VosT_Address Vos_Alloc_Object_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype _op_ob_hndl);
	VosT_Fun_Status Vos_Poolmem_Dealloc_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Address _op_ob_ptr);
} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
olsr_protolib_smf_state::olsr_protolib_smf (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (olsr_protolib_smf_state::olsr_protolib_smf ());
	try
		{
		/* Temporary Variables */
		Packet*				pkptr;
		Ici*				iciptr;
		Ici*				ici_ptr;
		double				pk_size;
		double				ete_delay;
		char				proc_model_name [128];
		List*			 	proc_record_handle_list_ptr;
		OmsT_Pr_Handle	 	ip_proc_record_handle;
		IpT_Info*		 	ip_info_ptr; 
		
		/* LP 4-19 commented out*/
		/* 
		struct hello_message hellopack; 
		struct sockaddr_in 	from;
		IpT_Address			src_ip_addr;
		int 				cc,i;
		int					intrpt_code;
		Objid				strm_objid;
		struct olsr*		inbuf_ptr;
		*/
		/* End of Temporary Variables */


		FSM_ENTER ("olsr_protolib_smf")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (proc_msg) enter executives **/
			FSM_STATE_ENTER_FORCED (0, "proc_msg", state0_enter_exec, "olsr_protolib_smf [proc_msg enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [proc_msg enter execs]", state0_enter_exec)
				{
#if OP_DEBUG1
				printf("Node %d - OLSR_protolib - Enter Proc_msg State\n", NODE_ID);
#endif
				       
				         
				/* Obtain the incoming packet.	*/
				pkptr = op_pk_get (op_intrpt_strm ());
				/*iciptr = op_intrpt_ici (); */
				/* save packet id for debugging */
				/*inpktid = op_pk_id (pkptr);  */
				
				/* Caclulate metrics to be updated.		*/
				pk_size = (double) op_pk_total_size_get (pkptr);
				ete_delay = op_sim_time () - op_pk_creation_time_get (pkptr);
				
				/* Update local statistics.				*/
				op_stat_write (bits_rcvd_stathandle, 		pk_size);
				op_stat_write (pkts_rcvd_stathandle, 		1.0);
				op_stat_write (ete_delay_stathandle, 		ete_delay);
				
				op_stat_write (bitssec_rcvd_stathandle, 	pk_size);
				op_stat_write (bitssec_rcvd_stathandle, 	0.0);
				op_stat_write (pktssec_rcvd_stathandle, 	1.0);
				op_stat_write (pktssec_rcvd_stathandle, 	0.0);
				
				/* Update global statistics.	*/
				/* LP 6-14-04 - commented out to test */
				/*
				op_stat_write (bits_rcvd_gstathandle, 		pk_size);
				op_stat_write (pkts_rcvd_gstathandle, 		1.0);
				op_stat_write (ete_delay_gstathandle, 		ete_delay);
				
				op_stat_write (bitssec_rcvd_gstathandle, 	pk_size);
				op_stat_write (bitssec_rcvd_gstathandle, 	0.0);
				op_stat_write (pktssec_rcvd_gstathandle, 	1.0);
				op_stat_write (pktssec_rcvd_gstathandle, 	0.0);
				*/ 
				/* end LP */
				
				/* LP 3-15-04- replaced to look at packet for handling the Opnet statistic */
				/*  before processing */
				/*  own_olsr_process.OnReceive(); */
				
				/* printf("Node %d - calling own_olsr_process.Onreceive \n", own_olsr_process.GetOlsrNodeId()); */
				own_olsr_process.OnReceive(pkptr);
				
				/* end LP */
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** state (proc_msg) exit executives **/
			FSM_STATE_EXIT_FORCED (0, "proc_msg", "olsr_protolib_smf [proc_msg exit execs]")


			/** state (proc_msg) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "proc_msg", "idle", "olsr_protolib_smf [proc_msg -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "init", state1_enter_exec, "olsr_protolib_smf [init enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [init enter execs]", state1_enter_exec)
				{
				
				/* Initialize the state variable */
				
				olsr_sv_init();
				//printf("Node %d - olsr_protolib.pr.c - Enter INIT state- my module_objid = %ld, olsrProc = %ld &olsrProc = %ld\n", 
				//	NODE_ID, own_module_objid, own_olsr_process, &own_olsr_process);
				
				
				
				/* Initilaize the GLOBAL statistic handles to keep	*/
				/* track of traffic sinked by this process.	*/
				
				/* LP 6-14-04 - Change the name of the Global Stats by prefix a "G_" to the old names */
				/* LP 6-14-04 - commented out to test */
				/*
				bits_rcvd_gstathandle 		= op_stat_reg ("OLSR.G_Traffic Received (bits)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				bitssec_rcvd_gstathandle 	= op_stat_reg ("OLSR.G_Traffic Received (bits/sec)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				pkts_rcvd_gstathandle 		= op_stat_reg ("OLSR.G_Traffic Received (packets)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				pktssec_rcvd_gstathandle 	= op_stat_reg ("OLSR.G_Traffic Received (packets/sec)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				ete_delay_gstathandle		= op_stat_reg ("OLSR.G_End-to-End Delay (seconds)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				
				
				bits_sent_gstathandle 		= op_stat_reg ("OLSR.G_Traffic Sent (bits)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				bitssec_sent_gstathandle 	= op_stat_reg ("OLSR.G_Traffic Sent (bits/sec)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				pkts_sent_gstathandle 		= op_stat_reg ("OLSR.G_Traffic Sent (packets)",	 OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				pktssec_sent_gstathandle 	= op_stat_reg ("OLSR.G_Traffic Sent (packets/sec)", OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
				*/
				
				/* end LP */
				
				udp_command_ici_ptr = op_ici_create("udp_command_v3");
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"olsr_protolib_smf")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "init", "olsr_protolib_smf [init exit execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [init exit execs]", state1_exit_exec)
				{
				
				/* printf("Node %d - olsr_protolib.pr.c - Exit INIT state\n", NODE_ID); */
				
				/* If woke up by the IP module, complete initialization steps dependent on */
				/* lower layer modules (e.g., UDP/IP) and start the OLSR process.  If not, */
				/* continue to wait */
				
				if (op_intrpt_type () == OPC_INTRPT_REMOTE)
					{
					OLSR_startup();
					     
					/* schedule first hello message transmission */
					
					/* LP 6-13-04 - commented out - we may not need this */
					
					/* op_intrpt_schedule_self(op_dist_uniform(1.0),STARTUP_INTRPT); */
					
					/* end LP */
					
					}
					
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (init) transition processing **/
			FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [init trans conditions]", state1_trans_conds)
			FSM_INIT_COND (IP_NOTIFICATION)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("init")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 2, state2_enter_exec, ;, "IP_NOTIFICATION", "", "init", "idle", "olsr_protolib_smf [init -> idle : IP_NOTIFICATION / ]")
				FSM_CASE_TRANSIT (1, 1, state1_enter_exec, ;, "default", "", "init", "init", "olsr_protolib_smf [init -> init : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "idle", state2_enter_exec, "olsr_protolib_smf [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"olsr_protolib_smf")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "idle", "olsr_protolib_smf [idle exit execs]")


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [idle trans conditions]", state2_trans_conds)
			FSM_INIT_COND (MESSAGE_RECEIVED)
			FSM_TEST_COND (TIMEOUT_EVENT)
			FSM_TEST_COND (PRINT_RT_EVENT)
			FSM_TEST_COND (PACKET_CAPTURE)
			FSM_TEST_COND (END_SIM)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state2_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 0, state0_enter_exec, ;, "MESSAGE_RECEIVED", "", "idle", "proc_msg", "olsr_protolib_smf [idle -> proc_msg : MESSAGE_RECEIVED / ]")
				FSM_CASE_TRANSIT (1, 3, state3_enter_exec, ;, "TIMEOUT_EVENT", "", "idle", "itimer", "olsr_protolib_smf [idle -> itimer : TIMEOUT_EVENT / ]")
				FSM_CASE_TRANSIT (2, 4, state4_enter_exec, ;, "PRINT_RT_EVENT", "", "idle", "print_rt", "olsr_protolib_smf [idle -> print_rt : PRINT_RT_EVENT / ]")
				FSM_CASE_TRANSIT (3, 5, state5_enter_exec, ;, "PACKET_CAPTURE", "", "idle", "proc_pcap", "olsr_protolib_smf [idle -> proc_pcap : PACKET_CAPTURE / ]")
				FSM_CASE_TRANSIT (4, 6, state6_enter_exec, ;, "END_SIM", "", "idle", "end_sim", "olsr_protolib_smf [idle -> end_sim : END_SIM / ]")
				FSM_CASE_TRANSIT (5, 2, state2_enter_exec, ;, "default", "", "idle", "idle", "olsr_protolib_smf [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (itimer) enter executives **/
			FSM_STATE_ENTER_FORCED (3, "itimer", state3_enter_exec, "olsr_protolib_smf [itimer enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [itimer enter execs]", state3_enter_exec)
				{
				/* printf("Node %d - Itimer State - own_olsr_process = %ld\n", NODE_ID, own_olsr_process); */
				/* printf("Node %d - calling own_olsr_process.OnSystemTimeOut \n", own_olsr_process.GetOlsrNodeId()); */
				own_olsr_process.OnSystemTimeout();
				 
				// LP 8-31-05 - added
				if (own_olsr_process.Hello_sent_stat_status_get() == OPNET_TRUE)
					{
					global_num_hello_pk_sent ++;
					num_hello_pk_sent = own_olsr_process.total_Hello_Sent_get();
					own_olsr_process.reset_Hello_sent_changed_flag();
					op_stat_write (num_hello_pk_sent_stathandle,  1.0);
								//	op_stat_write (num_hello_pk_sent_stathandle, (double) num_hello_pk_sent);
				//	op_stat_write (num_hello_pk_sent_stathandle, (double) 0);
				//	op_stat_write (g_num_hello_pk_sent_stathandle, (double) global_num_hello_pk_sent);
					op_stat_write (g_num_hello_pk_sent_stathandle, 1.0);
				//	op_stat_write (g_num_hello_pk_sent_stathandle, (double) 0);
					}
				else if (own_olsr_process.TC_sent_stat_status_get() == OPNET_TRUE)
					{
					global_num_TC_pk_sent ++;
					num_TC_pk_sent = own_olsr_process.total_TC_Sent_get();	
					own_olsr_process.reset_TC_sent_changed_flag();
					op_stat_write (num_TC_pk_sent_stathandle, (double) 1);
				//	op_stat_write (num_TC_pk_sent_stathandle, (double) 0);
					op_stat_write (g_num_TC_pk_sent_stathandle, (double) 1.0);
				//	op_stat_write (g_num_TC_pk_sent_stathandle, (double) 0);
					}
								
				// end LP
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** state (itimer) exit executives **/
			FSM_STATE_EXIT_FORCED (3, "itimer", "olsr_protolib_smf [itimer exit execs]")


			/** state (itimer) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "itimer", "idle", "olsr_protolib_smf [itimer -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (print_rt) enter executives **/
			FSM_STATE_ENTER_FORCED (4, "print_rt", state4_enter_exec, "olsr_protolib_smf [print_rt enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [print_rt enter execs]", state4_enter_exec)
				{
				/*olsr_rte_route_table_to_file_export(OPC_NIL, OPC_NIL);*/ /* JPH 11.0 - eliminated olsr_rte_route_table_to_file_export */
				olsr_rte_route_table_to_file_export(OPC_NIL, OPC_NIL); // LP 9-20-05 - added
				op_intrpt_schedule_self (op_sim_time() + print_rt_interval, SELF_INTRT_CODE_PRINT_RT_EVENT); 
					
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** state (print_rt) exit executives **/
			FSM_STATE_EXIT_FORCED (4, "print_rt", "olsr_protolib_smf [print_rt exit execs]")


			/** state (print_rt) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "print_rt", "idle", "olsr_protolib_smf [print_rt -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (proc_pcap) enter executives **/
			FSM_STATE_ENTER_FORCED (5, "proc_pcap", state5_enter_exec, "olsr_protolib_smf [proc_pcap enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [proc_pcap enter execs]", state5_enter_exec)
				{
#if OP_DEBUG1
				printf("Node %d - OLSR_protolib - Enter Proc_pcap State\n", NODE_ID);
#endif
				       
				         
				/* Obtain the incoming packet.	*/
				Ici* iciptr = op_intrpt_ici();
				
				smfT_olsr_ipc* ipcptr;
				op_ici_attr_get_ptr(iciptr,"pcap",(void**)&ipcptr);
				
				own_olsr_process.OnPktCapture(ipcptr);
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** state (proc_pcap) exit executives **/
			FSM_STATE_EXIT_FORCED (5, "proc_pcap", "olsr_protolib_smf [proc_pcap exit execs]")


			/** state (proc_pcap) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "proc_pcap", "idle", "olsr_protolib_smf [proc_pcap -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (end_sim) enter executives **/
			FSM_STATE_ENTER_FORCED (6, "end_sim", state6_enter_exec, "olsr_protolib_smf [end_sim enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_protolib_smf [end_sim enter execs]", state6_enter_exec)
				{
				printf("****************************************************************\n");
				printf("*                                                              *\n");
				printf("*                 NODE %d  - STATISTIC                         *\n", NODE_ID);
				printf("*                                                              *\n");
				printf("*   GLOBAL:                                                    *\n");
				printf("*     g_num_hello_pk_sent = %d     g_num_hello_pk_rcv = %d     *\n",
				    global_num_hello_pk_sent, global_num_hello_pk_rcv) ;
				printf("*     g_num_TC_pk_sent = %d     g_num_TC_pk_rcv = %d     *\n",
				    global_num_TC_pk_sent, global_num_TC_pk_rcv) ;
				printf("*     g_MPR_COUNT =    %d   MPR_incr = %d    MPR_decr = %d     *\n", 
					global_MRP_count, global_MRP_increase, global_MRP_decrease);
				printf("*      MPR_incr = %d    MPR_decr = %d                          *\n", 
					global_MPR_increase_[NODE_ID], global_MPR_decrease_[NODE_ID]);
				
				printf("*                                                              *\n");
				printf("*   LOCAL:                                                     *\n");
				printf("*     num_hello_pk_sent = %d     num_hello_pk_rcv = %d         *\n",
				    num_hello_pk_sent, num_hello_pk_rcv) ;
				printf("*     num_TC_pk_sent = %d        num_TC_pk_rcv = %d            *\n",
				    num_TC_pk_sent, num_TC_pk_rcv) ;
				printf("*                                                              *\n");
				printf("****************************************************************\n");
				 
				}
				FSM_PROFILE_SECTION_OUT (state6_enter_exec)

			/** state (end_sim) exit executives **/
			FSM_STATE_EXIT_FORCED (6, "end_sim", "olsr_protolib_smf [end_sim exit execs]")


			/** state (end_sim) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "end_sim", "idle", "olsr_protolib_smf [end_sim -> idle : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (1,"olsr_protolib_smf")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (olsr_protolib_smf)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
olsr_protolib_smf_state::_op_olsr_protolib_smf_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
#if defined (OPD_ALLOW_ODB)
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__+1;
#endif

	FIN_MT (olsr_protolib_smf_state::_op_olsr_protolib_smf_diag ())

	try
		{
		/* Temporary Variables */
		Packet*				pkptr;
		Ici*				iciptr;
		Ici*				ici_ptr;
		double				pk_size;
		double				ete_delay;
		char				proc_model_name [128];
		List*			 	proc_record_handle_list_ptr;
		OmsT_Pr_Handle	 	ip_proc_record_handle;
		IpT_Info*		 	ip_info_ptr; 
		
		/* LP 4-19 commented out*/
		/* 
		struct hello_message hellopack; 
		struct sockaddr_in 	from;
		IpT_Address			src_ip_addr;
		int 				cc,i;
		int					intrpt_code;
		Objid				strm_objid;
		struct olsr*		inbuf_ptr;
		*/
		/* End of Temporary Variables */

		/* Diagnostic Block */

		BINIT
		   

		/* End of Diagnostic Block */

		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (olsr_protolib_smf)",
			"In Diagnostic Block",
			(const char *)VOSC_NIL);
		}

	FOUT
#endif /* OPD_ALLOW_ODB */
	}

void
olsr_protolib_smf_state::operator delete (void* ptr)
	{
	FIN (olsr_protolib_smf_state::operator delete (ptr));
	Vos_Poolmem_Dealloc_MT (OP_SIM_CONTEXT_THREAD_INDEX_COMMA ptr);
	FOUT
	}

olsr_protolib_smf_state::~olsr_protolib_smf_state (void)
	{

	FIN (olsr_protolib_smf_state::~olsr_protolib_smf_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
olsr_protolib_smf_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (olsr_protolib_smf_state::operator new ());

	new_ptr = Vos_Alloc_Object_MT (VOS_THREAD_INDEX_UNKNOWN_COMMA olsr_protolib_smf_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

olsr_protolib_smf_state::olsr_protolib_smf_state (void) :
		_op_current_block (2)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "olsr_protolib_smf [init enter execs]";
#endif
	}

VosT_Obtype
_op_olsr_protolib_smf_init (int * init_block_ptr)
	{
	FIN_MT (_op_olsr_protolib_smf_init (init_block_ptr))

	olsr_protolib_smf_state::obtype = Vos_Define_Object_Prstate ("proc state vars (olsr_protolib_smf)",
		sizeof (olsr_protolib_smf_state));
	*init_block_ptr = 2;

	FRET (olsr_protolib_smf_state::obtype)
	}

VosT_Address
_op_olsr_protolib_smf_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	olsr_protolib_smf_state * ptr;
	FIN_MT (_op_olsr_protolib_smf_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new olsr_protolib_smf_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new olsr_protolib_smf_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_olsr_protolib_smf_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	olsr_protolib_smf_state		*prs_ptr;

	FIN_MT (_op_olsr_protolib_smf_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (olsr_protolib_smf_state *)gen_ptr;

	if (strcmp ("bits_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bits_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("bitssec_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bitssec_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("pkts_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("pktssec_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pktssec_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("ete_delay_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ete_delay_stathandle);
		FOUT
		}
	if (strcmp ("bits_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bits_sent_stathandle);
		FOUT
		}
	if (strcmp ("bitssec_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bitssec_sent_stathandle);
		FOUT
		}
	if (strcmp ("pkts_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_sent_stathandle);
		FOUT
		}
	if (strcmp ("pktssec_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pktssec_sent_stathandle);
		FOUT
		}
	if (strcmp ("mpr_list_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->mpr_list_sent_stathandle);
		FOUT
		}
	if (strcmp ("num_hello_pk_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_hello_pk_sent_stathandle);
		FOUT
		}
	if (strcmp ("num_TC_pk_sent_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_TC_pk_sent_stathandle);
		FOUT
		}
	if (strcmp ("MPR_status_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->MPR_status_stathandle);
		FOUT
		}
	if (strcmp ("NODE_ID" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->NODE_ID);
		FOUT
		}
	if (strcmp ("own_olsr_process" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_olsr_process);
		FOUT
		}
	if (strcmp ("olsr_protocol_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->olsr_protocol_id);
		FOUT
		}
	if (strcmp ("own_module_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_module_objid);
		FOUT
		}
	if (strcmp ("own_node_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_node_objid);
		FOUT
		}
	if (strcmp ("own_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_prohandle);
		FOUT
		}
	if (strcmp ("own_process_record_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_process_record_handle);
		FOUT
		}
	if (strcmp ("interface_info_pnt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->interface_info_pnt);
		FOUT
		}
	if (strcmp ("common_routing_table" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->common_routing_table);
		FOUT
		}
	if (strcmp ("olsr_port_info" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->olsr_port_info);
		FOUT
		}
	if (strcmp ("udp_command_ici_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->udp_command_ici_ptr);
		FOUT
		}
	if (strcmp ("my_udp_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_udp_objid);
		FOUT
		}
	if (strcmp ("my_smf_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_smf_objid);
		FOUT
		}
	if (strcmp ("my_rte_module_data" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_rte_module_data);
		FOUT
		}
	if (strcmp ("move_process_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->move_process_hndl);
		FOUT
		}
	if (strcmp ("smf_support" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->smf_support);
		FOUT
		}
	if (strcmp ("num_hello_pk_sent" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_hello_pk_sent);
		FOUT
		}
	if (strcmp ("num_hello_pk_rcv" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_hello_pk_rcv);
		FOUT
		}
	if (strcmp ("num_TC_pk_sent" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_TC_pk_sent);
		FOUT
		}
	if (strcmp ("num_TC_pk_rcv" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_TC_pk_rcv);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

