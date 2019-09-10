/* ip_rte_support.h */
/* Internal definitions file for IP routing procedures. 		*/
/* These are used only by ip_dispatch.pr.m and its associated	*/
/* child process models.										*/

/****************************************/
/* 	     Copyright (c) 1987-2006    	*/
/*		by OPNET Technologies, Inc.		*/
/*		(A Delaware Corporation)		*/
/*	7255 Woodmont Av., Suite 250  		*/
/*     Bethesda, MD 20814, U.S.A.       */
/*			All Rights Reserved.		*/
/****************************************/

#ifndef HDR_IP_RTE_SUPPORT_H
#define HDR_IP_RTE_SUPPORT_H

#include "opnet.h"
#include "ip_dgram_sup.h"
#include "ip_rte_v4.h"
#include "ip_rte_sup_v4.h"
#include "ip_addr_v4.h"
#include "oms_devices.h"
#include "oms_qm.h"
#include "oms_bgutil.h"
#include "oms_dist_support.h"
#include "ip_cmn_rte_table.h"
#include "ip_notif_log_support.h"
#include "ip_qos_notif_log_support.h"
#include "ip_frag_sup_v3.h"
#include "ip_vpn_support.h"
#include "ip_igmp_support.h"
#include "ip_acl_support.h"
#include "ip_rte_map_support.h"
#include "oms_load_balancer.h"
#include "oms_load_balancer.h"
#include "mpls_support.h"
#include "mpls_igp_interface_defs.h"
#include "ipv6_dest_cache.h"
#include "aodv.h"
#include "mipv6_defs.h"
#include "haipe_support.h"

/* Default redistribution API headers */
/* #include <dci_redistribution.h> */

#if defined (__cplusplus)
extern "C" {
#endif

/* Enumerated types describing the multicast routing	*/
/* protocol that can be specified.						*/
typedef enum IpT_Rte_Mcast_Rte_Proto_Type
	{
	IpC_Rte_Pim_Sm = 0,
	IpC_Rte_Custom_Mrp
	} IpT_Rte_Mcast_Rte_Proto_Type;

/* Enumerated type indicating the various packet formats*/
/* that can be handled at the IP module.				*/
typedef enum IpT_Packet_Format
	{
	IpC_Packet_Format_Ip_Dgram,
	IpC_Packet_Format_Lacp_Pdu,
	IpC_Packet_Format_Invalid
	} IpT_Packet_Format;

/* Action taken when adding/removing link header.	*/
typedef enum IpT_Header_Adjust_Action
	{
	IpC_Header_Remove = -1,
	IpC_Header_Add = 1
	} IpT_Header_Adjust_Action;

/* Flags indicating the nature of IP transmission	*/
/* if the packet being processed is to be sent to	*/
/* the network.										*/
#define IPC_PKT_TXTYPE_UCAST		1
#define IPC_PKT_TXTYPE_MCAST		2
#define IPC_PKT_TXTYPE_BCAST 		3

/* Default value for the time-to-live counter.		*/
/* This value is assigned when a packet is received	*/
/* which does not already have a ttl field.			*/
#define IPC_DEFAULT_TTL				32

#define	IPC_ADDR_INDEX_INVALID			-1
#define IPC_SRC_ADDR_UNDEFINED			-1
#define IPC_NEIGHBOR_NOTIFICATION		-1
#define IPC_BROADCAST_ALL_INTERFACES    -1
#define IPC_OUTSTRM_INVALID				-1
#define IPC_INTF_INDEX_INVALID			-50
#define IPC_SUBINTF_INDEX_INVALID		-50
#define IPC_INTF_TBL_INDEX_NULL0		-10
#define IPC_INTF_TBL_INDEX_LSP      	-20
#define IPC_INTF_TBL_INDEX_LDP_BIND		-30
#define IPC_INTF_TBL_INDEX_MPLS			-40
#define IPC_MCAST_MAJOR_PORT_INVALID	IPC_INTF_INDEX_INVALID
#define IPC_MCAST_ALL_MAJOR_PORTS	    -60

/* ManetT_Info related  */
#define	MANETC_PACKET_ARRIVAL			0
#define MANETC_DATA_ROUTE				1

/* Default value of tunnel interface index			*/
/* used in the ip_arp_ind_v4 ici format.			*/
#define IPC_TUNNEL_INTF_INDEX_NOT_USED	-50

/* Value of tunnel index indicating that a matching	*/
/* tunnel interface could not be found.				*/
#define IPC_TUNNEL_INTF_INDEX_NOT_FOUND	-1

/* Size of the part of TCP/IP Header in bits that	*/
/* can be compressed by using the TCP/IP Header		*/
/* Compression approach described in RFC 1144.		*/
/* Returns 320 bits (20 bytes for TCP header + 		*/
/* 20 bytes for IP header) if IPv4 and 480 bits 	*/
/* (20 bytes for TCP header + 40 bytes for IP 		*/
/* header) if IPv6									*/ 
#define IPC_TCP_COMPRESSABLE_HEADER_SIZE(_addr_family) (_addr_family == InetC_Addr_Family_v4) ? 320 : 480

#define LTRACE_COMPRESSION_ACTIVE	(op_prg_odb_ltrace_active ("ip_compression"))

#define LTRACE_IP_ACTIVE	(op_prg_odb_ltrace_active ("ip_rte") == OPC_TRUE)

/* Special slot values */
#define CENTRAL_CPU 1
#define SLOT_TO_CENTRAL_FORWARD	-2

/* Metric used with a static route entry.	*/
#define IPC_STATIC_RTE_METRIC         		0

/* Default link rate used for interfaces with no    */
/* links connected to them.                         */
#define	IPC_UNSPECIFIED_RATE		        1.0E+15 

/* Node level flags.			*/
#define IPC_NODE_FLAG_LAN			(0x01 << 0)
#define IPC_NODE_FLAG_FIREWALL		(0x01 << 1)
#define IPC_NODE_FLAG_CACHE_SERVER	(0x01 << 2)
#define	IPC_NODE_FLAG_MCAST_ROUTER	(0x01 << 3)
#define IPC_NODE_FLAG_CLOUD			(0x01 << 4)
#define IPC_NODE_FLAG_DUAL_MSFC_DRM	(0x01 << 5)
#define IPC_NODE_FLAG_IOS_XR		(0x01 << 6)
#define IPC_NODE_FLAG_HAIPE			(0x01 << 7)

#if defined (__cplusplus)
} /* stop 'extern C' to avoid requiring it for these definitions */
#endif

typedef void (*IpT_Rte_Cloud_Packet_Send_Proc)(void * cloud_info_ptr, 
	Packet * pkptr, int oustrm, double speed, int interface_type,
	InetT_Address dest_addr, InetT_Address next_addr, int conn_class, int minor_port);

/* Used for problem reporting with appropriate process model name */
typedef void (*IpT_Rte_Error_Proc)(const char * msg);
typedef void (*IpT_Rte_Warning_Proc)(const char * msg);
#if defined (__cplusplus)
extern "C" {
#endif


/* Stores IP interface QoS information. */
typedef struct IpT_Rte_Iface_QoS_Data
	{
	/* Store the incoming Marking information for the interface. */
	OmsT_Qm_Marking_Information *  marking_incoming_info_ptr;	
	/* Store the outgoing Marking information for the interface. */
	OmsT_Qm_Marking_Information *  marking_outgoing_info_ptr;	
	/* Store the incoming CAR profile for the interface.	 */
	OmsT_Qm_Car_Profile *		car_incoming_profile_ptr;
	/* Stores the traffic status (token bucket size) for each	 */
	/* COS (Class of Service in each incoming CAR profile.		 */
	OmsT_Qm_Car_Information *	car_incoming_info_ptr;
	/* Store the outgoing CAR profile for the interface.	 */
	OmsT_Qm_Car_Profile *		car_outgoing_profile_ptr;
	/* Stores the traffic status (token bucket size) for each	 */
	/* COS (Class of Service) in each outgoing CAR profile.		 */
	OmsT_Qm_Car_Information *	car_outgoing_info_ptr;
	/* Store the CAR stathandles for the interface.	 */
	OmsT_Qm_Car_Stat_Info *		car_stat_info_ptr;
	} IpT_Rte_Iface_QoS_Data;

typedef struct IpT_Load_Balancer_Info
	{
	Prohandle                   prohandle;
	} IpT_Load_Balancer_Info;

typedef struct IpT_Gtp_Info
	{
	Objid						gtp_objid;
	} IpT_Gtp_Info;

typedef struct IpT_Manet_Info
	{
	Prohandle					mgr_prohandle;
	IpT_Rte_Protocol			rte_protocol;
	AodvT_Route_Table*			aodv_route_table_ptr; 
	Boolean						manet_gateway_status;	
	} IpT_Manet_Info;

typedef struct IpT_Mpls_Info
	{
	Prohandle						mgr_prohandle;
	List*							fecs_lptr;
	MplsT_Label_Space_Handle*		lib_space_table_ptr;
	Boolean							label_space_global;
	MplsT_Support_IGP_Callback_Proc	igp_callback_proc;
	List*							igp_shortcut_lsps_lptr;
	} IpT_Mpls_Info;

typedef struct IpT_Mip_Info
	{
	Prohandle		mgr_phndl;
	} IpT_Mip_Info;

/* Data stored for MIPv6 support.	*/
typedef struct IpT_Mipv6_Info
	{		
	Mipv6T_Node_Type					node_type;					/* MIPv6 node type.					*/
	InetT_Address						home_agent_addr;			/* Home Agent Addres.				*/
	Boolean								out_of_home;				/* Flag that indicates when the		*/
																	/* node is out of its home network.	*/
	Mipv6T_Bind_Cache_Hash_Table*		binding_cache_hashtbl_ptr;	/* Binding Cache Table (binary hash	*/
																	/* table).							*/
	Mipv6T_Bind_Update_List_Hash_Table*	binding_update_hashtbl_ptr;	/* Binding Update List (binary hash	*/
																 	/* table).							*/
	Prohandle							mipv6_prohandle;			/* MIPv6 manager process.			*/
	Prohandle							mipv6_mn_prohandle;			/* MIPv6 mobile node process.		*/
	InetT_Address*						care_of_addr_ptr;			/* Current CoA for the mobile node.	*/
	InetT_Address						home_addr;					/* Home Addres of the mobile node.	*/
	List*								bind_update_list_lptr;		/* List of key for the binding 		*/
																	/* update list.						*/
	List*								bind_cache_table_lptr;		/* List of keys for the binding 	*/
																	/*cache table.						*/
	
	/* MIPv6 control traffic stathandlers.	*/
	Stathandle							local_ctrl_traffic_sent_pkts_shndl;
	Stathandle							local_ctrl_traffic_sent_bits_shndl;
	Stathandle							local_ctrl_traffic_rcvd_pkts_shndl;
	Stathandle							local_ctrl_traffic_rcvd_bits_shndl;
	Stathandle							global_ctrl_traffic_sent_pkts_shndl;
	Stathandle							global_ctrl_traffic_sent_bits_shndl;
	Stathandle							global_ctrl_traffic_rcvd_pkts_shndl;
	Stathandle							global_ctrl_traffic_rcvd_bits_shndl;
	Stathandle							binding_cache_table_size_shndl;
	Stathandle							binding_update_list_size_shndl;

	/* MIPv6 tables traffic stathandlers.	*/	
	Stathandle							local_tunnel_traffic_sent_pkts_shndl;
	Stathandle							local_tunnel_traffic_sent_bits_shndl;
	Stathandle							local_tunnel_traffic_rcvd_pkts_shndl;
	Stathandle							local_tunnel_traffic_rcvd_bits_shndl;
	Stathandle							local_tunnel_traffic_delay_shndl;
	Stathandle							global_tunnel_traffic_sent_pkts_shndl;
	Stathandle							global_tunnel_traffic_sent_bits_shndl;
	Stathandle							global_tunnel_traffic_rcvd_pkts_shndl;
	Stathandle							global_tunnel_traffic_rcvd_bits_shndl;
	Stathandle							global_tunnel_traffic_delay_shndl;

	/* MIPv6 route optimization traffic stathandlers.	*/
	Stathandle							local_optimization_traffic_sent_pkts_shndl;
	Stathandle							local_optimization_traffic_sent_bits_shndl;
	Stathandle							local_optimization_traffic_rcvd_pkts_shndl;
	Stathandle							local_optimization_traffic_rcvd_bits_shndl;
	Stathandle							local_optimization_overhead_bits_shndl;
	Stathandle							local_optimization_overhead_ratio_shndl;
	Stathandle							global_optimization_traffic_sent_pkts_shndl;
	Stathandle							global_optimization_traffic_sent_bits_shndl;
	Stathandle							global_optimization_traffic_rcvd_pkts_shndl;
	Stathandle							global_optimization_traffic_rcvd_bits_shndl;
	Stathandle							global_optimization_overhead_bits_shndl;
	Stathandle							global_optimization_overhead_ratio_shndl;
	Stathandle							local_tunnel_traffic_overhead_bits_shndl;	
	Stathandle							local_tunnel_traffic_overhead_ratio_shndl;	
	Stathandle							global_tunnel_traffic_overhead_bits_shndl;	
	Stathandle							global_tunnel_traffic_overhead_ratio_shndl;	
	} IpT_Mipv6_Info;


typedef struct IpT_Rte_Proto_Oms_Pr_Info
	{
	OmsT_Pr_Handle			rip_procreg_handle;
	OmsT_Pr_Handle			ospf_procreg_handle;
	OmsT_Pr_Handle			igrp_procreg_handle;
	OmsT_Pr_Handle			eigrp_procreg_handle;
	OmsT_Pr_Handle			bgp_procreg_handle;
	OmsT_Pr_Handle			isis_procreg_handle;
	OmsT_Pr_Handle			ripng_procreg_handle;
	OmsT_Pr_Handle			ip_procreg_handle;
	} IpT_Rte_Proto_Oms_Pr_Info;


/* Common data shared by various IP process models 			*/
/* A global pointer is used as for a process model state	*/
/* The pointer is set by the process models before invoking	*/
/* any routines in ip_rte_support.ex.c.						*/
typedef struct IpT_Rte_Module_Data
	{
	Objid						module_id;
	Objid						node_id;
	char*						node_name;
	Prohandle					ip_root_prohandle;	/* ip_dispatch */

	/* Process handle of the ip_icmp process		*/
	Prohandle					icmp_process_handle;

	/* Memory shared between various process models */
	/* (left-over from original ip_rte_v4)			*/
	OmsT_Qm_Shared_Memory 		shared_mem;
	Ici *						arp_iciptr;
	InetT_Address				arp_next_hop_addr;
	IpT_Router_Id				router_id; 
	int							as_number;
	List *						interface_table_ptr;

	/* Table consisting of an array of all interfaces of the node */
	IpT_Interface_Table			interface_table;

	/* Reference to the IpT_Cmn_Rte_Table object that represents  */
	/* the "common routing table" used to route IP packets in     */
	/* this node. All routing protocols that are set up here      */
	/* add and delete entries into this "common" routing table    */
	/* as and when routes are discovered and deleted during their */
	/* individual protocol operations.                            */
	IpT_Cmn_Rte_Table*			ip_route_table;

	IpT_Rte_Proto_Oms_Pr_Info*	rte_proto_oms_pr_info_ptr;

	/* Static Route Table */
	IpT_Rte_Table*				ip_static_rte_table;
	int							instrm_from_ip_encap;
	int							outstrm_to_ip_encap;
	int							num_interfaces;
	int							num_phys_interfaces; /* Number of rows under Interface Information */
	int							first_loopback_intf_index;
	int							first_ipv6_loopback_intf_index;
	int							first_intf_instrm_index;
	Boolean						gateway_status;
	Objid						ip_parameters_objid; /* Objid of IP Routing Parameters or	*/
													 /* IP Host Parameters attribute 		*/
	Objid						ip_qos_params_objid; /* IP QoS attribute object id	*/
	Objid						ipv6_params_objid;   /* IPv6 attribute object id	*/
	Objid						intf_info_objid;
	List *						mcast_addr_list_ptr;
	/* State for Background Utilization. */
	Boolean						do_bgutil;
	OmsT_Bgutil_Routed_State*	bgutil_routed_state_ptr;
	OmsT_Bgutil_Routed_State*	received_bgutil_routed_state_ptr;
	OmsT_Bgutil_Routed_State*	sent_bgutil_routed_state_ptr;
	/* Time at which the background utilization statistics generation begins. */
	double						received_last_stat_update_time;
	double						sent_last_stat_update_time;
	
	/* State for Background Utilization. */
	OmsT_Bgutil_Routed_State*	mcast_rcvd_bgutil_routed_state_ptr;
	OmsT_Bgutil_Routed_State*	mcast_sent_bgutil_routed_state_ptr;
	/* Time at which the background utilization statistics generation begins. */
	double						mcast_rcvd_last_stat_update_time;
	double						mcast_sent_last_stat_update_time;
	
	Stathandle					locl_num_mcasts_drop_pkts_hndl;
	Stathandle					locl_num_mcasts_drop_bps_hndl;
	double						mcast_drop_last_stat_update_time;
	OmsT_Bgutil_Routed_State*	mcast_drop_bgutil_routed_state_ptr;
	
	/* Memory shared between this process and the child		 */
	/* processes. Its purpose is to provide a method of		 */
	/* distinguishing the child from which the process was	 */
	/* invoked, and receiving a packet in this process from	 */
	/* the invoker child process.							 */
	IpT_Ptc_Memory				ip_ptc_mem;
	/* Default Route specification related attributes.	 */
	InetT_Address				default_route_addr_array[2];
	short						default_route_intf_index_array[2];

	short*						instrm_to_intf_index_array;
	short*						instrm_to_slot_index_array;
	OmsT_Dv_Proc_Scheme			processing_scheme;
	/* Packet count statistic handle variables.				 */
	Stathandle					locl_tot_pkts_sent_hndl;
	Stathandle					locl_num_mcasts_sent_hndl;
	Stathandle					locl_num_bcasts_sent_hndl;
	Stathandle					locl_tot_pkts_rcvd_hndl;
	Stathandle					locl_num_mcasts_rcvd_hndl;
	Stathandle					locl_num_bcasts_rcvd_hndl;
	Stathandle					locl_num_pkts_dropped_hndl;
	
	/* IP Hops statistics */
	Stathandle					locl_num_hops_src_hndl;
	Stathandle					locl_num_hops_dest_hndl;
	Stathandle					globl_num_hops_hndl;

	/* IPv6 related statistic handles.						*/
	Stathandle					locl_tot_ipv6_pkts_sent_hndl;
	Stathandle					locl_num_ipv6_mcasts_sent_hndl;
	Stathandle					locl_tot_ipv6_pkts_rcvd_hndl;
	Stathandle					locl_num_ipv6_mcasts_rcvd_hndl;
	Stathandle					locl_num_ipv6_pkts_dropped_hndl;

	/* Stathandle and var for global statistic.				 */
	Stathandle					globl_num_pkts_dropped_hndl;
	Stathandle					globl_num_ipv6_pkts_dropped_hndl;

	/* Statistic handle to record packet latency through	 */
	/* the IP layer (e.g., router delay)					 */
	Stathandle					ip_rte_pkt_latency_stathandle;
	/* Placeholder for bit flags that indicate the presence/absence */
	/* of routing protocols that have been set up in this node.     */
	int							routing_protos;
	/* Statistic to record the time taken for a tracer packet */
	/* to travel from the source to the destination.          */
	Stathandle					globl_tracer_ete_delay_hndl;
	/* Stathandle to store the End to End delay statistics of all the */
	/* tracer packet that originate from this node.                   */
	Stathandle					local_tracer_in_ete_hndl;
	/* The size of the datagram after compression. */
	OpT_Packet_Size				dgram_compressed_size;

	OpT_uInt8					flags;	/* within_lan_node, firewall_flag, ipcloud_flag	*/
										/* multicast_router, node_is_cache_server,		*/
										/* dual_msfc_in_drm								*/	
	
	/* Every IP packet that is originated at this node gets a unique  */
	/* datagram identifier. This variable is maintained to guarantee  */
	/* this. Th euniqueness is used by fragmentation/reassembly code. */
	int							dgram_id;
	/* Table that contains information about proxy servers deployed       */
	/* on the firewall. This table is created only if the node containing */
	/* this IP module is configured as a firewall.                        */
	List *						proxy_info_table_lptr;
	/* Packet forwarding routine for IP cloud */
	IpT_Rte_Cloud_Packet_Send_Proc	cloud_send_proc;
	/* First argument passed to cloud_send_proc */
	void *						cloud_send_proc_info_ptr;
	/* Check to see if the interface table entry has the 	 */
	/* information of the neighboring router.				 */
	Boolean						router_id_assigned;
	/* Flag to indicate unnumbered interfaces. */
	Boolean						unnumbered_interface_exists;
	
	/* Array storing QoS data for all interfaces. */
	IpT_Rte_Iface_QoS_Data **  interface_qos_data_pptr; 
		
	/* Specifies whether RSVP is enabled on at least one interface.	 */
	Boolean						rsvp_status;
	/* Specifies whether RSVP-TE is being used to setup LSPs.		*/
	Boolean						rsvp_te_status;

	/* In packets/second */
	double						service_rate;

	/* IGMP used to monopolize the module-wide memory	*/
	/* Now it is using a field in this structure instead	*/

	/* Passive RIP */
	Boolean *					passive_rip_ptr;

	/* IP Access Control List Table */
	IpT_Acl_Table *		acl_ext_table;
	IpT_Acl_Table *		acl_ipv6_ext_table;
	IpT_Acl_Table *		acl_filter_ext_table;
	IpT_Acl_Table *		acl_pre_table;
	IpT_Acl_Table *		acl_ipv6_pre_table;
	IpT_Acl_Table *		acl_as_path_table;
	IpT_Acl_Table *		acl_comm_table;
	IpT_Acl_Table *		acl_std_table;
	IpT_Acl_Table *		acl_fw_filter_table;
	
	/* Hash table that contains the object group definitions	*/
	/* These object groups may be referred to in ACLs.			*/
	PrgT_String_Hash_Table*	object_group_htable_ptr;
	
	/* IP Route Map Table */
	IpT_Rte_Map_Table *		rte_map_table;

	/* Firewall Filter table	*/
	IpT_Rte_Map_Table *		firewall_filter_table;

	/* Error/warning reporting routines.  These are updated			*/
	/* by each process model as needed.								*/
	IpT_Rte_Error_Proc			error_proc;
	IpT_Rte_Warning_Proc		warning_proc;

	/* Holds the name of local Policy Routing that will be applied	*/
    /* 	to all the packets originated from this node				*/
	char*							local_policy_name;

	/* IPv6 related attributes.										*/
	Prohandle			ipv6_prohandle;
	Prohandle			ipv6_ra_prohandle;

	/* Vendor information for this node								*/
	char*				vendor_name;
	char* 				os_version_str;
	
	struct IpT_Mpls_Info*			mpls_info_ptr;				/* Multiprotocol label switching info.	*/
	struct IpT_Manet_Info*			manet_info_ptr;				/* Mobile Ad hoc network information.	*/
	struct IpT_Gtp_Info*			gtp_info_ptr;				/* UMTS GTP specific information		*/
	struct IpT_Mip_Info*			mip_info_ptr;				/* Mobile IP specific information.		*/
	struct IpT_Load_Balancer_Info*	load_balancer_info_ptr;		
	struct IpT_L2TP_Info*			l2tp_info_ptr;				/* L2TP VPN information.				*/
	struct IpT_Vrf_Info*			vrf_info_ptr;				/* VPN/VRF table information			*/
	struct IpT_Nat_Info*			nat_info_ptr;				/* Network Address Translation info.	*/	
	struct IpT_Pix_Info*			pix_info_ptr;				/* PIX firewall specific information.	*/
	struct IpT_Grouping_Info*		group_info_ptr;				/* Interface aggregation specific info.	*/
	struct IpT_Mipv6_Info*			mipv6_info_ptr;				/* Mobile IPv6 related information.		*/
	struct HAIPE_Config_Info* 		haipe_params_ptr;			/* HAIPE information. 					*/

	/* Fragmentation related fields.	*/
	Sbhandle						seg_buf_ptr;				/* To fragment full datagrams			*/
	Sbhandle						reseg_buf_ptr;				/* To fragment fragments				*/
	Sbhandle						rsm_buf_ptr;				/* To reassemble fragments				*/		
	} IpT_Rte_Module_Data;

/* Argument memory to pass information to the ipv6		*/
/* process.												*/
typedef struct Ipv6T_Arg_Memory
	{
	IpT_Interface_Info*		intf_info_ptr;
	Objid					ipv6_intf_attr_objid;
	} Ipv6T_Arg_Memory;

/* Enumerated type to indicate type of routing process.	*/
/* Currently there are four types: 						*/
/*  Central cpu											*/
/*	Distributed cpu										*/
/*	Slot cpu											*/
/*	Cloud cpu											*/
typedef enum IpT_Rte_Process_Type
	{
	IpC_Rte_Process_Type_Central_Cpu,
	IpC_Rte_Process_Type_Distrib_Cpu,
	IpC_Rte_Process_Type_Slot,
	IpC_Rte_Process_Type_Cloud
	} IpT_Rte_Process_Type;

/* Information used for tracer packets that need to be forwarded	*/
/* to a set of interfaces.											*/
typedef struct IpT_Tracer_Info
	{
	IpT_Interface_Info *	interface_ptr;
	int						minor_port;
	int						output_intf_index;
	InetT_Address			next_addr;
	double					ratio;
	} IpT_Tracer_Info;

/* Structure to pass info to MANET routing protocol (AODV) from IP */
/* Code will define void* pointer type, which can be Application   */
/* layer packet or a Destination Address.						   */
typedef struct ManetT_Info
	{
	int 		code;
	void*		manet_info_type_ptr;
	} ManetT_Info;

/* Structure to pass on the nexthop info of MANET (AODV) control  */
/* packets to IP. This is facilitated by even state functions.    */
typedef struct ManetT_Nexthop_Info
	{
	InetT_Address			next_hop_addr;
	int						output_table_index;
	IpT_Interface_Info*		interface_info_ptr;
	} ManetT_Nexthop_Info;
	

/* the flow mapping on interface from one flow_id to another */
/* this is the element of the "per_if_flow_mapping" of IpT_Interface_Info */
typedef struct
	{
	double in_flow;
	double out_flow;
	InetT_Address next_hop_addr;
	} IpT_Flow_Pair; 

typedef enum IpT_Default_Metric_Code
	{
	IpC_Invalid_Metric				= -7,
	IpC_No_Default_Metric 			= -6,
	IpC_Use_Interface_Info_Metric 	= -5,
	IpC_Use_Native_Metric 			= -4,
	IpC_Use_Redist_Protocol_Metric 	= -3,
	IpC_Use_Igp_Metric 				= -2
	}IpT_Default_Metric_Code;

int 					
ip_rte_support_default_metric_get (int source_proto, int target_proto, char* vendor_name, char* os_version);

void 		
ip_rte_support_dci_iface_info_get (IpT_Interface_Info* ip_iface_elem_ptr, int* dci_default_mtu_ptr,
									double* dci_default_delay_ptr, double* dci_default_bw_ptr);

void
ip_rte_support_default_metric_interpret (int protocol, int* default_metric_ptr, Boolean* redist_enable_ptr);
	
/* Type used by the ip_rte_proto_intf_attr_objid_table functions	*/
typedef PrgT_String_Hash_Table*				IpT_Intf_Name_Objid_Table_Handle;
#define IpC_Intf_Name_Objid_Table_Invalid	((IpT_Intf_Name_Objid_Table_Handle) OPC_NIL)

void		ip_rte_set_procs (IpT_Rte_Module_Data * iprmd_ptr, 
	IpT_Rte_Error_Proc error_proc, IpT_Rte_Warning_Proc warning_proc);


/* Macro for checking whether a node is a gateway or not				*/
#define ip_rte_node_is_gateway(_iprmd_ptr)			((Boolean) ((_iprmd_ptr)->gateway_status))

/* Macros for checking if IPv4/IPv6 is active on a node.				*/
#define ip_rte_node_ipv4_active(_iprmd_ptr)			((Boolean) ((_iprmd_ptr)->first_loopback_intf_index != IPC_INTF_INDEX_INVALID))
#define ip_rte_node_ipv6_active(_iprmd_ptr)			((Boolean) ((_iprmd_ptr)->first_ipv6_loopback_intf_index != IPC_INTF_INDEX_INVALID))
#define ip_rte_node_ip_version_active(_iprmd_ptr, _ver)	\
													((Boolean) (((InetC_Addr_Family_v4 == (_ver)) && ((_iprmd_ptr)->first_loopback_intf_index != IPC_INTF_INDEX_INVALID)) || \
																((InetC_Addr_Family_v6 == (_ver)) && ((_iprmd_ptr)->first_ipv6_loopback_intf_index != IPC_INTF_INDEX_INVALID))))

/* Functions used to interface with the IpT_Interface_Table structure   */
#define	ip_rte_num_interfaces_get(_iprmd_ptr)		((_iprmd_ptr)->interface_table.num_ipv4_interfaces)
#define inet_rte_num_interfaces_get(_iprmd_ptr)		((_iprmd_ptr)->interface_table.total_interfaces)
#define inet_rte_num_phy_interfaces_get(_iprmd_ptr)	((_iprmd_ptr)->num_phys_interfaces)														
#define ipv6_rte_num_interfaces_get(_iprmd_ptr)		((_iprmd_ptr)->interface_table.num_ipv6_interfaces)
#define	inet_first_ipv4_intf_index_get(_iprmd_ptr)	(0)
#define	inet_last_ipv4_intf_index_get(_iprmd_ptr)	((_iprmd_ptr)->interface_table.num_ipv4_interfaces - 1)
#define	inet_first_ipv6_intf_index_get(_iprmd_ptr)	((_iprmd_ptr)->interface_table.total_interfaces - \
													 (_iprmd_ptr)->interface_table.num_ipv6_interfaces)
#define	inet_last_ipv6_intf_index_get(_iprmd_ptr)	((_iprmd_ptr)->interface_table.total_interfaces - 1)
#define inet_ipv6_intf_index_to_inet_index_convert(_iprmd_ptr, _ipv6_index) \
													((_ipv6_index) + inet_first_ipv6_intf_index_get (_iprmd_ptr))
#define inet_intf_index_to_ipv6_intf_index_convert(_iprmd_ptr, _inet_index) \
													((_inet_index) - inet_first_ipv6_intf_index_get (_iprmd_ptr))

/* Macros to check if IPv4/IPv6 is active on the interface.				*/
#define ip_rte_intf_ipv4_active(_intf_ptr)			((Boolean) ((_intf_ptr)->addr_range_ptr != OPC_NIL))
#define ip_rte_intf_ipv6_active(_intf_ptr)			((Boolean) ((_intf_ptr)->ipv6_info_ptr != OPC_NIL))
#define ip_rte_intf_ip_version_active(_intf_ptr, _ver)	\
													((Boolean) (((InetC_Addr_Family_v4 == (_ver)) && ((_intf_ptr)->addr_range_ptr != OPC_NIL)) || \
																((InetC_Addr_Family_v6 == (_ver)) && ((_intf_ptr)->ipv6_info_ptr != OPC_NIL))))
														
/* Macro for checking whether an interface is a subinterface or a		*/
/* physical interface. Note that even loopbacks will be considered		*/
/* physical since they are not subintefaces.							*/
#define	ip_rte_intf_is_physical(_intf_ptr)			((Boolean) (IPC_SUBINTF_PHYS_INTF == (_intf_ptr)->subintf_addr_index))

/* Macro for checking whether an interface is loopback.					*/													
#define	ip_rte_intf_is_loopback(_intf_ptr)			((Boolean) (IpC_Intf_Status_Loopback == (_intf_ptr)->phys_intf_info_ptr->intf_status))

/* Macro for checking whether an interface is unconnected.					*/													
#define	ip_rte_intf_is_unconnected(_intf_ptr)			((Boolean) (IpC_Intf_Status_Unconnected == (_intf_ptr)->phys_intf_info_ptr->intf_status))

/* Macro for checking whether an interface is a tunnel					*/
#define ip_rte_intf_is_tunnel(_intf_ptr)			((Boolean) ((_intf_ptr)->tunnel_info_ptr != OPC_NIL))

/* Macro for checking whether a given interface is logical.				*/
#define ip_rte_intf_is_logical(_intf_ptr)			((Boolean) (IPC_PORT_NUM_INVALID == ip_rte_intf_in_port_num_get (_intf_ptr)))

/* Macros for checking if a given tunnel interface is point to			*/
/* multipoint or not. 													*/
#define ip_rte_intf_tunnel_is_point_to_multipoint_v6(_intf_ptr)	((Boolean) (IpC_Tunnel_Mode_IPv6_6to4 == (_intf_ptr)->tunnel_info_ptr->mode))
#define ip_rte_intf_tunnel_is_point_to_multipoint_v4(_intf_ptr)	((Boolean) (0 != (_intf_ptr)->tunnel_info_ptr->dest_count))

/* Used to access what is currently		*/
/* IpT_Phys_Interface_Info type			*/
#define ip_rte_intf_type_get(_intf_ptr)				((IpT_Interface_Type) ((_intf_ptr)->phys_intf_info_ptr->intf_type))
#define	ip_rte_intf_addr_index_get(_intf_ptr)		((short) ((_intf_ptr)->phys_intf_info_ptr->addr_index))
#define	ip_rte_intf_ip_addr_index_get(_intf_ptr)	((short) ((_intf_ptr)->phys_intf_info_ptr->ip_addr_index))
#define ip_rte_intf_out_port_num_get(_intf_ptr)		((short) ((_intf_ptr)->phys_intf_info_ptr->port_num))
#define ip_rte_intf_in_port_num_get(_intf_ptr)		((short) ((_intf_ptr)->phys_intf_info_ptr->in_port_num))
#define ip_rte_intf_slot_index_get(_intf_ptr)		((short) ((_intf_ptr)->phys_intf_info_ptr->slot_index))
#define	ip_rte_intf_conn_link_objid_get(_intf_ptr)	((Objid) ((_intf_ptr)->phys_intf_info_ptr->connected_link_objid))
#define ip_rte_intf_link_bandwidth_get(_intf_ptr)	((double) ((_intf_ptr)->phys_intf_info_ptr->link_bandwidth))
#define ip_rte_intf_unnumbered(_intf_ptr)			((Boolean) (OPC_NIL != (_intf_ptr)->unnumbered_info))
#define ip_rte_unnumbered_intf_addr_get(_intf_ptr)	((IpT_Address) ((_intf_ptr)->unnumbered_info->interface_addr))
#define ip_rte_intf_status_get(_intf_ptr)			((IpT_Interface_Status) ((_intf_ptr)->phys_intf_info_ptr->intf_status))
#define ip_rte_intf_link_status_get(_intf_ptr)		((Boolean) ((_intf_ptr)->phys_intf_info_ptr->link_status))
#define ip_rte_intf_link_is_failed(_intf_ptr)		((Boolean) ((_intf_ptr)->phys_intf_info_ptr->link_status == 0))
#define ip_rte_intf_active(_intf_ptr)				((Boolean) (IpC_Intf_Status_Shutdown != ((_intf_ptr)->phys_intf_info_ptr->intf_status)))
#define ip_rte_intf_is_shutdown(_intf_ptr)			((Boolean) (IpC_Intf_Status_Shutdown == ((_intf_ptr)->phys_intf_info_ptr->intf_status)))
#define ip_rte_intf_is_group(_intf_ptr)				((Boolean) (IpC_Intf_Status_Group == ((_intf_ptr)->phys_intf_info_ptr->intf_status)))
#define	ip_rte_num_subinterfaces_get(_intf_ptr)		((const int) ((_intf_ptr)->phys_intf_info_ptr->num_subinterfaces))
#define ip_rte_ith_subintf_info_get(_intf_ptr, _i)	((IPC_SUBINTF_PHYS_INTF == _i) ? (_intf_ptr) : (_intf_ptr)->phys_intf_info_ptr->subintf_pptr[_i])
#define	ip_rte_intf_lower_layer_addr_get(_intf_ptr)	((int) ((_intf_ptr)->phys_intf_info_ptr->lower_layer_addr))
#define	ip_rte_intf_lower_layer_addr_type_get(_intf_ptr)	((IpT_Intf_Lower_Layer_Type) ((_intf_ptr)->phys_intf_info_ptr->lower_layer_type))

/* Used to access what is currently		*/
/* IpT_Interface_Info type				*/
#define ip_rte_intf_index_get(_intf_ptr)			((int) ((_intf_ptr)->intf_index))
#define ip_rte_intf_addr_range_get(_intf_ptr)		((IpT_Address_Range *) ((_intf_ptr)->addr_range_ptr))
#define ip_rte_intf_addr_get(_intf_ptr)				((const IpT_Address) ((_intf_ptr)->addr_range_ptr->address))
#define ip_rte_intf_mask_get(_intf_ptr)				((const IpT_Address) ((_intf_ptr)->addr_range_ptr->subnet_mask))
#define ip_rte_intf_network_address_get(_intf_ptr)	((const IpT_Address) ((_intf_ptr)->network_address))
#define ip_rte_intf_name_get(_intf_ptr)				((char *) ((_intf_ptr)->full_name))
#define ip_rte_intf_name_string_get(_intf_ptr, _intf_name_str) \
													(strcpy (_intf_name_str, ip_rte_intf_name_get (_intf_ptr)))
#define inet_rte_intf_mtu_get(_intf_ptr,_addr_family)	((InetC_Addr_Family_v6 == _addr_family) ? IPV6C_MIN_MTU : ((_intf_ptr)->mtu))
#define ip_rte_intf_mtu_get(_intf_ptr)				((_intf_ptr)->mtu)
#define ip_rte_intf_routing_prot_get(_intf_ptr)		((List *) ((_intf_ptr)->routing_protocols_lptr))
#define ip_rte_intf_load_bits_get(_intf_ptr)		((const double) ((_intf_ptr)->load_bits))
#define ip_rte_intf_load_bps_get(_intf_ptr)			((const double) ((_intf_ptr)->load_bps))
#define ip_rte_intf_avail_bw_get(_intf_ptr)			((const double) ((_intf_ptr)->avail_bw))
#define ip_rte_intf_delay_get(_intf_ptr)			((const double) ((_intf_ptr)->delay))
#define ip_rte_intf_reliability_get(_intf_ptr)		((const double) ((_intf_ptr)->reliability))
#define ip_rte_intf_comp_info_get(_intf_ptr)		((IpT_Compression_Info *) ((_intf_ptr)->comp_info))
#define	ip_rte_intf_group_info_get(_intf_ptr)		((IpT_Group_Intf_Info *) ((_intf_ptr)->phys_intf_info_ptr->group_info_ptr))
#define	ip_rte_intf_group_type_get(_intf_ptr)		((const IpT_Intf_Aggregation_Type) ((_intf_ptr)->phys_intf_info_ptr->group_info_ptr->aggregation_type))

#define ip_rte_intf_igmp_ph_get(_intf_ptr)			((Prohandle) ((_intf_ptr)->igmp_rte_iface_ph))
#define ip_rte_intf_load_bgutil_get(_intf_ptr)	 	((OmsT_Bgutil_Routed_State *) ((_intf_ptr)->load_bgutil_routed_state_ptr))
#define ip_rte_intf_last_load_update_get(_intf_ptr)	((double) ((_intf_ptr)->last_load_update_time))
#define ip_rte_intf_queuing_scheme_get(_intf_ptr)	((IpT_Queuing_Scheme) ((_intf_ptr)->queuing_scheme))
#define ip_rte_intf_output_ph_get(_intf_ptr)		((Prohandle) ((_intf_ptr)->output_iface_prohandle))
#define ip_rte_intf_sub_addr_index_get(_intf_ptr)	((short) ((_intf_ptr)->subintf_addr_index))
#define ip_rte_intf_l2_mappings_get(_intf_ptr)		((IpT_Layer2_Mappings) ((_intf_ptr)->layer2_mappings))
#define ip_rte_intf_user_metrics_get(_intf_ptr)		((IpT_Intf_User_Metrics *) ((_intf_ptr)->user_metrics))

#define ip_rte_intf_no_ip_address(_intf_ptr)		((Boolean) (ip_address_equal ((_intf_ptr)->addr_range_ptr->address, IpI_No_Ip_Address)))
#define ip_rte_intf_is_dumb(_intf_ptr)				((Boolean) (IpC_Intf_Type_Dumb == ip_rte_intf_type_get (_intf_ptr)))
#define ip_rte_intf_is_smart(_intf_ptr)				((Boolean) (IpC_Intf_Type_Smart == ip_rte_intf_type_get (_intf_ptr)))
#define	ip_rte_intf_is_ethernet_group(_intf_ptr)	((Boolean) (IpC_Intf_Aggregation_Type_Ethernet == ip_rte_intf_group_type_get (_intf_ptr)))

#define ip_rte_intf_mcast_enabled(_intf_ptr)		((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_MCAST_ENABLED) != 0))
#define ip_rte_intf_igmp_enabled(_intf_ptr)			((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_IGMP_ENABLED) != 0))
#define ip_rte_intf_rsvp_enabled(_intf_ptr)			((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_RSVP_ENABLED) != 0))
#define ip_rte_intf_manet_enabled(_intf_ptr)		((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_MANET_ENABLED) != 0))
#define ip_rte_intf_mip_enabled(_intf_ptr)			((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_MIP_ENABLED) != 0))													
#define ip_rte_intf_is_msfc_alt(_intf_ptr)			((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_MSFC_ALT) != 0))
#define ip_rte_intf_is_msfc_alt_host_lb(_intf_ptr)	((const Boolean) (((_intf_ptr)->flags & IPC_INTF_FLAG_MSFC_ALT_HOST_LB) != 0))
													
/* Macros for identifying MIPv6 node types.		*/
#define ip_rte_intf_is_mipv6_home_agent(_intf_ptr) 			(((_intf_ptr)->ipv6_info_ptr->mipv6_info_ptr != OPC_NIL) && ((_intf_ptr)->ipv6_info_ptr->mipv6_info_ptr->mipv6_iface_type ==  Mipv6C_Home_Agent))
#define ip_rte_node_is_mipv6_enabled(_iprmd_ptr) 			(((_iprmd_ptr)->mipv6_info_ptr != OPC_NIL))
#define ip_rte_node_is_mipv6_home_agent(_iprmd_ptr) 		(((_iprmd_ptr)->mipv6_info_ptr != OPC_NIL) && ((_iprmd_ptr)->mipv6_info_ptr->node_type == Mipv6C_Home_Agent))
#define ip_rte_node_is_mipv6_mobile_node(_iprmd_ptr) 		(((_iprmd_ptr)->mipv6_info_ptr != OPC_NIL) && ((_iprmd_ptr)->mipv6_info_ptr->node_type == Mipv6C_Mobile_Node))
#define ip_rte_node_is_mipv6_correspondent_node(_iprmd_ptr) (((_iprmd_ptr)->mipv6_info_ptr != OPC_NIL) && ((_iprmd_ptr)->mipv6_info_ptr->node_type == Mipv6C_Correspondent_Node))

/* Macros for accessing fields in IpT_Tunnel_Info structure	*/
#define ip_rte_intf_tunnel_mode_get(_intf_ptr)		((_intf_ptr)->tunnel_info_ptr->mode)
#define ip_rte_tunnel_dest_addr_get(_intf_ptr)		((_intf_ptr)->tunnel_info_ptr->dest_addr)

/* IPv6 related functions	*/
#define ip_rte_intf_link_local_addr_get(_intf_ptr)				(inet_address_range_addr_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[0])))
#define ip_rte_intf_link_local_addr_get_fast(_intf_ptr)			(inet_address_range_addr_get_fast (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[0])))
#define ip_rte_intf_link_local_addr_range_get_fast(_intf_ptr)	((&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[0])))
#define ip_rte_intf_link_local_addr_equal(_intf_ptr,_addr)		(inet_address_range_address_equal (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[0]), &(_addr)))
#define ip_rte_intf_num_ipv6_addrs_get(_intf_ptr)				((_intf_ptr)->ipv6_info_ptr->num_addresses)
#define ip_rte_intf_ith_ipv6_addr_get(_intf_ptr,_i)				(inet_address_range_addr_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i])))
#define ip_rte_intf_ith_ipv6_addr_get_fast(_intf_ptr, _i)		(inet_address_range_addr_get_fast (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i])))
#define ip_rte_intf_ith_ipv6_addr_equal(_intf_ptr, _i, _addr)	(inet_address_range_address_equal (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i]), &(_addr)))
#define ip_rte_intf_ith_ipv6_addr_range_get_fast(_intf_ptr, _i)	(&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i]))
#define ip_rte_intf_ith_ipv6_prefix_len_get(_intf_ptr, _i)		(inet_address_range_mask_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i])))
#define ip_rte_intf_ith_ipv6_ntwk_addr_get(_intf_ptr, _i)		(inet_address_range_network_addr_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i])))
#define ip_rte_intf_num_ipv6_gbl_addrs_get(_intf_ptr)			(ipv6_rte_intf_num_gbl_addrs_get ((_intf_ptr)->ipv6_info_ptr))
#define ip_rte_intf_ith_gbl_ipv6_addr_get(_intf_ptr,_i)			(inet_address_range_addr_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[(_i) + 1])))
#define ip_rte_intf_ith_gbl_ipv6_addr_get_fast(_intf_ptr, _i)	(inet_address_range_addr_get_fast (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[(_i) + 1])))
#define ip_rte_intf_ith_gbl_ipv6_addr_equal(_intf_ptr,_i,_addr)	(inet_address_range_address_equal (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[(_i) + 1]), _addr))
#define ip_rte_intf_ith_gbl_ipv6_addr_range_get(_intf_ptr, _i)	(ipv6_rte_intf_ith_gbl_addr_range_get ((_intf_ptr)->ipv6_info_ptr, (_i)))
#define ip_rte_intf_ith_gbl_ipv6_addr_range_get_fast(_intf_ptr, _i)	(ipv6_rte_intf_ith_gbl_addr_range_get_fast ((_intf_ptr)->ipv6_info_ptr, (_i)))
#define ip_rte_intf_ith_gbl_ipv6_prefix_len_get(_intf_ptr, _i)	(inet_address_range_mask_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i + 1])))
#define ip_rte_intf_ith_gbl_ipv6_ntwk_addr_get(_intf_ptr, _i)	(inet_address_range_network_addr_get (&((_intf_ptr)->ipv6_info_ptr->ipv6_addr_array[_i + 1])))
#define ip_rte_intf_mac_addr_get(_intf_ptr)						((_intf_ptr)->ipv6_info_ptr->mac_addr)
#define ipv6_rte_intf_num_gbl_addrs_get(_ipv6_info_ptr)			(((_ipv6_info_ptr)->num_addresses) - 1)
#define ipv6_rte_intf_ith_gbl_addr_range_get(_ipv6_info_ptr,_i)	(inet_address_range_copy ((_ipv6_info_ptr)->ipv6_addr_array[(_i) + 1]))
#define ipv6_rte_intf_ith_gbl_addr_range_get_fast(_ipv6_info_ptr, _i)	(&((_ipv6_info_ptr)->ipv6_addr_array[(_i) + 1]))

/* Default route related funcitons.					*/
InetT_Address	inet_default_route_get (IpT_Rte_Module_Data* iprmd_ptr, InetT_Addr_Family addr_family, short* out_intf_index_ptr);
#define inet_default_route_available(_iprmd_ptr, _addr_family)	(inet_address_valid (_iprmd_ptr->default_route_addr_array[_addr_family]))
#define ip_default_route_available(_iprmd_ptr)					(inet_address_valid ((_iprmd_ptr)->default_route_addr_array[InetC_Addr_Family_v4]))
#define ip_default_route_get(_iprmd_ptr, intf_index_ptr)		(inet_ipv4_address_get (\
	inet_default_route_get (_iprmd_ptr,InetC_Addr_Family_v4,intf_index_ptr)))

/* Macros for accessing the first loopback index.	*/
#define ip_rte_first_loopback_intf_index_get(_iprmd_ptr, _addr_family) \
			((InetC_Addr_Family_v4 == _addr_family) ? (_iprmd_ptr->first_loopback_intf_index) : (_iprmd_ptr->first_ipv6_loopback_intf_index))

/* Macros to access secondary IP address information */
#define ip_rte_intf_num_secondary_addresses_get(_intf_ptr) \
	((_intf_ptr->sec_addr_tbl_ptr == OPC_NIL) ? 0 : (_intf_ptr)->sec_addr_tbl_ptr->num_sec_addresses)
/* Following macros assume that the interface has secondary addresses */

/* Macro for accessing the ith secondary address. If the index		*/
/* passed is -1, the primary address is returned.					*/
#define ip_rte_intf_secondary_addr_range_get(_intf_ptr, _ith_addr) \
	((-1 == (_ith_addr)) ? ((_intf_ptr)->addr_range_ptr) : (&((_intf_ptr)->sec_addr_tbl_ptr->sec_addr_array[_ith_addr].ip_addr_range)))
#define inet_rte_intf_secondary_addr_range_get(_intf_ptr, _ith_addr) \
	((-1 == (_ith_addr)) ? (&((_intf_ptr)->inet_addr_range)) : (&((_intf_ptr)->sec_addr_tbl_ptr->sec_addr_array[_ith_addr].inet_addr_range)))
#define ip_rte_intf_secondary_addr_get(_intf_ptr, _ith_addr) \
	((-1 == (_ith_addr)) ? ((_intf_ptr)->addr_range_ptr->address) : ((_intf_ptr)->sec_addr_tbl_ptr->sec_addr_array[_ith_addr].ip_addr_range.address))
#define inet_rte_intf_secondary_addr_get(_intf_ptr, _ith_addr) \
	(inet_address_from_ipv4_address_create (ip_rte_intf_secondary_addr_get ((_intf_ptr), (_ith_addr))))
#define ip_rte_intf_secondary_addr_mask_get(_intf_ptr, _ith_addr) \
	((-1 == (_ith_addr)) ? ((_intf_ptr)->addr_range_ptr->subnet_mask) : ((_intf_ptr)->sec_addr_tbl_ptr->sec_addr_array[_ith_addr].ip_addr_range.subnet_mask))
#define inet_rte_intf_secondary_addr_equal(_intf_ptr, _i, _addr) \
	(ip_address_equal (ip_rte_intf_secondary_addr_get((_intf_ptr), (_i)), inet_ipv4_address_get (_addr)))

/* Macros for setting elements in the IpT_Interface_Info structure.	*/	
void		ip_rte_intf_last_load_update_set		(IpT_Interface_Info *intf_info_ptr, double new_last_load_update);
void		ip_rte_intf_load_bits_set				(IpT_Interface_Info *intf_info_ptr, double new_load_bits);
void		ip_rte_intf_load_bps_set				(IpT_Interface_Info *intf_info_ptr, double new_load_bps);
void		ip_rte_intf_load_bgutil_set				(IpT_Interface_Info *intf_info_ptr, struct OmsT_Bgutil_Routed_State *new_load_bgutil);
void		ip_rte_intf_mcast_enabled_set			(IpT_Interface_Info *intf_info_ptr, Boolean new_mcast_enabled);
void		ip_rte_intf_network_address_set			(IpT_Interface_Info *intf_info_ptr, IpT_Address new_network_address);
void		ip_rte_intf_name_set					(IpT_Interface_Info *intf_info_ptr, char* name);

/* Functions to validate interface indices.						*/
#define		ip_rte_intf_tbl_index_valid(_iprmd_ptr, _i)		(((_i) >= 0) && ((_i) < ip_rte_num_interfaces_get (_iprmd_ptr)))
#define		ipv6_rte_intf_tbl_index_valid(_iprmd_ptr, _i)	(((_i) >= 0) && ((_i) < ipv6_rte_num_interfaces_get (_iprmd_ptr)))
#define		inet_rte_intf_tbl_index_valid(_iprmd_ptr, _i)	(((_i) >= 0) && ((_i) < inet_rte_num_interfaces_get (_iprmd_ptr)))

/* Functions to access the ith interface.						*/
IpT_Interface_Info*	ip_rte_intf_tbl_access (IpT_Rte_Module_Data* iprmd_ptr, int i);
IpT_Interface_Info*	ipv6_rte_intf_tbl_access (IpT_Rte_Module_Data* iprmd_ptr, int i);
IpT_Interface_Info*	inet_rte_intf_tbl_access (IpT_Rte_Module_Data* iprmd_ptr, int i);

/* Function to convert an inet interface index to an IPv6 index	*/
int			ip_rte_ipv6_intf_index_get (IpT_Rte_Module_Data * iprmd_ptr, int intf_index);

/* Function that returns the mode of the interface.				*/
IpT_Interface_Mode ip_rte_intf_mode_get (const IpT_Interface_Info* intf_ptr);
IpT_Interface_Mode ip_rte_node_mode_get (const IpT_Rte_Module_Data* iprmd_ptr);

/* Macro for accessing the ith interface 						*/
#define		ip_rte_intf_tbl_access_by_port_info(_iprmd_ptr, _port_info)	\
				ip_rte_intf_tbl_access ((_iprmd_ptr), (int)(_port_info.intf_tbl_index))
#define		inet_rte_intf_tbl_access_by_port_info(_iprmd_ptr, _port_info)	\
				inet_rte_intf_tbl_access ((_iprmd_ptr), (int)((_port_info).intf_tbl_index))
/* Macro for accessing the interface info of a subinterface from*/
/* interface index of the parent interface and the subinterface	*/
/* index.														*/
#define		ip_rte_subintf_info_get(_iprmd_ptr, _phys_intf_tbl_index, _subintf_index) \
				(ip_rte_intf_tbl_access ((_iprmd_ptr), ((_phys_intf_tbl_index) + (_subintf_index) + 1)))
/* Macro for calculating the inteface index of a subinterface	*/
/* given the interface index of the parent interface and the	*/
/* subinterface index.											*/
#define		ip_rte_subintf_index_get(_iprmd_ptr, _phys_intf_tbl_index, _subintf_index) \
				((_phys_intf_tbl_index) + (_subintf_index) + 1)
/* Macro for getting the subnet level broadcast address			*/
/* of the IP subnet to which an interface belongs.				*/
#define		ip_rte_intf_broadcast_addr_get(_intf_ptr) \
				((IpT_Address) ip_address_node_broadcast_create (ip_rte_intf_addr_get((_intf_ptr)), ip_rte_intf_mask_get((_intf_ptr))))
				
int			ip_rte_intf_tbl_index_get (IpT_Rte_Module_Data* iprmd_ptr, IpT_Interface_Info *intf_info_ptr);

/* Function for obtaining the outstrm corresponding to an		*/
/* interface. For aggregate interfaces, this function will		*/
/* invoke the group process (LACP, PAgP etc.) to pick an		*/
/* output stream.												*/
int			ip_rte_intf_outstrm_get (IpT_Interface_Info* intf_info_ptr, Packet* pkptr, int* slot_index_ptr);

InetT_Address	inet_rte_intf_broadcast_addr_get (IpT_Interface_Info* iface_ptr, InetT_Addr_Family addr_family);

/* Macro for extracting the inteface index from the port info	*/
#define		ip_rte_intf_tbl_index_from_port_info_get(_iprmd_ptr, _port_info)	((int)((_port_info).intf_tbl_index))
int			ip_rte_minor_port_from_intf_table_index_get (IpT_Rte_Module_Data* iprmd_ptr, int table_index);
#define		ipv6_rte_intf_tbl_index_from_port_info_get(_iprmd_ptr, _port_info)	((int)((_port_info).intf_tbl_index - \
																					   inet_first_ipv6_intf_index_get(_iprmd_ptr)))
/* Function for obtaining the minor port (subinterface index) of	*/
/* the interface corresponding to the specified port info			*/
int		ip_rte_minor_port_from_port_info_get(IpT_Rte_Module_Data* iprmd_ptr, IpT_Port_Info port_info);

/* Macro for checking if a port info structure corresponds to a	*/
/* valid interface.												*/
#define		ip_rte_port_info_is_defined(_port_info)	((Boolean) ((_port_info).intf_tbl_index != IPC_INTF_INDEX_INVALID))
/* Macro for obtaining the addr_index of an interface specified	*/
/* by its interface index.										*/
#define		ip_rte_intf_tbl_index_to_addr_index(_iprmd_ptr, _table_index) \
				(ip_rte_intf_addr_index_get (ip_rte_intf_tbl_access((_iprmd_ptr), (_table_index))))
/* Macro for obtaining the interface index of the parent 		*/
/* interface of a subinterface									*/
#define		ip_rte_phys_intf_index_from_subintf_index_get(_iprmd_ptr, _subintf_index) \
				((_subintf_index) - ( 1 + ip_rte_minor_port_from_intf_table_index_get ((_iprmd_ptr), (_subintf_index))))

IpT_Port_Info	ip_rte_port_info_create (int intf_table_index, char* intf_name);
IpT_Port_Info	ipv6_rte_port_info_create (IpT_Rte_Module_Data* iprmd_ptr, int ipv6_intf_index);
IpT_Port_Info	ip_rte_port_info_from_tbl_index (IpT_Rte_Module_Data* iprmd_ptr, int intf_index);
#define		ip_rte_phys_intf_index_from_link_id_obtain(_iprmd_ptr, _link_objid)	\
				ip_rte_phys_intf_index_from_link_id_obtain_core (_iprmd_ptr, _link_objid, OPC_FALSE, OPC_NIL)
int			ip_rte_phys_intf_index_from_link_id_obtain_core (IpT_Rte_Module_Data * iprmd_ptr, Objid link_objid,
				Boolean group_intf_check, int* member_intf_index_ptr);
Boolean		ip_rte_node_multicast_enabled (IpT_Rte_Module_Data* iprmd_ptr);

/* Macro for checking if the specified interface address 		*/
/* corresponds to an unnumbered interface. Unnumbered interface	*/
/* addresses would be of the form 0.0.X.0 where X is a positive	*/
/* integer.														*/
#define		ip_rte_intf_addr_is_unnumbered(_intf_addr)((IP_ADDRESS_COMPONENT_GET (_intf_addr, 3) == 0) && (! ip_address_equal (_intf_addr, IpI_No_Ip_Address)))

/* InetT_Address based functions.		*/
#define	inet_rte_v4intf_addr_get(_intf_ptr)				(inet_address_range_addr_get (&((_intf_ptr)->inet_addr_range)))
#define	inet_rte_v4intf_mask_get(_intf_ptr)				(inet_address_range_mask_get (&((_intf_ptr)->inet_addr_range)))
#define	inet_rte_v4intf_broadcast_addr_get(_intf_ptr)	(inet_address_range_broadcast_addr_get (&((_intf_ptr)->inet_addr_range)))
#define	inet_rte_v6intf_broadcast_addr_get(_intf_ptr)	(inet_address_copy (InetI_Ipv6_All_Nodes_LL_Mcast_Addr))
#define	inet_address_is_broadcast_for_interface(_addr, _intf_ptr) \
				(ip_rte_next_hop_address_is_broadcast_for_interface (inet_ipv4_address_get (_addr), (_intf_ptr)))
#define	inet_rte_v4intf_network_address_get(_intf_ptr)	(inet_address_range_network_addr_get (&((_intf_ptr)->inet_addr_range)))
#define	inet_rte_v4intf_addr_range_get(_intf_ptr)		(&((_intf_ptr)->inet_addr_range))
#define inet_rte_v4intf_addr_equal(_intf_ptr, _addr)	(inet_address_range_address_equal (&((_intf_ptr)->inet_addr_range), &_addr))

Boolean		inet_rte_v4intf_addr_range_check (InetT_Address addr, IpT_Interface_Info* intf_ptr, InetT_Address_Range** addr_range_pptr);
Boolean		inet_rte_intf_addr_range_check (IpT_Interface_Info* intf_ptr, InetT_Address next_hop, InetT_Address_Range** addr_range_pptr);
IpT_Intf_Name_Objid_Table_Handle
			ip_rte_proto_intf_attr_objid_table_build (Objid proto_params_objid);
int			ip_rte_proto_intf_attr_objid_table_size (IpT_Intf_Name_Objid_Table_Handle table_handle);
Objid		ip_rte_proto_intf_attr_objid_table_lookup_by_name (IpT_Intf_Name_Objid_Table_Handle intf_name_htable_ptr,
				const char* interface_name);
#define		ip_rte_proto_intf_attr_objid_table_lookup(_table, _intf_ptr) \
				(ip_rte_proto_intf_attr_objid_table_lookup_by_name (_table, ip_rte_intf_name_get (_intf_ptr)))
void		ip_rte_proto_intf_attr_objid_table_destroy (IpT_Intf_Name_Objid_Table_Handle intf_name_htable_ptr);
IpT_Packet_Format
			ip_rte_packet_format_valid (IpT_Rte_Module_Data * iprmd_ptr, 
				Packet * pkptr);
Boolean		ip_rte_packet_arrival (IpT_Rte_Module_Data * iprmd_ptr,
				Packet ** pkpptr, int instrm,
				IpT_Rte_Ind_Ici_Fields ** intf_ici_fdstruct_pptr,
				IpT_Interface_Info ** iface_info_pptr);
void		ip_rte_packet_send (IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr, 
				Ici* pk_ici_ptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr,
				IpT_Rte_Process_Type process_type, void* process_info_ptr);
void 		ip_rte_dgram_forward (Packet * pkptr, 
				IpT_Rte_Ind_Ici_Fields *intf_ici_fdstruct_ptr);
void 		ip_rte_dgram_discard (IpT_Rte_Module_Data * iprmd_ptr,
				Packet* pkptr, Ici* intf_ici_ptr, const char* discard_reason);
double 		ip_rte_comp_delay_and_size_compute (IpT_Rte_Module_Data * iprmd_ptr,
				Packet* pkptr, IpT_Dgram_Fields* pk_fd_ptr, Ici* intf_ici_ptr, 
				IpT_Interface_Info* iface_info_ptr);
void 		ip_rte_intf_ici_destroy (Ici* intf_iciptr);
void		ip_rte_pk_stats_update (IpT_Rte_Module_Data * iprmd_ptr,
				Packet* pkptr, double * last_stat_update_time_ptr, 
				OmsT_Bgutil_Routed_State * stat_bgutil_routed_state_ptr, 
				Stathandle * packet_shandle_ptr);
void		ip_rte_next_hop_error (IpT_Address addr);
void		ip_rte_comp_decomp_trace_print (Packet* pkptr, 
				IpT_Compression_Method method, OpT_Packet_Size old_size, 
				OpT_Packet_Size new_size, const char action [15]);
void		inet_rte_datagram_broadcast (IpT_Rte_Module_Data * iprmd_ptr,
				Packet *pk_ptr, IpT_Rte_Ind_Ici_Fields* ici_fdstruct_ptr); 
				
#define 	ip_rte_datagram_broadcast(_iprmd_ptr,_forward_proc,_dest_addr,_pk_ptr,\
				_intf_tbl_index,_ici_fdstruct_ptr)\
			inet_rte_datagram_broadcast(_iprmd_ptr,_forward_proc,_dest_addr,_pk_ptr,\
				_intf_tbl_index,_ici_fdstruct_ptr)

void 		ip_rte_datagram_interface_forward_direct (
				IpT_Rte_Module_Data * iprmd_ptr, Packet* pk_ptr, 
				IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr);
Boolean		ip_rte_decompress (Packet * pkptr, 
				IpT_Rte_Ind_Ici_Fields * intf_ici_fdstruct_ptr,
				IpT_Dgram_Fields * pk_fd_ptr);
double 		ip_rte_compress (IpT_Rte_Module_Data * iprmd_ptr,Packet * pkptr, 
				OpT_Packet_Size packet_size, IpT_Rte_Ind_Ici_Fields * intf_ici_fdstruct_ptr, 
				IpT_Dgram_Fields * pk_fd_ptr);
Objid		ip_rte_parameters_objid_obtain (Objid node_id, 
				Objid module_id, Boolean* gateway_status_p);
Boolean		ip_interface_routing_protocols_contains (List* routing_protocols_lptr,
	            int routing_protocol);
void 		ip_rte_pk_stats_update_endsim (void * module_info_ptr, 
				int PRG_ARG_UNUSED(dumlocal_code));
Boolean		ip_rte_is_local_address(const IpT_Address intf_addr, IpT_Rte_Module_Data* iprmd_ptr,
				IpT_Interface_Info** interface_pptr, int* intf_index_ptr);
Boolean		inet_rte_is_local_address(const InetT_Address intf_addr, IpT_Rte_Module_Data* iprmd_ptr,
				int* intf_index_ptr);
Boolean		inet_rte_is_addr_duplicate (InetT_Address ip_address); 
IpT_Interface_Info*	ip_rte_first_loopback_intf_info_get (IpT_Rte_Module_Data* iprmd_ptr);
IpT_Interface_Info*	ipv6_rte_first_loopback_intf_info_get (IpT_Rte_Module_Data* iprmd_ptr);
InetT_Address	inet_rte_first_loopback_intf_addr_get (IpT_Rte_Module_Data* iprmd_ptr, InetT_Addr_Family addr_family);
InetT_Address	inet_rte_intf_addr_get (IpT_Interface_Info* intf_ptr, InetT_Addr_Family addr_family);
InetT_Address   inet_rte_intf_addr_get_fast (IpT_Interface_Info* intf_ptr, InetT_Addr_Family addr_family);
InetT_Address	ipv6_rte_intf_addr_get (IpT_Interface_Info* intf_ptr);
InetT_Address   ipv6_rte_intf_addr_get_fast (IpT_Interface_Info* intf_ptr); 
InetT_Address	ipv6_rte_non_duplicate_addr_get_fast (IpT_Interface_Info* intf_ptr); 

Compcode	ip_rte_addr_local_network (IpT_Address ip_address, IpT_Rte_Module_Data * iprmd_ptr,
				IpT_Interface_Info** interface_pptr, IpT_Port_Info* port_info_ptr, int* port_num_ptr);
Compcode	inet_rte_addr_local_network_core (InetT_Address ip_addr, IpT_Rte_Module_Data* iprmd_ptr, 
				IpT_Port_Info* port_info_ptr, InetT_Address_Range** addr_range_pptr);
Compcode	ip_rte_destination_local_network (IpT_Rte_Module_Data * iprmd_ptr, InetT_Address dest_addr, 
						short* table_index_ptr, IpT_Interface_Info** interface_pptr, int *outstrm_ptr,
						InetT_Address_Range** addr_range_pptr);
#define		inet_rte_addr_local_network(_addr, _iprmd_ptr, _port_info_ptr) \
				inet_rte_addr_local_network_core ((_addr), (_iprmd_ptr), (_port_info_ptr), OPC_NIL)
Boolean		ip_rte_dest_local_network (IpT_Address ip_addr, IpT_Rte_Module_Data* iprmd_ptr,
                int* intf_index_ptr);
IpT_Interface_Info* ip_rte_phys_intf_info_get (const IpT_Rte_Module_Data* iprmd_ptr, 
				const int intf_index);
int			ip_rte_intf_minor_port_from_tbl_index (const IpT_Rte_Module_Data* iprmd_ptr,
				const int intf_index);

Boolean		inet_rte_is_local_intf_name (char* intf_name, IpT_Rte_Module_Data* intf_lptr, int* intf_index_ptr,
				IpT_Interface_Info **intf_info_pptr, InetT_Addr_Family addr_family);
#define		ip_rte_is_local_intf_name(_name,_iprmd_ptr,_intf_index_ptr,_intf_info_pptr)	\
				(inet_rte_is_local_intf_name(_name,_iprmd_ptr,_intf_index_ptr,_intf_info_pptr,InetC_Addr_Family_v4))

Boolean		ip_rte_subintf_from_layer2_mapping_get (const char* mapping_name, IpT_Layer2_Mapping mapping_type,
				IpT_Rte_Module_Data* iprmd_ptr, int* intf_tbl_index_ptr);

Boolean		ip_rte_interfaces_on_same_phys_intf (IpT_Rte_Module_Data* iprmd_ptr, int table_index,
				int phys_intf_table_index);

int			ip_rte_flow_map_insert(const void* e0, const void* e1);
int			ip_rte_flow_map_search (const void* f1, const void* f2);

IpT_Address ip_rte_loopback_from_iface_addr_get (IpT_Address ipaddr);
IpT_Address ip_loopback_address_from_node_id (Objid node_objid);

Compcode	ip_rte_support_packet_socket_info_get (Packet* ip_dgram_ptr, IpT_Pkt_Socket_Info* socket_info_ptr);
Boolean		ip_rte_support_packet_match (Packet* pkt_ptr, IpT_Rte_Map_Match_Info* match_info_ptr, IpT_Acl_Table* acl_table);

#define		ip_rte_next_hop_address_range_check(_next_hop_addr, _ip_intf_ptr) (inet_rte_v4intf_addr_range_check \
				(inet_address_from_ipv4_address_create (_next_hop_addr), (_ip_intf_ptr), OPC_NIL))
Boolean		ip_rte_next_hop_address_is_broadcast_for_interface (IpT_Address addr, 
				IpT_Interface_Info*	ip_intf_ptr);

void		ip_rte_add_routes_to_nato_table (Objid node_objid, Objid module_objid, Objid attr_objid,
				 const char* cmpnd_attr_name, const char* address_attr_name, const char* mask_attr_name,
				 const char* auto_assigned_string);

IpT_Icmp_Ping_Data*	ip_rte_icmp_ping_data_create (InetT_Address ip_address, int mpls_label, int mpls_exp);
void		ip_rte_icmp_ping_data_destroy (IpT_Icmp_Ping_Data* ping_data_ptr);
int			ip_rte_intf_index_from_intf_addr_get (IpT_Rte_Module_Data* iprmd_ptr, InetT_Address intf_addr);

IpT_Address ip_rte_first_loopback_intf_addr_get(IpT_Rte_Module_Data* iprmd_ptr);
void		ip_rte_iface_rsvp_info_set (double* bw_ptr, double bandwidth,
				OpT_uInt8* iface_flags, IpT_Intf_Name_Objid_Table_Handle rsvp_intf_objid_lookup_table,
				char* iface_name, int lsp_signaling_protocol);
int			ip_rte_tunnel_to_dest_find (IpT_Rte_Module_Data* iprmd_ptr, InetT_Address dest_addr, int protocol);

void		ip_rte_support_policy_check_info_print (Packet* pkt_ptr, char* node_name, Boolean routable);

Boolean		ip_rte_intf_has_local_address (const IpT_Address ip_addr, IpT_Interface_Info* interface_ptr);
Boolean		ipv6_rte_intf_has_local_address(const InetT_Address intf_addr, IpT_Interface_Info* intf_ptr);
Boolean 	inet_rte_intf_has_local_address (const InetT_Address ip_addr, IpT_Interface_Info* intf_ptr);
Boolean		ip_packet_protocol_is_tunnel (IpT_Protocol_Type protocol);
void		ip_rte_arp_req_ici_destroy (Ici* ip_arp_req_ici_ptr);
Boolean		ip_rte_interfaces_are_compatible (IpT_Interface_Info* intf_info_ptr1, IpT_Interface_Info* intf_info_ptr2);
Compcode	ip_rte_local_interface_pick (IpT_Rte_Module_Data* iprmd_ptr, IpT_Interface_Info* remote_intf_info_ptr,
				int* intf_index_ptr);
void		ip_rte_from_ip_dest_fec_get (IpT_Cmn_Rte_Table_Entry* ip_route_ptr, char* fec_name);

char*		ip_rte_port_info_intf_name_get (IpT_Port_Info* port_info_ptr, IpT_Rte_Module_Data* iprmd_ptr);

/* Interface lower layer type get and set functions.	*/
#define		ip_rte_intf_lower_layer_is_fr(intf_ptr) ((Boolean) ((intf_ptr)->phys_intf_info_ptr->lower_layer_type == IpC_Intf_Lower_Layer_FR))
#define 	ip_rte_intf_lower_layer_is_atm(intf_ptr) ((Boolean) ((intf_ptr)->phys_intf_info_ptr->lower_layer_type == IpC_Intf_Lower_Layer_ATM))

#define		ip_rte_port_info_intf_name_set(_port_info_ptr, input_intf_name) (((_port_info_ptr)->output_info).intf_name = (input_intf_name))
#define		ip_rte_port_info_contains_mpls_info(_port_info_ptr) ((_port_info_ptr)->intf_tbl_index == IPC_INTF_TBL_INDEX_MPLS)
#define		ip_rte_port_info_mpls_bottom_label_get(_port_info_ptr) ((_port_info_ptr)->output_info.mpls_info_ptr->bottom_label)
#define		ip_rte_port_info_mpls_top_nhlfe_get(_port_info_ptr) ((_port_info_ptr)->output_info.mpls_info_ptr->top_nhlfe_ptr)

#define		ip_load_balancer_is_enabled(_iprmd_ptr) ((_iprmd_ptr)->load_balancer_info_ptr != OPC_NIL)	
#define		ip_mobile_ip_is_enabled(_iprmd_ptr) ((_iprmd_ptr)->mip_info_ptr != OPC_NIL)
#define		ip_mobile_ipv6_is_enabled(_iprmd_ptr) ((_iprmd_ptr)->mipv6_info_ptr != OPC_NIL)
#define		ip_mobile_ipv6_is_mobile_node(_iprmd_ptr) ((_iprmd_ptr)->mipv6_info_ptr->node_type == Mipv6C_Mobile_Node)
#define     ip_mobile_ipv6_is_mobility_enabled(_iprmd_ptr) ((Boolean) (ip_mobile_ipv6_is_enabled(_iprmd_ptr)) && (ip_mobile_ipv6_is_mobile_node(_iprmd_ptr)))
#define		ip_gtp_is_enabled(_iprmd_ptr) ((_iprmd_ptr)->gtp_info_ptr != OPC_NIL)
#define		ip_manet_is_enabled(_iprmd_ptr) ((_iprmd_ptr)->manet_info_ptr != OPC_NIL)
#define		ip_manet_aodv_rte_table_get(_iprmd_ptr) (((_iprmd_ptr)->manet_info_ptr != OPC_NIL)? (_iprmd_ptr)->manet_info_ptr->aodv_route_table_ptr: OPC_NIL)											
#define		ip_mpls_is_enabled(_iprmd_ptr) ((_iprmd_ptr)->mpls_info_ptr != OPC_NIL)	
#define		ip_mpls_fecs_list_get(_iprmd_ptr) ((_iprmd_ptr)->mpls_info_ptr->fecs_lptr)
#define		ip_mpls_label_space_is_global(_iprmd_ptr) ((_iprmd_ptr)->mpls_info_ptr->label_space_global)											
					
#define		ip_manet_proto_type(_iprmd_ptr) (ip_manet_is_enabled(_iprmd_ptr) ? (_iprmd_ptr)->manet_info_ptr->rte_protocol : IpC_Rte_None)
#define		ip_manet_proto_type_is_aodv(_iprmd_ptr) (ip_manet_proto_type(_iprmd_ptr) == IpC_Rte_Aodv)
#define		ip_manet_gateway_enabled(_iprmd_ptr) (ip_manet_is_enabled(_iprmd_ptr) ? (_iprmd_ptr)->manet_info_ptr->manet_gateway_status : OPC_FALSE)
#define		ip_manet_proto_type_is_olsr(_iprmd_ptr) (ip_manet_proto_type(_iprmd_ptr) == IpC_Rte_Olsr)
#define		ip_manet_proto_type_is_dsr(_iprmd_ptr) (ip_manet_proto_type(_iprmd_ptr) == IpC_Rte_Dsr)
#define		ip_manet_proto_type_is_tora(_iprmd_ptr) (ip_manet_proto_type(_iprmd_ptr) == IpC_Rte_Tora)
	
void		ip_manet_enable (IpT_Rte_Module_Data* iprmd_ptr, IpT_Rte_Protocol proto);

IpT_Address	ip_rte_highest_loopback_addr_get (IpT_Rte_Module_Data* ip_module_data_ptr);											
IpT_Address	ip_rte_highest_intf_addr_get (IpT_Rte_Module_Data* ip_module_data_ptr);

void		ip_rte_pk_bits_stats_update (IpT_Rte_Module_Data *iprmd_ptr,
				Packet *pkptr, double *last_stat_update_time_ptr,
				OmsT_Bgutil_Routed_State *stat_bgutil_routed_state_ptr,
				Stathandle *packet_sec_shandle_ptr, Stathandle *bits_sec_shandle_ptr);

void		ip_rte_link_header_size_adjust (Packet* pkptr, IpT_Interface_Info* iface_info_ptr, IpT_Header_Adjust_Action adjust_action);

#define ip_node_is_lan(iprmd_ptr) 				(((iprmd_ptr)->flags & IPC_NODE_FLAG_LAN) != 0)
#define ip_node_is_firewall(iprmd_ptr) 			(((iprmd_ptr)->flags & IPC_NODE_FLAG_FIREWALL) != 0)
#define ip_node_is_cache_server(iprmd_ptr) 		(((iprmd_ptr)->flags & IPC_NODE_FLAG_CACHE_SERVER) != 0)
#define ip_node_is_mcast_router(iprmd_ptr) 		(((iprmd_ptr)->flags & IPC_NODE_FLAG_MCAST_ROUTER) != 0)
#define ip_node_is_cloud(iprmd_ptr) 			(((iprmd_ptr)->flags & IPC_NODE_FLAG_CLOUD) != 0)
#define ip_node_is_dual_msfc_in_drm(iprmd_ptr) 	(((iprmd_ptr)->flags & IPC_NODE_FLAG_DUAL_MSFC_DRM) != 0)
#define ip_node_is_running_ios_xr(iprmd_ptr)	(((iprmd_ptr)->flags & IPC_NODE_FLAG_IOS_XR) != 0)	
#define ip_node_is_haipe(iprmd_ptr) 			(((iprmd_ptr)->flags & IPC_NODE_FLAG_HAIPE) != 0)

InetT_Prefix_Distance**
			ip_rte_support_per_prefix_admin_weights_parse (Objid process_params_id, IpT_Rte_Module_Data* ip_module_data_ptr, int* array_size_ptr);

Compcode
			ip_rte_support_prefix_distance_obtain (InetT_Prefix_Distance**	per_prefix_dist_arr_pptr,
														int per_prefix_dist_array_size, 
														InetT_Address inet_masked_address, InetT_Subnet_Mask dest_smask, 
														int* admin_distance_ptr);

#if defined (__cplusplus)
} /* end of 'extern "C" {' */
#endif

#endif /* HDR_IP_RTE_SUPPORT_H */

