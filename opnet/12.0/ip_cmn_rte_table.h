
/****************************************/
/*      Copyright (c) 1987-2006		*/
/*		by OPNET Technologies, Inc.		*/
/*       (A Delaware Corporation)      	*/
/*    7255 Woodmont Av., Suite 250     	*/
/*     Bethesda, MD 20814, U.S.A.       */
/*       All Rights Reserved.          	*/
/****************************************/

#ifndef			_IP_CMN_RTE_TABLE_H_INCL_
#define			_IP_CMN_RTE_TABLE_H_INCL_

/** Include directives.					**/
#include	<opnet.h>
#include	<ip_addr_v4.h>
#include	<ip_rte_v4.h>
#include	<oms_pr.h>
#include	<oms_sv.h>
#include 	<ip_acl_support.h>
#include 	<ip_rte_map_support.h>
#include	<oms_ptree.h>
#include    <oms_routing_convergence.h>
#include 	<dci_policy.h>

#if defined (__cplusplus)
extern "C" {
#endif

/** ----- Data Type Declarations -----	**/

/** A datatype that represents the type **/
/** of entry in a ip routes file.       **/
/** 0 denotes dynamic routing protocol routes **/
/** 1 denotes statically configured routes    **/
/** 2 denotes directly connected networks     **/
/**   sourced by ip.                          **/
typedef enum
    {
    IpC_Rte_Table_Type_Dyn    = 0,
    IpC_Rte_Table_Type_Static = 1,
    IpC_Rte_Table_Type_Direct = 2
    } IpT_Rte_Table_Type;

typedef enum
	{
	IpC_Rte_Table_Load_Packet = 0,
	IpC_Rte_Table_Load_Dest   =	1
	} IpT_Rte_Table_Load; 
 
/** A datatype that represents the		**/
/** set of routing protocols that can 	**/
/** contribute entries to the common  	**/
/** IP route table.						**/
typedef enum
	{
	IpC_Dyn_Rte_Invalid		= -1,
    IpC_Dyn_Rte_Directly_Connected = 0,
	IpC_Dyn_Rte_Ospf		= 1,
	IpC_Dyn_Rte_Rip			= 2,
	IpC_Dyn_Rte_Igrp		= 3,
	IpC_Dyn_Rte_Bgp			= 4,
	IpC_Dyn_Rte_Eigrp		= 5,
	IpC_Dyn_Rte_Isis		= 6,
	IpC_Dyn_Rte_Static		= 7,
    IpC_Dyn_Rte_Ext_Eigrp 	= 8,
	IpC_Dyn_Rte_IBgp		= 9,
	IpC_Dyn_Rte_Default 	= 10,
	IpC_Dyn_Rte_Ripng	 	= 11,
	IpC_Dyn_Rte_Tora	 	= 12,
	IpC_Dyn_Rte_Aodv        = 13,
	IpC_Dyn_Rte_Olsr        = 14,
	IpC_Dyn_Rte_Mobile_IP	= 15,
	IpC_Dyn_Rte_LDP			= 16,
	IpC_Dyn_Rte_Custom	 	= 17,
	IpC_Dyn_Rte_Local		= 18,	
	IpC_Dyn_Rte_Number		= 19 /* KEEP LAST */
	} IpT_Rte_Prot_Type;

/** ...and corresponding macros that	**/
/** can be used by the clients of this	**/
/** package.							**/
#define IPC_DYN_RTE_INVALID		IpC_Dyn_Rte_Invalid
#define IPC_DYN_RTE_DIRECTLY_CONNECTED IpC_Dyn_Rte_Directly_Connected
#define	IPC_DYN_RTE_OSPF		IpC_Dyn_Rte_Ospf
#define	IPC_DYN_RTE_RIP			IpC_Dyn_Rte_Rip
#define	IPC_DYN_RTE_IGRP		IpC_Dyn_Rte_Igrp
#define IPC_DYN_RTE_BGP			IpC_Dyn_Rte_Bgp
#define	IPC_DYN_RTE_EIGRP		IpC_Dyn_Rte_Eigrp
#define	IPC_DYN_RTE_ISIS		IpC_Dyn_Rte_Isis
#define	IPC_DYN_RTE_STATIC		IpC_Dyn_Rte_Static
#define	IPC_DYN_RTE_EXT_EIGRP 	IpC_Dyn_Rte_Ext_Eigrp
#define	IPC_DYN_RTE_IBGP	 	IpC_Dyn_Rte_IBgp
#define IPC_DYN_RTE_DEFAULT		IpC_Dyn_Rte_Default
#define IPC_DYN_RTE_CUSTOM		IpC_Dyn_Rte_Custom
#define IPC_DYN_RTE_RIPNG		IpC_Dyn_Rte_Ripng
#define IPC_DYN_RTE_TORA		IpC_Dyn_Rte_Tora
#define IPC_DYN_RTE_AODV		IpC_Dyn_Rte_Aodv
#define IPC_DYN_RTE_OLSR		IpC_Dyn_Rte_Olsr
#define IPC_DYN_RTE_MOBILE_IP	IpC_Dyn_Rte_Mobile_IP
#define IPC_DYN_RTE_LDP			IpC_Dyn_Rte_LDP
#define IPC_DYN_RTE_LOCAL		IpC_Dyn_Rte_Local
#define IPC_DYN_RTE_NUM			((int) IpC_Dyn_Rte_Number)

/* Used to store the status of VRF table entry	*/
#define IPC_VRF_TABLE_ENTRY_ACTIVE		1
#define IPC_VRF_TABLE_ENTRY_INACTIVE		2

/** Define a array of strings that contain	**/
/** the names of the supported standard		**/
/** routing protocols.						**/
extern const char*	IpC_Dyn_Rte_Prot_Names[IPC_DYN_RTE_NUM];

/** Macro representing the administrative **/
/** weight to be associated with directly **/
/** connected networks.                   **/
#define IPC_DIRECTLY_CONNECTED_ADMIN_WEIGHT     0

/** Macros representing the metrics or	**/
/** costs at which external routes are	**/
/** redistributed into various routing	**/
/** protocols.							**/
#define IPC_EXT_RTE_RIP_DEFAULT_METRIC			0
#define IPC_EXT_RTE_IGRP_DEFAULT_METRIC			1000000000
#define IPC_EXT_RTE_EIGRP_DEFAULT_METRIC        1000000000
#define IPC_EXT_RTE_BGP_DEFAULT_METRIC			0
#define IPC_EXT_RTE_OSPF_DEFAULT_METRIC			100

/** Macros representing the type of		**/
/** metric associated with an externally**/
/** derived route. Only OSPF uses this.	**/
#define IPC_EXT_RTE_METRIC_TYPE_UNUSED			-1
#define IPC_EXT_RTE_METRIC_TYPE_OSPF_EXT1		1
#define IPC_EXT_RTE_METRIC_TYPE_OSPF_EXT2		2

/** Default AS External Type (1 or 2)	**/
/** used by OSPF when advertising		**/
/** externally derived routing info.	**/
#define IPC_EXT_RTE_METRIC_TYPE_OSPF_DEFAULT	IPC_EXT_RTE_METRIC_TYPE_OSPF_EXT2

/** Number of address families			**/
/** (IPv4 and IPv6)						**/
#define IPC_NUM_ADDR_FAMILIES					2

/** Macro representing the integer code	**/
/** that is associated with the remote	**/
/** interrupt issued by the package to	**/
/** various routing protocol processes.	**/
#define IPC_EXT_RTE_REMOTE_INTRPT_CODE	-100	

/* Macro representing the initial value of custom routing protocol's id.*/
#define IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID 100

/* Macro representing the minor port default value.		*/
#define IPC_MINOR_PORT_DEFAULT	0

/* Macros which represent the type of routes	*/
/* which are being redistributed.  The 			*/
/* redistribution algorithm will determine		*/
/* which actions (if any) are performed based	*/
/* on this value.								*/
#define IPC_REDIST_TYPE_ADD					0
#define IPC_REDIST_TYPE_WITHDRAW			1
#define IPC_REDIST_TYPE_UPDATE				2
#define IPC_REDIST_TYPE_UPDATE_DIRECT		4

/* Macros which represent the redistribution	*/
/* type for BGP into other protocols.  Also		*/
/* contains a macro for instances where BGP is	*/
/* not the protocol being redistributed from.	*/
#define IPC_REDIST_EBGP_ONLY				0
#define IPC_REDIST_IBGP_AND_EBGP			1
#define IPC_REDIST_NOT_BGP					-1

/* Values used while adding IP Cmn Route Table Entries */
#define IPC_CMN_RTE_TABLE_ENTRY_NO_OPTION						0x00
#define IPC_CMN_RTE_TABLE_ENTRY_ADD_INDIRECT_NEXTHOP_OPTION		0x01

/* Most significant 32 bits represent the 		*/
/* routing protocol, and the least significant	*/
/* 32 bits represent the as_number.				*/
/* For protocols such as IS-IS where the		*/
/* process identifier (as number) is a string,	*/
/* there will be a hash table for mapping the	*/
/* string to an integer.						*/
typedef OpT_uInt64			IpT_Rte_Proc_Id;

/* Macro representing that multiple processes are to be	*/
/* ignored.												*/
#define IPC_NO_MULTIPLE_PROC	0

/* Macro for creating a routing process ID				*/
#define IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID(_prot_name,_as_number) ((IpT_Rte_Proc_Id)((((IpT_Rte_Proc_Id)_prot_name) << 32) | ((IpT_Rte_Proc_Id)_as_number)))

/* Macros for retreiving the routing protocol and AS	*/
/* number for a routing processes ID.					*/
#define IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL(_routeproc_id) ((int)(_routeproc_id >> 32))
#define IP_CMN_RTE_TABLE_ROUTEPROC_AS_NUMBER(_routeproc_id) ((int)(_routeproc_id & 0x00000000ffffffff))
#define IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT(_routeproc_id) (IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL(_routeproc_id) == IPC_DYN_RTE_DIRECTLY_CONNECTED)

/* Macro representing the function used for a lookup if the source and destination IP addresses aren't available */
#define ip_cmn_rte_table_lookup(fast_address_unused,route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr)\
 ip_cmn_rte_table_lookup_cache(fast_address_unused,route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr,IPC_FAST_ADDR_INVALID,IPC_FAST_ADDR_INVALID,0)
			
/* Macro representing the function used for a recursive lookup if the source and destination IP addresses aren't available */
#define ip_cmn_rte_table_recursive_lookup(fast_address_unused,route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr)\
 ip_cmn_rte_table_recursive_lookup_cache(fast_address_unused,route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr,IPC_FAST_ADDR_INVALID,IPC_FAST_ADDR_INVALID)

/* Macro representing the function used for a lookup if the source and destination IP addresses aren't available */
#define inet_cmn_rte_table_lookup(route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr)\
	inet_cmn_rte_table_lookup_cache(route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr,IPC_FAST_ADDR_INVALID,IPC_FAST_ADDR_INVALID,0)
			
/* Macro representing the function used for a recursive lookup if the source and destination IP addresses aren't available */
#define inet_cmn_rte_table_recursive_lookup(route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr)\
	inet_cmn_rte_table_recursive_lookup_cache(route_table,dest,next_hop_ptr,port_info_ptr,src_proto_ptr,rte_entry_pptr,IPC_FAST_ADDR_INVALID,IPC_FAST_ADDR_INVALID)

/* Enumerated type representing bit positions for each	*/
/* route flag.											*/
typedef enum IpT_Cmn_Rte_Table_Flag_Bitpos
	{
	IpC_Cmn_Rte_Table_Flag_Bitpos_Default =			0,	/* The route is used to resolve the NH of a 0.0.0.0/0 route	*/
	IpC_Cmn_Rte_Table_Flag_Bitpos_Default_Network =	1,	/* The route is used to resolve a default network route		*/
	IpC_Cmn_Rte_Table_Flag_Bitpos_Static =			2,	/* The route is used to resolve the nh of a static route	*/
	IpC_Cmn_Rte_Table_Flag_Bitpos_Cand_Default =	3,	/* The route is a candidate default route.					*/
	IpC_Cmn_Rte_Table_Flag_Bitpos_Dont_Display = 	4 	/* The route must NOT be displayed in OT output				*/
	} IpT_Cmn_Rte_Table_Flag_Bitpos;

/* Macros indicating bit positions in the flags field of*/
/* a common route table entry.							*/
#define IPC_COM_RTE_TABLE_ENTRY_FLAG_DEFAULT_ROUTE		((OpT_uInt16) (1 << IpC_Cmn_Rte_Table_Flag_Bitpos_Default))
#define IPC_COM_RTE_TABLE_ENTRY_FLAG_DEFAULT_NTWK_ROUTE	((OpT_uInt16) (1 << IpC_Cmn_Rte_Table_Flag_Bitpos_Default_Network))
#define IPC_COM_RTE_TABLE_ENTRY_FLAG_STATIC_ROUTE		((OpT_uInt16) (1 << IpC_Cmn_Rte_Table_Flag_Bitpos_Static))
#define IPC_COM_RTE_TABLE_ENTRY_FLAG_CANDIDATE_DEFAULT	((OpT_uInt16) (1 << IpC_Cmn_Rte_Table_Flag_Bitpos_Cand_Default))
#define IPC_COM_RTE_TABLE_ENTRY_FLAG_DONT_DISPLAY		((OpT_uInt16) (1 << IpC_Cmn_Rte_Table_Flag_Bitpos_Dont_Display))
 
/* Macros to set and inspect the various flags.			*/
#define ip_cmn_rte_table_entry_default_flag_set(_entry)				((_entry)->flags |= IPC_COM_RTE_TABLE_ENTRY_FLAG_DEFAULT_ROUTE)
#define ip_cmn_rte_table_entry_default_flag_is_set(_entry)			((Boolean) (0 != ((_entry)->flags & IPC_COM_RTE_TABLE_ENTRY_FLAG_DEFAULT_ROUTE)))
#define ip_cmn_rte_table_entry_default_ntwk_flag_set(_entry)		((_entry)->flags |= IPC_COM_RTE_TABLE_ENTRY_FLAG_DEFAULT_NTWK_ROUTE)
#define ip_cmn_rte_table_entry_default_ntwk_flag_is_set(_entry)		((Boolean) (0 != ((_entry)->flags & IPC_COM_RTE_TABLE_ENTRY_FLAG_DEFAULT_NTWK_ROUTE)))
#define ip_cmn_rte_table_entry_static_flag_set(_entry)				((_entry)->flags |= IPC_COM_RTE_TABLE_ENTRY_FLAG_STATIC_ROUTE)
#define ip_cmn_rte_table_entry_static_flag_is_set(_entry)			((Boolean) (0 != ((_entry)->flags & IPC_COM_RTE_TABLE_ENTRY_FLAG_STATIC_ROUTE)))
#define ip_cmn_rte_table_entry_cand_default_flag_set(_entry)		((_entry)->flags |= IPC_COM_RTE_TABLE_ENTRY_FLAG_CANDIDATE_DEFAULT)
#define ip_cmn_rte_table_entry_cand_default_flag_is_set(_entry)		((Boolean) (0 != ((_entry)->flags & IPC_COM_RTE_TABLE_ENTRY_FLAG_CANDIDATE_DEFAULT)))
#define ip_cmn_rte_table_entry_dont_display_flag_set(_entry)		((_entry)->flags |= IPC_COM_RTE_TABLE_ENTRY_FLAG_DONT_DISPLAY)
#define ip_cmn_rte_table_entry_dont_display_flag_is_set(_entry)	 	((Boolean) (0 != ((_entry)->flags & IPC_COM_RTE_TABLE_ENTRY_FLAG_DONT_DISPLAY)))

/* Macros to set and inspect Options flag while adding IP Cmn Route Table Entry */
#define ip_cmn_rte_table_entry_add_option_set(_options, _option_type)		((int)(_options |= _option_type))
#define ip_cmn_rte_table_entry_add_option_is_set(_options, _option_type)	(_options & _option_type)

/* Data structure describing a custom routing protocol.	*/
typedef struct
	{
	char*				custom_rte_protocol_label_ptr;	/* Name of the custom routing protocol	*/
				
	IpT_Rte_Proc_Id		custom_rte_protocol_id;			/* id assigned to the custom routing	*/
														/* protocol								*/
	} IpT_Custom_Rte_Protocol_Id_Table_Entry;

/* Data structure describing an IP port 	*/
typedef struct IpT_Port_Info
	{
	short 	intf_tbl_index;		/* Index of the interface in interface table 	*/
	
	short 	minor_port;			/* Index of sub-interface (not used by standard	*/
								/* - routing protocols), but handled by the 	*/
								/* IP forwarding engine.						*/
	union
		{
		char*							intf_name;		/* valid if intf_tbl_index is a valid index, or an LSP.		*/
		struct MplsT_Port_Output_Info*	mpls_info_ptr;  /* valid if intf_tbl_index is set to IPC_INT_TBL_INDEX_MPLS	*/
		} output_info;
	
	} IpT_Port_Info;

typedef struct IpT_Mcast_Port_Info
	{
	int			major_port;
	int			minor_port;
	} IpT_Mcast_Port_Info;

typedef InetT_Address_Range	IpT_Dest_Prefix;
 
#define	ip_cmn_rte_table_dest_prefix_print(_str, _prefix)	inet_address_range_print (_str, &(_prefix))
#define ip_cmn_rte_table_dest_prefix_create					inet_address_range_network_create
#define ip_cmn_rte_table_dest_prefix_from_addr_range_create	inet_address_range_network_from_addr_range_create
#define ip_cmn_rte_table_dest_prefix_destroy(_prefix)		inet_address_range_destroy(&(_prefix))
#define ip_cmn_rte_table_dest_prefix_addr_equal(_pre,_addr)	inet_address_range_address_equal(&(_pre), &(_addr))
#define ip_cmn_rte_table_dest_prefix_ipv4_addr_equal		inet_address_range_ipv4_address_equal
#define ip_cmn_rte_table_dest_prefix_ipv4_mask_equal		inet_address_range_ipv4_mask_equal
#define ip_cmn_rte_table_dest_prefix_ipv4_addr_get(_pre)	inet_address_range_ipv4_addr_get(&(_pre))
#define ip_cmn_rte_table_dest_prefix_ipv4_mask_get(_pre)	inet_address_range_ipv4_mask_get(&(_pre))
#define ip_cmn_rte_table_dest_prefix_ipv4_addr_range_get(_pre) \
															inet_ipv4_address_range_get(&(_pre))
#define ip_cmn_rte_table_dest_prefix_addr_print(_str, _pre)	inet_address_range_address_print(_str, &(_pre))
#define ip_cmn_rte_table_dest_prefix_v4mask_print(str,_pre)	ip_address_print(str, ip_smask_from_inet_smask_create (inet_address_range_mask_get (&(_pre))))
#define ip_cmn_rte_table_dest_prefix_addr_family_get(_pre)	(inet_address_range_family_get (&(_pre)))
#define ip_cmn_rte_table_dest_prefix_addr_get(_pre)			(inet_address_range_addr_get (&(_pre)))
#define ip_cmn_rte_table_dest_prefix_mask_get(_pre)			(inet_address_range_mask_get (&(_pre)))
#define ip_cmn_rte_table_dest_prefix_mask_len_get(_pre)		(inet_address_range_mask_len_get (&(_pre)))
#define ip_cmn_rte_table_dest_prefix_copy(_prefix)			(inet_address_range_copy (_prefix))
#define ip_cmn_rte_table_dest_prefix_str_parse(_str,_type)	(inet_address_range_str_parse ((_str), (_type)))
#define ip_cmn_rte_table_dest_prefix_valid(_prefix)			(inet_address_range_valid (_prefix))
#define ip_cmn_rte_table_dest_prefix_equal(_pre1, _pre2)	(inet_address_range_equal (&(_pre1), &(_pre2)))
#define ip_cmn_rte_table_ipv4_dest_prefix_equal(_p1,_p2)	(inet_ipv4_address_range_equal (&(_p1), &(_p2)))
#define ip_cmn_rte_table_dest_prefix_compare(_p1,_p2)		(inet_address_range_compare (&(_p1), &(_p2)))
#define ip_cmn_rte_table_dest_prefix_check(_addr, _pre)		(inet_address_range_check (_addr, &(_pre)))

#define ip_cmn_rte_table_entry_dest_get(_entry_ptr)			(ip_cmn_rte_table_dest_prefix_ipv4_addr_get (_entry_ptr->dest_prefix))
#define ip_cmn_rte_table_entry_mask_get(_entry_ptr)			(ip_cmn_rte_table_dest_prefix_ipv4_mask_get (_entry_ptr->dest_prefix))
#define ip_cmn_rte_table_entry_mask_len_get(_entry_ptr)		(ip_cmn_rte_table_dest_prefix_mask_len_get (_entry_ptr->dest_prefix))

/* Data types representing the dest source table used to implement	*/
/* destination based load balancing. Currently it is a string hash	*/
/* table. But we might change it in the future.						*/
typedef PrgT_Bin_Hash_Table*	IpT_Cmn_Rte_Dest_Src_Table_Handle;
typedef int*					IpT_Cmn_Rte_Dest_Src_Table_Key;

/** A datatype that represents an		**/
/** entry in the IP route table. Note	**/
/** that the following declaration		**/
/** implicitly supports CIDR.			**/
typedef struct IpT_Cmn_Rte_Table_Entry
	{
	IpT_Dest_Prefix			dest_prefix;
	IpT_Rte_Proc_Id			route_src_proto;
	double					route_insert_time;

	/* Flags to indicate whether this route is being*/
	/* used to resolve the next hop of another route*/
	/* bit position 0: Default flag.				*/
	/* bit position 1: Static route flag.			*/
	OpT_uInt16				flags;

	/* Ptr. to the route in the originating routing	*/
	/* protocol's routing table.					*/
	void*					route_src_obj_ptr;
	int 					admin_distance;	
    List*               	next_hop_list;
    List*               	backup_list;
	} IpT_Cmn_Rte_Table_Entry;

/** IpT_Rte_Table_Updates: Used as index for	**/
/** writing stats into the array of stathandles	**/
/** maintained as part of IP route tables.		**/ 
typedef enum
	{
	IpC_Rte_Table_Any_Update,
    IpC_Rte_Table_Entry_Add,
    IpC_Rte_Table_Entry_Delete,
    IpC_Rte_Table_Next_Hop_Update,
    IpC_Rte_Table_Time_Between_Any_Update,
    IpC_Rte_Table_Size
	} IpT_Rte_Table_Updates;

/** The IP route table data type.		 **/
/** The Process Registry handle members	 **/
/** will point to the process registry	 **/
/** records of the corresponding routing **/
/** processes in a node.				 **/
typedef struct IpT_Cmn_Rte_Table
	{
	Objid					node_objid;
	int						usage_threshold;
	
	/* Vector which keeps track of the process handles	*/
	/* of all routing processes (including any multiple	*/
	/* processes of the same protocol) that are running	*/
	/* on this node.									*/
	PrgT_Vector*			routeproc_vptr;
	
	/* Vector which keeps track of the redistribution	*/
	/* matrix for this node.  Each element in the list	*/
	/* will correspond to a routing process running on	*/
	/* this node (therefore, the size of this vector 	*/
	/* and the size of routeproc_vptr will be the		*/
	/* same).  Each element will have a corresponding	*/
	/* list of all the routing processes it				*/
	/* redistributes to.								*/
	PrgT_Vector*			redist_matrix_vptr;
	
	IpT_Rte_Table_Load		load_type;

	/* IPv4 and IPv6 Patricia trees.					*/
	OmsT_Ptree*				ptree_ptr_array[IPC_NUM_ADDR_FAMILIES];

	/* Total number of entries in the table.			*/
	int						num_entries;

	/* Statistics for monitoring routing table updates.	*/
	/* The array of stathandles will record statistics	*/
	/* separately for All updates, Add, Remove, Changes	*/
	/* and also time between two consecutive updates.	*/
	/* Uses "IpT_Rte_Table_Updates" as the indices.		*/
	Stathandle				update_stathandle [6];
	double					last_update_time;

	/* Key to the hash of convergence statistics */
	OmsT_Convergence_Handle	convg_handle;
	
	/* Information about the IPv4 default route			*/
	IpT_Cmn_Rte_Table_Entry	*gateway_of_last_resort;
	IpT_Cmn_Rte_Table_Entry	*best_default_route;

	/* Default routes need to mantained separately.		*/
	/* This is for IPv4 only.							*/
	List*					resolved_default_routes;
	List*					unresolved_default_routes;

	/* Pointer to the Module data of the parent node	*/
	struct IpT_Rte_Module_Data*	iprmd_ptr;

	/* Cache table used to implement destination based	*/
	/* load balancing.									*/
	IpT_Cmn_Rte_Dest_Src_Table_Handle	dest_src_table;

	/* Number of entries in the above table.			*/
	int									dest_src_table_size;

	/* VRF to which this route table belongs.			*/
	struct IpT_Vrf_Table*				vrf_table_ptr;

#ifdef OPD_PARALLEL
	/* Spinlock to serialize access to this route table */
	PrgT_Mt_Spinlock					ip_cmn_rte_table_spinlock;
#endif /* OPD_PARALLEL */
	} IpT_Cmn_Rte_Table;


typedef struct
    {
	InetT_Address			next_hop;
    double					route_insert_time;
    int						route_metric;
	List*					table_key_lptr;
	IpT_Port_Info			port_info;
    } IpT_Next_Hop_Entry;

typedef struct
    {
    IpT_Rte_Proc_Id	      	route_proto;
    int                    	admin_distance;
	
	/* Ptr. to the route in the originating routing	*/
	/* protocol's routing table.					*/
	void*					route_src_obj_ptr;
    } IpT_Backup_Entry;           

/* Structure to store an entry in the static routing table.	*/
typedef struct IpT_Rte_Table_Entry
    {
    Boolean		    		valid;	  	    
	IpT_Dest_Prefix			dest_prefix;
    InetT_Address           next_hop;
    int                     admin_weight;
    } IpT_Rte_Table_Entry;

/* Structure to store the entire static routing table.		*/
typedef struct IpT_Rte_Table
    {
    List*   		resolved_static_route_lists [IPC_NUM_ADDR_FAMILIES];
    List*   		unresolved_static_route_lists [IPC_NUM_ADDR_FAMILIES];
    } IpT_Rte_Table;

/* This structure is used in the routeproc_vptr	*/
/* vector.										*/
/* Is used to keep track of each routing		*/
/* process running on this node.				*/
typedef struct IpT_Rte_Proc_Info
	{
	IpT_Rte_Proc_Id			routeproc_id;				/* Specifies the ID of this routing		*/
														/* process.								*/
	Prohandle				routeproc_handle;			/* Specifies the process handle of this	*/
														/* routing process.						*/
	} IpT_Route_Proc_Info;

/* This structure is used in the				*/
/* redist_matrix_vptr vector.					*/
/* Is used to keep track of the redistribution	*/
/* information of each routing process running	*/
/* on this node.								*/
typedef struct IpT_Redist_Matrix_Entry
	{
	IpT_Rte_Proc_Id			routeproc_id;				/* Specifies the ID of this routing		*/
														/* process.								*/
	List*					redist_routeproc_lptr;		/* List of all the routing protocols	*/
														/* that this routing process will be	*/
														/* redistributing to.					*/
	} IpT_Redist_Matrix_Entry;

/* This structure is used in the				*/
/* redist_routeproc_lptr, which is part of the	*/
/* IpT_Redist_Matrix_Entry structure.			*/
typedef struct IpT_Redist_Info
	{
	IpT_Rte_Proc_Id			routeproc_id;				/* Specifies the ID of the routing		*/
														/* process that is being redistributed	*/
														/* to by the corresponding				*/
														/* IpT_Redist_Matrix_Entry.				*/
	void *					redist_metric;				/* The metric used in this instance of	*/
														/* redistribution.						*/
	OpT_Int8				bgp_redist_type;			/* Specifies whether the source protocol*/
														/* is BGP, and if it is, what type of	*/
														/* redistribution it performs.			*/
														/* (EBGP only, or both IBGP and EBGP).	*/
	OpT_uInt8				flags;						/* Supported address families etc.		*/
														/* 0 - IPv4, 1 - IPv6					*/				
	void*					rte_map_entry_ptr;

	} IpT_Redist_Info;

/* This structure is used for sending redist	*/
/* information in an ICI.						*/
typedef struct IpT_Redist_Ici_Info
	{
	IpT_Cmn_Rte_Table_Entry*	rte_table_entry;		/* The route table entry which is being	*/
														/* redistributed.						*/
	int							redist_type;			/* The message type for this			*/
														/* redistributed route.					*/
	IpT_Cmn_Rte_Table*			route_table_ptr;		/* Specifies the rte table to which		*/
														/* the src and dest processes are 		*/
														/* adding routes. Can be VRF specific	*/
														/* or the common route table.			*/	
	} IpT_Redist_Ici_Info;


/* Data structures part of the dynamic routing API. */
typedef void *					IpT_Rte_Table_Handle;
typedef IpT_Cmn_Rte_Table* 		IpT_Cmn_Table_Handle;
typedef Compcode	(* IpT_Rte_Table_Lookup_Proc) (int, IpT_Rte_Table_Handle, IpT_Address, IpT_Address *);

typedef Compcode        (* IpT_Rte_Table_Install_Proc) (int, IpT_Rte_Table_Handle, IpT_Cmn_Table_Handle, IpT_Address, IpT_Address);
typedef Compcode        (* InetT_Rte_Table_Install_Proc) (IpT_Rte_Table_Handle, IpT_Cmn_Table_Handle, IpT_Dest_Prefix);

typedef struct IpT_Rte_Info
	{
	IpT_Rte_Table_Handle			table_handle;	/* Pass to routing table services.			*/

	IpT_Rte_Table_Install_Proc      install_proc;   /* Install routes into common route table */

	InetT_Rte_Table_Install_Proc    inet_install_proc;   /* Inet version of the install proc 	*/

	} IpT_Rte_Info;

/** Pointer to the route table lookup	**/
/** function.							**/
typedef Compcode	(* IpT_Cmn_Rte_Table_Lookup_Proc) (int, IpT_Cmn_Rte_Table*, IpT_Address, IpT_Address *);

/** ------ Function Declarations ------	**/
IpT_Rte_Info *		ip_dyn_rte_info_create (void);

IpT_Cmn_Rte_Table*	ip_cmn_rte_table_create (Objid node_objid, struct IpT_Rte_Module_Data* intf_lptr,
						struct IpT_Vrf_Table* vrf_table_ptr);

IpT_Rte_Proc_Id		Ip_Cmn_Rte_Table_Custom_Rte_Protocol_Register (char* custom_rte_protocol_label_ptr);

Compcode			Inet_Cmn_Rte_Table_Entry_Add_Options (IpT_Cmn_Rte_Table* route_table,	void* src_obj_ptr,
						IpT_Dest_Prefix dest_prefix, InetT_Address next_hop,
						IpT_Port_Info port_info, int metric, IpT_Rte_Proc_Id proto, int admin_distance, int options);

Compcode			Inet_Cmn_Rte_Table_Entry_Delete (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
						InetT_Address next_hop, IpT_Rte_Proc_Id proto);

Compcode            Inet_Cmn_Rte_Table_Route_Delete (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
                        IpT_Rte_Proc_Id proto);

Compcode			Inet_Cmn_Rte_Table_Entry_Update (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
						InetT_Address next_hop, IpT_Rte_Proc_Id proto, InetT_Address new_next_hop, IpT_Port_Info new_port_info,
						int new_metric, void* src_obj_ptr);

Boolean				Inet_Cmn_Rte_Table_Entry_Exists (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
						int admin_distance);

void				Inet_Cmn_Rte_Table_Clear (IpT_Cmn_Rte_Table* route_table, InetT_Addr_Family addr_family);

/* Macro cover function for Inet_Cmn_Rte_Table_Entry_Add */
#define		Inet_Cmn_Rte_Table_Entry_Add(_rte_table, _src_ptr, _dest, _next_hop, _port_info, _metric, _proto, _admin) \
				Inet_Cmn_Rte_Table_Entry_Add_Options (_rte_table, _src_ptr, _dest, _next_hop, _port_info,\
					_metric, _proto, _admin, IPC_CMN_RTE_TABLE_ENTRY_NO_OPTION)

/* Macros for API funcitons using IpT_Address structure	*/
#define		Ip_Cmn_Rte_Table_Entry_Add(_rte_table, _src_ptr, _dest, _mask, _next_hop, _port_info, _metric, _proto, _admin) \
					Inet_Cmn_Rte_Table_Entry_Add (_rte_table, _src_ptr, ip_cmn_rte_table_v4_dest_prefix_create (_dest, _mask), \
						inet_address_from_ipv4_address_create (_next_hop), _port_info, _metric, _proto, _admin)

#define		Ip_Cmn_Rte_Table_Entry_Delete(_rte_table, _dest, _mask, _next_hop, _proto) \
					Inet_Cmn_Rte_Table_Entry_Delete (_rte_table, ip_cmn_rte_table_v4_dest_prefix_create (_dest, _mask), \
						inet_address_from_ipv4_address_create (_next_hop), _proto)

#define		Ip_Cmn_Rte_Table_Route_Delete(_rte_table, _dest, _mask, _proto) \
					Inet_Cmn_Rte_Table_Route_Delete (_rte_table, ip_cmn_rte_table_v4_dest_prefix_create (_dest, _mask), _proto)

#define		Ip_Cmn_Rte_Table_Entry_Update(_rte_table, _dest, _mask, _next_hop, _proto, _new_next_hop, _port_info, _metric, _src_obj_ptr) \
					Inet_Cmn_Rte_Table_Entry_Update (_rte_table, ip_cmn_rte_table_v4_dest_prefix_create ((_dest), (_mask)), \
						inet_address_from_ipv4_address_create (_next_hop), _proto, \
						inet_address_from_ipv4_address_create (_new_next_hop), _port_info, _metric, _src_obj_ptr)

#define		Ip_Cmn_Rte_Table_Entry_Exists(_rte_table, _dest, _mask, _admin) \
					Inet_Cmn_Rte_Table_Entry_Exists(_rte_table, ip_cmn_rte_table_v4_dest_prefix_create (_dest, _mask), _admin)

#define		ip_cmn_rte_table_v4_dest_prefix_create	inet_ipv4_address_range_network_create

Compcode			ip_cmn_rte_table_lookup_cache (int fast_address_unused, 
						IpT_Cmn_Rte_Table* route_table, IpT_Address dest, IpT_Address* next_hop_ptr,
						IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id* src_proto_ptr, IpT_Cmn_Rte_Table_Entry** rte_entry_pptr,
						int dest_fast_addr, int src_fast_addr, int lookup_index);

Compcode			ip_cmn_rte_table_recursive_lookup_cache (int fast_address_unused, 
						IpT_Cmn_Rte_Table* route_table, IpT_Address dest, 
						IpT_Address* next_hop_ptr, IpT_Port_Info* port_info_ptr, 
						IpT_Rte_Proc_Id* src_proto_ptr, IpT_Cmn_Rte_Table_Entry ** rte_entry_pptr, 
						int dest_host_addr, int src_host_addr);

Compcode			inet_cmn_rte_table_lookup_cache (IpT_Cmn_Rte_Table* route_table, InetT_Address dest,
						InetT_Address* next_hop_ptr, IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id* src_proto_ptr,
						IpT_Cmn_Rte_Table_Entry** rte_entry_pptr, int dest_host_addr, int src_host_addr, int lookup_index);

Compcode			inet_cmn_rte_table_recursive_lookup_cache (IpT_Cmn_Rte_Table* route_table,
						InetT_Address dest, InetT_Address* next_hop_ptr, IpT_Port_Info* port_info_ptr, 
						IpT_Rte_Proc_Id* src_proto_ptr, IpT_Cmn_Rte_Table_Entry ** rte_entry_pptr, 
						int dest_host_addr, int src_host_addr);

void				ip_cmn_rte_static_route_add (IpT_Cmn_Rte_Table* route_table, IpT_Rte_Table* static_route_table,
						IpT_Dest_Prefix dest_prefix, InetT_Address next_hop, IpT_Port_Info port_info,
						int admin_distance);

void				ip_cmn_rte_default_network_add (IpT_Cmn_Rte_Table* route_table, InetT_Address network_address);

void				ip_cmn_rte_table_entry_free (IpT_Cmn_Rte_Table_Entry* entry, IpT_Cmn_Rte_Table* route_table);

IpT_Rte_Proc_Id		ip_cmn_rte_table_entry_src_proto_get (IpT_Cmn_Rte_Table_Entry* route_entry);

Compcode			inet_cmn_rte_table_entry_exists (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
						IpT_Cmn_Rte_Table_Entry** route_entry_pptr);

#define		ip_cmn_rte_table_entry_exists(_route_table, _dest, _mask, _entry_pptr) \
					inet_cmn_rte_table_entry_exists (_route_table, ip_cmn_rte_table_v4_dest_prefix_create (_dest, _mask), \
						_entry_pptr)

int					ip_cmn_rte_table_num_entries_get (IpT_Cmn_Rte_Table* route_table, int addr_family);

IpT_Cmn_Rte_Table_Entry*
					ip_cmn_rte_table_access (IpT_Cmn_Rte_Table* route_table, int i, int addr_family);

void*				ip_cmn_rte_table_entry_src_obj_ptr_get (IpT_Cmn_Rte_Table_Entry* route_entry);

char*				ip_cmn_rte_proto_name_print (char* proto_str, IpT_Rte_Proc_Id protocol);

Compcode			ip_cmn_rte_table_print (IpT_Cmn_Rte_Table* route_table);

void				ip_cmn_rte_table_redistribute (IpT_Cmn_Rte_Table* route_table);

IpT_Rte_Prot_Type	ip_cmn_rte_table_intf_rte_proto_to_dyn_rte_proto (int);

void				ip_cmn_rte_table_import_from_external_file_log_write (void);

IpT_Rte_Proc_Id		ip_cmn_rte_table_custom_rte_protocol_id_get (char* custom_rte_protocol_label_ptr);

const char*			ip_cmn_rte_table_custom_rte_protocol_label_get (IpT_Rte_Proc_Id custom_rte_protocol_id);

#define				ip_cmn_rte_table_best_default_route_get(_route_table)	((_route_table)->best_default_route)

int 				ip_cmn_rte_table_entry_hop_num (IpT_Cmn_Rte_Table* route_table, IpT_Cmn_Rte_Table_Entry * rte_entry_ptr);

InetT_Address 		inet_cmn_rte_table_entry_hop_get (IpT_Cmn_Rte_Table_Entry * rte_entry_ptr, int hop_index, IpT_Port_Info* port_info_ptr);

#define				ip_cmn_rte_table_entry_hop_get(_entry, _index, _port_info_ptr)	inet_ipv4_address_get (inet_cmn_rte_table_entry_hop_get(_entry, _index, _port_info_ptr))

#define				ip_cmn_rte_table_next_hop_addr_get(_next_hop_ptr)	(inet_ipv4_address_get ((_next_hop_ptr)->next_hop))

char *				ip_cmn_rte_global_exp_file_create (void);

int					ip_cmn_rte_table_entry_least_cost_get (const IpT_Cmn_Rte_Table_Entry *rte_entry_ptr);

int 				ip_cmn_rte_table_entry_cost_get (IpT_Cmn_Rte_Table_Entry *rte_entry_ptr,int hop_index);

void				Ip_Cmn_Rte_Table_Install_Routing_Proc (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id routeproc_id, Prohandle routeproc_handle);

void				Inet_Cmn_Rte_Table_Install_Redist_Matrix_Entry (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id dest_routeproc_id,
						IpT_Rte_Proc_Id src_routeproc_id, void *redist_metric, int bgp_redist_type, InetT_Addr_Family addr_family, void* rte_map_entry_ptr);
#define				Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry(ip_route_table, dest_routeproc_id, src_routeproc_id, redist_metric, bgp_redist_type) \
						Inet_Cmn_Rte_Table_Install_Redist_Matrix_Entry(ip_route_table, dest_routeproc_id, src_routeproc_id, redist_metric, bgp_redist_type, InetC_Addr_Family_v4, OPC_NIL)

Prohandle			Ip_Cmn_Rte_Table_Pro_Handle_From_Proto_Id (IpT_Rte_Proc_Id routeproc_id, IpT_Cmn_Rte_Table *ip_route_table);
void *				Inet_Cmn_Rte_Table_Redist_Metric_Get (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id to_routeproc_id, IpT_Rte_Proc_Id from_routeproc_id, InetT_Addr_Family);
#define				Ip_Cmn_Rte_Table_Redist_Metric_Get(rte_table, to_routeproc_id, from_routeproc_id) \
					Inet_Cmn_Rte_Table_Redist_Metric_Get (rte_table, to_routeproc_id, from_routeproc_id, InetC_Addr_Family_v4)
void*				Inet_Cmn_Rte_Table_Redist_Rte_Map_Get (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id to_routeproc_id, IpT_Rte_Proc_Id from_routeproc_id, InetT_Addr_Family addr_family);
IpT_Rte_Proc_Id		Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (IpT_Rte_Proc_Id specific_routeproc_id);

/* Redistribution related procedures											*/
void				ip_cmn_rte_table_redist_proto_add_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
						IpT_Address dest_addr, int dest_mask_length, IpT_Address next_hop, int metric);
void				ip_cmn_rte_table_redist_proto_withdraw_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
						IpT_Address dest_addr, int dest_mask_length, IpT_Address next_hop);
void				ip_cmn_rte_table_redist_proto_update_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
						IpT_Address dest_addr, int dest_mask_length, IpT_Address next_hop, int metric);

void				inet_cmn_rte_table_redist_proto_add_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
						InetT_Address_Range* dest_prefix, InetT_Address next_hop, int metric);
void				inet_cmn_rte_table_redist_proto_withdraw_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
						InetT_Address_Range* dest_prefix, InetT_Address next_hop);
void				inet_cmn_rte_table_redist_proto_update_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
						InetT_Address_Range* dest_prefix, InetT_Address next_hop, int metric);

/* Routing Policies related procedures											*/
void*				ip_rte_table_static_entry_access (IpT_Rte_Table_Entry*, int);
Boolean				ip_rte_table_static_entry_match (IpT_Rte_Table_Entry* rte_entry_ptr, IpT_Rte_Map_Match_Info* match_info_ptr, 
								IpT_Acl_Table* as_path_table, IpT_Acl_Table* comm_table, 
								IpT_Acl_Table* acl_table, IpT_Acl_Table* prefix_table, IpT_Acl_Pre_Override* override);

void*				ip_cmn_rte_table_dir_conn_rte_entry_access (IpT_Cmn_Rte_Table_Entry* rte_entry_ptr, int match_condition);

Boolean				ip_cmn_rte_table_dir_conn_rte_entry_match (IpT_Cmn_Rte_Table_Entry* rte_entry_ptr, IpT_Rte_Map_Match_Info* match_info_ptr, 
								IpT_Acl_Table* as_path_table, IpT_Acl_Table* comm_table, 
								IpT_Acl_Table* acl_table, IpT_Acl_Table* prefix_table, IpT_Acl_Pre_Override* override);

DciT_Policy_Ret_Code ip_rte_rpl_dir_conn_entry_match (void* target_struct, DciT_Policy_Property property_type, 
	 DciT_Policy_Match_Condition condition_type, PrgT_List* values_lptr);
DciT_Policy_Ret_Code ip_rte_rpl_static_entry_match (void* target_struct, DciT_Policy_Property property_type, 
	 DciT_Policy_Match_Condition condition_type, PrgT_List* values_lptr);

void				ip_cmn_rte_table_dest_src_table_print (IpT_Cmn_Rte_Table* route_table_ptr);
void				ip_cmn_rte_table_redist_ici_info_destroy (IpT_Redist_Ici_Info* redistr_info_ptr);
IpT_Cmn_Rte_Table_Entry*
					ip_cmn_rte_table_entry_copy (IpT_Cmn_Rte_Table_Entry* entry_ptr);
void				ip_cmn_rte_table_golr_print (IpT_Cmn_Rte_Table* route_table);
void				ip_cmn_rte_table_default_routes_print (IpT_Cmn_Rte_Table* route_table);
IpT_Cmn_Rte_Table*	ip_cmn_rte_table_for_intf_get (struct IpT_Rte_Module_Data* iprmd_ptr, int intf_index);

#define				ip_cmn_rte_table_is_vrf(_ip_cmn_rte_table) ((_ip_cmn_rte_table)->vrf_table_ptr != OPC_NIL)

/* This function has been phased out. Calls to this function from routing protocol code may be deleted.	*/
#define				ip_cmn_rte_table_proto_init(_rte_table, proto_flag)  ;

#define				ip_cmn_rte_table_vrf_table_get(_ip_cmn_rte_table) ((_ip_cmn_rte_table)->vrf_table_ptr)

void				ip_cmn_rte_table_redist_from_all_configure (Objid node_objid, IpT_Cmn_Rte_Table* rte_table_ptr, IpT_Rte_Proc_Id target_proc_id, 
						void* metric_ptr, Boolean redist_from_connected);

#define				ip_redist_addr_family_set(redist_info_ptr, addr_family) (redist_info_ptr->flags |= 0x01<<addr_family)
#define				ip_redist_addr_family_is_set(redist_info_ptr, addr_family) ((redist_info_ptr->flags & (0x01 <<addr_family)) > 0)
	
void				ip_cmn_rte_table_redist_matrix_print (IpT_Cmn_Rte_Table* rte_table_ptr);

void				ip_rte_table_static_entry_print (IpT_Rte_Table_Entry* rte_entry_ptr);

Boolean				ip_cmn_rte_table_process_redistributes_direct (IpT_Cmn_Rte_Table*, IpT_Rte_Proc_Id, InetT_Addr_Family addr_family);

#if defined (__cplusplus)
} /* end of 'extern "C" {' */
#endif

#endif			/* _IP_CMN_RTE_TABLE_H_INCL_	*/

