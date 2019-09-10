/****************************************/
/*      Copyright (c) 1986-2005		*/
/*      by OPNET Technologies, Inc.    	*/
/*       (A Delaware Corporation)      	*/
/*    7255 Woodmont Av., Suite 250     	*/
/*     Bethesda, MD 20814, U.S.A.       */
/*       All Rights Reserved.          	*/
/****************************************/

#include	<opnet.h>
#include	<ip_addr_v4.h>
#include	<ip_rte_v4.h>
#include	<ip_cmn_rte_table.h>
#include	<ip_rte_table_v4.h>
#include 	<string.h>
#include 	<oms_tan.h>
#include	<stdlib.h>
#include	<ip_notif_log_support.h>
#include	<ip_rte_support.h>
#include	<ip_sim_attr_cache.h>
#include 	<eigrp_metric_support.h>
#include	<ctype.h>
#include 	<oms_string_support.h>
#include	<ip_vrf_table.h>
#include 	<mpls_support.h>
#include	<mpls_path_support.h>	

/* Globals.	*/

/** Define a array of strings that contain	**/
/** the names of the supported standard		**/
/** routing protocols.						**/
const char*	IpC_Dyn_Rte_Prot_Names[IPC_DYN_RTE_NUM] = 
	{"Direct", "OSPF", "RIP", "IGRP", "BGP", "EIGRP", "IS-IS",
	"STATIC", "EXT_EIGRP", "IBGP", "Default", "RIPng", "TORA",
	"AODV", "OLSR", "Mobile IP", "LDP", "Custom", "Local"};

/* Maximum length of a dest_src_key string.					*/
#define IPC_DEST_SRC_KEY_LEN	32

/* Global variables for "IP Routing Table Export/Import":    */ 
/* Selection of the simulation attribute "IP Routing */
/* Table Export/Import"								 */
int					routing_table_import_export_flag = IP_RTE_TABLE_NON_DET;

/* Static variable used for custom routing protocol registration.	*/
/* static List*		Custom_Rte_Protocol_Id_Table = OPC_NIL; */  /* LP 3-10-04 - declared in ip_cmn_rte_table.h */

/* Static variabele used to keep number of keys for hash table		*/
static int			IpC_Cmn_Rte_Table_Key_Length = 0;
static int			IpC_Cmn_Rte_Table_Hash_Size = 0;
int					ip_num_gateway_demands = 0;
int					ip_num_host_nodes = 0;
int					ip_num_bgp_neighbors = 0;

/* Pool memory object handles.										*/
static Pmohandle	ip_cmn_rte_table_entry_pmh;
static Pmohandle	ip_cmn_rte_table_next_hop_entry_pmh;
static Pmohandle	ip_cmn_rte_table_dest_src_table_entry_pmh;

/* Structures internal to the IP common route table.				*/
typedef struct IpT_Cmn_Rte_Dest_Src_Table_Entry
	{
	float						creation_time;
	IpT_Cmn_Rte_Table_Entry*	route_entry_ptr;
	IpT_Next_Hop_Entry*			next_hop_ptr;
	} IpT_Cmn_Rte_Dest_Src_Table_Entry;

static void			
ip_cmn_rte_table_entry_print (IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_gateway_of_last_resort_print (IpT_Cmn_Rte_Table* route_table);

static void                     
ip_cmn_rte_table_backup_print (IpT_Cmn_Rte_Table_Entry* route_entry);

static Compcode
ip_cmn_rte_table_backup_entry_src_obj_ptr_update (IpT_Cmn_Rte_Table_Entry* route_entry,
	IpT_Rte_Proc_Id proto, void* src_obj_ptr);

static void
ip_cmn_rte_table_last_update_time_set (IpT_Cmn_Rte_Table* route_table, char* convergence_reason);

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_table_entry_create (IpT_Dest_Prefix dest_prefix, IpT_Rte_Proc_Id src_proto,
	int admin_distance, void* src_obj_ptr);

static void
ip_cmn_rte_table_entry_next_hop_key_lists_clear (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry);

EXTERN_C_BEGIN
static void 
ip_cmn_rte_table_dest_src_tbl_entry_free (void* entry_ptr);
EXTERN_C_END
	
static void
ip_cmn_rte_table_next_hop_free (IpT_Next_Hop_Entry* next_hop_ptr, IpT_Cmn_Rte_Table* route_table);

static void
ip_cmn_rte_table_port_info_free (IpT_Port_Info*	port_info_ptr, IpT_Cmn_Rte_Table* route_table);
	
static IpT_Next_Hop_Entry*
ip_cmn_rte_table_next_hop_pick (IpT_Cmn_Rte_Table* route_table_ptr, IpT_Cmn_Rte_Table_Entry* route_entry_ptr);

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_route_table_ptree_lookup (IpT_Cmn_Rte_Table* route_table, InetT_Address dest);

static void
ip_cmn_rte_table_dest_src_key_list_entry_remove (IpT_Next_Hop_Entry* next_hop_ptr,
	IpT_Cmn_Rte_Dest_Src_Table_Key key);

static IpT_Cmn_Rte_Dest_Src_Table_Entry*
ip_cmn_rte_table_dest_src_table_entry_create (IpT_Cmn_Rte_Table_Entry* rte_entry_ptr,
	IpT_Next_Hop_Entry* next_hop_ptr);

static void
ip_cmn_rte_table_dest_src_table_entry_add (IpT_Cmn_Rte_Table* route_table_ptr, IpT_Cmn_Rte_Dest_Src_Table_Key key,
	IpT_Cmn_Rte_Dest_Src_Table_Entry* dest_src_table_entry);

static void
ip_cmn_rte_table_dest_src_table_entries_remove (IpT_Cmn_Rte_Table* route_table_ptr, IpT_Next_Hop_Entry* next_hop_ptr);

EXTERN_C_BEGIN

int
ip_cmn_rte_table_dest_src_table_entry_remove (void* route_table_void_ptr, void* key_ptr);

EXTERN_C_END

static void
ip_cmn_rte_table_dest_src_key_list_entry_add (IpT_Next_Hop_Entry* next_hop_ptr, IpT_Cmn_Rte_Dest_Src_Table_Key key);

static void			
ip_cmn_rte_table_entry_redistribute (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry, int redist_type, IpT_Rte_Proc_Id removed_proto);

static int
ip_cmn_rte_table_prune_backups_for_redistribution (IpT_Cmn_Rte_Table *cmn_rte_table,
	IpT_Cmn_Rte_Table_Entry *route_ptr, IpT_Rte_Proc_Id routeproc_id,
	IpT_Redist_Matrix_Entry *route_matrix_entry, char *message_str);

static List *
ip_cmn_rte_table_redist_matrix_entries_combine (IpT_Redist_Matrix_Entry *in_table_redist_matrix_entry,
	IpT_Redist_Matrix_Entry *removed_redist_matrix_entry);

static void
ip_cmn_rte_next_hop_add (IpT_Cmn_Rte_Table_Entry* route_entry,
	InetT_Address next_hop, int metric, IpT_Port_Info* port_info_ptr);

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_default_route_add (IpT_Cmn_Rte_Table* cmn_rte_table,
	void* src_obj_ptr, InetT_Address next_hop, IpT_Port_Info port_info, int metric,
	IpT_Rte_Proc_Id proto, int admin_distance);

static Compcode
ip_cmn_rte_default_route_delete (IpT_Cmn_Rte_Table* cmn_rte_table,
	IpT_Rte_Proc_Id proto, int* admin_dist_ptr);

static Compcode
ip_cmn_rte_table_default_route_update (IpT_Cmn_Rte_Table* route_table,
	InetT_Address next_hop, IpT_Rte_Proc_Id proto, InetT_Address new_next_hop,
	IpT_Port_Info new_port_info, int new_metric, void* src_obj_ptr);

static Compcode
ip_cmn_rte_default_route_next_hop_delete (IpT_Cmn_Rte_Table* cmn_rte_table,
	InetT_Address next_hop, IpT_Rte_Proc_Id proto);

static void
ip_cmn_rte_default_route_list_add (IpT_Cmn_Rte_Table* cmn_rte_table, List* route_lptr,
	IpT_Cmn_Rte_Table_Entry** new_entry_pptr);

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_default_route_list_find (List* route_lptr, IpT_Rte_Proc_Id proto, int* index_ptr);

static int
ip_cmn_rte_default_route_compare (IpT_Cmn_Rte_Table_Entry* entry1, IpT_Cmn_Rte_Table_Entry* entry2);

static void
ip_cmn_rte_gateway_of_last_resort_update (IpT_Cmn_Rte_Table* cmn_rte_table);

static Boolean
ip_cmn_rte_table_classful_entry_exists (IpT_Cmn_Rte_Table* route_table, InetT_Address network_address,
	IpT_Cmn_Rte_Table_Entry** curr_entry_pptr);

static void
ip_cmn_rte_table_new_default_route_handle (IpT_Cmn_Rte_Table* cmn_rte_table,
	IpT_Cmn_Rte_Table_Entry* new_default_route);

static void
ip_cmn_rte_table_default_network_route_update (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_unresolved_routes_check (IpT_Cmn_Rte_Table* route_table,
	InetT_Addr_Family addr_family, IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_unresolved_static_routes_check (IpT_Cmn_Rte_Table* route_table,
	InetT_Addr_Family addr_family, IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_unresolved_default_routes_check (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_default_network_route_resolve (IpT_Cmn_Rte_Table* route_table,
	int route_index, IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_resolved_routes_check (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_resolved_static_routes_check (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_resolved_default_routes_check (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry);

static IpT_Next_Hop_Entry*
ip_cmn_rte_table_next_hop_copy (IpT_Next_Hop_Entry* next_hop_ptr);

static IpT_Port_Info
ip_cmn_rte_table_port_info_copy (IpT_Port_Info* port_info_ptr);
	
static Boolean
ip_cmn_rte_enter_backup (IpT_Cmn_Rte_Table_Entry* route_entry, IpT_Rte_Proc_Id proto,
	int admin_distance, void *src_obj_ptr);

static IpT_Backup_Entry*
ip_cmn_rte_table_backup_entry_copy (IpT_Backup_Entry* backup_entry_ptr);

static void
ip_cmn_rte_delete_backup (IpT_Cmn_Rte_Table* cmn_rte_table, IpT_Rte_Proc_Id proto,
	IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_entry_replace (IpT_Cmn_Rte_Table* cmn_rte_table, void* src_obj_ptr,
	IpT_Dest_Prefix dest_prefix, InetT_Address next_hop, IpT_Port_Info port_info,
	int metric, IpT_Rte_Proc_Id proto, int admin_distance, IpT_Cmn_Rte_Table_Entry* route_entry);

static void
ip_cmn_rte_table_next_hop_list_update (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry, InetT_Address next_hop);

static int
ip_cmn_rte_next_hop_update (IpT_Cmn_Rte_Table_Entry* route_entry, InetT_Address next_hop,
	InetT_Address new_next_hop, IpT_Port_Info new_port_info, int new_metric, IpT_Cmn_Rte_Table* rte_table_ptr);

static int
ip_cmn_rte_next_hop_delete (IpT_Cmn_Rte_Table* cmn_rte_table, IpT_Cmn_Rte_Table_Entry* route_entry, 
	InetT_Address next_hop);

static Compcode
ip_cmn_rte_table_rte_list_entry_delete (IpT_Cmn_Rte_Table* route_table, IpT_Cmn_Rte_Table_Entry* route_entry,
	OmsT_Ptree_Entry_Index index, IpT_Rte_Proc_Id proto, IpT_Dest_Prefix dest_prefix);

EXTERN_C_BEGIN

static void
ip_cmn_rte_table_entry_free_proc (void* entry_ptr, void* state_ptr);

static void
ip_cmn_route_table_optimal_dest_src_values_print (void* state_ptr, int code);

EXTERN_C_END

char *
ip_cmn_rte_global_exp_file_create (void);

static void
ip_cmn_rte_table_dest_src_table_gbl_variables_init (void);

static IpT_Route_Proc_Info *
ip_cmn_rte_table_route_proc_info_create (IpT_Rte_Proc_Id routeproc_id, Prohandle routeproc_handle);

static IpT_Redist_Info*
ip_cmn_rte_table_redist_info_create (IpT_Rte_Proc_Id routeproc_id, void *redist_metric, int bgp_redist_type);

static IpT_Redist_Matrix_Entry *
ip_cmn_rte_table_redist_matrix_entry_create (IpT_Rte_Proc_Id routeproc_id);

static IpT_Redist_Matrix_Entry *
ip_cmn_rte_table_redist_matrix_entry_search (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id routeproc_id);

static IpT_Redist_Info *
ip_cmn_rte_table_redist_info_search (IpT_Redist_Matrix_Entry *redist_matrix_entry, IpT_Rte_Proc_Id routeproc_id);

static IpT_Route_Proc_Info *
ip_cmn_rte_table_route_proc_info_search (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id routeproc_id);

static void
ip_cmn_rte_table_rte_inject (int redist_type, Prohandle proc_handle, IpT_Cmn_Rte_Table_Entry* route_ptr, IpT_Cmn_Rte_Table* route_table_ptr);

static void
ip_cmn_rte_table_hash_key_create (char* key_str, int src_fast_addr, int dest_fast_addr, int lookup_index);

static int
ip_cmn_rte_fast_addr_to_hex_str (char* key_str, int fast_addr);

static int
ip_cmn_rte_hex_str_to_fast_addr (char* key_str);

static Compcode
ip_cmn_rte_table_fast_addrs_from_hash_key_get (char* key_str,
	int* src_fast_addr_ptr, int* dest_fast_addr_ptr, int* lookup_index_ptr);

static void
ip_cmn_rte_table_dest_src_table_entry_print (char* key, IpT_Cmn_Rte_Dest_Src_Table_Entry* dest_src_entry_ptr);

#define ip_cmn_rte_table_dest_prefix_addr_get_fast(dest_prefix)	inet_address_range_addr_get_fast (&(dest_prefix))
#define	ip_cmn_rte_table_dest_prefix_addr_check(_addr,_pre)	inet_address_range_check(_addr, &(_pre))
#define	ip_cmn_rte_table_ipv4_dest_prefix_addr_check(_addr,_pre)	inet_ipv4_ntwk_address_range_check(_addr, &(_pre))
#define ip_cmn_rte_table_dest_prefix_addr_ptr_get(_pre)				(inet_address_range_addr_ptr_get(&(_pre)))
#define ip_cmn_rte_table_entry_from_ptree_entry_get(_ptree_entry)	((IpT_Cmn_Rte_Table_Entry*) oms_ptree_entry_src_obj_get (_ptree_entry))
#define ip_cmn_rte_table_entry_mem_alloc()							((IpT_Cmn_Rte_Table_Entry*) op_prg_pmo_alloc (ip_cmn_rte_table_entry_pmh))
#define ip_cmn_rte_table_next_hop_entry_mem_alloc()					((IpT_Next_Hop_Entry*) op_prg_pmo_alloc (ip_cmn_rte_table_next_hop_entry_pmh))

#define ip_cmn_rte_table_dest_src_table_lookup(_dst_src_tbl, _key)	((IpT_Cmn_Rte_Dest_Src_Table_Entry*) prg_string_hash_table_item_get ((_dst_src_tbl), (_key)))
#define ip_cmn_rte_table_dest_src_table_create(_rte_table)			(prg_string_hash_table_create (IpC_Cmn_Rte_Table_Hash_Size, IpC_Cmn_Rte_Table_Key_Length))

#define ip_cmn_rte_table_entry_is_default(_entry)					(0 == ip_cmn_rte_table_entry_mask_len_get (_entry))
#define ip_cmn_rte_table_entry_is_default_network(_entry)			(IPC_DYN_RTE_DEFAULT == IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL ((_entry)->route_src_proto))

IpT_Cmn_Rte_Table*
ip_cmn_rte_table_create (Objid node_objid, IpT_Rte_Module_Data* ip_rmd_ptr,
	struct IpT_Vrf_Table* vrf_table_ptr)
	{
	IpT_Cmn_Rte_Table*	route_table;
	static Boolean		pmo_handles_init = OPC_FALSE;
	int my_node_id; /* LP 3-4-04 */

	/** Allocate memory for an IpT_Cmn_Rte_Table object **/
	/** and return a pointer to it.						**/
	/** NOTE:	The responsibility of calling this		**/
	/** 		function just once per (routing) node	**/
	/** 		belongs in the client side of this		**/
	/**			package.								**/
	FIN (ip_cmn_rte_table_create (node_objid));

	/* Allocate memory.									*/
	route_table = (IpT_Cmn_Rte_Table*) op_prg_mem_alloc (
						sizeof (IpT_Cmn_Rte_Table));
	
	/* LP 3-4-04 - added */
	op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &my_node_id);

	/* Check if memory has been allocated. */ 
	if (route_table == OPC_NIL)
		{
		/* Report an error message and terminate the simulation	*/
		op_sim_end ("Error in IP common route table support code: ", 
			"Could not allocate memory for IpT_Cmn_Rte_Table data structure", 
			OPC_NIL, OPC_NIL);
		}

	/* Set the node_objid element.						*/
	route_table->node_objid = node_objid;

	/* Set the route table type also.					*/
	route_table->vrf_table_ptr = vrf_table_ptr;

	/* Create the Patricia trees.						*/
	if (ip_rte_node_ipv4_active (ip_rmd_ptr))
		{
		route_table->ptree_ptr_array[InetC_Addr_Family_v4] = oms_ptree_create (32);

		/* Initialize the list of default route entries.			*/
		route_table->resolved_default_routes = op_prg_list_create ();
		route_table->unresolved_default_routes = op_prg_list_create ();
		}
	else
		{
		/* IPv4 is not enabled on this node.			*/
		route_table->ptree_ptr_array[InetC_Addr_Family_v4] = OPC_NIL;
		route_table->resolved_default_routes = OPC_NIL;
		route_table->unresolved_default_routes = OPC_NIL;
		}

	if (ip_rte_node_ipv6_active (ip_rmd_ptr))
		{
		route_table->ptree_ptr_array[InetC_Addr_Family_v6] = oms_ptree_create (128);
		}
	else
		{
		route_table->ptree_ptr_array[InetC_Addr_Family_v6] = OPC_NIL;
		}


	/* Initialize the gateway of last resort			*/
	route_table->gateway_of_last_resort = OPC_NIL;

	/* Set the number of entries to 0.					*/
	route_table->num_entries = 0;

	/* Set the routes threshold to 1 */
	/* This is just in case Passive RIP routing is used */
	route_table->usage_threshold = 1;

	/* Set the load balancing type, assume per-packet	*/
	route_table->load_type = IpC_Rte_Table_Load_Packet;
	
	/* Create the list of routing protocol process		*/
	/* information.										*/
	route_table->routeproc_vptr = prg_vector_create (0, OPC_NIL, OPC_NIL);

	/* Create the redistribution matrix list.			*/
	route_table->redist_matrix_vptr = prg_vector_create (0, OPC_NIL, OPC_NIL);
	
	/* Store the pointer to the Module data of			*/
	/* this router.										*/
	route_table->iprmd_ptr = ip_rmd_ptr;

	/* Initialize the time at which the routing table was last updated	*/
	/* using the time at which it is created -- i.e., now.				*/
	route_table->last_update_time = op_sim_time ();

	/* Define statistics to track route table updates.	*/
	route_table->update_stathandle [IpC_Rte_Table_Any_Update] = 
		op_stat_reg ("Route Table.Total Number of Updates", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	
	route_table->update_stathandle [IpC_Rte_Table_Entry_Add] = 
		op_stat_reg ("Route Table.Number of Route Additions", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	
	route_table->update_stathandle [IpC_Rte_Table_Entry_Delete] = 
		op_stat_reg ("Route Table.Number of Route Deletions", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	
	route_table->update_stathandle [IpC_Rte_Table_Next_Hop_Update] = 
		op_stat_reg ("Route Table.Number of Next Hop Updates", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	
	route_table->update_stathandle [IpC_Rte_Table_Time_Between_Any_Update] = 
		op_stat_reg ("Route Table.Time Between Updates (sec)", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	
	route_table->update_stathandle [IpC_Rte_Table_Size] = 
		op_stat_reg ("Route Table.Size (number of entries)", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	/* Set the Directly Connected route entry match funtion in IP module memory */
   	ip_rmd_ptr->rte_map_match_proc_array [IPC_DYN_RTE_DIRECTLY_CONNECTED] = 
				(IpT_Rte_Map_Entry_Match_Proc)  ip_cmn_rte_table_dir_conn_rte_entry_match;
	
	/* Initialize the pool memory object handles.				*/
	if (OPC_FALSE == pmo_handles_init)
		{
		pmo_handles_init = OPC_TRUE;
		ip_cmn_rte_table_entry_pmh = op_prg_pmo_define
			("IP Common route table entry", sizeof (IpT_Cmn_Rte_Table_Entry), 256);
		ip_cmn_rte_table_next_hop_entry_pmh = op_prg_pmo_define
			("IP common route table next hop entry", sizeof (IpT_Next_Hop_Entry), 256);
		ip_cmn_rte_table_dest_src_table_entry_pmh = op_prg_pmo_define
			("IP common route table dest src entry", sizeof (IpT_Cmn_Rte_Dest_Src_Table_Entry), 256);
		}

	/* Initialize the dest src table to NIL.					*/
	route_table->dest_src_table = OPC_NIL;
	route_table->dest_src_table_size = 0;

	FRET (route_table);
	}

static void
ip_cmn_rte_table_port_info_verify (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
	InetT_Address next_hop, IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id proto)
	{
	int							tbl_index;
	IpT_Interface_Info*			intf_ptr;
	InetT_Address_Range*		addr_range_ptr;
#ifndef OPD_NO_DEBUG
	char						dest_str [INETC_ADDR_STR_LEN];
	char						nh_str [INETC_ADDR_STR_LEN];
	char						src_proto_str [64];
	char						trace_msg [512];
#endif

	/** Verifies the port info information specified by the		**/
	/** routing protocol is correct.							**/

	FIN (ip_cmn_rte_table_port_info_verify (route_table, dest_prefix, next_hop, ...));

	tbl_index = ip_rte_intf_tbl_index_from_port_info_get (route_table->iprmd_ptr, *port_info_ptr);
	
	/* Skip this check for Null0 or LSP routes.	Also routes		*/
	/* that use tunnel interfaces might pass an invalid next hop*/
	/* Accept such routes wihtout further checks.				*/
	if ((IPC_INTF_TBL_INDEX_NULL0 == tbl_index) ||
		(IPC_INTF_TBL_INDEX_LSP == tbl_index) ||
		(IPC_INTF_TBL_INDEX_MPLS == tbl_index) ||
		(!inet_address_valid (next_hop)))
		{
		/* This is either a Null0 route or a LSP. Accept it.	*/
		}
	else if (IPC_INTF_INDEX_INVALID != tbl_index)
		{
		/* The port_info has been specified. Make sure it is	*/
		/* correct.												*/

		/* Get a pointer to the interface information of the	*/
		/* interface specified by the port_info					*/
		intf_ptr = inet_rte_intf_tbl_access_by_port_info (route_table->iprmd_ptr, *port_info_ptr);

		/* If the port_info specified was invalid or if the		*/
		/* next hop specified cannot be reached through the		*/
		/* specified interface, print out a log message.		*/
		if ((OPC_NIL == intf_ptr) ||
			((OPC_FALSE == ip_rte_intf_unnumbered (intf_ptr)) &&
			 (OPC_FALSE == inet_rte_intf_addr_range_check (intf_ptr, next_hop, &addr_range_ptr))))
			{
#ifndef OPD_NO_DEBUG	
			/* The port_info specified is incorrect				*/
			/* Create prinatble version of the route attributes	*/
			ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
			inet_address_print (nh_str, next_hop);

			/* Print out a sim log entry.						*/
			ipnl_invalid_port_info_log_write (dest_str, nh_str, proto, *port_info_ptr, route_table->iprmd_ptr);
			/* Print out a trace message also.					*/
			if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
				{
				ip_cmn_rte_proto_name_print (src_proto_str, proto);
				sprintf (trace_msg, "Dest: %s, Next hop: %s, Protocol: %s, Intf tbl index: %d", 
					dest_str, nh_str, src_proto_str, tbl_index);

				op_prg_odb_print_major ("The port info for the following entry was incorrect",
									trace_msg, OPC_NIL);
				}
#endif

			/* Call the function that would set the port_info	*/
			/* appropriately if the next hop is directly		*/
			/* connected.										*/
			inet_rte_addr_local_network (next_hop, route_table->iprmd_ptr, port_info_ptr);
			}
		}
	else
		{
		/* Either the major_port or the minor_port of the 		*/
		/* port_info has not been specified. Make sure that		*/
		/* the next hop is not directly connected.				*/
		if (OPC_COMPCODE_SUCCESS == inet_rte_addr_local_network (next_hop,
				route_table->iprmd_ptr, port_info_ptr))
			{
#ifndef OPD_NO_DEBUG
			/* The next_hop was actually directly connected.	*/
			/* print out a log message.							*/
			ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
			inet_address_print (nh_str, next_hop);

			/* Print out a sim log entry.						*/
			ipnl_port_info_not_specified_in_rte_log_write (dest_str, nh_str, 
				proto, *port_info_ptr, route_table->iprmd_ptr);

			/* Print out a trace message also.					*/
			if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
				{
				ip_cmn_rte_proto_name_print (src_proto_str, proto);
				sprintf (trace_msg, "Dest: %s, Next hop: %s, Protocol: %s, Intf tbl index: %d", 
					dest_str, nh_str, src_proto_str,
				    ip_rte_intf_tbl_index_from_port_info_get (route_table->iprmd_ptr, *port_info_ptr));

				op_prg_odb_print_major ("The port info for the following entry was not specified",
									trace_msg, OPC_NIL);
				}
#endif
			}
		}

	FOUT;
	}
	
static Compcode
ip_cmn_rte_table_dest_prefix_verify (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix)
	{
	/** Makes sure that the given destination prefix is valid	**/
	/** for the given route table.								**/

	FIN (ip_cmn_rte_table_dest_prefix_verify (route_table, dest_prefix));

	/* If the destination prefix is not valid or that particular*/
	/* IP version is not enabled on this node, return failure.	*/
	if ((!ip_cmn_rte_table_dest_prefix_valid (dest_prefix)) ||
		(OPC_NIL == route_table->ptree_ptr_array[ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix)]))
		{
#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_major ("Attempt to insert an invalid entry into the",
									"IP common route table", OPC_NIL);
			}
#endif
		FRET (OPC_COMPCODE_FAILURE);
		}
	else
		{
		/* The prefix is valid.									*/
		FRET (OPC_COMPCODE_SUCCESS);
		}
	}

Compcode
Inet_Cmn_Rte_Table_Entry_Add_Options (IpT_Cmn_Rte_Table* route_table,	void* src_obj_ptr,
	IpT_Dest_Prefix dest_prefix, InetT_Address next_hop, IpT_Port_Info port_info,
	int metric, IpT_Rte_Proc_Id proto, int admin_distance, int options)
	{
	InetT_Addr_Family			addr_family;
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	IpT_Cmn_Rte_Table_Entry*	curr_entry ;
	OmsT_Ptree_Entry*			new_ptree_entry;
	OmsT_Ptree_Entry*			curr_ptree_entry;
	IpT_Rte_Proc_Id				proto_type;
	IpT_Rte_Proc_Id 			removed_proto;
	int							redist_type;
	OmsT_Ptree*					ptree_ptr;
	OmsT_Ptree_Address			address;
	int 						tbl_index;
	
	char						convergence_reason [512];
	
	/* Debug vars.	*/
	char						dest_str [INETC_ADDR_STR_LEN];
	char						nh_str [INETC_ADDR_STR_LEN];
	char						src_proto_str [64];
	char						trace_msg [512];
	
	/** Check for an existing entry for the entered route.		**/
	/** If no entry exists, allocate memory for an				**/
	/** IpT_Cmn_Rte_Table_Entry object and initialize its data 	**/
	/** elements with the values passed in. Add it to the end 	**/
	/** of the route entries list pointed to by the route_table	**/
	/** argument.												**/
	/** If an entry does exist, either replace it (if the new 	**/
	/** admin distance is better), register the protocol in the **/
	/** backup list (if the current admin distance is better), 	**/
	/** or place this new route as an alternate for the route 	**/
	/** entry (if being entered by protocol currently being 	**/
	/** used in the route table.								**/
	FIN (Inet_Cmn_Rte_Table_Entry_Add_Options (route_table, src_obj_ptr, dest, mask,
		next_hop, port_info, metric, proto, admin_distance, options));
	
	/* Make sure the destination prefix is valid.				*/
	if (OPC_COMPCODE_FAILURE == ip_cmn_rte_table_dest_prefix_verify (route_table, dest_prefix))
		{
		FRET (OPC_COMPCODE_FAILURE);
		}

	/* Check if addition for inderect nexthop option is set */
	if (!ip_cmn_rte_table_entry_add_option_is_set (options, IPC_CMN_RTE_TABLE_ENTRY_ADD_INDIRECT_NEXTHOP_OPTION))
		{
		/* Perform the local connectivity check	*/
		/* and make sure port_info is accurate 	*/												
		ip_cmn_rte_table_port_info_verify (route_table, dest_prefix, next_hop,
			&port_info, proto);
		}
	else
		{
		/* Skip local connectivity check and add even 		*/
		/* indirect nexthop addresses and output port info 	*/
		/* This is usually done by MANET routing protocol	*/
		/* where two nodes in different subnet can store 	*/
		/* routes and talk directly as they work on /32 	*/
		/* subnet masks.									*/
		
		/* Verify table index sanity 						*/
		tbl_index = ip_rte_intf_tbl_index_from_port_info_get (route_table->iprmd_ptr, port_info);
		if (tbl_index == IPC_INTF_INDEX_INVALID)
			FRET (OPC_COMPCODE_FAILURE);
		}

	/* Find out whether we are dealing with an IPv4 or an IPv6	*/
	/* route.													*/
	addr_family = ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix);

	/* Initialize the ptree_ptr and address variables based on	*/
	/* the address family.										*/
	ptree_ptr = route_table->ptree_ptr_array[addr_family];
	address = ip_cmn_rte_table_dest_prefix_addr_ptr_get (dest_prefix);

	/* Get a reference to the type of protocol which is sourcing*/
	/* this route.												*/
	proto_type = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (proto);

	/* IPv4 Default routes being inserted into the forwarding	*/
	/* table need to be handled separately.						*/
	if ((0 == ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix)) &&
		(InetC_Addr_Family_v4 == addr_family) &&
		(ip_cmn_rte_table_is_vrf (route_table) == OPC_FALSE))
		{
		ip_cmn_rte_default_route_add (route_table, src_obj_ptr,
			next_hop, port_info, metric, proto, admin_distance);

		/* Nothing more to be done.								*/
		FRET (OPC_COMPCODE_SUCCESS);
		}

	/* Check if a standard routing protocol is adding an entry.	*/
	if ((proto_type < IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID) && (proto_type != IPC_DYN_RTE_DEFAULT))
		{
		/** A standard routing protocol is adding an entry.		**/
		
		/* Because of support for route redistribution and		*/
		/* route maps/filters, there are several cases which	*/
		/* need to be handled.									*/
		/* 														*/
		/* 1: There is no route to the destination network in	*/
		/* the route table from any protocol.					*/
		/* 2: There is a route to the destination network in	*/
		/* the route table and it is provided from the same		*/
		/* protocol.											*/
		/* 3: There is a route to the destination network in	*/
		/* the route table and it is provided from a protocol	*/
		/* which has a better admin distance.					*/
		/* 3A: The protocol in the table is directly connected.	*/
		/* 4: There is a route to the destination network in	*/
		/* the route table and it is provided from a protocol	*/
		/* which has a worse admin distance.					*/
		/* 4A: The new route's protocol is directly connected.	*/
		/*														*/
		/* Directly connected routes need to be handled			*/
		/* differently because the routing protocols which		*/
		/* provide routes to their networks need to be 			*/
		/* redistributed, even though the route table entry is	*/
		/* a directly connected route.							*/
		
		/* Use the keep route option to make sure that we do	*/
		/* not blindly overwrite the existing entry.			*/
		new_ptree_entry = oms_ptree_entry_add (ptree_ptr, address,
			ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix),
			OPC_NIL, OMSC_PTREE_ADD_KEEP_ROUTE, &curr_ptree_entry);
		
		if (PRGC_NIL != curr_ptree_entry)
			{
			/** An entry was found to this destination.			**/

			/* Access the IpT_Cmn_Rte_Table_Entry structure		*/
			/* associated with this entry.						*/
			curr_entry = ip_cmn_rte_table_entry_from_ptree_entry_get (curr_ptree_entry);
			
			if ((curr_entry->admin_distance == admin_distance) && (curr_entry->route_src_proto == proto))
				{
				/** Entry being added is from the same protocol	**/
				/** that is currently being used by IP for this	**/
				/** destination.								**/
				/** This is case number 2						**/
				
				/* Insert the new entry as a new next hop for	*/
				/* this destination.							*/
				ip_cmn_rte_next_hop_add (curr_entry, next_hop, metric, &port_info);
				
				/* Set the last update time.					*/
				if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
					{
					ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
					ip_cmn_rte_proto_name_print (src_proto_str, proto);
					
					if (!strcmp (src_proto_str, "Direct"))
						strcpy (src_proto_str, "Local");
					
					sprintf(convergence_reason, 
						"Added %s route to destination %s.", src_proto_str, dest_str);
					
					ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
					}
				else
					{	
					ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
					}

				/* The type of redistribution is different	*/
				/* in the case of directly connected routes	*/
				/* so determine if this route is directly	*/
				/* connected and set the redist type		*/
				/* accordingly.								*/
				if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (curr_entry->route_src_proto))
					redist_type = IPC_REDIST_TYPE_UPDATE_DIRECT;
				else
					redist_type = IPC_REDIST_TYPE_UPDATE;
				
				/* The protocol which sources this route	*/
				/* has not changed, so the remove proto		*/
				/* should be set to INVALID.				*/
				removed_proto = IpC_Dyn_Rte_Invalid;
				
				/* Redistribute an update message to other	*/
				/* protocols advertising the new next hop	*/
				ip_cmn_rte_table_entry_redistribute (route_table, curr_entry, redist_type, removed_proto);

				/* Check if this entry is being used to resolve	*/
				/* a default network route.						*/
				if (ip_cmn_rte_table_entry_default_ntwk_flag_is_set (curr_entry))
					{
					/* It is possible that the new next hop		*/
					/* caused the metric to improve. Call the	*/
					/* function that will update the default	*/
					/* network route.							*/
					ip_cmn_rte_table_default_network_route_update (route_table, curr_entry);
					}
				FRET (OPC_COMPCODE_SUCCESS);
				}	
			else if (curr_entry->admin_distance > admin_distance)
				{
				/* Entry being added has a better (lower)		*/
				/* admin distance than the entry currently in	*/
				/* the route table. This is case number 3 and 3A*/
				if (curr_entry->admin_distance != OPC_INT_INFINITY)
					{
					/* The current entry isn't being replaced 	*/
					/* When Route_Delete is called and there	*/
					/* is a backup routing protocol, the		*/
					/* admin distance is set to infinity as a	*/
					/* means of poisoning this protocol.  IP	*/
					/* then calls the backup routing protocols	*/
					/* install proc which in turn calls 		*/
					/* Entry_Add.  This essentially removes		*/
					/* the no longer available protocols route	*/
					
					/* Place the current entry in the backup 	*/
					/* list.									*/
					/* TODO: should we free port info			*/
					/* in this case also?						*/	
					ip_cmn_rte_enter_backup (curr_entry, curr_entry->route_src_proto,
						curr_entry->admin_distance, curr_entry->route_src_obj_ptr);
					}
				
				/* The routing protocol which sources this route*/
				/* is changing.  Set the removed_proto to be	*/
				/* the original protocol.						*/
				/* This needs to be set before the route entry	*/
				/* is replaced in the route table.				*/
				if (((curr_entry->admin_distance == OPC_INT_INFINITY) && (proto_type == IPC_DYN_RTE_DIRECTLY_CONNECTED)) ||
					(proto_type != IPC_DYN_RTE_DIRECTLY_CONNECTED))
					{
					removed_proto = curr_entry->route_src_proto;
					}
				else
					removed_proto = IpC_Dyn_Rte_Invalid;
				
				/* Replace the current entry w/ the new entry.	*/
				ip_cmn_rte_entry_replace (route_table, src_obj_ptr, dest_prefix, 
					next_hop, port_info, metric, proto, admin_distance, curr_entry);
				
				/* Set the last update time.					*/
				if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
					{
					ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
					ip_cmn_rte_proto_name_print (src_proto_str, proto);

					if (!strcmp (src_proto_str, "Direct"))
						strcpy (src_proto_str, "Local");			
					sprintf(convergence_reason, 
						"Added %s route to destination %s", src_proto_str, dest_str);
					
					ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
					}
				else
					{	
					ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
					}

				/* The type of redistribution is different	*/
				/* in the case of directly connected routes	*/
				/* so determine if this route is directly	*/
				/* connected and set the redist type		*/
				/* accordingly.								*/
				if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (curr_entry->route_src_proto))
					redist_type = IPC_REDIST_TYPE_UPDATE_DIRECT;
				else
					redist_type = IPC_REDIST_TYPE_UPDATE;
				
				/* Redistribute an update message to other	*/
				/* protocols with the changed information	*/
				/* for this destination.					*/
				ip_cmn_rte_table_entry_redistribute (route_table, curr_entry, redist_type, removed_proto);

				/* The administrative distance of an entry has improved. If	*/
				/* this entry is used to resolve a default network route,	*/
				/* the administrative distance of the default network route	*/
				/* also has to be updated.									*/
				if (ip_cmn_rte_table_entry_default_ntwk_flag_is_set (curr_entry))
					{
					ip_cmn_rte_table_default_network_route_update (route_table, curr_entry);
					}
				}
			else
				{
				/** Existing entry has the better (lower) admin	**/
				/** distance.									**/
				/** This is case number 4 and 4A				**/
				
				/* Insert the new entry into the list of		*/
				/* backup routes.								*/
				ip_cmn_rte_enter_backup (curr_entry, proto, admin_distance, src_obj_ptr);

				/* Some additional work needs to be done if this is a	*/
				/* VRF table entry. If this backup entry is promoted to	*/
				/* be the primary entry, the routing protocol is		*/
				/* invoked (via install_proc) to add the route again.	*/
				/* A fresh port_info object with top and bottom labels	*/
				/* will be generated then. The current MPLS label in	*/
				/* the port info can be freed now.						*/
				if (ip_rte_port_info_contains_mpls_info (&port_info))
					ip_cmn_rte_table_port_info_free (&port_info, route_table);

				
				
				/* If the route is to a directly connected		*/
				/* destination, we still need to send			*/
				/* redistribution interrupts.					*/
				if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (curr_entry->route_src_proto))
					{
					/* if the route which is in the				*/
					/* table currently is a directly connected	*/
					/* route, then the protocol sourcing the	*/
					/* new route must redistribute this route	*/
					/* into other protocols.					*/
					
					/* In this case, there is only one type of	*/
					/* redistribution.  If the route does get	*/
					/* redistributed, it will be for a directly	*/
					/* connected route and an update.			*/
					redist_type = IPC_REDIST_TYPE_UPDATE_DIRECT;
					
					/* The protocol which sources this route	*/
					/* has not changed, so the remove proto		*/
					/* should be set to INVALID.				*/
					removed_proto = IpC_Dyn_Rte_Invalid;
					
					/* Redistribute an update message to other	*/
					/* protocols with the changed information	*/
					/* for this destination.					*/
					/* This route should only be redistributed	*/
					/* if it is a directly connected route. In	*/
					/* all other cases, the backup list does not*/
					/* affect redistribution.					*/
					ip_cmn_rte_table_entry_redistribute (route_table, curr_entry, redist_type, removed_proto);
					}
				}
			FRET (OPC_COMPCODE_SUCCESS);
			}
		}
	else
		{
		/** A custom routing protocol is adding an entry.		**/

		/* Use the keep route option to make sure that we do	*/
		/* not blindly overwrite the existing entry.			*/
		new_ptree_entry = oms_ptree_entry_add (ptree_ptr, address,
			ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix),
			OPC_NIL, OMSC_PTREE_ADD_KEEP_ROUTE, &curr_ptree_entry);

		/* If the entry already exists, don't add it.			*/
		if (PRGC_NIL != curr_ptree_entry)
			{
			FRET (OPC_COMPCODE_FAILURE);
			}
		}

	/** There was no existing entry found in the route table to	**/
	/** this destination.  Create a new entry and add it to the	**/
	/** table.  Then redistribute it to other protocols as a	**/
	/** new route.												**/
	/** This is case number 1									**/

	/* Increment the number of entries in the route table.		*/
	++(route_table->num_entries);

	if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
		{
		ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
		ip_cmn_rte_proto_name_print (src_proto_str, proto);

		if (!strcmp (src_proto_str, "Direct"))
			strcpy (src_proto_str, "Local");
			
		sprintf(convergence_reason, 
			"Added %s route to destination %s", src_proto_str, dest_str);
		ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
		}
	else
		{	
		ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
		}

	/* Create a new IpT_Cmn_Rte_Table_Entry structure			*/
	route_entry = ip_cmn_rte_table_entry_create (dest_prefix, proto, admin_distance, src_obj_ptr);

	/* Make the first entry in the "next_hop" list for the new 	*/
	/* entry the new route.										*/
	ip_cmn_rte_next_hop_add (route_entry, next_hop, metric, &port_info);
	
	/* Set this structure as the src object in the new ptree*/
	/* structure.											*/
	oms_ptree_entry_src_obj_set (new_ptree_entry, route_entry);

	/* Update statistics for this route table.				*/
	op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Entry_Add], 1.0);
	op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
	op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Size], (double) route_table->num_entries);
	
	/* Print trace information.								*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
		{
		/* Re-use the destination and protocol */
		/* strings if created previously.      */
		ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
		ip_cmn_rte_proto_name_print (src_proto_str, proto);
		inet_address_print (nh_str, next_hop);

		/* And now the full message.						*/
		sprintf (trace_msg,
			"Dest |%s|, Next Hop |%s|, O/P Intf. |%d|, Metric |%d| and Src. Proto. |%s|.",
			dest_str, nh_str, ip_rte_intf_tbl_index_from_port_info_get (route_table->iprmd_ptr, port_info), 
			metric, src_proto_str);

		op_prg_odb_print_major ("Adding the following route to the Common IP Routing Table:", OPC_NIL);
		op_prg_odb_print_minor (trace_msg, OPC_NIL);
		}
#endif

	/* In this case, there is only one type of			*/
	/* redistribution.  This is a new route, so the type*/
	/* will be an ADD.									*/
	redist_type = IPC_REDIST_TYPE_ADD;
			
	/* Since there was no route in the table previously	*/
	/* there is no route which can be withdrawn.		*/
	removed_proto = IpC_Dyn_Rte_Invalid;
	
	/* Redistribute this route as a new route to other	*/
	/* routing protocols running on this node.			*/
	ip_cmn_rte_table_entry_redistribute (route_table, route_entry, redist_type, removed_proto);
	
	/* It is possible that because of this new entry, some	*/
	/* of the unresolved default/static routes have now		*/
	/* become resolved. Check for this.						*/
	ip_cmn_rte_table_unresolved_routes_check (route_table, addr_family, route_entry);

	FRET (OPC_COMPCODE_SUCCESS);
	}

void
Inet_Cmn_Rte_Table_Clear (IpT_Cmn_Rte_Table* route_table, InetT_Addr_Family addr_family)
	{
	OmsT_Ptree*			ptree_ptr = OPC_NIL; 
	
	/* Clear out the whole ptree at once using oms_ptree_clear function */
	/* oms_ptree_clear takes care of Lists (next_hop_list, backup_list)	*/
	/* We need to destroy Hash Table (IpT_Cmn_Rte_Dest_Src_Table_Handle)*/

	FIN (Inet_Cmn_Rte_Table_Clear (IpT_Cmn_Rte_Table*, InetT_Addr_Family));
	
	/* Get a pointer to the IPv4 (InetC_Addr_Family_v4)/ IPv6(InetC_Addr_Family_v6) ptree */
	ptree_ptr = route_table->ptree_ptr_array [addr_family];
	
	if (ptree_ptr == OPC_NIL)
		FOUT;
	
	oms_ptree_clear (ptree_ptr, ip_cmn_rte_table_entry_free_proc, route_table);

	/* Destroy the hash table, but do not destroy the values in it */
	prg_string_hash_table_free_proc (route_table->dest_src_table, ip_cmn_rte_table_dest_src_tbl_entry_free);
		
	/* Set table pointer as OPC_NIL */
	route_table->dest_src_table = OPC_NIL;
	
	FOUT;
	}

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_default_route_add (IpT_Cmn_Rte_Table* cmn_rte_table,
	void* src_obj_ptr, InetT_Address next_hop, IpT_Port_Info port_info,
	int metric, IpT_Rte_Proc_Id proto, int admin_distance)
	{
	IpT_Cmn_Rte_Table_Entry *	new_route_entry;
	IpT_Cmn_Rte_Table_Entry *	route_to_next_hop = OPC_NIL;
	IpT_Cmn_Rte_Table_Entry *	old_best_default_route;
	IpT_Dest_Prefix				default_dest_prefix;

	/** Add a 0/0 route to the route table. The route could	**/
	/** be inserted by a dynamic routing protocol or it		**/
	/** could be a static entry.							**/
	/** If this is a valid route the new route entry will be**/
	/** returned.											**/

	FIN (ip_cmn_rte_default_route_add (cmn_rte_table, addr_family, src_obj_ptr, ...));

	/* Create a route table entry structure.				*/
	default_dest_prefix = ip_cmn_rte_table_dest_prefix_create
		(InetI_Default_v4_Addr, inet_smask_from_length_create (0));
	new_route_entry = ip_cmn_rte_table_entry_create (default_dest_prefix,
		proto, admin_distance, src_obj_ptr);

	/* Since this is a 0/0 route, it is a candidate default	*/
	/* Flag the route appropritely.							*/
	ip_cmn_rte_table_entry_cand_default_flag_set (new_route_entry);

	/* Make the first entry in the "next_hop" list for the new entry */
	ip_cmn_rte_next_hop_add (new_route_entry, next_hop, metric, &port_info);

	/* Print trace information.								*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
		{
		char		dest_str [INETC_ADDR_STR_LEN];
		char		src_proto_str [64];
		char		nh_str [INETC_ADDR_STR_LEN];
		char		trace_msg [256];

		ip_cmn_rte_table_dest_prefix_print (dest_str, default_dest_prefix);
		ip_cmn_rte_proto_name_print (src_proto_str, proto);
		inet_address_print (nh_str, next_hop);

		/* And now the full message.						*/
		sprintf (trace_msg,
			"Dest |%s|, Next Hop |%s|, O/P Intf. |%d|, Metric |%d| and Src. Proto. |%s|.",
			dest_str, nh_str, ip_rte_intf_tbl_index_from_port_info_get (route_table->iprmd_ptr, port_info), 
			metric, src_proto_str);

		op_prg_odb_print_major ("Adding the following route to the Common IP Routing Table:", OPC_NIL);
		op_prg_odb_print_minor (trace_msg, OPC_NIL);
		}
#endif
	/* First check if the next hop is reachable.			*/
	/* Note that a default route cannot be used to resolve	*/
	/* the next hop. Do not perform this check for Null0	*/
	/* routes.												*/
	if ((!inet_address_equal (InetI_Null0_Next_Hop_Addr, next_hop)) &&
		(!inet_address_equal (INETC_ADDRESS_INVALID, next_hop)) &&
		((OPC_COMPCODE_FAILURE == inet_cmn_rte_table_lookup (cmn_rte_table,
		   next_hop, OPC_NIL, OPC_NIL, OPC_NIL, &route_to_next_hop)) ||
		 (ip_cmn_rte_table_entry_is_default (route_to_next_hop))))
		{
		/* Next hop is not reachable. Add the entry to the	*/
		/* list of unresolved default routes.				*/
		ip_cmn_rte_default_route_list_add (cmn_rte_table,
			cmn_rte_table->unresolved_default_routes, &new_route_entry);

#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_minor ("The next hop is not reachable.",
				"Adding the route to the list of unresolved default routes", OPC_NIL);
			}
#endif

		/* We need to return NIL since the next hop is not	*/
		/* reachable.										*/
		FRET (OPC_NIL);
		}

	/* If we used another route to resolve the next hop,	*/
	/* flag it.												*/
	if (OPC_NIL != route_to_next_hop)
		{
		ip_cmn_rte_table_entry_default_flag_set (route_to_next_hop);
		}

	/* Next hop is reachable. Add the entry to the list of	*/
	/* resolved default routes. If there is an existing		*/
	/* entry from the same protocol, a new next hop will be	*/
	/* added to that entry.									*/
	ip_cmn_rte_default_route_list_add (cmn_rte_table,
		cmn_rte_table->resolved_default_routes, &new_route_entry);

	/* Cache the existing best default route.				*/
	old_best_default_route = cmn_rte_table->best_default_route;

	/* The new route might replace the gateway of last		*/
	/* resort. Call the function that will check if this	*/
	/* is true.												*/
	ip_cmn_rte_gateway_of_last_resort_update (cmn_rte_table);

#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_minor ("Updating the gateway of last resort...",
				"The new gateway of last resort is:", OPC_NIL);
			ip_cmn_rte_table_entry_print (cmn_rte_table->gateway_of_last_resort);
			}
#endif

	/* Update statistics for this route table.				*/
	op_stat_write (cmn_rte_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
	
	if (oms_routing_convergence_status_check (cmn_rte_table->convg_handle) == OmsC_Convergence_Reached)
		{
		char	dest_str [INETC_ADDR_STR_LEN];
		char	src_proto_str [16];
		char	convergence_reason [256];

		ip_cmn_rte_table_dest_prefix_print (dest_str, new_route_entry->dest_prefix);
		ip_cmn_rte_proto_name_print (src_proto_str, proto); 
	
		sprintf(convergence_reason, 
			"Updated %s route to destination %s", src_proto_str, dest_str);
	
		ip_cmn_rte_table_last_update_time_set (cmn_rte_table, convergence_reason);
		}
	else
		{
		ip_cmn_rte_table_last_update_time_set (cmn_rte_table, OPC_NIL);
		}

	/* Check if the best default route was set.			*/
	if (OPC_NIL == old_best_default_route)
		{
		/* The new entry would have become the BDR. Send*/
		/* an ADD redistribution interrupt.				*/
		ip_cmn_rte_table_entry_redistribute (cmn_rte_table, new_route_entry,
			IPC_REDIST_TYPE_ADD, IpC_Dyn_Rte_Invalid);
		}
	/* There was an existing BDR. Did we add a NH to	*/
	/* this route.										*/
	else if (new_route_entry == old_best_default_route)
		{
		/* We just added a Next hop to the BDR. Send an	*/
		/* UPDATE redistribution interrupt.				*/
		ip_cmn_rte_table_entry_redistribute (cmn_rte_table, new_route_entry,
			IPC_REDIST_TYPE_UPDATE, IpC_Dyn_Rte_Invalid);
		}
	/* The entry that changed was not the original BDR	*/
	/* If the new entry has become the BDR, send an		*/
	/* update interrupt.								*/
	else if (new_route_entry == cmn_rte_table->best_default_route)
		{
		/* The BDR is now a different route, send an	*/
		/* update interrupt.							*/
		ip_cmn_rte_table_entry_redistribute (cmn_rte_table, new_route_entry,
			IPC_REDIST_TYPE_UPDATE, old_best_default_route->route_src_proto);
		}
	/*
	else
		{
		The new route did not become the BDR.
		No need to send any redistribution interrupts.	
		}
	*/

	/* Return the newly created entry.						*/
	FRET (new_route_entry);
	}

static Compcode
ip_cmn_rte_default_route_delete (IpT_Cmn_Rte_Table* cmn_rte_table,
	IpT_Rte_Proc_Id proto, int* admin_dist_ptr)
	{
	IpT_Cmn_Rte_Table_Entry*	default_route_ptr;
	int							index;

	/** A dynamic routing protocol is withdrawing a 0/0		**/
	/** route from the common route table.					**/

	FIN (ip_cmn_rte_default_route_delete (cmn_rte_table, proto));

	/* Print trace information.								*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
		{
		char	trace_msg [256];
		char	src_proto_str [64];
		ip_cmn_rte_proto_name_print (src_proto_str, proto);

		/* And now the full message.						*/
		sprintf (trace_msg, "Deleting the default route inserted by \"%s\".", src_proto_str);

		op_prg_odb_print_major (trace_msg, OPC_NIL);
		}
#endif
	/* Search for a default route inserted by the specified	*/
	/* protocol in the list of resolved default routes.		*/
	if (OPC_NIL != ip_cmn_rte_default_route_list_find
		(cmn_rte_table->resolved_default_routes, proto, &index))
		{
		/* We have found a matching entry.					*/
#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_minor ("Found a matching entry in the list of resolved default routes.", OPC_NIL);
			}
#endif

		/* Remove the entry from the list.					*/
		default_route_ptr = (IpT_Cmn_Rte_Table_Entry*)
			op_prg_list_remove (cmn_rte_table->resolved_default_routes, index);

		/* If this is the current best default route, pick a*/
		/* new one.											*/
		if (cmn_rte_table->best_default_route == default_route_ptr)
			{
			/* Update statistics for this route table.		*/
			op_stat_write (cmn_rte_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
			
			if (oms_routing_convergence_status_check (cmn_rte_table->convg_handle) == OmsC_Convergence_Reached)
				{
				char	dest_str [INETC_ADDR_STR_LEN];
				char	src_proto_str [16];
				char	convergence_reason [256];

				ip_cmn_rte_table_dest_prefix_print (dest_str, default_route_ptr->dest_prefix);
				ip_cmn_rte_proto_name_print (src_proto_str, proto); 
			
				sprintf(convergence_reason, 
					"Updated %s route to destination %s", src_proto_str, dest_str);
			
				ip_cmn_rte_table_last_update_time_set (cmn_rte_table, convergence_reason);
				}
			else
				{
				ip_cmn_rte_table_last_update_time_set (cmn_rte_table, OPC_NIL);
				}

			/* Update the gateway of last resort.			*/
			ip_cmn_rte_gateway_of_last_resort_update (cmn_rte_table);

			/* If the current best default route is unset,	*/
			/* send a WITHDRAW redistribution interrupt.	*/
			if (OPC_NIL == cmn_rte_table->best_default_route)
				{
				ip_cmn_rte_table_entry_redistribute (cmn_rte_table, default_route_ptr,
					IPC_REDIST_TYPE_WITHDRAW, proto);
				}
			else
				{
				/* We now have a different BDR. Send an		*/
				/* UPDATE redistribution interrupt.			*/
				ip_cmn_rte_table_entry_redistribute (cmn_rte_table, cmn_rte_table->best_default_route,
					IPC_REDIST_TYPE_UPDATE, proto);
				}
			}

		/* Fill in the admin distance if it is requested	*/
		if (OPC_NIL != admin_dist_ptr)
			{
			*admin_dist_ptr = default_route_ptr->admin_distance;
			}

		/* Free the memory allocated to the route.			*/
		ip_cmn_rte_table_entry_free (default_route_ptr, cmn_rte_table);

		/* Return SUCCESS to indicate a matching entry was	*/
		/* found.											*/
		FRET (OPC_COMPCODE_SUCCESS);
		}

	/* We did not find a match in the list of resolved		*/
	/* default routes. Try the list of unresolved default	*/
	/* routes.												*/
	if (OPC_NIL != ip_cmn_rte_default_route_list_find
		(cmn_rte_table->unresolved_default_routes, proto, &index))
		{
		/* We have found a matching entry.					*/
#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_minor ("Found a matching entry in the list of unresolved default routes.", OPC_NIL);
			}
#endif

		/* Remove the entry from the list.					*/
		default_route_ptr = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_remove
			(cmn_rte_table->unresolved_default_routes, index);

		/* Fill in the admin distance if it is requested	*/
		if (OPC_NIL != admin_dist_ptr)
			{
			*admin_dist_ptr = default_route_ptr->admin_distance;
			}

		/* Free the memory allocated to the route.			*/
		ip_cmn_rte_table_entry_free (default_route_ptr, cmn_rte_table);

		/* Return SUCCESS to indicate a matching entry was	*/
		/* found.											*/
		FRET (OPC_COMPCODE_SUCCESS);
		}

	/* No matching route could be found. Return failure.	*/
#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_minor ("Could not find a matching entry.", OPC_NIL);
			}
#endif

	FRET (OPC_COMPCODE_FAILURE);
	}

static Compcode
ip_cmn_rte_default_route_next_hop_delete (IpT_Cmn_Rte_Table* cmn_rte_table,
	InetT_Address next_hop, IpT_Rte_Proc_Id proto)
	{
	IpT_Cmn_Rte_Table_Entry*	default_route_ptr;
	int							index;

	/** A dynamic routing protocol is withdrawing a next	**/
	/** hop of a 0/0 route from the common route table.		**/

	FIN (ip_cmn_rte_default_route_next_hop_delete (cmn_rte_table, next_hop, proto));

	/* Print trace information.								*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
		{
		char	trace_msg [256];
		char	src_proto_str [64];
		char	nh_str [INETC_ADDR_STR_LEN];
		ip_cmn_rte_proto_name_print (src_proto_str, proto);
		inet_address_print (nh_str, next_hop);

		/* And now the full message.						*/
		sprintf (trace_msg, "Deleting NH (%s) of the default route inserted by \"%s\".", nh_str, src_proto_str);

		op_prg_odb_print_major (trace_msg, OPC_NIL);
		}
#endif

	/* Search for a default route inserted by the specified	*/
	/* protocol in the list of resolved default routes.		*/
	default_route_ptr = ip_cmn_rte_default_route_list_find
		(cmn_rte_table->resolved_default_routes, proto, &index);

	/* If we found a route, remove the specified next hop.	*/
	if (OPC_NIL != default_route_ptr)
		{
		/* Call the function that will delete the next hop.	*/
		/* If the specified next hop could not be found, the*/
		/* function will return 0.							*/
		if (0 != ip_cmn_rte_next_hop_delete (cmn_rte_table, default_route_ptr, next_hop))
			{
			/* We found a matching next hop.				*/
#ifndef OPD_NO_DEBUG
			if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
				{
				op_prg_odb_print_minor ("Found a matching entry in the list of resolved default routes.", OPC_NIL);
				}
#endif

			/* If we deleted the last next hop. Remove the entry*/
			/* altogether.										*/
			if (0 == op_prg_list_size (default_route_ptr->next_hop_list))
				{
				ip_cmn_rte_default_route_delete (cmn_rte_table, proto, OPC_NIL);
				}
			/* If this is the current best default route, check	*/
			/* if the gateway of last resort or the best default*/
			/* route needs to be updated.						*/
			else if (default_route_ptr == cmn_rte_table->best_default_route)
				{
				/* Update statistics for this route table.		*/
				op_stat_write (cmn_rte_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
				op_stat_write (cmn_rte_table->update_stathandle [IpC_Rte_Table_Next_Hop_Update], 1.0);
				
				if (oms_routing_convergence_status_check (cmn_rte_table->convg_handle) == OmsC_Convergence_Reached)
					{
					char	dest_str [INETC_ADDR_STR_LEN];
					char	src_proto_str [16];
					char	convergence_reason [256];

					ip_cmn_rte_table_dest_prefix_print (dest_str, default_route_ptr->dest_prefix);
					ip_cmn_rte_proto_name_print (src_proto_str, proto); 
				
					sprintf(convergence_reason, 
						"Updated %s route to destination %s", src_proto_str, dest_str);
				
					ip_cmn_rte_table_last_update_time_set (cmn_rte_table, convergence_reason);
					}
				else
					{
					ip_cmn_rte_table_last_update_time_set (cmn_rte_table, OPC_NIL);
					}

				/* Update the gateway of last resort and the	*/
				/* best default route.							*/
				ip_cmn_rte_gateway_of_last_resort_update (cmn_rte_table);

				/* If the best default route changed, send an	*/
				/* UPDATE redistribution interrupt.				*/
				if (default_route_ptr != cmn_rte_table->best_default_route)
					{
					/* Send an update interrupt to other		*/
					/* protocols.								*/
					ip_cmn_rte_table_entry_redistribute (cmn_rte_table, cmn_rte_table->best_default_route,
						IPC_REDIST_TYPE_UPDATE, proto);
					}
				else
					{
					/* The BDR has not changed, but it has lost	*/
					/* a next hop. Send an update interrupt.	*/
					ip_cmn_rte_table_entry_redistribute (cmn_rte_table, default_route_ptr,
						IPC_REDIST_TYPE_UPDATE, IpC_Dyn_Rte_Invalid);
					}
				}

			/* Return success to indicate that a matching route	*/
			/* was found.										*/
			FRET (OPC_COMPCODE_SUCCESS);
			}
		}

	/* We did not find a match in the list of resolved		*/
	/* default routes. Try the list of unresolved default	*/
	/* routes.												*/
	default_route_ptr = ip_cmn_rte_default_route_list_find
		(cmn_rte_table->unresolved_default_routes, proto, &index);

	/* If we found a route, remove the specified next hop.	*/
	if (OPC_NIL != default_route_ptr)
		{
		/* Call the function that will delete the next hop.	*/
		/* If the specified next hop could not be found, the*/
		/* function will return 0.							*/
		if (0 == ip_cmn_rte_next_hop_delete (cmn_rte_table, default_route_ptr, next_hop))
			{
			/* Invalid next hop. Return failure.			*/
			FRET (OPC_COMPCODE_FAILURE);
			}

#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			op_prg_odb_print_minor ("Found a matching entry in the list of unresolved default routes.", OPC_NIL);
			}
#endif

		/* If we deleted the last next hop. Remove the entry*/
		/* altogether.										*/
		if (0 == op_prg_list_size (default_route_ptr->next_hop_list))
			{
			op_prg_list_remove (cmn_rte_table->unresolved_default_routes, index);

			/* Free the memory allocated to the entry.		*/
			ip_cmn_rte_table_entry_free (default_route_ptr, cmn_rte_table);
			}

		/* Return success to indicate that a matching route	*/
		/* was found.										*/
		FRET (OPC_COMPCODE_SUCCESS);
		}

	/* We did not find a matching route. Return failure.	*/
	FRET (OPC_COMPCODE_FAILURE);
	}

static Compcode
ip_cmn_rte_table_default_route_update (IpT_Cmn_Rte_Table* route_table,
	InetT_Address next_hop, IpT_Rte_Proc_Id proto, InetT_Address new_next_hop,
	IpT_Port_Info new_port_info, int new_metric, void* src_obj_ptr)
	{
	IpT_Cmn_Rte_Table_Entry*	rte_entry_ptr;
	IpT_Cmn_Rte_Table_Entry*	old_best_default_route;
	int							index;
	int							admin_distance;
	Compcode					status;
	int							changed;

	/** Update the next hop and/or metric of a 0.0.0.0/0 route	**/

	FIN (ip_cmn_rte_table_default_route_update (route_table, next_hop, ...));

	/* If the new next hop specified is valid, it means that	*/
	/* we need to update the next hop also.						*/
	if (inet_address_valid (new_next_hop))
		{
		/* Just delete the existing route and add a new one.	*/
		/* TODO: Do a proper update rather than a delete and add*/

#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			char	trace_msg [256];
			char	src_proto_str [64];
			char	old_nh_str [INETC_ADDR_STR_LEN];
			char	new_nh_str [INETC_ADDR_STR_LEN];

			/* Print src_proto, next hop etc.					*/
			ip_cmn_rte_proto_name_print (src_proto_str, proto);
			inet_address_print (old_nh_str, next_hop);
			inet_address_print (new_nh_str, new_next_hop);
			sprintf (trace_msg,
				"Old Next Hop |%s|, New Next Hop |%s|, O/P Intf. |%d|, Metric |%d| and Src. Proto. |%s|.",
				old_nh_str, new_nh_str, ip_rte_intf_tbl_index_from_port_info_get (route_table->iprmd_ptr, new_port_info), 
				new_metric, src_proto_str);

			/* And now the full message.						*/
			op_prg_odb_print_major ("Changing the next hop of a default route", OPC_NIL);
			op_prg_odb_print_minor (trace_msg, OPC_NIL);
			}
#endif

		/* Delete the old route.								*/
		status = ip_cmn_rte_default_route_delete (route_table, proto, &admin_distance);

		/* Make sure that there was a matching route.			*/
		if (OPC_COMPCODE_SUCCESS == status)
			{
			/* We have successfully deleted the old route.		*/
			/* Add the new route.								*/
			ip_cmn_rte_default_route_add (route_table, src_obj_ptr,
				new_next_hop, new_port_info, new_metric, proto, admin_distance);
			}

		/* Return the status.									*/
		FRET (status);
		}

	/* The new next hop is invalid. So we only need to update	*/
	/* the metric.												*/

#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			char	trace_msg [256];
			char	src_proto_str [64];
			char	nh_str [INETC_ADDR_STR_LEN];

			/* Print src_proto, next hop etc.					*/
			ip_cmn_rte_proto_name_print (src_proto_str, proto);
			inet_address_print (nh_str, next_hop);
			sprintf (trace_msg,
				"Next Hop |%s|, Metric |%d| and Src. Proto. |%s|.",
				nh_str, new_metric, src_proto_str);

			/* And now the full message.						*/
			op_prg_odb_print_major ("Changing the metric of a default route", OPC_NIL);
			op_prg_odb_print_minor (trace_msg, OPC_NIL);
			}
#endif

	/* Cache the current best default route.					*/
	old_best_default_route = route_table->best_default_route;

	/* Search for a default route inserted by the specified		*/
	/* protocol in the list of resolved default routes.			*/
	rte_entry_ptr = ip_cmn_rte_default_route_list_find
		(route_table->resolved_default_routes, proto, &index);

	/* Did we find a matching entry?							*/
	if (OPC_NIL != rte_entry_ptr)
		{
		/* A resolved default route is being updated. Update the*/
		/* metric of the specified next hop.					*/
		changed = ip_cmn_rte_next_hop_update (rte_entry_ptr, next_hop, INETC_ADDRESS_INVALID,
			new_port_info, new_metric, route_table);

		/* If the entry was changed, update the gateway of		*/
		/* last resort.											*/
		if (changed)
			{
			/* Update the gateway of last resort and the best	*/
			/* default route.									*/
			ip_cmn_rte_gateway_of_last_resort_update (route_table);

			/* Update statistics for this route table.			*/
			op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
			
			if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
				{
				char	dest_str [INETC_ADDR_STR_LEN];
				char	src_proto_str [16];
				char	convergence_reason [256];

				ip_cmn_rte_table_dest_prefix_print (dest_str, rte_entry_ptr->dest_prefix);
				ip_cmn_rte_proto_name_print (src_proto_str, proto); 
				if (!strcmp (src_proto_str, "Direct"))
					strcpy (src_proto_str, "Local");
			
				sprintf(convergence_reason, 
					"Updated %s route to destination %s", src_proto_str, dest_str);
			
				ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
				}
			else
				{
				ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
				}

			/* Redistribute the changed route to other protocols*/
			/* if necessary.									*/

			/* Did the best default route change.				*/
			if (old_best_default_route != route_table->best_default_route)
				{
				/* The BDR is now a different route, send an	*/
				/* update interrupt.							*/
				ip_cmn_rte_table_entry_redistribute (route_table, route_table->best_default_route,
					IPC_REDIST_TYPE_UPDATE, old_best_default_route->route_src_proto);
				}
			/* The BDR is still the same entry. But it is the	*/
			/* entry whose metric we updated, we still need to	*/
			/* send an UPDATE redistribution interrupt.			*/
			else if (old_best_default_route == rte_entry_ptr)
				{
				/* The metric of the BDR has changed.			*/
				ip_cmn_rte_table_entry_redistribute (route_table, rte_entry_ptr,
					IPC_REDIST_TYPE_UPDATE, IpC_Dyn_Rte_Invalid);
				}
			/*
			else
				{
				The entry that we updated was not the BDR and it
				did not become the BDR. No redistribution needed
				}
			*/
			}
		}
	else
		{
		/* We did not find a matching route in the list of		*/
		/* resolved default routes. Try the list of unresolved	*/
		/* default_routes.										*/
		rte_entry_ptr = ip_cmn_rte_default_route_list_find
			(route_table->unresolved_default_routes, proto, &index);

		/* If we found a matching route, update its metric.		*/
		if (OPC_NIL != rte_entry_ptr)
			{
			ip_cmn_rte_next_hop_update (rte_entry_ptr, next_hop, INETC_ADDRESS_INVALID,
				new_port_info, new_metric, route_table);
			}
		else
			{
			/* There is no such route. Return failure.			*/
			FRET (OPC_COMPCODE_FAILURE);
			}
		}

	/* Return success.											*/
	FRET (OPC_COMPCODE_SUCCESS);
	}

static void
ip_cmn_rte_default_route_list_add (IpT_Cmn_Rte_Table* cmn_rte_table,
	List* route_lptr, IpT_Cmn_Rte_Table_Entry** new_entry_pptr)
	{
	int							entry_index, num_entries;
	IpT_Cmn_Rte_Table_Entry*	ith_list_entry;
	int							ith_next_hop, num_next_hops;
	IpT_Next_Hop_Entry*			next_hop_ptr;

	/** Add a new entry to the list of routes. If there is	**/
	/** an existing duplicate entry, a new next hop will be	**/
	/** added to the existing entry and the new entry will	**/
	/** destroyed.											**/

	FIN (ip_cmn_rte_default_route_list_add (route_lptr, new_entry_pptr));

	/* Find out the number of entries in the existing list.	*/
	num_entries = op_prg_list_size (route_lptr);

	/* Loop through the existing list and look for a		*/
	/* duplicate entry.										*/
	for (entry_index = 0; entry_index < num_entries; entry_index++)
		{
		/* Access the entry_index'th routing table entry.	*/
		ith_list_entry = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_access (
					route_lptr, entry_index);
		
		/* An entry will be considered duplicate only if	*/
		/* both the dest_prefix and the source protocol are	*/
		/* the same.										*/
		if ((ip_cmn_rte_table_dest_prefix_equal
				(ith_list_entry->dest_prefix, (*new_entry_pptr)->dest_prefix)) &&
			(ith_list_entry->route_src_proto == (*new_entry_pptr)->route_src_proto))
			{
			/* There is an existing entry. Add the next hops*/
			/* of the new entry to the existing entry.		*/
			num_next_hops = op_prg_list_size ((*new_entry_pptr)->next_hop_list);
			for (ith_next_hop = 0; ith_next_hop < num_next_hops; ith_next_hop++)
				{
				/* Remove the entry at the top of the next	*/
				/* hop list of the new route entry.			*/
				next_hop_ptr = (IpT_Next_Hop_Entry*) op_prg_list_remove
					((*new_entry_pptr)->next_hop_list, OPC_LISTPOS_HEAD);

				/* Append it to the next hop list of the	*/
				/* existing entry.							*/
				op_prg_list_insert (ith_list_entry->next_hop_list, next_hop_ptr, OPC_LISTPOS_TAIL);
				}

			/* Destroy the new entry.						*/
			ip_cmn_rte_table_entry_free (*new_entry_pptr, cmn_rte_table);

			/* Return the existing entry.					*/
			*new_entry_pptr = ith_list_entry;

			FOUT;
			}
		}

	/* There is no existing entry. Append the new entry to	*/
	/* the list.											*/
	op_prg_list_insert (route_lptr, *new_entry_pptr, OPC_LISTPOS_TAIL);

	FOUT;
	}

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_default_route_list_find (List* route_lptr, IpT_Rte_Proc_Id proto, int* index_ptr)
	{
	int							i, num_entries;
	IpT_Cmn_Rte_Table_Entry*	ith_default_route_ptr;

	/** Look for a 0.0.0.0/0 entry inserted by the given	**/
	/** protocol in the list of default routes.				**/

	FIN (ip_cmn_rte_default_route_list_find (route_lptr, proto, index_ptr));

	/* Find out the number of entries in the list.			*/
	num_entries = op_prg_list_size (route_lptr);

	/* Loop through the list.								*/
	for (i = 0; i < num_entries; i++)
		{
		/* Access the ith entry.							*/
		ith_default_route_ptr = (IpT_Cmn_Rte_Table_Entry*)
			op_prg_list_access (route_lptr, i);

		/* If this is not a default network route and the	*/
		/* was inserted by the protocol we are looking for,	*/
		/* return it.										*/
		if ((proto == ith_default_route_ptr->route_src_proto) &&
			(! ip_cmn_rte_table_entry_is_default_network (ith_default_route_ptr)))
			{
			/* We have found the entry we were looking for	*/

			/* Fill the index information.					*/
			*index_ptr = i;

			/* Return the route entry.						*/
			FRET (ith_default_route_ptr);
			}
		}

	/* No match. Return NIL.								*/
	FRET (OPC_NIL);
	}

static int
ip_cmn_rte_default_route_compare (IpT_Cmn_Rte_Table_Entry* entry1, IpT_Cmn_Rte_Table_Entry* entry2)
	{
	int				return_value;
	int				metric1, metric2;

	/** Compares two default route candidates and returns	**/
	/** an integer value indicating which is more preferred.**/
	/** If the return value is 1,  entry1 must be chosen.	**/
	/** If the return value is -1, entry2 must be chosen.	**/
	/** If the return value is 0, both entries are same.	**/

	FIN (ip_cmn_rte_default_route_compare (entry1, entry2));

	/* The following rules are applied in order until we get*/
	/* a result.											*/
	/* Rule 1: Prefer the route with the lower admin weight	*/
	/* Rule 2: If one is a default network and the other a	*/
	/* 		   0/0 route, prefer the one with lower metric	*/
	/* Rule 3: If one is a default network and the other a	*/
	/* 		   0/0 route, prefer the default network route.	*/
	/* Rule 4: Prefer the numerically lower default network.*/

	/* Check if rule 1 can be applied.						*/
	if (entry1->admin_distance != entry2->admin_distance)
		{
		if (entry1->admin_distance < entry2->admin_distance)
			{
			/* Prefer entry1.								*/
			return_value = 1;
			}
		else
			{
			/* Prefer entry2.								*/
			return_value = -1;
			}
		}
	/* Check if Rules 2 and 3 can be applied.				*/
	else if (((IPC_DYN_RTE_DEFAULT == IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (entry1->route_src_proto)) &&
		 (IPC_DYN_RTE_DEFAULT != IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (entry2->route_src_proto))) ||
		((IPC_DYN_RTE_DEFAULT == IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (entry2->route_src_proto)) &&
		 (IPC_DYN_RTE_DEFAULT != IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (entry1->route_src_proto))))
		{
		/* Check if rule 2 can be applied.					*/
		metric1 = ip_cmn_rte_table_entry_least_cost_get (entry1);
		metric2 = ip_cmn_rte_table_entry_least_cost_get (entry2);
		
		if (metric1 != metric2)
			{
			/* Pick the entry with the lower metric.(Rule 2)*/
			if (metric1 < metric2)
				{
				/* Prefer entry1.							*/
				return_value = 1;
				}
			else
				{
				/* Prefer entry2.							*/
				return_value = -1;
				}
			}
		else
			{
			/* Metrics are same. Prefer the default route	*/
			/* Rule 3.										*/
			if (IPC_DYN_RTE_DEFAULT == IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (entry1->route_src_proto))
				{
				/* entry1 is the default route.				*/
				return_value = 1;
				}
			else
				{
				/* entry2 is the default route.				*/
				return_value = -1;
				}
			}
		}
	/* Either both the entries are default network routes	*/
	/* or both entries are 0/0 routes. If they are default	*/
	/* network routes, prefer the numerically lower route	*/
	else if (IPC_DYN_RTE_DEFAULT == IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (entry1->route_src_proto))
		{
		return_value = ip_cmn_rte_table_dest_prefix_compare (entry2->dest_prefix, entry1->dest_prefix);
		}
	else
		{
		/* Both the entries are 0/0 routes with the same	*/
		/* admin distance prefer either one.				*/
		return_value = 0;
		}

	FRET (return_value);
	}

static void
ip_cmn_rte_gateway_of_last_resort_update (IpT_Cmn_Rte_Table* cmn_rte_table)
	{
	int							i, num_default_routes;
	IpT_Cmn_Rte_Table_Entry*	old_golr;
	IpT_Cmn_Rte_Table_Entry*	ith_default_route;

	/** Set the best default route as the gateway of last	**/
	/** resort.												**/

	FIN (ip_cmn_rte_gateway_of_last_resort_update (cmn_rte_table));

	/* Keep a handle to the existing gateway of last resort.*/
	old_golr = cmn_rte_table->gateway_of_last_resort;

	/* Print trace information.								*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_golr"))
		{
		op_prg_odb_print_major ("Updating the gateway of last resort...", OPC_NIL);
		if (OPC_NIL == cmn_rte_table->gateway_of_last_resort)
			{
			op_prg_odb_print_minor ("Currently, the gateway of last resort is unset.", OPC_NIL);
			}
		else
			{
			op_prg_odb_print_minor ("Current Gateway of last resort is", OPC_NIL);
			ip_cmn_rte_table_entry_print (cmn_rte_table->gateway_of_last_resort);

			/* If the GOLR is a default network route, print*/
			/* the BDR also.								*/
			if (ip_cmn_rte_table_entry_is_default_network (cmn_rte_table->gateway_of_last_resort))
				{
				if (OPC_NIL == cmn_rte_table->best_default_route)
					{
					op_prg_odb_print_minor ("Currently, the best default route is unset.", OPC_NIL);
					}
				else
					{
					op_prg_odb_print_minor ("Current Best Default Route is", OPC_NIL);
					ip_cmn_rte_table_entry_print (cmn_rte_table->best_default_route);
					}
				}
			}
		}
#endif

	/* Initialize the gateway of last resort and the best	*/
	/* default route to NIL.								*/
	cmn_rte_table->best_default_route = OPC_NIL;
	cmn_rte_table->gateway_of_last_resort = OPC_NIL;

	/* Find out the number of default routes available.		*/
	num_default_routes = op_prg_list_size (cmn_rte_table->resolved_default_routes);

	/* Loop thorough the remaining routes and look for the	*/
	/* default route.										*/
	for (i = 0; i < num_default_routes; i++)
		{
		/* Get the ith default route.						*/
		ith_default_route = (IpT_Cmn_Rte_Table_Entry*)
			op_prg_list_access (cmn_rte_table->resolved_default_routes, i);

		if ((OPC_NIL == cmn_rte_table->gateway_of_last_resort) ||
			(1 == ip_cmn_rte_default_route_compare (ith_default_route,
				cmn_rte_table->gateway_of_last_resort)))
			{
			/* Update the gateway of last resort.			*/
			cmn_rte_table->gateway_of_last_resort = ith_default_route;
			}

		/* If this is a 0.0.0.0/0 route, check if the		*/
		/* BDR needs to be updated.							*/
		if (! ip_cmn_rte_table_entry_is_default_network (ith_default_route))
			{
			/* If the BDR is currently unset, OR the		*/
			/* current route is better than the current		*/
			/* BDR, make the new route the BDR.				*/
			if ((OPC_NIL == cmn_rte_table->best_default_route) ||
				(1 == ip_cmn_rte_default_route_compare (ith_default_route,
						cmn_rte_table->best_default_route)))
				{
				/* Update the best default route.			*/
				cmn_rte_table->best_default_route = ith_default_route;
				}
			}
		}

	/* If the gateway of last resort has changed, set		*/
	/* the last update time.								*/
	if (old_golr != cmn_rte_table->gateway_of_last_resort)
		{
		ip_cmn_rte_table_last_update_time_set (cmn_rte_table, OPC_NIL);

		/* If the old golr was a 0/0 route, remove the		*/
		/* corresponding entries from the dest src table	*/
		if ((OPC_NIL != old_golr) &&
			(! ip_cmn_rte_table_entry_is_default_network (old_golr)))
			{
			/* Remove the corresponding entries from the	*/
			/* dest src table and free the memory allocated	*/
			/* to the list of keys.							*/
			ip_cmn_rte_table_entry_next_hop_key_lists_clear (cmn_rte_table, old_golr);
			}
		}

	/* Print trace information.								*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_golr"))
		{
		if (OPC_NIL == cmn_rte_table->gateway_of_last_resort)
			{
			op_prg_odb_print_minor ("The gateway of last resort is now unset.", OPC_NIL);
			}
		else
			{
			op_prg_odb_print_minor ("The gateway of last resort is now", OPC_NIL);
			ip_cmn_rte_table_entry_print (cmn_rte_table->gateway_of_last_resort);

			/* If the GOLR is a default network route, print*/
			/* the BDR also.								*/
			if (ip_cmn_rte_table_entry_is_default_network (cmn_rte_table->gateway_of_last_resort))
				{
				if (OPC_NIL == cmn_rte_table->best_default_route)
					{
					op_prg_odb_print_minor ("The best default route is now unset.", OPC_NIL);
					}
				else
					{
					op_prg_odb_print_minor ("The Best Default Route is now", OPC_NIL);
					ip_cmn_rte_table_entry_print (cmn_rte_table->best_default_route);
					}
				}
			}
		}
#endif

	FOUT;
	}

void
ip_cmn_rte_default_network_add (IpT_Cmn_Rte_Table* cmn_rte_table, InetT_Address network_address)
	{
	InetT_Address				major_network_address;
	IpT_Port_Info				port_info;
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	IpT_Cmn_Rte_Table_Entry*	route_to_next_hop;
	InetT_Subnet_Mask			default_mask;
	IpT_Dest_Prefix				dest_prefix;

	/** Add a default network route to the route table.		**/
	/** If we do not have a route to the specified network	**/
	/** this route will be added to the list of unresolved	**/
	/** default routes. If the route table has a route to	**/
	/** the major network specified, the route is accepted.	**/
	/** However if the route table only has a route to a	**/
	/** subnet route, the route is added to the list of		**/
	/** of unresolved next hops.							**/

	FIN (ip_cmn_rte_default_network_add (cmn_rte_table, network_address));

	/* Create a common route table entry to hold the route.	*/
	/* The destiation address will be set to the specified	*/
	/* network address and the mask to 0.0.0.0.				*/
	/* We should not use ip_cmn_rte_table_dest_prefix_create*/
	/* here because that would apply the mask to the network*/
	/* address.												*/
	dest_prefix = inet_address_range_create (network_address, inet_smask_from_length_create (0));
	route_entry = ip_cmn_rte_table_entry_create (dest_prefix,
		IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_DEFAULT, IPC_NO_MULTIPLE_PROC),
		OPC_INT_INFINITY, OPC_NIL);

	/* The above function creates an empty list for the		*/
	/* next_hop_list. We do not need it for this route		*/
	/* because we will be using the next hop list of the	*/
	/* route used to resolve this route.					*/
	op_prg_mem_free (route_entry->next_hop_list);
	route_entry->next_hop_list = OPC_NIL;

	/* Check if network is reachable.						*/
	/* Note that a default route cannot be used to 			*/
	/* resolve the network.									*/
	if ((OPC_COMPCODE_FAILURE == inet_cmn_rte_table_lookup (cmn_rte_table,
		network_address, OPC_NIL, OPC_NIL, OPC_NIL, &route_to_next_hop)) ||
		(ip_cmn_rte_table_entry_is_default (route_to_next_hop)))
		{
		/* Next hop is not reachable.						*/
		op_prg_list_insert (cmn_rte_table->unresolved_default_routes,
			route_entry, OPC_LISTPOS_TAIL);
		}
	else
		{
		/* Check if the specified network address is 		*/
		/* classful.										*/
		if (inet_network_address_is_classful (network_address))
			{
			/* The network address is classful. 			*/
			/* If there is a route to the major network in	*/
			/* the route table accept the route.			*/
			if (ip_cmn_rte_table_classful_entry_exists (cmn_rte_table,
				network_address, &route_to_next_hop))
				{
				/* Accept the route.						*/
				op_prg_list_insert (cmn_rte_table->resolved_default_routes,
					route_entry, OPC_LISTPOS_TAIL);

				/* Flag the route used to resolve the next hop.	*/
				ip_cmn_rte_table_entry_default_ntwk_flag_set (route_to_next_hop);

				/* Also mark that route as a candidate default	*/
				ip_cmn_rte_table_entry_cand_default_flag_set (route_to_next_hop);

				route_entry->admin_distance = route_to_next_hop->admin_distance;

				/* Use the next hop list of the route used to	*/
				/* resolve the default network.					*/
				route_entry->next_hop_list	= route_to_next_hop->next_hop_list;

				/* Update the gateway of last resort if necessary*/
				ip_cmn_rte_table_new_default_route_handle (cmn_rte_table, route_entry);
				}
			else
				{
				/* Store the entry in the list of unresolved	*/
				/* default routes.								*/
				op_prg_list_insert (cmn_rte_table->unresolved_default_routes,
					route_entry, OPC_LISTPOS_TAIL);
				}
			}
		else
			{
			/* The network address specified is not classful*/
			/* We need to add it into the list of unresolved*/
			/* default routes. If there is no route to the	*/
			/* major network, we also need to add a static	*/
			/* route to the same.							*/
			op_prg_list_insert (cmn_rte_table->unresolved_default_routes,
				route_entry, OPC_LISTPOS_TAIL);

			default_mask = inet_default_smask_create (network_address);
			major_network_address = inet_address_mask (network_address, default_mask);

			if (! ip_cmn_rte_table_classful_entry_exists (cmn_rte_table, major_network_address,
				&route_to_next_hop))
				{
				/* There is no existing entry to the major	*/
				/* network. Create a static entry.			*/
				inet_rte_addr_local_network (network_address, cmn_rte_table->iprmd_ptr, &port_info);
				dest_prefix = ip_cmn_rte_table_dest_prefix_create (major_network_address, default_mask);
				ip_cmn_rte_static_route_add (cmn_rte_table, cmn_rte_table->iprmd_ptr->ip_static_rte_table,
					dest_prefix, network_address, port_info, 1 /* admin distance */);
				}
			}
		}

	FOUT;
	}

static Boolean
ip_cmn_rte_table_classful_entry_exists (IpT_Cmn_Rte_Table* route_table, InetT_Address network_address,
	IpT_Cmn_Rte_Table_Entry** curr_entry_pptr)
	{
	InetT_Subnet_Mask		default_mask;
	IpT_Dest_Prefix			dest_prefix;

	/** A lookup performed on the given classful network address	**/
	/** returned the given route entry which might not be a route to**/
	/** the major network. This function will return success if the	**/
	/** the route table does contain a route to the major network.	**/
	/** The curr_entry_pptr argument will be made to point to the 	**/
	/** major network entry.										**/

	FIN (ip_cmn_rte_table_classful_entry_exists (route_table, network_address, curr_entry_pptr));

	/* Get the default subnet mask.									*/
	default_mask = inet_default_smask_create (network_address);
	dest_prefix = ip_cmn_rte_table_dest_prefix_create (network_address, default_mask);

	/* If the subnet mask of the current entry is the default mask	*/
	/* it is the route to the major network. Return success.		*/
	if ((inet_smask_equal (default_mask, ip_cmn_rte_table_dest_prefix_mask_get ((*curr_entry_pptr)->dest_prefix))) ||
		(OPC_COMPCODE_SUCCESS == inet_cmn_rte_table_entry_exists (route_table, dest_prefix, curr_entry_pptr)))
		{
		FRET (OPC_TRUE);
		}
	else
		{
		FRET (OPC_FALSE);
		}
	}

static void
ip_cmn_rte_table_new_default_route_handle (IpT_Cmn_Rte_Table* cmn_rte_table,
	IpT_Cmn_Rte_Table_Entry* new_default_route)
	{
	/** A new default is available. Update the gateway of last resort	**/
	/** if ncecessary.													**/

	FIN (ip_cmn_rte_table_new_default_route_handle (cmn_rte_table, new_default_route));

	/* If the gateway of last resort is not set, use the new route.		*/
	if (OPC_NIL == cmn_rte_table->gateway_of_last_resort)
		{
		cmn_rte_table->gateway_of_last_resort = new_default_route;

		/* If this is a 0.0.0.0/0 route, set the best default route also*/
		if (ip_cmn_rte_table_dest_prefix_addr_equal (new_default_route->dest_prefix, InetI_Default_v4_Addr))
			{
			cmn_rte_table->best_default_route = new_default_route;
			}

		/* Set the last update time.									*/
		ip_cmn_rte_table_last_update_time_set (cmn_rte_table, OPC_NIL);
		}
	/* OR if the new default route is better than the current gateway of*/
	/* last resort replace the gateway of last resort.					*/
	else if (1 == ip_cmn_rte_default_route_compare (new_default_route, cmn_rte_table->gateway_of_last_resort))
		{
		/* Remove all entries in the dest src table corresponding to the*/
		/* old gateway of last resort. If this is a default network		*/
		/* route, we also need to free the next hop list.				*/
		ip_cmn_rte_gateway_of_last_resort_update (cmn_rte_table);
		}
	/* If this is a 0.0.0.0/0 route and it is better than the current	*/
	/* best default route, make it the best default route.				*/
	else if ((! ip_cmn_rte_table_entry_is_default_network (new_default_route)) &&
			 (1 == ip_cmn_rte_default_route_compare (new_default_route, cmn_rte_table->best_default_route)))
		{
		/* Make the new route the best default route.					*/
		cmn_rte_table->best_default_route = new_default_route;
		}

	FOUT;
	}

void
ip_cmn_rte_static_route_add (IpT_Cmn_Rte_Table* route_table, IpT_Rte_Table* static_route_table,
	IpT_Dest_Prefix dest_prefix, InetT_Address next_hop, IpT_Port_Info port_info,
	int admin_distance)
	{
	IpT_Cmn_Rte_Table_Entry*	route_to_next_hop;
	IpT_Rte_Table_Entry*		entry_ptr;
	InetT_Addr_Family			addr_family;
	Boolean						add_route, flag_route;

	/** Add a static route to the common route table.		**/
	/** Before adding the route we need to make sure that	**/
	/** that the next hop of the route is reachable. If it	**/
	/** is not, then we need to store the entry in a		**/
	/** separate list until the next hop becomes reachable.	**/

	FIN (ip_cmn_rte_static_route_add (route_table, static_rte_table, dest, ...));

	/* Get the address family of the destination.			*/
	addr_family = ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix);

	/* Allocate memory for static route entry				*/
	entry_ptr = (IpT_Rte_Table_Entry *) op_prg_mem_alloc (sizeof (IpT_Rte_Table_Entry));

	/* Set the fields appropriately.						*/
	entry_ptr->dest_prefix 	= ip_cmn_rte_table_dest_prefix_copy (dest_prefix);
	entry_ptr->next_hop		= inet_address_copy (next_hop);
	entry_ptr->admin_weight = admin_distance;
		
	/* If this is an IPv4 default route, call the entry add	*/
	/* function directly. 									*/
	if ((0 == ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix)) &&
		(InetC_Addr_Family_v4 == addr_family))
		{
		Inet_Cmn_Rte_Table_Entry_Add (route_table, entry_ptr, entry_ptr->dest_prefix,
			entry_ptr->next_hop, port_info, 0,
			IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Static, IPC_NO_MULTIPLE_PROC),
			admin_distance);
		}
	else
		{
		/* Unless the next hop is null0, invalid or unnumbered, make 	*/
		/* sure that the next hop is reachable. Note that a	default		*/
		/* route cannot be used to resolve the next	hop.				*/
		if (inet_address_equal (InetI_Null0_Next_Hop_Addr, next_hop) ||
			inet_address_equal (INETC_ADDRESS_INVALID, next_hop) ||
			((InetC_Addr_Family_v4 == inet_address_family_get (&next_hop)) &&
			  ip_rte_intf_addr_is_unnumbered(inet_ipv4_address_get (next_hop))))
			{
			/* Next hop is null0, invalid or unnumbered. The route can be entered	*/
			/* into the routing table. Also there is no route in the routing table	*/
			/* that needs to be flagged as a next hop of static route.				*/
			add_route = OPC_TRUE;
			flag_route = OPC_FALSE;
			}
		else
			{
			/* We must ensure that the next hop is reachable. Also the next hop 	*/
			/* must not be reachable by a default route but by a more specific		*/
			/* route.																*/
			if ((OPC_COMPCODE_FAILURE == inet_cmn_rte_table_lookup (route_table,
			     next_hop, OPC_NIL, OPC_NIL, OPC_NIL, &route_to_next_hop)) || 
				 (ip_cmn_rte_table_entry_is_default (route_to_next_hop))) 
				{
				/* Next hop is either not reachable or it is reachable by a default	*/
				/* route. So this route is not ready and must be added to the list	*/
				/* of unresolved routes.											*/
				add_route = OPC_FALSE;
				}
			else
				{
				/* Next hop is reachable by an explicit route. This route can be 	*/
				/* added to the routing table. Also the route to next hop must be	*/
				/* flagged so that when that goes down, we take out this route too.	*/
				add_route = flag_route = OPC_TRUE;
				}
			}
		if (add_route)
			{
			/* Add the entry to the list of resolved static	*/
			/* routes.										*/
			op_prg_list_insert (static_route_table->resolved_static_route_lists[addr_family],
				entry_ptr, OPC_LISTPOS_TAIL);

			/* Add the entry to the common route table.		*/
			Inet_Cmn_Rte_Table_Entry_Add (route_table, entry_ptr, entry_ptr->dest_prefix,
				entry_ptr->next_hop, port_info, 0,
				IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Static, IPC_NO_MULTIPLE_PROC),
				admin_distance);

			if (flag_route)
				ip_cmn_rte_table_entry_static_flag_set (route_to_next_hop);
			}
		else
			{
			/* Route is not currently reachable.	*/
			op_prg_list_insert (static_route_table->unresolved_static_route_lists[addr_family],
				entry_ptr, OPC_LISTPOS_TAIL);
			}
		}
	
	FOUT;
	}

static void
ip_cmn_rte_table_default_network_route_update (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	int							i, num_default_routes;
	IpT_Cmn_Rte_Table_Entry*	ith_default_route;
	InetT_Address				route_entry_dest;

	/** The administrative distance and/or metric of a route**/
	/** that was used to resolve a default route has		**/
	/** changed. Check if we need to update the gateway of	**/
	/** last resort.										**/

	FIN (ip_cmn_rte_table_default_network_route_update (route_table, route_entry));

	/* Store the destination address of the route entry.	*/
	route_entry_dest = ip_cmn_rte_table_dest_prefix_addr_get (route_entry->dest_prefix);

	/* Loop through the list of resolved default routes.	*/
	num_default_routes = op_prg_list_size (route_table->resolved_default_routes);
	for (i = 0; i < num_default_routes; i++)
		{
		ith_default_route = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_access
			(route_table->resolved_default_routes, i);

		/* Check if the destination address of the default	*/
		/* route matches that of the given route.			*/
		if (ip_cmn_rte_table_dest_prefix_addr_equal (ith_default_route->dest_prefix, route_entry_dest))
			{
			/* We have found the default route.				*/
			/* Update its admin weight. Since the next hop	*/
			/* next hop list of this entry already points	*/
			/* to that of the entry used to resolve it, its	*/
			/* metric would be updated automatically.		*/
			ith_default_route->admin_distance = route_entry->admin_distance;

			/* Update the gateway of last resort.			*/
			ip_cmn_rte_gateway_of_last_resort_update (route_table);

			/* Stop looping. A route entry cannot match		*/
			/* more than one default network.				*/
			break;
			}
		}

	FOUT;
	}

static void
ip_cmn_rte_table_unresolved_routes_check (IpT_Cmn_Rte_Table* route_table,
	InetT_Addr_Family addr_family, IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	IpT_Rte_Table*			static_route_table;

	/** A new route entry was added. Check if this causes any	**/
	/** of the existing unresolved routes to become resolved.	**/

	FIN (ip_cmn_rte_table_unresolved_routes_check (route_table, route_entry));

	/* For VRF tables we do not want to perform this check.		*/
	if (ip_cmn_rte_table_is_vrf (route_table))
		{
		FOUT;
		}

	/* Get a pointer to the static routing table.				*/
	static_route_table = route_table->iprmd_ptr->ip_static_rte_table;

	/* If there are any unresolved static routes, check if they	*/
	/* are now reachable.										*/
	if ((OPC_NIL != static_route_table) &&
		(op_prg_list_size (static_route_table->unresolved_static_route_lists[addr_family]) > 0))
		{
		ip_cmn_rte_table_unresolved_static_routes_check (route_table,
			addr_family, route_entry);
		}

	/* If this is an IPv4 route and there are any unresolved	*/
	/* default routes, check if they are now reachable.			*/
	if ((InetC_Addr_Family_v4 == addr_family) &&
		(op_prg_list_size (route_table->unresolved_default_routes) > 0))
		{
		ip_cmn_rte_table_unresolved_default_routes_check (route_table, route_entry);
		}

	FOUT;
	}

static void
ip_cmn_rte_table_unresolved_static_routes_check (IpT_Cmn_Rte_Table* route_table,
	InetT_Addr_Family addr_family, IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	int						i, num_routes;
	IpT_Rte_Table_Entry*	ith_static_route;
	List*					temp_static_route_list = OPC_NIL;
	IpT_Port_Info			port_info;
	IpT_Rte_Table*			static_route_table;

	/** A new route entry was added. Check if this causes any	**/
	/** of the existing unresolved routes to become resolved.	**/

	FIN (ip_cmn_rte_table_unresolved_static_routes_check (unresolved_static_route_lptr, route_entry));

	/* Get a pointer to the static routing table.				*/
	static_route_table = route_table->iprmd_ptr->ip_static_rte_table;

	/* Loop thorough the list of unresolved static routes		*/
	/* Move any matching routes into a temporary list. We need	*/
	/* to use the temporary list because when we call entry add	*/
	/* to add the matching static routes, this function might	*/
	/* get called again recursively.							*/
	num_routes = op_prg_list_size (static_route_table->unresolved_static_route_lists[addr_family]);
	for (i = 0; i < num_routes; i++)
		{
		ith_static_route = (IpT_Rte_Table_Entry*) op_prg_list_access
			(static_route_table->unresolved_static_route_lists[addr_family], i);

		/* Check if the next hop of this entry falls under the	*/
		/* new route.											*/
		if (ip_cmn_rte_table_dest_prefix_check (ith_static_route->next_hop, route_entry->dest_prefix))
			{
			/* Create the temporary list if it is not already	*/
			/* done.											*/
			if (OPC_NIL == temp_static_route_list)
				{
				temp_static_route_list = op_prg_list_create ();
				ip_cmn_rte_table_entry_static_flag_set (route_entry);
				}
			op_prg_list_insert (temp_static_route_list, ith_static_route, OPC_LISTPOS_TAIL);

			/* Remove the entry from the current list.			*/
			op_prg_list_remove (static_route_table->unresolved_static_route_lists[addr_family], i);
			--i;
			--num_routes;
			}
		}

	/* Move all entries from the temporary list into the route 	*/
	/* table.													*/
	if (OPC_NIL != temp_static_route_list)
		{
		num_routes = op_prg_list_size (temp_static_route_list);
		for (i = 0; i < num_routes; i++)
			{
			ith_static_route = (IpT_Rte_Table_Entry*) op_prg_list_remove
				(temp_static_route_list, OPC_LISTPOS_HEAD);

			/* Insert it into the list of resolved static routes*/
			op_prg_list_insert (static_route_table->resolved_static_route_lists[addr_family],
				ith_static_route, OPC_LISTPOS_TAIL);

			/* Add the entry to the common route table.			*/
			inet_rte_addr_local_network_core (ith_static_route->next_hop, route_table->iprmd_ptr,
				&port_info, OPC_NIL);
			Inet_Cmn_Rte_Table_Entry_Add (route_table, ith_static_route, ith_static_route->dest_prefix,
				ith_static_route->next_hop, port_info, 0 /* metric */,
				IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Static, IPC_NO_MULTIPLE_PROC),
				ith_static_route->admin_weight);
			}

		/* Free the memory allocated to the temporary list.		*/
		op_prg_mem_free (temp_static_route_list);
		}

	FOUT;
	}

static void
ip_cmn_rte_table_unresolved_default_routes_check (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	int						i, num_routes;
	IpT_Port_Info			port_info;
	InetT_Subnet_Mask		default_mask;
	IpT_Dest_Prefix			major_network_prefix;
	IpT_Cmn_Rte_Table_Entry	*ith_default_route;
	int						j, num_next_hops;
	IpT_Next_Hop_Entry*		ith_next_hop;
	IpT_Cmn_Rte_Table_Entry	*temp_route_entry;
	IpT_Cmn_Rte_Table_Entry	*old_best_default_route, *current_best_default_route;
	Boolean					bdr_change = OPC_FALSE;
	Boolean					current_bdr_change = OPC_FALSE;
	InetT_Address			route_entry_dest_net;

	FIN (ip_cmn_rte_table_unresolved_default_routes_check (unresolved_default_route_lptr, route_entry));

	/* Cache the existing best default route.					*/
	old_best_default_route = route_table->best_default_route;

	/* Get the network address of the new route entry.			*/
	route_entry_dest_net = ip_cmn_rte_table_dest_prefix_addr_get (route_entry->dest_prefix);

	/* Loop thorugh the list of unresolved default routes and	*/
	/* check if any of them have become reachable now.			*/
	num_routes = op_prg_list_size (route_table->unresolved_default_routes);
	for (i = 0; i < num_routes; i++)
		{
		ith_default_route = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_access
			(route_table->unresolved_default_routes, i);

		/* There will be two types of entries in this list. Default	*/
		/* networks and 0/0 routes. Find out which type of route we	*/
		/* are dealing with here.									*/

		/* This is a default network.							*/
		if (ip_cmn_rte_table_dest_prefix_addr_equal (ith_default_route->dest_prefix, route_entry_dest_net))
			{
			/* If this is major class network, accept the 		*/
			/* default route.									*/
			if (inet_network_address_is_classful (route_entry_dest_net))
				{
				/* Move this default route to the list of		*/
				/* resolved default routes.						*/
				ip_cmn_rte_table_default_network_route_resolve (route_table, i, route_entry);

				/* Decrement the index and the number of routes	*/
				--i;
				--num_routes;
				}
			else
				{
				/* Add a static route to the major class network	*/
				/* unless it already exists.						*/
				default_mask = inet_default_smask_create (route_entry_dest_net);
				major_network_prefix = ip_cmn_rte_table_dest_prefix_create (route_entry_dest_net, default_mask);

				if (! inet_cmn_rte_table_entry_exists (route_table, major_network_prefix, &temp_route_entry))
					{
					/* There is no existing entry to the major		*/
					/* network. Create a static entry.				*/
					port_info = ip_rte_port_info_create (OPC_INT_UNDEF, OPC_NIL);
					ip_cmn_rte_static_route_add (route_table, route_table->iprmd_ptr->ip_static_rte_table,
						major_network_prefix, route_entry_dest_net, port_info, 1);
					}
				}
			}
		else if (ip_cmn_rte_table_dest_prefix_addr_equal (ith_default_route->dest_prefix, InetI_Default_v4_Addr))
			{
			/* This is a 0/0 route.										*/
			/* Check if any of the next hops are now reachable.			*/
			num_next_hops = op_prg_list_size (ith_default_route->next_hop_list);
			for (j = 0; j < num_next_hops; j++)
				{
				ith_next_hop = (IpT_Next_Hop_Entry*) op_prg_list_access
					(ith_default_route->next_hop_list, j);

				/* Check if the next hop of this entry falls under the	*/
				/* new route.											*/
				if (ip_cmn_rte_table_dest_prefix_check (ith_next_hop->next_hop, route_entry->dest_prefix))
					{
					/* This next hop is now reachable.				*/

					/* Create a new route entry with just this next	*/
					/* hop.	If the current entry has only one		*/
					/* next hop use it directly.					*/
					if (1 == num_next_hops)
						{
						/* Use the current default route itself.	*/
						temp_route_entry = ith_default_route;

						/* Remove this entry from the default route	*/
						/* list.									*/
						op_prg_list_remove (route_table->unresolved_default_routes, i);
						--i;
						--num_routes;

						/* Set the ith_default route variable to NIL*/
						ith_default_route = OPC_NIL;
						}
					else
						{
						/* Create a new entry.						*/
						temp_route_entry = ip_cmn_rte_table_entry_create (ith_default_route->dest_prefix,
							ith_default_route->route_src_proto,
							ith_default_route->admin_distance, ith_default_route->route_src_obj_ptr);

						/* Since this is a 0/0 route, it is a candidate	*/
						/* default route. Set the appropriate flag.		*/
						ip_cmn_rte_table_entry_cand_default_flag_set (temp_route_entry);

						/* Add the current next hop to the new route.	*/
						op_prg_list_insert (temp_route_entry->next_hop_list, ith_next_hop, OPC_LISTPOS_TAIL);

						/* Remove the next hop from the current entry.	*/
						op_prg_list_remove (ith_default_route->next_hop_list, j);
						--j;
						--num_next_hops;
						}

					/* Add the new route to the list of resolved	*/
					/* default routes.								*/
					ip_cmn_rte_default_route_list_add (route_table,
						route_table->resolved_default_routes, &temp_route_entry);

					/* Update the gateway of last resort if necessary*/
					ip_cmn_rte_table_new_default_route_handle (route_table, temp_route_entry);

					/* Flag the route use to resolve this route.	*/
					ip_cmn_rte_table_entry_default_flag_set (route_entry);

					/* Set the flag indicating the BDR might have	*/
					/* changed.										*/
					bdr_change = OPC_TRUE;

					/* If the entry that changed is the current BDR	*/
					/* set a separate flag.							*/
					if (temp_route_entry == route_table->best_default_route)
						{
						current_bdr_change = OPC_TRUE;
						}
					}
				}
			/* If there are no more next hops delete the entry altogether	*/
			if ((OPC_NIL != ith_default_route) &&
				(0 == op_prg_list_size (ith_default_route->next_hop_list)))
				{
				op_prg_list_remove (route_table->unresolved_default_routes, i);
				--i;
				--num_routes;
				ip_cmn_rte_table_entry_free (ith_default_route, route_table);
				}
		}
	}

/* If the BDR has changed, we might need to send redistribution	*/
/* interrupts.													*/
if (bdr_change)
	{
	/* Store a handle to the current BDR for faster access.		*/
	current_best_default_route = route_table->best_default_route;

	/* The bdr_change flag will be set only if at least one		*/
	/* default route became reachable. So the current BDR is	*/
	/* not unset. If the old BDR was unset, send an ADD			*/
	/* redistribution interrupt.								*/
	if (OPC_NIL == old_best_default_route)
		{
		ip_cmn_rte_table_entry_redistribute (route_table, current_best_default_route,
			IPC_REDIST_TYPE_ADD, IpC_Dyn_Rte_Invalid);
		}
	/* If a new route is the BDR, send an update interrupt.		*/
	else if (old_best_default_route != current_best_default_route)
		{
		ip_cmn_rte_table_entry_redistribute (route_table, current_best_default_route,
			IPC_REDIST_TYPE_UPDATE, old_best_default_route->route_src_proto);
		}
	/* The BDR is still the same. But if it got a new next hop	*/
	/* we need to send an UPDATE redistribution interrupt.		*/
	else if (current_bdr_change)
		{
		ip_cmn_rte_table_entry_redistribute (route_table, current_best_default_route,
			IPC_REDIST_TYPE_UPDATE, IpC_Dyn_Rte_Invalid);
		}
	/*
	else
		{
		The route that changed did not become the BDR
		No need to send any redistribution intrrupts.
		}
	*/
	}

FOUT;
}

static void
ip_cmn_rte_table_default_network_route_resolve (IpT_Cmn_Rte_Table* route_table,
int route_index, IpT_Cmn_Rte_Table_Entry* route_entry)
{
IpT_Cmn_Rte_Table_Entry*	default_network_route;

/** A default network route that was previously unreachable	**/
/** is now reachable. Move it from the list of unresolved	**/
/** default routes to the list of resolved default routes.	**/

FIN (ip_cmn_rte_table_default_network_route_resolve (route_table, route_index, route_entry));

/* Remove the entry from the list of unresolved		*/
/* default routes.									*/
default_network_route = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_remove
	(route_table->unresolved_default_routes, route_index);

/* Insert it into the list of resolved routes.		*/
op_prg_list_insert (route_table->resolved_default_routes,
	default_network_route, OPC_LISTPOS_TAIL);

/* Set the admin distance of this route to be the	*/
/* admin distance of the route used to resolve this	*/
/* network.											*/
default_network_route->admin_distance = route_entry->admin_distance;

/* Flag the route used to resolve this route.		*/
ip_cmn_rte_table_entry_default_flag_set (route_entry);
default_network_route->route_src_obj_ptr = route_entry;

/* Flag the route as a candidate default.			*/
ip_cmn_rte_table_entry_cand_default_flag_set (route_entry);

/* Also set the flag indicating that the route is	*/
/* being used to resolve a default network route.	*/
ip_cmn_rte_table_entry_default_ntwk_flag_set (route_entry);

/* Make the next_hop_list element point to the 		*/
/* corresponding element of the route entry used to	*/
/* resolve this route.								*/
default_network_route->next_hop_list = route_entry->next_hop_list;

/* Update the gateway of last resort if necessary.	*/
ip_cmn_rte_table_new_default_route_handle (route_table, default_network_route);

/* Return.											*/
FOUT;
}

static void
ip_cmn_rte_table_resolved_routes_check (IpT_Cmn_Rte_Table* route_table,
IpT_Cmn_Rte_Table_Entry* route_entry)
{
/** An entry that was used to resolve a static or a	default	**/
/** route has been removed. Make sure that all the routes	**/
/** are still resolved.										**/

FIN (ip_cmn_rte_table_resolved_routes_check (route_table, route_entry));

/* For VRF tables we do not want to perform this check.		*/
if (ip_cmn_rte_table_is_vrf (route_table))
	{
	FOUT;
	}

/* Check if the static route flag is set for this entry.	*/
if (ip_cmn_rte_table_entry_static_flag_is_set (route_entry))
	{
	ip_cmn_rte_table_resolved_static_routes_check (route_table, route_entry);
	}

/* Check if the default route or default network flag is	*/
/* set for this entry.										*/
if ((ip_cmn_rte_table_entry_default_flag_is_set (route_entry)) ||
	(ip_cmn_rte_table_entry_default_ntwk_flag_is_set (route_entry)))
	{
	ip_cmn_rte_table_resolved_default_routes_check (route_table, route_entry);
	}

FOUT;
}

static void
ip_cmn_rte_table_resolved_static_routes_check (IpT_Cmn_Rte_Table* route_table,
IpT_Cmn_Rte_Table_Entry* route_entry)
{
int						i, num_routes;
IpT_Rte_Table_Entry*	ith_static_route;
IpT_Cmn_Rte_Table_Entry	*route_to_next_hop;
List*					temp_static_route_list = OPC_NIL;
IpT_Rte_Table*			static_route_table;
InetT_Addr_Family		addr_family;

/** A route entry used to resolve a static route is no longer	**/
/** available. Move the affected static routes to the			**/
/** unresolved route list.										**/

FIN (ip_cmn_rte_table_resolved_static_routes_check (route_table, route_entry));

/* Get a pointer to the static route table.					*/
static_route_table = route_table->iprmd_ptr->ip_static_rte_table;

/* Get the address family of the new route.					*/
addr_family = ip_cmn_rte_table_dest_prefix_addr_family_get (route_entry->dest_prefix);

/* First loop thorough the list of resolved static routes	*/
/* Move any matching routes into a temporary list. We need	*/
/* to use the temporary list because when we call entry 	*/
/* remove to add the matching static routes, this function 	*/
/* might get called again recursively.						*/
num_routes = op_prg_list_size (static_route_table->resolved_static_route_lists[addr_family]);
for (i = 0; i < num_routes; i++)
	{
	ith_static_route = (IpT_Rte_Table_Entry*) op_prg_list_access
		(static_route_table->resolved_static_route_lists[addr_family], i);

	/* Check if the next hop of this entry falls under the	*/
	/* new route.											*/
	if (ip_cmn_rte_table_dest_prefix_check (ith_static_route->next_hop, route_entry->dest_prefix))
		{
		/* Look for an alternative route to the next hop.	*/
		if ((!inet_address_equal (InetI_Null0_Next_Hop_Addr, ith_static_route->next_hop)) &&
			(!inet_address_equal (INETC_ADDRESS_INVALID, ith_static_route->next_hop)) &&
			((OPC_COMPCODE_FAILURE == inet_cmn_rte_table_lookup (route_table,
			ith_static_route->next_hop, OPC_NIL, OPC_NIL, OPC_NIL, &route_to_next_hop)) ||
			(ip_cmn_rte_table_entry_is_default (route_to_next_hop))))
			{
			/* Create the temporary list if it is not already	*/
			/* done.											*/
			if (OPC_NIL == temp_static_route_list)
				{
				temp_static_route_list = op_prg_list_create ();
				}
			op_prg_list_insert (temp_static_route_list, ith_static_route, OPC_LISTPOS_TAIL);

			/* Remove the entry from the current list.			*/
			op_prg_list_remove (static_route_table->resolved_static_route_lists[addr_family], i);
			--i;
			--num_routes;
			}
			else if ((!inet_address_equal (InetI_Null0_Next_Hop_Addr, ith_static_route->next_hop)) &&
					 (!inet_address_equal (INETC_ADDRESS_INVALID, ith_static_route->next_hop)))
				{
				/* An alternative entry could be found. flag the route*/
				ip_cmn_rte_table_entry_static_flag_set (route_to_next_hop);
				}
			}
		}

	/* Delete all the routes in the temporary list.					*/
	if (OPC_NIL != temp_static_route_list)
		{
		num_routes = op_prg_list_size (temp_static_route_list);
		for (i = 0; i < num_routes; i++)
			{
			ith_static_route = (IpT_Rte_Table_Entry*) op_prg_list_remove
				(temp_static_route_list, OPC_LISTPOS_HEAD);

			/* Insert it into the list of unresolved static routes	*/
			op_prg_list_insert (static_route_table->unresolved_static_route_lists[addr_family],
				ith_static_route, OPC_LISTPOS_TAIL);

			/* Remove the entry from the common route table.		*/
			Inet_Cmn_Rte_Table_Entry_Delete (route_table, ith_static_route->dest_prefix,
				ith_static_route->next_hop,
				IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Static, IPC_NO_MULTIPLE_PROC));
			}
		op_prg_mem_free (temp_static_route_list);
		}

	FOUT;
	}

static void
ip_cmn_rte_table_resolved_default_routes_check (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	int						i, num_routes;
	IpT_Cmn_Rte_Table_Entry	*ith_default_route;
	IpT_Cmn_Rte_Table_Entry	*route_to_next_hop;
	int						j, num_next_hops;
	IpT_Next_Hop_Entry*		ith_next_hop;
	IpT_Cmn_Rte_Table_Entry	*temp_route_entry;
	InetT_Address			route_entry_dest_net;
	Boolean					bdr_change = OPC_FALSE;
	IpT_Cmn_Rte_Table_Entry	*old_best_default_route, *current_best_default_route;
	IpT_Rte_Proc_Id			old_best_default_route_proto;
	int						index;

	/** An entry used to resolve at least one default route has	**/
	/** been removed. Move all the affected default routes to	**/
	/** unresolved list.										**/

	FIN (ip_cmn_rte_table_resolved_default_routes_check (route_table, route_entry));

	/* Cache the current best default route and it protocol.	*/
	old_best_default_route = route_table->best_default_route;
	if (OPC_NIL != old_best_default_route)
		{
		old_best_default_route_proto = old_best_default_route->route_src_proto;
		}

	/* Get the destination network address of the route entry.	*/
	route_entry_dest_net = ip_cmn_rte_table_dest_prefix_addr_get (route_entry->dest_prefix);

	/* Now check the list of resolved default routes.				*/
	num_routes = op_prg_list_size (route_table->resolved_default_routes);
	for (i = 0; i < num_routes; i++)
		{
		ith_default_route = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_access
			(route_table->resolved_default_routes, i);

		/* There will be two types of entries in this list. Default	*/
		/* networks and 0/0 routes. Find out which type of route we	*/
		/* are dealing with here.									*/

		/* This is a default route.								*/
		if (ip_cmn_rte_table_dest_prefix_addr_equal (ith_default_route->dest_prefix, route_entry_dest_net))
			{
			/* The route entry used to resolve this default route*/
			/* is the one being removed. Move this route to the	*/
			/* list of unresolved default routes.				*/
			op_prg_list_insert (route_table->unresolved_default_routes,
				ith_default_route, OPC_LISTPOS_TAIL);

			op_prg_list_remove (route_table->resolved_default_routes, i);

			/* Update the loop variables.						*/
			--i;
			--num_routes;

			/* If this is the current gateway of last resort,	*/
			/* pick a new one.									*/
			if (route_table->gateway_of_last_resort == ith_default_route)
				{
				/* Remove entries corresponding to the current	*/
				/* gateway of last resort from the dest src		*/
				/* table, etc.									*/
				ip_cmn_rte_gateway_of_last_resort_update (route_table);
				}
			}
		else if (ip_cmn_rte_table_dest_prefix_addr_equal (ith_default_route->dest_prefix, InetI_Default_v4_Addr))
			{
			/* This is a 0/0 route. Check if any of the next hops	*/
			/* have become unreachable.								*/
			num_next_hops = op_prg_list_size (ith_default_route->next_hop_list);
			for (j = 0; j < num_next_hops; j++)
				{
				ith_next_hop = (IpT_Next_Hop_Entry*) op_prg_list_access
					(ith_default_route->next_hop_list, j);

				/* Check if the next hop of this entry falls under the	*/
				/* new route.											*/
				if ((!inet_address_equal (InetI_Null0_Next_Hop_Addr, ith_next_hop->next_hop)) &&
					(!inet_address_equal (INETC_ADDRESS_INVALID, ith_next_hop->next_hop)) &&
					(ip_cmn_rte_table_dest_prefix_check (ith_next_hop->next_hop, route_entry->dest_prefix)))
					{
					/* Look for an alternative route to the next hop.	*/
					if ((OPC_COMPCODE_FAILURE == inet_cmn_rte_table_lookup (route_table,
						  ith_next_hop->next_hop, OPC_NIL, OPC_NIL, OPC_NIL, &route_to_next_hop)) ||
						 (ip_cmn_rte_table_entry_is_default (route_to_next_hop)))
						{
						/* Create a new route entry with just this next	*/
						/* hop.	If this route has only one next hop,	*/
						/* use it directly.								*/
						if (1 == num_next_hops)
							{
							/* We have lost the only next hop. Remove	*/
							/* the entry from the list of resolved		*/
							/* default routes.							*/
							op_prg_list_remove (route_table->resolved_default_routes, i);

							/* Decrement the loop variables to handle	*/
							/* the fact that there is one less entry.	*/
							--i;
							--num_routes;

							/* Use the existing entry.					*/
							temp_route_entry = ith_default_route;
							}
						else
							{
							temp_route_entry = ip_cmn_rte_table_entry_create (ith_default_route->dest_prefix,
								ith_default_route->route_src_proto,
								ith_default_route->admin_distance, ith_default_route->route_src_obj_ptr);

							/* Move the next hop to the new list.		*/
							op_prg_list_insert (temp_route_entry->next_hop_list, ith_next_hop, OPC_LISTPOS_TAIL);

							/* Remove the next hop from the current entry*/
							op_prg_list_remove (ith_default_route->next_hop_list, j);

							/* Decrement the loop variables to indicate	*/
							/* that we have one less entry.				*/
							--j;
							--num_next_hops;
							}

						/* If this entry is the current best default 	*/
						/* route, check if it needs to be updated.		*/
						if (route_table->best_default_route == ith_default_route)
							{
							ip_cmn_rte_gateway_of_last_resort_update (route_table);
							
							/* Set the flag indicating that the best	*/
							/* default route might have changed.		*/
							bdr_change = OPC_TRUE;
							}

						/* Move temp_route_entry to the list of unresolved	*/
						/* default routes.									*/
						ip_cmn_rte_default_route_list_add (route_table,
							route_table->unresolved_default_routes, &temp_route_entry);
						}
					else
						{
						/* An alternative entry could be found. flag the route*/
						ip_cmn_rte_table_entry_default_flag_set (route_to_next_hop);
						}
					}
				}
			}
		}

	/* If the bdr changed, we might need to send a redistribution	*/
	/* interrupt.													*/
	if (bdr_change)
		{
		/* Since the bdr_change flag is set, it means that there was*/
		/* at least one resolved default route. So 					*/
		/* old_best_default_route is not NIL.						*/

		/* Get a handle to the current BDR for faster access.		*/
		current_best_default_route = route_table->best_default_route;

		/* If the BDR is still the same route, send an UPDATE		*/
		/* redistribution interrupt since we lost a next hop.		*/
		if (old_best_default_route == current_best_default_route)
			{
			ip_cmn_rte_table_entry_redistribute (route_table, current_best_default_route,
				IPC_REDIST_TYPE_UPDATE, IpC_Dyn_Rte_Invalid);
			}
		else if (OPC_NIL == current_best_default_route)
			{
			/* The current BDR is unset. Send a WITHDRAW			*/
			/* redistribution interrupt.							*/
			/* Note that the memory allocated to the				*/
			/* old_best_default_route might be freed by now. So we	*/
			/* need to obtain the current entry from the list of	*/
			/* unresolved default routes.							*/
			old_best_default_route = ip_cmn_rte_default_route_list_find (route_table->unresolved_default_routes,
				old_best_default_route_proto, &index);

			/* If we did not find a match it is an error.			*/
			if (OPC_NIL == old_best_default_route)
				{
				op_sim_error (OPC_SIM_ERROR_ABORT,
					"Logic Error in IP common route table.",
					"Unable to find default route.");
				}
			else
				{
				ip_cmn_rte_table_entry_redistribute (route_table, old_best_default_route,
					IPC_REDIST_TYPE_WITHDRAW, old_best_default_route_proto);
				}
			}
		else
			{
			/* The BDR has changed, send an update interrupt.		*/
			ip_cmn_rte_table_entry_redistribute (route_table, current_best_default_route,
				IPC_REDIST_TYPE_UPDATE, old_best_default_route_proto);
			}
		}

	FOUT;
	}

Compcode
Inet_Cmn_Rte_Table_Route_Delete (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix, IpT_Rte_Proc_Id proto)
	{
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	InetT_Addr_Family			addr_family;
	Compcode					retcode; 
	OmsT_Ptree*					ptree_ptr;
	OmsT_Ptree_Address			address;
	OmsT_Ptree_Entry_Index		index;

	/** Find and delete THE MATCHING ENTRY from the IP			**/
	/** route table. On success return OPC_COMPCODE_SUCCESS		**/
	/** otherwise, return OPC_COMPCODE_FAILURE.					**/
	/** An entry is characterized by its destination, mask		**/
	/** and source protocol values.								**/
	/** This function is called when a routing protocol no		**/
	/** longer has any routes to a particular destination.		**/
	
	FIN (Inet_Cmn_Rte_Table_Route_Delete (route_table, dest_prefix, proto));

	/* Get the address family.									*/
	addr_family = ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix);

	/* IPv4 Default routes need to be handled separately if this*/
	/* is a forwarding table.									*/
	if ((0 == ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix)) &&
		(InetC_Addr_Family_v4 == addr_family) &&
		(ip_cmn_rte_table_is_vrf (route_table) == OPC_FALSE))
		{
		retcode = ip_cmn_rte_default_route_delete (route_table, proto, OPC_NIL);

		/* Nothing more to be done.								*/
		FRET (retcode);
		}

	/* Initialize the ptree_ptr and address variables based on	*/
	/* the address family.										*/
	ptree_ptr = route_table->ptree_ptr_array[addr_family];
	address = ip_cmn_rte_table_dest_prefix_addr_ptr_get (dest_prefix);

	/* Check whether the entry actually exists.					*/
	index = oms_ptree_entry_exists (ptree_ptr, address,
		ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix));

	if (OMSC_PTREE_ENTRY_INDEX_INVALID == index)
		{
		/* There is no entry in the route table for the			*/
		/* provided destination.								*/

		FRET (OPC_COMPCODE_FAILURE);
		}
	
	/* Access the route entry itself.							*/
	route_entry = ip_cmn_rte_table_entry_from_ptree_entry_get
		(oms_ptree_entry_access_by_index (ptree_ptr, index));

	if (route_entry->route_src_proto != proto)
		{
		/* The entry in the route table was provided by a		*/
		/* different protocol than the one trying to delete		*/
		/* the route.											*/

		/* Delete the route provided by this protocol from		*/
		/* the backup list.										*/
		ip_cmn_rte_delete_backup (route_table, proto, route_entry);
		
		retcode = OPC_COMPCODE_SUCCESS;
		}
	else
		{
		/* The entry in the route table was provided by the		*/
		/* protocol trying to delete the route.					*/
		
		/* Remove the route from the route table. This function	*/
		/* will also promote a route from the backup list if	*/
		/* there are any. It will also take care of any 		*/
		/* redistributing or withdraw messages to other protocols*/
		retcode = ip_cmn_rte_table_rte_list_entry_delete (route_table, route_entry, index, proto, dest_prefix);
		}

	/* Free the memory allocated to the entry index.			*/
	oms_ptree_entry_index_destroy (index);

	FRET (retcode);
	}

static Compcode
ip_cmn_rte_table_rte_list_entry_delete (IpT_Cmn_Rte_Table* route_table, IpT_Cmn_Rte_Table_Entry* route_entry,
	OmsT_Ptree_Entry_Index index, IpT_Rte_Proc_Id proto, IpT_Dest_Prefix dest_prefix)
	{
	Compcode					retcode;
	int							dest_index;
	IpT_Rte_Info*				generic_rte_info_ptr = OPC_NIL;
	IpT_Backup_Entry*			backup_entry;
	IpT_Rte_Proc_Id				proto_type;
	int							redist_type;
	IpT_Rte_Proc_Id				removed_proto;
	OmsT_Ptree*					ptree_ptr;
	OmsT_Ptree_Entry*			ptree_entry;
	OmsT_Ptree_Address			address;
	int							i, num_next_hops;
	IpT_Next_Hop_Entry*			ith_next_hop;
	char						convergence_reason [512];

	/* Debug vars.	*/
	char						dest_str [INETC_ADDR_STR_LEN];
	char						new_proto_str [32];
	char						src_proto_str [32];
#ifndef OPD_NO_DEBUG
	char						trace_msg1 [512];
	char						trace_msg2 [512];
#endif
	IpT_Address					ipv4_dest;
	IpT_Address					ipv4_mask;
	char    					string [32];
	int							as_id;
	int							backup_proto_type;
	IpT_Rte_Proto_Oms_Pr_Info*	pr_reg_info_ptr;

	/** Delete the referenced entry from the IP route table.	**/
	/** Redistribute a withdraw message for this route to other	**/
	/** routing protocols.  If there are any routes in the 		**/
	/** backup list from other protocols, then promote them 	**/
	/** from the backup list and redistribute the new route to	**/
	/** other protocols.										**/
	/** If the route in the table is a directly connected		**/
	/** network, then check that the calling protocol is		**/
	/** configured on the appropriate interface.  If it is,		**/
	/** then send a withdrawal on behalf of this protocol.		**/
	
	FIN (ip_cmn_rte_table_rte_list_entry_delete (route_table, route_entry, index, proto, dest_prefix));
	
	/* Get a handle on the type of routing protocol which is	*/
	/* removing this entry.										*/
	proto_type = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (proto);

	if ((OPC_NIL != route_entry->backup_list) && (op_prg_list_size (route_entry->backup_list) > 0))
		{
		pr_reg_info_ptr = route_table->iprmd_ptr->rte_proto_oms_pr_info_ptr;
		
		/** This route table entry has a backup to this 		**/
		/** destination from another routing protocol.			**/
		
	   	/* Write out a sim log warning about deleted route 		*/
		ipnl_rte_table_route_loss (route_entry, OPC_TRUE);
		
		/* Poison current entry so it can be replaced by  		*/
		/* the backup routing protocol that will add its route 	*/
		/* The removing of this route as the primary route will	*/
		/* be handled in Entry_Add, which will be called by		*/
		/* the backup entry protocol's install proc.			*/
		route_entry->admin_distance = OPC_INT_INFINITY;
		
		/* Remove the top entry from the backup list and based	*/
		/* on the routing protocol which sourced it, call it's	*/
		/* install proc.										*/
		backup_entry = (IpT_Backup_Entry *) op_prg_list_remove (route_entry->backup_list, OPC_LISTPOS_HEAD);

		/* Use the normalized routing protocol of this entry.	*/
		backup_proto_type = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (backup_entry->route_proto));
		switch (backup_proto_type)
			{
			case IPC_DYN_RTE_OSPF: 
				{
				strcpy (new_proto_str, "OSPF");

				as_id = IP_CMN_RTE_TABLE_ROUTEPROC_AS_NUMBER (backup_entry->route_proto);
				
				sprintf (string, "\"routing information %d\"", as_id);
				
				oms_pr_attr_get (pr_reg_info_ptr->ospf_procreg_handle,
					string, OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
				
			case IPC_DYN_RTE_RIP:
				{
				strcpy (new_proto_str, "RIP");
				oms_pr_attr_get (pr_reg_info_ptr->rip_procreg_handle,
					"routing information", OMSC_PR_POINTER, &generic_rte_info_ptr);	
				break;
				}
				
			case IPC_DYN_RTE_IGRP:
				{
				strcpy (new_proto_str, "IGRP");
				oms_pr_attr_get (pr_reg_info_ptr->igrp_procreg_handle,
					"routing information", OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
				
			case IPC_DYN_RTE_EIGRP:
				{
				strcpy (new_proto_str, "EIGRP");

				as_id = IP_CMN_RTE_TABLE_ROUTEPROC_AS_NUMBER (backup_entry->route_proto);
				
				sprintf (string, "\"routing information %d\"", as_id);
					
				oms_pr_attr_get (pr_reg_info_ptr->eigrp_procreg_handle,
					string, OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
				
			case IPC_DYN_RTE_BGP:
				{
				strcpy (new_proto_str, "BGP");
				oms_pr_attr_get (pr_reg_info_ptr->bgp_procreg_handle,
					"routing information", OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
			case IPC_DYN_RTE_ISIS:
				{
				strcpy (new_proto_str, "IS-IS");
				oms_pr_attr_get (pr_reg_info_ptr->isis_procreg_handle,
					"routing information", OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
			case IPC_DYN_RTE_STATIC:
				{
				strcpy (new_proto_str, "STATIC");
				oms_pr_attr_get (pr_reg_info_ptr->ip_procreg_handle,
					"routing information", OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
			case IPC_DYN_RTE_RIPNG:
				{
				strcpy (new_proto_str, "RIPNG");
				oms_pr_attr_get (pr_reg_info_ptr->ripng_procreg_handle,
					"routing information", OMSC_PR_POINTER, &generic_rte_info_ptr);
				break;
				}
			default:
				{
				/* Not a standard routing protocol. Should not occur.	*/
				ip_cmn_rte_proto_name_print (new_proto_str, backup_entry->route_proto);
				break;
				}
			}
	
		if (generic_rte_info_ptr == OPC_NIL)
			{
			/** There was a problem with finding the correct	**/
			/** install proc.  Exit out of the function.		**/
			char msg [256];
			sprintf (msg, "Unable to find routing information for backup protocol: \"%s\"", new_proto_str);

			op_sim_error (OPC_SIM_ERROR_RECOVER, "In ip_cmn_rte_table_rte_list_entry_delete", msg);
			
			/* The administrative distance of an entry has worsened. If	*/
			/* this entry is used to resolve a default route, the		*/
			/* administrative distance of the default route also has to	*/
			/* be updated.												*/
			if (ip_cmn_rte_table_entry_default_ntwk_flag_is_set (route_entry))
				{
				ip_cmn_rte_table_default_network_route_update (route_table, route_entry);
				}

			FRET (OPC_COMPCODE_SUCCESS);
			}
		else
			{
			/** An install proc exists for the sourcing protocol**/

			/* Call the install proc for this protocol.				*/
			/* This will call the IP route add function to			*/
			/* install the route into the route table.				*/
		
			/* All protocols except RIPng and Static use 			*/
			/* install_proc. RIPng and Static use inet_install_proc	*/
			/* OSPFv3 now uses inet_install_proc as well.			*/
			if ((IPC_DYN_RTE_STATIC != backup_proto_type) &&
				(IPC_DYN_RTE_RIPNG != backup_proto_type) &&
				(IPC_DYN_RTE_OSPF != backup_proto_type))
				{
				/* RIP and IGRP currently rely on the NATO table.	*/
				/* Get the index for this destination.				*/
				/* Ensure that these protocols do not try to work	*/
				/* with invalid indices.							*/
				dest_index = inet_rtab_network_convert (ip_cmn_rte_table_dest_prefix_addr_get_fast (dest_prefix));
			 
				if (dest_index != IPC_FAST_ADDR_INVALID ||
					strcmp (new_proto_str, "BGP") == 0  ||
					strcmp (new_proto_str, "IS-IS") == 0 ||
					strcmp (new_proto_str, "EIGRP") == 0)
					{
					/** The index for RIP and IGRP was valid.		**/
					/** All other standard protocols can step right	**/
					/** into this statement.						**/

					ipv4_dest = ip_cmn_rte_table_dest_prefix_ipv4_addr_get (dest_prefix);
					ipv4_mask = ip_cmn_rte_table_dest_prefix_ipv4_mask_get (dest_prefix);
					
					/* Set the install proc for this protocol.		*/
					retcode = (*(generic_rte_info_ptr->install_proc)) (
						dest_index, generic_rte_info_ptr->table_handle, route_table, ipv4_dest, ipv4_mask);
					}
				else
					{
					/* The administrative distance of an entry has worsened. If	*/
					/* this entry is used to resolve a default route, the		*/
					/* administrative distance of the default route also has to	*/
					/* be updated.												*/
					if (ip_cmn_rte_table_entry_default_ntwk_flag_is_set (route_entry))
						{
						ip_cmn_rte_table_default_network_route_update (route_table, route_entry);
						}

					FRET (OPC_COMPCODE_SUCCESS);
					}
				}
			else
				{
				/* Use the inet_install_proc.					*/
				retcode = (*(generic_rte_info_ptr->inet_install_proc))
					(generic_rte_info_ptr->table_handle, route_table, dest_prefix);
				}
			}

		/**  Must add comments and  trace activated print 		**/
		/** statements to indicate that a route was replaced by	**/
		/** another routing protocol							**/
#ifndef OPD_NO_DEBUG		
		/* Print trace information.								*/
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
			ip_cmn_rte_proto_name_print (src_proto_str, proto);

			/* And now the full message.						*/
			sprintf (trace_msg1,
				"|%s| has removed its route entry to network |%s|",
				src_proto_str, dest_str);
			
			sprintf (trace_msg2,
				"|%s| has a route entry to network |%s| and will add it to the IP Routing Table",
				new_proto_str, dest_str);
			
			op_prg_odb_print_major (
				"Changing Routing Protocols for an IP Routing Table Entry:", OPC_NIL);
			op_prg_odb_print_minor (trace_msg1, OPC_NIL);
			op_prg_odb_print_minor (trace_msg2, OPC_NIL);
			}
#endif
		}
	else
		{
		/** There is no protocol with an entry in the backup	**/
		/** list for this destination.							**/
		
		/** Must add comments and  trace activated print		**/
		/** statements to indicate that a route was deleted 	**/
#ifndef OPD_NO_DEBUG		
		/* Print trace information.								*/
		if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
			{
			ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
			ip_cmn_rte_proto_name_print (src_proto_str, proto);

			sprintf (trace_msg1,
				"Dest |%s|, Src. Proto. |%s|.", dest_str, src_proto_str);
			
			op_prg_odb_print_major (
				"Deleting the following destination from the Common IP Routing Table:", OPC_NIL);
			op_prg_odb_print_minor (trace_msg1, OPC_NIL);
			}
#endif
		
		/* Initialize the ptree_ptr and address variables based */
		/* on the address family.								*/
		ptree_ptr = route_table->ptree_ptr_array[ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix)];
		address = ip_cmn_rte_table_dest_prefix_addr_ptr_get (dest_prefix);

		/* Remove the route entry from the route table.			*/
		ptree_entry = oms_ptree_entry_remove_by_index (ptree_ptr, index);

		/* Decrement the number of entries in the table.		*/
		--(route_table->num_entries);

		/* This process may have redistributed this route to	*/
		/* other routing processes.  Redistribute a withdraw	*/
		/* message to those protocols for this route.			*/
		/* NOTE: Withdraw messages are only sent when all		*/
		/* routes to a network have been removed from the route	*/
		/* table.												*/
		
		/* Since this route is no longer in the route table,	*/
		/* set the redist type to be a withdraw message.		*/
		redist_type = IPC_REDIST_TYPE_WITHDRAW;
		
		/* Since there is no change or source protocol for this	*/
		/* route, set the removed proto to be invalid.			*/
		removed_proto = IpC_Dyn_Rte_Invalid;
		
		/* Call the function that will redistribute this 	*/
		/* withdrawal messageinto other routing protocols. 	*/
		ip_cmn_rte_table_entry_redistribute (route_table, route_entry, redist_type, removed_proto);

		/* Update statistics for this route table.				*/
		op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Entry_Delete], 1.0);
		op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
		op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Size], (double) route_table->num_entries);
		if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
			{
			ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
			ip_cmn_rte_proto_name_print (src_proto_str, proto); 
			if (!strcmp (src_proto_str, "Direct"))
				strcpy (src_proto_str, "Local");
			
			sprintf (convergence_reason, 
				"Deleted %s route to destination %s", src_proto_str, dest_str); 
			
			ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
			}
		else
			{
			ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
			}
		
		/* If this entry is being used to resolve a		*/
		/* static or default route, we need to make sure*/
		/* that they have not become unreachable.		*/
		ip_cmn_rte_table_resolved_routes_check (route_table, route_entry);

		/* Loop through the list of next hops and withdraw the	*/
		/* corresponding dest src table entries.				*/
		num_next_hops = op_prg_list_size (route_entry->next_hop_list);
		for (i = 0; i < num_next_hops; i++)
			{
			ith_next_hop = (IpT_Next_Hop_Entry*) op_prg_list_access
				(route_entry->next_hop_list, i);
			ip_cmn_rte_table_dest_src_table_entries_remove (route_table, ith_next_hop);
			}

		/* Free the memory occupied by this entry.				*/
		/* Pass the common route table as the argument to the	*/
		/* destroy proc. IP module data information is used to	*/
		/* free any MPLS resources (bottom labels) associated	*/
		/* with the port info inside the next hop information.	*/
		oms_ptree_entry_destroy (ptree_entry, ip_cmn_rte_table_entry_free_proc, route_table);

		/* Set the entry status flag.							*/
		retcode = OPC_COMPCODE_SUCCESS;
		}
	
	FRET (retcode);
	}

static void
ip_cmn_rte_table_entry_free_proc (void* entry_ptr, void* state_ptr)
	{
	/** Function to be used with oms_ptree_entry_destroy		**/

	FIN (ip_cmn_rte_table_entry_free_proc (cmn_rte_table_ptr));

	ip_cmn_rte_table_entry_free ((IpT_Cmn_Rte_Table_Entry*) entry_ptr, (IpT_Cmn_Rte_Table*) state_ptr);

	FOUT;
	}

Compcode
Inet_Cmn_Rte_Table_Entry_Delete (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
	InetT_Address next_hop, IpT_Rte_Proc_Id proto)
	{
	int							changed;
	OmsT_Ptree_Entry_Index		index;
	IpT_Cmn_Rte_Table_Entry* 	route_entry;
	Boolean						delete_last_next_hop = OPC_FALSE;
	int							redist_type;
	IpT_Rte_Proc_Id				removed_proto;
	OmsT_Ptree*					ptree_ptr;
	OmsT_Ptree_Address			address;
   
	char						convergence_reason [512];
	
	char						dest_str [INETC_ADDR_STR_LEN];
	char 						src_proto_str[64];
	char						nhop_str [INETC_ADDR_STR_LEN];
	char						trace_msg1 [512];
	Compcode					status;
	InetT_Addr_Family			addr_family;
	
	/** This function will delete a next hop entry for given	**/
	/** destination.  The function will attempt to delete only	**/
  	/** the given next hop for the entry.  If the next hop is	**/
	/** the only next hop for the entry, then the entire entry	**/
	/** will be removed from the table.							**/

	FIN (Inet_Cmn_Rte_Table_Entry_Delete (route_table, dest_prefix, next_hop, proto));
	
	/* Get the address family.									*/
	addr_family = ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix);

	/* IPv4 Default routes need to be handled separately if this*/
	/* is a forwarding table.									*/
	if ((0 == ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix)) &&
		(InetC_Addr_Family_v4 == addr_family) &&
		(ip_cmn_rte_table_is_vrf (route_table) == OPC_FALSE))
		{
		status = ip_cmn_rte_default_route_next_hop_delete (route_table, next_hop, proto);

		/* Nothing more to be done.								*/
		FRET (status);
		}

	/* Initialize the ptree_ptr and address variables based on	*/
	/* the address family.										*/
	ptree_ptr = route_table->ptree_ptr_array[addr_family];
	address = ip_cmn_rte_table_dest_prefix_addr_ptr_get (dest_prefix);

	/* Check whether the entry actually exists.					*/
	index = oms_ptree_entry_exists (ptree_ptr, address,
		ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix));

	if (OMSC_PTREE_ENTRY_INDEX_INVALID == index)
		{
		/** There is no entry in the route table for the		**/
		/** provided destination.								**/

		FRET (OPC_COMPCODE_FAILURE);
		}
	
	/* Access the route entry itself.							**/
	route_entry = ip_cmn_rte_table_entry_from_ptree_entry_get
		(oms_ptree_entry_access_by_index (ptree_ptr, index));

	if (route_entry->route_src_proto != proto)
		{
		/** The rte protocol attempting to delete this entry,	**/
		/** didn't place the entry								**/
		/* Free the memory allocated to the entry index structure*/
		oms_ptree_entry_index_destroy (index);

		FRET (OPC_COMPCODE_SUCCESS);
		}
	
	/* Check if we are deleting the last next hop in the list.	*/
	/* If it is, then set the flag to true.						*/
	/* If there is only a single next hop, and it is the one	*/
	/* which is being removed, then just call the route remove	*/
	/* function to remove it and promote another protocol from	*/
	/* the backup list.											*/
	
	/* Delete the provided next hop to this destination.		*/
	changed = ip_cmn_rte_next_hop_delete (route_table, route_entry, next_hop);
	
	if (changed != 1)
		{
		/** There were either no next hops removed.				*/

		/* Free the memory allocated to the entry index structure*/
		oms_ptree_entry_index_destroy (index);
	
		FRET (OPC_COMPCODE_FAILURE);
		}

	if (op_prg_list_size (route_entry->next_hop_list) == 0)
		{
		/* There are no more next hops the whole entry needs to	*/
		/* be removed.											*/
		delete_last_next_hop = OPC_TRUE;
		}
	else
		{
		delete_last_next_hop = OPC_FALSE;
		}
	
	/* Update statistics for this route table.					*/
	op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Next_Hop_Update], 1.0);
	op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);

	if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
		{
		ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
		ip_cmn_rte_proto_name_print (src_proto_str, proto);
		
		if (!strcmp (src_proto_str, "Direct"))
			strcpy (src_proto_str, "Local");
	
		sprintf(convergence_reason, 
			"Deleted %s route to destination %s", src_proto_str, dest_str);

		ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
		}
	else
		{
		ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
		}
			
			
#ifndef OPD_NO_DEBUG
	/* Print trace information.									*/
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
		{
		ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
		inet_address_print (nhop_str, next_hop);
		ip_cmn_rte_proto_name_print (src_proto_str, proto);

		sprintf (trace_msg1,
			"Dest |%s|, Next Hop |%s|, and Src. Proto. |%s|.",
			dest_str, nhop_str, src_proto_str);

		op_prg_odb_print_major (
			"Deleting the following route from the Common IP Routing Table:", OPC_NIL);
		op_prg_odb_print_minor (trace_msg1, OPC_NIL);
		}
#endif

	/* Check if we deleted the only next hop of the route. If	*/
	/* so, delete the entire route table entry for this			*/
	/* protocol													*/
	/* If the only next hop in the list is the one which was	*/
	/* being deleted, then it has not actually been removed yet	*/
	/* This function call will take care of that and promote	*/
	/* anything from the backup list to replace it.				*/
	if (delete_last_next_hop == OPC_TRUE)
		{
		/* Delete the entire route table entry.					*/
		ip_cmn_rte_table_rte_list_entry_delete (route_table, route_entry, index, proto, dest_prefix);
		}
	else
		{
		/* The type of redistribution is different	*/
		/* in the case of directly connected routes	*/
		/* so determine if this route is directly	*/
		/* connected and set the redist type		*/
		/* accordingly.								*/
		if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (route_entry->route_src_proto))
			redist_type = IPC_REDIST_TYPE_UPDATE_DIRECT;
		else
			redist_type = IPC_REDIST_TYPE_UPDATE;
		
		/* Since there is no change or source protocol for this	*/
		/* route, set the removed proto to be invalid.			*/
		removed_proto = IpC_Dyn_Rte_Invalid;
		
		ip_cmn_rte_table_entry_redistribute (route_table, route_entry, redist_type, removed_proto);

		/* If the next hop that was deleted was the least cost	*/
		/* route, the metric of this route would have gone up.	*/
		/* If this route was used to resolve a default network	*/
		/* route, we need to check if we need to update the		*/
		/* gateway of last resort.								*/
		if (ip_cmn_rte_table_entry_default_ntwk_flag_is_set (route_entry))
			{
			ip_cmn_rte_table_default_network_route_update (route_table,route_entry);
			}
		}

	/* Free the memory allocated to the entry index structure.	*/
	oms_ptree_entry_index_destroy (index);
		
	FRET (OPC_COMPCODE_SUCCESS);
	}

Compcode
Inet_Cmn_Rte_Table_Entry_Update (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
	InetT_Address next_hop, IpT_Rte_Proc_Id proto, InetT_Address new_next_hop, IpT_Port_Info new_port_info,
	int new_metric, void* src_obj_ptr)
	{
	int							changed;
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	int							redist_type;
	IpT_Rte_Proc_Id				removed_proto;
	Compcode					status;
	
	char						dest_str [INETC_ADDR_STR_LEN]; 
    char						src_proto_str [32]; 
	char						convergence_reason [512];
	
	/** Find and update the next hop and/or metric of a route 	**/
	/** in the route table. This package itself does not care	**/
	/** about the semantics of the metric. On success return	**/
	/** OPC_COMPCODE_SUCCESS, otherwise return					**/
	/** OPC_COMPCODE_FAILURE.									**/
	
	FIN (Inet_Cmn_Rte_Table_Entry_Update (route_table, dest_prefix, next_hop, ...));
	
	/* If this function is called as Ip_Cmn_Rte_Table_Entry_Update	*/
	/* the new_next hop might be InetI_Invalid_v4_Addr. If this is	*/
	/* the case, set the address to INETC_ADDRESS_INVALID.			*/
	if (inet_address_equal (new_next_hop, InetI_Invalid_v4_Addr))
		{
		new_next_hop = INETC_ADDRESS_INVALID;
		}

	/* IPv4 Default routes need to be handled separately if this*/
	/* is a forwarding table.									*/
	if ((0 == ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix)) &&
		(InetC_Addr_Family_v4 == ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix)) &&
		(ip_cmn_rte_table_is_vrf (route_table) == OPC_FALSE))
		{
		/* Look for a 0/0 route inserted by this protocol.		*/
		status = ip_cmn_rte_table_default_route_update (route_table, next_hop, proto,
			new_next_hop, new_port_info, new_metric, src_obj_ptr);
	
		/* Return the status value returned by the function		*/
		FRET (status);
		}
	else
		{
		/* First check if the specified entry exists.			*/
		status = inet_cmn_rte_table_entry_exists (route_table, dest_prefix, &route_entry);

		/* If we did not find an entry, return failure.			*/
		if (OPC_COMPCODE_FAILURE == status)
			{
			FRET (OPC_COMPCODE_FAILURE);
			}

		/* If the primary route to the destination was not		*/
		/* inserted by the specified protocol, update the backup*/
		/* route if one is available.							*/
		if (route_entry->route_src_proto != proto)
			{
			/* Update the route_src_obj_ptr of the backup entry	*/
			status = ip_cmn_rte_table_backup_entry_src_obj_ptr_update
				(route_entry, proto, src_obj_ptr);

			FRET (status);
			}
		}

	/* Update the route_src_obj_ptr.							*/
	route_entry->route_src_obj_ptr = src_obj_ptr;

	if (inet_address_valid (new_next_hop))
		{
		/* If a new next hop is specified, then remove all of the	*/
		/* next hops currently listed for this entry.  Leave one	*/
		/* next hop which corresponds to the one which is being		*/
		/* changed.													*/
		ip_cmn_rte_table_next_hop_list_update (route_table, route_entry, next_hop);
		}
	
	/* Update the route table entry with the new next hop		*/
	/* and/or the new metric.									*/
	changed = ip_cmn_rte_next_hop_update (route_entry, next_hop, new_next_hop,
		new_port_info, new_metric, route_table);
	
	if (changed == 1)
		{
		/* Update statistics for this route table.				*/
		op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Next_Hop_Update], 1.0);
		op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Any_Update], 1.0);
		
		if (oms_routing_convergence_status_check (route_table->convg_handle) == OmsC_Convergence_Reached)
			{
			ip_cmn_rte_table_dest_prefix_print (dest_str, dest_prefix);
			ip_cmn_rte_proto_name_print (src_proto_str, proto); 
			if (!strcmp (src_proto_str, "Direct"))
				strcpy (src_proto_str, "Local");
		
			sprintf(convergence_reason, 
				"Updated %s route to destination %s", src_proto_str, dest_str);
		
			ip_cmn_rte_table_last_update_time_set (route_table, convergence_reason);
			}
		else
			{
			ip_cmn_rte_table_last_update_time_set (route_table, OPC_NIL);
			}
		
		/* If the entry that we just updated was used to resolve*/
		/* a default network route, update the gateway of last	*/
		/* resort.												*/
		if (ip_cmn_rte_table_entry_default_ntwk_flag_is_set (route_entry))
			{
			ip_cmn_rte_table_default_network_route_update (route_table, route_entry);
			}
		
		/* Since the next hop of a directly connected route will*/
		/* never change, there is no need to check if this is a	*/
		/* directly connected route.  Set the type to be update	*/
		redist_type = IPC_REDIST_TYPE_UPDATE;
		
		/* The routing protocol for this route did not change,	*/
		/* so set the removed proto to be invalid.				*/
		removed_proto = IpC_Dyn_Rte_Invalid;
		
		/* Redistribute this route as an update					*/
		/* to other protocols.									*/
		ip_cmn_rte_table_entry_redistribute (route_table, route_entry, redist_type, removed_proto);		
		
		FRET (OPC_COMPCODE_SUCCESS);
		}

	FRET (OPC_COMPCODE_FAILURE);
	}

Boolean
Inet_Cmn_Rte_Table_Entry_Exists (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
	int admin_distance)
	{
	Compcode					status;
	IpT_Cmn_Rte_Table_Entry*	entry_ptr;

	/** Returns a OPC_TRUE if an entry associated with a 	**/
	/** certain destination network address, mask and		**/
	/** administrative distance exists, otherwise returns	**/
	/** OPC_FALSE.											**/
	FIN (Inet_Cmn_Rte_Table_Entry_Exists (route_table, dest_prefix, admin_distance));

	/* Search for an existing entry to the specified		*/
	/* destination.											*/
	status = inet_cmn_rte_table_entry_exists (route_table, dest_prefix, &entry_ptr);

	/* If we found a matching entry and the administrative	*/
	/* distances match, return TRUE. Otherwise return false	*/
	FRET ((Boolean) ((OPC_COMPCODE_SUCCESS == status) && (entry_ptr->admin_distance == admin_distance)));
	}

/*** Internally callable functions	***/

static void
ip_cmn_rte_table_last_update_time_set (IpT_Cmn_Rte_Table* route_table, char* convergence_reason)
	{
	double		current_time;
	
	/** Updates the time at which the routing table got last updated.	**/
	FIN (ip_cmn_rte_table_last_update_time_set (route_table));
	
	current_time = op_sim_time ();
	op_stat_write (route_table->update_stathandle [IpC_Rte_Table_Time_Between_Any_Update], current_time - route_table->last_update_time);
	route_table->last_update_time = current_time;
	
	/* Signal a new change in the IP table 			*/
	/* for the benefit of the convergence statistic */
	oms_routing_convergence_event_trigger (OmsC_IP_Forwarding_Table ,route_table->convg_handle, 
		route_table->last_update_time, convergence_reason);
	
	FOUT;
	}
	
int
ip_cmn_rte_table_entry_hop_num (IpT_Cmn_Rte_Table* route_table, IpT_Cmn_Rte_Table_Entry * rte_entry_ptr)
	{
	int	list_size;
	int ret_val = 0;

	/** Return the number of values in the next hop list for the entry	**/
	FIN (ip_cmn_rte_table_entry_hop_hum (route_table, rte_entry_ptr));

	if (rte_entry_ptr == OPC_NIL)
		FRET (0);

	/* Obtain the size of the next hops list */
	list_size = op_prg_list_size (rte_entry_ptr->next_hop_list);
	
	/* Must determine if Multipath Routes Threshold has been set */
	if (route_table->usage_threshold == -1)
		{
		/* If the threshold is the max, just return the list size */
		ret_val = list_size;
		}
	else
		{
		/* Must determine if the next hops list is larger than the threshold */
		/* Return the lesser of the two values as the number of next hops	 */
		ret_val = (route_table->usage_threshold <= list_size)?route_table->usage_threshold:list_size;
		}
	
	FRET (ret_val);
	}


InetT_Address
inet_cmn_rte_table_entry_hop_get (IpT_Cmn_Rte_Table_Entry * rte_entry_ptr,
	int hop_index, IpT_Port_Info* port_info_ptr)
	{
	IpT_Next_Hop_Entry*			next_hop_ptr;
	InetT_Address				next_hop_addr;

	/** This function returns the specified next_hop of the	**/
	/** routing table entry. The corresponding port info is	**/
	/** also filled in if the argument  port_info_ptr is not**/
	/** OPC_NIL.											**/

	FIN (inet_cmn_rte_table_entry_hop_get (rte_entry_ptr, hop_index));

	if ((rte_entry_ptr == OPC_NIL) || (hop_index < 0))
		FRET (INETC_ADDRESS_INVALID);

	next_hop_ptr = (IpT_Next_Hop_Entry *)
		op_prg_list_access (rte_entry_ptr->next_hop_list, hop_index);
	if (next_hop_ptr == OPC_NIL)
		FRET (INETC_ADDRESS_INVALID);

	if (OPC_NIL != port_info_ptr)
		{
		*port_info_ptr = next_hop_ptr->port_info;
		}

	/* Create a copy of the next hop address				*/
	next_hop_addr = inet_address_copy (next_hop_ptr->next_hop);

	FRET (next_hop_addr);
	}

int
ip_cmn_rte_table_entry_cost_get (IpT_Cmn_Rte_Table_Entry *rte_entry_ptr,
	int hop_index)
	{
	IpT_Next_Hop_Entry*			next_hop_ptr;
	
	FIN (ip_cmn_rte_table_entry_cost_get (rte_entry_ptr, hop_index));
	
	if ((rte_entry_ptr == OPC_NIL) || (hop_index < 0))
		FRET (0);
	
	next_hop_ptr = (IpT_Next_Hop_Entry *)
		op_prg_list_access (rte_entry_ptr->next_hop_list, hop_index);
	if (next_hop_ptr == OPC_NIL)
		FRET (0);
	
	FRET (next_hop_ptr->route_metric);
	}

Compcode
inet_cmn_rte_table_lookup_cache (IpT_Cmn_Rte_Table* route_table, InetT_Address dest, 
	InetT_Address* next_hop_addr_ptr, IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id* src_proto_ptr,
	IpT_Cmn_Rte_Table_Entry ** rte_entry_pptr, int dest_fast_addr, int src_fast_addr,
	int lookup_index)
	{
	IpT_Cmn_Rte_Table_Entry*	best_entry_ptr;
	IpT_Next_Hop_Entry*			next_hop_ptr;
	IpT_Cmn_Rte_Dest_Src_Table_Entry*	dest_src_entry_ptr;
	char						dest_src_tbl_key[IPC_DEST_SRC_KEY_LEN];
	static Boolean				dest_src_table_gbl_variables_init = OPC_FALSE;

	/** Lookup function that is called by IP to get next hop.		**/
	/** This function will first search through the list of routes	**/
	/** until the best match is found. If no match is found, then	**/
	/** the default route is used. Otherwise FAILURE is returned. 	**/
	/** If a match is found then the port info and protocol are set **/
	/** and a next hop is chosen from the list of next hops.		**/
	/** The next hop chosen is determined by an algorithm that 		**/
	/** makes its decisions based on the protocols metric, this 	**/
	/** supports both equal and unequal cost load balancing			**/
	/** Entries are stored in decresing order of prefix length. So	**/
	/** if a match is found, it is guarenteed to be the one with	**/
	/** the longest prefix and we can break out of the loop.		**/
	FIN (inet_cmn_rte_table_lookup_cache (route_table, dest, next_hop_ptr, port_info_ptr, src_proto_ptr));

	/* If destination based load balancing is used, do a lookup in	*/
	/* the dest src table first.									*/
	if ((route_table->load_type == IpC_Rte_Table_Load_Dest) && 
		((dest_fast_addr != IPC_FAST_ADDR_INVALID) && (src_fast_addr != IPC_FAST_ADDR_INVALID)))
		{
		/* Create the dest src table if it has not been done already*/
		if (OPC_NIL == route_table->dest_src_table)
			{
			/* Initialize the global variables if no other node has	*/
			/* done so already.										*/
			if (dest_src_table_gbl_variables_init == OPC_FALSE)
				{
				dest_src_table_gbl_variables_init = OPC_TRUE;
				ip_cmn_rte_table_dest_src_table_gbl_variables_init ();
				}
	
			/* Create the table.									*/
			route_table->dest_src_table = ip_cmn_rte_table_dest_src_table_create (route_table);
			}

		/* Create a key for performing the lookup.					*/
		ip_cmn_rte_table_hash_key_create (dest_src_tbl_key, src_fast_addr, dest_fast_addr, lookup_index);
		dest_src_entry_ptr = ip_cmn_rte_table_dest_src_table_lookup (route_table->dest_src_table, dest_src_tbl_key);

		/* Check if the lookup was successful.						*/
		if (OPC_NIL != dest_src_entry_ptr)
			{
			/* Check if the route table has been updated since the	*/
			/* creation of this entry.								*/
			if (route_table->last_update_time > dest_src_entry_ptr->creation_time)
				{
				/* We need to perform a lookup to make sure that	*/
				/* the entry is still valid.						*/
				best_entry_ptr = ip_cmn_route_table_ptree_lookup (route_table, dest);

				/* Are the entries the same?						*/
				if (best_entry_ptr != dest_src_entry_ptr->route_entry_ptr)
					{
					/* The dest src table entry is no longer valid	*/
					/* Update it.									*/

					/* We need to first remove the reference to this*/
					/* entry from the old route table entry.		*/
					ip_cmn_rte_table_dest_src_key_list_entry_remove
						(dest_src_entry_ptr->next_hop_ptr, dest_src_tbl_key);
					dest_src_entry_ptr->route_entry_ptr = best_entry_ptr;
					dest_src_entry_ptr->next_hop_ptr = ip_cmn_rte_table_next_hop_pick (route_table, best_entry_ptr);

					/* Insert the key into the list of keys of the 	*/
					/* chosen next hop.								*/
					ip_cmn_rte_table_dest_src_key_list_entry_add
						(dest_src_entry_ptr->next_hop_ptr, prg_string_copy (dest_src_tbl_key));
					}
				}
			else
				{
				/* The dest src table entry is stil valid.			*/
				best_entry_ptr = dest_src_entry_ptr->route_entry_ptr;
				}

			/* The dest src table entry has just been				*/
			/* validated. Update its creation time.					*/
			dest_src_entry_ptr->creation_time = (float) op_sim_time ();

			/* Fill in the next hop to be returned.					*/
			next_hop_ptr = dest_src_entry_ptr->next_hop_ptr;
			}
		else
			{
			/* There is no existing entry in the dest src table.	*/
			/* Find out the route from the route table.				*/
			best_entry_ptr = ip_cmn_route_table_ptree_lookup (route_table, dest);

			/* Did we find a route?									*/
			if (OPC_NIL != best_entry_ptr)
				{
				/* Pick a next hop.									*/
				next_hop_ptr = ip_cmn_rte_table_next_hop_pick (route_table, best_entry_ptr);

				/* Create a dest src table entry and add it to the table*/
				dest_src_entry_ptr = ip_cmn_rte_table_dest_src_table_entry_create (best_entry_ptr, next_hop_ptr);
				ip_cmn_rte_table_dest_src_table_entry_add
					(route_table, dest_src_tbl_key, dest_src_entry_ptr);

				/* Insert the key into the list of keys of the 		*/
				/* chosen next hop.									*/
				ip_cmn_rte_table_dest_src_key_list_entry_add
					(next_hop_ptr, prg_string_copy (dest_src_tbl_key));
				}
			else
				{
				/* The lookup failed. Return Failure.				*/
				FRET (OPC_COMPCODE_FAILURE);
				}
			}
		}
	else
		{
		/* Packet based load balancing is being used.				*/

		/* Perform a route table lookup.							*/
		best_entry_ptr = ip_cmn_route_table_ptree_lookup (route_table, dest);

		/* Did we find a route?										*/
		if (OPC_NIL != best_entry_ptr)
			{
			/* Pick a next hop.										*/
			next_hop_ptr = ip_cmn_rte_table_next_hop_pick (route_table, best_entry_ptr);
			}
		else
			{
			/* The lookup failed. Return Failure.					*/
			FRET (OPC_COMPCODE_FAILURE);
			}
		}

	/* Fill in the return values.									*/
	/* If the route table entry itself is being requested, fill		*/
	/* in only that information.									*/
	if (rte_entry_pptr != OPC_NIL)
		*rte_entry_pptr = best_entry_ptr;
		
	/* If the next hop information is being asked, fill in that	*/
	/* information also.										*/
	if (next_hop_addr_ptr != OPC_NIL)
		{	
		/* Routes over tunnel interfaces might leave the next	*/
		/* hop as invalid. For such routes use the destination	*/
		/* address as the next hop.								*/
		if (! inet_address_valid (next_hop_ptr->next_hop))
			{
			*next_hop_addr_ptr = inet_address_copy (dest);
			}
		else
			{
			*next_hop_addr_ptr = inet_address_copy (next_hop_ptr->next_hop);
			}

		*port_info_ptr = next_hop_ptr->port_info;
		*src_proto_ptr = best_entry_ptr->route_src_proto;
		}

	/* Return success to indicate that the lookup succeeded.		*/
	FRET (OPC_COMPCODE_SUCCESS);
	}

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_route_table_ptree_lookup (IpT_Cmn_Rte_Table* route_table, InetT_Address dest)
	{
	InetT_Addr_Family			addr_family;
	OmsT_Ptree*					ptree_ptr;
	OmsT_Ptree_Address			address;
	OmsT_Ptree_Entry*			ptree_entry;
	IpT_Cmn_Rte_Table_Entry*	best_entry_ptr;

	/** Perform a longest prefix match in the route table.			**/

	FIN (ip_cmn_route_table_ptree_lookup (route_table, dest));

	/* Get the address family of the address.						*/
	addr_family = inet_address_family_get (&dest);

	/* Initialize the ptree_ptr and address variables based on		*/
	/* the address family.											*/
	ptree_ptr = route_table->ptree_ptr_array[addr_family];
	address = inet_address_addr_ptr_get (&dest);

	/* Lookup the address in the Ptree.								*/
	ptree_entry = oms_ptree_address_lookup (ptree_ptr, address);

	/* Was there a match?	*/
	if (PRGC_NIL == ptree_entry)
		{
		/* For IPv4 destinations use the gateway of last resort.	*/
		if (InetC_Addr_Family_v4 == addr_family)
			{
			best_entry_ptr = route_table->gateway_of_last_resort;
			}
		else
			{
			/* There is no gateway of last resort for IPv6.			*/
			best_entry_ptr = OPC_NIL;
			}
		}
	else
		{
		/* Get the IpT_Cmn_Rte_Table_Entry structure assoicated		*/
		/* with the entry.											*/
		best_entry_ptr = ip_cmn_rte_table_entry_from_ptree_entry_get (ptree_entry);
		}

	/* Return the route table entry.								*/
	FRET (best_entry_ptr);
	}

static IpT_Next_Hop_Entry*
ip_cmn_rte_table_next_hop_pick (IpT_Cmn_Rte_Table* route_table_ptr, IpT_Cmn_Rte_Table_Entry* route_entry_ptr)
	{
	int							i, list_size;
	double 						total_reciprocals, selected_reciprocal;
	double						one_over_hop_metric;
	IpT_Next_Hop_Entry*			next_hop_ptr;

	/** Pick a next hop from the list of next hops available. If	**/
	/** there are multiple next hops available, the selection		**/
	/** algorithm must ensure that the probability with which a		**/
	/** next hop is chosen is inversely proportional to its metric.	**/

	FIN (ip_cmn_rte_table_next_hop_pick (route_table_ptr, route_entry_ptr));

	/* Find out the number of next hops available. The number of	*/
	/* next hops to be considered is the lesser of the number of 	*/
	/* next hops and the usage threshold of the route table.		*/
	list_size = ip_cmn_rte_table_entry_hop_num (route_table_ptr, route_entry_ptr);

	/* If there is only one next hop, just give it 					*/
	if (list_size == 1)
		{
		next_hop_ptr = (IpT_Next_Hop_Entry *)
			op_prg_list_access (route_entry_ptr->next_hop_list, OPC_LISTPOS_HEAD);
		}
	else
		/* We have multiple route options to the destination. Now we need */
		/* to implement weighted round robin between the next hops		  */
		{
		total_reciprocals = 0.0;
	
		/* Loop through all the next hops in the next hop list to 	*/
		/* determine the range of metric reciprocals we have.		*/
		for (i = 0; i < list_size; i++)
			{
			next_hop_ptr = (IpT_Next_Hop_Entry *)
				op_prg_list_access (route_entry_ptr->next_hop_list, i);
			total_reciprocals += (1.0 / next_hop_ptr->route_metric);
			}
	
		/* Generate a uniform random distribution among all the metrics reciprocals */
		selected_reciprocal = op_dist_uniform (total_reciprocals);
	
		/* Find out which next hop we've selected through weighted randomization */
		total_reciprocals = 0.0;
	
		for (i=0; i < list_size; i++)
			{
			next_hop_ptr = (IpT_Next_Hop_Entry *)
				op_prg_list_access (route_entry_ptr->next_hop_list, i);
		
			one_over_hop_metric = 1.0 / next_hop_ptr->route_metric;
		
			/* Determine if this is the selected route */
			if ((selected_reciprocal >= total_reciprocals) && 
				(selected_reciprocal < (total_reciprocals + one_over_hop_metric)))
				break;
			else
				total_reciprocals += one_over_hop_metric;
			}
		}

	FRET (next_hop_ptr);
	}

static void
ip_cmn_rte_table_dest_src_key_list_entry_remove (IpT_Next_Hop_Entry* next_hop_ptr, IpT_Cmn_Rte_Dest_Src_Table_Key key)
	{
	int				key_index;

	/** Remove the specified key from the key list of the given	**/
	/** next hop entry.											**/

	FIN (ip_cmn_rte_table_dest_src_key_list_entry_remove (next_hop_ptr, key));

	/* Locate the key in the list.								*/
	if (OPC_NIL != op_prg_list_elem_find (next_hop_ptr->table_key_lptr,
		oms_string_compare_proc, key, &key_index, OPC_NIL))
		{
		op_prg_list_remove (next_hop_ptr->table_key_lptr, key_index);
		}

	FOUT;
	}

static IpT_Cmn_Rte_Dest_Src_Table_Entry*
ip_cmn_rte_table_dest_src_table_entry_create (IpT_Cmn_Rte_Table_Entry* rte_entry_ptr,
	IpT_Next_Hop_Entry* next_hop_ptr)
	{
	IpT_Cmn_Rte_Dest_Src_Table_Entry*	dest_src_entry_ptr;

	/** Create a new dest src table structure.					**/

	FIN (ip_cmn_rte_table_dest_src_table_entry_create (rte_entry_ptr, next_hop_ptr));

	/* Allocate enough memory.									*/
	dest_src_entry_ptr = (IpT_Cmn_Rte_Dest_Src_Table_Entry*)
		op_prg_pmo_alloc (ip_cmn_rte_table_dest_src_table_entry_pmh);

	/* Set the creation time.									*/
	dest_src_entry_ptr->creation_time = (float) op_sim_time ();

	/* Set the remaining fields.								*/
	dest_src_entry_ptr->route_entry_ptr = rte_entry_ptr;
	dest_src_entry_ptr->next_hop_ptr = next_hop_ptr;

	/* Return the newly created structure.						*/
	FRET (dest_src_entry_ptr);
	}

static void
ip_cmn_rte_table_dest_src_table_entry_add (IpT_Cmn_Rte_Table* route_table_ptr,
	IpT_Cmn_Rte_Dest_Src_Table_Key key,
	IpT_Cmn_Rte_Dest_Src_Table_Entry* dest_src_table_entry)
	{
	/** Add an entry to the dest src table.						**/

	FIN (ip_cmn_rte_table_dest_src_table_entry_add (route_table_ptr, key, dest_src_table_entry));

	/* Add an entry to the hash table.							*/
	prg_string_hash_table_item_insert (route_table_ptr->dest_src_table,
		key, dest_src_table_entry, PRGC_NIL);

	/* Increment the number of entries.							*/
	++(route_table_ptr->dest_src_table_size);

	FOUT;
	}

static void
ip_cmn_rte_table_dest_src_table_entries_remove (IpT_Cmn_Rte_Table* route_table_ptr,
	IpT_Next_Hop_Entry* next_hop_ptr)
	{
	/** Remove all dest src tables entries corresponding to the	**/
	/** given next hop.											**/

	FIN (ip_cmn_rte_table_dest_src_table_entries_remove (route_table_ptr, next_hop_ptr));

	/* Use the op_prg_list_map function to perform the removal	*/
	/* for each element of the list.							*/
	if (OPC_NIL != next_hop_ptr->table_key_lptr)
		{
		op_prg_list_map (next_hop_ptr->table_key_lptr,
			ip_cmn_rte_table_dest_src_table_entry_remove, route_table_ptr);
		}

	FOUT;
	}

int
ip_cmn_rte_table_dest_src_table_entry_remove (void* route_table_void_ptr, void* key_void_ptr)
	{
	IpT_Cmn_Rte_Table*	route_table_ptr;
	char*				key;
	
	/** Remove an entry from the dest src table.				**/
	FIN (ip_cmn_rte_table_dest_src_table_entry_remove (route_table_ptr, key));
	
	/* Cast the arguments into the appropriate pointer types.	*/
	route_table_ptr = (IpT_Cmn_Rte_Table*) route_table_void_ptr;
	key             = (char*) key_void_ptr;
	
	/* Remove the corresponding entry from the hash table.		*/
	prg_string_hash_table_item_remove (route_table_ptr->dest_src_table, key);

	/* Increment the number of entries.							*/
	--(route_table_ptr->dest_src_table_size);

	/* Return 1 to so that the op_prg_list_map function which	*/
	/* calls this function will continue.						*/
	FRET (1);
	}

static void
ip_cmn_rte_table_dest_src_key_list_entry_add (IpT_Next_Hop_Entry* next_hop_ptr,
	IpT_Cmn_Rte_Dest_Src_Table_Key key)
	{
	/** Add the given key to the list of dest src table keys of	**/
	/** of the given next hop entry.							**/

	FIN (ip_cmn_rte_table_dest_src_key_list_entry_add (next_hop_ptr, key));

	/* Create the list if it does not exist.					*/
	if (OPC_NIL == next_hop_ptr->table_key_lptr)
		{
		next_hop_ptr->table_key_lptr = op_prg_list_create ();
		}

	/* Add the key to the list.									*/
	op_prg_list_insert (next_hop_ptr->table_key_lptr, key, OPC_LISTPOS_TAIL);

	FOUT;
	}

Compcode
ip_cmn_rte_table_lookup_cache (int PRG_ARG_UNUSED (fast_addr), IpT_Cmn_Rte_Table* route_table, IpT_Address dest,
	IpT_Address* next_hop_ptr, IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id* src_proto_ptr,
	IpT_Cmn_Rte_Table_Entry** rte_entry_pptr, int dest_fast_addr, int src_fast_addr, int lookup_index)
	{
	InetT_Address		next_hop_inet_addr;
	Compcode			result;

	/** IPv4 wrapper to inet_cmn_rte_table_lookup_cache		**/

	FIN (ip_cmn_rte_table_lookup_cache (<args>));

	result = inet_cmn_rte_table_lookup_cache (route_table, inet_address_from_ipv4_address_create (dest),
		(next_hop_ptr == OPC_NIL) ? OPC_NIL : &next_hop_inet_addr,
		port_info_ptr, src_proto_ptr, rte_entry_pptr, dest_fast_addr, src_fast_addr, lookup_index);

	if (OPC_NIL != next_hop_ptr)
		*next_hop_ptr = inet_ipv4_address_get (next_hop_inet_addr);

	FRET (result);
	}

Compcode			
inet_cmn_rte_table_recursive_lookup_cache (IpT_Cmn_Rte_Table* route_table, InetT_Address dest, 
	InetT_Address* next_hop_ptr, IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id* src_proto_ptr,
	IpT_Cmn_Rte_Table_Entry ** rte_entry_pptr, int dest_fast_addr, int src_fast_addr)
	{
	IpT_Port_Info			port_info;
	InetT_Address			temp_dest_addr;
	List*					next_hop_addr_lptr = OPC_NIL;
	Compcode				ret_value;
	int						high_index, low_index;
	InetT_Address*			temp_next_hop_ptr;
	char					ip_addr_str[IPC_ADDR_STR_LEN];
	int						num_next_hops;
	int						lookup_index = 0;

	/** The next hops of route table entries need not always be	**/
	/** directly connected. If they are not, a recursive lookup	**/
	/** is done until a route entry with a directly connected	**/
	/** next_hop is found. Unless the route entry itself is		**/
	/** asked, the next_hop returned by this function is 		**/
	/** guaranteed to be directly connected.					**/
	/** If the route entry itself is asked, a recursive lookup	**/
	/** is done until a route with either a directly connected	**/
	/** next hop or multiple next hops is encountered.			**/

	FIN (inet_cmn_rte_table_recursive_lookup_cache (<args>));

	/* If the port_info_ptr argument is OPC_NIL, point it to	*/
	/* the local variable.										*/
	if (OPC_NIL == port_info_ptr)
		{
		port_info_ptr = &port_info;
		}

#ifndef OPD_NO_DEBUG
	/* Print a trace message.									*/
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table_lookup"))
		{
		char dest_addr_str [INETC_ADDR_STR_LEN];
		inet_address_print (dest_addr_str, dest);

		op_prg_odb_print_major ("Looking for a route to the destination",
			dest_addr_str, OPC_NIL);
		}
#endif

	/* Initialize the temp_dest_addr variable to the destination*/
	/* address.													*/
	temp_dest_addr = dest;

	/* Keep calling the inet_cmn_rte_table_lookup_cache function*/
	/* recursively until we get a directly connected next hop	*/
	 while (1)
		{
		if (OPC_COMPCODE_FAILURE == inet_cmn_rte_table_lookup_cache
			(route_table, temp_dest_addr, next_hop_ptr, port_info_ptr,
			 src_proto_ptr, rte_entry_pptr, dest_fast_addr, src_fast_addr, lookup_index++))
			{
			/* The lookup failed. Return failure.				*/
			ret_value = OPC_COMPCODE_FAILURE;

#ifndef OPD_NO_DEBUG
			/* Print a trace message.							*/
			if (op_prg_odb_ltrace_active ("ip_cmn_rte_table_lookup"))
				{
				op_prg_odb_print_major ("Lookup failed. Packet will be dropped", OPC_NIL);
				}
#endif
			break;
			}
		else
			{
			/* We found a matching route. 						*/

			/* If we asked for the route table entry itself,	*/
			/* check the number of hops of the route. If it is,	*/
			/* do not proceed. Return the entry as it is.		*/
			if (OPC_NIL != rte_entry_pptr)
				{
				/* We asked for the route entry itself. 		*/
				/* Get the number of hops of the entry			*/
				num_next_hops = ip_cmn_rte_table_entry_hop_num (route_table, *rte_entry_pptr);
				
				/* If there is more than one next hop, do not	*/
				/* proceed.										*/
				if (num_next_hops == 0)
					{
					/* Invaid route entry. Return failure.		*/
					ret_value = OPC_COMPCODE_FAILURE;

					/* Print a trace message.					*/
#ifndef OPD_NO_DEBUG
					if (op_prg_odb_ltrace_active ("ip_cmn_rte_table_lookup"))
						{
						op_prg_odb_print_major ("Lookup failed. Packet will be dropped", OPC_NIL);
						}
#endif
					break;
					}
				else if (num_next_hops > 1)
					{
					/* No need to do any more lookups			*/
					ret_value = OPC_COMPCODE_SUCCESS;

					/* Print a trace message.									*/
#ifndef OPD_NO_DEBUG
					if (op_prg_odb_ltrace_active ("ip_cmn_rte_table_lookup"))
						{
						char dest_prefix_str [INETC_ADDR_STR_LEN];
						ip_cmn_rte_table_dest_prefix_print (dest_prefix_str, (*rte_entry_pptr)->dest_prefix);

						op_prg_odb_print_major ("The destination address matched the following entry",
							dest_prefix_str, OPC_NIL);
						}
#endif
					break;
					}
				}

			/* Check if the next hop is directly connected. If	*/
			/* it is, break out of the loop.					*/
			if (ip_rte_port_info_is_defined (*port_info_ptr))
				{
				/* The next hop is directly connected. We		*/
				/* don't have to do anything more.				*/
				ret_value = OPC_COMPCODE_SUCCESS;
				break;
				}
			}
		
		/* The lookup retuned a next hop that is not			*/
		/* directly connected.									*/

		/* Before we do another lookup, make sure this next hop	*/
		/* did not occur earlier in this lookup. This might		*/
		/* happen if we have a loop in the routing table.		*/
		/* So check whether this next hop is already present in	*/
		/* the list of next hops maintained by this function	*/
		/* If the list hasn't been created yet, create it.		*/
		if (OPC_NIL == next_hop_addr_lptr)
			{
			next_hop_addr_lptr = op_prg_list_create ();
			}
		else if ((OPC_NIL != op_prg_list_elem_find (next_hop_addr_lptr, inet_address_ptr_compare_proc, 
				   next_hop_ptr, &low_index, &high_index)) || (lookup_index > 14))
			{
			/* There is loop within the routing table. Print out*/
			/* a log message and return failure.				*/

			inet_address_print (ip_addr_str, dest);
			ipnl_invalid_routing_table_log_write (ip_addr_str);

			ret_value = OPC_COMPCODE_FAILURE;
			break;
			}
		
		/* Insert the next hop into the list of next hops		*/
		temp_next_hop_ptr = inet_address_mem_alloc ();

		/* Do not use ip address copy since next_hop_ptr		*/
		/* would have been already allocated memory by 			*/
		/* inet_cmn_rte_table_lookup_cache						*/
		*temp_next_hop_ptr = *next_hop_ptr;
		
		op_prg_list_insert (next_hop_addr_lptr, temp_next_hop_ptr, OPC_LISTPOS_TAIL);

		/* Now set temp_dest_addr to the next_hop address 		*/
		temp_dest_addr = *next_hop_ptr;
		}

	/* Free the memory allocated to the list of next hops and	*/
	/* its contents.											*/
	if (OPC_NIL != next_hop_addr_lptr)
		{
		while (op_prg_list_size (next_hop_addr_lptr))
			{
			temp_next_hop_ptr = (InetT_Address*) op_prg_list_remove (next_hop_addr_lptr, OPC_LISTPOS_HEAD);
			inet_address_destroy (*temp_next_hop_ptr);
			op_prg_mem_free (temp_next_hop_ptr);
			}
		op_prg_mem_free (next_hop_addr_lptr);
		}

	FRET (ret_value);
	}

Compcode
ip_cmn_rte_table_recursive_lookup_cache (int PRG_ARG_UNUSED (fast_addr), IpT_Cmn_Rte_Table* route_table,
	IpT_Address dest, IpT_Address* next_hop_ptr, IpT_Port_Info* port_info_ptr, IpT_Rte_Proc_Id* src_proto_ptr,
	IpT_Cmn_Rte_Table_Entry ** rte_entry_pptr, int dest_host_addr, int src_host_addr)
	{
	InetT_Address		next_hop_addr;
	Compcode			result;

	/** IPv4 wrapper to inet_cmn_rte_table_recursive_lookup_cache	**/

	FIN (ip_cmn_rte_table_recursive_lookup_cache (<args>));

	result = inet_cmn_rte_table_recursive_lookup_cache (route_table, inet_address_from_ipv4_address_create (dest),
		(next_hop_ptr == OPC_NIL) ? OPC_NIL : &next_hop_addr, 
		port_info_ptr, src_proto_ptr, rte_entry_pptr, dest_host_addr, src_host_addr);

	if (next_hop_ptr != OPC_NIL)
		*next_hop_ptr = inet_ipv4_address_get (next_hop_addr);

	FRET (result);
	}

Compcode
inet_cmn_rte_table_entry_exists (IpT_Cmn_Rte_Table* route_table, IpT_Dest_Prefix dest_prefix,
	IpT_Cmn_Rte_Table_Entry** route_entry_pptr)
	{
	OmsT_Ptree*					ptree_ptr;
	OmsT_Ptree_Address			address;
	OmsT_Ptree_Entry_Index		index;
	Compcode					status;

	/** Checks whether the a specified entry exists in the table	**/
	/** If it does, the route entry is returned.					**/

	FIN (inet_cmn_rte_table_entry_exists (route_table, dest_prefix, route_entry_pptr));

	/* IPv4 Default routes need to be handled separately if this is	*/
	/* a forwarding table.											*/
	if ((0 == ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix)) &&
		(InetC_Addr_Family_v4 == ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix)) &&
		(ip_cmn_rte_table_is_vrf (route_table) == OPC_FALSE))
		{
		/* Check if the gateway of last resort is set.				*/
		if (OPC_NIL != route_table->gateway_of_last_resort)
			{
			*route_entry_pptr = route_table->gateway_of_last_resort;

			status = OPC_COMPCODE_SUCCESS;
			}
		else
			{
			/* Gateway of last resort is not set. Return failure.	*/
			status = OPC_COMPCODE_FAILURE;
			}
		}
	else
		{
		/* Initialize the ptree_ptr and address variables based on	*/
		/* the address family.										*/
		ptree_ptr = route_table->ptree_ptr_array[ip_cmn_rte_table_dest_prefix_addr_family_get (dest_prefix)];
		address = ip_cmn_rte_table_dest_prefix_addr_ptr_get (dest_prefix);

		/* Check whether the entry actually exists.					*/
		index = oms_ptree_entry_exists (ptree_ptr, address,
			ip_cmn_rte_table_dest_prefix_mask_len_get (dest_prefix));

		if (OMSC_PTREE_ENTRY_INDEX_INVALID != index)
			{
			/* Fill in the route_entry_pptr info.					*/
			*route_entry_pptr = ip_cmn_rte_table_entry_from_ptree_entry_get
				(oms_ptree_entry_access_by_index (ptree_ptr, index));

			/* Free the memory allocated to the entry index.		*/
			oms_ptree_entry_index_destroy (index);

			/* Return success.										*/
			status = OPC_COMPCODE_SUCCESS;
			}
		else
			{
			/* There is no entry in the route table for the			*/
			/* provided destination.								*/
			status = OPC_COMPCODE_FAILURE;
			}
		}

	/* Return the value of the status variable.						*/
	FRET (status);
	}

IpT_Rte_Proc_Id 
ip_cmn_rte_table_entry_src_proto_get (IpT_Cmn_Rte_Table_Entry* route_entry_ptr)
	{
	/** Return an integer code corresponding to the routing protocol**/
	/** that sourced a common routing table entry.					**/ 

	FIN (ip_cmn_rte_table_entry_src_proto_get (route_entry_ptr));

	FRET (route_entry_ptr->route_src_proto);
	}

void* 
ip_cmn_rte_table_entry_src_obj_ptr_get (IpT_Cmn_Rte_Table_Entry* route_entry_ptr)
	{
	/** Return an pointer to the corresponding object in the source	**/
	/** routing protocols routing data structure.					**/

	FIN (ip_cmn_rte_table_entry_src_obj_ptr_get (route_entry_ptr));

	FRET (route_entry_ptr->route_src_obj_ptr);
	}

int
ip_cmn_rte_table_num_entries_get (IpT_Cmn_Rte_Table* route_table, int addr_family)
	{
	int			num_entries;

	/** Return the number of entries in the table.					**/

	FIN (ip_cmn_rte_table_num_entries_get (route_table, addr_family));

	/* Find out the number of entries.								*/
	if (OPC_NIL == route_table->ptree_ptr_array[addr_family])
		{
		num_entries = 0;
		}
	else
		{
		num_entries = oms_ptree_size (route_table->ptree_ptr_array[addr_family]);
		}

	/* Return the number of entries.								*/
	FRET (num_entries);
	}

IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_table_access (IpT_Cmn_Rte_Table* route_table, int i, int addr_family)
	{
	IpT_Cmn_Rte_Table_Entry*	ith_entry_ptr;

	/** Access the ith entry.										**/

	FIN (ip_cmn_rte_table_access (route_table, i, addr_family));

	/* Access the ith entry from the appropriate ptree.				*/
	ith_entry_ptr = ip_cmn_rte_table_entry_from_ptree_entry_get
		(oms_ptree_entry_access (route_table->ptree_ptr_array[addr_family], i));

	/* Return the entry.											*/
	FRET (ith_entry_ptr);
	}

char*
ip_cmn_rte_proto_name_print (char* proto_str, IpT_Rte_Proc_Id proto)
	{
	const char*					temp_src_proto_str;
	char						temp_src_proto_as_str [16];
	int							proto_type;
	int							proto_as;

	/** This function returns the name of the specified		**/
	/** routing protocol. For custom routing protocols, it	**/
	/** Obtains the label using the function				**/
	/** ip_cmn_rte_table_custom_rte_protocol_label_get.		**/

	FIN (ip_cmn_rte_proto_name_print (proto_str, protocol));
	
	/* Break up the proto into the routing protocol type	*/
	/* and it's AS number.									*/
	proto_type = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (proto);
	proto_as = IP_CMN_RTE_TABLE_ROUTEPROC_AS_NUMBER (proto);

	/* First check whether it is a standard protocol.		*/
	if ((0 <= proto_type) &&
		(proto_type < IPC_DYN_RTE_NUM))
		{
		/* It is a standard protocol.						*/
		strcpy (proto_str, IpC_Dyn_Rte_Prot_Names [proto_type]);
		if (proto_as != IPC_NO_MULTIPLE_PROC)
			{
			sprintf (temp_src_proto_as_str, " %d", proto_as);
			strcat (proto_str, temp_src_proto_as_str);
			}
		}
	else if (proto_type >= IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID)
		{
		/* Obtain a pointer to the protocol label.	*/
		temp_src_proto_str = ip_cmn_rte_table_custom_rte_protocol_label_get (proto);

		/* Check if the label for this custom routing protocol is found.	*/
		if (temp_src_proto_str == OPC_NIL)
			{
			strcpy (proto_str, "Invalid");
			}
		else
			{
			/* Copy the label for this custom routing protocol.	*/
			strcpy (proto_str, temp_src_proto_str);
			if (proto_as != IPC_NO_MULTIPLE_PROC)
				{
				sprintf (temp_src_proto_as_str, " %d", proto_as);
				strcat (proto_str, temp_src_proto_as_str);
				}			
			}
		}
	else
		{
		strcpy (proto_str, "Invalid");
		}
	FRET (proto_str);
	}

Compcode
ip_cmn_rte_table_print (IpT_Cmn_Rte_Table* route_table)
	{
	int							i, num_entries;
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	int							addr_family;
	OmsT_Ptree*					ptree_ptr;
	const char*					ip_version_string[IPC_NUM_ADDR_FAMILIES] = {"IPv4", "IPv6" };
	const char					*vrf_name_str, *vrf_table_header_line1, *vrf_table_header_line2;	
	
	/** Print out the contents of the IP route table.	**/
	FIN (ip_cmn_rte_table_print (route_table));

	/* Print both IPv4 and IPv6 routing tables.			*/
	for (addr_family = 0; addr_family < IPC_NUM_ADDR_FAMILIES; addr_family++)
		{
		/* Get a pointer to the appropriate ptree.		*/
		ptree_ptr = route_table->ptree_ptr_array[addr_family];

		if (OPC_NIL == ptree_ptr)
			{
			/* This IP version is not enabled on this	*/
			/* node.									*/
			continue;
			}

		/* Get the number of entries in the table.			*/
		num_entries = oms_ptree_size (ptree_ptr);

		vrf_name_str = ip_vrf_table_name_get (route_table->vrf_table_ptr);

		if (OPC_NIL == vrf_name_str)
			{
			printf ("\n\t\t\t IP Forwarding Table\n\n");
			vrf_table_header_line1 = "\n";
			vrf_table_header_line2 = "\n";
			}
		else
			{
			printf ("\n\t\t\t VRF Table: %s\n\n", vrf_name_str);
			vrf_table_header_line1 = "     Top Lbl  Bottom Lbl\n";
			vrf_table_header_line2 = "     -------  ----------\n";
			}
		
		/* Print out the column headings first.				*/
		printf ("        Destination                  Next Hop       Port Info    Metric   Admin Dist.   Protocol   Ins. Time %s",vrf_table_header_line1);
		printf ("-----------------------------        --------       ---------    ------   -----------   --------   --------- %s",vrf_table_header_line2);

		if (num_entries == 0)
			{
			printf ("\n\t\t\tZERO ENTRIES IN THE %s ROUTE TABLE.\n", ip_version_string [addr_family]);
			continue;
			}

		/* Loop over the route table for further processing	*/
		for (i = 0; i < num_entries; i++)
			{
			/* Access the i'th entry in the route table.	*/
			route_entry = ip_cmn_rte_table_entry_from_ptree_entry_get
				(oms_ptree_entry_access (ptree_ptr, i));

			ip_cmn_rte_table_entry_print (route_entry);
			}
		
		/* For IPv4, 0/0 routes are stored separately. We	*/
		/* also need to print the gateway of last resort.	*/
		if (InetC_Addr_Family_v4 == addr_family)
			{
			/* If there are any 0/0 routes we need to write out the one with	*/
			/* the lowest admin distance.										*/
			route_entry = ip_cmn_rte_table_best_default_route_get (route_table);
		
			if (OPC_NIL != route_entry)
				{
				ip_cmn_rte_table_entry_print (route_entry);
				}

			/* Print the gateway of last resort.			*/
			ip_cmn_rte_table_gateway_of_last_resort_print (route_table);
			}

		/* Print the backup entries for each entry.			*/
		printf("\n \n \n");
		printf("\tBackup Entries For Each Destination \n");
		printf("\tDestination/Mask\t     Protocol\n");
		printf("\t----------------\t     --------\n");
		for (i = 0; i < num_entries; i++)
			{
			route_entry = ip_cmn_rte_table_entry_from_ptree_entry_get
				(oms_ptree_entry_access (ptree_ptr, i));

			ip_cmn_rte_table_backup_print (route_entry);
			}
		}
   
   	FRET (OPC_COMPCODE_SUCCESS);

   }

static void
ip_cmn_rte_table_entry_print (IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	char				dest [INETC_ADDR_STR_LEN];
	char				next_hop [INETC_ADDR_STR_LEN];
	char				proto_str [64];
	char                port_info [256];
	int					num_routes, i;
	IpT_Next_Hop_Entry*	next_hop_ptr;
	char				label_str [64] = "\n";
		
	/** Print to standard output the information contained in	**/
	/** a single routing table entry.							**/
	FIN (ip_cmn_rte_table_entry_print (route_entry));

	/* Assemble sub-strings for the various data	*/
	/* elements of an IP route entry.				*/
	ip_cmn_rte_table_dest_prefix_print (dest, route_entry->dest_prefix);
	ip_cmn_rte_proto_name_print (proto_str, route_entry->route_src_proto);

	num_routes = op_prg_list_size (route_entry->next_hop_list);
	
	for (i=0; i < num_routes; i++)
		{
		next_hop_ptr = (IpT_Next_Hop_Entry *)op_prg_list_access (route_entry->next_hop_list, i);
		inet_address_print (next_hop, next_hop_ptr->next_hop);
		
		/* Obtain the port information for the route entry. */
		if (ip_rte_port_info_is_defined (next_hop_ptr->port_info))
			{
			if (ip_rte_port_info_contains_mpls_info (&(next_hop_ptr->port_info)))
				{
				MplsT_Label			top_label;
				MplsT_Label			bottom_label;
				IpT_Address			next_hop_addr;
				int					out_intf_index;
				MplsT_NHLFE*		dummy_top_nhlfe_ptr;
				MplsT_NHLFE*		dummy_bottom_nhlfe_ptr;	

				strcpy (port_info, "VRF");
				
				ip_vrf_port_info_mpls_switching_info_get (&(next_hop_ptr->port_info), &out_intf_index, &next_hop_addr,
					&top_label, &bottom_label, &dummy_top_nhlfe_ptr, &dummy_bottom_nhlfe_ptr,
					OPC_NIL /* IP module data, calling function handles NIL values */); 
				
				/* Top label will not be present for sites connected to a local PE.	*/
				if (MPLSC_NULL_LABEL == top_label)
					sprintf (label_str, "    UNDEF        %3d\n", bottom_label);
				else
					sprintf (label_str, "    %3d          %3d\n", top_label, bottom_label);
				}
			else
				sprintf (port_info, "%d", next_hop_ptr->port_info.intf_tbl_index);
			}
		else
			{
			strcpy (port_info, "UNDEF");
			}
	
		/* Print to standard output.					*/
		printf ("%-33s   %-15s    %-5s  %10d       %3d        %-7s   %f   %s",
			dest, next_hop, port_info, next_hop_ptr->route_metric, route_entry->admin_distance, proto_str, next_hop_ptr->route_insert_time, label_str);

		/* The following lines of code have been commented	*/
		/* out on purpose because the information printed	*/
		/* here will be useful only while debugging the		*/
		/* dest src table.									*/
#ifdef IP_DEST_SRC_TABLE
		/* Print the contents of the dest_table_lptr.	*/
		if ((OPC_NIL != next_hop_ptr->table_key_lptr) && (op_prg_list_size (next_hop_ptr->table_key_lptr) > 0))
			{
			int				j, num_keys;
			char*			key;
			int				src_fast_addr, dest_fast_addr;
			char			src_addr_str[INETC_ADDR_STR_LEN], dest_addr_str[INETC_ADDR_STR_LEN];
			InetT_Address	src_ip_addr, dest_ip_addr;
			int				lookup_index;

			num_keys = op_prg_list_size (next_hop_ptr->table_key_lptr);
			for (j = 0; j < num_keys; j++)
				{
				key = (char*) op_prg_list_access (next_hop_ptr->table_key_lptr, j);

				/* Extract the source and Destination fast addresses	*/
				/* from the key string.									*/
				ip_cmn_rte_table_fast_addrs_from_hash_key_get (key,
					&src_fast_addr, &dest_fast_addr, &lookup_index);

				/* Get the actual addresses corresponding to the fast	*/
				/* addresses.											*/
				src_ip_addr = nato_table_index_to_major_inet_address
					(ip_table_handle, src_fast_addr);
				dest_ip_addr = nato_table_index_to_major_inet_address
					(ip_table_handle, dest_fast_addr);

				/* Get string representations of the source and			*/
				/* destination addresses.								*/
				inet_address_print (src_addr_str, src_ip_addr);
				inet_address_print (dest_addr_str, dest_ip_addr);

				printf ("\t\t\t%s:%s\n", src_addr_str, dest_addr_str);
				}
			}
#endif
		}
	
	FOUT;
	}

static void
ip_cmn_rte_table_gateway_of_last_resort_print (IpT_Cmn_Rte_Table* route_table)
	{
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	InetT_Address				next_hop_addr, dest_net_addr;
	char						next_hop_str [INETC_ADDR_STR_LEN];
	char						dest_addr_str [INETC_ADDR_STR_LEN];

	/** Writes out the information about the gateway of last resort.	**/

	FIN (ip_cmn_rte_table_gateway_of_last_resort_print (route_table));

	printf ("\n%s ","Gateway of last resort is");
	
	if (OPC_NIL != (route_table->gateway_of_last_resort))
		{
		/* Get the gateway of last resort.								*/
		route_entry = route_table->gateway_of_last_resort;

		/* Get the first next hop. Even if there are multiple next hops	*/
		/* we print out only the first one.								*/
		next_hop_addr = inet_cmn_rte_table_entry_hop_get (route_entry, 0, OPC_NIL);
		inet_address_print (next_hop_str, next_hop_addr);

		/* Print the destination network address also.					*/
		dest_net_addr = ip_cmn_rte_table_dest_prefix_addr_get (route_entry->dest_prefix);
		inet_address_print (dest_addr_str, dest_net_addr);
		printf ("%s to network %s\n", next_hop_str, dest_addr_str);

		/* Candidate default routes will be marked with a *. Add an		*/
		/* explanation.													*/
		printf ("* - candidate default\n");
		}
	else
		{
		/* Gateway of last resort is not set.							*/
		printf ("not set\n");
		}

	/* Return.		*/
	FOUT;
	}

static void
ip_cmn_rte_table_backup_print (IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	char				dest_str [INETC_ADDR_STR_LEN];
	char				proto_str[64];
	int					num_routes, i;
	IpT_Backup_Entry*	backup_ptr;
	
	/** Print to standard output the information contained in	**/
	/** a single routing table entry.							**/
	FIN (ip_cmn_rte_table_backup_print (route_entry));

	/* If the backup list does not exist, just return	*/
	if (OPC_NIL == route_entry->backup_list)
		{
		FOUT;
		}

	/* Assemble sub-strings for the various data	*/
	/* elements of an IP route entry.				*/
	ip_cmn_rte_table_dest_prefix_print (dest_str, route_entry->dest_prefix);

	num_routes = op_prg_list_size (route_entry->backup_list);
	
	for (i=0; i < num_routes; i++)
		{
		backup_ptr = (IpT_Backup_Entry *)op_prg_list_access (route_entry->backup_list, i);
		ip_cmn_rte_proto_name_print (proto_str, backup_ptr->route_proto);
		
		/* Print to standard output.					*/
		printf ("\t %s\t     %s\n", dest_str, proto_str);
		}
	
	
	FOUT;
	}

static Compcode
ip_cmn_rte_table_backup_entry_src_obj_ptr_update (IpT_Cmn_Rte_Table_Entry* route_entry,
	IpT_Rte_Proc_Id proto, void* src_obj_ptr)
	{
	int					i, num_backup_entries;
	IpT_Backup_Entry*	ith_backup_entry_ptr;

	/** Update the route_src_obj_ptr of the backup entry inserted	**/
	/** by the specified protcol. If a matching entry was found,	**/
	/** return success. Otherwise return failure.					**/

	FIN (ip_cmn_rte_table_backup_entry_src_obj_ptr_update (route_entry, proto, src_obj_ptr));

	/* First make sure that the backup list exists.					*/
	if (OPC_NIL == route_entry->backup_list)
		{
		/* There are no backup entries. Return failure.				*/
		FRET (OPC_COMPCODE_FAILURE);
		}

	/* Loop through the list of backup routes and look for an entry	*/
	/* inserted by the specified protocol.							*/
	num_backup_entries = op_prg_list_size (route_entry->backup_list);
	for (i = 0; i < num_backup_entries; i++)
		{
		/* Access the ith backup entry.								*/
		ith_backup_entry_ptr = (IpT_Backup_Entry*) op_prg_list_access
									(route_entry->backup_list, i);

		/* Was this entry inserted by the protocol we are interested*/
		/* in?														*/
		if (proto == ith_backup_entry_ptr->route_proto)
			{
			/* We have found the entry we are looking for. Update	*/
			/* its route_src_obj_ptr.								*/
			ith_backup_entry_ptr->route_src_obj_ptr = src_obj_ptr;
			
			/* Return success to indicate the entry was found.		*/
			FRET (OPC_COMPCODE_SUCCESS);
			}
		}

	/* We did not find an entry inserted by the specified protcol	*/
	/* in the backup list. Return Failure.							*/
	FRET (OPC_COMPCODE_FAILURE);
	}

static IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_table_entry_create (IpT_Dest_Prefix dest_prefix, IpT_Rte_Proc_Id src_proto,
	int admin_distance, void* src_obj_ptr)
	{
	IpT_Cmn_Rte_Table_Entry*	route_entry;

	/** Creates a route table entry structure with the specified	**/
	/** attributes.													**/

	FIN (ip_cmn_rte_table_entry_create (dest_prefix, src_proto, admin_distance, src_obj_ptr));

	/* Allocate memory for a new IpT_Cmn_Rte_Table_Entry object	*/
	/* Its OK to allocate memory for this inline because we	*/
	/* are initializing the data referenced in the object	*/
	/* immediately.											*/
	route_entry = ip_cmn_rte_table_entry_mem_alloc ();

	/* Check if memory has been allocated. */ 
	if (route_entry == OPC_NIL)
		{
		/* Report an error message and terminate the simulation	*/
		op_sim_end ("Error in IP common route table support code: ",
			"Could not allocate memory for IpT_Cmn_Rte_Table_Entry data structure.", OPC_NIL, OPC_NIL);
		}
	
	/* Initialize the data elements of the new object from	*/
	/* parameter values passed in.							*/
	route_entry->next_hop_list 		= op_prg_list_create ();
	/* Note that we do not need to do a deep copy on the	*/
	/* prefix becuase we can reuse the memory used by the	*/
	/* process which is adding this entry.					*/
	route_entry->dest_prefix		= dest_prefix;
	route_entry->route_src_proto	= src_proto;
	route_entry->admin_distance		= admin_distance;

	route_entry->backup_list 		= OPC_NIL;

	/* Set the source obj ptr. For directly connected routes*/
	/* it should be set to this route entry itself. This is	*/
	/* necessary for route maps to work. For other routes,	*/
	/* use the specified src_obj_ptr.						*/
	if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (route_entry->route_src_proto))
		{
		/* Directly connected route.						*/
		route_entry->route_src_obj_ptr	= route_entry;
		}
	else
		{
		/* Not a directly connected route.					*/
		route_entry->route_src_obj_ptr	= src_obj_ptr;
		}

	/* Record the time at which this entry was created.		*/
	route_entry->route_insert_time	= op_sim_time ();

	/* Reset all flags.										*/
	route_entry->flags				= 0;

	FRET (route_entry);
	}

IpT_Cmn_Rte_Table_Entry*
ip_cmn_rte_table_entry_copy (IpT_Cmn_Rte_Table_Entry* entry_ptr)
	{
	IpT_Cmn_Rte_Table_Entry*	new_entry_ptr = OPC_NIL;
	IpT_Backup_Entry*			backup_entry_ptr;
	IpT_Backup_Entry*			new_backup_entry_ptr;
	IpT_Next_Hop_Entry*			next_hop_ptr;
	IpT_Next_Hop_Entry*			new_next_hop_ptr;
	int							i;
	
	/** This function takes an IpT_Cmn_Rte_Table_Entry structure	**/
	/** and returns an exact duplicate copy of it.					**/
	
	FIN (ip_cmn_rte_table_entry_copy (entry));
	
	/* Allocate space in memory for the new IpT_Cmn_Rte_Table_Entry	*/
	/* structure.  If memory could not be allocated, then give an	*/
	/* error message.												*/
	new_entry_ptr = ip_cmn_rte_table_entry_mem_alloc ();
	if (new_entry_ptr == OPC_NIL)
		{
		/* Report an error message and terminate the simulation		*/
		op_sim_end ("Error in IP common route table support code: ",
			"Could not allocate memory for IpT_Cmn_Rte_Table_Entry data structure.", OPC_NIL, OPC_NIL);
		}
	
	/* Copy values to the new structure from the old one.			*/
	/* Note that we do not have to do a deep copy on the dest prefix*/
	/* because, the memory is actually owned by the process that	*/
	/* inserted the route.											*/
	new_entry_ptr->dest_prefix			= entry_ptr->dest_prefix;
	new_entry_ptr->route_src_proto		= Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (entry_ptr->route_src_proto);
	new_entry_ptr->route_insert_time	= entry_ptr->route_insert_time;
	new_entry_ptr->admin_distance		= entry_ptr->admin_distance;
	new_entry_ptr->route_src_obj_ptr	= entry_ptr->route_src_obj_ptr;
	
	/* Create the next hop list since there is definitely at least	*/
	/* a single next hop.											*/
	new_entry_ptr->next_hop_list		= op_prg_list_create ();

	/* Copy the next hop list.										*/
	for (i = 0; i < op_prg_list_size (entry_ptr->next_hop_list); i++)
		{
		next_hop_ptr = (IpT_Next_Hop_Entry *) op_prg_list_access (entry_ptr->next_hop_list, i);
		new_next_hop_ptr = ip_cmn_rte_table_next_hop_copy (next_hop_ptr);
		
		op_prg_list_insert (new_entry_ptr->next_hop_list, new_next_hop_ptr, i);
		}
	
	/* If there were elements in the backup list of the original	*/
	/* route entry, then copy the backup list.  Otherwise, do		*/
	/* nothing with it.												*/
	if (entry_ptr->backup_list != OPC_NIL)
		{
		/* Create the backup list now that we know the original		*/
		/* entry had entries in it's backup list.					*/
		new_entry_ptr->backup_list		= op_prg_list_create ();
		
		/* Copy the backup list										*/
		for (i = 0; i < op_prg_list_size (entry_ptr->backup_list); i++)
			{
			backup_entry_ptr = (IpT_Backup_Entry *) op_prg_list_access (entry_ptr->backup_list, i);
			new_backup_entry_ptr = ip_cmn_rte_table_backup_entry_copy (backup_entry_ptr);
			
			op_prg_list_insert (new_entry_ptr->backup_list, new_backup_entry_ptr, i);
			}
		}
	else
		{
		new_entry_ptr->backup_list		= OPC_NIL;
		}
	
	/* Return the newly created copy.								*/
	FRET (new_entry_ptr);
	}

static void
ip_cmn_rte_table_entry_next_hop_key_lists_clear (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	int					i, num_next_hops;
	IpT_Next_Hop_Entry*	ith_next_hop;

	/** Clear out the dest src table key list of all the next hops	**/
	/** of the given route. Remove the corresponding entries from	**/
	/** the dest src table also.									**/

	FIN (ip_cmn_rte_table_entry_next_hop_key_lists_clear (route_table, route_entry));

	/* Loop through the list of next hops and withdraw the	*/
	/* corresponding dest src table entries.				*/
	num_next_hops = op_prg_list_size (route_entry->next_hop_list);
	for (i = 0; i < num_next_hops; i++)
		{
		/* Remove the entry at the head of the list.				*/
		ith_next_hop = (IpT_Next_Hop_Entry*) op_prg_list_access
			(route_entry->next_hop_list, i);

		/* Remove the corresponding entries from the dest src table.*/
		ip_cmn_rte_table_dest_src_table_entries_remove (route_table, ith_next_hop);

		/* Free the memory allocated to the list of keys and the	*/
		/* keys themselves.											*/
		op_prg_list_free (ith_next_hop->table_key_lptr);
		op_prg_mem_free (ith_next_hop->table_key_lptr);
		ith_next_hop->table_key_lptr = OPC_NIL;
		}

	FOUT;
	}

void
ip_cmn_rte_table_entry_free (IpT_Cmn_Rte_Table_Entry* entry, IpT_Cmn_Rte_Table* route_table)
	{
	/** Free up the memory used for an IpT_Cmn_Rte_Table_Entry object.	**/
	FIN (ip_cmn_rte_table_entry_free (entry, table));

	/* Note that we should not free the memory allocated to the			*/
	/* destination prefix because the memory is owned by the process 	*/
	/* that inserted the entry.											*/

	/* Default network routes might have the next hop list set to NIL.	*/
	/* Check for that.													*/
	if (OPC_NIL != entry->next_hop_list)
		{
		while (op_prg_list_size (entry->next_hop_list))
			{
			ip_cmn_rte_table_next_hop_free ((IpT_Next_Hop_Entry*)
				op_prg_list_remove (entry->next_hop_list, OPC_LISTPOS_HEAD),
				route_table);
			}
		op_prg_mem_free (entry->next_hop_list);
		}

	if (OPC_NIL != entry->backup_list)
		{
		op_prg_list_free (entry->backup_list);
		op_prg_mem_free (entry->backup_list);
		}
	
	/* Free up the memory for the object.					*/
	op_prg_mem_free (entry);

	FOUT;
	}

static void 
ip_cmn_rte_table_dest_src_tbl_entry_free (void* entry_ptr)
	{
	/* This function is called to free the entry of dest_src_table */
	FIN (ip_cmn_rte_table_dest_src_tbl_entry_free (void*));
	
	op_prg_mem_free ((IpT_Cmn_Rte_Dest_Src_Table_Entry*) entry_ptr);
	
	FOUT;
	}
	
static void
ip_cmn_rte_table_next_hop_free (IpT_Next_Hop_Entry* next_hop_ptr, IpT_Cmn_Rte_Table* route_table)
	{
	FIN (ip_cmn_rte_table_next_hop_free (IpT_Next_Hop_Entry* next_hop_ptr));
	
	/* Note that we should not free the memory allocated to the			*/
	/* next hop address because the memory is owned by the process that	*/
	/* inserted the entry.												*/

	if (next_hop_ptr->table_key_lptr != OPC_NIL)
		{
		op_prg_list_free (next_hop_ptr->table_key_lptr);
		op_prg_mem_free (next_hop_ptr->table_key_lptr);
		}

	/* Free dynamically allocated (MPLS) resources that may be present inside the port info.	*/
	ip_cmn_rte_table_port_info_free (&(next_hop_ptr->port_info), route_table);
	
	op_prg_mem_free (next_hop_ptr);
	
	FOUT;
	}

static void
ip_cmn_rte_table_port_info_free (IpT_Port_Info*	port_info_ptr, IpT_Cmn_Rte_Table* route_table)
	{
	int									intf_index;
	IpT_Address							next_hop;
	MplsT_Label							top_label, bottom_label;
	MplsT_NHLFE*						top_nhlfe_ptr;
	MplsT_Label_Space_Handle			label_space_handle;
	MplsT_Port_Output_Info*				mpls_info_ptr;	
	char								msg_str [128];
	
	/** Free any dynamically allocated resources that may be present in the port info object.	**/
	FIN (ip_cmn_rte_table_port_info_free (port_info_ptr, route_table));

	/* Dynamically allocated resources are present only in VRF table entries that contain	*/
	/* MPLS label information.																*/
	if (ip_rte_port_info_contains_mpls_info (port_info_ptr))
		{
		mpls_info_ptr = port_info_ptr->output_info.mpls_info_ptr;
		
		/* Copies of the port info object are made by using a reference count, for efficiency.	*/
		/* Hence the reference count must be decremented and examined before freeing up the 	*/
		/* memory.																				*/
		mpls_info_ptr->ref_count--;
		
#ifndef	OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("mpls_port_info"))
			op_prg_odb_print_major ("Freeing MPLS port info", OPC_NIL);
#endif
		/* Free up the resources only when there are no more references to this port info.		*/
		if (0 == mpls_info_ptr->ref_count)
			{
			ip_vrf_port_info_mpls_switching_info_get (port_info_ptr, &intf_index, &next_hop, &top_label,
				&bottom_label, &top_nhlfe_ptr,  
				OPC_NIL /* placeholder for bottom NHLFE (optional) */,
	     		OPC_NIL /* IP module data, calling function can handle NIL values.	*/);	

			/* The bottom label must be freed only if it is a destination connected to a local CE,	*/
			/* since only then the bottom label was allocated by this node in the first place.		*/
			/* A destination can be considered to be connected to a local CE IFF the top NHLFE is	*/
			/* NIL (i.e. there is no LSP associated with this destination).							*/
			if (OPC_NIL == top_nhlfe_ptr)
				{
				/* Get the handle to Label Space. For VPNs, the label space index used is zero,		*/
				/* since traffic may come in from any interface.									*/
				label_space_handle = mpls_label_space_handle_get (route_table->iprmd_ptr, MPLSC_VPN_LABEL_SPACE_INDEX);
				mpls_label_free (label_space_handle, bottom_label);
				}

			op_prg_mem_free (port_info_ptr->output_info.mpls_info_ptr);

#ifndef OPD_NO_DEBUG
			if (op_prg_odb_ltrace_active ("mpls_port_info"))
				{
				sprintf (msg_str, "Freeing bottom label %d", bottom_label); 
				op_prg_odb_print_major (msg_str, OPC_NIL);
				}
#endif
			}
		}

	FOUT;
	}
			
/** Internal operations for new IP Routing Table **/
static void
ip_cmn_rte_next_hop_add (IpT_Cmn_Rte_Table_Entry* route_entry,
	InetT_Address next_hop, int metric, IpT_Port_Info* port_info_ptr)
	{
	IpT_Next_Hop_Entry*			hop_entry;	
	
	/* This function will add a new "next hop" to an entry in the IP Common Routing	*/
	/* Table, for the entry indexed by "index. This is used when the source routing	*/
	/* protocol has a new route to the same destination								*/
	FIN (ip_cmn_rte_next_hop_add (route_entry, next_hop, metric, port_info_ptr));
	
	/* Allocate structure and fill in fields for the new next hop entry */
	hop_entry = ip_cmn_rte_table_next_hop_entry_mem_alloc ();

	/* Do not use inet_address_copy here. Just reuse the memory used by	*/
	/* the process for the address.										*/
	hop_entry->next_hop 			= next_hop;
	hop_entry->route_insert_time 	= op_sim_time ();
	hop_entry->route_metric			= metric;
	hop_entry->port_info			= *port_info_ptr;
	
	/* Do not create the key list. We will create it when needed.		*/
	hop_entry->table_key_lptr = OPC_NIL;
	
	/* Insert the new next hop into to next hop list of the route entry */
	op_prg_list_insert (route_entry->next_hop_list, hop_entry, OPC_LISTPOS_TAIL);
	
	FOUT;
	}

static IpT_Next_Hop_Entry*
ip_cmn_rte_table_next_hop_copy (IpT_Next_Hop_Entry* next_hop_ptr)
	{
	IpT_Next_Hop_Entry*		new_next_hop_ptr = OPC_NIL;
	
	/** This function takes an existing IpT_Next_Hop_Entry structure	**/
	/** and returns an exact copy of it.								**/
	
	FIN (ip_cmn_rte_table_next_hop_copy (next_hop_ptr));
	
	/* Allocate space in memory for the new structure					*/
	/* If space can not be allocated, issue an error					*/
	/* message.															*/
	new_next_hop_ptr = ip_cmn_rte_table_next_hop_entry_mem_alloc ();
	if (new_next_hop_ptr == OPC_NIL)
		{
		/* Report an error message and terminate the simulation			*/
		op_sim_end ("Error in IP common route table support code: ",
			"Could not allocate memory for IpT_Next_Hop_Entry data structure.", OPC_NIL, OPC_NIL);
		}
	
	/* Assign values from the original structure to the new one.		*/
	/* Do not use inet_address_copy to copy the next hop because the	*/
	/* memory allocated to the next hop is owned by the process that	*/
	/* inserted the route.												*/
	new_next_hop_ptr->next_hop			= next_hop_ptr->next_hop;
	new_next_hop_ptr->route_insert_time	= next_hop_ptr->route_insert_time;
	new_next_hop_ptr->route_metric		= next_hop_ptr->route_metric;
	new_next_hop_ptr->port_info			= ip_cmn_rte_table_port_info_copy (&(next_hop_ptr->port_info));
	
	/* Do not copy the contents of the table_key_lptr, instead just		*/
	/* set it to NIL.													*/
	new_next_hop_ptr->table_key_lptr = OPC_NIL;
	
	/* Return the new copy.												*/
	FRET (new_next_hop_ptr);
	}

static IpT_Port_Info
ip_cmn_rte_table_port_info_copy (IpT_Port_Info* port_info_ptr)
	{
	/** Makes a copy of the port info object, if needed.	**/
	FIN (ip_cmn_rte_table_port_info_copy (port_info_ptr));

	/* If the port info object does not contain dynamically allocated	*/
	/* MPLS information, then we need not make copies.					*/
	if (ip_rte_port_info_contains_mpls_info (port_info_ptr))
		{
		/* The bottom label present inside the port information must be 	*/
		/* freed only once, since the MPLS tables will contain only one		*/
		/* instance of the label. Hence, we do not make explicit copies but	*/
		/* use a reference count instead.									*/
		port_info_ptr->output_info.mpls_info_ptr->ref_count++;

#ifndef OPD_NO_DEBUG
		if (op_prg_odb_ltrace_active ("mpls_port_info"))
			op_prg_odb_print_major ("Copying MPLS port info", OPC_NIL);
#endif
		}

	FRET (*port_info_ptr);
	}
		

static Boolean
ip_cmn_rte_enter_backup ( IpT_Cmn_Rte_Table_Entry* route_entry, IpT_Rte_Proc_Id proto,
	int admin_distance, void* src_obj_ptr)
	{
	IpT_Backup_Entry*			backup_entry;
	IpT_Backup_Entry*			temp_backup_entry;
	int							list_size, i;
	int							insert_position = 0;
	int							proto_type;
	
	/** If multiple routing protocols add an entry to the same destination,	**/
	/** the one with the lowest administrative distance will be inserted 	**/
	/** into common route table. The others will be stored in the backup 	**/
	/** list of the route. This function is used to insert a route into the	**/
	/** backup list.														**/
	FIN (ip_cmn_rte_entry_backup (cmn_rte_table, proto, ...));
	
	/* Create a backup entry only if it is a standard dynamic routing protocols.*/
	proto_type = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (proto);

	if ((proto_type >= IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID) ||
		(proto_type == IpC_Dyn_Rte_Directly_Connected))
		{
		/* Do not insert this entry into the backup list	*/
		FRET (OPC_FALSE);
		}

	backup_entry = (IpT_Backup_Entry *)op_prg_mem_alloc (sizeof (IpT_Backup_Entry));
	backup_entry->route_proto = proto;
	backup_entry->admin_distance = admin_distance;
	backup_entry->route_src_obj_ptr = src_obj_ptr;
		
	/* Create a list of backup routes if it doesn't		*/
	/* already exist.									*/
	if (OPC_NIL == route_entry->backup_list)
		{
		route_entry->backup_list = op_prg_list_create ();

		/* Insert the backup entry into the list.		*/
		op_prg_list_insert (route_entry->backup_list, backup_entry, OPC_LISTPOS_TAIL);

		/* Return true to indicate that the entry just	*/
		/* inserted is the best backup route.			*/
		FRET (OPC_TRUE);
		}

	/* Loop through the list and make sure that it does	*/
	/* not already contain an entry from the same 		*/
	/* protocol. While doing it also determine the 		*/
	/* position in the list where the new entry must be	*/
	/* inserted. Note that entries are to be stored in	*/
	/* the increasing order of administrative distances	*/ 

	/* Get the number of entries in the list.			*/
	list_size = op_prg_list_size (route_entry->backup_list);
	
	/* Test if the routing protocol has already registered a backup */
	for (i=0; i < list_size; i++)
		{
		temp_backup_entry = (IpT_Backup_Entry *)
			op_prg_list_access (route_entry->backup_list, i);
		
		if (temp_backup_entry->route_proto == proto)
			{
			/* An entry already exists. Return false	*/
			FRET (OPC_FALSE);
			}
		/* If the administrative distance of this		*/
		/* entry is lower than that of the new entry,	*/
		/* increment the insert_position.				*/
		if (temp_backup_entry->admin_distance < admin_distance)
			{
			++insert_position;
			}
		}
	
	/* This is a new entry. insert it in the position	*/
	/* that we determined.								*/
	op_prg_list_insert (route_entry->backup_list, backup_entry, insert_position);

	/* If the new entry was the best entry, return true	*/
	FRET ((Boolean) (0 == insert_position));
	}

static IpT_Backup_Entry*
ip_cmn_rte_table_backup_entry_copy (IpT_Backup_Entry* backup_entry_ptr)
	{
	IpT_Backup_Entry*	new_backup_entry_ptr = OPC_NIL;
	
	/** This function takes an existing IpT_Backup_Entry	**/
	/** structure and returns an exact copy of it.			**/
	
	FIN (ip_cmn_rte_table_backup_entry_copy (backup_entry_ptr));
	
	/* Allocate space in memory for the new structure		*/
	/* If space can not be allocated, issue an error		*/
	/* message.												*/
	new_backup_entry_ptr = (IpT_Backup_Entry*) op_prg_mem_alloc (sizeof (IpT_Backup_Entry));
	if (new_backup_entry_ptr == OPC_NIL)
		{
		/* Report an error message and terminate the simulation		*/
		op_sim_end ("Error in IP common route table support code: ",
			"Could not allocate memory for IpT_Backup_Entry data structure.", OPC_NIL, OPC_NIL);
		}

	/* Assign values from the old backup entry to the		*/
	/* new backup entry.									*/
	new_backup_entry_ptr->route_proto		= backup_entry_ptr->route_proto;
	new_backup_entry_ptr->admin_distance	= backup_entry_ptr->admin_distance;
	new_backup_entry_ptr->route_src_obj_ptr	= backup_entry_ptr->route_src_obj_ptr;
	
	/* Return the newly created copy.						*/
	FRET (new_backup_entry_ptr);
	}

static void
ip_cmn_rte_delete_backup (IpT_Cmn_Rte_Table* cmn_rte_table, IpT_Rte_Proc_Id proto,
	IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	IpT_Backup_Entry*			temp_backup_entry;
	int							list_size, i;
	int							redist_type;
	IpT_Rte_Proc_Id				removed_proto;
	
	/* This function will delete the backup registered by the routing proto given as a parm */
	/* for the route entry at the "index" position											*/
	FIN ( ip_cmn_rte_delete_backup (cmn_rte_table, proto, index));
	
	/* If the backup list does not exist, just return	*/
	if (OPC_NIL == route_entry->backup_list)
		{
		FOUT;
		}

	list_size = op_prg_list_size (route_entry->backup_list);
	
	for (i=0; i < list_size; i++)
		{
	   	temp_backup_entry = (IpT_Backup_Entry *)
			op_prg_list_access (route_entry->backup_list, i);
		
		if (temp_backup_entry->route_proto == proto)
			{
			op_prg_list_remove (route_entry->backup_list, i);
			prg_mem_free (temp_backup_entry);
			
			/* The type of redistribution is different	*/
			/* in the case of directly connected routes	*/
			/* so determine if this route is directly	*/
			/* connected and set the redist type		*/
			/* accordingly.								*/
			if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (route_entry->route_src_proto))
				redist_type = IPC_REDIST_TYPE_UPDATE_DIRECT;
			else
				redist_type = IPC_REDIST_TYPE_UPDATE;
			
			/* There is a protocol which is being removed.  So that	*/
			/* the redistributing function will know which protocol */
			/* is no longer available, set the removed proto to be	*/
			/* the protocol which is being deleted.					*/
			removed_proto = proto;
			
			/* If the entry in the route table is a directly		*/
			/* connected network, then advertisements by protocols	*/
			/* located in the backup list have beeen redistributed	*/
			/* to other protocols.  Redistribute the now			*/
			/* unavailable route to other protocols.				*/
			ip_cmn_rte_table_entry_redistribute (cmn_rte_table, route_entry, redist_type, removed_proto);
			break;
			}
		}
	
	FOUT;
	}
		
static void
ip_cmn_rte_entry_replace (IpT_Cmn_Rte_Table* cmn_rte_table, void* src_obj_ptr,
	IpT_Dest_Prefix PRG_ARG_UNUSED (dest_prefix), InetT_Address next_hop, IpT_Port_Info port_info,
	int metric, IpT_Rte_Proc_Id proto, int admin_distance, IpT_Cmn_Rte_Table_Entry* route_entry)
	{
	double						cur_time;
	
	/* Debug vars.	*/
	char						dest_str [INETC_ADDR_STR_LEN];
	char						nh_str [INETC_ADDR_STR_LEN];
	char 		 				proto_str[64];
	char						trace_msg1 [512];
	char						trace_msg2 [512];
	int							i, num_next_hops;
	InetT_Address				next_hop_addr;
	IpT_Port_Info				temp_port_info;
	
	/* This function is called when a better routing protocol has a route to a destination that a lesser	*/
	/* protocol had previously registered. This function will replace the route entry fields to reflect the */
	/* new protocol and add its next hop to the list */
	FIN (ip_cmn_rte_entry_replace (cmn_rte_table, src_obj_ptr, dest_prefix, 
		next_hop, port_info, metric, proto, admin_distance, index));
	
	/* Delete the next_hops one by one.						*/
	num_next_hops = ip_cmn_rte_table_entry_hop_num (cmn_rte_table, route_entry);

	for (i = 0; i < num_next_hops; i++)
		{
		/* Get the entry that is currently at the top of the*/
		/* list and delete it.								*/
		next_hop_addr = inet_cmn_rte_table_entry_hop_get (route_entry, 0, &temp_port_info);
		ip_cmn_rte_next_hop_delete (cmn_rte_table, route_entry, next_hop_addr);
		}

	/*Replace all values of the route entry at "index" with values in parms */
	cur_time = op_sim_time ();
	
	route_entry->route_src_proto	= proto;
	route_entry->route_insert_time 	= cur_time;
	route_entry->admin_distance		= admin_distance;
	
	/* Set the source obj ptr. For directly connected routes*/
	/* it should be set to this route entry itself. This is	*/
	/* necessary for route maps to work. For other routes,	*/
	/* use the specified src_obj_ptr.						*/
	if (IP_CMN_RTE_TABLE_PROTOCOL_IS_DIRECT (route_entry->route_src_proto))
		{
		/* Directly connected route.						*/
		route_entry->route_src_obj_ptr	= route_entry;
		}
	else
		{
		/* Not a directly connected route.					*/
		route_entry->route_src_obj_ptr	= src_obj_ptr;
		}

	ip_cmn_rte_next_hop_add (route_entry, next_hop, metric, &port_info);

	/** Debugging and Trace information **/
	/** Alert user if a protocol is "overtaking" an entry	**/ 
	/** due to a better (lower) administrative distance 	**/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_cmn_rte_table"))
		{
		ip_cmn_rte_table_dest_prefix_print (dest_str, route_entry->dest_prefix);
		inet_address_print (nh_str, next_hop);
		ip_cmn_rte_proto_name_print (proto_str, proto);
	
		/* Now print message	*/
		sprintf (trace_msg1,
			"|%s| is replacing the entry in the IP Routing Table for the following destination:",
			proto_str);
		sprintf (trace_msg2,
			"Dest |%s|, Next Hop |%s|, O/P Intf. |%d|, Metric |%d|",
			dest_str, nh_str, ip_rte_intf_tbl_index_from_port_info_get
			(cmn_rte_table->iprmd_ptr, port_info), metric);
		
		op_prg_odb_print_major (trace_msg1, OPC_NIL);
		op_prg_odb_print_minor (trace_msg2, OPC_NIL);
		}
#endif
	
	FOUT;
	}

static void
ip_cmn_rte_table_next_hop_list_update (IpT_Cmn_Rte_Table* route_table,
	IpT_Cmn_Rte_Table_Entry* route_entry, InetT_Address next_hop)
	{
	int							num_next_hops, i;
	IpT_Next_Hop_Entry*			next_hop_ptr;

	/** Remove all next hops except the specified one from the	**/
	/** list of next hops.										**/

	FIN (ip_cmn_rte_table_next_hop_list_update (route_table, route_entry, next_hop));

	num_next_hops = op_prg_list_size (route_entry->next_hop_list);

	/* Iterate through the list of next hops.					*/
	for (i = 0; i < num_next_hops; i ++)
		{
		/* Remove the next hop which is at the top of the list.	*/
		next_hop_ptr = (IpT_Next_Hop_Entry *) op_prg_list_remove (route_entry->next_hop_list, OPC_LISTPOS_HEAD);
	
		/* Check to see if this is the next hop address which	*/
		/* is being changed.  If it is, then add it back to the	*/
		/* next hop list.										*/
		if (inet_address_equal (next_hop_ptr->next_hop, next_hop))
			{
			op_prg_list_insert (route_entry->next_hop_list, next_hop_ptr, OPC_LISTPOS_TAIL);
			}
		else
			{
			/* Remove the dest src table entries corresponding	*/
			/* to this next hop.								*/
			ip_cmn_rte_table_dest_src_table_entries_remove (route_table, next_hop_ptr);

			/* Free the memory allocated to the entry itself.	*/
			ip_cmn_rte_table_next_hop_free (next_hop_ptr, route_table);
			}
		}
	
	/* Make sure that there is a valid Next hop to update,		*/
	/* else generate a recoverable error						*/
	if (0 == op_prg_list_size (route_entry->next_hop_list))
		{
		char error_msg [128];
		ip_cmn_rte_table_dest_prefix_print (error_msg, route_entry->dest_prefix);
		op_sim_error (OPC_SIM_ERROR_RECOVER, "Error in Entry Update", error_msg);
		}	
	
	FOUT;
	}

static int
ip_cmn_rte_next_hop_update (IpT_Cmn_Rte_Table_Entry* route_entry, InetT_Address next_hop,
	InetT_Address new_next_hop, IpT_Port_Info new_port_info, int new_metric, IpT_Cmn_Rte_Table* route_table)
	{
	int								list_size, i, changed = 0;
	double							cur_time;
	IpT_Next_Hop_Entry*				next_hop_ptr;
	Boolean							change_next_hop = OPC_FALSE;
   
	/** This function will search through the next hop		**/
	/** list of the route entry at "index" and will update	**/
	/** the next_hop value and/or the metric.  The next_hop	**/
	/** is being changed if the new_next_hop value is not	**/
	/** an invalid address.									**/
	FIN (ip_cmn_rte_next_hop_update (route_entry, next_hop, new_next_hop, new_port_info, new_metric, route_table));
   
	/* Determine whether this function is being called to 	*/
	/* update the next hop, and/or to update the metric for	*/
	/* this route.  If new_next_hop was passed in with an 	*/
	/* invalid IP address, then it means that the next hop 	*/
	/* is not being updated.  If it has a valid IP address,	*/
	/* then it is being changed.							*/
	if (inet_address_valid (new_next_hop))
		change_next_hop = OPC_TRUE;
   
	list_size = op_prg_list_size (route_entry->next_hop_list);
	if (list_size > 0)
		cur_time = op_sim_time ();
   
	/* Loop through the next hop list to find the entry		*/
	/* which needs to be updated.							*/
	for (i=0; i < list_size; i++)
		{
		/* Get a handle on the i_th next hop entry.			*/
		next_hop_ptr = (IpT_Next_Hop_Entry *)
			op_prg_list_access (route_entry->next_hop_list, i);
	   
		if (inet_address_equal (next_hop_ptr->next_hop, next_hop))
			{
			/* If change_next_hop is TRUE, then change the	*/
			/* address and port info of the next hop node.	*/
			if (change_next_hop == OPC_TRUE)
				{
				next_hop_ptr->next_hop = new_next_hop;
			
				/* Before overwriting the port info, delete any dynamic MPLS	*/
				/* information that may be present inside it.					*/
				ip_cmn_rte_table_port_info_free (&next_hop_ptr->port_info, route_table);
				
				next_hop_ptr->port_info = new_port_info;
				}
			/* Always set the metric.						*/
  			next_hop_ptr->route_metric = new_metric;
			
			/* Update the insertion time for the route.		      */
			/* next_hop_ptr->route_insert_time = cur_time;        */
			
			next_hop_ptr->route_insert_time = cur_time; 
			changed++;
			}
		}
	FRET (changed);
	}

static int
ip_cmn_rte_next_hop_delete (IpT_Cmn_Rte_Table* cmn_rte_table, IpT_Cmn_Rte_Table_Entry* route_entry, 
	InetT_Address next_hop)
	{
	IpT_Next_Hop_Entry*			next_hop_ptr;
	int							i, changed = 0;
	int							next_hop_list_size;
	
	/* Remove the next hop from the route entry at the given */
	/* index that  matches the next_hop address given.		 */
	
	FIN (ip_cmn_rte_next_hop_delete (cmn_rte_table, route_entry, next_hop));
	
	next_hop_list_size = op_prg_list_size (route_entry->next_hop_list);
	/* Traverse all entry next hops for this route entry for a match to the given next hop address */
	for (i=0; i < next_hop_list_size; i++)
		{
		next_hop_ptr = (IpT_Next_Hop_Entry *)
			op_prg_list_access (route_entry->next_hop_list, i);
		
		/* If this entry is a match, begin procedures to remove this entry */
		if (inet_address_equal (next_hop_ptr->next_hop, next_hop))
			{
			op_prg_list_remove (route_entry->next_hop_list, i);
			changed++;
			
			/* Remove the corresponding entries from the dest	*/
			/* src table.										*/
			ip_cmn_rte_table_dest_src_table_entries_remove (cmn_rte_table, next_hop_ptr);

			/* Now that the next_hop_ptr is no longer needed, it*/
			/* can be destroyed.								*/
			ip_cmn_rte_table_next_hop_free (next_hop_ptr, cmn_rte_table);			
	
			/* Now that we have found the matching next hop		*/
			/* entry, break out of the loop.					*/
			break;
			}
		}
		
	FRET (changed);
	}
	
void
ip_cmn_rte_table_redistribute (IpT_Cmn_Rte_Table* cmn_rte_table)
	{
	int							i, num_entries;
	IpT_Cmn_Rte_Table_Entry*	entry_ptr;
	OmsT_Ptree*					ptree_ptr;

	/** Scan the route table and initiate redistribution of	**/
	/** those entries that have not been redistributed.		**/
	/** This procedure is used once per router node to		**/
	/** redistribute initial routing information input by	**/
	/** whatever protocols have been set up. As such it is	**/
	/** invoked by the IP model in each router node.		**/
	FIN (ip_cmn_rte_table_redistribute (cmn_rte_table));

	/* Get a pointer to the IPv4 ptree. Redistribution is 	*/
	/* not currently supported for IPv6.					*/
	ptree_ptr = cmn_rte_table->ptree_ptr_array[InetC_Addr_Family_v4];

	if (OPC_NIL == ptree_ptr)
		{
		/* IPv4 is not enabled on this node.				*/
		FOUT;
		}

	/* Get the number of entries in the table.				*/
	num_entries = oms_ptree_size (ptree_ptr);

	/* Loop over the route table for further processing		*/
	for (i = 0; i < num_entries; i++)
		{
		/* Access the i'th entry in the route table.		*/
		entry_ptr = ip_cmn_rte_table_entry_from_ptree_entry_get
			(oms_ptree_entry_access (ptree_ptr, i));
		
		/* Redistribute the entry to other routing protocols*/
		ip_cmn_rte_table_entry_redistribute (cmn_rte_table, entry_ptr,
			IPC_REDIST_TYPE_UPDATE_DIRECT, IpC_Dyn_Rte_Invalid);
		}
		
	FOUT;
	}

IpT_Rte_Prot_Type	
ip_cmn_rte_table_intf_rte_proto_to_dyn_rte_proto (int intf_rte_proto)
	{
	/** Converts a value of enumerated type IpT_Rte_Protocol to the	**/
	/** corresponding value of type IpT_Rte_Prot_Type				**/

	FIN (ip_cmn_rte_table_intf_rte_proto_to_dyn_rte_proto (intf_rte_proto));

	switch (intf_rte_proto)
		{
		case IpC_Rte_None:
			FRET (IpC_Dyn_Rte_Invalid);
		case IpC_Rte_Igrp:
			FRET (IpC_Dyn_Rte_Igrp);
		case IpC_Rte_Ospf:
			FRET (IpC_Dyn_Rte_Ospf);
		case IpC_Rte_Isis:
			FRET (IpC_Dyn_Rte_Isis);
		case IpC_Rte_Bgp:
			FRET (IpC_Dyn_Rte_Bgp);
		case IpC_Rte_Eigrp:
			FRET (IpC_Dyn_Rte_Eigrp);
		case IpC_Rte_Rip:
			FRET (IpC_Dyn_Rte_Rip);
		case IpC_Rte_Ripng:
			FRET (IpC_Dyn_Rte_Ripng);
		default:
			/* Custom routing protocol. Return IpC_Dyn_Rte_Custom	*/
			FRET (IpC_Dyn_Rte_Custom);
		}

	/* Dummy FRET statement to suppress compiler warnings			*/
	FRET (IpC_Dyn_Rte_Invalid);
	}
	

static void
ip_cmn_rte_table_entry_redistribute (IpT_Cmn_Rte_Table* cmn_rte_table, IpT_Cmn_Rte_Table_Entry* route_ptr,
	int redist_type, IpT_Rte_Proc_Id removed_proto)

	{
	IpT_Route_Proc_Info*		dest_route_proc_info_ptr = OPC_NIL;
	IpT_Cmn_Rte_Table_Entry*	route_copy_ptr = OPC_NIL;
	IpT_Next_Hop_Entry*			next_hop_ptr = OPC_NIL;
	IpT_Rte_Proc_Id				normalized_src_proto;
	IpT_Rte_Proc_Id				normalized_removed_proto;
	IpT_Rte_Proc_Id				route_src_proto;
	int							i, j, num_backups;
	IpT_Redist_Matrix_Entry *	from_redist_matrix_entry;
	IpT_Redist_Matrix_Entry *	temp_from_redist_matrix_entry;
	IpT_Redist_Info *			to_redist_info;
	Prohandle					to_routeproc_handle;
	Boolean						redistributes_direct;
	Boolean						redistribute_withdrawal;
	List *						redist_routeproc_lptr;
	int							non_withdraw_count;
	
	char						src_proto_str [64], dest_proto_str [64], type_str [64];
	char						dest_str [INETC_ADDR_STR_LEN], next_hop_str [INETC_ADDR_STR_LEN];
	char						trace_msg [512], trace_msg2 [512], trace_msg3 [512], trace_msg4 [512];	

	/** Depending on the routing protocol that sourced an	**/
	/** entry in the common routing table, invoke the		**/
	/** appropriate procedure for every other routing		**/
	/** protocol that is also running in this node.			**/
	/** Currently, all route information that is injected	**/
	/** (redistributed) into a routing protocol is given a	**/
	/** metric of zero. This can be changed to allow		**/
	/** modeling of other implementations.					**/
	/** But note that these interrupts must not be sent if	**/
	/** routing tables are being imported from a file		**/
	FIN (ip_cmn_rte_table_entry_redistribute (cmn_rte_table, route_ptr, redist_type, removed_proto));
	
	/* Check if routing tables are being imported.			*/
	if (routing_table_import_export_flag == IP_RTE_TABLE_IMPORT)
		{
		/* Do not send any interrupts.						*/
		FOUT;
		}
	
	/* We do not currently support redistribution for IPv6	*/
	/* routes.												*/
	if (InetC_Addr_Family_v6 == ip_cmn_rte_table_dest_prefix_addr_family_get (route_ptr->dest_prefix))
		{
		FOUT;
		}

	/* Some routing protocols need to be changed into their	*/
	/* generic form.  For example, External EIGRP is the	*/
	/* specific form of EIGRP.  Transform this entry's		*/
	/* protocol into the normalized (generic) version.		*/
	normalized_src_proto = Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (route_ptr->route_src_proto);
	normalized_removed_proto = Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (removed_proto);
	
	/* Depending on the protocol that inserted the route,	*/
	/* redistribute it to other protocols.					*/
	/* Only redistribute this route to protocols that have	*/
	/* stated a desire to redistribute this protocol.  Use	*/
	/* the redistribution matrix.							*/
	from_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_search (cmn_rte_table, normalized_src_proto);
	
	if (redist_type == IPC_REDIST_TYPE_UPDATE_DIRECT)
		{
		/** This is redistribution for a directly connected	**/
		/** network.  This is a special case and needs to	**/
		/** be handled seperately.							**/
		
		/* There are several cases which will require a		*/
		/* redistribution message to be sent:				*/
		/*													*/
		/* 1: There is at least one protocol in the backup	*/
		/* list which will be redistributed to another 		*/
		/* process on this node.							*/
		/* 2: Directly connected routes are redistributed	*/
		/* to another process.								*/
		/* 3: A route which was previously in the backup	*/
		/* list has been removed.  The redistribution		*/
		/* message must be sent to the processes that it	*/
		/* previously redistributed to.  If no other		*/
		/* protocols in the backup list are redistributing	*/
		/* to that process, this is essentially a withdraw.	*/

		/* Loop through every routing process running on	*/
		/* this node.  With directly connected routes,		*/
		/* every protocol which is in the backup list will	*/
		/* be redistributed to it's own list of protocols.	*/
		/* Since each protocol may redistribute to other	*/
		/* protocols, and that list may not be the same,	*/
		/* loop through every routing process on this node	*/
		/* and create a separate list of protocols which	*/
		/* need to be redistributed to it.					*/
		for (i = 0; i < prg_vector_size (cmn_rte_table->routeproc_vptr); i++)
			{
			/* Initialize the trace_msg3 string.			*/
			/* Used for debugging purposes.					*/
			trace_msg3[0] = '\0';;
			
			/* Initialize the redistributes direct flag.	*/
			/* If this protocol redistributes direct, then	*/
			/* it will be set to TRUE.						*/
			redistributes_direct = OPC_FALSE;
			redistribute_withdrawal = OPC_FALSE;
			
			/* Get a reference to the ith route proc info.	*/
			dest_route_proc_info_ptr = (IpT_Route_Proc_Info *) prg_vector_access (cmn_rte_table->routeproc_vptr, i);
			
			/* Make a copy of the passed in route table 	*/
			/* entry to pass using redistribution.			*/
			/* NOTE: This function will return a route table*/
			/* entry which has all normalized protocols in	*/
			/* both the backup list, and as the source proto*/
			route_copy_ptr = ip_cmn_rte_table_entry_copy (route_ptr);
			
			/* For directly connected networks, all			*/
			/* protocols in the backup list are 			*/
			/* redistributed, as well as the directly		*/
			/* connected route itself.  However, all		*/
			/* protocols in the backup list are not			*/
			/* redistributing to the same protocols.  For	*/
			/* example, if RIP and IGRP are both in the		*/
			/* backup list, RIP may only be redistributing	*/
			/* to OSPF, whereas IGRP is redistributing to	*/
			/* OSPF and EIGRP.  Therefore, before sending	*/
			/* the entry to the destination protocol, the	*/
			/* protocols which are capable of redistributing*/
			/* needs to be determined.  This function will	*/
			/* prune the backup list of protocols which		*/
			/* do not redistribute into the destination		*/
			/* protocol.									*/
			/* This is CASE 1								*/
			num_backups = ip_cmn_rte_table_prune_backups_for_redistribution (cmn_rte_table, route_copy_ptr,
				dest_route_proc_info_ptr->routeproc_id, from_redist_matrix_entry, trace_msg3);
			
			/* If there were no backups which are			*/
			/* redistributed into this process, determine	*/
			/* if we should redistribute this route			*/
			/* anyway.										*/
			/* We should redistribute this route anyway if	*/
			/* the directly connected route is configured	*/
			/* for redistribution, or if the removed proto	*/
			/* is redistributed into this process.			*/
			/* This is CASE 2.  Don't check for CASE 2		*/
			/* unless CASE 1 fails.							*/
			if ((from_redist_matrix_entry != OPC_NIL) && (num_backups == 0))
				{
				for (j = 0; j < prg_list_size (from_redist_matrix_entry->redist_routeproc_lptr); j++)
					{
					to_redist_info = (IpT_Redist_Info *) op_prg_list_access (from_redist_matrix_entry->redist_routeproc_lptr, j);
					if (to_redist_info->routeproc_id == dest_route_proc_info_ptr->routeproc_id)
						{
						/* This protocol does redistribute		*/
						/* directly connected.					*/
						redistributes_direct = OPC_TRUE;
						break;
						}
					}
				}
			
			/* If we are still not redistributing this route,	*/
			/* then check to see if we should issue a withdraw.	*/
			/* This is CASE 3.  Only check for CASE 3 if both	*/
			/* CASE 1 and CASE 2 fail.							*/
			if ((num_backups == 0) && (redistributes_direct == OPC_FALSE) && (removed_proto != IpC_Dyn_Rte_Invalid))
				{
				temp_from_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_search (cmn_rte_table, normalized_removed_proto);
				
				if (temp_from_redist_matrix_entry != OPC_NIL)
					{
					for (j = 0; j < prg_list_size (temp_from_redist_matrix_entry->redist_routeproc_lptr); j++)
						{
						to_redist_info = (IpT_Redist_Info *) op_prg_list_access (temp_from_redist_matrix_entry->redist_routeproc_lptr, j);
						if (to_redist_info->routeproc_id == dest_route_proc_info_ptr->routeproc_id)
							{
							/* This protocol does should still		*/
							/* redistribute this route, but it will	*/
							/* essentially be a withdrawal.			*/
							redistribute_withdrawal = OPC_TRUE;
							break;
							}
						}
					}
				}
			
			/* If there is nothing to redistribute, then just	*/
			/* skip this destination protocol.					*/
			/* This will happen if none of the routes in the	*/
			/* backup list can redistribute, and directly		*/
			/* connected routes are not redistributed to the	*/
			/* destination protocol.							*/
			if ((num_backups == 0) && (redistributes_direct == OPC_FALSE) && (redistribute_withdrawal == OPC_FALSE))
				{
				/* Free the memory used by the route table copy	*/
				ip_cmn_rte_table_entry_free (route_copy_ptr, cmn_rte_table);
				continue;
				}
			
#ifndef OPD_NO_DEBUG
			if (op_prg_odb_ltrace_active ("ip_redist"))
				{
				ip_cmn_rte_proto_name_print (dest_proto_str, dest_route_proc_info_ptr->routeproc_id);
				ip_cmn_rte_table_dest_prefix_print (dest_str, route_ptr->dest_prefix);
				
				next_hop_ptr = (IpT_Next_Hop_Entry *) op_prg_list_access (route_ptr->next_hop_list, OPC_LISTPOS_HEAD);
				inet_address_print (next_hop_str, next_hop_ptr->next_hop);
			
				sprintf (trace_msg, "The following directly connected route is being redistributed into %s", dest_proto_str);
				sprintf (trace_msg2, "Dest: %s  Next Hop: %s", dest_str, next_hop_str);
				
				if (redistribute_withdrawal == OPC_TRUE)
					{
					ip_cmn_rte_proto_name_print (src_proto_str, normalized_removed_proto);
					sprintf (trace_msg3, "PROTOCOLS: %s", src_proto_str);
					sprintf (trace_msg4, "Redistribution Message Type: WITHDRAWAL");
					}
				else
					sprintf (trace_msg4, "Redistribution Message Type: UPDATE");
				
				op_prg_odb_print_major (trace_msg, trace_msg2, trace_msg3, trace_msg4, OPC_NIL);
				}
#endif
			
			/* Inject this route into the destination			*/
			/* routing process.									*/
			if (redistribute_withdrawal == OPC_TRUE)
				{
				/** There are no protocol to redistribute, but	**/
				/** a protocol that was previously redistributed**/
				/** is no longer available.  Just send a		**/
				/** withdrawal message.							**/
				
				/* Set the protocol of the route entry to the	*/
				/* removed protocol so that the receiving		*/
				/* protocol will know which protocol has		*/
				/* withdrawn it's route.						*/
				route_copy_ptr->route_src_proto = normalized_removed_proto;
				
				ip_cmn_rte_table_rte_inject (IPC_REDIST_TYPE_WITHDRAW, dest_route_proc_info_ptr->routeproc_handle, route_copy_ptr,
					cmn_rte_table);
				}
			else
				{
				/** This really is an update, send the original	**/
				/** redist_type.								**/
				
				ip_cmn_rte_table_rte_inject (redist_type, dest_route_proc_info_ptr->routeproc_handle, route_copy_ptr,
					cmn_rte_table);
				}
			}
		}
	else
		{
		/** The entry in the route table is not a directly		**/
		/** route.  Handle all other cases this way.			**/
		
		/* If this is an update in which the protocol in the	*/
		/* route table has changed, then it is possible that	*/
		/* the original protocol redistributed it's route to a	*/
		/* protocol, but the new route table entry does not.	*/
		/* In this case, a withdraw message must be sent to the	*/
		/* protocols which the old entry redistributed to, but	*/
		/* the new entry does not.								*/
		
		if (removed_proto == IpC_Dyn_Rte_Invalid)
			{
			/** The routing protocol in the table has not		**/
			/** changed.										**/
			
			/* If this protocol was not found in the matrix, then	*/
			/* it is not redistributed to any other protocols. Just	*/
			/* exit out of the function.							*/
			if (from_redist_matrix_entry == OPC_NIL)
				FOUT;

			/* The list of processes we need to redistribute to	*/
			/* is only the list of processes the current entry	*/
			/* will redistribute to.							*/
			redist_routeproc_lptr = from_redist_matrix_entry->redist_routeproc_lptr;
			
			/* Every element in this list is not withdrawing.	*/
			non_withdraw_count = prg_list_size (redist_routeproc_lptr);
			}
		else
			{
			/** The routing protocol in the table has changed.	**/
			/** We may need to send some withdrawal messages.	**/
			
			/* Get the redistribution matrix entry for the		*/
			/* protocol which was originally in the route table.*/
			temp_from_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_search (cmn_rte_table, normalized_removed_proto);
			
			if (from_redist_matrix_entry == OPC_NIL)
				{
				/** Any entry which gets redistributed will be	**/
				/** a withdraw message.							**/
				
				non_withdraw_count = 0;
				}
			else
				{			
				/* Every element in this list is not withdrawing.	*/
				non_withdraw_count = prg_list_size (from_redist_matrix_entry->redist_routeproc_lptr);
				}
			
			/* Call the function which will return a combined	*/
			/* list of the processes which need to receive a	*/
			/* regular redist message, and those which need	to	*/
			/* receive a definite withdrawal.					*/
			redist_routeproc_lptr = ip_cmn_rte_table_redist_matrix_entries_combine (from_redist_matrix_entry,
					temp_from_redist_matrix_entry);
			}
	
		/* For each protocol that from_redist_matrix_entry		*/
		/* redistributes to, get the process handle of that		*/
		/* routing process, and inject the route into that 		*/
		/* process.												*/
		for (i = 0; i < prg_list_size (redist_routeproc_lptr); i++)
			{
			to_redist_info = (IpT_Redist_Info *) op_prg_list_access (redist_routeproc_lptr, i);
			to_routeproc_handle = Ip_Cmn_Rte_Table_Pro_Handle_From_Proto_Id (to_redist_info->routeproc_id, cmn_rte_table);
			
			/* If the process has not been found (at time zero,	*/
			/* it may not have come up), move on to the next	*/
			/* one.												*/
			if (!op_pro_valid (to_routeproc_handle))
				continue;
				
			/* Make a copy of the passed in route table entry	*/
			/* to pass using redistribution.					*/
			route_copy_ptr = ip_cmn_rte_table_entry_copy (route_ptr);
			route_src_proto = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (route_ptr->route_src_proto);
			
			if (i >= non_withdraw_count)
				{
				/** The remaining entries in the list are		**/
				/** protocols who should receive a withdraw		**/
				/** message.									**/
				
				/* Set the redist type to be withdraw.			*/
				redist_type = IPC_REDIST_TYPE_WITHDRAW;
				
				/* Set the protocol of the route entry to the	*/
				/* removed protocol so that the receiving		*/
				/* protocol will know which protocol has		*/
				/* withdrawn it's route.						*/
				route_copy_ptr->route_src_proto = normalized_removed_proto;
				route_src_proto = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (removed_proto);
				}
		
#ifndef OPD_NO_DEBUG
			if (op_prg_odb_ltrace_active ("ip_redist"))
				{
				ip_cmn_rte_proto_name_print (src_proto_str, route_copy_ptr->route_src_proto);
				ip_cmn_rte_proto_name_print (dest_proto_str, to_redist_info->routeproc_id);
				ip_cmn_rte_table_dest_prefix_print (dest_str, route_ptr->dest_prefix);
			
				switch (redist_type)
					{
					case IPC_REDIST_TYPE_ADD:
						sprintf (type_str, "NEW ROUTE");
						break;
					case IPC_REDIST_TYPE_WITHDRAW:
						sprintf (type_str, "WITHDRAWAL");
						break;
					case IPC_REDIST_TYPE_UPDATE:
						sprintf (type_str, "UPDATE");
						break;
					case IPC_REDIST_TYPE_UPDATE_DIRECT:
						sprintf (type_str, "UPDATE");
						break;
					default:
						sprintf (type_str, "INVALID");
						break;
					}
			
				sprintf (trace_msg, "The following route is being redistributed into %s", dest_proto_str);
				sprintf (trace_msg2, "Dest: %s, Protocol: %s", dest_str, src_proto_str);
				sprintf (trace_msg3, "Next Hops: ");
				sprintf (trace_msg4, "Redistribution Message Type: %s", type_str);			
				for (j = 0; j < op_prg_list_size (route_ptr->next_hop_list); j++)
					{
					if (j > 0)
						strcat (trace_msg3, ", ");
					next_hop_ptr = (IpT_Next_Hop_Entry *) op_prg_list_access (route_ptr->next_hop_list, j);
					inet_address_print (next_hop_str, next_hop_ptr->next_hop);
					strcat (trace_msg3, next_hop_str);
					}
				op_prg_odb_print_major (trace_msg, trace_msg2, trace_msg3, trace_msg4, OPC_NIL);
				}
#endif
		
			/* Inject this route into the destination			*/
			/* routing process.									*/
			/* Don't redistribute this route if it is an IBGP	*/
			/* route and this protocol has not been configured	*/
			/* to redistribute IBGP routes.						*/
			if (!((route_src_proto == IPC_DYN_RTE_IBGP) && (to_redist_info->bgp_redist_type == IPC_REDIST_EBGP_ONLY)))
				ip_cmn_rte_table_rte_inject (redist_type, to_routeproc_handle, route_copy_ptr, 
					cmn_rte_table);
			}
		
		if (removed_proto != IpC_Dyn_Rte_Invalid)
			{
			/** We crated a separate redistribution list.  This	**/
			/** must be destroyed here.							**/
			
			prg_list_free (redist_routeproc_lptr);
			}
		}

	FOUT;
	}


static void
ip_cmn_rte_table_rte_inject (int redist_type, Prohandle proc_handle, IpT_Cmn_Rte_Table_Entry* route_ptr,
	IpT_Cmn_Rte_Table* route_table_ptr)
	{
	Ici*						ext_route_iciptr;
	IpT_Redist_Ici_Info*		redist_ici_info_ptr;

	/** This function is the interface between IP and other		**/
	/** routing protocols.  When a route from protocol A needs 	**/
	/** to be advertised to protocol B, that route will be		**/
	/** "injected" into protocol B via this function.  It		**/
	/** schedules process interrupts with protocol B and passes	**/
	/** the external route information to that protocol.		**/
	FIN (ip_cmn_rte_table_rte_inject (redist_type, proc_handle, new_entry, rte_table_ptr));
	
	/* Create an "ip_ext_route" ICI and set its					*/
	/* attributes with the particulars of the external			*/
	/* route being injected.									*/
	ext_route_iciptr = op_ici_create ("ip_ext_route");
	
	/* Allocate memory for the information which will be sent	*/
	/* via the ICI.												*/
	redist_ici_info_ptr = (IpT_Redist_Ici_Info *) op_prg_mem_alloc (sizeof (IpT_Redist_Ici_Info));
	
	/* Set the values for the elements of the redist_ici_info	*/
	/* structure.												*/
	redist_ici_info_ptr->rte_table_entry = route_ptr;
	redist_ici_info_ptr->redist_type = redist_type;
	redist_ici_info_ptr->route_table_ptr = route_table_ptr;

	/* Set the external metric element.							*/
	if (IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (route_ptr->route_src_proto) == IPC_DYN_RTE_OSPF)
		redist_ici_info_ptr->ext_metric_type = IPC_EXT_RTE_METRIC_TYPE_OSPF_DEFAULT;
	else
		redist_ici_info_ptr->ext_metric_type = IPC_EXT_RTE_METRIC_TYPE_UNUSED;
	
	/* Set the fields in the ici								*/
	op_ici_attr_set (ext_route_iciptr, "redist info", redist_ici_info_ptr);
		
	/* Install the ICI.											*/
	op_ici_install (ext_route_iciptr);

	/* Schedule the interrupt with the destination protocol.	*/
	/*op_intrpt_force_remote (IPC_EXT_RTE_REMOTE_INTRPT_CODE, mod_objid);*/
	op_intrpt_schedule_process (proc_handle, op_sim_time (), IPC_EXT_RTE_REMOTE_INTRPT_CODE);

	/* Un-install the ICI.										*/
	op_ici_install (OPC_NIL);
	
	FOUT;
	}


static int
ip_cmn_rte_table_prune_backups_for_redistribution (IpT_Cmn_Rte_Table *cmn_rte_table, IpT_Cmn_Rte_Table_Entry *route_ptr,
	IpT_Rte_Proc_Id dest_routeproc_id, IpT_Redist_Matrix_Entry *route_matrix_entry, char* message_str)
	{
	List*						backup_list;
	IpT_Backup_Entry*			backup_entry_ptr;
	IpT_Redist_Matrix_Entry *	from_redist_matrix_entry;
	IpT_Redist_Info *			to_redist_info;
	IpT_Rte_Proc_Id				src_routeproc_id, normalized_src_proto;
	int							num_backups, orig_list_size;
	int							i, j;
	char						temp_str [512], proto_str [512];
	int							num_protocols = 0;
	Boolean						found;
	
	/** This function examines the backup list of the route	**/
	/** table entry and removes any element who's protocol	**/
	/** does not redistribute into routeproc_id.  It will	**/
	/** then return the number of entries which remain in	**/
	/** the backup list.				   					**/
	FIN (ip_cmn_rte_table_prune_backups_for_redistribution (cmn_rte_table, route_ptr, ...));
	
	/* If we are debugging, and are redistributing directly	*/
	/* connected routes to the destination protocol, add	*/
	/* Directly connected to the message_str.				*/
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_redist"))
		{
		sprintf (message_str, "PROTOCOLS: ");
		
		if (route_matrix_entry != OPC_NIL)
			{
			for (i = 0; i < prg_list_size (route_matrix_entry->redist_routeproc_lptr); i++)
				{
				to_redist_info = (IpT_Redist_Info *) op_prg_list_access (route_matrix_entry->redist_routeproc_lptr, i);
				if (to_redist_info->routeproc_id == dest_routeproc_id)
					{
					ip_cmn_rte_proto_name_print (proto_str, route_ptr->route_src_proto);
					strcat (message_str, proto_str);
					num_protocols = num_protocols + 1;
					break;
					}
				}
			}
		}
#endif
	
	/* Obtain a handle on the backup list for this route	*/
	backup_list = route_ptr->backup_list;
	
	/* If the list does not exist, or is empty, return 0	*/
	if ((backup_list == OPC_NIL) || (op_prg_list_size (backup_list) == 0))
		FRET (0);
	
	orig_list_size = op_prg_list_size (backup_list);
	num_backups = orig_list_size;
	
	for (i = 0; i < orig_list_size; i++)
		{
		/* Initialize the found flag to false.					*/
		found = OPC_FALSE;
		
		/* Get a handle on this backup entry.					*/
		backup_entry_ptr = (IpT_Backup_Entry *) op_prg_list_remove (backup_list, OPC_LISTPOS_HEAD);
		
		/* NOTE: This is already the normalized route proc ID.	*/
		/* When the copy of the route ptr is made, it sets the	*/
		/* routing protocols to be the normalized versions.		*/
		src_routeproc_id = backup_entry_ptr->route_proto;
		
		/* Some routing protocols need to be changed into their	*/
		/* generic form.  For example, External EIGRP is the	*/
		/* specific form of EIGRP.  Transform this entry's		*/
		/* protocol into the normalized (generic) version.		*/
		normalized_src_proto = Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (src_routeproc_id);
	
		/* Depending on the protocol that inserted the route,	*/
		/* redistribute it to other protocols.					*/
		/* Only redistribute this route to protocols that have	*/
		/* stated a desire to redistribute this protocol.  Use	*/
		/* the redistribution matrix.							*/
		from_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_search (cmn_rte_table, normalized_src_proto);
		
		/* If this protocol is not redistributing to anyone, 	*/
		/* then it can be ignored, and left removed from the	*/
		/* backup list.											*/
		if (from_redist_matrix_entry == OPC_NIL)
			{
			/* Free the memory for this entry.					*/
			prg_mem_free (backup_entry_ptr);
			
			/* Decrement the number of backups in the list.		*/
			num_backups = num_backups - 1;
			continue;
			}
		
		/* At this point, the source protocol is redistributing	*/
		/* to some protocols.  We must now check if it 			*/
		/* redistributing to the destination protocol we are	*/
		/* intereseted in.										*/
		
		/* Loop through all the destination protocols.			*/
		for (j = 0; j < prg_list_size (from_redist_matrix_entry->redist_routeproc_lptr); j++)
			{
			/* Get a handle on this redistribution information	*/
			to_redist_info = (IpT_Redist_Info *) op_prg_list_access (from_redist_matrix_entry->redist_routeproc_lptr, j);
			
			/* If the backup entry protocol is IBGP, and this	*/
			/* protocol is not accepting IBGP routes, then skip	*/
			/* this entry.										*/
			if ((IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (src_routeproc_id) == IPC_DYN_RTE_IBGP) &&
				(to_redist_info->bgp_redist_type == IPC_REDIST_EBGP_ONLY))
				continue;
			
			if (to_redist_info->routeproc_id == dest_routeproc_id)
				{
				/* Insert the backup entry back into the list	*/
				op_prg_list_insert (backup_list, backup_entry_ptr, OPC_LISTPOS_TAIL);
				
				/* Make sure that the routing protocol which is	*/
				/* passed to the destination protocol for this	*/
				/* backup entry is the normalized version of	*/
				/* the source protocol.							*/
				backup_entry_ptr->route_proto = Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (backup_entry_ptr->route_proto);
				
#ifndef OPD_NO_DEBUG
				if (op_prg_odb_ltrace_active ("ip_redist"))
					{
					if (num_protocols > 0)
						{
						sprintf (temp_str, ", ");
						strcat (message_str, temp_str);
						}
					ip_cmn_rte_proto_name_print (proto_str, src_routeproc_id);
					strcat (message_str, proto_str);
					}
#endif
				found = OPC_TRUE;
				break;
				}
			}
		
		/* If there was no match found, then free the memory	*/
		/* and decrement the number of backups.					*/
		if (found == OPC_FALSE)
			{
			/* Free the memory for this entry.					*/
			prg_mem_free (backup_entry_ptr);
			
			/* Decrement the number of backups in the list.		*/
			num_backups = num_backups - 1;
			}
		}
	FRET (num_backups);
	}


static List *
ip_cmn_rte_table_redist_matrix_entries_combine (IpT_Redist_Matrix_Entry *in_table_redist_matrix_entry,
					IpT_Redist_Matrix_Entry *removed_redist_matrix_entry)
	{
	List *				redist_lptr = OPC_NIL;
	int					i, j;
	IpT_Redist_Info *	new_redist_info;
	IpT_Redist_Info *	old_redist_info;
	IpT_Redist_Info *	temp_redist_info;
	Boolean				can_be_ignored;
	
	/** This function takes two redistribution matrix entries:	**/
	/** One for the protocol which is currently in the IP route	**/
	/** table, and a second for the protocol which was 			**/
	/** previously in the IP route table.  Every protocol that	**/
	/** the old protocol redistributed to that the new protocol	**/
	/** does not redistribute to will be added to a list which	**/
	/** already contains all the protocols that the current		**/
	/** protocol does redistribute to.							**/
	
	FIN (ip_cmn_rte_table_redist_matrix_entries_combine (in_table_redist_matrix_entry, removed_redist_matrix_entry));
	
	/* Create the list which will store all the protocols that	*/
	/* need some form of redistribution.						*/
	redist_lptr = op_prg_list_create ();
	
	if (in_table_redist_matrix_entry != OPC_NIL)
		{
		/* Copy the current protocol's redist matrix elements to 	*/
		/* the new list.											*/
		prg_list_elems_copy (in_table_redist_matrix_entry->redist_routeproc_lptr, redist_lptr);
		}
	
	/* If the previous routing protocol did not redistriubte	*/
	/* to anyone, than just return the new protocol's redist	*/
	/* list.													*/
	if (removed_redist_matrix_entry == OPC_NIL)
		FRET (redist_lptr);
	
	/** Now all the processes which will be withdrawn (i.e.		**/
	/** processes which the old protocol redistributed to but	**/
	/** the new protocol does not) need to be added to the new	**/
	/** list.													**/
	
	/* Loop through every element in the old protocol's redist	*/
	/* matrix.  If it esists in the new protocols redist matrix	*/
	/* then ignore it, otherwise add it to the end of the new	*/
	/* redist list.												*/
	for (i = 0; i < op_prg_list_size (removed_redist_matrix_entry->redist_routeproc_lptr); i++)
		{
		/* Intialize the can be ignored flag to false.			*/
		can_be_ignored = OPC_FALSE;
		
		/* Get a handle on the ith redist info object.			*/
		old_redist_info = (IpT_Redist_Info *) op_prg_list_access (removed_redist_matrix_entry->redist_routeproc_lptr, i);
		
		/* Loop through the new protocols redist matrix to see	*/
		/* if this routeproc is already being redistributed.	*/
		for (j = 0; j < op_prg_list_size (redist_lptr); j++)
			{
			/* Get a handle on the jth redist info object.		*/
			new_redist_info = (IpT_Redist_Info *) op_prg_list_access (redist_lptr, j);
			
			/* If they are equal, than the new protocol is		*/
			/* redistributing to the same process that the old	*/
			/* protocol redistributed to.  This process does	*/
			/* not need to be added to the new redist list and	*/
			/* can be ignored.									*/
			if (old_redist_info->routeproc_id == new_redist_info->routeproc_id)
				{
				can_be_ignored = OPC_TRUE;
				break;
				}
			}

		if (!can_be_ignored)
			{
			/** This protocol must be added to the new redist	**/
			/** list since it can't be ignored.					**/
			
			/* Create a temporary redist info structure to use	*/
			/* for determining which protocol this is.			*/
			temp_redist_info = ip_cmn_rte_table_redist_info_create (old_redist_info->routeproc_id, old_redist_info->redist_metric,
				old_redist_info->bgp_redist_type);

			op_prg_list_insert (redist_lptr, temp_redist_info, OPC_LISTPOS_TAIL);
			}
		}
	
	FRET (redist_lptr);
	}

IpT_Rte_Proc_Id
Ip_Cmn_Rte_Table_Custom_Rte_Protocol_Register (char* custom_rte_protocol_label_ptr)
	{
	int			custom_rte_protocol_list_size;
	int			i;
	static int	Custom_Rte_Protocol_Id = IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID;
	
	IpT_Custom_Rte_Protocol_Id_Table_Entry*		custom_rte_protocol_entry_ptr;

	/** Assigns a protocol id to the custom routing protocol and	**/
	/** returns the id. If this protocol is already assigned an id,	**/
	/** this function returns that id.								**/
	FIN (Ip_Cmn_Rte_Table_Custom_Rte_Protocol_Register (custom_rte_protocol_label_ptr));
	
	/* Create the list which maintains the custom routing protocol	*/
	/* label and its identifier.									*/
	if (Custom_Rte_Protocol_Id_Table == OPC_NIL)
		{
		Custom_Rte_Protocol_Id_Table = op_prg_list_create ();
		}
	
	/** Traverse through the table to check if the custom routing	**/
	/** protocol is already assigned an id.							**/
	
	/* Determine the size of the table.	*/
	custom_rte_protocol_list_size = op_prg_list_size (Custom_Rte_Protocol_Id_Table);
	
	for (i = 0; i < custom_rte_protocol_list_size; i++)
		{
		/* Obtain the i_th entry from the table.	*/
		custom_rte_protocol_entry_ptr = (IpT_Custom_Rte_Protocol_Id_Table_Entry *)
			op_prg_list_access (Custom_Rte_Protocol_Id_Table, i);
	
		/* Check if this is the entry that matches the given protocol label.	*/
		if (strcmp (custom_rte_protocol_entry_ptr->custom_rte_protocol_label_ptr, custom_rte_protocol_label_ptr) == 0)
			{
			/* Return the id assigned to this protocol label.	*/
			FRET (custom_rte_protocol_entry_ptr->custom_rte_protocol_id);
			}
		}
	
	/** The protocol is not assigned an id yet. Create an entry for this	**/
	/** protocol and assign a unique id for it.								**/

	/* Create a table entry.	*/
	custom_rte_protocol_entry_ptr = (IpT_Custom_Rte_Protocol_Id_Table_Entry *)
		op_prg_mem_alloc (sizeof (IpT_Custom_Rte_Protocol_Id_Table_Entry));
	
	/* Check if memory has been allocated. */ 
	if (custom_rte_protocol_entry_ptr == OPC_NIL)
		{
		/* Report an error message and terminate the simulation	*/
		op_sim_end ("Error in IP common route table support code: ",
			"Could not allocate memory for IpT_Custom_Rte_Protocol_Id_Table_Entry data structure.",
			OPC_NIL, OPC_NIL);
		}

	/* Allocate memory for the protocol label.	*/
	custom_rte_protocol_entry_ptr->custom_rte_protocol_label_ptr = (char *)
		op_prg_mem_alloc ((strlen (custom_rte_protocol_label_ptr) + 1) * sizeof (char));

	/* Check if memory has been allocated. */ 
	if (custom_rte_protocol_entry_ptr->custom_rte_protocol_label_ptr == OPC_NIL)
		{
		/* Report an error message and terminate the simulation	*/
		op_sim_end ("Error in IP common route table support code: ",
			"Could not allocate memory for custom routing protocol label field.", OPC_NIL, OPC_NIL);
		}
	
	/* Set the protocol label field of this entry.	*/
	strcpy (custom_rte_protocol_entry_ptr->custom_rte_protocol_label_ptr, custom_rte_protocol_label_ptr);
	
	/* Assign a	unique protocol id for this protocol.	*/
	custom_rte_protocol_entry_ptr->custom_rte_protocol_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (Custom_Rte_Protocol_Id, IPC_NO_MULTIPLE_PROC);

	/* Insert this entry in the table.	*/
	op_prg_list_insert (Custom_Rte_Protocol_Id_Table, custom_rte_protocol_entry_ptr, OPC_LISTPOS_TAIL);

	/* Increment the custom routing protocol id value for new assignments.	*/ 
	Custom_Rte_Protocol_Id++;
	
	/* Return the id assigned to this protocol.	*/	
	FRET (custom_rte_protocol_entry_ptr->custom_rte_protocol_id);	
	}

IpT_Rte_Proc_Id
ip_cmn_rte_table_custom_rte_protocol_id_get (char* custom_rte_protocol_label_ptr)
	{
	IpT_Custom_Rte_Protocol_Id_Table_Entry		*custom_rte_protocol_entry_ptr;
	int											custom_rte_protocol_list_size;
	int											i;

	/** For the given protocol label returns the protocol id.	**/
	/** If the label is not found, returns IpC_Rte_None.					**/
	FIN (ip_cmn_rte_table_custom_rte_protocol_id_get (custom_rte_protocol_label_ptr));

	/** Traverse through the table to locate the entry for	**/
	/** the given custom routing protocol label.			**/

	/* Determine the size of the table.	*/
	custom_rte_protocol_list_size = op_prg_list_size (Custom_Rte_Protocol_Id_Table);

	for (i=0; i < custom_rte_protocol_list_size; i++)
		{
		/* Obtain the ith entry from the table.	*/
		custom_rte_protocol_entry_ptr = (IpT_Custom_Rte_Protocol_Id_Table_Entry *)
			op_prg_list_access (Custom_Rte_Protocol_Id_Table, i);

		/* Check if this entry matches the given protocol label.	*/
		if (strcmp (custom_rte_protocol_entry_ptr->custom_rte_protocol_label_ptr, custom_rte_protocol_label_ptr) == 0)
			{
			/* We found the entry for the given custom routing	*/
			/* protocol label. Return the protocol id assigned	*/
			/* to it.											*/
			FRET (custom_rte_protocol_entry_ptr->custom_rte_protocol_id);
			}
		}
	
	/* No entry is found for the given protocol label. Return IpC_Rte_None.	*/
	FRET (IpC_Rte_None);
	}

const char*
ip_cmn_rte_table_custom_rte_protocol_label_get (IpT_Rte_Proc_Id custom_rte_protocol_id)
	{
	IpT_Custom_Rte_Protocol_Id_Table_Entry		*custom_rte_protocol_entry_ptr;
	int											custom_rte_protocol_list_size;
	int											i;

	/** For the given custom routing protocol id, returns the	**/
	/** custom routing protocol label. If the protocol id is	**/
	/** not found, return OPC_NIL. Note that the return value 	**/
	/** is made const so that the value can	not be modified by	**/
	/** the client side of this package.						**/
	FIN (ip_cmn_rte_table_custom_rte_protocol_label_get (custom_rte_protocol_id));

	/** Traverse through the list to locate the entry for	**/
	/** the given custom routing protocol id.				**/
	  
	/* Determine the size of the table.	*/
	custom_rte_protocol_list_size = op_prg_list_size (Custom_Rte_Protocol_Id_Table);

	for (i = 0; i < custom_rte_protocol_list_size; i++)
		{
		/* Obtain the i_th entry from the table.	*/
		custom_rte_protocol_entry_ptr = (IpT_Custom_Rte_Protocol_Id_Table_Entry *)
			op_prg_list_access (Custom_Rte_Protocol_Id_Table, i);
	
		/* Check if this entry matches the given protocol id.	*/ 
		if (custom_rte_protocol_entry_ptr->custom_rte_protocol_id == custom_rte_protocol_id)
			{
			/* We found the entry for the given custom routing	*/
			/* protocol id. Return the protocol label assigned	*/
			/* to it.											*/
			FRET (custom_rte_protocol_entry_ptr->custom_rte_protocol_label_ptr);
			}
		}

	/* No custom routing protocol with the given id is found. Return OPC_NIL.*/
	FRET (OPC_NIL);
	}

char *
ip_cmn_rte_global_exp_file_create (void)
	{
	static double	last_time = -1.0;
	static int		index = 1;
	static char*	dir_name = OPC_NIL;
	char*	   	model_name;
	char		index_str [4];
	char		append_str [256];
	char		scenario_name [256];
	Boolean		dir_name_obtained;
	FILE*		file_ptr;
	
	/** This function maintains the current name of the IP Global Export file 	**/
	/** and creates a new file when an export for a new time is called			**/
	FIN (ip_global_rte_file_create (int index));
	
	/** "last_time" has been initialized to -1.0 so that this will always be TRUE the first call **/
	if (last_time < op_sim_time ())
		{
		/* Get the network model name from the net_name simulation attribute */
		model_name = ip_net_name_sim_attr_get (OPC_TRUE);

		/* This indicates a new file needs to be created for an export at a different time */
		if (model_name != OPC_NIL)
			{
			/* Get a string representation of the index */
			sprintf (index_str, "%d", index);
		
			/* create appendix for the scenario name */
			sprintf (append_str, "-ip_route_tables_%s.gdf", index_str);
		
			/*  Add "ip_routes.gdf" to the file name 					*/
			strcpy (scenario_name, model_name);
			strcat (scenario_name, append_str);

			/* Free the memory associated with the model_name */
			op_prg_mem_free (model_name);
			
			/* Only allocate space for the string once */
			if (dir_name == OPC_NIL)
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
			
			/* Create the new file and add the header information */
			file_ptr = fopen (dir_name, "w");
		   
			fprintf (file_ptr, "# This is as export of the IP Common Route Tables \n");
		    fprintf (file_ptr, "# for all of the routers in the simulation at time (%.2fs) \n\n", op_sim_time ());
			fprintf (file_ptr, "# The IP Common Route Table is used by IP for all packet \n");
			fprintf (file_ptr, "# forwarding decisions. \n");
			fprintf (file_ptr, "# NOTE: Each routing protocol maintains its own route table, \n");
			fprintf (file_ptr, "# however those entries are not used for forwarding unless they \n");
			fprintf (file_ptr, "# are accepted by the IP Common Route Table (IP Forwarding Table).\n");
			fprintf (file_ptr, "# NOTE: Acceptance in IP Common Route Table is based on the\n");
			fprintf (file_ptr, "# Administrative Weight configured under 'IP Routing Parameters' \n");
			fprintf (file_ptr, "# for each individual routing protocol. \n\n\n\n");
			
			fclose (file_ptr);
			
			/* Set the last_time this function was called and increase the index for the next file created */
			last_time = op_sim_time ();
			index++;
		
			FRET (dir_name);
			}
		else
			{
			/* Report an error message and terminate the simulation	*/
			op_sim_end ("Error in IP common route table support code: ", "Could not obtain the net_name", OPC_NIL, OPC_NIL);
			}
		}
	else 
		{
		/* This indicates that the a new file doesn't need to be created, just return the current "dir_name" */
		FRET (dir_name);
		}
	/* Return OPC_NIL to avoid a compiler warning			*/
	FRET (OPC_NIL);
	}

static void
ip_cmn_rte_table_dest_src_table_gbl_variables_init ()
	{
	int 		num_addrs;
	char		num_addrs_str [32];
	Boolean		print_log;

	FIN (ip_cmn_rte_table_dest_src_table_gbl_variables_init ());
	
	/* Get a string representation of the number of addreses. The length of this	*/
	/* string is the maximum length of a fast address string.						*/
	num_addrs = ip_rtab_num_addrs_registered ();
	ip_cmn_rte_fast_addr_to_hex_str (num_addrs_str, num_addrs);

	/* The maximum key length is 2 times the length of this string plus 1 (for the :)*/
	IpC_Cmn_Rte_Table_Key_Length = 2 * strlen (num_addrs_str) + 1;

	/* Check if a simulation attribute named "IP Source Dest Pairs" exists. If it	*/
	/* does use its value as the size of the hash table. Otherwise make an educated	*/
	/* guess.																		*/
	if (op_ima_sim_attr_exists ("IP Source Dest Pairs"))
		{
		op_ima_sim_attr_get (OPC_IMA_INTEGER, "IP Source Dest Pairs", &IpC_Cmn_Rte_Table_Hash_Size);
		}
	else
		{
		/* Estimate the size of the dest src hash table. The hash table will have an	*/
		/* entry for each src dest addr pair. The table size is estimated as follows	*/
		/* num_entries = full mesh between all host nodes within the network + number of*/
		/* demands connected to gateway nodes + number of bgp neighbors in the network	*/
		/* This is an upper limit. Also it is unlikely that all this traffic will flow	*/
		/* through a single router. So to conserve memory, the hash table size is set to*/
		/* 1/4th of this value.															*/
		IpC_Cmn_Rte_Table_Hash_Size =
			((ip_num_host_nodes * (ip_num_host_nodes - 1)) + ip_num_gateway_demands + ip_num_bgp_neighbors) / 4;
		}

	/* Sanity check. If the hash table size we came up with is 0, Make it 1.			*/
	if (0 == IpC_Cmn_Rte_Table_Hash_Size)
		{
		IpC_Cmn_Rte_Table_Hash_Size = 1;
		}

	/* At the end of the simulation we will be in a better position to know a more		*/
	/* optimal value for this attribute. Schedule a call to write a log message with	*/
	/* this information unless it was explicitly disabled by the user.					*/

	/* Check whether the user has configured the 'IP Source Dest Pairs Log' env.		*/
	/* attribute. By default, the log message must be printed.							*/
	print_log = OPC_TRUE;
	op_ima_sim_attr_get (OPC_IMA_TOGGLE, "IP Source Dest Pairs Log", &print_log);

	/* Unless the user has disabled printing of the log message, schedule an interrupt	*/
	/* for end of sim.																	*/
	if (print_log)
		{
		/* Schedule a call to print out the optimal values of the hash size at the end	*/
		/* of the simualation.															*/
		op_intrpt_schedule_call (OPC_INTRPT_SCHED_CALL_ENDSIM, 0,
			ip_cmn_route_table_optimal_dest_src_values_print, OPC_NIL);
		}

	FOUT;
	}

static void
ip_cmn_route_table_optimal_dest_src_values_print (void* PRG_ARG_UNUSED (state_ptr), int PRG_ARG_UNUSED (code))
	{
	List				proc_record_handle_list;
	int					max_hash_table_size = 0;
	int					num_hash_tables = 0;
	int					i, num_gateway_nodes;
	IpT_Cmn_Rte_Table*	ith_rte_table_ptr;
	OmsT_Pr_Handle		ith_process_record_handle;

	/** If the size of the hash tables used by the common route table was		**/
	/** determined automatically, it is possible that the estimate was wrong.	**/
	/** Now that the the simulation is over, we are in a position to estimate	**/
	/** more optimal values for this. Write a log message informing the user	**/
	/** about the optimal value.												**/

	FIN (ip_cmn_route_table_optimal_dest_src_values_print (state_ptr, code));
	
	/* Discover all gateway nodes in the network.								*/
	op_prg_list_init (&proc_record_handle_list);
	oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list,
		"protocol",		OMSC_PR_STRING,	"ip",
		"gateway node",	OMSC_PR_STRING,	"gateway",
		OPC_NIL);

	/* Get the number of gateway nodes.											*/
	num_gateway_nodes = op_prg_list_size (&proc_record_handle_list);

	/* Loop through the list of gateway nodes.									*/
	for (i = 0; i < num_gateway_nodes; i++)
		{
		/* Get the ith process record handle.									*/
		ith_process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove
			(&proc_record_handle_list, OPC_LISTPOS_HEAD);

		/* Access the route table of this node.									*/
		oms_pr_attr_get (ith_process_record_handle, "ip route table", OMSC_PR_POINTER, &ith_rte_table_ptr);

		/* If this node does not use destination load balancing ignore it.		*/
		if (ith_rte_table_ptr->load_type != IpC_Rte_Table_Load_Dest)
			{
			continue;
			}

		/* Increment the number of hash tables we have encountered.				*/
		++num_hash_tables;

		/* Update the maximum hash table size if necessary.						*/
		if (ith_rte_table_ptr->dest_src_table_size > max_hash_table_size)
			{
			max_hash_table_size = ith_rte_table_ptr->dest_src_table_size;
			}
		}

	/* Call the function that will actually write the sim log entry.			*/
	/* If the number of routing nodes is less than 5, do not write the log		*/
	/* message.																	*/
	if (num_hash_tables >= 5)
		{
		ipnl_cmn_rte_optimal_hash_size_values_log (IpC_Cmn_Rte_Table_Hash_Size, max_hash_table_size);
		}

	FOUT;
	}


int
ip_cmn_rte_table_entry_least_cost_get (const IpT_Cmn_Rte_Table_Entry *rte_entry_ptr)
	{
	/** This function will return the least cost	**/
	/** to the reach the destination.				**/
	IpT_Next_Hop_Entry*			next_hop_ptr;
	int							least_cost, count_i, num_next_hops;
	
	FIN (ip_cmn_rte_table_entry_least_cost_get (rte_entry_ptr));
	
	/* If the entry is NIL, return infinity			*/
	if (rte_entry_ptr == OPC_NIL)
		FRET (OPC_INT_INFINITY);
	
	/* Initialize the cost to infinity				*/
	least_cost = OPC_INT_INFINITY;

	/* Loop through the next hops and return the	*/
	/* least cost									*/
	num_next_hops = op_prg_list_size (rte_entry_ptr->next_hop_list);

	for (count_i = 0; count_i < num_next_hops; count_i++)
		{
		next_hop_ptr = (IpT_Next_Hop_Entry *)
			op_prg_list_access (rte_entry_ptr->next_hop_list, count_i);
		/* If the next_hop doesn't exist, skip 		*/
		if (next_hop_ptr == OPC_NIL)
			continue;
		/* If the cost of this next hop is less than*/
		/* the best cost we have found so far, use	*/
		/* this cost								*/
		if (next_hop_ptr->route_metric < least_cost)
			{
			least_cost = next_hop_ptr->route_metric;
			}
		}
		
	FRET (least_cost);
	}


/***** Publicly available Redistribution and Process information functions	*****/

void
Ip_Cmn_Rte_Table_Install_Routing_Proc (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id routeproc_id, Prohandle routeproc_handle)
	
	{
	/** This function tries to abstract the creation	**/
	/** of the IpT_Route_Proc_Info object.  The process	**/
	/** name and handle are passed in as arguments and	**/
	/** an IpT_Route_Proc_Info object is created and	**/
	/** added to the list of routing processes which	**/
	/** is located in the ip_route_table.				**/
	
	IpT_Route_Proc_Info	*				temp_routeproc_info = OPC_NIL;
	IpT_Route_Proc_Info *				this_routeproc_info = OPC_NIL;
	int									i;
	
	FIN (Ip_Cmn_Rte_Table_Install_Routing_Proc (ip_route_table, routeproc_id, routeproc_handle));
	
	/* Create the IpT_Route_Proc_Info object.  Check to	*/
	/* make sure that there was enough memory for the	*/
	/* object to be created.							*/
	temp_routeproc_info = ip_cmn_rte_table_route_proc_info_create (routeproc_id, routeproc_handle);
	if (temp_routeproc_info == OPC_NIL)
		FOUT;
	
	/* Insert this element in the vector.  The place it	*/
	/* is placed should be sorted.						*/
	for (i = 0; i < prg_vector_size (ip_route_table->routeproc_vptr); i++)
		{
		this_routeproc_info = (IpT_Route_Proc_Info *) prg_vector_access (ip_route_table->routeproc_vptr, i);
		if (this_routeproc_info->routeproc_id > routeproc_id)
			{
			/* This is where we want to insert this		*/
			/* element in the vector.					*/
			break;
			}
		}
	
	/* Insert this value into the position found at i.	*/
	/* If there was no position found, this value is now*/
	/* the largest in the vector, so just add it to the	*/
	/* end.												*/
	prg_vector_insert (ip_route_table->routeproc_vptr, temp_routeproc_info, i);
	
	FOUT;
	}


void
Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id dest_routeproc_id,
											  IpT_Rte_Proc_Id src_routeproc_id, void *redist_metric, int bgp_redist_type)
	
	{
	/** This function tries to abstract the creation	**/
	/** of the IpT_Redist_Matrix_Entry object.  The		**/
	/** information necessary for the entry is passed	**/
	/** along with a list of the names of all routing	**/
	/** processes this routing process will 			**/
	/** redistribute. What amounts to a reverse list	**/
	/** needs to be created.  Each entry in the			**/
	/** redistributed_prot_lptr should have a 			**/
	/** corresponding value in the redist_matrix_vptr.	**/
	/** Each one of those values should have the process**/
	/** specified by routeproc_id as an entry in it's	**/
	/** redist_routeproc_lptr.							**/
	
	IpT_Redist_Matrix_Entry	*			temp_redist_matrix_entry = OPC_NIL;
	IpT_Redist_Matrix_Entry *			this_redist_matrix_entry = OPC_NIL;
	int									j;
	IpT_Redist_Info *					temp_redist_info_ptr = OPC_NIL;
	char								src_proto_str [64], dest_proto_str [64];
	char								trace_msg [512];
	
	FIN (Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (ip_route_table, dest_routeproc_id, src_routeproc_id, redist_metric, bgp_redist_type));
	
	if (redist_metric == OPC_NIL)
		FOUT;
	
	/* Create an IpT_Redist_Info object using the	*/
	/* source protocol.  This will be inserted into	*/
	/* the redistribution matrix.					*/
	temp_redist_info_ptr = ip_cmn_rte_table_redist_info_create (src_routeproc_id, redist_metric, bgp_redist_type);
	if (temp_redist_info_ptr == OPC_NIL)
		FOUT;
		
#ifndef OPD_NO_DEBUG
	if (op_prg_odb_ltrace_active ("ip_redist"))
		{
		op_prg_odb_print_major ("Configuring Redistribution", OPC_NIL);
		
		if (ip_cmn_rte_table_is_vrf (ip_route_table))
			op_prg_odb_print_major ("VRF Table: ", ip_vrf_table_name_get (ip_route_table->vrf_table_ptr), OPC_NIL);

		ip_cmn_rte_proto_name_print (dest_proto_str, dest_routeproc_id);
		ip_cmn_rte_proto_name_print (src_proto_str, src_routeproc_id);

		sprintf (trace_msg, "Source Protocol: %s, Destination Protocol: %s, BGP_REDIST_TYPE: %d",
		src_proto_str, dest_proto_str, bgp_redist_type);
		op_prg_odb_print_minor (trace_msg, OPC_NIL);
		}
#endif
		
	/* Search through the redist_matrix using the	*/
	/* redist_info variable's routeproc_id as a key	*/
	/* If it is not found, then create a new		*/
	/* redist_matrix entry.							*/
	temp_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_search (ip_route_table, src_routeproc_id);
	if (temp_redist_matrix_entry == OPC_NIL)
		{
		temp_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_create (src_routeproc_id);
		if (temp_redist_matrix_entry == OPC_NIL)
			FOUT;
			
		/* Install the newly created matrix entry	*/
		/* into the vector.							*/
		for (j = 0; j < prg_vector_size (ip_route_table->redist_matrix_vptr); j++)
			{
			this_redist_matrix_entry = (IpT_Redist_Matrix_Entry *) prg_vector_access (ip_route_table->redist_matrix_vptr, j);
			if (this_redist_matrix_entry->routeproc_id > temp_redist_matrix_entry->routeproc_id)
				{
				break;
				}
			}
			
		/* Insert the entry either at the end, or	*/
		/* if the loop was terminated early, at the	*/
		/* position determined.						*/
		prg_vector_insert (ip_route_table->redist_matrix_vptr, temp_redist_matrix_entry, j);			
		}
		
	/* Change the routeproc_id of the redist_info	*/
	/* variable to the value of the routeproc_id	*/
	/* which was passed in to this function.  This	*/
	/* is because as values are being read from the	*/
	/* attribute parsing, it is stored as a list of	*/
	/* protocols that routeproc_id will redistribute*/
	/* For ease, we want to store as a list of 		*/
	/* protocols that are being redistributed to.	*/
	/* This is essentially a reverse list.			*/
	temp_redist_info_ptr->routeproc_id = dest_routeproc_id;
		
	/* Install this new route_proc_info into the	*/
	/* list of protocols that THIS redist_matrix	*/
	/* entry is redistributing to.					*/
	op_prg_list_insert (temp_redist_matrix_entry->redist_routeproc_lptr, temp_redist_info_ptr, OPC_LISTPOS_TAIL);
	
	FOUT;
	}


Prohandle
Ip_Cmn_Rte_Table_Pro_Handle_From_Proto_Id (IpT_Rte_Proc_Id routeproc_id, IpT_Cmn_Rte_Table *ip_route_table)
	
	{
	/** This function takes a routin process's unique	**/
	/** name and searches through the list of routing	**/
	/** processes until it finds it.  If it finds it in	**/
	/** the list, then it returns it's corresponding	**/
	/** process handle.  Otherwise it returns NIL.		**/
	
	IpT_Route_Proc_Info		*temp_routeproc_info = OPC_NIL;
	Prohandle				invalid_prohandle = OPC_PRO_HANDLE_INVALID;
	
	FIN (Ip_Cmn_Rte_Table_Pro_Handle_From_Proto_Id (routeproc_id, ip_route_table));
	
	temp_routeproc_info = ip_cmn_rte_table_route_proc_info_search (ip_route_table, routeproc_id);
	
	if (temp_routeproc_info == OPC_NIL)
		/* Something saying that the process ID was 	*/
		/* not found.									*/
		{
		FRET (invalid_prohandle);
		}
	
	FRET (temp_routeproc_info->routeproc_handle);
	}


void *
Ip_Cmn_Rte_Table_Redist_Metric_Get (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id to_routeproc_id, IpT_Rte_Proc_Id from_routeproc_id)
	
	{
	/** This function searches through the redistribution	**/
	/** matrix for the occurence when from_routeproc_id		**/
	/** redistributes into to_routeproc_id.  If it does,	**/
	/** then it returns the redistribution metric.  If it	**/
	/** does not, then it will return NIL.					**/
	
	IpT_Redist_Matrix_Entry *			temp_redist_matrix_entry = OPC_NIL;
	IpT_Redist_Info *					temp_redist_info = OPC_NIL;
	
	FIN (ip_cmn_rte_table_redist_metric_get (ip_route_table, to_routeproc_id, from_routeproc_id));
	
	/* Find the correct redist_matrix_entry that corresponds	*/
	/* to the from_routeproc_id.								*/
	temp_redist_matrix_entry = ip_cmn_rte_table_redist_matrix_entry_search (ip_route_table, from_routeproc_id);
	if (temp_redist_matrix_entry == OPC_NIL)
		FRET (OPC_NIL);
	
	/* Find the correct redist_info entry inside the matrix		*/
	/* entry we just found that corresponds to the 				*/
	/* to_routeproc_id.										*/
	temp_redist_info = ip_cmn_rte_table_redist_info_search (temp_redist_matrix_entry, to_routeproc_id);
	if (temp_redist_info == OPC_NIL)
		FRET (OPC_NIL);
	
	/* Return the redistribution metric for the correct process	*/
	FRET (temp_redist_info->redist_metric);
	}


IpT_Rte_Proc_Id
Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (IpT_Rte_Proc_Id specific_routeproc_id)
	
	{
	/** This function takes a routing process ID with	**/
	/** corresponding to a specific routing protocol	**/
	/** (i.e. External EIGRP) and returns a routing		**/
	/** process ID with the generic form of the routing	**/
	/** protocol (i.e. EIGRP).  If the routing process	**/
	/** ID passed in has the generic form of the		**/
	/** routing protocol, then the same ID is returned	**/
	int					generic_protocol;
	int					specific_protocol;
	int					as_number;
	IpT_Rte_Proc_Id		generic_routeproc_id;
	
	FIN (Ip_Cmn_Rte_Table_Normalized_Route_Proc_Id (specific_routeproc_id));
	
	/* Seperate the routing process ID into the 		*/
	/* routing protocol and as number.					*/
	specific_protocol 	= IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (specific_routeproc_id);
	as_number			= IP_CMN_RTE_TABLE_ROUTEPROC_AS_NUMBER (specific_routeproc_id);
	
	if (specific_protocol >= IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID)
		generic_protocol = IpC_Dyn_Rte_Custom;
	else
		{
		switch (specific_protocol)
			{
			case (IpC_Dyn_Rte_Ext_Eigrp):
				generic_protocol = IpC_Dyn_Rte_Eigrp;
				break;
			case (IpC_Dyn_Rte_IBgp):
				generic_protocol = IpC_Dyn_Rte_Bgp;
				break;
			default:
				generic_protocol = specific_protocol;
				break;
			}
		}
	
	generic_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (generic_protocol, as_number);
	
	FRET (generic_routeproc_id);
	}


/***** Redistribution ODB message procedures						*****/
void
ip_cmn_rte_table_redist_proto_add_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
										   IpT_Address dest_addr, int dest_mask_length, IpT_Address next_hop, int metric)
	{
	char	dest_proto_str [64], src_proto_str [64];
	char	dest_str [IPC_ADDR_STR_LEN], next_hop_str [IPC_ADDR_STR_LEN];
	char	trace_msg [512], trace_msg2 [512];
	
	/** This function writes an ODB message for the case	**/
	/** when a routing protocol has accepted a redistributed**/
	/** route from another routing process.					**/
	
	FIN (ip_cmn_rte_table_redist_proto_add_message (dest_routeproc_id, src_routeproc_id, dest_addr, dest_mask, next_hop, metric));
	
	ip_cmn_rte_proto_name_print (dest_proto_str, dest_routeproc_id);
	ip_cmn_rte_proto_name_print (src_proto_str, src_routeproc_id);
	ip_address_print (dest_str, dest_addr);
	ip_address_print (next_hop_str, next_hop);
			
	sprintf (trace_msg, "The following redistributed route is being added to the route table of %s", dest_proto_str);
	sprintf (trace_msg2, "Protocol: %s  Dest: %s/%d  Next Hop: %s  Metric: %d", src_proto_str, dest_str, dest_mask_length, next_hop_str, metric);
				
	op_prg_odb_print_major (trace_msg, trace_msg2, OPC_NIL);
	
	FOUT;
	}

void
ip_cmn_rte_table_redist_proto_withdraw_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
												IpT_Address dest_addr, int dest_mask_length, IpT_Address next_hop)
	{
	char	dest_proto_str [64], src_proto_str [64];
	char	dest_str [IPC_ADDR_STR_LEN], next_hop_str [IPC_ADDR_STR_LEN];
	char	trace_msg [512], trace_msg2 [512];
	
	/** This function writes an ODB message for the case	**/
	/** when a routing protocol has accepted a redistributed**/
	/** route from another protocol that now needs to be	**/
	/** withdrawn.											**/
	
	FIN (ip_cmn_rte_table_redist_proto_withdraw_message (dest_routeproc_id, src_routeproc_id, dest_addr, dest_mask, next_hop));
	
	ip_cmn_rte_proto_name_print (dest_proto_str, dest_routeproc_id);
	ip_cmn_rte_proto_name_print (src_proto_str, src_routeproc_id);
	ip_address_print (dest_str, dest_addr);
	ip_address_print (next_hop_str, next_hop);
			
	sprintf (trace_msg, "The following redistributed route is being withdrawn from the route table of %s", dest_proto_str);
	sprintf (trace_msg2, "Protocol: %s  Dest: %s/%d  Next Hop: %s", src_proto_str, dest_str, dest_mask_length, next_hop_str);
				
	op_prg_odb_print_major (trace_msg, trace_msg2, OPC_NIL);
	
	FOUT;
	}

void
ip_cmn_rte_table_redist_proto_update_message (IpT_Rte_Proc_Id dest_routeproc_id, IpT_Rte_Proc_Id src_routeproc_id,
											  IpT_Address dest_addr, int dest_mask_length, IpT_Address next_hop, int metric)
	{
	char						dest_proto_str [64], src_proto_str [64];
	char						dest_str [IPC_ADDR_STR_LEN], next_hop_str [IPC_ADDR_STR_LEN];
	char						trace_msg [512], trace_msg2 [512], trace_msg3 [512];
	
	/** This function writes an ODB message for the case	**/
	/** when a routing protocol has accepted an update to	**/
	/** a redistributed route.								**/
	
	FIN (ip_cmn_rte_table_redist_proto_update_message (dest_routeproc_id, src_routeproc_id, dest_addr, dest_mask, next_hop, metric));
	
	ip_cmn_rte_proto_name_print (dest_proto_str, dest_routeproc_id);
	ip_cmn_rte_proto_name_print (src_proto_str, src_routeproc_id);
	ip_address_print (dest_str, dest_addr);
	ip_address_print (next_hop_str, next_hop);
				
	sprintf (trace_msg, "The following redistributed route is being updated in the route table of %s", dest_proto_str);
	sprintf (trace_msg2, "New Information:");
	sprintf (trace_msg3, "Protocol: %s  Dest: %s/%d  Next Hop: %s  Metric: %d", src_proto_str, dest_str, dest_mask_length, next_hop_str, metric);
				
	op_prg_odb_print_major (trace_msg, trace_msg2, trace_msg3, OPC_NIL);
	
	FOUT;
	}


/***** Non public Redistribution and Process information functions	*****/

static IpT_Route_Proc_Info *
ip_cmn_rte_table_route_proc_info_create (IpT_Rte_Proc_Id routeproc_id, Prohandle routeproc_handle)
	
	{
	/** This function takes care of the memory creation	**/
	/** for the IpT_Route_Proc_Info data type.  The		**/
	/** unique process name obtained by calling 		**/
	/** ip_cmn_rte_table_unique_route_proto_name and	**/
	/** the process's handle are passed in as arguements**/
	
	static IpT_Route_Proc_Info 		*temp_route_proc_info = OPC_NIL;
	
	FIN (ip_cmn_rte_table_route_proc_info_create (routeproc_id, routeproc_handle));
	
	/* Check to make sure that the process hanle for	*/
	/* this routing process is valid.  If it isn't,		*/
	/* then retrun NIL.									*/
	if (!op_pro_valid (routeproc_handle))
		FRET (OPC_NIL);
	
	/* Check to make sure that this a valid routing		*/
	/* process name.									*/
	if (routeproc_id == 0)
		FRET (OPC_NIL);
	
	/* Create memory for the new object.				*/
	temp_route_proc_info = (IpT_Route_Proc_Info *) prg_mem_alloc (sizeof (IpT_Route_Proc_Info));
	
	/* Make sure that the object was created.			*/
	if (temp_route_proc_info == OPC_NIL)
		FRET (OPC_NIL);
	
	temp_route_proc_info->routeproc_id = routeproc_id;
	temp_route_proc_info->routeproc_handle = routeproc_handle;
	
	FRET (temp_route_proc_info);
	}


static IpT_Redist_Info*
ip_cmn_rte_table_redist_info_create (IpT_Rte_Proc_Id routeproc_id, void *redist_metric, int bgp_redist_type)
	{
	/** This function takes a unique routing process ID	**/
	/** and it's corresponding redistribution metric	**/
	/** and creates and then returns a IpT_Redist_Info	**/
	/** object corresponding to these values.			**/
	
	static IpT_Redist_Info		*temp_redist_info = OPC_NIL;
	
	FIN (ip_cmn_rte_table_redist_info_create (routeproc_id, redist_metric, bgp_redist_type));
	
	/* Create memory for the new object.				*/
	temp_redist_info = (IpT_Redist_Info *) prg_mem_alloc (sizeof (IpT_Redist_Info));
	if (temp_redist_info == OPC_NIL)
		FRET (OPC_NIL);
	
	temp_redist_info->routeproc_id = routeproc_id;
	temp_redist_info->redist_metric = redist_metric;
	temp_redist_info->bgp_redist_type = bgp_redist_type;
	
	FRET (temp_redist_info);
	}
	
void
ip_cmn_rte_table_redist_ici_info_destroy (IpT_Redist_Ici_Info* redist_info_ptr)
	{
	/** This function frees the memory allocated to the	**/
	/** redist info structure and the route entry it	**/
	/** contains.										**/

	FIN (ip_cmn_rte_table_redist_info_destroy (redist_info_ptr));

	/* Free the memory allocated to the route entry first*/
	ip_cmn_rte_table_entry_free (redist_info_ptr->rte_table_entry, redist_info_ptr->route_table_ptr);

	/* Now free the memory allocated to the outer		*/
	/* structure.										*/
	op_prg_mem_free (redist_info_ptr);

	FOUT;
	}
	
static IpT_Redist_Matrix_Entry *
ip_cmn_rte_table_redist_matrix_entry_create (IpT_Rte_Proc_Id routeproc_id)
	
	{
	/** This function takes care of the memory creation		**/
	/** for the IpT_Redist_Matrix_Entry data type.  The		**/
	/** information for this routing process obtained		**/
	/** by calling ip_cmn_rte_table_route_proc_info_create	**/
	/** is passed in as an argument.  The list for this		**/
	/** type is also created here.							**/
	
	static IpT_Redist_Matrix_Entry			*temp_redist_matrix_entry = OPC_NIL;
	
	FIN (ip_cmn_rte_table_redist_matrix_entry_create (routeproc_info, redist_routeproc_lptr));
	
	/* Create memory for the new object.					*/
	temp_redist_matrix_entry = (IpT_Redist_Matrix_Entry *) prg_mem_alloc (sizeof (IpT_Redist_Matrix_Entry));
   
	/* Make sure that the object was created.				*/
	if (temp_redist_matrix_entry == OPC_NIL)
		FRET (OPC_NIL);
	
	temp_redist_matrix_entry->routeproc_id = routeproc_id;
	temp_redist_matrix_entry->redist_routeproc_lptr = OPC_NIL;
	
	/* Create the list of protocols that this protocol		*/
	/* will redistribute.									*/
	temp_redist_matrix_entry->redist_routeproc_lptr = op_prg_list_create ();
	if (temp_redist_matrix_entry->redist_routeproc_lptr == OPC_NIL)
		{
		op_prg_mem_free (temp_redist_matrix_entry);
		FRET (OPC_NIL);
		}
	
	FRET (temp_redist_matrix_entry);
	}


static IpT_Redist_Matrix_Entry *
ip_cmn_rte_table_redist_matrix_entry_search (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id routeproc_id)
	
	{
	/** This function takes a routing process specified by	**/
	/** routeproc_id and returns the corresponding entry	**/
	/** in the redistribution matrix if it exists.  If it	**/
	/** does not exist, it will return NIL.					**/
	/** This is instituted using a binary search.			**/
	
	int								floor, ceiling, middle;
	IpT_Redist_Matrix_Entry *		temp_redist_matrix_entry;
	
	FIN (ip_cmn_rte_table_redist_matrix_entry_search (ip_route_table, routeproc_id));

	/* Initialization of floor and ceiling.					*/
	floor = 0;
	ceiling = prg_vector_size (ip_route_table->redist_matrix_vptr) - 1;
							   
	while (floor <= ceiling)
	    {
		/* We are always examining the entry corresponding	*/
		/* to the value between floor and ceiling.			*/
		/* Assign middle to this value, and then get the	*/
		/* entry in the redist_matrix_vptr which corresponds*/
		/* to that value.									*/
	    middle = (floor + ceiling) / 2;
		temp_redist_matrix_entry = (IpT_Redist_Matrix_Entry *) prg_vector_access (ip_route_table->redist_matrix_vptr, middle);
		
		if (temp_redist_matrix_entry->routeproc_id == routeproc_id)
			{
			/* If the routeproc_id of this entry is the same	*/
			/* as the one we are looking for, then return this	*/
			/* value.											*/
			FRET (temp_redist_matrix_entry);
			}
		
	    if	(temp_redist_matrix_entry->routeproc_id < routeproc_id)
			{
			/* The value we are looking for is higher up in		*/
			/* the vector, so adjust the floor value.			*/
			floor = middle + 1;
			}
	    else
			{
			/* The value we are looking for is lower in the		*/
			/* vector, so adjust the ceiling value.				*/
			ceiling = middle - 1;
			}
		}
	
	
	/* The process we were looking for was not found.			*/
	FRET (OPC_NIL);
	}


static IpT_Redist_Info *
ip_cmn_rte_table_redist_info_search (IpT_Redist_Matrix_Entry *redist_matrix_entry, IpT_Rte_Proc_Id routeproc_id)
	
	{
	/** This function takes a redistribution matrix entry	**/
	/** and searches through this entry for a redist_info	**/
	/** object represented by the routeproc_id.				**/
	/** This is instituted using a sequential search.		**/
	
	int						i;
	IpT_Redist_Info	*		temp_redist_info = OPC_NIL;
	
	FIN (ip_cmn_rte_table_redist_info_search (redist_matrix_entry, routeproc_id));
	
	for (i = 0; i < op_prg_list_size (redist_matrix_entry->redist_routeproc_lptr); i ++)
		{
		temp_redist_info = (IpT_Redist_Info *) op_prg_list_access (redist_matrix_entry->redist_routeproc_lptr, i);
		if (temp_redist_info == OPC_NIL)
			continue;
		
		/* Check to see if this is the value that we are	*/
		/* looking for.  If it is, then return that value	*/
		/* otherwise keep searching.						*/
		if (temp_redist_info->routeproc_id == routeproc_id)
			FRET (temp_redist_info);
		}

	/* The process we are looking for is not found.			*/
	FRET (OPC_NIL);
	}


static IpT_Route_Proc_Info *
ip_cmn_rte_table_route_proc_info_search (IpT_Cmn_Rte_Table *ip_route_table, IpT_Rte_Proc_Id routeproc_id)
	
	{
	/** This function takes a routing process specified by	**/
	/** routeproc_id and returns the corresponding entry	**/
	/** in the list of routing processes running on this	**/
	/** node if it exists, and NIL if it does not.			**/
	/** This is instituted using a binary search.			**/
	
	int							floor, ceiling, middle;
	IpT_Route_Proc_Info *		temp_routeproc_info;
	
	FIN (ip_cmn_rte_table_route_proc_info_search (ip_route_table, routeproc_id));
	
	/* Initialization of floor and ceiling.					*/
	floor = 0;
	ceiling = prg_vector_size (ip_route_table->routeproc_vptr) - 1;
							   
	while (floor <= ceiling)
	    {
		/* We are always examining the entry corresponding	*/
		/* to the value between floor and ceiling.			*/
		/* Assign middle to this value, and then get the	*/
		/* entry in the redist_matrix_vptr which corresponds*/
		/* to that value.									*/
	    middle = (floor + ceiling) / 2;
		temp_routeproc_info = (IpT_Route_Proc_Info *) prg_vector_access (ip_route_table->routeproc_vptr, middle);
		
		if (temp_routeproc_info->routeproc_id == routeproc_id)
			{
			/* If the routeproc_id of this entry is the same	*/
			/* as the one we are looking for, then return this	*/
			/* value.											*/
			FRET (temp_routeproc_info);
			}
		
	    if	(temp_routeproc_info->routeproc_id < routeproc_id)
			{
			/* The value we are looking for is higher up in		*/
			/* the vector, so adjust the floor value.			*/
			floor = middle + 1;
			}
	    else
			{
			/* The value we are looking for is lower in the		*/
			/* vector, so adjust the ceiling value.				*/
			ceiling = middle - 1;
			}
		}

	/* The process we are looking for was not found.		*/
	FRET (OPC_NIL);
	}


Boolean
ip_cmn_rte_table_dir_conn_rte_entry_match (IpT_Cmn_Rte_Table_Entry* rte_entry_ptr, IpT_Rte_Map_Match_Info* match_info_ptr, 
								IpT_Acl_Table* PRG_ARG_UNUSED (as_path_table), IpT_Acl_Table* PRG_ARG_UNUSED (comm_table), 
								IpT_Acl_Table* PRG_ARG_UNUSED (acl_table), IpT_Acl_Table* PRG_ARG_UNUSED (prefix_table), IpT_Acl_Pre_Override* override)
	{
	IpT_Address			address;
	IpT_Address			subnet_mask;
	int					int_value, i;
	Boolean				is_match	= OPC_FALSE;
	IpT_Next_Hop_Entry*	next_hop_ptr = OPC_NIL;
	
	/* This function is used to provide match to a Directly Connected route table entry */
	FIN (ip_cmn_rte_table_dir_conn_rte_entry_match (<args>));

	/* Use the ith match condition to check for a match */
	switch (match_info_ptr->match_property)
		{
		case (IpC_Rte_Map_Match_Property_None):
			/* Nothing being compared, indicate match */
			is_match = OPC_TRUE;
			
			break;
		case (IpC_Rte_Map_Match_Property_IpAddress):
			/* Extract the address and subnet mask from the dest prefix. */
			address = ip_cmn_rte_table_dest_prefix_ipv4_addr_get (rte_entry_ptr->dest_prefix);
			subnet_mask = ip_cmn_rte_table_dest_prefix_ipv4_mask_get (rte_entry_ptr->dest_prefix);

			/* Call the function that will perform the match.			*/
			is_match = ip_rte_map_ip_address_match (address, subnet_mask, match_info_ptr, override);

			break;
		case (IpC_Rte_Map_Match_Property_Next_Hop):
			/* Use the address of the first next hop.					*/
			next_hop_ptr = (IpT_Next_Hop_Entry *)
				op_prg_list_access (rte_entry_ptr->next_hop_list, OPC_LISTPOS_HEAD);
			address = inet_ipv4_address_get (next_hop_ptr->next_hop);

			/* Call the function that will perform the match.			*/
			/* Subnet mask doesn't make sense over here. Just set it to	*/
			/* an invalid value.										*/
			is_match = ip_rte_map_ip_address_match (address, IPC_ADDR_INVALID, match_info_ptr, override);

			break;
	  	case (IpC_Rte_Map_Match_Property_Metric):
			/* We are matching based on the Metric, obtain the Metric of the route entry */
			int_value = ip_cmn_rte_table_entry_least_cost_get (rte_entry_ptr);
			
			/* We must determine if the Metric of the route entry matches the given metric */
			is_match = (match_info_ptr->match_term.match_int == int_value);
						
			break;
		/* In this case the route type, 'internal' or 'external', of the entry must be returned */
		case IpC_Rte_Map_Match_Property_Route_Type:
			/* Directly Connected  Rte will always be internal	*/
			int_value = IpC_Rte_Map_Route_Type_Int;
			
			/* We must determine if the Route Type of the route entry matches the given route type */
			is_match = (match_info_ptr->match_term.match_int == int_value);
			
			break;

		case IpC_Rte_Map_Match_Property_Redist_Protocol:
			/* List of supported protocols must contain directly connected protocol.	*/
			for (i = 0; i < match_info_ptr->match_term.match_value_array.num_entries; i++)
				{
				is_match = oms_sv_range_check (match_info_ptr->match_term.match_value_array.value_array.number_range_array [i],
					IPC_DYN_RTE_DIRECTLY_CONNECTED);
				if (OPC_TRUE == is_match)
				   break;
				}

	  	default:
			/* Write a log message.										*/
			ip_nl_rte_map_invalid_match_log_write ("Direct",  match_info_ptr->match_property,
				match_info_ptr->match_condition);

			break;
			
		/* End of switch */	
		}
	FRET (is_match);
	}

static const char hex_digit_lookup_array[] = "0123456789ABCDEF";

static void
ip_cmn_rte_table_hash_key_create (char* key_str, int src_fast_addr, int dest_fast_addr, int lookup_index)
	{
	char*			temp_str;

	/** Create a string hash key from the destination and	**/
	/** source fast addresses and the lookup index. The		**/
	/** format of the string will be as follows.			**/
	/** <src fast addr>:<dest fast addr>:<lookup index>		**/

	FIN (ip_cmn_rte_table_hash_key_create (key_str, src_fast_addr, dest_fast_addr));

	/* Initialize the temp_str variable to the given string */
	/* It will always point to the end of the key_str.		*/
	temp_str = key_str;

	/* First print the src address in the string.			*/
	/* The function will return the length of the string	*/
	/* created. So increment the temp_str by that amount to	*/
	/* make it point to the end of the string.				*/
	temp_str += ip_cmn_rte_fast_addr_to_hex_str (temp_str, src_fast_addr);

	/* Append a ':' to the string.							*/
	*(temp_str++) = ':';

	/* Append the destination address string.				*/
	temp_str += ip_cmn_rte_fast_addr_to_hex_str (temp_str, dest_fast_addr);

	/* Append a ':' to the string.							*/
	*(temp_str++) = ':';

	/* Now add the lookup index to the string. Assume that	*/
	/* the lookup index will not be greater than 15. So		*/
	/* the lookup index can be represented using a single	*/
	/* hexadecimal character.								*/
	*(temp_str++) = hex_digit_lookup_array [lookup_index];

	/* Null terminate the string.							*/
	*(temp_str) = '\0';

	FOUT;
	}

static int
ip_cmn_rte_fast_addr_to_hex_str (char* key_str, int fast_addr)
	{
	const OpT_uInt32	four_bit_mask = 0xf;
	int					index = 0;

	/** Convert the given integer into a hex string. return	**/
	/** the length of the string.							**/

	FIN (ip_cmn_rte_fast_addr_to_hex_str (key_str, fast_addr));

	do
		{
		/* Mask the integer with a 4 bit mask and represent	*/
		/* those four bits using a hexadecimal digit		*/
		/* character.										*/
		key_str [index] = hex_digit_lookup_array [fast_addr & four_bit_mask];
		++index;

		/* Shift the integer to the right by 4 bits.		*/
		fast_addr = fast_addr >> 4;
		}
	while (fast_addr);

	/* Null terminate the string.							*/
	key_str [index] = '\0';

	/* Return the length of the string.						*/
	FRET (index);
	}

static Compcode
ip_cmn_rte_table_fast_addrs_from_hash_key_get (char* key_str,
	int* src_fast_addr_ptr, int *dest_fast_addr_ptr, int* lookup_index_ptr)
	{
	char		*field_ptr, *colon_ptr;

	/** Extract the source and destination fast addresses	**/
	/** and the lookup index from the key.					**/

	FIN (ip_cmn_rte_table_fast_addrs_from_hash_key_get (key_str, ...));

	/* The string consists of three colon separated fields	*/
	/* The first field starts at the begining of the string.*/
	field_ptr = key_str;

	/* Locate the first field separator. (:).				*/
	colon_ptr = strchr (field_ptr, ':');
	if (NULL == colon_ptr)
		{
		FRET (OPC_COMPCODE_FAILURE);
		}

	/* Replace first colon with a string so that field_ptr	*/
	/* now points to the first field alone.					*/
	/* Note that it is OK to modify these strings because	*/
	/* they are temporary variables.						*/
	*colon_ptr = '\0'; 

	/* The first field is the src address string.			*/
	*src_fast_addr_ptr = ip_cmn_rte_hex_str_to_fast_addr (field_ptr);

	/* Make the field_ptr point to the next field.			*/
	field_ptr = colon_ptr + 1;

	/* Replace the next colon with a null string.			*/
	colon_ptr = strchr (field_ptr, ':');
	if (NULL == colon_ptr)
		{
		FRET (OPC_COMPCODE_FAILURE);
		}
	*colon_ptr = '\0'; 

	/* field_ptr now points to the dest fast addr string.	*/
	*dest_fast_addr_ptr = ip_cmn_rte_hex_str_to_fast_addr (field_ptr);

	/* Make field_ptr point to the final field.				*/
	field_ptr = colon_ptr + 1;

	/* Convert the individual strings into integers.		*/
	*lookup_index_ptr = ip_cmn_rte_hex_str_to_fast_addr (field_ptr);

	/* Check for errors.									*/
	if ((IPC_FAST_ADDR_INVALID == *src_fast_addr_ptr) ||
		(IPC_FAST_ADDR_INVALID == *dest_fast_addr_ptr) ||
		(IPC_FAST_ADDR_INVALID == *lookup_index_ptr))
		{
		FRET (OPC_COMPCODE_FAILURE);
		}
	else
		{
		FRET (OPC_COMPCODE_SUCCESS);
		}
	}

static int
ip_cmn_rte_hex_str_to_fast_addr (char* key_str)
	{
	OpT_uInt32	fast_addr = 0;
	int			key_str_len;
	int			index;
	OpT_uInt32	digit;

	/* Recreate the fast address from the hexadecimal		*/
	/* representation.										*/
	FIN (ip_cmn_rte_hex_str_to_fast_addr (key_str));

	/* Handle the null string case.							*/
	if ('\0' == key_str[0])
		{
		FRET (IPC_FAST_ADDR_INVALID);
		}

	/* Get the length of the string.						*/
	key_str_len = strlen (key_str);

	/* The most significant digit will be at the end of the	*/
	/* string. So start from the end.						*/
	for (index = key_str_len - 1; index >= 0; index--)
		{
		/* Make sure this is a hexadecimal digit.			*/
		if (! isxdigit ((unsigned char) key_str [index]))
			{
			/* Error.										*/
			FRET (IPC_FAST_ADDR_INVALID);
			}
		/* Convert this character to its numerical notation	*/
		if (isdigit ((unsigned char) key_str [index]))
			{
			/* This is a digit from 0 to 9 (both incl.).	*/
			/* Just subtract '0' from the digit to get the	*/
			/* equivalent numerical value.					*/
			digit = key_str [index] - '0';
			}
		else
			{
			/* This is a letter from A to F. (both incl.)	*/
			digit = 10 + (key_str [index] - 'A');
			}

		/* Shift the existing number to the left by four and*/
		/* bitwise or it with the current digit.			*/
		fast_addr = (fast_addr << 4) | digit;
		}

	/* Return the Fast address created.						*/
	FRET (fast_addr);
	}

void
ip_cmn_rte_table_dest_src_table_print (IpT_Cmn_Rte_Table* route_table_ptr)
	{
	PrgT_List*			hash_table_key_list;
	int					i, num_entries;
	char*				ith_key;
	IpT_Cmn_Rte_Dest_Src_Table_Entry*	ith_entry_ptr;

	/** Print out the contents of the IP dest source table.	**/

	FIN (ip_cmn_rte_table_dest_src_table_print (route_table_ptr));

	/* If destination based load balancing is not used,		*/
	/* the dest src table will not be built.				*/
	if (IpC_Rte_Table_Load_Dest != route_table_ptr->load_type)
		{
		printf ("\t%s", "Destination based load balancing is not enabled\n"
						"on this router.\n");
		FOUT;
		}

	/* Even if Destination based load balancing is used, the*/
	/* table will not be created until, the first packet is	*/
	/* routed. Handle this case.							*/
	if (OPC_NIL == route_table_ptr->dest_src_table)
		{
		printf ("%s", "\tThe Destination source table on this node\n"
					  "\thas not yet been created.\n");
		FOUT;
		}

	/* Print out a header.									*/
	printf ("\t%20s %20s %5s %25s %20s %10s\n", "Source Address", "Destination Address", "Index",
												"Destination Network", "Next Hop", "Ins. Time");
	printf ("\t%20s %20s %5s %25s %20s %10s\n", "--------------", "-------------------", "-----",
												"-------------------", "--------", "---------");

	/* Get the list of keys in the hash tables.				*/
	hash_table_key_list = prg_string_hash_table_keys_get (route_table_ptr->dest_src_table);
	
	/* Get the number of keys.								*/
	num_entries = prg_list_size (hash_table_key_list);

	for (i = 0; i < num_entries; i++)
		{
		/* Access the ith key.								*/
		ith_key = (char*) prg_list_remove (hash_table_key_list, PRGC_LISTPOS_HEAD);

		/* Get the corresponding entry.						*/
		ith_entry_ptr = (IpT_Cmn_Rte_Dest_Src_Table_Entry*)
			prg_string_hash_table_item_get (route_table_ptr->dest_src_table, ith_key);

		/* Print the current entry.							*/
		ip_cmn_rte_table_dest_src_table_entry_print (ith_key, ith_entry_ptr);
		}

	/* Print the number of entries in the table.			*/
	printf ("Total number of entries = %d\n", route_table_ptr->dest_src_table_size);
	}

static void
ip_cmn_rte_table_dest_src_table_entry_print (char* key,
	IpT_Cmn_Rte_Dest_Src_Table_Entry* dest_src_entry_ptr)
	{
	int					src_fast_addr, dest_fast_addr, lookup_index;
	InetT_Address		src_ip_addr, dest_ip_addr;
	char				src_addr_str[INETC_ADDR_STR_LEN];
	char				dest_addr_str[INETC_ADDR_STR_LEN];
	char				dest_prefix_str[INETC_ADDR_STR_LEN];
	char				next_hop_addr_str[INETC_ADDR_STR_LEN];

	/** Print the contents of the given entry.				**/

	FIN (ip_cmn_rte_table_dest_src_table_entry_print (key, dest_src_entry_ptr));

	/* Extract the source and Destination fast addresses	*/
	/* from the key string.									*/
	ip_cmn_rte_table_fast_addrs_from_hash_key_get (key,
		&src_fast_addr, &dest_fast_addr, &lookup_index);

	/* Get the actual addresses corresponding to the fast	*/
	/* addresses.											*/
	src_ip_addr = nato_table_index_to_major_inet_address
		(ip_table_handle, src_fast_addr);
	dest_ip_addr = nato_table_index_to_major_inet_address
		(ip_table_handle, dest_fast_addr);

	/* Get string representations of the source and			*/
	/* destination addresses.								*/
	inet_address_print (src_addr_str, src_ip_addr);
	inet_address_print (dest_addr_str, dest_ip_addr);

	/* Print the destination prefix and next hop also.		*/
	ip_cmn_rte_table_dest_prefix_print (dest_prefix_str,
		dest_src_entry_ptr->route_entry_ptr->dest_prefix);
	inet_address_print (next_hop_addr_str,
		dest_src_entry_ptr->next_hop_ptr->next_hop);

	/* Print the contents of the entry.						*/
	printf ("\t%20s %20s %5d %25s %20s %10.3f\n", src_addr_str, dest_addr_str, lookup_index, dest_prefix_str,
											  	  next_hop_addr_str, dest_src_entry_ptr->creation_time);

	FOUT;
	}

void
ip_cmn_rte_table_golr_print (IpT_Cmn_Rte_Table* cmn_rte_table)
	{
	/** Print the GOLR and the BDR.							**/

	FIN (ip_cmn_rte_table_golr_print (route_table));

	if (OPC_NIL == cmn_rte_table->gateway_of_last_resort)
		{
		printf ("The gateway of last resort is unset.\n");
		}
	else
		{
		printf ("The gateway of last resort is\n");
		ip_cmn_rte_table_entry_print (cmn_rte_table->gateway_of_last_resort);

		/* If the GOLR is a default network route, print*/
		/* the BDR also.								*/
		if (ip_cmn_rte_table_entry_is_default_network (cmn_rte_table->gateway_of_last_resort))
			{
			if (OPC_NIL == cmn_rte_table->best_default_route)
				{
				printf ("The Best Default Route is unset\n");
				}
			else
				{
				printf ("The Best Default Route is\n");
				ip_cmn_rte_table_entry_print (cmn_rte_table->best_default_route);
				}
			}
		}

	FOUT;
	}

void
ip_cmn_rte_table_default_routes_print (IpT_Cmn_Rte_Table* route_table)
	{
	int							i, num_routes;
	IpT_Cmn_Rte_Table_Entry*	ith_default_route;

	/** Print all resolved and unresolved default routes	**/

	FIN (ip_cmn_rte_table_default_routes_print (route_table));

	printf ("Resolved Default routes\n");
	printf ("=======================\n\n");

	num_routes = op_prg_list_size (route_table->resolved_default_routes);
	for (i = 0; i < num_routes; i++)
		{
		ith_default_route = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_access (route_table->resolved_default_routes, i);
		ip_cmn_rte_table_entry_print (ith_default_route);
		}

	printf ("Unresolved Default routes\n");
	printf ("=========================\n\n");

	num_routes = op_prg_list_size (route_table->unresolved_default_routes);
	for (i = 0; i < num_routes; i++)
		{
		ith_default_route = (IpT_Cmn_Rte_Table_Entry*) op_prg_list_access (route_table->unresolved_default_routes, i);
		ip_cmn_rte_table_entry_print (ith_default_route);
		}

	FOUT;
	}


void
ip_cmn_rte_table_redist_from_all_configure (Objid node_objid, IpT_Cmn_Rte_Table* rte_table_ptr, IpT_Rte_Proc_Id target_proc_id, 
						void* metric_ptr, Boolean redist_from_connected)
	{
	IpT_Rte_Proc_Id			redist_routeproc_id;
	Objid					ospf_params_objid; 
	Objid					ospf_params_child_objid; 
	Objid					processes_comp_objid; 
	Objid					as_comp_objid; 
	Objid				    process_row_objid;
	Objid					as_row_objid; 
	Objid					addr_family_comp_objid; 
	
	Objid					eigrp_params_objid; 
	Objid					eigrp_params_child_objid; 
	
	int						i, num_processes; 
	int						j, num_as; 
	int						proc_number; 
	int						as_number; 
	
	/** This function configures redistribution from all protocols to 	**/
	/** a given target protocol. A boolean option is available to 		**/
	/** include or exclude directly-connected routes. LDP is interested	**/
	/** in all routes other than connected. BGP (in VRFs) is interested	**/
	/** in all routes including connected.								**/
	FIN (ip_cmn_rte_table_redist_from_all_configure ());

	/* Set redistribution from all OSPF processes in this node. */
	
	/* First find out how many OSPF processes are active on this node */
	op_ima_obj_attr_get (node_objid, "OSPF Parameters", &ospf_params_objid); 
	ospf_params_child_objid = op_topo_child (ospf_params_objid, OPC_OBJTYPE_GENERIC, 0); 
	op_ima_obj_attr_get (ospf_params_child_objid, "Processes", &processes_comp_objid);
	num_processes = op_topo_child_count (processes_comp_objid, OPC_OBJTYPE_GENERIC); 

	/* For each OSPF process active on this node ... */
	for (i = 0; i < num_processes; i++)
		{
		/* ... get the process tag (an integer) */
		process_row_objid = op_topo_child (processes_comp_objid, OPC_OBJTYPE_GENERIC, i);  
		op_ima_obj_attr_get (process_row_objid, "Process Tag", &as_number); 
		
		/* Use the process tag to create the routeproc id necessary for */
		/* setting up the redistribution matrix element from OSPF to 	*/
		/* the given target.	 										*/
		redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_OSPF, 
			/* AS number */ as_number); 
		
		Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
			target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);
		}
	
	/* Set redistribution from all EIGRP processes in this node */
	
	/* First find out how many EIGRP processes are active on this node 	   */
	op_ima_obj_attr_get (node_objid, "EIGRP Parameters", &eigrp_params_objid); 
	eigrp_params_child_objid = op_topo_child (eigrp_params_objid, OPC_OBJTYPE_GENERIC, 0); 
	op_ima_obj_attr_get (eigrp_params_child_objid, "Process Parameters", &processes_comp_objid);
	num_processes = op_topo_child_count (processes_comp_objid, OPC_OBJTYPE_GENERIC);
	
	/* For each EIGRP process active on this node ... */
	for (i = 0; i < num_processes; i++)
		{
		/* ... get the process number (an integer) */
		process_row_objid = op_topo_child (processes_comp_objid, OPC_OBJTYPE_GENERIC, i);  
		op_ima_obj_attr_get (process_row_objid, "Process ID", &proc_number);
		
		/* We need to check now if the AS number is "Same as Process ID" */
		op_ima_obj_attr_get (process_row_objid, "Process Parameters", &as_comp_objid); 		 
		num_as = op_topo_child_count (as_comp_objid, OPC_OBJTYPE_GENERIC); 
		
		for (j = 0; j < num_as; j++)
			{
			as_row_objid = op_topo_child (as_comp_objid, OPC_OBJTYPE_GENERIC, j); 
			op_ima_obj_attr_get (as_row_objid, "Address Family Parameters", &addr_family_comp_objid); 
			as_row_objid = op_topo_child (addr_family_comp_objid, OPC_OBJTYPE_GENERIC, 0); 
			op_ima_obj_attr_get (as_row_objid, "Autonomous System", &as_number); 
			
			if (as_number < 0)
				as_number = proc_number; 
			
			/* Use the AS number to create the routeproc id necessary for   */
			/* setting up the redistribution matrix element from EIGRP to   */
			/* the given target.	 										*/
			redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_EIGRP, 
				as_number); 
		
			Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
				target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);
			
			/* Note: the attribute structure in EIGRP may mean we are installing */
			/* the same redistribution matrix element more than once. We are     */
			/* assuming there is no hard in installing repeatedly. 				 */
			}
		}	
	
	/* Set redistribution from BGP, only if BGP is not the target protocol. */
	redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_BGP, 
		IPC_NO_MULTIPLE_PROC); 
	if (redist_routeproc_id != target_proc_id)
		{
		Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
			target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_IBGP_AND_EBGP);
		}

	/* Set redistribution from RIP */
	redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_RIP, IPC_NO_MULTIPLE_PROC); 
	Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
		target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);
	
	/* Set redistribution from IGRP */
	redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_IGRP, IPC_NO_MULTIPLE_PROC); 
	Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
		target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);
	
	/* Set redistribution from IS-IS */
	redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_ISIS, IPC_NO_MULTIPLE_PROC); 
	Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
		target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);
	
	/* Also register for static */
	redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_STATIC, IPC_NO_MULTIPLE_PROC); 
	Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
		target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);

	/* Configure redistribution from directly-connected, if requested.	*/
	if (redist_from_connected)
		{
		redist_routeproc_id = IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IPC_DYN_RTE_DIRECTLY_CONNECTED, IPC_NO_MULTIPLE_PROC); 
		Ip_Cmn_Rte_Table_Install_Redist_Matrix_Entry (rte_table_ptr, 
			target_proc_id, redist_routeproc_id, metric_ptr, IPC_REDIST_NOT_BGP);
		}
	
	FOUT; 
	}


IpT_Cmn_Rte_Table*
ip_cmn_rte_table_for_intf_get (IpT_Rte_Module_Data* iprmd_ptr, int intf_index)
	{
	IpT_Cmn_Rte_Table* 	ip_rte_table_ptr;
	/** Determines the routing instance to which this interface belongs.	**/
	FIN (ip_cmn_rte_table_for_intf_get ());

	if (!ip_node_is_pe (iprmd_ptr))
		FRET (iprmd_ptr->ip_route_table);

	ip_rte_table_ptr = ip_vrf_table_cmn_rte_table_get (ip_vrf_table_for_intf_index_get (iprmd_ptr, intf_index));

	if (ip_rte_table_ptr == OPC_NIL)
		ip_rte_table_ptr = iprmd_ptr->ip_route_table;

	FRET (ip_rte_table_ptr);
	}
