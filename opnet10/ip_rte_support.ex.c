/* ip_rte_support.ex.c */
/* Support routines for ip_dispatch and its associated child processes */

/****************************************/
/*      Copyright (c) 1987 - 2002       */
/*      by OPNET Technologies, Inc.     */
/*       (A Delaware Corporation)       */
/*    7255 Woodmont Av., Suite 250      */
/*     Bethesda, MD 20814, U.S.A.       */
/*       All Rights Reserved.           */
/****************************************/

/* ---- (SECTION_INC) Include Directives ---- */

#include <string.h>
#include <opnet.h>
#include <ip_rte_support.h>
#include <mpls_support.h>
#include <ip_addr_v4.h>
#include <oms_bgutil.h>
#include <ip_vrf_table.h>
#include <ip_rte_v4.h>
#include <ip_rte_slot.h>
#include <oms_slot.h>
#include <ip_cmn_rte_table.h>
#include <ip_rte_table_v4.h>
#include <icmp6_nd.h>
#include <dsr_pkt_support.h>
#include <ip_mcast_support.h>
#include <ip_sim_attr_cache.h>
#include <ip_ot_support.h>
#include <manet_tora_imep.h>
#include <mobile_ip_support.h>
#include <ip_notif_log_support.h>
#include <oms_rr.h>

/* ---- (SECTION_LP) External Declarations ---- */  /* JPH */

extern int host_routing_enabled;                    /* LP3-21-04 with JHP fix  */


/* ---- Internal Data types ---- */
typedef enum IpT_Support_Intf_Type
	{
	IpC_Support_Intf_Type_Physical = 0,
	IpC_Support_Intf_Type_Loopback = 1,
	IpC_Support_Intf_Type_Tunnel = 2,
	IpC_Support_Intf_Type_Number
	} IpT_Support_Intf_Type;

#define NUM_INTERFACE_TYPES		IpC_Support_Intf_Type_Number

const char* intf_types_str_array [NUM_INTERFACE_TYPES] = {"Interface Information", "Loopback Interfaces", "Tunnel Interfaces"};
static Pmohandle				objid_pmh;
static Boolean					objid_pmh_initialized = OPC_FALSE;
static char						intf_name_unknown_str[] = "Unknown";

/* ---- (SECTION_LP) Local Prototypes ---- */

static void
ip_rte_total_packets_received_stat_update (IpT_Rte_Module_Data * iprmd_ptr, int pkt_dest_type,
	Packet * pk_ptr, InetT_Addr_Family addr_family);

static void
ip_rte_dgram_options_process (IpT_Rte_Module_Data * iprmd_ptr, Packet* ip_pkptr, int output_table_index);

static Compcode
ip_rte_datagram_dest_get (IpT_Rte_Module_Data * iprmd_ptr, Packet* pkptr, Ici* rsvp_ici_ptr, Boolean force_fwd, 
	InetT_Address dest_addr, int instrm, int protocol_type,
	InetT_Address *next_addr_ptr, char** lsp_name_pstr, Boolean *broadcast_ptr, 
	Boolean *higher_layer_ptr, Boolean *destroy_pkt_ptr, IpT_Port_Info* output_port_info_ptr, 
	IpT_Interface_Info **interface_ptr, int * num_tracer_info_ptr, 
	IpT_Tracer_Info ** tracer_info_array_pptr, char** drop_reason_pstr, IpT_Rte_Proc_Id* src_proto_ptr);

static Compcode
ip_rte_mcast_datagram_dest_get (IpT_Rte_Module_Data * iprmd_ptr, Packet* pkptr, Ici* rsvp_ici_ptr, 
	IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr, InetT_Address dest_addr, 
	InetT_Address* next_addr_ptr, Boolean* broadcast_ptr, Boolean* higher_layer_ptr, Boolean* destroy_pkt_ptr, 
	int protocol_type,  int* output_table_index_ptr, IpT_Interface_Info** interface_pptr);

static double
ip_rte_decomp_delay_compute (Packet* pkptr, IpT_Dgram_Fields* pk_fd_ptr);

static void
ip_unnumbered_intf_router_id_assign (IpT_Rte_Module_Data * iprmd_ptr);

static IpT_Address
ip_obtain_neighbor_router_id (IpT_Rte_Module_Data * iprmd_ptr, Objid link_objid);

static void
ip_rte_pk_fragment (IpT_Rte_Module_Data * iprmd_ptr, Packet *pk_ptr, InetT_Address dest_addr, InetT_Address next_addr, 
	int conn_class, IpT_Rte_Ind_Ici_Fields* intf_ici_ptr);

static void
ip_rte_frag_send (IpT_Rte_Module_Data* iprmd_ptr, Packet* pk_ptr,
	InetT_Addr_Family addr_family, InetT_Address dest_addr, InetT_Address next_addr, 
	int conn_class, IpT_Interface_Info* iface_info_ptr, IpT_Rte_Ind_Ici_Fields* intf_ici_ptr);

static void
ip_rte_pk_sent_stats_update (IpT_Rte_Module_Data* iprmd_ptr, Packet* pk_ptr,
	int  ip_queuing_scheme, int pk_tx_type, InetT_Addr_Family addr_family);

static void
ip_src_address_determine (InetT_Address *src_addr_ptr, IpT_Rte_Module_Data* iprmd_ptr, int intf_tbl_index,
	InetT_Addr_Family addr_family);

static void
ip_inface_statistic_update (IpT_Rte_Module_Data * iprmd_ptr, int output_strm, double pkt_bitsize, Packet * pkptr);

static void
ip_forward_packet_to_output_queues (IpT_Rte_Module_Data * iprmd_ptr, Packet* pk_ptr, int outstrm,
	Ici* iciptr, int pkt_txtype, int output_interface_index, int incoming_iface);

static void
ip_rte_ip_vpn_tunnel_packet (IpT_Rte_Module_Data * iprmd_ptr, 
	Packet** pkptr, double* tunnel_delay);

static void
ip_packet_tunnel (IpT_Rte_Module_Data* iprmd_ptr, Packet* inner_pkptr,
	int instrm, InetT_Address next_addr, IpT_Interface_Info* tunnel_intf_ptr);

static Compcode
ip_rte_ipv6_manual_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, IpT_Interface_Info* tunnel_intf_ptr);

static Compcode
ip_rte_ipv6_auto_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, InetT_Address dest_addr,
	IpT_Interface_Info* tunnel_intf_ptr);

static Compcode
ip_rte_ipv6_6to4_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, InetT_Address dest_addr,
   	IpT_Interface_Info* tunnel_intf_ptr);

static Compcode
ip_rte_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, IpT_Interface_Info* tunnel_intf_ptr);

static Packet*
ip_rte_tunnel_gre_pkt_create (Packet* tunneled_pkptr);

static void
ip_rte_load_balancer_handle_packet (IpT_Rte_Module_Data* module_data, Packet** pkptr);

static Boolean		
ip_rte_load_balancer_packet_mine (const InetT_Address dest_address,
	IpT_Rte_Module_Data *iprmd_ptr, int* table_index_ptr);

static void
ip_rte_load_balancer_log ();

static char*
ip_mpls_packet_classify (IpT_Rte_Module_Data* iprmd_ptr, Packet* pkt_ptr, int in_iface);

int
ip_cmn_rte_table_entry_cost_get (IpT_Cmn_Rte_Table_Entry *rte_entry_ptr,int hop_index);

static void
ip_rte_flow_id_swap (OmsT_Bgutil_Tracer_Packet_Info* trc_pkt_info_ptr, 
	IpT_Interface_Info* interface_ptr, InetT_Address next_hop_addr);

static char*
ip_vpn_packet_classify (IpT_Rte_Module_Data* iprmd_ptr, Packet* pkt_ptr, int in_iface);

static int
ip_rte_minor_port_from_next_hop_get (IpT_Rte_Module_Data* iprmd_ptr, int phys_intf_index, InetT_Address next_hop);

static Boolean
ip_mpls_lsp_status_get (IpT_Rte_Module_Data* iprmd_ptr, char* lsp_name_str, int in_iface);

static InetT_Address
ip_rte_support_next_hop_set (IpT_Rte_Module_Data* iprmd_ptr, InetT_Addr_Family addr_family,
	const InetT_Address* addr_ptr, int* out_iface_ptr);

InetT_Address
ip_rte_next_hop_address_valid (IpT_Rte_Module_Data* iprmd_ptr, int intf_index);

static void
ip_rte_isis_pdu_send (IpT_Rte_Module_Data *iprmd_ptr, Packet *pk_ptr);

static void
ip_rte_isis_pdu_recv (IpT_Rte_Module_Data *iprmd_ptr, Packet *pk_ptr,
                        int instrm, IpT_Dgram_Fields* pk_fd_ptr);

static Compcode
ip_rte_pk_rcvd_intf_tbl_indx_get (IpT_Rte_Module_Data *iprmd_ptr, int instrm, IpT_Dgram_Fields* pk_fd_ptr,
                                int *minor_port_ptr, int *input_intf_tbl_index_ptr);

void
ip_policy_action_into_list_insert (List* ip_policy_action_lptr, char* node_name, char* rte_map_filter_name, 
										char* iface_name_str, IpT_Policy_Action policy_action);

static IpT_Policy_Action_Info*
ip_policy_action_info_mem_alloc (void);

static int
ip_rte_input_slot_index_determine (IpT_Rte_Module_Data *iprmd_ptr, IpT_Interface_Info* in_iface_ptr, int instrm);

static void
ip_rte_support_intf_objid_add (PrgT_String_Hash_Table* intf_name_htable_ptr, Objid intf_name_objid);

static Boolean
inet_rte_v6intf_addr_range_check (InetT_Address next_hop, IpT_Interface_Info* intf_ptr,
	InetT_Address_Range** addr_range_pptr);

static Boolean
ipv6_rte_is_local_address(const InetT_Address intf_addr, IpT_Rte_Module_Data* iprmd_ptr,
	int* intf_index_ptr);

static Boolean 
ip_rte_subintf_layer2_mapping_found (const char* mapping_name, IpT_Layer2_Mapping mapping_type, IpT_Layer2_Mappings layer2_map);

/* ---- (SECTION_ECP) Externally Callable Procedures ---- */

void
ip_rte_set_procs (IpT_Rte_Module_Data * iprmd_ptr, 
	IpT_Rte_Error_Proc error_p, IpT_Rte_Warning_Proc warning_p)
	{
	/** Until a more comprehensive revisit of this code to 	**/
	/** better repackage, we mimick what used to be a set	**/
	/** of process model state variables with a similar		**/
	/** structure that must be set by each model before		**/
	/** invoking any other function in this file.			**/
	FIN (ip_rte_set_procs (iprmd_ptr, error_p, warning_p));

	iprmd_ptr->error_proc = error_p;
	iprmd_ptr->warning_proc = warning_p;

	FOUT;
	}

Boolean
ip_interface_routing_protocols_contains (List* routing_protocols_lptr, int routing_protocol)
	{
	Boolean			protocol_is_in_this_list;
	int*			i_th_protocol_ptr;
	int				i_th_protocol, num_rte_protocols;
	
	/** Checks if the passed in routing protocol is not in the supplied list. **/
	FIN (ip_interface_routing_protocols_contains (routing_protocols_lptr, routing_protocol));

	/* Check for NIL list */
	if (routing_protocols_lptr == OPC_NIL)
		FRET (OPC_FALSE); 
	
	/* Assume that the passed in routing protocol is not in the supplied list.	*/
	protocol_is_in_this_list = OPC_FALSE;
	
	/* Loop though the different number of routing protocols	*/
	/* running on this interface.								*/
	num_rte_protocols = op_prg_list_size (routing_protocols_lptr);
	for (i_th_protocol = 0; i_th_protocol < num_rte_protocols; i_th_protocol++)
		{
		/* Access the first specification -- this element will	*/
		/* be a pointer to the routing protocol ID.				*/
		i_th_protocol_ptr = (int *) op_prg_list_access (routing_protocols_lptr, i_th_protocol);
		
		/* Check if the supplied protocol is same as this. There is	*/
		/* a special case when a custom routing protocol is used.	*/
		if (routing_protocol == IpC_Rte_Custom &&
			*i_th_protocol_ptr >= IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID)
			{
			protocol_is_in_this_list = OPC_TRUE;
			break;
			}
		else
			{
			/* this must be standard routing protocol (e.g., OSPF).	*/
			if (*i_th_protocol_ptr == routing_protocol)
				{
				protocol_is_in_this_list = OPC_TRUE;
				break;
				}
			}
		}
	
	FRET (protocol_is_in_this_list);
	}

Objid		
ip_rte_proto_intf_attr_objid_get (Objid intf_info_cattr_objid, IpT_Interface_Info* ip_iface_elem_ptr,
	int* phys_intf_index_ptr, int* subintf_index_ptr)
	{
	static int			phys_intf_index;
	static int			subintf_index;
	static Objid		intf_attr_objid;
	static Objid		subintf_info_cattr_objid;
	static Objid		local_intf_info_cattr_objid;
	static int			intf_info_cattr_size;
	static int			subintf_info_cattr_size;
	/** This function returns the object id of a row in the Interface		**/
   	/** Information or Subinterface Information compound attribute of a		**/
   	/** routing protocol. The row would correspond to the interface/subintf	**/
	/** specified by the intf_info_ptr attribute. The intf_info_cattr_objid	**/
	/** argument should be set to the objid of the Interface Information	**/
	/** compound attribute of routing protocol.								**/
	/** Remarks:															**/
	/** 1. The attributes should be of the standard structure.				**/
	/** 2. The interfaces should be passed in the order in which they are 	**/
	/**    stored in the interface_table maintained by ip.					**/
	/** 3. This function uses static variables internally. If multiple or	**/
	/**    simulataneous calls are made to this function, a high potential	**/
	/**    data corruption and inaccurate results exists.					**/
	/** 4. The first call to this function should be passed OPC_NIL as the	**/
	/**    intf_info_ptr argument. Subsequent calls should pe passed the	**/
	/**    interface info pointers in order until all interfaces are over.	**/
	/** 5. This functions handles the case when the there are insufficient	**/
	/**    rows under the routing protocol parameters.						**/

	FIN (ip_rte_proto_intf_attr_objid_get (intf_info_cattr_objid, intf_info_ptr));

	/* If ip_iface_elem_ptr is OPC_NIL, just reset all variables.			*/
	if (OPC_NIL == ip_iface_elem_ptr)
		{
		/* store a local copy of intf_info_cattr_objid for error checking	*/
		local_intf_info_cattr_objid = intf_info_cattr_objid;

		/* Find out the number of rows under the "Interface Information"	*/
		/* compound attribute.												*/
		intf_info_cattr_size = op_topo_child_count (intf_info_cattr_objid, OPC_OBJTYPE_GENERIC);

		/* Set the phys_intf_index to -1.									*/
		phys_intf_index = -1;

		FRET (OPC_OBJID_INVALID);
		}
	
	/* Make sure that the intf_info_cattr_objid matches the local variable	*/
	if (intf_info_cattr_objid != local_intf_info_cattr_objid)
		{
		op_sim_end ("In ip_rte_proto_intf_attr_objid_get, the objid",
					"passed did not match the locally stored value.",
					"Reset the value by passing the ip_iface_elem_ptr",
					"argument as OPC_NIL before using this function");
		FRET (OPC_OBJID_INVALID);
		}

	/* Do not try to access the interface info for loopback	interfaces.	*/
	if ((ip_rte_intf_is_loopback (ip_iface_elem_ptr)) ||
		(ip_rte_intf_is_tunnel (ip_iface_elem_ptr)))
		{
		/* Increment the physical interface index and reset the		*/
		/* subinterface index.										*/
		++phys_intf_index;
		subintf_index = IPC_SUBINTF_PHYS_INTF;

		/* For loopback interfaces just set the intf_attr_objid to	*/
		/* to OPC_OBJID_INVALID.									*/
		intf_attr_objid = OPC_OBJID_INVALID;
		}
	else if (ip_rte_intf_is_physical (ip_iface_elem_ptr))
		{
		/* Increment the physical interface index and reset the		*/
		/* subinterface index.										*/
		++phys_intf_index;
		subintf_index = IPC_SUBINTF_PHYS_INTF;

		/* Make sure a corresponding row exists under the 			*/
		/* Interface Information attribute of the routing protocol	*/
		if (ip_rte_intf_addr_index_get (ip_iface_elem_ptr) >= intf_info_cattr_size)
			{
			/* the row is missing									*/
			intf_attr_objid = OPC_OBJID_INVALID;
			subintf_info_cattr_objid = OPC_OBJID_INVALID;
			}
		else
			{
			/* Obtain the objid of the row in the interface information	*/
			intf_attr_objid = op_topo_child (intf_info_cattr_objid, OPC_OBJTYPE_GENERIC,
				ip_rte_intf_addr_index_get (ip_iface_elem_ptr));

			if (ip_rte_num_subinterfaces_get (ip_iface_elem_ptr) > 0)
				{
				/* Also obtain the objid of the Subinterface Information	*/
				/* compound attribute of this interface.					*/
				op_ima_obj_attr_get (intf_attr_objid, "Subinterface Information", &subintf_info_cattr_objid);
				subintf_info_cattr_size = op_topo_child_count 
					(subintf_info_cattr_objid, OPC_OBJTYPE_GENERIC);
				}
				
			}
		}
	else
		{
		/* This is subinterface.									*/
		/* Increment the subintf index.								*/
		++subintf_index;

		/* Make sure we found a matching row for the parent intf	*/
		if (OPC_OBJID_INVALID != subintf_info_cattr_objid)
			{
			/* Make sure that there are enough rows under the		*/
			/* Subinterface Information compound attribute			*/
			if (ip_rte_intf_sub_addr_index_get (ip_iface_elem_ptr) >= subintf_info_cattr_size)
				{
				intf_attr_objid = OPC_OBJID_INVALID;
				}
			else
				{
				intf_attr_objid = op_topo_child (subintf_info_cattr_objid, 
					OPC_OBJTYPE_GENERIC, ip_rte_intf_sub_addr_index_get (ip_iface_elem_ptr));
				}
			}
		}
	*phys_intf_index_ptr = phys_intf_index;
	*subintf_index_ptr = subintf_index;
	FRET (intf_attr_objid);
	}

IpT_Intf_Name_Objid_Table_Handle
ip_rte_proto_intf_attr_objid_table_build (Objid proto_params_objid)
	{
	PrgT_String_Hash_Table*	intf_name_htable_ptr;
	Objid					intf_info_objid;
	Objid					subintf_info_objid;
	int						intf_info_cattr_size;
	int						subintf_info_cattr_size;
	Objid					intf_attr_objid;
	int						intf_type, j, k;
	int						num_entries = 0;

	/** This function creates a lookup table for mapping between	**/
	/** an Interface name and the objid of the corresponding		**/
	/** interface under the protocol Parameters of a particular		**/
	/** protocol e.g. RIP Parameters. The attributes must be in the	**/
	/** standard form. i.e the given object must have a compound	**/
	/** attribute named "Interface Information". Each row of this	**/
	/** attriubte must have an attribute name "Name" whose value	**/
	/** would be the name of an interface on this node. 			**/
	/** Subinterfaces (if any) must be specified under an attribute	**/
	/** named "Subinterface Information". But it is not required.	**/
	/** This funciton also handles Loopback and Tunnel interfaces.	**/
	/** But it is not required that the given object have attributes**/
	/** named "Loopback Interfaces" or "Tunnel Interfaces".			**/

	/** The function named ip_rte_proto_intf_attr_objid_table_lookup**/
	/** can be used to look up the objid of a particular interface	**/
	/** in the table returned by this function.						**/

	/** The table thus created must be destroyed by calling			**/
	/** ip_rte_proto_intf_attr_objid_table_destroy to avoid a		**/
	/** memory leak.												**/

	FIN (ip_rte_proto_intf_attr_objid_table_build (proto_params_objid));

	/* Initialize the Pool memory object handle if it is not already		*/
	/* initialized.															*/
	if (OPC_FALSE == objid_pmh_initialized)
		{
		objid_pmh = op_prg_pmo_define ("Interface Objid", sizeof (Objid), 50);
		objid_pmh_initialized = OPC_TRUE;
		}

	/* Create a hash table to store the objid corresponding to		*/
	/* each interface name.											*/
	intf_name_htable_ptr = prg_string_hash_table_create (50, 25);

	/* Get the objids of the "Interface Information", 				*/
	/* "Loopback Interfaces" and "Tunnel Interfaces" attributes.	*/
	for (intf_type = 0; intf_type < NUM_INTERFACE_TYPES; intf_type++)
		{
		/* Make sure there is an attribute corresponing to this		*/
		/* interface type under this protocol's parameters.			*/
		if (op_ima_obj_attr_exists (proto_params_objid, intf_types_str_array [intf_type]))
			{
			op_ima_obj_attr_get (proto_params_objid, intf_types_str_array [intf_type], &(intf_info_objid));

			/* Find out the number of rows under this attribute.	*/
			intf_info_cattr_size = op_topo_child_count (intf_info_objid, OPC_OBJTYPE_GENERIC);

			/* Loop through all the rows and read in their names 	*/
			for (j = 0; j < intf_info_cattr_size; j++)
				{
				/* Get the object ID of the jth row.				*/
				intf_attr_objid = op_topo_child (intf_info_objid, OPC_OBJTYPE_GENERIC, j);

				/* Add this row to the hash table.					*/
				ip_rte_support_intf_objid_add (intf_name_htable_ptr, intf_attr_objid);
				++num_entries;

				/* For physical interfaces we need to go through	*/
				/* the list of Subinterfaces also.					*/
				if ((IpC_Support_Intf_Type_Physical == intf_type) &&
					(op_ima_obj_attr_exists (intf_attr_objid, "Subinterface Information")))
					{
					/* Get the object Id of the subinterface		*/
					/* information attribute.						*/
					op_ima_obj_attr_get (intf_attr_objid, "Subinterface Information", &subintf_info_objid);

					/* Get the number of subinterfaces.				*/
					subintf_info_cattr_size = op_topo_child_count (subintf_info_objid, OPC_OBJTYPE_GENERIC);

					/* Loop through the subinterfaces and add them	*/
					/* also to the hash table.						*/
					for (k = 0; k < subintf_info_cattr_size; k++)
						{
						/* Get the object ID of the ith row.		*/
						intf_attr_objid = op_topo_child (subintf_info_objid, OPC_OBJTYPE_GENERIC, k);

						/* Add this row to the hash table.			*/
						ip_rte_support_intf_objid_add (intf_name_htable_ptr, intf_attr_objid);
						++num_entries;
						}
					}
				}
			}
		}

	/* If the hash table is empty, delete it.						*/
	if (0 == num_entries)
		{
		prg_string_hash_table_free (intf_name_htable_ptr);
		intf_name_htable_ptr = IpC_Intf_Name_Objid_Table_Invalid;
		}

	/* Return the hash table. 										*/
	FRET (intf_name_htable_ptr);
	}

int
ip_rte_proto_intf_attr_objid_table_size (IpT_Intf_Name_Objid_Table_Handle table_handle)
	{
	PrgT_List*		key_lptr;
	int				table_size;

	/** Return the number of entries in the table.					**/

	FIN (ip_rte_proto_intf_attr_objid_table_size (table_handle));

	/* Currently there is no function that will directly give the	*/
	/* the number of entries in the hash table. So we have to		*/
	/* create the list of keys and get its size.					*/

	/* Get the list of keys.										*/
	key_lptr = prg_string_hash_table_keys_get (table_handle);

	/* The size of the table is the number of keys.					*/
	table_size = prg_list_size (key_lptr);

	/* Free the memory allocated to the list.						*/
	prg_list_free (key_lptr);
	prg_mem_free (key_lptr);

	/* Return the number of entries in the table.					*/
	FRET (table_size);
	}
	

Objid
ip_rte_proto_intf_attr_objid_table_lookup_by_name (IpT_Intf_Name_Objid_Table_Handle intf_name_htable_ptr,
	char* interface_name)
	{
	Objid*					intf_objid_ptr;
	Objid					intf_attr_objid;

	/** This function is used to obtain the objid of a row from the	**/
	/** table created using the 									**/
	/** ip_rte_proto_intf_attr_objid_table_build function. If a		**/
	/** matching element is not found, OPC_OBJID_INVALID will be	**/
	/** returned.													**/

	FIN (ip_rte_proto_intf_attr_objid_table_lookup_by_name (intf_name_htable_ptr, ip_iface_elem_ptr));

	/* We do not need to handle the case where the hash table is	*/
	/* NIL, because that case is handled by the						*/
	/* prg_string_hash_table_item_get function.						*/

	/* Look for a matching entry in the hash table.							*/
	intf_objid_ptr = (Objid*) prg_string_hash_table_item_get (intf_name_htable_ptr, interface_name);

	/* If no matching entry was found, return OPC_OBJID_INVALID				*/
	if (OPC_NIL == intf_objid_ptr)
		{
		intf_attr_objid = OPC_OBJID_INVALID;
		}
	else
		{
		/* We found a match return the stored value.						*/
		intf_attr_objid = *intf_objid_ptr;
		}

	FRET (intf_attr_objid);
	}

void
ip_rte_proto_intf_attr_objid_table_destroy (IpT_Intf_Name_Objid_Table_Handle intf_name_htable_ptr)
	{
	/** Frees the memory allocated to a table created using 		**/
	/** ip_rte_proto_intf_attr_objid_table_build.					**/

	FIN (ip_rte_proto_intf_attr_objid_table_destroy (intf_name_htable_ptr));

	prg_string_hash_table_free_proc (intf_name_htable_ptr, op_prg_mem_free);

	FOUT;
	}

static void
ip_rte_support_intf_objid_add (PrgT_String_Hash_Table* intf_name_htable_ptr, Objid intf_attr_objid)
	{
	void*				old_objid_ptr;
	char				intf_name [128];
	Objid*				intf_objid_ptr;

	/** This function adds the given interface name to the hash table.		**/
	FIN (ip_rte_support_intf_objid_add (intf_name_htable_ptr, intf_name_objid));

	/* Allocate enough memory to hod the object ID.							*/
	intf_objid_ptr = (Objid*) op_prg_pmo_alloc (objid_pmh);
	*intf_objid_ptr = intf_attr_objid;

	/* Get the name of this interface.										*/
	op_ima_obj_attr_get (intf_attr_objid, "Name", intf_name);

	/* Create a hash table entry corresponding to this interface			*/
	prg_string_hash_table_item_insert (intf_name_htable_ptr, intf_name, intf_objid_ptr, &old_objid_ptr);

	if (old_objid_ptr != OPC_NIL)
		{
		ipnl_dupl_intf_name_error (intf_attr_objid, intf_name);
		}

	FOUT;
	}

Boolean
ip_rte_packet_format_valid (IpT_Rte_Module_Data * iprmd_ptr,Packet * pkptr)
	{
	static Boolean			ip_error_message_printed = OPC_FALSE;
	char					ip_packet_format [256];

	/** Check that the packet format is appropriate for IP routing 	**/
	/** If not, discard the packet and return OPC_FALSE.			**/
	FIN (ip_rte_packet_format_valid (pkptr));

	/*	Obtain the format of the packet to verify that it is an		*/
	/*	IP datagram.												*/
	op_pk_format (pkptr, ip_packet_format);
	
	/* Ignore if this is not a valid IP datagram.	*/
	if (strcmp (ip_packet_format, "ip_dgram_v4") != 0)
		{
		/*	Print this error message only once.	*/
		if (ip_error_message_printed == OPC_FALSE)
			{
			/* Print a warning message in the simulation log.	*/	
			ipnl_protwarn_pkformat (op_pk_id (pkptr), op_pk_tree_id (pkptr), 
				ip_packet_format);
			ip_error_message_printed = OPC_TRUE;
			}
	
		/* Destroy the packet and update statistics.	*/
		ip_rte_dgram_discard (iprmd_ptr, pkptr, OPC_NIL, "Non IP packet received" /* Reason for drop */);
	
		/* Indicate that the packet insertion failed.	*/
		FRET (OPC_FALSE);
		}
	
	FRET (OPC_TRUE);
	}

Boolean
ip_rte_packet_arrival (IpT_Rte_Module_Data * iprmd_ptr,
	Packet ** pkpptr, int instrm, 
	IpT_Rte_Ind_Ici_Fields ** intf_ici_fdstruct_pptr,
	IpT_Interface_Info **rcvd_iface_info_pptr)
	{
	Boolean					ip_rte_trace;
	IpT_Dgram_Fields*		pk_fd_ptr;
	/* IP datagrams maintain an ICI to record information	*/
	/* required for proper routing (e.g., slot on which the	*/
	/* datagram arrived, output interface on which it		*/
	/* should be forwarded, etc.) -- all that information	*/
	/* is stored in a single structure field of the			*/
	/* ip_rte_ind_v4 ICI.									*/
	IpT_Rte_Ind_Ici_Fields	*intf_ici_fdstruct_ptr 		= OPC_NIL;
	Boolean					packet_from_lower_layer 	= OPC_FALSE;
	double					proxy_delay 				= 0.0;
	double					current_time 				= 0.0;
	Ici*					rsvp_ici_ptr 				= OPC_NIL;
	Ici*					mcast_ici_ptr 				= OPC_NIL;
	int						mcast_major_port 			= 0;
	int 					mcast_minor_port 			= 0;
	IpT_Interface_Info*		iface_info_ptr 				= OPC_NIL;
	int 					slot_index 					= -1;
	Ici*					intf_ici_ptr 				= OPC_NIL;
	int						minor_port_in				= IPC_SUBINTF_INDEX_INVALID;
	char					trace_msg [128];
	char*					intf_addr_str;
	InetT_Address			dest_addr;
	InetT_Addr_Family		addr_family;
	InetT_Address			next_addr 					= INETC_ADDRESS_INVALID;
	Boolean					broadcast 					= OPC_FALSE;
	Boolean					higher_layer 				= OPC_FALSE;
	Boolean					destroy_pkt 				= OPC_FALSE;
	Boolean					multicast_dest_addr;
	char*					dest_addr_str;
	int						pkt_dest_type;
	Boolean					force_fwd 					= OPC_FALSE;
	IpT_Interface_Info*		interface_ptr 				= OPC_NIL;
	Compcode				got_datagram_info;
	double					decomp_delay 				= 0.0;
	double					comp_delay					= 0.0;
	OpT_Packet_Size			packet_size;
	Boolean					car_packet_drop 			= OPC_FALSE;
	char					str0 [512];
	double					vpn_delay 					= 0.0;
	double					gtp_delay 					= 0.0;
	IpT_Address           	lb_addr;
	Boolean					packet_is_labeled 			= OPC_FALSE;
	Boolean					packet_from_manet 			= OPC_FALSE;
	char*					fec_name 					= OPC_NIL;
	int						num_tracer_info 			= 0;
	IpT_Tracer_Info *		tracer_info_array 			= OPC_NIL;
	int						input_intf_tbl_index		= IPC_INTF_INDEX_INVALID;
	int						output_table_index 			= IPC_INTF_INDEX_INVALID;
	char*					vrf_name 					= OPC_NIL;
	char*					lsp_name_str 				= OPC_NIL;
	char*					drop_reason_str 			= OPC_NIL;
	
	InetT_Address			rte_map_next_addr 			= INETC_ADDRESS_INVALID;
	int						rte_map_output_table_index 	= IPC_INTF_INDEX_INVALID;
	IpT_Rte_Table_Lookup	route_table_lookup 			= IpC_Rte_Table_Lookup;
	IpT_Rte_Proc_Id			src_proto					= 0;	
	char*					policy_name 				= OPC_NIL;
	Packet *                bgutil_pkptr;
	char					iface_name_str [256];
	IpT_Port_Info			output_port_info;
	char					msg0 [512];
	int						nodeid; 
	
	/** Perform the appropriate preprocessing on arriving packets	**/
	/** to either discard the unwanted packet or gather necessary	**/
	/** information for further routing.							**/
	/** The packet is expected to be in the ip_dgram_v4 format		**/
	FIN (ip_rte_packet_arrival (pkpptr, instrm, intf_ici_fdstruct_pptr, 
		iface_info_pptr));


#ifdef OP_DEBUG1
	op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &nodeid);
	printf("\t Node %d - ip_rte_support.c - ip_rte_packet_arrival()\n", nodeid);
#endif
	/* Check if this is a bgutil packet. */
	if (op_pk_encap_flag_is_set (*pkpptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX))
		{
		/* Get a copy of the bgutil packet.	*/
		op_pk_encap_pk_get (*pkpptr, "bgutil_tracer", &bgutil_pkptr);
		
		/* Update the segmentation information in the tracer packet. */
		oms_bgutil_segmentation_info_update (bgutil_pkptr, OPC_NIL, OmsC_Tracer_IP,    
			 OMSC_BGUTIL_OVERHEAD_IP, OMSC_BGUTIL_DO_NOT_SEGMENT, 0.0, 
			 oms_bgutil_tracer_segment_func, OPC_FALSE, OPC_NIL); 

		/* Destroy the copy packet.	*/
		op_pk_destroy (bgutil_pkptr);
		}
	
	/* Initialize return information */
	*intf_ici_fdstruct_pptr = OPC_NIL;

	/* Initialize output_port_info. Details are populated while performing	*/
	/* route table lookup for unicast destinations.							*/
	output_port_info = ip_rte_port_info_create (IPC_INTF_INDEX_INVALID, OPC_NIL);

	/* obtain whether the labelel trace for "ip_rte" is enabled		*/
	ip_rte_trace = LTRACE_IP_ACTIVE;

	/* If this is a labeled packet none of the IP header fields */
	/* would be visible. This will have an effect on the down 	*/
	/* the line processing of this packet						*/
	if (op_pk_nfd_is_set (*pkpptr, "MPLS Shim Header") == OPC_TRUE)
		packet_is_labeled = OPC_TRUE;

	/* First find out whether or not the packet came from the 	*/
	/* lower layer.												*/
	if ((iprmd_ptr->instrm_from_ip_encap == instrm) ||
		(IpC_Pk_Instrm_Child == instrm))
		{
		/* The packet did not come from the lower layer			*/
		packet_from_lower_layer = OPC_FALSE;
		}
	else
		{
		/* Packet is from the lower layer.						*/
		packet_from_lower_layer = OPC_TRUE;
		}

	/* Get a handle to the data structure stored in "fields"	*/
	/* field. This structure contains all the protocol header	*/
	/* information as well as some internal information 		*/
	/* attached to each IP datagram for simulation efficiency.  */
	op_pk_nfd_access (*pkpptr, "fields", &pk_fd_ptr);

	/* Check if this packet came from ISIS						*/
	if (pk_fd_ptr->protocol == IpC_Protocol_Isis)
		{
		/** If it is an ISIS PDU, don't do any IP processing	**/
		/** at all -- send the PDU out/up immediately.         	**/
		/** The IP protocol is used only as a delivery 			**/
		/** mechanism from the neighbor.						**/

		if (packet_from_lower_layer == OPC_FALSE)
			{
			ip_rte_isis_pdu_send (iprmd_ptr, *pkpptr);
			}
		else
			{
			ip_rte_isis_pdu_recv (iprmd_ptr, *pkpptr, instrm, pk_fd_ptr);
			}

		/* Return an OPC_FALSE so that it fools the parent		*/
		/* function into thinking that this pk was dropped		*/
		/* and that no further processing is necessary.			*/
		FRET (OPC_FALSE);
		}

	/* If the node containing this IP module is a firewall then */
	/* we need to check whether the arriving packet will be 	*/
	/* accepted by the proxy servers.							*/
	if ((iprmd_ptr->firewall_flag == OPC_TRUE) && 
		(packet_is_labeled	== OPC_FALSE) &&
		(!oms_dv_firewall_accept (*pkpptr, iprmd_ptr->proxy_info_table_lptr, &proxy_delay)))
		{
		/* The datagram could not make through the firewall.	*/
		/* Destroy the packet and update the statistics. Also	*/
		/* record that into the simulation log.					*/		
		ip_rte_dgram_discard (iprmd_ptr, *pkpptr, OPC_NIL, "Rejected at Firewall");
		ipnl_firewall_dgram_reject_log_write ();

		/* Indicate that the packet insertion failed.			*/
		FRET (OPC_FALSE);
		}

	/* Check IP VPN tunneling is enabled, there might be delay  */
	/* associated with encryption and decryption process.       */
	if ((iprmd_ptr->vpn_status == OPC_TRUE) &&
		(packet_is_labeled == OPC_FALSE)	&&
	    (OPC_TRUE == packet_from_lower_layer))
		{
		/* Get delay associated to VPN tunnel             		*/
		ip_rte_ip_vpn_tunnel_packet (iprmd_ptr, pkpptr, &vpn_delay);

		/* The pkpptr might be replaced by a new IP packet if   */
		/* compulsory tunnel is used, refresh the pk_fd_ptr     */
		op_pk_nfd_access (*pkpptr, "fields", &pk_fd_ptr);
		}

	/* Check GTP tunneling is enabled, there might be GTP delay */
	/* added 													*/
	if ((iprmd_ptr->gtp_status == OPC_TRUE) &&
		(packet_is_labeled == OPC_FALSE))
		{
		/* Get delay associated to the GTP tunnel.         		*/	
		gtp_delay = iprmd_ptr->ip_ptc_mem.gtp_delay;
		}

	/* Create an ICI and associate it with the datagram.	*/
	/* The ICI will carry information about the datagram	*/
	/* that will be used later when processing the packet	*/
	/* after queueing and forwarding to the output			*/
	/* interface.											*/
	intf_ici_ptr = op_ici_create ("ip_rte_ind_v4");

	/*	Create ip_rte_ind ICI fields data structure that 	*/
	/*	contains routing information which is used during	*/
	/* the life-cycle of the ICI in this process.			*/
	intf_ici_fdstruct_ptr = ip_rte_ind_ici_fdstruct_create ();
	*intf_ici_fdstruct_pptr = intf_ici_fdstruct_ptr;

	/*	Set the rte_info_fields in the ICI.	*/
	op_ici_attr_set (intf_ici_ptr, "rte_info_fields", intf_ici_fdstruct_ptr);

	/* If this node is configured as a firewall then the 	*/
	/* datagram may have an additional delay caused by		*/
	/* proxy server besides the routing delay. Associate	*/
	/* this delay, which is computed earlier, with the		*/
	/* packet. If the node is not a firewall then the delay	*/
	/* is always zero.										*/
	intf_ici_fdstruct_ptr->proxy_delay = proxy_delay;

	/* If VPN tunnel is enabled on this node. The vpn delay */
	/* may be added.Otherwise, delay is zero.               */
	intf_ici_fdstruct_ptr->vpn_delay   = vpn_delay;

	/* If GTP tunnel is enabled on this node. The GTP delay */
	/* may be added. Otherwise, delay is zero.              */
	intf_ici_fdstruct_ptr->gtp_delay   = gtp_delay;

	/* If this node is a load balancer, check whether this	*/
	/* packet is to be load balanced.						*/
	if (iprmd_ptr->load_balancer_enabled)
		{
		/* If the destination address equals the interface    */
		/* address, then it is destined for the load balancer */
		/* and should be processed.                           */
		if (ip_rte_load_balancer_packet_mine (pk_fd_ptr->dest_addr, iprmd_ptr, &output_table_index) == OPC_TRUE)
			{
			lb_addr = inet_ipv4_address_get (pk_fd_ptr->dest_addr);
			ip_rte_load_balancer_handle_packet (iprmd_ptr, pkpptr);
						
			/* If the source address has been set to  */
			/* OMSC_LOAD_BALANCER_ADDRESS_NONE or the */
			/* destination address is unchanged, then */
			/* there is an error.  Discard the packet */
			/* and warn the user.                     */
			if ((ip_address_equal (inet_ipv4_address_get (pk_fd_ptr->src_addr), OMSC_LOAD_BALANCER_ADDRESS_NONE)) ||
				(ip_address_equal (inet_ipv4_address_get (pk_fd_ptr->dest_addr), lb_addr)))
				{  
				ip_rte_load_balancer_log ();

				/* Since the load balancer did not know what*/
				/* to do with the packet, drop it.			*/
				ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Load Balancer Translation Error");

				/* Warns that the packet has not been accepted. */
				FRET (OPC_FALSE);
				}	
			}
		}	

	/*	Obtain the destination IP address information.			*/
	/* Do not use inet_address_copy because dest_addr is a		*/
	/* local variable.											*/
	dest_addr = pk_fd_ptr->dest_addr;
	
#ifdef OP_DEBUG2
	printf("\t Node %d - ip_rte_support.c - ip_rte_packet_arrival() - dest_addr = %u\n", 
			nodeid, dest_addr.address.ipv4_addr);
#endif
	
	multicast_dest_addr = inet_address_is_multicast (dest_addr);

	/* Find out whether this is an IPv4 packet of an IPv6 packet*/
	addr_family = inet_address_family_get (&dest_addr);

	/* Initialize the flag that stores whether this packet should	*/
	/* be forced to the lower layer to be false. A packet coming	*/
	/* from the higher layer in a LAN node should be forced to the	*/
	/* lower layer.													*/
	force_fwd = OPC_FALSE;

	/* Check if this packet came from a higher layer or from 	*/
	/* oms_basetraf_src.  Conceptually, both cases imply that 	*/
	/* this process must route the pk to the lower layers.		*/
	if (OPC_FALSE == packet_from_lower_layer)
		{
		/* Assign a unique identity to this packet - unique among	*/
		/* packets injected into the net by this host. This	is used	*/
		/* while reassembling data fragments on the destination.	*/
		/* However, oms_basetraf_src model set it to "-1" as bgutil	*/
		/* tracer packets never get fragmented.						*/
		/* Note: IP datagrams which are already assigned an			*/
		/* identifier (e.g. fragmented multicast data packets) may 	*/
		/* be received from ip_pim_sm child process. Datagrams which*/
		/* are not yet assigned an identifier will have their ident	*/
		/* field set to 0.											*/
		if ((pk_fd_ptr->ident != -1) && (pk_fd_ptr->ident == 0))
			{
			pk_fd_ptr->ident = iprmd_ptr->dgram_id++;
			}

		/* Indicate that the packet has not been processed yet.	*/
		/* This will be used while servicing the datagram in	*/
		/* the "svc_cmpl" state.								*/
		intf_ici_fdstruct_ptr->processed = OPC_FALSE;
		intf_ici_fdstruct_ptr->instrm = instrm;
		intf_ici_fdstruct_ptr->intf_recvd_index = iprmd_ptr->first_loopback_intf_index;

		/* Return NIL pointer if packet arrives from higher layer */
		*rcvd_iface_info_pptr = OPC_NIL;
			
		/* Set the packet insertion time.  This will be later	*/
		/* used to compute packet latency.						*/
		current_time = op_sim_time ();
		intf_ici_fdstruct_ptr->pkt_insertion_time = current_time;

		if (pk_fd_ptr->protocol == IpC_Protocol_Rsvp)
			{
			/* The packet is accompanied by an ICI. Get the ICI.	*/
			rsvp_ici_ptr = 	op_intrpt_ici ();
			}
		else if (multicast_dest_addr)
			{
			/**	The higher layer has specified multicast, so	**/
			/**	get the major and minor port information to 	**/
			/** which we want to send the multicast packet.		**/
			/** The major and minor port information will be	**/
			/** specified either in an ICI or in the			**/
			/** parent-to-child memory.							**/
			
			/* Check whether port information was specified		*/
			/* in the ICI										*/
			mcast_ici_ptr = op_intrpt_ici ();
			if (mcast_ici_ptr != OPC_NIL)
				{
				op_ici_attr_get (mcast_ici_ptr, "multicast_major_port", &mcast_major_port);
				op_ici_attr_get (mcast_ici_ptr, "multicast_minor_port", &mcast_minor_port);
			
				/* Destroy the multicast ICI.						*/
				op_ici_destroy (mcast_ici_ptr);
				} 
			else
				{
				/* The major and minor port information has been	*/
				/* specified in the parent-to-child memory.			*/
				mcast_major_port = iprmd_ptr->ip_ptc_mem.ip_igmp_ptc_info.major_port;	
				mcast_minor_port = iprmd_ptr->ip_ptc_mem.ip_igmp_ptc_info.minor_port;
				}				
							
			/* Store the multicast major and minor port information in	*/
			/* the ICI that will be associated with the packet			*/
			/* throughout its life cycle within IP.						*/
			intf_ici_fdstruct_ptr->multicast_major_port =  mcast_major_port;
			intf_ici_fdstruct_ptr->multicast_minor_port =  mcast_minor_port;
			}

		/* Check if this packet originated from one of the MANET	*/
		/* child processes.											*/
		if ((pk_fd_ptr->protocol == IpC_Protocol_Dsr) ||
			(pk_fd_ptr->protocol == IpC_Protocol_Tora))
			{
			/* This packet originated from either DSR or from TORA. */
			/* Appropriately set the boolean to indicate this.		*/
			packet_from_manet = OPC_TRUE;
			}	

		/* Check whether we need to set the force_fwd flag				*/
		if (iprmd_ptr->within_lan_node == OPC_TRUE)
			{
			/* The surrounding node is a LAN node. The IP datagram		*/
			/* should be forwarded to the lower layer, irrespective of	*/
			/* the ultimate destination.								*/
			force_fwd = OPC_TRUE;
			}
		}
	else
		{
#ifdef OP_DEBUG1
	op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &nodeid);
	printf("\t Node %d - ip_rte_support.c - ip_rte_packet_arrival() - packet from a lower layer\n", nodeid);
#endif
		
		/*	This packet came from a lower layer (e.g., ARP.)	*/
		/*	Check to see which interface it arrived on, so we	*/
		/*	can potentially forward this information to the		*/
		/*	higher layer (if the packet is eventually bound for	*/
		/*	the higher layer).									*/
		if (ip_rte_pk_rcvd_intf_tbl_indx_get (iprmd_ptr, instrm, pk_fd_ptr, 
					&minor_port_in, &input_intf_tbl_index) == OPC_COMPCODE_FAILURE)
			{
			ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Minor port could not be determined");
			FRET (OPC_FALSE);
			}

		/* Get a pointer to the interface information of the	*/
		/* corresponding interface.								*/
		iface_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, input_intf_tbl_index);
		*rcvd_iface_info_pptr = iface_info_ptr;

		/* Drop the packet if one of the following conditions is true.	*/
		/* 1. The interface is shutdown or								*/
		/* 2. The IP version of the packet is not enabled on this		*/
		/*    interface or												*/
		/* 3. The packet is an IPv4 packet and the interface is a		*/
		/* 	  No IP Address interface.									*/
		if ((ip_rte_intf_status_get (iface_info_ptr) == IpC_Intf_Status_Shutdown) ||
			(! ip_rte_intf_ip_version_active (iface_info_ptr, addr_family)) ||
			((InetC_Addr_Family_v4 == addr_family) && (ip_rte_intf_no_ip_address (iface_info_ptr))))
			{
			/* A "Shutdown" interface can't recieve traffic */
			/* Drop the packet and write log message. 		*/
			ipnl_shutdown_intf_recv_log_write (iprmd_ptr->node_id, ip_rte_intf_name_get (iface_info_ptr), op_pk_id (*pkpptr));
			ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Shutdown or No IP Address Interface");
					
			/* Return FALSE indicating packet was dropped */
			FRET (OPC_FALSE);
			}
		
		/* If the packet is a DSR or Tora packet, check if MANET is enabled	*/
		/* on this node. If not destroy the packet							*/
		if ((iprmd_ptr->manet_enabled == OPC_FALSE) && 
			((pk_fd_ptr->protocol == IpC_Protocol_Dsr) || (pk_fd_ptr->protocol == IpC_Protocol_Tora))
			)
			{
			/* The packet that arrived from the lower layer is a	*/
			/* DSR or Tora packet, but DSR is not enabled on this node.		*/
			/* Destroy the packet after writing a log message		*/			
			ip_nl_dsr_not_enabled_log_write ();
			ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "MANET packet received when MANET protocols are not running on this node");
			
			/* Return FALSE indicating packet was dropped */
			FRET (OPC_FALSE);
			}
		
		/* If any packet filter is configured for this interface	*/
		/* then check if the packet satisfies the packet filter		*/
		/* conditions. If no the this packet should be filtered out	*/
		/* and should be dropped									*/
		/* Do this check only if the packet is not a labeled packet	*/
		/* interface has some packet filter configured, and Ext ACL	*/
		/* is configured											*/
		
		if ((packet_is_labeled == OPC_FALSE) &&
			(iface_info_ptr->filter_info_ptr != OPC_NIL) &&
			(iface_info_ptr->filter_info_ptr->pre_filter_in != OPC_NIL) &&
			(packet_from_lower_layer == OPC_TRUE))		
			{
			/* Check if Packet passes the Packet filter, if no then	*/
			/* drop the packet										*/
			if (Inet_Acl_Apply_Packet (iface_info_ptr->filter_info_ptr->pre_filter_in, *pkpptr) == OPC_FALSE)
				{
				/* If this is a policy checker demand then output	*/
				/* the information that the packet is being dropped */	
				/* What happend to the flow in this life cycle		*/
				if (op_pk_encap_flag_is_set (*pkpptr, OMSC_SECURITY_ENCAP_FLAG_INDEX))
					ip_ot_security_demand_results_log (*pkpptr, iprmd_ptr->node_name, OPC_FALSE, 
						iface_info_ptr->filter_info_ptr->pre_filter_in->acl_list_id, iface_info_ptr->full_name);

				/* Packet does not pass the packet filter, drop		*/
				/* the packet										*/
				ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Dropped by Packet Filter");
					
				/* Return FALSE indicating packet was dropped 		*/
				FRET (OPC_FALSE);
				}
			}
				
		/* When the stream is found also get the slot	*/
		/* index of the interface.						*/
		if (OmsC_Dv_Slot_Based == iprmd_ptr->processing_scheme)
			{
			slot_index =  ip_rte_input_slot_index_determine (iprmd_ptr, iface_info_ptr, instrm);
			}
		else
			{
			slot_index = CENTRAL_CPU;
			}
            	
		/* Store the information about the interface	*/
		/* into the ICI.								*/
		intf_ici_fdstruct_ptr->interface_received = inet_rte_intf_addr_get (iface_info_ptr, addr_family);
		intf_ici_fdstruct_ptr->major_port_received = ip_rte_intf_addr_index_get (iface_info_ptr);
		intf_ici_fdstruct_ptr->intf_recvd_index = input_intf_tbl_index;
		intf_ici_fdstruct_ptr->slot_index = slot_index;
		intf_ici_fdstruct_ptr->instrm = instrm;

		/* Set additional information about the interface on which this	*/
		/* IP datagram arrived. This information may be used by the		*/
		/* higher layers (e.g., routing protocols like IGRP)			*/
		intf_ici_fdstruct_ptr->mtu 					= inet_rte_intf_mtu_get (iface_info_ptr, addr_family);
		intf_ici_fdstruct_ptr->iface_load 			= ip_rte_intf_load_bps_get (iface_info_ptr);
		intf_ici_fdstruct_ptr->iface_reliability 	= ip_rte_intf_reliability_get (iface_info_ptr);
		intf_ici_fdstruct_ptr->iface_speed 		    = ip_rte_intf_link_bandwidth_get (iface_info_ptr);

		/* Set the minor port information.				*/
		intf_ici_fdstruct_ptr->minor_port_received	= minor_port_in;

		/* Set the packet insertion time.  This will be	*/
		/* later used to compute packet latency.		*/
		intf_ici_fdstruct_ptr->pkt_insertion_time = op_sim_time ();

		/* Set the processed field of ICI to false to	*/
		/* indicate that the packet is freshly received	*/
		/* and not processed yet.						*/
		intf_ici_fdstruct_ptr->processed = OPC_FALSE;

		/*	Issue trace statement.						*/
		if ((ip_rte_trace == OPC_TRUE) && op_prg_odb_pktrace_active (*pkpptr))
			{
			intf_addr_str = inet_address_str_mem_alloc ();
			ip_address_print (intf_addr_str, iface_info_ptr->addr_range_ptr->address);
			if (iprmd_ptr->processing_scheme == OmsC_Dv_Slot_Based)
				{
				sprintf (trace_msg, "Packet ID (" SIMC_PK_ID_FMT ") [Tree ID " SIMC_PK_ID_FMT "] arrived on interface %s slot %d",
					op_pk_id (*pkpptr), op_pk_tree_id (*pkpptr), intf_addr_str, slot_index);
				}
			else
				{
				sprintf (trace_msg, "Packet ID (" SIMC_PK_ID_FMT ") [Tree ID " SIMC_PK_ID_FMT "] arrived on interface %s",
					op_pk_id (*pkpptr), op_pk_tree_id (*pkpptr), intf_addr_str);
				}

			/* Print the trace message.					*/
			op_prg_odb_print_minor (trace_msg, OPC_NIL);
			op_prg_mem_free (intf_addr_str);
			}

		/* IF CAR (Committed Access Rate) is enabled on this interface*/
		/* check whether this packet conforms the traffic contract.	  */
		/* If it doesn't, this packet might be dropped or set to a low*/
		/* type of service (TOS).									  */
		
		/* In case of uni-directional tunnels, a tunnel interface may	*/
		/* not be found in the outgoing direction. In that case, the	*/
		/* received interface table index will correspond to a loopback	*/
		/* interface, which does not have a CAR profile. Hence, we must	*/
		/* check for the presence of a CAR profile on the interface.	*/
		
		if (packet_is_labeled == OPC_FALSE &&
			iprmd_ptr->car_incoming_profile_ptr [input_intf_tbl_index] != OPC_NIL &&
			iprmd_ptr->car_incoming_profile_ptr [input_intf_tbl_index]->car_status == OPC_TRUE)
			{
			/* Returns whether the packet has to dropped to follow the*/
			/* policy. If the packet doesn't comply the policy, it is */
			/* necessarily dropped but only set to a lower precedence.*/
			car_packet_drop = Ip_Qos_Car_Policy_Limit (*pkpptr, input_intf_tbl_index, 
				iprmd_ptr->car_incoming_profile_ptr [input_intf_tbl_index], 
				iprmd_ptr->car_incoming_info_ptr [input_intf_tbl_index]);

			/* If the packet did not match a CAR policy specifiyng that	*/
			/* all non-conforming traffic has to be dropped, the packet	*/
			/* is dropped.												*/
			if (car_packet_drop)
				{
				/* Write a statistic for packet dropped on this interface.	*/
				op_stat_write (iprmd_ptr->car_stat_info_ptr [input_intf_tbl_index].in_traffic_dropped_in_bps_stathandle, 
					op_pk_total_size_get (*pkpptr));
				op_stat_write (iprmd_ptr->car_stat_info_ptr [input_intf_tbl_index].in_traffic_dropped_in_bps_stathandle, 0);

				op_stat_write (iprmd_ptr->car_stat_info_ptr [input_intf_tbl_index].in_traffic_dropped_in_pps_stathandle, 1);
				op_stat_write (iprmd_ptr->car_stat_info_ptr [input_intf_tbl_index].in_traffic_dropped_in_pps_stathandle, 0);

				if (op_prg_odb_ltrace_active ("car"))
					{
					sprintf (str0, "CAR drops packet " SIMC_PK_ID_FMT " to conform rate policies.", op_pk_id (*pkpptr));
					op_prg_odb_print_major (str0, OPC_NIL);
					}

				/* Drop the current IP datagram.	*/
				ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Rejected on CAR policy violation");

				/* Warns that the packet has not been accepted.	*/
				FRET (OPC_FALSE);
				}
            }
		}
	
	/*	If the received packet does not yet have a time-to-live	*/
	/*	field assignment, place the default value in this field	*/
	/*	In this model, TTL is treated as a hop allowance		*/
	/*	decremented by one prior to each transmission. If the	*/
	/*	decremented counter reaches zero, the packet is not		*/
	/*	transmitted.											*/
	if (pk_fd_ptr->ttl == IPC_TTL_UNSET)
		{
		pk_fd_ptr->ttl = IPC_DEFAULT_TTL;
		}

	/* Determine the interface to which the packet should be	*/
	/* forwarded. Store this information within the ICI since	*/
	/* it will be also used in the svc_comp state.				*/
	
   	/* Check if MPLS is enabled on this node or Check if		*/
	/* this node is a PE for any VPN.							*/
	if ((iprmd_ptr->mpls_status == OPC_TRUE) || (iprmd_ptr->pe_status == OPC_TRUE))
		{
		/* First check if this packet matches any of the FEC 	*/
		/* configured on this router interface					*/
		
		/* Or if this packet is coming from any					*/
		/* VPN site and etering the MPLS core or 				*/
		/* Is it coming from core and entering	the VPN site.	*/
		
		if (packet_is_labeled == OPC_FALSE) 
			{
			/* Not a labeled packet 							*/
			fec_name = ip_mpls_packet_classify (iprmd_ptr, *pkpptr, 
				intf_ici_fdstruct_ptr->intf_recvd_index);
			
			if (op_prg_odb_ltrace_active ("mpls_ip"))
				{
				if (fec_name != OPC_NIL)
					sprintf (msg0, "FEC Name = %s", fec_name);
				else
					strcpy (msg0, "FEC Name = OPC_NIL");
				
				op_prg_odb_print_major ("<ip_rte_packet_arrival>",
							msg0, OPC_NIL);
				}
			
			/* Check if the packet is for a VPN and do it only	*/
			/* if the destination address is not this nodes		*/
			/* local address									*/
			if ((iprmd_ptr->pe_status == OPC_TRUE) &&
				(inet_rte_is_local_address (pk_fd_ptr->dest_addr, iprmd_ptr, OPC_NIL) == OPC_FALSE))
				{
				/* Packet may be coming from a VPN site and 	*/
				/* may be entering the MPLS core.				*/
				/* Find the VRF tabel that it belongs to		*/
				vrf_name = ip_vpn_packet_classify (iprmd_ptr, *pkpptr, 
					intf_ici_fdstruct_ptr->intf_recvd_index);
				
				if (op_prg_odb_ltrace_active ("mpls_ip"))
					{
					if (vrf_name != OPC_NIL)
						sprintf (msg0, "VPN Name = %s", vrf_name);
					else
						strcpy (msg0, "VPN Name = OPC_NIL");
					
					op_prg_odb_print_major ("<ip_rte_packet_arrival>",
						msg0, OPC_NIL);
					}
				}
			}

		if ((fec_name != OPC_NIL) || 
			(packet_is_labeled == OPC_TRUE) ||
			(vrf_name != OPC_NIL))
			{
			/* We are dealing with a packet that is mpls bound	*/
			intf_ici_fdstruct_ptr->mpls_redirect = OPC_TRUE;
			
			/* Set the Packet Labeled flag in Intf ICI			*/
			intf_ici_fdstruct_ptr->packet_is_labeled = packet_is_labeled;
			
			/* set the FEC name in the ICI						*/
			intf_ici_fdstruct_ptr->mpls_fec_name = fec_name;

			/* set the VRF name in the ICI						*/
			intf_ici_fdstruct_ptr->pe_vrf_name = vrf_name;

			/* Set the ICI.		*/		
			op_pk_ici_set (*pkpptr, intf_ici_ptr);

			/* Fill in return values */
			*intf_ici_fdstruct_pptr = intf_ici_fdstruct_ptr;
			*rcvd_iface_info_pptr = iface_info_ptr;

			FRET (OPC_TRUE);
			}
		}

	/* Check if any Policy Routing is to be applied on the packets				*/
	if ((packet_is_labeled == OPC_FALSE) &&
		(iprmd_ptr->rte_map_table != OPC_NIL))		
		{
		/* If the packet is from lower layer then get the policy name from		*/
		/* the interface else get the local policy name							*/ 
		if (packet_from_lower_layer == OPC_TRUE)
			{
			/* Get the Iface policy name										*/
			if (iface_info_ptr != OPC_NIL)
				{
				policy_name = iface_info_ptr->policy_routing_name;
				
				strcpy (iface_name_str, iface_info_ptr->full_name);
				}
			}
		else
			{
			policy_name = iprmd_ptr->local_policy_name;
			strcpy (iface_name_str, "Local");
			}
		
		/* Apply the Route map configured in Policy Routing						*/
		if (policy_name != OPC_NIL)
			{
			/* Apply the route map policy to the packet							*/	
			Ip_Rte_Map_Packet_Apply (iprmd_ptr, policy_name, *pkpptr,
				ip_rte_support_packet_match, ip_rte_support_packet_alter,
				&rte_map_next_addr, &rte_map_output_table_index, &route_table_lookup, 
				iface_name_str);
			}
		}
		
	if (route_table_lookup != IpC_Bypass_Rte_Table_Lookup)
		{
		/*	Determine the interface the datagram should be forwarded to.	*/
		/*	Also determine whether the datagram should be broadcast, and/or	*/
		/*	the datagram should be forwarded to the higher layer.			*/
#ifdef OP_DEBUG1
	op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &nodeid);
	printf("\t Node %d - ip_rte_support.c - ip_rte_packet_arrival() - Determine which interface to forward\n", nodeid);
#endif

		if (multicast_dest_addr)
			{
			got_datagram_info = ip_rte_mcast_datagram_dest_get (iprmd_ptr, *pkpptr, 
				rsvp_ici_ptr, intf_ici_fdstruct_ptr, dest_addr, &next_addr, &broadcast,
				&higher_layer, &destroy_pkt, pk_fd_ptr->protocol, &output_table_index, 
				&interface_ptr);	
		
			/* Set the pkt_dest_type to multicast						*/
			intf_ici_fdstruct_ptr->pkt_dest_type = IPC_PKT_TXTYPE_MCAST;
			
			/* Create temporary port_info */
			output_port_info = ip_rte_port_info_create (output_table_index, OPC_NIL);
			}
		else
			{
			got_datagram_info = ip_rte_datagram_dest_get (iprmd_ptr, *pkpptr, 
				rsvp_ici_ptr, force_fwd, dest_addr, instrm, 
				pk_fd_ptr->protocol, &next_addr, &lsp_name_str, &broadcast, 
				&higher_layer, &destroy_pkt, &output_port_info, &interface_ptr, 
				&num_tracer_info, &tracer_info_array, &drop_reason_str, &src_proto);
			
			/* Cache the output interface index	*/
			output_table_index = output_port_info.intf_tbl_index;
		
			/* set the pkt_dest_type accordingly						*/
			if (broadcast)
				intf_ici_fdstruct_ptr->pkt_dest_type = IPC_PKT_TXTYPE_BCAST;
			else
				intf_ici_fdstruct_ptr->pkt_dest_type = IPC_PKT_TXTYPE_UCAST;
			}
		}
	
	/* If Rte lookup was bypassed or if defaults were not allowed by	*/
	/* rte map and defaults were returned, then use the next hops given	*/
	/* by rte map														*/
	/* Route_table_lookup can have three different values depending on	*/
	/* what set clause is configured for the route maps. It can be:		*/
	/* IpC_Bypass_Rte_Table_Lookup: If Rte map alter the out going 		*/
	/* interface name or address. In this case there is no need to		*/
	/* do a IP Cmn rte table lookup.									*/
	/* IpC_Rte_Table_Lookup_Use_No_Defaults: If Rte map alter the 		*/
	/* default out going interface name or address. In this case there	*/
	/* is need to do a IP Cmn rte table lookup but if it return			*/
	/* default or no rte then Rte map defaults will be used				*/
	/* IpC_Rte_Table_Lookup: For regular IP Cmn rte table lookup		*/
	if ((route_table_lookup == IpC_Bypass_Rte_Table_Lookup) ||
		((route_table_lookup == IpC_Rte_Table_Lookup_Use_No_Defaults) &&
		((IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (src_proto) == IPC_DYN_RTE_DEFAULT) ||
		 (!inet_address_valid (next_addr)))))	
		{
#ifdef OP_DEBUG1
		printf("\tip_rte_support - route_table_lookip = BYPASS\n");
#endif
		/* Use the next address returned by the Route Map				*/
		inet_address_destroy (next_addr);
		/* Do not use inet_address_copy as Ip_Rte_Map_Packet_Apply would*/
		/* have used it internally.										*/
		next_addr 			= rte_map_next_addr;
		output_table_index 	= rte_map_output_table_index;
		output_port_info	= ip_rte_port_info_create (output_table_index, OPC_NIL);
		
		/* If the out put interface is invalid then drop the packet		*/
		if ((output_table_index == IPC_INTF_INDEX_INVALID) || 
			(!inet_address_valid (rte_map_next_addr)))
			{
			/* Drop this denied IP datagram									*/
			ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Dropped by Policy Routing");
				
			FRET (OPC_FALSE);
			}
							
		/* Find the interface pointer.									*/
		interface_ptr = inet_rte_intf_tbl_access (iprmd_ptr, output_table_index);
		
		/* Do not destroy the packet even if Rte table lookup indicated	*/
		/* the packet to be destroyed. This is done because we are		*/
		/* using default route from the Policy routing. Thus if Rte		*/
		/* table lookup fails to find a rte and does not even have 		*/
		/* a default route then it will mark the packet to be destroyed	*/
		/* but we do not want that.										*/ 
		destroy_pkt 				= OPC_FALSE;
		
		/* Set Got Data gram info to SUCCESS							*/
		got_datagram_info = OPC_COMPCODE_SUCCESS;
		}

	/* Handling for the MANET case */
	if ((iprmd_ptr->manet_enabled == OPC_TRUE) && (packet_from_manet == OPC_FALSE))
		{
		if ((packet_from_lower_layer == OPC_FALSE) && (iprmd_ptr->manet_rte_protocol == IpC_Rte_Dsr))
			{
			/* The following are the conditions to send a packet to DSR	*/
			/* 1. If the packet is from the higher layer (application),	*/
			/*    always send the packet to the DSR process if DSR has 	*/
			/*    been enabled on this node.							*/
			/* 2. If the packet is from the DSR child process, never 	*/
			/*    send the packet back to the DSR process.				*/
			/* 3. If the packet is from the lower layer and DSR is 		*/
			/*    enabled on the node, send the packet to DSR if the	*/
			/*    protocol type in the IP datagram is set to DSR. If	*/
			/*    the protocol type is not set to DSR, send the packet	*/
			/*    directly to the higher layer.							*/
			intf_ici_fdstruct_ptr->manet_redirect = OPC_TRUE;
			}
		else if ((iprmd_ptr->manet_rte_protocol == IpC_Rte_Tora))
			{
			/* The MANET routing protocol is TORA.								 	*/
			/* 1. If it is an application layer packet and no route is available 	*/
			/*    then hand over packet to TORA until a route is found				*/
			/* 2. If it is a lower layer packet and no route is available, then  	*/
			/*    hand over the packet to TORA until a route is found			 	*/
			/* 3. If it is a packet meant for this node, and the protocol type is	*/
			/*    TORA (some control packets are unicast) then again redirect the	*/
			/*    packet to TORA.												 	*/
			if (got_datagram_info == OPC_COMPCODE_FAILURE)
				intf_ici_fdstruct_ptr->manet_redirect = OPC_TRUE;
			
			if ((interface_ptr == OPC_NIL) && ((pk_fd_ptr->protocol == IpC_Protocol_Tora)))
				intf_ici_fdstruct_ptr->manet_redirect = OPC_TRUE;
			}
		}
	
	/* If no rte was found and the node is not manet enabled then discard the packet	  */
	/* -- otherwise, the packet will be given to Manet for further routing and processing */
	if ((got_datagram_info == OPC_COMPCODE_FAILURE) && (intf_ici_fdstruct_ptr->manet_redirect == OPC_FALSE))
		{
#ifdef OP_DEBUG1
	op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &nodeid);
	printf("\t Node %d - ip_rte_support.c - ip_rte_packet_arrival() - NO Route found. Crop\n", nodeid);
#endif
		/*	Issue a trace message and destroy the packet.				*/
		if (ip_rte_trace == OPC_TRUE)
			{
			dest_addr_str = inet_address_str_mem_alloc ();
			inet_address_print (dest_addr_str, dest_addr);
			sprintf (str0, 
				"Routing error: Unable to route packet destined for (%s)", 
				dest_addr_str);
			op_prg_odb_print_major (str0, OPC_NIL);
			op_prg_mem_free (dest_addr_str);
			}
		
		/* Drop this unroutable IP datagram								*/
		ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Routing Blackhole");

		inet_address_destroy (next_addr);

		FRET (OPC_FALSE);
		}   
	   
	if (ip_rte_trace == OPC_TRUE)
		{
		dest_addr_str = inet_address_str_mem_alloc ();
		inet_address_print (dest_addr_str, dest_addr);
		/* Print a trace message.									*/
		sprintf (str0, "Received Packet to %s", dest_addr_str);
		op_prg_odb_print_major (str0, OPC_NIL);
		if (destroy_pkt)
			{
			printf ("\tPacket will be destroyed.\n");
			}
		else 
			{
			if (packet_from_lower_layer)
				{
				printf ("\tThe packet was received on Interface %s\n", 
					ip_rte_intf_name_get (iface_info_ptr));
				}
			else
				{
				printf ("\tPacket came from the higher layer\n");
				}
			printf ("\tTTL Field of the packet is %d\n", pk_fd_ptr->ttl);
			if (broadcast)
				{
				printf ("\tIt is a broadcast packet.\n");
				}
			if (higher_layer)
				{
				printf ("\tIt will be forwarded to the higher layer\n");
				}
			else
				{
				/* Check to make sure we have a valid interface.	*/
				/* If the packet is being forwarded on an LSP, then	*/
				/* the interface ptr is OPC_NIL.					*/
				if ((!broadcast)&& (OPC_NIL != interface_ptr))
					{
					inet_address_print (dest_addr_str, next_addr);
					printf ("\tIt will be forwarded to %s via %s\n", 
						dest_addr_str, ip_rte_intf_name_get (interface_ptr));
					}
				}
			printf ("\n");
			}
		op_prg_mem_free (dest_addr_str);
		}
	
	/* What kind of packet are we dealing with?	*/
	pkt_dest_type = intf_ici_fdstruct_ptr->pkt_dest_type;

	/*	If the packet was received from the lower layer, call the	*/
	/*	that would update the packet received stats.				*/
	if (OPC_TRUE == packet_from_lower_layer)
		{
		/* Update stats.											*/
		ip_rte_total_packets_received_stat_update (iprmd_ptr, pkt_dest_type, *pkpptr, addr_family);
		}

	/*	Obtain the fast address from the packet if it is set. This	*/
	/*	should only be done if no broadcast addresses are involved,	*/
	/*	because fast addresses are assigned only to addresses whose	*/
	/*	IP addresses are not broadcast addresses.					*/

	/* Check to see if a NATO fast lookup index is associated with	*/
	/* the destination IP address. If it is not, obtain one from	*/
	/* NATO package and set the corresponding field in the packet.	*/
	/* Do not do fast lookup for RSVP packets.						*/
	if ((IPC_PKT_TXTYPE_UCAST == pkt_dest_type) &&
		(pk_fd_ptr->protocol != IpC_Protocol_Rsvp) &&
		(pk_fd_ptr->dest_internal_addr == IPC_FAST_ADDR_INVALID))
		{
		/*	Obtain the fast address from the global table.		*/
		pk_fd_ptr->dest_internal_addr = inet_rtab_addr_convert (dest_addr);
   		}

	/* Check to see if the interface chosen to forward the datagram */
	/* has been set as a Shutdown Interface 						*/
	if (interface_ptr != OPC_NIL)
		{
		if (ip_rte_intf_status_get (interface_ptr) == IpC_Intf_Status_Shutdown)
			{
			/* An IP datagram cannot be forwarded over a Shutdown interface */
			/* Write the appropriate sim log message and drop the packet	*/
			ipnl_shutdown_intf_send_log_write (iprmd_ptr->node_id, 
				ip_rte_intf_addr_index_get (interface_ptr), op_pk_id (*pkpptr));
			ip_rte_dgram_discard (iprmd_ptr, *pkpptr, intf_ici_ptr, "Rejected at Shutdown Interface");
			inet_address_destroy (next_addr);

			FRET (OPC_FALSE);
			}
		}
	
	/* Check if any IP options have been set -- e.g., record route	*/
	/* option. If set, then process the options.					*/
	/* If it is a global broadcast packet generated by this node,	*/
	/* do not process the options yet. They will be processed after	*/
	/* copies of the packet have been made.							*/
	if ((pk_fd_ptr->options_field_set == OPC_TRUE) &&
		(output_table_index != IP_BROADCAST_ALL_INTERFACES) &&
		(output_table_index >= 0) &&
		(OPC_FALSE == destroy_pkt))
		{
		/* It is required to set certain options in the IP datagram	*/
		ip_rte_dgram_options_process (iprmd_ptr, *pkpptr, output_table_index);
		}

	/* Place the information collected into the ICI that is			*/
	/* associated with the packet. This information will be also 	*/
	/* used in the svc_comp state to forward the packet to the 		*/
	/* output interface. In case of the packet to be broadcasted,	*/
	/* only the broadcast index is of use and the interface_ptr		*/
	/* does not point to a valid memory area.						*/
	if (interface_ptr != OPC_NIL)
		{
		intf_ici_fdstruct_ptr->interface_type = ip_rte_intf_type_get (interface_ptr);
		intf_ici_fdstruct_ptr->outstrm 		  = ip_rte_intf_out_port_num_get (interface_ptr);
		intf_ici_fdstruct_ptr->outslot 		  = ip_rte_intf_slot_index_get (interface_ptr);
		intf_ici_fdstruct_ptr->output_mtu 	  = inet_rte_intf_mtu_get (interface_ptr, addr_family);
		intf_ici_fdstruct_ptr->iface_speed 	  = ip_rte_intf_link_bandwidth_get (interface_ptr);
		}
        	
	/* Fill the rest of the ICI fields with generic packet info.	*/
	intf_ici_fdstruct_ptr->dest_addr 			= inet_address_copy (dest_addr);
	/* No need to use inet_address_copy for the next_addr because 	*/
	/* it would have been allocated separate memory earlier.		*/
	intf_ici_fdstruct_ptr->next_addr 			= next_addr;
	intf_ici_fdstruct_ptr->broadcast 			= broadcast;
	intf_ici_fdstruct_ptr->higher_layer 		= higher_layer;
	intf_ici_fdstruct_ptr->destroy_pkt 			= destroy_pkt;
	intf_ici_fdstruct_ptr->output_intf_index 	= output_table_index;
	intf_ici_fdstruct_ptr->output_subintf_index = 
			ip_rte_minor_port_from_port_info_get (iprmd_ptr, output_port_info);
	
	if (drop_reason_str != OPC_NIL)
		intf_ici_fdstruct_ptr->drop_reason = drop_reason_str;
	
	/* Setting the mpls_redirect flag now. */
	if (output_table_index == IPC_INTF_TBL_INDEX_LSP)
		{
		/* This packet is using a LSP as its next hop (IGP shortcut)	*/
		/* to reach its destination node.								*/
				
		if (ip_mpls_lsp_status_get (iprmd_ptr, lsp_name_str, 
				intf_ici_fdstruct_ptr->intf_recvd_index) == OPC_TRUE)
			{
			/* Check the status of LSP, if it still exists. */			
			/* Redirect the packet to MPLS  */			
			intf_ici_fdstruct_ptr->mpls_redirect = OPC_TRUE;		
			intf_ici_fdstruct_ptr->mpls_fec_name = lsp_name_str;		
			intf_ici_fdstruct_ptr->pe_vrf_name = OPC_NIL;
			}
		else
			{
			/* Routing table has not been re-computed since a LSP has been 	*/
			/* torn down. Although a IGP shortcut exists, it is invalid.	*/
			intf_ici_fdstruct_ptr->mpls_redirect = OPC_FALSE;		
			intf_ici_fdstruct_ptr->mpls_fec_name = OPC_NIL;		
			intf_ici_fdstruct_ptr->pe_vrf_name = OPC_NIL;			
			intf_ici_fdstruct_ptr->destroy_pkt = OPC_TRUE;
			}
		}
	
	/* Also store any background utilization tracer packet info	*/
	/* for multiple forwarding.									*/
	intf_ici_fdstruct_ptr->num_tracer_info = num_tracer_info;
	intf_ici_fdstruct_ptr->tracer_info_array = tracer_info_array;

	/* Check whether the packet should be decompressed.			*/
	/* Decompression is necessary if:							*/
	/* a) Packet is compressed with TCP/IP Header compression.	*/
	/* b) Packet is compressed with Per Interface compression	*/
	/*    (entire packet compressed).           				*/
	/* c) Packet is compressed with Per Virtual Circuit 		*/
	/*    compression (payload compressed) and this node is the */
	/*    destination of the datagram; i.e. datagram will be 	*/
	/*    forwarded to higher layer.							*/ 
	if ((pk_fd_ptr->compression_method == IpC_TCPIP_Header_Comp) ||
		(pk_fd_ptr->compression_method == IpC_Per_Interface_Comp) ||
		((pk_fd_ptr->compression_method == IpC_Per_Virtual_Circuit_Comp) && (higher_layer)))
		{
		/* Decompression is necessary. Compute its delay.		*/
		decomp_delay = ip_rte_decomp_delay_compute (*pkpptr, pk_fd_ptr);

		/* If we will decompress the payload then we need to 	*/
		/* also update the frag_len field to reflect the size	*/
		/* of the payload correctly.							*/
		if (pk_fd_ptr->compression_method == IpC_Per_Virtual_Circuit_Comp)
			{
			packet_size = op_pk_total_size_get (*pkpptr);
			pk_fd_ptr->frag_len = (pk_fd_ptr->original_size - (packet_size - pk_fd_ptr->frag_len * 8)) / 8;
			}

		/* Reset the compression flag.							*/
		pk_fd_ptr->compression_method = IpC_No_Compression;
        	
		/* Set the decompression flag so that the packet is set	*/
		/* to its original size after service completion.		*/
		intf_ici_fdstruct_ptr->decompress = OPC_TRUE;
		}
	else
		{
		/* The packet is not compressed */
		decomp_delay = 0.0;
		}	

	/* If the datagram will be serviced once  (i.e. central		*/
	/* processing or port-to-port forward) and a compression 	*/
	/* will be applied then we need to compute also the			*/
	/* compression delay now, so that it can be added to the	*/
	/* service time in the "svc_start" state. Datagrams to be	*/
	/* forwarded to higher layer are not compressed, and		*/
	/* broadcast datagrams to be forwarded to all interfaces 	*/
	/* are compressed per interface basis after they are		*/
	/* duplicated.												*/
	if (((iprmd_ptr->processing_scheme == OmsC_Dv_Centralized) || 
		 ((slot_index == intf_ici_fdstruct_ptr->outslot) && 
		  (intf_ici_fdstruct_ptr->outslot != -1))) && 
        (!broadcast || 
		 (output_table_index != IP_BROADCAST_ALL_INTERFACES)) && 
		(!higher_layer))
		{
		/* Datagram will be serviced once. 						*/
		/* First determine whether we use compression at the	*/
		/* output interface.									*/
    	
		/* If compression is used then compute its delay. If 	*/
		/* the compression will not be applied then the 		*/
		/* function will return 0.0. The function will also		*/
		/* store the new size into ICI if the datagram will be	*/
		/* compressed. First determine whether we use 			*/
		/* compression at the output interface.					*/
		if ((interface_ptr == OPC_NIL) || 
			(interface_ptr->comp_info == OPC_NIL) || 
			(interface_ptr->comp_info->method == IpC_No_Compression))
			comp_delay = 0.0;
		else
			comp_delay = ip_rte_comp_delay_and_size_compute (iprmd_ptr, *pkpptr, 
				pk_fd_ptr, intf_ici_ptr, interface_ptr);
		}

	/* Store the compression & decompression delays into the	*/
	/* if they exists. These delays be added later to the 		*/
	/* service time in the "svc_start" state.					*/
	if (comp_delay + decomp_delay != 0.0) 
		intf_ici_fdstruct_ptr->comp_decomp_delay = comp_delay + decomp_delay;

	/* Set the ICI.		*/		
	op_pk_ici_set (*pkpptr, intf_ici_ptr);

	/* Fill in return values */
	*intf_ici_fdstruct_pptr = intf_ici_fdstruct_ptr;

	FRET (OPC_TRUE);
	}

void		
ip_rte_packet_send (IpT_Rte_Module_Data* module_data_ptr, Packet* pkptr, 
	Ici* pk_ici_ptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr,
	IpT_Rte_Process_Type process_type, void* process_info_ptr)
	{
	Packet 					*pk_copy_ptr;
	Ici 					*pk_ici_copy_ptr;
	IpT_Rte_Ind_Ici_Fields  *intf_ici_fdstruct_copy_ptr;
	IpT_Interface_Info		*output_intf_info_ptr, *input_intf_info_ptr;
	char					msg0 [256], msg1 [256];
	int						nodeid; 
	/** Once the ip datagram has been processed by the routing	**/
	/** process, this function is called to forward it 			**/
	/** appropriately.											**/

	FIN (ip_rte_packet_send (module_data_ptr, pkptr, intf_ici_fdstruct_ptr, process_type));

#ifdef OP_DEBUG1
		op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &nodeid);

	printf("\t Node %d - ip_rte_support.c - ip_rte_packet_send()\n", nodeid);
#endif
	/* Information regarding the next destination of the datagram	*/
	/* is obtained in "arrival" function and stored into the ICI 	*/
	/* that	is associated with the datagram.						*/ 
	
	/* If the packet is not to be destroyed, then process it further*/
	if (!intf_ici_fdstruct_ptr->destroy_pkt)
		{
		if (module_data_ptr->mobile_ip_enabled)
			{
			if (mip_sup_packet_check (module_data_ptr, pkptr, intf_ici_fdstruct_ptr)
				== OPC_COMPCODE_SUCCESS)
				{
				/* This packet is being handled by Mobile IP process. */
				FOUT;
				}
			}

		if (intf_ici_fdstruct_ptr->manet_redirect == OPC_TRUE)
			{
			/* The packet needs to be sent to the MANET routing		*/
			/* Forward the packet to the MANET manager 				*/
		  	op_pro_invoke (module_data_ptr->manet_mgr_prohandle, pkptr);
			}
		
		/*  The packet is not to be destroyed. Process it based on  */
		/*  the type of packet.                                     */
		else if (intf_ici_fdstruct_ptr->higher_layer)
			{
			/* The packet needs to be forwarded to the higher layer	*/

			/* If this packet is a remote subnet level broadcast,	*/
			/* we need to copy the packet, forward one copy to the	*/
			/* higher layer and broadcast the other on the			*/
			/* appropriate interface. Check for this condition.		*/
			/* If the destination address of a broadcast packet is	*/
			/* neither the subnet level broadcast address nor the	*/
			/* global broadcast address, it is a remote subnet		*/
			/* broadcast											*/
			if ((intf_ici_fdstruct_ptr->broadcast) &&
				(!inet_address_equal (intf_ici_fdstruct_ptr->dest_addr, InetI_Broadcast_v4_Addr) &&
				(!inet_address_equal (intf_ici_fdstruct_ptr->dest_addr, InetI_Ipv6_All_Nodes_LL_Mcast_Addr))))
				{
				/* This is a subnet level broadcast packet. i.e. the*/
				/* destination address of the packet is the subnet	*/
				/* broadcast address of the primiary or secondary	*/
				/* addresses of the interface specified by the 		*/
				/* output_intf_index. If the packet was received 	*/
				/* on a different interface, it is a remote subnet 	*/
				/* level broadcast and the packet needs to be 		*/
				/* handled as described above.						*/
				/* Note that we should never broadcast a packet back*/
				/* on the interface it was received on. 			*/
				/* RFC 919 Sec. 6 Gateways and Broadcasts.			*/

				/* If the input and output interface indices are	*/
				/* different. Send a copy of the packet to the lower*/
				/* layer. The original packet will be forwarded to	*/
				/* the higher layer.								*/
				if (intf_ici_fdstruct_ptr->output_intf_index != intf_ici_fdstruct_ptr->intf_recvd_index)
					{
					/* This is a remote subnet level broadcast. Create	*/
					/* a copy of the packet to be broadcasted on the	*/
					/* appropriate interface.							*/
					pk_copy_ptr = op_pk_copy (pkptr);

					/* Also create a new ip_rte_ind_v4 ici and associate*/
					/* it with the packet copy.							*/
					pk_ici_copy_ptr = op_ici_create ("ip_rte_ind_v4");
					op_pk_ici_set (pk_copy_ptr, pk_ici_copy_ptr);

					/* Also create a copy of the structure in the ici	*/
					/* and make the necessary modifications.			*/
					intf_ici_fdstruct_copy_ptr = ip_rte_ind_ici_fdstruct_copy (intf_ici_fdstruct_ptr);
					output_intf_info_ptr = inet_rte_intf_tbl_access (module_data_ptr,
						intf_ici_fdstruct_ptr->output_intf_index);
					intf_ici_fdstruct_copy_ptr->interface_type	= ip_rte_intf_type_get (output_intf_info_ptr);
					intf_ici_fdstruct_copy_ptr->outstrm 	  	= ip_rte_intf_out_port_num_get (output_intf_info_ptr);
					intf_ici_fdstruct_copy_ptr->outslot 		= ip_rte_intf_slot_index_get (output_intf_info_ptr);
					intf_ici_fdstruct_copy_ptr->output_mtu 	  	= inet_rte_intf_mtu_get (output_intf_info_ptr, InetC_Addr_Family_v4);
					intf_ici_fdstruct_copy_ptr->iface_speed 	= ip_rte_intf_link_bandwidth_get (output_intf_info_ptr);
					intf_ici_fdstruct_copy_ptr->higher_layer 	= OPC_FALSE;

					if (LTRACE_IP_ACTIVE)
						{
						/* Print a trace message.						*/
						input_intf_info_ptr = ip_rte_intf_tbl_access (module_data_ptr, intf_ici_fdstruct_ptr->intf_recvd_index);
						sprintf (msg0, "The packet was received on %s", ip_rte_intf_name_get (input_intf_info_ptr));
						sprintf (msg1, "The packet is being sent on %s", ip_rte_intf_name_get (output_intf_info_ptr));
						
						op_prg_odb_print_major ("<ip_rte_packet_send>",
							"Forwarding a remote directed broadcast packet",
												msg0, msg1, OPC_NIL);
						}

					/* Store the new structure in the ici.				*/
					op_ici_attr_set (pk_ici_copy_ptr, "rte_info_fields", intf_ici_fdstruct_copy_ptr);

					/* Forward the datagram to the appropriate interface*/
					inet_rte_datagram_broadcast (module_data_ptr, 
						ip_rte_datagram_interface_forward_direct,
						intf_ici_fdstruct_copy_ptr->dest_addr, pk_copy_ptr, 
						intf_ici_fdstruct_copy_ptr->output_intf_index, 
						intf_ici_fdstruct_copy_ptr);
					}
				}
			
			/* The datagram has reached its destination, forward    */
			/* it to the parent process for appropriate handling	*/
			/* it to the parent process for appropriate handling	*/
			/* Indicate that this is not from the other set of	  	*/
			/* child processes by setting their pkptr to nil.		*/
			module_data_ptr->ip_ptc_mem.child_pkptr = OPC_NIL;
			op_pro_invoke (module_data_ptr->ip_root_prohandle, pkptr);
			}
		else if (intf_ici_fdstruct_ptr->broadcast)
			{
			if (LTRACE_IP_ACTIVE)
				op_prg_odb_print_major ("<ip_rte_packet_send>",
					"Broadcasting packet on all interfaces", OPC_NIL);
			
			/*  This is a broadcast datagram. Forward it on the     */
			/*  relevant interface.                                 */
			inet_rte_datagram_broadcast (module_data_ptr, 
				ip_rte_datagram_interface_forward_direct,
				intf_ici_fdstruct_ptr->dest_addr, pkptr, 
				intf_ici_fdstruct_ptr->output_intf_index, 
				intf_ici_fdstruct_ptr);
			}
		else if ((IpC_Rte_Process_Type_Cloud != process_type) &&
				 (intf_ici_fdstruct_ptr->mpls_redirect))
			{
			if (LTRACE_IP_ACTIVE)
				op_prg_odb_print_major ("<ip_rte_packet_send>",
					"Re-directing packet to MPLS", OPC_NIL);
			
			/* Forward the packet to the MPLS manager */
		  	op_pro_invoke (module_data_ptr->mpls_mgr_prohandle, pkptr);
			}
		else if ((IpC_Rte_Process_Type_Slot == process_type) &&
				 (intf_ici_fdstruct_ptr->slot_index != intf_ici_fdstruct_ptr->outslot) &&
				 (OMSC_DV_LOOPBACK_SLOT != intf_ici_fdstruct_ptr->outslot))
			{
			if (LTRACE_IP_ACTIVE)
				op_prg_odb_print_major ("<ip_rte_packet_send>",
					"Forwarding packet to a different slot", OPC_NIL);
			
			/* The packet needs to go to a different slot			*/
			ip_rte_slot_forward (pkptr, intf_ici_fdstruct_ptr->outslot,
				(IpT_Routing_Slot_Ptc_Mem*) process_info_ptr);
			}
		else
			{
			if (LTRACE_IP_ACTIVE)
				op_prg_odb_print_major ("<ip_rte_packet_send>",
					"Sending packet on specific output interface", OPC_NIL);
				
			/*  Otherwise, forward the datagram on the appropriate  */
			/*  interface.                                          */
			ip_rte_datagram_interface_forward_direct (module_data_ptr,
				intf_ici_fdstruct_ptr->dest_addr, 
				intf_ici_fdstruct_ptr->next_addr, pkptr, 
				intf_ici_fdstruct_ptr->output_intf_index, 
				intf_ici_fdstruct_ptr);
			}
		}
	else
		{
		/* Destroy the packet and update statistics.    */
		ip_rte_dgram_discard (module_data_ptr, pkptr, pk_ici_ptr, intf_ici_fdstruct_ptr->drop_reason);
		}

	FOUT;
	}

Boolean		
ip_rte_decompress (Packet * pkptr, 
	IpT_Rte_Ind_Ici_Fields * intf_ici_fdstruct_ptr, 
	IpT_Dgram_Fields * pk_fd_ptr)
	{
	/** Check for and perform packet decompression 	**/
	/** Return OPC_TRUE if decompression took place	**/
	FIN (ip_rte_decompress (pkptr, intf_ici_fdstruct_ptr, pk_fd_ptr));

	if (intf_ici_fdstruct_ptr->decompress)
		{
		/* Set the size of the packet to its original size.	*/
		op_pk_total_size_set (pkptr, pk_fd_ptr->original_size);
	
		/* Reset the decompress field to prevent re-decompression.	*/
		intf_ici_fdstruct_ptr->decompress = OPC_FALSE;

		/* Issue a trace statement.	*/
		if (LTRACE_COMPRESSION_ACTIVE || op_prg_odb_pktrace_active (pkptr))
			ip_rte_comp_decomp_trace_print (pkptr, 
				pk_fd_ptr->compression_method, 0, 
				pk_fd_ptr->original_size, "decompression");
		FRET (OPC_TRUE);
		}

	FRET (OPC_FALSE);
	}


double
ip_rte_compress (IpT_Rte_Module_Data * iprmd_ptr, Packet * pkptr, 
	OpT_Packet_Size packet_size, IpT_Rte_Ind_Ici_Fields * intf_ici_fdstruct_ptr, 
	IpT_Dgram_Fields * pk_fd_ptr)
	{
	int						instrm;
	int						mtu;
	OpT_Packet_Size			compressed_size;
 
	/** Check for and perform packet compression	**/
	/** Returns the size after compression.			**/
	FIN (ip_rte_compress (pkptr, intf_ici_fdstruct_ptr, pk_fd_ptr));

	/* Compress datagram if specified. Compression is necessary if:	*/
	/* 1) Compression method field of the packet is not "None" AND	*/
	/* 2) if Per-Virtual Circuit compression is used then the		*/
	/*    packet must be from higher layer.							*/
	instrm = intf_ici_fdstruct_ptr->instrm;

	if ((pk_fd_ptr->compression_method != IpC_No_Compression) &&
		((pk_fd_ptr->compression_method != IpC_Per_Virtual_Circuit_Comp) || 
		 (instrm == iprmd_ptr->instrm_from_ip_encap || instrm == IpC_Pk_Instrm_Child)))
		{
		/* Size after compression is computed earlier. Retrieve		*/
		/* this data.												*/
		compressed_size = (OpT_Packet_Size)intf_ici_fdstruct_ptr->compressed_size;

		/* If Per-Interface compression is used and the size of the	*/
		/* datagram will be still greater than mtu after			*/
		/* compression, then we will not compress the packet now,	*/
		/* but will compress it after the fragmentation. Also check */
		/* this case before compressing the datagram.				*/
		mtu = intf_ici_fdstruct_ptr->output_mtu;
	
		/* We obtained the mtu size, compare it with the size of	*/
		/* datagram after compression.								*/
		if (!((pk_fd_ptr->compression_method == IpC_Per_Interface_Comp) && 
			(compressed_size > mtu * 8)))
			{
			/* Store the original size of the packet, which will be	*/
			/* used for decompression.								*/
			pk_fd_ptr->original_size = packet_size;
	
			/* Compress the packet with resizing.					*/
			op_pk_total_size_set (pkptr, compressed_size);
	
			/* Issue a trace statement.								*/
			if (LTRACE_COMPRESSION_ACTIVE || op_prg_odb_pktrace_active (pkptr))
				ip_rte_comp_decomp_trace_print (pkptr, 
					pk_fd_ptr->compression_method, packet_size, 
					compressed_size, "compression");
			}

		/* Reset the ICI field.										*/
		intf_ici_fdstruct_ptr->compressed_size = IPC_COMPRESSION_NOT_USED;
		}	
	else
		{
		/* No compression is used.	*/
		compressed_size = IPC_COMPRESSION_NOT_USED;
		}

	FRET (compressed_size);
	}


void
inet_rte_datagram_broadcast (IpT_Rte_Module_Data * iprmd_ptr,
	IpT_Rte_Datagram_Interface_Forward forward_proc,
	InetT_Address dest_addr, Packet *pk_ptr, int intf_tbl_index, 
	IpT_Rte_Ind_Ici_Fields* ici_fdstruct_ptr)
	{
	int						num_ifaces;
	IpT_Interface_Info *	iface_ptr;
	Packet *				pk_copy_ptr;
	IpT_Dgram_Fields*		pkt_fields_ptr;
	Ici*					pk_ici_ptr;
	double					comp_size;
	InetT_Address			next_addr;
	InetT_Addr_Family		addr_family;
	IpT_Rte_Ind_Ici_Fields* ith_ici_fdstruct_ptr;
	int						interface_index;
		
	/** Broadcast a datagram on all applicable interfaces. **/
	FIN (inet_rte_datagram_broadcast (forward_proc, dest_addr, pk_ptr, intf_tbl_index));
	
	/*	Access the datagram field information structure	*/
	op_pk_nfd_access (pk_ptr, "fields", &pkt_fields_ptr);
	
	/* Get the destination address family	*/
	addr_family = inet_address_family_get (&dest_addr);
	
	/* If interface_index == IP_BROADCAST_ALL_INTERFACES, 	*/
	/* then this is a broadcast that needs to be sent out	*/
	/* on all the IP interfaces connected to this node. 	*/
	/* Else, interface_index points to the position in the	*/
	/* interface list of the interface over which the 		*/
	/* broadcast has to be sent out.						*/
	if (intf_tbl_index == IP_BROADCAST_ALL_INTERFACES)
		{
		/*	If the received packet does not yet have a time-to-live	*/
		/*	field assignment, set the TTL to 1						*/
		if (pkt_fields_ptr->ttl == IPC_TTL_UNSET)
			{
			pkt_fields_ptr->ttl = 1;
			}
		
		/* Loop through all interfaces, and send a copy of the	*/
		/*packet on each applicable interface.					*/
		num_ifaces = inet_rte_num_interfaces_get (iprmd_ptr);
		
		for (interface_index = 0; interface_index < num_ifaces; interface_index++)
			{
			/* Obtain a handle on the i_th interface. */
			iface_ptr = inet_rte_intf_tbl_access (iprmd_ptr, interface_index);
			
			/* If this is a loopback or a shutdown interface we	*/
			/* should not try to send the packet.				*/
			if (IpC_Intf_Status_Active != ip_rte_intf_status_get (iface_ptr) ||
				(!ip_rte_intf_ip_version_active (iface_ptr, addr_family)))
				{
				/* If this is the last interface, destroy the	*/
				/* packet and break out of the loop.			*/
				if (interface_index == (num_ifaces - 1))
					{
					/* Get the ici associated with the packet.	*/
					pk_ici_ptr = op_pk_ici_get (pk_ptr);

					/* Destroy the ici							*/
					op_ici_destroy (pk_ici_ptr);

					/* Destroy the packet and free the memory	*/
					/* allocated to the ici_fdstruct_ptr		*/
					op_pk_destroy (pk_ptr);
					ip_rte_ind_ici_fdstruct_destroy (ici_fdstruct_ptr);
					break;
					}
				else
					{
					/* In case, there are more than one loopbacks defined. */
					continue;
					}
				}

			
			/* If the interface we are working with is not the	*/
			/* last one, then we need to create a copy of the	*/
			/* packet and send out the copy. The orig. packet	*/
			/* will be sent out the last interface in the list.	*/
			/* Create a copy of the intf_ici structure and also	*/
			/* create a new ici to go with the packet.			*/
			if (interface_index < (num_ifaces - 1))
				{
				pk_copy_ptr = op_pk_copy (pk_ptr);
				ith_ici_fdstruct_ptr = ip_rte_ind_ici_fdstruct_copy (ici_fdstruct_ptr);

				/* Create a new ici to go with the packet		*/
				pk_ici_ptr = op_ici_create ("ip_rte_ind_v4");

				/*	Set the rte_info_fields in the ICI.			*/
				op_ici_attr_set (pk_ici_ptr, "rte_info_fields", ith_ici_fdstruct_ptr);

				/* Set this ici in the copy packet				*/
				op_pk_ici_set (pk_copy_ptr, pk_ici_ptr);
				}
			else
				{
				/* This is the last interface. Use the original	*/
				/* packet.										*/
				pk_copy_ptr = pk_ptr;
				ith_ici_fdstruct_ptr = ici_fdstruct_ptr;
				}
			
			/*	Access the datagram field information structure	*/
			/* 	to assign source address information.			*/
			op_pk_nfd_access (pk_copy_ptr, "fields", &pkt_fields_ptr);

			/* Set the source address before forwarding the packet. */
			if (!inet_address_valid (pkt_fields_ptr->src_addr))
				{
				inet_address_destroy (pkt_fields_ptr->src_addr);
				pkt_fields_ptr->src_addr = inet_rte_intf_addr_get (iface_ptr, addr_family);
				}
	
			/* Since for unnumbered OSPF point-to-point interfaces	*/
			/* the interface address is just the interface number,	*/
			/* a different check is performed.						*/ 
			if (ip_rte_intf_unnumbered (iface_ptr) == OPC_FALSE)
				pkt_fields_ptr->src_internal_addr =	inet_rtab_addr_convert (pkt_fields_ptr->src_addr);
			else
				pkt_fields_ptr->src_internal_addr = ip_rtab_addr_convert (ip_rte_intf_network_address_get (iface_ptr));

			/* Check whether datagram compression is used at	*/
			/* this interface. If it is and if we use central	*/
			/* based processing then we need to compress packet	*/
			/* now since the packet will not processed again.	*/
			if ((iprmd_ptr->processing_scheme == OmsC_Dv_Centralized) && 
				(iface_ptr->comp_info->method != IpC_No_Compression))
				{
				/* Retrieve the ICI associated with the packet.	*/
				pk_ici_ptr = op_pk_ici_get (pk_copy_ptr);
				if (pk_ici_ptr == OPC_NIL)
					(*iprmd_ptr->error_proc) ("Error in extracting the associated ICI from the IP datagram.");

				/* Compute the compressed size. If compression	*/
				/* is applicable it will be stored into the ICI.*/
				ip_rte_comp_delay_and_size_compute (iprmd_ptr, pk_copy_ptr, pkt_fields_ptr, pk_ici_ptr, iface_ptr);

				/* Retrieve the data and check whether we need	*/
				/* to compress.									*/
				comp_size = ith_ici_fdstruct_ptr->compressed_size;
				if (comp_size != IPC_COMPRESSION_NOT_USED)
					{
					/* If Per-Interface compression is used and	*/
					/* the size of the datagram will be still	*/
					/* greater than mtu after compression, then	*/
					/* we will not compress the packet now, but	*/
					/* will compress it after the fragmentation.*/
					/* Also check this case before compressing	*/
					/* the datagram.							*/
					if (!((pkt_fields_ptr->compression_method == IpC_Per_Interface_Comp) && 
                   	    ((OpT_Packet_Size)comp_size > inet_rte_intf_mtu_get (iface_ptr, InetC_Addr_Family_v4) * 8)))
						{
						/* Store the packet's original size,	*/
						/* which will be used for decompression.*/
						pkt_fields_ptr->original_size = op_pk_total_size_get (pk_copy_ptr);

						/* Compress the packet with resizing.	*/
						op_pk_total_size_set (pk_copy_ptr, (OpT_Packet_Size) comp_size);

						/* Issue a trace statement.				*/
						if (LTRACE_COMPRESSION_ACTIVE || op_prg_odb_pktrace_active (pk_copy_ptr))
							ip_rte_comp_decomp_trace_print (pk_copy_ptr, 
								pkt_fields_ptr->compression_method, 
								pkt_fields_ptr->original_size, 
								(OpT_Packet_Size) comp_size, "compression");
						}

					/* Reset the ICI field.						*/
					ici_fdstruct_ptr->compressed_size = IPC_COMPRESSION_NOT_USED;
					}	
				}
			/* Set the next address to the subnet level broadcast	*/
			/* address of this interface.							*/
			next_addr = inet_rte_intf_broadcast_addr_get (iface_ptr, addr_family);

			/* Set the output interface index and the outstrm		*/
			/* correctly											*/
			ith_ici_fdstruct_ptr->output_intf_index = interface_index;
			ith_ici_fdstruct_ptr->outstrm = ip_rte_intf_out_port_num_get (iface_ptr);
			ith_ici_fdstruct_ptr->interface_type = ip_rte_intf_type_get (iface_ptr);
			ith_ici_fdstruct_ptr->iface_speed = ip_rte_intf_link_bandwidth_get (iface_ptr);
			ith_ici_fdstruct_ptr->output_mtu = inet_rte_intf_mtu_get (iface_ptr, InetC_Addr_Family_v4);
			
			/* Free any dynamic memory associated with next_addr.	*/
			inet_address_destroy (ith_ici_fdstruct_ptr->next_addr);
			ith_ici_fdstruct_ptr->next_addr = inet_address_copy (next_addr);

			ith_ici_fdstruct_ptr->output_subintf_index =
					ip_rte_minor_port_from_intf_table_index_get (iprmd_ptr, interface_index);

			/* Check if any IP options have been set -- e.g., record route	*/
			/* option. If set, then process the options.					*/
			if (pkt_fields_ptr->options_field_set == OPC_TRUE)
				{
				/* It is required to set certain options in the IP datagram	*/
				ip_rte_dgram_options_process (iprmd_ptr, pk_copy_ptr, interface_index);
				}

			/* Forward the packet.									*/
			(*forward_proc) (iprmd_ptr, dest_addr, next_addr, pk_copy_ptr,
				interface_index, ith_ici_fdstruct_ptr);

			inet_address_destroy (next_addr);
			} /* for (interface index = ....)	*/
		} /* if (interface_index == IPC_BROA...)*/	
	else
		{
		/* Global broadcast and directed broadcast packets are	*/
		/* not supposed to go beyond nodes that are one ip hop	*/
		/* away. Due to misconfigurations, it is possible that	*/
		/* one of the receiving nodes might try to route this	*/
		/* packet without realizing that this is a broadcast	*/
		/* packet. This might cause a packet 'storm'. Set the 	*/
		/* TTL of the packet to 1 to make sure that this does 	*/
		/* not happen.											*/
		if ((ici_fdstruct_ptr->instrm == iprmd_ptr->instrm_from_ip_encap) || 
			(ici_fdstruct_ptr->instrm == IpC_Pk_Instrm_Child))
			{
			/* The packet was generated on this node. Set the	*/
			/* ttl to 1.										*/
			pkt_fields_ptr->ttl = 1;
			}
		else if (pkt_fields_ptr->ttl > 2)
			{
			/* This is a remote directed broadcast. Set the ttl	*/
			/* to 2, because we will be decrementing the ttl in	*/
			/* the ip_rte_iterface_forward_direct function.		*/
			pkt_fields_ptr->ttl = 2;
			}
		
		iface_ptr = inet_rte_intf_tbl_access (iprmd_ptr, intf_tbl_index);

		/* Set the source address before forwarding the packet. */
		/* if it has not been already set						*/
		if (!inet_address_valid (pkt_fields_ptr->src_addr))
			{
			pkt_fields_ptr->src_addr =  inet_rte_intf_addr_get (iface_ptr, addr_family);
			}

		/* For unnumbered interfaces the address representation	*/
		/* is different and that is why a seperate comparision	*/
		/* is required.											*/
		if (ip_rte_intf_unnumbered (iface_ptr) == OPC_FALSE)
			pkt_fields_ptr->src_internal_addr =	ip_rtab_addr_convert (iface_ptr->addr_range_ptr->address);
		else
			pkt_fields_ptr->src_internal_addr = ip_rtab_addr_convert (ip_rte_intf_network_address_get (iface_ptr));

		(*forward_proc)(iprmd_ptr, dest_addr, dest_addr, pk_ptr,
			intf_tbl_index, ici_fdstruct_ptr);
		}

	FOUT;
	}


int 
ip_rte_flow_map_insert(const void* e0, const void* e1)
	{
	const IpT_Flow_Pair* flow_pair0_ptr = (const IpT_Flow_Pair*) e0;
	const IpT_Flow_Pair* flow_pair1_ptr = (const IpT_Flow_Pair*) e1; 
	int rc = 0; 
	
	/* Function used as criterion for an op_prg_insert_sorted() */
	/* call inside the function ip_rte_flow_id_swap()           */
	FIN (ip_rte_flow_map_insert(e0,e1));
	
	if(flow_pair0_ptr->in_flow < flow_pair1_ptr->in_flow)
		rc = 1;
	else if (flow_pair0_ptr->in_flow > flow_pair1_ptr->in_flow)
		rc = -1; 
	else 
		{
		rc = inet_address_ptr_compare (&flow_pair0_ptr->next_hop_addr,
			&flow_pair1_ptr->next_hop_addr);
		}
	
	FRET(rc);
	}

int 
ip_rte_flow_map_search (const void* f1_temp, const void* f2_temp)
	{
	const IpT_Flow_Pair* f1 = (const IpT_Flow_Pair*) f1_temp;
	const IpT_Flow_Pair* f2 = (const IpT_Flow_Pair*) f2_temp;

	int rc = -1; 
	
	/* Function used as criterion for an op_prg_list_elem_find() */
	/* call inside the function ip_rte_flow_id_swap()         */
	FIN(ip_rte_flow_map_search(e, match));
	
	if (inet_address_equal (f1->next_hop_addr, f2->next_hop_addr))
		{
		if (f1->in_flow < f2->in_flow)
			rc = 1 /*less than*/; 
		else if (f1->in_flow > f2->in_flow) 
			rc = -1 /*greater than*/;
		else if (f1->in_flow == f2->in_flow)
			rc = 0 /*equal value*/;
		}
	else
		{
		if (f1->in_flow < f2->in_flow)
			rc = 1 /*less than*/; 
		else if (f1->in_flow > f2->in_flow) 
			rc = -1 /*greater than*/;
		else
			rc = inet_address_ptr_compare (&f1->next_hop_addr,
				&f2->next_hop_addr);
		}
	
	FRET (rc);
	}


void
ip_rte_flow_id_swap (OmsT_Bgutil_Tracer_Packet_Info* trc_pkt_info_ptr, 
	IpT_Interface_Info* interface_ptr, InetT_Address pkt_next_hop_addr)
    {
	double 	  		in_flow_id; 
	IpT_Flow_Pair	*flow_pair_ptr = OPC_NIL;
	IpT_Flow_Pair	*new_flow_pair_ptr = OPC_NIL; 
	IpT_Flow_Pair  	compare_flow_pair;	

	/** This func. maps the incoming flow id of the tracer pk.  **/
	/** to an outgoing flow id, based on a mapping list on the  **/
	/** on the interface. If necessary, it also updates the     **/
	/** mapping list.                                           **/
	/** If Recycle_Flow_Id is true, then we re-use the incoming **/
	/** flow id as outgoing flow id.                            **/
    FIN (ip_rte_flow_id_swap (pkptr, tracer_info_ptr));
	
	if (interface_ptr->flow_id_map_list_ptr == OPC_NIL)
		interface_ptr->flow_id_map_list_ptr = op_prg_list_create(); 
			
	/* Search for the mapping entry corresponding to the incoming flow id */
	in_flow_id = trc_pkt_info_ptr->flow_id;
	
	/* Create a base flow pair to compare with other flow pairs */
	/* in the list. The search criteria is on next_hop_addr and */
	/* incoming flow id.										*/
	compare_flow_pair.in_flow = in_flow_id;

	/* No need to use inet_address_copy							*/
	compare_flow_pair.next_hop_addr = pkt_next_hop_addr;
	
	flow_pair_ptr = (IpT_Flow_Pair*) op_prg_list_elem_find (
		interface_ptr->flow_id_map_list_ptr, 
		ip_rte_flow_map_search, 
		&compare_flow_pair, VOSC_NIL, VOSC_NIL); 
	
	if (flow_pair_ptr)
		{
		/* if the mapping entry corresponding to the incoming flow id */
		/* is found, then write the outgoing flow id into the tracer  */
		trc_pkt_info_ptr->flow_id = flow_pair_ptr->out_flow;
		}
	else 
		{		
		/* if there is no mapping entry corresp. to the incoming flow id */
		/* then create such a mapping for the first time now, and assign */
		/* an outgoing flow id to it. 									 */
		new_flow_pair_ptr = (IpT_Flow_Pair*) op_prg_mem_alloc(sizeof(IpT_Flow_Pair));
		new_flow_pair_ptr->in_flow = in_flow_id; 
		new_flow_pair_ptr->out_flow = oms_basetraf_get_flow_index();
		new_flow_pair_ptr->next_hop_addr = inet_address_copy (pkt_next_hop_addr);

		/* insert the newly created mapping entry in the interface */
		/* mapping list ordered by incoming flow id. 			   */						  
		op_prg_list_insert_sorted(interface_ptr->flow_id_map_list_ptr,
			new_flow_pair_ptr, ip_rte_flow_map_insert);
		
		/* write the outgoing flow id into the tracer */
		trc_pkt_info_ptr->flow_id = new_flow_pair_ptr->out_flow;
		}

    FOUT;
    }

void
ip_rte_datagram_interface_forward_direct (IpT_Rte_Module_Data * iprmd_ptr,
	InetT_Address dest_addr, InetT_Address next_addr, Packet* pk_ptr, 
	int intf_tbl_index, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr)
	{
	char				str0 [512], str1 [512];
	char*				dest_addr_str;
	char*				next_addr_str;
	char*				intf_addr_str;
	Ici*                intf_ici_ptr;
	IpT_Dgram_Fields*	pk_fd_ptr;
	Boolean				ip_rte_trace;
	Packet *			tracer_orig;
	Packet *			bgutil_pkptr = OPC_NIL;
	OmsT_Bgutil_Tracer_Packet_Info*     trc_pkt_info_ptr = OPC_NIL;
	unsigned long		num_packets, packet_index;
	IpT_Tracer_Info *	tracer_info_array;
	IpT_Tracer_Info *	tracer_info_ptr;
	IpT_Interface_Info *interface_ptr;
	double				ratio;
	Boolean				packet_is_labeled 		= OPC_FALSE;
	Boolean				packet_from_lower_layer = OPC_FALSE;
	InetT_Addr_Family	addr_family; 
	
	/** Forward a datagram to a particular IP interface (specified by a	**/
	/** stream and MTU). This function should only be used for direct	**/
	/** transmission, i.e.:												**/
	/** 1. the processing scheme is NOT slot based,						**/
	/** 2. or it is a port-to-port transmission							**/
	/** 3. or it has been processed before by the server of input slot	**/
	/**    and forwarded to the output slot through the central 		**/
	FIN (ip_rte_datagram_interface_forward_direct (dest_addr, next_addr, 
		pk_ptr, intf_tbl_index, intf_ici_fdstruct_ptr));
	
	/*	 Retrieve the ICI associated with the packet.					*/
	if (intf_ici_fdstruct_ptr == OPC_NIL)
		{
		(*iprmd_ptr->error_proc) ("Error in extracting the associated ICI from the IP datagram.");
		FOUT;
		}

	/* Figure out whether we are dealing with an IPv4 or an IPv6 packet	*/
	addr_family = inet_address_family_get (&dest_addr);

	/*	Access "fields" structure from ip datagram.						*/
	op_pk_nfd_access (pk_ptr, "fields", &pk_fd_ptr);

	intf_ici_ptr = op_pk_ici_get (pk_ptr);
	
	/* Find the interface ptr */
	interface_ptr = inet_rte_intf_tbl_access (iprmd_ptr, intf_tbl_index); 
	
	/* No packets should be sent out on unconnected interfaces.	*/
	/* Destroy the packet in that case.							*/
	if (interface_ptr->phys_intf_info_ptr->intf_status == IpC_Intf_Status_Unconnected)
		{
		/* Destroy the packet and its associated ICI */
		ip_rte_intf_ici_destroy (intf_ici_ptr);
		op_pk_destroy (pk_ptr);
		
		FOUT;
		}
	
	/* If this is a labeled packet none of the IP header fields */
	/* would be visible. This will have an effect on the down 	*/
	/* the line processing of this packet						*/
	if (op_pk_nfd_is_set (pk_ptr, "MPLS Shim Header") == OPC_TRUE)
		packet_is_labeled = OPC_TRUE;
	
	/* First find out whether or not the packet came from the 	*/
	/* lower layer.												*/
	if ((iprmd_ptr->instrm_from_ip_encap == intf_ici_fdstruct_ptr->instrm) ||
		(IpC_Pk_Instrm_Child == intf_ici_fdstruct_ptr->instrm))
		{
		/* The packet did not come from the lower layer			*/
		packet_from_lower_layer = OPC_FALSE;
		}
	else
		{
		/* Packet is from the lower layer.						*/
		packet_from_lower_layer = OPC_TRUE;
		}
	
	/* If any packet filter is configured for this interface	*/
	/* then check if the packet satisfies the packet filter		*/
	/* conditions. If no the this packet should be filtered out	*/
	/* and should be dropped									*/
	/* Do this check only if the packet is not a labeled packet	*/
	/* interface has some packet filter configured, and Ext ACL	*/
	/* is configured											*/
	/* Apply ACLs only to transit packets but not to the one	*/
	/* that originated at this node itself						*/
	if ((packet_is_labeled == OPC_FALSE) &&
		(interface_ptr->filter_info_ptr != OPC_NIL) &&
		(interface_ptr->filter_info_ptr->pre_filter_out != OPC_NIL) &&
		(packet_from_lower_layer == OPC_TRUE))		
		{
		/* Check if Packet passes the Packet filter, if no then	*/
		/* drop the packet										*/
		if (Inet_Acl_Apply_Packet (interface_ptr->filter_info_ptr->pre_filter_out, pk_ptr) == OPC_FALSE)
			{
			/* If this is a policy checker demand then output	*/
			/* the information that the packet is being dropped */	
			/* What happend to the flow in this life cycle		*/
			if (op_pk_encap_flag_is_set (pk_ptr, OMSC_SECURITY_ENCAP_FLAG_INDEX))
				ip_ot_security_demand_results_log (pk_ptr, iprmd_ptr->node_name, OPC_FALSE, 
					interface_ptr->filter_info_ptr->pre_filter_out->acl_list_id, interface_ptr->full_name);
			
			/* Packet does not pass the packet filter, drop		*/
			/* the packet										*/
			ip_rte_dgram_discard (iprmd_ptr, pk_ptr, intf_ici_ptr, "Dropped by Packet Filter");
				
			/* Packet was dropped return the function			*/
			FOUT;
			}
		}
	
	/*	Decrement packet's time to live field, if the packet came from		*/
	/*	lower layer and is not being sent to higher layer. If this becomes	*/
	/*	zero, discard the packet											*/
	if ((intf_ici_fdstruct_ptr->instrm != iprmd_ptr->instrm_from_ip_encap) && 
		(intf_ici_fdstruct_ptr->instrm != IpC_Pk_Instrm_Child) &&
		(intf_ici_fdstruct_ptr->higher_layer == OPC_FALSE))
		pk_fd_ptr->ttl--;
	
	if (pk_fd_ptr->ttl == 0)
		{
		/* Create string references to the destination and next addresses. 	*/
		dest_addr_str = inet_address_str_mem_alloc ();
		inet_address_print (dest_addr_str, dest_addr);

		/* Get a printable version of the interface addr. on which this pkt.*/
		/* was received.													*/
		intf_addr_str = inet_address_str_mem_alloc ();
		inet_address_print (intf_addr_str, intf_ici_fdstruct_ptr->interface_received);

		/* In debug mode, indicate that a packet is destroyed due to expired ttl. */
		if (op_prg_odb_ltrace_active ("ip_errs"))
			{
			sprintf (str0, "Discarding packet (" SIMC_PK_ID_FMT ") with expired TTL", op_pk_id (pk_ptr));
			sprintf (str1, "Destination: (%s)", dest_addr_str);
			op_prg_odb_print_major (str0, str1, OPC_NIL);
			}

		/* Issue a simulation log message.									*/
		ipnl_reswarn_ttlexp (op_pk_id (pk_ptr), op_pk_tree_id (pk_ptr), 
			intf_addr_str, dest_addr_str);

		op_prg_mem_free (dest_addr_str);
		op_prg_mem_free (intf_addr_str);
		/* Drop this unroutable IP datagram	*/
		ip_rte_dgram_discard (iprmd_ptr, pk_ptr, intf_ici_ptr, "Routing Loop");

		FOUT;
		}
	
	/* If we are dealing with a tracer packet, we need to split	*/
	/* its content evenly amongst all the possible interfaces.	*/
	/* If it is not a tracer packet or there is only one 		*/
	/* interface, nothing special needs to be done.				*/
	num_packets = intf_ici_fdstruct_ptr->num_tracer_info;	
	
	if (op_pk_encap_flag_is_set (pk_ptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX))
		{		
		if (num_packets == 0)
			{
			/* num_packets is zero if there is only one interface */
			
			/* Obtain the tracer packet, use encap_pk_get since	*/
			/* the tracer packet may have been encapsulated		*/
			op_pk_encap_pk_get (pk_ptr, "bgutil_tracer", &bgutil_pkptr);

			/* Access the bits/sec and pkts/sec information from the    */
			/* bgutil packet. We will split this information by         */
			/* dividing it by the number of multi-paths.                */
			op_pk_nfd_access (bgutil_pkptr, "trac_pkt_info_ptr", &trc_pkt_info_ptr);		
	
			/* Find the interface ptr */
			interface_ptr = inet_rte_intf_tbl_access(iprmd_ptr, intf_tbl_index); 
			
			if (interface_ptr != OPC_NIL)
				{
				/* this always assign different flow id on other side of interface        */
				/* if we are to save on unnecessary flow ids, we need to call a milder    */
				/* version of flow_id_swap here. However re-using the flow id in as flow  */
				/* id out may result in 2 interfaces sharing the same (id in, id out) pair*/
				ip_rte_flow_id_swap(trc_pkt_info_ptr->orig_struct_ptr, interface_ptr, next_addr);
				}
			
			/* op_pk_encap_pk_get is not like op_pk_nfd_get, it does not	*/
			/* remove the packet. Also encap_pk_get creates a copy of the 	*/
			/* packet, free that copy										*/
			op_pk_destroy (bgutil_pkptr);
			}
		else
			{
			/* Save a copy of the original packet */
			tracer_orig = op_pk_copy (pk_ptr);
			
			/* num_packets = number of interfaces, */ 
			/* if there is more than one interface */
			
		    /* Obtain the tracer packet, use encap_pk_get since	*/
			/* the tracer packet may have been encapsulated		*/
			op_pk_encap_pk_get (pk_ptr, "bgutil_tracer", &bgutil_pkptr);

			/* Access the bits/sec and pkts/sec information from the    */
			/* bgutil packet. We will split this information by         */
			/* dividing it by the number of multi-paths.                */
			op_pk_nfd_access (bgutil_pkptr, "trac_pkt_info_ptr", &trc_pkt_info_ptr);		
	
			/* Get the ratio of the traffic in the last element		*/
			/* of the array.										*/
			tracer_info_array = (IpT_Tracer_Info *)
				intf_ici_fdstruct_ptr->tracer_info_array;
			tracer_info_ptr = &(tracer_info_array [num_packets - 1]);
			ratio = tracer_info_ptr->ratio;
		
			/* Scale down the bps, pps values of the packet to ratio*/
			/* Make sure that we make the change in the original	*/
			/* packet structure rather than in the copy since the 	*/
			/* copy will be destroyed.								*/
			oms_bgutil_tracer_ratio_split (trc_pkt_info_ptr->orig_struct_ptr, ratio);

			/* Swap the in-flow id for the out-flow id inside the tracer */
			ip_rte_flow_id_swap (trc_pkt_info_ptr->orig_struct_ptr, 
				tracer_info_ptr->interface_ptr, next_addr); 

			/* Set the next_addr variable to the next_hop to which	*/
			/* the current packet is to be sent.					*/
			/* Do not use inet_address_copy.						*/
			next_addr = tracer_info_ptr->next_addr;

			/* op_pk_encap_pk_get is not like op_pk_nfd_get, it does not	*/
			/* remove the packet. Also encap_pk_get creates a copy of the 	*/
			/* packet, free that copy										*/
			op_pk_destroy (bgutil_pkptr);
			}
		}
	
	packet_index = 0;
	ip_rte_trace = LTRACE_IP_ACTIVE;
	
	do
		{
		/* Compute packet latency through the IP layer. Since we	*/
		/* stored the time at which the datagram actually arrived	*/
		/* at IP, we can calculate "latency" as the difference of	*/
		/* of the current time to that time.						*/
		op_stat_write (iprmd_ptr->ip_rte_pkt_latency_stathandle, 
			(double) op_sim_time () - intf_ici_fdstruct_ptr->pkt_insertion_time);
		 	
		/*	In debug mode, trace the routing action.*/
		if (ip_rte_trace == OPC_TRUE)
			{
			/* Create string references to the destination and next addresses. 	*/
			dest_addr_str = inet_address_str_mem_alloc ();
			next_addr_str = inet_address_str_mem_alloc ();

			inet_address_print (dest_addr_str, dest_addr);
			inet_address_print (next_addr_str, next_addr);

			sprintf (str1, "Next hop (%s), output stream (%d)", next_addr_str, 
				intf_ici_fdstruct_ptr->outstrm);
			op_prg_odb_print_major ("Routing Packet", str1, OPC_NIL);

			op_prg_mem_free (dest_addr_str);
			op_prg_mem_free (next_addr_str);
			}

		/* If the source address is not set, set it here.			*/
		if (! inet_address_valid (pk_fd_ptr->src_addr))
			{
			ip_src_address_determine (&(pk_fd_ptr->src_addr), iprmd_ptr, intf_tbl_index, addr_family);
			pk_fd_ptr->src_internal_addr = inet_rtab_addr_convert (pk_fd_ptr->src_addr);
			}
		else if (pk_fd_ptr->src_internal_addr == IPC_FAST_ADDR_INVALID)
			{
			/* Set the internal address if it has not been set */
			pk_fd_ptr->src_internal_addr = inet_rtab_addr_convert (pk_fd_ptr->src_addr);
			}

		/* Set the next hop address before sending the packet.		*/
		/* First free the memory allocated to the current value.	*/
		inet_address_destroy (pk_fd_ptr->next_addr);
		pk_fd_ptr->next_addr = inet_address_copy (next_addr);

		/* Disassociate the ici from the outgoing packet			*/
		op_pk_ici_set (pk_ptr, OPC_NIL);
		
		/* rkakaraparthi.	*/
		if (ip_rte_trace)
			{
			printf ("Sending packet to\n");
			inet_address_print_debug (&(intf_ici_fdstruct_ptr->next_addr));
			}

		/* Then send the IP packet in fragments.					*/
		ip_rte_pk_fragment (iprmd_ptr, pk_ptr, dest_addr, next_addr, 
			pk_fd_ptr->connection_class, intf_ici_fdstruct_ptr);

		if ((num_packets > 1) && ((packet_index+1) < num_packets))
			{
			/* Dealing with tracer packet sent to multiple interfaces	*/
			/* Update the information to send the next packet clone		*/
	  		pk_ptr = op_pk_copy (tracer_orig);

			/* Update the pk_fd_ptr to make it point to the structure	*/
			/* in the current packet.									*/
			op_pk_nfd_access (pk_ptr, "fields", &pk_fd_ptr);

			tracer_info_ptr = &(tracer_info_array [packet_index]);

			ratio = (double)tracer_info_ptr->ratio;
			
			/* Obtain the tracer packet, use encap_pk_get since	*/
			/* the tracer packet may have been encapsulated		*/
			op_pk_encap_pk_get (pk_ptr, "bgutil_tracer", &bgutil_pkptr);

			/* Access the bits/sec and pkts/sec information from the    */
			/* bgutil packet. We will split this information by         */
			/* dividing it by the number of multi-paths.                */
			op_pk_nfd_access (bgutil_pkptr, "trac_pkt_info_ptr", &trc_pkt_info_ptr);
			
			/* Scale down the bps, pps values of the packet to ratio*/
			/* Make sure that we make the change in the original	*/
			/* packet structure rather than in the copy since the 	*/
			/* copy will be destroyed.								*/
			oms_bgutil_tracer_ratio_split (trc_pkt_info_ptr->orig_struct_ptr, ratio);
			
			/* Swap the in-flow id for the out-flow id inside the tracer */
			ip_rte_flow_id_swap (trc_pkt_info_ptr->orig_struct_ptr, 
				tracer_info_ptr->interface_ptr, next_addr);
			
			interface_ptr = tracer_info_ptr->interface_ptr;
			intf_ici_fdstruct_ptr->interface_type = ip_rte_intf_type_get (interface_ptr);
			intf_ici_fdstruct_ptr->outstrm 		  = ip_rte_intf_out_port_num_get (interface_ptr);
			intf_ici_fdstruct_ptr->outslot 		  = ip_rte_intf_slot_index_get (interface_ptr);
			intf_ici_fdstruct_ptr->output_mtu 	  = inet_rte_intf_mtu_get (interface_ptr, addr_family);
			intf_ici_fdstruct_ptr->iface_speed 	  = ip_rte_intf_link_bandwidth_get (interface_ptr);
			intf_ici_fdstruct_ptr->next_addr = inet_address_copy (tracer_info_ptr->next_addr);		   		   
			intf_ici_fdstruct_ptr->output_intf_index = tracer_info_ptr->output_intf_index;
			intf_ici_fdstruct_ptr->output_subintf_index = tracer_info_ptr->minor_port;
			
			/* The variable next_addr is being used in trace statements and other	*/
			/* places. This variable must be refreshed with the correct value.		*/
			/* But first, any dynamic memory inside next_addr must be freed.		*/			
			inet_address_destroy (next_addr);
			next_addr = inet_address_copy (intf_ici_fdstruct_ptr->next_addr);
			
			/* op_pk_encap_pk_get is not like op_pk_nfd_get, it does not	*/
			/* remove the packet. Also encap_pk_get creates a copy of the 	*/
			/* packet, free that copy										*/
			op_pk_destroy (bgutil_pkptr);
			}

		++packet_index;

		/* If this was the last packet, destroy the original packet			*/
		if (packet_index == num_packets)
			op_pk_destroy (tracer_orig);

		} while (packet_index < num_packets);

	/* Check the higher layer indication ICI.  If set, then remove it, since  */
	/* we are not forwarding the packet to the higher layer. Also, deallocate */
	/* the contents of the ICI (interface address on which the dgram was 	  */
	/* received.)															  */
	if (intf_ici_fdstruct_ptr != OPC_NIL)
		{
		/* Here there is no need to deallocate the memory used by two other	 */
		/* structure fields of the ICI, namely dest_addr and next_addr, 	 */
		/* since their contents may have passed as arguments to this function*/
		/* that are accessed also in the rest of the function. In these cases*/
		/* this memory will be freed later on. For other cases, the contents */ 
		/* of these fields are NIL.											 */

		/* Destroy the ICI.		*/
		ip_rte_ind_ici_fdstruct_destroy (intf_ici_fdstruct_ptr);

		/* MPLS sends out tracer copies without rte_ind_ici.	*/
		/* Moreover it occurs when MPLS performs load-balancing	*/
		if (intf_ici_ptr != OPC_NIL)
			/* Destroy the ici associated with the packet */
			op_ici_destroy (intf_ici_ptr);
		}

	FOUT;
	}

void
ip_rte_dgram_discard (IpT_Rte_Module_Data * iprmd_ptr, Packet* pkptr, 
						Ici* intf_ici_ptr, const char* discard_reason)
	{
	char				reason_str [256];
	char				pk_format_str [128];
	IpT_Dgram_Fields*	ip_dgram_fields_ptr;

	/** Discards IP datagram and updates the packets	**/
	/** statistics.										**/ 
	FIN (ip_rte_dgram_discard (pkptr, intf_ici_ptr));

	if (discard_reason != OPC_NIL)
		{
		/* Append "Incomplete to the reason to indicate	*/
		/* that this is an incomplete route.			*/
		sprintf (reason_str, "Incomplete (%s)", discard_reason);
		
		/* Update the "record route" option with the	*/
		/* appropriate hop and reason for discard of	*/
		/* the IP datagram if this is a tracer packet	*/
		oms_rr_info_update (pkptr, iprmd_ptr->node_name);
		oms_rr_info_update (pkptr, reason_str);
		}
	
	/* Note that this function can get called if IP receives	*/
	/* a packet that is not an ip datagram. Write out stats		*/
	/* only if the packet is an IP datagram.					*/
	op_pk_format (pkptr, pk_format_str);

	if (0 == strcmp (pk_format_str, "ip_dgram_v4"))
		{
		/* This is an IP datagram.								*/

		/* Write out a new data point for the "Packets	*/
		/* Dropped" statistics.							*/
		op_stat_write (iprmd_ptr->locl_num_pkts_dropped_hndl, 1.0);
		op_stat_write (iprmd_ptr->globl_num_pkts_dropped_hndl, 1.0);

		/* Write out a zero value to signal the end of the duration to  */
		/* hold the statistic at the previously written out value.		*/
		op_stat_write (iprmd_ptr->locl_num_pkts_dropped_hndl, 0.0);
		op_stat_write (iprmd_ptr->globl_num_pkts_dropped_hndl, 0.0);

		/* If this is an IPv6 packet we need to update the IPv6 stats also	*/
		op_pk_nfd_access (pkptr, "fields", &ip_dgram_fields_ptr);

		/* Make sure that IPv6 is enabled on this node before trying to	*/
		/* do this. On an IPv4 only node the IPv6 statistics will not	*/
		/* be registered.												*/
		if ((InetC_Addr_Family_v6 == inet_address_family_get (&(ip_dgram_fields_ptr->dest_addr))) &&
			(ip_rte_node_ipv6_active (iprmd_ptr)))
			{
			/* Write out a new data point for the "Packets	*/
			/* Dropped" statistics.							*/
			op_stat_write (iprmd_ptr->locl_num_ipv6_pkts_dropped_hndl, 1.0);
			op_stat_write (iprmd_ptr->globl_num_ipv6_pkts_dropped_hndl, 1.0);

			/* Write out a zero value to signal the end of the duration to  */
			/* hold the statistic at the previously written out value.		*/
			op_stat_write (iprmd_ptr->locl_num_ipv6_pkts_dropped_hndl, 0.0);
			op_stat_write (iprmd_ptr->globl_num_ipv6_pkts_dropped_hndl, 0.0);
			}
		}

	/* Also deallocate the associated ICI and its	*/
	/* fields if the ICI exists.					*/
	ip_rte_intf_ici_destroy (intf_ici_ptr);

	/* Drop the packet.	*/
	op_pk_destroy (pkptr);

	FOUT;
	}

double
ip_rte_comp_delay_and_size_compute (IpT_Rte_Module_Data * iprmd_ptr, 
	Packet* pkptr, IpT_Dgram_Fields* pk_fd_ptr, 
	Ici* intf_ici_ptr, IpT_Interface_Info* iface_info_ptr)
	{
	IpT_Compression_Info*		comp_info_ptr;
	double						size, comp_size;
	double						ratio;
	int							instrm, decompress;
	int							output_intf_index, output_subintf_index;
	IpT_Rte_Ind_Ici_Fields*		intf_ici_fdstruct_ptr;
	InetT_Addr_Family			addr_family;

	/** This function computes the datagram's size after 			**/
	/** compression process and the amount of processing time		**/
	/** necessary to compress the packet. It updates the associated	**/
	/** ICI with the compressed datagram size and returns the value	**/
	/** of compression delay.										**/ 
	FIN (ip_rte_comp_delay_and_size_compute (pkptr, pk_fd_ptr, intf_ici_ptr, iface_info_ptr));

	/* Get a handle to the compression scheme used for the output	*/
	/* interface.													*/
	comp_info_ptr = ip_rte_intf_comp_info_get (iface_info_ptr);

	/* If the packet is already compressed we do not compress again.*/
	if (pk_fd_ptr->compression_method != IpC_No_Compression)
		FRET (0.0);

	/* Figure out whether we are dealing with an IPv4 or an IPv6	*/
	/* packet.														*/
	addr_family = inet_address_family_get (&(pk_fd_ptr->dest_addr));

	/* Get the current size of the datagram. There can be a			*/
	/* decompression scheduled for the datagram which will take 	*/
	/* place before the compression. If this is the case, then the	*/
	/* current size of the packet is not its original size. In this	*/
	/* case get the original size from associated ICI.				*/
	op_ici_attr_get (intf_ici_ptr, "rte_info_fields", &intf_ici_fdstruct_ptr);
	decompress = intf_ici_fdstruct_ptr->decompress;
	if (decompress)
		size = pk_fd_ptr->original_size;
	else
		size = op_pk_total_size_get (pkptr);

	/* Obtain a random compression ratio from the loaded PDF. Get	*/
	/* another value if distrubution returns a negative value,		*/
	/* since we cannot have negative packet size after compression. */
	do
		{
		ratio = op_dist_outcome (comp_info_ptr->comp_ratio_dist_ptr);
		} while (ratio < 0.0);

	/* Set the decompression delay so that it may be used at other	*/
	/* nodes to decompress the compressed information.				*/
	pk_fd_ptr->decompression_delay = iface_info_ptr->comp_info->decompression_delay;

	/* Based on compression method used determine the size and		*/
	/* delay.														*/
	switch (comp_info_ptr->method) 
		{
		case IpC_TCPIP_Header_Comp:
			/* TCP/IP header compression is used. First make sure	*/
			/* the encapsulated packet is a TCP packet.				*/
			if (pk_fd_ptr->protocol != IpC_Protocol_Tcp)
				FRET (0.0);
			
			/* Simply compress the header.	*/
			comp_size = size - (IPC_TCP_COMPRESSABLE_HEADER_SIZE * (1 - ratio));

			/* Make sure after compression the datagram is smaller	*/
			/* than mtu.											*/
			if (comp_size / 8 + 1 > (double)(inet_rte_intf_mtu_get (iface_info_ptr, addr_family)))
				{
				/* Datagram is still greater than mtu which will 	*/
				/* require fragmentation. Header compression is not	*/
				/* applicable. Don't compress the packet and log a	*/
				/* warning.											*/
				output_intf_index 		= intf_ici_fdstruct_ptr->output_intf_index;
				output_subintf_index 	= intf_ici_fdstruct_ptr->output_subintf_index;
				ipnl_cfgwarn_compcfg (output_intf_index, output_subintf_index);

				FRET (0.0);
				}
			else
				{
				/* Set the compressed size and compression method	*/
				/* into associated ICI and return the delay.		*/
				intf_ici_fdstruct_ptr->compressed_size = comp_size;
				pk_fd_ptr->compression_method = IpC_TCPIP_Header_Comp;

				FRET ((double) (comp_info_ptr->compression_delay * IPC_TCP_COMPRESSABLE_HEADER_SIZE));
				}

		case IpC_Per_Interface_Comp:
			/* Per-Interface (entire packet) compression is used.	*/
			/* Apply the ratio to entire packet.					*/
			comp_size = size * ratio;

			/* Set the compressed size and compression method into	*/
			/* associated ICI and return the delay.					*/
			intf_ici_fdstruct_ptr->compressed_size = comp_size;
			pk_fd_ptr->compression_method = IpC_Per_Interface_Comp;

			FRET ((double) (comp_info_ptr->compression_delay * size));

		case IpC_Per_Virtual_Circuit_Comp:
			/* Per-Virtual Circuit (payload) compression is used.	*/
			/* We compress only if the packet is from higher layer.	*/
			instrm = intf_ici_fdstruct_ptr->instrm;
			
			if (instrm == iprmd_ptr->instrm_from_ip_encap || instrm == IpC_Pk_Instrm_Child)
				{
				/* Packet is from higher layer. Apply the ratio		*/
				/* only to payload when computing the compressed	*/
				/* file size.										*/
				comp_size = size - (pk_fd_ptr->orig_len * 8 * (1 - ratio));

				/* Adjust the compressed size to byte size (i.e.	*/
				/* multiple of eight).								*/
				comp_size = ((OpT_Packet_Size) comp_size / 8) * 8;

				/* Update the size of the payload in the packet.	*/
				/* This data will be used for fragmentation if it	*/
				/* performed.										*/
				pk_fd_ptr->frag_len -= (OpT_Packet_Size)((size - (OpT_Packet_Size) comp_size)  / 8);

				/* Set the compressed size and compression method	*/
				/* into associated ICI and return the delay.		*/
				intf_ici_fdstruct_ptr->compressed_size = comp_size;
				pk_fd_ptr->compression_method = IpC_Per_Virtual_Circuit_Comp;

				FRET ((double) (comp_info_ptr->compression_delay * pk_fd_ptr->orig_len * 8));
				}
        	else
				{
				FRET (0.0)
				}
		default:
			{
			/* No Compression delay and change of datagram packet size.	*/
			FRET (0.0);
			}
		}
	}

void 
ip_rte_intf_ici_destroy (Ici* intf_iciptr)
	{
	IpT_Rte_Ind_Ici_Fields*	intf_ici_struct_ptr;

	/**	Deallocate the ICI and memory allocated to the			**/
	/**	contained fields.										**/
	FIN (ip_rte_intf_ici_destroy (intf_iciptr));

	/* Also deallocate the associated ICI and its 		*/
	/* fields if the ICI exists.						*/
	if (intf_iciptr != OPC_NIL)
		{
		op_ici_attr_get (intf_iciptr, "rte_info_fields", &intf_ici_struct_ptr);
		ip_rte_ind_ici_fdstruct_destroy (intf_ici_struct_ptr);
		op_ici_destroy (intf_iciptr);
		}

	FOUT;
	}


void
ip_rte_pk_stats_update (IpT_Rte_Module_Data *iprmd_ptr,
	Packet *pkptr, double *last_stat_update_time_ptr,
	OmsT_Bgutil_Routed_State *stat_bgutil_routed_state_ptr,
	Stathandle *packet_sec_shandle_ptr)
	{
	
	/**	Record the IP stats for packets sent and received.	**/
	FIN (ip_rte_pk_stats_update (pkptr, pksize, ...));

	if ((iprmd_ptr->do_bgutil == OPC_TRUE) &&
		(stat_bgutil_routed_state_ptr != OPC_NIL))
		{
		/* Update bgutil traffic statistics and	*/
		/* update statistic update time. 		*/
		oms_bgutil_stats_update (pkptr, last_stat_update_time_ptr,	
			stat_bgutil_routed_state_ptr, OPC_NIL, packet_sec_shandle_ptr,
			OPC_NIL, OPC_NIL, OPC_NIL, iprmd_ptr->service_rate, OPC_NIL);
		}

	/* Maintain time at which these statistics were last updated.	*/
	*last_stat_update_time_ptr = op_sim_time ();
	

	/* pkptr is OPC_NIL when this proc is called from end_sim */	
	if (pkptr != OPC_NIL)
		{
		/* Update statistics for the explicit packet */		
		op_stat_write (*packet_sec_shandle_ptr, 1.0);
		op_stat_write (*packet_sec_shandle_ptr, 0.0);
		}

	FOUT;
	}

void
ip_rte_next_hop_error (IpT_Address addr)
	{
	char			addr_str [IPC_ADDR_STR_LEN];

	/** Print out an error indicating an invalid next hop. **/
	FIN (ip_rte_next_hop_error (addr));

	/* Get a printable version of the next hop address.		*/
	ip_address_print (addr_str, addr);

	/* Write a message to the simulation log.				*/
	ipnl_proterr_nexthop_error (addr_str);

	FOUT;
	}

void
ip_rte_comp_decomp_trace_print (Packet* pkptr, IpT_Compression_Method method, 
	OpT_Packet_Size old_size, OpT_Packet_Size new_size, const char action [15])
	{
	char	odb_msg1 [128], odb_msg2 [128], comp_method [64];

	/** This function prints compression related odb trace 	**/
	/** statements.											**/
	FIN (ip_rte_comp_decomp_trace_print (Packet* pkptr, IpT_Compression_Method method, int old_size, int new_size, char action [15]));

	if (strcmp (action, "decompression") == 0)
		{
		sprintf (odb_msg1, "Decompressing the packet: " SIMC_PK_ID_FMT "  Setting back to its original size:  " OPC_PACKET_SIZE_FMT " bits", op_pk_id (pkptr), new_size);
		op_prg_odb_print_minor (odb_msg1, OPC_NIL);
		FOUT;
		}

	/* Else the action is compression.	*/
	switch (method)
		{
		case IpC_TCPIP_Header_Comp:
			{
			strcpy (comp_method, "TCP/IP Header Compression"); 
			break;
			}
		case IpC_Per_Interface_Comp:
			{
			strcpy (comp_method, "Per-Interface Compression");
			break;
			}
		case IpC_Per_Virtual_Circuit_Comp:
			{
			strcpy (comp_method, "Per-Virtual Circuit Compression");
			break;
			}
		default:
			{
			break;
			}
		}

	sprintf (odb_msg1, "Compressing the packet: " SIMC_PK_ID_FMT "  Method: %s", op_pk_id (pkptr), comp_method);
	sprintf (odb_msg2, "Original size:  " OPC_PACKET_SIZE_FMT " bits   Compressed size:  " OPC_PACKET_SIZE_FMT " bits", old_size, new_size);
	op_prg_odb_print_minor (odb_msg1, odb_msg2, OPC_NIL);

	FOUT;
	}


Objid
ip_rte_parameters_objid_obtain (Objid node_id, Objid module_id, Boolean* gateway_status_p)
	{
	Compcode status;
	Objid    comp_attr_objid, ip_parameters_objid;
	Boolean  gtwy_status;
	char	 router_params [128], host_params [128], gateway_attr [128];
	Objid	 target_objid;
	
	/** Function to determine the IP node being parsed and return the OBJID **/
	/** of corresponding IP Parameters attribute.							**/
	FIN (ip_rte_parameters_objid_obtain (Objid node_id, Objid module_id, Boolean* gateway_status_p));
	

	if ((node_id == OPC_OBJID_NULL) && (module_id != OPC_OBJID_NULL))
		{
		/* If IP's module id is passed as an argument to this function */		
		strcpy (router_params, "ip router parameters");
		strcpy (host_params, "ip host parameters");
		strcpy (gateway_attr, "gateway");
		target_objid = module_id;
		}
	else if ((module_id == OPC_OBJID_NULL) && (node_id != OPC_OBJID_NULL))
		{
		/* If the node id which contains IP module is passed	*/
		/* as an argument to this function.						*/
		strcpy (router_params, "ip.ip router parameters");
		strcpy (host_params, "ip.ip host parameters");
		strcpy (gateway_attr, "ip.gateway");
		target_objid = node_id;
		}
	else
		{
		op_sim_end ("IP Attribute Parser", "Either module id or node id should be NULL or", 
			"Atmost one of module id / node id should be specified", OPC_NIL);
		}
	
	/*	Determine whether this IP node is a gateway.				*/
	status = op_ima_obj_attr_get (target_objid, gateway_attr,	&gtwy_status);
	
    if (status == OPC_COMPCODE_FAILURE)
		op_sim_end ("IP Attribute Parser", "Unable to get gateway status from attribute.", 
			OPC_NIL, OPC_NIL);
	
	/* Depending on whether this is a host or a gateway, we have	*/
	/* differently named IP parameters.								*/
	if (gtwy_status)
		status = op_ima_obj_attr_get (target_objid,
			router_params, &comp_attr_objid);
	else
		status = op_ima_obj_attr_get (target_objid,
			host_params, &comp_attr_objid);
	
	if (status == OPC_COMPCODE_FAILURE)
		op_sim_end ("IP Attribute Parser", "Unable to get IP Parameters attributes", 
			OPC_NIL, OPC_NIL);
	
	ip_parameters_objid = op_topo_child (comp_attr_objid, OPC_OBJTYPE_GENERIC, 0);
	
	/* Set the gateway status if required by the invoker */
	if (gateway_status_p != OPC_NIL)
		*gateway_status_p = gtwy_status;
	
	FRET (ip_parameters_objid);
	}

/***************************IP Interface Table functions*************************/


IpT_Interface_Info*	
ip_rte_intf_tbl_access (struct IpT_Rte_Module_Data* iprmd_ptr, int i)
	{
	char				*msg_str0, *msg_str1;

	/** This function returns the ith element in the table	**/

	FIN (ip_rte_intf_tbl_access (iprmd_ptr, i));

	/* Make sure that the index specified is less than the	*/
	/* number of interfaces.								*/
	if ((i < ip_rte_num_interfaces_get (iprmd_ptr)) &&
		(i >= 0))
		{
		FRET (iprmd_ptr->interface_table.intf_info_ptr_array[i]);
		}
	else
		{
		/* The following function will cause a diagnostic	*/
		/* error. This will help us get the FCS.			*/
		op_prg_mem_alloc (0);
		
		msg_str0 = (char*) op_prg_mem_alloc (64 * sizeof (char));
		msg_str1 = (char*) op_prg_mem_alloc (64 * sizeof (char));
		sprintf (msg_str0, "index (%d) is invalid.", i);
		sprintf (msg_str1, "The interface table size is %d.", ip_rte_num_interfaces_get (iprmd_ptr));
		op_sim_end ("In function ip_rte_intf_tbl_access, the",
					msg_str0, msg_str1, OPC_NIL);
		}

	/* Dummy return call just to avoid compilation warnings*/
	FRET (OPC_NIL);
	}

IpT_Interface_Info*	
ipv6_rte_intf_tbl_access (struct IpT_Rte_Module_Data* iprmd_ptr, int i)
	{
	char				*msg_str0, *msg_str1;

	/** This function returns the ith element in the table	**/

	FIN (ipv6_rte_intf_tbl_access (iprmd_ptr, i));

	/* Make sure that the index specified is less than the	*/
	/* number of interfaces.								*/
	if ((i < ipv6_rte_num_interfaces_get (iprmd_ptr)) &&
		(i >= 0))
		{
		FRET (iprmd_ptr->interface_table.first_ipv6_intf_ptr[i]);
		}
	else
		{
		/* The following function will cause a diagnostic	*/
		/* error. This will help us get the FCS.			*/
		op_prg_mem_alloc (0);
		
		msg_str0 = (char*) op_prg_mem_alloc (64 * sizeof (char));
		msg_str1 = (char*) op_prg_mem_alloc (64 * sizeof (char));
		sprintf (msg_str0, "index (%d) is invalid.", i);
		sprintf (msg_str1, "The interface table size is %d.", ipv6_rte_num_interfaces_get (iprmd_ptr));
		op_sim_end ("In function ipv6_rte_intf_tbl_access, the",
					msg_str0, msg_str1, OPC_NIL);
		}

	/* Dummy return call just to avoid compilation warnings*/
	FRET (OPC_NIL);
	}

IpT_Interface_Info*	
inet_rte_intf_tbl_access (struct IpT_Rte_Module_Data* iprmd_ptr, int i)
	{
	char				*msg_str0, *msg_str1;

	/** This function returns the ith element in the table	**/

	FIN (inet_rte_intf_tbl_access (iprmd_ptr, i));

	/* Make sure that the index specified is less than the	*/
	/* number of interfaces.								*/
	if ((i < inet_rte_num_interfaces_get (iprmd_ptr)) &&
		(i >= 0))
		{
		FRET (iprmd_ptr->interface_table.intf_info_ptr_array[i]);
		}
	else
		{
		/* the following function will cause a diagnostic	*/
		/* error. This will help us get the FCS.			*/
		op_prg_mem_alloc (0);
		
		msg_str0 = (char*) op_prg_mem_alloc (64 * sizeof (char));
		msg_str1 = (char*) op_prg_mem_alloc (64 * sizeof (char));
		sprintf (msg_str0, "index (%d) is invalid.", i);
		sprintf (msg_str1, "The interface table size is %d.", inet_rte_num_interfaces_get (iprmd_ptr));
		op_sim_end ("In function inet_rte_intf_tbl_access, the",
					msg_str0, msg_str1, OPC_NIL);
		}

	/* Dummy return call just to avoid compilation warnings*/
	FRET (OPC_NIL);
	}

InetT_Address
inet_rte_intf_broadcast_addr_get (IpT_Interface_Info* iface_ptr, InetT_Addr_Family addr_family)
	{
	InetT_Address		broadcast_addr;
	
	/** Returns the broadcast address for v4 or v6 family	**/
	FIN (inet_rte_intf_broadcast_addr_get (<args>));
	
	if (addr_family == InetC_Addr_Family_v4)
		broadcast_addr = inet_rte_v4intf_broadcast_addr_get (iface_ptr);
	else
		broadcast_addr = inet_rte_v6intf_broadcast_addr_get (iface_ptr);
	
	FRET (broadcast_addr);
	}


int
ip_rte_ipv6_intf_index_get (IpT_Rte_Module_Data * iprmd_ptr, int intf_index)
	{
	/** Returns the IPv6 index corresponding to an interface	**/
	/** specified by its inet interface index.					**/
	
	FIN (ip_rte_ipv6_intf_index_get (iprmd_ptr, intf_index));

	/* If the intf_index is invalid, return 					*/
	/* IPC_INTF_INDEX_INVALID									*/
	if ((intf_index >= iprmd_ptr->interface_table.total_interfaces) ||
		(intf_index < (iprmd_ptr->interface_table.total_interfaces -
					   iprmd_ptr->interface_table.num_ipv6_interfaces)))
		{
		FRET (IPC_INTF_INDEX_INVALID);
		}

	/* The interface Index is valid. Subtract the number of		*/
	/* IPv4 only interfaces from the intf_index to get the		*/
	/* IPv6 interface index.									*/
	FRET (intf_index - (iprmd_ptr->interface_table.total_interfaces -
						iprmd_ptr->interface_table.num_ipv6_interfaces));
	}

IpT_Interface_Mode
ip_rte_intf_mode_get (const IpT_Interface_Info* intf_ptr)
	{
	/** Returns the interface mode of the specified interface	**/
	/** There are three possible interface modes: IPv4 only,	**/
	/** IPv4/IPv6 and IPv6 only.								**/

	FIN (ip_rte_intf_mode_get (intf_ptr));

	/* First check if IPv4 is enabled on this interface.		*/
	if (ip_rte_intf_ipv4_active (intf_ptr))
		{
		/* IPv4 is active check for IPv6.						*/
		if (ip_rte_intf_ipv6_active (intf_ptr))
			{
			/* This is an IPv4/IPv6 interface.					*/
			FRET (IpC_Interface_Mode_IPv4_IPv6);
			}
		else
			{
			/* IPv4 only.										*/
			FRET (IpC_Interface_Mode_IPv4_Only);
			}
		}
	else
		{
		/* IPv4 is not active. So IPv6 must be active. Else		*/
		/* we wouldn't have created this interface.				*/
		FRET (IpC_Interface_Mode_IPv6_Only);
		}
	}

IpT_Interface_Mode
ip_rte_node_mode_get (const IpT_Rte_Module_Data* node_ptr)
	{
	/** Returns the interface mode of the specified interface	**/
	/** There are three possible interface modes: IPv4 only,	**/
	/** IPv4/IPv6 and IPv6 only.								**/

	FIN (ip_rte_node_mode_get (node_ptr));

	/* First check if IPv4 is enabled on this interface.		*/
	if (ip_rte_node_ipv4_active (node_ptr))
		{
		/* IPv4 is active check for IPv6.						*/
		if (ip_rte_node_ipv6_active (node_ptr))
			{
			/* This is an IPv4/IPv6 interface.					*/
			FRET (IpC_Interface_Mode_IPv4_IPv6);
			}
		else
			{
			/* IPv4 only.										*/
			FRET (IpC_Interface_Mode_IPv4_Only);
			}
		}
	else
		{
		/* IPv4 is not active. So IPv6 must be active. Else		*/
		/* we wouldn't have created this interface.				*/
		FRET (IpC_Interface_Mode_IPv6_Only);
		}
	}

int
ip_rte_intf_tbl_index_get (IpT_Rte_Module_Data* iprmd_ptr, IpT_Interface_Info *intf_info_ptr)
	{
	/** This function takes an interface specified by 		**/
	/** intf_info_ptr and returns what it's table index is	**/
	
	int							i;
	IpT_Interface_Info 			*ip_intf_ptr;
	
	FIN (ip_rte_intf_tbl_index_get (iprmd_ptr, intf_info_ptr));
	
	for (i = 0; i < ip_rte_num_interfaces_get (iprmd_ptr); i ++)
		{
		ip_intf_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);
		if (ip_address_equal ((ip_rte_intf_addr_range_get (intf_info_ptr))->address,
			(ip_rte_intf_addr_range_get (ip_intf_ptr))->address))
			FRET (i);
		}
	
	/* Dummy call to avoid compilation warnings			*/
	FRET (-1);
	}


int
ip_rte_intf_tbl_index_from_addr_index_get (IpT_Rte_Module_Data* iprmd_ptr, int addr_index)
	{
	int						i;
	IpT_Interface_Info*		intf_info_ptr;
	
	/** This function takes addr_index and returns the		**/
	/** table index of the IP interface table for the 		**/
	/** corresponding IP interface.							**/
	
	FIN (ip_rte_intf_tbl_index_from_addr_index_get (iprmd_ptr, addr_index));
	
	for (i = 0; i < ip_rte_num_interfaces_get (iprmd_ptr); i ++)
		{
		intf_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);
		/* Check if this interface has the addr_index we	*/
		/* are looking for.									*/
		if (ip_rte_intf_addr_index_get (intf_info_ptr) == addr_index)
			{
			FRET (i);
			}
		}
	
	/* Dummy call to avoid compilation warnings */
	/* Should never get to here.  If it does,	*/
	/* then it means an invalid addr_index was	*/
	/* specified in the node model for a link	*/
	/* between IP and a Frame Relay interface.	*/
	FRET (-1);
	}


int
ip_rte_minor_port_from_intf_table_index_get (IpT_Rte_Module_Data* iprmd_ptr, int table_index)
	{
	int			minor_port = IPC_SUBINTF_PHYS_INTF;

	/** This function returns the minor port value of the	**/
	/** interface specified by table_index.					**/

	FIN (ip_rte_minor_port_from_intf_table_index_get (iprmd_ptr, table_index));

	/* Keep looping back through the interface table 		*/
	/* starting at the specified interface until a physical	*/
	/* interface is found.									*/
	while (! ip_rte_intf_is_physical (inet_rte_intf_tbl_access 
		(iprmd_ptr, table_index - (minor_port - IPC_SUBINTF_PHYS_INTF))))
		{
		++minor_port;
		}

	FRET (minor_port);
	}

int			
ip_rte_phys_intf_index_from_link_id_obtain (IpT_Rte_Module_Data * iprmd_ptr, Objid link_objid)
	{
	int					i, num_interfaces;
	IpT_Interface_Info*	intf_info_ptr;

	/** This function returns the index in teh interface table	**/
	/** of the physical interface that is connected to the		**/
	/** specified link.											**/
	
	FIN (ip_rte_phys_intf_index_from_link_id_obtain (iprmd_ptr, link_objid));

	num_interfaces = inet_rte_num_interfaces_get (iprmd_ptr);
	
	for (i = 0; i < num_interfaces; i++)
		{
		intf_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

		/* Check whether this interface is connected to the link*/
		if (ip_rte_intf_conn_link_objid_get (intf_info_ptr) == link_objid)
			{
			/* We have found the correct interface				*/
			FRET (i);
			}

		/* Skip subinterfaces									*/
		i += ip_rte_num_subinterfaces_get (intf_info_ptr);
		}

	/* We did not find a matching interface. return undef		*/
	FRET (IPC_INTF_INDEX_INVALID);
	}

Boolean		
ip_rte_node_multicast_enabled (IpT_Rte_Module_Data* iprmd_ptr)
	{
	int					i, num_interfaces;
	IpT_Interface_Info*	intf_info_ptr;

	/** This function checks whtehr atleast one of the interfaces	**/
	/** of this node is enabled for multicasting.					**/

	FIN (ip_rte_phys_intf_index_from_link_id_obtain (iprmd_ptr, link_objid));

	num_interfaces = inet_rte_num_interfaces_get (iprmd_ptr);
	
	for (i = 0; i < num_interfaces; i++)
		{
		intf_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

		/* Check whether this interface is multicast enabled	*/
		if (ip_rte_intf_mcast_enabled (intf_info_ptr))
			{
			/* We have found a n interface on which multicasting*/
			/* is enabled.										*/
			FRET (OPC_TRUE);
			}
		}

	/* We did not find a multicast interface. return false		*/
	FRET (OPC_FALSE);
	}

IpT_Port_Info
ip_rte_port_info_create (int table_index, char* intf_name)
	{
	/** This function takes an index to the ip interface	**/
	/** table and returns the corresponding physical and	**/
	/** subinterface port info.								**/	
	IpT_Port_Info			port_info;
	
	FIN (ip_rte_port_info_create (table_index));
	
	port_info.intf_tbl_index 	= table_index;
	port_info.minor_port		= IPC_SUBINTF_INDEX_INVALID;
	
	/* This function assumes that interface name string	*/
	/* is in a usable memory location. 					*/
	if (OPC_NIL != intf_name)
		{
		port_info.intf_name = intf_name;
		}
	else
		{
		port_info.intf_name = intf_name_unknown_str;
		}
	
	FRET (port_info);
	}

IpT_Port_Info
ipv6_rte_port_info_create (IpT_Rte_Module_Data* iprmd_ptr, int ipv6_intf_index)
	{
	IpT_Port_Info		port_info;

	/** Creates a port_info_structure from the given IPv6 interface index	**/

	FIN (ipv6_rte_port_info_create (iprmd_ptr, ipv6_intf_index));

	/* Set the minor port to an invalid value.							*/
	port_info.minor_port		= IPC_SUBINTF_INDEX_INVALID;

	/* Handle the case where the interface index is invalid				*/
	if (IPC_INTF_INDEX_INVALID == ipv6_intf_index)
		{
		port_info.intf_tbl_index = ipv6_intf_index;
		port_info.intf_name = intf_name_unknown_str;
		}
	else
		{
		/* Convert the ipv6 interface index into an inet interface index*/
		port_info.intf_tbl_index = inet_ipv6_intf_index_to_inet_index_convert (iprmd_ptr, ipv6_intf_index);
		
		/* Fill in the interface name appropriately.					*/
		port_info.intf_name = ip_rte_intf_name_get (ipv6_rte_intf_tbl_access (iprmd_ptr, ipv6_intf_index));
		}
		
	FRET (port_info);
	}

void
ip_rte_intf_last_load_update_set (IpT_Interface_Info **intf_info_pptr, double new_last_load_update)
	{
	/** This function takes the value specified by new_last_load_update	**/
	/** and sets the corresponding element in the intf_info_pptr		**/

	FIN (ip_rte_intf_last_load_update_set (intf_info_pptr, new_last_load_update));
	(*intf_info_pptr)->last_load_update_time = new_last_load_update;
	FOUT;
	}

void
ip_rte_intf_load_bits_set (IpT_Interface_Info **intf_info_pptr, double new_load_bits)
	{
	/** This function takes the value specified by new_load_bits		**/
	/** and sets the corresponding element in the intf_info_pptr		**/
	
	FIN (ip_rte_intf_load_bits_set (intf_info_pptr, new_load_bits));
	(*intf_info_pptr)->load_bits = new_load_bits;
	FOUT;
	}

void
ip_rte_intf_load_bps_set (IpT_Interface_Info **intf_info_pptr, double new_load_bps)
	{
	/** This function takes the value specified by new_load_bps			**/
	/** and sets the corresponding element in the intf_info_pptr		**/
	
	FIN (ip_rte_intf_load_bps_set (intf_info_pptr, new_load_bps));
	(*intf_info_pptr)->load_bps = new_load_bps;
	FOUT;
	}

void
ip_rte_intf_neighbor_rtr_id_set (IpT_Interface_Info **intf_info_pptr, IpT_Address new_neighbor_rtr_id)
	{
	/** This function takes the value specified by new_neighbor_rtr_id	**/
	/** and sets the corresponding element in the intf_info_pptr		**/
	
	FIN (ip_rte_intf_neighbor_rtr_id_set (intf_info_pptr, new_neighbor_rtr_id));
	(*intf_info_pptr)->phys_intf_info_ptr->neighboring_rtr_id = new_neighbor_rtr_id;
	FOUT;
	}

void
ip_rte_intf_load_bgutil_set (IpT_Interface_Info **intf_info_pptr, struct OmsT_Bgutil_Routed_State *new_load_bgutil)
	{
	/** This function takes the value specified by new_load_bgutil		**/
	/** and sets the corresponding element in the intf_info_pptr		**/
	
	FIN (ip_rte_intf_load_bgutil_set (intf_info_pptr, new_load_bgutil));
	(*intf_info_pptr)->load_bgutil_routed_state_ptr = new_load_bgutil;
	FOUT;
	}

void
ip_rte_intf_mcast_enabled_set (IpT_Interface_Info **intf_info_pptr, Boolean new_mcast_enabled)
	{
	/** This function takes the value specified by new_mcast_enabled	**/
	/** and sets the corresponding element in the intf_info_pptr.		**/
	
	FIN (ip_rte_intf_mcast_enabled_set (intf_info_pptr, new_mcast_enabled));
	(*intf_info_pptr)->multicast_enabled = new_mcast_enabled;
	FOUT;
	}

void
ip_rte_intf_network_address_set (IpT_Interface_Info **intf_info_pptr, IpT_Address new_network_address)
	{
	/** This function takes the value specified by new_network_address	**/
	/** and sets the corresponding element in the intf_info_pptr.		**/
	
	FIN (ip_rte_intf_network_address_set (intf_info_pptr, new_network_address));
	(*intf_info_pptr)->network_address = new_network_address;
	FOUT;
	}

void
ip_rte_intf_name_set (IpT_Interface_Info *intf_info_ptr, char* name)
	{
	/** Allocates enough memory and sets the interfaace name			**/

	FIN (ip_rte_intf_name_set (intf_info_ptr, name));

	if (OPC_NIL == name)
		{
		intf_info_ptr->full_name = OPC_NIL;
		}
	else
		{
		intf_info_ptr->full_name = (char*) op_prg_mem_alloc ((strlen (name) + 1) * sizeof (char));
		strcpy (intf_info_ptr->full_name, name);
		}

	FOUT;
	}

void
ip_rte_pk_stats_update_endsim (void * module_info_ptr, int PRG_ARG_UNUSED(dumlocal_code))
	{

	IpT_Rte_Module_Data * module_data_ptr;

	/** This procedure is scheduled for the end of simulation for the 	**/
	/** purpose of providing a background utilization stat update if 	**/
	/** needed. 														**/  
	FIN (ip_rte_pk_stats_update_endsim (dumlocal_state, dumlocal_code));

	module_data_ptr = (IpT_Rte_Module_Data *) module_info_ptr;  		

	/* Update first the load stats, then the traffic received stats. 	*/
	/* A nil packet pointer means that we do not have a new packet 		*/
	/* to examine for background utilization information.				*/ 

	/* Update the pk received statistics.								*/		
	/* These statistics take into account background traffic, if any.	*/
	ip_rte_pk_stats_update (module_data_ptr, OPC_NIL, 
		&module_data_ptr->received_last_stat_update_time,
		module_data_ptr->received_bgutil_routed_state_ptr, 
		&module_data_ptr->locl_tot_pkts_rcvd_hndl);

	/* Update the pk sent statistics.									*/		
	/* These statistics take into account background traffic, if any.	*/
	ip_rte_pk_stats_update (module_data_ptr, OPC_NIL, 
		&module_data_ptr->sent_last_stat_update_time,
		module_data_ptr->sent_bgutil_routed_state_ptr, 
		&module_data_ptr->locl_tot_pkts_sent_hndl);

	/* If this node supports IPv6, update the IPv6 stats also.			*/
	if (ip_rte_node_ipv6_active (module_data_ptr))
		{
		/* Update the pk received statistics.								*/		
		/* These statistics take into account background traffic, if any.	*/
		ip_rte_pk_stats_update (module_data_ptr, OPC_NIL, 
			&module_data_ptr->received_last_stat_update_time,
			module_data_ptr->received_bgutil_routed_state_ptr, 
			&module_data_ptr->locl_tot_ipv6_pkts_rcvd_hndl);

		/* Update the pk sent statistics.									*/		
		/* These statistics take into account background traffic, if any.	*/
		ip_rte_pk_stats_update (module_data_ptr, OPC_NIL, 
			&module_data_ptr->sent_last_stat_update_time,
			module_data_ptr->sent_bgutil_routed_state_ptr, 
			&module_data_ptr->locl_tot_ipv6_pkts_sent_hndl);
		}

	
    FOUT;
	}

Boolean
ip_basetraf_protocol_parse(void** protocol_info_ptr, char* sname, char* dname, 
	char* stat_annotate_str, Objid bgutil_specs_objid, Objid demand_objid, 
	Objid dest_objid, Boolean is_src_to_dest_traffic)
	{
	IpT_Conversation_Info* 		ip_conv_info_ptr; 
	char 						addr_str[INETC_ADDR_STR_LEN];
	char						temp_str [256];
	InetT_Address* 				dest_net_addr; 
	Boolean 					dest_set = OPC_FALSE; 
	
	InetT_Address* 				src_ip_addr_ptr; 
	Objid 						src_objid;
		
	
	FIN (ip_basetraf_protocol_parse(protocol_info, hname, dname,...));
    /* Parses the IP-specific field of conversation pair data */
    /* at the time the traffic agenda is built.               */
	/* Returns TRUE if destination IP address is successfully */
	/* set inside the IP-specific protocol information.       */
		 
	ip_conv_info_ptr = (IpT_Conversation_Info*) op_prg_mem_alloc(
	   sizeof(IpT_Conversation_Info));
	
    /* Initialize ip_conv_info_ptr's members */
	ip_conv_info_ptr->demand_name = OPC_NIL;
	ip_conv_info_ptr->src_addr = INETC_ADDRESS_INVALID; 
	ip_conv_info_ptr->dest_addr = INETC_ADDRESS_INVALID;
	ip_conv_info_ptr->route_record_option = OmsC_Tracer_RR_One_Per_Flow; 
	ip_conv_info_ptr->route_recorded = OPC_FALSE;
	ip_conv_info_ptr->bgutil_tos = OmsC_Qm_Tos_Unspecified;
	ip_conv_info_ptr->actual_src_addr = INETC_ADDRESS_INVALID; 
	ip_conv_info_ptr->actual_dest_addr = INETC_ADDRESS_INVALID; 
	ip_conv_info_ptr->src_port 	= OPC_INT_INVALID; 
	ip_conv_info_ptr->dest_port = OPC_INT_INVALID; 
	ip_conv_info_ptr->protocol	= OPC_INT_INVALID; 
	ip_conv_info_ptr->policy_check_info_ptr 	= OPC_NIL;
	ip_conv_info_ptr->demand_name = OPC_NIL;
	
	/* Read in IP-specific attributes */
	if (op_ima_obj_attr_exists(bgutil_specs_objid, "Type of Service"))
		{
		op_ima_obj_attr_get(bgutil_specs_objid, "Type of Service",
			&ip_conv_info_ptr->bgutil_tos);
		}
	
	if (op_ima_obj_attr_exists(bgutil_specs_objid, "Record Route Option"))
		{
		op_ima_obj_attr_get(bgutil_specs_objid, "Record Route Option", 
			&ip_conv_info_ptr->route_record_option);
		}
	
	/* Read in the src IP address from demand attribute		*/
	/* If valid, assign it to the IP-specific protocol info */
	if (is_src_to_dest_traffic)
		op_ima_obj_attr_get(demand_objid, "Source IP Address", addr_str);
	else
		op_ima_obj_attr_get(demand_objid, "Destination IP Address", addr_str);
	
	if (ip_address_string_test(addr_str))
		{
		ip_conv_info_ptr->src_addr = inet_address_create(addr_str, InetC_Addr_Family_v4);
		}
	
	/* Read in the dest IP address from demand attribute */
	/* If valid, assign it to the IP-specific protocol info */
	/* Otherwise let the loopback interface be chosen for   */
	/* destination. 										*/
	if (is_src_to_dest_traffic)
		op_ima_obj_attr_get(demand_objid, "Destination IP Address", addr_str);
	else
		op_ima_obj_attr_get(demand_objid, "Source IP Address", addr_str);
	
	if (ip_address_string_test(addr_str))
		{
	    ip_conv_info_ptr->dest_addr = inet_address_create(addr_str, InetC_Addr_Family_v4); 
		dest_set = OPC_TRUE; /* remember if dest. successfully set */
		}
	else
		{
		dest_set = (oms_basetraf_node_addr_from_objid(dest_objid, OmsC_Protocol_IP, 
			(void**) &dest_net_addr) == OPC_COMPCODE_SUCCESS); /* remember if dest. successfully set */
		if (dest_set)
			{
			ip_conv_info_ptr->dest_addr = inet_address_copy (*dest_net_addr); 
			}
		}
	
	/* Read in the actual src IP address from demand attribute		*/
	/* If valid, assign it to the IP-specific protocol info 		*/
	op_ima_obj_attr_get(demand_objid, "Actual Source IP Address", addr_str);
	if (strcmp (addr_str, "Same As Source") == 0)
		{
		/* Make sure that the src address is valid					*/
		if (inet_address_valid (ip_conv_info_ptr->src_addr))
			{
			/* Source address is valid, copy it to actual address	*/
			ip_conv_info_ptr->actual_src_addr = inet_address_copy(ip_conv_info_ptr->src_addr);
			}
		else
			{
			/* Source address is invalid thus						*/			
			/* Get the source that originated this demand 			*/
			src_objid = op_topo_assoc(demand_objid, OPC_TOPO_ASSOC_OUT, OPC_OBJTYPE_NDFIX, 0);
			
			/* Get the IP address for the src object				*/			
			if (oms_basetraf_node_addr_from_objid(src_objid, OmsC_Protocol_IP, (void**) &src_ip_addr_ptr) == OPC_COMPCODE_SUCCESS)
				{
				/* Store this objects address as actual src IP addr	*/
				ip_conv_info_ptr->actual_src_addr = *src_ip_addr_ptr; 
				}
			}
		}
	else if (ip_address_string_test(addr_str))
		ip_conv_info_ptr->actual_src_addr = inet_address_create(addr_str, InetC_Addr_Family_v4);
	
		
	/* Read in the actual dest IP address from demand attribute 	*/
	/* If valid, assign it to the IP-specific protocol info 		*/
	/* Otherwise let the loopback interface be chosen for   		*/
	/* destination. 												*/
	op_ima_obj_attr_get(demand_objid, "Actual Destination IP Address", addr_str);
	if (strcmp (addr_str, "Same As Destination") == 0)
		ip_conv_info_ptr->actual_dest_addr = ip_address_copy(ip_conv_info_ptr->dest_addr);
	else if (ip_address_string_test(addr_str))
		ip_conv_info_ptr->actual_dest_addr = inet_address_create(addr_str, InetC_Addr_Family_v4); 
		
	/* Read in Source/Dest ort and protocol information				*/
	op_ima_obj_attr_get(demand_objid, "Source Port", &ip_conv_info_ptr->src_port); 
	op_ima_obj_attr_get(demand_objid, "Destination Port", &ip_conv_info_ptr->dest_port); 
	op_ima_obj_attr_get(demand_objid, "Protocol", &ip_conv_info_ptr->protocol); 
	
	
	/* Read in the name of the demand. This is used to	*/
	/* distinguish between various demands, when		*/
	/* looking at the demands in the route browser		*/
	op_ima_obj_attr_get(demand_objid, "name", temp_str);
	ip_conv_info_ptr->demand_name = (char*) op_prg_mem_alloc ((strlen (temp_str) + 1) * sizeof (char));
	strcpy (ip_conv_info_ptr->demand_name, temp_str);

	/* Create an IP-specific stat annotation for Ete Delay stat */
	if ((sname != OPC_NIL) &&
		(dname != OPC_NIL) &&
		(stat_annotate_str != OPC_NIL))
		{
		sprintf(stat_annotate_str, "%s -> %s [TOS %d]", sname, dname,  
											ip_conv_info_ptr->bgutil_tos);
		}
		
	/* Return the ptr to the IP-specific        */
    /* conversation data in the form of 'void*' */
	*protocol_info_ptr = ip_conv_info_ptr; 

	FRET(dest_set); 
	}

/* ---- (SECTION_ICP) Internally Callable Procedures ---- */

static Boolean
ip_mpls_lsp_status_get (IpT_Rte_Module_Data* iprmd_ptr, char* lsp_name_str, int in_iface)
	{
	MplsT_Label_Space_Handle	temp_mpls_lib_space_table_ptr = OPC_NIL;
	Boolean						lsp_status = OPC_FALSE;
	
	/** MPLS maintains NHLFEs based on FEC names and LSP names	**/
	/** NHLFE exists only if LSP is active. This function is	**/
	/** used to find status of LSP. A packet should can be		**/
	/** re-directed to MPLS only if has an associated NHLFE.	**/
	FIN (ip_mpls_lsp_status_get (char* lsp_name_str, int in_iface));
	
	/* Get the ptr to Label Space Tabel							*/
	temp_mpls_lib_space_table_ptr = iprmd_ptr->mpls_lib_space_table_ptr [in_iface];
	
	if (temp_mpls_lib_space_table_ptr == OPC_NIL)
		FRET (OPC_FALSE);

	/* Check if there is a valid NHLFE for this LSP name 		*/
	lsp_status = mpls_nhlfe_for_fec_exist (temp_mpls_lib_space_table_ptr, (MplsT_FEC) lsp_name_str);
		
	FRET (lsp_status);	
	}

static char*
ip_mpls_packet_classify (IpT_Rte_Module_Data* iprmd_ptr, Packet* pkt_ptr, int in_iface)
	{
	int							tos;
	int							protocol;
	IpT_Address					dest_address;
	IpT_Address					source_address;
	int							source_port;
	int							dest_port;
	int							fec_index;
	char*						fec_name 			= OPC_NIL;
	int							fec_list_size;
	MplsT_Fec_Info*				mpls_fec_info_ptr 	= OPC_NIL;
	MplsT_Label_Space_Handle	temp_mpls_lib_space_table_ptr = OPC_NIL;
	Packet*						tracer_pk_ptr 		= OPC_NIL;
	IpT_Tracer_Pkt_IP_Info*		tracer_ip_info_ptr 	= OPC_NIL;
	Boolean						nhlfe_exist 		= OPC_FALSE;
	IpT_Pkt_Socket_Info 		pkt_ip_info;
	
	/* Construct FEC for the packet */
	FIN (ip_mpls_packet_classify (Packet* pkt_ptr));
	
	/* Check and make sure that MPLS FECs exist								*/
	/* If no then exit the function and return nil							*/
	if (iprmd_ptr->mpls_fecs_lptr == OPC_NIL)
		FRET (OPC_NIL);
		
	/* Get the ptr to Label Space Tabel										*/
	temp_mpls_lib_space_table_ptr = iprmd_ptr->mpls_lib_space_table_ptr [in_iface];
			
	/* If MPLS Info is not available then return NIL						*/
	if ((iprmd_ptr->mpls_fecs_lptr == OPC_NIL) || (temp_mpls_lib_space_table_ptr == OPC_NIL))
		FRET (OPC_NIL);
	
	/* Get the ToS, protocol, IP source and destination 					*/
	/* addresses from the packet.		   									*/	   
	if (OPC_COMPCODE_FAILURE == (ip_support_ip_pkt_socket_info_extract (pkt_ptr, &pkt_ip_info)))
		FRET (OPC_NIL);
	
	/* Get the ToS, protocol, IP source and destination 					*/
	/* addresses from the datagram.		   									*/	   
	tos 	  		=  pkt_ip_info.packet_tos; 
	protocol 		=  pkt_ip_info.protocol;   				    	
	
	/* Get the source and destination IP addresses.							*/
	source_address 	= inet_ipv4_address_get (pkt_ip_info.source_address);
	dest_address 	= inet_ipv4_address_get (pkt_ip_info.dest_address);
	
	/* Get the source and destination ports									*/
	source_port		= pkt_ip_info.source_port;
	dest_port		= pkt_ip_info.dest_port;	
	
	/* Loop throgh the list of specified FECs and see if a match is found 	*/
	fec_list_size = op_prg_list_size (iprmd_ptr->mpls_fecs_lptr);
					
	/* Loop through all FECs to find the right match.						*/
	for (fec_index = 0; fec_index < fec_list_size; fec_index++)
		{
		/* Get a fec entry from the list 									*/
		mpls_fec_info_ptr = (MplsT_Fec_Info*) op_prg_list_access (iprmd_ptr->mpls_fecs_lptr, fec_index);
		
		/* First check if this fec was parsed for this iface 				*/
		if (mpls_fec_info_ptr->parsed_iface != in_iface)
			continue;
		
		/**** Perform lookup ****/
		/* Check TOS 														*/
		if ((mpls_fec_info_ptr->tos != Unspecified_Int) && (mpls_fec_info_ptr->tos != tos))
			continue;
		
		/* Check protocol 													*/
		if ((mpls_fec_info_ptr->protocol != Unspecified_Int) && (mpls_fec_info_ptr->protocol != protocol))
			continue;
		
		/* Check src port 													*/
		if ((mpls_fec_info_ptr->src_port != Unspecified_Int) && (mpls_fec_info_ptr->src_port != source_port))
			continue;
		
		/* Check dest port 													*/
		if ((mpls_fec_info_ptr->dest_port != Unspecified_Int) && (mpls_fec_info_ptr->dest_port != dest_port))
			continue;
		
		/* Check incoming interface 										*/
		if ((mpls_fec_info_ptr->in_iface != Unspecified_Int) && (mpls_fec_info_ptr->in_iface != in_iface))
			continue;
		
		/* Check source address 											*/
		if ((mpls_fec_info_ptr->src_addr_range_ptr != OPC_NIL) && 
			(ip_address_range_check (source_address, mpls_fec_info_ptr->src_addr_range_ptr) == OPC_FALSE))
			continue;
		
		/* Check destination address 										*/
		if ((mpls_fec_info_ptr->dest_addr_range_ptr != OPC_NIL) &&
			(ip_address_range_check (dest_address, mpls_fec_info_ptr->dest_addr_range_ptr) == OPC_FALSE))
			continue;
		
		/* All the filed match so get the FEC name							*/
		fec_name = mpls_fec_info_ptr->fec_name;
		
		/* Check if there is a valid NHLFE for this FEC name 				*/
		nhlfe_exist = mpls_nhlfe_for_fec_exist (temp_mpls_lib_space_table_ptr, (MplsT_FEC) fec_name);
	
		/* If there is no NHLFE for this FEC then set FEC name to NIL again */
		if (nhlfe_exist == OPC_FALSE)
			fec_name = OPC_NIL;
		
		break;
		}
						
	FRET (fec_name);
	}

static void
ip_forward_packet_to_output_queues (IpT_Rte_Module_Data * iprmd_ptr,
	Packet* pk_ptr, int outstrm, Ici* iciptr, int pkt_txtype, 
	int output_interface_index, int incoming_iface)
	{
	IpT_Interface_Info*		iface_info_ptr;

	/** This function is in charge of sending a packet when	**/
	/** a output queuing processing scheme such as WFQ, 	**/
	/** FIFO, Priority Queuing or Custom Queuing is chosen.	**/
	/** It is called after being put in the	main queue in 	**/
	/** the case of "Central Processing", or after being 	**/
	/** put in the output slot queue in the case of "slot	**/
	/** based processing". NOTE that the output queues		**/
	/** process might discard packets, when it determines	**/	
	/**	that there is congestion.							**/
	FIN (ip_forward_packet_to_output_queues (pk_ptr, outstream, iciptr, pkt_txtype, output_interface_index, incoming_iface));

	/* Set the incoming interface in the ICI.	*/
	if (op_ici_attr_set (iciptr, "incoming_iface", incoming_iface) == OPC_COMPCODE_FAILURE)
		(*iprmd_ptr->error_proc) ("Unable to set incoming interface in ICI.");

	/* Set the IP Packet Type in order to write a statistic for	*/
	/* the specific type of packet sent. (multicast...)			*/
	if (op_ici_attr_set (iciptr, "pkt_txtype", pkt_txtype) == OPC_COMPCODE_FAILURE)
        (*iprmd_ptr->error_proc) ("Unable to set packet type in ICI.");

	/* Associate the ICI to the current packet	*/
	op_pk_ici_set (pk_ptr, iciptr);	

	/* Give to the child process via the shared		*/
	/* via the shared memory the outstream where	*/
	/* the packet will be sent and a specific IP	*/
	/* function which reads IP attributes.			*/
	iprmd_ptr->shared_mem.outstream = outstrm;
	iprmd_ptr->shared_mem.iface_index = output_interface_index;
	
	/* Call the output_iface child process in charge of the output queues.	*/
	iface_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, output_interface_index);
	op_pro_invoke (iface_info_ptr->output_iface_prohandle, pk_ptr);

	FOUT;
	}


static void
ip_inface_statistic_update (IpT_Rte_Module_Data * iprmd_ptr, 
	int output_strm, double pkt_bitsize, Packet * pkptr)
	{
	int						i_th_iface;
	int						active_interfaces;
	IpT_Interface_Info*		i_th_iface_info_ptr;

	double 					curr_sim_time;
	double					background_utilization_bps;
	double					background_utilization_bits;
	double					bgutil_routed_packets_per_sec;
	double					bgutil_routed_pk_size_std_dev;
	char					msg [512];
	
	/** Updates the statistics maintains on aper interface basis.	**/	
	/** The interface for which the statistics needs to be updated	**/
	/** is determined based on the output stream the datagram is	**/
	/** being forwarded on.											**/
	FIN (ip_inface_statistic_update (output_strm, pkt_bitsize, pkptr));

	/* Obtain the current sim time.	*/
	curr_sim_time = op_sim_time ();
	
	/* Obtain the total number of active interfaces.				*/
	active_interfaces = ip_rte_num_interfaces_get (iprmd_ptr);

	/* Loop thorugh these interfaces to find the one of interest.	*/
	for (i_th_iface = 0; i_th_iface < active_interfaces; i_th_iface++)
		{
		/* Obtain a handle on the i_th interface.					*/
		i_th_iface_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i_th_iface);

		/* Check if the output stream on which the packet is being	*/
		/* sent correcponds to this interface.						*/
		if (ip_rte_intf_out_port_num_get (i_th_iface_info_ptr) == output_strm)
			{
			/* This is the interface of interest. increment the		*/
			/* load statistic accumulator for this interface to		*/
			/* reflect the total number of bits sent to date.		*/
			ip_rte_intf_load_bits_set (&i_th_iface_info_ptr, ip_rte_intf_load_bits_get (i_th_iface_info_ptr) + pkt_bitsize);

			/* Determine if we are using background utilization.	*/
			if (iprmd_ptr->do_bgutil)
				{
				/* We are using background utilization.				*/
				if (ip_rte_intf_load_bgutil_get (i_th_iface_info_ptr) == OPC_NIL)
					{
					/* This background utlization routed state has never 	*/
					/* been used. As a memory optimization, only 			*/
					/* allocate the routed state pointer when the interface */
					/* is first used (which is now).						*/
					/* As the interface is serviced at link data rate, we	*/
				   	/* assume units of bps for this table.					*/
					/* Scaling the table is not necessary as this call occurs*/
			        /* on the interface, after scaling inside CPU            */
					ip_rte_intf_load_bgutil_set (&(i_th_iface_info_ptr), 
						oms_bgutil_routed_state_create (UNITS_IN_BPS, DO_NOT_SCALE));
					}

				/* Obtain the background utilization till the current time.	*/
				/* The value returned denotes the background utilization 	*/
				/* which is valid until right before the current time.  	*/
				/* This function is efficient if there is no routed 		*/
				/* background utilization.									*/
				/* Use a data rate of 1.0 so that this function returns 	*/
				/* bps instead of util.										*/
				background_utilization_bps = oms_bgutil_routed_utilization_get (
					ip_rte_intf_load_bgutil_get (i_th_iface_info_ptr), 
					pkptr, curr_sim_time, 1.0, &bgutil_routed_packets_per_sec, 
					&bgutil_routed_pk_size_std_dev, OmsC_Bgutil_Get_Prev);
				
				/* We are only interested in the bits/sec.  Fill the bit 	*/
				/* usage counter up with the number of bits due to 			*/
				/* background utilization since this measurement interval 	*/
				/* started. In the future, a more sophisticated method		*/
				/* of filling the bit counter could be used.				*/
				background_utilization_bits = background_utilization_bps *
					(curr_sim_time - ip_rte_intf_last_load_update_get (i_th_iface_info_ptr));

				/* Add these bgutil bits to the per interface load.			*/
				ip_rte_intf_load_bits_set (&i_th_iface_info_ptr,
					ip_rte_intf_load_bits_get (i_th_iface_info_ptr) + background_utilization_bits);

				/* We have now accounted for the background utilization over*/
			    /* this inteface up till the current time.  This will be the*/
				/* starting time the next time we have to update the load.	*/
				ip_rte_intf_last_load_update_set (&i_th_iface_info_ptr, curr_sim_time);
				}
			else
				{
				/* We are not doing background utilization in this simulation.*/
				background_utilization_bits = 0.0;
				}
				
			ip_rte_intf_load_bps_set (&i_th_iface_info_ptr, ip_rte_intf_load_bits_get (i_th_iface_info_ptr) / curr_sim_time);

			if (op_prg_odb_ltrace_active ("ip_rte_interface_load"))
				{
				sprintf (msg, "Adding explicit (%f) and bgutil (%f) bits to load on interface index (%i)",
					pkt_bitsize, background_utilization_bits, i_th_iface); 
				op_prg_odb_print_major (msg, OPC_NIL);
				}
			/* Break out of the loop now that we have found the correct		*/
			/* interface.													*/
			break;
			}
		}

	FOUT;
	}

static void
ip_src_address_determine (InetT_Address *src_addr_ptr, IpT_Rte_Module_Data* iprmd_ptr,
	int intf_tbl_index, InetT_Addr_Family addr_family)
	{
	IpT_Interface_Info *	iface_elem_ptr;

	/** This procedure is used to determine the correct src address based **/
	/** on the next hop address.                                          **/
	FIN (ip_src_address_determine (dest_addr, src_addr_ptr, iface_table_ptr, addr_family));

	/* Get the interface_info of the interface specified.					*/
	iface_elem_ptr = inet_rte_intf_tbl_access (iprmd_ptr, intf_tbl_index);

	/* If the interface is unnumbered, use the network address as the		*/
	/* source address. Otherwise, use the interface address.				*/
	if (OPC_TRUE == ip_rte_intf_unnumbered (iface_elem_ptr))
		{
		*src_addr_ptr = inet_address_from_ipv4_address_create (ip_rte_intf_network_address_get (iface_elem_ptr));
		}
	else
		{
		*src_addr_ptr = inet_rte_intf_addr_get (iface_elem_ptr, addr_family);
		}
	FOUT;
	}

static void
ip_rte_pk_fragment (IpT_Rte_Module_Data * iprmd_ptr, Packet *pk_ptr, 
	InetT_Address dest_addr, InetT_Address next_addr, 
	int conn_class, IpT_Rte_Ind_Ici_Fields* intf_ici_ptr)
	{
	OpT_Packet_Size			frag_size, data_size, len; 
	OpT_Packet_Size			header_size;
	int						num_frags, frag_index, frag_accum;
	OpT_Packet_Size			original_size_accum; 
	char					str0 [512];
	Packet *				ip_pkptr;
	Packet *				data_pkptr;
	Packet *				frag_ptr;
	Packet *                bgutil_pkptr;
	Boolean					is_frag;
	IpT_Dgram_Fields*		pk_fd_ptr;
	IpT_Dgram_Fields*		frag_pk_fd_ptr;
	int						mtu;
	int						interface_type;
	int						interface_index;
	IpT_Interface_Info*		iface_info_ptr;
	int						offset;
	InetT_Addr_Family		addr_family;

	/**	Fragment the IP packet and send the fragments over the given  **/
	/**	Also assocaites an ICI if the interface can process an ICI	  **/
	/**	(e.g., ARP) -- such interfaces are called smart interfaces.	  **/
	/** Point-to-Point duplex link comes in the category of a "Dumb"  **/
	/**	interface as it cannot process an incoming ICI, and will, 	  **/
	/**	therefore, leak memory, if installed for such interfaces.	  **/
	FIN (ip_rte_pk_frag_send (pk_ptr, dest_addr, next_addr, conn_class, intf_ici_ptr));

	/* Find out if we are dealing with an IPv4 or an IPv6 packet.	*/
	addr_family = inet_address_family_get (&dest_addr);

	/* Obtain the interface parameters from the Interface ICI		*/
	mtu 			= intf_ici_ptr->output_mtu;
	interface_type 	= intf_ici_ptr->interface_type;
	interface_index = intf_ici_ptr->output_intf_index;

	/* Applies the CAR policy. CAR limits the traffic based on application	*/
	/* type, incoming port or TOS. Non conforming traffic might be dropped.	*/
	if (iprmd_ptr->car_outgoing_profile_ptr [interface_index] != OPC_NIL &&
		iprmd_ptr->car_outgoing_profile_ptr [interface_index]->car_status == OPC_TRUE)
		{
		/* Returns whether the packet has to dropped to follow the	*/
		/* policy. If the packet doesn't comply the policy, it is	*/
		/* necessarily dropped but only set to a lower precedence.	*/		
		if (Ip_Qos_Car_Policy_Limit (pk_ptr, intf_ici_ptr->intf_recvd_index, iprmd_ptr->car_outgoing_profile_ptr [interface_index],
			iprmd_ptr->car_outgoing_info_ptr [interface_index]))
			{
			/* Write a statistic for packet dropped on this interface*/
			op_stat_write (iprmd_ptr->car_stat_info_ptr [interface_index].out_traffic_dropped_in_bps_stathandle, op_pk_total_size_get (pk_ptr));
			op_stat_write (iprmd_ptr->car_stat_info_ptr [interface_index].out_traffic_dropped_in_bps_stathandle, 0);

			op_stat_write (iprmd_ptr->car_stat_info_ptr [interface_index].out_traffic_dropped_in_pps_stathandle, 1);
			op_stat_write (iprmd_ptr->car_stat_info_ptr [interface_index].out_traffic_dropped_in_pps_stathandle, 0);

			if (op_prg_odb_ltrace_active ("car"))
				{
				sprintf (str0, "CAR drops packet " SIMC_PK_ID_FMT " to conform rate policies.", op_pk_id (pk_ptr));
				op_prg_odb_print_major (str0, OPC_NIL);
				}

			/* Drop the current IP datagram.	*/
			ip_rte_dgram_discard (iprmd_ptr, pk_ptr, OPC_NIL, "Rejected on CAR policy violation");

			FOUT;
			}
		}

	/* Check if this is a bgutil tracer packet. */
	if (op_pk_encap_flag_is_set (pk_ptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX))
		{
		/* Get a copy of the bgutil packet.		*/
		op_pk_encap_pk_get (pk_ptr, "bgutil_tracer", &bgutil_pkptr);
		
		/* Segment the background traffic based on the interface mtu*/
		oms_bgutil_segmentation_info_update (bgutil_pkptr, OPC_NIL, OmsC_Tracer_IP,    
			 OMSC_BGUTIL_OVERHEAD_IP, 8.0 * mtu, 0.0, oms_bgutil_tracer_segment_func, 
			 OPC_TRUE, OPC_NIL); 

		/* Destroy the copy packet.				*/
		op_pk_destroy (bgutil_pkptr);
		}
	
	/* Get a handle to the output interface.						*/
	iface_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, interface_index);

	/* Associate an ICI to the datagram only if the interface type 	*/
	/* is smart,  i.e if the interface can process the ICI. Before	*/
	/* make sure an interface has been identified.					*/
	if (interface_type == IpC_Intf_Type_Unspec)
		{
		(*iprmd_ptr->error_proc) ("Interface of type \"unspecified\" encountered.");
		}

	/* Obtain the size in bytes of the packet. */
	frag_size = op_pk_total_size_get (pk_ptr) / 8;

	/*	Get the fields structure from ip datagram.					*/
	op_pk_nfd_access (pk_ptr, "fields", &pk_fd_ptr);

	/* Obtain the number of bytes of data carried in this fragment. */
	data_size = pk_fd_ptr->frag_len;

	/* Extract the offset of the fragment							*/
	offset = pk_fd_ptr->offset;

	/* Also obtain the difference between the packet size and		*/
	/* the length field; this is the size of the header.     		*/
	header_size = frag_size - data_size;

	/* If the fragment size is smaller than the MTU, send as is. 	*/
	/* Also make sure that if we will compress the packet it is		*/
	/* still smaller than MTU after compression. This rare case		*/
	/* can happen when Per-Interface compression method is used		*/
	/* (where packet are compressed after fragmentation if			*/
	/* fragmentation is necessary) and if the compression actually	*/
	/* results with a greater packet than original packet, which	*/
	/* may happen based on compression ratio PDF.					*/
	if ((frag_size <= mtu) && 
        (pk_fd_ptr->compression_method == IpC_No_Compression || 
			(OpT_Packet_Size) iprmd_ptr->dgram_compressed_size <= mtu * 8))
		{
		/* Call the function that will send this fragment to the	*/
		/* lower layer.												*/
		ip_rte_frag_send (iprmd_ptr, pk_ptr, addr_family, dest_addr,
			next_addr, conn_class, iface_info_ptr, intf_ici_ptr);

		/* Nothing more to be done. Return.							*/
		FOUT;
		}

	/* We might have to break the packet up into fragments.			*/

	/* When Per-Interface compression is used, if the compressed	*/
	/* compressed packet is greater than the actual packet, which	*/
	/* may happen based on the compression ratio PDF, we need to	*/
	/* adjust the MTU for proper fragmentation.						*/
	if ((pk_fd_ptr->compression_method == IpC_Per_Interface_Comp) 
		&& ((OpT_Packet_Size) iprmd_ptr->dgram_compressed_size > frag_size * 8))
		{
		mtu = (int) (mtu * ((double) frag_size * 8 / iprmd_ptr->dgram_compressed_size));
		}

	/* For IPv6 fragments will have an addtional fragment header	*/
	/* add the size of the fragment header to the header size.		*/
	if (InetC_Addr_Family_v6 == addr_family)
		{
		header_size += IPV6C_DGRAM_FRAG_HEADER_LEN_BYTES;
		}

	/* The number of data bytes that can be sent out in each		*/
	/* fragment will be mtu - header_size. Calculate the number		*/
	/* of fragments required to send the entire data.				*/
	num_frags = (data_size + (mtu - header_size) - 1) / (mtu - header_size);

	/* In debug mode indicate the fragmentation. */
	if (op_prg_odb_ltrace_active ("ip_frag"))
		{
		sprintf (str0, "Breaking datagram into (%d) fragments", num_frags);
		op_prg_odb_print_major (str0, OPC_NIL);
		}

	/* If the fragment is carrying the original datagram given to	*/
	/* IP, extract it before copies are made.  Only one fragment	*/
	/* can carry the original packet for the reassembly model to	*/
	/* work properly.												*/
	if (op_pk_nfd_is_set (pk_ptr, "ip_dgram"))
		{
		if (op_pk_nfd_get (pk_ptr, "ip_dgram", &ip_pkptr) == OPC_COMPCODE_FAILURE)
			(*iprmd_ptr->error_proc) ("Unable to get datagram from packet.");
		}
	else
		ip_pkptr = OPC_NIL;

	/* If the packet is carrying any encapsulated data (normally this */
	/* would happen only for a packet fragmented for the first time), */
	/* extract this data packet so that it will not appear in each    */
	/* fragment generated by copying.                                 */
	if (op_pk_nfd_is_set (pk_ptr, "data"))
		{
		if (op_pk_nfd_get (pk_ptr, "data", &data_pkptr) == OPC_COMPCODE_FAILURE)
			(*iprmd_ptr->error_proc) ("Unable to get data from packet.");
		}
	else
		data_pkptr = OPC_NIL;

	frag_accum = 0;
	original_size_accum = 0;
	for (frag_index = 0; frag_index < num_frags; frag_index++)
		{
		/* Make a copy of the original packet. */
		frag_ptr = op_pk_copy (pk_ptr);
		if (frag_ptr == OPC_NIL)
			(*iprmd_ptr->error_proc) ("Unable to copy packet to be fragmented.");

		op_pk_nfd_access (frag_ptr, "fields", &frag_pk_fd_ptr);

		/* Indicate that the copy is a fragment. */
		frag_pk_fd_ptr->frag = 1;
		
		/* Set the correct offset of this fragment */
		frag_pk_fd_ptr->offset = offset + frag_accum;

		/* For all but the last fragment, the size is the MTU */
		/* and the encapsulated IP packet is not included.    */
		if (frag_index < num_frags - 1)
			{
			frag_pk_fd_ptr->frag_len = mtu - header_size;

			if (op_pk_total_size_set (frag_ptr, 8 * mtu) == OPC_COMPCODE_FAILURE)
				(*iprmd_ptr->error_proc) ("Unable to set size of fragment.");
			
			frag_accum += (mtu - header_size);

			/* If payload is compressed then we need to also	*/
			/* adjust the field original_size, which determines */
			/* the datagrams' size after decompression, since	*/
			/* the fragments will first decompressed and then	*/
			/* assembled. Otherwise after decompression all the	*/
			/* fragments would have the size of the original,	*/
			/* unfragmented packet. Made the adjustment based	*/
			/* on the equality of size ratios:					*/
			/* compressed load in fragment / compressed load =	*/
			/* load in fragment / load							*/
			if (frag_pk_fd_ptr->compression_method == IpC_Per_Virtual_Circuit_Comp)
				{
				frag_pk_fd_ptr->original_size = (int)
					((frag_pk_fd_ptr->original_size - header_size * 8) * ((double) frag_pk_fd_ptr->frag_len / (double) data_size) + header_size * 8);

				/* Adjust the original size to byte size (i.e.	*/
				/* multiple of eight). This is necessary for	*/
				/* proper re-assembly of the fragments at the	*/
				/* other end.									*/
				frag_pk_fd_ptr->original_size = (frag_pk_fd_ptr->original_size / 8) * 8;

				original_size_accum += frag_pk_fd_ptr->original_size - header_size * 8;
				}

			/* If Per-Interface compression is used then the	*/
			/* datagrams are compressed after fragmentation.	*/
			/* Check the compression method and compress if		*/
			/* necessary.										*/
			else if (frag_pk_fd_ptr->compression_method == IpC_Per_Interface_Comp)
				{
				/* Store the original size of the packet, which	*/
				/* will be used for decompression.				*/
				frag_pk_fd_ptr->original_size = mtu * 8;

				/* Resize the packet proportional to the 		*/
				/* compression ratio.							*/ 
				op_pk_total_size_set (frag_ptr, (OpT_Packet_Size) ((iprmd_ptr->dgram_compressed_size / frag_size) * mtu));

				/* Issue a trace statement.						*/
				if (LTRACE_COMPRESSION_ACTIVE || op_prg_odb_pktrace_active (frag_ptr))
					ip_rte_comp_decomp_trace_print (frag_ptr, frag_pk_fd_ptr->compression_method, frag_pk_fd_ptr->original_size,
						(OpT_Packet_Size) ((iprmd_ptr->dgram_compressed_size / frag_size) * mtu), "compression");
				}
			}
		else
			{
			/* For the last fragment, set the fragment size to be */
			/* whatever packet size remains plus the header size. */
			len = data_size - frag_accum;
			frag_pk_fd_ptr->frag_len = len;
			if (op_pk_total_size_set (frag_ptr, 8 * (header_size + len)) == OPC_COMPCODE_FAILURE)
				(*iprmd_ptr->error_proc) ("Unable to set size of final fragment.");

			/* If payload is compressed then we need to also	*/
			/* adjust the field original_size, which determines */
			/* the datagrams' size after decompression, since	*/
			/* the fragments will first decompressed and then	*/
			/* assembled. Otherwise after decompression all the	*/
			/* fragments would have the size of the original,	*/
			/* unfragmented packet. The last fragment claims	*/
			/* the remainings of the uncompressed load.			*/ 
			if (frag_pk_fd_ptr->compression_method == IpC_Per_Virtual_Circuit_Comp)
				frag_pk_fd_ptr->original_size -= original_size_accum;

			/* If Per-Interface compression is used then the	*/
			/* datagrams are compressed after fragmentation.	*/
			/* Check the compression method and compress if		*/
			/* necessary.										*/
			else if (frag_pk_fd_ptr->compression_method == IpC_Per_Interface_Comp)
				{
				/* Store the original size of the packet, which	*/
				/* will be used for decompression.				*/
				frag_pk_fd_ptr->original_size =  8 * (header_size + len);

				/* Resize the packet proportional to the 		*/
				/* compression ratio.							*/ 
				op_pk_total_size_set (frag_ptr, (OpT_Packet_Size) ((iprmd_ptr->dgram_compressed_size / frag_size) * (header_size + len)));

				/* Issue a trace statement.						*/
				if (LTRACE_COMPRESSION_ACTIVE || op_prg_odb_pktrace_active (frag_ptr))
					ip_rte_comp_decomp_trace_print (frag_ptr, frag_pk_fd_ptr->compression_method, frag_pk_fd_ptr->original_size,
						(OpT_Packet_Size) ((iprmd_ptr->dgram_compressed_size / frag_size) * (header_size + len)), "compression");
				}

			/* If the original packet was not a fragment, encapsulate it */
			/* into the last fragment created here.                      */
			is_frag = pk_fd_ptr->frag;

			if (!is_frag)
				{
				/* If the packet contained encapsulated data (i.e., from the */
				/* transport), that data will have been removed to avoid its */
				/* duplication in the fragments.  The data should now be     */
				/* reinserted into the original packet.                      */
				if (data_pkptr != OPC_NIL)
					{
					if (op_pk_nfd_set (pk_ptr, "data", data_pkptr) == OPC_COMPCODE_FAILURE)
						(*iprmd_ptr->error_proc) ("Unable to set data in final fragment.");
					}

				/* In either case the original packet is encapsualted in the fragment. */	
				if (op_pk_nfd_set (frag_ptr, "ip_dgram", pk_ptr) == OPC_COMPCODE_FAILURE)
					(*iprmd_ptr->error_proc) ("Unable to set datagram in final fragment.");
				}
			else
				{
				/* Otherwise the packet can be discarded. */
				op_pk_destroy (pk_ptr);

				/* Also, if the packet included the original datagram   */
				/* from which it was generated, transfer that datagram  */
				/* into the last fragment created here.  Note that it   */
				/* is possible, in the case where a fragment is itself  */
				/* being fragmented, that none of the created fragments */
				/* will contain the original datagram.                  */
				if (ip_pkptr != OPC_NIL)
					if (op_pk_nfd_set (frag_ptr, "ip_dgram", ip_pkptr) == OPC_COMPCODE_FAILURE)
						(*iprmd_ptr->error_proc) ("Unable to set datagram in packet.");
				}
			}

		/* Call the function that will send this fragment to the lower	*/
		/* layer.														*/
		ip_rte_frag_send (iprmd_ptr, frag_ptr, addr_family, dest_addr,
			next_addr, conn_class, iface_info_ptr, intf_ici_ptr);
		}

	FOUT;
	}

static void
ip_rte_frag_send (IpT_Rte_Module_Data* iprmd_ptr, Packet* pk_ptr,
	InetT_Addr_Family addr_family, InetT_Address dest_addr, InetT_Address next_addr, 
	int conn_class, IpT_Interface_Info* iface_info_ptr, IpT_Rte_Ind_Ici_Fields* intf_ici_ptr)
	{
	OpT_Packet_Size		frag_size;
	Ici*				iciptr;
	int					ip_queuing_scheme;
	int					interface_type;
	int					pkt_txtype;
	int					interface_index;
	int					minor_port;
	int					outstrm;
	double				speed;
	InetT_Address*		ici_next_addr_ptr;

	/** Send a packet fragment out on the interface. If	*/
	/** QoS is enabled on the interface, the packet will*/
	/** forwarded to the ip_output_iface process.		*/
	/** the packet will be directly sent to the lower	*/
	/** layer. 											*/

	FIN (ip_rte_frag_send (<args>));

	/* Get the size of the IP fragment.					*/
	frag_size = op_pk_total_size_get (pk_ptr) / 8;

	/* Extract the necessary fields from the associated	*/
	/* ICI structure.									*/
	interface_type 	= intf_ici_ptr->interface_type;
	pkt_txtype		= intf_ici_ptr->pkt_dest_type;
	interface_index = intf_ici_ptr->output_intf_index;
	minor_port		= intf_ici_ptr->output_subintf_index;
	outstrm 		= intf_ici_ptr->outstrm;
	speed 			= intf_ici_ptr->iface_speed;

	/* Get the queuing scheme configured on the interface.	*/
	ip_queuing_scheme = ip_rte_intf_queuing_scheme_get (iface_info_ptr);

	/* Unless the output interface is a tunnel, we will need an	*/
	/* ici to be associated with the interrupt.					*/
	if (!ip_rte_intf_is_tunnel (iface_info_ptr))
		{
		/* If an output queuing is enabled associate an ICI to each	*/
		/* datagram. It will carry the arival time of the datagram.	*/
		if (ip_queuing_scheme != IpC_No_Queuing)
			{
			/* Create an ICI or type ip_arp_req_v4 to carry the		*/
			/* next hop address information to the ip_output_iface	*/
			/* process.												*/
			iciptr = op_ici_create ("ip_arp_req_v4");

			/* Also allocate memory for the next_addr field in the	*/
			/* ICI.													*/
			ici_next_addr_ptr = inet_address_create_dynamic (INETC_ADDRESS_INVALID);

			/* Set the next_addr field of the ICI to this address.	*/
			op_ici_attr_set_ptr (iciptr, "next_addr", ici_next_addr_ptr);
			}
		else
			{
			/* Use iprmd_ptr->arp_iciptr.							*/
			iciptr = iprmd_ptr->arp_iciptr;

			/* The next_addr field of the ICI points to the			*/
			/* arp_next_hop_addr element of module data.			*/
			ici_next_addr_ptr = &(iprmd_ptr->arp_next_hop_addr);
			
			/* LP 3-22-04 - add JPH fixed for Opnet 10 */
			/* Set the next_addr field of the ICI to this address.	*/   
			op_ici_attr_set_ptr (iciptr, "next_addr", ici_next_addr_ptr);  /* JPH 10.0 fix */
			
			/* end LP */
			}

		/*	Prepare ICI to carry "next_addr" information. This will be used	  */
		/*	by lower layer address resolution layer to convert the IP address */
		/*	to a lower layer address (e.g., ethernet, ATM, etc.)			  */ 
		if (interface_type == IpC_Intf_Type_Smart)
			{
			/* If this is an IPv4 packet or if the packet is going	*/
			/* to be forwarded to the ip_output_iface process, fill	*/
			/* in the address information in the ici.				*/
			if ((InetC_Addr_Family_v4 == addr_family) || (ip_queuing_scheme != IpC_No_Queuing))
				{
				/* Set up the ICI indicating to the lower layer what the next */
				/* IP hop is.												  */
				*ici_next_addr_ptr = inet_address_copy (next_addr);
				}

			/* Get the connection_class and set it in the packet ICI.	*/
			if (op_ici_attr_set (iciptr, "connection_class", conn_class) == OPC_COMPCODE_FAILURE)
				(*iprmd_ptr->error_proc) ("Unable to set connection class in ICI.");
			
			/* Set the corresponding minor port in the ICI.		*/
			if (op_ici_attr_set (iciptr, "minor_port", minor_port) == OPC_COMPCODE_FAILURE)
				(*iprmd_ptr->error_proc) ("Unable to set minor port in ICI.");
								
			/* If an output queuing scheme is chosen then a 	*/
			/* child process is in charge of sending the 		*/
			/* packets and installing the ICI.					*/
			if (ip_queuing_scheme == IpC_No_Queuing)
				{
				/*	Install the ICI.	*/
				op_ici_install (iprmd_ptr->arp_iciptr);
				}
			}

		/* Update the pk sent statistics.								 */	
		ip_rte_pk_sent_stats_update (iprmd_ptr, pk_ptr, ip_queuing_scheme, pkt_txtype, addr_family); 
		}

	/* Update statistics for the interface on which this datagram is being*/
	/*	sent. NOTE: Currently, this is only required if IGRP is running as*/
	/*	the dynamic routing protocol in this node. Hence, for simulation  */
	/*	efficiency purposes, we will call it only if IGRP is enabled.	  */
	if ((iprmd_ptr->routing_protos & IPC_RTE_PROTO_IGRP) != 0)
		{
		ip_inface_statistic_update (iprmd_ptr, outstrm, frag_size*8.0, pk_ptr);
		}

	/* If the output interface is a tunnel, call the*/
	/* function that will encapsulate the packet and*/
	/* send it out.									*/
	if (ip_rte_intf_is_tunnel (iface_info_ptr))
		{
		ip_packet_tunnel (iprmd_ptr, pk_ptr, intf_ici_ptr->instrm, next_addr, iface_info_ptr);
		}
	/* If an output queuing scheme is chosen then	*/
	/* a child process is in charge of sending the	*/
	/* packets.										*/	
	else if (ip_queuing_scheme != IpC_No_Queuing)
		{
		ip_forward_packet_to_output_queues (iprmd_ptr, pk_ptr, outstrm, 
			iciptr, pkt_txtype, interface_index, 
			intf_ici_ptr->intf_recvd_index);
		}

	/* Check if the surrounding node is an IP cloud.	*/
	else if (iprmd_ptr->ipcloud_flag == OPC_TRUE)
		{
		(*(iprmd_ptr->cloud_send_proc))(iprmd_ptr->cloud_send_proc_info_ptr,
			pk_ptr, outstrm, (int)speed, interface_type,
			dest_addr, next_addr, conn_class, minor_port);
		}
	else if (InetC_Addr_Family_v6 == addr_family)
		{
		ipv6_packet_to_mac_send (iprmd_ptr, pk_ptr, iciptr, next_addr, iface_info_ptr);
		}
	else
		{
		/* We are sending the packet to the lower layer	*/
		/* If there is a layer-2, send the packet as a	*/
		/* forced interrupt so that the contents of the	*/
		/* ICI are not overwritten. 					*/
		if (interface_type == IpC_Intf_Type_Smart)
			{
			op_pk_send_forced (pk_ptr, outstrm);
			}
		else
			{
			op_pk_send (pk_ptr, outstrm);
			}

		/* Free the memory allocated to the next hop address	*/
		inet_address_destroy (iprmd_ptr->arp_next_hop_addr);
		}

	/* Uninstall the ICI.									*/
	op_ici_install (OPC_NIL);

	FOUT;
	}

static void
ip_rte_pk_sent_stats_update (IpT_Rte_Module_Data* iprmd_ptr, Packet* pk_ptr,
	int  ip_queuing_scheme, int pkt_txtype, InetT_Addr_Family addr_family)
	{
	/** We are sending a packet out on an interface. Update the traffic	**/
	/** sent statistics.												**/

	FIN (ip_rte_pk_sent_stats_update (<args>));

	/* These statistics take into account background traffic, if any.*/
	/* Note that to avoid double counting, we should not call this	*/
	/* function for tunnel interfaces.								*/
	ip_rte_pk_stats_update (iprmd_ptr, pk_ptr, 
			&iprmd_ptr->sent_last_stat_update_time,
			iprmd_ptr->sent_bgutil_routed_state_ptr, 
			&iprmd_ptr->locl_tot_pkts_sent_hndl); 

	/* If this is an IPv6 Packet, update the IPv6 stat also.		*/
	if (InetC_Addr_Family_v6 == addr_family)
		{
		op_stat_write (iprmd_ptr->locl_tot_ipv6_pkts_sent_hndl, 1.0);
		op_stat_write (iprmd_ptr->locl_tot_ipv6_pkts_sent_hndl, 0.0);
		}

	/* Write the statistic for 'Packets Sent' if there are no output queuing.	*/
	if (ip_queuing_scheme == IpC_No_Queuing)
		{
		/* Update the appropriate "Total X Packets Sent" statistic 	*/
		/* based on	value of the pkt_txtype parameter.				*/
		switch (pkt_txtype)
			{
			case IPC_PKT_TXTYPE_UCAST:
				{
				/* No additional stat update is necessary. 			*/
				break;
				}
			case IPC_PKT_TXTYPE_MCAST:
				{
				op_stat_write (iprmd_ptr->locl_num_mcasts_sent_hndl, 1.0);

				/* Write out a zero value to signal the end of the duration */
				/* to hold the statistic at the previously written out value*/
				op_stat_write (iprmd_ptr->locl_num_mcasts_sent_hndl, 0.0);
				break;
				}
			case IPC_PKT_TXTYPE_BCAST:
				{
				op_stat_write (iprmd_ptr->locl_num_bcasts_sent_hndl, 1.0);

				/* Write out a zero value to signal the end of the duration */
				/* to hold the statistic at the previously written out value*/
				op_stat_write (iprmd_ptr->locl_num_bcasts_sent_hndl, 0.0);
				break;
				}
			default:
				{
				/* This is an error.	*/
				(*iprmd_ptr->error_proc) ("IP Datagram transmission not categorized.");

				break;
				}
			}

		/* Update IPv6 stats also if applicable.							*/
		if (InetC_Addr_Family_v6 == addr_family)
			{
			/* Update the appropriate "Total X Packets Sent" statistic 	*/
			/* based on	value of the pkt_txtype parameter.				*/
			switch (pkt_txtype)
				{
				case IPC_PKT_TXTYPE_UCAST:
					{
					/* No additional stat update is necessary. 			*/
					break;
					}
				case IPC_PKT_TXTYPE_MCAST:
					{
					op_stat_write (iprmd_ptr->locl_num_ipv6_mcasts_sent_hndl, 1.0);

					/* Write out a zero value to signal the end of the duration */
					/* to hold the statistic at the previously written out value*/
					op_stat_write (iprmd_ptr->locl_num_ipv6_mcasts_sent_hndl, 0.0);
					break;
					}
				case IPC_PKT_TXTYPE_BCAST:
					/* No IPv6 Broadcast.	*/
				default:
					{
					/* This is an error.	*/
					(*iprmd_ptr->error_proc) ("IP Datagram transmission not categorized.");

					break;
					}
				}
			}
		}

	FOUT;
	}

static IpT_Address 
ip_obtain_neighbor_router_id (IpT_Rte_Module_Data * iprmd_ptr, Objid link_objid)
	{
	Objid					local_objid;	
	Objid					local_node_objid;
	Objid					node_objid;
	int						num_of_nodes;
	int						index;
	Objid 					mod_objid;
	IpT_Address				router_id;
	IpT_Rte_Module_Data*	neighbor_ip_mod_data;
	
	/** The idea here is to go through all the nodes 	**/
	/** connected to a link (For point to point there	**/
	/** should not be more than two nodes connected to	**/
	/** a single link). After the initial scanning we	**/
	/** would obtain two node objects. We are more		**/
	/** concerned with the remote node's object. The	**/
	/** test here thus is to compare the obtained node's**/
	/** object with the current node object. If they 	**/
	/** happen to be equal then obtain the OSPF state 	**/
	/** variable called \"ospf_router_id\".				**/
	FIN (ip_obtain_neighbor_router_id (link_objid));

	local_objid = op_id_self ();
	local_node_objid = op_topo_parent (local_objid);

	num_of_nodes = op_topo_assoc_count (link_objid , OPC_TOPO_ASSOC_OUT, OPC_OBJTYPE_NDFIX);
	if (num_of_nodes != 2)
		{
		(*iprmd_ptr->error_proc) ("The link either is unconnected or connected to just one node\n");
		FRET (IPC_ADDR_INVALID);
		}

	for (index = 0; index < num_of_nodes; ++index)
		{
		/* Obtain the object id's of both the nodes.	*/
		node_objid = op_topo_assoc (link_objid, OPC_TOPO_ASSOC_OUT, OPC_OBJTYPE_NDFIX, index);

		/* There are two nodes connected to a point to point link. 	*/
		/* We are interested only about the remote node.			*/
		if (local_node_objid == node_objid)
			continue;
		else
			{
			/* Obtain the module objid of the ospf protocol from the*/
			/* Node object itself. If no name matches that means 	*/
			/* the current node does not have a OSPF module on it.	*/
			mod_objid = op_id_from_name (node_objid, OPC_OBJTYPE_PROC, "ip");

			if (mod_objid == OPC_OBJID_INVALID)
				{
				FRET (IPC_ADDR_INVALID);
				}
			else
				{
				neighbor_ip_mod_data = (IpT_Rte_Module_Data*) op_ima_obj_svar_get (mod_objid, "module_data");
				
				router_id = neighbor_ip_mod_data->router_id;
				FRET (router_id);
				}
			}
		}

	FRET (IPC_ADDR_INVALID);
	}	


static void
ip_unnumbered_intf_router_id_assign (IpT_Rte_Module_Data * iprmd_ptr)
	{
	int						i, iface_table_size;
    IpT_Interface_Info *	iface_elem_ptr;
	IpT_Address				router_id;

	/* Store the router_id of the neighboring router connected	*/
	/* through this interface if the current interface is a 	*/
	/* unnumbered interface.									*/
	FIN (ip_unnumbered_intf_router_id_assign ());

	/* Obtain the size of the interface table on the IP layer 	*/
	iface_table_size = ip_rte_num_interfaces_get (iprmd_ptr);
	for (i = 0; i < iface_table_size; i++)
		{
		/* Access each and every element from the interface		*/
		iface_elem_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);

		if (ip_rte_intf_unnumbered (iface_elem_ptr) == OPC_TRUE)
			{
			/* Obtain the neighbor's router identifier. This is	*/
			/* a complex process in which the neighboring node 	*/
			/* is obtained and then its OSPF module id is 		*/
			/* fetch to get the state variable value of the 	*/
			/* OSPF Router ID.									*/
			if ((router_id = ip_obtain_neighbor_router_id (iprmd_ptr, 
					ip_rte_intf_conn_link_objid_get (iface_elem_ptr))) == IPC_ADDR_INVALID)
				{
				/* No OSPF module present on the neighbor interface. */
				continue;
				}
			else
				{
				/* Store the neighboring router identification 	*/
				/* in the interface structure for future		*/
				/* verification.								*/
				ip_rte_intf_neighbor_rtr_id_set (&iface_elem_ptr, ip_address_copy (router_id));
				}
			}
		else
			continue;
		}	

	FOUT;
	}

Compcode
ip_rte_destination_local_network (IpT_Rte_Module_Data * iprmd_ptr,
	InetT_Address dest_addr, short* table_index_ptr, 
	IpT_Interface_Info** interface_pptr, int *outstrm_ptr,
	InetT_Address_Range** addr_range_pptr)
    {
	Compcode			result;
	IpT_Port_Info		output_port_info;
	short				table_index;
	IpT_Interface_Info	*intf_info_ptr;
	
	/** This procedure is used to determine whether the IP datagram is **/
	/** destined for a direct neighbor of this node.                   **/
	FIN (ip_rte_destination_local_network (dest_addr, output_intf_index_ptr, interface_ptr));

	if (iprmd_ptr->router_id_assigned == OPC_FALSE && 
		iprmd_ptr->unnumbered_interface_exists == OPC_TRUE)
		{
		/* When dealing with unnumbered OSPF point-to-point interfaces,	*/
		/* the IP layer needs to know the neighboring router ID for		*/
		/* every interface. This is essential in order to route the		*/
		/* the routing protocol's traffic.								*/
		ip_unnumbered_intf_router_id_assign (iprmd_ptr);
		iprmd_ptr->router_id_assigned = OPC_TRUE;
		}

	/* Call the function that would loop through the interfaces and 	*/
	/* subinterfaces and look for a match and return the result			*/
	result = inet_rte_addr_local_network_core (dest_addr, iprmd_ptr,
		&output_port_info, addr_range_pptr);

	if (result == OPC_COMPCODE_SUCCESS)
		{
		table_index = ip_rte_intf_tbl_index_from_port_info_get (iprmd_ptr, output_port_info);
		intf_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, table_index);

		if (table_index_ptr != OPC_NIL)
			*table_index_ptr = table_index;
		
		if (interface_pptr != OPC_NIL)
			*interface_pptr =  intf_info_ptr;
				
		if (outstrm_ptr != OPC_NIL)
			*outstrm_ptr = ip_rte_intf_out_port_num_get (intf_info_ptr);
		}

	FRET (result);
	}

Compcode
ip_rte_addr_local_network (IpT_Address dest_addr, IpT_Rte_Module_Data * iprmd_ptr,
	IpT_Interface_Info** interface_pptr, IpT_Port_Info* port_info_ptr, int* port_num_ptr)
	{
	Compcode				result;
	IpT_Port_Info			output_port_info;
	IpT_Interface_Info*		intf_ptr;

	/** Checks whether the given address belongs to a directly connnected network.	**/

	FIN (ip_rte_addr_local_network (ip_address, iprmd_ptr,...));

	/* Use local variables for unspecified arguements.						*/
	if (OPC_NIL == port_info_ptr)
		{
		port_info_ptr = &output_port_info;
		}
	if (OPC_NIL == interface_pptr)
		{
		interface_pptr = &intf_ptr;
		}

	/* Call the inet_rte_addr_local_network to perform the actual check.	*/
	result = inet_rte_addr_local_network_core (inet_address_from_ipv4_address_create (dest_addr),
		iprmd_ptr, port_info_ptr, OPC_NIL);

	/* If the call succeeded, fill the rest of the return values.			*/
	if (result == OPC_COMPCODE_SUCCESS)
		{
		*interface_pptr = inet_rte_intf_tbl_access_by_port_info (iprmd_ptr, *port_info_ptr);

		if (OPC_NIL != port_num_ptr)
			{
			*port_num_ptr = ip_rte_intf_out_port_num_get (*interface_pptr);
			}
		}

	FRET (result);
	}

static void
ip_rte_total_packets_received_stat_update (IpT_Rte_Module_Data * iprmd_ptr, 
	int pkt_dest_type, Packet * pk_ptr, InetT_Addr_Family addr_family)
	{
	/** Updates statistics on total packets received based on the	**/
	/** packet type.												**/
	FIN (ip_rte_total_packets_received_stat_update (pkt_dest_type));
	
	/* Update the pk received statistics.								*/		
	/* These statistics take into account background traffic, if any.	*/
	ip_rte_pk_stats_update (iprmd_ptr, pk_ptr, 
		&iprmd_ptr->received_last_stat_update_time,
		iprmd_ptr->received_bgutil_routed_state_ptr, 
		&iprmd_ptr->locl_tot_pkts_rcvd_hndl);

	/* Write out a zero value to signal the end of the duration to  */
	/* hold the statistic at the previously written out value.		*/
	op_stat_write (iprmd_ptr->locl_tot_pkts_rcvd_hndl, 0.0);
	
	switch (pkt_dest_type)
		{
		case IPC_PKT_TXTYPE_UCAST:
			{
			/* No additional stat update is neccessary. 					*/
			break;
			}

		case IPC_PKT_TXTYPE_MCAST:
			{
			op_stat_write (iprmd_ptr->locl_num_mcasts_rcvd_hndl, 1.0);

			/* Write out a zero value to signal the end of the duration to  */
			/* hold the statistic at the previously written out value.		*/
			op_stat_write (iprmd_ptr->locl_num_mcasts_rcvd_hndl, 0.0);
			break;
			}

		case IPC_PKT_TXTYPE_BCAST:
			{
			op_stat_write (iprmd_ptr->locl_num_bcasts_rcvd_hndl, 1.0);

			/* Write out a zero value to signal the end of the duration to  */
			/* hold the statistic at the previously written out value.		*/
			op_stat_write (iprmd_ptr->locl_num_bcasts_rcvd_hndl, 0.0);
			break;
			}

		default:
			{
			(*iprmd_ptr->error_proc) ("Processing uncategorized IP datagram.");
			}
		}

	/* Update IPv6 stats also if applicable.								*/
	if (InetC_Addr_Family_v6 == addr_family)
		{
		/* Update the pk received statistics.								*/		
		/* These statistics take into account background traffic, if any.	*/
		ip_rte_pk_stats_update (iprmd_ptr, pk_ptr, 
			&iprmd_ptr->received_last_stat_update_time,
			iprmd_ptr->received_bgutil_routed_state_ptr, 
			&iprmd_ptr->locl_tot_ipv6_pkts_rcvd_hndl);

		/* Write out a zero value to signal the end of the duration to  */
		/* hold the statistic at the previously written out value.		*/
		op_stat_write (iprmd_ptr->locl_tot_ipv6_pkts_rcvd_hndl, 0.0);
		
		if (IPC_PKT_TXTYPE_MCAST == pkt_dest_type)
			{
			op_stat_write (iprmd_ptr->locl_num_ipv6_mcasts_rcvd_hndl, 1.0);

			/* Write out a zero value to signal the end of the duration to  */
			/* hold the statistic at the previously written out value.		*/
			op_stat_write (iprmd_ptr->locl_num_ipv6_mcasts_rcvd_hndl, 0.0);
			}
		}

	FOUT;
	}


static Compcode
ip_rte_datagram_dest_get (IpT_Rte_Module_Data * iprmd_ptr, Packet* pkptr, 
	Ici* rsvp_ici_ptr, Boolean force_fwd, InetT_Address dest_addr, int instrm, 
	int protocol_type, InetT_Address *next_addr_ptr, 
	char** lsp_name_pstr, Boolean *broadcast_ptr, Boolean *higher_layer_ptr, 
	Boolean *destroy_pkt_ptr, IpT_Port_Info* output_port_info_ptr, 
	IpT_Interface_Info **interface_pptr, int * num_tracer_info_ptr, 
	IpT_Tracer_Info** tracer_info_array_pptr, char** drop_reason_pstr, IpT_Rte_Proc_Id* src_proto_ptr)
	{
	char*					dest_addr_str;
	char					error_str [512];
	char					drop_reason_str [512] = "NULL";
	Compcode				route_status;
	Compcode				dir_conn_dest_status;
	int						outstrm;
	IpT_Interface_Info *	output_intf_info_ptr;
	RsvpT_Rte_Ici_Struct*	rsvp_route_info_ptr;
	Boolean					tracer_pkt_split;
	IpT_Cmn_Rte_Table_Entry * route_entry_ptr;
	int						i, j, num_next_hops;
	int						valid_entry_index;
	IpT_Tracer_Info *		tracer_info_ptr;
	int						ith_cost;
	double					total_share = 0.0;
	int						num_zero_cost_routes = 0;
	IpT_Tracer_Info*		new_tracer_info_array_ptr;
	int						dest_fast_ip_addr;
	int						src_fast_ip_addr;
	IpT_Dgram_Fields*		pk_fds_ptr;
	InetT_Address			dir_conn_next_addr;
	InetT_Address_Range*	output_addr_range_ptr;
	DsrT_Route_Info*		dsr_route_info_ptr;
	Ici*					dsr_ici_ptr;
	short					output_intf_index;
	InetT_Address			in_intf_addr;
	int 					nodeid; /* LP */
	
	/** Retrieve and return the outstream, outslot and mtu to which we should**/
	/** send the datagram. This function may also return status flags		 **/
	/** indicating that the datagram should be broadcast, and/or the datagram**/
	/** should be forwarded to the higher layer.  If OPC_COMPCODE_SUCCESS is **/
	/** returned, the datagram can be dispatched by the client of this		 **/
	/** procedure; if OPC_COMPCODE_FAILURE is returned, a routing message	 **/
	/** error shoud be generated, and the datagram should be destroyed.		 **/
	FIN (ip_rte_datagram_dest_get (pkptr, rsvp_ici_ptr, force_fwd, 
		dest_addr, instrm, protocol_type, next_addr_ptr, broadcast_ptr, 
		higher_layer_ptr, destroy_pkt_ptr, output_port_info_ptr, 
		interface_pptr, num_tracer_info_ptr, tracer_info_array_pptr, src_proto_ptr));

#ifdef OP_DEBUG1
	op_ima_obj_attr_get (op_topo_parent(op_id_self()), "user id", &nodeid);
	printf("\t Node %d - ip_rte_support.c - ip_rte_datagram_dest_get()\n", nodeid);

#endif
	/* If this node does not have any interfaces, drop	*/
	/* the packet.										*/
	/* By default the packet should not be destroyed*/
	*destroy_pkt_ptr = OPC_FALSE;

	/* Initialize the flags to OPC_FALSE.	*/
	*higher_layer_ptr = OPC_FALSE;
	*broadcast_ptr = OPC_FALSE;
	*lsp_name_pstr = OPC_NIL;

	/* Initialize fields of port_info */
	*output_port_info_ptr = ip_rte_port_info_create (IPC_INTF_INDEX_INVALID, OPC_NIL);
	
	/* No tracer info unless set explicitly later on */
	*num_tracer_info_ptr = 0;

	/* Check if the packet is received from higher or lower layer.	*/
	if (instrm == iprmd_ptr->instrm_from_ip_encap || 
		instrm == IpC_Pk_Instrm_Child)
		{
		/** The packet came from higher layer or a child process. **/

		/* If this is an RSVP packet, do not perform route query, 	*/
		/* but rather set the routing parameters.					*/
		if (protocol_type == IpC_Protocol_Rsvp)
			{
			/** This is an RSVP packet.		**/

			/* The packet should be accompanied by ICI.		*/
			/* Read the routing information in the ICI.		*/
			op_ici_attr_get (rsvp_ici_ptr, 
				"RSVP Packet Route Info", &rsvp_route_info_ptr);

			/* Set the next hop address based on the next hop specified by RSVP and already	*/
			/* set in the forwarding ICI.													*/ 
			*next_addr_ptr = inet_address_from_ipv4_address_create (rsvp_route_info_ptr->next_hop_addr);

			/* Store the index of this interface object in intf_index.	*/
			output_port_info_ptr->intf_tbl_index = rsvp_route_info_ptr->intf_index;

			/* RSVP does not currently support subinterfaces			*/

			/* Find the interface pointer.	*/
			*interface_pptr = ip_rte_intf_tbl_access (iprmd_ptr, output_port_info_ptr->intf_tbl_index);

			/* Deallocate memory allocated for the ICI DS.	*/
			op_prg_mem_free (rsvp_route_info_ptr);

			/* Destroy the RSVP ICI.							*/
			op_ici_destroy (rsvp_ici_ptr);

			FRET (OPC_COMPCODE_SUCCESS);
			}

		/* Check to see if the destination address is a broadcast address for	*/
		/* all interfaces, i.e 255.255.255.255. If so set the variable			*/
		/* representing the interface on which the packet is to be sent out to	*/
		/* IP_BROADCAST_ALL_INTERFACES.											*/
		if (inet_address_equal (dest_addr, InetI_Broadcast_v4_Addr))
			{
			/* Set the flags accordingly.						*/
			*broadcast_ptr = OPC_TRUE;
			/* higher_layer flag has been initialized to false	*/
			
			output_port_info_ptr->intf_tbl_index = IP_BROADCAST_ALL_INTERFACES;
			*interface_pptr = OPC_NIL;
#ifdef OP_DEBUG1
	printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper layer and dest is broadcast\n");
#endif

			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		if (protocol_type == IpC_Protocol_Dsr)
			{
			/* Packet came from the DSR MANET child process		*/
			/* The packet should be routed to the lower layer	*/
			/* based on the DSR source route in the packet		*/
			dsr_ici_ptr = op_pk_ici_get (pkptr);
			
			if (dsr_ici_ptr == OPC_NIL)
				{
				/* There is no ICI associated 	*/
				/* with the packet. Do nothing	*/
				}
			else
				{
				/* Get the next hop information from the ICI	*/
				op_ici_attr_get (dsr_ici_ptr, 
				"DSR Routing Info", &dsr_route_info_ptr);
				
				/* Set the routing information	*/
				
				/* Set the next hop address	*/
				*next_addr_ptr = inet_address_copy (dsr_route_info_ptr->next_hop_addr);

				/* Store the index of this interface object in intf_index.	*/
				output_port_info_ptr->intf_tbl_index = dsr_route_info_ptr->output_table_index;
				
				/* Set the interface pointer.	*/
				*interface_pptr = dsr_route_info_ptr->interface_info_ptr;
				
				/* Destroy the IP address	*/
				inet_address_destroy (dsr_route_info_ptr->next_hop_addr);
				
				/* Deallocate memory allocated for the ICI DS.	*/
				op_prg_mem_free (dsr_route_info_ptr);
				
				/* Destroy the DSR ICI.							*/
				op_ici_destroy (dsr_ici_ptr);
				
				FRET (OPC_COMPCODE_SUCCESS);
				} /* end if dsr_ici != NIL */
			} /* end if DSR */
		} /* endif from upper layer */
	else
		{
		/** Packet came from a lower layer.		**/
		
		/* Check if this node has RSVP enabled.	*/
		if ((iprmd_ptr->rsvp_status == OPC_TRUE) && 
			(protocol_type == IpC_Protocol_Rsvp))
			{
			/* All RSVP packets comming from the lower layer need to	*/
			/* be forwarded to the higher layer.							*/
			*higher_layer_ptr = OPC_TRUE;
			
			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		/* Check if this node has MANET enabled	*/
		if ((iprmd_ptr->manet_enabled == OPC_TRUE) &&
			(protocol_type == IpC_Protocol_Dsr))
			{
			/* Send all DSR packets to the DSR 	*/
			/* routing protocol child			*/
			*destroy_pkt_ptr = OPC_FALSE;
			*higher_layer_ptr = OPC_TRUE;
			
			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		/* Check if the node is a cache server.	*/
		if ((iprmd_ptr->node_is_cache_server == OPC_TRUE) &&
			((protocol_type == IpC_Protocol_Tcp) || 
			 (protocol_type == IpC_Protocol_Udp)))
			{
			/* All TCP and UDP packets comming from the lower layer need to	*/
			/* be forwarded to the higher layer.							*/
			*higher_layer_ptr = OPC_TRUE;
#ifdef OP_DEBUG1
	printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from lower and node is catch server\n");
#endif
			
			FRET (OPC_COMPCODE_SUCCESS);
			}
	
		/* Check to see if the destination address is a broadcast address for	*/
		/* all interfaces, i.e 255.255.255.255. If so, forward the packet to	*/
		/* the higher layer.													*/
		if (inet_address_equal (dest_addr, InetI_Broadcast_v4_Addr))
			{
			/* Set the flags accordingly.						*/
			*higher_layer_ptr = OPC_TRUE;
			*broadcast_ptr = OPC_TRUE;

			/* Set the port_info to point to the first interface*/
			/* Other wise the ip_rte_options_process function	*/
			/* might crash.										*/
			output_port_info_ptr->intf_tbl_index = 0;
			
			*interface_pptr = OPC_NIL;
#ifdef OP_DEBUG1
	printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from lower and dest is broadcastr\n");
#endif

			FRET (OPC_COMPCODE_SUCCESS);
			}
		} /* end if from lower layer */

	/*	Now check if this node is capable of making routing 		*/
	/*	decisions. A node is capable of making routing decisions if	*/
	/*	it is either a gateway node or it is an end node with		*/
	/*	passive RIP enabled.										*/
	if (iprmd_ptr->gateway_status == OPC_FALSE && 
		(*(iprmd_ptr->passive_rip_ptr)) == OPC_FALSE)
		{
		/* This is not a node capable of making routing decisions	*/

		/* Check whether the packet came from the lower layer.		*/
		if (instrm == iprmd_ptr->instrm_from_ip_encap || instrm == IpC_Pk_Instrm_Child)
			{
			/* The packet did not come from the lower layer			*/
#ifdef OP_DEBUG1
	printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper and node is NOT gateway\n");
#endif

			/* MANET Tora-IMEP support for handling upper layer packets 					 */
			if ((iprmd_ptr->manet_enabled == OPC_TRUE) && (protocol_type != IpC_Protocol_Tora))
				{
				/* This is an application layer packet. Check if a route exists	*/
				/* to the destination in the common route table					*/
				route_status = inet_cmn_rte_table_recursive_lookup_cache (iprmd_ptr->ip_route_table, dest_addr, 
					next_addr_ptr, output_port_info_ptr, src_proto_ptr, OPC_NIL, IPC_ADDR_INVALID, IPC_ADDR_INVALID);
				
				if (route_status != OPC_COMPCODE_FAILURE)
					{
					/* Found a route to the destination. Set the next hop	*/
					/* Determine the outgoing interface for the next hop	*/
					if (ip_rte_destination_local_network (iprmd_ptr, *next_addr_ptr, 
						&(output_port_info_ptr->intf_tbl_index), &output_intf_info_ptr, &outstrm,
						&output_addr_range_ptr) == OPC_COMPCODE_SUCCESS)
						{
						*interface_pptr = output_intf_info_ptr;
						FRET (OPC_COMPCODE_SUCCESS);
						}
					else
						{
						FRET (OPC_COMPCODE_FAILURE);
						}
					}
				else
					{
					FRET (OPC_COMPCODE_FAILURE);
					}
				} /* end if MANET and upper layer  and NOT Gateway */
			
			/* Check if the destination address of the packet		*/
			/* belongs to a directly connected network. 		 	*/

			/* Do an address range check */
			if (ip_rte_destination_local_network (iprmd_ptr, dest_addr, 
					&(output_port_info_ptr->intf_tbl_index), &output_intf_info_ptr, &outstrm,
					&output_addr_range_ptr) == OPC_COMPCODE_SUCCESS)
				{
				/* Now check whether the packet is destined for this*/
				/* node itself.										*/
				if (inet_address_range_address_equal (output_addr_range_ptr, &dest_addr))
					{
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper and FOR ME\n");
#endif

					/* Indicate that the packet should be sent to	*/
					/* the higher layer unless force_fwd flag is set*/
					if (!force_fwd)
						{
						*higher_layer_ptr = OPC_TRUE;

						/* Set the port_info correctly				*/
						output_port_info_ptr->intf_tbl_index = 0;
						}
					else
						{
						/* This packet is destined for this node,	*/
						/* but has to be forced to the lower layer	*/
						/* because this is a LAN node.				*/

						/* Also fill in the other return values.	*/
						*interface_pptr = output_intf_info_ptr;
						*next_addr_ptr = inet_address_copy (dest_addr);

						/* The output_table_index would have been	*/
						/* set already.								*/
						}
					} /* end if the packet is for myself */

				/* For IPv4 packets, check if this packet is being	*/
				/* broadcast on the directly connected network.		*/
				else if ((InetC_Addr_Family_v4 == inet_address_family_get (&dest_addr)) &&
						 (inet_address_range_addr_is_broadcast (output_addr_range_ptr, &dest_addr)))
					{
					/* Set the broadcast flag to true and the		*/
					/* higher layer flag to false.					*/
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper and broadcast to a direct connect ntwork\n");
#endif
					*broadcast_ptr = OPC_TRUE;

					/* Also fill in the other return values.		*/
					*interface_pptr = output_intf_info_ptr;
					*next_addr_ptr = inet_address_copy (dest_addr);
					}
				else
					{
					/* The packet is a unicast packet destined for	*/
					/* some other node in the network or it is 		*/
					/* destined for this node, but needs to be sent */
					/* sent to the lowe layer because force_fwd flag*/
					/* is set. In either case indicate that the 	*/
				    /* packet is to be sent to the lower layer.		*/ 	

					/* Also fill in the other return values.		*/
					output_port_info_ptr->intf_tbl_index = 0;
					*interface_pptr = output_intf_info_ptr;
					*next_addr_ptr = inet_address_copy (dest_addr);
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper and for some other nodes in the net\n");
#endif
					}
				} /* if (ip_rte_destination_local_network...)	*/

			/* The destination of the packet does not belong to		*/
			/* the directly connected network. Send the packet to	*/
			/* the default gateway if one is avilable				*/
			else if (inet_default_route_available (iprmd_ptr, inet_address_family_get (&dest_addr)))
				{
#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper for othernetwork.  Send to gateway\n");
#endif
				/* A default gateway has been specified.			*/

				/* Set the flags.									*/
				*broadcast_ptr = OPC_FALSE;

				/* Fill in the return values.						*/

				/* Set the next addr to be the default route.		*/
				*next_addr_ptr = inet_default_route_get (iprmd_ptr, inet_address_family_get (&dest_addr), 
					&(output_port_info_ptr->intf_tbl_index));
				*interface_pptr = inet_rte_intf_tbl_access (iprmd_ptr, output_port_info_ptr->intf_tbl_index);
				} /* end if dest is not for a direclty connected network */
			else
				{
#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from upper for othernetwork.  No gateway.  Destroy\n");
#endif
				/* No default gateway is available. Indicate that	*/
				/* the packet should be destroyed.					*/
				*destroy_pkt_ptr = OPC_TRUE;
				sprintf (drop_reason_str, "No Route to Destination");
				*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
				strcpy (*drop_reason_pstr, drop_reason_str);
				}
			} /* end if from upper layer */
		
		else /* if (instrm == ...)	*/
			{
#ifdef OP_DEBUG1
	printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - NOT Gateway.  pk from lower\n");
#endif
			/* Handling the Tora-IMEP packets */
			if ((iprmd_ptr->manet_enabled == OPC_TRUE) && (protocol_type != IpC_Protocol_Tora))
				{
				/* An application packet has arrived from the lower layer	*/
				/* If this node is the destination, then send the packet to	*/
				/* the higherlayer. Else, lookup the common route table to 	*/
				/* find a route to the destination. If no route exists, to	*/
				/* the destination of the packet, it will be forwarded to	*/
				/* the TORA process.										*/
				
				/* Dont destroy the packet */
				*destroy_pkt_ptr = OPC_FALSE;
				
				/* Check if the destination address belongs this node	*/
				if (ip_rte_destination_local_network (iprmd_ptr, dest_addr, &output_intf_index, 
							 &output_intf_info_ptr, &outstrm, &output_addr_range_ptr) == OPC_COMPCODE_SUCCESS)
					{
					/* Get the incoming interface address	*/
					in_intf_addr = inet_address_range_addr_get (output_addr_range_ptr);
		
					/* Packet belongs to a directly connected network	*/
					/* Check if the packet is destined for this node	*/
					if (inet_address_equal (dest_addr, in_intf_addr))
						{
						/* Send the packet to the higher layer	*/
						*higher_layer_ptr = OPC_TRUE;
						
						/* The packet is destined for this node	*/
						FRET (OPC_COMPCODE_SUCCESS);
						}
					}
				
				/* The destination does not belong to this node	*/
				/* Check if the common route table has a route	*/
				/* to the destination of the packet				*/
				route_status = inet_cmn_rte_table_recursive_lookup_cache (iprmd_ptr->ip_route_table, dest_addr, 
					next_addr_ptr, output_port_info_ptr, src_proto_ptr, OPC_NIL, IPC_ADDR_INVALID, IPC_ADDR_INVALID);
				
				if (route_status != OPC_COMPCODE_FAILURE)
					{
					/* Determine the outgoing interface for the next hop	*/
					if (ip_rte_destination_local_network (iprmd_ptr, *next_addr_ptr, 
						&(output_port_info_ptr->intf_tbl_index), &output_intf_info_ptr, &outstrm,
						&output_addr_range_ptr) == OPC_COMPCODE_SUCCESS)
						{
						*interface_pptr = output_intf_info_ptr;
						FRET (OPC_COMPCODE_SUCCESS);
						}
					else
						{
						FRET (OPC_COMPCODE_FAILURE);
						}
					}
				else
					{
					FRET (OPC_COMPCODE_FAILURE);
					}
				}	/* end if Manet */	
			
			/* The packet came from the lower layer. Since this is	*/
			/* not a gateway, accept the packet only if it is 		*/
			/* destined for this node or if it is an IPv4 subnet 	*/
			/* level broadcast packet.								*/
			if (ip_rte_destination_local_network (iprmd_ptr, dest_addr, &(output_port_info_ptr->intf_tbl_index),
					&output_intf_info_ptr, &outstrm, &output_addr_range_ptr) == OPC_COMPCODE_SUCCESS)
				{
				/* The destination address is directly connected.	*/
				/* Check if it is destined for this node itself.	*/
				if (inet_address_range_address_equal (output_addr_range_ptr, &dest_addr))
					{
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from lower and FOR ME\n");
#endif
					/* Accept the packet.							*/
					*broadcast_ptr = OPC_FALSE;
					*higher_layer_ptr = OPC_TRUE;
					}
				/* Check if the destination address is the IPv4		*/
				/* subnet level broadcast address.					*/
				else if (inet_address_range_addr_is_broadcast (output_addr_range_ptr, &dest_addr))
					{
					/* Set the flags.								*/
					*broadcast_ptr = OPC_TRUE;
					*higher_layer_ptr = OPC_TRUE;

					/* Set the port_info 							*/
					output_port_info_ptr->intf_tbl_index = 0;
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from lower and broadcast\n");
#endif
					}
				else
					{
					/* The packet should be dropped.				*/
					*destroy_pkt_ptr = OPC_TRUE;
					sprintf (drop_reason_str, "Dropped on a non-routing node");
					*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
					strcpy (*drop_reason_pstr, drop_reason_str);
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from lower and not for me nor broadcast.Drop\n");
#endif
					}
				} /* end if dest is for my network */
			else
				{
				if ((protocol_type == IpC_Protocol_Icmp) && (iprmd_ptr->mobile_ip_enabled))
					{
					/* If this is an mobile IP advertisement packet, do not send it back out. */
					*broadcast_ptr = OPC_FALSE;
					*higher_layer_ptr = OPC_TRUE;
					
					/* Set the port_info 							*/
					output_port_info_ptr->intf_tbl_index = 0;
					}
				else
					{
					/* The destination address does not belong			*/
					/* to any of the connected networks. Drop the packet*/
					*destroy_pkt_ptr = OPC_TRUE;
					sprintf (drop_reason_str, "Dropped on a non-routing node");
					*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
					strcpy (*drop_reason_pstr, drop_reason_str);
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c - ip_rte_datagram_dest_get() - pk from lower and NOT my network\n");
#endif
					}
				} /* end not for my net */
			}  /* end from  lower */
		/* We have figured out what to do with the packet.		*/
		FRET (OPC_COMPCODE_SUCCESS);
		} /* end if NOT Gateway node */

	/* This node is either a gateway node or an endstation with	*/
	/* passive RIP enabled.										*/		
	/* First Check if the destination address belongs to one	*/
	/* of the directly connected networks of this node.			*/
	dir_conn_dest_status = ip_rte_destination_local_network (iprmd_ptr, dest_addr, 
								&(output_port_info_ptr->intf_tbl_index), &output_intf_info_ptr, 
								&outstrm, &output_addr_range_ptr);

	/* If the destination belongs to a directly connected		*/
	/* network, make sure that the connected link is active and	*/
	/* that the interface is not shutdown.						*/
	if (OPC_COMPCODE_SUCCESS == dir_conn_dest_status)
		{
		if ((ip_rte_intf_link_is_failed (output_intf_info_ptr)) ||
			(ip_rte_intf_is_shutdown (output_intf_info_ptr)))
			{
			/* The connected link has failed or the interface	*/
			/* is shutdown. Unless the packet is destined for	*/
			/* this node itself, pretend that the destination is*/
			/* not directly connected so that we will do a		*/
			/* routing table lookup for the packet.				*/
			if (! inet_rte_intf_has_local_address (dest_addr, output_intf_info_ptr))
				{
				/* The address does not belong to this node.	*/
				/* Set the directly connected flag to false		*/
				/* so that we will do a route table lookup and	*/
				/* use an alternate route to the network if		*/
				/* available.									*/
				dir_conn_dest_status = OPC_COMPCODE_FAILURE;
#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c - ip_rte_datagram_dest_get()- Gateway node - for my net but link is down - no local addr\n");
#endif
				}
#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c - ip_rte_datagram_dest_get()- Gateway node - for my net but link is down - Found local addr\n");
#endif
			}
		}

	if (OPC_COMPCODE_SUCCESS == dir_conn_dest_status)
		{
		/* Next, check if the packet is destined for this node	*/
		/* itself.												*/
		if (inet_address_range_address_equal (output_addr_range_ptr, &dest_addr))
			{
			/* If this is a LAN node and this packet came the	*/
			/* higher layer, we should force the packet to the	*/
			/* lower layer.										*/
			if (((instrm == iprmd_ptr->instrm_from_ip_encap) || 
				 (instrm == IpC_Pk_Instrm_Child)) &&
				(force_fwd))
				{
				/* Set the flags.								*/
				*broadcast_ptr = OPC_FALSE;
				*higher_layer_ptr = OPC_FALSE;
#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-Gateway node.  From upper and FOR ME\n");
#endif
				}
			else
				{
				/* If this node is running TORA, and this is a TORA packet, then do not forward the packet */
				/* to the higher layer, instead return FAILURE, so that it can be manet_redirected to TORA */
				if ((iprmd_ptr->manet_rte_protocol == IpC_Rte_Tora) && (iprmd_ptr->manet_enabled == OPC_TRUE))
					{
					*higher_layer_ptr = OPC_FALSE;
					*broadcast_ptr = OPC_FALSE;

					FRET (OPC_COMPCODE_FAILURE);
					}
				else
					{
					/* Set the flags									*/
					*broadcast_ptr = OPC_FALSE;
					*higher_layer_ptr = OPC_TRUE;
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-Gateway node.  From lower and FOR ME\n");
#endif

					}

				} /* end from lower */
			/* Fill in the return values.					*/
			*interface_pptr = output_intf_info_ptr;

			} /* end if inet_address_rage equal */
		/* Check whether this packet is being broadcast on		*/
		/* an IP subnet connected to the node.					*/
		else if (inet_address_range_addr_is_broadcast (output_addr_range_ptr, &dest_addr))
			{

			/* Set the broadcast flag							*/
			*broadcast_ptr = OPC_TRUE;

			/* Now check whether the packet came from the		*/
			/* lower layer or the higher layer.					*/
			if ((instrm == iprmd_ptr->instrm_from_ip_encap) ||
				(instrm == IpC_Pk_Instrm_Child))
				{
				/* The packet came from the higher layer.		*/
				/* So the packet must be broadcast on the		*/
				/* interface.									*/
				/* Set the higher layer flag to false to		*/
				/* indicate that this packet should be sent		*/
				/* to the lower layer							*/
				*higher_layer_ptr = OPC_FALSE;

				/* Fill in the return values.					*/
				*interface_pptr = output_intf_info_ptr;

#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-Gateway node.  From upper and broadcast\n");
#endif
				}
			else
				{
				/* This packet came from the lower layer. We	*/
				/* must accept the packet.						*/
				*higher_layer_ptr = OPC_TRUE;

#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-Gateway node.  From lower and broadcast\n");
#endif
				}
			} /* end else if addr is broadcast */
		else
			{
			/* The packet is destined for a directly connected	*/
			/* node.											*/
			/* If this packet came from the lower layer and this*/
			/* node is not a gateway, drop the packet.			*/

			if ((instrm != iprmd_ptr->instrm_from_ip_encap) &&
				(instrm != IpC_Pk_Instrm_Child) &&
				(iprmd_ptr->gateway_status == OPC_FALSE))
				{

				/* Drop the packet								*/
				*destroy_pkt_ptr = OPC_TRUE;
				sprintf (drop_reason_str, "Dropped on a non-routing node");
				*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
				strcpy (*drop_reason_pstr, drop_reason_str);
#ifdef OP_DEBUG1
				printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-NOT Gateway node.  From lower and for someone else in my net\n");
#endif

				FRET (OPC_COMPCODE_SUCCESS);
				}
			/* Make sure that we are not trying to send the		*/
			/* packet to a loopback interface. This might occur	*/
			/* if the destination address of the packet falls	*/
			/* in the same IP subnet as the loopback interface.	*/
			/* due to misconfiguration.							*/
			if (ip_rte_intf_is_loopback (output_intf_info_ptr))
				{

				/* See if a Mobile IP process is enabled on the loopback interface. */
				if (output_intf_info_ptr->mip_enabled == OPC_FALSE)
					{

					/* Drop the packet.								*/
					*destroy_pkt_ptr = OPC_TRUE;
					sprintf (drop_reason_str, "Forwarding interface is Loopback");
					*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
					strcpy (*drop_reason_pstr, drop_reason_str);
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-Gateway node.  OutputIntf is Loopback.  Drop\n");
#endif
				
					FRET (OPC_COMPCODE_SUCCESS);
					}
				}

			/* Set the flags									*/
			*broadcast_ptr = OPC_FALSE;
			*higher_layer_ptr = OPC_FALSE;
#ifdef OP_DEBUG1
			printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()-Gateway node.  For someone else: %u \n", 
				dest_addr.address.ipv4_addr);
#endif


			/* LP 3-21-04 - added with JPH proposed fixed for Opnet 10 */	
		    /* If host routes are used, e.g., for manet protocols,  */  /* JPH */
	        /* skip this block that handles local destination.      */  /* JPH */
			
			if (host_routing_enabled)  goto hrt;                        /* JPH */

			/* end LP */
			
			/* Fill in the return values.						*/
			*next_addr_ptr = inet_address_copy (dest_addr);
			*interface_pptr = output_intf_info_ptr;
			}

		/* We have figured out what to do with the packet.		*/

		FRET (OPC_COMPCODE_SUCCESS);
		} /* end if Comcode = Success */
	else
		{
#ifdef OP_DEBUG1
			printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()- Comcode = FAIL \n");
#endif
		/* This is a packet that is addressed to none of the local interfaces. */
		/* See if a mobile IP process should handle this ICMP packet. */
			

		if (protocol_type == IpC_Protocol_Icmp)
			{
			if (iprmd_ptr->mobile_ip_enabled)
				{
				if (OPC_COMPCODE_SUCCESS == mip_sup_incoming_interface_check (iprmd_ptr,
					instrm, &output_intf_info_ptr))
					{
					/* Set the flag. */
					*higher_layer_ptr = OPC_TRUE;
				
					/* Fill in the return values. */
					*next_addr_ptr = inet_rte_v4intf_addr_get (output_intf_info_ptr);
					*interface_pptr = output_intf_info_ptr;
					output_port_info_ptr->intf_tbl_index = ip_rte_intf_tbl_index_get 
						(iprmd_ptr, output_intf_info_ptr);				
#ifdef OP_DEBUG1
					printf("\t ip_rte_support.c-ip_rte_datagram_dest_get()- Comcode = FAIL.  ICMP and Mobil IP are OK\n");
#endif
				
					FRET (OPC_COMPCODE_SUCCESS);
					}
				}
			}

		} /* end if comcode fail */

	/* The packet is not destined for this node or any other 	*/
	/* node directly connected to this node.					*/
	/* We need to do a common route table lookup to figure out	*/
	/* how to route the packet. 								*/
	


		/* LP 3-21-04 - added with JPH proposed fixed for Opnet 10 */	

hrt:    // JPH 10.0 hack - end LP

#ifdef OP_DEBUG1
	printf("\tip_rte_support.c - ip_rte_datagram_dest_get() - Dest is not directly connected.  Lookup RT\n");
#endif
	/* Destroy the packet if its comming from the lower layer and is not destined for this node.*/
	/* The packet is only processed if the node is a gateway.									*/

	if ((instrm != iprmd_ptr->instrm_from_ip_encap) && 
		(instrm != IpC_Pk_Instrm_Child) && 
		(iprmd_ptr->gateway_status == OPC_FALSE))
		{

		/* Destroy the packet if it is not destined for this node.	*/
		*destroy_pkt_ptr = OPC_TRUE;
		sprintf (drop_reason_str, "Dropped on a non-routing node");
		*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
		strcpy (*drop_reason_pstr, drop_reason_str);
#ifdef OP_DEBUG1
	printf("\tip_rte_support.c - ip_rte_datagram_dest_get()-Dest is not directly connected. Pk from lower.  Not gateway. Drop\n");
#endif

		FRET (OPC_COMPCODE_SUCCESS);
		}


	/* The destination is neither a broadcast nor does it match an	*/
	/* IP interface on this node. 									*/
	*broadcast_ptr = OPC_FALSE;

	/* If this is a tracer packet and we are using packet		*/
	/* based load balancing, we might have to split the packet	*/
	/* Set the flag to indicate this condition.					*/
	tracer_pkt_split = (Boolean) 
		((op_pk_encap_flag_is_set (pkptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX)) && 
		 (iprmd_ptr->ip_route_table->load_type == IpC_Rte_Table_Load_Packet));

	
	/* If this is a security check pkt then we will not split the pkt		*/
	if (op_pk_encap_flag_is_set (pkptr, OMSC_SECURITY_ENCAP_FLAG_INDEX))
		tracer_pkt_split = OPC_FALSE;		
	
	/* If this router has been configured for per-destination load balancing */
	/* then we must strip the destination and source from the IP packet.	 */
	if (iprmd_ptr->ip_route_table->load_type == IpC_Rte_Table_Load_Dest)
		{
		op_pk_nfd_access (pkptr, "fields", &pk_fds_ptr);
		dest_fast_ip_addr	= pk_fds_ptr->dest_internal_addr;
		src_fast_ip_addr	= pk_fds_ptr->src_internal_addr;
		}
	else
		{
		dest_fast_ip_addr	= IPC_ADDR_INVALID;
		src_fast_ip_addr	= IPC_ADDR_INVALID;
		}

	/* Invoke routing table lookup.	*/
	/* If this is a tracer packet and we are doing packet based	*/
	/* load balancing, get the route table entry itself.		*/

	route_status = inet_cmn_rte_table_recursive_lookup_cache (iprmd_ptr->ip_route_table,
		dest_addr, next_addr_ptr, output_port_info_ptr, src_proto_ptr,
		(tracer_pkt_split ? &route_entry_ptr : OPC_NIL), dest_fast_ip_addr, src_fast_ip_addr);

	/* If the routing table lookup fails, look for a default gateway.	*/
	if (route_status == OPC_COMPCODE_FAILURE)
		{	
#ifdef OP_DEBUG1
		printf("\t\t FAIL CME RT look up. No route is found \n");
#endif

		/* The common route table lookup failed. Drop the packet if the node is not running MANET */

		/* The route was not found from the lookup -- so, if MANET is enabled, on the  */
		/* router, then do not destroy the packet, instead return FAILURE, so that the packet */
		/* can be forwarded to MANET 													*/
		if ((iprmd_ptr->manet_enabled == OPC_TRUE) && (protocol_type != IpC_Protocol_Tora))
			{
			/* The idea is to force the packet to Tora since the lookup failed */
			*destroy_pkt_ptr = OPC_FALSE;
			FRET (OPC_COMPCODE_FAILURE);		
			}
	
		/* Create a printable version of the destination 	*/
		/* IP address being	processed.						*/
		dest_addr_str = inet_address_str_mem_alloc ();
		inet_address_print (dest_addr_str, dest_addr);
				
		/* A route to the destination address cannot be found. 	*/
		/* Report an error. Construct error string.				*/
		sprintf (error_str, "Unable to find a gateway while routing datagram destined for (%s)", dest_addr_str);

		/* Write a message to the simulation log file.	*/
		ipnl_proterr_noroute_ripospf (
			dest_addr_str, "RIP/OSPF/IGRP/STATIC", op_pk_id (pkptr), op_pk_tree_id (pkptr));
				
		/* Set the boolean flag indicating that this packet	*/
		/* should be destroyed by the client.				*/
		*destroy_pkt_ptr = OPC_TRUE;
		sprintf (drop_reason_str, "No route to destination");
		*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
		strcpy (*drop_reason_pstr, drop_reason_str);

		op_prg_mem_free (dest_addr_str);

		FRET (OPC_COMPCODE_SUCCESS);
		}  /* end if route_status = FAILDED */

	/* If we asked for the route table entry, check the number of	*/
	/* next hops in the route. If there is  only one next hop, we	*/
	/* can handle the packet like any other packet.					*/
	if (tracer_pkt_split)
		{
		num_next_hops = ip_cmn_rte_table_entry_hop_num (iprmd_ptr->ip_route_table, route_entry_ptr);
#ifdef OP_DEBUG1
		printf("\t\t Found a route.  Num of next hop = %d \n", num_next_hops);
#endif


		if (num_next_hops == 1)
			{

			/* Only one interface, just do normal behavior */
			*next_addr_ptr = inet_cmn_rte_table_entry_hop_get (route_entry_ptr, 0, output_port_info_ptr);

			/* The recursive lookup function guarantees that	*/
			/* if the number of next hops of the returned is	*/
			/* one, it will be directly connected.				*/

			/* Reset the tracer_pkt_split flag to indicate that no	*/
			/* splitting is required.								*/
			tracer_pkt_split = OPC_FALSE;
			}
		}
			
	/* Unless this is a tracer packet that might have to be split	*/
	/* because we are using packet based load balancing, we would	*/
	/* have a valid next hop.										*/
	if (tracer_pkt_split == OPC_FALSE)
		{
#ifdef OP_DEBUG1
	printf("\tip_rte_support.c - ip_rte_datagram_dest_get() - Dest is not directly connected.  tracer_pk_split = FALSE\n");
#endif
		/* If the output table index is IPC_INTF_TBL_INDEX_NULL0, it 	*/
		/* means that the matching route was a Null0 route. Drop the	*/
		/* packet.														*/
	

		if (IPC_INTF_TBL_INDEX_NULL0 == output_port_info_ptr->intf_tbl_index)
			{
			*destroy_pkt_ptr = OPC_TRUE;
			sprintf (drop_reason_str, "Null0 next hop");
			*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
			strcpy (*drop_reason_pstr, drop_reason_str);

			inet_address_destroy (*next_addr_ptr);
			}

		else if (IPC_INTF_TBL_INDEX_LSP == output_port_info_ptr->intf_tbl_index)
			{
			/* Obtain LSP name */
			*lsp_name_pstr = output_port_info_ptr->intf_name;
			}

		else 
			{
#ifdef OP_DEBUG1
		printf("\t\t Found a valid route.  \n");
#endif

			/* We have a valid route (and a valid next hop). Get a pointer	*/
			/* to the interface info of the interface this hop corresponds to*/
			*interface_pptr = inet_rte_intf_tbl_access (iprmd_ptr, output_port_info_ptr->intf_tbl_index);

			/* Make sure that the interface index was valid.				*/
			if (OPC_NIL == *interface_pptr)
				{
				/* The Interface index specified was invalid. Destroy the	*/
				/* packet.													*/
				inet_address_destroy (*next_addr_ptr);

				FRET (OPC_COMPCODE_FAILURE);
				}
			}

		FRET (OPC_COMPCODE_SUCCESS);
		}

	/* This is background utilization packet. These packets need	*/
	/* to be handled separately because, in case there are			*/
	/* multiple routes to the destination, this packet will be		*/
	/* split so that background utilization will be seen on all		*/
	/* the routes. However if destination based load balancing is	*/
	/* used, the tracer packet will not be split.					*/
	/* Iterate through the various next hops of the routing	entry.  */
	/* The last invocation will provide the settings used for the 	*/
	/* rest of the processing.										*/

	/* This is packet based load balancing so the packet */
	/* will be split among all available next hops		 */
	/* according to the cost associated with each one.	 */
#ifdef OP_DEBUG1
	printf("\tip_rte_support.c - ip_rte_datagram_dest_get() - background utilization packet.\n");
#endif

	*num_tracer_info_ptr = num_next_hops;
	*tracer_info_array_pptr = (IpT_Tracer_Info *)
		op_prg_mem_alloc ((num_next_hops) * sizeof (IpT_Tracer_Info));
		
	/*Determine the traffic share for each route			*/
	for (i = 0, valid_entry_index = 0; i < num_next_hops; i++)
		{
		/* The traffic has to be shared in the ratio of the inverse	*/
		/* of the costs. Store the inverse of the cost of each		*/
		/* next hop. simulataneously, calculate the sum of these	*/
		/* inverses also. Note that unreachable next hops will be	*/
		/* ignored during this calculation.							*/

		/* It is possible that some or all of the routes have a		*/
		/* zero cost. In that case, the traffic should be split		*/
		/* equally among the zero cost routes and no traffic should	*/
		/* be sent on the other routes.								*/

		/* Get the ith next hop										*/
		*next_addr_ptr = inet_cmn_rte_table_entry_hop_get (route_entry_ptr, i, output_port_info_ptr);

		/* It is possible that this next hop is not directly*/
		/* connected. In that case do a recursive lookup	*/
		/* to find a directly connected next hop			*/
		if (! ip_rte_port_info_is_defined (*output_port_info_ptr))
			{
			/* Do a recursive lookup to find a directly connected	*/
			/* next hop.											*/
			if (OPC_COMPCODE_FAILURE == inet_cmn_rte_table_recursive_lookup_cache
				(iprmd_ptr->ip_route_table, *next_addr_ptr, &dir_conn_next_addr,
				output_port_info_ptr, src_proto_ptr, OPC_NIL, IPC_ADDR_INVALID, IPC_ADDR_INVALID))
				{
				/* The next hop is not reachable. Ignore this route		*/
				inet_address_destroy (*next_addr_ptr);
				continue;
				}
			else
				{
				/* Use the directly connected next hop instead of the	*/
				/* actual one.											*/
				inet_address_destroy (*next_addr_ptr);
				*next_addr_ptr = dir_conn_next_addr;
				}
			}

		/* We no longer need the next_addr_ptr. All we need is the	*/
		/* directly connected next address which is stored in		*/
		/* dir_conn_next_addr.										*/
		inet_address_destroy (*next_addr_ptr);

		/* Make sure the next hop is not Null0.						*/
		/* LSPs also do not support tracer splitting.				*/
		if ((IPC_INTF_TBL_INDEX_NULL0 == output_port_info_ptr->intf_tbl_index) ||
			(IPC_INTF_TBL_INDEX_LSP == output_port_info_ptr->intf_tbl_index))
			{
			/* Ignore this next hop									*/
			continue;
			}

		/* Get the cost of the this route							*/
		ith_cost = ip_cmn_rte_table_entry_cost_get (route_entry_ptr, i);

		/* Check whether the cost is zero.							*/
		if (0 == ith_cost)
			{
			/* Increment the number of zero cost routes. and store	*/
			/* the inverse of the cost as infinity					*/
			++num_zero_cost_routes;
			(*tracer_info_array_pptr)[valid_entry_index].ratio = OPC_DBL_INFINITY;
			}
		else
			{
			/* Store the inverse of the cost and also increment the	*/
			/* vriable that stores the sum of the inverses.			*/
			(*tracer_info_array_pptr)[valid_entry_index].ratio = 1.0 / (double) ith_cost;
			total_share += (*tracer_info_array_pptr)[valid_entry_index].ratio;
			}

		/* Fill in the rest of the information.						*/
		*interface_pptr = ip_rte_intf_tbl_access (iprmd_ptr, output_port_info_ptr->intf_tbl_index);
			
		tracer_info_ptr = &((*tracer_info_array_pptr)[valid_entry_index]);
		tracer_info_ptr->interface_ptr = *interface_pptr;
		tracer_info_ptr->output_intf_index = output_port_info_ptr->intf_tbl_index;
		tracer_info_ptr->minor_port = 
			ip_rte_minor_port_from_port_info_get (iprmd_ptr, *output_port_info_ptr);

		/* Store the next hop address also. No need to use				*/
		/* inet_address_copy because inet_cmn_rte_table_entry_hop_get	*/
		/* or inet_cmn_rte_table_recursive_lookup_cache function would	*/
		/* have done it already.										*/
		tracer_info_ptr->next_addr = *next_addr_ptr;
		
		/* rkakaraparthi: multi-path splitting error.	*/
		if (op_prg_odb_ltrace_active ("ip_rte"))
			{
			printf ("Splitting demand to: \n");
			inet_address_print_debug (next_addr_ptr);
			}

		/* Increment the valid entry index							*/
		++valid_entry_index;

}
		
	/* Consider only the valid next hops.							*/
	num_next_hops = valid_entry_index;
	*num_tracer_info_ptr = num_next_hops;

	/* Make sure there is atleast one valid next hop				*/
	if (0 == num_next_hops)
		{
		/* None of the next hops were valid.						*/
		*destroy_pkt_ptr = OPC_TRUE;
		sprintf (drop_reason_str, "No Valid Next hops");
		*drop_reason_pstr = (char*) op_prg_mem_alloc ((strlen (drop_reason_str) + 1) * sizeof (char));
		strcpy (*drop_reason_pstr, drop_reason_str);

		FRET (OPC_COMPCODE_SUCCESS);
		}

	/* Now that we know the costs of all the routes we can figure	*/
	/* out the share of traffic for each							*/
	for (i = 0; i < num_next_hops; i++)
		{
		tracer_info_ptr = &((*tracer_info_array_pptr)[i]);

		/* Divide each of the shares with the total share to get	*/
		/* the ratio of the traffic to be sent on each next hop		*/
		/* However if there are zero cost routes, set the ratio to	*/
		/* 1 / num_zero_cost_routes for zero cost routes and 0 for	*/
		/* other routes.											*/
		if (num_zero_cost_routes)
			{
			if (OPC_DBL_INFINITY == tracer_info_ptr->ratio)
				{
				/* This is a zero cost route.						*/
				tracer_info_ptr->ratio = 1.0 / (double) num_zero_cost_routes;
				}
			else
				{
				/* This is not a zero cost route.					*/
				tracer_info_ptr->ratio = 0.0;
				}
			}
		else
			{
			/* There are no zero cost routes. Compute the ratio by	*/
			/* dividing the inverse of the cost with the sum of the	*/
			/* inverses.											*/
			tracer_info_ptr->ratio /= total_share; 
			}
		}


	/* If some of the routes had a zero cost, we will not be sending*/
	/* traffic on all the routes. Create a new array containg only	*/
	/* routes that will actually carry traffic.						*/
	if ((0 != num_zero_cost_routes) && (num_zero_cost_routes != num_next_hops))
		{
		/* Allocate memory for the new array.						*/
		new_tracer_info_array_ptr = (IpT_Tracer_Info *)
			op_prg_mem_alloc ((num_zero_cost_routes) * sizeof (IpT_Tracer_Info));
		/* Copy over all the necessary elements from the original	*/
		/* array.													*/
		for (i = 0, j = 0; i < num_next_hops; i++)
			{
			if ((*tracer_info_array_pptr)[i].ratio)
				{
				new_tracer_info_array_ptr[j++] = (*tracer_info_array_pptr)[i];
				}
			}
		/* Free the memory allocated to the old_array and use the	*/
		/* new one instead.											*/
		op_prg_mem_free (*tracer_info_array_pptr);
		*tracer_info_array_pptr = new_tracer_info_array_ptr;
		*num_tracer_info_ptr = num_zero_cost_routes;
		}

	FRET (OPC_COMPCODE_SUCCESS);
	}
		
static Compcode
ip_rte_mcast_datagram_dest_get (IpT_Rte_Module_Data * iprmd_ptr, Packet* pkptr, Ici* rsvp_ici_ptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr, 
	InetT_Address dest_addr, InetT_Address* next_addr_ptr, Boolean* broadcast_ptr, Boolean* higher_layer_ptr, 
	Boolean* destroy_pkt_ptr, int protocol_type,  int* output_table_index_ptr, IpT_Interface_Info** interface_pptr)
	{
	int							num_of_intfs;
	IpT_Interface_Info*			intf_info_ptr;
	IpT_Rte_Rsvp_Route*			rsvp_route_info_ptr;
	DsrT_Route_Info*			dsr_route_info_ptr;
	Ici*						dsr_ici_ptr;
	InetT_Address				dest_mcast_address;
	
	/** Retrieve and return the outstream, outslot and mtu to which we should**/
	/** multicast the datagram. This function may also return status flags	 **/
	/** indicating that the datagram should be forwarded to the higher layer.**/
	/** If OPC_COMPCODE_SUCCESS is returned, the datagram can be dispatched	 **/
	/** by the client of this procedure; if OPC_COMPCODE_FAILURE is returned,**/
	/** a routing message error shoud be generated, and the datagram should	 **/
	/** be destroyed. RSVP packets are treated as a special case, when the	 **/
	/** routing parameters are set based on the parameters set in the 		 **/
	/** intf_ici. The parameters in intf_ici were previously set based on ICI**/
	/** accompanying the RSVP packet.										 **/
	FIN (ip_rte_mcast_datagram_dest_get (pkptr, intf_ici_fdstruct_ptr, dest_addr, protocol_type, rsvp_ici_ptr,
		next_addr_ptr, higher_layer_ptr, destroy_pkt_ptr, output_intf_index_ptr, interface_pptr));

#ifdef OP_DEBUG1
	printf("\tip_rte_support.c - ip_rte_mcast_datagram_dest_get() \n");
#endif

	/* Initialize the flags to OPC_FALSE.	*/
	*higher_layer_ptr = OPC_FALSE;
	*destroy_pkt_ptr = OPC_FALSE;

	/* Determine the size of the interface table.	*/
	num_of_intfs = ip_rte_num_interfaces_get (iprmd_ptr);

	/* Check if the packet is received from higher or lower layer	*/
	if ((intf_ici_fdstruct_ptr->instrm == iprmd_ptr->instrm_from_ip_encap) || 
		(intf_ici_fdstruct_ptr->instrm == IpC_Pk_Instrm_Child))
		{
		/** The packet came from higher layer or a child process **/

		/* If this is an RSVP packet, do not perform route query, 	*/
		/* but rather set the routing parameters.					*/
		if ((protocol_type == IpC_Protocol_Rsvp) && 
			(intf_ici_fdstruct_ptr->instrm != IpC_Pk_Instrm_Child))
			{
			/** This is an RSVP packet.		**/

			/* The packet should be accompanied by ICI.		*/
			/* Read the routing information in the ICI.		*/
			op_ici_attr_get (rsvp_ici_ptr, "RSVP Packet Route Info", &rsvp_route_info_ptr);

			/* Destroy the RSVP ICI.							*/
			op_ici_destroy (rsvp_ici_ptr);

			/* Store the index of this interface object in output_intf_index	*/
			*output_table_index_ptr = rsvp_route_info_ptr->output_intf_index;

			/* Find the interface pointer.	*/
			intf_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, rsvp_route_info_ptr->output_intf_index);

			/* Set the out port information in the packet ICI	*/
			intf_ici_fdstruct_ptr->multicast_major_port = rsvp_route_info_ptr->output_intf_index;

			/* Deallocate memory allocated for the ICI DS.	*/
			op_prg_mem_free (rsvp_route_info_ptr);

			/* Store this interface object in interface_ptr.	*/
			*interface_pptr = intf_info_ptr;

			/* Check if this interface is enabled for multicasting	*/
			if (ip_rte_intf_mcast_enabled (intf_info_ptr) == OPC_TRUE)
				{
				/** Multicasting is enabled on this interface	*/
				
				/* Do not try to send packets to the loopback interface.			*/
				if (ip_rte_intf_is_loopback (intf_info_ptr))
					{
					/* Write out a message to the sim. log.	*/
					ipnl_protwarn_mcast_cannot_fwd_pkt_to_intf (pkptr, intf_ici_fdstruct_ptr->multicast_major_port);
					
					FRET (OPC_COMPCODE_FAILURE);
					}
				
				/** The multicast packet should be forwarded to this interface **/
				
				/* For IPv4 packets, set the next address to the subnet level	*/
				/* broadcast address of the interface. This is necessary to		*/
				/* support subinterfaces on ppp (dumb) interfaces.				*/
				if (InetC_Addr_Family_v4 == inet_address_family_get (&dest_addr))
					*next_addr_ptr = inet_rte_v4intf_broadcast_addr_get (intf_info_ptr);
				
				FRET (OPC_COMPCODE_SUCCESS);
				}
			
			FRET (OPC_COMPCODE_FAILURE);
			}
		
		/* Check to see if the destination address is a IPv6 broadcast address 	*/
		/* for all interfaces, If so set the variable representing the 			*/
		/* interface on which the packet is to be sent out to					*/
		/* IP_BROADCAST_ALL_INTERFACES.											*/
		if (inet_address_equal (dest_addr, InetI_Ipv6_All_Nodes_LL_Mcast_Addr))
			{
			/* higher_layer flag has been initialized to false	*/
			*output_table_index_ptr = IP_BROADCAST_ALL_INTERFACES;
			*broadcast_ptr = OPC_TRUE;
			*interface_pptr = OPC_NIL;			
			
			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		if (protocol_type == IpC_Protocol_Dsr)
			{
			/* Packet came from the DSR MANET child process		*/
			/* The packet should be routed to the lower layer	*/
			/* based on the DSR source route in the packet		*/
			dsr_ici_ptr = op_pk_ici_get (pkptr);
			
			if (dsr_ici_ptr == OPC_NIL)
				{
				/* There is no ICI associated 	*/
				/* with the packet. Do nothing	*/
				}
			else
				{
				/* Get the next hop information from the ICI	*/
				op_ici_attr_get (dsr_ici_ptr, 
				"DSR Routing Info", &dsr_route_info_ptr);
				
				/* Set the routing information	*/
				
				/* Set the next hop address	*/
				*next_addr_ptr = inet_address_copy (dsr_route_info_ptr->next_hop_addr);

				/* Store the index of this interface object in intf_index.	*/
				*output_table_index_ptr = dsr_route_info_ptr->output_table_index;
				
				/* Set the interface pointer.	*/
				*interface_pptr = dsr_route_info_ptr->interface_info_ptr;
				
				/* Destroy the IP address	*/
				inet_address_destroy (dsr_route_info_ptr->next_hop_addr);
				
				/* Deallocate memory allocated for the ICI DS.	*/
				op_prg_mem_free (dsr_route_info_ptr);
				
				/* Destroy the DSR ICI.							*/
				op_ici_destroy (dsr_ici_ptr);
				
				FRET (OPC_COMPCODE_SUCCESS);
				}
			}
		
		/* Get the Interface information of the interface on which the packet	*/
		/* is being sent out.													*/
		intf_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, intf_ici_fdstruct_ptr->multicast_major_port);

		/* Check if this interface is enabled for multicasting	*/
		/* Also check if the destination is the IMEP multicast destination */
		/* address. If either condition is met then perform the multicast operation */
		dest_mcast_address = inet_address_from_ipv4_address_create (ip_address_create (ALL_IMEP_ROUTERS));
		if ((ip_rte_intf_mcast_enabled (intf_info_ptr) == OPC_TRUE) ||
			(inet_address_equal (dest_addr, dest_mcast_address) == OPC_TRUE))
			{
			/** Multicasting is enabled on this interface	*/

			/* Do not try to send packets to the loopback interface.			*/
			if (ip_rte_intf_is_loopback (intf_info_ptr))
				{
				/* Write out a message to the sim. log.	*/
				ipnl_protwarn_mcast_cannot_fwd_pkt_to_intf (pkptr, intf_ici_fdstruct_ptr->multicast_major_port);

				FRET (OPC_COMPCODE_FAILURE);
				}

			/** The multicast packet should be forwarded to this interface **/

			/* For IPv4 packets, set the next address to the subnet level	*/
			/* broadcast address of the interface. This is necessary to		*/
			/* support subinterfaces on ppp (dumb) interfaces.				*/
			if (InetC_Addr_Family_v4 == inet_address_family_get (&dest_addr))
				{
				*next_addr_ptr = inet_rte_v4intf_broadcast_addr_get (intf_info_ptr);
				}
			else
				{
				/* IPv6 packet. Set the next address to be the the			*/
				/* destination address itself.								*/
				*next_addr_ptr = inet_address_copy (dest_addr);
				}

			/* Store the index of this interface object in output_intf_index	*/
			*output_table_index_ptr = intf_ici_fdstruct_ptr->multicast_major_port;	

			/* Store this interface object in interface_ptr	*/
			*interface_pptr = intf_info_ptr;
		
			FRET (OPC_COMPCODE_SUCCESS);
			}

		/** This interface is not enabled for multicasting	**/

		/* Report a log message	*/
		ipnl_protwarn_mcast_cannot_fwd_pkt_to_intf (pkptr, intf_ici_fdstruct_ptr->multicast_major_port);

		/* Discard the packet	*/		
		FRET (OPC_COMPCODE_FAILURE);
		}
	else
		{
		/** The packet came from lower layer	**/

		/* Obtain the interface object for the interface on which this packet was received	*/
		if (intf_ici_fdstruct_ptr->intf_recvd_index != -1)
			{
			intf_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, intf_ici_fdstruct_ptr->intf_recvd_index);
			}
		else
			{
			(*iprmd_ptr->error_proc)("The interface on which the multicast packet was received is not specified in the packet's ICI.");
			}
		
		/* Check to see if the destination address is a IPv6 multicast address 	*/
		/* If so, forward the packet to	the higher layer.						*/
		if (inet_address_equal (dest_addr, InetI_Ipv6_All_Nodes_LL_Mcast_Addr))
			{
			/* Set the flags accordingly.						*/
			*higher_layer_ptr = OPC_TRUE;

			/* Set the port_info to point to the first interface*/
			/* Other wise the ip_rte_options_process function	*/
			/* might crash.										*/
			*output_table_index_ptr = 0;
			*interface_pptr = OPC_NIL;

			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		/* If the packet is a multicast IMEP packet - then also forward to the upper layer */
		dest_mcast_address = inet_address_from_ipv4_address_create (ip_address_create (ALL_IMEP_ROUTERS));
		if ((inet_address_equal (dest_addr, dest_mcast_address) == OPC_TRUE))
			{
			/* Forward the packet to upper layer */
			*higher_layer_ptr = OPC_TRUE;
			FRET (OPC_COMPCODE_SUCCESS);			
			}

		if (ip_rte_intf_mcast_enabled (intf_info_ptr) == OPC_FALSE)
			{
			/** The interface on which this packet was received is not enabled for multicasting	**/

			/* This packet was not filtered by DLL, just discard it	*/
			FRET (OPC_COMPCODE_FAILURE);
			}

		/** The interface on which this packet was received is enabled for multicasting **/

		if ((protocol_type == IpC_Protocol_Rsvp) && 
			(iprmd_ptr->rsvp_status == OPC_TRUE))
			{
			/** This is an RSVP packet and RSVP is enabled at the node.		**/

			/* All RSVP packets received from the network should be sent to the 	*/
			/* local RSVP process.													*/
			*higher_layer_ptr = OPC_TRUE;

			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		/* Check if this node has MANET enabled	*/
		if ((iprmd_ptr->manet_enabled == OPC_TRUE) && (protocol_type == IpC_Protocol_Dsr))
			{
			/* Send all DSR packets to the DSR 	*/
			/* routing protocol child			*/
			*destroy_pkt_ptr = OPC_FALSE;
			*higher_layer_ptr = OPC_TRUE;
			
			FRET (OPC_COMPCODE_SUCCESS);
			}
		
		/* If any application on this node has registered to accept this packet or this	*/
		/* node is a multicast router, forward the packet to upper layer				*/
		if ((iprmd_ptr->multicast_router == OPC_TRUE) ||
			(inet_address_multicast_accept (iprmd_ptr, dest_addr, intf_ici_fdstruct_ptr->intf_recvd_index,
										  IP_MCAST_NO_PORT) == OPC_TRUE)
			)
			{
			/* Forward the packet to upper layer */
			*higher_layer_ptr = OPC_TRUE;
			FRET (OPC_COMPCODE_SUCCESS);
			}
				
		/* This packet was not filtered by DLL, just discard it.*/
		FRET (OPC_COMPCODE_FAILURE);
		}
	}

static void
ip_rte_dgram_options_process (IpT_Rte_Module_Data * iprmd_ptr, 
	Packet* ip_pkptr, int output_table_index)
	{
	IpT_Dgram_Options*		ip_dgram_options_ptr		= OPC_NIL;
	IpT_Dgram_Options*		origin_ip_dgram_options_ptr	= OPC_NIL;
	IpT_Icmp_Ping_Data*		ping_data_ptr				= OPC_NIL;
	IpT_Dgram_Fields*		pk_fd_ptr					= OPC_NIL;
	Packet *				origin_pkptr				= OPC_NIL;
	InetT_Addr_Family		addr_family;
	InetT_Address 			ip_address = INETC_ADDRESS_INVALID;
	
	/** IP supports setting "options" while transmitting datagrams	**/
	/** across source-destination pairs - currently the only option	**/
	/** supported in this model is the "Record Route" option,		**/
	/** wherein every router in the path records the address of the	**/
	/** interface it uses to forward the packet to the next hop.	**/
	FIN (ip_rte_dgram_options_process (ip_pkptr, output_iface_index));

	/* Obtain the "options" fields from the IP datagram.	*/
	op_pk_nfd_access (ip_pkptr, "options", &ip_dgram_options_ptr);

	/* Extract the field of the IP packet					*/
	op_pk_nfd_access (ip_pkptr, "fields", &pk_fd_ptr);

	/* Find out if we are dealing with an IPv4 or an IPv6 packet*/
	addr_family = inet_address_family_get (&(pk_fd_ptr->dest_addr));

	/* Currently the model only supports IP record route option	*/
	/* Check if that option is being used.						*/
	if ((ip_dgram_options_ptr != OPC_NIL) &&
		(ip_dgram_options_ptr->type == IpC_Option_Record_Route))
		{
		/* Obtain the IP address of the output interface to be 	*/
		/* used to forward this datagram to the next node.		*/

		/* Get the Interface IP Address							*/
		ip_address = inet_rte_intf_addr_get (inet_rte_intf_tbl_access (iprmd_ptr, output_table_index), addr_family);
		
		/* Insert this address in the route data field of the	*/
		/* options data structure.								*/
		ping_data_ptr = ip_rte_icmp_ping_data_create (ip_address, OPC_INT_UNDEF, OPC_INT_UNDEF);
		
		if (pk_fd_ptr->frag)
			{
			/* Packet fragment needs special attention			   */
			if (op_pk_nfd_is_set (ip_pkptr, "ip_dgram"))
				{
				/* This is the last segment of the original packet */
				/* Extract the original IP packet and the option   */
				op_pk_nfd_get (ip_pkptr, "ip_dgram", &origin_pkptr);
				
				/* Obtain the "options" fields from the original IP datagram.	*/
				op_pk_nfd_access (origin_pkptr, "options", &origin_ip_dgram_options_ptr);

				/* Record the route in the original IP packet header			*/
				op_prg_list_insert (origin_ip_dgram_options_ptr->route_data_lptr, ping_data_ptr, OPC_LISTPOS_TAIL);
				
				/* Increment the lenth of the entries in the route data list.	*/
				origin_ip_dgram_options_ptr->length++;
				
				/* Set original IP packet back to the IP packet				    */
				op_pk_nfd_set (ip_pkptr, "ip_dgram", origin_pkptr);
				
				}
			else
				{
				/* For a fragment which does not contain the original data gram */
				/* there is no need to record the route.						*/
				ip_rte_icmp_ping_data_destroy (ping_data_ptr);
				}
			}
		else
			{
			/* Not a segement */
			op_prg_list_insert (ip_dgram_options_ptr->route_data_lptr, ping_data_ptr, OPC_LISTPOS_TAIL);
			/* Increment the lenth of the entries in the route data list.	*/
			ip_dgram_options_ptr->length++;
			}
		}

	FOUT;
	}

static double
ip_rte_decomp_delay_compute (Packet* pkptr, IpT_Dgram_Fields* pk_fd_ptr)
	{
	OpT_Packet_Size		size;
	OpT_Packet_Size		decompressed_size;
	double				decomp_delay = 0.0;

	/** This fucntion computes the amount of processing time 		**/
	/** necessary to decompress the compressed parts of the input	**/
	/** datagram. The computed delay value is returned.				**/
	FIN (ip_rte_decomp_delay_compute (pkptr, pk_fd_ptr));

	/* Get the current size of the datagram.	*/
	size = op_pk_total_size_get (pkptr);

	/* Based on the method used to compress the datagram, compute	*/
	/* the size of packet's compressed parts.						*/
	switch (pk_fd_ptr->compression_method) 
		{
		case IpC_TCPIP_Header_Comp:
			{
			decompressed_size = IPC_TCP_COMPRESSABLE_HEADER_SIZE - (pk_fd_ptr->original_size - size);
			break;
			}
		case IpC_Per_Interface_Comp:
			{
			decompressed_size = size;
			break;
			}
		case IpC_Per_Virtual_Circuit_Comp:
			{
			decompressed_size = pk_fd_ptr->frag_len * 8;
			break;
			}
		default:
			{
			break;
			}
		}

	/* Decompression delay is the multiplication of per-bit			*/
	/* decompression delay (a charecteristic of compression method)	*/
	/* the size of packet's compressed parts.						*/
	decomp_delay = pk_fd_ptr->decompression_delay * decompressed_size; 

	FRET (decomp_delay);
	}

static void
ip_rte_ip_vpn_tunnel_packet (IpT_Rte_Module_Data * iprmd_ptr, 
	Packet** pkptr, double* tunnel_delay)
	{
	/** This function is called to handle packet from **/
	/** lower layer only. Anything from higher layer  **/
	/** will not be checked for tunneling. Tunnel is  **/
	/** enabled only on routers.                      **/
	
	FIN (ip_rte_ip_vpn_tunnel_packet (pkptr, tunnel_delay));
	
	/* Pass the packet pointer to ip_vpn process     */
	/* through parent to child memory installed      */
	/* during child process creation                 */
	
	iprmd_ptr->vpn_ptc_mem.child_pkptr = *pkptr;
	
	/* Initilize vpn delay to be zero */
	iprmd_ptr->vpn_ptc_mem.vpn_delay = 0.0;
	
	/* Invoke the child process to handle the packet */
	/* if the packet needs to be tunneled or comes   */
	/* from a tunnel,ie the packet is at the tunnel  */
	/* end node, encryption/decryption delay may be  */
	/* incured. NAPT?                                */
	op_pro_invoke (iprmd_ptr->vpn_process_handle, OPC_NIL);
	
	/* Get the delay from VPN tunneling */
	*tunnel_delay = iprmd_ptr->vpn_ptc_mem.vpn_delay;
	
	/* Take back the packet processed.This packet    */
	/* could be changed due to tunnel encapsulation  */
	/* by ip.                                        */
	*pkptr = iprmd_ptr->vpn_ptc_mem.child_pkptr;
	
	FOUT;
	}


static void
ip_packet_tunnel (IpT_Rte_Module_Data* iprmd_ptr, Packet* inner_pkptr,
	int instrm, InetT_Address next_addr, IpT_Interface_Info* tunnel_intf_ptr)
	{
	Packet*				ipv4_pkptr;
	Packet*				gre_pkptr;
	OpT_Packet_Size		inner_packet_size;
	IpT_Dgram_Fields*	outer_pk_fields_ptr;
	Compcode			status;
	double				encapsulation_delay = 0.0;
	int					tos;
	int					ttl;
	IpT_Dgram_Fields*	inner_pk_fields_ptr = OPC_NIL;
	Boolean				proto_enabled	= OPC_FALSE;
	InetT_Addr_Family	addr_family;
	int					temp_intf_index = 0;
	char				str0 [512], str1 [512];
	
	/** The packet is being sent out on a tunnel interface.		**/
	/** Encapsulate the packet and call ip_rte_interface_forward**/
	/** to forward it.											**/

	FIN (ip_packet_tunnel (args));
	
	/* We must ensure that there are no routing loops that are	*/
	/* causing multiple encapsulations of the packet. Just 		*/
	/* checking the source address of the packet against the	*/
	/* interfaces on this node is not sufficient, since the 	*/
	/* packet may be originating from this node. So, we check 	*/
	/* the protocol value of the inner packet and also the 		*/
	/* source address of the packet.							*/
	
	op_pk_nfd_access (inner_pkptr, "fields", &inner_pk_fields_ptr);
	
	if (ip_packet_protocol_is_tunnel ((IpT_Protocol_Type) inner_pk_fields_ptr->protocol))
		{
		if (inet_rte_is_local_address (inner_pk_fields_ptr->src_addr, iprmd_ptr, &temp_intf_index))
			{
			/* This is a tunnel packet from this node that has found	*/
			/* its way to this node again. This indicates a routing		*/
			/* loop and this packet must be discarded.					*/
			ip_rte_dgram_discard (iprmd_ptr, inner_pkptr, OPC_NIL,
				"Routing loop within tunnel");
			
			ip_nl_tunnel_routing_loop_src_log_write (tunnel_intf_ptr->full_name);
			FOUT;
			}
		}
	
	/* Create an IPv4 datagram.									*/
	ipv4_pkptr = ip_dgram_create ();

	/* Determine the size of the IPv6 packet.					*/
	inner_packet_size =  op_pk_total_size_get (inner_pkptr);

	/* Create a structure to hold the fields.					*/
	outer_pk_fields_ptr = ip_dgram_fdstruct_create ();
	
	/* The source address is the same for all tunnels.	*/
	outer_pk_fields_ptr->src_addr	= tunnel_intf_ptr->tunnel_info_ptr->src_addr;
	
	/* Add the tunnel header size to the inner packet size.			*/
	/* Only GRE has a tunnel header. The correct header size, based */
	/* on GRE options, has been computed during initialization.		*/
	inner_packet_size += tunnel_intf_ptr->tunnel_info_ptr->hdr_size_bits;
	
	/* If the tunnel mode is GRE, then the inner packet gets put inside	*/
	/* a GRE packet. After that it cannot be read (for TOS and TTL). 	*/
	/* Hence these fields are set prior to (potential) encapsulation  	*/
	/* inside a GRE packet.												*/			
	
	tos = tunnel_intf_ptr->tunnel_info_ptr->tos;
	ttl = tunnel_intf_ptr->tunnel_info_ptr->ttl;
	
	/* If the TOS value is set to inherited, we must use the TOS value from the	*/
	/* inner packet. 															*/
	if (tos == IPC_TUNNEL_TOS_INHERITED)
		tos = inner_pk_fields_ptr->tos;
	
	/* If the TTL value is set to inherited, we must use the TTL value from the	*/
	/* inner packet. 															*/
	if (ttl == IPC_TUNNEL_TTL_INHERITED) 
		ttl = inner_pk_fields_ptr->ttl;
		
	
	outer_pk_fields_ptr->tos = tos;
	outer_pk_fields_ptr->ttl = ttl;

	/* The src and dest addresses used will depend on the 		*/
	/* tunneling mechanism.										*/
	switch (tunnel_intf_ptr->tunnel_info_ptr->mode)
		{
		case IpC_Tunnel_Mode_IPv6_Manual:
			status = ip_rte_ipv6_manual_tunnel_pkt_fields_set (outer_pk_fields_ptr, tunnel_intf_ptr);
			outer_pk_fields_ptr->protocol	= IpC_Protocol_IPv6;
			/* In case of IPv6 tunnels, the enabled protocol		*/
			/* is only IPv6, enforced during tunnel initialization.	*/
			proto_enabled = OPC_TRUE;
			
			break;
		
		case IpC_Tunnel_Mode_IPv6_Auto:
			status = ip_rte_ipv6_auto_tunnel_pkt_fields_set (outer_pk_fields_ptr, next_addr, tunnel_intf_ptr);
			outer_pk_fields_ptr->protocol	= IpC_Protocol_IPv6;		
			/* In case of IPv6 tunnels, the enabled protocol		*/
			/* is only IPv6, enforced during tunnel initialization.	*/
			proto_enabled = OPC_TRUE;
			break;
		
		case IpC_Tunnel_Mode_IPv6_6to4:
			status = ip_rte_ipv6_6to4_tunnel_pkt_fields_set (outer_pk_fields_ptr, next_addr, tunnel_intf_ptr);	
			outer_pk_fields_ptr->protocol	= IpC_Protocol_IPv6;
			/* In case of IPv6 tunnels, the enabled protocol		*/
			/* is only IPv6, enforced during tunnel initialization.	*/
			proto_enabled = OPC_TRUE;
			break;

		case IpC_Tunnel_Mode_GRE:
			status = ip_rte_tunnel_pkt_fields_set (outer_pk_fields_ptr, tunnel_intf_ptr);
			gre_pkptr = ip_rte_tunnel_gre_pkt_create (inner_pkptr);	
			outer_pk_fields_ptr->protocol	= IpC_Protocol_GRE;
			/* In case of GRE, we must make sure that the protocol	*/
			/* is enabled on the tunnel. The protocol of the packet	*/
			/* is obtained by looking at the address family of the	*/
			/* destination.											*/
			addr_family = inet_address_family_get (&(inner_pk_fields_ptr->dest_addr));
			if (addr_family == InetC_Addr_Family_v4)
				{
				proto_enabled = IP_TUNNEL_PASSENGER_PROTOCOL_IPV4_IS_ENABLED (tunnel_intf_ptr->tunnel_info_ptr);
				if (!proto_enabled)
					{
					ip_nl_tunnel_passenger_proto_log_write (tunnel_intf_ptr->full_name, "IPv4");
					}
				
				}
			else if (addr_family == InetC_Addr_Family_v6)
				{
				proto_enabled = IP_TUNNEL_PASSENGER_PROTOCOL_IPV6_IS_ENABLED (tunnel_intf_ptr->tunnel_info_ptr);
				if (!proto_enabled)
					{
					ip_nl_tunnel_passenger_proto_log_write (tunnel_intf_ptr->full_name, "IPv6");
					}

				}			
			break;
 	
		case IpC_Tunnel_Mode_IPIP:	
			status = ip_rte_tunnel_pkt_fields_set (outer_pk_fields_ptr, tunnel_intf_ptr);
			outer_pk_fields_ptr->protocol	= IpC_Protocol_Ip;
			/* In case of IP-IP tunnels, the enabled protocol		*/
			/* is only IPv4, enforced during tunnel initialization.	*/
			proto_enabled = OPC_TRUE;

			break;
		
		default:
			/* Invalid tunnel mode. Terminate the simualtion.	*/
			op_sim_end ("In ip_packet_tunnel, the tunnel mode specified",
						"is invalid.", OPC_NIL, OPC_NIL);
			break;
		}

	/* If there was an error destroy both packets.				*/
	if (OPC_COMPCODE_FAILURE == status || OPC_FALSE == proto_enabled)
		{
		if (OPC_COMPCODE_FAILURE == status)
			strcpy (str0, "Attempt to tunnel packet failed");
		else 
			{
			strcpy (str0, "Passenger protocol not enabled on tunnel");			
			}
				
		
		/* If the tunnel mode is GRE, extract the inner packet.	*/
		if (tunnel_intf_ptr->tunnel_info_ptr->mode == IpC_Tunnel_Mode_GRE)
			{
			op_pk_nfd_get (gre_pkptr, "payload", &inner_pkptr);
			op_pk_destroy (gre_pkptr);
			}
		
		/* Drop the inner packet.								*/
		ip_rte_dgram_discard (iprmd_ptr, inner_pkptr, OPC_NIL,
			str0 /* Reason for drop */);

		/* Also destroy the IPv4 packet we just created. 		*/
		op_pk_destroy (ipv4_pkptr);

		/* Free the memory allocated to the IP fields structure.*/
		ip_dgram_fdstruct_destroy (outer_pk_fields_ptr);

		FOUT;
		}
		
	/* Fill in the rest of the fields.							*/
   	
	outer_pk_fields_ptr->orig_len		= (int) (inner_packet_size / 8);
	outer_pk_fields_ptr->frag_len		= outer_pk_fields_ptr->orig_len;
	outer_pk_fields_ptr->original_size 	= IPC_DGRAM_HEADER_LEN_BITS + inner_packet_size;	
	outer_pk_fields_ptr->ident 			= iprmd_ptr->dgram_id++;
	
	/* In order to test the sequence datagrams feature, we change the	*/
	/* identity field to a small value for one packet. This is done 	*/
	/* for the second packet going through the tunnel. This internal	*/
	/* test condition is easier to generate than building a network 	*/
	/* that delivers IP datagrams out of sequence. 						*/
	
	/* Start code for checking sequence-datagrams
	{
	static int i = 0;
	if (i == 2)
		outer_pk_fields_ptr->ident--;
	i++;
	}
	End code for checking sequence-datagrams	*/
	
	
	/* Set the fields structure in the packet.					*/
	op_pk_nfd_set (ipv4_pkptr, "fields", outer_pk_fields_ptr,
		ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof (IpT_Dgram_Fields));

	/* Encapsulate the tunneled packet in the IPv4 packet.			*/
	/* In case of GRE tunnels, the tunneled packet is encapsulated	*/
	/* in a GRE packet, which finally goes into the ipv4 packet.	*/
	if (IpC_Tunnel_Mode_GRE == tunnel_intf_ptr->tunnel_info_ptr->mode)
		op_pk_nfd_set (ipv4_pkptr, "data", gre_pkptr);
	else
		op_pk_nfd_set (ipv4_pkptr, "data", inner_pkptr);

	/* Set the bulk size of the IPv4 packet to be the size of	*/
	/* the inner packet.											*/
	op_pk_bulk_size_set (ipv4_pkptr, inner_packet_size);

	/* It is important that we use the same input stream on		*/
	/* which the original packet was received. This will ensure	*/
	/* that in routers with slot based processing, the tunneled	*/
	/* packet is also processed by the same slot that processed	*/
	/* the original packet. If the stream on which the packet	*/
	/* was received is set to IpC_Pk_Instrm_Child, use the 		*/
	/* stream from ip_encap. Otherwise, use the input argument. */
	if (IpC_Pk_Instrm_Child == instrm)
		{
		instrm = iprmd_ptr->instrm_from_ip_encap;
		}
	
	/* Compute the encapsulation delay.	*/
	encapsulation_delay = oms_dist_nonnegative_outcome (tunnel_intf_ptr->tunnel_info_ptr->encapsulation_delay);

	if (op_sim_debug () && op_prg_odb_ltrace_active ("ip_tunnel"))
		{
		sprintf (str0, "Interface = %s\t Protocol = %s", tunnel_intf_ptr->full_name, 
			ip_higher_layer_proto_name_find (outer_pk_fields_ptr->protocol));
		
		sprintf (str1, "Payload Size (bits): "OPC_PACKET_SIZE_FMT"\t Encapsulation Delay (sec): %f", 
			inner_packet_size, encapsulation_delay);
				 
		op_prg_odb_print_major ("Sending packet through tunnel", str0, str1, OPC_NIL);
		op_pk_print (ipv4_pkptr);
		}
	
	/* Update statistics corresponding to any flows traversing the	*/
	/* tunnel interface.											*/	
	
	/* The tunnel info object contains a routed state object that 	*/
	/* keeps track of bgutil traffic. This object must be created 	*/
	/* if it is not already present.								*/
	if (tunnel_intf_ptr->tunnel_info_ptr->bgutil_sent_state_ptr == OPC_NIL)
		tunnel_intf_ptr->tunnel_info_ptr->bgutil_sent_state_ptr 
		= oms_bgutil_routed_state_create (UNITS_IN_BPS, DO_NOT_SCALE);
	
	/* The oms function that records stats is requested to record	*/
	/* only bps and pps stats because we are not interested in the	*/
	/* bits, packets and utilization stats.							*/
	oms_bgutil_bkg_stats_update (ipv4_pkptr, &(tunnel_intf_ptr->tunnel_info_ptr->last_sent_update_time),
		tunnel_intf_ptr->tunnel_info_ptr->bgutil_sent_state_ptr,
		OPC_NIL,
		tunnel_intf_ptr->tunnel_info_ptr->traffic_sent_pps_lsh,
		OPC_NIL,
		tunnel_intf_ptr->tunnel_info_ptr->traffic_sent_bps_lsh,
		OPC_NIL,
		1.0);
	
	/* The last update time is used by the bgutil package to ensure that 	*/
	/* stats are not written into buckets that are already closed.			*/
	tunnel_intf_ptr->tunnel_info_ptr->last_sent_update_time = op_sim_time ();
	
	/* Explicit traffic stats must be written out explicitly.	*/
	if (!op_pk_encap_flag_is_set (ipv4_pkptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX))
		{
		/* Write stats for explicit traffic.Traffic stats are collected in	*/
		/* bucket mode sum/time mode :- record a zero after the value to 	*/
		/* prevent the value from influencing the start value of the next	*/
		/* bucket.															*/	
		Oms_Dim_Stat_Write (tunnel_intf_ptr->tunnel_info_ptr->traffic_sent_pps_lsh, 1.0);
		Oms_Dim_Stat_Write (tunnel_intf_ptr->tunnel_info_ptr->traffic_sent_pps_lsh, 0.0);
		Oms_Dim_Stat_Write (tunnel_intf_ptr->tunnel_info_ptr->traffic_sent_bps_lsh, (double) op_pk_total_size_get (ipv4_pkptr));
		Oms_Dim_Stat_Write (tunnel_intf_ptr->tunnel_info_ptr->traffic_sent_bps_lsh, 0.0);
		}
	
	/* If the node is a gateway, then the outer packet must be routed.	*/
	if (iprmd_ptr->gateway_status == OPC_TRUE)
		{
		/* Deliver the IPv4 packet to the IP module again so that it*/
		/* will be routed appropriately.							*/
		op_pk_deliver_delayed (ipv4_pkptr, iprmd_ptr->module_id, instrm, encapsulation_delay);
		}
	
	/* In an end-device, packets are being pushed on a tunnel interface */
	/* using default routes (tunnel interface's end is the next hop).	*/
	/* If we deliver the packet back to the IP module, then the packet	*/
	/* will be pushed out on the tunnel interface again, in a recursive	*/
	/* fashion. This condition is trapped by some code in this function	*/
	/* itself. But to avoid dropping the packet, we must send it out on	*/
	/* phys intf strm, the only stream on which a physical interface is	*/
	/* present.															*/		
	else
		{
		op_pk_send_delayed (ipv4_pkptr,
			tunnel_intf_ptr->tunnel_info_ptr->source_intf_ptr->phys_intf_info_ptr->port_num , 
			encapsulation_delay);
		}

	FOUT;
	}

static Compcode
ip_rte_ipv6_manual_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, IpT_Interface_Info* tunnel_intf_ptr)
	{
	/** Fill in the appropriate fields of an IPv4 packet used	**/
	/** to tunnel an IPv6 datagram through an IPv4 network.		**/
	
	FIN (ip_rte_ipv6_manual_tunnel_pkt_fields_set (pkt_fields_ptr, tunnel_intf_ptr));

	/* Encapsulate the IPv6 packet in an IPv4 packet with the	*/
	/* following fields.										*/
	/* Destination address: Destination address of the tunnel.	*/
	/* Source Address: Address of the source interface.			*/
	pkt_fields_ptr->dest_addr	= inet_address_copy (tunnel_intf_ptr->tunnel_info_ptr->dest_addr);

	FRET (OPC_COMPCODE_SUCCESS);
	}

static Compcode
ip_rte_ipv6_auto_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, InetT_Address dest_addr,
	IpT_Interface_Info* PRG_ARG_UNUSED (tunnel_intf_ptr))
	{
	/** Fill in the appropriate fields of an IPv4 packet used	**/
	/** to tunnel an IPv6 datagram through an IPv4 network.		**/

	FIN (ip_rte_ipv6_auto_tunnel_pkt_fields_set (pkt_fields_ptr, dest_addr, tunnel_intf_ptr));

	/* Encapsulate the IPv6 packet in an IPv4 packet with the	*/
	/* fields set as follows.									*/
	/* Destination address: IPv4 address from the IPv4		 	*/
	/* 						compatible destination address.		*/
	/* Source address: IPv4 address of the source interface of	*/
	/*                 of the tunnel.							*/
	pkt_fields_ptr->dest_addr	= inet_ipv4_addr_from_ipv4_compat_addr_get (&dest_addr);

	FRET (OPC_COMPCODE_SUCCESS);
	}

static Compcode
ip_rte_ipv6_6to4_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, InetT_Address dest_addr,
   	IpT_Interface_Info* PRG_ARG_UNUSED (tunnel_intf_ptr))
	{
	/** Fill in the appropriate fields of an IPv4 packet used	**/
	/** to tunnel an IPv6 datagram through an IPv4 network.		**/

	FIN (ip_rte_ipv6_6to4_tunnel_pkt_fields_set (pkt_fields_ptr, tunnel_intf_ptr));

	/* Encapsulate the IPv6 packet in an IPv4 packet with the	*/
	/* fields set as follows.									*/
	/* Destination address: IPv4 address from the 6to4		 	*/
	/* 						compatible destination address.		*/
	/* Source address: IPv4 address of the source interface of	*/
	/*                 of the tunnel.							*/

	/* First make sure that the destination address is a valid	*/
	/* 6to4 address. In misconfigured networks, it is possible	*/
	/* even other packets might get sent out a tunnel interface	*/
	/* e.g. if RIPng is enabled on a 6to4 tunnel interface.		*/
	if (inet_address_is_6to4 (&dest_addr))
		{
		pkt_fields_ptr->dest_addr	= inet_ipv4_addr_from_6to4_addr_get (&dest_addr);

		/* Return success.										*/
		FRET (OPC_COMPCODE_SUCCESS);
		}
	else
		{
		/* IPv6: need a log message.							*/
		op_prg_odb_print_major ("Attempting to send packet to a non-6to4 destination",
			"through a 6to4 tunnel. Make sure RIPng is not enabled on this interface.",
			OPC_NIL);

		/* Return failure.										*/
		FRET (OPC_COMPCODE_FAILURE);
		}
	}

static Compcode
ip_rte_tunnel_pkt_fields_set (IpT_Dgram_Fields* pkt_fields_ptr, IpT_Interface_Info* tunnel_intf_ptr)
	{
	/** Fill in the tunnel source and destination addresses	**/
	/** into the IPv4 packet header. 						**/
	
	FIN (ip_rte_gre_tunnel_pkt_fields_set (pkt_fields_ptr, tunnel_intf_ptr, gre_pptr));
	
	pkt_fields_ptr->dest_addr	= tunnel_intf_ptr->tunnel_info_ptr->dest_addr;
	
	FRET (OPC_COMPCODE_SUCCESS);
	}

static Packet*
ip_rte_tunnel_gre_pkt_create (Packet* tunneled_pkptr)
	{
	/** Encapsulate the packet to be tunneled inside a GRE packet.	**/
 
	Packet* 			gre_pkptr 	= OPC_NIL;
	
	FIN (ip_rte_tunnel_gre_pkt_create (tunneled_pkptr));
	
	gre_pkptr = op_pk_create_fmt ("ip_gre");
	op_pk_nfd_set (gre_pkptr, "payload", tunneled_pkptr);
	op_pk_nfd_set (gre_pkptr, "hdr_fields", OPC_NIL, op_prg_mem_copy_create, 
		op_prg_mem_free, sizeof (IpT_Tunnel_GRE_Hdr_Fields));
	
	FRET (gre_pkptr);
	}

static void
ip_rte_load_balancer_handle_packet (IpT_Rte_Module_Data* module_data, Packet **pkptr)
	{
	/* Take the packet, determine which server is appropriate   */
	/* for serving the request, and perform NAT on that packet. */
	/* It can then be sent out to that server.                  */
	FIN (ip_rte_load_balancer_handle_packet (module_data, pkptr));
	
	/* Pass the packet to gna_load_balancer process through the */
	/* parent child memory installed during the child process   */
	/* creation.                                                */
	module_data->ip_ptc_mem.child_pkptr = *pkptr;
	
	/* Invoke the child process to handle the packet.           */
	op_pro_invoke (module_data->load_balancer_process_handle, OPC_NIL);
	
	/* Take back the packet so that it can be forwarded.        */
	*pkptr = module_data->ip_ptc_mem.child_pkptr;
	
	FOUT;
	}
		
static Boolean
ip_rte_load_balancer_packet_mine (const InetT_Address dest_address, IpT_Rte_Module_Data* iprmd_ptr,
									int* table_index_ptr)
	{
	int                   	i;
	IpT_Interface_Info*   	phys_iface_info_ptr;
	int						num_intfs;

	/* Return true if the address is one of the addresses for this node. */
	FIN (ip_rte_load_balancer_packet_mine (dest_address, iprmd_ptr, table_index_ptr));
	
	num_intfs = ip_rte_num_interfaces_get (iprmd_ptr);

	for (i = 0; i < num_intfs; i++)
		{
		phys_iface_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);
		
		/* Check if the ip address matches.					*/
		if (inet_address_range_address_equal (inet_rte_v4intf_addr_range_get (phys_iface_info_ptr), &dest_address))
			{
			*table_index_ptr = i;
			FRET (OPC_TRUE);
			}
		}
	/* We did not find a even after looping through all the		*/
	/* physical and subinterfaces. return false					*/
	FRET (OPC_FALSE);
	}

static void
ip_rte_load_balancer_log ()
	{
	static Log_Handle        log_hndl;
	static Boolean           handle_created = OPC_FALSE;
	
	/* Write a message to the sim log indicating that the load balancer */
	/* dropped a packet.                                                */
	FIN (ip_rte_load_balancer_log ());
	
	if (handle_created == OPC_FALSE)
		{
		log_hndl = op_prg_log_handle_create (OpC_Log_Category_Protocol, "IP",
			"Packet Drop", 25);
		
		handle_created = OPC_TRUE;
		}
	
	op_prg_log_entry_write (log_hndl, 
		"BEHAVIOR:\n"
		"The load balancer node has discarded an IP datagram.\n"
		"\n"
		"CAUSE:\n"
		"1. The load balancer had previously established a connection\n"
		"between a specific client and server.  Before the conversation\n"
		"completed, the server failed.\n"
		"2. The load balancer has not been configured to intercept packets\n"
		"and one or more clients is sending application traffic to the load\n"
		"balancer.\n"
		"3. The load balancer has been configured to consider servers\n"
		"which do not exist in the network.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Verify that the Load Balancer Configuration attribute is not\n"
		"sent to None."
		"2. Verify the Load Balancer Configuration attribute on the\n"
		"load balancer contains valid server names.\n");

	FOUT;
	}

Compcode    
inet_rte_addr_local_network_core (InetT_Address ip_addr, IpT_Rte_Module_Data* iprmd_ptr,
    IpT_Port_Info* port_info_ptr, InetT_Address_Range** addr_range_pptr)
	{
	int						i;
	int						start_index, end_index;
	IpT_Interface_Info*		ith_intf_ptr;
	InetT_Addr_Family		addr_family;
	InetT_Address_Range*	temp_addr_range_ptr;

	/** This functions checks whether the specified address	**/
	/** belongs to one of the directly connected networks of**/
	/** a router. If it is, the requested return values are	**/
	/** filled in. If any of the values is not required, the**/
	/** corresponding argument may be passed in as OPC_NIL	**/

	FIN (inet_rte_addr_local_network_core (ip_addr, iprmd_ptr, interface_pptr...));

	/* Find out the version of Address.						*/
	addr_family = inet_address_family_get (&ip_addr);

	/* If the addr_range_pptr argument is not used, use the	*/
	/* address of the local variable instead.				*/
	if (OPC_NIL == addr_range_pptr)
		{
		addr_range_pptr = &temp_addr_range_ptr;
		}

	switch (addr_family)
		{
		case InetC_Addr_Family_v4:
			/* Get the indices of the first and the last IPv4 		*/
			/* interfaces											*/
			start_index = inet_first_ipv4_intf_index_get (iprmd_ptr);
			end_index = inet_last_ipv4_intf_index_get (iprmd_ptr);

			/* loop through each of the interfaces and check whether*/
			/* the address belongs to the connected network			*/
			for (i = start_index; i <= end_index; i++)
				{
				ith_intf_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

				/* Check whether the specified address belongs to	*/
				/* the network connected to this interface.			*/
				if (inet_rte_v4intf_addr_range_check (ip_addr, ith_intf_ptr, addr_range_pptr))
					{
					/* We have found the correct interface. Fill in	*/
					/* the requested return values.					*/
					*port_info_ptr = ip_rte_port_info_create (i, ith_intf_ptr->full_name);

					/* Return success.								*/
					FRET (OPC_COMPCODE_SUCCESS);
					}
				}
			/* If we are here that means that a matching interface 	*/
			/* was not found. Return failure.						*/

			/* If the port_info was requested, set it to INVALID index */
			*port_info_ptr = ip_rte_port_info_create (IPC_INTF_INDEX_INVALID, OPC_NIL);

			FRET (OPC_COMPCODE_FAILURE);
			
		case InetC_Addr_Family_v6:
			/* Get the indices of the first and the last IPv6 		*/
			/* interfaces											*/
			start_index = inet_first_ipv6_intf_index_get (iprmd_ptr);
			end_index = inet_last_ipv6_intf_index_get (iprmd_ptr);

			/* Check if the address is a link local address.		*/
			/* All link local addresses will have the same prefix.	*/
			/* We need to ensure that we return the right interface	*/
			/* if the link local address belongs to one of the local*/
			/* interfaces.											*/
			if (inet_rte_ipv6_addr_is_link_local (ip_addr))
				{
				/* Loop through each interface and check if this	*/
				/* address is the link local address of the 		*/
				/* interface.										*/
				for (i = start_index; i <= end_index; i++)
					{
					ith_intf_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

					if (ip_rte_intf_link_local_addr_equal (ith_intf_ptr, ip_addr))
						{
						/* The given address is the link local 		*/
						/* address of this interface. Fill in the	*/
						/* return values.							*/
						*port_info_ptr = ip_rte_port_info_create (i, ith_intf_ptr->full_name);
						*addr_range_pptr = ip_rte_intf_link_local_addr_range_get_fast (ith_intf_ptr);

						/* Return Success.							*/
						FRET (OPC_COMPCODE_SUCCESS);
						}
					}
				}
			else
				{
				/* This is not a link local address.				*/

				/* Loop through each of the interfaces and check if	*/
				/* the address belongs to the connected network		*/
				for (i = start_index; i <= end_index; i++)
					{
					ith_intf_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

					/* Check whether the specified address belongs	*/
					/* to the network connected to this interface.	*/
					if (inet_rte_v6intf_addr_range_check (ip_addr, ith_intf_ptr, addr_range_pptr))
						{
						/* We have found the correct interface. Fill*/
						/* in the requested return values.			*/
						*port_info_ptr = ip_rte_port_info_create (i, ith_intf_ptr->full_name);

						/* Return success.							*/
						FRET (OPC_COMPCODE_SUCCESS);
						}
					}
				}

			/* If we are here that means that a matching interface 	*/
			/* was not found. Return failure.						*/

			/* If the port_info was requested, set it to UNDEF.		*/
			*port_info_ptr = ip_rte_port_info_create (IPC_INTF_INDEX_INVALID, OPC_NIL);

			FRET (OPC_COMPCODE_FAILURE);
	
		default:
			/* Invalid Address family. Return failure.				*/
			FRET (OPC_COMPCODE_FAILURE);
		}
	}

Boolean
ip_rte_dest_local_network (IpT_Address ip_addr, IpT_Rte_Module_Data* iprmd_ptr,
    int* intf_index_ptr)
	{
	int						i, j;
	int						num_interfaces;
	IpT_Interface_Info*		ith_intf_ptr;
	IpT_Address_Range*		secondary_addr_range_ptr = OPC_NIL;
	Boolean					is_local_network = OPC_FALSE;
	
	/** This functions checks whether the specified address	**/
	/** belongs to one of the directly connected networks of**/
	/** a router. If it is, the intf_index is set.			**/

	FIN (ip_rte_dest_local_network (ip_addr, interface_lptr, intf_index_ptr));

	/* Find out the number of interfaces.					*/
	num_interfaces = ip_rte_num_interfaces_get (iprmd_ptr);

	/* loop through each of the interfaces and check whether*/
	/* the address belongs to the connected network			*/
	for (i = 0; i < num_interfaces; i++)
		{
		ith_intf_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);

		/* Check whether the specified address belongs to	*/
		/* the network connected to this interface.			*/
		if (ip_address_range_check (ip_addr, ip_rte_intf_addr_range_get (ith_intf_ptr)))
			{
			is_local_network = OPC_TRUE;
			}
		else
			{
			/* Check if the destination address is in one	*/
			/* of the secondary address networks.			*/
			for (j = 0; j < ip_rte_intf_num_secondary_addresses_get (ith_intf_ptr); j ++)
				{
				secondary_addr_range_ptr = 
					ip_rte_intf_secondary_addr_range_get (ith_intf_ptr, j);
			
				if (ip_address_range_check (ip_addr, secondary_addr_range_ptr))
					{
					is_local_network = OPC_TRUE;
					break;
					}
				}
			}

		if (is_local_network)
			{
			/* We have found the correct interface.			*/
			if (intf_index_ptr)
				*intf_index_ptr = i;

			/* Return true.									*/
			FRET (OPC_TRUE);
			}
		}
	
	/* If we are here that means that a matching interface 	*/
	/* was not found. Return failure.						*/
	*intf_index_ptr = IPC_INTF_INDEX_INVALID;

	FRET (OPC_FALSE);
	}
	
Boolean		
ip_rte_is_local_address (const IpT_Address ip_addr, IpT_Rte_Module_Data* iprmd_ptr,
	IpT_Interface_Info** interface_pptr, int* intf_index_ptr)
	{
	int						i;
	int						num_interfaces;
	IpT_Interface_Info*		ith_intf_ptr;

	/** This functions checks whether the specified address	**/
	/** belongs to one of the interfaces of this node.		**/

	FIN (ip_rte_is_local_address (ip_addr, iprmd_ptr, interface_pptr...));

	/* Find out the number of interfaces.					*/
	num_interfaces = ip_rte_num_interfaces_get (iprmd_ptr);

	/* loop through each of the interfaces and check whether*/
	/* the address belongs to the interface					*/
	for (i = 0; i < num_interfaces; i++)
		{
		ith_intf_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);

		if (ip_rte_intf_has_local_address (ip_addr, ith_intf_ptr))
			{
			/* We have found the correct interface. Fill in	*/
			/* the requested return values only if the		*/
			/* caller really requested them					*/
			if (interface_pptr != OPC_NIL)				
				{
				*interface_pptr = ith_intf_ptr;
				}
			if (intf_index_ptr != OPC_NIL)
				{
				*intf_index_ptr = i;
				}

			/* Return true.									*/
			FRET (OPC_TRUE);
			}
		}
	/* If we are here that means that a matching interface 	*/
	/* was not found. Return false.							*/
	FRET (OPC_FALSE);
	}

IpT_Interface_Info*
ip_rte_first_loopback_intf_info_get (IpT_Rte_Module_Data* iprmd_ptr)
	{
	IpT_Interface_Info*			loopback_intf_info;

	/** This function returns the interface info structureof**/
	/** the first loopback interface of a router.			**/
	FIN (ip_rte_first_loopback_intf_info_get (iprmd_ptr));

	if (iprmd_ptr->first_loopback_intf_index == IPC_INTF_INDEX_INVALID)
		FRET (OPC_NIL);
	
	loopback_intf_info = inet_rte_intf_tbl_access 
		(iprmd_ptr, iprmd_ptr->first_loopback_intf_index);

	FRET (loopback_intf_info);
	}

IpT_Interface_Info*
ipv6_rte_first_loopback_intf_info_get (IpT_Rte_Module_Data* iprmd_ptr)
	{
	IpT_Interface_Info*			loopback_intf_info;

	/** This function returns the interface info structureof**/
	/** the first loopback interface of a router.			**/
	FIN (ipv6_rte_first_loopback_intf_info_get (iprmd_ptr));

	if (iprmd_ptr->first_ipv6_loopback_intf_index == IPC_INTF_INDEX_INVALID)
		FRET (OPC_NIL);
	
	loopback_intf_info = inet_rte_intf_tbl_access 
		(iprmd_ptr, iprmd_ptr->first_ipv6_loopback_intf_index);

	FRET (loopback_intf_info);
	}

InetT_Address
inet_rte_first_loopback_intf_addr_get (IpT_Rte_Module_Data* ip_module_data_ptr, InetT_Addr_Family addr_family)
	{
	IpT_Interface_Info*		ip_iface_elem_ptr;
	InetT_Address			ip_address;

	/** Returns the address of the first interface of the specified	**/
	/** address family.												**/

	FIN (inet_rte_first_loopback_intf_addr_get (ip_module_data_ptr, addr_family));

	/* Get the interface index based on the address family.			*/
	switch (addr_family)
		{
		case InetC_Addr_Family_v4:
			/* Get a pointer to the first IPv4 loopback		*/
			/* interface.									*/
			ip_iface_elem_ptr = ip_rte_first_loopback_intf_info_get (ip_module_data_ptr);
			if (OPC_NIL == ip_iface_elem_ptr)
				{
				/* Error: This node does not have an IPv4	*/
				/* address. Return INETC_ADDRESS_INVALID	*/
				ip_address = INETC_ADDRESS_INVALID;
				}
			else
				{
				/* Return the IPv4 address of the interface	*/
				ip_address = inet_rte_v4intf_addr_get (ip_iface_elem_ptr);
				}
			break;
		case InetC_Addr_Family_v6:
			/* Get a pointer to the first IPv6 loopback		*/
			/* interface.									*/
			ip_iface_elem_ptr = ipv6_rte_first_loopback_intf_info_get (ip_module_data_ptr);
			if (OPC_NIL == ip_iface_elem_ptr)
				{
				/* Error: This node does not have an IPv6	*/
				/* address. Return INETC_ADDRESS_INVALID	*/
				ip_address = INETC_ADDRESS_INVALID;
				}
			else
				{
				/* Return the IPv6 address of the interface	*/
				ip_address = ip_rte_intf_ith_gbl_ipv6_addr_get (ip_iface_elem_ptr, 0);
				}
			break;
		default:
			/* Invalid address family. Return invalid address.		*/
			ip_address = INETC_ADDRESS_INVALID;
			break;
		}

	/* Return the address 									*/
	FRET (ip_address);
	}

IpT_Address
ip_rte_first_loopback_intf_addr_get (IpT_Rte_Module_Data* ip_module_data_ptr)
	{
	IpT_Interface_Info*		ip_iface_elem_ptr;
	IpT_Address				ip_address;

	/** Returns the address of the first interface of the specified	**/
	/** address family.												**/

	FIN (ip_rte_first_loopback_intf_addr_get (iprmd_ptr));

	/* Get a pointer to the first IPv4 loopback		*/
	/* interface.									*/
	ip_iface_elem_ptr = ip_rte_first_loopback_intf_info_get (ip_module_data_ptr);
	if (OPC_NIL == ip_iface_elem_ptr)
		{
		/* Error: This node does not have an IPv4	*/
		/* address. Return IPC_ADDR_INVALID			*/
		ip_address = IPC_ADDR_INVALID;
		}
	else
		{
		/* Return the IPv4 address of the interface	*/
		ip_address = ip_rte_intf_addr_get (ip_iface_elem_ptr);
		}

	/* Return the address 									*/
	FRET (ip_address);
	}

InetT_Address
inet_rte_intf_addr_get (IpT_Interface_Info* intf_ptr, InetT_Addr_Family addr_family)
	{
	InetT_Address			ip_address;

	/** Returns the address of the first interface of the specified	**/
	/** address family.												**/

	FIN (inet_rte_intf_addr_get (intf_ptr, addr_family));

	/* Get the interface index based on the address family.			*/
	switch (addr_family)
		{
		case InetC_Addr_Family_v4:
			/* Return the IPv4 address of the interface.			*/
			ip_address = inet_rte_v4intf_addr_get (intf_ptr);
			break;
		case InetC_Addr_Family_v6:
			/* Return the first global address.						*/
			if (ip_rte_intf_num_ipv6_gbl_addrs_get (intf_ptr) > 0)
				{
				ip_address = ip_rte_intf_ith_gbl_ipv6_addr_get (intf_ptr, 0);
				}
			else
				{
				/* This interface does not have a global IPv6 		*/
				/* address. Return an invalid address.				*/
				ip_address = INETC_ADDRESS_INVALID;
				}
			break;
		default:
			/* Invalid address family. Return invalid address.		*/
			ip_address = INETC_ADDRESS_INVALID;
			break;
		}

	/* Return the address 									*/
	FRET (ip_address);
	}

Boolean		
inet_rte_is_local_intf_name (char* intf_name, IpT_Rte_Module_Data* iprmd_ptr, int* intf_index_ptr,
	IpT_Interface_Info **intf_info_pptr, InetT_Addr_Family addr_family)
	{
	int					i, start_index, end_index;
	IpT_Interface_Info*	intf_info_ptr;

	/** This function checks if this router has an interface 	**/
	/** with the specified name.								**/

	FIN (inet_rte_is_local_intf_name (intf_name, intf_lptr, intf_index_ptr....));

	/* Set the starting and ending interface indices that we are*/
	/* going ot search based on the address family.				*/
	switch (addr_family)
		{
		case InetC_Addr_Family_v4:
			/* IPv4 interfaces only.							*/
			start_index = inet_first_ipv4_intf_index_get (iprmd_ptr);
			end_index = inet_last_ipv4_intf_index_get (iprmd_ptr);
			break;
		case InetC_Addr_Family_v6:
			/* IPv6 interfaces only.							*/
			start_index = inet_first_ipv6_intf_index_get (iprmd_ptr);
			end_index = inet_last_ipv6_intf_index_get (iprmd_ptr);
			break;
		case InetC_Addr_Family_Unknown:
			/* All interfaces.									*/
			start_index = 0;
			end_index = inet_rte_num_interfaces_get (iprmd_ptr) - 1;
			break;
		default:
			/* Invalid address family. Return false.			*/
			FRET (OPC_FALSE);
		}

	/* Loop through the list of interfaces and look for one with*/
	/* the specified name.										*/
	for (i = start_index; i <= end_index; i++)
		{
		/* Get a pointer to the interface info of this intf		*/
		intf_info_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

		/* Check if its name matches the specified intf name	*/
		if (strcmp (intf_name, ip_rte_intf_name_get (intf_info_ptr)) == 0)
			{
			/* We have found the correct interface				*/
			
			/* Fill in the return values.						*/
			if (OPC_NIL != intf_index_ptr)
				{
				*intf_index_ptr = i;
				}

			if (OPC_NIL != intf_info_pptr)
				{
				*intf_info_pptr = intf_info_ptr;
				}

			/* Return true.										*/
			FRET (OPC_TRUE);
			}
		}

	FRET (OPC_FALSE);
	}		   
		

static Boolean 
ip_rte_subintf_layer2_mapping_found (const char* mapping_name, IpT_Layer2_Mapping mapping_type, IpT_Layer2_Mappings layer2_map)
	{
	int			vc_index; 
	
	/* Returns TRUE, if there is at least one (IP destination address, vc_name)  */
	/* entry in the given layer2_map of a multi-point interface, such that the   */
	/* vc_name is the same as mapping_name. 									 */
	FIN (ip_rte_subintf_layer2_mapping_found (mapping_name, mapping_type, layer2_map)); 
	
	if (mapping_type == IpC_Layer2_Mapping_ATM_PVC)
		{
		/* Nothing to search for, if there are no ATM VCs */
		if (layer2_map.num_atm_pvcs == 0)
			FRET (OPC_FALSE); 

		for (vc_index = 0; vc_index < layer2_map.num_atm_pvcs; vc_index ++)
			{
			/* In case the name of the vc has been set as 'None' ...*/
			if (layer2_map.atm_pvc_set [vc_index].vc_name == OPC_NIL)
				continue; 
			
			if (strcmp (layer2_map.atm_pvc_set [vc_index].vc_name, mapping_name) == 0)
				break;
			}
	
		if (vc_index < layer2_map.num_atm_pvcs)
			{
			FRET (OPC_TRUE);
			}
		}
	else if (mapping_type == IpC_Layer2_Mapping_FR_PVC)
		{
		/* Nothing to search for, if there are no FR VCs */
		if (layer2_map.num_fr_pvcs == 0)
			FRET (OPC_FALSE); 
		
		for (vc_index = 0; vc_index < layer2_map.num_fr_pvcs; vc_index ++)
			{
			/* In case the name of the VC has been set as 'None' ... */
			if (layer2_map.fr_pvc_set [vc_index].vc_name == OPC_NIL)
				continue; 
			
			if (strcmp (layer2_map.fr_pvc_set [vc_index].vc_name, mapping_name) == 0)
				break;
			}
		
		if (vc_index < layer2_map.num_fr_pvcs)
			{
			FRET (OPC_TRUE);
			}
		}
	
	FRET (OPC_FALSE); 
	}

Boolean	
ip_rte_subintf_from_layer2_mapping_get (const char* mapping_name, IpT_Layer2_Mapping mapping_type, 
	IpT_Rte_Module_Data* iprmd_ptr, int* intf_tbl_index_ptr, IpT_Address* subintf_addr_ptr, 
	IpT_Address* subintf_net_addr_ptr)
	{
	int					i;
	int					num_interfaces;
	IpT_Interface_Info	*intf_info_ptr;
	Boolean				mapping_found = OPC_FALSE;

	/** This functions loops through the subinterfaces in		**/
	/** intf_lptr and looks for any that are connected to the	**/
	/** PVC named pvc_name.										**/

	FIN (ip_rte_subintf_from_layer2_mapping_get (pvc_name, iprmd_ptr, subintf_ptr, subintf_addr_ptr, subintf_net_addr_ptr));

	/* Find out the number of interfaces on this router.		*/
	num_interfaces = ip_rte_num_interfaces_get (iprmd_ptr);

	/* Loop through all the physical interfaces.				*/
	for (i = 0; i < num_interfaces; i++)
		{
		/* get a pointer to the interface info of this intf		*/
		intf_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);

		/* Check what kind of layer2 info is being queried	*/
		mapping_found = ip_rte_subintf_layer2_mapping_found (mapping_name, mapping_type, 
			intf_info_ptr->layer2_mappings); 
		
		/* Check if the PVC is connected to this subinterface	*/
		if (mapping_found)
			{
			/* We have found the right interface		*/
			/* Fill in the return values.				*/
			if (OPC_NIL != intf_tbl_index_ptr)
				{
				*intf_tbl_index_ptr = i;
				}
			if (OPC_NIL != subintf_addr_ptr)
				{
				*subintf_addr_ptr = ip_address_copy (intf_info_ptr->addr_range_ptr->address);
				}
			if (OPC_NIL != subintf_net_addr_ptr)
				{
				*subintf_net_addr_ptr = ip_address_copy (intf_info_ptr->network_address);
				}
				
			/* Return true to indicate that a match was found*/
			FRET (OPC_TRUE);
			}
		}
	/* If we reached here, we did not find a matching interface	*/
	/* return false												*/
	FRET (OPC_FALSE);
	}


Boolean
ip_rte_interfaces_on_same_phys_intf (IpT_Rte_Module_Data* iprmd_ptr, int table_index, int phys_intf_table_index)
	{
	int		num_subinterfaces;
	
	/** This function checks whether the interface specified	**/
	/** by table_index is a subinterface (or the actual			**/
	/** physical interface) on the physical interface specified	**/
	/** by phys_intf_table_index.								**/
	
	FIN (ip_rte_interfaces_on_same_phys_intf (iprmd_ptr, table_index, phys_intf_table_index));
	
	/* First check if the table_index is the same as			*/
	/* phys_intf_table_index.  This would mean that they are 	*/
	/* the same physical interfae.								*/
	if (table_index == phys_intf_table_index)
		{
		FRET (OPC_TRUE);
		}
	
	/* Now check if the table_index is a subinterface on the	*/
	/* interface specified by phys_intf_table_index.			*/
	num_subinterfaces = ip_rte_num_subinterfaces_get (ip_rte_intf_tbl_access (iprmd_ptr, phys_intf_table_index));
	if ((table_index > phys_intf_table_index) && (table_index <= (phys_intf_table_index + num_subinterfaces)))
		{
		FRET (OPC_TRUE);
		}
	
	/* The interface specified by table_index was not an		*/
	/* interface on the same physical interface specified by	*/
	/* phys_intf_table_index.									*/
	FRET (OPC_FALSE);
	}

static char*
ip_vpn_packet_classify (IpT_Rte_Module_Data* iprmd_ptr, Packet* pkt_ptr, int in_iface)
	{
	char*						vrf_name 		= OPC_NIL;
	char						in_interface_str [256];
	
	int							out_interface 	= OPC_INT_INVALID;
	IpT_Vrf_Table*				vrf_rte_table 	= OPC_NIL;
	IpT_Address					next_hop_addr;
	MplsT_Label					bottom_label;
	MplsT_Label					top_label;
	IpT_Dgram_Fields*			pk_fd_ptr 			= OPC_NIL;
	
	/* This function finds the corresponding VRF for		*/
	/* this incoming packet									*/
	FIN (ip_vpn_packet_classify (Packet* pkt_ptr));
	
	/* Check if the VRF hash table exist					*/
	if (iprmd_ptr->vrf_names_hash_table_ptr != OPC_NIL)
		{
		/* Copy the in_interface 							*/
		sprintf (in_interface_str, "%d", in_iface);
		
		/* Get the name of the VRF from hash table 			*/
		/* depending on	the in interface					*/
		vrf_name = (char*) prg_string_hash_table_item_get (iprmd_ptr->vrf_names_hash_table_ptr, 
															in_interface_str);
		
		if (iprmd_ptr->vrfs_hash_table_ptr != OPC_NIL)
			{
			/* Get the VRf table from the hash table						*/
			vrf_rte_table = (IpT_Vrf_Table*) prg_string_hash_table_item_get (iprmd_ptr->vrfs_hash_table_ptr, vrf_name);
			
			/* If we do not find any VRF table then return NIL	*/
			if (vrf_rte_table == OPC_NIL)
				FRET (OPC_NIL);
			
			/* Get the IP fields of the incoming packet 		*/
			op_pk_nfd_access (pkt_ptr, "fields", &pk_fd_ptr);
			
			/* Get the out interface infor mation from the VRF table	*/
			out_interface = ip_vrf_table_next_hop_info_get (vrf_rte_table,
				inet_ipv4_address_get (pk_fd_ptr->dest_addr), &next_hop_addr,
				&bottom_label, &top_label);
		
			/* If VRF table know how to route this packet		*/
			/* then send VRF name else send OPC_NIL				*/
			if ((out_interface != OPC_INT_INVALID) &&
				(out_interface != IPC_INTF_TBL_INDEX_NULL0) &&
				(out_interface != IPC_INTF_INDEX_INVALID))
				{
				FRET (vrf_name);
				}
			}
		}
			
	FRET (OPC_NIL);
	}

static int
ip_rte_minor_port_from_next_hop_get (IpT_Rte_Module_Data* iprmd_ptr, 
	int phys_intf_index, InetT_Address next_hop)
	{
	IpT_Interface_Info	*phys_intf_ptr, *ith_subintf_ptr;
	int					i, num_subinterfaces;
	
	/** A packet was received on a slip interface. Since no	**/
	/** icis are associated with such packets, we need to	**/
	/** look at the next hop address of the packet to figure**/
	/** out the subinterface on which it was received. 		**/
	/** Loop through all the subinterfaces of the physical	**/
	/** interface and look for a subinterface that shares	**/
	/** a common IP subnet as the specified next hop address**/

	FIN (ip_rte_minor_port_from_next_hop_get (iprmd_ptr, phys_intf_index, next_hop));

	/* Get a pointer to the interface info of the physical	*/
	/* interface.											*/
	phys_intf_ptr = ip_rte_intf_tbl_access (iprmd_ptr, phys_intf_index);

	/* Get the number of subinterfaces.						*/
	num_subinterfaces = ip_rte_num_subinterfaces_get (phys_intf_ptr);

	for (i = IPC_SUBINTF_PHYS_INTF; i < num_subinterfaces; i++)
		{
		ith_subintf_ptr = ip_rte_ith_subintf_info_get (phys_intf_ptr, i);

		if (inet_rte_intf_addr_range_check (ith_subintf_ptr, next_hop))
			{
			/* We have found the correct subinterface		*/
			FRET (i);
			}
		}

	/* We did not find a matching subinterface				*/
	FRET (IPC_SUBINTF_INDEX_INVALID);
	}

Boolean
inet_rte_intf_addr_range_check (IpT_Interface_Info* intf_ptr, InetT_Address next_hop)
	{
	Boolean						ret_value;
	int							i;

	/** This function checks whether the given address		**/
	/** falls in the same IP subnet as one of the addresses	**/
	/** of this interface.									**/
	
	FIN (inet_rte_intf_addr_range_check (intf_ptr, next_hop));

	/* If the IP version of the address is not enabled on 	*/
	/* the interface at all, return false.					*/
	if (! ip_rte_intf_ip_version_active (intf_ptr, inet_address_family_get (&next_hop)))
		{
		FRET (OPC_FALSE);
		}

	/* Determine the address family of the given address.	*/
	switch (inet_address_family_get (&next_hop))
		{
		case InetC_Addr_Family_v4:
			/* Check whether the address falls in the same 	*/
			/* IP subnet as the IPv4 address of this intf.	*/
			ret_value = inet_rte_v4intf_addr_range_check (next_hop, intf_ptr, OPC_NIL);
			FRET (ret_value);
		case InetC_Addr_Family_v6:
			/* Check whether the address falls in the same	*/
			/* IP subnet as any of the IPv6 addresses.		*/
			for (i = 0; i < ip_rte_intf_num_ipv6_addrs_get (intf_ptr); i++)
				{
				/* Check whether the given address falls in	*/
				/* the same IP subnet as the ith IPv6 address*/
				if (inet_address_range_check (next_hop, ip_rte_intf_ith_ipv6_addr_range_get_fast (intf_ptr, i)))
					{
					/* It was a match. Return true.			*/
					FRET (OPC_TRUE);
					}
				}
			/* We did not find a matching IP address.		*/
			/* Return false.								*/
			FRET (OPC_FALSE);
		default:
			/* Invalid address. Just return false.			*/
			FRET (OPC_FALSE);
		}

	/* Dummy return call to avoid compiler warnings.		*/
	FRET (OPC_FALSE);
	}

Boolean
inet_rte_is_local_address(const InetT_Address intf_addr, IpT_Rte_Module_Data* iprmd_ptr,
	int* intf_index_ptr)
	{
	Boolean				ret_value;
	IpT_Interface_Info*	intf_ptr;

	/** This function checks whether the given address		**/
	/** belongs to any of the interfaces of this node.		**/
	
	FIN (inet_rte_is_local_address (intf_addr, iprmd_ptr, intf_index_ptr));

	/* If the IP version of the address is not enabled on 	*/
	/* the node at all, return false.						*/
	if (! ip_rte_node_ip_version_active (iprmd_ptr, inet_address_family_get (&intf_addr)))
		{
		FRET (OPC_FALSE);
		}

	/* Determine the address family of the given address.	*/
	switch (inet_address_family_get (&intf_addr))
		{
		case InetC_Addr_Family_v4:
			/* Check if this node has a matching IPv4 address*/
			ret_value = ip_rte_is_local_address (inet_ipv4_address_get (intf_addr),
				iprmd_ptr, &intf_ptr, intf_index_ptr);
			FRET (ret_value);
		case InetC_Addr_Family_v6:
			/* Check if this node has a matching IPv6 address*/
			ret_value = ipv6_rte_is_local_address (intf_addr, iprmd_ptr, intf_index_ptr);
			FRET (ret_value);
		default:
			/* Invalid address. Just return false.			*/
			FRET (OPC_FALSE);
		}
	}

static Boolean
ipv6_rte_is_local_address(const InetT_Address intf_addr, IpT_Rte_Module_Data* iprmd_ptr,
	int* intf_index_ptr)
	{
	int					ith_intf, num_interfaces;
	IpT_Interface_Info*	intf_ptr;

	/** Check whether the given IPv6 address belongs to this**/
	/** node.												**/

	FIN (ipv6_rte_is_local_address (intf_addr, iprmd_ptr, intf_index_ptr));

	/* Find out the number of IPv6 addresses of this node.	*/
	num_interfaces = ipv6_rte_num_interfaces_get (iprmd_ptr);

	/* Loop through the list of interfaces and look for		*/
	/* one with the specified address.						*/
	for (ith_intf = 0; ith_intf < num_interfaces; ith_intf++)
		{
		/* Access the ith interface.						*/
		intf_ptr = ipv6_rte_intf_tbl_access (iprmd_ptr, ith_intf);
		
		if (ipv6_rte_intf_has_local_address (intf_addr, intf_ptr))
			{
			/* We have found a match.					*/
			/* Store the interface index.				*/
			*intf_index_ptr = ith_intf;
			
			/* Return true.								*/
			FRET (OPC_TRUE);
			}
		}
	/* We did not find a match. Return false.				*/
	FRET (OPC_FALSE);
	}
		
static Boolean
inet_rte_v6intf_addr_range_check (InetT_Address next_hop, IpT_Interface_Info* intf_ptr,
	InetT_Address_Range** addr_range_pptr)
	{
	int							i;

	/** This function checks whether the given IPv6 address	**/
	/** is one of the addresses assigned to this interface.	**/

	FIN (inet_rte_v6intf_addr_range_check (intf_ptr, next_hop, addr_range_pptr));

	/* Check whether the address falls in the same	*/
	/* IP subnet as any of the IPv6 addresses.		*/
	for (i = 0; i < ip_rte_intf_num_ipv6_addrs_get (intf_ptr); i++)
		{
		/* Check whether the given address falls in	*/
		/* the same IP subnet as the ith IPv6 address*/
		if (inet_address_range_check (next_hop, ip_rte_intf_ith_ipv6_addr_range_get_fast (intf_ptr, i)))
			{
			/* It was a match. Return true.			*/
			*addr_range_pptr = ip_rte_intf_ith_ipv6_addr_range_get_fast (intf_ptr, i);
			FRET (OPC_TRUE);
			}
		}
	/* We did not find a matching IP address.		*/
	/* Return false.								*/
	FRET (OPC_FALSE);
	}

IpT_Address
ip_rte_loopback_from_iface_addr_get (IpT_Address ipaddr)
	{
	int							ipaddr_lkup_index;
	Objid						node_objid;
	IpT_Address 				loopback_ipaddr;
		
	/** This function is called internally to obtain the name of the	**/
	/** node that has an IP interface whose address is the same as the	**/
	/** one passed in as the first argument.							**/
	FIN (ip_rte_loopback_from_iface_addr_get (IpT_Address ipaddr))

	/*
	 * Obtain the index to use in looking up the corresponding entry
	 * in the NATO table.
	 */
	ipaddr_lkup_index = ip_rtab_addr_convert (ipaddr);

	/* If the lookup failed, copy in an appropriate string	*/
	/* and return.											*/
	if (ipaddr_lkup_index == IPC_FAST_ADDR_INVALID)
		FRET (IPC_ADDR_INVALID);

	/*
	 * Get the object ID of the node object that contains the IP
	 * interface denoted by this IP address. Recall that this
	 * association (of IP address to containing node object ID)
	 * is created when the IP model registers the IP addresses
	 * of local interfaces during the execution of the auto
	 * addressing phase.
	 */
	node_objid = nato_table_address_node_objid_get (ip_table_handle, ipaddr_lkup_index);

	/* Get the loopback address for this node				*/
	loopback_ipaddr = ip_loopback_address_from_node_id (node_objid);

	FRET (loopback_ipaddr);
	}

IpT_Address
ip_loopback_address_from_node_id (Objid node_objid)
	{
	List*				proc_record_handle_list_ptr;
	OmsT_Pr_Handle		process_record_handle;
	IpT_Info*			ip_info_ptr;
	List*				iface_table_ptr;
	IpT_Interface_Info*	ip_iface_elem_ptr;
	IpT_Address			ip_address;
	int					list_index;
	
	/** Given a node object ID, this function returns the first		**/
	/** valid IP address available in that node. It uses process	**/
	/** registry to  get a handle on the IP interface table for the	**/
	/** specified node, and then objtains an address on that node.	**/		
	FIN (ip_address_from_node_id (node_objid));

	/* Obtain the process record handle of the ip process that	*/
	/* resides in the specified node.							*/
	proc_record_handle_list_ptr = op_prg_list_create ();
	oms_pr_process_discover (OPC_OBJID_INVALID, proc_record_handle_list_ptr,
			"node objid",	OMSC_PR_OBJID,		node_objid,
			"protocol",		OMSC_PR_STRING,		"ip",
			OPC_NIL);

	/* Get the process record handle for this process.	*/
	if (op_prg_list_size (proc_record_handle_list_ptr) != 0)
		{
		process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
		}
	else
		{
		/* The specified node does not contain an IP layer -- so ping	*/
		/* traffic cannot be routed to that node. Return failure.		*/
		FRET (ip_address_create ("0.0.0.0"));
		}
 
	/* Obtain the interface information from this record -- this	*/
	/* contains the address information for each of the interfaces	*/
	/* configured on that node.										*/
	oms_pr_attr_get (process_record_handle, "interface information", OMSC_PR_ADDRESS, &ip_info_ptr);

	/* Obtain the pointer to the IP interface table.	*/
	iface_table_ptr = ip_info_ptr->ip_iface_table_ptr;

	/* Obtain the first valid IP interface element.	*/
	if (op_prg_list_size (iface_table_ptr) > 0)
		{
		for (list_index = 0; list_index < op_prg_list_size (iface_table_ptr); list_index++)
			{
			/* Get a handle on the next entry in the interface table.	*/
			ip_iface_elem_ptr = (IpT_Interface_Info *) op_prg_list_access (iface_table_ptr, list_index);
			
			if (ip_rte_intf_status_get (ip_iface_elem_ptr) == IpC_Intf_Status_Loopback)
				{
				/* Get the interface IP address. */
				ip_address = ip_address_copy (ip_iface_elem_ptr->addr_range_ptr->address);
				}
			}
		}
	else
		{
		/* Create an invalid IP address so that the calling traps	*/
		/* a failure to map an IP address.							*/
		ip_address = ip_address_create ("0.0.0.0");
		}

	FRET (ip_address);
	}

Boolean
ip_rte_support_packet_match (Packet* pkt_ptr, IpT_Rte_Map_Match_Info* match_info_ptr, 
								IpT_Acl_Table* PRG_ARG_UNUSED (acl_table))
	{
	Boolean						is_match 			= OPC_FALSE;
	IpT_Pkt_Socket_Info			socket_info;
	int							packet_size;
	Compcode					status;
	
	/* This function is used to provide match to a Packet	*/
	/* with the route map. Depending on the Match conditions*/
	FIN (ip_rte_support_packet_match ());
	
	/* Check the validity of the passed arguments			*/
	if ((match_info_ptr == OPC_NIL) || (pkt_ptr == OPC_NIL))
		FRET (OPC_TRUE);
	
	/* Extract the socket information from the packet.		*/
	status = ip_support_ip_pkt_socket_info_extract (pkt_ptr, &socket_info);

	/* If there was an error in extracting this information	*/
	/* just accept the packet.								*/
	if (OPC_COMPCODE_FAILURE == status)
		{
		FRET (OPC_TRUE);
		}

	/* Use the ith match condition to check for a match 	*/
	switch (match_info_ptr->match_property)
		{
		case (IpC_Rte_Map_Match_Property_None):
			{
			/* Nothing being compared, indicate match 		*/
			is_match = OPC_TRUE;
			break;
			}
		case (IpC_Rte_Map_Match_Property_IpAddress):
		case (IpC_Rte_Map_Match_Property_Dest_IpAddress):
		case (IpC_Rte_Map_Match_Property_NA):
		case (IpC_Rte_Map_Match_Property_Source_IpAddress):
			/* Call the function that will perform the match*/
			is_match = ip_rte_map_ip_address_packet_match (pkt_ptr, &socket_info, match_info_ptr);
			break;
		
		case (IpC_Rte_Map_Match_Property_Source_Port):
			{
			/* If we are performing a match using the		*/
			/* Source Port									*/
			switch (match_info_ptr->match_condition)
				{
				/* Now we must determine if we are using	*/
				/* Equal condition							*/
				case (IpC_Rte_Map_Match_Condition_Equals):
					{
					/* If the Src Port is found, set to		*/
					/* TRUE and end search 					*/
					if (socket_info.source_port == match_info_ptr->match_term.match_int)
						is_match = OPC_TRUE;
					
					break;
					}
				default:
					{
					/* Invalid choice, this will be caught in the route map's creation */
					is_match = OPC_FALSE;
					}
				}	
			break;
			}
		
		case (IpC_Rte_Map_Match_Property_Dest_Port):
			{
			/* If we are performing a match using the		*/
			/* Dest Port									*/
			switch (match_info_ptr->match_condition)
				{
				/* Now we must determine if we are using	*/
				/* Equal condition							*/
				case (IpC_Rte_Map_Match_Condition_Equals):
					{
					/* If the Dest Port is found, set to	*/
					/* TRUE and end search 					*/
					if (socket_info.dest_port == match_info_ptr->match_term.match_int)
						is_match = OPC_TRUE;
					
					break;
					}
				default:
					{
					/* Invalid choice, this will be caught in the route map's creation */
					is_match = OPC_FALSE;
					}
				}	
			break;
			}
		
		case (IpC_Rte_Map_Match_Property_Tos):
			{
			/* If we are performing a match using the		*/
			/* Type of Service								*/
			switch (match_info_ptr->match_condition)
				{
				/* Now we must determine according to the	*/
				/* condition configured						*/
				case (IpC_Rte_Map_Match_Condition_Equals):
					{
					/* If the Tos is found, set to	TRUE 	*/
					/* and end search 						*/
					if (IP_TOS_COMPONENT_MATCH (socket_info.packet_tos, match_info_ptr->match_term.match_int))
						is_match = OPC_TRUE;
					
					break;
					}
				default:
					{
					/* Invalid choice, this will be caught in the route map's creation */
					is_match = OPC_FALSE;
					}
				}	
			break;
			}
			
		case (IpC_Rte_Map_Match_Property_Precedence):
			{
			/* If we are performing a match using the		*/
			/* Protocol										*/
			switch (match_info_ptr->match_condition)
				{
				/* Now we must determine if we are using	*/
				/* Equal condition							*/
				case (IpC_Rte_Map_Match_Condition_Equals):
					{
					/* If the precedence match set to		*/
					/* TRUE and end search 					*/
					if (IP_PREC_COMPONENT_MATCH (socket_info.packet_tos, match_info_ptr->match_term.match_int))
						is_match = OPC_TRUE;
					
					break;
					}
				default:
					{
					/* Invalid choice, this will be caught in the route map's creation */
					is_match = OPC_FALSE;
					}
				}
			}
			
		case (IpC_Rte_Map_Match_Property_Packet_Length):
			{
			/* If we are performing a match using the		*/
			/* Packet Size									*/
			packet_size = (int) op_pk_total_size_get (pkt_ptr);
			
			/* Switch on the match condition				*/
			switch (match_info_ptr->match_condition)
				{
				/* Now we must determine if we are using	*/
				/* Equal condition							*/
				case (IpC_Rte_Map_Match_Condition_Equals):
					{
					/* Check for the packet size condition	*/
					if (packet_size == match_info_ptr->match_term.match_int)
						is_match = OPC_TRUE;
					
					break;
					}
				case (IpC_Rte_Map_Match_Condition_Less_Than):
					{
					/* Check for the packet size less than 	*/
					/* condition							*/
					if (packet_size < match_info_ptr->match_term.match_int)
						is_match = OPC_TRUE;
					
					break;
					}
				case (IpC_Rte_Map_Match_Condition_Greater_Than):
					{
					/* Check for the packet size greater	*/
					/* than	condition						*/
					if (packet_size > match_info_ptr->match_term.match_int)
						is_match = OPC_TRUE;
					
					break;
					}	
				default:
					{
					/* Invalid choice, this will be caught in the route map's creation */
					is_match = OPC_FALSE;
					}
				}
			
			break;
			}	
		default:
			/* Invalid match property. Return false.		*/
			is_match = OPC_FALSE;
			break;

		/* End of switch statement */
		}
	
	FRET (is_match);
	}


Compcode 
ip_rte_support_packet_alter (Packet* pkt_ptr, int set_attr, int set_oper, const void* value_ptr, 
								IpT_Rte_Module_Data* iprmd_ptr, InetT_Address* next_hop_ptr, int* out_iface_ptr, 
								IpT_Rte_Table_Lookup* rt_lookup_ptr, char* rte_map_name, char* iface_name_str)
	{
	const int*						int_value_ptr;
	IpT_Dgram_Fields*				pk_fd_ptr;
	char*							string_value_ptr;
	Packet*							tracer_pk_ptr;
	IpT_Tracer_Pkt_IP_Info*			tracer_ip_info_ptr;
	IpT_Policy_Check_Info*			policy_check_info_ptr	= OPC_NIL;
	List*							ip_policy_action_lptr	= OPC_NIL;
	InetT_Addr_Family				addr_family;
		
	/* This proc alters the information in the packet		*/
	/* according to set Clause in the Route Map configured	*/
	FIN (ip_rte_support_packet_alter ());
	
	/* Check the validity of the passed arguments			*/
	if ((value_ptr == OPC_NIL) || (pkt_ptr == OPC_NIL))
		FRET (OPC_COMPCODE_FAILURE);
	
	/* Get the content of the Field called "fields" in the IP-Datagram			*/
	/* in order to get the tos, protocol, the destination and source address.	*/
	if (op_pk_nfd_access (pkt_ptr, "fields", &pk_fd_ptr) == OPC_COMPCODE_FAILURE)
		{
		FRET (OPC_COMPCODE_FAILURE);
		}
	
	/* Check if this is a tracer packet. If yes then		*/
	/* we need to get the info from IP Info field			*/
	/* inside the tracer packet								*/
	else if ((op_pk_encap_flag_is_set (pkt_ptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX)) ||
			(op_pk_encap_flag_is_set (pkt_ptr, OMSC_SECURITY_ENCAP_FLAG_INDEX)))	
		{
		/* This is a tracer packet get the IP info		*/
		/* from the field inside the tracer packet		*/
		
		/* Get the IP info field from inside the tracer	*/
		/* packet										*/	
		if ((op_pk_nfd_get (pkt_ptr, "data", &tracer_pk_ptr) == OPC_COMPCODE_SUCCESS) &&
			(op_pk_nfd_access (tracer_pk_ptr, "ip_info_ptr", &tracer_ip_info_ptr) == OPC_COMPCODE_SUCCESS))
			{
			/* Get the Policy Checker info ptr if 		*/
			/* it is set we will get the pointer else	*/
			/* we will get nil							*/
			if (tracer_ip_info_ptr->ip_policy_check_info_ptr != OPC_NIL)
				{
				/* Get the Policy Checker info ptr		*/
				policy_check_info_ptr = tracer_ip_info_ptr->ip_policy_check_info_ptr;
				
				/* Create the list of IP Policy Actions	*/
				/* if it does not exist					*/
				if (policy_check_info_ptr->ip_policy_action_lptr == OPC_NIL)
					policy_check_info_ptr->ip_policy_action_lptr = op_prg_list_create ();
				
				/* Get the list of IP Policy Actions	*/
				ip_policy_action_lptr = policy_check_info_ptr->ip_policy_action_lptr;
				}
			
			/* Encapsulate the tracer packet back into	*/
			/* IP Dgram packet again					*/	
			if (tracer_pk_ptr != OPC_NIL)
				op_pk_nfd_set (pkt_ptr, "data", tracer_pk_ptr);
			}
		}
	
	/* Determine whether we are dealing with an IPv4 packet	*/
	/* or an IPv6 packet.									*/
	addr_family = inet_address_family_get (&(pk_fd_ptr->dest_addr));

	switch (set_attr)
		{
		case IpC_Rte_Map_Set_Attr_Next_Hop:
			/* In this case Next hop an outgoing interface for the packet will	*/
			/* be altered 														*/
			*next_hop_ptr = ip_rte_support_next_hop_set (iprmd_ptr, addr_family,
				(const InetT_Address*) value_ptr, out_iface_ptr);

			/* Set the return code for the calling function that now it		*/
			/* should not look into the Routing table 						*/
			*rt_lookup_ptr = IpC_Bypass_Rte_Table_Lookup;
		
			/* If IP Policy actions are required to be printed at the end	*/
			/* then store this information 									*/
			if ((ip_policy_action_lptr != OPC_NIL) &&
				(policy_check_info_ptr->record_details == OPC_TRUE))
				{
				/* Add all the action info to the list						*/
				/* This info will be ouput at the end in					*/		
				/* IP Policy Check Report OT Tables							*/
				ip_policy_action_into_list_insert (ip_policy_action_lptr, iprmd_ptr->node_name, rte_map_name, 
														iface_name_str, IpC_Policy_Action_Reroute);
				}

			FRET (OPC_COMPCODE_SUCCESS);
		
		case IpC_Rte_Map_Set_Attr_Interface:
			/* In this case outgoing interface for the packet will be altered 	*/
		
			/* If attribute is interface, value_ptr is assumed to be char* 	*/
			string_value_ptr = (char*) value_ptr;
		
			/* Get the interface number from interface name					*/
			if (ip_rte_is_local_intf_name (string_value_ptr, iprmd_ptr, out_iface_ptr, OPC_NIL))
				{
				/* The interface name specified is valid. Determine the		*/
				/* next hop corresponding to this interface.				*/

				/* Get the next hop address from this interface name			*/
				*next_hop_ptr = ip_rte_next_hop_address_from_intf_name_get
					(iprmd_ptr, string_value_ptr, addr_family, OPC_NIL);
				}
			else
				{
				/* Invalid interface name, probably null0. Set the interface*/
				/* number to an	invalid value. The packet will be dropped.	*/
				*out_iface_ptr = IPC_INTF_INDEX_INVALID;
				}
		
			/* If IP Policy actions are required to be printed at the end	*/
			/* then store this information 									*/
			if ((ip_policy_action_lptr != OPC_NIL) &&
				(policy_check_info_ptr->record_details == OPC_TRUE))
				{
				/* Add all the action info to the list						*/
				/* This info will be ouput at the end in					*/		
				/* IP Policy Check Report OT Tables							*/
				ip_policy_action_into_list_insert (ip_policy_action_lptr, iprmd_ptr->node_name, rte_map_name, 
														iface_name_str, IpC_Policy_Action_Reroute);
				}
			
			/* Set the return code for the calling function that now it		*/
			/* should not look into the Routing table 						*/
			*rt_lookup_ptr = IpC_Bypass_Rte_Table_Lookup;
			
			FRET (OPC_COMPCODE_SUCCESS);
			
		/* In this case the TOS value of the packet will be altered */	
		case IpC_Rte_Map_Set_Attr_IP_ToS:
			{
			if (set_oper == IpC_Rte_Map_Set_Oper_SetAs)
				{
				/* If attribute is ToS, the value_ptr is assumed to be int* */
				int_value_ptr = (const int*) value_ptr;
			
				/* Alter the ToS value								*/
				pk_fd_ptr->tos = IP_TOS_COMPONENT_SET (pk_fd_ptr->tos, (*int_value_ptr));
				
				/* If IP Policy actions are required to be printed at the end	*/
				/* then store this information 									*/
				if ((ip_policy_action_lptr != OPC_NIL) &&
					(policy_check_info_ptr->record_details == OPC_TRUE))
					{
					/* Add all the action info to the list						*/
					/* This info will be ouput at the end in					*/		
					/* IP Policy Check Report OT Tables							*/
					ip_policy_action_into_list_insert (ip_policy_action_lptr, iprmd_ptr->node_name, rte_map_name, 
															iface_name_str, IpC_Policy_Action_Alter_Tos);
					}
				
				FRET (OPC_COMPCODE_SUCCESS);
				}
			else
				{
				/* Unrecognized set operation */
				FRET (OPC_COMPCODE_FAILURE);
				}
				
			}
			
		case IpC_Rte_Map_Set_Attr_IP_Precedence:
			{
			/* In this case the precedence for the packet will be altered */
		
			if (set_oper == IpC_Rte_Map_Set_Oper_SetAs)
				{
				/* If attribute is precedence, the value_ptr is assumed to be int* */
				int_value_ptr = (const int*) value_ptr;
			
				/* Alter the IP precedence value							*/
				pk_fd_ptr->tos = IP_PREC_COMPONENT_SET (pk_fd_ptr->tos, (*int_value_ptr));
				
				/* If IP Policy actions are required to be printed at the end	*/
				/* then store this information 									*/
				if ((ip_policy_action_lptr != OPC_NIL) &&
					(policy_check_info_ptr->record_details == OPC_TRUE))
					{
					/* Add all the action info to the list						*/
					/* This info will be ouput at the end in					*/		
					/* IP Policy Check Report OT Tables							*/
					ip_policy_action_into_list_insert (ip_policy_action_lptr, iprmd_ptr->node_name, rte_map_name, 
															iface_name_str, IpC_Policy_Action_Alter_Prec);
					}
				
				FRET (OPC_COMPCODE_SUCCESS);
				}
			else
				{
				/* Unrecognized set operation */
				FRET (OPC_COMPCODE_FAILURE);
				}
			}
		
		case IpC_Rte_Map_Set_Attr_Dscp:
			{
			/* In this case the DSCP for the packet will be altered 		*/
		
			if (set_oper == IpC_Rte_Map_Set_Oper_SetAs)
				{
				/* If attribute is dscp, the value_ptr is assumed to be int* */
				int_value_ptr = (const int*) value_ptr;
			
				/* Alter the IP precedence value							*/
				pk_fd_ptr->tos = (*int_value_ptr);
				
				/* If IP Policy actions are required to be printed at the end	*/
				/* then store this information 									*/
				if ((ip_policy_action_lptr != OPC_NIL) &&
					(policy_check_info_ptr->record_details == OPC_TRUE))
					{
					/* Add all the action info to the list						*/
					/* This info will be ouput at the end in					*/		
					/* IP Policy Check Report OT Tables							*/
					ip_policy_action_into_list_insert (ip_policy_action_lptr, iprmd_ptr->node_name, rte_map_name, 
															iface_name_str, IpC_Policy_Action_Alter_Dscp);
					}
				
				FRET (OPC_COMPCODE_SUCCESS);
				}
			else
				{
				/* Unrecognized set operation */
				FRET (OPC_COMPCODE_FAILURE);
				}
			}	

		case IpC_Rte_Map_Set_Attr_Default_Next_Hop:
			/* In this case Next hop an outgoing interface for the packet will	*/
			/* be altered if the node does not have an explicit route to the	*/
			/* destination.														*/
			*next_hop_ptr = ip_rte_support_next_hop_set (iprmd_ptr, addr_family,
				(const InetT_Address*) value_ptr, out_iface_ptr);

			/* Set the return code for the calling function that now it			*/
			/* should not use a default route to route the packet.				*/
			*rt_lookup_ptr = IpC_Rte_Table_Lookup_Use_No_Defaults;
			
			FRET (OPC_COMPCODE_SUCCESS);

		case IpC_Rte_Map_Set_Attr_Default_Interface:
			/* In this case, the outgoing interface for the packet will be	*/
			/* altered if the node does not have an explicit route to the	*/
			/* destination.													*/
		
			/* If attribute is interface, value_ptr is assumed to be char* 	*/
			string_value_ptr = (char*) value_ptr;
		
			/* Get the interface number from interface name					*/
			if (ip_rte_is_local_intf_name (string_value_ptr, iprmd_ptr, out_iface_ptr, OPC_NIL))
				{
				/* The interface name specified is valid. Determine the		*/
				/* next hop corresponding to this interface.				*/

				/* Get the next hop address from this interface name			*/
				*next_hop_ptr = ip_rte_next_hop_address_from_intf_name_get
					(iprmd_ptr, string_value_ptr, addr_family, OPC_NIL);
				}
			else
				{
				/* Invalid interface name, probably null0. Set the interface*/
				/* number to an	invalid value. The packet will be dropped.	*/
				*out_iface_ptr = IPC_INTF_INDEX_INVALID;
				}

			/* Set the return code for the calling function that now it		*/
			/* should not use a default route to route the packet.				*/
			*rt_lookup_ptr = IpC_Rte_Table_Lookup_Use_No_Defaults;

			FRET (OPC_COMPCODE_SUCCESS);

	  	default:
			{
			/* Need a sim log message */
			break;
			}
			
		/* End of switch */	
		}
	
	FRET (OPC_COMPCODE_FAILURE);
	}

static InetT_Address
ip_rte_support_next_hop_set (IpT_Rte_Module_Data* iprmd_ptr, InetT_Addr_Family addr_family,
	const InetT_Address* addr_ptr, int* out_iface_ptr)
	{
	InetT_Address		next_addr, temp_inet_addr;
	IpT_Port_Info		output_port_info;
	IpT_Rte_Proc_Id		src_proto;
	IpT_Interface_Info*	output_intf_ptr;
	Compcode			route_status;

	/** Update the next hop address based on the route map set statement.		**/

	FIN (ip_rte_support_next_hop_set (iprmd_ptr, addr_family, addr_ptr, out_iface_ptr));

	/* If the address family of the next hop address is	not correct,*/
	/* set the next hop address to an invalid value.				*/
	if (addr_family != inet_address_family_get (addr_ptr))
		{
		FRET (INETC_ADDRESS_INVALID);
		}

	/* If the next hop is not directly connected, perform a			*/
	/* recursive lookup to determine a directly connected next hop.	*/
	if (OPC_COMPCODE_FAILURE == inet_rte_addr_local_network
		(*addr_ptr, iprmd_ptr, &output_port_info))
		{
		/* This next hop is not directly connected. Do a recursive	*/
		/* lookup to find a directly connected next hop				*/
		route_status = inet_cmn_rte_table_recursive_lookup
			(iprmd_ptr->ip_route_table, *addr_ptr, &next_addr,
			&output_port_info, &src_proto, OPC_NIL);
	
		/* Convert port info back into table index						*/
		if (route_status == OPC_COMPCODE_SUCCESS)
			{
			*out_iface_ptr = ip_rte_intf_tbl_index_from_port_info_get (iprmd_ptr, output_port_info);
			}
		}
	else
		{
		/* The specified next hop is directly connected.			*/
		/* Convert port info back into table index						*/
		*out_iface_ptr = ip_rte_intf_tbl_index_from_port_info_get (iprmd_ptr, output_port_info);

		/* Get a handle to the output interface.					*/
		output_intf_ptr = inet_rte_intf_tbl_access (iprmd_ptr, *out_iface_ptr);

		/* Check if the specified address is that of this node.		*/
		if (inet_rte_intf_has_local_address (*addr_ptr, output_intf_ptr))
			{
			/* Get a handle to the output interface structure.		*/
			output_intf_ptr = inet_rte_intf_tbl_access (iprmd_ptr, *out_iface_ptr);

			/* The given next hop address corresponds to this node	*/
			/* itself. Call the function that will determine the	*/
			/* actual next hop.										*/
			next_addr = ip_rte_next_hop_address_from_intf_get
				(iprmd_ptr, output_intf_ptr, addr_family);
			}
		else
			{
			/* The given address is not a local address. Use it as	*/
			/* the next hop address.								*/
			temp_inet_addr =  (*addr_ptr);
			next_addr = inet_address_copy (temp_inet_addr);
			}
		}
		
	FRET (next_addr);
	}

InetT_Address
ip_rte_next_hop_address_valid (IpT_Rte_Module_Data* iprmd_ptr, int intf_index)
	{
	int			num_addrs_in_same_subnet = 0;
	int			self_addr_index;
	int			temp_addr_index = 0;

	IpT_Interface_Info	*intf_info_ptr = OPC_NIL;
	InetT_Address		temp_ip_addr, next_hop_ip_addr;

	/* Check if the specified next hop is a braodcast address or	*/
	/* a valid point to point. This func returns IPC_ADDR_INVALID	*/
	/* if this is a braodcast address								*/
	FIN (ip_rte_next_hop_address_valid (IpT_Rte_Module_Data* iprmd_ptr, int intf_index));
	
	/* Get the interface info										*/
	intf_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, intf_index);
	
	/* Make sure the interface IP address was not set as 			*/
	/* NO IP Address												*/
	temp_ip_addr = inet_rte_v4intf_addr_get (intf_info_ptr);
	if (inet_address_equal (InetI_No_Ipv4_Address, temp_ip_addr))
		{
		/* Write a log message										*/
		ipnl_cfgwarn_next_hop_name_for_no_ip_addr_intf (ip_rte_intf_name_get (intf_info_ptr));

		FRET (INETC_ADDRESS_INVALID);
		}

	/* If the interface is unnumbered, use the local address as the	*/
	/* next hop.													*/
	if (ip_rte_intf_unnumbered (intf_info_ptr))
		{
		next_hop_ip_addr = inet_rte_v4intf_addr_get (intf_info_ptr);

		FRET (next_hop_ip_addr);
		}

	/* We have found a local interface with required name. Now find */
	/* another address in the global IP table lying in the same 	*/
	/* address range.												*/
	
	/* Find the position of the this interface address in NATO 		*/
	self_addr_index = ip_rtab_addr_convert (intf_info_ptr->addr_range_ptr->address);	
	
	/* if this interface address is not registered in the global	*/
	/* IP table return a invalid next hop address.					*/							
	if (self_addr_index == IPC_FAST_ADDR_INVALID)
		FRET (INETC_ADDRESS_INVALID);
	
	/* Search for addresses in the global IP table which lie in the	*/
	/* same IP network as this interface. As the global IP table is	*/
	/* sorted on IP addresses, other addresses in the same network	*/
	/* should be above or below in the list.						*/
	
	
	/* start searching below first */
	temp_addr_index = self_addr_index;

	while (1)
		{
		temp_addr_index ++;
		temp_ip_addr = inet_rtab_index_to_addr_convert (temp_addr_index);
		
		if ((!inet_address_valid (temp_ip_addr)) ||
			!inet_rte_v4intf_addr_range_check (temp_ip_addr, intf_info_ptr, OPC_NIL))
			{
			break;
			}
		else
			{
			num_addrs_in_same_subnet ++;		
			/* Do not use inet_address_copy	*/
			next_hop_ip_addr = temp_ip_addr;
			}
		}

	inet_address_destroy (temp_ip_addr);

	/* start searching above */
	temp_addr_index = self_addr_index;
		
	while (1)
		{
		temp_addr_index --;
		temp_ip_addr = inet_rtab_index_to_addr_convert (temp_addr_index);
		
		if ((!inet_address_valid (temp_ip_addr)) ||
			!inet_rte_v4intf_addr_range_check (temp_ip_addr, intf_info_ptr, OPC_NIL))
			{
			break;
			}
		else
			{
			num_addrs_in_same_subnet ++;
			/* Do not use inet_address_copy	*/
			next_hop_ip_addr = temp_ip_addr;
			}
		}
	
	inet_address_destroy (temp_ip_addr);

	/* No other address in the same subnet */
	if (num_addrs_in_same_subnet == 0)
		{
		FRET (INETC_ADDRESS_INVALID);
		}
	else if (num_addrs_in_same_subnet > 1)
		{
		/* Write a log that name-based next hop	is		*/
		/* unsupported for broadcast and NBMA networks.	*/
		ipnl_cfgwarn_next_hop_name_for_broadcast_intf (ip_rte_intf_name_get (intf_info_ptr));
		
		FRET (INETC_ADDRESS_INVALID);
		}
	else 
		{
		FRET (next_hop_ip_addr);
		}
	}

InetT_Address
inet_default_route_get (IpT_Rte_Module_Data* iprmd_ptr, InetT_Addr_Family addr_family, short* out_intf_index_ptr)
	{
	InetT_Address default_route;

	/**This function returns the default route of the specified type**/

	FIN (inet_default_route_get (iprmd_ptr, addr_family, out_intf_index_ptr));

	/* Fill in the out_intf_index_ptr								*/
	*out_intf_index_ptr = iprmd_ptr->default_route_intf_index_array[addr_family];

	/* Copy the default route information.							*/
	default_route = inet_address_copy (iprmd_ptr->default_route_addr_array[addr_family]);

	FRET (default_route);
	}

int
ip_rte_tunnel_to_dest_find (IpT_Rte_Module_Data* iprmd_ptr, InetT_Address dest_addr, int protocol)
	{
	int					i, num_interfaces;
	IpT_Interface_Info*	ith_intf_ptr;
	char 				dest_addr_str [INETC_ADDR_STR_LEN];
	int					best_match = IPC_TUNNEL_INTF_INDEX_NOT_FOUND;
	
	/** This function searches for a tunnel interface to the 		**/
	/** specified destination. In case of pt-to-multipt tunnels		**/
	/** a specified 												**/

	FIN (ip_rte_tunnel_to_dest_find (iprmd_ptr, dest_addr, protocol));

	/* Loop through all the interfaces of the node.					*/
	num_interfaces = inet_rte_num_interfaces_get (iprmd_ptr);
	for (i = 0; i < num_interfaces; i++)
		{
		/* Get a pointer to the ith interface.						*/
		ith_intf_ptr = inet_rte_intf_tbl_access (iprmd_ptr, i);

		/* If this is a tunnel interface and its destinaton address	*/
		/* matches the specifed value return its index.				*/
		if (ip_rte_intf_is_tunnel (ith_intf_ptr))
			{
			/* This interface is a tunnel. Check the destination	*/
			/* address.												*/
			if (inet_address_equal (dest_addr, ip_rte_tunnel_dest_addr_get (ith_intf_ptr)))
				{
				/* We found a matching tunnel.						*/
				FRET (i);
				}
			/* In the case of 6to4 tunnels, we might not find a		*/
			/* matching tunnel. So in the case of IPv6 packets, if	*/
			/* we do not find a matching tunnel and the node has a	*/
			/* 6to4 tunnel, assume that the packet was received on	*/
			/* the 6to4 tunnel.										*/
			if ((IpC_Protocol_IPv6 == protocol) &&
				(IpC_Tunnel_Mode_IPv6_6to4 == ip_rte_intf_tunnel_mode_get (ith_intf_ptr)))
				{
				best_match = i;
				}
			}
		}

	/* We could not find a matching tunnel. Return 					*/
	/* IPC_TUNNEL_INTF_INDEX_NOT_FOUND.								*/
	if (IPC_TUNNEL_INTF_INDEX_NOT_FOUND == best_match)
		{
		inet_address_print (dest_addr_str, dest_addr);	
		ip_nl_tunnel_to_dest_not_found_log_write (dest_addr_str);
		}
	
	FRET (best_match);
	}

void
ipv6_packet_to_mac_send (struct IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr, Ici* arp_ici_ptr,
	InetT_Address next_addr, struct IpT_Interface_Info* out_intf_ptr)
	{
	int						mac_addr;
	int						remote_minor_port;

	/** Send an IPv6 packet to the lower layer.					**/

	FIN (ipv6_packet_to_mac_send (iprmd_ptr, pkptr, arp_ici_ptr, out_intf_ptr));

	/* If this is a 'dumb' interface, just send the packet out	*/
	if (IpC_Intf_Type_Dumb == ip_rte_intf_type_get (out_intf_ptr))
		{
		op_pk_send (pkptr, ip_rte_intf_out_port_num_get (out_intf_ptr));
		}
	else
		{
		/* This interface has a MAC layer, we need to find out	*/
		/* the MAC address corresponding to the next hop IP		*/
		/* address.												*/

		/* For multicast packets, use the broadcast address.	*/
		if (inet_address_is_multicast (next_addr))
			{
			mac_addr = IPC_PHYS_ADDR_BROADCAST;
			}
		/* If ARP Simulation efficiency is enabled, use the		*/
		/* nato table to find the mac address of the neighbor.	*/
		else if (ip_arp_sim_eff_sim_attr_get (OPC_FALSE))
			{
			if (icmp6_nd_phys_addr_get (next_addr, &mac_addr, &remote_minor_port) == OPC_COMPCODE_FAILURE)
				{
				/* The next hop address is invalid. Drop the	*/
				/* packet.										*/
				ip_rte_dgram_discard (iprmd_ptr, pkptr, OPC_NIL, "ARP for Next hop failed");

				FOUT;
				}
			}
		else
			{
			/* Not currently supported.							*/
			op_sim_end ("ARP Simulation efficiency must be enabled", OPC_NIL, OPC_NIL, OPC_NIL);
			}

		/* Found the physical address 					*/
		/* Set the mac address in the arp ici and send	*/
		/* the packet out.								*/
		op_ici_attr_set (arp_ici_ptr, "mac_addr", mac_addr);
		op_ici_attr_set (arp_ici_ptr, "remote_minor_port", remote_minor_port);
		op_ici_install (arp_ici_ptr);
		op_pk_send_forced (pkptr, ip_rte_intf_out_port_num_get (out_intf_ptr));
		op_ici_install (OPC_NIL);

		/* Reset the "mac_addr" field in the ici.		*/
		/* Otherwise it might cause problems if this	*/
		/* Ici is reused for an IPv4 packet.			*/
		op_ici_attr_set (arp_ici_ptr, "mac_addr", IPC_PHYS_ADDR_INVALID);
		}

	FOUT;
	}


Boolean
inet_rte_v4intf_addr_range_check (InetT_Address next_hop_addr, 
	IpT_Interface_Info*	ip_intf_ptr, InetT_Address_Range** addr_range_pptr)
	{
	int					jth_2ndary_addr;
	
	/* For a next_hop_address, check if it is in the same network as	*/
	/* any of the addresses on the given interface. An interface can be	*/
	/* a primary or sub-interface. Address check includes secondary		*/
	/* addresses on primary or sub-interface.							*/	
	FIN (inet_rte_v4intf_addr_range_check (next_hop_addr, ip_intf_ptr));
	
	/* Loop through the primary and secondary addresses. Note that a	*/
	/* secondary address index of -1 corresponds to the primary address.*/
	for (jth_2ndary_addr = -1; 
		 jth_2ndary_addr < ip_rte_intf_num_secondary_addresses_get (ip_intf_ptr); 
		 jth_2ndary_addr ++)
		{
		if (ip_address_range_check (inet_ipv4_address_get (next_hop_addr),
			ip_rte_intf_secondary_addr_range_get (ip_intf_ptr, jth_2ndary_addr)))
			{
			if (addr_range_pptr != OPC_NIL)
				{
				*addr_range_pptr = inet_rte_intf_secondary_addr_range_get (ip_intf_ptr, jth_2ndary_addr);
				}
			FRET (OPC_TRUE);
			}
		}
	
	/* if we reach here, there is no match */
	FRET (OPC_FALSE);
	}

Boolean
ip_rte_next_hop_address_is_broadcast_for_interface (IpT_Address addr, 
	IpT_Interface_Info*	ip_intf_ptr)
	{
	int				i;
	IpT_Address 	iface_addr, iface_smask;
	IpT_Address 	iface_network_addr;
	IpT_Address		iface_smask_complement;
	IpT_Address		iface_bcast_addr;
	
	/** Returns true if the supplied "addr" is a broadcast address with	**/
	/** respect to the network address and subnet mask of the supplied	**/
	/** IP interface's information.										**/
	FIN (ip_rte_next_hop_address_is_broadcast_for_interface (addr, ip_intf_ptr));

	/* Get primary address/mask of the interface */
	iface_addr 	= ip_rte_intf_addr_get (ip_intf_ptr);
	iface_smask = ip_rte_intf_mask_get (ip_intf_ptr);
	
	/* Create a broascast address for this interface.	*/
	iface_network_addr     = ip_address_mask (iface_addr, iface_smask);
	iface_smask_complement = ip_address_complement (iface_smask);
	iface_bcast_addr       = iface_smask_complement | iface_network_addr;

	/* Check if the supplied address is same as the broadcast address	*/
	/* for this interface.												*/
	if (ip_address_equal (addr, iface_bcast_addr))
		FRET (OPC_TRUE);
	
	for (i = 0; 
		 i < ip_rte_intf_num_secondary_addresses_get (ip_intf_ptr); 
		 i++)
		{
		/* Get i-th secondary ip address */
		iface_addr 	= ip_rte_intf_secondary_addr_get (ip_intf_ptr, i);
		iface_smask = ip_rte_intf_secondary_addr_mask_get (ip_intf_ptr, i);

		/* Create a broascast address for this secondary address	*/
		iface_network_addr     = ip_address_mask (iface_addr, iface_smask);
		iface_smask_complement = ip_address_complement (iface_smask);
		iface_bcast_addr       = iface_smask_complement | iface_network_addr;

		/* Check if the supplied address is same as the broadcast address	*/
		if (ip_address_equal (addr, iface_bcast_addr))
			FRET (OPC_TRUE);
		}
	
	FRET (OPC_FALSE);
	}

static void
ip_rte_isis_pdu_send (IpT_Rte_Module_Data *iprmd_ptr, Packet *pk_ptr)
	{
	Ici*                    isis_ici_ptr                = OPC_NIL;
	Ici*                    arp_ici_ptr                 = OPC_NIL;
	int						isis_out_index				= 0;
	IpT_Interface_Info*		ip_interface_ptr 			= OPC_NIL;
	int 					minor_port;
	int						connection_class;
	IpT_Dgram_Fields*   	pk_fd_ptr;

	/** If it is an ISIS PDU, don't do any IP processing**/
	/** at all -- send the PDU out immediately.         **/
	/** The IP protocol is used only as a delivery 		**/
	/** mechanism to the neighbor.						**/
	FIN (ip_rte_isis_pdu_send (iprmd_ptr, pk_ptr));

	/**	The higher layer has specified the output index	**/
	/** in an ICI. Get the out_index from the major 	**/
	/**	port of the ICI, find the corresponding out  	**/
	/** stream and then	send the ISIS packet.			**/

	isis_ici_ptr = op_intrpt_ici ();
	if (isis_ici_ptr != OPC_NIL)
		{
		/* Get the output index of the interface out of */
		/* which the ISIS packet must be sent 			*/
		op_ici_attr_get (isis_ici_ptr, "out_intf_index", &isis_out_index);

		/* Destroy the ICI.								*/
		op_ici_destroy (isis_ici_ptr);

		/* Get the ip interface ptr from the intf index	*/
		ip_interface_ptr = ip_rte_intf_tbl_access (iprmd_ptr, isis_out_index);
				
		/* Do not send packets on unconnected interfaces.	*/
		/* If the interface is unconnected, just destroy the packet.	*/
		if (ip_rte_intf_is_unconnected (ip_interface_ptr))
			{
			op_pk_destroy (pk_ptr);
			FOUT;
			}
		
		/* If the outgoing interface is a tunnel, then the tunneling	*/
		/* function must be called. The stream on which the packet		*/
		/* came is the stream from ip_encap.							*/
		if (ip_rte_intf_is_tunnel (ip_interface_ptr))
			{
			op_pk_nfd_access (pk_ptr, "fields", &pk_fd_ptr);
			
			ip_packet_tunnel (iprmd_ptr, pk_ptr, iprmd_ptr->instrm_from_ip_encap,
				pk_fd_ptr->dest_addr, ip_interface_ptr);
			FOUT;
			}
		
		if (ip_rte_intf_type_get (ip_interface_ptr) == IpC_Intf_Type_Smart)
			{
			/* Set the ARP ICI                             							*/
			/* Since output queuing is not enabled, use iprmd_ptr->arp_iciptr.		*/
			arp_ici_ptr = iprmd_ptr->arp_iciptr;
		
			/*  Access "fields" structure from ip datagram.                     	*/
			op_pk_nfd_access (pk_ptr, "fields", &pk_fd_ptr);

			/* Get the connection class of the ISIS packet							*/
			connection_class = pk_fd_ptr->connection_class;

			/* Get the minor port number from the intf_index 						*/
			minor_port = ip_rte_minor_port_from_intf_table_index_get (iprmd_ptr, isis_out_index);

			/*	Prepare ICI to carry "next_addr" information. This will be used	  	*/
			/*	by lower layer address resolution layer to convert the IP address 	*/
			/*	to a lower layer address (e.g., ethernet, ATM, etc.)			  	*/ 
			/*  Get the next_address and set it in the packet ICI.					*/
			iprmd_ptr->arp_next_hop_addr = pk_fd_ptr->dest_addr;

			/* Get the connection_class and set it in the packet ICI.				*/
			if (op_ici_attr_set (arp_ici_ptr, "connection_class", connection_class) == OPC_COMPCODE_FAILURE)
				(*iprmd_ptr->error_proc) ("Unable to set connection class in ICI.");
		
			/* Set the corresponding minor port in the ICI.							*/
			if (op_ici_attr_set (arp_ici_ptr, "minor_port", minor_port) == OPC_COMPCODE_FAILURE)
				(*iprmd_ptr->error_proc) ("Unable to set minor port in ICI.");
							
			/* Since no output queuing scheme is chosen, install the ICI.			*/
			/* No queuing is necessary for ISIS										*/
			op_ici_install (arp_ici_ptr);
			}

		/* Send packet out of the output stream										*/
		op_pk_send_forced (pk_ptr, ip_rte_intf_out_port_num_get (ip_interface_ptr));
		
		if (ip_rte_intf_type_get (ip_interface_ptr) == IpC_Intf_Type_Smart)
			{
			/* Uninstall the ICI.													*/
			op_ici_install (OPC_NIL);
			}
		}
	else 
		{
		/* An ISIS packet has arrived at IP without an ICI -- report an error	*/
		(*iprmd_ptr->error_proc)("Unable to obtain the ICI associated with the outgoing ISIS packet.");
		}

	FOUT;
	}

static void
ip_rte_isis_pdu_recv (IpT_Rte_Module_Data *iprmd_ptr, Packet *pk_ptr, 
						int instrm, IpT_Dgram_Fields* pk_fd_ptr)
	{
	int						minor_port_in				= IPC_SUBINTF_INDEX_INVALID;
	int						input_intf_tbl_index		= IPC_INTF_INDEX_INVALID;
	IpT_Interface_Info *	rcvd_intf_info_ptr 			= OPC_NIL;
	Ici *					intf_ici_ptr				= OPC_NIL;
	IpT_Rte_Ind_Ici_Fields *intf_ici_fdstruct_ptr 		= OPC_NIL;

	/** If it is an ISIS PDU, don't do any IP processing at **/
	/** all -- send the PDU up immediately.          		**/
	/** The IP protocol is used only as a delivery 			**/
	/** mechanism from the neighbor.						**/
	FIN (ip_rte_isis_pdu_recv (iprmd_ptr, pk_ptr, pk_fd_ptr));

	/*	This packet came from a lower layer (e.g., ARP.)	*/
	/*	Check to see which interface it arrived on, so we	*/
	/*	can potentially forward this information to the		*/
	/*	higher layer (if the packet is eventually bound for	*/
	/*	the higher layer).									*/

	if (ip_rte_pk_rcvd_intf_tbl_indx_get (iprmd_ptr, instrm, pk_fd_ptr, 
				&minor_port_in, &input_intf_tbl_index) == OPC_COMPCODE_FAILURE)
		{
		/* An ISIS packet has arrived from a neighbor for which the 	*/
		/* incoming intf table index and minor port can't be determined */
		/* (*iprmd_ptr->error_proc)("Minor port could not be determined for the incoming ISIS packet."); */
		ip_rte_dgram_discard (iprmd_ptr, pk_ptr, OPC_NIL, "Minor port could not be determined");

		FOUT;
		}

	/* Get a pointer to the interface information of the	*/
	/* corresponding interface.								*/
	rcvd_intf_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, input_intf_tbl_index);

	/* If this interface is shutdown or set to No IP		*/
	/* Address drop the packet.								*/
	if ((ip_rte_intf_status_get (rcvd_intf_info_ptr) == IpC_Intf_Status_Shutdown) ||
			(ip_address_equal (IpI_No_Ip_Address, ip_rte_intf_addr_get (rcvd_intf_info_ptr))))
		{
		/* A "Shutdown" interface can't receive traffic 	*/
		/* Drop the packet and write log message. 			*/
		ipnl_shutdown_intf_recv_log_write (iprmd_ptr->node_id, ip_rte_intf_name_get (rcvd_intf_info_ptr), op_pk_id (pk_ptr));
					
		FOUT;
		}

	/* Create an ICI and associate it with the datagram.	*/
	/* The ICI will carry information about the datagram	*/
	/* including the interface it was received on			*/
	intf_ici_ptr = op_ici_create ("ip_rte_ind_v4");

	/* Create ip_rte_ind ICI fields data structure that 	*/
	/* contains routing information which is used during	*/
	/* the life-cycle of the ICI in this process.			*/
	intf_ici_fdstruct_ptr = ip_rte_ind_ici_fdstruct_create ();

	/* Set the rte_info_fields in the ICI.					*/
	op_ici_attr_set (intf_ici_ptr, "rte_info_fields", intf_ici_fdstruct_ptr);

    /* Store the information about the interface 			*/
	/* into the ICI.                                		*/
    intf_ici_fdstruct_ptr->interface_received = inet_rte_v4intf_addr_get (rcvd_intf_info_ptr);
    intf_ici_fdstruct_ptr->major_port_received = ip_rte_intf_addr_index_get (rcvd_intf_info_ptr);
    intf_ici_fdstruct_ptr->intf_recvd_index = input_intf_tbl_index;
    intf_ici_fdstruct_ptr->instrm = instrm;

    /* Set additional information about the interface on which this */
    /* IP datagram arrived. This information may be used by the     */
    /* higher layers (e.g., routing protocols like IGRP)            */
    intf_ici_fdstruct_ptr->mtu                  = ip_rte_intf_mtu_get (rcvd_intf_info_ptr);
    intf_ici_fdstruct_ptr->iface_load           = ip_rte_intf_load_bps_get (rcvd_intf_info_ptr);
    intf_ici_fdstruct_ptr->iface_reliability    = ip_rte_intf_reliability_get (rcvd_intf_info_ptr);
    intf_ici_fdstruct_ptr->iface_speed          = ip_rte_intf_link_bandwidth_get (rcvd_intf_info_ptr);

    /* Set the minor port information.              		*/
    intf_ici_fdstruct_ptr->minor_port_received  = minor_port_in;

	/* Set the ICI.     									*/
    op_pk_ici_set (pk_ptr, intf_ici_ptr);

	/* Send the packet directly to IP encap					*/
	op_pk_send (pk_ptr, iprmd_ptr->outstrm_to_ip_encap);

	FOUT;
	}

static Compcode
ip_rte_pk_rcvd_intf_tbl_indx_get (IpT_Rte_Module_Data *iprmd_ptr, int instrm, IpT_Dgram_Fields* pk_fd_ptr, 
								int *minor_port_ptr, int *input_intf_tbl_index_ptr)
	{
	Ici 	*iciptr;
	int		input_phys_intf_tbl_index;
	int		num_subinterfaces = 0;
	int		input_tunnel_index;

	/* Perform the processing required to determine the minor port and 	*/
	/* interface table index of the incoming interface that the packet	*/
	/* just	arrived on. This includes processing of arp's ICI 			*/
	/* If the intf table index of the incoming interface can't be 		*/
	/* determined, return FAILURE										*/
	FIN (ip_rte_pk_rcvd_intf_tbl_indx_get (iprmd_ptr, instrm, pk_fd_ptr, 
					minor_port_ptr, input_intf_tbl_index_ptr));

	/* Find out the intf_index corresponding to the input	*/
	/* stream on which the packet arrived using the			*/
	/* instrm_to_intf_index array.							*/
	input_phys_intf_tbl_index = iprmd_ptr->instrm_to_intf_index_array[instrm];

	/* Obtain minor port information and calculate interface index.	*/
	/* Minor port information is obtained from one of the following:*/
	/*	1. From ip_arp_ind_v4 ICI if sent by lower layer. (or)		*/
	/*	2. Calculated from interface_tbl_index.	(or)				*/
	/*	3. none.													*/
	
	/* As a result of this function, minor port will be one of		*/
	/*		1. IPC_SUBINTF_PHYS_INDEX	(or)						*/
	/*		2. IPC_SUBINTF_INDEX_INVALID (or)						*/
	/*		3. valid number.										*/

	/* If an ICI is associated with the packet (smart interfaces),	*/
	/* the ici will also have another field named tunnel index. If	*/
	/* this is a tunneled packet that was op_pk_delivered to this	*/
	/* module after decapsulation, this fields will be set to the	*/
	/* interface index of the appropriate tunnel interface. If a 	*/
	/* matching tunnel interface could not be found, it will be set	*/
	/* to IPC_TUNNEL_INTF_INDEX_NOT_FOUND. For other packets this	*/
	/* field will be set to IPC_TUNNEL_INTF_INDEX_NOT_USED.			*/

	/* Check whether there is an accompanying ici.					*/
	/* Obtain the ICI.												*/
	iciptr = op_intrpt_ici ();
	
	/* Find if there are any sub-interfaces configured on the		*/
	/* physical interface on which the packet arrived.				*/
	num_subinterfaces = ip_rte_num_subinterfaces_get (
		inet_rte_intf_tbl_access (iprmd_ptr, input_phys_intf_tbl_index));

	if (iciptr != OPC_NIL)
		{
		if (op_ici_attr_get (iciptr, "minor_port", minor_port_ptr) == OPC_COMPCODE_FAILURE)
			{
			(*iprmd_ptr->error_proc)("Unable to obtain minor_port from the ICI associated with the incoming packet.");
			}
		if (op_ici_attr_get (iciptr, "tunnel_index", &input_tunnel_index) == OPC_COMPCODE_FAILURE)
			{
			(*iprmd_ptr->error_proc)("Unable to obtain tunnel_index from the ICI associated with the incoming packet.");
			}

		/* Destroy the ici.											*/
		op_ici_destroy (iciptr);
		}
	else if (num_subinterfaces > 0)
		{
		/* There was no ip_arp_ind_v4 ici. Figure out the minor port*/
		/* from the next hop address of the packet.					*/
		*minor_port_ptr = ip_rte_minor_port_from_next_hop_get (iprmd_ptr,
			input_phys_intf_tbl_index, pk_fd_ptr->next_addr);
		
		/* If the minor port could not be detarmined, drop the 		*/
		/* packet and print out a log message.						*/
		if ((*minor_port_ptr) == IPC_SUBINTF_INDEX_INVALID)
			{
			ipnl_invalid_next_hop_in_pkt_log_write (iprmd_ptr, input_phys_intf_tbl_index, pk_fd_ptr);
			FRET (OPC_COMPCODE_FAILURE);
			}

		/* Use the default value for tunnel index.					*/
		input_tunnel_index = IPC_TUNNEL_INTF_INDEX_NOT_USED;
		}
	else
		{
		/* No ici was associated with this packet. Assume thet it	*/
		/* arrived on the physical interface.						*/
		*minor_port_ptr = IPC_SUBINTF_PHYS_INTF;

		/* Use the default value for tunnel index.					*/
		input_tunnel_index = IPC_TUNNEL_INTF_INDEX_NOT_USED;
		}
		
	/* For tunnneled packets we can get the input interface index	*/
	/* from the ici itself. For other packets, we need to compute it*/
	if (IPC_TUNNEL_INTF_INDEX_NOT_USED == input_tunnel_index)
		{
		/* This is not a tunneled packet.							*/
		
		/* If there are no sub-interfaces on an interface, minor_port is	*/
		/* typically set to IPC_SUBINTF_PHYS_INTF. However, custom lower	*/
		/* layers can override by sending a minor port value through ICI. 	*/

		if (num_subinterfaces > 0)
			{
			/* Compute the table index of the physical/subinterface from 	*/
			/* table index of the physical interface and the input minor 	*/
			/* port.														*/
			*input_intf_tbl_index_ptr = input_phys_intf_tbl_index + ((*minor_port_ptr) - IPC_SUBINTF_PHYS_INTF);
			}
		else
			{
			*input_intf_tbl_index_ptr = input_phys_intf_tbl_index;
			}
		}
	else if (IPC_TUNNEL_INTF_INDEX_NOT_FOUND == input_tunnel_index)
		{
		/* This is a tunneled packet, but we cound not determine the*/
		/* tunnel on which it was received. This is expected		*/
		/* behavior for Automatic and 6to4 tunnels. For other		*/
		/* tunnels (GRE, IP-IP, IPv6 manual), return a failure.		*/
		if (!inet_address_is_6to4 (&pk_fd_ptr->dest_addr) &&
			!inet_address_is_ipv4_compat (&pk_fd_ptr->dest_addr))
			{						
			FRET (OPC_COMPCODE_FAILURE);
			}
		
		/* Pick the first Interface that supports the address family*/
		*input_intf_tbl_index_ptr = ip_rte_first_loopback_intf_index_get (iprmd_ptr,
			inet_address_family_get (&(pk_fd_ptr->dest_addr)));
		}
	else
		{
		/* A valid tunnel interface index was specified. Just use it*/
		*input_intf_tbl_index_ptr = input_tunnel_index;
		}

	FRET (OPC_COMPCODE_SUCCESS);
	}

static int
ip_rte_input_slot_index_determine (IpT_Rte_Module_Data *iprmd_ptr, IpT_Interface_Info* in_iface_ptr, int instrm)
	{
	int							slot_index;

	/** Determine the slot corresponding to the input interface.	**/
	/** In most cases we can directly return the slot index stored	**/
	/** in the IpT_Interface_Info structure. However in the case of	**/
	/** of tunnel interfaces we need to figure out the slot index	**/
	/** from the input stream index.								**/

	FIN (ip_rte_input_slot_index_determine (iprmd_ptr, in_iface_ptr, instrm));

	/* Get the slot index of the input interface.					*/
	slot_index = ip_rte_intf_slot_index_get (in_iface_ptr);

	/* If this is a logical interface, use the slot index of the	*/
	/* physical interface corresponding to the input stream.		*/
	if (OMSC_DV_LOOPBACK_SLOT == slot_index)
		{
		slot_index = ip_rte_intf_slot_index_get (inet_rte_intf_tbl_access
			(iprmd_ptr, iprmd_ptr->instrm_to_intf_index_array[instrm]));
		}

	FRET (slot_index);
	}
		
void
ip_rte_add_routes_to_nato_table (Objid node_objid, Objid module_objid, Objid attr_objid,
	const char* cmpnd_attr_name, const char* address_attr_name, const char* mask_attr_name,
	const char* auto_assigned_string)
	{
	int 						num_routes, count_i;
	Objid						cmpnd_attr_objid;
	Objid						ith_attr_objid;
	char						addr_str[64];
	IpT_Address 				ntwk_addr, subnet_mask, ip_network_address;
    int              		   	status;
    int               		  	int_ip_net_addr;
	
	
	FIN (ip_rte_static_routes_add_to_nato_table (node_objid, module_objid, attr_objid,
		cmpnd_attr_name, address_attr_name, mask_attr_name));

	/* If the global nato tables haven't been created, create them.		*/
	if (OPC_FALSE == ip_nato_tables_created)
		{
		/* Create a table to contain all possible IP interface			*/
		/* addresses in the network.									*/
		ip_table_handle = nato_table_build_start ("ip_table", NATOC_ONE_COMPONENT_ADDR);

		/* Create a tabel to contain possible IP networks in the model.	*/
		ip_networks_table_handle = nato_table_build_start ("ip_networks_table", NATOC_ONE_COMPONENT_ADDR);

		/* Set the flag indicating that the tables have been created.	*/
		ip_nato_tables_created = OPC_TRUE;
		}
	
	/* First get the object Id of the compound attribute which will	*/
	/* be read and processed.										*/
	op_ima_obj_attr_get (attr_objid, cmpnd_attr_name, &cmpnd_attr_objid);
	
	/* Find the number of routes specified.							*/
	num_routes = op_topo_child_count (cmpnd_attr_objid, OPC_OBJTYPE_GENERIC);
	
	for (count_i = 0; count_i < num_routes; count_i++)
		{
		ith_attr_objid = op_topo_child (cmpnd_attr_objid, OPC_OBJTYPE_GENERIC, count_i);
		
		/* First read in the network address.						*/
		op_ima_obj_attr_get (ith_attr_objid, address_attr_name, addr_str);

		/* Make sure the string is a valid network address.			*/
		if (OPC_FALSE == ip_address_string_test (addr_str))
			{
			/* The address entered is either invalid or it is still	*/
			/* uninitialized. move on to the next entry.			*/
			continue;
			}

		/* Convert the specified string into an IP address			*/
		ntwk_addr = ip_address_create (addr_str);

		/* Otherwise, read in the subnet mask.						*/
		op_ima_obj_attr_get (ith_attr_objid, mask_attr_name, addr_str);
	
		/* If it is set to Auto Assigned, use the default subnet mask*/
		if (0 == strcmp (addr_str, auto_assigned_string))
			{
			subnet_mask = ip_default_smask_create (ntwk_addr);
			}
		else
			{
			subnet_mask = ip_address_create (addr_str);
			}
		
		/* If the subnet mask is invalid, print out a log message	*/
		/* and ignore the entry.									*/
		if (ip_address_equal (IPC_ADDR_INVALID, subnet_mask))
			{
			continue;
			}
			
		/* Create a prefix and a route entry corresponding to it.	*/
		ip_network_address = ip_address_mask (ntwk_addr, subnet_mask);
				
		/* Convert IP address to a integer representation, so that it may   */
		/* be stored in the NATO table.                                     */
		int_ip_net_addr = ip_address_to_int (ip_network_address);

		/* Check to see if this network address has already been registered */
		/* If it has been, then do not register it again.                   */
		if (nato_table_one_component_address_entry_exists (ip_networks_table_handle, int_ip_net_addr) == OPC_FALSE)
			{
			/* The IP network address has not yet been registered.          */
			status = nato_table_address_register (ip_networks_table_handle, int_ip_net_addr, 0, node_objid, module_objid);

			/* If the registration was not successful, return an error.     */
			if (status == NATOC_TABLE_FORM_INVALID)
				{
				op_sim_end ("Error at function ip_rtab_local_network_register: global ip networks table",
					"is in usage mode and no further registrations can be performed", OPC_NIL, OPC_NIL);
				}
			}
        }
	
	FOUT;
	}

IpT_Icmp_Ping_Data*
ip_rte_icmp_ping_data_create (InetT_Address ip_address, int mpls_label, int mpls_exp)
	{
	IpT_Icmp_Ping_Data*		ping_data_ptr = OPC_NIL;
	
	/* This function create ICMP Ping data					*/
	FIN (ip_rte_icmp_ping_data_create ());
	
	/* Insert this address in the route data field of the	*/
	/* options data structure.								*/
	ping_data_ptr = (IpT_Icmp_Ping_Data *) op_prg_mem_alloc (sizeof (IpT_Icmp_Ping_Data));

	/* No need to use inet_address_copy here because the	*/
	/* calling function would have done so already.			*/
	ping_data_ptr->ip_address 			= ip_address;
	ping_data_ptr->current_entry_time 	= op_sim_time ();
		
	/* Add the MPLS label stack entry and the EXP bits		*/
	ping_data_ptr->mpls_label 			= mpls_label;
	ping_data_ptr->mpls_exp 			= mpls_exp;		
	
	FRET (ping_data_ptr);
	}

void
ip_rte_icmp_ping_data_destroy (IpT_Icmp_Ping_Data* ping_data_ptr)
	{
	/** Free the memory allocated to the Ping Data structure**/
	
	FIN (ip_rte_icmp_ping_data_destroy (ping_data_ptr));

	/* Free the memory allocted to the IP address.			*/
	inet_address_destroy (ping_data_ptr->ip_address);

	/* Now free the memory allocated the the structure itself*/
	op_prg_mem_free (ping_data_ptr);

	FOUT;
	}

void
ip_basetraf_conv_info_free (IpT_Conversation_Info* ip_conv_info_ptr)
	{
	/* this function free the memory allocated for IP conv	*/
	/* info by ip_basetraf_protocol_parse					*/
	FIN (ip_basetraf_conv_info_free (<args>));
	
	/* Check that we have a valid ip_conv_info_ptr 			*/
	if (ip_conv_info_ptr == OPC_NIL)
		FOUT;
	
	/* Free the demand name if allocated					*/
	if (ip_conv_info_ptr->demand_name != OPC_NIL)
		op_prg_mem_free (ip_conv_info_ptr->demand_name);
	
	/* Free the policy check info if allocated				*/
	if (ip_conv_info_ptr->policy_check_info_ptr != OPC_NIL)
		{
		/* Free the list if available						*/
		if (ip_conv_info_ptr->policy_check_info_ptr->ip_policy_action_lptr != OPC_NIL)
			op_prg_list_free (ip_conv_info_ptr->policy_check_info_ptr->ip_policy_action_lptr);
		
		/* Free the policy check info						*/
		op_prg_mem_free (ip_conv_info_ptr->policy_check_info_ptr);
		}
	
	/* Free the IP Conv info itself							*/
	op_prg_mem_free (ip_conv_info_ptr);
	
	FOUT;
	}

void
ip_policy_action_into_list_insert (List* ip_policy_action_lptr, char* node_name, char* rte_map_name, 
										char* iface_name_str, IpT_Policy_Action policy_action)
	{
	IpT_Policy_Action_Info*			policy_action_info_ptr = OPC_NIL;
	
	/* This function creates the action info taken on		*/
	/* a node and insert it into the passed list			*/	
	FIN (ip_policy_action_into_list_insert (<args>));
	
	/* Check if we have a valid list						*/
	if (ip_policy_action_lptr == OPC_NIL)
		FOUT;
	
	/* Add all the action info to the list					*/
	/* This info will be ouput at the end in				*/		
	/* IP Policy Check Report OT Tables						*/
	policy_action_info_ptr = ip_policy_action_info_mem_alloc ();
	policy_action_info_ptr->node_name = (char*) op_prg_mem_alloc ( sizeof (char) * (strlen (node_name) + 1));
	strcpy (policy_action_info_ptr->node_name, node_name);
	
	policy_action_info_ptr->policy_action = policy_action;
	
	policy_action_info_ptr->rte_map_or_filter_name = (char*) op_prg_mem_alloc ( sizeof (char) * (strlen (rte_map_name) + 20));
	sprintf (policy_action_info_ptr->rte_map_or_filter_name, "Route Map \"%s\"", rte_map_name);
										
	policy_action_info_ptr->iface_name = (char*) op_prg_mem_alloc ( sizeof (char) * (strlen (iface_name_str) + 1));
	strcpy (policy_action_info_ptr->iface_name, iface_name_str);
						
	/* Insert the message into the list that will be carried*/
	/* with the packet										*/
	op_prg_list_insert (ip_policy_action_lptr, policy_action_info_ptr, OPC_LISTPOS_TAIL);
	
	FOUT;
	}

static IpT_Policy_Action_Info*
ip_policy_action_info_mem_alloc (void)
	{
	static Pmohandle		policy_action_pmh 		= OPC_PMO_INVALID;
	IpT_Policy_Action_Info* policy_action_info_ptr 	= OPC_NIL;
	
	/** Function to allocate memory for Policy Action	*/
	FIN (ip_policy_action_info_mem_alloc (void));
	
	/* If PMO handle does not exist then create it		*/
	if (policy_action_pmh == OPC_PMO_INVALID)
		policy_action_pmh = op_prg_pmo_define ("IP Policy Action Information", sizeof (IpT_Policy_Action_Info), 20);
	
	/* If PMO handle still does not exist then allocate	*/
	/* regular memory or else allocate pool memory		*/
	if (policy_action_pmh == OPC_PMO_INVALID)
		policy_action_info_ptr 	= (IpT_Policy_Action_Info*) op_prg_mem_alloc (sizeof (IpT_Policy_Action_Info));
	else
		policy_action_info_ptr 	= (IpT_Policy_Action_Info*) op_prg_pmo_alloc (policy_action_pmh);
		
	/* Initialize the members of DS */
	policy_action_info_ptr->node_name 				= OPC_NIL;
	policy_action_info_ptr->rte_map_or_filter_name 	= OPC_NIL;
	policy_action_info_ptr->iface_name 				= OPC_NIL;
	policy_action_info_ptr->policy_action 			= IpC_Policy_Action_Unknown;
	
	FRET (policy_action_info_ptr);
	}

int
ip_rte_minor_port_from_port_info_get (IpT_Rte_Module_Data* iprmd_ptr, IpT_Port_Info output_port_info)
	{
	int minor_port = IPC_SUBINTF_INDEX_INVALID;
	int	output_intf_table_index, output_intf_minor_port;
	
	/* Given output port information, obtain minor_port (a.k.a subinterface_index)	*/
	/* This function is used after routing table lookups and by lower layers.		*/
	FIN (ip_rte_minor_port_from_port_info_get (iprmd_ptr, port_info));

	output_intf_table_index = ip_rte_intf_tbl_index_from_port_info_get (iprmd_ptr, output_port_info);
	output_intf_minor_port = output_port_info.minor_port;
	
	
	/* Do not attempt to obtain minor port if interface index is	*/
	/* INDEX_NULL0 or INDEX_LSP or INDEX_INVALID.					*/	
	if (output_intf_table_index >= 0)
		{
		if (output_intf_minor_port == IPC_SUBINTF_INDEX_INVALID)
			{
			/* Resolve output interface index to minor_port (subintf_index)	*/
			minor_port	= 
				ip_rte_minor_port_from_intf_table_index_get (iprmd_ptr, output_intf_table_index);
			}
		else
			{
			/* If minor_port is stored as part of routing table, use that information */
			minor_port	= output_intf_minor_port;
			}

		/* Minor port is valid if is 		*/
		/*	1. Valid positive number (or)	*/
		/*  2. IPC_SUBINTF_PHYS_INTF (-1) 	*/
		if ((minor_port < 0) && (minor_port != -1))
			{
			char	tstr [64];
			sprintf (tstr, "Intf Index = %d, Subintf Index = %d\n", output_intf_table_index, minor_port);
			op_prg_mem_alloc (0);
			op_sim_end ("Computed Invalid minor port", tstr, "","");
			}
		}
	
	FRET (minor_port);
	}

Boolean		
ip_rte_intf_has_local_address (const IpT_Address ip_addr, IpT_Interface_Info* interface_ptr)
	{
	int						j;
	int						num_secondary_interfaces;		
	IpT_Address_Range*		secondary_addr_range_ptr = OPC_NIL;
	Boolean					is_local_address = OPC_FALSE;

	/** This functions checks whether the specified address	**/
	/** belongs to the given interface.						**/

	FIN (ip_rte_intf_has_local_address (ip_addr, interface_ptr));
	
	/* Check whether the specified address belongs to	*/
	/* this interface.									*/
	if (ip_address_equal (ip_addr, interface_ptr->addr_range_ptr->address))
		{
		is_local_address = OPC_TRUE;
		}
	else
		{
		num_secondary_interfaces = ip_rte_intf_num_secondary_addresses_get (interface_ptr);
		/* Check if the given address is one of the secondary IP addresses.	*/
		for (j = 0; j <num_secondary_interfaces ; j ++)
			{
			secondary_addr_range_ptr = 	ip_rte_intf_secondary_addr_range_get (interface_ptr, j);
			
			if (ip_address_equal (ip_addr, secondary_addr_range_ptr->address))
				{
				is_local_address = OPC_TRUE;
				break;
				}
			}
		}
	
	FRET (is_local_address);
	}

Boolean
ipv6_rte_intf_has_local_address(const InetT_Address intf_addr, IpT_Interface_Info* intf_ptr)
	{
	
	int					ith_addr, num_addrs;
	Boolean				match_found = OPC_FALSE;

	/** Check whether the given IPv6 address belongs to this interface. **/

	FIN (ipv6_rte_intf_has_local_address (intf_addr, intf_ptr));

	/* Loop through all the addresses of this interface	*/
	num_addrs = ip_rte_intf_num_ipv6_addrs_get (intf_ptr);
	
	for (ith_addr = 0; ith_addr < num_addrs; ith_addr++)
		{
		/* Check if the given address matches the ith	*/
		/* address.										*/
		if (ip_rte_intf_ith_ipv6_addr_equal (intf_ptr, ith_addr, intf_addr))
			{
			/* We have found a match.					*/
			match_found = OPC_TRUE;
			break;
			}
		}
	
	FRET (match_found);
	}

Boolean 
inet_rte_intf_has_local_address (const InetT_Address ip_addr, IpT_Interface_Info* intf_ptr)
	{
	
	/** Check whether the given IP address (v4 or v6) belongs to this interface.	**/
	
	Boolean		match_found = OPC_FALSE;
	
	FIN (inet_rte_intf_has_local_address (ip_addr, intf_ptr));
	
	switch (inet_address_family_get (&ip_addr))
		{
		case InetC_Addr_Family_v4:
		
			/* Check if this interface has a matching IPv4 address*/
			match_found = ip_rte_intf_has_local_address (inet_ipv4_address_get (ip_addr), intf_ptr);
			break;

		case InetC_Addr_Family_v6:
			
			/* Check if this interface has a matching IPv6 address*/
			match_found = ipv6_rte_intf_has_local_address (ip_addr,intf_ptr);
			break;
		
		default:
		/* Invalid address. Just return false.			*/											
			match_found = OPC_FALSE;
		}
	
	FRET (match_found);
   
	}

Boolean
ip_packet_protocol_is_tunnel (IpT_Protocol_Type protocol)
	{
	
	/** This function indicates whether the protocol	**/
	/** is a tunnel protocol handled by the code		**/
	/** pertaining to tunnel interfaces. 				**/
	/** Note that L2TP and GTP do not fall under this	**/
	/** category.										**/
	Boolean		is_tunnel = OPC_FALSE;
	
	
	FIN (ip_packet_protocol_is_tunnel (protocol));
	
	switch (protocol)
		{
		case IpC_Protocol_IPv6:
		case IpC_Protocol_GRE:
		case IpC_Protocol_Ip:
			is_tunnel = OPC_TRUE;
			break;
		
		default:
			is_tunnel = OPC_FALSE;
		break;
		}
	FRET (is_tunnel);
	}
	
void
ip_rte_arp_req_ici_destroy (Ici* ip_arp_req_ici_ptr)
	{
	InetT_Address*		next_addr_ptr;

	/** Deallocates the memory allocated to an ICI of format**/
	/** ip_arp_req_v4. The memory allocated to the address	**/
	/** in the next_addr field is also de-allocated.		**/

	FIN (ip_rte_arp_req_ici_destroy (ip_arp_req_ici_ptr));

	/* Get the address pointer stored in the next_addr field*/
	op_ici_attr_get_ptr (ip_arp_req_ici_ptr, "next_addr", (void**) &next_addr_ptr);

	/* Free the memory allocated to the address.			*/
	inet_address_destroy_dynamic (next_addr_ptr);

	/* Free the memory allocated to the ICI itself.			*/
	op_ici_destroy (ip_arp_req_ici_ptr);

	FOUT;
	}
