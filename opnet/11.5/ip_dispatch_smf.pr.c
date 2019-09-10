/* Process model C form file: ip_dispatch_smf.pr.c */
/* Portions of this file copyright 1992-2006 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char ip_dispatch_smf_pr_c [] = "MIL_3_Tfile_Hdr_ 115A 30A op_runsim 7 4540BC79 4540BC79 1 apocalypse Jim@Hauser 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 d50 3                                                                                                                                                                                                                                                                                                                                                                                                   ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

/***** Includes *****/
#include "ip_addr_v4.h"
#include "oms_data_def.h"

#include "ip_rte_v4.h"
#include "ip_rte_support.h"
#include "ip_rte_slot.h"
#include "ip_cmn_rte_table.h"
#include "ip_dgram_sup.h"
#include "ip_notif_log_support.h"
#include "ip_qos_notif_log_support.h"
#include "ip_support.h"
#include "ip_acl_support.h"
#include "ip_rte_map_support.h"

#include "ip_frag_sup_v3.h"
#include "ip_rte_table_v4.h"
#include "ip_rte_sup_v4.h"
#include "ip_auto_addr_sup_v4.h"
#include "ip_sim_attr_cache.h"
#include "rsvp.h"
#include "umts_gtp_support.h"
#include "mpls_support.h"
#include "mpls_path_support.h"
#include "ip_ot_support.h"
#include "oms_ot_support.h"
#include "ip_pim_sm_support.h"

#include "nato.h"

#include "oms_pr.h"
#include "oms_qm.h"
#include "oms_tan.h"
#include "oms_devices.h"
#include "oms_slot.h"
#include "oms_dist_support.h"
#include "oms_vlan_support.h"	
#include "oms_string_support.h"
#include "oms_log_support.h"	
#include "ip_firewall.h"

/* Call to function that parses RSVP interface Max Reservable Bandwidth.	*/
#include "ip_te_support.h"

/* Make use of the Opnet Model Support package for baseline traffic generation. */
#include "oms_basetraf_ext.h"

/* Make use of the Opnet Model Support package for calculating background utilization. */
#include "oms_bgutil.h"

/* Make use of the Opnet Model Support package for buffer pools */
#include "oms_buffer.h"
#include "ip_qos_support.h"

#include  <ip_vrf_table.h>
#include  <bgp.h>
#include <ip_mcast_support.h>
#include <mobile_ip_support.h>
#include <oms_routing_convergence.h>
#include <rrp.h>
#include <ip_observer.h>
#include <ipv6_ra.h>
#include <ip_icmp_pk.h>
#include <ip_grouping.h>
#include <mipv6_support.h>
#include <ipv6_extension_headers_sup.h>
#include <mipv6_signaling_sup.h>

/* Macros Used to Represent Transitions. */
#define	SELF_NOTIFICATION	(intrpt_type == OPC_INTRPT_SELF)	

#define	SELF_NOTIFICATION_ACTIVE	((intrpt_type == OPC_INTRPT_SELF) && \
							 (inet_rte_num_interfaces_get (&module_data) != 0))	

#define MCAST_RSVP_VPN		((invoke_mode == OPC_PROINV_DIRECT) && \
							 (intrpt_type == OPC_INTRPT_REMOTE) && \
                             (intrpt_code >= IPC_OBSERVER_INTRPT_LIMIT))

#define CHILD_INVOCATION	(invoke_mode == OPC_PROINV_INDIRECT)

/* Macro to handle the transition caused by a stream interrupt  */
/* received by this process. This shouldn't happen normally     */
/* since stream interrupts are handled by the routing child proc*/
#define STRM_INTRPT			((intrpt_type == OPC_INTRPT_STRM) && \
							 (invoke_mode == OPC_PROINV_DIRECT))

#define FAIL_REC            ((invoke_mode == OPC_PROINV_DIRECT) && \
							(intrpt_code < IPC_OBSERVER_INTRPT_LIMIT))

#define INACTIVE			(inet_rte_num_interfaces_get (&module_data) == 0)
		

#define			LOWER_BYTE_MASK	0xffffff00
#define 		UPPER_THREE_MASK 0x000000ff
#define       	LSP_SIGNALING_PROTOCOL_RSVP    1

#define			IP_FAIL_REC_CODE	-99

#define			INFINITE_METRIC	0xFFFFFFFFU


/* Default value of the Layer 2 mapping attributes		*/
#define IPC_DEFAULT_LAYER2_MAPPING_STRING	"None"
#define IPC_DEFAULT_LAYER2_MAPPING_INT		0

/* Constants that will be used to tell the ip_interface_info_create	*/
/* function whether it is a physical or a subinterface				*/
#define IPC_PHYS_INTF	-1
#define IPC_SUBINTF		 0

/* Value corresponding to the symbol map Auto calculate of the		*/
/* Load attribute under Metric Information.							*/
#define IPC_LOAD_AUTO_CALCULATE	-1

#define IPC_MAX_STR_SIZE	256

#define TUNNEL_STAT_GROUP_NAME		"IP Tunnel"

/* Do not operate routing protocol if fwding table is imported */
#define IPC_OPERATE_ROUTING_PROTO	1
#define IPC_STALL_ROUTING_PROTO		2


/* Global variables for "IP Routing Table Export/Import":    */ 
/* Selection of the simulation attribute "IP Routing */
/* Table Export/Import"								 */
extern int 			routing_table_import_export_flag;

/* Flag used to indicate whether or not a node with incorrect	*/
/* number of rows under the Interface Information compound		*/
/* attribute exists in the network.								*/
static Boolean		misconfigured_node_exists = OPC_FALSE;

/* Flag to indicate whether the routes dump		*/
/* has already been cleared by another process	*/
static Boolean		ip_mpls_dump_file_cleared = OPC_FALSE;

/* List of routing protocols that will contain just one	*/
/* entry. IpC_Rte_None.									*/
static List* 		no_routing_proto_lptr = OPC_NIL;

/* Log handle for warning user about overlapping	*/
/* IP subnets.										*/
static OmsT_Log_Handle	ip_subnet_overlap_loghandle;
static Boolean			ip_subnet_overlap_loghandle_created = OPC_FALSE;

/* Global variables used to decide whether we need	*/
/* to export IPv6 addresses to a gdf file.			*/
static Boolean			ipv6_intf_addr_export_mode_determined = OPC_FALSE;
static Boolean			ipv6_intf_addr_export = OPC_FALSE;

/* Global variables for IP routing convergence */
static OmsT_Stat_Names_Set  convergence_stat_names = 
	{
	"Route Table.Forwarding Table Convergence Duration", 
	"Route Table.Forwarding Table Convergence Activity"
	};

static OmsT_Stat_Names_Set  parent_convergence_stat_names = 
	{
	"IP.Network Convergence Duration (sec)", 
	"IP.Network Convergence Activity"
	};



#define	LTRACE_GLOBAL_TABLE_ACTIVE	(op_prg_odb_ltrace_active ("global_table"))

#define LTRACE_FDSTRUCT_ACTIVE		(op_prg_odb_ltrace_active ("fields"))

/***** Globals *****/
extern IpT_Address		IpI_Broadcast_Addr;
extern IpT_Address		IpI_Default_Addr;

/* Structure Declarations */
typedef struct IpT_Intf_Info_Attrs
	{
	Objid			phys_intf_comp_attr_objid;
	Objid			loop_intf_comp_attr_objid;
	Objid			tunnel_intf_comp_attr_objid;
	Objid			aggr_intf_comp_attr_objid;
	int				num_physical_interfaces;
	int				num_loopback_interfaces;
	int				num_tunnel_interfaces;
	int				num_aggr_interfaces;
	} IpT_Intf_Info_Attrs;

typedef struct IpT_Rte_Proto_List_Cache_Entry
	{
	char*			rte_proto_str;
	List*			custom_rte_proto_label_lptr;
	List*			rte_proto_lptr;
	} IpT_Rte_Proto_List_Cache_Entry;

typedef struct IpT_Intf_Routing_Instance
	{
	char*			intf_name;
	char*			routing_instance_name;
	} IpT_Intf_Routing_Instance;

typedef struct IpT_Intf_Objid_Lookup_Tables
	{
	IpT_Intf_Name_Objid_Table_Handle	ipv6_table;
	IpT_Intf_Name_Objid_Table_Handle	rsvp_table;
	IpT_Intf_Name_Objid_Table_Handle	pim_table;
	IpT_Intf_Name_Objid_Table_Handle	igmp_table;
	} IpT_Intf_Objid_Lookup_Tables;

/***** Procedure Declarations *****/
static void					ip_dispatch_sv_init ();
static void					ip_dispatch_number_of_hops_update (IpT_Dgram_Fields* pk_fd_ptr);
static void					ip_stream_from_iface_index (int iface_index, int* in_stream_ptr, 
								int* out_stream_ptr, IpT_Interface_Type* interface_type_ptr);
static void					ip_local_dyn_route_protos_invoke (int protos, int invoke_flag, List* active_custom_rte_proto_label_lptr);
static void					ip_rtab_init (void);
static void					ip_rte_determine_lan_node_context (void);
static void					ip_rtab_local_network_register (InetT_Address* ip_net_addr_ptr);

static void					ip_networks_print (void);
static void					ip_interface_table_print (IpT_Rte_Module_Data* iprmd_ptr);

static void					ip_rtab_table_handle_register (void);
static void					ip_rtab_print (void);
static void					ip_dispatch_error (const char* msg);
static void					ip_dispatch_warn (const char *msg);
static IpT_Interface_Info*	ip_interface_info_create (int intf_type);
static void					ip_rte_stathandle_init ();
static void					ip_rte_qos_information_process (void);
extern int					ip_rtab_num_addrs_registered (void);
extern void					ip_rte_attr_config_info (void);
static void					ip_register_routerid_as_local_netaddr ();

static int*					ip_rte_protocol_ptr_create (int rte_protocol_id);
static List* 				ip_interface_routing_protocols_obtain (Objid intf_info_objid,
								Objid ipv6_attrs_objid, IpT_Interface_Status intf_status,
								List* active_custom_rte_proto_label_lptr);
static void					ip_dispatch_active_custom_routing_proto_list_populate (List* node_active_custom_rte_proto_label_lptr,
								List* intf_active_custom_rte_proto_label_lptr);
static IpT_Router_Id		ip_rte_router_id_calculate (void);
static int					ip_rte_as_number_get (void);
static void					ip_rte_igmp_host_create_init (void);
static void					ip_rte_igmp_rte_intf_create_init (double mcast_start_time);
static void					ip_rte_pim_sm_create_init (double mcast_start_time);
static void					ip_rte_custom_mrp_create_init (void);
static void					ip_rte_default_mcast_addr_register (void);
static void					ip_dispatch_default_networks_parse (void);
static void					ip_dispatch_default_gateway_configured_check (void);

static Boolean
ip_rte_car_profile_get (OmsT_Qm_Car_Profile** car_profile_pptr, 
	OmsT_Qm_Car_Information**  car_info_pptr, const char* direction, 
	IpT_QoS_Iface_Config* qos_iface_config_ptr);

static void					ip_rte_car_information_print ();
static IpT_Rte_Iface_QoS_Data* ip_rte_qos_data_create ();

static Prohandle			ip_rtab_phandle_from_intf_get (RsvpT_TC_Ici_Struct *	ici_data_struct_ptr);
static void					ip_rte_rsvp_init_notify (void);
static void 				ip_rte_datagram_higher_layer_forward (Packet *pk_ptr);

static void					ip_rte_icmp_init (void);
static void					ip_interface_table_verify (IpT_Rte_Module_Data* iprmd_ptr);

static void					ip_cmn_rte_table_export (void* data_ptr, int code);
static Boolean				ip_dispatch_ra_export_status_get (void);

static void					ip_dispatch_do_init (void);
static void					ip_dispatch_wait_for_registrations (void);
static void					ip_dispatch_init_phase_2 (void);
static void					ip_dispatch_distribute_routing_info (void);
static void					ip_dispatch_cleanup_and_create_child_processes (void);
static void					ip_dispatch_handle_mcast_rsvp (void);
static void 				ip_dispatch_forward_packet (void);
static void					ip_dispatch_default_route_process (char* default_rte_str, InetT_Addr_Family addr_family);
static void					ip_dispatch_vpn_init (void);
static void                 ip_dispatch_load_balancer_init ();
static void					ip_directly_connected_networks_insert (void);
EXTERN_C_BEGIN
static void					ip_global_rte_export (void* data_ptr, int code);
EXTERN_C_END
static IpT_Interface_Info*	ip_dispatch_find_intf_with_name (const char* intf_name, List* interface_lptr);
static char*				ip_rte_export_string (void);
static void					ip_dispatch_route_table_init (void);
static IpT_Intf_User_Metrics*	ip_intf_metrics_read (Objid intf_attr_objid, double data_rate);
static void					ip_dispatch_subintf_info_read (IpT_Interface_Info* parent_intf_ptr, Objid subintf_info_attr_objid, 
								IpT_Intf_Objid_Lookup_Tables* intf_objid_lookup_tables_ptr, int num_subinterfaces,
								List* active_custom_rte_proto_label_lptr, int lsp_signaling_protocol, 
								Boolean is_vlan_iface, List* routing_instance_lptr);
static void					ip_dispatch_intfs_count (IpT_Intf_Info_Attrs* intf_info_attrs_ptr);
static void					ip_dispatch_subintf_ip_version_check (IpT_Interface_Info* phys_intf_info_ptr);
static void					ip_dispatch_enable_ipv4_on_interface (IpT_Interface_Info* iface_info_ptr);
static void					ip_dispatch_enable_ipv6_on_interface (IpT_Interface_Info* iface_info_ptr);
static IpT_Intf_Name_Objid_Table_Handle
							ip_dispatch_intf_objid_lookup_table_build (const char* top_level_attr_name);
static void					ip_dispatch_intf_objid_lookup_table_destroy (IpT_Intf_Name_Objid_Table_Handle ipv6_intf_objid_table);
static void					ip_dispatch_gtwy_ipv6_attrs_read (Objid ipv6_attrs_objid, IpT_Interface_Info* iface_info_ptr);
static void					ip_dispatch_host_ipv6_attrs_read (Objid iface_description_objid, IpT_Interface_Info* iface_info_ptr);
static void					ip_dispatch_ipv6_auto_tunnel_attrs_set (IpT_Interface_Info* iface_info_ptr);
static IpT_Tunnel_Info*		ip_dispatch_tunnel_attrs_read (Objid iface_description_objid, char* iface_name);
static void					ip_dispatch_routing_options_add (List* routing_protocols_lptr);
static void					ip_directly_connected_networks_insert (void);
static void					ip_dispatch_layer2_mappings_read (IpT_Interface_Info* iface_info_ptr, Objid iface_description_objid);
static void					ip_dispatch_intf_table_create (int total_interfaces, int highest_instrm);
static void					ip_dispatch_strm_intrpt_handle (void);
static void					ip_dispatch_unnumbered_interfaces_resolve (void);
static IpT_Interface_Info*	ip_dispatch_unnumbered_src_intf_pick (void);
static void					ip_dispatch_fail_rec_handle (int intrpt_type);
static void	 				ip_misconfigured_node_check (void);

static 
IpT_Intf_Routing_Instance* 	ip_dispatch_intf_routing_instance_create (const char* intf_name, const char* vrf_name);
static void					ip_dispatch_mpls_info_read (void);
static void					ip_dispatch_interface_vpns_init (List* vrf_name_info_lptr);
static void					ip_dispatch_interface_mpls_init (void);
static void					ip_vrf_table_export (void* PRG_ARG_UNUSED(data_ptr), int PRG_ARG_UNUSED(code));

static Objid				ip_dispatch_intf_info_objid_get (int intf_index, const IpT_Intf_Info_Attrs* intf_info_attrs_ptr,
								IpT_Interface_Status* intf_status_ptr, int* addr_index_ptr);

static IpT_Tunnel_GRE_Params*	ip_dispatch_tunnel_gre_params_create (void);		
static IpT_Interface_Info*		ip_dispatch_find_intf_with_addr (InetT_Address ip_addr, List* intf_table_ptr);
static void						ip_dispatch_tunnel_passenger_protocols_read (Objid tunnel_info_objid, 
									IpT_Tunnel_Info* tunnel_info_ptr);
static void						ip_dispatch_tunnel_packet_process (Packet* ip_pkptr, IpT_Dgram_Fields* pkt_fields_ptr,
									Ici* intf_ici_ptr, IpT_Rte_Ind_Ici_Fields*	intf_ici_fdstruct_ptr);
static void						ip_dispatch_higher_layer_rsvp_forward (Packet* ip_pkptr, Ici* intf_ici_ptr);	
static void						ip_dispatch_bgutil_packet_process (Packet* pk_ptr, Ici* intf_ici_ptr, InetT_Address* dest_addr_ptr);
static void						ip_dispatch_incoming_packet_info_get (Packet* pk_ptr, IpT_Dgram_Fields** pkt_fields_pptr,
									Ici** intf_ici_pptr, IpT_Rte_Ind_Ici_Fields** intf_ici_fdstruct_ptr,
									Packet** ip_pptr, Boolean* ip_mcast_data_pkt_on_rte_ptr);
static void						ip_dispatch_igmp_child_invoke (Packet* ip_pkptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr);
static void 					ip_dispatch_send_packet_up (Packet* ip_pkptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr);	
static void						ip_dispatch_tunnel_rcvd_stats_write (IpT_Tunnel_Info* tunnel_info_ptr, Packet* pkptr,
									double decapsulation_delay, Boolean drop_pkt);

/* static void						ip_rrp_init (void);*/
static void						ip_manet_rte_mgr_init(void);

#if defined (__cplusplus)
extern "C" {
#endif

static int					ip_rte_proto_list_cache_compare (const void* cache_entry1, const void* cache_entry2);
static int					ip_dispatch_intf_compare_proc (const void* intf1_ptr, const void* intf2_ptr);

#if defined (__cplusplus)
} /* end of 'extern "C" {' */
#endif
static List*				ip_rte_proto_string_parse (char* routing_proto_str, List* active_custom_rte_proto_label_lptr);
static void					ip_dispatch_secondary_ip_addresses_read (IpT_Interface_Info* iface_info_ptr, Objid iface_objid);
static int					ip_dispatch_virtual_ifaces_add (int last_ip_index, int lsp_signaling_protocol, 
								IpT_Intf_Objid_Lookup_Tables* intf_objid_lookup_tables_ptr, List* routing_instance_lptr, List* active_custom_rte_proto_label_lptr);
static Boolean				ip_dispatch_switch_module_is_present (void);
static void					ip_dispatch_vlan_id_read (IpT_Interface_Info* iface_info_ptr, Objid attr_objid);

static void					ip_rsvp_qos_config_check (void);

static Boolean				ip_igmp_iface_enabled (IpT_Intf_Name_Objid_Table_Handle igmp_intf_objid_lookup_table,
								const char* iface_name);
static void					ip_dispatch_ipv6_ra_process_create (void);
static void					ip_dispatch_icmp_pk_higher_layer_forward (Packet* ip_pkptr, IpT_Dgram_Fields* pkt_fields_ptr,
								IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr);
static Boolean				ip_dispatch_member_intf_check (Objid iface_description_objid, const char* intf_name,
								int instrm, int outstrm, int addr_index, IpT_Interface_Status interface_status);
static IpT_Group_Intf_Info* ip_dispatch_aggregate_intf_attrs_read (Objid iface_description_objid, const char* iface_name);
static void					ip_dispatch_ppp_intf_set (void);
EXTERN_C_BEGIN
static void					ip_dispatch_endsim_tunnel_stats_write (void* state_ptr, int code);	
EXTERN_C_END

static Boolean				ip_node_dual_msfc_status_determine (void);
static int					ip_dispatch_dual_msfc_alt_config_parse (void);
static IpT_Interface_Info*	ip_dispatch_dual_msfc_alt_interface_parse (Objid intf_objid, Boolean loopback_intf);
static void					ip_directly_connected_networks_for_interface_handle (IpT_Interface_Info* interface_ptr, int intf_index, Boolean insert);


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
typedef struct
	{
	/* Internal state tracking for FSM */
	FSM_SYS_STATE
	/* State Variables */
	IpT_Rte_Module_Data	    		module_data                                     ;	/* State information that all children need to access  */
	Boolean	                		is_ip_initialized                               ;	/* Flag to indicate that the IP process if IP has   */
	                        		                                                	/* initialized its state variables.              */
	Prohandle	              		child_ptr                                       ;	/* Pointer to the WFQ child process  */
	ip_dgram_list *	        		dgram_list_ptr                                  ;
	int	                    		default_ttl                                     ;
	List*	                  		radio_intf_list_ptr                             ;
	List *	                 		slot_table_lptr                                 ;
	IpT_Info *	             		ip_info_ptr                                     ;
	Boolean	                		dynamic_routing_enabled                         ;
	List*	                  		link_iface_table_ptr                            ;
	OmsT_Pr_Handle	         		own_process_record_handle                       ;
	char	                   		proc_model_name [20]                            ;
	Objid	                  		comp_attr_objid                                 ;
	Objid	                  		subnet_objid                                    ;
	int	                    		interface_table_size                            ;
	int*	                   		slot_iface_map_array                            ;
	IpT_Iface_Addressing_Mode			iface_addressing_mode                           ;	/* Specifed the mode in which IP addresses need to be assigned  */
	int	                    		oms_basetraf_process_id                         ;	/* Process identifier for the OMS basetraf process running as a   */
	                        		                                                	/* child process of this IP process (this process is responsible  */
	                        		                                                	/* for generating background utilization tracer packets.          */
	IpT_Compression_Info*	  		tcpip_header_comp_info_ptr                      ;	/* Information about the compression scheme "TCP/IP Header  */
	                        		                                                	/* Compression". This pointer allows this access to the     */
	                        		                                                	/* decompression delay, compression delay. compression      */
	                        		                                                	/* distribution...                                          */
	IpT_Compression_Info*	  		per_interface_comp_info_ptr                     ;	/* Information about the compression scheme "Per-Interface  */
	                        		                                                	/* Compression". This pointer allows this access to the     */
	                        		                                                	/* decompression delay, compression delay. compression      */
	                        		                                                	/* distribution...                                          */
	IpT_Compression_Info*	  		per_virtual_circuit_comp_info_ptr               ;	/* Information about the compression scheme "Per-Virtual Circuit  */
	                        		                                                	/* Compression". This pointer allows this access to the           */
	                        		                                                	/* decompression delay, compression delay. compression            */
	                        		                                                	/* distribution...                                                */
	Prohandle	              		igmp_host_process_handle                        ;	/* The process handle for the IGMP Host process. This process  */
	                        		                                                	/* is created only if this node is not a multicast router     */
	Prohandle	              		pim_sm_process_handle                           ;	/* The process handle for the PIM-SM process. This process  */
	                        		                                                	/* is created only if this node is a multicast router      */
	Prohandle	              		custom_mrp_process_handle                       ;	/* The process handle for the Custom_Mrp process. This process  */
	                        		                                                	/* is created only if this node is a multicast router.         */
	Prohandle	              		routing_prohandle                               ;	/* Child process model taking care of core routing  */
	Prohandle	              		invoke_prohandle                                ;	/* If invoked from a child, handle of that child  */
	IpT_Rte_Mcast_Rte_Proto_Type			mcast_rte_protocol                              ;	/* The multicast routing protocol specified on this node.  */
	                        		                                                	/* By default, PIM-SM will be used.                  */
	Boolean	                		passive_rip                                     ;	/* Here to allow RIP to access the value  */
	List*	                  		crt_export_time_lptr                            ;	/* List to store the times at which common route table needs  */
	                        		                                                	/* to be printed, if enabled.                         */
	List*	                  		global_crt_export_time_lptr                     ;	/* List to store times all the routers in the network will dump there IP Route Table to a GDF file  */
	List*	                  		unknown_instrm_index_lptr                       ;	/* List of input stremas that could not be mapped to an interface   */
	                        		                                                	/* This list is used by the ip_dispatch_strm_index_handle function  */
	                        		                                                	/* to make sure that we do not write a log message about the same  */
	                        		                                                	/* input stream twice.                                  */
	IpT_Rte_Info*	          		static_rte_info                                 ;
	char	                   		ad_hoc_routing_protocol_str [32]                ;	/* The type of ad-hoc routing protocol running on this node  */
	List*	                  		vrf_export_time_lptr                            ;
	} ip_dispatch_smf_state;

#define pr_state_ptr            		((ip_dispatch_smf_state*) (OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))
#define module_data             		pr_state_ptr->module_data
#define is_ip_initialized       		pr_state_ptr->is_ip_initialized
#define child_ptr               		pr_state_ptr->child_ptr
#define dgram_list_ptr          		pr_state_ptr->dgram_list_ptr
#define default_ttl             		pr_state_ptr->default_ttl
#define radio_intf_list_ptr     		pr_state_ptr->radio_intf_list_ptr
#define slot_table_lptr         		pr_state_ptr->slot_table_lptr
#define ip_info_ptr             		pr_state_ptr->ip_info_ptr
#define dynamic_routing_enabled 		pr_state_ptr->dynamic_routing_enabled
#define link_iface_table_ptr    		pr_state_ptr->link_iface_table_ptr
#define own_process_record_handle		pr_state_ptr->own_process_record_handle
#define proc_model_name         		pr_state_ptr->proc_model_name
#define comp_attr_objid         		pr_state_ptr->comp_attr_objid
#define subnet_objid            		pr_state_ptr->subnet_objid
#define interface_table_size    		pr_state_ptr->interface_table_size
#define slot_iface_map_array    		pr_state_ptr->slot_iface_map_array
#define iface_addressing_mode   		pr_state_ptr->iface_addressing_mode
#define oms_basetraf_process_id 		pr_state_ptr->oms_basetraf_process_id
#define tcpip_header_comp_info_ptr		pr_state_ptr->tcpip_header_comp_info_ptr
#define per_interface_comp_info_ptr		pr_state_ptr->per_interface_comp_info_ptr
#define per_virtual_circuit_comp_info_ptr		pr_state_ptr->per_virtual_circuit_comp_info_ptr
#define igmp_host_process_handle		pr_state_ptr->igmp_host_process_handle
#define pim_sm_process_handle   		pr_state_ptr->pim_sm_process_handle
#define custom_mrp_process_handle		pr_state_ptr->custom_mrp_process_handle
#define routing_prohandle       		pr_state_ptr->routing_prohandle
#define invoke_prohandle        		pr_state_ptr->invoke_prohandle
#define mcast_rte_protocol      		pr_state_ptr->mcast_rte_protocol
#define passive_rip             		pr_state_ptr->passive_rip
#define crt_export_time_lptr    		pr_state_ptr->crt_export_time_lptr
#define global_crt_export_time_lptr		pr_state_ptr->global_crt_export_time_lptr
#define unknown_instrm_index_lptr		pr_state_ptr->unknown_instrm_index_lptr
#define static_rte_info         		pr_state_ptr->static_rte_info
#define ad_hoc_routing_protocol_str		pr_state_ptr->ad_hoc_routing_protocol_str
#define vrf_export_time_lptr    		pr_state_ptr->vrf_export_time_lptr

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#  define FIN_PREAMBLE_DEC	ip_dispatch_smf_state *op_sv_ptr;
#if defined (OPD_PARALLEL)
#  define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((ip_dispatch_smf_state *)(sim_context_ptr->_op_mod_state_ptr));
#else
#  define FIN_PREAMBLE_CODE	op_sv_ptr = pr_state_ptr;
#endif


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

/* Transition Executives */

static void
ip_dispatch_do_init (void)
	{
	int		scheme = 0;
	int		status;
	Objid	ip_proc_info_objid, compound_objid;
	Objid	ip_multicast_info_objid;
	Objid	ip_acl_config_objid;
    Objid	compound_attr_objid;
	Boolean	mcast_router;
	char	vendor_name_str [64];
	char	system_objid_str [64];
	char	machine_type_str [64];
	char	os_info_str [64];
	OpT_Sim_Selfdesc_Characteristic_Type   	vendor_search_type;
	
	
	FIN (ip_dispatch_do_init ());

	/* Initialize the flags */
	module_data.flags					= 0;

	/* Prepare the fake model state shared by the various children */
	op_pro_modmem_install (&module_data);
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);
	
	/* Initialize the default routes (v4 and v6) to invalid.	*/
	module_data.default_route_addr_array [InetC_Addr_Family_v4] = INETC_ADDRESS_INVALID;
	module_data.default_route_addr_array [InetC_Addr_Family_v6] = INETC_ADDRESS_INVALID;
	module_data.default_route_intf_index_array [InetC_Addr_Family_v4] = IPC_MCAST_MAJOR_PORT_INVALID;
	module_data.default_route_intf_index_array [InetC_Addr_Family_v6] = IPC_MCAST_MAJOR_PORT_INVALID;

	/* Initialize the IP address package.							*/
	ip_address_pkg_initialize ();
		
	/* Initialize the IP datagram package.							*/
	ip_dgram_package_init ();

	/* Initialize the ICMP packet package.							*/
	ip_icmp_pk_package_init ();

	/* Initialize important state variables for this process.		*/
	ip_dispatch_sv_init ();
	
	/* Initialize the global address table.							*/
	ip_rtab_init ();
	
	/* Initialize statistic handles to be used for collecting IP	*/
	/* layer statistics.											*/
	ip_rte_stathandle_init ();
	
	/* Initialize the Sim. Log notification handles that will be	*/
	/* used in this process model. This initialization is done via	*/
	/* an external C file.											*/
	ip_notif_log_handles_init ();
	
	/* The interface table pointer is made available to other		*/
	/* processes by registering it in the model-wide registry.		*/
	/* Allocate memory for the data structure used to store this	*/
	/* information and set the interface table information.			*/
	ip_info_ptr = (IpT_Info *) op_prg_mem_alloc (sizeof (IpT_Info));
	ip_info_ptr->ip_iface_table_ptr = module_data.interface_table_ptr;
	
	/* Determine whether the IP is using slots, which have their 	*/
	/* own CPUs and buffers, or it has only one centralized CPU 	*/
	/* and buffer.													*/
	status = op_ima_obj_attr_get (module_data.module_id,
		"ip processing information", &ip_proc_info_objid);
	if (status == OPC_COMPCODE_FAILURE)
		ip_dispatch_error ("Unable to get ip processing information from attribute");
	compound_objid = op_topo_child (ip_proc_info_objid, OPC_OBJTYPE_GENERIC, 0);
	status = op_ima_obj_attr_get (compound_objid, "Processing Scheme", &scheme);
	if (scheme == 0)
		module_data.processing_scheme = OmsC_Dv_Centralized;
	else 
		module_data.processing_scheme = OmsC_Dv_Slot_Based;
	
	/* Check out whether the node containing this IP module is		*/
	/* configured as a firewall. If it is a firewall, then also		*/
	/* build proxy server information table.						*/
	module_data.proxy_info_table_lptr = OPC_NIL;
	if (oms_dv_device_is_firewall (module_data.node_id, &module_data.proxy_info_table_lptr))
		module_data.flags |= IPC_NODE_FLAG_FIREWALL;  
	
	/* Check whether the packet latency compound attribute is 		*/
	/* present on the surrounding node. If so, then the node is 	*/
	/* assumed to be an IP cloud object. 							*/
	if (oms_dv_device_is_ipcloud (module_data.node_id, module_data.module_id))
		module_data.flags |= IPC_NODE_FLAG_CLOUD;

	/* The rest of IP cloud-related initializations are performed	*/
	/* by the IP cloud child process model.							*/
	
	/*	Determine whether this IP node is a gateway.				*/
	status = op_ima_obj_attr_get (module_data.module_id, "gateway", 
		&module_data.gateway_status);
    if (status == OPC_COMPCODE_FAILURE)
		ip_dispatch_error ("Unable to get gateway status from attribute.");

	module_data.ip_parameters_objid = ip_rte_parameters_objid_obtain (OPC_OBJID_NULL,
		module_data.module_id, &module_data.gateway_status);
	
	/* Get the object ID of the IPv6 Parameters objid. Note that	*/
	/* attribute will be used only for gateway nodes.				*/
	op_ima_obj_attr_get (module_data.module_id, "ipv6 parameters", &compound_attr_objid);
	module_data.ipv6_params_objid = op_topo_child (compound_attr_objid, OPC_OBJTYPE_GENERIC, 0);

	/* Obtain the ip qos attribute objid and store it in module data. */
	status = op_ima_obj_attr_get (module_data.module_id, "ip qos parameters" , &compound_attr_objid);
	 if (status == OPC_COMPCODE_FAILURE)
		ip_dispatch_error ("Unable to get the IP QoS Parameters compound attribute.");

	module_data.ip_qos_params_objid = op_topo_child (compound_attr_objid, OPC_OBJTYPE_GENERIC, 0);
	 if (module_data.ip_qos_params_objid == OPC_OBJID_INVALID)
		ip_dispatch_error ("Unable to get the IP QoS Parameters attribute.");
	
	/* Also store the objid of the interface information attribute	*/
	op_ima_obj_attr_get (module_data.ip_parameters_objid, "Interface Information", &(module_data.intf_info_objid));

	/*	Obtain the name of the process. It is the "process model"	*/
	/*	attribute of the module.									*/
	op_ima_obj_attr_get (module_data.module_id, "process model", proc_model_name);
	
	/*	Register the process in the model-wide registry.			*/
	own_process_record_handle = (OmsT_Pr_Handle) oms_pr_process_register 
		(module_data.node_id, module_data.module_id, 
		 module_data.ip_root_prohandle, proc_model_name);
	
	/*	Create the list of multicast addresses this node can		*/
	/*	handle -- publish that list through the process registry.	*/
	module_data.mcast_addr_list_ptr = op_prg_list_create ();
	
	/* Create list to store radio interfaces for this node.	*/
	radio_intf_list_ptr = op_prg_list_create ();
	
	/*	Register the following attributes in the process registery:	*/
	/*		1. subnet information -- to allow gateways in the local	*/
	/*		   OPNET subnet to be found.							*/
	/*		2. protocol -- which is "ip" in this case				*/
	/* 		3. the address information maintained by this process	*/
	/*		4. multicast addresses list handles by this node		*/
	/*		5. The radio interface list, used by the auto assignmet */
	/*         procedure, will be destroyed after IP Auto Assignment*/
	/*		   is completed. (exit exec of Wait state)				*/
	/*		6. module information -- to allow applications to		*/
	/*		   register multicast addresses using remote interrupt	*/
	oms_pr_attr_set (own_process_record_handle, 
		"subnet",					OMSC_PR_OBJID,		subnet_objid, 
		"protocol",					OMSC_PR_STRING,		"ip", 
		"address",					OMSC_PR_POINTER,	&module_data.interface_table_ptr,
		"interface information", 	OMSC_PR_POINTER,	ip_info_ptr,
		"multicast address list",	OMSC_PR_POINTER,	module_data.mcast_addr_list_ptr,
		"radio interface list",		OMSC_PR_POINTER,	radio_intf_list_ptr,
		"module objid", 			OMSC_PR_OBJID,		module_data.module_id,
		"module data",				OMSC_PR_POINTER,	&module_data,
		"instrm from ip_encap",		OMSC_PR_NUMBER,		(double) (module_data.instrm_from_ip_encap),
		OPC_NIL);
	
	/* If this is a gateway node, read gateway specific attributes */
	if (module_data.gateway_status == OPC_TRUE)
		{
		oms_pr_attr_set (own_process_record_handle, 
			"gateway node",	OMSC_PR_STRING,	"gateway", 
			OPC_NIL);
		
		/* Build the table holding the Access Control Lists for this router */
		op_ima_obj_attr_get (module_data.ip_parameters_objid,
			"Extended ACL Configuration", &ip_acl_config_objid);
		module_data.acl_ext_table = Inet_Acl_Table_Create (ip_acl_config_objid, IpC_Acl_Type_Ext, &module_data);
		
		/* Parse Standard ACLs also.							*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid,
			"Standard ACL Configuration", &ip_acl_config_objid);
		module_data.acl_std_table = Inet_Acl_Table_Create (ip_acl_config_objid, IpC_Acl_Type_Std, &module_data);

		/* Parse IPv6 access lists also.						*/
		op_ima_obj_attr_get (module_data.ipv6_params_objid,
			"ACL Configuration", &ip_acl_config_objid);
		module_data.acl_ipv6_ext_table = Inet_Acl_Table_Create (ip_acl_config_objid, IpC_Acl_Type_IPv6_Ext, &module_data);

		/* Build the table holding the Prefix Lists for this router */
		op_ima_obj_attr_get (module_data.ip_parameters_objid,
			"Prefix Filter Configuration", &ip_acl_config_objid);
		module_data.acl_pre_table = Ip_Acl_Table_Create (ip_acl_config_objid, IpC_Acl_Type_Pre, &module_data);
		
		/* Parse IPv6 prefix lists also.						*/
		op_ima_obj_attr_get (module_data.ipv6_params_objid,
			"Prefix Filter Configuration", &ip_acl_config_objid);
		module_data.acl_ipv6_pre_table = Ip_Acl_Table_Create (ip_acl_config_objid, IpC_Acl_Type_IPv6_Pre, &module_data);
		
		/* Parse filter type ACL table (for PIX nodes.	*/
		module_data.acl_filter_ext_table = ip_pix_acl_table_build (&module_data);

		/* This is not applicable to gateway nodes */
		passive_rip = OPC_FALSE;
		
		/* Only gateway nodes are capable of MPLS.	*/
		ip_dispatch_mpls_info_read ();

		/* We need to find out the number of traffic demands	*/
		/* originating at this node. This information will be	*/
		/* used for estimating the hash table size in the IP	*/
		/* common route table.									*/
		ip_num_gateway_demands += op_topo_assoc_count
			(module_data.node_id, OPC_TOPO_ASSOC_OUT,OPC_OBJTYPE_DEMAND_FLOW);
		}
	else
		{
		/* If this is not gateway node, read the "Passive RIP Routing"	*/
		/* attribute to determine if the node will be using RIP for		*/
		/* routing decisions.											*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, 
			"Passive RIP Routing", &passive_rip);

		/* Check if any MANET Routing protocols have been enabled	*/
		op_ima_obj_attr_get (module_data.module_id, "manet_mgr.AD-HOC Routing Protocol", &ad_hoc_routing_protocol_str);
		
		/* Increment the number of host nodes in the network.	*/
		/* This information will be used for estimating the		*/
		/* size of the hash table in the IP common route table.	*/
		++ip_num_host_nodes;
		}
	
	/* Store that in module data for faster access during xmit	*/
	/* Still needed as a state variable to allow other modules	*/
	/* such as RIP to access its value.							*/
	module_data.passive_rip_ptr = &passive_rip;
	
	/*	A global address table is used to associate IP addresses	*/
	/*	with the corresponding lower layer address. This table is	*/
	/*	is managed by the NATO sub-package and optimizes address	*/
	/*	conversion table lookup. The IP routing process registers	*/
	/*	addresses in this table and makes it available (e.g., to 	*/
	/*	the IP ARP process) via process registry.					*/
	ip_rtab_table_handle_register ();
	
	/*	Schedule a self interrupt at the current time to let all	*/
	/*	the ip modules resolve their IP addresses. This involves	*/
	/*	assigning unique addresses and making sure that these are	*/
	/*	unique. Note that dynamically assigned addresses may change	*/
	/*	until all the statically assigned addresses have been		*/
	/*	checked for uniqueness.										*/
	op_intrpt_schedule_self (op_sim_time (), 0);
	
	/*	Create an ICI for communicating destination addresses to	*/
	/*	the address resultion protocol (ARP)						*/
	module_data.arp_iciptr = op_ici_create ("ip_arp_req_v4");
	if (module_data.arp_iciptr == OPC_NIL)
		ip_dispatch_error ("Unable to create ICI for communication with ARP.");
	
	/* Initialize the arp_next_hop_addr to an invalid value.		*/
	module_data.arp_next_hop_addr = INETC_ADDRESS_INVALID;

	/* Set the next_addr field in the ARP ici to the arp next hop	*/
	/* address variable. This way we won't have to dynamically		*/
	/* allocate memory for an InetT_Address strucutre every time	*/
	/* we need to use the ICI.										*/
	op_ici_attr_set_ptr (module_data.arp_iciptr, "next_addr", &(module_data.arp_next_hop_addr));

#ifndef OPD_NO_DEBUG
	/* Register a print proc for the next_addr_field.				*/
	op_ici_format_print_proc_set ("ip_arp_req_v4", "next_addr", inet_address_ici_field_print);
#endif

	/*	Create a datagram list to store datagram fragments until	*/
	/*	the complete datagram can be constructed.					*/
	dgram_list_ptr = ip_frag_sup_setup ();
	
	/* Read the simulation attribute "IP Routing Table Export/Import" 	*/
	/* The global var. into which this value is store, is initialized	*/
	/* to IP_RTE_TABLE_NON_DET. Checking for this value, eliminates 	*/
	/* multiple calls to op_ima_sim_attr_get ().						*/
	if (routing_table_import_export_flag == IP_RTE_TABLE_NON_DET)
		routing_table_import_export_flag = ip_rte_imp_exp_sim_attr_get (OPC_FALSE);
	
	/* Indicate that the IP process has been initialized.				*/
	is_ip_initialized = OPC_TRUE;
	
	/* Initialize the value of the unnumbered interface flags			*/
	module_data.unnumbered_interface_exists	= OPC_FALSE;
	
	status = op_ima_obj_attr_get (module_data.module_id,
		"ip multicast information", &ip_multicast_info_objid);
	if (status == OPC_COMPCODE_FAILURE)
		ip_dispatch_error ("Unable to get ip multicast information from attribute");
	compound_objid = op_topo_child (ip_multicast_info_objid, OPC_OBJTYPE_GENERIC, 0);
	
	/* Determine whether this node is a multicast router	*/
	status = op_ima_obj_attr_get (compound_objid, "Multicast Routing",	&mcast_router);
    if (status == OPC_COMPCODE_FAILURE)
		ip_dispatch_error ("Unable to get multicast router status (Multicast Routing) from attribute.");
	else if (mcast_router)
		module_data.flags |= IPC_NODE_FLAG_MCAST_ROUTER;
	
	/* Obtain the "multicast routing protocol" specified in the model attribute.	*/
	status = op_ima_obj_attr_get (compound_objid, "Multicast Routing Protocol",
	   	&mcast_rte_protocol);
   	if (status == OPC_COMPCODE_FAILURE)
		ip_dispatch_error ("Unable to get multicast routing protocol attribute.");
	
	/* Initialize the list of input streams that could not be mapped*/
	/* to an interface to OPC_NIL.									*/
	unknown_instrm_index_lptr = OPC_NIL;
	
	/* Get the vendor name information for this node				*/
	if (OPC_COMPCODE_FAILURE == op_ima_obj_selfdesc_characteristic_get (module_data.node_id, "Vendor", 64, vendor_name_str, &vendor_search_type))
		strcpy(vendor_name_str, "");
		
	if (OPC_COMPCODE_FAILURE == op_ima_obj_selfdesc_characteristic_get (module_data.node_id, "System Object ID", 64, system_objid_str, &vendor_search_type))
		strcpy(system_objid_str, "");
		
	if (OPC_COMPCODE_FAILURE == op_ima_obj_selfdesc_characteristic_get (module_data.node_id, "machine type", 64, machine_type_str, &vendor_search_type))
		strcpy(machine_type_str, "");

	/* For Firewall use the "System Object ID" to determine Vendor */
	if (strstr(machine_type_str, "firewall") != OPC_NIL)
		{
		if (strstr(system_objid_str, "Cisco") != OPC_NIL)
			strcpy(vendor_name_str, "Cisco PIX");
		else if (strstr(system_objid_str, "Check Point") != OPC_NIL)
			strcpy(vendor_name_str, "Check Point");
		}
	
	if (0 != strcmp(vendor_name_str, ""))
		{
		/* Allocate memory for vendor name and store the value		*/
		module_data.vendor_name = (char *) op_prg_mem_alloc (sizeof (char) * (strlen (vendor_name_str) + 1));
		strcpy (module_data.vendor_name, vendor_name_str);
		}
	else
		module_data.vendor_name = OPC_NIL;

	/* Initialize the OS version									*/
	module_data.os_version_str = OPC_NIL;
		
	/* Get the OS Version											*/
	if (op_ima_obj_attr_exists (module_data.node_id, "Router OS Version"))
		{
		op_ima_obj_attr_get (module_data.node_id, "Router OS Version", os_info_str);
		if (strcmp (os_info_str, "Not Configured") != 0)
			{
			/* Allocate memory for OS version and store the value	*/
			module_data.os_version_str = (char *) op_prg_mem_alloc (sizeof (char) * (strlen (os_info_str) + 1));
			strcpy (module_data.os_version_str, os_info_str);
			}
		}
			
	/* Now add an entry corresponding to this node in the hash table*/
	/* Used to do the mapping between the node objid and the 		*/
	/* module data pointer.											*/
	ip_support_module_data_htable_entry_add (&module_data);

	/* Determine whether this node is a dual MSFC operating in dual router mode.	*/
	/* IP, HSRP, BGP etc. will have to handle such devices in a different way.		*/
	if (OPC_TRUE == ip_node_dual_msfc_status_determine ())	
		module_data.flags |= IPC_NODE_FLAG_DUAL_MSFC_DRM;

	FOUT;
	}

static void
ip_global_rte_export (void* PRG_ARG_UNUSED(data_ptr), int code)
	{
	List *				exp_time_lptr;	
	int					file_index = 1;
	FILE*				file_ptr;
	char*				file_name;
	char*				message_string;
	double*				exp_time_ptr;
	
	FIN (ip_global_rte_export (void));
	
	/* The first call to this function will set code = 0 */
	/* all other calls will set the code = 1 			 */
	if (code == 0)
		{		
		/* First check to see if a global route table export   */
		/* has been configured through the IP Attribute object */
		exp_time_lptr = (List *) oms_data_def_entry_access ("IP Global Route Export Table", "IP Global Route Export");
		
		if (exp_time_lptr != OPC_NIL)
			{
			/* There are configurations for a global export of the IP Route Tables  */
			/* Initialize the local List that will hold the export times */
			global_crt_export_time_lptr = op_prg_list_create ();
			
			/* Copy the list from the IP Attribute into the local List */
			op_prg_list_elems_copy (exp_time_lptr, global_crt_export_time_lptr);
			
			/* Remove the first export time from the local List and schedule the first export */
			exp_time_ptr = (double *) op_prg_list_remove (global_crt_export_time_lptr, OPC_LISTPOS_HEAD);
			
			if (*exp_time_ptr == OPC_DBL_INFINITY)
				*exp_time_ptr = OPC_INTRPT_SCHED_CALL_ENDSIM;
	
			/* Schedule the first call to print out the route tables */
			op_intrpt_schedule_call (*exp_time_ptr, 1, ip_global_rte_export, OPC_NIL);
			}
		}
	else
		/* This call is to print out the route table to the .gdf file */
		{
		/* Create the file name for the first export							*/
		file_name = ip_cmn_rte_global_exp_file_create ();
		
		/* Open the  file for to append the IP Common Route for this node */
		file_ptr = fopen (file_name, "a");
		
		/* Print out a header for the specifying this router */
		fprintf (file_ptr, "IP Common Route Table for router: (%s)\n\n", module_data.node_name);
		
		/* Get the string that contains the route table export and print it to the file */
		message_string = ip_rte_export_string ();
		fprintf (file_ptr, message_string);
		fprintf (file_ptr, "\n\n\n");
		
		fclose (file_ptr);
		
		/* Free the memory allocated to the routing table string		*/
		op_prg_mem_free (message_string);

		/* Check the export list for more entries and recall export function if necessary */
		if (op_prg_list_size (global_crt_export_time_lptr) > 0)
			{
			/* Get the time for the next export to occur */
			exp_time_ptr = (double *) op_prg_list_remove (global_crt_export_time_lptr, OPC_LISTPOS_HEAD);
			
			if (*exp_time_ptr == OPC_DBL_INFINITY)
				*exp_time_ptr = OPC_INTRPT_SCHED_CALL_ENDSIM;
			
			/* Index the file name to differentiate the gdf files */
			file_index++;
	
			/* Schedule the first call to print out the route tables */
			op_intrpt_schedule_call (*exp_time_ptr, 1, ip_global_rte_export, OPC_NIL);
			}
		}
	
	FOUT;
	}
		
 
static char *
ip_rte_export_string (void)
	{
	char *						message_string;
	
	IpT_Cmn_Rte_Table_Entry*	route_entry;
	int							i_th_entry;
	char						temp_string [1000];
    char						dest_prefix_str [INETC_ADDR_STR_LEN];
    char						next_hop [IPC_ADDR_STR_LEN];
    char						rte_protocol [256];
    int							i_th_rte, num_routes;
	int							num_entries;
	int							max_int;
    IpT_Next_Hop_Entry*			next_hop_ptr;
	InetT_Address				gateway_of_last_resort;
	int							message_string_len;
	char						unknown_intf_name [] = "Unknown";
	const char*					intf_name;
	int							addr_family;

	FIN (ip_rte_export_string (void));
	
	/* This is an interrupt where we need to export routing table.	*/

	/* Set the max double as int */
	max_int = (int) INFINITE_METRIC;
	
	/* Allocate size for message string  */
	/* and initialize it to a null string*/
	message_string = (char *) op_prg_mem_alloc (sizeof (char) * 1000001);
	strcpy (message_string, "");
	
	/* Export both IPv4 and IPv6 routes.								*/
	for (addr_family = 0; addr_family < IPC_NUM_ADDR_FAMILIES; addr_family++)
		{
		/* Determine the number of entries in the common routing table.	*/
		num_entries = ip_cmn_rte_table_num_entries_get (module_data.ip_route_table, addr_family);

		/* Print out the column headings first.             			*/
		strcpy (temp_string, "\n\n  Dest. Address/Mask Length             Next Hop                  Interface Name    Metric      Protocol    Insertion Time\n");
		strcat (message_string, temp_string);
		strcpy (temp_string, "  -------------------------             -----------               ---------------    ------      --------    --------------\n\n");
		strcat (message_string, temp_string);
		
		/* Keep track of the length of the message_string to make sure it	*/
		/* doesn't exceed the limit.										*/
		message_string_len = strlen (message_string);

		if (num_entries == 0)
			{
			/* Check if the addr family is IPv4 or IPv6						*/
			if (addr_family == InetC_Addr_Family_v4)
				strcpy (temp_string, "\t\t\tThere are zero entries in the IPv4 routing table.\n");
			else if (addr_family == InetC_Addr_Family_v6)
				strcpy (temp_string, "\t\t\tThere are zero entries in the IPv6 routing table.\n");
					
			/* Concatenate the new string								*/
			strcat (message_string, temp_string);
			}
		else
			{
			/* Loop over the route table for further processing */
			for (i_th_entry = 0; i_th_entry < num_entries; i_th_entry++)
				{
				/* Access the i'th entry in the route table.    */
				route_entry = ip_cmn_rte_table_access (
					module_data.ip_route_table, i_th_entry, addr_family);
				
				/* Determine routing protocol for this entry.	*/
				ip_cmn_rte_proto_name_print (rte_protocol, route_entry->route_src_proto);

				/* Create temporary strings for printing destination-specific	*/
				/* information.													*/
				ip_cmn_rte_table_dest_prefix_print (dest_prefix_str, route_entry->dest_prefix);

				/* Obtain the next hop information.	*/
				num_routes = op_prg_list_size (route_entry->next_hop_list);
				if (num_routes == 0)
					{					
					/* Insert this information in the output list.  */
					sprintf (temp_string, "  %-36s  %s\n",
						dest_prefix_str, "*** No next hop information is available for this destination ***");
					}
				else
					{
					/* Loop thorugh the available routes.	*/
					for (i_th_rte = 0; i_th_rte < num_routes; i_th_rte++)
						{
						next_hop_ptr = (IpT_Next_Hop_Entry *) op_prg_list_access (route_entry->next_hop_list, i_th_rte);
						inet_address_print (next_hop, next_hop_ptr->next_hop);

						/* Get the interface name.						*/
						intf_name =  ip_rte_port_info_intf_name_get (&(next_hop_ptr->port_info), &module_data);
						if (OPC_NIL == intf_name)
							intf_name = unknown_intf_name;
						
						/* Get the next hop name */
						if (next_hop_ptr->port_info.intf_tbl_index == IPC_INTF_TBL_INDEX_NULL0)
							strcpy (next_hop, "<N/A>");
						else if (next_hop_ptr->port_info.intf_tbl_index == IPC_INTF_TBL_INDEX_LSP)
							strcpy (next_hop, "<LSP>");
						else
							inet_address_print (next_hop, next_hop_ptr->next_hop);
						
						/* Insert this information in the output list.  */
						if (i_th_rte == 0)
							{
							if (next_hop_ptr->route_metric != max_int && next_hop_ptr->route_metric != -1)
								{
								sprintf (temp_string, "  %-36s  %-25s  %-15s   %-9d    %-9s        %.3f\n",
									dest_prefix_str, next_hop, intf_name,
									next_hop_ptr->route_metric, rte_protocol, next_hop_ptr->route_insert_time);
								}
							else
								{
								sprintf (temp_string, "  %-36s  %-25s  %-15s   %-9s    %-9s        %.3f\n",
									dest_prefix_str, next_hop, intf_name,
									"Infinite", rte_protocol, next_hop_ptr->route_insert_time);
								}
							}
						else
							{
							if (next_hop_ptr->route_metric != max_int && next_hop_ptr->route_metric != -1)
								{
								sprintf (temp_string, "  %-36s  %-25s  %-15s   %-9d    %-9s        %.3f\n",
									" ", next_hop, intf_name,
									next_hop_ptr->route_metric, rte_protocol, next_hop_ptr->route_insert_time);
								}
							else
								{
								sprintf (temp_string, "  %-36s  %-25s  %-15s   %-9s    %-9s        %.3f\n",
									dest_prefix_str, next_hop, intf_name,
									"Infinite", rte_protocol, next_hop_ptr->route_insert_time);
								}
							}
						/* Copy the temporary string in a message buffer to be printed.	*/
						if ((message_string_len += strlen (temp_string)) < 1000000)
							strcat (message_string, temp_string);
						else
							break;
						}
					
					}
				}
			}
		}
	
	/* If the default route is set print out that information also.			*/
	if (OPC_NIL != module_data.ip_route_table->gateway_of_last_resort)
		{
		gateway_of_last_resort = inet_cmn_rte_table_entry_hop_get
			(module_data.ip_route_table->gateway_of_last_resort, 0, OPC_NIL);
		inet_address_print (next_hop, gateway_of_last_resort);
		sprintf (temp_string, "\nThe gateway of last resort is set to %s\n", next_hop);

		if ((message_string_len += strlen (temp_string)) < 1000000)
			strcat (message_string, temp_string);
		}
	else if ((message_string_len += 45) < 1000000)
		{
		strcat (message_string, "\nThe gateway of last resort is not set\n");
		}

	FRET (message_string);
	}

static void
ip_dispatch_wait_for_registrations (void)
	{
	/**************************************************************************/
	/**	At this time, it is assured that all IP and IPX processes in the model*/
	/** have registered themselves in the Process Registry. With the		  */
	/** possibility that an IPX stack may coexist with this IP stack, it is	  */
	/** necessary to wait for registration to happen before building the 'link*/
	/** interface table'. This is because, walking the node's topology from a */
	/**	transceiver to the IP module (given that an IPX stack is present) will*/
	/** find MULTIPLE PATHS to the IP module where the last stream used to	  */
	/** reach the IP module will have the 'ipx addr index' extended attribute.*/
	/** In order to eliminate this ambiguity, it is necessary to eliminate	  */
	/** traversing all paths to the IP module through an INTERMEDIATE IPX	  */
	/** module. And locating the intermediate IPX module involves identifying */
	/** its presence from the Process Registry.								  */
	/**************************************************************************/
	FIN (ip_dispatch_wait_for_registrations (void));
	
	/* Set error/warning error procedures */
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);

	/* Call the function that would ckeck for any kind of	*/
	/* misconfiguration resulting from incorrect number of	*/
	/* rows under the Interface information attribute. If	*/
	/* a misconfiguration is detected, we write out a sim	*/
	/* log message and set a global flag to indicate this	*/
	/* condition. We do not terminate the simulation		*/
	/* immediately in order to allow all such nodes to log	*/
	/* simulation log messages.								*/
	if (module_data.gateway_status == OPC_TRUE)
		{
		ip_misconfigured_node_check ();
		}

	/* Check the existence of ip attribute object. We will read the compression*/
	/* information for each interface from the attribute database. The special*/
	/* object defines all the compession informaiton. Although this function  */
	/* gets called from each IP process instance in the network, functionally */
	/* it only gets executed only once for each simulation.					  */
	ip_rte_attr_config_info ();
	
	/* Initialize the OT file												*/
	Oms_Ot_File_Init ();
	
	/* Initialize the security ot file									 	*/		
	ip_security_ot_file_init ();

	/* Check if the surrounding node is acting like a LAN node. This is needed*/
	/* because if this surrounding node is a LAN object, then all the packets */
	/* received from the higher layer will be forwarded to the lower layer	  */
	/* (which may forward it back to the higher layer, if it is destined for  */
	/* the same node.) If the node is not a LAN object, then higher layer	  */
	/* packets destined	the same node will be directly sent to the higher layer*/
	ip_rte_determine_lan_node_context ();
	
	/* Build a table relating the process' interfaces to the links attached to*/
	/* the node.  This is used, among other potential purposes, for the auto-*/
	/* addressing capability.  Since mobile and satellite nodes do not support*/
	/* point-to-point or bus link connections, such a table is not built for*/
	/* those type of nodes. Build the table only if this is a fixed node.	*/
	link_iface_table_ptr = op_prg_list_create ();
	if (op_id_to_type (module_data.node_id) == OPC_OBJTYPE_NDFIX)
		{
		ip3_link_iface_table_build (module_data.node_id, link_iface_table_ptr);
		}
	
	/* Create the list that will contain the radio interfaces.				*/
	ip3_radio_iface_table_build (module_data.node_id, radio_intf_list_ptr, module_data.ip_parameters_objid);

	/* Detect if the current node is a UMTS GGSN node. GTP protocol must 	*/
	/* be initialized in that case.											*/
	umts_gtp_support_ggsn_init (&module_data);
	
	/* Registering the node as radio ip node if it has one or more radio	*/
	/* interfaces.															*/
	if (op_prg_list_size (radio_intf_list_ptr) != 0)
		{
		oms_pr_attr_set (own_process_record_handle, 
		"protocol type",	OMSC_PR_STRING,	 "radio ip", OPC_NIL);
		}
	
	/* Schedule a self interrupt to start auto addressing phase of this process	*/
	op_intrpt_schedule_self (op_sim_time (), 0);
	
	/* Initialize the flag to indicate that in the interface structure no	*/
	/* router id has been assigned till now.								*/
	module_data.router_id_assigned = OPC_FALSE;
	
	/* Check to see if there is the possibility of background traffic */
	if (oms_basetraf_set_bgutil_for_demands())
		module_data.do_bgutil = OPC_TRUE; 
	else
		module_data.do_bgutil = OPC_FALSE; 
	
	FOUT;
	}


static void
ip_dispatch_init_phase_2 (void)
	{
	/* Flag to track whether any ip addresses have been		*/
	/* created on this node.								*/
	Boolean					ip_addr_created;
	int						i, intf_list_size;
	int						addr_index;
	int 					intf_unnumbered;
	Compcode				unnumbered_status;
	Objid					iface_description_objid;
	List					tunnel_intf_objid_list;
	int						instrm, outstrm;
	int						highest_instrm = 0;
	
	/* Place holder for value of the "routing protocol" column		*/
	/* of a row in the "Interface Information" compound attribute.	*/
	List*				  	routing_protocols_lptr = OPC_NIL;
	
	/* Temporary Variable needed to check is RSVP-TE is being used.	*/
	int						lsp_signaling_protocol;
	
	/* Temporary variables used for invoking custom routing	*/
	/* protocols. Labels of the custom routing protocols	*/
	/* active in this node are maintained in a list, which	*/
	/* is freed after the custom routing protocols are		*/
	/* invoked.												*/
	List*					active_custom_rte_proto_label_lptr;
	List					active_custom_rte_proto_label_list;
	int						active_custom_rte_protos_size;

	Boolean					multicast_enabled;
	Boolean					igmp_enabled = OPC_FALSE;
	Compcode				return_status = OPC_COMPCODE_FAILURE;
	Objid					line_objid;
	char					rtr_id_str [IPC_MAX_STR_SIZE];
	char					ip_addr_str [IPC_MAX_STR_SIZE];
	char					subnet_mask_str [IPC_MAX_STR_SIZE];
	int						mtu = -1;
	char					comp_info_str [256];
	IpT_Address				ip_addr;
	IpT_Interface_Info*		iface_info_ptr;
	Prohandle				child_prohandle;
	IpT_Address				subnet_mask_addr;
	double					iface_data_rate;
	IpT_Interface_Type		interface_type = IpC_Intf_Type_Unspec;
	IpT_Interface_Status	intf_status;
	char					iface_name [IPC_MAX_STR_SIZE];
	Objid					subintf_comp_attr_objid;
	Objid					virtual_iface_cmp_objid;
	int						num_subinterfaces;
	int						total_interfaces = 0;
	List*					shutdown_intf_lptr;
	IpT_Intf_Info_Attrs		intf_info_attrs;
	Boolean					unconnected_node = OPC_FALSE;
	
	Objid					pkt_filter_objid;
	char					policy_routing_name [256];
	char					local_policy_name [256];
	Objid					ipv6_attrs_objid;
	IpT_Group_Intf_Info*	group_info_ptr;
	InetT_Address			temp_inet_addr;
	IpT_Intf_Objid_Lookup_Tables	intf_objid_lookup_tables;
	Boolean					is_radio_iface;
	Boolean					link_condition;
	
	/* Temporary variabled used to query RSVP attributes.	*/
	Objid					rsvp_params_cattr_objid;	
	Objid					rsvp_params_objid;	

	Objid					ip_rte_map_config_objid;
	double 					metric_bandwidth = 0.0;
	char*					unnumbered_intf_name;
	
	List					routing_instance_list; /* List of intf name, routing instance pairs.	*/
	IpT_Intf_Routing_Instance*	routing_instance_ptr;
	char					routing_instance_str [64];
	Boolean					endsim_tunnel_stat_call_scheduled = OPC_FALSE;	
	Objid*					intf_objid_ptr;

	/** At this point, the enter executives of the 'init' state are	**/
	/** guaranteed to have completed for all IP modules across the 	**/
	/** entire network model. This allows us to know that certain 	**/
	/** initializations have been performed on a global level. In 	**/
	/** particular, all IP modules have registered their primary 	**/
	/** process registry attributes. Transitioning from the 'wait'	**/
	/** we can now perform a second wave of initializations that 	**/
	/** rely on this first wave having completed. These activities 	**/
	/** include: 													**/
	/** 1) verifying consistency of interface addreess and subnet 	**/
	/**    mask assignments (consistency with other nodes as well). **/
	/** 2) choosing values for all "auto-assigned" inteface			**/
	/**    addresses and subnet masks. 								**/
	/** 3) checking for certain construcion problems in the node	**/
	/**	   model. 													**/
	/** 4) Construction of an interface table in the form of a state**/
	/**    variable that reflects the assignments to the interface 	**/
	/**    attributes of the IP object. 							**/
	/** 5) Registration of each IP interface address into a global 	**/
	/**    address table to support a simulation efficiency method.	**/
	/** 6) Discovery of dynamic vs. static routing configuration and**/
	/**    notification of dynamic routing processes that IP is 	**/
	/**    "ready" (i.e., fully configured.)						**/
	FIN (ip_dispatch_init_phase_2 ());
	
	if (module_data.gateway_status == OPC_TRUE)
		{		
		/* Make sure there were no nodes in the network that did not have enough	*/
		/* rows in the Interface Information compound attribute. If there were any,	*/
		/* terminate the simulation.												*/
		if (OPC_TRUE == misconfigured_node_exists)
			{
			ip_dispatch_error ("Encountered at least one node with a fatal misconfiguration");
			}

		/* If this is a router, read in the Route map table.			*/
		/* It is important that we do this after invoking the routing	*/
		/* protocols because bgp will parse community lists and as path	*/
		/* only upon receiving the interrupt from ip.					*/
		/* Build the IP Route Map Table for this router				*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid,
			"Route Map Configuration", &ip_rte_map_config_objid);
		
		module_data.rte_map_table = Ip_Rte_Map_Table_Create (&module_data,
			ip_rte_map_config_objid, IpC_Rte_Map_Type_Route_Map);

		/* Build the table of firewall filters also.				*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid,
			"Firewall Filter Configuration", &ip_rte_map_config_objid);
		
		module_data.firewall_filter_table = Ip_Rte_Map_Table_Create (&module_data,
			ip_rte_map_config_objid, IpC_Rte_Map_Type_Firewall_Filter);

		/* Firewall filters can also be applied as ACLs. Create an	*/
		/* ACL table from the firewall filter table.				*/
		module_data.acl_fw_filter_table = ip_acl_fw_filter_table_create (&module_data);

		/* Call the function that will check if IPv6 is enabled on	*/
		/* this node. If it is, then it will spawn an ipv6 process	*/
		/* that will later be used to read in IPv6 related			*/
		/* attributes.												*/
		intf_objid_lookup_tables.ipv6_table = ip_dispatch_intf_objid_lookup_table_build ("ipv6 parameters");

		/* If there is at least one IPv6 interface, spawn an ipv6	*/
		/* child process.											*/
		if (IpC_Intf_Name_Objid_Table_Invalid != intf_objid_lookup_tables.ipv6_table)
			{
			module_data.ipv6_prohandle = op_pro_create ("ipv6", &module_data);
			op_pro_invoke (module_data.ipv6_prohandle, OPC_NIL);
			}

		/* Call the function that will create a table that will		*/
		/* allow us to quickly get the object ID of an interface	*/
		/* under the PIM Parameters attribute.						*/
		intf_objid_lookup_tables.pim_table = ip_dispatch_intf_objid_lookup_table_build ("PIM Parameters");

		/* Create a similar table for IGMP Parameters.				*/
		intf_objid_lookup_tables.igmp_table = ip_dispatch_intf_objid_lookup_table_build ("IGMP Parameters");
		}

	/* Initialize load balancer information.						*/
	module_data.load_balancer_info_ptr = OPC_NIL;

	/* Set error/warning error procedures */
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);

	/* Initialize the list for shutdown interfaces.					*/
	shutdown_intf_lptr = op_prg_list_create ();
	
	op_prg_list_init (&routing_instance_list);
	
	/* Count the number of loopback, tunnel, and aggregate interfaces*/
	ip_dispatch_intfs_count (&intf_info_attrs);

	/* Read in the interface objid information for RSVP. This will	*/
	/* be used to determine the RSVP status of the interface and	*/
	/* also the RSVP reservable bandwidth that may be configured	*/
	/* on an interface.												*/
	if (op_ima_obj_attr_exists (module_data.node_id, "RSVP Protocol Parameters"))
		{
		op_ima_obj_attr_get (module_data.node_id, "RSVP Protocol Parameters", &rsvp_params_cattr_objid);
		rsvp_params_objid = op_topo_child (rsvp_params_cattr_objid, OPC_OBJTYPE_GENERIC, 0);
		intf_objid_lookup_tables.rsvp_table = 
				ip_rte_proto_intf_attr_objid_table_build (rsvp_params_objid);
		}
	else
		{
		intf_objid_lookup_tables.rsvp_table = IpC_Intf_Name_Objid_Table_Invalid;
		}
	
	/* Also check to see if MPLS is using RSVP as the signaling protocol.	*/
	/* We need to read the RSVP reservable bandwidth only if MPLS is using	*/
	/* RSVP. In case of CR-LDP, the reservable bandwidth is equal to the	*/
	/* physical interface bandwidth for interfaces and sub-interfaces.		*/	
	/* Get the LSP signaling protocol set in Simulation attributes. */
	lsp_signaling_protocol = mpls_support_lsp_signaling_protocol_get ();
		
	/* Examine each interface in turn to: 							*/
	/*  1) verify that it is configured appropriately.				*/
	/*  2) complete its specifcation if necessary.					*/
	/*  3) extract information from it to construct an interface	*/
	/*     table in a state variable for faster access.				*/
	
	/* Set the flag to indicate that no interface has yet			*/
	/* registered an IP address.									*/
	ip_addr_created = OPC_FALSE;
	
	/* Create the list for maintaining active custom protocol labels*/
	op_prg_list_init (&active_custom_rte_proto_label_list);
	active_custom_rte_proto_label_lptr = &active_custom_rte_proto_label_list;
	
	/* Tunnel interface attributes are read in a second pass, since	*/
	/* all interfaces (including VLAN interfaces) must be parsed 	*/
	/* before tunnel attrs are read. So we need a list to cache the	*/
	/* tunnel interface objids during the first pass.				*/
	op_prg_list_init (&tunnel_intf_objid_list);
	
	/* Loop over the rows in the "Interface Information" compound	*/
	/* attribute and process each one.								*/
	for (i = 0; i < module_data.num_interfaces; i++)
		{
		/* Initialize the variable used to track if the i_th iface	*/
		/* is unnumbered.											*/
		intf_unnumbered = OPC_FALSE;
		
		/* Initialize the objid of the link to which this interface	*/
		/* is connected, to ensure that radio interfaces are 		*/
		/* handled correctly.										*/
		line_objid = OPC_OBJID_INVALID;
		
		/* Call the function that will return the objid of the		*/
		/* appropriate row under Interface Information or Loopback	*/
		/* Interfaces attribute. The intf_status will also be set	*/
		/* correctly.												*/
		iface_description_objid = ip_dispatch_intf_info_objid_get (i, &intf_info_attrs,
			&intf_status, &addr_index);

		/* For shutdown tunnel interfaces the above function will	*/
		/* return OPC_OBJID_INVALID. Ignore such interfaces.		*/
		if (OPC_OBJID_INVALID == iface_description_objid)
			{
			continue;
			}

		/* Obtain the Name assigned to the IP interface				*/
		op_ima_obj_attr_get (iface_description_objid, "Name", iface_name);
		
		/* For physical interfaces, verify that at least one		*/
		/* stream exists to support this interface. If not, issue a	*/
		/* warning. The system can still function, but it is		*/
		/* probably not what the node model developer intended. 	*/
		if ((IpC_Intf_Status_Active == intf_status) || (IpC_Intf_Status_Shutdown == intf_status))
			{
			ip_stream_from_iface_index (addr_index, &instrm, &outstrm, &interface_type);
	
			/* The existence of an outstream to support an interface	*/
			/* is required. Otherwise,  IP might try to send packet on	*/
			/* an attached stream, which will generate errors.			*/
			if (outstrm == IPC_PORT_NUM_INVALID)
				{
				ipnl_cfgwarn_intfcfg (addr_index);
				continue;
				}

			/* Check if this interface is part of a group. If so, all we*/
			/* have to do is add this interface to the list of			*/
			/* member interfaces of the group. Any configuration done	*/
			/* on this interface can be ignored. For efficiency purposes*/
			/* perform this check only of at least one aggregate		*/
			/* interface has been configured on this node.				*/
			if (intf_info_attrs.num_aggr_interfaces > 0)
				{
				if (ip_dispatch_member_intf_check (iface_description_objid, iface_name,
													instrm, outstrm, addr_index, intf_status))
					{
					/* This interface is part of a group. No need to	*/
					/* its attributes.									*/
					
					/* Update highest_instrm if necessary.				*/
					if (instrm > highest_instrm)
						{
						highest_instrm = instrm;
						}

					continue;
					}
				}
			}
		else
			{
			/* Logical interfaces do not have associated streams		*/
			outstrm = IPC_PORT_NUM_INVALID;
			instrm = IPC_PORT_NUM_INVALID;
			interface_type = IpC_Intf_Type_Dumb;
			}
			
		/* For gateway nodes, get the objid of the IPv6 attributes of	*/
		/* this interface also.											*/
		if (module_data.gateway_status == OPC_TRUE)
			{
			ipv6_attrs_objid = ip_rte_proto_intf_attr_objid_table_lookup_by_name
				(intf_objid_lookup_tables.ipv6_table, iface_name);
			}
		else
			{
			/* For end stations, set the ipv6_attrs_objid to invalid.	*/
			ipv6_attrs_objid = OPC_OBJID_INVALID;
			}

		/* Read in the routing protocol(s) specified on the interface	*/
		/* and process that information appropriately.					*/
		routing_protocols_lptr = ip_interface_routing_protocols_obtain (iface_description_objid,
			ipv6_attrs_objid, intf_status, active_custom_rte_proto_label_lptr);

		/* Determine whether this is a radio interface.					*/
		if ((IpC_Intf_Status_Active == intf_status) || (IpC_Intf_Status_Shutdown == intf_status))
			{
			is_radio_iface = ip3_interface_is_radio_verify (radio_intf_list_ptr, addr_index, module_data.num_interfaces);
			}
		else
			{
			/* Logical interfaces cannot be radio interfaces.			*/
			is_radio_iface = OPC_FALSE;
			}

		/* The address resolution feature is used depending	upon the value specified	*/
		/* to the simulation attribute - "IP Interface Addressing Mode".				*/
		/* NOTE: Tunnel interface addresses are CANNOT be auto-assigned. However, they 	*/
		/* may be set to "Unnumbered", in which case a special address will be assigned	*/
		/* to them. Since this is done inside ip3_addr_resolve (), this function must	*/
		/* be called for tunnel interfaces also.										*/
		if ((iface_addressing_mode != IpC_Iface_Manually_Addressed) &&
			(iface_addressing_mode != IpC_Iface_Manual_Address_Export) &&
			(intf_status != IpC_Intf_Status_Group))
			{
			if (!is_radio_iface)
				{
				return_status = ip3_addr_resolve (iface_description_objid, addr_index, 
					link_iface_table_ptr, routing_protocols_lptr, 
					&intf_unnumbered, &unnumbered_intf_name, &line_objid, intf_status);
				}
			else
				{
				/* Radio interface addresses are resolved later (in ip3_radio_address_resolve).	*/
				/* Radio interfaces are always considered active.								*/
				return_status = OPC_COMPCODE_SUCCESS;
				}
			
			/* Read in the Address and subnet mask of this interface.	*/
			op_ima_obj_attr_get (iface_description_objid, "Address", ip_addr_str);
			op_ima_obj_attr_get (iface_description_objid, "Subnet Mask", subnet_mask_str);
			
			/* Check whether this interface is an unconnected interface.		*/
			/* Unconnected interfaces have their IP address set to a valid		*/
			/* address and are active. The previous function (ip3_addr_resolve	*/
			/* will return failure status and invalid link object ID for 		*/
			/* unconnected interface. Use this to set the interface type.		*/
			if ((intf_status == IpC_Intf_Status_Active) && (line_objid == OPC_OBJID_INVALID) 
				&& (is_radio_iface == OPC_FALSE) && (intf_unnumbered == OPC_FALSE) &&
				(strcmp (ip_addr_str, IPC_AUTO_ADDRESS) != 0) && (strcmp (ip_addr_str, IPC_NO_IP_ADDRESS) != 0))
				{
				intf_status = IpC_Intf_Status_Unconnected;
				}
			
			/* Here the interface is not connected to a valid	*/
			/* link. The goal is to avoid the further interface	*/
			/* assignments. But if this the last interface of an*/
			/* unconnected node, we should process this			*/
			/* interface so that unconnected hosts can send		*/
			/* traffic to themselves. Also, we need to continue	*/
			/* processing if this is an unconnected interface.	*/
			if ((return_status == OPC_COMPCODE_FAILURE) && (is_radio_iface == OPC_FALSE) &&
				(IpC_Intf_Status_Loopback != intf_status) && (IpC_Intf_Status_Unconnected != intf_status) &&
				(IpC_Intf_Status_Tunnel != intf_status) &&
				(! ((ip_addr_created == OPC_FALSE) && (i == (module_data.num_interfaces - 1)))))
				{
				continue;
				}

			/* Auto Assign IP address to radio interfaces if needed.*/
			if (op_prg_list_size (radio_intf_list_ptr) != 0)
				{
				ip3_radio_address_resolve (radio_intf_list_ptr, subnet_objid, module_data.module_id);
				
				/* Read in the Address and subnet mask of this interface.	*/
				op_ima_obj_attr_get (iface_description_objid, "Address", ip_addr_str);
				op_ima_obj_attr_get (iface_description_objid, "Subnet Mask", subnet_mask_str);
				}
			}
		else
			{
			/* As Auto Addressing resolution code is not invoked 	*/
			/* in case of Manually addresses mode, the link objid is*/
			/* to be obtained to determine the validity of the 		*/
			/* current interface.									*/
			if ((IpC_Intf_Status_Active == intf_status) || (IpC_Intf_Status_Shutdown == intf_status))
				{
				line_objid = ip3_link_iface_link_from_index (link_iface_table_ptr, addr_index, 0);
				}
			else
				{
				/* Logical interfaces do not have connected links.	*/
				line_objid = OPC_OBJID_INVALID;
				}

			/* Check for unnumbered interfaces.							*/
			unnumbered_status = ip_unnumbered_address_resolve (iface_description_objid, addr_index, IPC_SUBINTF_PHYS_INTF,
				routing_protocols_lptr, &intf_unnumbered, &unnumbered_intf_name, line_objid);

			/* If there was an error, ignore this interface.			*/
			if (OPC_COMPCODE_FAILURE == unnumbered_status)
				{
				continue;
				}

			/* Read in the Address and subnet mask of this interface.	*/
			op_ima_obj_attr_get (iface_description_objid, "Address", ip_addr_str);
			op_ima_obj_attr_get (iface_description_objid, "Subnet Mask", subnet_mask_str);
			
			/* Check whether this interface is an unconnected interface.		*/
			/* Unconnected interfaces have their IP address set to a valid		*/
			/* address and are active. The previous function 					*/
			/* ip3_link_iface_link_from_index () an invalid link object ID for 	*/
			/* unconnected interface. Use this to reset the interface type.		*/
			if ((intf_status == IpC_Intf_Status_Active) && (line_objid == OPC_OBJID_INVALID) 
				&& (is_radio_iface == OPC_FALSE) && (strcmp (ip_addr_str, IPC_AUTO_ADDRESS) != 0))
				{
				intf_status = IpC_Intf_Status_Unconnected;
				}
			}
		
		/* If the address and or subnet mask are still auto assigned, 	*/
		/* then it must mean that the interface is not connected to any	*/
		/* links. Rather than leaving an unconfigured interface in the 	*/
		/* the interface table, simply do not create an interface entry.*/
		if (strcmp (ip_addr_str, IPC_AUTO_ADDRESS) == 0)
			{
			/* If this is the last interface, and no addresses have been	*/
			/* assigned, assign an address to this interface.				*/
			if (((ip_addr_created == OPC_FALSE) && (i == (module_data.num_interfaces - 1))) ||
				(IpC_Intf_Status_Loopback == intf_status))
				{
				/* We know that all physical interfaces are unconnected. To	*/
				/* conclude that the node is unconnected, we need make sure	*/
				/* that the node also doesn't have a switching module or it	*/
				/* is present but doesn't have any VLAN interfaces 			*/
				/* configured.												*/
				if (module_data.gateway_status == OPC_TRUE)
					{
					op_ima_obj_attr_get (module_data.ip_parameters_objid, "VLAN Interfaces", &(virtual_iface_cmp_objid));
					if (op_topo_child_count (virtual_iface_cmp_objid, OPC_OBJTYPE_GENERIC) > 0 &&
						ip_dispatch_switch_module_is_present ())
						{
						/* The node has switching module and configured VLAN	*/
						/* interfaces. Assume it is a connected node.			*/
						continue;
						}
					}
				
				/* The node is unconnected. Assign an address for the last	*/
				/* interface.												*/
				ip3_addr_unconn_node_create (iface_description_objid, 0, link_iface_table_ptr);

				/* The above function would have set the Address and subnet	*/
				/* mask of the inerface appropriately. Read in the values	*/
				op_ima_obj_attr_get (iface_description_objid, "Address",        	ip_addr_str);
				op_ima_obj_attr_get (iface_description_objid, "Subnet Mask",    	subnet_mask_str);

				/* If this not a loopback inteface, set the flag indicating	*/
				/* that an address was assigned to this interface because	*/
				/* it is the last physical interface of an un connected node*/
				if ((IpC_Intf_Status_Loopback != intf_status) &&
					(IpC_Intf_Status_Shutdown != intf_status))					
					{
					unconnected_node = OPC_TRUE;
					intf_status = IpC_Intf_Status_Unconnected;
					}
				}
			else
				{
				/* This interface did not receive an assignment. Do not continue 	*/
				/* setup for it. 													*/
				continue;
				}
			}
		else if (!strcmp (ip_addr_str, IPC_NO_IP_ADDRESS))
			{
			/* Assign 0.0.0.0 to the IP address and 255.255.255.255 to	*/
			/* the subnet mask.											*/
			strcpy (ip_addr_str, "0.0.0.0");
			strcpy (subnet_mask_str, "255.255.255.255");
			}

		/* Tunnel interfaces must have valid IP addresses or should be	*/
		/* Unnumbered. Make that check here.							*/
		if ((IpC_Intf_Status_Tunnel == intf_status) && !intf_unnumbered && !ip_address_string_test (ip_addr_str))
			{
			ip_nl_tunnel_creation_error_log_write ("Address", ip_addr_str);
			continue;
			}
		
		/* At least one ip_address has been assigned for this node.	*/
		ip_addr_created = OPC_TRUE;

		/* At this point, we have found a row in the "IP Address	*/
		/* Information" comp. attr. that has non-default values for	*/
		/* the "address" and "subnet mask" subattributes. These		*/
		/* values may be the result of the auto addressing scheme	*/
		/* having set these values, or, the user setting these		*/
		/* values - in which case the auto addressing scheme leaves	*/
		/* them unaltered. There is the possibility that the user	*/
		/* may have assigned values to an interface that is not		*/
		/* connected to any link. Failure to check this and execute	*/
		/* the code below will result in the creation of			*/
		/* IpT_Interface_Info objects for interfaces that cannot be	*/
		/* used to forward IP datagrams. Check for this now.		*/
		/*															*/
		/* There is one exception that we need to allow for. This	*/
		/* is the case where a stand-alone node (typically a LLM	*/
		/* node) is part of the network. This case is supported via	*/
		/* the if check (unconnected_node == OPC_TRUE)				*/ 

		/* Create an interface object and enter it into the IP		*/
		/* interface table if:										*/
		/* 1. The link connected to this interface is valid.		*/
		/* 2. The interface is connected to a radio transceiver and */
		/*    a valid address assignment has been made.				*/
		/* 3. This is the last interface of an unconnected node.	*/
		/* 4. This is a loopback interface.							*/
		/* 5. This is a tunnel interface.							*/
		/* 6. This is an unconnected interface.						*/
		/* 7. This is an interface group.							*/
		if ((line_objid != OPC_OBJID_INVALID) || (IpC_Intf_Status_Loopback == intf_status) ||
			(IpC_Intf_Status_Tunnel == intf_status) || (IpC_Intf_Status_Group == intf_status) ||
			((is_radio_iface == OPC_TRUE) && (strcmp (ip_addr_str, IPC_AUTO_ADDRESS) != 0)) ||
			(unconnected_node == OPC_TRUE) || (IpC_Intf_Status_Unconnected == intf_status))
			{
			/* Read in the Compression Information, MTU, Access Groups,	*/
			/* and the Multicast Enabled flag if this is an active		*/
			/* interface.												*/
			if ((intf_status == IpC_Intf_Status_Active) || (intf_status == IpC_Intf_Status_Tunnel) ||
				(intf_status == IpC_Intf_Status_Unconnected) || (intf_status == IpC_Intf_Status_Group))
				{
				op_ima_obj_attr_get (iface_description_objid, "MTU", &mtu);
				
				/* Compression information does not exist on tunnel interfaces.	*/
				if (op_ima_obj_attr_exists (iface_description_objid, "Compression Information"))
					{
					op_ima_obj_attr_get (iface_description_objid, "Compression Information", comp_info_str);
					}
				else
					{
					/* This is a tunnel or loopback interface. Set the 			*/
					/* compression information to None.							*/
					strcpy (comp_info_str, "None");
					}
				
				/* If OSPF or EIGRP is enabled on this interface, set the 	*/
				/* multicast enabled flag to true.							*/
				if (ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Ospf) ||
					ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Eigrp))
					{
					multicast_enabled = OPC_TRUE;
					}
				else
					{					
					/* If PIM-SM is supported on the node, the multicast status will be set to true by PIM-SM process.	*/
					/* the exception is a host node where PIM-SM is not run and thus the process will not be called.	*/
					/* In that case, find multicast support now.														*/
					
					//  JPH SMF - Modify code to set multicast_enabled for router as well as for host.
					//        Added 'Multicast Mode' to 'ip router parameters' compound attribute.
					
					/* For Host nodes read the IP Host Parameters -> Multicast Enabled attribute*/
					//if (module_data.gateway_status == OPC_FALSE)
					//	{
						/* Multicast is enabled on hosts if "Multicast Mode" is	enabled. */
					//	op_ima_obj_attr_get (module_data.ip_parameters_objid,"Multicast Mode", &multicast_enabled);
					//	}
					//else
					//	{
					//	multicast_enabled = OPC_FALSE;
					//	}
					
					op_ima_obj_attr_get (module_data.ip_parameters_objid,"Multicast Mode", &multicast_enabled);
					// end JPH SMF
					}
				
				if (module_data.gateway_status == OPC_TRUE)
					{					
					/* Find whether IGMP is enabled on the interface.	*/
					igmp_enabled 		= ip_igmp_iface_enabled (intf_objid_lookup_tables.igmp_table, iface_name); 
					}
				else
					igmp_enabled = multicast_enabled;
				}
			else
				{
				/* For loopback interfaces set the compression string to None.	*/
				/* and multicast_enabled to false.								*/
				strcpy (comp_info_str, "None");
				multicast_enabled 	= OPC_FALSE;
				igmp_enabled 		= OPC_FALSE;
				}
		
			/* Convert the string representations of the address/mask	*/
			/* to IP internal form. These will be stored as part of the	*/
			/* interface's 'address range' created below.				*/
			ip_addr = ip_address_create (ip_addr_str);
			subnet_mask_addr = ip_address_create (subnet_mask_str);

			/* For Aggregate initerfaces, read aggregation related		*/
			/* parameters.												*/
			if (IpC_Intf_Status_Group == intf_status)
				{
				group_info_ptr = ip_dispatch_aggregate_intf_attrs_read (iface_description_objid, iface_name);

				/* If there was an error in the Group configuration, the*/
				/* above function will return NIL. Ignore such			*/
				/* interfaces.											*/
				if (OPC_NIL == group_info_ptr)
					{
					continue;
					}
				}
			else
				{
				/* For non-aggregate interfaces, set the group info to	*/
				/* NIL.													*/
				group_info_ptr = OPC_NIL;
				}

			/*	Create and initialize a new cell to hold the interface	*/
			iface_info_ptr = ip_interface_info_create (IPC_PHYS_INTF);
			iface_info_ptr->phys_intf_info_ptr->ip_addr_index = addr_index;
			iface_info_ptr->network_address = ip_address_mask (ip_addr, subnet_mask_addr);
			iface_info_ptr->mtu	= mtu;
			iface_info_ptr->phys_intf_info_ptr->port_num = outstrm;
			iface_info_ptr->phys_intf_info_ptr->in_port_num = instrm;
			ip_rte_intf_mcast_enabled_set (iface_info_ptr, multicast_enabled);
			if (igmp_enabled)
				iface_info_ptr->flags |= IPC_INTF_FLAG_IGMP_ENABLED;
			iface_info_ptr->flow_id_map_list_ptr = OPC_NIL;
			iface_info_ptr->phys_intf_info_ptr->group_info_ptr = group_info_ptr;

			/* For unnumbered interfaces, store the source interface also*/
			if (intf_unnumbered)
				{
				iface_info_ptr->unnumbered_info = (IpT_Unnumbered_Info*) op_prg_mem_alloc (sizeof (IpT_Unnumbered_Info));
				iface_info_ptr->unnumbered_info->interface_name = unnumbered_intf_name;

				/* Set the flag indicating that this node has at least 	*/
				/* one unnumbered interface.							*/
				module_data.unnumbered_interface_exists = OPC_TRUE;

				/* Only point to point interfaces can be unnumbered. If	*/
				/* this interface has a lower layer, log a warning. 	*/
				if ((IpC_Intf_Type_Dumb != interface_type) || is_radio_iface)
					{
					ipnl_cfgwarn_unnumbered_intf_not_dumb (module_data.node_id, iface_name);
					}
				}
			else
				{
				iface_info_ptr->unnumbered_info = OPC_NIL;
				}

			/* Read the interface speed for unconnected interface 	*/
			/* and for radio interfaces on gateway nodes.			*/
			if (((intf_status == IpC_Intf_Status_Unconnected) ||
				 (intf_status == IpC_Intf_Status_Group) ||
				 (is_radio_iface && (IpC_Intf_Status_Loopback != intf_status))) &&
				(module_data.gateway_status))
				{	
				op_ima_obj_attr_get (iface_description_objid, "Interface Speed", &iface_data_rate);
				
				/* For aggregate interfaces, it might be set to Auto		*/
				/* Calculate.												*/
				if (IPC_INTF_SPEED_AUTO_CALCULATE == iface_data_rate)
					{
					/* The actual vaule will be assigned by ip_grouping.	*/
					iface_info_ptr->phys_intf_info_ptr->link_bandwidth = IPC_INTF_SPEED_AUTO_CALCULATE;
					iface_info_ptr->avail_bw = IPC_INTF_SPEED_AUTO_CALCULATE;
					}
				else
					{
					/* An explicit value has been specified.				*/

					/* Interface speed is configured in kbps, change it to	*/
					/* bps.													*/
					iface_info_ptr->phys_intf_info_ptr->link_bandwidth = iface_data_rate * 1000;

					/* Initialize the available bandwidth to interface speed */
					iface_info_ptr->avail_bw = iface_info_ptr->phys_intf_info_ptr->link_bandwidth;				
					}
				}
			
			/* Store the interface name.								*/
			ip_rte_intf_name_set (iface_info_ptr, iface_name);

			/* Check if MANET is enabled on this interaface	*/
			if (ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Dsr))
				{
			   	ip_manet_enable (&module_data, IpC_Rte_Dsr);
				iface_info_ptr->flags |= IPC_INTF_FLAG_MANET_ENABLED;
				}
			else if	(ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Tora))
				{
				ip_manet_enable (&module_data, IpC_Rte_Tora);
				iface_info_ptr->flags |= IPC_INTF_FLAG_MANET_ENABLED;
				}
			else if (ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Aodv))
				{
				ip_manet_enable (&module_data, IpC_Rte_Aodv);
				iface_info_ptr->flags |= IPC_INTF_FLAG_MANET_ENABLED;
				}
			else if (ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Olsr))
				{
				ip_manet_enable (&module_data, IpC_Rte_Olsr);
				iface_info_ptr->flags |= IPC_INTF_FLAG_MANET_ENABLED;
				}

			/* Store the status of the interface; Active, Shutdown, 	*/
			/* a loopback, tunnel or unconnected interface.				*/
			iface_info_ptr->phys_intf_info_ptr->intf_status = intf_status;
		
			/* Initialize the Packet filter and Policy Routing name		*/		 
			iface_info_ptr->policy_routing_name = OPC_NIL;
			iface_info_ptr->filter_info_ptr 	= OPC_NIL;

			if (module_data.gateway_status == OPC_TRUE)
				{
				/* If a matching row was found under IPv6 Parameters, 	*/
				/* read in the IPv6 related attributes.					*/
				if (OPC_OBJID_INVALID != ipv6_attrs_objid)
					{
					ip_dispatch_gtwy_ipv6_attrs_read (ipv6_attrs_objid, iface_info_ptr);
					}

				/* If this is an active physical interface, find out	*/
				/* the number of subinterfaces for this interface.		*/
				if ((IpC_Intf_Status_Active == intf_status) ||
					(IpC_Intf_Status_Unconnected == intf_status) ||
					(IpC_Intf_Status_Group == intf_status))
					{
					/* Get the objid of the Subinterface information attribute*/
					op_ima_obj_attr_get (iface_description_objid, "Subinterface Information", &subintf_comp_attr_objid);
				
					/* Find the number of rows under this attribute			*/
					num_subinterfaces = op_topo_child_count (subintf_comp_attr_objid, OPC_OBJTYPE_GENERIC);
					}
				else
					{
					num_subinterfaces = 0;
					}
			
				/* If this interface was assigned a valid IP address,	*/
				/* store this information in the corresponding interface*/
				/* information structure.								*/
				if (! ip_address_equal (ip_addr, IpI_No_Ip_Address))
					{
					/* IPv4 is enabled on this interface. Set the		*/
					/* address range appropriately.						*/
					iface_info_ptr->addr_range_ptr = ip_address_range_create (ip_addr, subnet_mask_addr);
					iface_info_ptr->inet_addr_range = inet_ipv4_address_range_create (ip_addr, subnet_mask_addr);
					}
				}
			else
				{
				/* This is an end station node.							*/

				/* If IPv6 is enabled on this node, read the IPv6		*/
				/* related attributes.									*/
				ip_dispatch_host_ipv6_attrs_read (iface_description_objid, iface_info_ptr);

				/* Check if IPv4 is enabled on this interface.			*/
				/* IPv4 is enabled if one of the following conditions	*/
				/* is true.												*/
				/* 1. The IP address is not set to No IP Address.		*/
				/* 2. IPv6 is not enabled on this interface and this	*/
				/*    interface is not a tunnel.						*/
				if ((! ip_address_equal (ip_addr, IpI_No_Ip_Address)) ||
					((! ip_rte_intf_ipv6_active (iface_info_ptr)) && (IpC_Intf_Status_Tunnel != intf_status)))
					{
					/* IPv4 is enabled on this interface. Set the		*/
					/* address range appropriately.						*/
					iface_info_ptr->addr_range_ptr = ip_address_range_create (ip_addr, subnet_mask_addr);
					iface_info_ptr->inet_addr_range = inet_ipv4_address_range_create (ip_addr, subnet_mask_addr);
					}

				/* End stations will not have subinterfaces.			*/
				num_subinterfaces = 0;
				}

			/* If Packet Filter attribute exists for this interface then*/
			/* get send and receive filters configured for this	iface	*/
			if ((module_data.gateway_status == OPC_TRUE) &&
				((intf_status == IpC_Intf_Status_Active) || (intf_status == IpC_Intf_Status_Tunnel)
				|| (intf_status == IpC_Intf_Status_Unconnected)
				|| (intf_status == IpC_Intf_Status_Group)))
				{
				/* Get the object ID of the packet filter attribute		*/
				op_ima_obj_attr_get (iface_description_objid, "Packet Filter", &pkt_filter_objid);
				
				/* Get the configured filter info						*/	
				iface_info_ptr->filter_info_ptr = Inet_Acl_Filter_Read (&module_data, pkt_filter_objid, OPC_NIL);
				 
				/* Get the configured Policy Routing attribute			*/
				op_ima_obj_attr_get (iface_description_objid, "Policy Routing", &policy_routing_name);

				/* Store the name of the policy if its configured		*/
				if (strcmp (policy_routing_name, "None") != 0)
					{
					iface_info_ptr->policy_routing_name = (char *) op_prg_mem_alloc (sizeof (char) * (strlen (policy_routing_name) + 1));
					strcpy (iface_info_ptr->policy_routing_name, policy_routing_name);
					}
				}
			
			/* Read Routing Instance, if present. The routing instance is stored	*/
			/* in a temporary list and is then converted into an array, after the	*/
			/* interface table is built. Routing instance is only present on		*/
			/* physical and loopback interfaces. It is also present on sub and 		*/
			/* virtual interfaces, but they are parsed in a different function.		*/
			if ((module_data.gateway_status == OPC_TRUE) && 
				op_ima_obj_attr_exists (iface_description_objid, "Routing Instance"))
				{
				op_ima_obj_attr_get_str (iface_description_objid, "Routing Instance", 64, routing_instance_str);
				
				/* If some routing instance is present, store it.	*/
				if (strcmp (routing_instance_str, "None") != 0)
					{
					routing_instance_ptr = ip_dispatch_intf_routing_instance_create (iface_name, routing_instance_str);
					op_prg_list_insert (&routing_instance_list, routing_instance_ptr, OPC_LISTPOS_TAIL);
					}
				}

			/* A global address table is used to associate IP addresses	*/
			/* with the corresponding lower layer address. This table	*/
			/* IS Managed by the NATO sub-package. The IP routing		*/
			/* process registers addresses in this table and makes it	*/
			/* available to other processes (e.g., IP ARP) via process	*/
			/* registry. Also register the network address.				*/
			if ((intf_unnumbered == OPC_FALSE) && (!ip_address_equal (ip_addr, IpI_No_Ip_Address)))
				{
				temp_inet_addr = inet_address_from_ipv4_address_create (ip_addr);
				ip_rtab_local_addr_register (&temp_inet_addr, &module_data);
				temp_inet_addr = inet_address_from_ipv4_address_create (iface_info_ptr->network_address);
				ip_rtab_local_network_register (&temp_inet_addr);
				}

			/* Set the subintf_addr_index to IPC_SUBINTF_PHYS_INTF (-1) */
			/* to indicate that this is a physical interface.			*/
			iface_info_ptr->subintf_addr_index = IPC_SUBINTF_PHYS_INTF;

			/* Copy the contents of the temporary list containing information	*/
			/* about which routing protocols run on this interface.				*/
			iface_info_ptr->routing_protocols_lptr = routing_protocols_lptr;
			
			/* Set the routing_protocols_lptr variable to NIL so that we do not	*/
			/* accidently destroy the list										*/
			routing_protocols_lptr = OPC_NIL;			
			
			/* Retrieve the information about the compression scheme	*/
			/* used for this interface from the network-wide attribute	*/
			/* database. Use the comp_info_str (name) as the reference.	*/
			iface_info_ptr->comp_info = (IpT_Compression_Info *)
				oms_data_def_entry_access ("IP Compression Information", 
					comp_info_str);

			if (iface_info_ptr->comp_info == OPC_NIL)
				{
				/* The specified compression scheme does not exists		*/
				/* in the attribute database. Add an entry into			*/
				/* the simulation notification log.						*/
				ipnl_cfgwarn_unknown_comp_scheme (iface_name, comp_info_str);

				/* Set the compression scheme to "None" as default for	*/
				/* the interface.										*/
				iface_info_ptr->comp_info = (IpT_Compression_Info *)
					oms_data_def_entry_access ("IP Compression Information", "None");
				}

			/* Store the object ID of the link to which this interface	*/
			/* is connected.											*/
			iface_info_ptr->phys_intf_info_ptr->connected_link_objid = line_objid;

			/*	Determine and set the speed at which this interface operates	*/
			/*  only if we are not processing a stand-alone node.				*/
			if (line_objid != OPC_OBJID_INVALID)
				{
				op_ima_obj_attr_get (
					line_objid, "data rate", &iface_data_rate);
				iface_info_ptr->phys_intf_info_ptr->link_bandwidth = iface_data_rate;

				/* Initialize the available bandwidth to interface speed */
				iface_info_ptr->avail_bw = iface_info_ptr->phys_intf_info_ptr->link_bandwidth;				

				/* Initialize the intf_status based on whether or not the	*/
				/* link is active.											*/
				op_ima_obj_attr_get (line_objid, "condition", &link_condition);
				iface_info_ptr->phys_intf_info_ptr->link_status = (short) link_condition;
				}
			else
				{
				/* This is a wireless or unconnected network. Set the link	*/
				/* status to Enabled.										*/
				iface_info_ptr->phys_intf_info_ptr->link_status = 1;
				}
			
			/* If the node is a router and interface status is not loopback,*/
			/* then read the attributes for Interface metrics				*/
			if (module_data.gateway_status && intf_status != IpC_Intf_Status_Loopback)
				{
				/* If the node is a router, read the attributes for Interface metrics	*/
				iface_info_ptr->user_metrics = ip_intf_metrics_read (iface_description_objid,
					iface_info_ptr->phys_intf_info_ptr->link_bandwidth);
				
				/* Set metric basndwidth as configured. Multiply by 1000 to change to bps	*/
				metric_bandwidth = ((double) iface_info_ptr->user_metrics->bandwidth * 1000.0);
				}
			else
				{
				/* Set metric basndwidth as link avail bw					*/
				metric_bandwidth = iface_info_ptr->avail_bw;
				}
				
			/* For non-group interfaces, read in the RSVP information for	*/
			/* the interface. This can be done for both connected and		*/
			/* unconnected interfaces, though the information may not be	*/
			/* used for unconnected interfaces.								*/
			if (intf_status != IpC_Intf_Status_Group)
				{
				ip_rte_iface_rsvp_info_set (&iface_info_ptr->avail_bw,
											metric_bandwidth,
											&iface_info_ptr->flags,
											intf_objid_lookup_tables.rsvp_table,
											iface_name,
											lsp_signaling_protocol);
				}

			/* If RSVP is enabled on the interface, then set the	*/
			/* module RSVP status.									*/	
			if (ip_rte_intf_rsvp_enabled (iface_info_ptr))
				module_data.rsvp_status 		= OPC_TRUE;
			
			/* Find out whether RSVP-TE is being used for setting up LSPs.	*/			
			if ((lsp_signaling_protocol == LSP_SIGNALING_PROTOCOL_RSVP) && 
				Mpls_Path_Support_Lsp_Type_Exists (MplsC_Lsp_Type_Dynamic))
				{
				module_data.rsvp_te_status = OPC_TRUE;
				}

			/* Based on what has been set up, initialize the			*/
			/* routing_protocols_lptr member of the corresponding		*/
			/* IpT_Interface_Info object. At the same time, set the		*/
			/* corresponding bit in the routing_options SV. This SV		*/
			/* will be used later in determining which routing protocol	*/
			/* modules IP is going to "remote interrupt".				*/
			if (!ip_rte_intf_manet_enabled (iface_info_ptr))
				ip_dispatch_routing_options_add (iface_info_ptr->routing_protocols_lptr);
			
			/*	Initialize the outbound load from this interface. Also	*/
			/*	set the reliability of the interface as 100% reliable.	*/
			iface_info_ptr->load_bits = 0.0;
			iface_info_ptr->load_bps = 0.0;
			iface_info_ptr->reliability = 1.0;

			/* For the time being, we do not know whether we are using	*/
			/* slots or not.  This will be filled in appropriately 		*/
			/* if slots are created.									*/
			iface_info_ptr->phys_intf_info_ptr->slot_index = OMSC_DV_UNSPECIFIED_SLOT;
		
			/* Store the type of this interface. This is required in 	*/
			/* determining whether an ICI is to be associated with the	*/
			/* packets sent throug this interface. We do not have to 	*/
			/* associate any ICI with packets sent out through "slip"	*/
			/* interfaces.												*/
			iface_info_ptr->phys_intf_info_ptr->intf_type = interface_type;
			
			/* At this point we are sure that this interface is active 	*/
			/* and will be included in this node's list of IP intefaces	*/
			/* If the status of this interface is "Shutdown", enter 	*/
			/* this interface into the list for a Simulation Log entry	*/
			if (intf_status == IpC_Intf_Status_Shutdown)
				{
				op_prg_list_insert (shutdown_intf_lptr, iface_info_ptr, OPC_LISTPOS_TAIL);
				}

			/* For non-loopback interfaces, read in 	       */
			/* the layer 2 mappings and the metric information */
			/* We introduced the layer 2 mapping attribute on  */
			/* workstations, thus eliminating the restriction  */
			/* of reading the layer 2 mapping only on gateway  */
			/* nodes. 										   */
			if (IPC_PORT_NUM_INVALID != ip_rte_intf_in_port_num_get (iface_info_ptr))
				{
				/*	Read in the information entered under the Layer 2 	*/
				/*	Mappings attribute									*/
				ip_dispatch_layer2_mappings_read (iface_info_ptr, iface_description_objid);

				/* Keep track of the highest instrm value we have		*/
				/* encountered so far.									*/
				if (ip_rte_intf_in_port_num_get (iface_info_ptr) > highest_instrm)
					{
					highest_instrm = ip_rte_intf_in_port_num_get (iface_info_ptr);
					}
				}

			/* Check if there are any subinterfaces defined for this	*/
			/* physical interface  if this is a gateway node			*/
			/* In the case of endstations, just leave the elements		*/
			/* as they are. They would have been initialized to their	*/
			/* default values in ip_iface_info_create					*/
			/* If there are any subinterfaces, call the function that	*/
			/* would read them											*/
			if (0 != num_subinterfaces)
				{
				ip_dispatch_subintf_info_read (iface_info_ptr, subintf_comp_attr_objid, 
					&intf_objid_lookup_tables, num_subinterfaces, active_custom_rte_proto_label_lptr,
					lsp_signaling_protocol, OPC_FALSE, &routing_instance_list);
				}

			/* Read secondary address information */
			if ((OPC_TRUE == module_data.gateway_status) &&
				((IpC_Intf_Status_Active == intf_status) ||
					(IpC_Intf_Status_Loopback == intf_status)
					|| (IpC_Intf_Status_Unconnected == intf_status)
					|| (IpC_Intf_Status_Group == intf_status)))
				{
				/* Read secondary IP addresses, if configured on this physical or loopback interface */
				ip_dispatch_secondary_ip_addresses_read (iface_info_ptr, iface_description_objid);					
				}

			/*	Insert the cell into the interface table. 				*/
			op_prg_list_insert (module_data.interface_table_ptr, iface_info_ptr, OPC_LISTPOS_TAIL);


			/* Tunnel interface objids are stored in a list so that the	*/
			/* other attributes of tunnel interfaces can be read in a 	*/
			/* second pass through all the interfaces.					*/
			if (IpC_Intf_Status_Tunnel == intf_status)
				{
				intf_objid_ptr = (Objid *) op_prg_mem_alloc (sizeof (Objid));
				*intf_objid_ptr = iface_description_objid;
				op_prg_list_insert (&tunnel_intf_objid_list, intf_objid_ptr, OPC_LISTPOS_TAIL);
				}
			
			/* Because of the way the IP interface table is built, a	*/
			/* physical interface and all its subinterfaces must have	*/
			/* the same versions of IP enabled on them. Call the		*/
			/* function that will make sure that this condition is met.	*/
			ip_dispatch_subintf_ip_version_check (iface_info_ptr);

			/* Update the variable that tracks the total number of		*/
			/* interfaces on this router (physical and subinterfaces).	*/
			total_interfaces += (ip_rte_num_subinterfaces_get (iface_info_ptr) + 1);
			
			}/* if (line_objid != ....) 								*/
		
		/* We do not need to free mem allocated to routing_protocols_lptr	*/
		/* because the list is being used in the iface info structure		*/
		}/* for (i = 0;...) 												*/

	if (module_data.gateway_status == OPC_TRUE)
		{
		/* If any "VLAN Interfaces" were configured and this node has	*/
		/* an interface to the switch module, add virtual interfaces to	*/
		/* the interface table.											*/
		
		total_interfaces += ip_dispatch_virtual_ifaces_add (intf_info_attrs.num_physical_interfaces, lsp_signaling_protocol, 
								&intf_objid_lookup_tables, &routing_instance_list, active_custom_rte_proto_label_lptr);
		
		/* Get the configured Policy Routing attribute			*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, "Local Policy", &local_policy_name);

		/* Store the name of the policy if its configured		*/
		if (strcmp (local_policy_name, "None") != 0)
			{
			module_data.local_policy_name = (char *) op_prg_mem_alloc (sizeof (char) * (strlen (local_policy_name) + 1));
			strcpy (module_data.local_policy_name, local_policy_name);
			}

		/* Destroy the table used to lookup the objid of IPv6 interfaces	*/
		if (intf_objid_lookup_tables.ipv6_table != IpC_Intf_Name_Objid_Table_Invalid)
			{
			op_pro_destroy (module_data.ipv6_prohandle);
			ip_dispatch_intf_objid_lookup_table_destroy (intf_objid_lookup_tables.ipv6_table);
			}

		/* Destroy the PIM and IGMP tables also.							*/
		ip_dispatch_intf_objid_lookup_table_destroy (intf_objid_lookup_tables.pim_table);
		ip_dispatch_intf_objid_lookup_table_destroy (intf_objid_lookup_tables.igmp_table);
		}
	
	/* Read the attributes of tunnel interfaces. This has to be done after	*/
	/* the VLAN interfaces are read, because tunnel interfaces can select	*/
	/* VLAN interfaces as "tunnel source". To be able to validate a VLAN	*/
	/* interface configured as the tunnel source of a tunnel interface, all	*/
	/* the VLAN	intercaces have to be already parsed and recorded before	*/
	/* the information records of the tunnel interfaces are created.		*/
	for (i = 0, intf_list_size = op_prg_list_size (module_data.interface_table_ptr); i < intf_list_size; i++)
		{
		/* Get the iterface record and check whether it is a tunnel			*/
		/* interface.														*/
		iface_info_ptr = (IpT_Interface_Info *) op_prg_list_access (module_data.interface_table_ptr, i);
		if (iface_info_ptr->phys_intf_info_ptr->intf_status == IpC_Intf_Status_Tunnel)
			{
			/* Read the tunnel specific attributes.							*/

			/* The order of tunnel interfaces in the list is the same as 	*/
			/* the order of the stored objids in the list.					*/
			intf_objid_ptr = (Objid *) op_prg_list_remove (&tunnel_intf_objid_list, OPC_LISTPOS_HEAD);
			iface_info_ptr->tunnel_info_ptr = 
				ip_dispatch_tunnel_attrs_read (*intf_objid_ptr, ip_rte_intf_name_get (iface_info_ptr));
			op_prg_mem_free (intf_objid_ptr);
			
			/* For tunnel interfaces the MTU value must be adjusted so that	*/
			/* the outer header and (optional) GRE header can also be		*/
			/* accommodated in the total MTU size.							*/
			if (iface_info_ptr->tunnel_info_ptr != OPC_NIL)
				{
				iface_info_ptr->mtu -= (int) ((iface_info_ptr->tunnel_info_ptr->hdr_size_bits + IPC_DGRAM_HEADER_LEN_BITS) / 8.0);
				
				if (iface_info_ptr->mtu < IPC_DGRAM_HEADER_LEN_BYTES)
					{
					iface_info_ptr->mtu = IPC_DGRAM_HEADER_LEN_BYTES + 1;
					ip_nl_tunnel_mtu_log_write (ip_rte_intf_name_get (iface_info_ptr));
					}

				/* Also, schedule a call at end of simulation to update		*/
				/* bgutil stats for	tunnel traffic sent and received. Since	*/
				/* the function handles all tunnel interfaces on the node,	*/
				/* schedule the call only once.								*/
				if (OPC_FALSE == endsim_tunnel_stat_call_scheduled)
					{
					op_intrpt_schedule_call (OPC_INTRPT_SCHED_CALL_ENDSIM, 0,
						ip_dispatch_endsim_tunnel_stats_write, &module_data);
					endsim_tunnel_stat_call_scheduled = OPC_TRUE;
					}

				/* If this is an IPv6 automatic tunnel, call the function	*/
				/* that will set the appropriate attributes.				*/
				if (IpC_Tunnel_Mode_IPv6_Auto == ip_rte_intf_tunnel_mode_get (iface_info_ptr))
					{
					ip_dispatch_ipv6_auto_tunnel_attrs_set (iface_info_ptr);
					}
				}			
			}
		else
			/* The interface is not a tunnel interface.						*/
			iface_info_ptr->tunnel_info_ptr = OPC_NIL;
		}
	
	/* Now that the interfaces list has been set, create a simulation log	*/
	/* entry notifying user's of the result of shutdown interfaces.			*/
	/* Write a sim log entry warning user of configuration effects 			*/
	if (op_prg_list_size (shutdown_intf_lptr) > 0)
		{
		ipnl_shutdown_intf_log_write (shutdown_intf_lptr);
		}
	
	/* Free the memory from the list 									*/
	op_prg_mem_free (shutdown_intf_lptr);

	/* If this is a dual MSFC running in dual router mode, the logical	*/
	/* interfaces (loopback, tunnel and VLAN) will have two addresses	*/
	/* each. The addresses belonging to the non-designated MSFC card	*/
	/* are treated as belonging to a different interface. Dummy 		*/
	/* loopback interfaces are created for each address in order to be	*/
	/* able to source and sink traffic to these addresses.				*/
	if (ip_node_is_dual_msfc_in_drm (&module_data))
		total_interfaces += ip_dispatch_dual_msfc_alt_config_parse ();	
	
	/* Call the function that would create a single array of all the	*/
	/* physical and subinterfaces. This function will also populate		*/
	/* the array that stores the interface index corresponding to each	*/
	/* input stream.													*/
	ip_dispatch_intf_table_create (total_interfaces, highest_instrm);
	
	/* Initialize the IP common route table and the static routing table.	*/
	ip_dispatch_route_table_init ();		
	
	/* Now that the addressing is done deallocate the memory for the 	*/
	/* radio interface table and its entries.							*/
	while (op_prg_list_size (radio_intf_list_ptr))
		{
		ip3_link_iface_entry_destroy ((IpT_Link_Iface_Entry *)
			op_prg_list_remove (radio_intf_list_ptr, OPC_LISTPOS_HEAD));
		}
	
	/* Free the memory for the list itself								*/
	op_prg_mem_free (radio_intf_list_ptr);
	
	/* In case of a Router running OSPF with all connected interfaces	*/
	/* as unnumbered link interfaces, the router ID is registered as 	*/
	/* local network address. This function initially checks if all the	*/
	/* interfaces of the router are unnumbered and if so gets the 		*/
	/* Router ID from the OSPF model attribute called "Router ID". 		*/
	ip_register_routerid_as_local_netaddr ();
	
	/* Verify that the interface addresses don't overlap. */
	ip_interface_table_verify (&module_data);
	
	/** At this time, the routing_protos SV has bits set for those	**/
	/** routing protocols that have been "individually" activated	**/
	/** on those interfaces that have been discovered in this node.	**/
	/** For each such routing protocol, the following must now be	**/
	/** done:														**/
	/**		1.	Get a reference to the OMS PR record for the		**/
	/**			routing protocol.									**/	
	/**		2.	Store the result from 1 (above) in the appropriate	**/
	/**			member of the IpT_Cmn_Rte_Table object that			**/
	/**			represents the IP Routing Table for this node.		**/
	/**		3.	Get the parent module object ID of the routing		**/
	/**			protocol process instance in this node and issue	**/
	/**			a remote interrupt to it.							**/
	/**																**/
	/**	NOTE:	Step 3. is not carried out if we are importing the	**/
	/**			routing tables in the simulation. This is determined**/
	/**			by the value to which the global var.				**/
	/**			routing_table_import_export_flag is set.			**/
	/**																**/
	/** All of this is done by the ip_local_dyn_route_protos_invoke	**/
	/** procedure that is invoked below.							**/
	/** The ip_local_dyn_route_protos_invoke procedure takes a list	**/
	/** as an argument, which has the custom routing protocol labels**/
	/** running on this node. For each of the custom routing		**/
	/** protocol label in this list the procedure issues a remote	**/
	/** interrupt.													**/
	
	/* Get the no of active custom routing protocols running on this node.	*/
	active_custom_rte_protos_size = op_prg_list_size (active_custom_rte_proto_label_lptr);

	if ((module_data.gateway_status == OPC_TRUE || passive_rip == OPC_TRUE) &&
		(ip_manet_is_enabled (&module_data) == OPC_FALSE) &&
		((module_data.routing_protos != 0) || (active_custom_rte_protos_size != 0)))
		{
		/* If we are not importing our routing tables, "wake up" the	*/
		/* routing protocols configured on this node.					*/
		if (routing_table_import_export_flag != IP_RTE_TABLE_IMPORT)  
			{		
			ip_local_dyn_route_protos_invoke (module_data.routing_protos, IPC_OPERATE_ROUTING_PROTO, 
				active_custom_rte_proto_label_lptr);
			}	
		/* Else, if we are importing our routing tables, do steps 1		*/
		/* and 2 above but not 3.										*/
		else 
			{
			ip_local_dyn_route_protos_invoke (module_data.routing_protos, IPC_STALL_ROUTING_PROTO,
				active_custom_rte_proto_label_lptr);
			}
		
		/* Parse the Static Route table for this node and add all	*/
		/* networks that have not been processed to the NATO table.	*/
		/* This way, networks that have been configured as static	*/
		/* routes but not actually configured in the network can	*/
		/* appear in routing tables by way of redistribution.		*/
		ip_rte_add_routes_to_nato_table (module_data.node_id, module_data.module_id,
			module_data.ip_parameters_objid, "Static Routing Table", "Destination Address",
			"Subnet Mask", IPC_RTE_TABLE_SMASK_CLASS_BASED);
		}
	
	/* If this is a router, initialize rte map table, the AS number		*/
	/* and the router ID												*/
	if (module_data.gateway_status == OPC_TRUE)
		{
		/* Read in the AS Number attribute								*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, "Autonomous System Number",
								&module_data.as_number);

		/* Get an AS number assignment if it is Auto-assigned			*/
		if (module_data.as_number == IPC_AS_NUMBER_AUTOASSIGNED)
			module_data.as_number = ip_rte_as_number_get ();

		/* Read in the Router ID attribute								*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, "Router ID", rtr_id_str);

		/* If it is set to Auto Assigned, calculate the router ID		*/
		if (!strcmp (rtr_id_str, IPC_ROUTER_ID_STR_AUTOASSIGNED))
			{
			module_data.router_id = ip_rte_router_id_calculate ();
			}
		else
			{
			/* The router ID is a string attribute. Convert it to an 	*/
			/* 32 bit unsigned int (IP Address)							*/
			module_data.router_id = ip_address_create (rtr_id_str);
			}

		/* Spawn the ip_grouping process if there are any aggregate interfaces	*/
		if (module_data.group_info_ptr != OPC_NIL)
			{
			module_data.group_info_ptr->ip_grouping_prohandle = op_pro_create ("ip_grouping", OPC_NIL);
			op_pro_invoke (module_data.group_info_ptr->ip_grouping_prohandle, intf_objid_lookup_tables.rsvp_table);
			}
		}

	/* If there are demands originating or terminating from/at this		*/
	/* node, it is a potential background traffic source/sink. Create	*/
	/* child process to perform the same.								*/
	if ((op_topo_assoc_count(module_data.node_id, OPC_TOPO_ASSOC_OUT, OPC_OBJTYPE_DEMAND_FLOW)>0)||
		(op_topo_assoc_count(module_data.node_id, OPC_TOPO_ASSOC_IN, OPC_OBJTYPE_DEMAND_FLOW)>0) ||
		(op_topo_assoc_count(module_data.node_id, OPC_TOPO_ASSOC_OUT, OPC_OBJTYPE_PATH)>0))
		{
		/* Spawn oms_basetraf_src.  This child process will generate 	*/
		/* tracer packets containing traffic information about          */
		/* src/dest conversation pairs as specified in the TIM file.    */
		/* If this node has no TIM destinations or if there is no 		*/
		/* TIM file, the oms_basetraf_src child process will not have 	*/
		/* any effect.													*/
		/* When we create the child process, we install shared memory,  */
		/* which we will later use to receive a packet from the child.  */
		child_prohandle = op_pro_create ("oms_basetraf_src", 
			&module_data.ip_ptc_mem);
		op_pro_invoke (child_prohandle, OPC_NIL);
		
		/* Store the process ID of this child process for later use. It	*/
		/* will be later used to distinguish that a packet came from	*/
		/* basetraf child process (as opposed to ICMP child process.	*/
		oms_basetraf_process_id = op_pro_id (child_prohandle);
		
		/* Spawn security_demand_ src. This child process will generate	*/
		/* tracer packets containing security check info.				*/
		/* When we create the child process, we install shared memory,  */
		/* which we will later use to receive a packet from the child.  */
		child_prohandle = op_pro_create ("ip_security_demand_src", 
								&module_data.ip_ptc_mem);
	
		/* Invoke the ip_security process								*/	
		op_pro_invoke (child_prohandle, OPC_NIL);
		}
	
	/* If MPLS Parameters exist then get the MPLS info for each interface	*/
	if (op_ima_obj_attr_exists (module_data.node_id, "MPLS Parameters") == OPC_TRUE)
		{
		/* Set the MPLS Interface information for all ifaces on this node	*/
		mpls_support_iface_mpls_info_set (module_data.node_id, module_data.interface_table_ptr, &module_data);
		}
	
	/* Destroy the temporary table created to read RSVP interface information.	*/
	ip_rte_proto_intf_attr_objid_table_destroy (intf_objid_lookup_tables.rsvp_table);
	
	/* This is required only if fail-rec node is in the network or if 	*/
	/* tunnel interfaces are configured on this node (future req).		*/
	child_prohandle = op_pro_create ("ip_observer", OPC_NIL);
	op_pro_invoke (child_prohandle, OPC_NIL);
	
	/* We have to migrate IP immediately as these interrupts are being steered */
	op_intrpt_type_register (OPC_INTRPT_FAIL, child_prohandle);
	op_intrpt_type_register (OPC_INTRPT_RECOVER, child_prohandle);
	
	/* Register with the IP Observer to deliver failure-recovery   */
	/* interrupts only about this node and its connected link.     */  
	ip_observer_client_register (module_data.node_id, IPC_INTRPT_TYPE_FAILREC_SPECIFIC_NODE,
		OPC_NIL, module_data.node_name, module_data.ip_root_prohandle, module_data.module_id, OPC_NIL);
	ip_observer_client_register (module_data.node_id, IPC_INTRPT_TYPE_FAILREC_ALL_LOCAL_LINKS, 
		OPC_NIL, module_data.node_name, module_data.ip_root_prohandle, module_data.module_id, OPC_NIL);
		
	/* Additional initialization (routers only).				*/
	if (module_data.gateway_status == OPC_TRUE)
		{
		/* The interface table has been built. Interface specific configuration */
		/* for MPLS and VPNs can now be read. 									*/
		ip_dispatch_interface_mpls_init ();
	
		/* Pass the temporary list of routing instance information to the VPN	*/
		/* init function. The called function will free up all dynamic memory	*/
		/* that needs to be freed.												*/
		ip_dispatch_interface_vpns_init (&routing_instance_list);
		
		/* Read PIX and NAT parameters. PIX parameters must be read before NAT.	    */
		/* NAT parameters may refer to aliases defined in the PIX parameters.		*/
		ip_pix_init (&module_data);
		ip_nat_init (&module_data);
		}
	
	/* Enable IP Common Route Table export  */
	/* 	If this IP node is a gateway, OR 	*/
	/* 	If node is configured to run MANET  */
	/* 	routing protocol 					*/
	if ((module_data.gateway_status == OPC_TRUE)||
		(ip_manet_is_enabled (&module_data)))
		{
		/* Export the common rte table if configured							*/
		ip_cmn_rte_table_export (OPC_NIL, 0);

		/* Check the IP Global Rte Export attribute to determine if there will be */
		/* any global exports of the IP Common Route Tables of the IP Routers	  */
		ip_global_rte_export (OPC_NIL, 0);
		}
	
	FOUT;
	}

static void
ip_dispatch_subintf_info_read (IpT_Interface_Info* parent_intf_ptr, Objid subintf_info_attr_objid, 
	IpT_Intf_Objid_Lookup_Tables* intf_objid_lookup_tables_ptr, int num_subinterfaces,
	List* active_custom_rte_proto_label_lptr, int lsp_signaling_protocol, 
	Boolean is_vlan_iface, List* routing_instance_lptr)
	{
	int						count_i, count_j;
	IpT_Interface_Info*		subintf_info_ptr;
	IpT_Interface_Info**	subinterface_info_pptr;
	Objid					ith_subintf_objid;
	char					addr_str[IPC_MAX_STR_SIZE];
	IpT_Address				ip_addr;
	IpT_Address				subnet_mask;
	char					subintf_name[IPC_MAX_STR_SIZE];
	List*					routing_protocols_lptr = OPC_NIL;
	Boolean					status;
	int						num_valid_subinterfaces;
	char					comp_info_str[IPC_MAX_STR_SIZE];
	Compcode				unnumbered_status;
	Boolean					intf_unnumbered;
	char*					unnumbered_intf_name;
	
	Objid					pkt_filter_objid;
	char					policy_routing_name [256];
	InetT_Address			temp_inet_addr;
	Objid					ipv6_attrs_objid;
	char					routing_instance_str [64];
	IpT_Intf_Routing_Instance* routing_instance_ptr;

	/** Function that reads in the subinterfaces defined under the	**/
	/** Subinterface Information compound attribute. This function	**/
	/** will then appropriately set the subintf_tbl_ptr attribute	**/
	/** in the parent interface 									**/
	
	FIN (ip_dispatch_subintf_info_read (parent_intf_ptr, subintf_info_attr_objid,.....));
	
	/* Allocate memory to store the array of subinterfaces.			*/
	subinterface_info_pptr = (IpT_Interface_Info**) op_prg_mem_alloc (num_subinterfaces * sizeof (IpT_Interface_Info*));

	/* Assume that all subinterfaces are valid. If invalid or		*/
	/* shutdown subinterfaces are encountered, this value will be	*/
	/* decremented.													*/
	num_valid_subinterfaces = num_subinterfaces;
	
	/* Now loop through each subinterface and read in its attributes*/
	for (count_i = 0; count_i <  num_subinterfaces; count_i++)
		{		
		/* Get the objid of the appropriate row.					*/
		ith_subintf_objid = op_topo_child (subintf_info_attr_objid, OPC_OBJTYPE_GENERIC, count_i);
		
		/* First check whether this interface is active				*/
		op_ima_obj_attr_get (ith_subintf_objid, "Status", &status);
		
		if (OPC_FALSE == status)
			{
			/* This subinterface is shutdown. skip it.				*/
			--num_valid_subinterfaces;
			subinterface_info_pptr[count_i] = OPC_NIL;
			continue;
			}

		/* Obtain the name of the subinterface						*/
		op_ima_obj_attr_get (ith_subintf_objid, "Name", subintf_name);
		
		/* Check if there is a row corresponding to this			*/
		/* subinterface under IPv6 parameters.						*/
		ipv6_attrs_objid = ip_rte_proto_intf_attr_objid_table_lookup_by_name
			(intf_objid_lookup_tables_ptr->ipv6_table, subintf_name);

		/* Get the list of routing protocols enabled on this 		*/
		/* interface												*/
		routing_protocols_lptr = ip_interface_routing_protocols_obtain (ith_subintf_objid,
			ipv6_attrs_objid, IpC_Intf_Status_Active, active_custom_rte_proto_label_lptr);

		/* Check for unnumbered interfaces.							*/
		unnumbered_status = ip_unnumbered_address_resolve (ith_subintf_objid, ip_rte_intf_ip_addr_index_get (parent_intf_ptr),
			count_i, routing_protocols_lptr, &intf_unnumbered, &unnumbered_intf_name,
			ip_rte_intf_conn_link_objid_get (parent_intf_ptr));

		/* Obtain the IP address assigned to this subinterface		*/
		op_ima_obj_attr_get (ith_subintf_objid, "Address", addr_str);
		
		/* If there was an error, ignore this subinterface.			*/
		if (OPC_COMPCODE_FAILURE == unnumbered_status)
			{
			ipnl_invalid_address_for_subinterface_log_write 
				(subintf_name, ip_rte_intf_name_get (parent_intf_ptr), addr_str);
			continue;
			}

		/* Handle no ip address interfaces							*/
		if (!strcmp (addr_str, IPC_NO_IP_ADDRESS))
			{
			/* This subinterface will not have an ip address		*/
			/* Internally this will be represented by an address of	*/
			/* 0.0.0.0 and a mask of 255.255.255.255				*/
			ip_addr = ip_address_copy (IpI_No_Ip_Address);
			subnet_mask = ip_address_copy (IpI_Broadcast_Addr);
			}
		else
			{
			/* Make sure the string specified is a valid ip address	*/
			if ((0 == strcmp (addr_str, "0.0.0.0")) ||
				(!intf_unnumbered && (OPC_FALSE == ip_address_string_test (addr_str))))
				{
				/* Print a log message.								*/
				ipnl_invalid_address_for_subinterface_log_write 
					(subintf_name, ip_rte_intf_name_get (parent_intf_ptr), addr_str);

				if (op_prg_odb_ltrace_active ("ip_addressing"))
					{
					char msg1 [256], msg2 [256];
					sprintf (msg1, "The string %s specified as address of the interface", addr_str);
					sprintf (msg2, "%s.%s is invalid. This subinterface will be ignored",
								  ip_rte_intf_name_get (parent_intf_ptr), subintf_name);

					op_prg_odb_print_major (msg1, msg2, OPC_NIL);
					}

				/* Ignore this subinterface							*/
				--num_valid_subinterfaces;
				subinterface_info_pptr[count_i] = OPC_NIL;
				continue;
				}

			/* A valid IP address was assigned.						*/
			ip_addr = ip_address_create (addr_str);

			/* Read in the subnet mask.								*/
			op_ima_obj_attr_get (ith_subintf_objid, "Subnet Mask", addr_str);

			/* If the subnet mask was auto assigned, use the default*/
			/* subnet mask.											*/
			if (!strcmp (addr_str, IPC_AUTO_ADDRESS))
				{
				subnet_mask = ip_default_smask_create (ip_addr);
				}
			else
				{
				subnet_mask = ip_address_create (addr_str);
				}
			}

		/* Set the appropriate bits in the routing_options field in	*/
		/* module_data. The value of this field will be used to		*/
		/* decide which routing protocols are going to be invoked.	*/
		ip_dispatch_routing_options_add (routing_protocols_lptr);

		/* Allocate memory to store this subinterface				*/
		subintf_info_ptr = ip_interface_info_create (IPC_SUBINTF);

		/* Initialize the pointer to the structure that stores the	*/
		/* physical interface information. As a memory optimization	*/
		/* subinterfaces share this structure with their parent		*/
		subintf_info_ptr->phys_intf_info_ptr = parent_intf_ptr->phys_intf_info_ptr;

		/* Store the row number of this subinterface				*/
		subintf_info_ptr->subintf_addr_index = count_i;

		/* Store the name of the subinterface.						*/
		ip_rte_intf_name_set (subintf_info_ptr, subintf_name);
		
		/* For unnumbered interfaces, store the source interface also*/
		if (intf_unnumbered)
			{
			subintf_info_ptr->unnumbered_info = (IpT_Unnumbered_Info*) op_prg_mem_alloc (sizeof (IpT_Unnumbered_Info));
			subintf_info_ptr->unnumbered_info->interface_name = unnumbered_intf_name;

			/* Set the flag indicating that this node has at least	*/
			/* one unnumbered interface.							*/
			module_data.unnumbered_interface_exists = OPC_TRUE;
			}
		else
			{
			subintf_info_ptr->unnumbered_info = OPC_NIL;
			}

		/* Unless the IP address was set to No IP Address,  Set the	*/
		/* address range and network address for this intf			*/
		if (! ip_address_equal (ip_addr, IpI_No_Ip_Address))
			{
			subintf_info_ptr->addr_range_ptr = ip_address_range_create (ip_addr, subnet_mask);
			subintf_info_ptr->network_address = ip_address_mask (ip_addr, subnet_mask);
			subintf_info_ptr->inet_addr_range = inet_ipv4_address_range_create (ip_addr, subnet_mask);

			/* Read secondary IP addresses, if configured on this sub-interface */
			ip_dispatch_secondary_ip_addresses_read (subintf_info_ptr, ith_subintf_objid);					
			}

		/* Read in the MTU.											*/
		op_ima_obj_attr_get (ith_subintf_objid, "MTU", &(subintf_info_ptr->mtu));
		
		/* Check if the MTU was set as Same as parent, then use the */
		/* parent interfaces MTU.									*/
		if (IPC_MTU_SAME_AS_PARENT == subintf_info_ptr->mtu)
			{
			subintf_info_ptr->mtu = parent_intf_ptr->mtu;
			}
		/* Read in the Metrics specified for this subinterface.		*/
		subintf_info_ptr->user_metrics = ip_intf_metrics_read (ith_subintf_objid,
			subintf_info_ptr->phys_intf_info_ptr->link_bandwidth);

		subintf_info_ptr->avail_bw = subintf_info_ptr->phys_intf_info_ptr->link_bandwidth;
		
		/* Get the RSVP status and max reservable bw for the		*/
		/* subinterface. Skip this step for aggregate interfaces.	*/
		if (IpC_Intf_Status_Group != ip_rte_intf_status_get (parent_intf_ptr))
			{
			ip_rte_iface_rsvp_info_set (&subintf_info_ptr->avail_bw,
										((double) subintf_info_ptr->user_metrics->bandwidth * 1000.0),
										&subintf_info_ptr->flags, 
										intf_objid_lookup_tables_ptr->rsvp_table,
										subintf_name,
										lsp_signaling_protocol);
			}
		
		/* If RSVP is enabled on the subinterface, then set the module	*/
		/* RSVP status.												*/	
		if (ip_rte_intf_rsvp_enabled (subintf_info_ptr))
			module_data.rsvp_status 		= OPC_TRUE;

		/* Store the routing protocols list in the subinterface 	*/
		/* information												*/
		subintf_info_ptr->routing_protocols_lptr = routing_protocols_lptr;

		/* Find out if multicast has been enabled in this interface	*/
		/* OSPF and EIGRP use multicast. So if they are configured	*/
		/* on the interface, then mcast must be enabled.			*/
		if (ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Ospf)||
			ip_interface_routing_protocols_contains (routing_protocols_lptr, IpC_Rte_Eigrp))
			{
			ip_rte_intf_mcast_enabled_set (subintf_info_ptr, OPC_TRUE);
			}
		
		/* Find whether IGMP is enabled on this subinterface.	*/
		if (ip_igmp_iface_enabled (intf_objid_lookup_tables_ptr->igmp_table, subintf_name))
			subintf_info_ptr->flags |= IPC_INTF_FLAG_IGMP_ENABLED; 
	   
		/* Read in the Compression Information						*/
		op_ima_obj_attr_get (ith_subintf_objid, "Compression Information", comp_info_str);
		
		/* Retrieve the information about the compression scheme	*/
		/* used for this interface from the network-wide attribute	*/
		/* database. Use the comp_info_str (name) as the reference.	*/
		subintf_info_ptr->comp_info = (IpT_Compression_Info *)
			oms_data_def_entry_access ("IP Compression Information", 
			comp_info_str);
		
		if (OPC_NIL == subintf_info_ptr->comp_info)
			{
			/* The specified compression scheme does not exists		*/
			/* in the attribute database. Add an entry into			*/
			/* the simulation notification log.						*/
			ipnl_cfgwarn_unknown_comp_scheme (subintf_name, comp_info_str);
			
			/* Set the compression scheme to "None" as default for	*/
			/* the interface.										*/
			subintf_info_ptr->comp_info = (IpT_Compression_Info *)
				oms_data_def_entry_access ("IP Compression Information", "None");
			}

		/* Initialize the Packet filter and Policy Routing name		*/		 
	   	subintf_info_ptr->policy_routing_name = OPC_NIL;
		subintf_info_ptr->filter_info_ptr 	= OPC_NIL;

		/* If Packet Filter attribute exist for this interface then	*/
		/* get send and receive filters configured for this	iface	*/
		if (op_ima_obj_attr_exists (ith_subintf_objid, "Packet Filter"))
			{
			/* Get the object ID of the packet filter attribute		*/
			op_ima_obj_attr_get (ith_subintf_objid, "Packet Filter", &pkt_filter_objid);
			
			/* Get the configured filter info						*/	
			subintf_info_ptr->filter_info_ptr = Inet_Acl_Filter_Read (&module_data, pkt_filter_objid, OPC_NIL);
			}
			 
		/* If Policy Routing attribute exist for this interface		*/
	    /* then	get the Route Map for this interface				*/
		if (op_ima_obj_attr_exists (ith_subintf_objid, "Policy Routing"))
			{
			/* Get the configured Policy Routing attribute			*/
			op_ima_obj_attr_get (ith_subintf_objid, "Policy Routing", &policy_routing_name);

			/* Store the name of the policy if its configured		*/
			if (strcmp (policy_routing_name, "None") != 0)
				{
				subintf_info_ptr->policy_routing_name = (char *) op_prg_mem_alloc (
					sizeof (char) * (strlen (policy_routing_name) + 1));
				strcpy (subintf_info_ptr->policy_routing_name, policy_routing_name);
				}
			}

		/* Read Routing Instance, if present. The routing instance is stored	*/
		/* in a temporary list and is then converted into an array, after the	*/
		/* interface table is built. 											*/
		if (module_data.gateway_status == OPC_TRUE)
			{
			/* Do not read the routing interface for VLAN interfaces.	*/
			if (!is_vlan_iface)
				{
				op_ima_obj_attr_get_str (ith_subintf_objid, "Routing Instance", 64, routing_instance_str);
			
				/* If some routing instance is present, store it.	*/
				if (strcmp (routing_instance_str, "None") != 0)
					{
					routing_instance_ptr = ip_dispatch_intf_routing_instance_create (subintf_name, routing_instance_str);
					op_prg_list_insert (routing_instance_lptr, routing_instance_ptr, OPC_LISTPOS_TAIL);
					}
				}
			}
		
		if (is_vlan_iface == OPC_TRUE)
			{
			ip_dispatch_vlan_id_read (subintf_info_ptr, ith_subintf_objid);
			}
		else
			{			   	   
			/*	Read in the information entered under the Layer 2 		*/
			/*	Mappings attribute										*/
			ip_dispatch_layer2_mappings_read (subintf_info_ptr, ith_subintf_objid);
			}

		/* Register the Ip address of this subinterface in the global	*/
		/* Ip table used to associate Ip addresses with lower layer		*/
		/* addresses. This table is managed by the nato sub-package.	*/
		/* the Ip routing process makes this package available to other	*/
		/* processes like ARP through the process registry				*/
		temp_inet_addr = inet_address_from_ipv4_address_create (ip_addr);
		ip_rtab_local_addr_register (&temp_inet_addr, &module_data);

		/* Like the global table for interface addresses, another		*/
		/* global table is is maintained for all the possible Ip 		*/
		/* networks in the model. Register the network address of this	*/
		/* subinterface in that table.									*/
		temp_inet_addr = inet_address_from_ipv4_address_create (subintf_info_ptr->network_address);
		ip_rtab_local_network_register (&temp_inet_addr);

		/* If we found a matching row, read in the IPv6 attributes of	*/
		/* this subinterface.											*/
		if (OPC_OBJID_INVALID != ipv6_attrs_objid)
			{
			ip_dispatch_gtwy_ipv6_attrs_read (ipv6_attrs_objid, subintf_info_ptr);
			}

		/* Store this subinterface in the array							*/
		subinterface_info_pptr[count_i] = subintf_info_ptr;
		} /* for (count_i =0;..... */
	
	/* Set the number of valid subinterfaces in the parent.				*/
	parent_intf_ptr->phys_intf_info_ptr->num_subinterfaces = num_valid_subinterfaces;

	/* If all the subinterfaces were valid, we do not need to create a	*/
	/* new array of pointers for the subinterface table of the parent	*/
	/* We can use the one we created in this function					*/
	if (num_valid_subinterfaces == num_subinterfaces)
		{
		parent_intf_ptr->phys_intf_info_ptr->subintf_pptr = subinterface_info_pptr;
		FOUT;
		}
	/* If there were no valid subinterfaces at all, set the subinterface*/
	/* table pointer to OPC_NIL. and free the memory allocated to the 	*/
	/* list in this function											*/
	if (0 == num_valid_subinterfaces)
		{
		parent_intf_ptr->phys_intf_info_ptr->subintf_pptr = OPC_NIL;
		op_prg_mem_free (subinterface_info_pptr);
		FOUT;
		}

	/* If some of the subinterfaces were invalid or shutdown, we need	*/
	/* create a new array of the appropriate size and copy the valid	*/
	/* subinterfaces alone.												*/

	/* Allocate enough memory.										*/
	parent_intf_ptr->phys_intf_info_ptr->subintf_pptr = (IpT_Interface_Info**)
		op_prg_mem_alloc (num_valid_subinterfaces * sizeof (IpT_Interface_Info*));
	
	/* Copy the valid subinterfaces alone.							*/
	for (count_i = 0, count_j = 0; count_i < num_subinterfaces; count_i++)
		{
		/* If it is a valid interface copy it and increment the 	*/
		/* the index of the new array.								*/
		if (OPC_NIL != subinterface_info_pptr[count_i])
			{
			parent_intf_ptr->phys_intf_info_ptr->subintf_pptr[count_j] = subinterface_info_pptr[count_i];
			count_j++;
			}
		}
	
	/* Deallocate the memory for the original array.				*/
	op_prg_mem_free (subinterface_info_pptr);

	FOUT;	
	}

static void
ip_dispatch_intfs_count (IpT_Intf_Info_Attrs* intf_info_attrs_ptr)
	{
	/** Populate the memebers of the IpT_Intf_Info_Attrs structure.	**/

	FIN (ip_dispatch_intfs_count (intf_info_attrs_ptr));

	/* Obtain a handle on the interface table. This attribute is 	*/
	/* a compound attribute (i.e., an  object) whose sub-objects	*/
	/* are individual interfaces. 									*/
	op_ima_obj_attr_get (module_data.ip_parameters_objid, "Interface Information", &comp_attr_objid);
	intf_info_attrs_ptr->phys_intf_comp_attr_objid = comp_attr_objid;

	/* Determine the number of interfaces in the table.				*/
	module_data.num_interfaces = op_topo_child_count (intf_info_attrs_ptr->phys_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC);
	intf_info_attrs_ptr->num_physical_interfaces = module_data.num_interfaces;
	
	/* Store the number of physical interfaces.						*/
	module_data.num_phys_interfaces = intf_info_attrs_ptr->num_physical_interfaces;

	/* For gateway nodes, consider loopback, tunnel and aggregate	*/
	/* interfaces also.												*/
	if (module_data.gateway_status == OPC_TRUE)
		{
		/* Add loopback interfaces also the total number of interfaces	*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, "Loopback Interfaces", &(intf_info_attrs_ptr->loop_intf_comp_attr_objid));
		intf_info_attrs_ptr->num_loopback_interfaces = op_topo_child_count (intf_info_attrs_ptr->loop_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC);
		module_data.num_interfaces += intf_info_attrs_ptr->num_loopback_interfaces;

		/* Add tunnel interfaces also the total number of interfaces	*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, "Tunnel Interfaces",
			&(intf_info_attrs_ptr->tunnel_intf_comp_attr_objid));
		intf_info_attrs_ptr->num_tunnel_interfaces = op_topo_child_count
			(intf_info_attrs_ptr->tunnel_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC);
		module_data.num_interfaces += intf_info_attrs_ptr->num_tunnel_interfaces;

		/* Add aggregate interfaces also to the total number of		*/
		/* interfaces.												*/
		op_ima_obj_attr_get (module_data.ip_parameters_objid, "Aggregate Interfaces",
			&(intf_info_attrs_ptr->aggr_intf_comp_attr_objid));
		intf_info_attrs_ptr->num_aggr_interfaces = op_topo_child_count
			(intf_info_attrs_ptr->aggr_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC);
		module_data.num_interfaces += intf_info_attrs_ptr->num_aggr_interfaces;

		/* If the number of aggregate interfaces is non-zero,		*/
		/* allocate memory for the group info structure.			*/
		if (intf_info_attrs_ptr->num_aggr_interfaces > 0)
			{
			module_data.group_info_ptr = (IpT_Grouping_Info*) op_prg_mem_alloc (sizeof (IpT_Grouping_Info));
			}
		}
	else
		{
		/* End stations do  not have any logical interfaces.		*/
		intf_info_attrs_ptr->num_loopback_interfaces = 0;
		intf_info_attrs_ptr->num_tunnel_interfaces = 0;
		intf_info_attrs_ptr->num_aggr_interfaces = 0;
		}

	FOUT;
	}

static void
ip_dispatch_subintf_ip_version_check (IpT_Interface_Info* phys_intf_info_ptr)
	{
	int					num_subinterfaces;
	Boolean				ipv4_active = OPC_FALSE;
	Boolean				ipv6_active = OPC_FALSE;
	int					subintf_index;
	IpT_Interface_Info*	subintf_ptr;

	/** Because of the way the IP interface table is build, it is	**/
	/** necessary that the same version(s) of IP be enabled on a	**/
	/** physical interface and all its subinterfaces. This function	**/
	/** will loop through all the subinterfaces of a physical		**/
	/** interface and enable IPv4/IPv6 on individual interfaces to	**/
	/** make sure that the above condition is met.					**/

	FIN (ip_dispatch_subintf_ip_version_check (phys_intf_info_ptr));

	/* Get the number of subinterfaces	*/
	num_subinterfaces = ip_rte_num_subinterfaces_get (phys_intf_info_ptr);

	/* Loop through each subinterface and set the ipv4_active and	*/
	/* ipv6_active flags. The ipv4_active flag should be set if		*/
	/* IPv4 is enabled on at least one subinterface. Similarly the	*/
	/* ipv6_active flag should be set if IPv6 is active on at least	*/
	/* one subinterface.											*/
	for (subintf_index = IPC_SUBINTF_PHYS_INTF; subintf_index < num_subinterfaces; subintf_index++)
		{
		/* Get a handle to the ith subinterface.					*/
		subintf_ptr = ip_rte_ith_subintf_info_get (phys_intf_info_ptr, subintf_index);

		/* If IPv4 is enabled on this subinterface, set the			*/
		/* ipv4_active flag.										*/
		ipv4_active = ipv4_active || ip_rte_intf_ipv4_active (subintf_ptr);

		/* If IPv6 is enabled on this subinterface, set the			*/
		/* ipv6_active flag.										*/
		ipv6_active = ipv6_active || ip_rte_intf_ipv6_active (subintf_ptr);
		}

	/* Special case: If all the IPv4 addresses were set to 'No IP	*/
	/* Address' and IPv6 is not active on any of the interfaces,	*/
	/* both the ipv4_active and ipv6_active flags will be false.	*/
	/* If this is case, set the ipv4_active flag.					*/
	if (!ipv4_active && !ipv6_active)
		{
		ipv4_active = OPC_TRUE;
		}

	/* Loop through each subinterface once again, this time enabling*/
	/* IPv4/IPv6 depending on whether the ipv4_active/ipv6_active	*/
	/* flag is set.													*/
	for (subintf_index = IPC_SUBINTF_PHYS_INTF; subintf_index < num_subinterfaces; subintf_index++)
		{
		/* Get a handle to the ith subinterface.					*/
		subintf_ptr = ip_rte_ith_subintf_info_get (phys_intf_info_ptr, subintf_index);

		/* If the ipv4_active flag is set and IPv4 is not enabled	*/
		/* on this interface, enabled IPv4.							*/
		if (ipv4_active && ! ip_rte_intf_ipv4_active (subintf_ptr))
			{
			ip_dispatch_enable_ipv4_on_interface (subintf_ptr);
			}

		/* If the ipv6_active flag is set and IPv6 is not enabled	*/
		/* on this interface, enabled IPv6.							*/
		if (ipv6_active && ! ip_rte_intf_ipv6_active (subintf_ptr))
			{
			ip_dispatch_enable_ipv6_on_interface (subintf_ptr);
			}
		}

	FOUT;
	}

static void
ip_dispatch_enable_ipv4_on_interface (IpT_Interface_Info* iface_info_ptr)
	{
	/** Enable IPv6 on an interface by setting its IPv4 address to	**/
	/** No IP Address.												**/

	FIN (ip_dispatch_enable_ipv4_on_interface (iface_info_ptr));

	iface_info_ptr->addr_range_ptr = ip_address_range_create (IpI_No_Ip_Address, IpI_Broadcast_Addr);
	iface_info_ptr->network_address = ip_address_mask (IpI_No_Ip_Address, IpI_Broadcast_Addr);
	iface_info_ptr->inet_addr_range = inet_ipv4_address_range_create (IpI_No_Ip_Address, IpI_Broadcast_Addr);

	FOUT;
	}

static void
ip_dispatch_enable_ipv6_on_interface (IpT_Interface_Info* iface_info_ptr)
	{
	int						intf_id;
	InetT_Address			link_local_address;
	Ipv6T_Interface_Info*	ipv6_info_ptr;

	/** Enable IPv6 on an interface by assigning it a link local	**/
	/** address.													**/
	
	FIN (ip_dispatch_enable_ipv6_on_interface (iface_info_ptr));
	/* Obtain the Interface ID 										*/
	intf_id = IpI_Interface_ID++;

	/* Create a link local address from the interface ID.			*/
	link_local_address = inet_ipv6_link_local_addr_create (intf_id);

	/* Register the link local address								*/
	ip_rtab_local_addr_register (&link_local_address, &module_data);
	
	/* Allocate memory for the ipv6_info_ptr structure.				*/
	ipv6_info_ptr = (Ipv6T_Interface_Info*) op_prg_mem_alloc (sizeof (Ipv6T_Interface_Info));
	iface_info_ptr->ipv6_info_ptr = ipv6_info_ptr;

	/* Store the interface ID.										*/
	ipv6_info_ptr->intf_id = intf_id;

	/* Allocate enough memory for array of IPv6 addresses. The		*/
	/* only entry will be the link local address.					*/
	ipv6_info_ptr->ipv6_addr_array = (InetT_Address_Range*)
		op_prg_mem_alloc (sizeof (InetT_Address_Range));
	ipv6_info_ptr->num_addresses = 1;
	
	/* Store the link local address range using the default			*/
	/* subnet mask length of 64.									*/
	ipv6_info_ptr->ipv6_addr_array[0] = inet_address_range_create_fast (link_local_address, 64);

	FOUT;
	}

static IpT_Intf_Name_Objid_Table_Handle
ip_dispatch_intf_objid_lookup_table_build (const char* top_level_attr_name)
	{
	Objid								top_level_attr_objid;
	IpT_Intf_Name_Objid_Table_Handle	intf_objid_table;

	/** This function builds a lookup table to find out the			**/
	/** object ID of the row corresponding to a given interface		**/
	/** under attributes like IPv6 Parameters, PIM Parameters etc.	**/

	FIN (ip_dispatch_intf_objid_lookup_table_build (void));

	/* Get the object ID of the top level attribute.				*/
	op_ima_obj_attr_get_objid (module_data.module_id, top_level_attr_name, &top_level_attr_objid);
	top_level_attr_objid = op_topo_child (top_level_attr_objid, OPC_OBJTYPE_GENERIC, 0);

	/* Call the function that will build a hash table to perform the*/
	/* lookup between the interface name and the objid of the 		*/
	/* compound attribute corresponding to the interface.			*/
	intf_objid_table = ip_rte_proto_intf_attr_objid_table_build (top_level_attr_objid);

	FRET (intf_objid_table);
	}

static void
ip_dispatch_intf_objid_lookup_table_destroy (IpT_Intf_Name_Objid_Table_Handle intf_objid_table)
	{
	/** Destory the interface objid hash table						**/

	FIN (ip_dispatch_intf_objid_lookup_table_destroy (intf_objid_table));

	/* Call the free proc.											*/
	if (IpC_Intf_Name_Objid_Table_Invalid != intf_objid_table)
		{
		ip_rte_proto_intf_attr_objid_table_destroy (intf_objid_table);
		}

	FOUT;
	}

static void
ip_dispatch_gtwy_ipv6_attrs_read (Objid ipv6_attrs_objid, IpT_Interface_Info* iface_info_ptr)
	{
	Ipv6T_Arg_Memory		ipv6_arg_memory;

	/** Reads in the IPv6 related attributes of a particular 		**/
	/** interface.													**/
	FIN (ip_dispatch_ipv6_attrs_read (ipv6_attrs_objid, iface_info_ptr));

	/* Fill in the information in the argument memory and invoke the*/
	/* child process.												*/
	ipv6_arg_memory.intf_info_ptr = iface_info_ptr;
	ipv6_arg_memory.ipv6_intf_attr_objid = ipv6_attrs_objid;

	/* Invoke the ipv6 child process to read the information.		*/
	op_pro_invoke (module_data.ipv6_prohandle, &ipv6_arg_memory);

	FOUT;
	}

static void
ip_dispatch_host_ipv6_attrs_read (Objid iface_description_objid, IpT_Interface_Info* iface_info_ptr)
	{
	Objid					ipv6_params_objid;
	char					link_local_addr_str[IPC_MAX_STR_SIZE];
	Ipv6T_Arg_Memory		ipv6_arg_memory;

	/** Check if IPv6 is enabled on this host node. If it is, then	**/
	/** spawn an ipv6 child process and invoke it to read the IPv6	**/
	/** related attributes.											**/

	FIN (ip_dispatch_host_ipv6_attrs_read (ipv6_attrs_objid, iface_info_ptr));

	/* Get the object ID of the IPv6 attributes.					*/
	op_ima_obj_attr_get (iface_description_objid, "IPv6 Parameters", &ipv6_params_objid);
	ipv6_params_objid = op_topo_child (ipv6_params_objid, OPC_OBJTYPE_GENERIC, 0);

	/* If IPv6 is not enabled, the link local address will be set	*/
	/* to "Not Active".												*/
	op_ima_obj_attr_get (ipv6_params_objid, "Link-Local Address", link_local_addr_str);

	if (0 != strcmp (link_local_addr_str, "Not Active"))
		{
		/* IPv6 is active on this node.								*/
		module_data.ipv6_prohandle = op_pro_create ("ipv6", &module_data);

		/* Fill in the information in the argument memory and invoke*/
		/* the child process.										*/
		ipv6_arg_memory.intf_info_ptr = iface_info_ptr;
		ipv6_arg_memory.ipv6_intf_attr_objid = ipv6_params_objid;

		/* Invoke the ipv6 child process to read the information.	*/
		op_pro_invoke (module_data.ipv6_prohandle, &ipv6_arg_memory);

		/* Now that we have read the IPv6 information, kill the		*/
		/* IPv6 process.											*/
		op_pro_destroy (module_data.ipv6_prohandle);
		}

	FOUT;
	}

static IpT_Tunnel_Info*	
ip_dispatch_tunnel_attrs_read (Objid iface_description_objid, char* iface_name)
	{
	Objid						tunnel_description_objid;
	Objid						tunnel_desc_cattr_objid;	
	IpT_Tunnel_Info*			tunnel_info_ptr;
	IpT_Tunnel_Mode				tunnel_mode;
	char						attr_string [128];
	IpT_Interface_Info*			src_intf_ptr;
	InetT_Address				dest_addr;
	Objid						delay_cattr_objid, delay_objid;
	InetT_Address				src_addr;
	IpT_Protocol_Type			proto_number;	
	char						proto_name [128];
	int	   						checksum_enabled;
	IpT_Tunnel_Address_Map*		dest_array;
	int							dest_index, dest_count;
	Objid						tmp_objid, dest_map_objid;

	/** Read in the tunnel specific attributes of a tunnel interface**/
	
	FIN (ip_dispatch_tunnel_attrs_read (iface_description_objid, iface_name));

	/* Tunnel specific information is present in a sub-attribute.	*/
	op_ima_obj_attr_get (iface_description_objid, "Tunnel Information", &tunnel_desc_cattr_objid);
	tunnel_description_objid = op_topo_child (tunnel_desc_cattr_objid, OPC_OBJTYPE_GENERIC, 0);
	
	/* Get the tunnel mode.											*/
	op_ima_obj_attr_get (tunnel_description_objid, "Tunnel Mode", &tunnel_mode);

	/* Register the correct protocol based on tunnel mode so that the	*/
	/* payload information for tunneled packets is outputted correctly	*/
	/* when using packet printing routines in the code or the debugger.	*/
	
	switch (tunnel_mode)
		{
		case IpC_Tunnel_Mode_IPv6_Manual:			
		case IpC_Tunnel_Mode_IPv6_Auto:			
		case IpC_Tunnel_Mode_IPv6_6to4:		
			proto_number = IpC_Protocol_IPv6;
			strcpy (proto_name, "IPv6");
			break;

		case IpC_Tunnel_Mode_GRE:
			proto_number = IpC_Protocol_GRE;
			strcpy (proto_name, "GRE");
			break;
 	
		case IpC_Tunnel_Mode_IPIP:	
			proto_number = IpC_Protocol_Ip;
			strcpy (proto_name, "IP-IP");
			break;
			
		case IpC_Tunnel_Mode_IPsec:
			/* IPsec is currently not supported in DES.	*/
			tunnel_mode = IpC_Tunnel_Mode_GRE;
			proto_number = IpC_Protocol_GRE;
			strcpy (proto_name, "GRE");
			ip_nl_tunnel_mode_ipsec_not_supported_log_write (iface_description_objid);
			break;
		
		default:
			break;
		}	
	

	/* The protocol must be registered as a higher layer protocol	*/
	/* since this will be carried in the IP header. The name is		*/
	/* used to display the contents of the IP packet by the	packet	*/
	/* printing routines.											*/
	
	Inet_Higher_Layer_Protocol_Register (proto_name, (int *) &proto_number);
	
	/* Read in the the source interface specified 					*/
	op_ima_obj_attr_get (tunnel_description_objid, "Tunnel Source", attr_string);

	/* The source may be specified as an interface name or IP address.	*/
	
	/* Check whether the string corresponds to an IP address.	*/
	if (inet_address_string_test (attr_string, InetC_Addr_Family_Unknown) == OPC_TRUE)
		{
		/* Convert the string to an IP address.	*/
		src_addr = inet_address_create (attr_string, InetC_Addr_Family_Unknown);		

		/* We will save the source address also, since a secondary address	*/
		/* or a subinterface/VLAN interface address of an interface may be	*/
		/* specified as the tunnel source.									*/		
		src_intf_ptr = ip_dispatch_find_intf_with_addr (src_addr, module_data.interface_table_ptr);
		}		
	else
		{
		/* String is not an IP address. We assume it to be the interface name.	*/
	
		/* Loop through the interface list and find the specified		*/
		/* interface.													*/
		src_intf_ptr = ip_dispatch_find_intf_with_name (attr_string, module_data.interface_table_ptr);
		
		/* Pick the primary address of the interface as the source address.	*/
		if ((OPC_NIL != src_intf_ptr) && (ip_rte_intf_ipv4_active (src_intf_ptr)))
			src_addr = inet_rte_v4intf_addr_get (src_intf_ptr);
		}

	/* If the source interface could not be found, or if IPv4 is not*/
	/* enabled on it, return NIL.									*/
	if ((OPC_NIL == src_intf_ptr) || (! ip_rte_intf_ipv4_active (src_intf_ptr)))
		{
		ip_nl_tunnel_creation_error_log_write ("Tunnel Source", attr_string);

		FRET (OPC_NIL);
		}
	
	/* Check if this tunnel has multiple destinations. */
	op_ima_obj_attr_get (tunnel_description_objid, "Multipoint Tunnel Destinations", &dest_map_objid);
	dest_count = op_topo_child_count (dest_map_objid, OPC_OBJTYPE_GENERIC);
	if (dest_count > 0)
		{
		/* prepare the map array. */
		dest_array = (IpT_Tunnel_Address_Map*) op_prg_mem_alloc (sizeof (IpT_Tunnel_Address_Map) * dest_count);
		
		/* Parse the destination compound attribute. */
		for (dest_index=0; dest_index < dest_count; dest_index++)
			{
			tmp_objid = op_topo_child (dest_map_objid, OPC_OBJTYPE_GENERIC, dest_index);
			op_ima_obj_attr_get (tmp_objid, "Tunnel Address", attr_string);
	
			if (!ip_address_string_test (attr_string))
				{
				ip_nl_tunnel_creation_error_log_write ("Tunnel Address", attr_string);
				FRET (OPC_NIL);
				}
				
			dest_array [dest_index].tunnel_addr = inet_address_create (attr_string, InetC_Addr_Family_Unknown);
		
			/* If the address is invalid, return NIL.					*/
			if (! inet_address_valid (dest_array [dest_index].tunnel_addr))
				{
				ip_nl_tunnel_creation_error_log_write ("Tunnel Address", attr_string);
				FRET (OPC_NIL);
				}
				
			/* Now on for the physical address of the tunnel endpoint. */
			op_ima_obj_attr_get (tmp_objid, "Tunnel Physical Address", attr_string);
	
			if (!ip_address_string_test (attr_string))
				{
				ip_nl_tunnel_creation_error_log_write ("Tunnel Physical Address", attr_string);
				FRET (OPC_NIL);
				}
				
			dest_array [dest_index].tunnel_phy_addr = inet_address_create (attr_string, InetC_Addr_Family_Unknown);
		
			/* If the address is invalid, return NIL.					*/
			if (! inet_address_valid (dest_array [dest_index].tunnel_phy_addr))
				{
				ip_nl_tunnel_creation_error_log_write ("Tunnel Physical Address", attr_string);
				FRET (OPC_NIL);
				}
			}
		}
	else
		{
		/* Unless this is an IPv6 auto tunnel or a 6to4 tunnel,			*/
		/* read in the destinationaddress specified.					*/
		if ((IpC_Tunnel_Mode_IPv6_Auto != tunnel_mode) &&
			(IpC_Tunnel_Mode_IPv6_6to4 != tunnel_mode))
			{
			/* Read in the destination address.							*/
			op_ima_obj_attr_get (tunnel_description_objid, "Tunnel Destination", attr_string);

			if (!ip_address_string_test (attr_string))
				{
				ip_nl_tunnel_creation_error_log_write ("Tunnel Destination", attr_string);
				FRET (OPC_NIL);
				}
			
			dest_addr = inet_address_create (attr_string, InetC_Addr_Family_Unknown);
		
			/* If the address is invalid, return NIL.					*/
			if (! inet_address_valid (dest_addr))
				{
				ip_nl_tunnel_creation_error_log_write ("Tunnel Destination", attr_string);
				FRET (OPC_NIL);
				}
			}
		else
			{
			/* For Auto tunnels, set the destination address to Invalid.*/
			dest_addr = INETC_ADDRESS_INVALID;
			}
		}

	/* Allocate enough memory to hold the tunnel info.				*/
	tunnel_info_ptr = (IpT_Tunnel_Info*) op_prg_mem_alloc (sizeof (IpT_Tunnel_Info));

	/* Store the tunnel mode and the source interface.				*/
	tunnel_info_ptr->mode = tunnel_mode;
	tunnel_info_ptr->source_intf_ptr = src_intf_ptr;

	/* Set the source address of the tunnel. This will be used in the	*/
	/* header field of the outer packet.								*/
	tunnel_info_ptr->src_addr = src_addr;
	
	/* Store the destination address. Note that we should not use	*/
	/* inet_address_copy because dest_addr is a temporary variable	*/
	if (dest_count == 0)
		{
		tunnel_info_ptr->dest_addr = dest_addr;
		tunnel_info_ptr->dest_count = 0;
		tunnel_info_ptr->dest_addr_array = OPC_NIL;
		}
	else
		{
		/* We have multipoint tunnel. */
		dest_addr = INETC_ADDRESS_INVALID;
		tunnel_info_ptr->dest_count = dest_count;
		tunnel_info_ptr->dest_addr_array = dest_array;
		}

	/* Read in the Encapsulation and Decapsulation delays.			*/
	op_ima_obj_attr_get (tunnel_description_objid, "Delays", &delay_cattr_objid);
	delay_objid = op_topo_child (delay_cattr_objid, OPC_OBJTYPE_GENERIC, 0);

	op_ima_obj_attr_get (delay_objid, "Encapsulation Delay", attr_string);
	tunnel_info_ptr->encapsulation_delay = oms_dist_load_from_string (attr_string);

	op_ima_obj_attr_get (delay_objid, "Decapsulation Delay", attr_string);
	tunnel_info_ptr->decapsulation_delay = oms_dist_load_from_string (attr_string);
	
	/* Other attributes of the tunnel must be read.	*/
	op_ima_obj_attr_get (tunnel_description_objid, "Type Of Service (TOS)", &(tunnel_info_ptr->tos));
	op_ima_obj_attr_get (tunnel_description_objid, "Time-to-live (TTL)", &(tunnel_info_ptr->ttl));
	
	/* Read the enabled passenger protocols on the tunnel and set	*/
	/* the flags accordingly.										*/
	ip_dispatch_tunnel_passenger_protocols_read (tunnel_description_objid, tunnel_info_ptr);
		
	/* All tunnels except GRE tunnels have no specific headers of their own.	*/
	tunnel_info_ptr->hdr_size_bits = 0;
	
	/* Read GRE specific parameters, if required.	*/
	tunnel_info_ptr->gre_params_ptr = OPC_NIL;
	
	if (IpC_Tunnel_Mode_GRE == tunnel_mode)
		{
		/* GRE tunnel packets have a GRE header.	*/
		tunnel_info_ptr->hdr_size_bits += IPC_TUNNEL_GRE_BASE_HDR_SIZE_BITS;
		
		tunnel_info_ptr->gre_params_ptr = ip_dispatch_tunnel_gre_params_create ();
		op_ima_obj_attr_get (tunnel_description_objid, "GRE Tunnel Checksum", &checksum_enabled);
		op_ima_obj_attr_get (tunnel_description_objid, "GRE Sequence Datagrams", &(tunnel_info_ptr->gre_params_ptr->sequence_dgrams));
		
		/* If GRE checksumming is enabled, then the header has more fields.	*/
		if (checksum_enabled)
			{
			tunnel_info_ptr->hdr_size_bits += IPC_TUNNEL_GRE_HDR_OPTIONS_SIZE_BITS;
			}
		
		/* Initialize max sequence number seen. Will be used to */
		/* drop out of sequence datagrams received on this		*/
		/* interface.											*/
		tunnel_info_ptr->gre_params_ptr->max_seq_number = 0;
		}
	
	/* Register all the statistics that will be written.	*/
	tunnel_info_ptr->traffic_sent_bps_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Traffic Sent (bits/sec)", iface_name, OPC_STAT_LOCAL);
	tunnel_info_ptr->traffic_sent_pps_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Traffic Sent (packets/sec)", iface_name, OPC_STAT_LOCAL);	
	tunnel_info_ptr->traffic_rcvd_bps_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Traffic Received (bits/sec)", iface_name, OPC_STAT_LOCAL);
	tunnel_info_ptr->traffic_rcvd_pps_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Traffic Received (packets/sec)", iface_name, OPC_STAT_LOCAL);
	tunnel_info_ptr->traffic_dropped_bps_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Traffic Dropped (bits/sec)", iface_name, OPC_STAT_LOCAL);
	tunnel_info_ptr->traffic_dropped_pps_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Traffic Dropped (packets/sec)", iface_name, OPC_STAT_LOCAL);	
	tunnel_info_ptr->delay_sec_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "ETE Delay (sec)", iface_name, OPC_STAT_LOCAL);	
	tunnel_info_ptr->delay_jitter_sec_lsh = Oms_Dim_Stat_Reg (module_data.module_id, TUNNEL_STAT_GROUP_NAME, "Delay Variation (sec)", iface_name, OPC_STAT_LOCAL);		

	/* Annotate the stathandles with the tunnel interface name.	*/
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->traffic_sent_bps_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->traffic_sent_pps_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->traffic_rcvd_bps_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->traffic_rcvd_pps_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->traffic_dropped_bps_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->traffic_dropped_pps_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->delay_sec_lsh, iface_name);
	Oms_Dim_Stat_Annotate (tunnel_info_ptr->delay_jitter_sec_lsh, iface_name);
	
	/* oms_stat_support package is used to compute delay variation.	*/
	tunnel_info_ptr->delay_stat_ptr = oms_stat_info_create ();
	oms_stat_data_init (tunnel_info_ptr->delay_stat_ptr);
	
	/* Initialize pointers to bkg routed state information.	*/
	tunnel_info_ptr->bgutil_sent_state_ptr = OPC_NIL;
	tunnel_info_ptr->bgutil_rcvd_state_ptr = OPC_NIL;
	tunnel_info_ptr->last_sent_update_time = 0.0;
	tunnel_info_ptr->last_rcvd_update_time = 0.0;
	
	/* Return the tunnel info structure.							*/
	FRET (tunnel_info_ptr);
	}

static void
ip_dispatch_ipv6_auto_tunnel_attrs_set (IpT_Interface_Info* iface_info_ptr)
	{
	Ipv6T_Interface_Info*		ipv6_info_ptr;
	InetT_Address				ipv6_address;

	/** This function set the attributes in an IPv6 auto tunnel	**/
	/** interface.												**/

	FIN (ip_dispatch_ipv6_auto_tunnel_attrs_set (iface_info_ptr));

	/* Create a structure to hold the IPv6 related information.	*/
	ipv6_info_ptr = (Ipv6T_Interface_Info*) op_prg_mem_alloc (sizeof (Ipv6T_Interface_Info));

	/* Assign a unique interface ID to this interface.			*/
	ipv6_info_ptr->intf_id = IpI_Interface_ID++;

	/* This interface will have two addresses, a link local		*/
	/* address and a global address.							*/
	ipv6_info_ptr->num_addresses = 2;

	/* Create a default link local address.						*/
	ipv6_address = inet_ipv6_link_local_addr_create (ipv6_info_ptr->intf_id);

	/* Register the link local address in the nato table.		*/
	ip_rtab_local_addr_register (&ipv6_address, &module_data);
	
	/* Convert the link local address to an address range and	*/
	/* store it in the IPv6 info structure.						*/
	ipv6_info_ptr->ipv6_addr_array = (InetT_Address_Range*)
		op_prg_mem_alloc ((sizeof (InetT_Address_Range)) * 2);
	ipv6_info_ptr->ipv6_addr_array[0] = inet_address_range_create_fast
		(ipv6_address, inet_smask_from_length_create (64));

	/* Create a global IPv6 address range from the IPv4			*/
	/* address of the source interface. Note that the actual	*/
	/* address itself is not very important. All we need to		*/
	/* ensure is that the first 96 bits are zeros and the subnet*/
	/* mask is 96. Even an all zeros address will do. But		*/
	/* using a unique address for each interface will be useful	*/
	/* in debugging.											*/
	ipv6_address = inet_ipv4_compat_addr_from_ipv4_addr_create
		(inet_rte_v4intf_addr_get (iface_info_ptr->tunnel_info_ptr->source_intf_ptr));

	/* Register this address in the nato table.					*/
	ip_rtab_local_addr_register (&ipv6_address, &module_data);
	
	/* Create an IPv6 address range from this address using a	*/
	/* subnet mask length of 96.								*/
	ipv6_info_ptr->ipv6_addr_array[1] = inet_address_range_create_fast
		(ipv6_address, inet_smask_from_length_create (96));

	/* Store the IPv6 info structure in the interface structure	*/
	iface_info_ptr->ipv6_info_ptr = ipv6_info_ptr;

	/* No routing protocol must be enabled on an auto tunnel	*/
	/* interface.												*/
	iface_info_ptr->routing_protocols_lptr = no_routing_proto_lptr;

	/* Return.													*/
	FOUT;
	}

static IpT_Interface_Info*
ip_dispatch_find_intf_with_name (const char* intf_name, List* interface_lptr)
	{
	int					i, num_interfaces;
	int					j, num_subinterfaces;
	IpT_Interface_Info	*ith_phys_intf_info_ptr, *jth_subintf_ptr;

	/** Looks for an interface with the specified name in			**/
	/** the interface list.											**/
	/** Note that this function is meant to be used during			**/
	/** initialization before the interface table has been built.	**/
	/** Once the interface table has been built, use				**/
	/** inet_rte_is_local_intf_name instead.						**/

	FIN (ip_dispatch_find_intf_with_name (intf_name, interface_lptr));

	/* Get the number of physical interfaces.						*/
	num_interfaces = op_prg_list_size (interface_lptr);

	/* Loop through the list of interfaces an look for an interface	*/
	/* with the specifed name.										*/
	for (i = 0; i < num_interfaces; i++)
		{
		/* Access the ith physical interface.						*/
		ith_phys_intf_info_ptr = (IpT_Interface_Info*) op_prg_list_access
			(interface_lptr, i);

		/* Get the number of subinterfaces.							*/
		num_subinterfaces = ip_rte_num_subinterfaces_get (ith_phys_intf_info_ptr);

		/* Loop through the physical interface and subinterfaces.	*/
		for (j = IPC_SUBINTF_PHYS_INTF; j < num_subinterfaces; j++)
			{
			/* Access the jth subinterface.							*/
			jth_subintf_ptr = ip_rte_ith_subintf_info_get (ith_phys_intf_info_ptr, j);

			/* Check if it is the interface we are looking for.		*/
			if (0 == strcmp (jth_subintf_ptr->full_name, intf_name))
				{
				/* Return the current interface.					*/
				FRET (jth_subintf_ptr);
				}
			}
		}

	/* We did not find a interface with the specified name.			*/
	/* Return NIL.													*/
	FRET (OPC_NIL);
	}

static void
ip_dispatch_routing_options_add (List* routing_protocols_lptr)
	{
	int					i_th_protocol;
	int					num_rte_protocols;
	int*				i_th_protocol_ptr;
	IpT_Rte_Protocol	i_th_routing_protocol_id;

	/** Go through the list of routing protocols enabled**/
	/** an interface and enable them in the routing		**/
	/** options variable.								**/

	FIN (ip_dispatch_routing_options_add (routing_protocols_lptr));

	num_rte_protocols = op_prg_list_size (routing_protocols_lptr);

	/* Loop though the different number of routing protocols	*/
	/* running on this interface.								*/
	for (i_th_protocol = 0; i_th_protocol < num_rte_protocols; i_th_protocol++)
		{
		/* Access the first specification -- this element will	*/
		/* be a pointer to the routing protocol ID.				*/
		i_th_protocol_ptr = (int *) op_prg_list_access (routing_protocols_lptr, i_th_protocol);
		i_th_routing_protocol_id = (IpT_Rte_Protocol)*i_th_protocol_ptr;
		
		/* Check which of the dynamic routing protocol is	*/
		/* specified.										*/ 
		switch (i_th_routing_protocol_id)
			{
			case IpC_Rte_Rip:
				module_data.routing_protos |= IPC_RTE_PROTO_RIP;
				break;
			case IpC_Rte_Igrp:
				module_data.routing_protos |= IPC_RTE_PROTO_IGRP;
				break;
			case IpC_Rte_Ospf:
				module_data.routing_protos |= IPC_RTE_PROTO_OSPF;
				break;
			case IpC_Rte_Isis:
				module_data.routing_protos |= IPC_RTE_PROTO_ISIS;
				break;
			case IpC_Rte_Bgp:
				module_data.routing_protos |= IPC_RTE_PROTO_BGP;
				break;
			case IpC_Rte_Eigrp:
				module_data.routing_protos |= IPC_RTE_PROTO_EIGRP;
				break;
			case IpC_Rte_Ripng:
				module_data.routing_protos |= IPC_RTE_PROTO_RIPNG;
				break;
			default:
				{
				if (i_th_routing_protocol_id >= IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID ||
					i_th_routing_protocol_id == IpC_Rte_None)
					{
					/* This must be a custom routing protocol or non-gateway node.	*/
					}
				else
					{
					ip_dispatch_error ("Invalid routing protocol specified for IP Interface.");
					}
				break;
				}
			}
		}
	
	/* Set BGP to always receive the intrpt from IP */
	module_data.routing_protos |= IPC_RTE_PROTO_BGP;

	FOUT;
	}

static void
ip_dispatch_distribute_routing_info (void)
	{
	Objid			ipv6_parameters_objid;
	Objid			static_rte_table_objid;
	int				num_ifaces;
	Objid 			my_node_objid;
	char			default_rte_str [IPC_MAX_STR_SIZE]; 

	FIN (ip_dispatch_distribute_routing_info ());

	/* Set error/warning error procedures */
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);

	/** At this time, all routing protocols that have been configured on this	**/
	/** router have received and processed the remote-interrupt schedule by IP	**/
	/** in the exit executives of the previous state, i.e. 'wait'. This			**/
	/** constitutes a "Wake up, you have been asked to run on these interfaces."**/
	/** statement from IP. One of the functional elements of each routing		**/
	/** protocol upon receiving this wake-up call is, to add entries for the	**/
	/** networks attached to the interfaces on which they have been set up into **/
	/** the common route table. This initial routing information must be		**/
	/** redistributed among the routing protocols in this node.					**/ 
	/** Note that this needs to be done before IP itself inserts these routes	**/
	/** into the common route table because the routes inserted by IP will 		**/
	/** replace those inserted by the routing protocols in the common route 	**/
	/** table.																	**/
	if (((module_data.gateway_status == OPC_TRUE) || (passive_rip))&& 
		(routing_table_import_export_flag != IP_RTE_TABLE_IMPORT))
		{
		/* Insert routes to all the directly connected networks		*/
		ip_directly_connected_networks_insert ();
		}		
	
	/* For non-gateway nodes, read in the default route.			*/
	/* Processing of the default network attribute for gateway		*/
	/* nodes will be done later										*/
	if (! ip_rte_node_is_gateway (&module_data))
		{
		/* If IPv4 is enabled on this node, process the IPv4		*/
		/* default route specification.								*/
		if (ip_rte_node_ipv4_active (&module_data))
			{
			/* The IPv4 default route is specified under the		*/
			/* Default Route attribute.								*/
			op_ima_obj_attr_get (module_data.ip_parameters_objid, "Default Route", default_rte_str);
			ip_dispatch_default_route_process (default_rte_str, InetC_Addr_Family_v4);
			}

		/* If IPv6 is enabled on this node, process the IPv6		*/
		/* default route specification.								*/
		if (ip_rte_node_ipv6_active (&module_data))
			{
			/* The IPv6 default route is specified under the		*/
			/* IPv6 Default Route attribute.						*/
			op_ima_obj_attr_get (module_data.ip_parameters_objid, "IPv6 Default Route", default_rte_str);
			ip_dispatch_default_route_process (default_rte_str, InetC_Addr_Family_v6);
			}
		}

	/* If the node is set up to be a router, parse the static 		*/
	/* routing table compound attribute and incorporate	those 		*/
	/* entries into the common routing table.						*/
	if ((module_data.gateway_status == OPC_TRUE) &&
		(routing_table_import_export_flag != IP_RTE_TABLE_IMPORT))
		{		
		/* Parse the IPv4 static routing table and add any entries	*/
		/* therein to the common routing table.						*/
		if (ip_rte_node_ipv4_active (&module_data))
			{
			op_ima_obj_attr_get (module_data.ip_parameters_objid, "Static Routing Table", &static_rte_table_objid);
			ip_rte_table_parse (static_rte_table_objid, module_data.ip_route_table, &module_data, InetC_Addr_Family_v4);
			}

		/* Parse the IPv6 static routing table and add any entries	*/
		/* therein to the common routing table.						*/
		if (ip_rte_node_ipv6_active (&module_data))
			{
			op_ima_obj_attr_get (op_id_self (), "ipv6 parameters", &ipv6_parameters_objid);
			ipv6_parameters_objid = op_topo_child (ipv6_parameters_objid, OPC_OBJTYPE_GENERIC, 0);
			op_ima_obj_attr_get (ipv6_parameters_objid, "Static Routing Table", &static_rte_table_objid);
			ip_rte_table_parse (static_rte_table_objid, module_data.ip_route_table, &module_data, InetC_Addr_Family_v6);
			}

		
		/* Initialize the route info for the static route table.	*/
		/* Create the rte info ptr */
		static_rte_info					= ip_dyn_rte_info_create ();
		static_rte_info->table_handle 	= module_data.ip_static_rte_table;
		static_rte_info->inet_install_proc	= (InetT_Rte_Table_Install_Proc) ip_rte_table_route_install;
	
		/* Set the rte info ptr in the IP process handle */
		oms_pr_attr_set (own_process_record_handle, 
			"routing information",	OMSC_PR_POINTER,	static_rte_info, 
			OPC_NIL);
		}
	
	/* For gateway nodes, parse the default network information	*/
	if (module_data.gateway_status)
		{
		/* Parse the default networks attribute.				*/
		/* It is important that we do this after parsing the	*/
		/* static routing table because some the default		*/
		/* networks specified might be static routes.			*/
		ip_dispatch_default_networks_parse ();

		/* We do not support the Default Gateway attribute, but	*/
		/* if it set to anything other than unspecified, write	*/
		/* a log message warning the user that it will be		*/
		/* ignored.												*/
		ip_dispatch_default_gateway_configured_check ();
		}

	/* At this stage all the interface information must	*/
	/* have been setup. Check if it is needed to export	*/
	/* this information to an external file.			*/
	if ((iface_addressing_mode == IpC_Iface_Auto_Address_Export) ||
		(iface_addressing_mode == IpC_Iface_Manual_Address_Export))
		{
		ip_iface_address_export (module_data.node_id, &module_data);
		}
	
	/* Initialize ICMP message processing from this node.	*/
	ip_rte_icmp_init ();
	
	/* Import Forwarding Table */
	if (routing_table_import_export_flag == IP_RTE_TABLE_IMPORT)
		ip_cmn_rte_table_import_from_ot (&module_data);
	
	/** At this time, all routing protocols that have been configured on this	**/
	/** router have received and processed the remote-interrupt schedule by IP	**/
	/** in the exit executives of the previous state, i.e. 'wait'. This			**/
	/** constitutes a "Wake up, you have been asked to run on these interfaces."**/
	/** statement from IP. One of the functional elements of each routing		**/
	/** protocol upon receiving this wake-up call is, to add entries for the	**/
	/** networks attached to the interfaces on which they have been set up into **/
	/** the common route table. This initial routing information must be		**/
	/** redistributed among the routing protocols in this node.					**/ 
	
	/** Based on the model attribute "multicast routing protocol", either PIM-SM**/
	/** or custom multicast child process will be used. If PIM-SM is specified,	**/
	/** standard IGMP model is also used. If custom multicast routing protocol	**/
	/** is specified we do not use standard IGMP and RSVP is disabled.			**/
			
	/* If the model attribute "multicast routing protocol" is set to */
	/* PIM-SM, we will use PIM-SM and the standard IGMP model.		 */
	if (mcast_rte_protocol == IpC_Rte_Pim_Sm)
		{
		/* Create and initialize the IGMP Host or IGMP Router child process	*/
		/* depending on whether this node is a multicast router or not.		*/
		if (!ip_node_is_mcast_router (&module_data))
			{
			/** This node is not a multicast router	**/
			
			/* Create and initialize an IGMP Host process	*/
			ip_rte_igmp_host_create_init ();
			}
		else
			{
			/** This node is a multicast router **/
			char				mcast_start_time_str [64];
			OmsT_Dist_Handle	start_time_dist_handle;
			Objid				ip_multicast_info_objid;
			Objid				compound_objid;
			double				start_time;
			
			/* Compute the start time */
			op_ima_obj_attr_get (module_data.module_id, "ip multicast information", &ip_multicast_info_objid);
			compound_objid = op_topo_child (ip_multicast_info_objid, OPC_OBJTYPE_GENERIC, 0);
			
			op_ima_obj_attr_get (compound_objid, "Start Time", mcast_start_time_str);
			start_time_dist_handle =  oms_dist_load_from_string (mcast_start_time_str);
			start_time	= oms_dist_outcome (start_time_dist_handle);
			
			if (start_time < 5.0)
				{
				/* If the distribution returns a value less than 5s,	*/
				/* set it to 5s.										*/
				start_time = 5.0;
				}
			
			/* Create and initialize a PIM-SM process		*/
			/* Note: Create and Initialize PIM-SM process	*/
			/* before initializing IGMP Router process as	*/
			/* we need to pass the process handle of PIM-SM	*/
			/* process to IGMP Router process				*/
			ip_rte_pim_sm_create_init (start_time);
			
			/* Create and initialize an IGMP Router process	*/
			/* for each multicast enabled IP interface		*/
			ip_rte_igmp_rte_intf_create_init (start_time);			
			}
		/* Register the default multicast addresses for each	*/
		/* IP interface which is enabled for multicast			*/
		ip_rte_default_mcast_addr_register ();
		}
	else
		{
		/* Custom multicast routing protocol is specified.	*/
		if (ip_node_is_mcast_router (&module_data))
			{
			/** This node is a multicast router. **/
			/* Create and initialize "ip_custom_mrp" process.*/
			ip_rte_custom_mrp_create_init ();
			}
	
	    /* Custom multicasting is being used. Set the rsvp_status*/
		/* to OPC_FALSE so that RSVP is disabled.				 */
		module_data.rsvp_status = OPC_FALSE;		
		}
	
	if (module_data.rsvp_status == OPC_TRUE)
		{
		/** RSVP is enabled on the node.	*/
	
		/* Send a remote interrupt to RSVP process. Upon receiving this	*/
		/* notification, RSVP will finish its initialization process.	*/
		/* It is important that this interrupt is received after 		*/
		/* IP PIM process registers itself in the process registry,		*/
		/* because RSVP will try to get a pointer to IP PIM routing		*/
		/* table.														*/
		/* However, if there is no RSVP module, the function does not	*/
		/* send an interrupt to RSVP, and it sets its status to FALSE.	*/
		ip_rte_rsvp_init_notify ();
		}
	
	/* Create a table of label spaces for interface */
	num_ifaces = op_prg_list_size (module_data.interface_table_ptr);	
	
	/* Get the node's ID	*/
	my_node_objid = op_topo_parent (op_id_self());
	
	/* Create and invoke the MPLS manager process if required.	*/
	if (ip_mpls_is_enabled (&module_data))
		{
		module_data.mpls_info_ptr->mgr_prohandle	= op_pro_create ("mpls_mgr", &module_data);	
		op_pro_invoke (module_data.mpls_info_ptr->mgr_prohandle, OPC_NIL);
		}
	
	FOUT;
	}

static void
ip_dispatch_default_route_process (char* default_route_str, InetT_Addr_Family addr_family)
	{
	IpT_Port_Info			port_info;
	InetT_Address			default_route;

	/** This function processes the specified default route for		**/
	/** a host node.												**/
	FIN (ip_dispatch_default_route_process (default_route_str, out_intf_index_ptr));

	/* Check if the default route is set to Auto Assigned.		*/
	if (strcmp (default_route_str, IPC_DEFAULT_RTE_AUTOASSIGNED) == 0)
		{
		/*	No value has been specified to the "default gateway"	*/
		/*	model attribute. This means that an IP datagram may be	*/
		/*	dropped if a possible next hop cannot be determined		*/
		/*	using the routing tables. Store the fact that a default	*/
		/*	gateway information is not available.					*/
		default_route = INETC_ADDRESS_INVALID;
		}
	else if (inet_address_string_test (default_route_str, addr_family))
		{
		/*	Create the IP address of the default gateway from the	*/
		/*	string equivalent of the address.						*/
		default_route = inet_address_create (default_route_str, addr_family);

		if (!inet_address_valid (default_route))
			{
			/* If the specified string does not represent a valid	*/
			/* IP address, write a log message						*/
			ipnl_invalid_default_route (default_route_str, addr_family);
			}
		}
	else
		{
		/* The string specified is not a valid IP address.			*/
		/* Write a log message.										*/
		ipnl_invalid_default_route (default_route_str, addr_family);

		/* Set the default route to invalid.						*/
		default_route = INETC_ADDRESS_INVALID;
		}
	
	/* For IPv4 enabled endstations attempt to find a gateway if no	*/
	/* valid default route is specified. Do this only if auto		*/
	/* addressing is used.											*/
	if (!inet_address_valid (default_route))
		{
		if (InetC_Addr_Family_v4 == addr_family)
			{
			if ((IpC_Iface_Auto_Addressed == iface_addressing_mode) ||
				(IpC_Iface_Auto_Address_Export == iface_addressing_mode))
				{
				ip_rte_local_gateway_find (&module_data, &default_route, &port_info);
				}
			else
				{
				/* Manual addressing is used, but a default route	*/
				/* was not specified. Write a log message.			*/
				ipnl_cfgerr_defroute (addr_family);
				}
			}

		/* At this point if we do not have a valid default route,	*/
		/* store that information in the module data and return.	*/
		if (!inet_address_valid (default_route))
			{
			module_data.default_route_addr_array[addr_family] = INETC_ADDRESS_INVALID;
			FOUT;
			}
		}

	/* Make sure that the default route is directly connected.		*/
	if (OPC_COMPCODE_FAILURE == inet_rte_addr_local_network
			(default_route, &module_data, &port_info))
		{
		/* The default route is not directly connected. 	*/
		/* Print out a sim log message and mark the default	*/
		/* route as unavailable.							*/
		ipnl_default_route_not_directly_connected_log_write (default_route_str, addr_family);
		module_data.default_route_addr_array[addr_family] = INETC_ADDRESS_INVALID;
		}
	else
		{
		/* The default route is directly connected. accept it*/
		module_data.default_route_addr_array[addr_family] = default_route;
		module_data.default_route_intf_index_array[addr_family] =
			ip_rte_intf_tbl_index_from_port_info_get (&module_data, port_info);
		}

	FOUT;
	}

static void
ip_dispatch_cleanup_and_create_child_processes (void)
	{
	List*					proc_record_handle_list_ptr;
	int						record_handle_list_size;
	OmsT_Pr_Handle			process_record_handle;
	Objid					ip_encap_objid;

	FIN (ip_dispatch_cleanup_and_create_child_processes (void));

	/* Set error/warning error procedures */
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);

	/*	The process will enter this state when all IP interfaces	*/
	/*	have been treated via the "ip3_addr_resolve ()" service.	*/
	/*	Perform cleanup operations (e.g., memory deallocation) for	*/
	/*	the state built while using this service.					*/
	ip3_auto_addr_cleanup ();
	
	/*	Obtain the outstream index to ip_encap module.				*/
	proc_record_handle_list_ptr = op_prg_list_create ();
	
	oms_pr_process_discover (module_data.module_id, proc_record_handle_list_ptr, 
		"protocol", OMSC_PR_STRING, "ip_encap", 
		OPC_NIL);
	
	record_handle_list_size = op_prg_list_size (proc_record_handle_list_ptr);
	if (record_handle_list_size != 1)
		{
		/*	An error should be created if there are zero or		*/
		/*	more than one ip_encap process in the local node.	*/
		op_sim_end ("Error: either zero or several ip_encap modules connected to IP.",
			"", "", "");
		}
	else
		{
		process_record_handle = (OmsT_Pr_Handle) 
			op_prg_list_access (proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
		}
	
	/*	Obtain the ip_encap module objid, and the output stream		*/
	/*	index from IP to IP Encap module.							*/
	oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &ip_encap_objid);
	oms_tan_neighbor_streams_find (module_data.module_id, ip_encap_objid, 
		&module_data.instrm_from_ip_encap, &module_data.outstrm_to_ip_encap);
	
	/*	Deallocate no longer needed process registry information.	*/
	/*	There is only one entry since we aborted above otherwise	*/
	op_prg_list_remove (proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
	op_prg_mem_free (proc_record_handle_list_ptr);
	
	/* At this point all lower layer protocols set the interface types.	*/
	/* If any of them were left unassigned, check whether they are		*/
	/* connected to PPP links and if yes, set the lower layer protocol.	*/
	ip_dispatch_ppp_intf_set ();

	/* Determine the queuing managment: FIFO, WFQ, Priority Queuing		*/
	/* or Custom Queuing. The IP process will deleguate	its tasks 		*/
	/* to a child process on each interface for sending the packets.	*/
	/* This is done before creating the other routing child processes	*/
	/* that will take care of finishing the qos initialization, if any	*/
	ip_rte_qos_information_process ();
	
	/* If any MANET routing protocol is running on this node, create	*/
	/* and invoke the corresponding root process that will in turn 		*/
	/* spawn the appropriate MANET routing protocol child process		*/
	if (ip_manet_is_enabled (&module_data))
		{
		/* Create the MANET process	*/

		if ((module_data.manet_info_ptr)->rte_protocol == IpC_Rte_Olsr)
			{
			/* Olsr manet protocol is enabled on this node  */
			/* Make sure IP Rte Table Import is NOT Enabled */
			if (routing_table_import_export_flag != IP_RTE_TABLE_IMPORT)
				ip_manet_rte_mgr_init ();
			}
		else
			{
			/* Either AODV, DSR or TORA is enabled as manet protocol */
			module_data.manet_info_ptr->mgr_prohandle = op_pro_create ("manet_mgr", OPC_NIL);
			op_pro_invoke (module_data.manet_info_ptr->mgr_prohandle, OPC_NIL);
			}
		}
	
	if (ip_node_is_cloud (&module_data))
		{
		/* A single cloud child handling all incoming streams */
		/* No parent-to-child memory.  Everything is currently shared	*/
		/* via the module-wide memory.									*/
		routing_prohandle = op_pro_create ("ip_rte_cloud", OPC_NIL);
		op_pro_invoke (routing_prohandle, OPC_NIL);
		}
	else  /* not a cloud */
		{
		if (module_data.processing_scheme == OmsC_Dv_Centralized)
			{
			/* A single routing child handling all incoming streams */
			/* No parent-to-child memory.  Everything is currently shared	*/
			/* via the module-wide memory.									*/
			routing_prohandle = op_pro_create ("ip_rte_central_cpu", OPC_NIL);
			op_pro_invoke (routing_prohandle, OPC_NIL);
			}
		else /* processing_scheme == OmsC_Dv_Slot_Based */
			{
			IpT_Routing_Cpu_Arg_Mem	routing_arg_mem;
			/* A routing cpu child handling upper layer packets	*/
			/* and one slot child per slot handling the lower	*/
			/* layer packets for the interfaces on that slot	*/
			/* No parent-to-child memory.  Everything is currently shared	*/
			/* via the module-wide memory.									*/
			routing_prohandle = op_pro_create ("ip_rte_distrib_cpu", OPC_NIL);
			op_pro_invoke (routing_prohandle, &routing_arg_mem);
			
			/* Obtain slot info for diagnostic use */
			slot_table_lptr = routing_arg_mem.slot_lptr;
			slot_iface_map_array = routing_arg_mem.iface_map_array;
			}
		}

	/* See if the local node has Mobile IP support. */
	if (mip_sup_is_mobility_enabled (module_data))
		{
		/* Launch the child process. */
		module_data.mip_info_ptr = (IpT_Mip_Info *) op_prg_mem_alloc (sizeof (IpT_Mip_Info));
		module_data.mip_info_ptr->mgr_phndl = op_pro_create ("mobile_ip_mgr", OPC_NIL);
		op_pro_invoke (module_data.mip_info_ptr->mgr_phndl, OPC_NIL);
		}

	/* Create the ipv6_ra_host/ipv6_ra_gtwy process and mipv6_mgr if 	*/
	/* necessary.														*/
	if (ip_rte_node_ipv6_active (&module_data))
		{
		/* The following call will create the mipv6_mgr child process	*/
		/* if MIPv6 is enabled on the current node then the appropriate	*/
		/* information structure (mipv6_info_ptr) will be added to 		*/
		/* module_data.													*/
		mipv6_proc_mgr_create (&module_data);
		
		/* Create IPv6 RA process.										*/
		ip_dispatch_ipv6_ra_process_create ();

		/* Check if we need to export IPv6 addresses.					*/

		/* Read the sim attribute if we haven't done so already.		*/
		if (! ipv6_intf_addr_export_mode_determined)
			{
			if (op_ima_sim_attr_exists ("IPv6 Interface Address Export"))
				{
				/* Read the value of the attribute.						*/
				op_ima_sim_attr_get_int32 ("IPv6 Interface Address Export", &ipv6_intf_addr_export);
				}

			/* Set the flag indicating that we have read the simulation	*/
			/* attribute.												*/
			ipv6_intf_addr_export_mode_determined = OPC_TRUE;
			}

		/* If IPv6 address export is enabled, schedule a call to the	*/
		/* appropriate function at end of sim. We should wait till the	*/
		/* end of the simulation to make sure that dynamically learnt	*/
		/* addresses are included.										*/
		if (ipv6_intf_addr_export)
			{
			op_intrpt_schedule_call (OPC_INTRPT_SCHED_CALL_ENDSIM, 0,
				ipv6_iface_address_export, &module_data);
			}
		}

	/* If there are any aggregate interfaces, invoke the ip_group		*/
	/* child process for the second phase of initializaton.				*/
	if (OPC_NIL != module_data.group_info_ptr)
		{
		op_pro_invoke (module_data.group_info_ptr->ip_grouping_prohandle, OPC_NIL);
		}

	FOUT;
	}

static void
ip_dispatch_handle_mcast_rsvp (void)
	{
	Ici*					ici_ptr;
	IpT_Rte_App_Ici_Type	ici_type;
	char					ip_addr_str [IPC_ADDR_STR_LEN];
	RsvpT_TC_Ici_Struct *	ici_data_struct_ptr;
	IpT_Mcast_Ptc_Info *	igmp_ptr;
	IpT_Interface_Info*		ip_intf_info_ptr;

	/** A Join/Leave from an application, or RSVP request 	**/
	/** to modify queue parameters has been received.		**/
	/** If this is a  multicast request,	 				**/
	/** registers/deregisters the multicast	address and 	**/
	/** invokes the IGMP host (child) process, so that it 	**/
	/** can send an IGMP Report/Leave message to the 		**/
	/** multicast routers									**/ 
	/** If this is an RSVP request, forward the request to	**/
	/** the appropriate interface process.					**/
	/** If this is a VPN initialization request, a child    **/
	/** process of ip_vpn is created and invoked for init-  **/
	/** lization.                                           **/
	FIN (ip_dispatch_handle_mcast_rsvp ());
	
	/* Set error/warning error procedures */
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);

	/* Get the ICI associated with the interrupt	*/
	ici_ptr = op_intrpt_ici ();
	
	/* Find whether this is a multicast or an RSVP ICI.	*/
	op_ici_attr_get (ici_ptr, "type", &ici_type);
	
	switch (ici_type)
		{
	   	case IpC_Rte_Mcast_Ici:
			{
			if (mcast_rte_protocol != IpC_Rte_Pim_Sm)
				{
				/* Custom multicast routing protocol is being used.	*/
				/* A Join/Leave request can not be sent, as standard*/
				/* IGMP is disabled. Generate a log message and		*/
				/* ignore the Join/Leave request.					*/
				ipnl_protwarn_mcast_custom_invalid_application_req ();
				}
			else
				{
				/** This is a multicast request and PIM-SM is the multicast routing protocol.				**/
				/** Obtain the information provided in the ICI and store it in the parent-to-child memory 	**/
	
				igmp_ptr = &module_data.ip_ptc_mem.ip_mcast_ptc_info;
		
				/* Obtain the value of "multicast_major_port" attribute */
				op_ici_attr_get (ici_ptr, "multicast_major_port", &(igmp_ptr->major_port));
		
				/* Obtain the value of "multicast_group_address" attribute */
				op_ici_attr_get (ici_ptr, "multicast_group_address", &(igmp_ptr->ip_grp_addr));
		
				/* Obtain the value of "type" attribute */
				op_ici_attr_get (ici_ptr, "mcast_type", &(igmp_ptr->type));
				
				/* Obtain the value of the "multicast_application_port" attribute */
				op_ici_attr_get (ici_ptr, "multicast_application_port", &(igmp_ptr->application_port));
						
				/* Check if this node is a multicast router	*/
				if (ip_node_is_mcast_router (&module_data))
					{
					/** This node is a multicast router	**/
		
					/* Report a log message and ignore the Join/Leave request	*/
					ip_address_print (ip_addr_str, igmp_ptr->ip_grp_addr);
					ipnl_protwarn_mcast_rte_cannot_join_leave_grp (ip_addr_str, igmp_ptr->major_port);
					}
				else
					{
					/** This node is not a multicast router	**/
		
					/* Check the type of request */
					switch (igmp_ptr->type)
						{
						case IpC_Igmp_Host_Join_Req:
							{
							/** A Join request has been received from an application	**/
				
							/* Only if the interface on which the application wants to join	*/
							/* the IP group is multicast enabled, register it				*/
							if (ip_rte_intf_igmp_enabled (ip_rte_intf_tbl_access (&module_data, igmp_ptr->major_port)) == OPC_TRUE)
								{
								/** Multicast is enabled on the interface	**/
		
								/* Register the IP group address on the interface	*/
								Ip_Address_Multicast_Register (igmp_ptr->ip_grp_addr, 
									igmp_ptr->major_port, igmp_ptr->application_port, module_data.node_id);
		
								/* Invoke the IGMP Host process, so that it can send	*/
								/* an IGMP Report message to the multicast routers		*/
								op_pro_invoke (igmp_host_process_handle, OPC_NIL);
								}
							else
								{
								/** The interface number is either invalid or multicast is disabled	**/
		
								/* Report a log message and ignore the request	*/
								ip_intf_info_ptr = ip_rte_intf_tbl_access (&module_data, igmp_ptr->major_port);
								ipnl_protwarn_mcast_invalid_intf (ip_rte_intf_name_get (ip_intf_info_ptr));
								}			
		
							break;	
							}
		
						case IpC_Igmp_Host_Leave_Req:
							{
							/** A Leave request has been received from an application	**/
		
							/* The group address is registered on the interface only if the interface	*/
							/* is enabled for multicast. So, do the deregistration only if multicast is	*/
							/* is enabled on the interface												*/
							if (ip_rte_intf_igmp_enabled (ip_rte_intf_tbl_access (&module_data, igmp_ptr->major_port)) == OPC_TRUE)
								{
								/* Deregister the IP group address on the interface	*/
								Ip_Address_Multicast_Deregister (igmp_ptr->ip_grp_addr, 
									igmp_ptr->major_port, igmp_ptr->application_port, module_data.node_id);
		
								/* Invoke the IGMP Host process, so that it can send	*/
								/* an IGMP Leave message to the multicast routers		*/
								op_pro_invoke (igmp_host_process_handle, OPC_NIL);
								}
							else
								{
								/* Report a log message and ignore the request	*/
								ip_intf_info_ptr = ip_rte_intf_tbl_access (&module_data, igmp_ptr->major_port);
								ipnl_protwarn_mcast_invalid_intf (ip_rte_intf_name_get (ip_intf_info_ptr));
								}
		
							break;
							}
		
						default:
							{
							/** An invalid request has been received	**/
		
							/* Report a log message and ignore the request */
							ipnl_protwarn_mcast_invalid_application_req ();
		
							break;
							}
						}
					}
		    	}
		
			/* Destroy the ICI */
			op_ici_destroy (ici_ptr);
			break;
			}
		case IpC_Rte_Rsvp_Ici:
			{
			/** This request was sent from RSVP.	**/
			Prohandle	intf_phandle;
		
			/* Get the interface index from the ICI.	*/
			op_ici_attr_get (ici_ptr, "RSVP Traffic Control Request", &ici_data_struct_ptr);
		
			/* Find the process handle of the interface process.	*/
			intf_phandle = ip_rtab_phandle_from_intf_get (ici_data_struct_ptr);
		
			/* Set a pointer to the ICI data structure in the module shared memory.	*/
			/* This memory will be accessed by the interface process to get the 	*/
			/* request parameters.													*/
			module_data.shared_mem.rsvp_request_ptr = ici_data_struct_ptr;
		
			/* Invoke the interface traffic control process.	*/
			op_pro_invoke (intf_phandle, OPC_NIL);
			break;
			}
		case IpC_Rte_Vpn_Ici:
			{
			/* This block is reached when ip_vpn_config process     */
			/* sends an initialize remote interupt to this module   */
			/* The ip module will invoke ip_vpn child process       */
			/* model to handle all the tunneling packages           */
		
			/* The child process could be initilaized more than once*/
			/* each interrupt will initialize one row in the global */
			/* vpn tunnel description table.                        */
			ip_dispatch_vpn_init ();
			break;
			}
		default:
			break;
		}

	FOUT;
	}


static void
ip_dispatch_forward_packet (void)
	{
	/** A packet is being received from one of the child processes	**/
	/** Forward that packet to the appropriate recipient, which can	**/
	/** be another child process, or the stream connecting IP to	**/
	/** the upper module.											**/
	FIN (ip_dispatch_forward_packet ());

	/* Set error/warning error procedures */
	ip_rte_set_procs (&module_data, ip_dispatch_error, ip_dispatch_warn);

	/* The non-routing children use the parent-to-child memory		*/
	/* The routing children set that to NIL and use argument memory */
	if (module_data.ip_ptc_mem.child_pkptr == OPC_NIL)
		{
		/* Packet to forward to "higher layers", which might include	*/
		/* some of the special child processes in IP.					*/
		Packet *	pkptr = (Packet *)op_pro_argmem_access ();
		ip_rte_datagram_higher_layer_forward (pkptr);
		}
	else
		{
		/* Extract packet sent from child and have routing process 	*/
		/* take care of it.											*/
		op_pro_invoke (routing_prohandle, module_data.ip_ptc_mem.child_pkptr);

		}

	FOUT;
	}

/* Support routines */

static void
ip_dispatch_sv_init (void)
	{
	char		node_name [OMSC_HNAME_MAX_LEN];
	
	/** Initializes the state variables used by this process.	**/
	FIN (ip_dispatch_sv_init ());
	
	/*	Get module's own object identifier.					*/
	module_data.module_id = op_id_self ();

	module_data.ip_root_prohandle = op_pro_self ();
  						
	/*	Obtain the node and subnet's objid.							*/
	module_data.node_id = op_topo_parent (module_data.module_id);
	subnet_objid = op_topo_parent (module_data.node_id);
	
	/* Get the name of this node.	*/
	oms_tan_hname_get (module_data.node_id, node_name);
	module_data.node_name = (char *) op_prg_mem_alloc (sizeof (char) * (strlen (node_name) + 1));
	strcpy (module_data.node_name, node_name);

	/* Check what kind of IP interface addressing is used for assigning	*/
	/* IP addresses to the various interfaces of this node.				*/
	iface_addressing_mode = ip_iface_addressing_mode_determine ();

	/*	Create the interface table.					*/
	module_data.interface_table_ptr = op_prg_list_create ();

	/*	No slot table info for the moment */
	slot_table_lptr = OPC_NIL;
	slot_iface_map_array = OPC_NIL;

	/* Uninitialized list for common route table export.	*/
	crt_export_time_lptr = (List *) OPC_NIL;
	
	/* Uninitialized list for global common route table export.	*/
	global_crt_export_time_lptr = (List *) OPC_NIL;
		
	/* Initialize the routing_protos SV.			*/
	module_data.routing_protos = 0;

	/* Initialize the datagram identifier SV.		*/
	module_data.dgram_id = 1;

	/* Initialize RSVP status.						*/
	module_data.rsvp_status = OPC_FALSE;
	
	/* Check if the surrounding node is a cache server.	*/
	if (oms_dv_device_is_cache_server (module_data.node_id))
		module_data.flags |= IPC_NODE_FLAG_CACHE_SERVER;

	/* Set the first loopback interface to IPC_MCAST_MAJOR_PORT_INVALID  	*/
	/* to indicate that it has not been set.								*/
	module_data.first_loopback_intf_index = IPC_MCAST_MAJOR_PORT_INVALID;
	
	module_data.l2tp_info_ptr 			= OPC_NIL;
	module_data.manet_info_ptr			= OPC_NIL;
	
	FOUT;
	}


static void	
ip_rtab_init (void)
	{
	/** Create the underlying optimized address lookup structures	**/	
	/** if this has not been already done.							**/
    FIN (ip_rtab_init (void));

	/* If the nato tables haven't been created, create them.		*/
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

	FOUT;
	}

static void
ip_rtab_table_handle_register (void)
	{
	/** This function is used to register the global IP address		**/
	/**	table handle in the model-wide registry.					**/
	FIN (ip_rtab_table_handle_register (void));

	/*	Publish handle to the IP table in the process registry.		*/
	oms_pr_attr_set (own_process_record_handle, 
		"ip table handle",			OMSC_PR_POINTER,	ip_table_handle, 
		"ip networks table handle",	OMSC_PR_POINTER,	ip_networks_table_handle, 
		OPC_NIL);

	FOUT;
	}

static IpT_Router_Id
ip_rte_router_id_calculate (void)
	{
	int 				num_intf;
	int					intf_index;
	IpT_Interface_Info*	iface_info_ptr 	= OPC_NIL;
	IpT_Router_Id 		rtr_id 			= IPC_ROUTER_ID_INVALID;

	/**	This function is responsible for the following tasks:	**/
	/**	1.	Checks if a loop back interface is configured on 	**/
	/** 	router. If it is then the 'ospf_router_id' is the 	**/
	/**		loopbak interface									**/
	/**	2. 	Else Verifies whether all the interfaces of the 	**/
	/**		present router are unnumbered. If yes then this is	**/
	/**		a error condition as we expect the user to provide	**/
	/**		the "router id" in case all interfaces are 			**/
	/**		unnumbered. We terminate the simulation with a log	**/
	/**		message expecting the user to correct the behavior.	**/
	/**3. 	Else, at least one of the interface of the router	**/
	/**		is connected to a numbered link. In this case the	**/
	/**		"router id" is assigned the interface address of 	**/
	/**		a valid IP interface								**/
	/**4. 	When there are more than one valid IP interface the	**/
	/** 	the highest interface address is selected as the	**/
	/**		router ID											**/
	FIN (ip_rte_router_id_calculate ());

	/* Check if we have loopback iface index in module data	*/
 	/* If yes then we do not need to loop through the table	*/
	if (module_data.first_loopback_intf_index != IPC_MCAST_MAJOR_PORT_INVALID)
		{
		/* Get the loopback iface							*/
		iface_info_ptr = ip_rte_intf_tbl_access (&module_data, (int) module_data.first_loopback_intf_index);
			
		/* If the router has a loopback address configured	*/
		/* then the loopback address would be the ideal 	*/
		/* candidate for Rtr ID								*/
		if (iface_info_ptr->phys_intf_info_ptr->intf_status == IpC_Intf_Status_Loopback) 
			{
			/* This is a good candidate for the Router ID */
			rtr_id = iface_info_ptr->addr_range_ptr->address;
			FRET (rtr_id);
			}
		}
	
	/* The router has not been assigned. Obtain the total	*/
	/* number of active interfaces.							*/
	num_intf = ip_rte_num_interfaces_get (&module_data);
	
	for (intf_index = 0; intf_index < num_intf; intf_index++)
		{
		/* Get the next iface								*/
		iface_info_ptr = ip_rte_intf_tbl_access (&module_data, intf_index);
			
		/* Loopback interfaces have already been considered	*/
		/* So if its a loopback then continue with next one	*/
		if (iface_info_ptr->phys_intf_info_ptr->intf_status == IpC_Intf_Status_Loopback)
			continue;
		else
			{
			/* Each element obtained from the list published by IP corresponds	*/
			/* to a row in IP's 'ip addr info' attribute. The OSPF Interface	*/
			/* that corresponds to this is the one specified in the same row	*/
			/* of OSPF's 'Interface Table' attribute. Make sure that we are		*/
			/* not dealing with an unnumbered interface.						*/
			if (! ip_rte_intf_unnumbered (iface_info_ptr))
				{
				/* This interface was "not" an unnumbered interface. Since it	*/
				/* must have a valid IP address (either via auto-assignment or	*/
				/* manual addressing, use it as the router identifier.			*/
				if (rtr_id <= iface_info_ptr->addr_range_ptr->address)
					rtr_id = iface_info_ptr->addr_range_ptr->address;
				}
			}	
		}

	/* Return the router identifier.	*/
	FRET (rtr_id);
	}

static int
ip_rte_as_number_get ()
	{
	static int next_available_as_num = 1;

	/** An AS number is assigned to the routers that make a call to this	**/
	/** function. The AS number may not be unique if a user chose to assign **/
	/** values for some routers and leave the rest to be Auto Assigned. 	**/
	/** Function does not preclude reserved AS numbers from being assigned.	**/ 
	FIN (ip_rte_as_number_get (void))

	if (next_available_as_num < 65536)
		{
		FRET (next_available_as_num++);
		}
	else
		{
		/* The next available AS number has reached the maximum of possible	*/
		/* AS values. Start assigning from 1.								*/
		next_available_as_num = 1;
		FRET (next_available_as_num++);
		}
	}
	
static void
ip_rte_stathandle_init (void)
	{
	/**	Register the stathandles to be used for collecting statistics	**/
	/**	from the IP layer.												**/
	FIN (ip_rte_stathandle_init (void));

	/* Register the statistics that will be maintained by this model.	*/
	module_data.locl_tot_pkts_sent_hndl      = 
		op_stat_reg ("IP.Traffic Sent (packets/sec)",				OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_mcasts_sent_hndl    = 
		op_stat_reg ("IP.Multicast Traffic Sent (packets/sec)",    	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_bcasts_sent_hndl    = 
		op_stat_reg ("IP.Broadcast Traffic Sent (packets/sec)",     OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_tot_pkts_rcvd_hndl      = 
		op_stat_reg ("IP.Traffic Received (packets/sec)",          	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_mcasts_rcvd_hndl    = 
		op_stat_reg ("IP.Multicast Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_bcasts_rcvd_hndl    = 
		op_stat_reg ("IP.Broadcast Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_pkts_dropped_hndl   = 
		op_stat_reg ("IP.Traffic Dropped (packets/sec)",			OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.globl_num_pkts_dropped_hndl	 = 
		op_stat_reg ("IP.Traffic Dropped (packets/sec)",			OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
	module_data.globl_tracer_ete_delay_hndl  = 
		op_stat_reg ("IP.Background Traffic Delay (sec)",			OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
	module_data.local_tracer_in_ete_hndl	 = 
		op_stat_reg ("IP.Background Traffic Delay <-- (sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_hops_dest_hndl	 = 
		op_stat_reg ("IP.Number of Hops <--",						OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_hops_src_hndl	 = 
		op_stat_reg ("IP.Number of Hops -->",						OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.globl_num_hops_hndl	 = 
		op_stat_reg ("IP.Number of Hops",							OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);


	/* Register statistic handle to record packet latency through the	*/
	/* IP layer.														*/
	module_data.ip_rte_pkt_latency_stathandle = 
		op_stat_reg ("IP.Processing Delay (sec)", OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	module_data.locl_num_mcasts_drop_pkts_hndl    = 
		op_stat_reg ("IP.Multicast Traffic Dropped (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	module_data.locl_num_mcasts_drop_bps_hndl    = 
		op_stat_reg ("IP.Multicast Traffic Dropped (bits/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	FOUT;
	}

static void
ip_rte_determine_lan_node_context ()
	{
	List			proc_record_handle_list;
	int				record_handle_list_size;

	/** Checks if the surrounding node is acting like a LAN node (is needed		**/
	/** because if this surrounding node is a LAN object, then all the packets	**/
	/** received from the higher layer will be forwarded to the lower layer		**/
	/** (which may forward it back to the higher layer, if it is destined for	**/
	/** the same node.) If the node is not a LAN object, then higher layer		**/
	/** packets destined the same node will be directly sent back up.			**/
	FIN (ip_rte_determine_lan_node_context ());

	/* Initialize state variable used to indicate if this node is within a LAN.	*/
	module_data.flags &= ~IPC_NODE_FLAG_LAN;

	/* Find out the node type from model wide process registry.	*/
	op_prg_list_init (&proc_record_handle_list);

	oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list, 
			"node objid",	OMSC_PR_OBJID,		module_data.node_id, 
			"node_type", 	OMSC_PR_STRING, 	"lan_mac", 
			OPC_NIL);

	/* Obtain the list size of the discovered processes.	*/
	record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
	if (record_handle_list_size == 1)
		{
		/* Set a flag indicating that this is a LAN node.	*/
		module_data.flags |= IPC_NODE_FLAG_LAN;
		}

	/* Deallocate no longer needed process registry information.	*/
	while (record_handle_list_size > 0)
		{
		op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);
		--record_handle_list_size;
		}

	FOUT;
	}

static void
ip_rte_icmp_init (void)
	{
	/** Creates an ICMP child process for this process. The ICMP	**/
	/** process will be used to transfer "ping" traffic with		**/
	/** different destinations as specified on the IP Ping Traffic	**/
	/** model attribute. The ICMP child process will generate ICMP	**/
	/** echo packets. A shared memory is also installed for later	**/
	/** use to get packets from the child process.					***/
	FIN (ip_rte_icmp_init ());

	/* Create an ICMP process and invoke it for initialization.		*/
	module_data.icmp_process_handle = op_pro_create ("ip_icmp", &module_data.ip_ptc_mem);
	op_pro_invoke (module_data.icmp_process_handle, OPC_NIL);

	FOUT;
	}

static void
ip_stream_from_iface_index (int iface_index, int* in_stream_ptr, int* out_stream_ptr, IpT_Interface_Type* interface_type_ptr)
	{
	int				num_dirs, assoc_dir;
	int				s, num_streams;
	int				assigned_iface_index;
	Objid			stream_objid;

	/* Find a stream connected to the IP-layer module that supports 	*/
	/* the specified interface. The interface is specified by its 		*/
	/* index in the interface table. 									*/
	FIN (ip_stream_from_iface_index (int iface_index, int* out_stream_ptr, int* in_stream_ptr, IpT_Interface_Type* interface_type_ptr))

	/*	Initialize the stream index output arguments to indicate that	*/
	/*	no streams were found. These values will be overwritten if the	*/
	/*	streams are found.												*/
	*in_stream_ptr = *out_stream_ptr = IPC_PORT_NUM_INVALID;

	/* Loop through all input and output streams to check for the 		*/
	/* presence and value of the "ip addr index" attribute. This 		*/
	/* extended attribute specifies the interface supported by the 		*/
	/* stream, if any. 													*/
	for (num_dirs = 0, assoc_dir = OPC_TOPO_ASSOC_IN; num_dirs < 2; 
		assoc_dir = OPC_TOPO_ASSOC_OUT, num_dirs++)
		{
		/* For each direction (in and out), now loop through the streams of that type. */
		num_streams = op_topo_assoc_count (module_data.module_id, assoc_dir, OPC_OBJTYPE_STRM);
		for (s = 0; s < num_streams; s++)
			{
			/* Obtain the object ID of the s_th stream. */
			stream_objid = op_topo_assoc (module_data.module_id, assoc_dir, OPC_OBJTYPE_STRM, s);
			
			/* The extended attribute might not exist on all connected streams, 	*/
			/* so check first for its presence. This avoids generating an error 	*/
			/* when getting the attribute value. 									*/
			if (op_ima_obj_attr_exists (stream_objid, "ip addr index") == OPC_TRUE)
				{
				/* Obtain the index of the interface assigned to the stream and 	*/
				/* compare to the sought interface index. 							*/
				op_ima_obj_attr_get (stream_objid, "ip addr index", &assigned_iface_index);
				if (assigned_iface_index == iface_index)
					{
					/*	Based on the direction of the packet stream (incoming to IP	*/
					/*	module or outgoing from IP module), determine the stream 	*/
					/*	index.														*/
					if (assoc_dir == OPC_TOPO_ASSOC_IN)
						{
						 op_ima_obj_attr_get (stream_objid, "dest stream", in_stream_ptr);
						}
					else
						{
						/* What is on the other side of the stream ?. If it happens */
						/* to be a transmitter, regarded as dumb, it cannot do 		*/
						/* anything useful with ICIs associated with the packets  	*/
						/* sent through this stream.								*/
						if (op_topo_assoc_count (stream_objid, OPC_TOPO_ASSOC_OUT, OPC_OBJMTYPE_XMIT) ==1)
							{
							 /* The stream is connected to a transmitter.			*/
							*interface_type_ptr = IpC_Intf_Type_Dumb;
							}
						else
							{
							/* The stream is connected to a module. The module is   */
							/* assumed to be smart enough to process the datagrams  */
							/* and the associated file.								*/
							*interface_type_ptr = IpC_Intf_Type_Smart;
							}
 
						op_ima_obj_attr_get (stream_objid, "src stream", out_stream_ptr);
						}
					}
				}
			}	
		}

	FOUT	
	}

static void
ip_local_dyn_route_protos_invoke (int protos, int invoke_flag, List* active_custom_rte_proto_label_lptr)
	{
	int					bit_pos, max_bit_pos;
	List				proc_record_handle_list;
	OmsT_Pr_Handle		process_record_handle;		
	Objid				dyn_rte_objid;
	int 				i;
	int					num_custom_rte_protocols;
	char*				custom_rte_protocol_name_ptr;
	char				error_string [512];
	const char*			proto_names [] = {"rip", "igrp", "ospf", "bgp", "eigrp", "isis", "ripng"};
	Boolean				invoke_this_proto;
	IpT_Rte_Proto_Oms_Pr_Info*	pr_reg_info_ptr;
	
	
	/** The input argument, protos, has bits set for those standard	**/
	/** routing protocols that have been "individually" activated   **/
	/** on those interfaces that have been discovered in this node. **/
	/** For each such routing protocol, the following is now donw   **/
	/**     1.  Get a reference to the OMS PR record for the        **/
	/**         routing protocol.                                   **/
	/**     2.  Store the result from 1 (above) in the appropriate  **/
	/**         member of the IpT_Cmn_Rte_Table object that         **/
	/**         represents the IP Routing Table for this node.      **/
	/**     3.  Get the parent module object ID of the routing      **/
	/**         protocol process instance in this node and issue    **/
	/**         a remote interrupt to it. This is done only if the	**/
	/**			second argument, invoke_flag, is set to OPC_TRUE.	**/
	/** The input argument, active_custom_rte_proto_label_lptr,		**/
	/** has a list of custom routing protocols that have been		**/
	/** individually activated on those interfaces that have been	**/
	/** discovered in this node. For each such routing protocol,	**/
	/** get the parent module object ID of the routing protocol 	**/
	/** instance in this node and issue a remote interrupt to it.	**/
	/** This is done only if the second argument, invoke_flag is	**/
	/** set to OPC_TRUE.											**/
	FIN (ip_local_dyn_route_protos_invoke (protos, invoke_flag, active_custom_rte_proto_label_lptr));
	
	/* Since the IPv6 versions of the routing protocols are in the	*/
	/* same module as the IPv4 versions, we do not need to interrupt*/
	/* them seperately. However, it is possible that the IPv6		*/
	/* version of a routing protocol is enabled, but not the		*/
	/* corresponding IPv4 version. To handle such cases, if an IPv6	*/
	/* routing protocol is enabled, assume that the corresponding	*/
	/* IPv4 protocol is also enabled.								*/
	/* Currently RIPng is the only IPv6 routing protocol that we	*/
	/* support.														*/
	if (protos & IPC_RTE_PROTO_RIPNG)
		{
		/* Mark RIP as enabled.										*/
		protos |= IPC_RTE_PROTO_RIP;
		}

	/* Allocate memory to hold the oms_pr handles. Do it in this	*/
	/* function to ensure that we do not waste memory on end nodes.	*/
	pr_reg_info_ptr = (IpT_Rte_Proto_Oms_Pr_Info *) op_prg_mem_alloc (sizeof (IpT_Rte_Proto_Oms_Pr_Info));
	module_data.rte_proto_oms_pr_info_ptr = pr_reg_info_ptr;
	
	/* IP oms_pr handle is used to install static routes.  */
	pr_reg_info_ptr->ip_procreg_handle = own_process_record_handle;
		
	/* Reading from LSB to MSB, currently, bits 0, 1, 2, 3, 4, 5, 6	*/
	/* used to flag the activation of RIP, IGRP, OSPF, BGP, EIGRP	*/
	/* IS-IS and RIPng respectively. Since RIP and RIPng share a	*/
	/* module, there is no need to invoke RIPng separately. So the	*/
	/* maximum bit position that needs to be evaluated is five.		*/
	max_bit_pos = 5;

	/* Test bits 6, 5, 4, 3, 2, 1 and 0(reading from MSB to LSB)that*/
	/* correspond to RIPng, IS-IS, EIGRP, BGP, OSPF, IGRP and RIP. And for */	
	/* each	bit that is set to one, perform the tasks outlined above*/
	for (bit_pos = max_bit_pos; bit_pos >= 0; --bit_pos)
		{
		/* Is the bit_pos bit set?	*/
		if ((protos & (1<<bit_pos)) != 0)
			{
			invoke_this_proto = OPC_TRUE;
			
			/*	Search through the process registry to find the		*/
			/*	appropriate process.								*/
			op_prg_list_init (&proc_record_handle_list);

			oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list, 
					"node objid",	OMSC_PR_OBJID,	module_data.node_id, 
					"protocol",		OMSC_PR_STRING,	proto_names [bit_pos], 
					OPC_NIL);

			/* Sanity check.											*/
			if (op_prg_list_size (&proc_record_handle_list) != 1)
				{
				/* An error message should be generated if zero or more	*/
				/* than one process record for a single routing protocol*/
				/* has been registered in OMS PR - in the local node.	*/
				if (strcmp (proto_names [bit_pos], "bgp") != 0)
					{
					ipnl_no_process (proto_names [bit_pos]);
					}
				}
			else
				{
	
				/* Get a reference to the process record.				*/
				process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (
						&proc_record_handle_list, OPC_LISTPOS_HEAD);

				/* Initialize the placeholder for the OMS PR record of	*/
				/* the corresponding routing protocol in the			*/
			 	/* IpT_Cmn_Rte_Table object. A reference to this is		*/
				/* available via the module_data.ip_route_table SV.		*/
				if (((1<<bit_pos) & IPC_RTE_PROTO_RIP) != 0)
					pr_reg_info_ptr->rip_procreg_handle = process_record_handle;
				else if (((1<<bit_pos) & IPC_RTE_PROTO_IGRP) != 0)
					pr_reg_info_ptr->igrp_procreg_handle = process_record_handle;
				else if (((1<<bit_pos) & IPC_RTE_PROTO_OSPF) != 0)
					pr_reg_info_ptr->ospf_procreg_handle = process_record_handle;
				else if (((1<<bit_pos) & IPC_RTE_PROTO_BGP) != 0)
					pr_reg_info_ptr->bgp_procreg_handle = process_record_handle;
				else if (((1<<bit_pos) & IPC_RTE_PROTO_EIGRP) != 0)
					pr_reg_info_ptr->eigrp_procreg_handle = process_record_handle;
				else if (((1<<bit_pos) & IPC_RTE_PROTO_ISIS) != 0)
					pr_reg_info_ptr->isis_procreg_handle = process_record_handle;
				else if (((1<<bit_pos) & IPC_RTE_PROTO_RIPNG) != 0)
					{
					pr_reg_info_ptr->ripng_procreg_handle = process_record_handle;
					/* No need to invoke ripng separately. We would have*/
					/* already invoked RIP.								*/
					invoke_this_proto = OPC_FALSE;
					}

				if (invoke_this_proto) 
					{
					/*	Obtain the object id of the module performing the	*/
					/*	dynamic routing.									*/
					oms_pr_attr_get (process_record_handle,
						"module objid", OMSC_PR_OBJID, &dyn_rte_objid);

					if (invoke_flag == IPC_OPERATE_ROUTING_PROTO)
						{
						/*	Schedule a remote interrupt to the local dynamic	*/
						/*	routing protocol process to notify it that the IP	*/
						/*	interface table can now be accessed.				*/
						op_intrpt_schedule_remote (op_sim_time (), 0, dyn_rte_objid);
						}
					else if (invoke_flag == IPC_STALL_ROUTING_PROTO)
						{
						/* Inform routing protocol to stall routing */
						op_intrpt_schedule_remote (op_sim_time (), IP_IMPORT_TABLE, dyn_rte_objid);
						}
					}					
				}
			}
		}
	
	/** For each of the custom routing protocols running on	this node	**/
	/** discover their process handle and schedule a remote	interrupt	**/
	/** to invoke the custom routing protocol.							**/

	/* Is this node a router?									*/	
	if (invoke_flag == OPC_TRUE)
		{
		/* Get the number of custom routing protocols that are active on this node	*/
		num_custom_rte_protocols = op_prg_list_size (active_custom_rte_proto_label_lptr);
	
		/* Loop through the list of active custom routing protocols	*/
		for (i = 0; i < num_custom_rte_protocols; i++)
			{
			/* Access the ith protocol label from the list.			*/
			custom_rte_protocol_name_ptr = (char *) op_prg_list_access (active_custom_rte_proto_label_lptr, i);
		
			/* Search through the process registry to find the		*/
			/* appropriate process.									*/
			op_prg_list_init (&proc_record_handle_list);
		
			oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list, 
					"node objid",	OMSC_PR_OBJID,	module_data.node_id, 
					"protocol",		OMSC_PR_STRING,	custom_rte_protocol_name_ptr, 
					OPC_NIL);

			/* Sanity check.											*/
			if (op_prg_list_size (&proc_record_handle_list) != 1)
				{
				/* An error message is generated if zero or more than	*/
				/* one process record for a single custom routing		*/
				/* protocol has been registered in OMS PR - in the local*/
				/* node.												*/
				sprintf (error_string, "%s in this routing node.", custom_rte_protocol_name_ptr);
				op_sim_end (
					"Error: Found none, or more than one OMS Process Record(s) for",
					error_string, OPC_NIL, OPC_NIL);
				}
			else
				{

				/* Get a reference to the process record.					*/
				process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (
										&proc_record_handle_list, OPC_LISTPOS_HEAD);
			
				/*	Obtain the object id of the module performing the	*/
				/*	dynamic routing.									*/
				oms_pr_attr_get (process_record_handle,
					"module objid", OMSC_PR_OBJID, &dyn_rte_objid);

				/*	Schedule a remote interrupt to the custom routing	*/
				/*	protocol process to notify it that the IP interface */
				/*	table can now be accessed.							*/
				op_intrpt_schedule_remote (op_sim_time (), 0, dyn_rte_objid);
				}
			}
			
		}
		
	/* The list for active custom routing protocols is no longer	*/
	/* needed. Remove the cells from the list. Note that we must	*/
	/* not free the memory allocated to the strings in the list		*/
	/* because the routing protocol cache maintains a handle to them*/
	/* The list itself is temporary memory and must not be freed.	*/
	while (op_prg_list_size (active_custom_rte_proto_label_lptr) > 0)
		op_prg_list_remove (active_custom_rte_proto_label_lptr, OPC_LISTPOS_HEAD);
	
	FOUT;
	}

static void
ip_rtab_local_network_register (InetT_Address* ip_network_address_ptr)
	{
	int					status;

	/** Register the possible networks that exist across the interfaces	**/
	/** of this node. These indicate the networks that this node can	**/
	/** reach without using any routing protocols.						**/
	FIN (ip_rtab_local_network_register (ip_network_address_ptr));

	/* Store this IP address along with its compacted (integer) form	*/
	/* in the global IP address table maintained in the NATO package.	*/
	/* Since NATO allows for storing address types with two components	*/
	/* and IP addresses are implemented as "single" component addresses	*/
	/* use "0" for the second component argument of the registration	*/
	/* function below.													*/

	/* Also, create an association between this IP network address and	*/
	/* the object ID of the surrounding node. This may provide a		*/
	/* convenient mapping of IP addresses to containing node object IDs	*/
	/* which helps in mapping IP networks addresses to associated node	*/
	/* names when printing out simulation log messages.					*/

	/* Check to see if this network address has already been registered	*/
	/* If it has been, then do not register it again.					*/
	if (nato_table_one_component_inet_address_entry_exists (ip_networks_table_handle, ip_network_address_ptr) == OPC_FALSE)
		{
		/* The IP network address has not yet been registered.			*/
		status = nato_table_inet_address_register (ip_networks_table_handle, ip_network_address_ptr,
			0, module_data.node_id, module_data.module_id);

		/* If the registration was not successful, return an error.		*/
		if (status == NATOC_TABLE_FORM_INVALID)
			{
			op_sim_end ("Error at function ip_rtab_local_network_register: global ip networks table",
						"is in usage mode and no further registrations can be performed", OPC_NIL, OPC_NIL);
			}
		}

	FOUT;
	}

static void
ip_interface_table_print (IpT_Rte_Module_Data* iprmd_ptr)
	{
    int						i, j;
	char					str0 [512];
	int						num_entries;
	IpT_Interface_Info *	ip_interface_info_ptr;
	char					addr_str [IPC_ADDR_STR_LEN];
	char					subnet_mask_str [IPC_ADDR_STR_LEN];

	/** This function is used to print out the contents of the ip interface table. **/
	FIN (ip_interface_table_print (iprmd_ptr));

	/* Print out the route table information only if the route table exists.*/
	if (iprmd_ptr != OPC_NIL)
		{
		/* First print all the IPv4 interfaces.								*/
		if (ip_rte_node_ipv4_active (iprmd_ptr))
			{
			op_prg_odb_print_major ("IPv4 Interface Table Contents\n", OPC_NIL);
			op_prg_odb_print_minor ("Interface\tAddress\t\tSubnet Mask\tOutput\tInput", OPC_NIL);
			op_prg_odb_print_minor ("---------\t-------\t\t-----------\t------\t-----\n", OPC_NIL);
		
			num_entries = ip_rte_num_interfaces_get (iprmd_ptr);

			for (i = 0; i < num_entries; i++)
				{
				ip_interface_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, i);

				/* Get string representations of the address and subnet mask.*/
				ip_address_print (addr_str, ip_interface_info_ptr->addr_range_ptr->address);
				ip_address_print (subnet_mask_str, ip_interface_info_ptr->addr_range_ptr->subnet_mask);

				sprintf (str0, "  %s\t%s\t%s\t  %d\t  %d\n",
					ip_rte_intf_name_get (ip_interface_info_ptr), addr_str, subnet_mask_str, 
					ip_interface_info_ptr->phys_intf_info_ptr->port_num, ip_interface_info_ptr->phys_intf_info_ptr->in_port_num);

				op_prg_odb_print_minor (str0, OPC_NIL);
				}
			}

		/* Now print the IPv6 interfaces if any.						*/
		if (ip_rte_node_ipv6_active (iprmd_ptr))
			{
			op_prg_odb_print_major ("IPv6 Interface Table Contents\n", OPC_NIL);
		
			num_entries = ipv6_rte_num_interfaces_get (iprmd_ptr);

			for (i = 0; i < num_entries; i++)
				{
				ip_interface_info_ptr = ipv6_rte_intf_tbl_access (iprmd_ptr, i);

				for (j=0; j < ip_rte_intf_num_ipv6_addrs_get (ip_interface_info_ptr); j++)
					{
					/* Get string representations of the address and subnet mask.*/
					inet_address_range_print (addr_str, ip_rte_intf_ith_ipv6_addr_range_get_fast (ip_interface_info_ptr, j));
				
					sprintf (str0, "\t%s", addr_str);

					op_prg_odb_print_minor (str0, OPC_NIL);
					}
				}
			}
		}
	else
		{
		/* Print out an error message saying that the route table does not exist. */
		op_prg_odb_print_major ("IP Interface Table does not exist\n", OPC_NIL);
		}

    FOUT;
	}

static void
ip_networks_print (void)
	{
	int					num_networks;
	int					i_th_network;
	NatoT_Table_Entry *	table_entry_ptr;
	char				header_str [128], header2_str [128];
	char				table_entry_str [512], title_str [512], blank_str [512] = "";
	InetT_Address 		ip_net_addr;
	char				ip_net_addr_str [IPC_ADDR_STR_LEN];

	/** This function is used to print the global IP networks table.	**/
	FIN (ip_networks_print (void));

	/* Print the table header. */
	strcpy (title_str, "Global IP Network Address Information");
	strcpy (header_str,  "IP Network Address   Internal Address");
	strcpy (header2_str, "------------------   ----------------");
	op_prg_odb_print_minor (blank_str, title_str, blank_str, header_str, header2_str, OPC_NIL);

	/* Determine the total number of registered networks.		*/
	num_networks = nato_table_size (ip_networks_table_handle);

	/* Loop through all the networks and print informaiton.		*/
	for (i_th_network = 0; i_th_network < num_networks; i_th_network++)
		{
		/* Get the i_th network address entry.					*/
		table_entry_ptr = nato_table_entry_get (ip_networks_table_handle, i_th_network);

		/* Get the major address -- the IP network address.		*/
		ip_net_addr = nato_table_entry_major_inet_addr_get (table_entry_ptr);

		/* Get string representation of the network address.	*/
		inet_address_print (ip_net_addr_str, ip_net_addr);

		/* Prepare the display string.							*/
		sprintf (table_entry_str, " %-15s          %3d", ip_net_addr_str, i_th_network);

		/* Print out table entry.								*/
		op_prg_odb_print_minor (table_entry_str, OPC_NIL);
		}

	FOUT;
	}

static void
ip_rtab_print (void)
	{
	int					table_size, table_index;
	NatoT_Table_Entry *	table_entry_ptr;
	char				header_str [128], header2_str [128];
	char				table_entry_str [512], title_str [512], blank_str [512] = "";
	InetT_Address 		ip_addr;
	char				ip_addr_str [IPC_ADDR_STR_LEN];
	int					lower_layer_addr;
	int					lower_layer_index;
	Boolean				phys_addr_found;

	/** This function is used to print the global address table. **/
	FIN (ip_rtab_print (void));
	
	/* Print the table header. */
	strcpy (title_str, "Global IP Address Mapping Table:");
	strcpy (header_str, "IP Address\t\tLower Layer Address");
	strcpy (header2_str, "----------\t\t-------------------");
	op_prg_odb_print_minor (blank_str, title_str, blank_str, header_str, header2_str, OPC_NIL);

	/* We do not use the standard nato table print function, so */
	/* can print out IP addresses in a readable form.           */
	table_size = nato_table_size (ip_table_handle);
	
	for (table_index = 0; table_index < table_size; table_index++)
		{
		/* Get the current table entry. */
		table_entry_ptr = nato_table_entry_get (ip_table_handle, table_index);

		/* Get the major address, which is the IP address. */
		ip_addr = nato_table_entry_major_inet_addr_get (table_entry_ptr);

		/* Get string representation of address. */
		inet_address_print (ip_addr_str, ip_addr);

		/* Loop through the lower layer addresses, and print out the */
		/* address that's defined.                                   */
		phys_addr_found = OPC_FALSE;
		for (lower_layer_index = 0; lower_layer_index < NATOC_NUM_LOWER_LAYER_ADDRS; lower_layer_index++)
			{
			if ((lower_layer_addr = nato_table_entry_phys_addr_get (table_entry_ptr, lower_layer_index)) !=
				NATOC_LOWER_LAYER_ADDR_UNDEFINED)
				{
				sprintf (table_entry_str, "(%s)\t\t%d (Type %d)",
					ip_addr_str, lower_layer_addr, lower_layer_index);
				phys_addr_found = OPC_TRUE;
				}

			if (!phys_addr_found)
				sprintf (table_entry_str, "(%s)\t\t(No physical address)",
					ip_addr_str);
			}

		/* Print out table entry. */
		op_prg_odb_print_minor (table_entry_str, OPC_NIL);
		}

	FOUT;
	}

static void
ip_dispatch_error (const char *msg)
	{
	/** Print an error message and exit the simulation. **/
	FIN (ip_dispatch_error (msg));

	op_sim_end (
		"Error in IP routing process model (ip_dispatch):",
		msg,
		"Check simulation log messages from the IP model for more information.",
		"Simulation Logging can be enabled/disabled in the Simulation Editor."); 
	FOUT;
	}

static void
ip_dispatch_warn (const char *msg)
	{
	/** Print a warning message and resume. **/
	FIN (ip_dispatch_warn (msg));

	op_sim_message ("Warning from IP routing process model (ip_dispatch):", msg);

	FOUT;
	}



static IpT_Interface_Info *
ip_interface_info_create (int intf_type)
	{
	IpT_Interface_Info *		iface_info_ptr;

	/** Create an interface information structure. **/
	FIN (ip_interface_info_create (void));

	/* Allocate memory for the structure. */
	iface_info_ptr = (IpT_Interface_Info *) op_prg_mem_alloc (sizeof (IpT_Interface_Info));

	/* If this structure is being created for a physical interface,	*/
	/* Allocate memory for the physical interface info structure	*/
	/* Subinterfaces will have a pointer to the structure of their	*/
	/* parent interfaces.											*/
	if (IPC_PHYS_INTF == intf_type)
		{
		iface_info_ptr->phys_intf_info_ptr = (IpT_Phys_Interface_Info*)
			op_prg_mem_alloc (sizeof (IpT_Phys_Interface_Info));
	
		/* Initialize the members of this structure					*/
		iface_info_ptr->phys_intf_info_ptr->ip_addr_index = 0;
		iface_info_ptr->phys_intf_info_ptr->port_num = 0;
		iface_info_ptr->phys_intf_info_ptr->in_port_num = 0;
		iface_info_ptr->phys_intf_info_ptr->connected_link_objid = OPC_OBJID_INVALID;
		iface_info_ptr->phys_intf_info_ptr->num_subinterfaces = 0;
		iface_info_ptr->phys_intf_info_ptr->subintf_pptr = OPC_NIL;
		iface_info_ptr->phys_intf_info_ptr->link_bandwidth = IPC_UNSPECIFIED_RATE;
		iface_info_ptr->phys_intf_info_ptr->lower_layer_addr = OPC_INT_INVALID;
		iface_info_ptr->phys_intf_info_ptr->lower_layer_type = (OpT_Int8) IpC_Intf_Lower_Layer_Invalid;
		}
	else
		{
		/* For subinterfaces set this pointer to NIL. It will	*/
		/* appropriately initialized later						*/
		iface_info_ptr->phys_intf_info_ptr = OPC_NIL;
		}

	/* Initialize fields of the IpT_Interface_Info structure. */
	iface_info_ptr->addr_range_ptr = OPC_NIL;
	iface_info_ptr->inet_addr_range = INETC_ADDR_RANGE_INVALID;
	iface_info_ptr->mtu = 0;
	iface_info_ptr->avail_bw = 1E+15;
	iface_info_ptr->load_bits = 0.0;
	iface_info_ptr->load_bps = 0.0;
	iface_info_ptr->reliability = 1.0;
	iface_info_ptr->last_load_update_time = 0.0;
	iface_info_ptr->flags = 0;
	iface_info_ptr->routing_protocols_lptr = OPC_NIL;
	iface_info_ptr->user_metrics = OPC_NIL;
	iface_info_ptr->ipv6_info_ptr = OPC_NIL;
	iface_info_ptr->tunnel_info_ptr = OPC_NIL;
	ip_rte_intf_name_set (iface_info_ptr, OPC_NIL);
    iface_info_ptr->queuing_scheme = IpC_No_Queuing;
	iface_info_ptr->sec_addr_tbl_ptr = OPC_NIL;
	
	/* As an memory optimization, only allocate this 		*/
	/* background utilization routed state pointer when the */
	/* interface is used.									*/
	iface_info_ptr->load_bgutil_routed_state_ptr = OPC_NIL;

	FRET (iface_info_ptr);
	}

static void
ip_interface_table_verify (IpT_Rte_Module_Data* iprmd_ptr)
    {
    int                     num_intfs, intf_index, check_index;
    IpT_Interface_Info		*intf_ptr;
    IpT_Interface_Info		*check_intf_ptr;
	Boolean					overlapping_subnets_found = OPC_FALSE;
	char					addr_str1 [INETC_ADDR_STR_LEN], addr_str2 [INETC_ADDR_STR_LEN];

    /** Return OPC_TRUE if the list of interfaces given does not overlap **/
    /** address ranges.  Return OPC_FALSE if two or more interfaces      **/
    /** contain overlapping address ranges.                              **/
    FIN (ip_interface_table_verify (iprmd_ptr));

    /* Loop through all interfaces and check for address range conflicts. */
    num_intfs = ip_rte_num_interfaces_get (iprmd_ptr);;

    for (intf_index = 0; intf_index < num_intfs; intf_index++)
        {
        intf_ptr = ip_rte_intf_tbl_access (iprmd_ptr, intf_index);

		/* Ignore this interface if it has not been assigned an	*/
		/* ip address.											*/
		if (ip_rte_intf_no_ip_address (intf_ptr))
			{
			continue;
			}

		/* Check this interface's address with others previously seen. */
		for (check_index = 0; check_index < intf_index; check_index++)
			{
			check_intf_ptr = ip_rte_intf_tbl_access (iprmd_ptr, check_index);

			/* Ignore this interface if it has not been assigned an	*/
			/* ip address.											*/
			if (ip_rte_intf_no_ip_address (check_intf_ptr))
				{
				continue;
				}

			/* Check if the address of this interface falls in the	*/
			/* address range of the interface in the outer loop or	*/
			/* vice versa.											*/
			if ((ip_address_range_check (ip_rte_intf_addr_get (intf_ptr), check_intf_ptr->addr_range_ptr)) ||
				(ip_address_range_check (ip_rte_intf_addr_get (check_intf_ptr), intf_ptr->addr_range_ptr)))
				{
				/* In case of dual MSFCs, the dummy interfaces are created	*/
				/* for the alt addresses. These interfaces will overlap 	*/
				/* with the primary interfaces. Do not write a log message	*/
				/* in this case.											*/
				if ((ip_rte_intf_is_msfc_alt (intf_ptr) && !ip_rte_intf_is_msfc_alt (check_intf_ptr)) ||
				   	(!ip_rte_intf_is_msfc_alt (intf_ptr) && ip_rte_intf_is_msfc_alt (check_intf_ptr)))	
					{
					/* One of the interfaces is a normal interface and the other is an ALT interface.	*/
					continue;
					}
				
				/* We've detected an address overlap. Initialize the*/
				/* log handler if it has not been done already.		*/
				if (! ip_subnet_overlap_loghandle_created)
					{
					/* Create a log handle to log this warning.		*/
					ip_subnet_overlap_loghandle = oms_log_handle_create (OpC_Log_Category_Configuration,
						"IP", "Model_Configuration_Warning", 100, op_sim_time (),
						"WARNING(s):\n"
						"  Detected at least one IP node with interfaces in\n"
						"  overlapping IP subnets. The list of such nodes\n"
						"  and the interfaces with overlapping addresses\n"
						"  on each of them are listed below.\n", "");
					ip_subnet_overlap_loghandle_created = OPC_TRUE;
					}

				/* If this is the first time we have encountered	*/
				/* overlapping subnet on this node, add the node	*/
				/* to the log message.								*/
				if (! overlapping_subnets_found)
					{
					/* Add the node name to the log message.		*/
					oms_log_message_append (ip_subnet_overlap_loghandle, "%s\n", iprmd_ptr->node_name);

					/* Indicate that we have encountered at least	*/
					/* one pair of overlapping subnets.				*/
					overlapping_subnets_found = OPC_TRUE;
					}

				/* Create string representations of the IP addresses*/
				inet_address_range_print (addr_str1, inet_rte_v4intf_addr_range_get (intf_ptr));
				inet_address_range_print (addr_str2, inet_rte_v4intf_addr_range_get (check_intf_ptr));

				/* Append a line containing the interface names and	*/
				/* IP addresses to the log message.					*/
				oms_log_message_append (ip_subnet_overlap_loghandle, "\t%s (%s) and %s (%s)\n",
					ip_rte_intf_name_get (intf_ptr), addr_str1,
					ip_rte_intf_name_get (check_intf_ptr), addr_str2);

				}
			}
        }

	/* Return.	*/
	FOUT;
	}


static void
ip_rte_qos_information_process (void)
	{
	int					iface_table_size, iface_id;
    int                 iface_index;
	IpT_Interface_Info*	iface_info_ptr;
	int					incoming_car_stat_index = 0;
	int					outgoing_car_stat_index = 0;
	int                 total_num_of_qos_ifaces = 0;
	int                 qos_iface_index; 
	char				annotation [1024];
	List                   qos_ifaces_list;
	OmsT_Qm_Car_Stat_Info *	csi_ptr;
	IpT_Qos_Info*		intf_qos_info;
	IpT_QoS_Iface_Config   * qos_iface_config_ptr;
	IpT_Rte_Iface_QoS_Data * interface_qos_data_ptr;
	IpT_Intf_Name_Objid_Table_Handle	intf_objid_lookup_table;

	/** Creates the child processes for processing packets on the 		**/
	/** output queue. One child process is spawned by interface.		**/
	/** Each of them models an output queuing mechanism such as FIFO,	**/
	/** WFQ, Custom Queuing or Priority Queuing, as well as congestion	**/
	/** avoidance mechanisms such as RED/WRED.							**/
	/** This function initializes also the CAR parameters and state		**/
	/** information on each interface.									**/
	FIN (ip_rte_qos_information_process ());

	/* Store in the shared memory information	*/
	/* about each interface.					*/
	module_data.shared_mem.iprmd_ptr = &module_data;

	/* Store in the shared memory the handles for		*/
	/* packets dropped and packet sent.					*/
	/* Other state variables are also shared with		*/
	/* the output interface process model in order to 	*/
	/* take into account the background traffic in the	*/
	/* statistics written in the output interface		*/
	/* process model.									*/
	module_data.shared_mem.locl_pk_dropped_hdl_ptr = &module_data.locl_num_pkts_dropped_hndl;
	module_data.shared_mem.globl_pk_dropped_hdl_ptr = &module_data.globl_num_pkts_dropped_hndl;
	module_data.shared_mem.locl_num_pkts_sent_hdl_ptr = &module_data.locl_tot_pkts_sent_hndl;
	module_data.shared_mem.locl_num_mcasts_sent_hdl_ptr = &module_data.locl_num_mcasts_sent_hndl;
	module_data.shared_mem.locl_num_bcasts_sent_hdl_ptr = &module_data.locl_num_bcasts_sent_hndl;
	module_data.shared_mem.sent_pk_last_update_time = module_data.sent_last_stat_update_time;
	module_data.shared_mem.sent_bgutil_state_ptr = module_data.sent_bgutil_routed_state_ptr;
	module_data.shared_mem.bgutil = module_data.do_bgutil;
	module_data.shared_mem.statistic_index = 0;
	module_data.shared_mem.rsvp_request_ptr = OPC_NIL;
	module_data.shared_mem.rsvp_statistic_index = 0;

	/* Get the number of interfaces.	*/
	iface_table_size = inet_rte_num_interfaces_get (&module_data);

	/* If the interface table is empty, just return.			*/
	if (0 == iface_table_size)
		{
		module_data.interface_qos_data_pptr = OPC_NIL;

		FOUT;
		}

	/* Initilaize the QoS iface list. */
	op_prg_list_init (&qos_ifaces_list);
	
	/* Check the existence of the QoS config utility object.  */
	/* Create default profiles if the utility does not exist. */
	ip_rte_qos_attr_config_info ();
	
	/* Obtain and preprocess the local IP QoS info */
	ip_qos_info_process ((void *) &module_data, &qos_ifaces_list);
	
	/* Get the number of QoS active interfaces. */
	total_num_of_qos_ifaces = op_prg_list_size (&qos_ifaces_list);
	
	/* Allocate memory for the interface QoS data array. */
	module_data.interface_qos_data_pptr = (IpT_Rte_Iface_QoS_Data **) 
		op_prg_mem_alloc (iface_table_size * sizeof (IpT_Rte_Iface_QoS_Data *));
	
	/* Initialize the interface QoS data array. */
	for (iface_index = 0; iface_index < iface_table_size ; ++iface_index)			
		{
		module_data.interface_qos_data_pptr [iface_index] = OPC_NIL;
		}	
		
	/* Create a table to lookup the the objid of each interface	*/
	intf_objid_lookup_table = ip_rte_proto_intf_attr_objid_table_build (module_data.ip_parameters_objid);

	/* Loop through the all the QoS active interfaces to initialize QoS   */
	/* related parameters such as queuing schemes, CAR and RED/WRED.	  */
	for (qos_iface_index = 0; qos_iface_index < total_num_of_qos_ifaces; qos_iface_index ++)
		{
		qos_iface_config_ptr = (IpT_QoS_Iface_Config *) op_prg_list_remove (&qos_ifaces_list, OPC_LISTPOS_HEAD);
		
		/* Obtain the iface_info_ptr from the interface name */
		 if (inet_rte_is_local_intf_name (qos_iface_config_ptr->iface_name, &module_data, &iface_id, 
			&iface_info_ptr, InetC_Addr_Family_Unknown))
			 {
			 /* Enable Queuing on this Interface */
			 if (qos_iface_config_ptr->qm_attr_ptr != OPC_NIL)
				 {
				 iface_info_ptr->queuing_scheme = qos_iface_config_ptr->queuing_scheme;
				 
				 /* Create a structure to pass the objid of the qos information attribute	*/
				 /* to the ip_output_iface process model.									*/
				 intf_qos_info = (IpT_Qos_Info*) op_prg_mem_alloc (sizeof (IpT_Qos_Info));				 
				 intf_qos_info->reserved_bandwidth  = qos_iface_config_ptr->reserved_bandwidth;
				 intf_qos_info->bandwidth_type      = qos_iface_config_ptr->bandwidth_type;
				 intf_qos_info->q_profile_name      = qos_iface_config_ptr->q_profile_name;
				 intf_qos_info->buffer_size         = qos_iface_config_ptr->buffer_size;
				 intf_qos_info->attribs_ptr = qos_iface_config_ptr->qm_attr_ptr;
				 intf_qos_info->llq_attribs_ptr = qos_iface_config_ptr->llq_qm_attr_ptr;
				 			 
				 /* Spawn a child process for the interface.	*/
				 iface_info_ptr->output_iface_prohandle = 
				 op_pro_create ("ip_output_iface", &module_data.shared_mem);

				 /* Invoke the child process in charge of the output queues for initialization.	*/
				 module_data.shared_mem.iface_index = iface_id;
				 op_pro_invoke (iface_info_ptr->output_iface_prohandle, intf_qos_info);
				 }
			 
			 /* Enable Incoming packet Marking on this interface */
			 if (qos_iface_config_ptr->marking_incoming_info_ptr != OPC_NIL)
				 {
				 interface_qos_data_ptr = module_data.interface_qos_data_pptr [iface_id] = ip_rte_qos_data_create ();
				 interface_qos_data_ptr->marking_incoming_info_ptr = qos_iface_config_ptr->marking_incoming_info_ptr;
				 }
			 
			 /* Enable Outgoing packet Marking on this interface */
			 if (qos_iface_config_ptr->marking_outgoing_info_ptr != OPC_NIL)
				 {
				 interface_qos_data_ptr = module_data.interface_qos_data_pptr [iface_id] = ip_rte_qos_data_create ();
				 interface_qos_data_ptr->marking_outgoing_info_ptr = qos_iface_config_ptr->marking_outgoing_info_ptr;
				 }

             /* Enable Incoming CAR Profile on this interface */
			 if (qos_iface_config_ptr->car_incoming_profile_ptr != OPC_NIL)
				 {
				 Boolean created_iface_qos_data = OPC_FALSE;
					 
				 if (module_data.interface_qos_data_pptr [iface_id] == OPC_NIL)
					 {
					 /* Allocate memory for the iface QoS data. */
					 module_data.interface_qos_data_pptr [iface_id] = ip_rte_qos_data_create ();
					 created_iface_qos_data = OPC_TRUE;
					 } 
				 
				 /* Cache the qos interface data. */
				 interface_qos_data_ptr = module_data.interface_qos_data_pptr [iface_id];
				 
				 /* Check whether the CAR profile is valid. */
				 if (ip_rte_car_profile_get (&interface_qos_data_ptr->car_incoming_profile_ptr, 
					  &interface_qos_data_ptr->car_incoming_info_ptr,"Incoming", qos_iface_config_ptr))
					 {
					 csi_ptr = interface_qos_data_ptr->car_stat_info_ptr = (OmsT_Qm_Car_Stat_Info *) 
						 op_prg_mem_alloc (sizeof (OmsT_Qm_Car_Stat_Info));
				
					 /* Register statistic handle for traffic dropped by CAR if the	*/
					 /* interface supports CAR.										*/
					 csi_ptr->in_traffic_dropped_in_pps_stathandle = 
					 op_stat_reg ("IP Interface.CAR Incoming Traffic Dropped (packets/sec)", 
						 incoming_car_stat_index, OPC_STAT_LOCAL);
					 csi_ptr->in_traffic_dropped_in_bps_stathandle =
						 op_stat_reg ("IP Interface.CAR Incoming Traffic Dropped (bits/sec)", 
							 incoming_car_stat_index, OPC_STAT_LOCAL);

					 /* Renaming statistics to include the interface index.	*/
					 strncpy (annotation, ip_rte_intf_name_get (iface_info_ptr), 1023);
					 op_stat_annotate (csi_ptr->in_traffic_dropped_in_pps_stathandle, annotation);
					 op_stat_annotate (csi_ptr->in_traffic_dropped_in_bps_stathandle, annotation);

					 /* Increments the statistic index.	*/
					 incoming_car_stat_index ++;
					 }
				 else
					 {
					 /* Invalid CAR profile. */
					 
					 if (created_iface_qos_data)
						 {
						 /* Destroy the unused memory. */
						 op_prg_mem_free (module_data.interface_qos_data_pptr [iface_id]);
						 module_data.interface_qos_data_pptr [iface_id] = OPC_NIL;
						 }
					 }
				 }
			 
			 /* Enable Outgoing CAR Profile on this interface */
			 if (qos_iface_config_ptr->car_outgoing_profile_ptr != OPC_NIL)
				 {
				 Boolean created_iface_qos_data = OPC_FALSE;
					 
				 if (module_data.interface_qos_data_pptr [iface_id] == OPC_NIL)
					 {
					 /* Allocate memory for the iface QoS data. */
					 module_data.interface_qos_data_pptr [iface_id] = ip_rte_qos_data_create ();
					 created_iface_qos_data = OPC_TRUE;
					 } 
				 
				 /* Cache the qos interface data. */
				 interface_qos_data_ptr = module_data.interface_qos_data_pptr [iface_id];
				 
				 /* Check whether the CAR profile is valid. */
				 if (ip_rte_car_profile_get (&interface_qos_data_ptr->car_outgoing_profile_ptr, 
					 &interface_qos_data_ptr->car_outgoing_info_ptr,"Outgoing",
					 qos_iface_config_ptr))
					 {
					 csi_ptr = interface_qos_data_ptr->car_stat_info_ptr = (OmsT_Qm_Car_Stat_Info *) 
						 op_prg_mem_alloc (sizeof (OmsT_Qm_Car_Stat_Info));

					 /* Register statistic handle for traffic dropped by CAR if the	*/
					 /* interface supports CAR.										*/
					 csi_ptr->out_traffic_dropped_in_pps_stathandle =
					 op_stat_reg ("IP Interface.CAR Outgoing Traffic Dropped (packets/sec)", 
						 outgoing_car_stat_index, OPC_STAT_LOCAL);
					 csi_ptr->out_traffic_dropped_in_bps_stathandle =
						 op_stat_reg ("IP Interface.CAR Outgoing Traffic Dropped (bits/sec)", 
							 outgoing_car_stat_index, OPC_STAT_LOCAL);

					 /* Renaming statistics to include the interface index.	*/
					 strncpy (annotation, ip_rte_intf_name_get (iface_info_ptr), 1023);
					 op_stat_annotate (csi_ptr->out_traffic_dropped_in_pps_stathandle, annotation);
					 op_stat_annotate (csi_ptr->out_traffic_dropped_in_bps_stathandle, annotation);
					 
					 /* Increments the statistic index.	*/
					 outgoing_car_stat_index ++;
					 }
				 else
					 {
					 /* Invalid CAR profile. */
					 
					 if (created_iface_qos_data)
						 {
						 /* Destroy the unused memory. */
						 op_prg_mem_free (module_data.interface_qos_data_pptr [iface_id]);
						 module_data.interface_qos_data_pptr [iface_id] = OPC_NIL;
						 }
					 }
				 }
			 
			 }
		else
			{
			 /* Interface name not resolved. Write a log message. */
			 qosnl_qos_info_not_resolved (IpC_QoS_Log_Unresolved_Iface_Name, op_id_self(), 
				qos_iface_config_ptr->iface_name, (char *) "N/A");			 
			}
			
		/* Free some memory we will not need anymore. */
		op_prg_mem_free (qos_iface_config_ptr->iface_name);
		op_prg_mem_free (qos_iface_config_ptr);
		}
	
	/* Free the memory allocated to the lookup table.				*/
	ip_rte_proto_intf_attr_objid_table_destroy (intf_objid_lookup_table);
	
	/* Check the configuration consistency for RSVP. Since RSVP requires CQ or WFQ	*/
	/* to be configured on interfaces, make sure that this is indeed the case.		*/
	/* This function can be executed only now, once the QoS parameters have been 	*/
	/* read. Execute the check only if RSVP is used for IntServ, and not for MPLS.	*/
	if (module_data.rsvp_te_status == OPC_FALSE)
		ip_rsvp_qos_config_check ();

	FOUT;
	}

static Boolean
ip_rte_car_profile_get (OmsT_Qm_Car_Profile** car_profile_pptr, 
	OmsT_Qm_Car_Information**  car_info_pptr, const char* direction, 
	IpT_QoS_Iface_Config* qos_iface_config_ptr)
	{
	int				cos;
	OmsT_Qm_Car_Profile     *  car_profile_ptr = OPC_NIL;
	OmsT_Qm_Car_Information *  car_info_ptr = OPC_NIL; 
	
	/** This function gets the CAR profile for one interface.	**/
	/** It initializes, allocates memory for the two CAR		**/
	/** structures in charge of keeping track of CAR parameters	**/
	/** and states. CAR will be disabled if the specified		**/
	/** does not exist or if the CAR profile is set to "None".	**/
	FIN (ip_rte_car_profile_get (<args>))
		
		
	if (!strcmp (direction, "Incoming"))	
		car_profile_ptr = qos_iface_config_ptr->car_incoming_profile_ptr;
	else
		car_profile_ptr = qos_iface_config_ptr->car_outgoing_profile_ptr;

	if (car_profile_ptr != OPC_NIL)
		{
		/* Allocate memory for each class of service (COS).	*/
		car_info_ptr = (OmsT_Qm_Car_Information *) 
			op_prg_mem_alloc (car_profile_ptr->number_of_cos * sizeof (OmsT_Qm_Car_Information));

		/* Initialize the traffic state for each COS.	*/
		for (cos = 0; cos < car_profile_ptr->number_of_cos; cos++)
			{
			car_info_ptr [cos].bucket_size = 0;
			car_info_ptr [cos].last_update_time = 0;
			}
		
	    *car_info_pptr    = car_info_ptr;
	    *car_profile_pptr = car_profile_ptr;
		
		FRET (OPC_TRUE);
		}
	else
		{
		/* CAR is disabled on this interface. Initialize  */
		/* data structures to NIL values. 				  */
		*car_profile_pptr = OPC_NIL;	
		*car_info_pptr    = OPC_NIL;
		
		FRET (OPC_FALSE);
		}
	}


static IpT_Rte_Iface_QoS_Data *
ip_rte_qos_data_create ()
    {
	IpT_Rte_Iface_QoS_Data *  interface_qos_data_ptr; 
	
	/* Create and initialize interface QoS data. */
	FIN (ip_rte_qos_data_create ());
	
	/* Allocate memory for the new QoS data ptr. */
	interface_qos_data_ptr = (IpT_Rte_Iface_QoS_Data *) op_prg_mem_alloc (sizeof (IpT_Rte_Iface_QoS_Data));
	
	/* Initialize the new pointer. */
	interface_qos_data_ptr->marking_incoming_info_ptr = OPC_NIL;
	interface_qos_data_ptr->marking_outgoing_info_ptr = OPC_NIL;
	interface_qos_data_ptr->car_incoming_profile_ptr  = OPC_NIL;
	interface_qos_data_ptr->car_outgoing_profile_ptr  = OPC_NIL;
	interface_qos_data_ptr->car_incoming_info_ptr     = OPC_NIL;
	interface_qos_data_ptr->car_outgoing_info_ptr     = OPC_NIL;
	interface_qos_data_ptr->car_stat_info_ptr         = OPC_NIL;
	
	FRET (interface_qos_data_ptr);
	}


static void
ip_register_routerid_as_local_netaddr ()
	{
	int 					unnumbered_size = 0;
	IpT_Interface_Info* 	iface_info_ptr;
	int						index;
	int						intf_table_size;
	Objid					local_objid;
	Objid					node_objid;
	InetT_Address 			inet_router_id;
	IpT_Address*			router_id_ptr;
    List*               	proc_record_handle_list_ptr;
    OmsT_Pr_Handle      	process_record_handle;
	int						proc_record_list_size = 0;
	double					as_count;
	int						i;
	char					string [32];

	/** In case of a Router running OSPF with all connected interfaces	**/
	/** as unnumbered link interfaces, the router ID is registered as 	**/
	/** local network address. This function initially checks if all the**/
	/** interfaces of the router are unnumbered and if so gets the 		**/
	/** Router ID from the OSPF model attribute called "Router ID". 	**/
	FIN (ip_register_routerid_as_local_netaddr ());

	/* Loop through the available interface list to find	*/
	/* whether all the OSPF interfaces are unnumbered or not*/
	/* Also store the interface pointer into a local var	*/
	/* to be used later for accessing interface information	*/
	intf_table_size = op_prg_list_size (module_data.interface_table_ptr);
	for (index = 0; index < intf_table_size ; ++index)
		{
		iface_info_ptr = (IpT_Interface_Info *) op_prg_list_access (module_data.interface_table_ptr, index);

		if (ip_rte_intf_unnumbered (iface_info_ptr) &&
			ip_interface_routing_protocols_contains (iface_info_ptr->routing_protocols_lptr, IpC_Rte_Ospf) == OPC_TRUE)
			{
			++unnumbered_size;
			}
		}

	/* Check whether the number of unnumbered interface 	*/
	/* equals the interface table size. If so the Router ID	*/
	/* is registered as the local network address.			*/			 
	if (intf_table_size > 0 && unnumbered_size == intf_table_size)
		{
		/* Obtain the Object Identifier for the current 	*/
		/* module and the surrounding node. 				*/	
		local_objid = op_id_self ();
		node_objid = op_topo_parent (local_objid);

		/*  Search through the process registry to find the     */
		/*  appropriate process.                                */
		proc_record_handle_list_ptr = op_prg_list_create ();

		oms_pr_process_discover (OPC_OBJID_INVALID, proc_record_handle_list_ptr,
				"node objid",   OMSC_PR_OBJID,  node_objid,
				"protocol",     OMSC_PR_STRING, "ospf",
				OPC_NIL);

		/* Store the size of the process list in the temporary var */
		proc_record_list_size = op_prg_list_size (proc_record_handle_list_ptr);

		/* Sanity check.                                        */
		if (proc_record_list_size > 1)
			{
			/* An error should be created if there are more than    */
			/* one process record for a single routing protocol has */
			/* been registered in OMS PR - in the the local node.   */
            op_sim_end (
                "Error: Found none, or more than one OMS Process Record(s) for",
                "a OSPF routing protocol in this routing node.", "", "");
			}
		else if (proc_record_list_size == 0)
			{
			/* No OSPF process in the current node */
			op_prg_mem_free (proc_record_handle_list_ptr);
			FOUT;
			}
		else
			{
			/* Get a reference to the process record.                   */
			process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (
				proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
				/* Get the number of active OSPF processes.	*/
			oms_pr_attr_get (process_record_handle,	
				"process count", 	OMSC_PR_NUMBER,		&as_count, 
			OPC_NIL);

			for (i = 0; i < (int) as_count; i++)
				{		
				string [0] = '\0';
				sprintf (string, "\"router id %d\"", i);
				
				/* Obtain the "router id" of the OSPF router registered	*/
				/* in the init enter execs of the OSPF process model.	*/
				oms_pr_attr_get (process_record_handle,
					string, OMSC_PR_POINTER, &router_id_ptr);

				/* Obtain the router id from the router id pointer		*/
				/* We pass the pointer to the router id so that even if	*/
				/* the router id is changed the current valid router id	*/
				/* would only be obtained.								*/
				inet_router_id = inet_address_from_ipv4_address_create (*router_id_ptr);

				/* Now register the Router ID as the local 		*/
				/* network address								*/
				ip_rtab_local_addr_register (&inet_router_id, &module_data);
				}

			/* free memory */
			op_prg_list_remove (proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
			op_prg_mem_free (proc_record_handle_list_ptr);
			}
		}	

	FOUT;
	}

/**** Routing protocol specification related. ****/
static List* 
ip_interface_routing_protocols_obtain (Objid intf_info_objid, Objid ipv6_attrs_objid,
	IpT_Interface_Status intf_status, List* active_custom_rte_proto_label_lptr)
	{
	static Boolean			initialization_complete = OPC_FALSE;
	static List*			rte_proto_list_cache = OPC_NIL;
	static List*			sim_attr_rte_prot_lptr = OPC_NIL;
	static char*			sim_attr_custom_rte_proto_label = OPC_NIL;
	List					sim_attr_custom_rte_proto_label_list;
	int*					rte_proto_ptr;
	char					ip_dyn_rte_spec [32];
	char					ipv6_dyn_rte_spec [32];
	IpT_Rte_Proto_List_Cache_Entry	rte_cache_entry;
	IpT_Rte_Proto_List_Cache_Entry*	cache_entry_ptr;
	char					addr_str [IPC_MAX_STR_SIZE];
	
	/** What is the routing protocol(s) that the user has set up **/
	/** on this interface?  Note that:                           **/
	/**  1. Router nodes may specify different routing protocols **/
	/**     on different router interfaces.                      **/
	/**  2. These specifications may be overridden by the        **/
	/**     "IP Dynamic Routing Protocol", if a routing protocol **/
	/**     is specified there.                                  **/
	/**  3. Any routing protocol configured on a shutdown 		 **/
	/**     or No IP Address interface must be ignored.			 **/
	/**  4. The end nodes (client workstations and servers) do   **/
	/**     not run any dynamic rotuing protocols. However if	 **/
	/**     passive rip is enabled, assume that the routing		 **/
	/**		protocol is RIP.									 **/

	FIN (ip_interface_routing_protocols_obtain (intf_info_objid, intf_status));

	/* If this is the first time this function is being called,	*/
	/* Perform the initialization steps.						*/
	if (!initialization_complete)
		{
		/* Set the flag indicating that initialization is 		*/
		/* complete												*/
		initialization_complete = OPC_TRUE;

		/* Initialize the global variable that corresponds to a	*/
		/* a list with only one element, IpC_Rte_None			*/
		no_routing_proto_lptr = op_prg_list_create ();
		rte_proto_ptr = ip_rte_protocol_ptr_create (IpC_Rte_None);
		op_prg_list_insert (no_routing_proto_lptr, rte_proto_ptr, OPC_LISTPOS_HEAD);

		/* If the sim attribute IP Dynamic Routing Protocol is	*/
		/* set to something other than Default. Initialize the	*/
		/* sim_attr_rte_prot_lptr also.							*/
        /* Initialize the variable used to determine whether	*/
        /* which dynamic routing protocol is used.				*/
        strcpy (ip_dyn_rte_spec, "Default");
 
        /* Obtain the value of the simulation attribute "IP	*/
        /* Dynamic Routing Protocol", if specified.			*/
        if (op_ima_sim_attr_exists ("IP Dynamic Routing Protocol") == OPC_TRUE)
            {
            /* The simulation attribute has been specified a value. */
            op_ima_sim_attr_get (OPC_IMA_STRING, "IP Dynamic Routing Protocol", ip_dyn_rte_spec);
            }

        /*  Store this information as a process model state. This   */
        /*  will be used at various places in the model.            */
        if (strcmp (ip_dyn_rte_spec, "Default") != 0)
            {
			/* The routing protocol has been specified in the sim	*/
			/* attribute. Parse this string and store the values in	*/
			/* in sim_attr_rte_prot_lptr.				 			*/

			/* Create an empty list to hold the list of active		*/
			/* custom routing protocols.							*/
			op_prg_list_init (&sim_attr_custom_rte_proto_label_list);
			sim_attr_rte_prot_lptr = ip_rte_proto_string_parse (ip_dyn_rte_spec, 
				&sim_attr_custom_rte_proto_label_list);

			/* Check if the specified protocol is a custom routing	*/
			/* protocol.											*/
			if (op_prg_list_size (&sim_attr_custom_rte_proto_label_list) > 0)
				{
				/* Make sure that there is only one entry in the list*/
				if (op_prg_list_size (&sim_attr_custom_rte_proto_label_list) > 1)
					{
					op_sim_error (OPC_SIM_ERROR_WARNING,
						"More than one custom routing protocol specified in",
						"the \"IP Dynamic Routing Protocol\" simulation attribute");
					}

				/* Store a handle to the only entry in the list.	*/
				sim_attr_custom_rte_proto_label = (char*) op_prg_list_remove
					(&sim_attr_custom_rte_proto_label_list, OPC_LISTPOS_HEAD);
				}
            }

		/* The sim attribute was left as default. Initialize	*/
		/* the list to cache the routing protocol strings		*/
		/* configured on the interfaces.						*/
		rte_proto_list_cache = op_prg_list_create ();
		}

	/* If this is an endstation w/o passive rip or if the interface	*/
	/* is shutdown, assume that there are no routing protocols		*/
	if (IpC_Intf_Status_Shutdown == intf_status)
		{
		/* Return no_routing_proto_lptr.							*/
		FRET (no_routing_proto_lptr);
		}	

	/* If this is an endstation running passive RIP, set assume		*/
	/* the routing protocol specified is RIP						*/
	if (!module_data.gateway_status)
		{
		
		/* Return if the sim attribute was configured */
		if ((sim_attr_rte_prot_lptr != OPC_NIL))
			{
			FRET (sim_attr_rte_prot_lptr);
			}
		
		/* End nodes can have MANET routing protocols running. 		*/
		if (!strcmp (ad_hoc_routing_protocol_str, "DSR"))
			{
			/* DSR MANET Routing protocol has been specified on		*/
			/* this interface										*/
			strcpy (ip_dyn_rte_spec, "DSR");
			}
		else if (!strcmp (ad_hoc_routing_protocol_str, "TORA"))
			{
			/* TORA routing */
			strcpy (ip_dyn_rte_spec, "TORA");
			}
		else if (!strcmp (ad_hoc_routing_protocol_str, "AODV"))
			{
			/* AODV routing */
			strcpy (ip_dyn_rte_spec, "AODV");
			}	
		else if (!strcmp (ad_hoc_routing_protocol_str, "OLSR"))
			{
			/* OLSR routing */
			strcpy (ip_dyn_rte_spec, "OLSR");
			}	
		else if (passive_rip)
			{
			strcpy (ip_dyn_rte_spec, "RIP");
			}
		else
			{
			/* This is not a gateway node and neither MANET nor		*/
			/* passive RIP is enabled on this node. 				*/
			/* Return no_routing_proto_lptr.						*/
			FRET (no_routing_proto_lptr);
			}
		}
	else
		{
		/* Check if the address is set to NO IP Address. If so,		*/
		/* assume that the routing protocol configured is "None".	*/
		op_ima_obj_attr_get (intf_info_objid, "Address", addr_str);

		if (strcmp (addr_str, IPC_NO_IP_ADDRESS) == 0)
			{
			strcpy (ip_dyn_rte_spec, "None");
			}
		/* If the sim attribute IP Dynamic Routing Protocol has been*/
		/* set to a non-default value, return the protocol specifed	*/
		/* there.													*/
		else if (OPC_NIL != sim_attr_rte_prot_lptr)
			{
			/* Check if the specified routing protocol is a custom	*/
			/* routing protocol.									*/
			if (sim_attr_custom_rte_proto_label != OPC_NIL)
				{
				/* If this is the first interface on this node, the	*/
				/* list of custom routing protocols active on this	*/
				/* node will be empty. If this is the case, add the	*/
				/* the sim routing protocol to this list.			*/
				if (0 == op_prg_list_size (active_custom_rte_proto_label_lptr))
					{
					op_prg_list_insert (active_custom_rte_proto_label_lptr,
						sim_attr_custom_rte_proto_label, OPC_LISTPOS_TAIL);
					}
				}
			
			FRET (sim_attr_rte_prot_lptr);
			}
		else
			{
			/* Otherwise read in the routing protocol(s) specified 	*/
			/* on the interface.									*/
			op_ima_obj_attr_get (intf_info_objid, "Routing Protocol(s)", ip_dyn_rte_spec);
			
			/* If this is a loopback interface with no routing protocol, log a warning.	*/
			if ((IpC_Intf_Status_Loopback == intf_status) &&
				(!strcmp (ip_dyn_rte_spec, "None")))
				{
				ip_nl_loopback_no_rte_proto_warn ();
				}
			}

		/* If there is a corresponding row under IPv6 Parameters	*/
		/* also, append the list of IPv6 routing protocols to this	*/
		/* list.													*/
		if (OPC_OBJID_INVALID != ipv6_attrs_objid)
			{
			op_ima_obj_attr_get (ipv6_attrs_objid, "Routing Protocol(s)", ipv6_dyn_rte_spec);

			/* Unless this attribute has been set to None, append	*/
			/* this string to the list of IPv4 routing protocols.	*/
			if (strcmp (ipv6_dyn_rte_spec, "None") != 0)
				{
				/* Use a comma to separate the two strings.			*/
				strcat (ip_dyn_rte_spec, ",");
				strcat (ip_dyn_rte_spec, ipv6_dyn_rte_spec);
				}
			}
		}

	/* Look for an entry in the cache corresponding to this string	*/
	rte_cache_entry.rte_proto_str = ip_dyn_rte_spec;
	cache_entry_ptr = (IpT_Rte_Proto_List_Cache_Entry*) op_prg_list_elem_find (rte_proto_list_cache,
		ip_rte_proto_list_cache_compare, &rte_cache_entry, OPC_NIL, OPC_NIL);

	if (OPC_NIL != cache_entry_ptr)
		{
		/* We found a cached entry. Return the routing protocol list*/
		/* in the entry.											*/

		/* If there are any custom routing protocols in the list,	*/
		/* add them to the list of custom routing protocol active	*/
		/* on this node.											*/
		if (OPC_NIL != cache_entry_ptr->custom_rte_proto_label_lptr)
			{
			ip_dispatch_active_custom_routing_proto_list_populate
				(active_custom_rte_proto_label_lptr, cache_entry_ptr->custom_rte_proto_label_lptr);
			}

		FRET (cache_entry_ptr->rte_proto_lptr);
		}

	/* We don't have a cached entry. Parse the string.				*/

	/* Create an entry to be added to the cache.					*/
	cache_entry_ptr = (IpT_Rte_Proto_List_Cache_Entry*) op_prg_mem_alloc
						(sizeof (IpT_Rte_Proto_List_Cache_Entry));
	cache_entry_ptr->rte_proto_str = prg_string_copy (ip_dyn_rte_spec);

	/* Create an empty list to hold any custom routing protocols	*/
	/* that might be enabled on this interface.						*/
	cache_entry_ptr->custom_rte_proto_label_lptr = op_prg_list_create ();
	cache_entry_ptr->rte_proto_lptr = ip_rte_proto_string_parse (ip_dyn_rte_spec,
		cache_entry_ptr->custom_rte_proto_label_lptr);

	/* If there were no custom routing protocols, free the memory	*/
	/* allocated to the list that we created.						*/
	if (op_prg_list_size (cache_entry_ptr->custom_rte_proto_label_lptr) == 0)
		{
		op_prg_mem_free (cache_entry_ptr->custom_rte_proto_label_lptr);
		cache_entry_ptr->custom_rte_proto_label_lptr = OPC_NIL;
		}
	else
		{
		/* There is at least one custom routing protocol enabled on	*/
		/* this interface. Update the list of custom routing		*/
		/* protocols enabled on the node.							*/
		ip_dispatch_active_custom_routing_proto_list_populate
			(active_custom_rte_proto_label_lptr, cache_entry_ptr->custom_rte_proto_label_lptr);
		}

	/* Add the new entry to the cache.								*/
	op_prg_list_insert (rte_proto_list_cache, cache_entry_ptr, OPC_LISTPOS_TAIL);

	/* Return the list of routing protocols.						*/
	FRET (cache_entry_ptr->rte_proto_lptr);
	}

static void
ip_dispatch_active_custom_routing_proto_list_populate (List* node_active_custom_rte_proto_label_lptr,
	List* intf_active_custom_rte_proto_label_lptr)
	{
	int					i, num_intf_protos;
	char*				ith_intf_proto;

	/** Add the list of custom routing protcols enabled on an		**/
	/** interface to the list of custom routing protcools enabled	**/
	/** on the entire node. Make sure we do not create duplicate	**/
	/** entries.													**/

	FIN (ip_dispatch_active_custom_routing_proto_list_populate (<args>));

	/* Loop through each entry in the list of custom routing		*/
	/* protocols of each interface.									*/
	num_intf_protos = op_prg_list_size (intf_active_custom_rte_proto_label_lptr);

	for (i = 0; i < num_intf_protos; i++)
		{
		/* Get the ith entry.										*/
		ith_intf_proto = (char*) op_prg_list_access (intf_active_custom_rte_proto_label_lptr, i);

		/* Add it to the node list if it is not already present.	*/
		if (op_prg_list_elem_find (node_active_custom_rte_proto_label_lptr, 
			oms_string_compare_proc, ith_intf_proto, OPC_NIL, OPC_NIL) == OPC_NIL)
			{
			/* Insert the label in the list.									*/
			op_prg_list_insert (node_active_custom_rte_proto_label_lptr, 
				ith_intf_proto, OPC_LISTPOS_TAIL);
			}
		}

	FOUT;
	}

static int
ip_rte_proto_list_cache_compare (const void* cache_entry1, const void* cache_entry2)
	{
	/** Function used to compare two entries in the route		**/
	/** protocol list cache. 									**/

	FIN (ip_rte_proto_list_cache_compare (cache_entry1, cache_entry2));

	/* To compare two cache entries just compare the strings.	*/
	FRET (strcmp (((const IpT_Rte_Proto_List_Cache_Entry*) cache_entry1)->rte_proto_str,
				  ((const IpT_Rte_Proto_List_Cache_Entry*) cache_entry2)->rte_proto_str));
	}
		
static List*
ip_rte_proto_string_parse (char* routing_proto_str, List* active_custom_rte_proto_label_lptr)
	{
	List*				routing_protocol_lptr;
	int					num_rte_protocols;
	char				msg_string [256];
	int					ith_protocol;
	char*				ith_protocol_name;
	int					routing_protocol;
	List*				rte_protocol_str_lptr;
	char*				custom_rte_protocol_label_ptr;
	int*				routing_protocol_ptr;

	/** Parse the specified string and create a list of routing		**/
	/** protocols.													**/

	FIN (ip_rte_proto_string_parse (routing_proto_str, active_custom_rte_proto_label_lptr));

	/* Create (List *) that will be returned from this function */
	routing_protocol_lptr = op_prg_list_create ();
	
	/* Since there could be more than on routing protocol specified	*/
	/* for a particular interface, parse this specification.		*/ 
	rte_protocol_str_lptr = op_prg_str_decomp (routing_proto_str, ",");
	num_rte_protocols  = op_prg_list_size (rte_protocol_str_lptr);
	
	/* Print debugging information	*/
	if (op_prg_odb_ltrace_active ("ip_interfaces") == OPC_TRUE)
		{
		sprintf (msg_string, "The routing protocols configured on this interface are = %s", routing_proto_str);
		op_prg_odb_print_minor (msg_string, OPC_NIL);
		}

	/* Loop through the specified dynamic routing protocols.	*/
	for (ith_protocol = 0; ith_protocol < num_rte_protocols; ith_protocol++)
		{
		/* Determine the i_th specification.	*/
		ith_protocol_name = (char *) op_prg_list_access (rte_protocol_str_lptr, ith_protocol);
		
		/* Assign the protocol id based on its value.				*/
		if (strcmp (ith_protocol_name, "RIP") == 0)
			{
			/* RIP protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Rip;
			}
		else if (strcmp (ith_protocol_name, "IGRP") == 0)
			{
			/* IGRP protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Igrp;
			}
		else if (strcmp (ith_protocol_name, "EIGRP") == 0)
			{
			/* EIGRP protocol has been specified to be used on this  */
			/* interface.                         */
			routing_protocol = IpC_Rte_Eigrp;
			}
		else if (strcmp (ith_protocol_name, "OSPF") == 0)
			{
			/* OSPF protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Ospf;
			}
		else if (strcmp (ith_protocol_name, "IS-IS") == 0)
			{
			/* IS-IS protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Isis;
			}
		else if (strcmp (ith_protocol_name, "BGP") == 0)
			{
			/* IS-IS protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Bgp;
			}
		else if (strcmp (ith_protocol_name, "OLSR") == 0)
			{
			/* OLSR Routing protocol has been specified on			*/
			/* this interface										*/
			routing_protocol = IpC_Rte_Olsr;
			}
		else if (strcmp (ith_protocol_name, "DSR") == 0)
			{
			/* DSR MANET Routing protocol has been specified on		*/
			/* this interface										*/
			routing_protocol = IpC_Rte_Dsr;
			}
		else if (strcmp (ith_protocol_name, "TORA") == 0)
			{
			/* TORA MANET Routing protocol has been specified on	*/
			/* this interface										*/
			routing_protocol = IpC_Rte_Tora;
			}
		else if (strcmp (ith_protocol_name, "AODV") == 0)
			{
			/* AODV MANET Routing protocol has been specified on	*/
			/* this interface										*/
			routing_protocol = IpC_Rte_Aodv;
			}
		else if (strcmp (ith_protocol_name, "RIPng") == 0)
			{
			/* BGP protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Ripng;
			}
		else if (strcmp (ith_protocol_name, "OSPFv3") == 0)
			{
			/* OSPFv3 protocol has been specified to be used on this	*/
			/* interface.											*/
			routing_protocol = IpC_Rte_Ospf;
			}
		else if (strcmp (ith_protocol_name, "None") == 0)
			{
			/* No dynamic protocol has been specified to be used	*/
			/* on this interface.									*/
			routing_protocol = IpC_Rte_None;
			}
		else 
			{
			/* Custom routing protocol has been specified to be 	*/
			/* used on this interface. Obtain protocol id for this	*/
			/* protocol label.										*/
			routing_protocol = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (
				ip_cmn_rte_table_custom_rte_protocol_id_get (ith_protocol_name));
			
			/* If this custom protocol has not been added to the	*/
			/* list of custom routing protocols, already do it now.	*/
			if (op_prg_list_elem_find (active_custom_rte_proto_label_lptr, 
				oms_string_compare_proc, ith_protocol_name, OPC_NIL, OPC_NIL) == OPC_NIL)
				{
				/* Allocate memory.										*/
				custom_rte_protocol_label_ptr = prg_string_copy (ith_protocol_name);			
				
				/* Insert the label in the list.									*/
				op_prg_list_insert (active_custom_rte_proto_label_lptr, 
					custom_rte_protocol_label_ptr, OPC_LISTPOS_TAIL);
				}
			}
		
		/* Insert this supporting routing protocol in this interface's	*/
		/* supported protocols list.									*/
		routing_protocol_ptr = ip_rte_protocol_ptr_create (routing_protocol);
		op_prg_list_insert (routing_protocol_lptr, routing_protocol_ptr, OPC_LISTPOS_TAIL);
		}
	
	/* Free up the temporarily created lists.	*/
	op_prg_list_free (rte_protocol_str_lptr);
	op_prg_mem_free (rte_protocol_str_lptr);

	/* Return the list of routing protocols							*/
	FRET (routing_protocol_lptr);
	}

static int*
ip_rte_protocol_ptr_create (int rte_protocol_id)
	{
	int*		rte_protocol_id_ptr;
	
	/** Creates a pointer to an integer to store routing protocols.	*/
	FIN (ip_rte_protocol_ptr_create (rte_protocol_id));
	
	rte_protocol_id_ptr  = (int *) op_prg_mem_alloc (sizeof (int));
	*rte_protocol_id_ptr = rte_protocol_id;
	
	FRET (rte_protocol_id_ptr);
	}

/**** IGMP-related function declarations *****/

static void
ip_rte_igmp_host_create_init (void)
	{
	/** Creates and initializes an IGMP Host process for this IP	**/
	/** process. A shared memory is installed for communication		**/
	/** between the IP process and the created IGMP	Host process	**/
	FIN (ip_rte_igmp_host_init (void));

	/* Create an IGMP Host process and install a parent-to-child memory */
	igmp_host_process_handle = op_pro_create ("ip_igmp_host", &module_data.ip_ptc_mem);

	/* Invoke the IGMP Host process to allow it	*/
	/* to initialize itself						*/
	op_pro_invoke (igmp_host_process_handle, OPC_NIL);

	FOUT;
	}

static void
ip_rte_igmp_rte_intf_create_init (double mcast_start_time)
	{
	IpT_Igmp_Rte_Arg_Memory		igmp_rte_arg_mem;
	int 						i, num_ip_intfs;
	IpT_Interface_Info*			intf_info_ptr;

	/** Creates and initializes an IGMP Router Interface process for each	**/
	/** IP interface, which is enabled for multicasting. Stores the process	**/
	/** handle for the created process in IpT_Interface_Info object of the	**/
	/** interface. A shared memory is installed for communication between	**/
	/** IP and the created IGMP Router Interface process					**/
	FIN (ip_rte_igmp_rte_intf_create_init (mcast_start_time));

	/* Determine the number of IP interfaces for this node	*/
	num_ip_intfs = ip_rte_num_interfaces_get (&module_data);

	/** Create and initialize an IGMP Router Interface process for each	**/
	/**	IP interface of this node, which is enabled for multicasting	**/
	for (i=0; i<num_ip_intfs; i++)
		{
		/* Get the ith IpT_Interface_Info object from the list	*/
		intf_info_ptr = ip_rte_intf_tbl_access (&module_data, i);
		
		/* Create an IGMP Router Interface process for this interface, only if multicast is enabled */
		if (ip_rte_intf_igmp_enabled (intf_info_ptr))
			{
			/* Create an IGMP Router Interface process	*/
			intf_info_ptr->igmp_rte_iface_ph = op_pro_create ("ip_igmp_rte_intf", &module_data.ip_ptc_mem);

			/** Invoke the IGMP Router Interface process with argument memory, so that	**/
			/** it can initialize itself. The argument memory contains the interface	**/
			/** number, interface IP address and the process handle of PIM-SM process	**/
	
			/* Set the field of this argument memory */
			igmp_rte_arg_mem.interface_number 	= i;
			igmp_rte_arg_mem.ip_address 		= ip_address_copy (intf_info_ptr->addr_range_ptr->address);
			igmp_rte_arg_mem.intf_name			= intf_info_ptr->full_name; 
			igmp_rte_arg_mem.pim_sm_ph 			= pim_sm_process_handle;
			igmp_rte_arg_mem.mcast_start_time	= mcast_start_time;

			/* Invoke the IGMP Router Interface process to allow it to initialize itself */
			op_pro_invoke (intf_info_ptr->igmp_rte_iface_ph, &igmp_rte_arg_mem);
			}
		}
	
	FOUT;
	}


static void
ip_rte_pim_sm_create_init (double start_time)
	{
	/** Creates and initializes a PIM-SM process for this IP	**/
	/** process. A shared memory is installed for communication	**/
	/** between the IP process and the created PIM-SM process	**/
	FIN (ip_rte_pim_sm_create_init (void));

	/* Create a PIM-SM process and install a parent-to-child memory */
	pim_sm_process_handle = op_pro_create ("ip_pim_sm", &module_data.ip_ptc_mem);

	/* Invoke the PIM-SM process to allow it to initialize itself	*/
	op_pro_invoke (pim_sm_process_handle, &start_time);

	FOUT;
	}

static void
ip_rte_custom_mrp_create_init (void)
	{
	/** Creates and initializes the ip_custom_mrp process	**/
	/** for this IP	process. A shared memory is installed	**/
	/** for communication between the IP process and the	**/
	/** created ip_custom_mrp process.						**/
	FIN (ip_rte_custom_mrp_create_init (void));

	/* Create the ip_custom_mrp process and install a	*/
	/* parent-to-child memory.							*/
	custom_mrp_process_handle = op_pro_create ("ip_custom_mrp", &module_data.ip_ptc_mem);

	/* Invoke the ip_custom_mrp process to allow it to	*/
	/* initialize itself.								*/
	op_pro_invoke (custom_mrp_process_handle, OPC_NIL);

	FOUT;
	}


static void
ip_rte_default_mcast_addr_register (void)
	{
	int						i;
	int						num_ip_intfs;
	IpT_Interface_Info*		intf_info_ptr;
	IpT_Address				all_node_mcast_addr;
	IpT_Address				all_rte_mcast_addr;
	IpT_Address				all_pim_rte_mcast_addr;

	/** Registers the default multicast addresses, 224.0.0.1, 224.0.0.2	**/
	/** and 224.0.0.13 for each IP interface, which is enabled for		**/
	/** multicast. 224.0.0.2 and 224.0.0.13 are registered only for		**/
	/** multicast routers												**/
	FIN (ip_rte_default_mcast_address_register (void));

	/* Create an ip address from the dotted decimal notation	*/
	all_node_mcast_addr = ip_address_create (IPC_ALL_SYSTEMS_MULTICAST_ADDR);
	all_rte_mcast_addr = ip_address_create (IPC_ALL_ROUTERS_MULTICAST_ADDR);
	all_pim_rte_mcast_addr = ip_address_create (IPC_ALL_PIM_ROUTERS_MULTICAST_ADDR);

	/* Determine the size of the interface table	*/
	num_ip_intfs = ip_rte_num_interfaces_get (&module_data);

	/* Traverse through the list and register the default	*/
	/* multicast addresses for each IP interface which is	*/
	/* enabled for multicast								*/
	for (i=0; i<num_ip_intfs; i++)
		{
		/* Access ith element from the list	*/
		intf_info_ptr = ip_rte_intf_tbl_access (&module_data, i);

		/* Check if this interface is enabled for multicast	*/
		if (ip_rte_intf_igmp_enabled (intf_info_ptr) == OPC_TRUE)
			{
			/* This interface is enabled for multicast.	*/
			/* Register the default addresses			*/
			Ip_Address_Multicast_Register (all_node_mcast_addr, i, IP_MCAST_NO_PORT, module_data.node_id);

			/* If this node is a multicast router, register the	*/
			/* all routers and PIM router addresses too			*/
			if (ip_node_is_mcast_router (&module_data))
				{
				Ip_Address_Multicast_Register (all_rte_mcast_addr, i, IP_MCAST_NO_PORT, module_data.node_id);
				Ip_Address_Multicast_Register (all_pim_rte_mcast_addr, i, IP_MCAST_NO_PORT, module_data.node_id);
				}
			}
		}

	/* Destroy the ip addresses */
	ip_address_destroy (all_node_mcast_addr);
	ip_address_destroy (all_rte_mcast_addr);
	ip_address_destroy (all_pim_rte_mcast_addr);

	/* If IPv6 is active on this node, register all the pre-defined		*/
	/* multicast addresses.												*/
	if (ip_rte_node_ipv6_active (&module_data))
		{
		/* All nodes (Node Local) multicast address.					*/
		Inet_Address_Multicast_Register (IPv6C_ALL_NODES_NL_MCAST_ADDR, IP_MCAST_ALL_INTFS,
			IP_MCAST_NO_PORT, &module_data);

		/* All nodes (Link Local) multicast address.					*/
		Inet_Address_Multicast_Register (IPv6C_ALL_NODES_LL_MCAST_ADDR, IP_MCAST_ALL_INTFS,
			IP_MCAST_NO_PORT, &module_data);

		/* For gateway nodes, also register the All router addresses	*/
		if (ip_rte_node_is_gateway (&module_data))
			{
			/* All Routers (Node Local) multicast address.				*/
			Inet_Address_Multicast_Register (IPv6C_ALL_RTRS_NL_MCAST_ADDR, IP_MCAST_ALL_INTFS,
				IP_MCAST_NO_PORT, &module_data);

			/* All Routers (Link Local) multicast address.				*/
			Inet_Address_Multicast_Register (IPv6C_ALL_RTRS_LL_MCAST_ADDR, IP_MCAST_ALL_INTFS,
				IP_MCAST_NO_PORT, &module_data);

			/* All Routers (Site Local) multicast address.				*/
			Inet_Address_Multicast_Register (IPv6C_ALL_RTRS_SL_MCAST_ADDR, IP_MCAST_ALL_INTFS,
				IP_MCAST_NO_PORT, &module_data);
			}
		}

	FOUT;
	}

static void
ip_dispatch_default_networks_parse (void)
	{
	Objid			default_ntwk_cattr_objid;
	Objid			ith_default_ntwk_objid;
	int				i, num_default_ntwks;
	char			default_ntwk_str [IPC_MAX_STR_SIZE];
	InetT_Address	default_network;

	/** Parse the information specified under the Default	**/
	/** Networks attribute 									**/

	FIN (ip_dispatch_default_networks_parse (void));

	/* Get the objid of the Default Networks compound		*/
	/* attribute.											*/
	op_ima_obj_attr_get (module_data.ip_parameters_objid, "Default Network(s)",
		&default_ntwk_cattr_objid);

	/* Find out the number of default networks.				*/
	num_default_ntwks = op_topo_child_count (default_ntwk_cattr_objid, OPC_OBJTYPE_GENERIC);

	/* Handle each default route.							*/
	for (i = 0; i < num_default_ntwks; i++)
		{
		/* Get the objid of the ith row.					*/
		ith_default_ntwk_objid = op_topo_child (default_ntwk_cattr_objid, OPC_OBJTYPE_GENERIC, i);

		/* Read the network address specified.				*/
		op_ima_obj_attr_get (ith_default_ntwk_objid, "Network Address", default_ntwk_str);

		/* Convert the string into an address.				*/
		default_network = inet_address_create (default_ntwk_str, InetC_Addr_Family_v4);
		
		/* Skip invalid addresses. Need log message.		*/
		if (! inet_address_valid (default_network))
			{
			continue;
			}

		/* Add this default network to the route table.		*/
		ip_cmn_rte_default_network_add (module_data.ip_route_table, default_network);
		}

	FOUT;
	}

static void
ip_dispatch_default_gateway_configured_check (void)
	{
	char	default_gtwy_str[IPC_MAX_STR_SIZE];

	/** We no longer support the Default Gateway attribute.	**/
	/** If it is set to any value other than the default	**/
	/** value, write a log message warning the user that it	**/
	/** will be ignored.									**/

	FIN (ip_dispatch_default_gateway_configured_check (void));

	/* Read in the value of the attribute.					*/
	op_ima_obj_attr_get (module_data.ip_parameters_objid, "Default Gateway", default_gtwy_str);

	if (0 != strcmp (default_gtwy_str, "Unassigned"))
		{
		ipnl_default_gtwy_configuration_ignored_log_write ();
		}

	FOUT;
	}


static void
ip_rte_car_information_print ()
    {
    double      		    current_time; 
	int						number_of_iface, iface_index, cos;
	char					str1 [256], str2 [256], str3 [256], str4 [256], str5 [256], str6 [256];
	IpT_Interface_Info*		interface_info_ptr;
	OmsT_Qm_Car_Information * car_info_ptr;
	IpT_Rte_Iface_QoS_Data  * iface_qos_data_ptr;

    /** This functions prints the CAR parameters when using ODB. **/
    FIN (ip_rte_car_information_print ())
 
    /* Get the current time.    */
    current_time = op_sim_time (); 

	/* Get the number of connected interfaces in the IP module.	*/     
	number_of_iface = ip_rte_num_interfaces_get (&module_data);

	/* Loop through all the interfaces in this IP module and print	*/
	/* CAR information for each of them.							*/
	/* Note that the loopback interface doesn't have any CAR		*/
	/* information, so it will be skipped in the loop. 				*/	
	for (iface_index = 0; iface_index < number_of_iface ; iface_index++)
		{ 
		/* Get interface information.	*/
		interface_info_ptr = ip_rte_intf_tbl_access (&module_data, iface_index);

		/* Skip loopback interfaces.								*/
		if (ip_rte_intf_is_loopback (interface_info_ptr))
			{
			continue;
			}

		/* Get the qos interface data. */
		iface_qos_data_ptr = module_data.interface_qos_data_pptr [iface_index];
		
		/* Loop through the class of service for one interface and	*/
		/* print in ODB the Incoming CAR parameters for each COS.	*/
	    for (cos = 0; cos < iface_qos_data_ptr->car_incoming_profile_ptr->number_of_cos; cos++)
			{
			/* Cache the Incoming CAR info_ptr. */
			car_info_ptr = iface_qos_data_ptr->car_incoming_info_ptr;
			
    		sprintf (str1, "CAR information on incoming interface: %s COS: %d\n", ip_rte_intf_name_get (interface_info_ptr), cos); 
    		sprintf (str2, "Bucket size: %f\n", car_info_ptr [cos].bucket_size);
    		sprintf (str3, "Actual debt: %f\n", car_info_ptr [cos].actual_debt);
			sprintf (str4, "Compounded debt: %f\n", car_info_ptr [cos].compounded_debt);
    		sprintf (str5, "Last update time: %f\n", car_info_ptr [cos].last_update_time);
			sprintf (str6, "Current time: %f\n\n", current_time);
			op_prg_odb_print_major (str1, str2, str3, str4, str5, str6, OPC_NIL);
    		}
		
		/* Loop through the class of service for one interface and	*/
		/* print in ODB the Outgoing CAR parameters for each COS.	*/
	    for (cos = 0; cos < iface_qos_data_ptr->car_outgoing_profile_ptr->number_of_cos; cos++)
			{
			/* Cache the Outgoing CAR info_ptr. */
			car_info_ptr = iface_qos_data_ptr->car_outgoing_info_ptr;
			
    		sprintf (str1, "CAR information on outgoing interface: %s COS: %d\n", ip_rte_intf_name_get (interface_info_ptr), cos);
    		sprintf (str2, "Bucket size: %f\n", car_info_ptr [cos].bucket_size);
    		sprintf (str3, "Actual debt: %f\n", car_info_ptr [cos].actual_debt);
			sprintf (str4, "Compounded debt: %f\n", car_info_ptr [cos].compounded_debt);
    		sprintf (str5, "Last update time: %f\n", car_info_ptr [cos].last_update_time);
			sprintf (str6, "Current time: %f\n\n", current_time);
			op_prg_odb_print_major (str1, str2, str3, str4, str5, str6, OPC_NIL);
    		}
    	}
    FOUT;
    }


static Prohandle
ip_rtab_phandle_from_intf_get (RsvpT_TC_Ici_Struct *	ici_data_struct_ptr)
	{
	IpT_Interface_Info *	iface_elem_ptr;

	/** Based on the interface index, get process handle of a child process.	**/
	FIN (ip_rtab_phandle_from_intf_ge (ici_data_struct_ptr));

	/* Get the interface information.	*/
	iface_elem_ptr = ip_rte_intf_tbl_access (&module_data, ici_data_struct_ptr->intf_index);

	/* Return process handle.	*/
	FRET (iface_elem_ptr->output_iface_prohandle);
	}

static void
ip_rte_rsvp_init_notify (void)
	{
	Objid				rsvp_module_id;
	List*				proc_rec_handle_list_ptr;
	OmsT_Pr_Handle		process_record_handle;
	int 				record_handle_list_size;

	/** This function is called after IP interface table is built and 	**/
	/** RSVP is supported at at least one interface.					**/
	/** RSVP module object id is found from the database and a remote	**/
	/** interrupt is sent to RSVP local process.						**/
	FIN (ip_rte_rsvp_init_notify ());

	/** 1. Find the object ID of the RSVP local process.	**/

	/* Create a temporary list to store discovered processe information.	*/
	proc_rec_handle_list_ptr =  op_prg_list_create ();

	/* Obtain the process record handle of the IP process residing in the local node.	*/
	oms_pr_process_discover (OPC_OBJID_INVALID, proc_rec_handle_list_ptr, 
		"node objid", 		OMSC_PR_OBJID, 		module_data.node_id, 
		"protocol", 		OMSC_PR_STRING, 	"rsvp",
		OPC_NIL);

	/* An error should be created if there are more than one ip process in the local node	*/
	record_handle_list_size = op_prg_list_size (proc_rec_handle_list_ptr);

	if (record_handle_list_size > 1)
		{
		op_sim_end ("Error: Several RSVP processes found in the local node", "", "", "");
		}
	else if (record_handle_list_size == 1)
		{
		process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_rec_handle_list_ptr, OPC_LISTPOS_HEAD);

		/* Obtain a reference to the IpT_Cmn_Rte_Table object   		*/
		/* for this node. This object is created and registered by IP.	*/
		oms_pr_attr_get (process_record_handle, "module id", 		  OMSC_PR_OBJID,  &rsvp_module_id);

		/** 2. Send a remote interrupt to RSVP.					**/
		op_intrpt_schedule_remote (op_sim_time (), 0, rsvp_module_id);
		}
	else
		{
         /** There is no RSVP module.	**/

		/* Set RSVP status to FALSE.	*/
		module_data.rsvp_status = OPC_FALSE;
		}

	/* Deallocate no longer needed process registry information.	*/
	if (record_handle_list_size > 0)
		{
		op_prg_list_remove (proc_rec_handle_list_ptr, OPC_LISTPOS_HEAD);
		}
	/* Free the list.	*/
	op_prg_mem_free (proc_rec_handle_list_ptr); 

	FOUT;
	}

static void
ip_rte_datagram_higher_layer_forward (Packet *frag_pk_ptr)
	{
	Packet *						ip_pkptr	= OPC_NIL;
	char							str0 [512];
	char							dest_addr_str [INETC_ADDR_STR_LEN];
	Ici *							intf_ici_ptr;
	IpT_Dgram_Fields*				pkt_fields_ptr;
	IpT_Rte_Ind_Ici_Fields*			intf_ici_fdstruct_ptr=OPC_NIL;
	Boolean							ip_mcast_data_pkt_on_rte = OPC_FALSE;
	ManetT_Info             		manet_info;
	

	
	/** Forward a datagram to the higher layer. Note that IP also	**/
	/** has four child processes -- oms_basetraf_src for background	**/
	/** traffic, ip_icmp for ICMP messages, ip_igmp_rte_intf or		**/
	/** ip_igmp_host for IGMP messages and ip_pim_sm for PIM and IP	**/
	/** multicast messages. Conceptually, these processes are at a	**/
	/** higher layer than IP (as they supply datagrams to IP to		**/
	/** route across the network.) Thus, this function also checks	**/
	/** packets destined for these processes.						**/
	FIN (ip_rte_datagram_higher_layer_forward (frag_pk_ptr));

	/** First Check if this is a multicast router and the			**/
	/** packet is a multicast data packet.							**/
	/** Note: On a multicast router, since PIM-SM child process 	**/
	/** acts as a forwarding agent for IP multicast data packets	**/
	/** these packets shouldn't be reassembled before sending		**/
	/** to PIM-SM child process. IP multicast data packets are 		**/
	/** those whose dest_addr is a multicast address and which		**/
	/** needs to be forwarded by this multicast router. If this	 	**/
	/** router hasn't joined the multicast group to which the		**/
	/** packets are sent, then this router forwards the packets.	**/

	/*  Obtain a handle on the information carried in the "fields" 	*/
	/* data structure in the incoming IP datagram.					*/
	ip_dispatch_incoming_packet_info_get (frag_pk_ptr, &pkt_fields_ptr,
					&intf_ici_ptr, &intf_ici_fdstruct_ptr, &ip_pkptr,
					&ip_mcast_data_pkt_on_rte);
	
	/* Update the number of hops statistics */
	if (!(ip_packet_protocol_is_tunnel ((IpT_Protocol_Type) pkt_fields_ptr->protocol)))
		{
		/* Do not perform Number of Hops stats update for tunneled packets */
		ip_dispatch_number_of_hops_update (pkt_fields_ptr);
		}
	
	/* Call the fragment reassembly procedure to determine if    */
	/* a complete packet has arrived.  Note that the packet      */
	/* will be destroyed in this procedure call unless it is     */
	/* itself the complete datagram (i.e., it isn't a fragment). */
	/* If this node is a multicast router and the packet is a 	 */
	/* multicast data packet, send the packet to the PIM-SM		 */
	/* process without reassembling.							 */
	if ((ip_mcast_data_pkt_on_rte == OPC_TRUE) || 
		((ip_pkptr = ip_frag_sup_insert (dgram_list_ptr, frag_pk_ptr)) != OPC_NIL))
		{
		/* In debug mode, issue a  trace statement. */
		if (op_prg_odb_ltrace_active ("ip_frag"))
			{
			inet_address_print (dest_addr_str, intf_ici_fdstruct_ptr->dest_addr);
			sprintf (str0, "Complete Datagram Received at (%s)", dest_addr_str);
			op_prg_odb_print_major (str0, OPC_NIL);
			}

		/*  Obtain a handle on the information carried in the "fields" 	*/
		/* data structure in the incoming IP datagram.					*/
		op_pk_nfd_access (ip_pkptr, "fields", &pkt_fields_ptr);

		/* Set the destination address before sending the packet. */
		/* Only set the destination address if the field is not set. */
		if (! inet_address_valid (pkt_fields_ptr->dest_addr))
			{
			pkt_fields_ptr->dest_addr = inet_address_copy (intf_ici_fdstruct_ptr->dest_addr);
			}

		/* Check the 'interface received' ICI.  If the ICI isn't set in the packet,  */
		/* set it with IP default address (0.0.0.0) as the interface received. This	 */
		/* corresponds to the situation where the higher layer sends a packet to     */
		/* itself (except in the case of broadcast).                                 */
		if ((intf_ici_ptr = op_pk_ici_get (ip_pkptr)) == OPC_NIL)
			{
			intf_ici_ptr = op_ici_create ("ip_rte_ind_v4");
			intf_ici_fdstruct_ptr = ip_rte_ind_ici_fdstruct_create ();
			
			/* Set the interface_received and minor port recieved to	*/
			/* to their default values.									*/
			intf_ici_fdstruct_ptr->interface_received = inet_address_copy (InetI_Default_v4_Addr);
			intf_ici_fdstruct_ptr->minor_port_received = IPC_MINOR_PORT_DEFAULT;
			
			/* Set the rte_info_fields of the ICI.						*/
			op_ici_attr_set (intf_ici_ptr, "rte_info_fields", intf_ici_fdstruct_ptr);

			/* Attach the interface information with the packet.			*/
			op_pk_ici_set (ip_pkptr, intf_ici_ptr);
			}
		
		/* Always refresh the rte_info_fields from the returned packet's	*/
		/* ICI, in case the original ICI is destroyed during the reassembly	*/
		/* of IP fragments.													*/
		op_ici_attr_get (intf_ici_ptr, "rte_info_fields", &intf_ici_fdstruct_ptr);

		/* Mobile IPv6 processing. The following processing just applies 	*/
		/* for IPv6 packets, also multicast and local link addresses are 	*/
		/* not currently supported by MIPv6. 								*/
		if (ip_rte_node_is_mipv6_enabled (&module_data) && (inet_address_family_get(&(pkt_fields_ptr->dest_addr)) == InetC_Addr_Family_v6) &&
			(!inet_address_is_multicast (pkt_fields_ptr->dest_addr))  &&
			(!inet_rte_ipv6_addr_is_link_local (pkt_fields_ptr->dest_addr)))
			{
			/* Check for tunnels set by Mobile IPv6 protocol.				*/	
			if (pkt_fields_ptr->protocol == IpC_Protocol_IPv6)
				{
				/* Process IPv6 packets encapsulated by Mobile Ipv6.		*/
				if (!mipv6_tunnel_end_point_pkt_process (&module_data, &ip_pkptr, &intf_ici_fdstruct_ptr)) 
					{
					/* Destroy the associated interface ici which we 		*/
					/* obtained above. 										*/
					ip_rte_intf_ici_destroy (intf_ici_ptr);
					
					FOUT;
					}
				}
			
			/* Check for IPv6 extension headers carried by the packet.		*/
			if (ipv6_extension_header_exists(pkt_fields_ptr))
				{
				/* Process the IPv6 extension headers.						*/
				if (ipv6_extension_header_process (&module_data, &ip_pkptr, &pkt_fields_ptr, &intf_ici_fdstruct_ptr, OPC_FALSE) == OPC_FALSE)
					{
					/* Destroy the associated interface ici which we 		*/
					/* obtained above. 										*/
					ip_rte_intf_ici_destroy (intf_ici_ptr);
					
					/* If the IPv6 datagram was destroyed during when 		*/
					/* processing the extension headers, then do not 		*/
					/* proceed.												*/
					FOUT;
					}
				}
			}
		
		if (ip_mobile_ip_is_enabled (&module_data))
			{
			/* See if this is a Mobile IP tunneled packet going to the FA process. */
			if (mip_sup_tunneled_pkt_check (&module_data, ip_pkptr, intf_ici_fdstruct_ptr)
					== OPC_COMPCODE_SUCCESS)		
				{
				FOUT;
				}
			}
		
		/* Check if this packet is destined for ICMP process within this	*/
		/* node. Note that ICMP packets are handled by a child process of	*/
		/* this process -- ip_icmp. If it is for the ICMP process, invoke	*/
		/* the ICMP child process and pass the packet to it.				*/

		if (ip_proto_is_icmp_v4_or_v6 (pkt_fields_ptr->protocol))
			{
			/* Call the function that would forward the packet based on the	*/
			/* ICMP packet type.											*/
			ip_dispatch_icmp_pk_higher_layer_forward (ip_pkptr, pkt_fields_ptr, intf_ici_fdstruct_ptr);
			}
		else if ((pkt_fields_ptr->protocol == IpC_Protocol_Dsr) ||
			(pkt_fields_ptr->protocol == IpC_Protocol_Tora))
			{
			/* Set the ICI back in the packet before sending to DSR/TORA	*/
			op_ici_attr_set (intf_ici_ptr, "rte_info_fields", intf_ici_fdstruct_ptr);
			op_pk_ici_set (ip_pkptr, intf_ici_ptr);
			
			/* Send the packet to the DSR/TORA child process	*/
			op_pro_invoke (module_data.manet_info_ptr->mgr_prohandle, ip_pkptr);
			}
		else if (pkt_fields_ptr->protocol == IpC_Protocol_Aodv) 
			{
			/* Set the ICI back in the packet before sending to DSR/TORA	*/
			op_ici_attr_set (intf_ici_ptr, "rte_info_fields", intf_ici_fdstruct_ptr);
			op_pk_ici_set (ip_pkptr, intf_ici_ptr);
			
			/* AODV can be invoked while either sending packet 	*/
			/* or refreshing routes. Fill out ManetT_Info 		*/
			/* structure to inform the cause of invocation.		*/
			manet_info.code = MANETC_PACKET_ARRIVAL;
            manet_info.manet_info_type_ptr = (void *) ip_pkptr;

			/* Send the packet to the AODV child process	*/
            op_pro_invoke (module_data.manet_info_ptr->mgr_prohandle, &manet_info);
			}
		else if ((pkt_fields_ptr->protocol == IpC_Protocol_Igmp) &&
				(mcast_rte_protocol == IpC_Rte_Pim_Sm))
			{			
			/** An IGMP message has been received. Invoke the corresponding	**/
			/** IGMP child process to process this message					**/
			ip_dispatch_igmp_child_invoke (ip_pkptr, intf_ici_fdstruct_ptr);

			/* Destroy the associated interface ici which we obtained above. */
			ip_rte_intf_ici_destroy (intf_ici_ptr);
			}
		else if ((pkt_fields_ptr->protocol == IpC_Protocol_Pim) || 
				 (ip_node_is_mcast_router (&module_data) && 
				  (inet_address_is_multicast (pkt_fields_ptr->dest_addr) == OPC_TRUE)))
			{
			/** A PIM-SM control packet or multicast data packet has been	**/
			/** received. Invoke the PIM-SM child process or the custom_mrp	**/
			/** child process to process this message.						**/

			/** Note: The limitation of IP Multicast model is that any 		**/
			/** layer above IP can't join an IP multicast group in a		**/
			/** Multicast router node . But, OSPF model joins certain		**/
			/** multicast groups. The following if statement handles this	**/
			if (pkt_fields_ptr->protocol == IpC_Protocol_Rsvp)
				{
				ip_dispatch_higher_layer_rsvp_forward (ip_pkptr, intf_ici_ptr);
				}
			else if ((pkt_fields_ptr->protocol == IpC_Protocol_Ospf) || (pkt_fields_ptr->protocol == IpC_Protocol_Eigrp))
				{
				if ((inet_address_multicast_accept (&module_data, pkt_fields_ptr->dest_addr, 
					intf_ici_fdstruct_ptr->intf_recvd_index, IP_MCAST_NO_PORT) == OPC_TRUE))
					{
					/** The multicast packet is for OSPF model	**/

					/* Forward it to higher layer	*/
					op_pk_send (ip_pkptr, module_data.outstrm_to_ip_encap);
					}
				else
					{
					/* Silently drop the packet.	*/
					op_pk_destroy (ip_pkptr);
					}
				}
			else
				{
				/**	Send the multicast packet to the multicast child process	**/
				/** so that it can be routed.									**/
				/** For custom multicasting if the router joined the multicast	**/
				/** groups address forward the packet to higher layer.			**/
				/** Note: If the SV mcast_rte_protocol is "IpC_Rte_Pim_Sm" we	**/
				/** invoke PIM-SM else custom_mrp is invoked.					**/

				if (!ip_node_is_mcast_router (&module_data))
					{
					/* Received a packet for PIM-SM or custom multicast child	*/
					/* process. But, the child process is not created as the	*/
					/* multicast routing capability is disabled on this node.	*/
					/* Report a log message and terminate the simulation.	*/
					ipnl_cfgerr_pim_sm_child_process_not_created ();
					ip_dispatch_error ("The multicast child process, ip_pim_sm, doesn't exist on this node.");
					}
				
				/* Install the IP packet in the memory being shared	*/
				/* with the multicast child process.				*/
				module_data.ip_ptc_mem.child_pkptr = ip_pkptr;

				/* Set other fields of the shared memory			*/
				if (intf_ici_fdstruct_ptr->intf_recvd_index != -1)
					{
					module_data.ip_ptc_mem.ip_mcast_ptc_info.major_port = intf_ici_fdstruct_ptr->intf_recvd_index;
					module_data.ip_ptc_mem.ip_mcast_ptc_info.minor_port = intf_ici_fdstruct_ptr->minor_port_received;
					}
				else
					{
					op_sim_end ("Error in IP routing process model (ip_dispatch): ",
						"The interface on which the PIM-SM control or multicast data",
						"packet was received is not specified in the packet's ICI", OPC_NIL);
					}
				
				if (mcast_rte_protocol == IpC_Rte_Pim_Sm)
					{
					/* Invoke the PIM-SM child process						*/
					op_pro_invoke (pim_sm_process_handle, OPC_NIL);

					/* Destroy the associated interface ici, which we obtained above. */
					ip_rte_intf_ici_destroy (intf_ici_ptr);
                    }
				else 
					{
					/* Custom multicasting is being used. If the router joined the	*/
					/* multicast address send the packet to higher layer, else send	*/
					/* the packet to custom_mrp child process for routing.			*/
					if (inet_address_multicast_accept (&module_data, pkt_fields_ptr->dest_addr, 
							intf_ici_fdstruct_ptr->intf_recvd_index, IP_MCAST_NO_PORT) == OPC_TRUE)
						{
						/* Forward it to higher layer	*/
						op_pk_send (ip_pkptr, module_data.outstrm_to_ip_encap);
						}
					else
						{
						/* Invoke the Custom_Mrp child process						*/
						op_pro_invoke (custom_mrp_process_handle, OPC_NIL);

						/* Destroy the associated interface ici, which we obtained above. */
						ip_rte_intf_ici_destroy (intf_ici_ptr);
						}
					}
				}
			}
		
		else if (ip_packet_protocol_is_tunnel ((IpT_Protocol_Type) pkt_fields_ptr->protocol))
			{
			ip_dispatch_tunnel_packet_process (ip_pkptr, pkt_fields_ptr, intf_ici_ptr, intf_ici_fdstruct_ptr);			
			}
		else if (pkt_fields_ptr->protocol == IpC_Protocol_Basetraf)
			{			
			ip_dispatch_bgutil_packet_process (ip_pkptr, intf_ici_ptr, &(pkt_fields_ptr->dest_addr));			
			}
		else if (pkt_fields_ptr->protocol == IpC_Protocol_Rsvp)
			{
			ip_dispatch_higher_layer_rsvp_forward (ip_pkptr, intf_ici_ptr);			
			}
		else
			{
			ip_dispatch_send_packet_up (ip_pkptr, intf_ici_fdstruct_ptr);			
			}						
		}

	FOUT;
	}

static void
ip_dispatch_number_of_hops_update (IpT_Dgram_Fields* pk_fd_ptr)
	{
	/* This function checks if this is a data packet 	*/
	/* which is being sent to higher layer. If yes, 	*/
	/* it updates the Number of Hops IP statistics		*/
	int 		hops;
	
	FIN (ip_dispatch_number_of_hops_update (<args>));
	
	/* Check if stat handle ptr is set 			*/
	/* Special check for DSR as data pkts are 	*/
	/* sometimes encapsulated in DSR options 	*/
	/* when DSR is configured 					*/
	if ((pk_fd_ptr->src_num_hops_stat_hndl_ptr != OPC_NIL) && 
		(pk_fd_ptr->protocol != IpC_Protocol_Dsr))
		{
		/* Handle is set at source node for a data pkt 	*/
		/* Its a data packet, update the stat 			*/
		hops = 32 - (pk_fd_ptr->ttl -1);
		
		/* Write stat at destination node */
		op_stat_write (module_data.locl_num_hops_dest_hndl, hops);
		
		/* Write stat at source node */
		op_stat_write (*pk_fd_ptr->src_num_hops_stat_hndl_ptr, hops);
		
		/* Write global stats */
		op_stat_write (module_data.globl_num_hops_hndl, hops);
		}

	FOUT;
	}

static void
ip_dispatch_vpn_init (void)
	{
	IpT_Rte_Module_Data*	iprmd_ptr;
	
	FIN (ip_dispatch_vpn_init ());
	
	if (ip_l2tp_vpn_is_enabled (&module_data) == OPC_FALSE)
		{
		/* This is the first time this module get the remote */
		/* interrupt. Create the child process. Otherwise    */
		/* just invoke the existing child process            */
		module_data.l2tp_info_ptr = (IpT_L2TP_Info *) op_prg_mem_alloc (sizeof (IpT_L2TP_Info));
		module_data.l2tp_info_ptr->vpn_process_handle = op_pro_create ("ip_vpn", &(module_data.l2tp_info_ptr->vpn_ptc_mem));
		}
	
	/* Invoke the child process to initilize. 			*/
	/* State variables cannot be passed to macros.		*/
	iprmd_ptr = &module_data;
	ip_l2tp_vpn_process_invoke (iprmd_ptr, OPC_NIL);	
	
	FOUT;
	}

static void
ip_dispatch_load_balancer_init ()
	{
	/* Create and initialize the load balancer child process. */
	FIN (ip_dispatch_load_balancer_init ());
	
	module_data.load_balancer_info_ptr = (IpT_Load_Balancer_Info *) op_prg_mem_alloc (sizeof (IpT_Load_Balancer_Info));
	module_data.load_balancer_info_ptr->prohandle = op_pro_create ("gna_load_balancer", &module_data);
	
	op_pro_invoke (module_data.load_balancer_info_ptr->prohandle, OPC_NIL);
	
	/* If load balancer is not enabled on this node, the child process will	*/
	/* destroy itself and set load_balancer_info to NIL.					*/	
	
	FOUT;
	}

static void
ip_directly_connected_networks_insert (void)
	{
	Boolean					link_condition;
	int						num_interfaces, intf_index;
	IpT_Interface_Info*		ith_interface_ptr;

	/** If there are connected interfaces on which no routing	**/
	/** protocol has beeen enabled, Ip needs to originate a 	**/
	/** route to those networks.								**/
	
	FIN (ip_directly_connected_networks_insert (void));

	/* Find out the number of interfaces on this router.		*/
	num_interfaces = inet_rte_num_interfaces_get (&module_data);

	/* For each of these interfaces check if it satisfies the	*/
	/* above mentioned condition.								*/
	for (intf_index=0; intf_index < num_interfaces; intf_index++)
		{
		ith_interface_ptr = inet_rte_intf_tbl_access (&module_data, intf_index);

		/* If this interface has a link connected to it, make	*/
		/* sure that it is active.								*/
		if ((ip_rte_intf_conn_link_objid_get (ith_interface_ptr) != OPC_OBJID_INVALID) &&
			(OPC_COMPCODE_SUCCESS == op_ima_obj_attr_get (ip_rte_intf_conn_link_objid_get
									  (ith_interface_ptr), "condition", &link_condition)) &&
		    (OPC_FALSE == link_condition))
			{
			/* The link connected to this interface is failed.	*/
			/* skip this interface.								*/
			continue;
			}

		ip_directly_connected_networks_for_interface_handle (ith_interface_ptr, intf_index, OPC_TRUE /* insert */);
		}

	FOUT;
	}

static void 
ip_directly_connected_networks_for_interface_handle (IpT_Interface_Info* interface_ptr, int intf_index, Boolean insert)
	{
	IpT_Cmn_Rte_Table*		ip_rte_table;
	IpT_Port_Info			port_info;
	IpT_Dest_Prefix			dest_prefix;
	InetT_Address 			intf_addr;
	IpT_Rte_Prot_Type		protocol_type;
	int						num_secondary_addrs, num_ipv6_global_addrs, count_j;
	IpT_Cmn_Rte_Table_Entry*	rte_entry_ptr;
	
	/* Insert/delete directly connected network entries for addresses on this interface.	*/
	/* Handles IPv4 and IPv6 addresses. Handles special conditions like dual MSFC devices,	*/
	/* display suppression on Juniper routers, etc. This function is called at the start	*/							
	/* of the simulation and on failure/recovery interrupts.								*/
	FIN (ip_directly_connected_networks_for_interface_handle ());
			
	/* Skip shutdown interfaces.							*/
	if (ip_rte_intf_is_shutdown (interface_ptr))
		FOUT;

	/* The directly connected may need to be added to the	*/
	/* common route table or to a VRF table, depending on	*/
	/* the interface configuration.							*/
	ip_rte_table = ip_cmn_rte_table_for_intf_get (&module_data, intf_index);

	/* Create a port_info structure to be passed to		*/
	/* the Inet_Cmn_Rte_Table_Entry_Add function.		*/
	if (insert)
		port_info = ip_rte_port_info_create (intf_index, interface_ptr->full_name);

	/* If IPv4 is enabled on this interface and it has a	*/
	/* valid IPv4 address, add a route to the directly		*/
	/* connected IPv4 networks.								*/
	if ((ip_rte_intf_ipv4_active (interface_ptr)) &&
		(! ip_rte_intf_no_ip_address (interface_ptr)) &&
		(! ip_rte_intf_unnumbered (interface_ptr)))
		{
		/* Add routes to the primary IP subnet and each of	*/
		/* the secondary IP subnets.						*/
		num_secondary_addrs = ip_rte_intf_num_secondary_addresses_get (interface_ptr);
		for (count_j = -1; count_j < num_secondary_addrs; count_j++)
			{
			intf_addr = inet_rte_intf_secondary_addr_get (interface_ptr, count_j);
			
			dest_prefix = ip_cmn_rte_table_dest_prefix_from_addr_range_create
				(inet_rte_intf_secondary_addr_range_get (interface_ptr, count_j));

			/* If this interface belongs to a VRF, call a function that will allocate	*/
			/* a (bottom) label for the network, and create a port info structure that	*/
			/* contains this information.												*/
			/* A next hop value of IPC_ADDR_INVALID is used so that at the time of 		*/
			/* sending packets to directly connected destinations, the dest address of 	*/
			/* the packet is used as the next hop.										*/				
			if (insert && ip_cmn_rte_table_is_vrf (ip_rte_table))
				{
				MplsT_Label bottom_label = MPLSC_NULL_LABEL;
				port_info = ip_vrf_entry_port_info_create (IPC_ADDR_INVALID,
									OPC_NIL, /* top label is not present for local routes */
									&bottom_label, /* bottom label will be allocated by called function */
									intf_index,
									&module_data);
				}
			
		
			/* Normal interfaces (other than dual MSFC devices) are handled in the normal	*/
			/* way.																			*/
			if (!ip_rte_intf_is_msfc_alt (interface_ptr))
				{
				if (insert)
					{
					/* Insert the route in the routing table.	*/
					Inet_Cmn_Rte_Table_Entry_Add (ip_rte_table, (void*) OPC_NIL,
						dest_prefix, intf_addr, port_info, 0 /* metric value */,
						IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Directly_Connected, IPC_NO_MULTIPLE_PROC),
						0 /* admin dist */);
					}
				else
					{
					/* Remove the directly connected network from the IP route table.	*/
					Inet_Cmn_Rte_Table_Entry_Delete (ip_rte_table, dest_prefix, intf_addr,
						IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Directly_Connected, IPC_NO_MULTIPLE_PROC));
					}

				/* A more-specific host route with /32 mask is also added to the table. 	*/
				/* This address will let the node accept packets destined to its interfaces	*/
				/* even if there is a more specific route in its routing table (from some	*/
				/* other protocol like BGP). This /32 entry is explicit on Juniper devices.	*/
				/* It is present in the routing table output. In Cisco, it is not present	*/
				/* in the routing table, but is present in the cef table. Also, Cisco's		*/
				/* behavior is consistent with Juniper in the presence of a more-explicit	*/
				/* route.																	*/	
				/* This route will be of protocol type "Local" to differentiate it from the	*/
				/* protocol "connected". These routes will not be redistributed to any		*/
				/* other protocol. In the event of failrec, "local" routes are treated in	*/
				/* the same way as directly-connected routes.								*/

				/* Add this new route only for those interfaces that do not have a /32 mask.*/
				/* Packets bound for /32 (loopback) addresses will anyway be handled well.	*/
				if (!inet_address_range_ipv4_mask_equal (&dest_prefix, IpI_Broadcast_Addr))
					{
					/* Create a prefix with /32 mask.	*/
					dest_prefix = inet_address_range_create (intf_addr, inet_smask_from_length_create (IPC_V4_ADDR_LEN));

					if (insert)
						{
						/* Add to routing table with protocol "local".	*/
						Inet_Cmn_Rte_Table_Entry_Add (ip_rte_table, (void*) OPC_NIL,
							dest_prefix, intf_addr, port_info, 0 /* metric value */,
							IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Local, IPC_NO_MULTIPLE_PROC),
							0 /* admin dist */);

						/* On non-Juniper routers, hide this entry so that it does not	*/
						/* show up in the forwarding table OT output.					*/
						if ((OPC_NIL == module_data.vendor_name) || (strcmp (module_data.vendor_name, "Juniper Networks") != 0))
							{
							inet_cmn_rte_table_entry_exists (ip_rte_table, dest_prefix, &rte_entry_ptr);
							ip_cmn_rte_table_entry_dont_display_flag_set(rte_entry_ptr);
							}
						}
					else
						{
						/* Remove the directly connected network from the IP route table.	*/
						Inet_Cmn_Rte_Table_Entry_Delete (ip_rte_table, dest_prefix, intf_addr,
							IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Local, IPC_NO_MULTIPLE_PROC));
						}
					}
				}
			else
				{
				/* Alt interfaces on dual MSFC devices have to be handled differently. These	*/
				/* special interfaces are a modeling convenience and do not have real-world 	*/
				/* counterparts. These interfaces have /32 addresses so that the router can 	*/
				/* accept packets destined for the alt addresses. But since the address range	*/
				/* of the alt interface is already covered by the primary interface, the alt	*/
				/* interface address must not be treated like a normal dir-conn network - it	*/
				/* must not be present in the routing table, and it must not be redistributed	*/
				/* to other protocols along with other directly connected networks. Hence we 	*/
				/* use a different protocol type (local). An exception to this exception is a 	*/
				/* /32 loopback. An alt /32 loopback address is not covered by a /32 primary	*/
				/* loopback. Hence both the interfaces must be present in the routing table and */
				/* must be redistributed as directly connected networks.						*/

				/* Is this the special case where we have a pseudo alt-intf whose range is 		*/
				/* already covered by the primary interface? If so, insert this a "local" route	*/
				/* instead of a directly connected route.										*/
				protocol_type =  (ip_rte_intf_is_msfc_alt_host_lb (interface_ptr)) ? 
					IpC_Dyn_Rte_Directly_Connected : IpC_Dyn_Rte_Local;
		
				if (insert)
					{
					/* Insert the route in the routing table.	*/
					Inet_Cmn_Rte_Table_Entry_Add (ip_rte_table, (void*) OPC_NIL,
						dest_prefix, intf_addr, port_info, 0 /* metric value */,
						IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (protocol_type, IPC_NO_MULTIPLE_PROC),
						0 /* admin dist */);

					/* Pseudo-alt interfaces for dual MSFC devices must not show up in routing	*/
					/* table output. These are not real-interfaces.								*/
					if (!ip_rte_intf_is_msfc_alt_host_lb (interface_ptr))
						{
						inet_cmn_rte_table_entry_exists (ip_rte_table, dest_prefix, &rte_entry_ptr);
						ip_cmn_rte_table_entry_dont_display_flag_set(rte_entry_ptr);
						}
					}
				else
					{
					/* Remove the directly connected network from the IP route table.	*/
					Inet_Cmn_Rte_Table_Entry_Delete (ip_rte_table, dest_prefix, intf_addr,
						IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (protocol_type, IPC_NO_MULTIPLE_PROC));
					}
				} /* End else - if this interface is dual MSFC */
			} /* End for - all addresses on this interface */
		} /* End if - v4 is active on this interface */

	/* If IPv6 is active on this interface, add a route to	*/
	/* the directly connected IPv6 subnets.					*/
	if (ip_rte_intf_ipv6_active (interface_ptr))
		{
		/* Add routes to each of the global addresses of	*/
		/* this interface.									*/
		num_ipv6_global_addrs = ip_rte_intf_num_ipv6_gbl_addrs_get (interface_ptr);
		for (count_j = 0; count_j < num_ipv6_global_addrs; count_j++)
			{
			dest_prefix = ip_cmn_rte_table_dest_prefix_from_addr_range_create
				(ip_rte_intf_ith_gbl_ipv6_addr_range_get_fast (interface_ptr, count_j));

			if (insert)
				{
				Inet_Cmn_Rte_Table_Entry_Add (ip_rte_table, (void*) OPC_NIL,
					dest_prefix, ip_rte_intf_ith_gbl_ipv6_addr_get_fast (interface_ptr, count_j),
					port_info, 0 /* metric value */,
					IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Directly_Connected, IPC_NO_MULTIPLE_PROC),
					0 /* admin dist */);
				}
			else
				{
				/* Remove the directly connected network from the IP route table.	*/
				Inet_Cmn_Rte_Table_Entry_Delete (ip_rte_table, dest_prefix,
					ip_rte_intf_ith_gbl_ipv6_addr_get_fast (interface_ptr, count_j),
					IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Directly_Connected, IPC_NO_MULTIPLE_PROC));
				}
			
			/* Host addresses of interfaces are visible in the IPv6 routing table on	*/
			/* routers. The protocol used is "Local", not directly connected. These 	*/
			/* entries will help in accepting packets destined to these interfaces, but	*/
			/* will not be redistributed into other routing protocols. This behavior	*/
			/* is in line with that of real-world devices.								*/	
			intf_addr = ip_rte_intf_ith_gbl_ipv6_addr_get_fast (interface_ptr, count_j);
			dest_prefix = inet_address_range_create (intf_addr, inet_smask_from_length_create (IPC_V6_ADDR_LEN));

			if (insert)
				{
				Inet_Cmn_Rte_Table_Entry_Add (ip_rte_table, (void*) OPC_NIL,
					dest_prefix, ip_rte_intf_ith_gbl_ipv6_addr_get_fast (interface_ptr, count_j),
					port_info, 0 /* metric value */,
					IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Local, IPC_NO_MULTIPLE_PROC),
					0 /* admin dist */);
				}
			else
				{
				/* Remove the directly connected network from the IP route table.	*/
				Inet_Cmn_Rte_Table_Entry_Delete (ip_rte_table, dest_prefix,
					ip_rte_intf_ith_gbl_ipv6_addr_get_fast (interface_ptr, count_j),
					IP_CMN_RTE_TABLE_UNIQUE_ROUTE_PROTO_ID (IpC_Dyn_Rte_Local, IPC_NO_MULTIPLE_PROC));

				}
			}
		}
	FOUT;
	}
	

static void
ip_dispatch_layer2_mappings_read (IpT_Interface_Info* iface_info_ptr, Objid iface_description_objid)
	{
	Objid			layer2_mapping_cattr_objid;
	Objid			layer2_mapping_cattr_child_objid;
	Objid			atm_pvc_name_cattr_objid; 
	Objid			fr_pvc_name_cattr_objid; 
	int				num_rows; 
	int 			catch_all_index; 
	int				row_index; 
	Objid			ip_dest_to_vc_mapping_objid; 
	InetT_Address	swap_ip_address; 
	
	
	char			layer2_mapping [IPC_MAX_STR_SIZE];

	/** This function reads in the information specified under the	**/
	/** Layer2 Mappings attribute of either a physical or a 		**/
	/** subinterface.												**/

	FIN (ip_dispatch_layer2_mappings_read (iface_info_ptr, iface_description_objid));
	
	/* Get the objid of the compond attribute that stores the layer2*/
	/* Mappings of this subinterface								*/
	op_ima_obj_attr_get (iface_description_objid, "Layer 2 Mappings", &layer2_mapping_cattr_objid);

	/* Get the objid of the only row under this attribute			*/
	layer2_mapping_cattr_child_objid = op_topo_child (layer2_mapping_cattr_objid, OPC_OBJTYPE_GENERIC, 0);
	
	/* Get the objid of the ATM PVC Mapping compound attribute */
	op_ima_obj_attr_get (layer2_mapping_cattr_child_objid, "ATM PVC Mapping", &atm_pvc_name_cattr_objid); 
	
	/* Get the (IP destination addr, ATM PVC name) pairs from */
	/* the ATM PVC Mapping attribute. */
	num_rows = op_topo_child_count (atm_pvc_name_cattr_objid, OPC_OBJTYPE_GENERIC);
	iface_info_ptr->layer2_mappings.num_atm_pvcs = num_rows; 
	
	if (num_rows > 0)
		{
		iface_info_ptr->layer2_mappings.atm_pvc_set = (IpT_Dest_To_VC_Mapping*) 
			op_prg_mem_alloc (sizeof (IpT_Dest_To_VC_Mapping) * num_rows); 
		}
	
	/* Prepare to remember the index of a catch-all VC. */
	/* Such a VC will be specified against a dummy IP   */
	/* address (0.0.0.0) and will be used for lack of   */
	/* any match on a specific IP destination address.  */
	catch_all_index = -1; 
	
	/* Look through all the (IP destination addr, ATM PVC name) pairs */
	for (row_index = 0; row_index < num_rows; row_index ++)
		{
		ip_dest_to_vc_mapping_objid = op_topo_child (atm_pvc_name_cattr_objid, OPC_OBJTYPE_GENERIC, row_index); 
		
		/* Get IP destination address */
		op_ima_obj_attr_get (ip_dest_to_vc_mapping_objid, "IP Address", layer2_mapping);  
		
		if (strcmp (layer2_mapping, IPC_RTE_TABLE_ADDR_ANY) == 0)
			{
			/* The catch-all layer 2 mapping will be inserted    */
			/* at the end of the atm_pvc_set. Remember its       */
			/* index for a swap to bring it in the last position */
			catch_all_index = row_index; 	
			}

		iface_info_ptr->layer2_mappings.atm_pvc_set [row_index].ip_dest_addr = inet_address_create (
			layer2_mapping, InetC_Addr_Family_Unknown); 
		
		/* Read in the ATM PVC name and store it if it was */
		/* assigned a non-default value by the user.       */
		op_ima_obj_attr_get (ip_dest_to_vc_mapping_objid, "ATM PVC Name", layer2_mapping); 
		
		if (strcmp (layer2_mapping, IPC_DEFAULT_LAYER2_MAPPING_STRING) == 0)
			{
			/* No ATM PVC was specified. Set the pvc name to OPC_NIL	*/
			iface_info_ptr->layer2_mappings.atm_pvc_set [row_index].vc_name = OPC_NIL;
			}
		else 
			{
			/* Allocate enough memory to store the PVC name				*/
			iface_info_ptr->layer2_mappings.atm_pvc_set [row_index].vc_name = (char *)
				op_prg_mem_alloc (strlen (layer2_mapping) + 1);
			/* Copy the string name */
			strcpy (iface_info_ptr->layer2_mappings.atm_pvc_set [row_index].vc_name, 
				layer2_mapping); 

			}
		}

	if (catch_all_index >= 0)
		{
		/* A catch-all VC was found among the list    */
		/* of VCs configured in the Layer 2 Mapping - */
		/* - move it to the end of the list (note: 	  */
		/* a move is not needed if the catch-all VC is*/
		/* the only VC configured in Layer 2 Mapping) */
		/* or if the catch-all VC is already the last */
		if ((num_rows > 1) && (catch_all_index < num_rows -1))
			{
			/* Swap VC names */
			strcpy (layer2_mapping, iface_info_ptr->layer2_mappings.atm_pvc_set [num_rows-1].vc_name); 
			strcpy (iface_info_ptr->layer2_mappings.atm_pvc_set [num_rows-1].vc_name, 
				iface_info_ptr->layer2_mappings.atm_pvc_set [catch_all_index].vc_name);
			strcpy (iface_info_ptr->layer2_mappings.atm_pvc_set [catch_all_index].vc_name, layer2_mapping); 
			
			/* Swap IP destination addresses */
			swap_ip_address = iface_info_ptr->layer2_mappings.atm_pvc_set [num_rows-1].ip_dest_addr; 
			iface_info_ptr->layer2_mappings.atm_pvc_set [num_rows-1].ip_dest_addr = 
				iface_info_ptr->layer2_mappings.atm_pvc_set [catch_all_index].ip_dest_addr;
			iface_info_ptr->layer2_mappings.atm_pvc_set [catch_all_index].ip_dest_addr = swap_ip_address;
			}
		}

	/* Get the objid of the FR PVC Mapping compound attribute */
	op_ima_obj_attr_get (layer2_mapping_cattr_child_objid, "Frame Relay PVC Mapping", &fr_pvc_name_cattr_objid); 
	
	/* Get the (IP destination addr, FR PVC name) pairs from */
	/* the FR PVC Mapping attribute. */
	num_rows = op_topo_child_count (fr_pvc_name_cattr_objid, OPC_OBJTYPE_GENERIC);
	iface_info_ptr->layer2_mappings.num_fr_pvcs = num_rows; 
	
	if (num_rows > 0)
		{
		iface_info_ptr->layer2_mappings.fr_pvc_set = (IpT_Dest_To_VC_Mapping*)
			op_prg_mem_alloc (sizeof (IpT_Dest_To_VC_Mapping) * num_rows); 
		}
	
	/* Prepare to remember the index of a catch-all VC. */
	/* Such a VC will be specified against a dummy IP   */
	/* address (0.0.0.0) and will be used for lack of   */
	/* any match on a specific IP destination address.  */
	catch_all_index = -1; 
	
	/* Look through all the (IP destination addr, FR PVC name) pairs */
	for (row_index = 0; row_index < num_rows; row_index ++)
		{
		ip_dest_to_vc_mapping_objid = op_topo_child (fr_pvc_name_cattr_objid, OPC_OBJTYPE_GENERIC, row_index); 
		
		/* Get the IP destination address */
		op_ima_obj_attr_get (ip_dest_to_vc_mapping_objid, "IP Address", layer2_mapping);  
		
		if (strcmp (layer2_mapping, IPC_RTE_TABLE_ADDR_ANY) == 0)
			{
			/* The catch-all layer 2 mapping will be inserted    */
			/* at the end of the fr_pvc_set. Remember its       */
			/* index for a swap to bring it in the last position */
			catch_all_index = row_index; 	
			}
		
		iface_info_ptr->layer2_mappings.fr_pvc_set [row_index].ip_dest_addr = inet_address_create (
			layer2_mapping, InetC_Addr_Family_Unknown);
		
		/* Read in the FR PVC name and store it if it was */
		/* assigned a non-default value by the user.       */
		op_ima_obj_attr_get (ip_dest_to_vc_mapping_objid, "Frame Relay PVC Name", layer2_mapping); 

		if (strcmp (layer2_mapping, IPC_DEFAULT_LAYER2_MAPPING_STRING) == 0)
			{
			/* No FR PVC was specified. Set the pvc name to OPC_NIL	*/
			iface_info_ptr->layer2_mappings.fr_pvc_set [row_index].vc_name = OPC_NIL;
			}
		else 
			{
			/* Allocate enough memory to store the PVC name				*/
			iface_info_ptr->layer2_mappings.fr_pvc_set [row_index].vc_name = (char *)
				op_prg_mem_alloc (strlen (layer2_mapping) + 1);
			/* Copy the string name */
			strcpy (iface_info_ptr->layer2_mappings.fr_pvc_set [row_index].vc_name, 
				layer2_mapping); 
			}
		}
	
	if (catch_all_index >= 0)
		{
		/* A catch-all VC was found among the list    */
		/* of VCs configured in the Layer 2 Mapping - */
		/* - move it to the end of the list (note: 	  */
		/* a move is not needed if the catch-all VC is*/
		/* the only VC configured in Layer 2 Mapping) */
		/* or if the catch-all VC is already the last */
		if ((num_rows > 1) && (catch_all_index < num_rows -1))
			{
			/* Swap VC names */
			strcpy (layer2_mapping, iface_info_ptr->layer2_mappings.fr_pvc_set [num_rows-1].vc_name); 
			strcpy (iface_info_ptr->layer2_mappings.fr_pvc_set [num_rows-1].vc_name, 
				iface_info_ptr->layer2_mappings.fr_pvc_set [catch_all_index].vc_name);
			strcpy (iface_info_ptr->layer2_mappings.fr_pvc_set [catch_all_index].vc_name, layer2_mapping);
			
			/* Swap IP destination addresses */
			swap_ip_address = iface_info_ptr->layer2_mappings.fr_pvc_set [num_rows-1].ip_dest_addr; 
			iface_info_ptr->layer2_mappings.fr_pvc_set [num_rows-1].ip_dest_addr = 
				iface_info_ptr->layer2_mappings.fr_pvc_set [catch_all_index].ip_dest_addr;
			iface_info_ptr->layer2_mappings.fr_pvc_set [catch_all_index].ip_dest_addr = swap_ip_address;
			}
		}

	/* Read in the identifier of the VLAN to which the subinterface	*/
	/* belongs.														*/
	ip_dispatch_vlan_id_read (iface_info_ptr, layer2_mapping_cattr_child_objid);
	
	/* Forget about ELANs for now. We can read in the attributes	*/
	/* when they are supported.										*/
	FOUT;
	}

static void
ip_dispatch_route_table_init (void)
	{
	int		multipath_threshold;
	int		load_type;

	/** Initialize the IP common route table.					**/

	FIN (ip_dispatch_route_table_init (void));

	/* Allocate memory for the common IP route table that will  */
	/* be populated by the dyn. routing protocols configured    */
	/* by the user.                                             */
	module_data.ip_route_table = ip_cmn_rte_table_create (module_data.node_id, 
		&module_data, 
		OPC_NIL /* The VRF to which the route table belongs */);
	
	/* Prepare for collecting convergence statistics */
	module_data.ip_route_table->convg_handle = oms_routing_convergence_register (OmsC_IP_Forwarding_Table, 
		module_data.node_id, convergence_stat_names, parent_convergence_stat_names);

	/* Publish a pointer to the route table object in the       */
	/* process registry so that whatever dyn. routing protocols */
	/* are going to run in this node, they will have a reference*/
	/* to it.                                                   */
	oms_pr_attr_set (own_process_record_handle,
		"ip route table", OMSC_PR_POINTER, module_data.ip_route_table,
		OPC_NIL);

	/* If this is a gateway node, read gateway specific attributes */
	if (module_data.gateway_status == OPC_TRUE)
		{
		/* Also set the multipath routes threshold for the router */
		op_ima_obj_attr_get (module_data.ip_parameters_objid, 
			"Multipath Routes Threshold", &multipath_threshold);
		module_data.ip_route_table->usage_threshold = multipath_threshold;
		
		/* Determine the type of load balancing performed by this router */
		op_ima_obj_attr_get (module_data.ip_parameters_objid,
			"Load Balancing Options", &load_type);
		module_data.ip_route_table->load_type = (IpT_Rte_Table_Load) load_type;

		/* Create an empty static routing table. We need to do this	*/
		/* before adding any routes into the common route table.	*/
		module_data.ip_static_rte_table = ip_rte_table_create (&module_data);
		}

	FOUT;
	}

static IpT_Intf_User_Metrics*
ip_intf_metrics_read (Objid intf_attr_objid, double data_rate)
	{
	Objid					metric_objid, metric_child_objid;
	IpT_Intf_User_Metrics*	user_metrics_ptr;	
	int						bandwidth;
	
	/* Read the user defined interface metrics */
	FIN (ip_intf_metrics_read (double data_rate));
	
	user_metrics_ptr = (IpT_Intf_User_Metrics *) op_prg_mem_alloc (sizeof (IpT_Intf_User_Metrics));
	
	/* Obtain the objid for the user-defined intf metrics */
	op_ima_obj_attr_get (intf_attr_objid, "Metric Information", &metric_objid);
	metric_child_objid = op_topo_child (metric_objid, OPC_OBJTYPE_GENERIC, 0);
	
	/* Do not set the metric value to any thing specific	*/
	/* even if it is Auto-assigned. Auto-assigned			*/
	/* might have different connotations for different 		*/
	/* protocos e.g., EIGRP, CSPF etc						*/
	op_ima_obj_attr_get (metric_child_objid, "Delay", &(user_metrics_ptr->delay));
	
	
	op_ima_obj_attr_get (metric_child_objid, "Reliability", &(user_metrics_ptr->reliability));
	op_ima_obj_attr_get (metric_child_objid, "Load", &(user_metrics_ptr->load));
		
	op_ima_obj_attr_get (metric_child_objid, "Bandwidth", &bandwidth);
	if (bandwidth == IPC_BW_USE_LINK_BW)
		{
		/* We need to normalize bandwidth to kbps.	*/
		/* This is the unit expected by EIGRP.		*/
		user_metrics_ptr->bandwidth = (int) (data_rate/1000);
		}
	else
		{
		user_metrics_ptr->bandwidth = bandwidth;
		}
	
	FRET (user_metrics_ptr);
	}

static void
ip_dispatch_strm_intrpt_handle (void)
	{
	int					strm_index;
	Ici*				iciptr;
	Packet*				pk_ptr;
	IpT_Dgram_Fields*	pk_fd_ptr;
	char				dest_addr_str[IPC_ADDR_STR_LEN];
	SimT_Pk_Id			pkt_id, pkt_tree_id;
	int					i, *ith_elem;

	/** Stream interrupts are handled by the routing process	**/
	/** But in rare circumstances, the stream interrupt might be**/
	/** received by the parent process. e.g if the packet is	**/
	/** is received on an interface that is not in the interface**/
   	/**	list. In such cases, just destroy the packet and write	**/
	/** a log entry.											**/

	FIN (ip_dispatch_strm_intrpt_handle ());

	strm_index = op_intrpt_strm ();

	/* Obtain the packet and determine its destination address	*/
	pk_ptr = op_pk_get (strm_index);
	pkt_id = op_pk_id (pk_ptr);
	pkt_tree_id = op_pk_tree_id (pk_ptr);
	op_pk_nfd_access (pk_ptr, "fields", &pk_fd_ptr);
	inet_address_print (dest_addr_str, pk_fd_ptr->dest_addr);

	/* Destroy the packet.										*/
	op_pk_destroy (pk_ptr);

	/* If there is an ici associated with the packet, destroy	*/
	/* it also.													*/
	iciptr = op_intrpt_ici ();
	if (iciptr != OPC_NIL)
		{
		/* Destroy the incoming ICI.	*/
		op_ici_destroy (iciptr);
		}

	/* Print out a sim log entry if we haven't already done so	*/
	/* for this input stream. The list of input streams for		*/
	/* which this log message has already been written is stored*/
	/* in the SV unknown_instrm_index_lptr. Print the log 		*/
	/* message only	if we the current stream in not in the list.*/

	/* Check if the list of such streams has been created		*/
	if (OPC_NIL == unknown_instrm_index_lptr)
		{
		/* The list has not been created. Create it and insert	*/
		/* this stream into it.									*/
		unknown_instrm_index_lptr = op_prg_list_create ();
		}
	else
		{
		/* The list already exists, make sure that the current	*/
		/* stream is not already present in it.					*/
		for (i = 0; i < op_prg_list_size (unknown_instrm_index_lptr); i++)
			{
			ith_elem = (int*) op_prg_list_access (unknown_instrm_index_lptr, i);
			if (*ith_elem == strm_index)
				{
				/* We found a match. we don't have to write the	*/
				/* log message. return.							*/
				FOUT;
				}
			}
		}
	/* We did not write a log message for this interface. Insert*/
	/* the stream into the list and write the log message.		*/
	ith_elem = (int*) op_prg_mem_alloc (sizeof (int));
	*ith_elem = strm_index;
	op_prg_list_insert (unknown_instrm_index_lptr, ith_elem, OPC_LISTPOS_TAIL);

	ipnl_unknown_input_iface_log_write (strm_index, dest_addr_str, pkt_id, pkt_tree_id);

	FOUT;
	}

void
ip_dispatch_intf_table_create (int total_interfaces, int highest_instrm)
	{
	int						phys_index, num_phys_interfaces;
	int						subintf_index, num_subinterfaces;
	int						intf_array_index = 0;
	int						strm_array_index;
	IpT_Interface_Info*		ith_phys_intf_ptr, *jth_subintf_ptr;
	IpT_Rte_Module_Data*	iprmd_ptr;
	int						candidate_first_v4_loopback_intf = IPC_MCAST_MAJOR_PORT_INVALID;
	int						candidate_first_v6_loopback_intf = IPC_MCAST_MAJOR_PORT_INVALID;
	IpT_Group_Intf_Info*	group_info_ptr;
	int						ith_member, num_member_intfs, instrm_array_size;
	IpT_Member_Intf_Info*	member_intf_ptr;

	/** This function initializes the intf_table in module_data	**/
	/** The intf_table consists of an array of pointers to all	**/
	/** interfaces of a router, physical and subinterfaces.		**/

	FIN (ip_dispatch_intf_table_create (total_interfaces));

	/* Get a pointer to the module data of this node.			*/
	iprmd_ptr = &module_data;

	/* Initialize the first loopback indices to an invalid value*/
	module_data.first_loopback_intf_index = IPC_MCAST_MAJOR_PORT_INVALID;
	module_data.first_ipv6_loopback_intf_index = IPC_MCAST_MAJOR_PORT_INVALID;
	
	/* Also initialize the variable for storing the input stream*/
	/* index of the first physical interface.					*/
	/* This is used to deliver tunneled packets.				*/
	module_data.first_intf_instrm_index = IPC_PORT_NUM_INVALID;

	/* Also set the number of interfaces.						*/
	module_data.interface_table.total_interfaces = total_interfaces;

	/* Initialize the number of IPv4 and IPv6 interfaces to 0	*/
	module_data.interface_table.num_ipv4_interfaces = 0;
	module_data.interface_table.num_ipv6_interfaces = 0;

	/* If the number of interfaces is 0, generate a sim log		*/
	if (0 == total_interfaces)
		{
		/* Generate Sim Log										*/
		ipnl_no_valid_iface ();
		FOUT;
		}

	/* Allocate enough memory.									*/
	module_data.interface_table.intf_info_ptr_array = (IpT_Interface_Info**)
		op_prg_mem_alloc (total_interfaces * sizeof (IpT_Interface_Info*));
	
	/* Sort the elements in the list as following order.		*/
	/* IPv4 only interfaces.									*/
	/* IPv4/IPv6 interfaces.									*/
	/* IPv6 only interfaces.									*/
	op_prg_list_sort (module_data.interface_table_ptr, ip_dispatch_intf_compare_proc);

	/* Get the number of physical interfaces of this router.	*/
	num_phys_interfaces = op_prg_list_size (module_data.interface_table_ptr);

	/* Populate the array that stores the interface index corresponding	*/
	/* to each input stream. This will make it easy for IP to find out	*/
	/* which interface a particular input stream belongs to.			*/
	/* The variable highest instrm corresponds to the highest instream	*/
	/* index seen among the physical interfaces. The actual array must	*/
	/* contain two more elements - one for the stream coming in from 	*/
	/* ip_encap, and one for the stream coming from a potential RSM		*/
	/* module. Note that we do not use this array for packets coming	*/
	/* in from IP encap, but it still takes up one stream. For example,	*/
	/* a node may have 5 physical interfaces (instrm 0 to instrm 4),	*/
	/* a stream from ip_encap (instrm 5) and a stream from the RSM 		*/
	/* module (instrm 6). Our array must therefore be of size 7, since	*/
	/* we want an instrm to interface mapping for the RSM interface.	*/
	instrm_array_size = highest_instrm + 2;
	
	module_data.instrm_to_intf_index_array = (short*) op_prg_mem_alloc 
		(instrm_array_size * sizeof (short));

	/* Initialize all the entries to an invalid value.			*/
	for (strm_array_index = 0; strm_array_index < instrm_array_size; strm_array_index++)
		{
		module_data.instrm_to_intf_index_array[strm_array_index] = IPC_MCAST_MAJOR_PORT_INVALID;
		}

	/* Also allocate memory for the instrm to slot index array,			*/
	/* if slot based processing is used.								*/
	if (OmsC_Dv_Slot_Based == module_data.processing_scheme)
		{
		module_data.instrm_to_slot_index_array = (short*) op_prg_mem_alloc 
			(instrm_array_size * sizeof (short));
		}

	/* If there is at least one member interface, do the same for the	*/
	/* instrm_to_member_index_array.									*/
	if (module_data.group_info_ptr != OPC_NIL)
		{
		module_data.group_info_ptr->instrm_to_member_index_array = (short*) op_prg_mem_alloc 
			(instrm_array_size * sizeof (short));

		/* Initialize all the entries to an invalid value.				*/
		for (strm_array_index = 0; strm_array_index < instrm_array_size; strm_array_index++)
			{
			module_data.group_info_ptr->instrm_to_member_index_array[strm_array_index] = IPC_MEMBER_INTF_INDEX_INVALID;
			}
		}

	/* Loop through all the interfaces and move them to the new	*/
	/* array.													*/
	for (phys_index = 0; phys_index < num_phys_interfaces; phys_index++)
		{
		/* get a pointer to interface info of this interface	*/
		ith_phys_intf_ptr = (IpT_Interface_Info*) op_prg_list_access
			(module_data.interface_table_ptr, phys_index);

		/* Initialize the corresponding entry in the 			*/
		/* instrm_to_intf_index_array.							*/
		if (IPC_PORT_NUM_INVALID != ip_rte_intf_in_port_num_get (ith_phys_intf_ptr))
			{
			if (ip_rte_intf_in_port_num_get (ith_phys_intf_ptr) > instrm_array_size)
				{
				char msg [32];
				sprintf (msg, "In port: %d Highest instrm: %d", ip_rte_intf_in_port_num_get (ith_phys_intf_ptr), highest_instrm);
				op_prg_mem_alloc (0);
				op_sim_end ("Invalid port number for interface", ith_phys_intf_ptr->full_name, msg, "");
				}

			module_data.instrm_to_intf_index_array[ip_rte_intf_in_port_num_get (ith_phys_intf_ptr)] = (short) intf_array_index;

			/* Set the first_intf_instrm_index, if it has not	*/
			/* been done already.								*/
			if (IPC_PORT_NUM_INVALID == module_data.first_intf_instrm_index)
				{
				module_data.first_intf_instrm_index = ip_rte_intf_in_port_num_get (ith_phys_intf_ptr);
				}
			}
		/* We must explicitly check to see if the interface is loopback,	*/
		/* since it can also be a tunnel interface.							*/
		/* Currently loopback interfaces cannot be shutdown,*/
		/* but to be on the safe side, check for that too.	*/
		else if ((ip_rte_intf_is_loopback (ith_phys_intf_ptr)) &&
				 (! ip_rte_intf_is_shutdown (ith_phys_intf_ptr)))
			{
			/* If IPv4 is enabled on this interface and we		*/
			/* haven't encountered any other IPv4 loopback		*/
			/* interfaces, store its index.						*/
			/* Do not consider the alt addresses as candidates	*/
			/* for first loopback, router ID etc. We must use	*/
			/* configuration from the primary attributes for	*/
			/* dual MSFC devices.								*/
			if ((ip_rte_intf_ipv4_active (ith_phys_intf_ptr)) &&
				(! ip_rte_intf_no_ip_address (ith_phys_intf_ptr)) &&
				(module_data.first_loopback_intf_index == IPC_MCAST_MAJOR_PORT_INVALID) &&
				(!ip_rte_intf_is_msfc_alt (ith_phys_intf_ptr)))
				{
				module_data.first_loopback_intf_index = (short) intf_array_index;

				/* Since we have found an IPv4 enabled loopback	*/
				/* we don't need to look for a candidate		*/
				/* loopback.									*/
				candidate_first_v4_loopback_intf = intf_array_index;
				}

			/* If IPv6 is enabled on this interface and we		*/
			/* haven't encountered any other IPv6 loopback		*/
			/* interfaces, store its index.						*/
			/* Make sure that the interface has at least one	*/
			/* global IPv6 address.								*/
			if ((ip_rte_intf_ipv6_active (ith_phys_intf_ptr)) &&
				(ip_rte_intf_num_ipv6_gbl_addrs_get (ith_phys_intf_ptr) > 0) &&
				(module_data.first_ipv6_loopback_intf_index == IPC_MCAST_MAJOR_PORT_INVALID))
				{
				module_data.first_ipv6_loopback_intf_index = (short) intf_array_index;

				/* Since we have found an IPv6 enabled loopback	*/
				/* we don't need to look for a candidate		*/
				/* loopback.									*/
				candidate_first_v6_loopback_intf = intf_array_index;
				}
			}
		else if (ip_rte_intf_is_group (ith_phys_intf_ptr))
			{
			/* Register this index for the instrms of all the	*/
			/* member interfaces.								*/

			/* Get a handle to structure that stores	*/
			/* group related parameters.				*/
			group_info_ptr = ith_phys_intf_ptr->phys_intf_info_ptr->group_info_ptr;

			/* Get the number of member interfaces.		*/
			num_member_intfs = group_info_ptr->num_members;

			/* Loop through each member and check if its*/
			/* outstrm matches the outstrm we are		*/
			/* looking for.								*/
			for (ith_member = 0; ith_member < num_member_intfs; ith_member++)
				{
				/* Get a handle to the ith member		*/
				member_intf_ptr = &(group_info_ptr->member_intf_array[ith_member]);

				/* Register the current interface for	*/
				/* the specified instrm index.			*/
				module_data.instrm_to_intf_index_array[member_intf_ptr->instrm] = (short) intf_array_index;

				/* Also populate the corresponding entry*/
				/* in the instrm_to_member_index_array	*/
				module_data.group_info_ptr->instrm_to_member_index_array[member_intf_ptr->instrm] = (short) ith_member;
				}
			}

		/* If this interface is not shutdown, check if it can	*/
		/* be used as a candidate loopback interface should		*/
		/* we not find any loopback interfaces.					*/
		if (! ip_rte_intf_is_shutdown (ith_phys_intf_ptr))
			{
			/* If this interface has a valid IPv4 address, consider	*/
			/* it as a possible candidate for the first loopback	*/
			/* interface should there be no loopback interfaces.	*/
			if ((IPC_MCAST_MAJOR_PORT_INVALID == candidate_first_v4_loopback_intf) &&
				(ip_rte_intf_ipv4_active (ith_phys_intf_ptr)) &&
				(! ip_rte_intf_unnumbered (ith_phys_intf_ptr)) &&
				(! ip_rte_intf_no_ip_address (ith_phys_intf_ptr)))
				{
				candidate_first_v4_loopback_intf = intf_array_index;
				}

			/* If this interface has a valid IPv6 address, consider	*/
			/* it as a possible candidate for the first loopback	*/
			/* interface should there be no loopback interfaces.	*/
			if ((IPC_MCAST_MAJOR_PORT_INVALID == candidate_first_v6_loopback_intf) &&
				(ip_rte_intf_ipv6_active (ith_phys_intf_ptr)) &&
				(ip_rte_intf_num_ipv6_gbl_addrs_get (ith_phys_intf_ptr) > 0))
				{
				candidate_first_v6_loopback_intf = intf_array_index;
				}
			}

		/* Get the number of subinterfaces of this interface	*/
		num_subinterfaces = ip_rte_num_subinterfaces_get (ith_phys_intf_ptr);

		/* Loop through the physical interface and the			*/
		/* subinterfaces.										*/
		module_data.interface_table.intf_info_ptr_array[intf_array_index] = ith_phys_intf_ptr;

		/* Store the index in the IpT_Interface_Info structure	*/
		ith_phys_intf_ptr->intf_index = (short) intf_array_index;

		/* Increment the number of IPv4 interfaces if this		*/
		/* interface is IPv4 enabled.							*/
		if (ip_rte_intf_ipv4_active (ith_phys_intf_ptr))
			{
			++module_data.interface_table.num_ipv4_interfaces;
			}

		/* Increment the number of IPv6 interfaces if this		*/
		/* interface is IPv6 enabled.							*/
		if (ip_rte_intf_ipv6_active (ith_phys_intf_ptr))
			{
			++module_data.interface_table.num_ipv6_interfaces;
			}

		/* Increment the index in the interface array.			*/
		++intf_array_index;

		for (subintf_index = 0; subintf_index < num_subinterfaces; subintf_index++)
			{
			/* Get a handle to the ith subinterface.			*/
			jth_subintf_ptr = ith_phys_intf_ptr->phys_intf_info_ptr->subintf_pptr[subintf_index];

			/* Store the current interface in the intf table	*/
			module_data.interface_table.intf_info_ptr_array[intf_array_index] = jth_subintf_ptr;

			/* Store the index in IpT_Interface_Info structure	*/
			jth_subintf_ptr->intf_index = (short) intf_array_index;

			/* Increment the number of IPv4 interfaces if this	*/
			/* interface is IPv4 enabled.						*/
			if (ip_rte_intf_ipv4_active (jth_subintf_ptr))
				{
				++module_data.interface_table.num_ipv4_interfaces;
				}

			/* Increment the number of IPv6 interfaces if this	*/
			/* interface is IPv6 enabled.						*/
			if (ip_rte_intf_ipv6_active (jth_subintf_ptr))
				{
				++module_data.interface_table.num_ipv6_interfaces;
				}

			/* If this interface is not shutdown, check if it can	*/
			/* be used as a candidate loopback interface should		*/
			/* we not find any loopback interfaces.					*/
			if (! ip_rte_intf_is_shutdown (jth_subintf_ptr))
				{
				/* If this interface has a valid IPv4 address, consider	*/
				/* it as a possible candidate for the first loopback	*/
				/* interface should there be no loopback interfaces.	*/
				if ((IPC_MCAST_MAJOR_PORT_INVALID == candidate_first_v4_loopback_intf) &&
					(ip_rte_intf_ipv4_active (jth_subintf_ptr)) &&
					(! ip_rte_intf_unnumbered (jth_subintf_ptr)) &&
					(! ip_rte_intf_no_ip_address (jth_subintf_ptr)))
					{
					candidate_first_v4_loopback_intf = intf_array_index;
					}

				/* If this interface has a valid IPv6 address, consider	*/
				/* it as a possible candidate for the first loopback	*/
				/* interface should there be no loopback interfaces.	*/
				if ((IPC_MCAST_MAJOR_PORT_INVALID == candidate_first_v6_loopback_intf) &&
					(ip_rte_intf_ipv6_active (jth_subintf_ptr)) &&
					(ip_rte_intf_num_ipv6_gbl_addrs_get (jth_subintf_ptr) > 0))
					{
					candidate_first_v6_loopback_intf = intf_array_index;
					}
				}

			/* Increment the index in the interface array.		*/
			++intf_array_index;
			}
		}

	/* Set the first_ipv6_intf_ptr correctly					*/
	module_data.interface_table.first_ipv6_intf_ptr = module_data.interface_table.intf_info_ptr_array
		+ (total_interfaces - module_data.interface_table.num_ipv6_interfaces);

	/* Make sure that the loopback indices have been set.		*/
	if ((IPC_MCAST_MAJOR_PORT_INVALID == module_data.first_loopback_intf_index) &&
		(module_data.interface_table.num_ipv4_interfaces > 0))
		{
		/* IPv4 is enabled on this node, but not on any of the	*/
		/* loopback interfaces. Pick the first IPv4 enabled		*/
		/* interface with a valid address.						*/
		if (IPC_MCAST_MAJOR_PORT_INVALID != candidate_first_v4_loopback_intf)
			{
			module_data.first_loopback_intf_index = candidate_first_v4_loopback_intf;
			}
		else
			{
			module_data.first_loopback_intf_index = inet_first_ipv4_intf_index_get (&module_data);
			}	
		}

	if ((IPC_MCAST_MAJOR_PORT_INVALID == module_data.first_ipv6_loopback_intf_index) &&
		(module_data.interface_table.num_ipv6_interfaces > 0))
		{
		/* IPv6 is enabled on this node, but not on any of the	*/
		/* loopback interfaces. Pick the first IPv6 enabled		*/
		/* interface with a valid address.						*/
		if (IPC_MCAST_MAJOR_PORT_INVALID != candidate_first_v6_loopback_intf)
			{
			module_data.first_ipv6_loopback_intf_index = candidate_first_v6_loopback_intf;
			}
		else
			{
			module_data.first_ipv6_loopback_intf_index = inet_first_ipv6_intf_index_get (&module_data);
			}
		}

	/* If there is at least one unnumbered interface, call the	*/
	/* function that will resolve the source interfaces of		*/
	/* unnumbered interfaces.									*/
	if (module_data.unnumbered_interface_exists)
		{
		ip_dispatch_unnumbered_interfaces_resolve ();
		}

	FOUT;
	}

static void
ip_dispatch_unnumbered_interfaces_resolve (void)
	{
	int					i, num_interfaces;
	IpT_Interface_Info	*ith_intf_info_ptr;
	IpT_Interface_Info	*src_intf_info_ptr;
	Boolean				src_intf_resolved;
	int					src_intf_index;

	/** Each unnumbered interface should have an interface whose addresss	**/
	/** it can use while sending packets out on the interface. Users		**/
	/** specify this interface by name. This function will resolve these	**/
	/** interface names to the actual interface.							**/

	FIN (ip_dispatch_unnumbered_interfaces_resolve (void));

	/* Loop through all IPv4 interfaces.									*/
	num_interfaces = ip_rte_num_interfaces_get (&module_data);

	/* Loop through the list of interfaces an look for unnumbered interfaces*/
	for (i = 0; i < num_interfaces; i++)
		{
		/* Access the ith physical interface.								*/
		ith_intf_info_ptr = ip_rte_intf_tbl_access (&module_data, i);

		/* Check if the current interface is unnumbered.				*/
		if (ip_rte_intf_unnumbered (ith_intf_info_ptr))
			{
			/* For backward compatibility, we need to support the case	*/
			/* where an interface name has not been specified.			*/
			if ('\0' == *(ith_intf_info_ptr->unnumbered_info->interface_name))
				{
				/* Use the first available IPv4 interface.				*/
				src_intf_info_ptr = ip_dispatch_unnumbered_src_intf_pick ();

				/* Set the intf_resolved flag to true.					*/
				src_intf_resolved = OPC_TRUE;
				}
			else
				{
				/* Look for an interface with the specified name in the	*/
				/* interface list.										*/
				src_intf_resolved = ip_rte_is_local_intf_name (ith_intf_info_ptr->unnumbered_info->interface_name, 
					&module_data, &src_intf_index, &src_intf_info_ptr);
				}

			/* Make sure that we found an interface and that it has a	*/
			/* valid address.											*/
			if ((OPC_FALSE == src_intf_resolved) ||
				(OPC_NIL == src_intf_info_ptr) ||
				(! ip_rte_intf_ipv4_active (src_intf_info_ptr)) ||
				(ip_rte_intf_unnumbered (src_intf_info_ptr)) ||
				(ip_rte_intf_no_ip_address (src_intf_info_ptr)))
				{
				/* Write a log message warning the user about the		*/
				/* misconfiguration.									*/
				ipnl_invalid_unnumbered_source_intf_log_write
					(ip_rte_intf_name_get (ith_intf_info_ptr), ith_intf_info_ptr->unnumbered_info->interface_name);

				/* Free the memory allocated to the interface name.		*/
				op_prg_mem_free (ith_intf_info_ptr->unnumbered_info->interface_name);

				/* Set the source address of the interface to an invalid*/
				/* value.												*/
				ith_intf_info_ptr->unnumbered_info->interface_addr = IPC_ADDR_INVALID;

				/* Disable any routing protocols that might be enabled	*/
				/* on this interface.									*/
				ith_intf_info_ptr->routing_protocols_lptr = no_routing_proto_lptr;
				}
			else
				{
				/* Free the memory allocated to the interface name.		*/
				op_prg_mem_free (ith_intf_info_ptr->unnumbered_info->interface_name);

				/* Fill in the source address for the interface.		*/
				ith_intf_info_ptr->unnumbered_info->interface_addr = ip_rte_intf_addr_get (src_intf_info_ptr);
				}
			}
		}

	/* We have processed all interfaces. Return.							*/
	FOUT;
	}

static IpT_Interface_Info*
ip_dispatch_unnumbered_src_intf_pick (void)
	{
	IpT_Interface_Info*			src_intf_info_ptr;

	/** An interface on this node was marked as unnumbered, but a	**/
	/** source interface was not explicitly specified. Pick an		**/
	/** appropriate interface using the following logic.			**/
	/** Pick the first active IPv4 loopback interface. If one could	**/
	/** not be found, pick the first active, numbered physical		**/
	/** interface.													**/

	FIN (ip_dispatch_unnumbered_src_intf_pick (void));

	src_intf_info_ptr = ip_rte_first_loopback_intf_info_get (&module_data);

	FRET (src_intf_info_ptr);
	}

static void
ip_dispatch_fail_rec_handle (int intrpt_code)
	{
	int						ith_subintf, num_subinterfaces, ith_subintf_ip_index;
	int						failed_link_intf_index;
	IpT_Interface_Info		*phys_intf_info_ptr, *ith_subintf_ptr; 
	IpT_Observer_Client_Info* observer_client_info_ptr;
	MplsT_Invoke_Info		mpls_invoke_info;
	Boolean					insert;
	
	/* This function will handle a failure or recovery intrpt received by IP */
	/* It will update the static route table according to the type of intrpt */
	/* received by either deleting or adding routes, w.r.t the intrpt.		 */
	FIN (ip_dispatch_fail_rec_handle (int intrpt_type));

	/* Obtain the IP Observer event state. */
	observer_client_info_ptr = (IpT_Observer_Client_Info*) op_ev_state (op_ev_current ());
	
	/* Check if the invocation is for same process or for any child process	*/
	if (op_pro_id (observer_client_info_ptr->client_phandle) != op_pro_id (module_data.ip_root_prohandle))
		{
		/* This invocation is for some child of this IP root process,		*/
		/* invoke child process												*/
		
		/* Check if it is for MPLS.											*/
		if ((OPC_NIL != module_data.mpls_info_ptr) && 
			(op_pro_id (observer_client_info_ptr->client_phandle) == op_pro_id (module_data.mpls_info_ptr->mgr_prohandle)))
			{
			/* Here invocation is for MPLS, create the argument for MPLS	*/
			/* and send it													*/
			mpls_invoke_info.invoke_type 		= MplsC_Invoke_Fail_Rec;
			mpls_invoke_info.invocation_arg_ptr = (void*) observer_client_info_ptr;
			op_pro_invoke (observer_client_info_ptr->client_phandle, &mpls_invoke_info);
			}
		else
			{
			/* It is for some other child of IP.							*/
			op_pro_invoke (observer_client_info_ptr->client_phandle, observer_client_info_ptr);
			}

		FOUT;
		}
		
	/* Check whether this is a link failure/recovery. 	*/
	if (IPC_INTRPT_TYPE_LINK_FAIL == intrpt_code || IPC_INTRPT_TYPE_LINK_RECOVER == intrpt_code)
		{
		/* Get the index of the interface connected to the failed link.	*/
		failed_link_intf_index = observer_client_info_ptr->interface_index;

		/* If the failed link is not connected to this node, return	*/
		if (IPC_MCAST_MAJOR_PORT_INVALID == failed_link_intf_index)
			{
			FOUT;
			}

		/* Get a pointer to the corresponding physical interface.	*/
		phys_intf_info_ptr = inet_rte_intf_tbl_access (&module_data, failed_link_intf_index);

		/* Update the link_status.									*/
		if (IPC_INTRPT_TYPE_LINK_FAIL == intrpt_code)
			{
			phys_intf_info_ptr->phys_intf_info_ptr->link_status = 0;
			}
		else
			{
			phys_intf_info_ptr->phys_intf_info_ptr->link_status = 1;
			}

		/* Loop through the subinterfaces of this interface and		*/
		/* handle each of them.										*/
		num_subinterfaces = ip_rte_num_subinterfaces_get (phys_intf_info_ptr);
		for (ith_subintf = IPC_SUBINTF_PHYS_INTF; ith_subintf < num_subinterfaces; ith_subintf++)
			{
			/* Access the ith subinterface.							*/
			ith_subintf_ptr = ip_rte_ith_subintf_info_get (phys_intf_info_ptr, ith_subintf);
			ith_subintf_ip_index = ip_rte_intf_index_get (ith_subintf_ptr);

			/* If this is a recovery interrupt, insert the routes. 	*/
			/* Otherwise, delete the routes.						*/
			insert = (IPC_INTRPT_TYPE_LINK_RECOVER == intrpt_code); 

			ip_directly_connected_networks_for_interface_handle (ith_subintf_ptr, ith_subintf_ip_index, insert);
			}
		}
	else if (IPC_INTRPT_TYPE_NODE_FAIL == intrpt_code || IPC_INTRPT_TYPE_NODE_RECOVER == intrpt_code)
		{
		/* Node failed or recovered. */

		if (intrpt_code == IPC_INTRPT_TYPE_NODE_RECOVER)
			{
			/* The surrounding node has failed. Destroy all packets that might be waiting 	*/
			/* on a stream from ip_encap process. These packets were created just before	*/
			/* the node failed and should not be sent out, but destroyed.					*/			
			op_strm_flush (OPC_STRM_ALL);
			}
		}

	FOUT;
	}

static void
ip_dispatch_mpls_info_read (void)
	{
	Objid			mpls_params_comp_objid;
	Objid			mpls_params_row_objid;
	char			label_allocation [128];
	Boolean			mpls_status;
	
	/** Read node-level MPLS information pertinent to IP.	**/
	FIN (ip_dispatch_mpls_info_read ());
	
	/* Initialize with default values. If we do it here, we need not worry	*/
	/* about setting default values at each else condition.					*/	
	module_data.mpls_info_ptr = OPC_NIL;
	
	if (op_ima_obj_attr_exists (module_data.node_id, "MPLS Parameters")) 
		{
		/* Get the user configuration for MPLS					 		*/
		op_ima_obj_attr_get (module_data.node_id, "MPLS Parameters", &mpls_params_comp_objid);
		mpls_params_row_objid = op_topo_child (mpls_params_comp_objid, OPC_OBJTYPE_GENERIC, 0);
		
		/* Get the status of MPLS Configured on this node				*/
		op_ima_obj_attr_get (mpls_params_row_objid, "Status", &mpls_status);
		
		if (mpls_status == OPC_TRUE)
			{				
			/* Create the MPLS Information structure in Module data			*/
			module_data.mpls_info_ptr 		= mpls_support_mpls_info_create ();
			
			/* Get the user configuration for MPLS					 		*/
			op_ima_obj_attr_get (module_data.node_id, "MPLS Parameters", &mpls_params_comp_objid);
			mpls_params_row_objid = op_topo_child (mpls_params_comp_objid, OPC_OBJTYPE_GENERIC, 0);
			
			/* Get the user configuration for Label Space allocation 		*/
			op_ima_obj_attr_get (mpls_params_row_objid, "Label Space Allocation", &label_allocation);
			
			if (strcmp (label_allocation, "Global") == 0)
				{	
				/* Set the flag that Node is using Global Label Space 		*/
				module_data.mpls_info_ptr->label_space_global = OPC_TRUE;
				}
			else
				{
				/* Set the flag that Node is not using Global Label Space 	*/
				module_data.mpls_info_ptr->label_space_global = OPC_FALSE;
				}
			}
		}
	
	FOUT;
	}
					

static void
ip_dispatch_interface_mpls_init (void)
	{
	int				num_ifaces;
	
	/** Perform interface specific initialization of MPLS.	**/
	FIN (ip_dispatch_interface_mpls_init ());

	if (!ip_mpls_is_enabled (&module_data))
		FOUT;
			
	/* Create a table of label spaces for interface 					*/
	num_ifaces = ip_rte_num_interfaces_get (&module_data);	
	
	/* The node may be unconnected, or it may have only IPv6 interfaces.	*/
	/* Do not try to allocate memory in such a case.						*/
	if (num_ifaces > 0)
		{	
		/* Label Space allocation is interface specific therefore  		*/
		/* allocate the memory for all the interfaces.					*/
		module_data.mpls_info_ptr->lib_space_table_ptr = (MplsT_Label_Space_Handle*) op_prg_mem_alloc (num_ifaces * sizeof (MplsT_Label_Space_Handle));
		}

	FOUT;	
	}

static void
ip_dispatch_interface_vpns_init (List* vrf_name_info_lptr)
	{
	IpT_Intf_Routing_Instance*		intf_routing_instance_ptr;
	int								num_ifaces, num_vrf_ifaces, iface_index, vrf_index;
	IpT_Interface_Info*				ip_intf_info_ptr;
	IpT_Vrf_Table*					vrf_table;
	List							tmp_vrf_list;
	IpT_Vrf_Info*					vrf_info_ptr;
	
	/** This function goes through the list of VRF names and builds	**/
	/** an array of the VRF names, indexed by the interface index.	**/	
	FIN (ip_dispatch_interface_vpns_init (vrf_name_info_lptr));
	
	/* Initialize with default values. If we do it here, we need not worry	*/
	/* about setting default values at each else condition.					*/	
	module_data.vrf_info_ptr = OPC_NIL;

	num_vrf_ifaces = op_prg_list_size (vrf_name_info_lptr);

	/* Create VRF information structure if a VRF is configured on at least	*/
	/* one interface on the node.											*/
	if (num_vrf_ifaces > 0)
		{
		vrf_info_ptr = (IpT_Vrf_Info *) op_prg_mem_alloc (sizeof (IpT_Vrf_Info));
	
		/* We will temporarily store the VRFs in a list and convert the	*/
		/* list into an array after all VRFs have been initialized.		*/
		op_prg_list_init (&tmp_vrf_list);
		
		/* Create an array of VRF names indexed by interface index. Even	*/
		/* though we end up allocating memory for all interfaces, this is	*/
		/* better than hash table creation, for both speed and memory.		*/		
		num_ifaces  = ip_rte_num_interfaces_get (&module_data);
		
		vrf_info_ptr->intf_index_to_vrf_table_array = (IpT_Vrf_Table **) op_prg_mem_alloc (num_ifaces * sizeof (IpT_Vrf_Table *));
		
		/* Loop through all interfaces with VRF names set, and perform initialization.	*/		
		
		for (vrf_index = 0; vrf_index < num_vrf_ifaces; vrf_index++)
			{
			intf_routing_instance_ptr = (IpT_Intf_Routing_Instance *) 
				op_prg_list_remove (vrf_name_info_lptr, OPC_LISTPOS_HEAD);

			/* Get the interface index corresponding to this name.	*/
			ip_rte_is_local_intf_name (intf_routing_instance_ptr->intf_name, &module_data,
				&iface_index, &ip_intf_info_ptr);

			/* Check if the VRF table corresponding to this name has already been built.	*/
			vrf_table = ip_vrf_table_from_list (&tmp_vrf_list, intf_routing_instance_ptr->routing_instance_name);

			/* Create the VRF table if it has not been created yet.	*/
			if (vrf_table == OPC_NIL)
				{
				vrf_table = ip_vrf_table_create (module_data.node_id, 
					intf_routing_instance_ptr->routing_instance_name, 
					&module_data);

				/* If a VRF has been successfully created, add it to the list of VRFs.	*/
				if (vrf_table != OPC_NIL)
					op_prg_list_insert (&tmp_vrf_list, vrf_table, OPC_LISTPOS_TAIL);
				}

			/* If a VRF exists for this interface (existing or freshly created)	*/
			/* populate the interface to VRF table mapping.						*/
			if (vrf_table != OPC_NIL)
				vrf_info_ptr->intf_index_to_vrf_table_array [iface_index] = vrf_table;
			
			/* The ip_vrf_table_create function makes copies of the VRF name.	*/
			/* This is done to prevent memory leaks in the case of VRF 			*/
			/* misconfiguration.												*/
			op_prg_mem_free (intf_routing_instance_ptr->routing_instance_name);
			op_prg_mem_free (intf_routing_instance_ptr->intf_name);
			op_prg_mem_free (intf_routing_instance_ptr);
			}

		/* Convert the list of VRF tables into an array for efficiency.	*/
		vrf_info_ptr->num_vrfs = op_prg_list_size (&tmp_vrf_list);

		if (vrf_info_ptr->num_vrfs > 0)
			{
			vrf_info_ptr->vrf_table_array = (IpT_Vrf_Table **) op_prg_mem_alloc (vrf_info_ptr->num_vrfs * sizeof (IpT_Vrf_Table *));
			
			for (vrf_index = 0; vrf_index < vrf_info_ptr->num_vrfs; vrf_index++)
				{
				vrf_info_ptr->vrf_table_array [vrf_index] = 
					(IpT_Vrf_Table *) op_prg_list_remove (&tmp_vrf_list, OPC_LISTPOS_HEAD);

				/* The VRF table keeps track of its index for cross-reference.	*/
				vrf_info_ptr->vrf_table_array [vrf_index]->tbl_index = vrf_index;
				}
			module_data.vrf_info_ptr = vrf_info_ptr;
			}
		else
			{
			/* No valid VRFs on node. Free up memory allocated in this function.	*/
			op_prg_mem_free (vrf_info_ptr->intf_index_to_vrf_table_array);
			op_prg_mem_free (vrf_info_ptr);
			}
		
		/* Export the VRF Table										*/
		ip_vrf_table_export (OPC_NIL, 0);

		}
	
	FOUT;
	}

static IpT_Intf_Routing_Instance* 
ip_dispatch_intf_routing_instance_create (const char* intf_name, const char* vrf_name)
	{	
	static Boolean 				first_time = OPC_TRUE;
	static Pmohandle			pmh;
	IpT_Intf_Routing_Instance*	routing_instance_ptr;
	
	FIN (ip_intf_routing_instance_alloc (intf_name, vrf_name));
	
	if (first_time)
		{
		pmh = op_prg_pmo_define ("IpT_Intf_Routing_Instance", 16,sizeof (IpT_Intf_Routing_Instance));
		first_time = OPC_FALSE;
		}
	
	routing_instance_ptr = (IpT_Intf_Routing_Instance *) op_prg_pmo_alloc (pmh);
	
	routing_instance_ptr->intf_name = prg_string_copy (intf_name);
	routing_instance_ptr->routing_instance_name = prg_string_copy (vrf_name);
	
	FRET (routing_instance_ptr);
	}
	
	

static void
ip_vrf_table_export (void* PRG_ARG_UNUSED(data_ptr), int PRG_ARG_UNUSED (code))
	{
	/** Export the contents of the VRF table as an OT report.			**/
	FIN (ip_vrf_table_export (data_ptr, code));
		
	/* Check if this function is being called for the first time		*/
	/* by this model.													*/
	if (vrf_export_time_lptr == OPC_NIL)
		{
		/* Get the Export times for this table							*/
		vrf_export_time_lptr = Oms_Ot_Table_Export_Time_Get (module_data.module_id, "VRF Table");
		
		
		/* If the export times are not configured then return 			*/
		if (vrf_export_time_lptr == OPC_NIL)
			FOUT;
		
		/* Open the OT file where all the tables will be written		*/
		Oms_Ot_File_Open ();
		
		/* Trace for opening the file									*/
		if (op_prg_odb_ltrace_active ("vrf_ot") == OPC_TRUE)
			op_prg_odb_print_major ("Opening OT File", OPC_NIL);
		
		/* Schedule an interrupt to call the export table function 		*/
		/* at next export time configured								*/
		Oms_Ot_Export_Intrpt_Schedule (vrf_export_time_lptr, (OmsT_Table_Export_Proc) ip_vrf_table_export);
		}
	else
		{
		/* This is an interrupt where we need to export VRF table.	*/
        /* Export the VRF table for this router                		 */
        ip_ot_vrf_table_export (&module_data);

        /* Trace for exporting to the OT file                           */
        if (op_prg_odb_ltrace_active ("vrf_ot") == OPC_TRUE)
        	op_prg_odb_print_major ("Exporting VRF to OT File", OPC_NIL);
						
		/* Check if a next export needs to be scheduled?				*/
		if (op_prg_list_size (vrf_export_time_lptr) <= 0)
			{
			op_prg_mem_free (vrf_export_time_lptr);
			
			/* Close the OT file when all the tables are written		*/
			Oms_Ot_File_Close ();
		
			/* Trace for closing the file								*/
			if (op_prg_odb_ltrace_active ("vrf_ot") == OPC_TRUE)
				op_prg_odb_print_major ("Closing OT File", OPC_NIL);
		
			FOUT;
			}
		
		/* Schedule an interrupt to call the export table function 		*/
		/* at next export time configured								*/
		Oms_Ot_Export_Intrpt_Schedule (vrf_export_time_lptr, (OmsT_Table_Export_Proc) ip_vrf_table_export);
		}
	
	FOUT;
	}

static void
ip_misconfigured_node_check (void)	
	{
	int				num_streams;
	int				total_num_phy_intf = 0;
	int				num_cattr_rows;
	Objid			intf_info_comp_attr;
	List			proc_record_handle_list;
	int				record_handle_list_size;
	
	/** This function is used the check misconfigured node **/
	/** A mis-configured node is a node which has the      **/
	/** number of rows in the IP Parameters->Interface     **/
	/** information attribute less than the number of phy- **/
	/** sical interfaces connected to the ip module.       **/
	FIN (ip_misconfigured_node_check ());

	/* Find out the number of streams connected to this		*/
	/* module. The number of physical interfaces is one		*/
	/* less than  the number of streams (Excluding the 		*/
	/* stream connected to the ip_encap module).			*/
	num_streams = op_topo_assoc_count (module_data.module_id, OPC_TOPO_ASSOC_IN, OPC_OBJTYPE_STRM);
	total_num_phy_intf = num_streams - 1;
	
	/* Now find out the number of rows under the Interface Information		*/
	/* compound attribute.													*/
	op_ima_obj_attr_get (module_data.ip_parameters_objid, "Interface Information",
		&intf_info_comp_attr);
	num_cattr_rows = op_topo_child_count (intf_info_comp_attr, OPC_OBJTYPE_GENERIC);

	/* Make sure there are enough rows in the compound	*/
	/* attribute.										*/
	if (num_cattr_rows < total_num_phy_intf)
		{
		/* It is necessary to consider switch interfaces.	*/
		/* If this node contains a switch interface, the	*/
		/* number of rows under Interface Parameters will	*/
		/* be one less than the number of streams.			*/
		/* To find out whether RSM is present, check whether*/
		/* this node contains a module that registered 		*/
		/* itself as a bridge.								*/
		if (num_cattr_rows + 1 == total_num_phy_intf)
			{				
			/* Create a list that will contain found bridge modules.	*/
			op_prg_list_init (&proc_record_handle_list);
	
			/* Discover any bridge module inside this node.	*/
			oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list,
				"node objid", 	OMSC_PR_OBJID, 		module_data.node_id, 
				"protocol",		OMSC_PR_STRING,		"bridge", 
				OPC_NIL);
	
			/* Get the size of the list.	*/
			record_handle_list_size = op_prg_list_size (&proc_record_handle_list);

			while (op_prg_list_size (&proc_record_handle_list) > 0)
				op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);
		
			if (record_handle_list_size == 1)
				{
				FOUT;
				}
			
			}
		
		/* The number of rows in the compound attribute */
		/* is lesser. We cannot proceed with the 		*/
		/* simulation (We will run into a program abort	*/
		/* in the auto addressing package). Set the 	*/
		/* flag indicating this condition after 		*/
		/* writing a sim. log message.					*/
		ipnl_missing_rows_in_intf_info_log_write (num_cattr_rows, total_num_phy_intf);

		/* Set the flag which would ensure that we		*/
		/* terminate the simulation once all nodes have	*/
		/* performed this checked and logged the errors	*/
		misconfigured_node_exists = OPC_TRUE;
		}
	
	FOUT;
	}

static Objid
ip_dispatch_intf_info_objid_get (int intf_index, const IpT_Intf_Info_Attrs* intf_info_attrs_ptr,
	IpT_Interface_Status* intf_status_ptr, int* addr_index_ptr)
	{
	Objid					intf_info_objid;
	Boolean					intf_active;

	/** This function returns the Objid of the row under Interface		**/
	/** Information, Loopback Interfaces and Tunnel Interfaces attrs	**/
	/** corresponding to the specified interface.						**/
	/** Interfaces are returned in the following order.					**/
	/** 1. Aggregate interfaces.										**/
	/** 2. Physical interfaces.											**/
	/** 3. Loopback interfaces.											**/
	/** 4. Tunnel interfaces.											**/

	FIN (ip_dispatch_intf_info_objid_get (intf_index, intf_info_attrs_ptr, intf_status_ptr));
	
	/* Pick Aggregate interfaces first.									*/
	if (intf_index < intf_info_attrs_ptr->num_aggr_interfaces)
		{
		/* This is an aggregate interface.								*/
		/* Get the objid of the appropriate row under Aggregate			*/
		/* Interfaces													*/
		intf_info_objid = op_topo_child (intf_info_attrs_ptr->aggr_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC, intf_index);
		
		/* Set the interface status to group.							*/
		*intf_status_ptr = IpC_Intf_Status_Group;

		/* Get the interface status. For group interfaces that are		*/
		/* shutdown, just set the Routing Protocols string to None.		*/
		op_ima_obj_attr_get (intf_info_objid, "Status", &intf_active);

		if (!intf_active)
			{
			op_ima_obj_attr_set_str (intf_info_objid, "Routing Protocol(s)", "None");
			}

		/* The addr_index field is not used for logical interfaces.		*/
		*addr_index_ptr = IPC_ADDR_INDEX_IVNALID;
		}
	/* First find out whether this is a physical interface or a loopback*/
	/* interface. For physical interfaces the intf_index value will be	*/
	/* less than the number of physical intefaces.						*/
	else if (intf_index < intf_info_attrs_ptr->num_aggr_interfaces + intf_info_attrs_ptr->num_physical_interfaces)
		{
		/* This is a physical interface.								*/

		/* Subtract the number of aggregate intefaces from intf_index	*/
		/* to get the index of this row under Interface Information		*/
		intf_index -= intf_info_attrs_ptr->num_aggr_interfaces;

		/* Get the objid of the appropriate row under Interface			*/
		/* Information.													*/
		intf_info_objid = op_topo_child (intf_info_attrs_ptr->phys_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC, intf_index);

		/* If this is an endstaiton node, there will be no status		*/
		/* attribute. Assume it to be active. For gateway nodes read in	*/
		/* the value of the status attribute.							*/
		if (! module_data.gateway_status)
			{
			*intf_status_ptr = IpC_Intf_Status_Active;
			}
		else
			{
			/* Check whether it is active.								*/
			op_ima_obj_attr_get (intf_info_objid, "Status", &intf_active);

			/* Set the interface status appropriately.					*/
			*intf_status_ptr = (intf_active) ? IpC_Intf_Status_Active : IpC_Intf_Status_Shutdown;
			}
		
		/* Set the addr_index to the row number under Interface			*/
		/* Information.													*/
		*addr_index_ptr = intf_index;
		}
	else if (intf_index < (intf_info_attrs_ptr->num_aggr_interfaces + intf_info_attrs_ptr->num_physical_interfaces +
			intf_info_attrs_ptr->num_loopback_interfaces))
		{
		/* This is a loopback interface									*/
		/* Subtract the number of physical and aggregate intefaces from	*/
		/* intf_index to get the index of this attribute under			*/
		/* Loopback Interfaces											*/
		intf_index -= intf_info_attrs_ptr->num_aggr_interfaces + intf_info_attrs_ptr->num_physical_interfaces;

		/* Get the objid of the appropriate row under Loopback 			*/
		/* Interfaces													*/
		intf_info_objid = op_topo_child (intf_info_attrs_ptr->loop_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC, intf_index);

		/* Set the interface status to loopback.						*/
		*intf_status_ptr = IpC_Intf_Status_Loopback;

		/* Get the interface status. For loopback interfaces that are	*/
		/* shutdown, just set the Routing Protocols string to None.		*/
		op_ima_obj_attr_get (intf_info_objid, "Status", &intf_active);

		if (!intf_active)
			{
			op_ima_obj_attr_set (intf_info_objid, "Routing Protocol(s)", "None");
			}

		/* The addr_index field is not used for logical interfaces.		*/
		*addr_index_ptr = IPC_ADDR_INDEX_IVNALID;
		}
	else
		{
		/* This is a tunnel interface.									*/

		/* Get the index of this interface under the Tunnel Interfaces	*/
		/* attribute.													*/
		intf_index -= intf_info_attrs_ptr->num_aggr_interfaces + intf_info_attrs_ptr->num_physical_interfaces +
			intf_info_attrs_ptr->num_loopback_interfaces;

		/* Get the object ID of the appropriate row.					*/
		intf_info_objid = op_topo_child (intf_info_attrs_ptr->tunnel_intf_comp_attr_objid, OPC_OBJTYPE_GENERIC, intf_index);

		/* Set the interface status to loopback.						*/
		*intf_status_ptr = IpC_Intf_Status_Tunnel;

		/* Get the interface status. If it is shutdown, return 			*/
		/* OPC_OBJID_INVALID to indicate that this interface must be	*/
		/* ignored.														*/
		op_ima_obj_attr_get (intf_info_objid, "Status", &intf_active);

		if (!intf_active)
			{
			intf_info_objid = OPC_OBJID_INVALID;
			}

		/* Return the correct addr_index. It will be used to compute an	*/
		/* IP address for this node if the interface address is set to	*/
		/* "Unnumbered".												*/
		*addr_index_ptr = intf_index;
		}

	/* Return the objid of the interface.								*/
	FRET (intf_info_objid);
	}

static int
ip_dispatch_intf_compare_proc (const void* intf1_ptr, const void* intf2_ptr)
	{
	IpT_Interface_Mode			intf1_mode, intf2_mode;
	
	/** Function used to sort the interface list.						**/

	FIN (ip_dispatch_intf_compare_proc (intf1_ptr, intf2_ptr));

	/* The order in which the interfaces must appear is as follows		*/
	/* IPv4 only interfaces.											*/
	/* IPv4/IPv6 interfaces.											*/
	/* IPv6 only interfaces.											*/

	/* Get the interface modes of each interface.						*/
	intf1_mode = ip_rte_intf_mode_get ((const IpT_Interface_Info*) intf1_ptr);
	intf2_mode = ip_rte_intf_mode_get ((const IpT_Interface_Info*) intf2_ptr);

	/* Compare the interface modes directly.							*/
	if (intf1_mode < intf2_mode)
		{
		FRET (1);
		}
	else if (intf1_mode > intf2_mode)
		{
		FRET (-1);
		}
	else
		{
		FRET (0);
		}
	}

static void
ip_dispatch_secondary_ip_addresses_read (IpT_Interface_Info* iface_info_ptr, Objid iface_objid)
	{
	Objid	secondary_addr_comp_objid, ith_secondary_addr_objid;
	int		num_of_secondary_addr, ith_row, num_of_valid_secondary_addr = 0;
	char	secondary_ip_addr_str [IPC_ADDR_STR_LEN];
	char	secondary_ip_addr_mask_str [IPC_ADDR_STR_LEN];
	
	IpT_Address			secondary_ip_addr, secondary_subnet_mask;
	IpT_Address_Range*	ip_address_range_ptr = OPC_NIL;
	InetT_Address		inet_addr;

	/* Parse all secondary IP addresses of a given interface and	*/
	/* store each address/mask pair as a address_range element, in 	*/
	/* a vector maintained by interface description data structure.	*/
	FIN (ip_dispatch_secondary_ip_addresses_read (iface_info_ptr, iface_objid));

	/* Check if there are secondary addresses configured */
	op_ima_obj_attr_get (iface_objid, "Secondary Address Information", &secondary_addr_comp_objid);
	num_of_secondary_addr = op_topo_child_count (secondary_addr_comp_objid, OPC_OBJTYPE_GENERIC);
	
	/* Quit if there are none */
	if (num_of_secondary_addr == 0)
		{
		iface_info_ptr->sec_addr_tbl_ptr = OPC_NIL;
		FOUT;
		}
	
	/* Create an array to store the Secondary addresses.			*/
	iface_info_ptr->sec_addr_tbl_ptr = (IpT_Sec_Addr_Table*) op_prg_mem_alloc (sizeof (IpT_Sec_Addr_Table));
	iface_info_ptr->sec_addr_tbl_ptr->sec_addr_array =
		(IpT_Secondary_Address*) op_prg_mem_alloc (num_of_secondary_addr * sizeof (IpT_Secondary_Address));
	
	/* Iterate through each entry and store them	*/
	for (ith_row = 0; ith_row < num_of_secondary_addr; ith_row ++)
		{
		/* Handle to each row attribute */
		ith_secondary_addr_objid = op_topo_child (secondary_addr_comp_objid, OPC_OBJTYPE_GENERIC, ith_row);
		
		/* Parse address */
		op_ima_obj_attr_get (ith_secondary_addr_objid, "Address", &secondary_ip_addr_str);
		
		if (!strcmp (secondary_ip_addr_str, "Specify..."))
			continue;
		
		/* Convert string to address DS */
		secondary_ip_addr = ip_address_create (secondary_ip_addr_str);

		/* Parse subnet-mask */
		op_ima_obj_attr_get (ith_secondary_addr_objid, "Subnet Mask", &secondary_ip_addr_mask_str);

		/* If the subnet mask was auto assigned, use the default*/
		/* subnet mask.											*/
		if (!strcmp (secondary_ip_addr_mask_str, IPC_AUTO_ADDRESS))
			secondary_subnet_mask = ip_default_smask_create (secondary_ip_addr);
		else
			secondary_subnet_mask = ip_address_create (secondary_ip_addr_mask_str);
		
		/* Store the address and mask in the secondary address table.	*/
		
		ip_address_range_ptr = ip_address_range_create (secondary_ip_addr, secondary_subnet_mask);
		
		/* Store the address_range DS in the vector */
		iface_info_ptr->sec_addr_tbl_ptr->sec_addr_array[num_of_valid_secondary_addr].ip_addr_range.address = secondary_ip_addr;
		iface_info_ptr->sec_addr_tbl_ptr->sec_addr_array[num_of_valid_secondary_addr].ip_addr_range.subnet_mask = secondary_subnet_mask;

		/* Also store the address in Inet format.						*/
		iface_info_ptr->sec_addr_tbl_ptr->sec_addr_array[num_of_valid_secondary_addr].inet_addr_range =
			inet_ipv4_address_range_create (secondary_ip_addr, secondary_subnet_mask);

		/* Register the Ip address of this subinterface in the global	*/
		/* Ip table used to associate Ip addresses with lower layer		*/
		/* addresses. This table is managed by the nato sub-package.	*/
		/* the Ip routing process makes this package available to other	*/
		/* processes like ARP through the process registry				*/
		inet_addr = inet_address_from_ipv4_address_create (secondary_ip_addr);
		ip_rtab_local_addr_register (&inet_addr, &module_data);

		/* Like the global table for interface addresses, another		*/
		/* global table is is maintained for all the possible Ip 		*/
		/* networks in the model. Register the network address of this	*/
		/* subinterface in that table.									*/
		inet_addr = inet_address_from_ipv4_address_create
			(ip_address_mask (secondary_ip_addr, secondary_subnet_mask));
		ip_rtab_local_network_register (&inet_addr);		
		
		/* Keep count of valid secondary addresses	*/
		num_of_valid_secondary_addr++;
		}
	
	if (num_of_valid_secondary_addr)
		{
		/* Set the number of secondary addresses appropriately.				*/
		iface_info_ptr->sec_addr_tbl_ptr->num_sec_addresses = num_of_valid_secondary_addr;
		}
	else
		{
		/* If there no valid secondary addresses, destroy the array			*/
		op_prg_mem_free (iface_info_ptr->sec_addr_tbl_ptr->sec_addr_array);
		op_prg_mem_free (iface_info_ptr->sec_addr_tbl_ptr);
		}
	
	FOUT;
	}

static void
ip_cmn_rte_table_export (void* PRG_ARG_UNUSED(data_ptr), int code )
	{
	Boolean						ra_export_status = OPC_FALSE;
	
	/** Export the contents of the route table to an ot file.			*/
	FIN (ip_cmn_rte_table_export (data_ptr, code));
	
	/* Check if this function is being called for the first time		*/
	/* by this model.													*/
	if (crt_export_time_lptr == OPC_NIL)
		{
		/* Get the Export times for this table							*/
		crt_export_time_lptr = Oms_Ot_Table_Export_Time_Get (module_data.module_id, "IP Forwarding Table");
		
		/* Also get the RA Info export status							*/
		ra_export_status = ip_dispatch_ra_export_status_get ();
		if ((ra_export_status != OPC_FALSE) || (routing_table_import_export_flag == IP_RTE_TABLE_EXPORT))
			{
			/* If Reachability Analysis (RA) Info export status is set,	*/
			/* or if simulation attrib routing table export flag is set */
			/* then export the IP Forwarding Table at the end of sim.	*/

			/* Create an empty list to hold the export times if it		*/
			/* doesn't already exist.									*/
			if (crt_export_time_lptr == OPC_NIL)
				crt_export_time_lptr = op_prg_list_create ();
			
			/* Call the function that will add End of Sim to the list of*/
			/* export times if does not already exist.					*/
			Oms_Ot_Table_Export_Time_Eos_Add (crt_export_time_lptr);
			}
		/* If the export times are not configured then return 			*/
		else if (crt_export_time_lptr == OPC_NIL)
			{
			FOUT;
			}
		
		/* Open the OT file where all the tables will be written		*/
		Oms_Ot_File_Open ();
		
		/* Trace for opening the file									*/
		if (op_prg_odb_ltrace_active ("ip_ot") == OPC_TRUE)
			{
			op_prg_odb_print_major ("Opening OT File for IP Forwarding Table export", OPC_NIL);
			}
		
		/* Schedule an interrupt to call the export table function 		*/
		/* at next export time configured								*/
		Oms_Ot_Export_Intrpt_Schedule (crt_export_time_lptr, (OmsT_Table_Export_Proc) ip_cmn_rte_table_export);
		}
	else
		{
		/* This is an interrupt where we need to export routing table.	*/
		/* Call the function to export Common rte table to OT reports	*/
		ip_ot_cmn_rte_table_export (&module_data, code);
			
		/* Trace for exporting to the OT file							*/
		if (op_prg_odb_ltrace_active ("ip_ot") == OPC_TRUE)
			{
			op_prg_odb_print_major ("Exporting to IP Forwarding Table OT File", OPC_NIL);
			}
		
		/* Check if a next export needs to be scheduled?				*/
		if (op_prg_list_size (crt_export_time_lptr) <= 0)
			{
			/* Free the export time list								*/
			op_prg_mem_free (crt_export_time_lptr);
			
			/* Close the OT file when all the tables are written		*/
			Oms_Ot_File_Close ();
		
			/* Trace for closing the file								*/
			if (op_prg_odb_ltrace_active ("ip_ot") == OPC_TRUE)
				{
				op_prg_odb_print_major ("Closing OT File after IP Forwarding Table export", OPC_NIL);
				}
		
			FOUT;
			}
		
		/* Schedule an interrupt to call the export table function 		*/
		/* at next export time configured								*/
		Oms_Ot_Export_Intrpt_Schedule (crt_export_time_lptr, (OmsT_Table_Export_Proc) ip_cmn_rte_table_export);
		}

	FOUT;
	}

static IpT_Tunnel_GRE_Params*
ip_dispatch_tunnel_gre_params_create (void)
	{
	
	/** Allocate memory for a data structure to hold GRE-specific tunnel	**/
	/** parameters. A pooled memory handle will be used for efficiency		**/
	/** and easy tracking of memory.										**/
	
	static Boolean					first_time		= OPC_TRUE;
	static Pmohandle				gre_params_pmh;		
	IpT_Tunnel_GRE_Params*			gre_params_ptr	= OPC_NIL;
	
	FIN (ip_dispatch_tunnel_gre_params_create ());
	
	if (first_time)
		{
		/* The third argument is then number of units of the object requested	*/
		/* from the OS by the simulation kernel. Since the number of tunnels 	*/
		/* is expected to be low in a normal network, the quantum of request is	*/
		/* a small number (8).													*/
		gre_params_pmh = op_prg_pmo_define ("ip_dispatch: GRE Parameters",
			sizeof (IpT_Tunnel_GRE_Params), 8);
		
		first_time = OPC_FALSE;
		}
	
	gre_params_ptr = (IpT_Tunnel_GRE_Params *) op_prg_pmo_alloc (gre_params_pmh);
	
	FRET (gre_params_ptr);
	}
		
static IpT_Interface_Info*
ip_dispatch_find_intf_with_addr (InetT_Address ip_addr, List* intf_table_ptr)
	{
	
	/** Loop through the list of interfaces and find the 	**/
	/** interface that contains this address.				**/

	int						num_interfaces, num_subinterfaces;
	int						i, j;
	IpT_Interface_Info*		ith_intf_ptr;
	IpT_Interface_Info*		jth_subintf_ptr;
	
	FIN (ip_dispatch_find_intf_with_addr (ip_addr, intf_table_ptr));
	
	/* Obtain the number of the interfaces.					*/
	num_interfaces = op_prg_list_size (intf_table_ptr);	
	for (i = 0; i < num_interfaces; i++)
		{
		ith_intf_ptr = (IpT_Interface_Info *) op_prg_list_access (intf_table_ptr, i);
		
		/* Check whether the given address is the address 	*/
		/* of the interface or one of its secondary			*/
		/* interfaces.										*/
		if (inet_rte_intf_has_local_address (ip_addr, ith_intf_ptr))
			{
			FRET (ith_intf_ptr);
			}

		/* If no match found, search the subinterfaces of	*/
		/* the interface.									*/
		num_subinterfaces = ip_rte_num_subinterfaces_get (ith_intf_ptr);	
		for (j = 0; j < num_subinterfaces; j++)
			{
			/* Call the same search function this time for	*/
			/* the j'th subinterface.						*/
			jth_subintf_ptr = ip_rte_ith_subintf_info_get (ith_intf_ptr, j);
			if (inet_rte_intf_has_local_address (ip_addr, jth_subintf_ptr))
				{				
				/* In case of match return the subinterface.*/
				FRET (jth_subintf_ptr);
				}
			}
		}
	
	FRET (OPC_NIL);
	}
		
static void
ip_dispatch_tunnel_passenger_protocols_read (Objid tunnel_info_objid, IpT_Tunnel_Info* tunnel_info_ptr)
	{
	
	/** This function reads the enabled passenger protocols on	**/
	/** the given tunnel and sets the appropriate flags in the	**/
	/** tunnel information object. It checks the tunnel mode	**/
	/** to ensure that invalid protocols are not enabled for a	**/
	/** given tunnel mode.										**/
	List*			proto_str_lptr 	= OPC_NIL;
	char*			proto_str		= OPC_NIL;
	char			attr_str [256];
	
	FIN (ip_dispatch_tunnel_passenger_protocols_read (tunnel_info_objid, tunnel_info_ptr));
	
	switch (tunnel_info_ptr->mode)
		{
		/* If the tunnel mode is one of the IPv6 modes, then the only	*/
		/* passenger protocol possible is IPv6.							*/
		case IpC_Tunnel_Mode_IPv6_Manual:
		case IpC_Tunnel_Mode_IPv6_Auto:
		case IpC_Tunnel_Mode_IPv6_6to4:
			IP_TUNNEL_PASSENGER_PROTOCOL_ENABLE_IPV6 (tunnel_info_ptr);
			break;
		
		/* If the tunnel mode is IP-IP, then IPv4 is the only option.	*/
		case IpC_Tunnel_Mode_IPIP:
			IP_TUNNEL_PASSENGER_PROTOCOL_ENABLE_IPV4 (tunnel_info_ptr);
			break;
		
		/* In case of GRE tunnels, IPv4 and IPv6 are possible.	*/
		case IpC_Tunnel_Mode_GRE:
			op_ima_obj_attr_get (tunnel_info_objid, "Passenger Protocol(s)", attr_str);
			proto_str_lptr = op_prg_str_decomp (attr_str, ",");
			while (op_prg_list_size (proto_str_lptr) > 0)
				{
				proto_str = (char *) op_prg_list_remove (proto_str_lptr, OPC_LISTPOS_HEAD);
				if (strcmp (proto_str, "IPv4") == 0)
					{
					IP_TUNNEL_PASSENGER_PROTOCOL_ENABLE_IPV4 (tunnel_info_ptr);
					}
				else if (strcmp (proto_str, "IPv6") == 0)
					{
					IP_TUNNEL_PASSENGER_PROTOCOL_ENABLE_IPV6 (tunnel_info_ptr);					
					}
				
				op_prg_mem_free (proto_str);
				}
			op_prg_mem_free (proto_str_lptr);
			break;
			
   		default:
			op_sim_end ("ip_dispatch_tunnel_passenger_protocols_read", 
				"Unknown tunnel mode", "", "");
			}
	
	FOUT;
	}
			

static void
ip_dispatch_tunnel_packet_process (Packet* ip_pkptr, IpT_Dgram_Fields* pkt_fields_ptr, 
	Ici* intf_ici_ptr, 	IpT_Rte_Ind_Ici_Fields*	intf_ici_fdstruct_ptr)	
	{
	/** Decapsulate the packet that has come in on the tunnel	**/
	/** and deliver the inner packet back to this node so that	**/
	/** it may get routed to its final destination.				**/
	
	int								input_tunnel_index;
	Ici*							ip_arp_ind_v4_ici_ptr 		= OPC_NIL;
	Packet*							inner_pkptr					= OPC_NIL;
	Packet*							gre_pkptr					= OPC_NIL;
	IpT_Interface_Info*				intf_info_ptr 				= OPC_NIL;
	double							decapsulation_delay 		= 0.0;	
	IpT_Dgram_Fields*				inner_pk_fields_ptr 		= OPC_NIL;
	char							str0 [512], str1 [512];	
	
	FIN (ip_dispatch_tunnel_packet_process (ip_pkptr, pkt_fields_ptr, intf_iciptr, intf_icifdstruct_ptr));
	
	/* Look for a local tunnel interface to the source 		*/
	/* address of the IPv4 packet. If we find a match, use	*/
	/* it as the input interface for the inner packet.		*/
	input_tunnel_index = ip_rte_tunnel_to_dest_find (&module_data, pkt_fields_ptr->src_addr,
		pkt_fields_ptr->protocol);
	
	/* For IPv6 tunnels, if a matching interface is found, 	*/
	/* make sure that IPv6 is enabled on it.				*/
	if ((pkt_fields_ptr->protocol == IpC_Protocol_IPv6) &&
		(IPC_TUNNEL_INTF_INDEX_NOT_FOUND != input_tunnel_index) &&
		(! ip_rte_intf_ipv6_active (inet_rte_intf_tbl_access (&module_data, input_tunnel_index))))
		{
		/* We found a matching tunnel, but IPv6 is not		*/
		/* enabled on it. Set the tunnel index to an invalid*/
		/* value to indicate a tunnel could not be found.	*/
		input_tunnel_index = IPC_TUNNEL_INTF_INDEX_NOT_FOUND;
		}
	
	/* If a matching tunnel interface that can act as the	*/
	/* receiver of this packet is found, then we may need	*/
	/* to drop out-of-sequence datagrams, depending on the	*/
	/* tunnel configuration.								*/
	if (input_tunnel_index != IPC_TUNNEL_INTF_INDEX_NOT_FOUND)
		{
		intf_info_ptr = inet_rte_intf_tbl_access (&module_data, input_tunnel_index);
		
		/* Ensure that the modes of the incoming and the outgoing tunnels are	*/
		/* the same. If not, destroy the packet and flag an error.				*/
		/* From the header fields of the tunnel packet, only some of the		*/
		/* mismatches can be checked.											*/
		/*		- Tunnel is GRE but incoming packet is not.						*/
		/*		- Incoming packet is GRE but tunnel is not.						*/
		/*		- Tunnel is an IPv6 tunnel but incoming packet is not.			*/
		/*		- Incoming packet is IPv6 but tunnel does not support IPv6		*/
		if (((intf_info_ptr->tunnel_info_ptr->mode == IpC_Tunnel_Mode_GRE) &&
				(pkt_fields_ptr->protocol != IpC_Protocol_GRE)) ||
			((intf_info_ptr->tunnel_info_ptr->mode != IpC_Tunnel_Mode_GRE) &&
				(pkt_fields_ptr->protocol == IpC_Protocol_GRE)) ||
			(((intf_info_ptr->tunnel_info_ptr->mode == IpC_Tunnel_Mode_IPv6_Manual) ||
				(intf_info_ptr->tunnel_info_ptr->mode == IpC_Tunnel_Mode_IPv6_Auto) ||
				(intf_info_ptr->tunnel_info_ptr->mode == IpC_Tunnel_Mode_IPv6_6to4)) &&
				(pkt_fields_ptr->protocol != IpC_Protocol_IPv6)) ||
			((intf_info_ptr->tunnel_info_ptr->mode == IpC_Tunnel_Mode_IPIP) &&
				(pkt_fields_ptr->protocol == IpC_Protocol_IPv6)))
			{
			/* Write tunnel stats. Last argument is set to true if packet is	*/
			/* to be dropped.													*/	
			ip_dispatch_tunnel_rcvd_stats_write (intf_info_ptr->tunnel_info_ptr, ip_pkptr, decapsulation_delay, OPC_TRUE);		
			
			ip_rte_dgram_discard (&module_data, ip_pkptr, intf_ici_ptr,
				"Tunnel modes of peer tunnels do not match");
			ip_nl_tunnel_modes_mismatch_log_write (intf_info_ptr->full_name, 
				ip_higher_layer_proto_name_find (pkt_fields_ptr->protocol));
			FOUT;
			}
		
		if ((intf_info_ptr->tunnel_info_ptr->gre_params_ptr != OPC_NIL) &&
			(intf_info_ptr->tunnel_info_ptr->gre_params_ptr->sequence_dgrams == OPC_TRUE))
			{
			
			/* Compare the max sequence number seen so far against the	*/
			/* sequence number of the datagram to make a decision.		*/
			if (intf_info_ptr->tunnel_info_ptr->gre_params_ptr->max_seq_number < pkt_fields_ptr->ident)
				{
				intf_info_ptr->tunnel_info_ptr->gre_params_ptr->max_seq_number = pkt_fields_ptr->ident;
				}
			else
				{
				/* Write tunnel stats. Last argument is set to true if packet is	*/
				/* to be dropped.													*/	
				ip_dispatch_tunnel_rcvd_stats_write (intf_info_ptr->tunnel_info_ptr, ip_pkptr, decapsulation_delay, OPC_TRUE);		
			
				ip_rte_dgram_discard (&module_data, ip_pkptr, intf_ici_ptr, 
					"GRE tunnel dropping out-of-sequence datagram");
				ip_nl_tunnel_gre_sequence_log_write (intf_info_ptr->full_name);
				
				FOUT;
				}
			}
		
		/* User may have configured a decapsulation delay for this interface.	*/
		
		decapsulation_delay = 
			oms_dist_nonnegative_outcome (intf_info_ptr->tunnel_info_ptr->decapsulation_delay);		
		}
	
	/* This is an IPv4 packet containing an encapsulated	*/
	/* packet. Decapsulate the inner packet and	deliver		*/
	/* it to this module again so that it will be handled	*/
	/* appropriately.										*/
	op_pk_nfd_get (ip_pkptr, "data", &inner_pkptr);
	
	/* If the tunnel is a GRE tunnel, then this packet is	*/
	/* a GRE packet. The payload is encapsulated inside 	*/
	/* this packet.											*/
	if (pkt_fields_ptr->protocol == IpC_Protocol_GRE)
		{
		gre_pkptr = inner_pkptr;
		op_pk_nfd_get (gre_pkptr, "payload", &inner_pkptr);
		}
	
	/* Make sure that the payload destination is not equal to the incoming	*/
	/* tunnel source, which is the same as the outgoing tunnel destination.	*/
	/* This check is present in order to handle routing loops.				*/
	/* This check must be performed only after the inner packet is taken	*/
	/* out from the GRE packet (if the tunnel is a GRE tunnel).				*/
	
	op_pk_nfd_access (inner_pkptr, "fields", &inner_pk_fields_ptr);

	/* Set the fields back in the original packet so that the stats (for		*/
	/* explicit packets as well as background packets) are written correctly.	*/
	if (pkt_fields_ptr->protocol == IpC_Protocol_GRE)
		{
		op_pk_nfd_set (gre_pkptr, "payload", inner_pkptr);
		inner_pkptr = gre_pkptr;
		}

	op_pk_nfd_set (ip_pkptr, "data", inner_pkptr);

	if ((input_tunnel_index != IPC_TUNNEL_INTF_INDEX_NOT_FOUND) &&
		(inet_address_equal (inner_pk_fields_ptr->dest_addr, intf_info_ptr->tunnel_info_ptr->dest_addr)))
		{
		/* Write tunnel stats. Last argument is set to true if packet is	*/
		/* to be dropped. 													*/	
		ip_dispatch_tunnel_rcvd_stats_write (intf_info_ptr->tunnel_info_ptr, ip_pkptr, decapsulation_delay, OPC_TRUE);		
	
		ip_rte_dgram_discard (&module_data, ip_pkptr, intf_ici_ptr, 
			"Routing loop detected at tunnel destination");
		ip_nl_tunnel_routing_loop_dest_log_write (intf_info_ptr->full_name);
	
		FOUT;
		}
	
	/* Write tunnel stats for successful packets.								*/
	/* Stats can be written only if an incoming tunnel intf has been found.		*/
	/* Total end-to-end delay (for stats) must include the decapsulation delay.	*/
	/* The last arg must be set to FALSE if the packet is NOT being dropped.	*/
	if (input_tunnel_index != IPC_TUNNEL_INTF_INDEX_NOT_FOUND)
		{
		ip_dispatch_tunnel_rcvd_stats_write (intf_info_ptr->tunnel_info_ptr, ip_pkptr, decapsulation_delay, OPC_FALSE);		
		}

	/* Create an ip_arp_ind_v4 ici to accompany the packet	*/
	ip_arp_ind_v4_ici_ptr = op_ici_create ("ip_arp_ind_v4");
	
	/* Set the tunnel index field in the ici.				*/
	op_ici_attr_set (ip_arp_ind_v4_ici_ptr, "tunnel_index", input_tunnel_index);
	
	/* Install the Ici.										*/
	op_ici_install (ip_arp_ind_v4_ici_ptr);
	
	if (op_sim_debug () && op_prg_odb_ltrace_active ("ip_tunnel"))
		{
		sprintf (str0, "Interface: %s\t Protocol: %s", 
			intf_info_ptr->full_name, ip_higher_layer_proto_name_find (pkt_fields_ptr->protocol));
		sprintf (str1, "Decapsulation Delay (sec):  %f", decapsulation_delay);
		op_prg_odb_print_major ("Receiving packet on tunnel", str0, str1, OPC_NIL);
		}

	/* Remove the outer packet(s) and deliver the inner packet.	*/
	op_pk_nfd_get (ip_pkptr, "data", &inner_pkptr);
	
	/* If the tunnel is a GRE tunnel, then this packet is	*/
	/* a GRE packet. The payload is encapsulated inside 	*/
	/* this packet.											*/
	if (pkt_fields_ptr->protocol == IpC_Protocol_GRE)
		{
		gre_pkptr = inner_pkptr;
		op_pk_nfd_get (gre_pkptr, "payload", &inner_pkptr);
		op_pk_destroy (gre_pkptr);
		}
	
	/* Deliver the inner packet to this module again.		*/
	/* Use the same input stream on which the packet was	*/
	/* received. We do not need to handle the case where	*/
	/* the input stream in set to IpC_Pk_Instrm_Child,		*/
	/* since the outer packet could not have been created by*/
	/* this node itself unless we have a tunnel from a node */
	/* to itself!!! Such cases should be handled elsewhere.	*/
	op_pk_deliver_delayed (inner_pkptr, module_data.module_id, 
		intf_ici_fdstruct_ptr->instrm, decapsulation_delay);
	
	/* Uninstall the ici.									*/
	op_ici_install (OPC_NIL);
	
	/* Destroy the outer packet and the accompanying ici.	*/
	op_pk_destroy (ip_pkptr);
	ip_rte_intf_ici_destroy (intf_ici_ptr);
	
	FOUT;
	}
			
static void 
ip_dispatch_send_packet_up (Packet* ip_pkptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr)
	{
	IpT_Dgram_Fields*		pkt_fields_ptr	= OPC_NIL;
	int						source_port, dest_port;
	Ici*					rte_intf_ici_ptr = OPC_NIL;

	/** Send packet to ip_encap	layer **/	
	FIN (ip_dispatch_send_packet_up (Packet* ip_pkptr));
	
	/* Forward the complete packet to the higher layer.		*/
	if (ip_node_is_cloud (&module_data))
		{
		(*module_data.cloud_send_proc)(module_data.cloud_send_proc_info_ptr, 
			ip_pkptr, module_data.outstrm_to_ip_encap, OPC_DBL_INFINITY,
			IpC_Intf_Type_Unspec, INETC_ADDRESS_INVALID, INETC_ADDRESS_INVALID, 0, 0);
		}
	else
		{
		/* Send the packet as a forced interrupt so that	*/
		/* the contents of the ICI are not overwritten.		*/
		
		/* Obtain a handle on the information carried in the "fields" */
		/* data structure in the incoming IP datagram. */
		op_pk_nfd_access (ip_pkptr, "fields", &pkt_fields_ptr);
		
		/* Check if the address this packet is destined for is a multicast address */
		/* If it is destined for a multicast address, then check to see if this    */
		/* host supports multicasting at this address on this port.  If it doesn't */
		/* then destroy the packet, otherwise forward it to the next layer.        */
		if (inet_address_is_multicast (pkt_fields_ptr->dest_addr) == OPC_TRUE)
			{
			/* Get the destination application port from the UDP/TCP header	*/
			/* inside the IP datagram.										*/
			ip_qos_application_type_get (ip_pkptr, pkt_fields_ptr, &source_port, &dest_port);
			
			if (inet_address_multicast_accept (&module_data, pkt_fields_ptr->dest_addr,
				intf_ici_fdstruct_ptr->intf_recvd_index, dest_port) == OPC_FALSE
				&& OPC_FALSE   //  JPH SMF - temp hack to force delivery of multicast packets
				)
				{
				/* Destroy associated ICI */
				rte_intf_ici_ptr = op_pk_ici_get (ip_pkptr);
				ip_rte_intf_ici_destroy (rte_intf_ici_ptr);
				
				/* Destroy the packet */
				op_pk_destroy (ip_pkptr);
				}
			else
				{
				op_pk_send (ip_pkptr, module_data.outstrm_to_ip_encap);
				}
			}
		else
			{
			op_pk_send (ip_pkptr, module_data.outstrm_to_ip_encap);
			}
		}

	FOUT;
	}
	
static void
ip_dispatch_higher_layer_rsvp_forward (Packet* ip_pkptr, Ici* intf_ici_ptr)	
	
	{
	/** Send the packet to higher layer, if RSVP is enabled on this node.	**/
	
	FIN (ip_dispatch_higher_layer_rsvp_forward (ip_pkptr, intf_ici_ptr));
		
	/** The multicast packet is for the RSVP layer.	**/
	
	if ( (module_data.rsvp_status == OPC_TRUE) || (module_data.rsvp_te_status == OPC_TRUE))
		{
		/** RSVP is enabled on the node.		**/
	   	/** Or it is being used to set up LSPs.	**/
		
		/* Forward the packet to the higher layer   */
		op_pk_send (ip_pkptr, module_data.outstrm_to_ip_encap);
		}
	else
		{
		/* Destroy the packet.	*/ 
		ip_rte_dgram_discard (&module_data, ip_pkptr, intf_ici_ptr, "RSVP not enabled");
		
		/* Write a log message.	*/
		rsvpnl_no_intf_support ();
		}
	
	FOUT;
	}
			
static void
ip_dispatch_bgutil_packet_process (Packet* pk_ptr, Ici* intf_ici_ptr, InetT_Address* dest_addr_ptr)
	{
	Packet*							bgutil_pkptr 		= OPC_NIL;
	Packet*				            demand_pkptr 		= OPC_NIL;
	OmsT_Bgutil_Tracer_Packet_Info*	trc_pkt_info_ptr 	= OPC_NIL;
	char							dest_node_name [512];
	
	/** Process the background utilization packet.	**/
	FIN (ip_dispatch_bgutil_packet_process (pk_ptr, intf_ici_ptr, dest_addr_ptr));

	/* This packet was generated by the oms_basetraf_src proceess.	*/
	/* We will destroy the packet here.								*/
	
	/* If this is a policy checker demand then output				*/
	/* the information that the packet is being dropped 			*/	
	/* What happend to the flow in this life cycle					*/
	if (op_pk_encap_flag_is_set (pk_ptr, OMSC_SECURITY_ENCAP_FLAG_INDEX))
		{
		/* Write the ot log											*/	
		ip_ot_security_demand_results_log (pk_ptr, module_data.node_name, OPC_TRUE, OPC_NIL, OPC_NIL);

		/* This is a tracer packet destined for here. The packet	*/
		/* has served its purpose, so instead of forwarding it to	*/
		/* the oms_basetraf_src model, we can safely destroy the	*/
		/* packet here. Write the ETE route before destroying		*/
		/* the tracer packet. Drill to get the actual tracer packet	*/
		op_pk_encap_pk_get (pk_ptr, (char *)"bgutil_tracer", &bgutil_pkptr);
		
		/* Handle processing of the incoming tracer packet.	*/
		if (bgutil_pkptr != OPC_NIL)
			{
			/* Get the tracer packet information.  */
			op_pk_nfd_get (bgutil_pkptr, "trac_pkt_info_ptr", &trc_pkt_info_ptr);
			
			/* Check if this packet has any route information that needs recording.	*/
			/* Check if we have file in which to write data	*/
			/* Record information contained in this list.	*/
			if ((trc_pkt_info_ptr != OPC_NIL) &&
				(op_prg_list_size (&trc_pkt_info_ptr->route_data_list) > 0) &&
				 (trc_pkt_info_ptr->rte_file_handle != OPC_NIL))
				oms_basetraf_rr_info_file_write (trc_pkt_info_ptr->rte_file_handle, &trc_pkt_info_ptr->route_data_list,  OPC_NIL);
			}
		}
		
	/* Check here if the packet to be forwarded to the higher		*/
	/* layer contains a backgroung traffic tracer packet.			*/
	/* (destination to source packets do not contain a tracer pk).	*/
	if (op_pk_encap_flag_is_set (pk_ptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX) == OPC_TRUE)
		{
		/* This is a tracer packet destined for here. The packet	*/
		/* has served its purpose, so instead of forwarding it to	*/
		/* the oms_basetraf_src model, we can safely destroy the		*/
		/* packet here. Write the ETE statistic before destroying	*/
		/* the tracer packet. Drill to get the actual tracer packet	*/
		op_pk_encap_pk_get (pk_ptr, (char *)"bgutil_tracer", &bgutil_pkptr);
		
		/* Handle processing of the incoming tracer packet.	*/
		if (bgutil_pkptr != OPC_NIL)
			{			
			if (inet_address_is_multicast (*dest_addr_ptr) == OPC_TRUE)
				{
				/* The packet was received with multicast dest address.	*/
				/* Copy the dest node name to the string.				*/
				oms_tan_hname_get (module_data.node_id, dest_node_name);
		
				oms_basetraf_pkt_dest_process (bgutil_pkptr, 
					module_data.local_tracer_in_ete_hndl,
					module_data.globl_tracer_ete_delay_hndl, dest_node_name);
				}
			else
				{
				oms_basetraf_pkt_dest_process (bgutil_pkptr, 
					module_data.local_tracer_in_ete_hndl,
					module_data.globl_tracer_ete_delay_hndl, OPC_NIL);				
				}
			}
		}

	if (op_pk_encap_flag_is_set (pk_ptr, OMSC_DEMAND_ENCAP_FLAG_INDEX) == OPC_TRUE)
		{
		/* This is a demand packet destined for here. The packet	*/
		/* has served its purpose, so instead of forwarding it to	*/
		/* the oms_basetraf_src model, we can safely destroy the	*/
		/* packet here. Write the ETE statistic before destroying	*/
		/* the demand packet. Drill to get the actual demand packet	*/
		op_pk_encap_pk_get (pk_ptr, (char *)"demand_info", &demand_pkptr);
		
		/* Handle processing of the incoming demand packet.	*/
		if (demand_pkptr != OPC_NIL)
			oms_basetraf_demand_pkt_dest_handle (demand_pkptr,
				module_data.local_tracer_in_ete_hndl,
				module_data.globl_tracer_ete_delay_hndl); 
		}

	/* Destroy the associated interface ici which we obtained above. */
	ip_rte_intf_ici_destroy (intf_ici_ptr);
	
	/* Now destroy the IP packet.	*/
	op_pk_destroy (pk_ptr);	

	FOUT;
	}

static void
ip_dispatch_incoming_packet_info_get (Packet* pk_ptr, IpT_Dgram_Fields** pkt_fields_pptr,
					Ici** intf_ici_pptr, IpT_Rte_Ind_Ici_Fields** intf_ici_fdstruct_pptr,
					Packet** ip_pptr, Boolean* ip_mcast_data_pkt_on_rte_ptr)
	{
	
	/** Read the packet header and the ICI fields.		**/
	/** Determine whether this packet is a multicast	**/
	/** packet that needs to be forwarded by this node.	**/
	
	FIN (ip_dispatch_incoming_packet_info_get (args));
	
	*pkt_fields_pptr = ip_dgram_fields_access (pk_ptr);

	if ((ip_node_is_mcast_router (&module_data)) && 
		(inet_address_is_multicast ((*pkt_fields_pptr)->dest_addr) == OPC_TRUE) && 
		((*pkt_fields_pptr)->protocol != IpC_Protocol_Rsvp))
		{
		/* Get the ICI associated with the packet. If no ICI exists,	*/
		/* report an error message and terminate the simulation.		*/
		*intf_ici_pptr = op_pk_ici_get (pk_ptr);
	   	if (*intf_ici_pptr == OPC_NIL)
			{
			op_sim_end ("Error in IP routing process model (ip_dispatch): ",
						"No ip_rte_ind_v4 ICI has been associated with the",
						"multicast packet.", OPC_NIL);			
			}

		/* Get the "rte_info_fields" field from the ICI					*/
		op_ici_attr_get (*intf_ici_pptr, "rte_info_fields", intf_ici_fdstruct_pptr);

		/* If the interface on which the multicast packet was received is not */
		/* specified in the ICI, its an error. Report an error message and	  */
		/* terminate the simulation.										  */
		if ((*intf_ici_fdstruct_pptr)->intf_recvd_index == -1)
			{
			op_sim_end ("Error in IP routing process model (ip_dispatch): ",
						"The interface on which the multicast packet was received is",
						"not specified in the packet's ICI.", OPC_NIL);
			}

		/* If the router did not join the multicast address, we set the flag */
		/* ip_mcast_data_pkt_on_rte to OPC_TRUE so that the multicast packets*/
		/* are not reassembled before sending it to the child process.		 */
		if (inet_address_multicast_accept (&module_data, (*pkt_fields_pptr)->dest_addr, 
			(*intf_ici_fdstruct_pptr)->intf_recvd_index, IP_MCAST_NO_PORT) == OPC_FALSE)
			{
			*ip_mcast_data_pkt_on_rte_ptr = OPC_TRUE;
			*ip_pptr = pk_ptr;
			}
		}
	else
		{
		/* Get the ICI associated with the packet. If no ICI exists,	*/
		/* report an error message and terminate the simulation.		*/
		*intf_ici_pptr = op_pk_ici_get (pk_ptr);
	   	if (*intf_ici_pptr == OPC_NIL)
			{
			op_sim_end ("Error in IP routing process model (ip_dispatch): ",
						"No ip_rte_ind_v4 ICI has been associated with the",
						"packet.", OPC_NIL);			
			}

		/* Get the "rte_info_fields" field from the ICI					*/
		op_ici_attr_get (*intf_ici_pptr, "rte_info_fields", intf_ici_fdstruct_pptr);		
		}
	FOUT;
	}

static void
ip_dispatch_igmp_child_invoke (Packet* ip_pkptr, IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr)
	{
	
	/** Forward the packet to the appropriate child process	**/
	/** handling multicast packets.							**/
	
	IpT_Interface_Info*				intf_info_ptr;
	
	FIN (ip_dispatch_igmp_child_invoke (ip_pkptr, intf_ici_fdstruct_ptr));
	
	if (intf_ici_fdstruct_ptr->intf_recvd_index != -1)
		{
		/* Access the IpT_Interface_Info object for the interface	*/
		/* on which this packet was received						*/
		intf_info_ptr = ip_rte_intf_tbl_access (&module_data, 
				intf_ici_fdstruct_ptr->intf_recvd_index);
			
		/* Make sure that IGMP is supported on interface.	*/
		if (!ip_rte_intf_igmp_enabled (intf_info_ptr))
			{			
			/* Drop the packet and write a log message.	*/
			ipnl_protwarn_mcast_igmp_pkt_on_unsupp_intf (intf_info_ptr->full_name);
				
			op_pk_destroy (ip_pkptr);
			FOUT;
			}
		}
	else
		{
		op_sim_end ("Error in IP routing process model (ip_dispatch): ",
			"The interface on which the IGMP packet was received is",
			"not specified in the packet's ICI.", OPC_NIL);
		}
			
	/* Check if this node is a multicast router */
	if (ip_node_is_mcast_router (&module_data))
		{
		/** This node is a multicast router. Invoke the IGMP Router	**/
		/** Interface child process to process this message			**/
		
		/* Install the IP packet in the memory being shared with	*/
		/* IGMP Router Interface child process						*/
		module_data.ip_ptc_mem.child_pkptr = ip_pkptr;
		
		/* Invoke the IGMP Router Interface child process of the	*/
		/* interface												*/
		op_pro_invoke (intf_info_ptr->igmp_rte_iface_ph, OPC_NIL);
		}	
	else
		{
		/** This node is a multicast host. Invoke the IGMP Host		**/
		/** child process to process this IGMP message				**/
		
		/* Install the IP packet in the memory being shared with	*/
		/* IGMP Host child process									*/
		module_data.ip_ptc_mem.child_pkptr = ip_pkptr;
		
		/* Set other fields of the shared memory					*/
		module_data.ip_ptc_mem.ip_mcast_ptc_info.type = IpC_Igmp_Host_Other;

		module_data.ip_ptc_mem.ip_mcast_ptc_info.major_port = intf_ici_fdstruct_ptr->intf_recvd_index;
		module_data.ip_ptc_mem.ip_mcast_ptc_info.minor_port = intf_ici_fdstruct_ptr->minor_port_received;
		
		/* Invoke the IGMP Host child process						*/
		op_pro_invoke (igmp_host_process_handle, OPC_NIL);
		}
	
	FOUT;
	}

static Boolean
ip_dispatch_ra_export_status_get (void)
	{
	List				*proc_record_handle_lptr;
	OmsT_Pr_Handle		ra_proc_handle;
	double				ra_export_status_double;
	static Boolean		export_status_determined = OPC_FALSE;
	static Boolean		ra_export_status;
	
	/** Get the status of the RA Info Export attribute. This attribute	**/
	/** indicates that the user wishes to export routing information	**/
	/** for use by Reachability Information (RA).						**/
	FIN (ip_dispatch_ra_export_status_get (void));
	
	/* If this is not the first time that this function is being called,*/
	/* just return the cached value.									*/
	if (export_status_determined)
		{
		FRET (ra_export_status);
		}

	/* Set the flag indicating the subsequent calls to this function	*/
	/* should just look at the cached value.							*/
	export_status_determined = OPC_TRUE;

	/* First check for the presence of the RA process.	*/
	proc_record_handle_lptr = op_prg_list_create ();
	oms_pr_process_discover (OPC_OBJID_INVALID, proc_record_handle_lptr,
		"process name", OMSC_PR_STRING, "Reachability Analysis",
		OPC_NIL);
	
	/* If there is no process, RA isn't enabled.	*/
	if (op_prg_list_size (proc_record_handle_lptr) == 0)
		{
		/* Free the memory allocted to the list.						*/
		op_prg_mem_free (proc_record_handle_lptr);

		/* Cache the return value.										*/
		ra_export_status = OPC_FALSE;

		/* Return.														*/
		FRET (OPC_FALSE);
		}
	
	/* There should only be one process, but even if there are more,	*/
	/* just get the first process record handle.						*/
	ra_proc_handle = (OmsT_Pr_Handle) op_prg_list_access (
		proc_record_handle_lptr, OPC_LISTPOS_HEAD);
	
	/* Get the RA Export Status.	*/
	oms_pr_attr_get (ra_proc_handle, "RA Export Status", OMSC_PR_NUMBER, 
		&ra_export_status_double);
	ra_export_status = (Boolean) ra_export_status_double;
	
	/* Destroy the process record handle list.	*/
	while (op_prg_list_size (proc_record_handle_lptr) > 0)
		op_prg_list_remove (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
	op_prg_mem_free (proc_record_handle_lptr);
	
	FRET (ra_export_status);
	}

static void
ip_dispatch_tunnel_rcvd_stats_write (IpT_Tunnel_Info* tunnel_info_ptr, Packet* pkptr, double decapsulation_delay, Boolean drop_pkt)
	{	
	double							packet_size_bits			= 0.0;
	double							tunnel_ete_delay_sec		= 0.0;
	/** This function updates the received stats on a tunnel interface.	**/
	/** Traffic received/dropped stats and end-to-end delay and delay 	**/
	/** variation stats are written. Stats are updated for explicit		**/
	/** and background traffic.											**/
	
	FIN (ip_dispatch_tunnel_rcvd_stats_write (tunnel_info_ptr, pkptr, decap_delay, drop_pkt));
	
	/* Update stats for any flows that may be traversing this interface.*/
	
	/* Check to see if this interface has a valid routed state object.	*/
	/* This object is used by oms_bgutil to keep track of traffic on	*/
	/* this interface.													*/	
	if (tunnel_info_ptr->bgutil_rcvd_state_ptr == OPC_NIL)			
		tunnel_info_ptr->bgutil_rcvd_state_ptr = oms_bgutil_routed_state_create (UNITS_IN_BPS, DO_NOT_SCALE);

	/* Update received statistics. Only packets/sec and bits/sec are of	*/
	/* interest to us. Packets, bits and utilization stats are not 		*/
	/* being written for tunnel traffic.								*/
	oms_bgutil_bkg_stats_update (pkptr, &(tunnel_info_ptr->last_rcvd_update_time),
		tunnel_info_ptr->bgutil_rcvd_state_ptr,
		OPC_NIL,
		tunnel_info_ptr->traffic_rcvd_pps_lsh,
		OPC_NIL,
		tunnel_info_ptr->traffic_rcvd_bps_lsh,
		OPC_NIL,
		1.0);
	
	/* The last stat write time is used by the bgutil package to ensure that	*/
	/* stats are not written in closed buckets.									*/
	tunnel_info_ptr->last_rcvd_update_time = op_sim_time ();
	
	/* If the packet just received is an explicit traffic packet, then we must	*/
	/* write the stat for this specific packet.									*/
	if (!op_pk_encap_flag_is_set (pkptr, OMSC_BGUTIL_ENCAP_FLAG_INDEX))
		{
		packet_size_bits = (double) op_pk_total_size_get (pkptr);
		tunnel_ete_delay_sec = op_sim_time () - op_pk_creation_time_get (pkptr) + decapsulation_delay;

		oms_stat_sample_add (tunnel_info_ptr->delay_stat_ptr, tunnel_ete_delay_sec);		
		Oms_Dim_Stat_Write (tunnel_info_ptr->delay_sec_lsh, tunnel_ete_delay_sec);		
		Oms_Dim_Stat_Write (tunnel_info_ptr->delay_jitter_sec_lsh, 
			oms_stat_point_deviance_obtain (tunnel_info_ptr->delay_stat_ptr, tunnel_ete_delay_sec));
	
		if (drop_pkt)
			{
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_dropped_bps_lsh, packet_size_bits);
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_dropped_bps_lsh, 0.0);
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_dropped_pps_lsh, 1.0);
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_dropped_pps_lsh, 0.0);
			}
		else
			{
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_rcvd_bps_lsh, packet_size_bits);
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_rcvd_bps_lsh, 0.0);
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_rcvd_pps_lsh, 1.0);				
			Oms_Dim_Stat_Write (tunnel_info_ptr->traffic_rcvd_pps_lsh, 0.0);				
			}
		}

	FOUT;
	}
	
#if 0
static void
ip_rrp_init (void)
	{
	Objid				rrp_module_id;
	List*				proc_rec_handle_list_ptr;
	OmsT_Pr_Handle		process_record_handle;
	int 				record_handle_list_size;

	/** This function is called after IP interface table is built and 	**/
	/** RRP is supported at at least one interface.						**/
	/** RRP module object id is found from the database and a remote	**/
	/** interrupt is sent to RRP local process.							**/
	FIN (ip_rrp_init ());

	/** 1. Find the object ID of the RRP local process.					**/

	/* Create a temporary list to store discovered processe information */
	proc_rec_handle_list_ptr =  op_prg_list_create ();

	/* Obtain the process record handle of the IP process				*/
	/* residing in the local node.										*/
	oms_pr_process_discover (OPC_OBJID_INVALID, proc_rec_handle_list_ptr, 
		"node objid", 		OMSC_PR_OBJID, 		module_data.node_id, 
		"protocol", 		OMSC_PR_STRING, 	"rrp",
		OPC_NIL);

	/* An error should be created if there are more than				*/
	/* one ip process in the local node									*/
	record_handle_list_size = op_prg_list_size (proc_rec_handle_list_ptr);

	if (record_handle_list_size == 1)
		{
		process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_rec_handle_list_ptr, OPC_LISTPOS_HEAD);

		/* Obtain a reference to the IpT_Cmn_Rte_Table object   		*/
		/* for this node. This object is created and registered by IP.	*/
		oms_pr_attr_get (process_record_handle, "module id", 		  OMSC_PR_OBJID,  &rrp_module_id);

		/* 2. Send a remote interrupt to RRP.							*/
		op_intrpt_schedule_remote (op_sim_time (), RrpC_Ip_Notif, rrp_module_id);
		}

	/* Deallocate no longer needed process registry information.		*/
	if (record_handle_list_size > 0)
		op_prg_list_remove (proc_rec_handle_list_ptr, OPC_LISTPOS_HEAD);
		
	/* Free the list.	*/
	op_prg_mem_free (proc_rec_handle_list_ptr); 

	FOUT;
	}	
#endif

static void
ip_manet_rte_mgr_init (void)
	{
	Objid				manet_rte_mgr_module_id;
	List*				proc_rec_handle_list_ptr;
	OmsT_Pr_Handle		process_record_handle;
	int 				record_handle_list_size;

	/** This function is called after IP module data pointer is built and 	**/
	/** OLSR is supported at at-least one interface.						**/
	/** manet_rte_mgr module object id is found from the database 			**/
	/** and a remote interrupt is sent to manet_rte_mgr local process.		**/
	FIN (ip_manet_rte_mgr_init (void));

	/** 1. Find the object ID of the manet_rte_mgr local process			**/

	/* Create a temporary list to store discovered processe information */
	proc_rec_handle_list_ptr =  op_prg_list_create ();

	/* Obtain the process record handle of the IP process				*/
	/* residing in the local node.										*/
	oms_pr_process_discover (OPC_OBJID_INVALID, proc_rec_handle_list_ptr, 
		"node objid", 		OMSC_PR_OBJID, 		module_data.node_id, 
		"protocol", 		OMSC_PR_STRING, 	"manet_rte_mgr",
		OPC_NIL);

	/* An error should be created if there are more than				*/
	/* one ip process in the local node									*/
	record_handle_list_size = op_prg_list_size (proc_rec_handle_list_ptr);
	if (record_handle_list_size == 0)
		{
		op_sim_error (OPC_SIM_ERROR_WARNING, "Unable to find manet_rte_mgr process in the node.", 
			"OLSR requires presence of manet_rte_mgr process.");
		op_sim_message ("Use a standard node model (e.g. wlan_wkstn_adv), or add a",
						"module containing the manet_rte_mgr process above UDP.");
		}

	else if (record_handle_list_size == 1)
		{
		process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_rec_handle_list_ptr, OPC_LISTPOS_HEAD);

		/* Obtain a reference to the IpT_Cmn_Rte_Table object   		*/
		/* for this node. This object is created and registered by IP.	*/
		oms_pr_attr_get (process_record_handle, "module id", OMSC_PR_OBJID,  &manet_rte_mgr_module_id);
		
		/* 2. Send a remote interrupt to manet_rte_mgr.							*/
		op_intrpt_schedule_remote (op_sim_time (), 0, manet_rte_mgr_module_id);
		}

	/* Deallocate no longer needed process registry information.		*/
	if (record_handle_list_size > 0)
		op_prg_list_remove (proc_rec_handle_list_ptr, OPC_LISTPOS_HEAD);
		
	/* Free the list.	*/
	op_prg_mem_free (proc_rec_handle_list_ptr); 

	FOUT;
	}	

static int
ip_dispatch_virtual_ifaces_add (int last_ip_index, int lsp_signaling_protocol, 
	IpT_Intf_Objid_Lookup_Tables* intf_objid_lookup_tables_ptr, 
	List* routing_instance_lptr, List* active_custom_rte_proto_label_lptr)
	{
	
	/* Place holder for value of the "routing protocol" column		*/
	/* of a row in the "Interface Information" compound attribute.	*/
	List*				  	routing_protocols_lptr = OPC_NIL;
	int						instrm, outstrm;		
	IpT_Address				ip_addr;
	IpT_Interface_Info*		iface_info_ptr;
	IpT_Address				subnet_mask_addr;
	IpT_Interface_Type		interface_type = IpC_Intf_Type_Unspec;
	char					iface_name [IPC_MAX_STR_SIZE];
		
	double 					metric_bandwidth = 0.0;
	
	Objid					virtual_iface_cmp_objid;
	int						num_virtual_ifaces;

	/** This function is called to determine whether a switch module	**/
	/** is present on the gateway and if that is the case, it reads		**/
	/** the switch interface settings as configured in "VLAN 			**/
	/** Interfaces" attribute.											**/	
	FIN (ip_dispatch_virtual_ifaces_add (in_port, out_port, last_ip_index, lsp_signaling_protocol, 
		intf_objid_lookup_tables_ptr, routing_instance_lptr));
	
	/* Check whether the surrounding node contains a switch module. If	*/
	/* it doesn't then do not even bother to read "VLAN	Interfaces"		*/
	/* configuration.													*/
	if (ip_dispatch_switch_module_is_present() == OPC_FALSE)
		{
		/* This node has no switching module. Return.					*/
		FRET (0);
		}
	
	/* This node contains a switch module.	*/
		
	/* Virtual interfaces will be internally represented as a dummy	*/
	/* interface with subinterfaces equal to the configured virtual	*/
	/* interfaces. In the following, read the configured attributes */
	/* and create the new interface.								*/ 
	
	/* First find whether there were any virtual interfaces configured.	*/
	/* Only then create a new interface data structure.					*/
	op_ima_obj_attr_get (module_data.ip_parameters_objid, "VLAN Interfaces",
			&(virtual_iface_cmp_objid));
			
	/* Find the number of rows under this attribute			*/
	num_virtual_ifaces = op_topo_child_count (virtual_iface_cmp_objid, OPC_OBJTYPE_GENERIC);
	
	if (num_virtual_ifaces == 0)
		FRET (0);
	
	/* Add the dummy physical interface to the total number of interfaces.	*/
	module_data.num_interfaces ++;
		
	/* Read attributes configured under "Virtual Interface" attribute.						*/
	/* Virtual interfaces will be stored as subinterfaces of a dummy physical interface.	*/

	/*	Create and initialize a new cell to hold the interface	*/
	iface_info_ptr = ip_interface_info_create (IPC_PHYS_INTF);
		
	/* Set the addr_index to an invalid value.		*/
	iface_info_ptr->phys_intf_info_ptr->ip_addr_index = IPC_ADDR_INDEX_IVNALID;
				
	/* Set the physical interface IP address to "No IP address".	*/
	ip_addr = ip_address_copy (IpI_No_Ip_Address);
	subnet_mask_addr = IpI_Broadcast_Addr;

	iface_info_ptr->network_address = ip_address_mask (ip_addr, subnet_mask_addr);		
	iface_info_ptr->addr_range_ptr 	= ip_address_range_create (ip_addr, subnet_mask_addr);
	iface_info_ptr->inet_addr_range = inet_ipv4_address_range_create (ip_addr, subnet_mask_addr);

	/* Set the interface MTU.	*/
	iface_info_ptr->mtu	= 1500;

	/* Set the instream and outstream indices.	*/
	ip_stream_from_iface_index (last_ip_index, &instrm, &outstrm, &interface_type);

	interface_type 	= IpC_Intf_Type_Smart;
		
	iface_info_ptr->phys_intf_info_ptr->port_num 	= outstrm;
	iface_info_ptr->phys_intf_info_ptr->in_port_num = instrm;
		
	/* This is not an unnumbered interface.	*/
	iface_info_ptr->unnumbered_info		= OPC_NIL;
				
	iface_info_ptr->flow_id_map_list_ptr 	= OPC_NIL; 
	iface_info_ptr->tunnel_info_ptr 		= OPC_NIL;

	/* Store the status of the interface; Active, Shutdown, 	*/
	/* a loopback, tunnel or unconnected interface.				*/
	iface_info_ptr->phys_intf_info_ptr->intf_status = IpC_Intf_Status_Active;
		
	/* Initialize the Packet filter and Policy Routing name		*/		 
	iface_info_ptr->policy_routing_name = OPC_NIL;
	iface_info_ptr->filter_info_ptr 	= OPC_NIL;
	
	/* Set the subintf_addr_index to IPC_SUBINTF_PHYS_INTF (-1) */
	/* to indicate that this is a physical interface.			*/
	iface_info_ptr->subintf_addr_index = IPC_SUBINTF_PHYS_INTF;
		
	/* No routing protocols should be supported on this interface.	*/
	routing_protocols_lptr = ip_interface_routing_protocols_obtain (OPC_OBJID_INVALID,
				OPC_OBJID_INVALID, IpC_Intf_Status_Shutdown, OPC_NIL);

	/* Copy the contents of the temporary list containing information	*/
	/* about which routing protocols run on this interface.				*/
	iface_info_ptr->routing_protocols_lptr = routing_protocols_lptr;
								
	/* Set the compression information	*/
	iface_info_ptr->comp_info = (IpT_Compression_Info *)
					oms_data_def_entry_access ("IP Compression Information", "None");
		
	iface_info_ptr->phys_intf_info_ptr->connected_link_objid = OPC_OBJID_INVALID;
	iface_info_ptr->phys_intf_info_ptr->link_status = 1;
	
	/* Store the interface name.								*/
	strcpy (iface_name, "RSM");
	ip_rte_intf_name_set (iface_info_ptr, iface_name);
	
	/* The default bandwidth for VLAN interfaces is 10 Mbps.	*/
	iface_info_ptr->phys_intf_info_ptr->link_bandwidth = 10e6;

	/* Initialize the available bandwidth to interface speed */
	iface_info_ptr->avail_bw = iface_info_ptr->phys_intf_info_ptr->link_bandwidth;				
	
	/* Set metric basndwidth as link avail bw					*/
	metric_bandwidth = iface_info_ptr->avail_bw;
	
	/*	Initialize the outbound load from this interface. Also	*/
	/*	set the reliability of the interface as 100% reliable.	*/
	iface_info_ptr->load_bits 	= 0.0;
	iface_info_ptr->load_bps 	= 0.0;
	iface_info_ptr->reliability = 1.0;

	/* For the time being, we do not know whether we are using	*/
	/* slots or not.  This will be filled in appropriately 		*/
	/* if slots are created.									*/
	iface_info_ptr->phys_intf_info_ptr->slot_index = OMSC_DV_UNSPECIFIED_SLOT;
	
	/* Store the type of this interface. This is required in 	*/
	/* determining whether a ICI is to be associated with the	*/
	/* packets sent throug this interface. We do not have to 	*/
	/* associate any ICI with packets sent out through "slip"	*/
	/* interfaces.												*/
	iface_info_ptr->phys_intf_info_ptr->intf_type = interface_type;

	/* Set Layer2 mapping.	*/
	iface_info_ptr->layer2_mappings.vlan_identifier = OMSC_VLAN_NULL_VID;
	iface_info_ptr->layer2_mappings.num_atm_pvcs 	= 0;
	iface_info_ptr->layer2_mappings.num_fr_pvcs 	= 0; 
	
	/* Set the number of configured subinterfaces.	*/
	iface_info_ptr->phys_intf_info_ptr->num_subinterfaces = num_virtual_ifaces;

	if (0 != num_virtual_ifaces)
		{
		
		ip_dispatch_subintf_info_read (iface_info_ptr, virtual_iface_cmp_objid, 
											intf_objid_lookup_tables_ptr, num_virtual_ifaces, 
											active_custom_rte_proto_label_lptr,
											lsp_signaling_protocol, OPC_TRUE, routing_instance_lptr);
		}
	
	/* Make sure that the interface versions are consistent.	*/
	/* If not, update them.										*/
	ip_dispatch_subintf_ip_version_check (iface_info_ptr);
	
	/*	Insert the cell into the interface table. 				*/
	op_prg_list_insert (module_data.interface_table_ptr, iface_info_ptr, OPC_LISTPOS_TAIL);

	/* Return the number of new interfaces.						*/
	FRET (iface_info_ptr->phys_intf_info_ptr->num_subinterfaces + 1);	
	}
	

static Boolean
ip_dispatch_switch_module_is_present (void)
	{
	List		proc_record_handle_list;
	int			record_handle_list_size;

	/** This function returns OPC_TRUE if the surrounding module	**/
	/** contains a switching module, otherwise it returns OPC_FALSE.**/
	FIN (ip_dispatch_switch_module_is_present (void));
	
	/* Create a list that will contain found bridge modules.		*/
	op_prg_list_init (&proc_record_handle_list); 
	
	/* Discover any bridge module inside this node.					*/
	oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list,
		"node objid", 	OMSC_PR_OBJID, 		module_data.node_id, 
		"protocol",		OMSC_PR_STRING,		"bridge", 
		OPC_NIL);
	
	/* Get the size of the list.									*/
	record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
		
	if (record_handle_list_size > 1)
		{
		op_sim_end ("Detected more than one switch module.",
			"This configuration is currently not supported.",
				"Please check your node model.", OPC_NIL);
		
		}

	if (record_handle_list_size == 0)
		{
		/* This node has no switching module. Return.				*/
		FRET (OPC_FALSE);
		}
	
	/*	Deallocate no longer needed process registry information.	*/
	op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);
	
	/* Return OPC_TRUE since a single switching module is found.	*/
	FRET (OPC_TRUE);
	}
	
static void
ip_dispatch_vlan_id_read (IpT_Interface_Info* iface_info_ptr, Objid attr_objid)
	{
	int 			vid;
	
	/** Read VLAN ID attribute.	*/
	FIN (ip_dispatch_vlan_id_read (iface_info_ptr, attr_objid));
	
	/* Read in the identifier of the VLAN to which the subinterface	*/
	/* belongs.														*/
	op_ima_obj_attr_get (attr_objid, "VLAN Identifier", &vid);
	
	if (vid == IPC_DEFAULT_LAYER2_MAPPING_INT)
		{
		/* No VLAN information is specified for the subinterface.	*/
		iface_info_ptr->layer2_mappings.vlan_identifier = OMSC_VLAN_NULL_VID;
		}
	else
		{
		/* Accept the VID if it is valid.							*/
		if (vid >= OMSC_VLAN_MIN_VID && vid <= OMSC_VLAN_MAX_VID)
			iface_info_ptr->layer2_mappings.vlan_identifier = vid;
		else
			iface_info_ptr->layer2_mappings.vlan_identifier = OMSC_VLAN_NULL_VID;
		}
			
	FOUT;
	}

static void
ip_rsvp_qos_config_check (void)
	{
	int						i, num_entries;
	IpT_Interface_Info *	ip_interface_info_ptr;
	Objid					my_node_objid;
	static Boolean			log_call_scheduled = OPC_FALSE;
	
	/** Check the configuration consistency for RSVP. Since RSVP requires CQ or WFQ	**/
	/** to be configured on interfaces, make sure that this is indeed the case.		**/
	FIN (ip_rsvp_qos_config_check (void));
	
	num_entries = ip_rte_num_interfaces_get (&module_data);
	
	for (i = 0; i < num_entries; i++)
		{
		ip_interface_info_ptr = ip_rte_intf_tbl_access (&module_data, i);

		if (ip_rte_intf_rsvp_enabled (ip_interface_info_ptr) &&
			(ip_interface_info_ptr->queuing_scheme != IpC_WFQ_Queuing) &&
			(ip_interface_info_ptr->queuing_scheme != IpC_Custom_Queuing))
			{
			if (log_call_scheduled == OPC_FALSE)
				{
				/* This is the first time the function is called network-wide.	*/
					
				op_intrpt_schedule_call (op_sim_time (), 0, 
						ip_qosnl_rsvp_config_check_write, OPC_NIL);
						
				log_call_scheduled = OPC_TRUE;
				}
						
			my_node_objid = op_topo_parent (op_id_self());
			ip_qosnl_rsvp_config_missing_msg_add (ip_interface_info_ptr->full_name, my_node_objid);
			
			/* Switch the RSVP flag off by ANDing with the complement (inverse).	*/
			ip_interface_info_ptr->flags &= ~IPC_INTF_FLAG_RSVP_ENABLED;
			
			if (ip_interface_info_ptr->rsvp_info_ptr != OPC_NIL)
				{
				op_prg_mem_free (ip_interface_info_ptr->rsvp_info_ptr);
				ip_interface_info_ptr->rsvp_info_ptr = OPC_NIL;
				}
			}
		}

	FOUT;
	}

static Boolean
ip_igmp_iface_enabled (IpT_Intf_Name_Objid_Table_Handle igmp_intf_objid_lookup_table,
	const char* iface_name)
	{
	Objid				igmp_params_intf_objid;
	Boolean				mcast_status;
	Boolean			 	igmp_status;
	
	/** Determines whether IGMP is enabled on the specified interface.	**/
	FIN (ip_igmp_routing_iface_enabled (igmp_intf_objid_lookup_table, iface_name));
	
	/* For Host nodes, read the IP Host Parameters -> Multicast Enabled attribute*/
	if (module_data.gateway_status == OPC_FALSE)
		{
		/* Multicast is enabled on hosts if "Multicast Mode" is	enabled. */
		op_ima_obj_attr_get (module_data.ip_parameters_objid,"Multicast Mode", &mcast_status);
		
		FRET (mcast_status);
		}
	
	/* For gateway nodes, get the object ID of the corresponding row under		*/
	/* IGMP Parameters.															*/
	igmp_params_intf_objid = ip_rte_proto_intf_attr_objid_table_lookup_by_name (igmp_intf_objid_lookup_table, iface_name);

	/* If we did not find a matching row, return FALSE.							*/
	if (OPC_OBJID_INVALID == igmp_params_intf_objid)
		{
		FRET (OPC_FALSE);
		}

	/* We found the interface. Now get the status.	*/							
	op_ima_obj_attr_get	(igmp_params_intf_objid, "Status", &igmp_status);

	FRET (igmp_status);
	}

static void
ip_dispatch_ipv6_ra_process_create (void)
	{
	IpT_Interface_Info*		ip_intf_ptr;
	int						intf_index, num_ipv6_interfaces, num_ra_interfaces;

	/** Create the ipv6_ra_host/ipv6_ra_gtwy process if		**/
	/** necessary.											**/

	FIN (ip_dispatch_ipv6_ra_process_create (void));
	
	/* We do not support router advertisement over ATM/FR	*/
	/* interfaces. So on ATM/FR host nodes, do not create	*/
	/* the ipv6_ra_host process.							*/
	if (! ip_rte_node_is_gateway (&module_data))
		{
		/* Get a handle to the only interface.				*/
		ip_intf_ptr = ipv6_rte_intf_tbl_access (&module_data, 0);

		/* On nodes with smart interfaces, make sure that	*/
		/* the lower layer initialization is complete.		*/
		if ((ip_rte_intf_is_smart (ip_intf_ptr)) &&
			(IpC_Intf_Lower_Layer_Invalid == ip_rte_intf_lower_layer_addr_type_get (ip_intf_ptr)))
			{
			/* The lower layer has not initialized yet.		*/
			op_sim_error (OPC_SIM_ERROR_ABORT, "Error in ip_dispatch_ipv6_ra_process_create",
				"The ARP layer has not completed initialization");
			}

		/* For Frame Relay and ATM interfaces, do not create*/
		/* the ra_host process.								*/
		if ((ip_rte_intf_lower_layer_is_fr (ip_intf_ptr)) ||
			(ip_rte_intf_lower_layer_is_atm (ip_intf_ptr)))
			{
			/* If the node has not been assigned an global	*/
			/* address, write a log message.				*/
			if (ip_rte_intf_num_ipv6_gbl_addrs_get (ip_intf_ptr) == 0)
				{
				ipnl_no_ipv6_gbl_addrs_log_write (module_data.node_name);
				}
			/* Make sure that the IPv6 default route is also*/
			/* specified.									*/
			else if (!inet_address_valid (module_data.default_route_addr_array [InetC_Addr_Family_v6]))
				{
				ipnl_cfgerr_defroute (InetC_Addr_Family_v6);
				}

			FOUT;
			}

		/* Lower layer is either a LAN interface or a PPP	*/
		/* interface. Spawn the ipv6_ra_host process.		*/
		module_data.ipv6_ra_prohandle = op_pro_create ("ipv6_ra_host", OPC_NIL);
		op_pro_invoke (module_data.ipv6_ra_prohandle, OPC_NIL);
		}
	else
		{
		/* This is a gateway node. Loop through all the		*/
		/* IPv6 enabled interfaces. If there are any		*/
		/* interfaces with RA enabled, we need to create	*/
		/* the ipv6_ra_gtwy process.						*/

		/* Initialize the number of RA enabled interfaces to*/
		/* 0.												*/
		num_ra_interfaces = 0;

		/* Get the number of IPv6 enabled interfaces.		*/
		num_ipv6_interfaces = ipv6_rte_num_interfaces_get (&module_data);

		for (intf_index = 0; intf_index < num_ipv6_interfaces; intf_index++)
			{
			/* Get the ith interface.						*/
			ip_intf_ptr = ipv6_rte_intf_tbl_access (&module_data, intf_index);

			/* If router advertisements are not enabled on	*/
			/* this interface, ignore it.					*/
			if (OPC_NIL == ip_intf_ptr->ipv6_info_ptr->ra_info.ra_gtwy_info_ptr)
				{
				continue;
				}

			/* Make sure that the arp layer has initialized	*/
			if ((ip_rte_intf_is_smart (ip_intf_ptr)) &&
				(IpC_Intf_Lower_Layer_Invalid == ip_rte_intf_lower_layer_addr_type_get (ip_intf_ptr)))
				{
				/* The lower layer has not initialized yet.	*/
				op_sim_error (OPC_SIM_ERROR_ABORT, "Error in ip_dispatch_ipv6_ra_process_create",
					"The ARP layer has not completed initialization");
				}

			/* If this is an ATM/FR interface, disable RA	*/
			if ((ip_rte_intf_lower_layer_is_fr (ip_intf_ptr)) ||
				(ip_rte_intf_lower_layer_is_atm (ip_intf_ptr)))
				{
				/* TODO: Write a log message warning the	*/
				/* user that RA is being disabled.			*/
				/* Free the memory allocated to the RA		*/
				/* structures.								*/
				ipv6_ra_gtwy_info_destroy (ip_intf_ptr->ipv6_info_ptr->ra_info.ra_gtwy_info_ptr);
				ip_intf_ptr->ipv6_info_ptr->ra_info.ra_gtwy_info_ptr = OPC_NIL;
				}
			else
				{
				/* Increment the number of RA enabled		*/
				/* interfaces.								*/
				++num_ra_interfaces;
				}
			}

		/* Create an invoke the ipv6_ra_gtwy process if		*/
		/* there is at least one RA enabled interface.		*/
		if (num_ra_interfaces)
			{
			module_data.ipv6_ra_prohandle = op_pro_create ("ipv6_ra_gtwy", OPC_NIL);
			op_pro_invoke (module_data.ipv6_ra_prohandle, OPC_NIL);
			}
		}

	/* Return.		*/
	FOUT;
	}

static void
ip_dispatch_icmp_pk_higher_layer_forward (Packet* ip_pkptr, IpT_Dgram_Fields* pkt_fields_ptr,
	IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr)
	{
	Packet*							icmp_pk_ptr;
	const IpT_Icmp_Packet_Fields*	icmp_pk_fields_ptr;

	/** Forward an ICMP packet to the appropriate child		**/

	FIN (ip_dispatch_icmp_pk_higher_layer_forward (ip_pkptr, pkt_fields_ptr, intf_ici_fdstruct_ptr));

	/* If mobile IP is enabled, forward the packet to the	*/
	/* mobile IP process if it is enabled.					*/
	if ((pkt_fields_ptr->icmp_type == IcmpC_Type_IRDP_Ad) ||
		(pkt_fields_ptr->icmp_type == IcmpC_Type_IRDP_Sol))
		{
		if (ip_mobile_ip_is_enabled (&module_data))
			{
			/* Call appropriate function.					*/
			mip_sup_IRDP_packet_forward (&module_data, ip_pkptr, intf_ici_fdstruct_ptr, pkt_fields_ptr->icmp_type);
			}
		else
			{
			/* This node cannot handle the packet.Destroy it*/
			op_pk_destroy (ip_pkptr);
			
			/* Clean up ICI as well. 						*/
			ip_rte_ind_ici_fdstruct_destroy (intf_ici_fdstruct_ptr);
			}
		}
	else
		{
		/* This is either a ping packet or an IPv6 ND packet*/
		/* Look at the ICMP message type of find out which	*/
		/* is the case.										*/
		/* Get a handle to the ip_icmp packet.				*/
		icmp_pk_ptr = ip_dgram_data_pkt_get (ip_pkptr);

		/* Get a hanlde to the structure in the "fields"	*/
		/* field of the icmp  packet.						*/
		icmp_pk_fields_ptr = ip_icmp_packet_fields_access (icmp_pk_ptr);

		/* Set the ICMP packet back into the IP packet.		*/
		ip_dgram_data_pkt_set (ip_pkptr, icmp_pk_ptr);

		/* Check the message type.							*/
		switch (icmp_pk_fields_ptr->message_type)
			{
			case IpC_Icmp_Message_Type_Echo_Request:
			case IpC_Icmp_Message_Type_Echo_Reply:
				/* Ping packet. Forward to the ICMP process	*/
				/* Install the IP packet in the memory being*/
				/* shared with ICMP							*/
				module_data.ip_ptc_mem.child_pkptr = ip_pkptr;

				/* Invoke the icmp child process to handle	*/
				/* the packet.								*/
				op_pro_invoke (module_data.icmp_process_handle, OPC_NIL);
				break;

			case IpC_Icmp_Message_Type_Nbr_Solicit:
			case IpC_Icmp_Message_Type_Nbr_Advertise:
				/* Neighbor solicitation and neighbor		*/
				/* discovery packets have to be handled at	*/
				/* the ARP layer. Destroy the packet.		*/
				op_pk_destroy (ip_pkptr);
				ip_rte_ind_ici_fdstruct_destroy (intf_ici_fdstruct_ptr);

				/* Generate a diagnostic error.				*/
				op_sim_error (OPC_SIM_ERROR_DIAGNOSTIC, "A neighbor advertisement or neighbor solicitation",
					"packet was received at the IP layer");
				break;

			case IpC_Icmp_Message_Type_Rtr_Solicit:
				/* Router solicitation.						*/

				/* If this is a host node, discard the		*/
				/* packet silently.							*/
				if (! ip_rte_node_is_gateway (&module_data))
					{
					/* Destroy the packet and the ICI.		*/
					op_pk_destroy (ip_pkptr);
					ip_rte_ind_ici_fdstruct_destroy (intf_ici_fdstruct_ptr);
					}
				/* Forward the packet to the ipv6_ra_gtwy	*/
				/* process.									*/
				else
					{
					op_pro_invoke (module_data.ipv6_ra_prohandle, ip_pkptr);
					}
				break;

			case IpC_Icmp_Message_Type_Rtr_Advertise:
				/* Router Advertisement.					*/

				/* If this is a host node, discard the packet*/
				/* silently.								*/
				if (ip_rte_node_is_gateway (&module_data))
					{
					/* Destroy the packet and the ICI.		*/
					op_pk_destroy (ip_pkptr);
					ip_rte_ind_ici_fdstruct_destroy (intf_ici_fdstruct_ptr);
					}
				/* Forward the packet to the ipv6_ra_host	*/
				/* process.									*/
				else
					{
					op_pro_invoke (module_data.ipv6_ra_prohandle, ip_pkptr);
					}
				break;

			default:
				/* Invalid message type.					*/
				op_sim_error (OPC_SIM_ERROR_ABORT, "In ip_dispatch_icmp_pk_higher_layer_forward",
					"the ICMP message type is invalid.");
				break;
			}

		}

	/* Return.		*/
	FOUT;
	}
static void
ip_dispatch_ppp_intf_set (void)
	{
	int						num_intf, intf_index;
	IpT_Interface_Info* 	iface_info_ptr;
	
	/** Loop through interfaces and if the interface is connected 	**/
	/** to a ppp link, set the lower layer type to ppp.				**/
	/** It is assumed that if the interface is over a MAC layer, 	**/
	/** MAC layer has already set the interface type and lower 		**/
	/** layer address.												**/
	FIN (ip_dispatch_ppp_intf_set ());
	
	/* The router has not been assigned. Obtain the total	*/
	/* number of active interfaces.							*/
	num_intf = inet_rte_num_interfaces_get (&module_data);
	
	for (intf_index = 0; intf_index < num_intf; intf_index++)
		{
		/* Get the next iface								*/
		iface_info_ptr = inet_rte_intf_tbl_access (&module_data, intf_index);
				
		/* Set the lower layer to PPP if this interface 									*/
		/* 1. does not run over a MAC layer (lower layers have not set lower layer type.	*/
		/* 2. and it is not a radio interface (thus connected link objid is valid).			*/
		if ((iface_info_ptr->phys_intf_info_ptr->intf_type == IpC_Intf_Type_Dumb)
			&& (iface_info_ptr->phys_intf_info_ptr->connected_link_objid != OPC_OBJID_INVALID))
			{
			iface_info_ptr->phys_intf_info_ptr->lower_layer_type = IpC_Intf_Lower_Layer_PPP;
			}
		}
	
	FOUT;
	}

static IpT_Group_Intf_Info*
ip_dispatch_aggregate_intf_attrs_read (Objid iface_description_objid, const char* PRG_ARG_UNUSED (iface_name))
	{
	IpT_Group_Intf_Info*	group_info_ptr;

	/** Read attributes specific to aggregate interfaces.			**/

	FIN (ip_dispatch_aggregate_intf_attrs_read (iface_description_objid, iface_name));

	/* Allocate enough memory for the group info structure.			*/
	group_info_ptr = (IpT_Group_Intf_Info*) op_prg_mem_alloc (sizeof (IpT_Group_Intf_Info));

	/* Initialize the fields.										*/
	group_info_ptr->grp_intf_row_objid = iface_description_objid;
	group_info_ptr->member_intf_array = OPC_NIL;
	group_info_ptr->num_members = 0;

	/* Return a pointer to the group info structure.				*/
	FRET (group_info_ptr);
	}

static Boolean
ip_dispatch_member_intf_check (Objid iface_description_objid, const char* intf_name,
	int instrm, int outstrm, int addr_index, IpT_Interface_Status interface_status)
	{
	Objid					aggr_params_objid;
	char					aggr_intf_name [128];
	IpT_Interface_Info*		aggr_intf_ptr;
	IpT_Group_Intf_Info*	group_info_ptr;
	IpT_Member_Intf_Info*	member_info_ptr;
	Objid					line_objid;

	/** Check if the specified interface is part of an interface	**/
	/** group. If it is, then add it to the list of member			**/
	/** interfaces of the group and return TRUE. If not, return		**/
	/** FALSE.														**/

	FIN (ip_dispatch_member_intf_check (iface_description_objid, instrm, outstrm, interface_type));

	/* Get the objid of the Aggregation Parameters attribute.		*/
	op_ima_obj_attr_get_objid (iface_description_objid, "Aggregation Parameters", &aggr_params_objid);
	aggr_params_objid = op_topo_child (aggr_params_objid, OPC_OBJTYPE_GENERIC, 0);

	/* Get the value of the Aggregate Interface attribute.			*/
	op_ima_obj_attr_get_str (aggr_params_objid, "Aggregate Interface", sizeof (aggr_intf_name), aggr_intf_name);

	/* If the interface name is set to "Not Configured", it means	*/
	/* that the interface is not part of a group.					*/
	if (0 == strcmp (aggr_intf_name, "Not Configured"))
		{
		/* Return FALSE to indicate that the interface is not part	*/
		/* of a group.												*/
		FRET (OPC_FALSE);
		}

	/* If the current interface is shutdown, ignore it.				*/
	if (IpC_Intf_Status_Shutdown == interface_status)
		{
		/* Return TRUE to indicate that the interface was configured*/
		/* to be part of a group.									*/
		FRET (OPC_TRUE);
		}

	/* Get the objid of the link connected to the member interface.	*/
	line_objid = ip3_link_iface_link_from_index (link_iface_table_ptr, addr_index, 0);

	/* If the interface is not connected, ignore it.				*/
	if (OPC_OBJID_INVALID == line_objid)
		{
		/* Return TRUE to indicate that the interface was configured*/
		/* to be part of group.										*/
		FRET (OPC_TRUE);
		}

	/* Look for an aggregate interface with the specified name.		*/
	aggr_intf_ptr = ip_dispatch_find_intf_with_name (aggr_intf_name, module_data.interface_table_ptr);

	/* Make sure that we found an interface and it is an aggregate	*/
	/* interface.													*/
	if ((OPC_NIL == aggr_intf_ptr) || (! ip_rte_intf_is_group (aggr_intf_ptr)) ||
		(! ip_rte_intf_is_physical (aggr_intf_ptr)))
		{
		/* Write a warning message.									*/
		ipnl_aggregate_intf_invalid_log_write (intf_name, aggr_intf_name);

		/* Return TRUE to indicate that the interface was			*/
		/* configured to be part of a group, though an invalid one.	*/
		FRET (OPC_TRUE);
		}

	/* Add the current interface to the list of member interfaces	*/
	/* of the group.												*/
	
	/* Get a handle to the group information.						*/
	group_info_ptr = aggr_intf_ptr->phys_intf_info_ptr->group_info_ptr;

	/* Increment the number of member interfaces.					*/
	++(group_info_ptr->num_members);

	/* Allocate enough memory to hold the new member.				*/
	group_info_ptr->member_intf_array = (IpT_Member_Intf_Info*) op_prg_mem_realloc
		(group_info_ptr->member_intf_array, group_info_ptr->num_members * sizeof (IpT_Member_Intf_Info));

	/* Get a handle to the last entry in the array.					*/
	member_info_ptr = &(group_info_ptr->member_intf_array [group_info_ptr->num_members - 1]);

	/* Fill in the elements of the structure.						*/
	member_info_ptr->intf_info_objid = iface_description_objid;
	member_info_ptr->connected_link_objid = line_objid;
	member_info_ptr->instrm = instrm;
	member_info_ptr->outstrm = outstrm;
	member_info_ptr->addr_index = addr_index;
	member_info_ptr->intf_name = prg_string_copy (intf_name);

	/* Intialize the status to FALSE. It will be set to TRUE by		*/
	/* link aggregation protocol when it is available for use.		*/
	member_info_ptr->status = OPC_FALSE;

	/* Initialize the slot_index also. In nodes that use slot based	*/
	/* processing, it would be set appropriately by the				*/
	/* ip_rte_distrib_cpu process.									*/
	member_info_ptr->slot_index = OMSC_DV_UNSPECIFIED_SLOT;

	/* Return TRUE to indicate that this interface is part of a		*/
	/* group.														*/
	FRET (OPC_TRUE);
	}

static void
ip_dispatch_endsim_tunnel_stats_write (void* state_ptr, int PRG_ARG_UNUSED (code))
	{
	IpT_Rte_Module_Data*	iprmd_ptr;
	int						num_interfaces, intf_index;
	IpT_Interface_Info*		intf_info_ptr;
	
	/** This function is invoked at end of simulation to update bgutil related statistics.	**/
	/** Currently, only traffic sent and received stats on tunnel interfaces require this	**/
	/** endsim update.																		**/
	FIN (ip_dispatch_endsim_stats_write ());

	iprmd_ptr = (IpT_Rte_Module_Data *)	state_ptr;

	num_interfaces = ip_rte_num_interfaces_get (iprmd_ptr);

	for (intf_index = 0; intf_index < num_interfaces; intf_index++)
		{
		intf_info_ptr = ip_rte_intf_tbl_access (iprmd_ptr, intf_index);

		if (ip_rte_intf_is_tunnel (intf_info_ptr))
			{
			if (OPC_NIL != intf_info_ptr->tunnel_info_ptr->bgutil_sent_state_ptr)
				{
				oms_bgutil_bkg_stats_update (OPC_NIL, &(intf_info_ptr->tunnel_info_ptr->last_sent_update_time),
					intf_info_ptr->tunnel_info_ptr->bgutil_sent_state_ptr,
					OPC_NIL,
					intf_info_ptr->tunnel_info_ptr->traffic_sent_pps_lsh,
					OPC_NIL,
					intf_info_ptr->tunnel_info_ptr->traffic_sent_bps_lsh,
					OPC_NIL,
					1.0);
				}

			if (OPC_NIL != intf_info_ptr->tunnel_info_ptr->bgutil_rcvd_state_ptr)
				{
				oms_bgutil_bkg_stats_update (OPC_NIL, &(intf_info_ptr->tunnel_info_ptr->last_rcvd_update_time),
					intf_info_ptr->tunnel_info_ptr->bgutil_rcvd_state_ptr,
					OPC_NIL,
					intf_info_ptr->tunnel_info_ptr->traffic_rcvd_pps_lsh,
					OPC_NIL,
					intf_info_ptr->tunnel_info_ptr->traffic_rcvd_bps_lsh,
					OPC_NIL,
					1.0);
				}
			}
		}
	FOUT;
	}
static void
ip_dispatch_routing_processes_in_table_print (IpT_Cmn_Rte_Table* ip_rte_table, const char* instance_name)
	{
	int						ith_proc;	
	char					routeproc_name [256];
	IpT_Route_Proc_Info*	proc_info_ptr;
	
	/** Print info about all routing processes in one routing table.	**/
	FIN (ip_dispatch_routing_processes_in_table_print ());

	printf ("Routing processes in %s\n", instance_name);
	printf ("======================================\n");

	for (ith_proc = 0; ith_proc < prg_vector_size (ip_rte_table->routeproc_vptr); ith_proc++)
		{
		proc_info_ptr = (IpT_Route_Proc_Info *) prg_vector_access (ip_rte_table->routeproc_vptr, ith_proc);
		ip_cmn_rte_proto_name_print (routeproc_name, proc_info_ptr->routeproc_id);
		printf ("%s\n", routeproc_name);
		}
		
	printf ("\n");
	FOUT;
	}

static void
ip_dispatch_routing_processes_print (void)
	{
	IpT_Vrf_Table*			vrf_table;
	int						num_vrfs, ith_vrf;
	
	/** Print out all the IP routing processes on all the routing tables on this node.	**/
	FIN (ip_dispatch_routing_processes_print ());

	/* Print out the processes working on the common routing table.	*/
	ip_dispatch_routing_processes_in_table_print (module_data.ip_route_table, "Common Route Table");

	/* If there are any VRFs on this node, print out the processes working on them.	*/
	if (ip_node_is_pe (&module_data))
		{
		num_vrfs = ip_vrf_table_num_vrfs_get (&module_data);

		for (ith_vrf = 0; ith_vrf < num_vrfs; ith_vrf++)
			{
			vrf_table = ip_vrf_table_for_vrf_index_get (&module_data, ith_vrf);

			ip_dispatch_routing_processes_in_table_print (
				ip_vrf_table_cmn_rte_table_get (vrf_table),
				ip_vrf_table_name_get (vrf_table));
			}
		}
	FOUT;
	}

static IpT_Interface_Info*
ip_dispatch_dual_msfc_alt_interface_parse (Objid intf_objid, Boolean loopback_intf)
	{
	IpT_Interface_Info		*primary_intf_ptr, *iface_info_ptr;
	int						num_sec_addrs, sec_addr_index;	
	InetT_Address_Range		primary_addr_range, alt_addr_range;
	IpT_Address				ip_addr, subnet_mask_addr;
	List					sec_addr_list;
	IpT_Sec_Addr_Table*		sec_addr_table_ptr;		
	IpT_Secondary_Address*	sec_addr_ptr;
	InetT_Address			inet_addr;
	char					intf_name [64], intf_addr_str [32], intf_smask_str [32];
	Objid					sec_addr_objid, sec_addr_cmpd_objid;
	Boolean					host_loopback_addr;
	/** Read information about a single interface in the alt configuration.	**/
	FIN (ip_dispatch_dual_msfc_alt_interface_parse ());

	op_ima_obj_attr_get_str (intf_objid, "Name", 32, intf_name);

	primary_intf_ptr = ip_dispatch_find_intf_with_name	(intf_name, module_data.interface_table_ptr);
	if (OPC_NIL == primary_intf_ptr)
		{
		ipnl_dual_msfc_intf_misconfig_write (module_data.node_id, intf_name, 
			"Non-designated interface does not have a matching designated interface");
		FRET (OPC_NIL);
		}

	op_ima_obj_attr_get_str (intf_objid, "Address", 32, intf_addr_str);
	op_ima_obj_attr_get_str (intf_objid, "Subnet Mask", 32, intf_smask_str);
	
	ip_addr = ip_address_create (intf_addr_str);
	subnet_mask_addr = ip_address_create (intf_smask_str);
	alt_addr_range = inet_ipv4_address_range_create (ip_addr, subnet_mask_addr);

	/* Make sure that the alt interface is in the same subnet as the primary interface.	*/
	/* This check should be skipped for loopback interfaces with /32 mask because that	*/
	/* is an allowed configuration.														*/
	host_loopback_addr = (loopback_intf && (ip_smask_length_count (subnet_mask_addr) == IPC_V4_ADDR_LEN)); 
	if (!host_loopback_addr)
		{	
		primary_addr_range = primary_intf_ptr->inet_addr_range;

		if (inet_address_range_mask_get (&primary_addr_range) != inet_address_range_mask_get (&alt_addr_range))
			{
			ipnl_dual_msfc_intf_misconfig_write (module_data.node_id, intf_name, 
				"Subnet addresses for designated and non-designated interfaces do not match");
			FRET (OPC_NIL);
			}

		if (!inet_address_subnets_overlap (&primary_addr_range, &alt_addr_range))
			{
			ipnl_dual_msfc_intf_misconfig_write (module_data.node_id, intf_name, 
				"Subnet addresses for designated and non-designated interfaces do not match");
			FRET (OPC_NIL);
			}
		}

	/* After making the configuration checks, we will use a more specific mask for the	*/
	/* alt address. This is done to ensure that all packets destined to the alt address	*/
	/* are received on this interface, and not on the primary interface corresponding 	*/
	/* to the same subnet. If that interface is picked, then the packet will be pushed 	*/
	/* out of the interface again. But if a more specific address is present, then the	*/
	/* routing table will match the destination to that entry.							*/	
	inet_address_range_mask_set (&alt_addr_range, inet_smask_from_length_create (IPC_V4_ADDR_LEN));
	subnet_mask_addr = ip_address_copy (IpI_Broadcast_Addr);

	/* Create an interface object and populate its fields.	*/
	iface_info_ptr = ip_interface_info_create (IPC_PHYS_INTF);
	iface_info_ptr->network_address = ip_address_mask (ip_addr, subnet_mask_addr);
	iface_info_ptr->inet_addr_range = alt_addr_range;
	iface_info_ptr->addr_range_ptr = ip_address_range_create (ip_addr, subnet_mask_addr);
	iface_info_ptr->phys_intf_info_ptr->port_num = IPC_PORT_NUM_INVALID;
	iface_info_ptr->phys_intf_info_ptr->in_port_num = IPC_PORT_NUM_INVALID;
	iface_info_ptr->flags |= IPC_INTF_FLAG_MSFC_ALT;

	/* If this is a /32 loopback address, then we must run routing protocols 	*/
	/* separately on this interface, since the primary loopback's network does	*/
	/* not cover the alt loopback's network. Also, we must flag this interface	*/
	/* with a special flag since the directly connected route must appear in	*/
	/* the routing table.														*/	
	if (host_loopback_addr)
		{
		iface_info_ptr->flags |= IPC_INTF_FLAG_MSFC_ALT_HOST_LB;
		iface_info_ptr->routing_protocols_lptr = primary_intf_ptr->routing_protocols_lptr;
		}

	/* Append the keyword "ALT" to the intf name for easy recognition.	*/
	strcat (intf_name, "-ALT");
	ip_rte_intf_name_set (iface_info_ptr, intf_name);

	/* Register the address with the global package so that other utilities	*/
	/* like reports, ping initialization etc. are aware of this address.	*/
	inet_addr = inet_address_from_ipv4_address_create (ip_addr);
	ip_rtab_local_addr_register (&inet_addr, &module_data);

	/* Read in the secondary address configuration.	*/
	if (op_ima_obj_attr_exists (intf_objid, "Secondary Address Information"))
		{
		op_prg_list_init (&sec_addr_list);
		op_ima_obj_attr_get_objid (intf_objid, "Secondary Address Information", &sec_addr_cmpd_objid);
		num_sec_addrs = op_topo_child_count (sec_addr_cmpd_objid, OPC_OBJTYPE_GENERIC);

		/* TODO: Error checking for alt secondary addresses.	*/
		for (sec_addr_index = 0; sec_addr_index < num_sec_addrs; sec_addr_index++)
			{
			sec_addr_objid = op_topo_child (sec_addr_cmpd_objid, OPC_OBJTYPE_GENERIC, sec_addr_index);
			op_ima_obj_attr_get_str (sec_addr_objid, "Address", 32, intf_addr_str);
			op_ima_obj_attr_get_str (sec_addr_objid, "Subnet Mask", 32, intf_smask_str);
			ip_addr = ip_address_create (intf_addr_str);
			subnet_mask_addr = ip_address_create (intf_smask_str);

			sec_addr_ptr = (IpT_Secondary_Address *) op_prg_mem_alloc (sizeof (IpT_Secondary_Address));
			sec_addr_ptr->ip_addr_range.address = ip_addr;

			/* the actual subnet mask used for ALT interfaces is /32.	*/
			sec_addr_ptr->ip_addr_range.subnet_mask = ip_address_copy (IpI_Broadcast_Addr);
			sec_addr_ptr->inet_addr_range = inet_ipv4_address_range_create (ip_addr, IpI_Broadcast_Addr);

			/* Register the address with the global package so that other utilities	*/
			/* like reports, ping initialization etc. are aware of this address.	*/
			inet_addr = inet_address_from_ipv4_address_create (ip_addr);
			ip_rtab_local_addr_register (&inet_addr, &module_data);

			op_prg_list_insert (&sec_addr_list, sec_addr_ptr, OPC_LISTPOS_TAIL);
			} /* End for all secondary addresses on the interface	*/

		/* Move the address ranges from the list to an array.	*/
		num_sec_addrs = op_prg_list_size (&sec_addr_list);

		if (num_sec_addrs > 0)
			{
			sec_addr_table_ptr = (IpT_Sec_Addr_Table *) op_prg_mem_alloc (sizeof (IpT_Sec_Addr_Table));
			sec_addr_table_ptr->num_sec_addresses = num_sec_addrs;
			sec_addr_table_ptr->sec_addr_array = (IpT_Secondary_Address *) op_prg_mem_alloc (num_sec_addrs * sizeof (IpT_Secondary_Address));

			for (sec_addr_index = 0; sec_addr_index < num_sec_addrs; sec_addr_index++)
				{
				sec_addr_ptr = (IpT_Secondary_Address *) op_prg_list_remove (&sec_addr_list, OPC_LISTPOS_HEAD);
				sec_addr_table_ptr->sec_addr_array [sec_addr_index] = *sec_addr_ptr;
				op_prg_mem_free (sec_addr_ptr);
				}
			iface_info_ptr->sec_addr_tbl_ptr = sec_addr_table_ptr;
			}
		}
	FRET (iface_info_ptr);
	}

static int
ip_dispatch_dual_msfc_alt_config_parse (void)
	{
	int						num_alt_intf = 0, num_alt_intf_types = 3, alt_intf_type_index, num_intf, intf_index;
	const char*	 			alt_intf_types [] = {"Loopback Interfaces", "Tunnel Interfaces", "VLAN Interfaces"};
	Objid					intf_cmpd_objid, alt_objid, intf_objid;
	IpT_Interface_Info		*iface_info_ptr, *vlan_intf_ptr;
	List					vlan_intf_list;
	IpT_Address				ip_addr, subnet_mask_addr;
	Boolean					loopback_intf;

	/** Parses the addresses present under the non-designated router parameters	**/
	/** and creates loopback interfaces. This will help in sourcing and sinking	**/
	/** traffic from the alt addresses.											**/
	FIN (ip_dispatch_dual_msfc_alt_config_parse ());

	op_prg_list_init (&vlan_intf_list);
	
	op_ima_obj_attr_get_objid (module_data.node_id, "Non-Designated MSFC Configuration", &alt_objid);
	alt_objid = op_topo_child (alt_objid, OPC_OBJTYPE_GENERIC, 0);

	/* Loop through all interfaces that have alt configuration.	*/
	for (alt_intf_type_index = 0; alt_intf_type_index < num_alt_intf_types; alt_intf_type_index++)
		{
		op_ima_obj_attr_get_objid (alt_objid, alt_intf_types [alt_intf_type_index], &intf_cmpd_objid);
		num_intf = op_topo_child_count (intf_cmpd_objid, OPC_OBJTYPE_GENERIC);

		loopback_intf = (strcmp (alt_intf_types [alt_intf_type_index], "Loopback Interfaces") == 0);

		/* Loop through all interfaces for a given type (loopback, tunnel, VLAN).	*/
		for (intf_index = 0; intf_index < num_intf; intf_index++)
			{
			intf_objid = op_topo_child (intf_cmpd_objid, OPC_OBJTYPE_GENERIC, intf_index);

			iface_info_ptr = ip_dispatch_dual_msfc_alt_interface_parse (intf_objid, loopback_intf);

			if (iface_info_ptr != OPC_NIL)
				{
				num_alt_intf++;

				/* For tunnel and loopback interfaces, we set the alt interface to be of 	*/
				/* type loopback, to prevent IP from trying to forward packets on these 	*/
				/* interfaces.																*/
				if (strcmp (alt_intf_types [alt_intf_type_index], "VLAN Interfaces") != 0)
					{
					iface_info_ptr->phys_intf_info_ptr->intf_status = IpC_Intf_Status_Loopback;
					op_prg_list_insert (module_data.interface_table_ptr, iface_info_ptr, OPC_LISTPOS_TAIL);
					}
				else
					{
					/* For VLAN interfaces, we create a dummy physical interface and set the	*/
					/* configured interfaces as subinterfaces of this physical interface. This	*/
					/* is required by ARP to respond to queries for these addresses.			*/
					op_prg_list_insert (&vlan_intf_list, iface_info_ptr, OPC_LISTPOS_TAIL);
					}
				}
			} /* End for all interfaces within a given interface type	*/
		} /* End for all interface types with alt addresses	*/

	/* If there is at least one alt VLAN interface, create the dummy physical interface that	*/
	/* will serve as the parent of the VLAN interfaces.											*/
	num_intf = op_prg_list_size (&vlan_intf_list);

	if (num_intf > 0)
		{
		num_alt_intf++;

		/*	Create and initialize a new cell to hold the interface	*/
		iface_info_ptr = ip_interface_info_create (IPC_PHYS_INTF);
		
		/* Set the addr_index to an invalid value.		*/
		iface_info_ptr->phys_intf_info_ptr->ip_addr_index = IPC_ADDR_INDEX_IVNALID;

		/* We do not want to send packets out of this interface.	*/
		iface_info_ptr->phys_intf_info_ptr->port_num = IPC_PORT_NUM_INVALID;
		iface_info_ptr->phys_intf_info_ptr->in_port_num = IPC_PORT_NUM_INVALID;
				
		/* Set the physical interface IP address to "No IP address".	*/
		ip_addr = ip_address_copy (IpI_No_Ip_Address);
		subnet_mask_addr = IpI_Broadcast_Addr;

		iface_info_ptr->network_address = ip_address_mask (ip_addr, subnet_mask_addr);		
		iface_info_ptr->addr_range_ptr 	= ip_address_range_create (ip_addr, subnet_mask_addr);
		iface_info_ptr->inet_addr_range = inet_ipv4_address_range_create (ip_addr, subnet_mask_addr);

		/* Set the interface MTU.	*/
		iface_info_ptr->mtu	= 1500;

		/* Store the status of the interface; Active, Shutdown, 	*/
		/* a loopback, tunnel or unconnected interface.				*/
		iface_info_ptr->phys_intf_info_ptr->intf_status = IpC_Intf_Status_Active;
		
		/* Set the subintf_addr_index to IPC_SUBINTF_PHYS_INTF (-1) */
		/* to indicate that this is a physical interface.			*/
		iface_info_ptr->subintf_addr_index = IPC_SUBINTF_PHYS_INTF;
		
		/* No routing protocols should be supported on this interface.	*/
		iface_info_ptr->routing_protocols_lptr = ip_interface_routing_protocols_obtain (OPC_OBJID_INVALID,
				OPC_OBJID_INVALID, IpC_Intf_Status_Shutdown, OPC_NIL);				
		
		iface_info_ptr->phys_intf_info_ptr->connected_link_objid = OPC_OBJID_INVALID;
		iface_info_ptr->phys_intf_info_ptr->link_status = 1;
	
		/* Store the interface name.								*/
		ip_rte_intf_name_set (iface_info_ptr, "RSM-ALT");
		iface_info_ptr->flags |= IPC_INTF_FLAG_MSFC_ALT;
	
		/* The default bandwidth for VLAN interfaces is 10 Mbps.	*/
		iface_info_ptr->phys_intf_info_ptr->link_bandwidth = 10e6;

		/* Initialize the available bandwidth to interface speed */
		iface_info_ptr->avail_bw = iface_info_ptr->phys_intf_info_ptr->link_bandwidth;				
	
		/*	Initialize the outbound load from this interface. Also	*/
		/*	set the reliability of the interface as 100% reliable.	*/
		iface_info_ptr->load_bits 	= 0.0;
		iface_info_ptr->load_bps 	= 0.0;
		iface_info_ptr->reliability = 1.0;

		/* For the time being, we do not know whether we are using	*/
		/* slots or not.  This will be filled in appropriately 		*/
		/* if slots are created.									*/
		iface_info_ptr->phys_intf_info_ptr->slot_index = OMSC_DV_UNSPECIFIED_SLOT;
	
		/* Store the type of this interface. This is required in 	*/
		/* determining whether a ICI is to be associated with the	*/
		/* packets sent throug this interface. We do not have to 	*/
		/* associate any ICI with packets sent out through "slip"	*/
		/* interfaces.												*/
		iface_info_ptr->phys_intf_info_ptr->intf_type = IpC_Intf_Type_Smart;

		/* Set Layer2 mapping.	*/
		iface_info_ptr->layer2_mappings.vlan_identifier = OMSC_VLAN_NULL_VID;
		iface_info_ptr->layer2_mappings.num_atm_pvcs 	= 0;
		iface_info_ptr->layer2_mappings.num_fr_pvcs 	= 0; 
	
		/* Set the number of configured subinterfaces.	*/
		iface_info_ptr->phys_intf_info_ptr->num_subinterfaces = num_intf;

		/* Allocate enough memory.										*/
		iface_info_ptr->phys_intf_info_ptr->subintf_pptr = (IpT_Interface_Info**)
			op_prg_mem_alloc (num_intf * sizeof (IpT_Interface_Info*));
	
		/* Copy the valid subinterfaces alone.							*/
		for (intf_index = 0; intf_index < num_intf; intf_index++)
			{
			vlan_intf_ptr = (IpT_Interface_Info *) op_prg_list_remove (&vlan_intf_list, OPC_LISTPOS_HEAD);
			iface_info_ptr->phys_intf_info_ptr->subintf_pptr[intf_index] = vlan_intf_ptr;
			}
		op_prg_list_insert (module_data.interface_table_ptr, iface_info_ptr, OPC_LISTPOS_TAIL);
		}

	FRET (num_alt_intf);
	}
			
static Boolean
ip_node_dual_msfc_status_determine (void)
	{
	Boolean 				is_dual_msfc_in_drm = OPC_FALSE;
	Objid					msfc_params_objid;
	char					msfc_mode [32];
	Boolean					config_sync_enabled;
	
	FIN (ip_node_dual_msfc_status_determine ());
	
	if (!(op_ima_obj_attr_exists (module_data.node_id, "MSFC Parameters")))
		FRET (OPC_FALSE);
			
	op_ima_obj_attr_get_objid (module_data.node_id, "MSFC Parameters", &msfc_params_objid);
	msfc_params_objid = op_topo_child (msfc_params_objid, OPC_OBJTYPE_GENERIC, 0);
	
	op_ima_obj_attr_get_str (msfc_params_objid, "MSFC Mode", 32, msfc_mode);

	if (strcmp (msfc_mode, "Hybrid-DRM") != 0)
		FRET (OPC_FALSE);
	
	/* We support only config sync enabled.	*/
	op_ima_obj_attr_get_toggle (msfc_params_objid, "Configuration Synchronization", &config_sync_enabled);
		if (config_sync_enabled)
		{
		is_dual_msfc_in_drm = OPC_TRUE;
		/* A global flag is also set. This global flag is used as an efficiency technique.	*/
		ip_support_dual_msfc_devices_exist_status_set ();
		}
	else
		{
		/* We do not support config-sync disabled. Inform user that we will default to SRM.	*/
		ipnl_dual_msfc_config_sync_disabled_unsupported_write (module_data.node_id);
		}
	FRET (is_dual_msfc_in_drm);
	}

			
	   	


/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

#if defined (__cplusplus)
extern "C" {
#endif
	void ip_dispatch_smf (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Obtype _op_ip_dispatch_smf_init (int * init_block_ptr);
	VosT_Address _op_ip_dispatch_smf_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int);
	void _op_ip_dispatch_smf_diag (OP_SIM_CONTEXT_ARG_OPT);
	void _op_ip_dispatch_smf_terminate (OP_SIM_CONTEXT_ARG_OPT);
	void _op_ip_dispatch_smf_svar (void *, const char *, void **);


	VosT_Obtype Vos_Define_Object_Prstate (const char * _op_name, unsigned int _op_size);
	VosT_Address Vos_Alloc_Object_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype _op_ob_hndl);
	VosT_Fun_Status Vos_Poolmem_Dealloc_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Address _op_ob_ptr);
#if defined (__cplusplus)
} /* end of 'extern "C"' */
#endif




/* Process model interrupt handling procedure */


void
ip_dispatch_smf (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (ip_dispatch_smf ());

		{
		/* Temporary Variables */
		/* used for transition selection */
		int						intrpt_type;
		int						invoke_mode;
		int						intrpt_code;
		
		/* End of Temporary Variables */


		FSM_ENTER ("ip_dispatch_smf")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "ip_dispatch_smf [init enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [init enter execs]", state0_enter_exec)
				{
				ip_dispatch_do_init ();
				
				/* Clear the routes dump for IP flows and MPLS LSP	*/
				if (ip_mpls_dump_file_cleared == OPC_FALSE)
					{
					/* Clear the IP flows	*/
					Oms_Ext_File_Clear (OMSC_EXT_FILE_PROJ_SCEN_NAME, "conv_flow_routes", OMSC_EXT_FILE_GDF);
						
					/* Clear the MPLS LSP	*/
					Oms_Ext_File_Clear (OMSC_EXT_FILE_PROJ_SCEN_NAME, "lsp_route_dump", OMSC_EXT_FILE_GDF);
									
					ip_mpls_dump_file_cleared = OPC_TRUE;
					}
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"ip_dispatch_smf")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "ip_dispatch_smf [init exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [init exit execs]", state0_exit_exec)
				{
				/* Capture the type of interrupt into this place-holder. It is used in the	*/
				/* Header Block (HB) to define the transition out of here.					*/
				intrpt_type = op_intrpt_type ();
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (init) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIFICATION), 1, state1_enter_exec, ip_dispatch_wait_for_registrations ();, init, "SELF_NOTIFICATION", "ip_dispatch_wait_for_registrations ()", "init", "wait", "ip_dispatch_smf [init -> wait : SELF_NOTIFICATION / ip_dispatch_wait_for_registrations ()]")
				/*---------------------------------------------------------*/



			/** state (wait) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "wait", state1_enter_exec, "ip_dispatch_smf [wait enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"ip_dispatch_smf")


			/** state (wait) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "wait", "ip_dispatch_smf [wait exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [wait exit execs]", state1_exit_exec)
				{
				/* Capture the type of interrupt into this place-holder. It is used in the	*/
				/* Header Block (HB) to define the transition out of here.					*/
				intrpt_type = op_intrpt_type ();
				
				/*  Call a function to Initialize the MPLS LSP table 						*/
				/* If there is a MPLS Config Object in the network then LSP table might		*/
				/* have already been initialized, so this functionm will just return back,	*/
				/* doing nothing in this case. Whereas, if MPLS Config Object is not there	*/
				/* in the network, then this function will parse any LSPs present in		*/
				/* the network																*/
				/* Note: If there is no MPLS in the network, at all. i.e. no LSPs then 		*/
				/* This function will just look for LSPs and will do nothing				*/
				Mpls_Path_Support_Lsp_Table_Init ("Not Used");
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (wait) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIFICATION), 2, state2_enter_exec, ip_dispatch_init_phase_2 ();, wait, "SELF_NOTIFICATION", "ip_dispatch_init_phase_2 ()", "wait", "cmn_rte_tbl", "ip_dispatch_smf [wait -> cmn_rte_tbl : SELF_NOTIFICATION / ip_dispatch_init_phase_2 ()]")
				/*---------------------------------------------------------*/



			/** state (cmn_rte_tbl) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "cmn_rte_tbl", state2_enter_exec, "ip_dispatch_smf [cmn_rte_tbl enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [cmn_rte_tbl enter execs]", state2_enter_exec)
				{
				/** This state is used to initiate the initial redistribution of routing	**/
				/** information between the routing protocols configured on this router.	**/
				/** This is done via an invocation of the ip_cmn_rte_table_redistribute		**/
				/** function in the executive of the transition out of this state.			**/
				
				/* Schedule a self-interrupt so we can move into the exit executives of		*/
				/* this state.																*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"ip_dispatch_smf")


			/** state (cmn_rte_tbl) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "cmn_rte_tbl", "ip_dispatch_smf [cmn_rte_tbl exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [cmn_rte_tbl exit execs]", state2_exit_exec)
				{
				/* Capture the type of interrupt into this place-holder. It is used in the	*/
				/* Header Block (HB) to define the transition out of here.					*/
				intrpt_type = op_intrpt_type ();
				}
				FSM_PROFILE_SECTION_OUT (state2_exit_exec)


			/** state (cmn_rte_tbl) transition processing **/
			FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [cmn_rte_tbl trans conditions]", state2_trans_conds)
			FSM_INIT_COND (SELF_NOTIFICATION_ACTIVE)
			FSM_TEST_COND (INACTIVE)
			FSM_TEST_LOGIC ("cmn_rte_tbl")
			FSM_PROFILE_SECTION_OUT (state2_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 3, state3_enter_exec, ip_dispatch_distribute_routing_info ();, "SELF_NOTIFICATION_ACTIVE", "ip_dispatch_distribute_routing_info ()", "cmn_rte_tbl", "init_too", "ip_dispatch_smf [cmn_rte_tbl -> init_too : SELF_NOTIFICATION_ACTIVE / ip_dispatch_distribute_routing_info ()]")
				FSM_CASE_TRANSIT (1, 5, state5_enter_exec, ;, "INACTIVE", "", "cmn_rte_tbl", "inactive", "ip_dispatch_smf [cmn_rte_tbl -> inactive : INACTIVE / ]")
				}
				/*---------------------------------------------------------*/



			/** state (init_too) enter executives **/
			FSM_STATE_ENTER_UNFORCED (3, "init_too", state3_enter_exec, "ip_dispatch_smf [init_too enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [init_too enter execs]", state3_enter_exec)
				{
				/* This state is used to finish the initialization.	*/
				/* It involves creating the appropriate set of		*/
				/* child processes 									*/
				/* This is done via the exec executive.				*/
				
				/* Schedule a self-interrupt so we can move into the exit executives of		*/
				/* this state.																*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (7,"ip_dispatch_smf")


			/** state (init_too) exit executives **/
			FSM_STATE_EXIT_UNFORCED (3, "init_too", "ip_dispatch_smf [init_too exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [init_too exit execs]", state3_exit_exec)
				{
				/* Capture the type of interrupt into this place-holder. It is used in the	*/
				/* Header Block (HB) to define the transition out of here.					*/
				intrpt_type = op_intrpt_type ();
				ip_dispatch_cleanup_and_create_child_processes ();
				
				/* Determine if we are being invoked by one of the child proceses	*/
				/* maintained by IP. Note that "ip_icmp" is used for ICMP messages	*/
				/* (currently only supports "ping") and "oms_basetraf_src" is used	*/
				/* background utilization traffic specification generation.			*/
				invoke_prohandle = op_pro_invoker (module_data.ip_root_prohandle, &invoke_mode);
				if ((invoke_mode != OPC_PROINV_INDIRECT) && (invoke_mode != OPC_PROINV_DIRECT))
					{
					ip_dispatch_error ("Unable to determine if how IP process got invoked."); 	
					}
				
				/* Initialize the load balancer. */
				ip_dispatch_load_balancer_init ();
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (init_too) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIFICATION), 4, state4_enter_exec, ;, init_too, "SELF_NOTIFICATION", "", "init_too", "idle", "ip_dispatch_smf [init_too -> idle : SELF_NOTIFICATION / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (4, "idle", state4_enter_exec, "ip_dispatch_smf [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (9,"ip_dispatch_smf")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (4, "idle", "ip_dispatch_smf [idle exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [idle exit execs]", state4_exit_exec)
				{
				/* determine the interrupt type */
				intrpt_type = op_intrpt_type ();
				intrpt_code = op_intrpt_code ();
				
				/* Determine if we are being invoked by one of the child proceses	*/
				/* maintained by IP. Note that "ip_icmp" is used for ICMP messages	*/
				/* (currently only supports "ping") and "ip_basetraf_src" is used	*/
				/* background utilization traffic specification generation.			*/
				invoke_prohandle = op_pro_invoker (module_data.ip_root_prohandle, &invoke_mode);
				if ((invoke_mode != OPC_PROINV_INDIRECT) && (invoke_mode != OPC_PROINV_DIRECT))
					{
					ip_dispatch_error ("Unable to determine if how IP process got invoked."); 	
					}
				}
				FSM_PROFILE_SECTION_OUT (state4_exit_exec)


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [idle trans conditions]", state4_trans_conds)
			FSM_INIT_COND (CHILD_INVOCATION)
			FSM_TEST_COND (STRM_INTRPT)
			FSM_TEST_COND (MCAST_RSVP_VPN)
			FSM_TEST_COND (FAIL_REC)
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state4_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 4, state4_enter_exec, ip_dispatch_forward_packet ();, "CHILD_INVOCATION", "ip_dispatch_forward_packet ()", "idle", "idle", "ip_dispatch_smf [idle -> idle : CHILD_INVOCATION / ip_dispatch_forward_packet ()]")
				FSM_CASE_TRANSIT (1, 4, state4_enter_exec, ip_dispatch_strm_intrpt_handle ();, "STRM_INTRPT", "ip_dispatch_strm_intrpt_handle ()", "idle", "idle", "ip_dispatch_smf [idle -> idle : STRM_INTRPT / ip_dispatch_strm_intrpt_handle ()]")
				FSM_CASE_TRANSIT (2, 4, state4_enter_exec, ip_dispatch_handle_mcast_rsvp ();, "MCAST_RSVP_VPN", "ip_dispatch_handle_mcast_rsvp ()", "idle", "idle", "ip_dispatch_smf [idle -> idle : MCAST_RSVP_VPN / ip_dispatch_handle_mcast_rsvp ()]")
				FSM_CASE_TRANSIT (3, 4, state4_enter_exec, ip_dispatch_fail_rec_handle (intrpt_code);, "FAIL_REC", "ip_dispatch_fail_rec_handle (intrpt_code)", "idle", "idle", "ip_dispatch_smf [idle -> idle : FAIL_REC / ip_dispatch_fail_rec_handle (intrpt_code)]")
				}
				/*---------------------------------------------------------*/



			/** state (inactive) enter executives **/
			FSM_STATE_ENTER_UNFORCED (5, "inactive", state5_enter_exec, "ip_dispatch_smf [inactive enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [inactive enter execs]", state5_enter_exec)
				{
				/* This is a node whose all IP interfaces are set to Shutdown 		*/
				/* As none of the iface is active, IP will go into this INACTIVE	*/
				/* state and will not do any more processing						*/
				
				if (op_prg_odb_ltrace_active ("ip") == OPC_TRUE)
					op_prg_odb_print_minor ("IP module is entering the unconnected state.", 
											"This node is not connected to any other node and "
											"there are no valid active interfaces", OPC_NIL);
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (11,"ip_dispatch_smf")


			/** state (inactive) exit executives **/
			FSM_STATE_EXIT_UNFORCED (5, "inactive", "ip_dispatch_smf [inactive exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_dispatch_smf [inactive exit execs]", state5_exit_exec)
				{
				/* Ideally this FSM should remain in the enter	*/
				/* executive of this state when unconnected.	*/
				/* However, if there are spurious interrupts,it	*/
				/* will enter exit executive, where we have to 	*/
				/* handle various possibilities.				*/
				
				if (op_intrpt_type () == OPC_INTRPT_STRM)
					{
					/* If a packet arrives, accept and destroy */
					op_pk_destroy (op_pk_get (op_intrpt_strm ()));
					}
				}
				FSM_PROFILE_SECTION_OUT (state5_exit_exec)


			/** state (inactive) transition processing **/
			FSM_TRANSIT_FORCE (5, state5_enter_exec, ;, "default", "", "inactive", "inactive", "ip_dispatch_smf [inactive -> inactive : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"ip_dispatch_smf")
		}
	}




void
_op_ip_dispatch_smf_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
#if defined (OPD_ALLOW_ODB)
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__+1;
#endif

	FIN_MT (_op_ip_dispatch_smf_diag ())

	if (1)
		{

		/* Diagnostic Block */

		BINIT
		{
		if (is_ip_initialized == OPC_FALSE)
			{
			printf ("\t\t***************************************************************\n");
			printf ("\t\t* The IP process in this node has not been initialized.        *\n");
			printf ("\t\t* Any process has to receive atleast its \"BEGSIM\" interrupt   *\n");
			printf ("\t\t* before it can be queried.								   *\n");
			printf ("\t\t***************************************************************\n");
			}
		else
			{
			if (op_prg_odb_ltrace_active ("ip_frag"))
				{
				ip_frag_sup_print (dgram_list_ptr);
				}	
		
			if (op_prg_odb_ltrace_active ("global_table"))
				{
				ip_rtab_print ();
				}
		
			if (op_prg_odb_ltrace_active ("ip_table"))
				{
				nato_table_print (ip_table_handle);
				}
		
			if (op_prg_odb_ltrace_active ("global_ip_networks"))
				{
				ip_networks_print ();
				}
		
			if (op_prg_odb_ltrace_active ("ip_rte_table"))
				{
				ip_cmn_rte_table_print (module_data.ip_route_table);
				}
		
			if (op_prg_odb_ltrace_active ("ip_interfaces"))
				{
				ip_interface_table_print (&module_data);
				}
		
			if (op_prg_odb_ltrace_active ("ip_rte_slot"))
				{
				oms_dv_slot_table_print (slot_table_lptr);
				oms_dv_iface_slot_map_print (slot_iface_map_array, module_data.num_interfaces);
				}
		
			if (op_prg_odb_ltrace_active ("car"))
				{
				ip_rte_car_information_print ();
				}
			
			if (op_prg_odb_ltrace_active ("acl") || op_prg_odb_ltrace_active ("ext_acl"))
				{
				Inet_Acl_Table_Print (module_data.acl_ext_table, IpC_Acl_Type_Ext, module_data.node_name);
				Inet_Acl_Table_Print (module_data.acl_filter_ext_table, IpC_Acl_Type_Pix_Ext, module_data.node_name);
		
				if (ip_rte_node_ipv6_active (&module_data))
					{
					Inet_Acl_Table_Print (module_data.acl_ipv6_ext_table, IpC_Acl_Type_IPv6_Ext, module_data.node_name);
					}
				}
			
			if (op_prg_odb_ltrace_active ("acl") || op_prg_odb_ltrace_active ("pre_acl"))
				{
				Inet_Acl_Table_Print (module_data.acl_pre_table, IpC_Acl_Type_Pre, module_data.node_name);
		
				if (ip_rte_node_ipv6_active (&module_data))
					{
					Inet_Acl_Table_Print (module_data.acl_ipv6_pre_table, IpC_Acl_Type_IPv6_Pre, module_data.node_name);
					}
				}
			
			if (op_prg_odb_ltrace_active ("acl") || op_prg_odb_ltrace_active ("as_path_acl"))
				{
				Inet_Acl_Table_Print (module_data.acl_as_path_table, IpC_Acl_Type_AS, module_data.node_name);
				}
			
			if (op_prg_odb_ltrace_active ("acl") || op_prg_odb_ltrace_active ("std_acl"))
				{
				Inet_Acl_Table_Print (module_data.acl_std_table, IpC_Acl_Type_Std, module_data.node_name);
				}
			
			if (op_prg_odb_ltrace_active ("acl") || op_prg_odb_ltrace_active ("comm_acl"))
				{
				Inet_Acl_Table_Print (module_data.acl_comm_table, IpC_Acl_Type_Comm, module_data.node_name);
				}
			
			if (op_prg_odb_ltrace_active ("rte_map"))
				{
				Ip_Rte_Map_Table_Print (module_data.rte_map_table, module_data.node_name);
				}
			
			if (op_prg_odb_ltrace_active ("firewall_filter"))
				{
				Ip_Rte_Map_Table_Print (module_data.firewall_filter_table, module_data.node_name);
				}
			
			if (op_prg_odb_ltrace_active ("ip_vrf"))
				{
				int 					num_vrfs, vrf_index;
				IpT_Vrf_Table*			vrf_rte_table;
				
				num_vrfs = ip_vrf_table_num_vrfs_get (&module_data);
		
				for (vrf_index = 0; vrf_index < num_vrfs; vrf_index++)
					{
					vrf_rte_table = ip_vrf_table_for_vrf_index_get (&module_data, vrf_index);
		
					ip_cmn_rte_table_print (ip_vrf_table_cmn_rte_table_get (vrf_rte_table));
					}
				
				}			
		
			if (op_prg_odb_ltrace_active ("oms_pr"))
				{
				oms_pr_print_registry (module_data.node_id);
				}
		
			if (op_prg_odb_ltrace_active ("ip_dest_src_table"))
				{
				ip_cmn_rte_table_dest_src_table_print (module_data.ip_route_table);
				}
		
			if (op_prg_odb_ltrace_active ("oms_ptree"))
				{
				if (ip_rte_node_ipv4_active (&module_data))
					{
					oms_ptree_print (module_data.ip_route_table->ptree_ptr_array[InetC_Addr_Family_v4]);
					}
				if (ip_rte_node_ipv6_active (&module_data))
					{
					oms_ptree_print (module_data.ip_route_table->ptree_ptr_array[InetC_Addr_Family_v6]);
					}
				}
			
			if (op_prg_odb_ltrace_active ("ip_nat"))
				ip_nat_xlate_config_print (&module_data);
			
			if (op_prg_odb_ltrace_active ("ip_golr"))
				{
				ip_cmn_rte_table_golr_print (module_data.ip_route_table);
				}
		
			if (op_prg_odb_ltrace_active ("ip_default_routes"))
				{
				ip_cmn_rte_table_default_routes_print (module_data.ip_route_table);
				}
		
			if (op_prg_odb_ltrace_active ("ip_routing_protocols"))
				{
				ip_dispatch_routing_processes_print ();
				}
		
			if (op_prg_odb_ltrace_active ("ip_vrf_info"))
				{
				int 					num_vrfs, vrf_index;
				IpT_Vrf_Table*			vrf_rte_table;
				
				num_vrfs = ip_vrf_table_num_vrfs_get (&module_data);
		
				for (vrf_index = 0; vrf_index < num_vrfs; vrf_index++)
					{
					vrf_rte_table = ip_vrf_table_for_vrf_index_get (&module_data, vrf_index);
		
					ip_vrf_info_print (vrf_rte_table);
					}
				}		
			}
		}

		/* End of Diagnostic Block */

		}

	FOUT
#endif /* OPD_ALLOW_ODB */
	}




void
_op_ip_dispatch_smf_terminate (OP_SIM_CONTEXT_ARG_OPT)
	{

	FIN_MT (_op_ip_dispatch_smf_terminate ())


	/* No Termination Block */

	Vos_Poolmem_Dealloc_MT (OP_SIM_CONTEXT_THREAD_INDEX_COMMA pr_state_ptr);

	FOUT
	}


/* Undefine shortcuts to state variables to avoid */
/* syntax error in direct access to fields of */
/* local variable prs_ptr in _op_ip_dispatch_smf_svar function. */
#undef module_data
#undef is_ip_initialized
#undef child_ptr
#undef dgram_list_ptr
#undef default_ttl
#undef radio_intf_list_ptr
#undef slot_table_lptr
#undef ip_info_ptr
#undef dynamic_routing_enabled
#undef link_iface_table_ptr
#undef own_process_record_handle
#undef proc_model_name
#undef comp_attr_objid
#undef subnet_objid
#undef interface_table_size
#undef slot_iface_map_array
#undef iface_addressing_mode
#undef oms_basetraf_process_id
#undef tcpip_header_comp_info_ptr
#undef per_interface_comp_info_ptr
#undef per_virtual_circuit_comp_info_ptr
#undef igmp_host_process_handle
#undef pim_sm_process_handle
#undef custom_mrp_process_handle
#undef routing_prohandle
#undef invoke_prohandle
#undef mcast_rte_protocol
#undef passive_rip
#undef crt_export_time_lptr
#undef global_crt_export_time_lptr
#undef unknown_instrm_index_lptr
#undef static_rte_info
#undef ad_hoc_routing_protocol_str
#undef vrf_export_time_lptr

#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

VosT_Obtype
_op_ip_dispatch_smf_init (int * init_block_ptr)
	{
	VosT_Obtype obtype = OPC_NIL;
	FIN_MT (_op_ip_dispatch_smf_init (init_block_ptr))

	obtype = Vos_Define_Object_Prstate ("proc state vars (ip_dispatch_smf)",
		sizeof (ip_dispatch_smf_state));
	*init_block_ptr = 0;

	FRET (obtype)
	}

VosT_Address
_op_ip_dispatch_smf_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype obtype, int init_block)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	ip_dispatch_smf_state * ptr;
	FIN_MT (_op_ip_dispatch_smf_alloc (obtype))

	ptr = (ip_dispatch_smf_state *)Vos_Alloc_Object_MT (VOS_THREAD_INDEX_COMMA obtype);
	if (ptr != OPC_NIL)
		{
		ptr->_op_current_block = init_block;
#if defined (OPD_ALLOW_ODB)
		ptr->_op_current_state = "ip_dispatch_smf [init enter execs]";
#endif
		}
	FRET ((VosT_Address)ptr)
	}



void
_op_ip_dispatch_smf_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	ip_dispatch_smf_state		*prs_ptr;

	FIN_MT (_op_ip_dispatch_smf_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (ip_dispatch_smf_state *)gen_ptr;

	if (strcmp ("module_data" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->module_data);
		FOUT
		}
	if (strcmp ("is_ip_initialized" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->is_ip_initialized);
		FOUT
		}
	if (strcmp ("child_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->child_ptr);
		FOUT
		}
	if (strcmp ("dgram_list_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dgram_list_ptr);
		FOUT
		}
	if (strcmp ("default_ttl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->default_ttl);
		FOUT
		}
	if (strcmp ("radio_intf_list_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->radio_intf_list_ptr);
		FOUT
		}
	if (strcmp ("slot_table_lptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->slot_table_lptr);
		FOUT
		}
	if (strcmp ("ip_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ip_info_ptr);
		FOUT
		}
	if (strcmp ("dynamic_routing_enabled" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dynamic_routing_enabled);
		FOUT
		}
	if (strcmp ("link_iface_table_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->link_iface_table_ptr);
		FOUT
		}
	if (strcmp ("own_process_record_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_process_record_handle);
		FOUT
		}
	if (strcmp ("proc_model_name" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->proc_model_name);
		FOUT
		}
	if (strcmp ("comp_attr_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->comp_attr_objid);
		FOUT
		}
	if (strcmp ("subnet_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->subnet_objid);
		FOUT
		}
	if (strcmp ("interface_table_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->interface_table_size);
		FOUT
		}
	if (strcmp ("slot_iface_map_array" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->slot_iface_map_array);
		FOUT
		}
	if (strcmp ("iface_addressing_mode" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->iface_addressing_mode);
		FOUT
		}
	if (strcmp ("oms_basetraf_process_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->oms_basetraf_process_id);
		FOUT
		}
	if (strcmp ("tcpip_header_comp_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcpip_header_comp_info_ptr);
		FOUT
		}
	if (strcmp ("per_interface_comp_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->per_interface_comp_info_ptr);
		FOUT
		}
	if (strcmp ("per_virtual_circuit_comp_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->per_virtual_circuit_comp_info_ptr);
		FOUT
		}
	if (strcmp ("igmp_host_process_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->igmp_host_process_handle);
		FOUT
		}
	if (strcmp ("pim_sm_process_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pim_sm_process_handle);
		FOUT
		}
	if (strcmp ("custom_mrp_process_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->custom_mrp_process_handle);
		FOUT
		}
	if (strcmp ("routing_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->routing_prohandle);
		FOUT
		}
	if (strcmp ("invoke_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->invoke_prohandle);
		FOUT
		}
	if (strcmp ("mcast_rte_protocol" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->mcast_rte_protocol);
		FOUT
		}
	if (strcmp ("passive_rip" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->passive_rip);
		FOUT
		}
	if (strcmp ("crt_export_time_lptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->crt_export_time_lptr);
		FOUT
		}
	if (strcmp ("global_crt_export_time_lptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_crt_export_time_lptr);
		FOUT
		}
	if (strcmp ("unknown_instrm_index_lptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->unknown_instrm_index_lptr);
		FOUT
		}
	if (strcmp ("static_rte_info" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->static_rte_info);
		FOUT
		}
	if (strcmp ("ad_hoc_routing_protocol_str" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->ad_hoc_routing_protocol_str);
		FOUT
		}
	if (strcmp ("vrf_export_time_lptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->vrf_export_time_lptr);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

