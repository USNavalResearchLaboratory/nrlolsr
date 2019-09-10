
/** IP Model Suite support package		**/
/** for simulation notification logging.**/

/****************************************/
/*		Copyright (c) 1987 - 2002		*/
/*      by OPNET Technologies, Inc.		*/
/*       (A Delaware Corporation)      	*/
/*    7255 Woodmont Av., Suite 250     	*/
/*     Bethesda, MD 20814, U.S.A.       */
/*       All Rights Reserved.          	*/
/****************************************/


/** Include directives.			**/
#include <opnet.h>
#include <ip_addr_v4.h>
#include <ip_rte_v4.h>
#include <nato.h>
#include <oms_tan.h>
#include <ip_notif_log_support.h>
#include <ip_cmn_rte_table.h>
#include <ip_rte_map_support.h>
#include <ip_acl_support.h>
#include <ip_sim_attr_cache.h>
#include <string.h>
#include <ip_rte_support.h>
#include <oms_string_support.h>

/** Macros **/
#define MAX(_a, _b)		(((_a) > (_b)) ? (_a) : (_b))

/** Global data.				**/

/* Log handles for model configuration messages.	*/ 
Log_Handle				ip_addr_map_loghndl;
Log_Handle				ip_config_error_loghndl;
Log_Handle				ip_config_warning_loghndl;

/* Log handles for protocol event messages.			*/
Log_Handle				ip_prot_error_loghndl;
Log_Handle				ip_prot_warning_loghndl;
Log_Handle       		ip_packet_drop_loghndl;

/* Log handles for messages indicating unexpected	*/
/* results.											*/
Log_Handle				ip_results_warn_loghndl;

/* Log handles for KP invocation failures.			*/
Log_Handle				ip_kp_error_loghndl;

/* Log handles for IP auto assignment for radio		*/
/* nodes											*/
Log_Handle				ip_radio_2wireless_intf_loghndl;
Log_Handle				ip_radio_wireless_intf_loghndl;

   				
/* Log handle to inform user about useful results	*/
Log_Handle				ip_result_loghndl;


typedef struct
	{
	char*		demand_name;
	char*		node_name;	
	Boolean		routable;
	double		check_time;
	List*		life_cycle_lptr;	
	Objid 		demand_id;
	} IpT_Notif_Demand_Info;

/* ---- Local Functions ------ */
#if defined (__cplusplus)
extern "C" {
#endif

static void 
ipnl_invalid_ip_address_string_log_write (void* lptr, int PRG_ARG_UNUSED(i));

#if defined (__cplusplus)
} /* end of 'extern "C" {' */
#endif

/* ---- Externally Callable Procedures ---- */
void
ip_notif_log_handles_init (void)
	{
    static Boolean	ip_notif_log_handles_init = OPC_FALSE;
	int				ip_conf_log_limit		= 25;
	int				ip_proto_log_limit		= 25;
	int				ip_results_log_limit	= 25;	
	int				ip_low_lev_log_limit	= 25;

	/** This function initializes Log_Handle global vars. and as	**/
	/** a result sets up <Category, Class, Subclass> tuple instances**/
	/** that will be used to output messages to the simulation log	**/
	/** by the ip3_rte process model.								**/
	FIN (ip_notif_log_handles_init (void))

	if (ip_notif_log_handles_init == OPC_FALSE)
		{
		/* If present, obtain the values set for the maximum	*/
		/* number of log entries on a per "category" basis.		*/
		if (op_ima_sim_attr_exists (IPC_CONF_LOG_LIMIT))
			{
			op_ima_sim_attr_get (
				OPC_IMA_INTEGER, IPC_CONF_LOG_LIMIT, &ip_conf_log_limit);
	   	 	}

		if (op_ima_sim_attr_exists (IPC_PROTO_LOG_LIMIT))
		    {
			op_ima_sim_attr_get (
				OPC_IMA_INTEGER, IPC_PROTO_LOG_LIMIT, &ip_proto_log_limit);
	    	}

		if (op_ima_sim_attr_exists (IPC_RESULTS_LOG_LIMIT))
			{
			op_ima_sim_attr_get (
				OPC_IMA_INTEGER, IPC_CONF_LOG_LIMIT, &ip_results_log_limit);
			}

		if (op_ima_sim_attr_exists (IPC_LOW_LEV_LOG_LIMIT))
			{
			op_ima_sim_attr_get (
				OPC_IMA_INTEGER, IPC_CONF_LOG_LIMIT, &ip_low_lev_log_limit);
			}

		/* Initialize the log handle placeholders.			*/
		ip_addr_map_loghndl			= op_prg_log_handle_create (
										OpC_Log_Category_Lowlevel,
										"IP",
										"Address_Mapping_via_NATO",
										ip_conf_log_limit);

		ip_prot_error_loghndl		= op_prg_log_handle_create (
										OpC_Log_Category_Protocol,
										"IP",
										"Protocol_Error",
										ip_proto_log_limit);

		ip_prot_warning_loghndl		= op_prg_log_handle_create (
										OpC_Log_Category_Protocol,
										"IP",
										"Protocol_Warning",
										ip_proto_log_limit);

		ip_config_error_loghndl		= op_prg_log_handle_create (
										OpC_Log_Category_Configuration,
										"IP",
										"Model_Configuration_Error",
										ip_conf_log_limit);

		ip_config_warning_loghndl	= op_prg_log_handle_create (
										OpC_Log_Category_Configuration,
										"IP",
										"Model_Configuration_Warning",
										ip_conf_log_limit);

		ip_kp_error_loghndl			= op_prg_log_handle_create (
										OpC_Log_Category_Lowlevel,
										"IP",
										"KP_Invocation_Error",
										ip_low_lev_log_limit);

		ip_results_warn_loghndl		= op_prg_log_handle_create (
										OpC_Log_Category_Results,
										"IP",
										"Unexpected_Results",
										ip_results_log_limit);

		ip_packet_drop_loghndl		= op_prg_log_handle_create (
										OpC_Log_Category_Protocol,
										"IP",
										"Packet Drop",
										ip_proto_log_limit);

       ip_radio_2wireless_intf_loghndl 	= op_prg_log_handle_create (
										OpC_Log_Category_Protocol,
										"IP",
										"Wireless2Intf_Auto_Assignment_Warning",
										ip_proto_log_limit);

       ip_radio_wireless_intf_loghndl 	= op_prg_log_handle_create (
										OpC_Log_Category_Protocol,
										"IP",
										"Static_Auto_Assignment_Warning",
										ip_proto_log_limit);	   

	   ip_result_loghndl				= op_prg_log_handle_create (
		   								OpC_Log_Category_Results,
										"IP",
										"Results",
										ip_results_log_limit);

		ip_notif_log_handles_init = OPC_TRUE;
		}

	FOUT
	}

void
ipnl_duplicate_ip_address_error (const char* addr, const char* mask)
	{
	/** Logs when detecting a duplicate IP address.	**/
	FIN (ipnl_duplicate_ip_address_error (addr, mask));

	op_prg_log_entry_write (ip_config_error_loghndl,
		"ERROR:\n"
		" IP address auto-assignment procedure detected the\n"
		" following address to be configured on more than\n"
		" one IP interface in this network:\n"
		"\n"
		"   Network Address: %s\n"
		"   Subnet Mask:     %s\n"
		"\n"
		" The interface with duplicate address may also be \n"
		" a tunnel interface.	\n"
		"\n"	
		"LOCATION:\n"
		" You can obtain the location of the duplicate IP\n"
		" address assignment using the following approaches:\n"
		"\n"
		" 1. Run \"IP Addressing\" specific NetDoctor rules.\n"
		"    (i.e., using NetDoctor Validation)\n"
		" 2. Using \"Protocols->IP->Addressing->Select Node\n"
		"	 with Specified IP Address...\" menu item.\n"
		"\n"
		"SUGGESTION:\n"
		" In order to run a discrete event simulation using\n"
		" this network, you may choose either of the following\n"
		" workarounds:\n"
		"\n"
		"   1. Make all IP address assignments unique.\n"
		"   2. Set the simulation attribute \"IP Interface\n"
		"      Addressing Mode\" to \"Manually Addressed\".\n"
		"\n"
		" NOTE: For networks created by importing information\n"
		" from router configuration files use option 2.\n"
		" \n",		
		addr, mask);
	
	FOUT;
	}

void
ipnl_addresses_unavailable_in_subnet_error (const char* subnet)
	{
	/** Logs when no more addresses are avaialibe in a subnet	**/
	
	FIN (ipnl_addresses_unavailable_in_subnet_error (subnet));
	
	op_prg_log_entry_write (ip_config_error_loghndl,
		"ERROR:\n"
		" IP address auto-assignment procedure detected that\n"
		" there are no more addresses available in this subnet\n"
		"\n"
		"   Subnet Address: %s\n"
		"\n"
		"SUGGESTION:\n"
		" Use a new subnet for assigning further IP addresses.\n",
		subnet);
	FOUT;
	}

void
ipnl_incompatible_subnet_error (const char* subnet, const char* prev_subnet, const char* objects)
	{
	/** Logs when incompatible subnet mask is used		**/
	
	FIN (ipnl_incompatible_subnet_error (subnet, prev_subnet, objects));
	
	op_prg_log_entry_write (ip_config_error_loghndl,
		"ERROR:\n"
		" IP address auto-assignment procedure detected that\n"
		" there was an incompatible subnet mask used.\n"
		"\n"
		"   Subnet 1: %s\n"
		"   Subnet 2: %s\n"
		"\n"
		"LOCATION:\n"
		" You can check the interfaces of the following nodes\n"
		" and links against neighbors:\n"
		" %s\n"
		"\n"
		"SUGGESTION:\n"
		" Make sure that all subnet masks are compatible with\n"
		" neighbor's subnet masks.\n",
		subnet, prev_subnet, objects);
	FOUT;
	}

void
ipnl_incompatible_network_addresses_error (const char* address, const char* cand_address)
	{
	/** Logs when incompatible subnet addresses are used	**/
	
	FIN (ipnl_incompatible_network_addresses_error (address, cand_address));
	
	op_prg_log_entry_write (ip_config_warning_loghndl,
		"WARNING:\n"
		" IP address auto-assignment procedure detected that\n"
		" there are incompatible subnet addresses used on the\n"
		" same network. IP expects all interfaces connected to\n"
		" a lower layer network (e.g an ethernet network) to\n"
		" belong to the same IP subnet, i.e the network address\n"
		" portion of their addresses should be the same.\n"
		" The different network addresses detected in the same\n"
		" lower layer network are:\n"
		"\n"
		"   Network Address 1: %s\n"
		"   Network Address 2: %s\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. If the lower layer network is logically partitioned\n"
	 	"   through the use of VLANs, PVCs etc. and the interfaces\n"
		"   belonging to the two IP subnets are in different\n"
		"   partitions, this is not an error and this log\n"
		"   message may be ignored.\n"
		"2. Otherwise, make sure that the above condition is\n"
		"   met by all interfaces in the IP subnets listed above.\n"
		"\n"
	    "RESULT(s):\n"
		"1. Interfaces in different IP subnets will not be able\n"
		"   to send packets to each other.\n"
		"2. Packets broadcasted on one IP subnet might not be\n"
		"   handled correctly by nodes belonging to the other\n"
		"   IP subnet.\n",
		address, cand_address);
	FOUT;
	}

void
ipnl_incompatible_address_and_subnet_error (const char* address, const char* mask, const char* objects)
	{
	/** Logs when an address and subnet mask conflict		**/
	
	FIN (ipnl_incompatiable_address_and_subnet_error (address, mask, objects));
	
	op_prg_log_entry_write (ip_config_error_loghndl,
		"ERROR:\n"
		" IP address auto-assignment procedure detected that\n"
		" there is an address and subnet conflict.\n"
		"\n"
		"   Address:      %s\n"
		"   Subnet Mask:  %s\n"
		"\n"
		"LOCATION:\n"
		" You can check the following interfaces and it's\n"
		" neighbors:\n"
		"%s\n"
		"\n"
		"SUGGESTION:\n"
		" Make sure that all IP addresses correspond to a\n"
		" legal and coinciding subnet mask.\n",
		address, mask, objects);
	FOUT;
	}

void
ipnl_cfgerr_multiple_rte_protocol (void)
	{
	/** This log message is called when it is detected 	**/
	/** that the network has been configured to use more**/
	/** than one routing protocol.						**/
	FIN (ipnl_cfgerr_multiple_rte_protocol (void));

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(s):\n"
		" The network model has been configured with \n" 
		" more than one routing protocol.  E.g Some	\n"
		" routers could have been configured to		\n"
		" run RIP while some others might have  		\n"
		" OSPF or IGRP running.						\n"
		"SUGGESTION(S):\n"	
		" Configure all the routers to use the same	\n"
		" routing protocol. Edit the attribute		\n"
		" \"IP Routing Information\" so that the 	\n"
		"entire network runs the same routing protocol\n");

	FOUT;
	}

void
ipnl_invalid_default_route (const char* default_rte_str, InetT_Addr_Family addr_family)
	{
	const char* proto_params_str;

	/** Writes a log message indicating that the string	**/
	/** specified under the Default Route attribute of	**/
	/** a node does not represent a valid IP address.	**/

	FIN (ipnl_invalid_default_route (default_rte_str, addr_family));

	/* Set the proto_params_str appropriately.			*/
	if (InetC_Addr_Family_v4 == addr_family)
		{
		proto_params_str = "IP Host Parameters";
		}
	else
		{
		proto_params_str = "IPv6 Parameters";
		}

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(S):\n"
		"1. The %s default route specified on this node is\n"
		"   invalid. The string \"%s\" specified under\n"
		"   the %s->Default Route attribute of this node\n"
		"   does not represent a valid %s address.\n"
		"\n"
		"SUGGESTION(S):\n"
		"1. Make sure the above attribute value is set to\n"
		"   a valid IP address.\n"
		"\n"
		"RESULT(S):\n"
		"1. This attribute will be reset to \"Auto Assigned\"\n",
		inet_addr_family_string (addr_family), default_rte_str,
		proto_params_str, inet_addr_family_string (addr_family));

	FOUT;
	}

void
ipnl_cfgerr_defroute (InetT_Addr_Family addr_family)
	{
	const char*	protocol_name;
	const char*	attribute_name;
	static Boolean message_written = OPC_FALSE;

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgerr_defroute (addr_family));

	/* Do not write this log message more than once.	*/
	if (message_written)
		{
		FOUT;
		}

	/* Set the flag indicating that we have written the	*/
	/* log message at least once.						*/
	message_written = OPC_TRUE;

	/* Initialize the variables based on the addr family*/
	if (InetC_Addr_Family_v4 == addr_family)
		{
		protocol_name = "IPv4";
		attribute_name = "Default Route";
		}
	else
		{
		protocol_name = "IPv6";
		attribute_name = "IPv6 Default Route";
		}

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(S):\n"
		" The %s default route for this node\n"
		" has not been explicitly configured.\n"
		"\n"
		"SUGGESTIONS:\n"
		" 1. If the network contains only one %s\n"
		"    subnet, this message my be ignored.\n"
		" 2. Set the IP Host Parameters->%s \n"
		"    attribute on this node to the address\n"
		"    of a router interface in the same IP subnet.\n"
		" 3. IPv4 default routes may be automatically\n"
		"    assigned by setting the simulation attribute\n"
		"    \"IP Interface Addressing Mode\" to\n"
		"    \"Auto Addressed\" or \"Auto Addressed/Export\"\n"
		"RESULT(s):\n"
		"1. This node will not be able to send packets to\n"
		"   nodes that are not in the same IP subnet.\n"
		"\n"
		"Note: this message will not be repeated.\n",
		protocol_name, protocol_name, attribute_name);

	FOUT;
	}

void
ipnl_default_gtwy_configuration_ignored_log_write (void)
	{
	static Boolean	log_written = OPC_FALSE;

	/** Write a log message warning the user that the	**/
	/** IP Routing Parameters -> Default Gateway 		**/
	/** attribute configuration is being ignored.		**/

	FIN (ipnl_default_gtwy_configuration_ignored_log_write (void));

	/* Do not write this message multiple times.		*/
	if (OPC_FALSE == log_written)
		{
		op_prg_log_entry_write (
			ip_config_warning_loghndl,
			"WARNING(S):\n"
			"The IP Routing Parameters -> Default Gateway\n"
			"attribute configuration on this node is\n"
			"being ignored.\n"
			"\n"
			"POSSIBLE CAUSE(S):\n"
			"This attribute is no longer used.\n"
			"\n"
			"SUGGESTIONS:\n"
			" 1. To configure the gateway of last resort\n"
			"    on this node, use either the\n"
			"    IP Routing Parameters -> Default Network(s)\n"
			"    attribute or configure a static route to\n"
			"    0.0.0.0/0.\n");
		log_written = OPC_TRUE;
		}

	FOUT;
	}

void
ipnl_cfgwarn_intfcfg (int intf_index)
	{
	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_intfcfg (intf_index))

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING:\n"
		" Could not map the %d'th row in \"IP\n"
		" Address Information\" to an IP interface.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" An extra row has been added by the user to\n"
		" the \"IP Address Information\" attribute.\n" 
		"\n"
		"SUGGESTIONS:\n"
		" Delete row number %d from the \"IP\n"
		" Address Information\" attribute.\n"
		"\n"
		"NOTE:\n"
		" Row numbers in compound attributes start\n"
		" at zero.",
		intf_index, intf_index);

	FOUT
	}

void			
ipnl_missing_rows_in_intf_info_log_write (int num_cattr_rows, int total_num_phy_intf)
	{
	/** This function prints out a log message			**/
	/** indicating that the number of rows in the 		**/
	/** Interface Information compound attribute is		**/
	/** less than the number of physical interfaces of	**/
	/** this node.										**/

	FIN (ipnl_missing_rows_in_intf_info_log_write (num_cattr_rows, total_num_phy_intf));

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		" The number of rows under the \"IP Routing Parameters ->\n"
		" Interface Information\" compound attribute\n"
		" of this node does not match the actual\n"
		" number of physical interfaces of this node. The\n"
		" number of rows in the compound attribute is (%d),\n"
		" but the number of interfaces is (%d).\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" 1. The number of rows was manually changed.\n"
		" 2. The attribute \"model\" of this node was changed.\n"
		" 3. The node model architecture was manually modified\n"
		"    using the node editor.\n"
		"\n"
		"SUGGESTION(S):\n"
		" 1. Remove this node from the network and replace it\n"
		"    with a new one from the object palette. Note\n"
		"    that you will need to repeat any configuration\n"
		"    that you might have done on this node.\n"
		" 2. If this node model was manually modified,\n"
		"    recreate it using Device Creator.\n",
		num_cattr_rows, total_num_phy_intf);

	FOUT;
	}	

void
ipnl_cfgwarn_compcfg (int intf_index, int subintf_row_num)
	{
	char			subintf_name_str[128];

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_compcfg (intf_index, subintf_row_num))

	if (IPC_SUBINTF_PHYS_INTF == subintf_row_num)
		{
		/* This is the physical interface.				*/
		/* Set the subintf_name_str to the null string	*/
		strcpy (subintf_name_str, "");
		}
	else
		{
		/* This is a subinterface. Create an appropriate*/
		/* string for output							*/
		sprintf (subintf_name_str, "subinterface %d of ", subintf_row_num);
		}
	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING:\n"
		" Could not apply TCP/IP Header Compression\n"
		" to the datagram to be forwarded through\n"
		" %s the interface %d.\n"
		"Forwarding the datagram uncompressed.\n"
		"\n"
		"CAUSE:\n"
		" The size of the datagram is greater than\n"
		" the mtu of the interface.\n" 
		"\n"
		"NOTE:\n"
		" TCP/IP Header Compression is a compression\n"
		" scheme used for IP datagrams with\n"
        " relatively small payload transferred on\n"
		" slow links.\n"	
		"\n"
		"SUGGESTIONS:\n"
		" 1) Reduce the size of IP datagram by\n"
        "    reducing the application size.\n"
		" 2) Increase the mtu of interface %d\n"
        " 3) Use another compression method for\n"
        "    interface %d\n",
		intf_index, subintf_name_str, intf_index, intf_index);

	FOUT
	}

void			
ipnl_unnumbered_interface_made_auto_assigned (char* iface_name)
	{
	/** Detected an unnumbered interface that is not	**/
	/** running ospf. it will be made auto assigned.	**/

	FIN (ipnl_unnumbered_interface_made_auto_assigned (iface_name));

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(S):\n"
		" The interface %s of this node was configured as\n"
		" \"Unnumbered\", but the routing protocol on this\n"
		" interface was not set to OSPF. Currently \n"
		" all unnumbered interfaces are required\n"
		" to run ospf as the only routing protocol.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Set the address of this interface to \"Auto Assigned\"\n"
		"2. Manually assign a valid IP address to this interface.\n"
		"3. Set the routing protocol on this interface to ospf.\n"
		"\n"
		"RESULT(s):\n"
		"1. The address of this interface will be set to\n"
		"   \"Auto Assigned\".\n",
		iface_name);

	FOUT;
	}


void
ipnl_protwarn_pkformat (SimT_Pk_Id pkid, SimT_Pk_Id pktreeid, const char* pkformat)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_protwarn_pkformat (pkid, pktreeid, pkformat))

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" A packet with the wrong format has been\n"
		" received by the IP model.\n"
		" \tRcvd. Packet ID\t\t= " SIMC_PK_ID_FMT "\n"
		" \tRcvd. Packet Tree ID\t= " SIMC_PK_ID_FMT "\n"
		" \tRcvd. Packet Format\t= %s\n"
		"\n"
		" Expected Packet Format is \"ip_dgram_v4\".\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" The underlying data link protocol(s) have\n"
		" routed the packet incorrectly to IP.\n"
		" Examples of data link protocols are ATM\n"
		" Frame Relay and Ethernet.\n"
		"\n"
		"SUGGESTIONS:\n"
		" Check the simulation log for messages from\n"
		" data link models that may indicate a\n"
		" possible problem.\n",
		pkid, pktreeid, pkformat);

	FOUT
	}

void
ipnl_protwarn_mcast_no_major_port_specified (Packet* pkptr, InetT_Address dest_addr)
	{
	char 		dest_addr_str [IPC_ADDR_STR_LEN];
	
	/** Reports a log message to indicate that no major	and		**/
	/** minor information is specified for the multicast packet.**/
	FIN (ipnl_protwarn_mcast_no_major_port_specified (pkptr, dest_addr));

	/* Get a printable version of the address.		*/
	inet_address_print (dest_addr_str, dest_addr);
	
	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" Application joining the multicast\n"
		" group [%s], did not specify\n"
		" the major port information for the\n"
		" multicast packet [Pkt ID: " SIMC_PK_ID_FMT ",\n"
		" Pkt Tree ID: " SIMC_PK_ID_FMT "].\n"
		"\n"
		"ACTION(S):\n"
		" Sending the multicast packet on\n"
		" the 0th major port.\n"
		"\n"
		"SUGGESTION(S):\n"
		" Specify the major and minor port\n"
		" values the packet needs to be\n"
		" multicasted on in the ICI\n"
		" ip_encap_req.v4.\n"
		"\n",
		dest_addr_str, op_pk_id (pkptr), op_pk_tree_id (pkptr));

	FOUT;
	}

void
ipnl_protwarn_mcast_custom_invalid_application_req (void)
	{
	/** Reports a log message to indicate that a 	**/
	/** Join/Leave request cannot be received from	**/
	/** an application when custom multicast routing**/
	/** protocol is being used.						**/
	FIN (ipnl_protwarn_mcast_custom_invalid_application_req (void));

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" Received a Join or Leave IP multicast\n"
		" group request for the standard IGMP model\n"
		" from the application layer. But, custom\n"
		" multicast routing protocol is specified.\n"
		"\n"
		"ACTION(S):\n"
		" Ignoring this request from the application\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" Custom multicast routing protocol is being\n"
		" used and application is sending a Join/Leave\n"
		" IP multicast group request to standard IGMP,\n"
		" but standard IGMP is disabled.\n"
		"\n"
		"SUGGESTION(S):\n"
		" Custom multicast routing protocol is being\n"
		" used, application should send Join/Leave IP\n"
		" multicast group request to custom IGMP model.\n"
		"\n");

	FOUT;
	}

void
ipnl_protwarn_mcast_invalid_application_req (void)
	{
	/** Reports a log message to indicate that an 	**/
	/** invalid request has been received from		**/
	/** an multicast application					**/
	FIN (ipnl_protwarn_mcast_invalid_application_req (void));

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" Expecting a Join or Leave IP multicast\n"
		" group request from the application but,\n"
		" received an invalid request.\n"
		"\n"
		"ACTION(S):\n"
		" Ignoring this request from the application\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" The application has used wrong value\n"
		" for the request type. The valid values\n"
		" are:\n"
		"    IpC_Igmp_Host_Join_Req and\n"
		"    IpC_Igmp_Host_Leave_Req\n"
		" Note: These constants are defined in\n"
		" ip_igmp_support.h include file\n"
		"\n"
		"SUGGESTION(S):\n"
		" Use the above mentioned constants for\n"
		" the request type.\n"
		"\n");

	FOUT;
	}


void
ipnl_protwarn_mcast_invalid_intf (int intf_num)
	{
	/** Reports a log message to indicate that multicast	**/
	/** is disabled on the given interface					**/
	FIN (ipnl_protwarn_mcast_invalid_intf (intf_num));

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" An application is trying to Join/Leave an\n"
		" IP multicast group on the IP interface, %d,\n"
		" but this interface is invalid.\n"
		"\n"
		"ACTION(S):\n"
		" Ignoring the Join/Leave request received\n"
		" from the application.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" 1. The IP interface, %d is not enabled for\n"
		"    IP multicasting.\n"
		" 2. The IP interface, %d is not connected\n"
		"    to any link.\n"
		" 3. The interface number, %d is an invalid\n"
		"    number.\n"
		"\n"
		"SUGGESTION(S):\n"
		" Make sure that the IP interface specified in\n"
		" the Join/Leave request is:\n"
		"  a) Enabled for IP multicasting. This can be\n"
		"     done by setting the attribute, 'multicast'\n"
		"     in the compound attribute, 'IP Address\n"
		"     Information' for this IP interface to\n"
		"     'Enabled'.\n"
		"  b) Is connected to a link.\n"
		"  c) Is a valid interface number.\n"
		"\n",
		intf_num, intf_num, intf_num, intf_num);

	FOUT;
	}

void
ipnl_protwarn_mcast_rte_cannot_join_leave_grp (char* ip_addr_str, int ip_intf_num)
	{
	/** Reports a log message to indicate that an application in	**/
	/** a multicast router cannot Join or Leave a multicast group	**/
	FIN (ipnl_protwarn_mcast_rte_cannot_join_leave_grp (ip_addr_str, ip_intf_num));

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" An application in a multicast router is trying\n"
		" to Join/Leave the multicast group, %s\n"
		" on the IP interface, %d. Applications in multicast\n"
		" routers cannot Join/Leave a multicast group. Only\n"
		" applications on multicast hosts are allowed to\n"
		" Join/Leave a group.\n"
		"\n"
		"ACTION(S):\n"
		" Ignoring the Join/Leave request received from\n"
		" the application.\n"
		"\n",
		ip_addr_str, ip_intf_num);

	FOUT;
	}

void
ipnl_protwarn_mcast_cannot_fwd_pkt_to_intf (Packet* pkptr, int intf_num)
	{
	/** Reports a log message to indicate that a multicast	**/
	/** packet cannot be forwarded to an IP interface		**/
	FIN (ipnl_protwarn_mcast_cannot_fwd_pkt_to_intf (pkptr, intf_num));

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" The IP multicast packet [Pkt ID: " SIMC_PK_ID_FMT ",\n"
		" Pkt Tree ID: " SIMC_PK_ID_FMT "] cannot be forwarded\n"
		" to the IP interface, %d.\n"
		"\n"
		"ACTION(S):\n"
		" Discarding the IP multicast packet.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" 1. The IP interface, %d is not enabled\n"
		"    for IP multicasting.\n"
		" 2. The IP interface, %d is not connected\n"
		"    to any link.\n"
		" 3. The IP interface number, %d is an\n"
		"    invalid interface number.\n"
		"\n"
		"SUGGESTION(S):\n"
		" 1. Set the 'multicast' attribute for the\n"
		"    IP interface, %d to 'Enabled'. This\n"
		"    attribute can be found in the compound\n"
		"    attribute 'IP Address Information'.\n"
		" 2. Ignore this message if you have\n"
		"    intentionally set this attribute to\n"
		"    'Disabled'.\n"
		"\n",
		op_pk_id (pkptr), op_pk_tree_id (pkptr), intf_num, intf_num, intf_num, intf_num, intf_num);

	FOUT;
	}


void
ipnl_reswarn_pktinsert (SimT_Pk_Id pkid, SimT_Pk_Id pktreeid, const char* intf_addr)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_protwarn_pktinsert (pkid, pktreeid, intf_addr))

	op_prg_log_entry_write (
		ip_results_warn_loghndl,
		"WARNING(S):\n"
		" An IP datagram received on interface\n"
		" [%s] could not be inserted into\n"
		" IP's service queue due to insufficient\n"
		" space.\n"
		"\n"
		" The datagram [ID " SIMC_PK_ID_FMT ", Tree ID " SIMC_PK_ID_FMT "] is being\n"
		" discarded.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" The service queue is full.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. This condition may indicate insufficient\n"
		"   space in the service queue and/or:\n"
		"2. Insufficient packet processing rate.\n"
		"3. This condition may also result in:\n"
		"   a. Unexpected packet related\n"
		"      statistics, and\n"
		"   b. Unexpected behavior from upper layer\n"
		"      protocols such as TCP. E.g. TCP\n"
		"      retransmissions etc.\n",
		intf_addr, pkid, pktreeid);

	FOUT
	}


void
ipnl_reswarn_slot_pktinsert (SimT_Pk_Id pkid, SimT_Pk_Id pktreeid, const char* intf_addr, int slot_index)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_protwarn_pktinsert (pkid, pktreeid, intf_addr, slot_index))

	op_prg_log_entry_write (
		ip_results_warn_loghndl,
		"WARNING(S):\n"
		" An IP datagram received on interface\n"
		" [%s] and slot no. [%d] could not be\n"
		" inserted into the slot buffer due to\n"
		" insufficient space.\n"
		"\n"
		" The datagram [ID " SIMC_PK_ID_FMT " Tree ID " SIMC_PK_ID_FMT "] is being\n"
		" discarded.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" The slot buffer has insufficient space.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. This condition may indicate an unstable\n"
		"   network. For slot # [%d] check the\n"
		"   value of the following attributes:\n"
		"   \"Processor Speed\" & \"Buffer Capacity\"\n"
		"   in the \"Slot Information\" compound\n"
		"   attribute.\n"
		"2. This condition may result in:\n"
		"   a. Unexpected packet related\n"
		"      statistics, and\n"
		"   b. Unexpected behavior from upper layer\n"
		"      protocols such as TCP. E.g. TCP\n"
		"      retransmissions etc.\n",
		intf_addr, slot_index, pkid, pktreeid, slot_index);

	FOUT
	}


void
ipnl_cfgwarn_nonrouting_multihomed (int num_intfs)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_nonrouting_multihomed (num_intfs))

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(S):\n"
		"A non-routing node with multiple IP interfaces \n"
		"whose \"IP Default Route\" attribute was not set\n"
		"by the user, has been found.\n"	
		"\n"
		"If this node has only one physical interface, but	\n"
		"one or more tunnel interfaces, then this warning 	\n"
		"may be ignored.\n"
		"\n"	
		"Otherwise, IP will forward non-local unicast\n"
		"datagrams to the first router detected in\n"
		"any of the %d local subnets. Subnets are\n"
		"checked starting at row number zero in the\n"
		"\"IP Address Information\" attribute.\n"
		"\n"
		"This may not be desired behavior."
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. Same as above.\n"
		"2. The \"IP Gateway Function\" attribute\n"
		"   is set to \"Disabled\" in error.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Check to see if the router that will be\n"
		"   used as a default is the correct one.\n"
		"2. Specify the IP address of the router\n"
		"   interface that you want to be used as\n"
		"	the default gateway. Set the \"IP\n"
		"   Default Route\" attribute accordingly.\n"
		"3. If possible cause #2 is valid, fix it.\n",
		num_intfs);

	FOUT
	}

void
ipnl_proterr_nexthop_error (const char* addr)
	{
	InetT_Address	ipaddr;
	char			nodename [OMSC_HNAME_MAX_LEN] = "Unknown";

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_proterr_nexthop_error (addr))

	/* Convert the address string to an IP address
	 * and obtain the name of the node that has an
	 * IP interface with the same address.
	 */
	ipaddr = inet_address_create (addr, InetC_Addr_Family_v4);

	/* Get the hierarchical name of the node.			*/
	ipnl_inet_addr_to_nodename (ipaddr, nodename);

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(S):\n"
		"A local interface could not be found on\n"
		"which the next hop address %s\n"
		"could be reached.\n"
		"\n"
		"The next hop IP address is an\n"
		"interface on the following node:\n"
		"[%s].\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The user specified value for the \"IP\n"
		"   Default Route\" is incorrect.\n"
		"2. If this is a routing node and dynamic\n"
		"   routing protocols are being used, the\n"
		"   next hop address in the dynamic routing\n"
		"   table is incorrect.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Make sure that the value of the \"IP\n"
		"   Default Route\" attr. is part of any\n"
		"   one directly connected subnet by\n"
		"   correlating it with the subnet masks\n"
		"   specified for all the IP interfaces in\n"
		"   this node.\n"
		"2. Debug the configured dynamic routing\n"
		"   protocol to find out why (and how) an\n"
		"   incorrect next hop address is present\n"
		"   in the routing table. Check for messages\n"
		"   from these protocols in the simulation\n"
		"   log.\n",
		addr, nodename);

	/* Destroy the IP address object created earlier.	*/
	inet_address_destroy (ipaddr);

	FOUT
	}

void
ipnl_invalid_next_hop_in_pkt_log_write (IpT_Rte_Module_Data* iprmd_ptr, 
	int input_intf_tbl_index, IpT_Dgram_Fields* pk_fd_ptr)
	{
	char					src_addr_str  [IPC_ADDR_STR_LEN];
	char					dest_addr_str [IPC_ADDR_STR_LEN];
	char					next_addr_str [IPC_ADDR_STR_LEN];
	
	/** a packet was received on an interface whose next hop	**/
	/** address did not fall into the same subnet as the		**/
	/** physical interface or any of the subinterfaces of the	**/
	/** interface on which it was received.						**/

	FIN (ipnl_invalid_next_hop_in_pkt_log_write (iprmd_ptr, input_intf_tbl_index, pk_fd_ptr));

	inet_address_print (src_addr_str,  pk_fd_ptr->src_addr);
	inet_address_print (dest_addr_str, pk_fd_ptr->dest_addr);
	inet_address_print (next_addr_str, pk_fd_ptr->next_addr);

	op_prg_log_entry_write (ip_prot_warning_loghndl,
		"WARNING(s):\n"
		" A packet received on the interface %s was dropped		\n"
		" because the next hop address of the packet (%s)		\n"
		" does not fall into the same subnet as the physical	\n"
		" interface or any of the subinterfaces of this 		\n"
		" interface. \n"
		" Source address of the packet: %s. \n"
		" Destination address of the packet: %s. \n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. Incorrect IP address configuration.\n"
		"2. Dynamic routing protocol misconfiguration.\n"
		"3. Misconfigured static or default routes.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Using Net Doctor or otherwise, identify any			\n"
		"   misconfigurations in the network and fix them.		\n"
		"\n"
		"RESULT(s):\n"
		"1. This packet will be dropped without any further		\n"
		"   processing.\n",
		ip_rte_intf_name_get (ip_rte_intf_tbl_access (iprmd_ptr, input_intf_tbl_index)),
		next_addr_str, src_addr_str, dest_addr_str);

	FOUT;	
	}

void
ipnl_proterr_major_port_error (int major_port, IpT_Address next_hop, int out_intf)
	{
	char 		next_hop_str [IPC_ADDR_STR_LEN];
	char		next_hop_nodename [OMSC_OBJNAME_MAX_LEN];
	
	/** Description of the condition flagged by this	**/
	/** notification log message.				**/
	FIN (ipnl_proterr_major_port_error (major_port, next_hop, out_intf));

	/* Get a printable version of the next hop address.	*/
	ip_address_print (next_hop_str, next_hop);

	/* Get the hierarchical name of the node that has	*/
	/* next_hop as an IP interface.				*/
	ipnl_ipaddr_to_nodename (next_hop, next_hop_nodename);

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(S):\n"
		" The next hop [%s], could not\n"
		" be reached on the major port [%d]\n"
		" specified in the route entry.\n"
		"\n"
		" The next hop address specified in\n"
		" the route entry is the address of\n"
		" an interface on the following node\n"
		" [%s].\n"
		"\n"
		"ACTION(S):\n"
		" Using the out interface [%d] to\n"
		" reach the next hop [%s].\n"
		" Using the default value for minor\n"
		" port (IPC_MINOR_PORT_DEFAULT).\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" The major port value specified\n"
		" in the route entry to reach the\n"
		" next hop address is invalid.\n"
		"\n"
		"SUGGESTION(S):\n"
		" Check the major port specified\n"
		" in the route entry to reach the\n"
		" next hop address [%s].\n",
		next_hop_str, major_port, next_hop_nodename,
		out_intf, next_hop_str, next_hop_str);

	op_prg_mem_free (next_hop_nodename);

	FOUT;
	}

void
ipnl_proterr_major_port_invalid (int major_port, IpT_Rte_Proc_Id src_proto)
        {
        const char*                     src_proto_str = OPC_NIL;
 
        /** Description of the condition flagged by this        **/
        /** notification log message.                           **/
        FIN (ipnl_proterr_major_port_invalid (major_port, src_proto));
 
        /* Obtain the label of the custom routing protocol. */
        src_proto_str = ip_cmn_rte_table_custom_rte_protocol_label_get (src_proto);
 
        op_prg_log_entry_write (
                ip_prot_error_loghndl,
                "ERROR(S):\n"
                " The major port [%d] is invalid\n"
                " on the node.\n"
                "\n"
                "ACTION(S):\n"
                " Dropping the packet.\n"
                "\n"
                "POSSIBLE CAUSE(S):\n"
                " The major port value specified\n"
                " in the route entry does not exist.\n"
                "\n"
                "SUGGESTION(S):\n"
                " Check the major port [%d] specified\n"
                " in the route entry which is added by\n"
                " the custom routing protocol %s.\n"
                " \n",
                major_port, major_port, src_proto_str);
 
        FOUT;
        }


void
ipnl_cfgwarn_mcastrcv (SimT_Pk_Id pkid, SimT_Pk_Id pktreeid, const char* addr)
	{
	static Boolean		this_msg_printed = OPC_FALSE;

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_mcastrcv (pkid, pktreeid, addr))

	if (this_msg_printed == OPC_FALSE)
		{
		this_msg_printed = OPC_TRUE;

		op_prg_log_entry_write (
			ip_config_warning_loghndl,
			"WARNING(S):\n"
			"A multicast IP datagram with address %s\n"
			"has been received at this node.\n"
			"(Pkt. ID [" SIMC_PK_ID_FMT "] and Pkt. Tree ID [" SIMC_PK_ID_FMT "])\n"
			"No protocol on this node has registered\n"
			"itself for this multicast address.\n"
			"The IP datagram is being dropped.\n"
			"\n"
			"THIS MESSAGE WILL NOT BE REPEATED DURING\n"
			"THE REST OF THIS SIMULATION.\n"
			"\n"
			"POSSIBLE CAUSE(S):\n"
			"1. This is a router node using RIP, IGRP or\n"
			"   BGP4 whereas neighboring routers' peer\n"
			"   interfaces are running OSPF.\n"
			"2. This is an endstation that is connected\n"
			"   to a data link subnet that supports\n"
			"   multicasting AND an OSPF router is also\n"
			"   connected to the same data link subnet.\n"
			"3. This is a router running OSPF on a\n"
			"   broadcast capable (eg. ethernet) interface\n"
			"   with other OSPF routers, and, this router\n"
			"   is NOT the Designated Router.\n"
			"\n"
			"SUGGESTIONS:\n"
			"1. Set the \"Dynamic Routing Protocol\"\n"
			"   on all router nodes to either RIP or\n"
			"   OSPF.\n"
			"2. If cause no. 2 or 3 is true, IGNORE this\n"
			"   message.\n",
			addr, pkid, pktreeid);
		}

	FOUT
	}

void
ipnl_unknown_input_iface_log_write (const int strm_index, const char* addr,
	const SimT_Pk_Id pkid, const SimT_Pk_Id pktreeid)
	{
	InetT_Address		ipaddr;
	char				nodename [OMSC_HNAME_MAX_LEN] = "Unknown";
	
	/** This function prints out a log message indicating	**/
	/**	that the interface on which a certain packet was	**/
	/** received could not be determined and hence it will	**/
	/** be dropped.											**/

	FIN (ipnl_unknown_input_iface_log_write (strm_index));

	/* Create an IP address object corresponding to the
	 * address string passed in in the first parameter.
	 */
	ipaddr = inet_address_create (addr, InetC_Addr_Family_v4);

	/* Build the hierarchical name of the node that
	 * has an IP interface with this address.
	 */
	ipnl_inet_addr_to_nodename (ipaddr, nodename);

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(s):\n"
		"Could not determine the IP interface corresponding\n"
		"to the input stream (%d) on which the following\n"
		"packet was received.\n"
		"  Packet ID: " SIMC_PK_ID_FMT "\n"
		"  Packet Tree ID: " SIMC_PK_ID_FMT "\n"
		"  Destination IP Address: %s\n"
		"The destination IP address above corresponds\n"
		"to an interface on the following node:\n"
		"[%s]\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The interface corresponding to this stream is\n"
		"   incorrectly configured.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. If the corresponding interface is marked as\n"
		"   'Shutdown', ignore this message\n"
		"2. Otherwise make sure that the interface \n"
		"   configuration is correct.\n"
		"\n"
		"RESULT(s):\n"
		"1. The packet will be dropped.\n"
		"\n"
		"Note: This message will not be repeated for\n"
		"      this input stream on this node.\n",
		strm_index, pkid, pktreeid, addr, nodename);

	FOUT;
	}
	
void
ipnl_proterr_noroute_ripospf (const char* addr, 
	const char* PRG_ARG_UNUSED(protocol), SimT_Pk_Id pkid, SimT_Pk_Id pktreeid)
	{
	InetT_Address		ipaddr;
	char				nodename [OMSC_HNAME_MAX_LEN] = "Unknown";

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_proterr_noroute_ripospf (addr, protocol))

	/* Create an IP address object corresponding to the
	 * address string passed in in the first parameter.
	 */
	ipaddr = inet_address_create (addr, InetC_Addr_Family_Unknown);

	/* Build the hierarchical name of the node that
	 * has an IP interface with this address.
	 */
	ipnl_inet_addr_to_nodename (ipaddr, nodename);

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(S):\n"
		"The IP routing table on this node does\n"
		"not have a route to the destination\n"
		"%s.\n"
		"\n"
		"The destination IP address above\n"
		"corresponds to an interface on the\n"
		"following node:\n"
		"[%s]\n"
		"\n"
		"The corresponding IP datagram [ID " SIMC_PK_ID_FMT ",\n"
		"Tree ID " SIMC_PK_ID_FMT "] is being dropped.\n"
		"\n"
		"The IP routing table is a composite of\n"
		"routes contributed by one or any\n"
		"combination of RIP, IGRP, OSPF, BGP4,\n"
		"EIGRP, IS-IS and static route\n"
		"configuration by the user.\n"
		"\n"
		"Background Traffic is not present or\n"
		"is not starting at the expected time.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. Sufficient time has not elapsed for\n"
		"   dynamic routing protocol(s) to build\n"
		"   the routing table.\n"
		"2. A configuration problem has prevented\n"
		"   the dynamic routing protocol(s) from\n"
		"   detecting a route to this destination\n"
		"3. If only static (user configured) routing\n"
		"   is being used, the user has omitted to\n"
		"   set up a route to this destination.\n"
		"4. If this destination belongs to another\n"
		"   routing domain (e.g. another Autonomous\n"
		"   system), this router might not have a\n"
		"   route to the destination unless route\n"
		"   redistribution is enabled between the\n"
		"   routing domains (e.g. between the EGP\n"
		"   and the IGP).\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. If GNA models are being used to\n"
		"   generate data traffic, check the value\n"
		"   of the \"Application Start Time\" attr.\n"
		"   If Background Traffic is being used,\n"
		"   check the value of the \"Background\n"
		"   Traffic Start Delay\" simulation\n"
		"   attribute. All Background Traffic\n"
		"   is delayed by this value. For RIP,\n" 
		"   these values should be around 15\n"
		"   seconds. For OSPF, these values should\n"
		"   be around 100 secs. These values are\n"
		"   based on empirical data and may vary\n"
		"   with the number of IP routers in your\n"
		"   network model\n"
		"2. Check the simulation log for previous\n"
		"   IP model messages. These may indicate\n"
		"   a configuration problem that interfered\n"
		"   with the operation of the dynamic\n"
		"   routing protocol(s).\n",
		addr, nodename, pkid, pktreeid);

	/* Destroy the IP address that was instantiated for
	 * the purposes of this debug message.
	 */
	inet_address_destroy (ipaddr);

	FOUT
	}


void
ipnl_proterr_noroute_static (const char* addr, SimT_Pk_Id pkid, SimT_Pk_Id pktreeid)
	{
	InetT_Address		ipaddr;
	char				nodename [OMSC_HNAME_MAX_LEN] = "Unknown";

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_proterr_noroute_static (addr, pkid, pktreeid))

	/* Create an IP address object corresponding to the
	 * address string passed in in the first parameter.
	 */
	ipaddr = inet_address_create (addr, InetC_Addr_Family_v4);

	/* Build the hierarchical name of the node that
	 * has an IP interface with this address.
	 */
	ipnl_inet_addr_to_nodename (ipaddr, nodename);

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(S):\n"
		"The user-defined static routing table on\n"
		"this node does not have a route the\n"
		"destination %s.\n"
		"\n"
		"The destination IP address mentioned\n"
		"above corresponds to an IP interface in\n"
		"the following node in the network model:\n"
		"[%s]\n"
		"\n"
		"The IP datagram [ID " SIMC_PK_ID_FMT ", Tree ID " SIMC_PK_ID_FMT "] is\n"
		"being dropped.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"Same as above.\n"
		"\n"
		"SUGGESTIONS:\n"
		"Add a route to this destination in the\n"
		"\"Internal Routing Table\" subobject of\n"
		"the \"IP Routing Information\" attribute\n"
		"on this node.\n",
		addr, nodename, pkid, pktreeid);

	/* Destroy the IP address that was instantiated for
	 * the purposes of this debug message.
	 */
	inet_address_destroy (ipaddr);

	FOUT
	}

void
ipnl_default_route_not_directly_connected_log_write (char* default_route_addr_str,
	InetT_Addr_Family addr_family)
	{
	static Boolean	message_already_logged = OPC_FALSE;
	const char*		protocol_name;

	/** Writes a log message warning the user that the	**/
	/** default route specified for a node is not		**/
	/** directly connected and hence will be ignored.	**/
	FIN (ipnl_default_route_not_directly_connected_log_write (default_route_addr_str));

	/* Do not print this message more than once.		*/
	if (OPC_TRUE == message_already_logged)
		{
		FOUT;
		}

	if (InetC_Addr_Family_v4 == addr_family)
		{
		protocol_name = "IPv4";
		}
	else
		{
		protocol_name = "IPv6";
		}

	message_already_logged = OPC_TRUE;
	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(S):\n"
		"The %s default route \"%s\"\n"
		"specified for this node is invalid.\n"
		"\n"
		"REASON(s):\n"
		"1. The specified default route is not directly\n"
		"   connected to this node. Default routes specified\n"
		"   should be withing one ip hop from the node. i.e.\n"
		"   It should be in the same IP subnet as one of the\n"
		"   interfaces of this node.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Specify a valid default route.\n"
		"\n"
		"RESULT(s):\n"
		"1. The Default route specification will be ignored.\n"
		"2. This node will not be able to send packets to\n"
		"   nodes that are not in the same IP subnet.\n"
		"NOTE: This message will not be repeated.\n",
		default_route_addr_str);

	FOUT;
	}

void
ipnl_invalid_routing_table_log_write (char* ip_addr_str)
	{
	/** This function prints out a log message indicating	**/
	/** that a loop exists in the routing table.			**/

	FIN (ipnl_invalid_routing_table_log_write (ip_addr_str));

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(S):\n"
		"Unable to route packet to the destination\n"
		"%s.\n"
		"\n"
		"REASON(s):\n"
		"1. While doing a recursive lookup to find the\n"
		"   next hop to reach this destination, a loop\n"
		"   was encountered.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. Routing Protocol misconfiguration.\n"
		"2. Incorrect static routes.\n"
		"\n"
		"SUGESTION(s):\n"
		"1. Export the routing table of this node and\n"
		"   and try to find the erroneous route(s).\n",
		ip_addr_str);

	FOUT;
	}
		
		
void
ipnl_port_info_not_specified_in_rte_log_write (const char* dest_str, const char* nh_str,
	IpT_Rte_Proc_Id proto, IpT_Port_Info port_info, IpT_Rte_Module_Data* PRG_ARG_UNUSED (iprmd_ptr))
	{
	char					routing_protocol_name [32];
	int						intf_tbl_index;
	int						protocol;

	/** The port info structure of a route table entry is	**/
	/** supposed to contain information about the interface	**/
	/** to be used to reach the next hop. If this			**/
	/** is not specified, ip will have to go through the	**/
	/** entire interface list to find out the interface		**/
	/** that is to be used to reach the next hop. 			**/
	
	FIN (ipnl_port_info_not_specified_in_rte_log_write (dest_str, mask_str, nh_str, proto, port_info));
	
	protocol = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (proto);
	
	/* Get the name of the routing protocol					*/
	strcpy (routing_protocol_name, IpC_Dyn_Rte_Prot_Names [proto]);

	intf_tbl_index = ip_rte_intf_tbl_index_from_port_info_get (iprmd_ptr, port_info);

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		"   The following routing table entry inserted "
		"   into the common route table by the \"%s\"\n"
		"   routing protocol did not specify the\n"
		"   interface through which the next hop can\n"
		"   be reached.\n"
		"   Destination: %s.\n"
		"   Next Hop:    %s.\n"
		"   The next hop is in the same subnet as\n"
		"   interface# %d in the ip interface table\n"
		"\n"
		"RESULTS(S):\n"
		"1. The interface to reach the next hop will\n"
		"   be set as %d.\n"
		"\n"
		"SUGGESTIONS(S);\n"
		"1. If this a standard routing protocol,\n"
		"   please contact OPNET Technical support.\n"
		"2. If this is a custom routing protocol,\n"
		"   make sure that the port_info element of\n"
		"   the route is specified correctly while\n"
		"   inserting the route into the common\n"
		"   routing table.\n",
	    routing_protocol_name, dest_str,
		nh_str, intf_tbl_index, intf_tbl_index);
			
	FOUT;
	}

void
ipnl_invalid_port_info_log_write (const char* dest_str, const char* nh_str, IpT_Rte_Proc_Id proto,
	IpT_Port_Info port_info, IpT_Rte_Module_Data* PRG_ARG_UNUSED (iprmd_ptr))
	{

	char					routing_protocol_name [32];
	int						intf_tbl_index;
	int						protocol;
	
	/** The port info structure of a route table entry is	**/
	/** supposed to contain information about the interface	**/
	/** to be used to reach the next hop. This function is	**/
	/** called if the next hop of the route is not reachable**/
	/** through the specified interface.					**/
	
	FIN (ipnl_invalid_port_info_in_route_table_entry_log_write (src_protocol));
	
	protocol = IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (proto);
	
	/* Get the name of the routing protocol					*/
	/* LP 3-16-04 - replaced to fix OPnet bug in handling Custome Routing Protocol - */
	
	/*	strcpy (routing_protocol_name, IpC_Dyn_Rte_Prot_Names [protocol]);*/

	if (protocol < IPC_INITIAL_CUSTOM_RTE_PROTOCOL_ID)
		strcpy (routing_protocol_name, IpC_Dyn_Rte_Prot_Names [protocol]);
	else
		ip_cmn_rte_proto_name_print(routing_protocol_name, proto);
	/* end Custome Routing section  - end LP */
	
	intf_tbl_index = ip_rte_intf_tbl_index_from_port_info_get (iprmd_ptr, port_info);
	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		"   The interface to reach the next hop specified\n"
		"   in the following route inserted into the\n"
	    "   common routing table by \"%s\" is incorrect.\n"
		"   Destination: %s.\n"
		"   Next Hop:    %s.\n"
		"   Port Info:   %d.\n"
		"\n"
		"RESULTS(S):\n"
		"1. The port_info will be set correctly\n"
		"   if the specified next hop is\n"
		"   directly connected.\n"
		"\n"
		"SUGGESTIONS(S);\n"
		"1. If this a standard routing protocol,\n"
		"   please contact OPNET Technical support.\n"
		"2. If this is a custom routing protocol,\n"
		"   make sure that the port_info element of\n"
		"   the route is specified correctly while\n"
		"   inserting the route into the common\n"
		"   routing table. The major_port of the\n"
		"   port info should be set to the index\n"
		"   of the outgoing interface in the list\n"
		"   of interfaces maintained by IP. Note that\n"
		"   this index might be different from the\n"
		"   row number of this interface in the\n"
		"   Interface Information attribute if\n"
		"   there are unconnected interfaces.\n"
		"   If the next hop is not directly\n"
		"   connected, set the major port value\n"
		"   to OPC_INT_UNDEF\n",
	    routing_protocol_name, dest_str, nh_str, intf_tbl_index);
	FOUT;
	}
	
void
ipnl_cfgerr_intfnoslot (const char* iface_list)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgerr_intfnoslot (iface_list))

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(S):\n"
		"The following IP Interfaces have not been\n"
		"assigned to any slots although \"IP\n"
		"Processing Scheme\" has been set to \"Slot\n"
		"Based Processing\".\n"
		"[%s]\n"
		"Note that row numbers in \"Router/IP Slot\n"
		"Information\" start at zero.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"An IP interface that is connected to an IP\n"
		"subnet has not been assigned to any slot\n"
		"and \"Slot Based Processing\" is being\n"
		"used.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Modify the \"Interface List\" sub-object\n"
		"   of the \"Router/IP Slot Information\"\n"
		"   compound attribute to include the row\n"
		"   number(s) mentioned above, or\n"
		"2. Set \"IP Processing Scheme\" to \"Central\n"
		"   Processing\".\n"
		"\n",
		iface_list);

	FOUT
	}


void
ipnl_cfgwarn_intfmultislot (int iface_index, int orig_slot, int dup_slot)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_intfmultislot (iface_index, orig_slot, dup_slot))

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"ERROR(S):\n"
		"Interface number %d has been assigned to\n"
		"more than one slot.\n"
		"The original slot number is %d.\n"
		"The duplicate slot assignment is %d.\n"
		"The duplicate slot assignment will be\n"
		"ignored.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"Same as above.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Check the \"Interface List\" sub-object\n"
		"   of the \"Router/IP Slot Information\"\n"
		"   attribute and make sure that an IP\n"
		"   Interface is assigned to one and only\n"
		"   one slot.\n",
		iface_index, orig_slot, dup_slot);

	FOUT
	}

void
ipnl_cfgwarn_unknown_comp_scheme (int iface_index, int subintf_row_num, const char* scheme_name)
	{
	char			intf_desc [128];

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_unknown_comp_scheme (iface_index, scheme_name))

	/* Create a description for the interface based on	*/
	/* whether its is physical or a subinterface		*/
	if (IPC_SUBINTF_PHYS_INTF == subintf_row_num)
		{
		/* It is a physical interface					*/
		sprintf (intf_desc, "Interface %d\n", iface_index);
		}
	else
		{
		/* It is a subinterface							*/
		sprintf (intf_desc, "Interface    %d\nSubinterface %d\n", iface_index, subintf_row_num);
		}

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"ERROR(S):\n"
		"The compression scheme \"%s\"\n"
		"specified for the following interface is unknown.\n"
		"%s\n"
		"Ignoring the specified compression scheme\n"
		"and not applying any compression at this\n"
		"interface.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The IP Attribute Definition object is\n"
		"   not included in the network model,\n"
		"   and/or\n"
		"2. A compression scheme with the name\n"
		"   \"%s\" is not defined under the\n"
		"   attribute IP Compression Information in\n"
		"   the IP Attribute Definition object.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Open the utilities object palette and\n"
		"   add IP Attribute Definition object to\n"
		"   your model, and\n"
		"2. a) Define the compression scheme\n"
		"   \"%s\" under the attribute\n"
		"   IP Compression Information with the\n"
		"   exact same name and fill the other\n"
		"   fields accordingly, or\n"
		"   b) Use one of the schemes already\n"
		"   defined under this attribute for the\n"
		"   above interface.\n",
		scheme_name, intf_desc, scheme_name, scheme_name);

	FOUT
	}


void
ipnl_cfgwarn_ospf_route_noredist (InetT_Address dest)
	{
	char			dest_str [IPC_ADDR_STR_LEN];
	char			nodename [OMSC_HNAME_MAX_LEN] = "Unknown";
	static Boolean	message_already_logged = OPC_FALSE;

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgwarn_ospf_route_noredist (dest))

	/* Check if this message has already been logged.	*/
	if (message_already_logged == OPC_FALSE)
		{
		message_already_logged = OPC_TRUE;

		/* Convert the IP address to printable form.		*/
		inet_address_print (dest_str, dest);

		/* Map the input IP address to the hierarchical		*/
		/* name of the object that contains the				*/
		/* corresponding IP interface.						*/
		ipnl_inet_addr_to_nodename (dest, nodename);

		op_prg_log_entry_write (
			ip_config_warning_loghndl,
			"WARNING(S):\n"
			"A route computed by OSPF to a destination\n"
			"will not be redistributed to other routing\n"
			"protocols that may have been configured on\n"
			"this router node.\n"
			"\n"
			"The destination IP address is [%s].\n"
			"\n"
			"The destination IP address above\n"
			"corresponds to an interface on the\n"
			"following node:\n"
			"[%s]\n"
			"\n"
			"POSSIBLE CAUSE(S):\n"
			"1. This is a destination connected to this\n"
			"   router via point-to-point link technology.\n"
			"   OSPF associates a mask of 255.255.255.255\n"
			"   with such destinations, and uses this mask\n"
			"   value when finding the best match route to\n"
			"   a destination during route table lookup.\n"
			"\n"
			"SUGGESTIONS:\n"
			"1. If there are no other routing protocols\n"
			"   configured on this router apart from OSPF\n"
			"   ignore this message.\n"
			"2. If this destination corresponds to a router\n"
			"   interface, ignore this message.\n"
			"3. If this destination corresponds to a\n"
			"   host interface, i.e. this is a host route\n"
			"   then:\n"
			"   (a) Connect the host to this router with\n"
			"       non point-to-point link technology.\n"
			"   (b) Do not use OSPF as the routing protocol\n"
			"       on this router's interface that connects\n"
			"       to the host.\n"
			"\n"
			"NOTE: This message will not be repeated.\n",
			dest_str, nodename);
		}

	FOUT;
	}

void
ipnl_invalid_ip_address_string_warn (const char* addr_str)
	{
	static List*		addr_str_lptr = OPC_NIL;
	char*				local_string_copy;

	/** This function is used by the ip_address_create	**/
	/** function to warn users about invalid strings	**/
	/** passed to this function. This function does not	**/
	/** write a log message for each call. Instead it	**/
	/** caches them in a list and prints them all out	**/
	/** together at the end of the simulation.			**/

	FIN (ipnl_invalid_ip_address_string_warn (addr_str));

	/* Check if the list of address strings has been	*/
	/* created. If not, create it. Also schedule a		*/
	/* procedure call interrupt for the end of 			*/
	/* simulation to actually print out the log message	*/
	if (OPC_NIL == addr_str_lptr)
		{
		addr_str_lptr = op_prg_list_create ();

		op_intrpt_schedule_call (OPC_INTRPT_SCHED_CALL_ENDSIM, 0,
			ipnl_invalid_ip_address_string_log_write, addr_str_lptr);
		}
	else
		{
		/* Make sure the string has not occurred earlier*/
		/* in the list.									*/
		if (OPC_NIL != op_prg_list_elem_find (addr_str_lptr,
			oms_string_compare_proc, (void*) addr_str, OPC_NIL, OPC_NIL))
			{
			/* Ignore this string. It has occurred in	*/
			/* the list earlier.						*/
			FOUT;
			}
		}

	/* Make a local copy of the string					*/
	local_string_copy = (char*) op_prg_mem_alloc ((strlen (addr_str) +1) * sizeof (char));
	strcpy (local_string_copy, addr_str);

	/* Insert the string into the list.					*/
	op_prg_list_insert (addr_str_lptr, local_string_copy, OPC_LISTPOS_TAIL);

	FOUT;
	}

static void
ipnl_invalid_ip_address_string_log_write (void* lptr, int PRG_ARG_UNUSED(i))
	{
	char*			ip_addr_list;
	char*			temp_ip_addr_list;
	int				ip_addr_list_max_size;
	char*			end_of_ip_addr_list_ptr;
	int				curr_ip_addr_list_size;
	int				list_index, list_size;
	char*			curr_ip_addr_str;
	int				curr_ip_addr_str_len;
	List* 			addr_str_lptr;

	/** This function is called by 						**/
	/** ipnl_invalid_ip_address_string_warn to actually	**/
	/** write the log message at the end of simulation	**/
	FIN (ipnl_invalid_ip_address_string_log_write (addr_str_lptr));
	
	addr_str_lptr = (List*) lptr;
	
	/* First create a string by  concatenating all 		*/
	/* entries in the list.								*/

	/* Allocate enough memory to hold all the ip addresses	*/
	/* The additional 6 characters are for the serial number*/
	/* space character and new line						*/
	ip_addr_list_max_size = op_prg_list_size (addr_str_lptr) * (IPC_ADDR_STR_LEN + 6);
	ip_addr_list = (char*) op_prg_mem_alloc ((ip_addr_list_max_size + 1) * sizeof (char));

	/* Initialize the end_of_ip_addr_list_ptr			*/
	/* It will always point to the null character at the*/
	/* end of ip_addr_list string						*/
	end_of_ip_addr_list_ptr = ip_addr_list;
	curr_ip_addr_list_size = 0;
	
	/* Null terminate the string						*/
	*end_of_ip_addr_list_ptr = '\0';

	/* Loop through each entry in the list and append 	*/
	/* it to the end of the string.						*/
	list_size = op_prg_list_size (addr_str_lptr);
	for (list_index = 0; list_index < list_size; list_index++)
		{
		/* Get the list entry							*/
		curr_ip_addr_str = (char*) op_prg_list_access (addr_str_lptr, list_index);

		/* Calculate the additional memory required for	*/
		/* the current string. The additional 6 		*/
		/* characters are for the serial number, space 	*/
		/* character and new line.						*/
		curr_ip_addr_str_len = strlen (curr_ip_addr_str) + 6;

		/* Allocate additional memory if necessary		*/
		if ((curr_ip_addr_str_len + curr_ip_addr_list_size) > ip_addr_list_max_size)
			{
			/* Expand the size of the string by a factor*/
			/* of 2. If the current IP address string is*/
			/* so long that that is not sufficient, use	*/
			/* curr_ip_addr_str_len + curr_ip_addr_list_size*/
			/* instead.									*/
			ip_addr_list_max_size = MAX (2 * ip_addr_list_max_size, curr_ip_addr_str_len + curr_ip_addr_list_size);

			/* Create a larger string and copy the		*/
			/* existing string into it.					*/
			temp_ip_addr_list = (char*) op_prg_mem_alloc ((ip_addr_list_max_size + 1) * sizeof (char));
			strcpy (temp_ip_addr_list, ip_addr_list);

			/* Free the memory allocated to the current	*/
			/* string and make it point to the new sting*/
			op_prg_mem_free (ip_addr_list);
			ip_addr_list = temp_ip_addr_list;

			/* Update the curr_ip_addr_list_ptr			*/
			end_of_ip_addr_list_ptr = ip_addr_list + curr_ip_addr_list_size;
			}

		/* Concatenate the current entry to the string	*/
		curr_ip_addr_list_size += sprintf (end_of_ip_addr_list_ptr, "%d) %s\n", list_index + 1, curr_ip_addr_str);
		end_of_ip_addr_list_ptr = ip_addr_list + curr_ip_addr_list_size;
		}
	
	/* Write the log message.							*/
	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(S):\n"
		"Encountered at least one invalid string in the\n"
		"ip_address_create function. The list of all such\n"
		"instances in this network are given at the end of\n"
		"this message. IP addresses should be specified in\n"
		"the form a.b.c.d where a, b, c and d are values\n"
		"between 0 and 255 (both inclusive).\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The strings listed below were specified\n"
		"   for an attribute where an IP address was\n"
		"   expected.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Make sure the values specified for all\n"
		"   IP address attributes are of the specified\n"
		"   form.\n"
		"\n"
		"RESULT(s):\n"
		"1. The actual handling of this case depends on\n"
		"   the attribute for which the value was\n"
		"   specified. Look for other log messages\n"
		"   that might indicate how these values were\n"
		"   handled.\n"
		"\n"
		"List of all such instances\n"
		"==========================\n"
		"%s",
		ip_addr_list);

	/* Free the memory allocated to the list and the string	*/
	op_prg_list_free (addr_str_lptr);
	op_prg_mem_free (addr_str_lptr);
	op_prg_mem_free (ip_addr_list);

	FOUT;
	}

void
ipnl_cfgerr_rte_proto_inconsistency (Objid node_objid, int intf_index)
	{
	Objid			subnet_objid;
	char			node_name [OMSC_HNAME_MAX_LEN] = "Unknown";
	char			subnet_name [OMSC_HNAME_MAX_LEN] = "Unknown";

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_cfgerr_rte_proto_inconsistency (node_objid, intf_index))

	/* Get the name of the node.	*/
	op_ima_obj_attr_get (node_objid, "name", &node_name);

	/* Containing subnet's object ID	*/
	subnet_objid = op_topo_parent (node_objid);

	/* Get the name of the parent subnet.	*/
	op_ima_obj_attr_get (subnet_objid, "name", &subnet_name);

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(S):\n"
		"Interface number [%d] on the following router\n"
		"node has a routing protocol assignment that is\n"
		"inconsistent with other router interfaces that\n"
		"are connected to the same IP subnetwork.\n"
		"\n"
		"Router: [%s.%s]\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The user has purposely assigned multiple \n"
		"   routing protocols on the same IP subnetwork \n"
		"2. The user has assigned an inconsistent\n"
		"   routing protocol to the above interface\n"
		"   on the router node.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. If this was desired then take no action.\n"	
		"2. Modify the routing protocol assignment\n"
		"   on this interface to be consistent with\n"
		"   other router interfaces in this subnet.\n"
		"3. Go over the routing protocol assignments\n"
		"   on all router interfaces and ensure that\n"
		"   all of them are consistent.\n",
		intf_index, subnet_name, node_name);

	FOUT;
	}


void
ipnl_cfgerr_pim_sm_child_process_not_created (void)
	{

	/** Reports a log message to indicate that a PIM-SM packet	**/
	/** has been received at a node, but the ip_pim_sm child	**/
	/** process is not created									**/
	FIN (ipnl_cfgerr_pim_sm_child_process_not_created (void));

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(S):\n"
		" A PIM-SM packet has been received at this\n"
		" node. But, ip_pim_sm child process has not\n"
		" been created on this node.\n"
		"\n"
		"ACTION(S):\n"
		" Terminating the simulation.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" 1. If this node is a router, then multicast\n"
		"    routing is disabled.\n"
		" 2. If this node is a workstation, then this\n"
		"    packet is a stray packet. This happens if\n"
		"    the specified Rendezvous Point (RP) address\n"
		"    is the address of this workstation.\n"
		"\n"
		"SUGGESTION(S):\n"
		" 1. If this node is a router, then set the\n"
		"    attribute 'IP Multicast Routing' to 'Enabled'.\n"
		" 2. If this node is a workstation, then check\n"
		"    your Rendezvous Point (RP) assignments.\n"
		"    Because, one of your RP addresses is the\n"
		"    address of this workstation. A RP must be\n"
		"    a multicast router.\n"
		"\n");

	FOUT;
	}


void
ipnl_reswarn_ttlexp (SimT_Pk_Id pkid, SimT_Pk_Id pktreeid, const char* intf_addr, const char* dest_addr)
	{

	/** Description of the condition flagged by this	**/
	/** notification log message.						**/
	FIN (ipnl_reswarn_ttlexp (pkid, pktreeid, intf_addr, dest_addr))

	op_prg_log_entry_write (
		ip_results_warn_loghndl,
		"WARNING(S):\n"
		"The IP packet (ID " SIMC_PK_ID_FMT ", Tree " SIMC_PK_ID_FMT ") is being\n"
		"dropped because its TTL field decrements\n"
		"to zero.\n"
		"Interface Received:\t%s\n"
		"Packet Destination:\t%s\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The network model has IP routing tables\n"
		"   with loops.\n"
		"2. The optimal routed path taken by this\n"
		"   packet does indeed have more than 32\n"
		"   hops.\n"
		"3. This might be a directed broadcast packet\n"
		"   whose TTL was set to 1 by the broadcasting\n"
		"   router to prevent the packet from being\n"
		"   routed.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. If hand configured, make sure that\n"
		"   the \"Internal Routing Table\"\n"
		"   does not have any route loops.\n"
		"2. If this is a directed broadcast packet,\n"
		"   find out why it was delivered to this\n"
		"   node. The most probable cause for this\n"
		"   is that interfaces belonging to the same\n"
		"   lower layer network do not have the same\n"
		"   IP Network Address.\n",
		pkid, pktreeid, intf_addr, dest_addr);

	FOUT
	}


void
ipnl_sim_terminate (void)
	{
	/** Print an error message and exit the simulation. **/
	FIN (ipnl_sim_terminate (void));

	op_sim_end (
		"An error has been detected by the IP model.",
		"Check the simulation log for details. If the simulation log was not",
		"enabled, rerun the simulation after enabling this feature in the",
		"Project/Simulation Editor.");

	FOUT;
	}

void
ipnl_invalid_icmp_echo_reply_log_write (Objid src_module_objid, Objid this_module_objid)
	{
	Objid			src_node_objid;
	char			src_node_name [256];
	static List*	already_logged_lptr = OPC_NIL;
	char			temp_objid_str [128];
	char*			objid_str;
	int				objid_str_len;

	/** This function is called if a node receives an	**/
	/** icmp echo packet destined to another node. The	**/
	/** most probable reason for this is duplicate ip	**/
	/** addresses.										**/

	FIN (ipnl_invalid_icmp_echo_reply_log_write (echo_reply_pkptr));

	/* First we need to make sure that we have not already	*/
	/* logged a message about this pair of objects.			*/

	/* Create a string to do the search in the list		*/
	objid_str_len = sprintf (temp_objid_str, "%d:%d", src_module_objid, this_module_objid);

	/* If the list of already logged objid combinations	*/
	/* exists, look for the string in the list.			*/
	if (OPC_NIL != already_logged_lptr)
		{
		if (OPC_NIL != op_prg_list_elem_find (already_logged_lptr,
			oms_string_compare_proc, temp_objid_str, OPC_NIL, OPC_NIL))
			{
			/* We already logged a message. Return		*/
			FOUT;
			}
		}
	else
		{
		/* The list does not exist. Create an empty one	*/
		already_logged_lptr = op_prg_list_create ();
		}

	/* Add the current string to the list.				*/
	objid_str = (char*) op_prg_mem_alloc (objid_str_len + 1);
	strcpy (objid_str, temp_objid_str);
	op_prg_list_insert (already_logged_lptr, objid_str, OPC_NIL);

	/* First find out the node to which the packet should	*/
	/* have been sent.										*/
	src_node_objid = op_topo_parent (src_module_objid);
	oms_tan_hname_get (src_node_objid, src_node_name);

	op_prg_log_entry_write (
		ip_prot_error_loghndl,
		"ERROR(s):\n"
		" Received an icmp echo packet destined for\n"
		" %s.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The icmp request packet was generated by the node\n"
		"   mentioned above, but the reply was forwarded\n"
		"   to this node because the two nodes have at least\n"
		"   one common IP address.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Remove any instances of duplicate ip addresses \n"
		"   in the network.\n"
		"\n"
		"RESULT(s):\n"
		"1. This packet will be ignored.\n"
		"\n"
		"Note: This message will not be repeated on this\n"
		"      node for packets sourced by the node mentioned\n"
		"      above\n",
		src_node_name);

	FOUT;
	}

void
ipnl_icmp_ping_pattern_not_found (const char* ping_pattern_str)
	{
	/** The specified Ping Pattern could not be found.	**/

	FIN (ipnl_icmp_ping_pattern_not_found (ping_pattern_str));

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(s):\n"
		" The \"Ping Pattern\" specified on one of the\n"
		" ping traffic demands originating on this node\n"
		" is invalid. \"%s\" is not a valid ping pattern\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. There is no \"IP Attribute Config\" node in\"\n"
		"   the network.\n"
		"2. The Ping pattern \"%s\" is not defined on the\n"
		"   the \"IP Attribute Config\" node.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Make sure that there is an \"IP Attribute Config\"\n"
		"   node in the network and the Ping Pattern \"%s\"\n"
		"   is defined under the \"IP Ping Parameters\" attribute.\n"
		"\n"
		"RESULT(s)\n"
		"1. This ping demand will be ignored\n",
		ping_pattern_str, ping_pattern_str, ping_pattern_str);

	FOUT;
	}

void
ipnl_icmp_ip_version_not_supported (const char* dest_name, InetT_Addr_Family version)
	{
	const char*			version_str;

	/** The version specified for one of the ping demands	**/
	/** originating on this node is not supported on this	**/
	/** node.												**/

	FIN (ipnl_icmp_ip_version_not_supported (dest_name, version));

	/* Get a string form of the version.						*/
	version_str = inet_addr_family_string (version);

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(s):\n"
		" The ping demand to \"%s\" from this node is invalid.\n"
		" The version attribute of the ping pattern of the\n"
		" demand is set to %s, but %s is not supported on this\n"
		" node.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1.The Version attribute for the specified ping pattern\n"
		"   is set to %s.\n"
		"2. This node does not have even a single %s address.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Set the Version attribute correctly for the Ping pattern.\n"
		"   Ping patterns are configured under the \"IP Ping Parameters\"\n"
		"   attribute on the \"IP Attribute Config\" node.\n"
		"2. Choose a Ping Pattern with the correct version.\n"
		"3. Make sure that this node has at least one connected\n"
		"   interface that is %s enabled.\n"
		"\n"
		"RESULT(s)\n"
		"1. This ping demand will be ignored\n",
		dest_name, version_str, version_str, version_str, version_str, version_str);

	FOUT;
	}
 
void
ipnl_icmp_no_valid_address_for_destination (const char* dest_name, InetT_Addr_Family version)
	{
	const char*			version_str;

	/* The destination node of the ping demand does not have	*/
	/* an address of the specified version.						*/

	FIN (ipnl_icmp_no_valid_address_for_destination (dest_name, version));

	/* Get a string form of the version.						*/
	version_str = inet_addr_family_string (version);

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(s):\n"
		" The node \"%s\" does not have an address\n"
		" of type \"%s\", but a ping demand to that node has\n"
		" its version set to \"%s\".\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The Version attribute for the specified ping pattern\n"
		"   is set to \"%s\".\n"
		"2. The destination node does not have even a single\n"
		"   \"%s\" address.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Set the Version attribute correctly for the Ping pattern.\n"
		"   Ping patterns are configured under the \"IP Ping Parameters\"\n"
		"   attribute on the \"IP Attribute Config\" node.\n"
		"2. Choose a Ping Pattern with the correct version.\n"
		"3. Make sure that the destination node has at least one connected\n"
		"   interface that is \"%s\" enabled.\n"
		"\n"
		"RESULT(s)\n"
		"1. This ping demand will be ignored\n",
		dest_name, version_str, version_str, version_str, version_str, version_str);

	FOUT;
	}

void
ipnl_icmp_invalid_address_specification (const char* ip_addr_str, InetT_Addr_Family version)
	{
	const char*			version_str;

	/* The destination address specified for a ping demand	*/
	/* originating on this node invalid.					*/
	FIN (ipnl_icmp_no_valid_address_for_destination (dest_name, version));

	/* Get a string form of the version.						*/
	version_str = inet_addr_family_string (version);

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(s):\n"
		" The destination address specified for a ping demand\n"
		" originating on this node invalid. The string \"%s\"\n"
		" does not represent an %s address.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The destinaton address attribute of the demand is set\n"
		"   incorrectly.\n"
		"2. The Version attribute for the specified ping pattern\n"
		"   is set incorrectly.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Make sure there are no errors in the Address specification.\n"
		"2. Set the Version attribute correctly for the Ping pattern.\n"
		"   Ping patterns are configured under the \"IP Ping Parameters\"\n"
		"   attribute on the \"IP Attribute Config\" node.\n"
		"3. Choose a Ping Pattern with correct version.\n"
		"\n"
		"RESULT(s)\n"
		"1. This ping demand will be ignored\n",
		ip_addr_str, version_str);

	FOUT;
	}

void
ipnl_icmp_invalid_address_for_destination (const char* ip_addr_str, const char* dest_name)
	{
	/* The destination address specified for a ping demand	*/
	/* originating on this node does not belong the 		*/
	/* destinaton node.										*/
	
	FIN (ipnl_icmp_invalid_address_for_destination (ip_addr_str, dest_name));

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(s):\n"
		" The destination address specified for a ping demand\n"
		" originating on this node does not belong the\n"
		" destinaton node. The address \"%s\" does not\n"
		" belong to the node \"%s\".\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The destinaton address attribute of the demand is set\n"
		"   incorrectly.\n"
		"2. There are multiple nodes with the same address in\n"
		"   in the network.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Make sure the destination address is specified correctly.\n"
		"2. If there are duplicate addresses in the network, note\n"
		"   the ping packet might be delivered to the wrong node.\n"
		"\n"
		"RESULT(s)\n"
		"1. The ping packets will be generated, but they might\n"
		"   lead to unexpected results.\n",
		ip_addr_str, dest_name);

	FOUT;
	}

void
ipnl_icmp_invalid_source_address_specification (const char* ip_addr_str, const char* dest_name, InetT_Addr_Family version)
	{
	const char*		version_str;

	/** The source address specified for a ping demand	**/
	/** originating on this node is invalid.			**/

	FIN (ipnl_icmp_invalid_source_address_specification (ip_addr_str, dest_name));

	/* Get a string form of the version.						*/
	version_str = inet_addr_family_string (version);

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"ERROR(s):\n"
		" The destination address specified for the ping demand\n"
		" to \"%s\" from this node is invalid.\n"
		" The string \"%s\" does not represent\n"
		" a valid %s address.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. The source address attribute of the demand is set\n"
		"   incorrectly.\n"
		"2. The Version attribute for the specified ping pattern\n"
		"   is set incorrectly.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Make sure there are no errors in the Address specification.\n"
		"2. Set the Version attribute correctly for the Ping pattern.\n"
		"   Ping patterns are configured under the \"IP Ping Parameters\"\n"
		"   attribute on the \"IP Attribute Config\" node.\n"
		"3. Choose a Ping Pattern with correct version.\n"
		"\n"
		"RESULT(s)\n"
		"1. The source address of the packets will be set to the\n"
		"   address of the outgoing interface",
		dest_name, ip_addr_str, version_str);

	FOUT;
	}

void
ipnl_rte_table_from_file_log_write (void)
	{
	static Boolean	import_from_external_file_log_displayed = OPC_FALSE;

	/** Generates a notification log message to indicate that	**/
	/**	the simulation attribute "IP Routing Table Export		**/
	/**	Import" is set to "Import".								**/
	FIN (ipnl_rte_table_from_file_log_write ());

	/* Has this log message been displayed before.		*/
	if (import_from_external_file_log_displayed == OPC_FALSE)
		{
		/* Set flag to avoid duplicate message generation.	*/
		import_from_external_file_log_displayed = OPC_TRUE;

		op_prg_log_entry_write (ip_config_warning_loghndl,
			"SYMPTOM(S):\n"
			"This simulation was run with the\n"
			"\"IP Routing Table Export/Import\" simulation\n"
			"attribute set to \"Import\"\n"
			"This means that dynamic routing protocols,\n"
			"including RIP, OSPF, IGRP, BGP, etc. were \n"
			"not run to build the distributed IP routing\n"
			"tables. Instead, their routing tables were\n"
			"saved (in a previous run) and reused in this\n"
			"run.\n"
			"\nThis feature is typically used is situations\n"
			"where:\n"
			"1. These routing protocols are not part of the\n"
			"   study being conducted.\n"
			"2. The IP connectivity between nodes in the network\n"
			"   does not change during the course of simulation.\n"
			"   An IP connectivity change - for example - would\n"
			"   be the failure of a link between two routers.\n"
			"\n"
			"POSSIBLE CAUSE(S):\n"
			"Modification of the external file containing\n"
			"routing tables can lead to packets being lost.\n"
			"\n"
			"SUGGESTIONS:\n"
			"None.\n");
		}

	FOUT;
	}


void
ipnl_rte_table_import_inconsistency_log_write (char* scenario_name, 
	char* error_type,int module_id, int correct_number_entries)
	{

	/** Generates a notification log message to indicate that	**/
	/**	inconsistencies were found in the routing tables file	**/
	FIN (ipnl_rte_table_import_inconsistency_log_write (scenario_name, 
		error_type, module_id, correct_number_entries));

	op_prg_log_entry_write (ip_config_error_loghndl,
		"SYMPTOM(S):\n"
		"An inconsistency was detected when reading\n"
        "the routing table export file: \n"
		"%s.gdf.\n"
		"The expected number of %s in the routing table\n"
		"for object with module id %d is %d.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The export file has been modified after\n"
		"   'exporting' it.\n"
		"2. The scenario which 'imported' the file\n"
		"   is not the same as the scenario that\n"
		"   'exported' it.\n"
		"   Even small changes in the network model\n"
		"   can cause such problems.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Rerun the simulation for this scenario\n"
		"   with the simulation attribute \"IP Routing\n"
		"   Table Export/Import\" set to \"Export\"\n"
		"   to recreate the routing tables eport file.\n"
		"2. Rerun the simulation for this scenario with\n"
		"   Export/Import simulation attribute set to\n"
		"   \"Import\".\n",
		scenario_name, error_type, module_id, correct_number_entries);

	FOUT;
	}


void
ipnl_rte_table_import_static_tbl_error_log_write (int entry_number, int line_number)
	{
	int				correct_nmb_entries;
	char			error_in [24];

	/** Generates a notification log message to indicate that	**/
	/**	inconsistencies were found in the routing tables file	**/
	FIN (ipnl_rte_table_import_static_tbl_error_log_write (entry_number, 
			line_number));

	if (entry_number != IP_TABLE_IMPORT_IP_STATIC_TBL_INV_NMB_CLMNS)
		{
		switch (entry_number)
			{
			case (IP_TABLE_IMPORT_IP_STATIC_TBL_DEST_ADDR):
				{
				strcpy (error_in,"Destination Address");
				break;
				}

			case (IP_TABLE_IMPORT_IP_STATIC_TBL_SUBNET_MASK):
				{
				strcpy (error_in, "Subnet Mask");
				break;
				}

			case (IP_TABLE_IMPORT_IP_STATIC_TBL_NEXT_HOP):
				{
				strcpy (error_in, "Next Hop");
				break;
				}
			}

			op_prg_log_entry_write (ip_config_error_loghndl,
				"SYMPTOM(S):\n"
				"An inconsistency has been detected when reading\n"
				"the previously exported IP static routing table.\n"
				"This inconsistency is at the line number [%d]\n"
				"and the entry number [%d], which is\n"
				"%s.\n"
				" \n"
				"POSSIBLE CAUSE(S):\n"
				"1. The export file has been modified after\n"
				"   'exporting' it.\n"
				"2. The scenario which 'imported' the file\n"
				"   is not the same as the scenario that\n"
				"   'exported' it.\n"
				"   Even small changes in the network model\n"
				"   can cause such problems.\n"
				"\n"
				"SUGGESTIONS:\n"
				"1. Rerun the simulation for this scenario\n"
				"   with the simulation attribute \"IP Routing\n"
				"   Table Export/Import\" set to \"Export\"\n"
				"   to recreate the routing tables eport file\n"
				"2. Rerun the simulation for this scenario with\n"
				"   Export/Import simulation attribute set to\n"
				"   \"Import\".\n", line_number, entry_number + 1, error_in);
		}
	else
		{

		/* Save the correct number of entries that will be printed out.	*/
		correct_nmb_entries = IP_TABLE_IMPORT_IP_STATIC_TBL_CLMNS;

		op_prg_log_entry_write (ip_config_error_loghndl,
			"SYMPTOM(S):\n"
			"An inconsistency has been detected when reading\n"
			"the previously exported IP static routing table.\n"
			"The number of entries at the line number [%d]\n"
			"does not agree with the number of entries\n"
			"in the IP static routing table, which is %d\n"
			"\n"
			"POSSIBLE CAUSE(S):\n"
			"1. The export file has been modified after\n"
			"   'exporting' it.\n"
			"2. The scenario which 'imported' the file\n"
			"   is not the same as the scenario that\n"
			"   'exported' it.\n"
			"   Even small changes in the network model\n"
			"   can cause such problems.\n"
			"\n"
			"SUGGESTIONS:\n"
			"1. Rerun the simulation for this scenario\n"
				"   with the simulation attribute \"IP Routing\n"
			"   Table Export/Import\" set to \"Export\"\n"
			"   to recreate the routing tables eport file.\n"
			"2. Rerun the simulation for this scenario with\n"
			"   Export/Import simulation attribute set to\n"
			"   \"Import\".\n", line_number, correct_nmb_entries);
			}

	FOUT;
	}


void
ipnl_rte_table_import_diff_ntwrk_log_write (char* scenario_name)
	{

	/** Generates a notification log message to indicate that	**/
	/** since the last routing table export, the networks has 	**/
	/** been modified.											**/
	FIN (ipnl_rte_table_import_diff_ntwrk_log_write (scenario_name));

	op_prg_log_entry_write (ip_config_error_loghndl,
	"SYMPTOM(S):\n"
	"  An inconsistency was detected when reading\n"
	"  the routing table export file: \n"
	"  %s.gdf.\n"
	"\n"
	"POSSIBLE CAUSE:\n"
	"  The scenario for which the routing tables were\n"
	"  exported differs from the current scenario,\n"
	"  which can mean one of the following:\n"
	"  1. New object(s) was/were added to the\n"
	"     network model.\n"
	"  2. Compound attribute values may have\n"
	"     been modified.\n"
	"\n"
	"SUGGESTIONS:\n"
	"1. Rerun the simulation for this scenario\n"
	"   with the simulation attribute \"IP Routing\n"
	"   Table Export/Import\" set to \"Export\"\n"
	"   to recreate the routing tables export file.\n"
	"   Then execute the simulation for this scenario\n"
	"   with \"Export/Import\" simulation attribute\n"
	"   set to \"Import\".\n"
	"2. Run the scenario with the simulation attribute\n"
	"   \"IP Routing Table Export/Import\" set to\n"
	"   \"Not Used.\"\n",
	scenario_name);

	FOUT;
	}

void                    
ipnl_firewall_dgram_reject_log_write (void)
    {
    static Boolean	firewall_dgram_reject_log_displayed = OPC_FALSE;

	/** Generates a notification log message to indicate that	**/
	/**	the firewall has rejected at least one datagram		**/
	/**	due to its security policies.							**/
	FIN (ipnl_firewall_dgram_reject_log_write (void));

	/* Has this log message been displayed before.		*/
	if (firewall_dgram_reject_log_displayed == OPC_FALSE)
		{
		/* Set flag to avoid multiple message generation.	*/
		firewall_dgram_reject_log_displayed  = OPC_TRUE;

		op_prg_log_entry_write (ip_packet_drop_loghndl,
			"BEHAVIOR:\n"
			"The firewall node has rejected at least\n"
			"one IP datagram.\n"
			"\n"
			"CAUSE:\n"
			"This is expected behavior of a firewall.\n"
			"Firewalls accept/reject datagrams based on\n"
			"their assigned security policies. These\n"
			"policies can be defined by modifying\n"
			"Proxy Server Information attribute of the\n"
			"firewall nodes.\n"
			"\n"
			"SUGGESTIONS:\n"
			"In the Proxy Server Information table,\n"
                        "provide a proxy server for each\n"
			"application whose datagrams you want to\n"
                        "allow through the firewall.\n");
		}

	FOUT;

	}  

void
ipnl_protwarn_mcast_custom_rte_invalid_update_req (void)
	{
	
	/** Reports a log message to indicate that an 	**/
	/** invalid request has been received for		**/
	/** updating a custom multicast route entry.	**/
	FIN (ipnl_protwarn_mcast_custom_rte_invalid_update_req (void));

	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" Expecting a Add or Delete IP\n"
		" custom multicast route entry\n"
		" update request but, received\n"
		" an invalid request.\n"
		"\n"
		"ACTION(S):\n"
		" Ignoring this update request.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		" A wrong update request value is\n"
		" used. The valid values are:\n"
		"\n"
		"    IpC_Mcast_Custom_Out_Port_Info_Add and\n"
		"    IpC_Mcast_Custom_Out_Port_Info_Delete\n"
		"\n"
		" Note: These constants are defined in\n"
		" ip_mcast_custom_rte_table.h include file.\n"
		"\n"
		"SUGGESTION(S):\n"
		" Use the above mentioned constants for\n"
		" the update request.\n"
		"\n");

	FOUT;
	}

void
ipnl_protwarn_radio_staticassignment_req (void)
	{
	
	/** Reports a log message to indicate that an 	**/
	/** invalid request has been received for		**/
	/** auto assigning IP address for 2 wireless	**/
	/** interface node.								**/
	FIN (ipnl_protwarn_radio_staticassignment_req (void));

	op_prg_log_entry_write (
		ip_radio_2wireless_intf_loghndl,
		"WARNING(S):\n"
		" Radio node with 2 wireless \n"
		" interfaces is detected.\n"
		" Both or one of the interface(s) \n"
		" is auto assigned.\n"
		"\n"
		"ACTION(S):\n"
		" In this case only one Radio	\n"
		" interface will be auto assigned. \n"
		"\n"
		"RECOMMENDATION(S):\n"
		" 1. Statically assign IP address for	\n"
		" each wireless interface in the	\n"
		" node model. 						\n"
		" 2. Configure them such that each 	\n"
		" interface will have a different 	\n"
		" subnet address.					"
		"\n");

	FOUT;
	}
 
void
ipnl_protwarn_radio_static_reassign (char* address_string_old, char* address_string)
	{
	/** Reports a log message to indicate that an 	**/
	/** explicit IP assignment has been changed due	**/
	/** to different network address.				**/
	FIN (ipnl_protwarn_radio_staticassignment_reassign  (char* address_string_old, char* address_string));

	op_prg_log_entry_write (
		ip_radio_wireless_intf_loghndl,
		"WARNING(S):\n"
		" The explicit (manually assigned) IP address \n"
		" (%s) needs to be changed to (%s). \n"
		" This is because two IP radio interfaces     \n"
		" within the same OPNET subnet have different \n"
		" IP network addresses.                       \n"
		"RECOMMENDATION(S):\n"
		" 1. Configure the radio IP network such that \n"
		"    each OPNET subnet represent one IP       \n"
		"    network.		                          \n"
		" 2. If you wish to configure multiple radio  \n"
		"    networks within same subnet then         \n"
		"    configure all the IP addresses in the    \n"
		"    network manually and disable IP auto     \n"
		"    addressing for the simulation.			  \n",
		address_string_old, address_string);
	
	FOUT;
	}

void
ipnl_rte_table_route_loss (IpT_Cmn_Rte_Table_Entry* route_entry, Boolean abool)
	{
	const char *	do_str;
	const char *	src_proto_str;
	char			dest_str [IPC_ADDR_STR_LEN];
	/** Reports a log message to indicate that the	**/
	/** IP Routing Table has lost a route to a		**/
	/** destination network, another routing protcol**/
	/** might have a route to the destination		**/
	
	FIN (ipnl_rte_table_route_loss (route_entry, abool));
	
	ip_cmn_rte_table_dest_prefix_print (dest_str, route_entry->dest_prefix);

	switch (IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (route_entry->route_src_proto))
		{
		case IPC_DYN_RTE_OSPF:
			src_proto_str = "OSPF";
			break;
		case IPC_DYN_RTE_ISIS:
			src_proto_str = "IS-IS";
			break;
		case IPC_DYN_RTE_RIP:
			src_proto_str = "RIP";
			break;
		case IPC_DYN_RTE_IGRP:
			src_proto_str = "IGRP";
			break;
		case IPC_DYN_RTE_EIGRP:
			src_proto_str = "EIGRP";
			break;
		case IPC_DYN_RTE_BGP:
			src_proto_str = "BGP";
			break;
		default:
			src_proto_str = "Unknown";
			break;
		}
	
	if (abool == OPC_TRUE)
		{
		do_str = "DOES";
		}
	else
		{
		do_str = "DOESN'T";
		}
	
	op_prg_log_entry_write (
	   ip_prot_warning_loghndl,
	   "WARNING: \n"
	   " The IP Routing Table has lost \n"
	   " its route to IP network       \n"
	   " (%s).				   		   \n"
	   " using %s. It %s have a backup \n"               
	   " using another protocol        \n"
	   " \n"	   
	   " POSSIBLE CAUSES: \n"
	   " If a node or link has been set \n"
	   " to fail this is expected behavior.\n"
	   " If this isn't the case, check for\n"
	   " log messages within the specific\n"
	   " routing protocol. \n		     ",
	   dest_str, src_proto_str, do_str);
	
	FOUT;
	}

void
ipnl_redist_default_warn (IpT_Rte_Proc_Id route_proto, Objid node_id, const char* orig_proto)
	{
	const char *		src_proto_str;
	char				node_name [256];
	static Boolean 		message_printed = OPC_FALSE;
	
	FIN (ipnl_redist_default_warn (route_proto, node_id));
	
	if (message_printed == OPC_FALSE)
		{
		message_printed = OPC_TRUE;
	   
		switch (IP_CMN_RTE_TABLE_ROUTEPROC_PROTOCOL (route_proto))
			{
			case 0:
		 		src_proto_str = "Directly Connected Networks";
				break;
			case IPC_DYN_RTE_OSPF:
				src_proto_str = "OSPF";
				break;
			case IPC_DYN_RTE_ISIS:
				src_proto_str = "IS-IS";
				break;
			case IPC_DYN_RTE_RIP:
				src_proto_str = "RIP";
				break;
		  	case IPC_DYN_RTE_IGRP:
				src_proto_str = "IGRP";
				break;
			case IPC_DYN_RTE_EIGRP:
				src_proto_str = "EIGRP";
				break;
		  	case IPC_DYN_RTE_BGP:
				src_proto_str = "BGP";
				break;
			default:
				src_proto_str = "Unknown";
				break;
			}
	
		oms_tan_hname_get (node_id, node_name);
	
		op_prg_log_entry_write (
			ip_prot_warning_loghndl,
			"WARNING:\n"
			" Route redistribution has been \n"
	  		" enabled for %s\n" 
			" into %s \n"
		   	" using the Default Metric.\n"
		   	" However the Default Metric\n"
		   	" hasn't been changed and is \n"
		  	" set to 0.\n"
			" NOTE: THIS MESSAGE WILL ONLY\n"
		    " BE PRINTED ONCE THROUGHOUT \n"
			" THE SIMULATION.\n"
			"\n"
		   	"SUGGESTION:\n"
		  	" Manually set the Default Metric\n"
		  	" to an appropriate value for %s\n"
		  	" on %s.\n"
			" This should be done on all routers\n"
			" that allow redistribution\n",
			src_proto_str, orig_proto, orig_proto, node_name);
		}
		
	FOUT;
	}

void
ipnl_no_process (const char* rte_proto)
	{
	/** This is a warning if attempting to discover a **/
	/** routing process model that hasn't been registered **/
	FIN (ip_no_process (char* err_string));
	
	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		" The OMS Process Discover \n"
		" has found either none or \n"
		" multiple instances of the \n"
		" protocol %s.\n"
		"\n"
		"ACTION(S):\n"
		" Ensure that the node model contains\n"
		" the process model that that is being \n"
		" searched for. \n"
		"\n",
		rte_proto);
	FOUT;
	}
	
void
ipnl_pim_sm_pkt_dropped_in_start_log_write (double start_time)
	{
	/** This is a warning if attempting to discover a **/
	/** routing process model that hasn't been registered **/
	FIN (ipnl_pim_sm_pkt_dropped_in_start_log_write (void));
	
	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"SYMPTOM(S):\n"
		"   Discarding PIM-SM hello message\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. A router will drop all hello messages received\n"
		"   before the specified multicast start time.\n"
		"   The multicast start time on this node is\n"
		"   %fs.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. If routers in the network have different\n"
		"   Multicast start times, it is normal for a\n"
		"   router to discard hello messages received\n"
		"   from neighbors before the specified start\n"
		"   time. If this is the case no action is required\n"
		"\n"
		"This message will not be repeated for this node\n",
		start_time);
	FOUT;
	}
	
void
ipnl_igmp_pkt_dropped_in_start_log_write (double start_time, int interface)
	{
	/** This is a warning if attempting to discover a **/
	/** routing process model that hasn't been registered **/
	FIN (ipnl_igmp_pkt_dropped_in_start_log_write (interface));
	
	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"SYMPTOM(S):\n"
		"   Discarding IGMP query message received on\n"
		"   interface %d.\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. A router will drop all query messages received\n"
		"   before the specified multicast start time.\n"
		"   The multicast start time on this node is\n"
		"   %fs.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. If routers in the network have different\n"
		"   multicast start times, it is normal for a\n"
		"   router to discard query messages received\n"
		"   from neighbors before the specified start\n"
		"   time. If this is the case no action is required\n"
		"\n"
		"This message will not be repeated for this interface\n",
		interface, start_time);
	FOUT;
	}

/* Sim Log messages concerning "Shutdown" IP Interfaces */
void
ipnl_shutdown_intf_log_write (List* shutdown_intf_lptr)
	{
	int						ith_intf = 1;
	char					hold_str [100];
	char					message_str [10001] = "";
	IpT_Interface_Info*		iface_ptr;
	
	/* This message is a warning about the operation */
	/* of shutdown interfaces. 						 */
	FIN (ipnl_shutdown_intf_log_write (Objid node_id));
		
	/* Create a string that holds all the shutdown interfaces of the node */
	while (op_prg_list_size (shutdown_intf_lptr))
		{
		iface_ptr = (IpT_Interface_Info *) op_prg_list_remove (shutdown_intf_lptr, OPC_LISTPOS_HEAD);
		sprintf (hold_str, "  %d. %s\n", ith_intf, ip_rte_intf_name_get (iface_ptr));
		
		if ((strlen (message_str) + strlen (hold_str)) < 10000)
			strcat (message_str, hold_str);
		else
			break;
		
		ith_intf++;
		}
	
	op_prg_log_entry_write (
	ip_config_warning_loghndl,
			"WARNING:\n"
			" The following connected interfaces\n"
			" are configured as administratively\n"
			" \"Shutdown\": \n"
			"\n"
			"%s"
			"\n"
			" A Shutdown interface will not send \n"
			" or receive network traffic. It will \n"
			" also not be included in any routing \n"
			" updates.\n"
			"\n"
		   	"SUGGESTION:\n"
		  	" If this is the desired setting, then \n"
			" no actions need to be taken. \n"
			"\n"
			" If this is not the desired setting,\n"
			" then change value to \"Active\" for\n"
			" the following attribute:\n"
			"  \"IP Routing Parameters->Interface\n"
			"   Information->Status\"\n",
			message_str);
	FOUT;
	}

void
ipnl_shutdown_intf_send_log_write (Objid node_id, int intf_index, SimT_Pk_Id packet_id)
	{
	char		node_name [512];
	static int	error_count = 0;
	
	/* This message warns of packets being dropped that are sent 	*/
	/* out of an interface that has been marked "Shutdown"	   		*/
	FIN (ipnl_shutdown_intf_send_log_write(Objid node_id, int intf_index));
	
	if (error_count < 5)
		{
		/** This error will only be reported for a max of 5 times **/
		oms_tan_hname_get (node_id, node_name);

		op_prg_log_entry_write (
			ip_packet_drop_loghndl,
			"WARNING(S):\n"
			" The IP packet (ID " SIMC_PK_ID_FMT ") is being dropped \n"
		    " because it cannot be sent out on interface \n"
		    " index (%d) of node (%s). \n"
		    " This interface has been configured as 'Shutdown'.\n"
 		    "\n"
		    "POSSIBLE CAUSE(S):\n"
		    "1. A static or dynamic route entry has \n"
		    "   been entered that chooses a next hop \n"
		    "   found through this interface. \n"
		    "2. A default route exists that chooses \n"
		    "   a next hop found through this interface\n"
		    "\n"
		    "SUGGESTIONS:\n"
		    "1. Ensure that no static or dynamic routes \n"
		    "   choose a next hop that will use this \n"
		    "   interface. \n"
		    "2. If this interface shouldn't be in \n"
		    "   'Shutdown' status check the setting in \n"
		    "   the Interface Table. \n"
			"NOTE: This warning will only be printed a max of 5 times\n",
			packet_id, intf_index, node_name);
		
		error_count++;
		}
	FOUT;
	}
	
void
ipnl_shutdown_intf_recv_log_write (Objid node_id, const char* intf_name, SimT_Pk_Id packet_id)
	{
	char		node_name [512];
	static int	error_count = 0;
	
	/* This message warns of packets being dropped that are sent 	*/
	/* out of an interface that has been marked "Shutdown"	   		*/
	FIN (ipnl_shutdown_intf_recv_log_write(Objid node_id, char* intf_name));
	
	if (error_count < 5)
		{
		/** This error will only be reported for a max of 5 times **/
		
		oms_tan_hname_get (node_id, node_name);

		op_prg_log_entry_write (
			ip_packet_drop_loghndl,
			"WARNING(S):\n"
			" The IP packet (ID " SIMC_PK_ID_FMT ") is being dropped \n"
			" because it cannot be received on interface \n"
			" (%s) of node (%s). \n"
 		    "\n"
		    "POSSIBLE CAUSE(S):\n"
			"1. This interface is marked as shutdown.\n"
			"2. The address of this interface is set to No IP Address.\n"
			"3. The version of the IP packet is not supported on this\n"
			"   interface.\n"
		    "\n"
		    "SUGGESTIONS:\n"
		    "1. Ensure that no default of static routes \n"
		    "   choose this interface as a next hop. \n"
		    "2. If this interface shouldn't be in \n"
		    "   'Shutdown' status check the setting in \n"
		    "   the Interface Table. \n"
			"NOTE: This warning will only be printed a max of 5 times\n",
			packet_id, intf_name, node_name);
		
		/* increase error count */
		error_count++;
		}
	FOUT;
	}

void
ipnl_unmappable_vlan_pkt_drop_log_write (Objid node_id, const char* intf_name, int pkt_vid, Packet* pkptr)
	{
	char			pkt_format [64];
	static List*	already_logged_lptr = OPC_NIL;
	char			temp_key_str [256];
	char*			key_str;

	/** If a tagged VLAN packet is received on an interface	**/
	/** and none of the subinterfaces on the interface		**/
	/** belong to that VLAN, the packet will be dropped.	**/

	FIN (ipnl_unmappable_vlan_pkt_drop_log_write (intf_name, pkptr));

	/* Get the packet format. It can be either ip_dgram_v4	*/
	/* or arp_v2 (if arp sim eff is disabled).				*/
	op_pk_format (pkptr, pkt_format);

	/* Create a key that we can use for searching in the	*/
	/* list of already logged information, to determine if	*/
	/* we already wrote a log mesage for a similar packet	*/
	sprintf (temp_key_str, "%d%s%s%d", node_id, intf_name, pkt_format, pkt_vid);

	/* If the list already exists search for this string	*/
	if (OPC_NIL != already_logged_lptr)
		{
		if (OPC_NIL != op_prg_list_elem_find (already_logged_lptr,
			oms_string_compare_proc, temp_key_str, OPC_NIL, OPC_NIL))
			{
			/* we already printed a log.					*/
			FOUT;
			}
		}
	else
		{
		/* The list doesn't exist. Create an empty one.		*/
		already_logged_lptr = op_prg_list_create ();
		}

	/* Insert the key string into the list.					*/
	key_str = (char*) op_prg_mem_alloc (strlen (temp_key_str) + 1);
	strcpy (key_str, temp_key_str);
	op_prg_list_insert (already_logged_lptr, key_str, OPC_NIL);
	
	op_prg_log_entry_write (
		ip_packet_drop_loghndl,
		"WARNING(S):\n"
		" Dropping Packet (ID " SIMC_PK_ID_FMT ") of format \"%s\"\n"
		" received on the interface \"%s\". The packet was\n"
		" tagged with a VLAN ID of %d, but none of the\n"
		" subinterfaces of this interface belong to this VLAN.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. Interfaces belonging to different IP subnets\n"
		"   are in the same VLAN.\n"
		"2. VLAN configuration on switches is incorrect\n"
		"\n"
		"RESULT(s):\n"
		"1. This packet will be dropped.\n"
		"\n"
		"NOTE: This message will not be repeated on this\n"
		"      interface for other packets of the same\n"
		"      format and belonging to the same VLAN.\n",
		op_pk_id (pkptr), pkt_format, intf_name, pkt_vid);

	FOUT;
	}

void
ipnl_subintf_without_vlan_id_log_write (const char* intf_name)
	{
	/** This function prints out a log message informing the	**/
	/** user that a subinterface was encountered which was not	**/
	/** configured to be part of any VLAN.						**/

	FIN (ipnl_subintf_without_vlan_id_log_write (intf_name));

	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR(s)\n"
		"The subinterface %s on this node was not\n"
		"assigned a valid VLAN ID. All subinterfaces\n"
		"are supposed to be assigned a valid VLAN ID.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Assign a valid VLAN ID to this subinterface.\n"
		"\n"
		"RESULT(s):\n"
		"1. Packets sent out on this subinterface will\n"
		"   be untagged and will be associated with the\n"
		"   VLAN tag specified under the PVID of the port of\n"
		"   the switch to which this interface is connected\n",
		intf_name);

	FOUT;
	}

void
ipnl_invalid_address_for_subinterface_log_write (const char* subintf_name, const char* parent_intf_name, 
	const char* addr_str)
	{
	/** This is a warning if attempting to discover a **/
	/** routing process model that hasn't been registered **/
	FIN (ipnl_igmp_pkt_dropped_in_start_log_write (interface));
	
	op_prg_log_entry_write (
		ip_prot_warning_loghndl,
		"WARNING(S):\n"
		"   The subinterface named \"%s\" under\n"
		"   the parent interface \"%s\" on\n"
		"   this router was not assigned a valid\n"
		"   IP address. The address of this subinterface\n"
		"   was specified as \"%s\"\n"
		"   which does not represent a valid IP address.\n"
		"\n"
		"RESULT(S):\n"
		"1. This subinterface will be ignored.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. If this subinterface is to be used, assign\n"
		"   a valid IP address to it.\n"
		"2. Otherwise remove this entry from the Subinterface\n"
		"   Information table.\n",
		subintf_name, parent_intf_name, addr_str);
	FOUT;
	}
	
void
ipnl_invalid_row_in_prefix_filter_config (const char* list_id, int row_index, const char* network_str)
	{
	/** Writes a log message warning the user that a statement in	**/
	/** a prefix filter configuration is being ignored because of	**/
	/** of an invalid network string.								**/

	FIN (ipnl_invalid_row_in_prefix_filter_config (list_id, row_index, network_str));

	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(s):\n"
		"1. The row at index %d under the List Configuration of the\n"
		"   the prefix filter \"%s\" is being ignored.\n"
		"   Note that row indices begin at 0.\n"
		"\n"
		"REASON(s):\n"
		"1. The string \"%s\" specified for the\n"
		"   \"Network/Length\" attribute of this row is not\n"
		"   in the correct format.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Refer the comments of the above attribute for\n"
		"   more information on the expected format.\n"
		"\n"
		"RESULT(s):\n"
		"1. This row will be ignored.\n",
		row_index, list_id, network_str);

	FOUT;
	}

void
ipnl_rte_map_invalid_match_prop (Objid match_objid, int match_property,
	int match_condition, const char* match_value_str)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/* This message reports an error in configuring a route map with a match */
	/* property that is not supported in DES, report the error and actions.	 */
	FIN (ipnl_rte_map_invalid_match_prop (term_objid, match_property, match_condition, match_value_str));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING(s):\n"
		" The following match clause in term '%s' of\n"
		" route map '%s' will be ignored.\n"
		"\n"
		" Match Property: '%s'\n"
		" Match Condition: '%s'\n"
		" Match Value: '%s'\n"
		" \n"
		"POSSIBLE CAUSES(S):\n"
		"1. The match property '%s' is not currently\n"
		"   supported.\n"
		"\n"
		"SUGGESTIONS:\n"
		"1. Please refer the IP Model Description section\n"
		"   of the online documentation for a list of\n"
		"   supported match properties.\n"
		"\n"
		"RESULT(S):\n"
		"1. If this is the only match clause in this term,\n"
		"   this term will always match.\n"
		"2. If there are other match clauses, the term will\n"
		"   match if all of those statements match.\n",
		term_name, map_name, match_prop_array [match_property],
		match_cond_array [match_condition], match_value_str,
		match_prop_array [match_property]);
		
	FOUT;
	}

void
ipnl_rte_map_invalid_match_condition (Objid match_objid, int match_condition)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/* This message reports an error in configuring a route map with a match */
	/* property that is not supported in DES, report the error and actions.	 */
	FIN (ipnl_rte_map_invalid_match_condition (Objid term_objid, int match_condition));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		" A match clause in term, '%s' \n"
		" of route map '%s' cannot be read  \n"
		" due to the match condition, '%s' .\n"
		" This match condition is not currently \n"
		" supported in Discrete Event Simulation \n"
		" \n"
		"ACTION(S):\n"
		" This match clause will be omitted from \n"
	    " the term of the route map.\n"
		" \n"
		"SUGGESTIONS:\n"
		" The following match conditions are NOT \n"
		" currently supported by IP Route Maps: \n"
		" 	1. Is One Of \n"
		"  	2. Is Not One Of \n",
		term_name, map_name, match_cond_array [match_condition]);
		
	
	FOUT;
	}


void
ipnl_rte_map_invalid_match_combo (Objid match_objid,int match_property, int match_condition)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/* This message reports an error in configuring a route map with a match  */
	/* property and match condition combination that is not supported in DES, */
	/* report the error and actions.	 */
	FIN (ipnl_rte_map_invalid_match_condition (Objid term_objid, int match_condition));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		" A match clause in term, '%s' \n"
		" of route map '%s' cannot be read due to \n"
		" the use of  match property, '%s' in \n"
		" conjuction with the match condition '%s' \n"
		" This combiniation is not currently \n"
		" supported in Discrete Event Simulation or\n"
		" is an invalid combination.\n"			
		" \n"
		"ACTION(S):\n"
		" This match clause will be omitted from \n"
	    " the term of the route map.\n"
		" If this is the only match statement in the\n"
		" term, this term will always match.\n"
		" \n"
		"SUGGESTIONS:\n"
		" Please refer the IP model description in the\n"
		" product documentation for a list of valid\n"
		" match properties and conditions.\n",
		term_name, map_name, match_prop_array [match_property], match_cond_array [match_condition]);
		
	
	FOUT;
	}

void
ipnl_rte_map_invalid_filter_in_match_info_log_write (Objid match_objid,
	const char* filter_name)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/** This functions warns the users that a filter name	**/
	/** used to match against an address in a route map is	**/
	/** is invalid.											**/

	FIN (ipnl_rte_map_invalid_filter_in_match_info_log_write (term_objid, filter_name));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		"1. A prefix filter/extended ACL name specified\n"
		"   under the 'Match Value' attribute in\n"
		"   term '%s' of route map '%s' is invalid.\n"
		"   '%s' is not the name of a valid prefix filter\n"
		"   or extended ACL configured on this node.\n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. There is a typo in this attribute specification.\n"
		"2. The prefix filter or extended ACL referenced\n"
		"   by this name was removed.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Configure an ACL or Prefix Filter with the above name.\n"
		"2. Change the attribute configuration so that it\n"
		"   references a valid ACL or prefix filter.\n"
		"\n"
		"RESULT(s):\n"
		"1. This prefix filter/ACL will be ignored. If there are\n"
		"   other valid prefix filters/ACLs specified in the attribute\n"
		"   they will still be applied.\n"
		"2. If this was the only prefix filter/ACL in the statement\n"
		"   the entire match statement will be ignored.\n",
		term_name, map_name, filter_name);

	FOUT;
	}

void
ipnl_rte_map_invalid_match_value_log_write (Objid match_objid, IpT_Rte_Map_Match_Prop match_property,
	IpT_Rte_Map_Match_Cond match_condition, const char* match_value)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/** The match value specified in a match statement is invalid.		**/

	FIN (ipnl_rte_map_invalid_match_value_log_write (<args>));

	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		"1. The string specified under the 'Match Value'\n"
		"   attribute of the following match statement in\n"
		"   term `%s` of route map '%s' is invalid.\n"
		"\n"
		"   Match Property:  %s\n"
		"   Match Condition: %s\n"
		"   Match Value:     \"%s\"\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Refer the IP Model Description in the product\n"
		"   documentation for the correct format in which\n"
		"   the Match Value has to be specified.\n"
		"\n"
		"RESULT(s):\n"
		"1. If this is the only match clause in this term,\n"
		"   this term will always match.\n"
		"2. If there are other match clauses, the term will\n"
		"   match if all of those statements match.",
		term_name, map_name, match_prop_array [match_property],
		match_cond_array [match_condition], match_value);

	FOUT;
	}

void
ipnl_rte_map_invalid_addr_str (Objid match_objid)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/* This message reports an error in configuring a route map with a match  */
	/* property and match condition combination that is not supported in DES, */
	/* report the error and actions.	 */
	FIN (ipnl_rte_map_invalid_addr_str (Objid match_objid));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		" A match clause in term, '%s' \n"
		" of route map '%s' \n"
		" cannot be read due to an invalid \n"
		" address, subnet mask combination. \n"
		" entered in the match value. \n"
		" \n"
		"ACTION(S):\n"
		" This match clause will be omitted from \n"
	    " the term of the route map.\n"
		" \n"
		"SUGGESTIONS:\n"
		" If 'IP Address' and 'Equals' are \n"
		" used as the match property and condition\n"
		" the value must be entered in the form of \n"
		" 'addr mask', where addr and mask are both \n"
		" dotted decimal IP addresses. \n",
		term_name, map_name);
		
	FOUT;
	}

void
ipnl_rte_map_invalid_set_combo (Objid set_objid, int set_attr, int set_oper)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/* This message reports an error in configuring a route map with a match  */
	/* property and match condition combination that is not supported in DES, */
	/* report the error and actions.	 */
	FIN (ipnl_rte_map_invalid_set_combo (set_objid, set_attr, set_oper));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (set_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		" A set clause in term, '%s' of route map \n"
		" '%s' cannot be applied due to \n"
		" the use of the set attribute '%s' in \n"
		" conjuction with the set operation '%s' \n"
		" This combiniation is not currently \n"
		" supported in Discrete Event Simulation or\n"
		" is an invalid combination.\n"			
		" \n"
		"RESULT(S):\n"
		" This set clause will be omitted from \n"
	    " the term of the route map.\n"
		" \n"
		"SUGGESTIONS:\n"
		" Please refer the IP model description in the\n"
		" product documentation for a list of valid\n"
		" set attributes and operations.\n",
		term_name, map_name, set_attr_array [set_attr], set_oper_array [set_oper]);
		
	FOUT;
	}

void
ipnl_rte_map_invalid_set_info_log_write (const char* rte_map_label_str, const char* term_str,
	IpT_Rte_Map_Set_Attr set_attr, IpT_Rte_Map_Set_Oper set_oper, const char* set_value_str)
	{
	/** This function prints out a log message warning the user	**/
	/** that an invlaid set clause was encountered in a route 	**/
	/** map and it will be ignored.								**/

	FIN (ipnl_rte_map_invalid_set_info_log_write (<args>));
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"ERROR:\n"
		" A set clause in term, '%s' \n"
		" of route map '%s' \n"
		" is invalid.\n"
		" Set Attribute: %s\n"
		" Set Operation: %s\n"
		" Set Value:     %s\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The set operation is not valid for the specified\n"
		"   set attribute.\n"
		"2. The string specified under Set Value is not of the\n"
		"   format expected for the specified set attribute and\n"
		"   operation.\n"
		"3. If the set clause is to change the interface,	\n"
		"   then the interface set is a broadcast interface. \n"	
		"\n"
		"SUGGESTION(S):\n"
		"1. Make sure that the the specified set operation is\n"
		"   valid for the set attribute chosen.\n"
		"2. Make sure the string specified under Set Value is of\n"
		"   the correct format.\n"
		"RESULT(S)\n"
		"1. This set clause will be ignored\n",
		term_str, rte_map_label_str, set_attr_array [set_attr],
		set_oper_array [set_oper], set_value_str);
	
	FOUT;
	}

void
ipnl_rte_map_invalid_set_attr_log_write (const char* rte_map_label_str, const char* term_str,
	IpT_Rte_Map_Set_Attr set_attr, IpT_Rte_Map_Set_Oper set_oper, const char* set_value_str)
	{
	/** This function prints out a log message warning the user	**/
	/** that a set clause was encountered in a route map and was**/
	/** ignored because the specified Set Attribute is not		**/
	/** valid.													**/

	FIN (ipnl_rte_map_invalid_set_attr_log_write (<args>));
	
	op_prg_log_entry_write (
		ip_config_warning_loghndl,
		"WARNING:\n"
		" The following set clause in term, '%s' \n"
		" of route map '%s' will be ignored.\n"
		" Set Attribute: %s\n"
		" Set Operation: %s\n"
		" Set Value:     %s\n"
		"\n"
		"POSSIBLE CAUSE(S):\n"
		"1. The set attribute `%s` is not currently\n"
		"   supported.\n"
		"\n"
		"RESULT(S)\n"
		"1. This set clause will be ignored\n",
		term_str, rte_map_label_str, set_attr_array [set_attr],
		set_oper_array [set_oper], set_value_str, set_attr_array [set_attr]);
	
	FOUT;
	}

void
ipnl_acl_invalid_label_for_route (int acl_type, char* acl_name)
	{
	static int		count = 0;
	const char*		acl_type_str;
	
	
	/* This message will be called when an acl is called to be applied 	*/
	/* to a route update, however the label is found not to exist.		*/
	FIN (ipnl_acl_invalid_label_log_write (int acl_type, char* acl_name));
	
	switch (acl_type)
		{
		case IpC_Acl_Type_Pre:
			{
			acl_type_str = "Prefix";
			break;
			}
		case IpC_Acl_Type_Ext:
			{
			acl_type_str = "Extended";
			break;
			}
		case IpC_Acl_Type_AS:
			{
			acl_type_str = "AS Path";
			break;
			}
		case IpC_Acl_Type_Comm:
			{
			acl_type_str = "Community";
			break;
			}
		}
	
	if (count < 5)
		{
		op_prg_log_entry_write (
			ip_config_warning_loghndl,
			"WARNING(S):\n"
			" The %s Access Control List \n"
			" with the label <%s> \n"
		    " has not been configured. \n"
		    "\n"
		    "ACTION(S):\n"
		    " An undefined Access Control List \n"
			" that is applied to a route will \n"
			" always match or permit the route.\n"
			" \n"
			"SUGGESTION: \n"
			" Make sure that <%s> has been \n"
			" configured in the appropriate place.\n"
			" Prefix and Extended Acess Control Lists \n"
			" are configured under the IP Routing \n"
			" Parameters attribute and \n"
			" AS Path and Community Lists are \n"
			" configured under the BGP Parameters \n"
			" attribute.\n"
			" NOTE: This log will only be written \n"
			" a maximum of 5 times \n"
		    "\n",
			acl_type_str, acl_name, acl_name);
		
		count++;
		}
	
	FOUT;
	}
		 
void
ipnl_rtab_addr_error_log_started_log_write (void)
    {
    char*       	project_scenario_name;
	static Boolean	log_written = OPC_FALSE;
   
    /** message indicating that a log file with IP address  **/
    /** warnings have been generated. This log will be      **/
    /** written only once                                   **/
    FIN (ipnl_rtab_addr_error_log_started_log_write ());
   
	/* If this log message has been written once, don't do	*/
	/* it again.											*/
	if (log_written)
		{
		FOUT;
		}

	/* Indicate that the log message has been written once	*/
	log_written = OPC_TRUE;
	
    /* Porject scenario name - used to generate the file name */
    project_scenario_name = ip_net_name_sim_attr_get (OPC_FALSE);
   
    op_prg_log_entry_write (
        ip_config_error_loghndl,
        "WARNING:\n"
        " Simulation encountered some IP network addresses  \n"
        " that are not registered in the global IP table.   \n"
        "\n"
        " Information about these networks has been logged  \n"
        " in the following file:                            \n"
        "   %s-ip_addr_err_log.gdf \n"
        "\n"
        " The global IP table is maintained for a faster    \n"
        " lookup, and is mainly used by RIP and IGRP.\n"
        " This table contains destination addresses based on\n"
        " their classful boundaries.                        \n"

        "\n"
        "REASON(S):\n"
        " 1. None of the IP interfaces in the current network   \n"
        "    model belong to the unregistered networks.         \n"
        "   \n"
        "    This is possible with router configuration import  \n"
        "    where only part of the network is being imported.  \n"
        "    The IP networks that trigger this warning belong to\n"
        "    the part of the network that has not been imported.\n"
        "    But static routes to these networks are configured \n"
        "    on the imported routers and are redistributed to   \n"
        "    other routing protocols.                           \n"
        "    \n"
        " 2. The networks that trigger these error messages are \n"
        "    summary addresses that are being redistributed into\n"
        "    RIP, IGRP or EIGRP                                 \n"
        "   \n"
        " 3. The networks are subnetted with VLSM and are being \n"
        "    redistributed into classful protocols like RIP, IGRP\n"
        "    and EIGRP.                                         \n"
        "    \n"

        "RESULT(S): \n"
        " In all the above cases the routing tables that are built\n"
        " by the routing protocols and the forwarding tables may  \n"
        " not contain these addresses. This will specifically     \n"
        " true on routers that use RIPv1 or IGRP to build the     \n"
        " forwarding tables.                                      \n"
        "\n"
        " Note this will have not have any significant impact on  \n"
        " the routing studies that you may perform.               \n",
        project_scenario_name);

    /* Free the memory for the project scenario                 */
    op_prg_mem_free (project_scenario_name);

	FOUT;
	}

void
ipnl_unmappable_next_hop_addr_log_write (void)
    {
    char*       	project_scenario_name;
	static Boolean	log_written = OPC_FALSE;
   
	/** Message indicating that the next hop address of		**/
	/** an ip packet could not be mapped to a MAC address. 	**/
	/** The details will be written into the ip address		**/
	/** error log file. This simulation log message will be	**/
	/** printed out once to point the user to this file.	**/
    FIN (ipnl_unmappable_next_hop_addr_log_write ());
   
	/* If this log message has been written once, don't do	*/
	/* it again.											*/
	if (log_written)
		{
		FOUT;
		}

	/* Indicate that the log message has been written once	*/
	log_written = OPC_TRUE;
	
    /* Porject scenario name - used to generate the file name */
    project_scenario_name = ip_net_name_sim_attr_get (OPC_FALSE);
   
    op_prg_log_entry_write (
        ip_config_error_loghndl,
        "ERROR:\n"
		"An ARP module in the network encountered an IP\n"
		"packet whose next hop address could not be mapped\n"
		"to a MAC layer address.\n"
		"\n"
		"Information about all such addresses has been\n"
		"logged in the following file:\n"
		"   %s-ip_addr_err_log.gdf \n"
		"\n"
		"POSSIBLE CAUSE(s):\n"
		"1. No interface with these IP addresses exists in\n"
		"   this network.\n"
		"2. The interfaces with these addresses do not run a\n"
		"   compatible MAC protocol.\n"
		"\n"
		"SUGGESTION(s):\n"
		"1. Make sure that these IP addresses exist.\n"
		"2. Make sure they belong to the correct MAC protocol.\n"
		"\n"
		"RESULT(s):\n"
		"1. These packets will be dropped.\n",
        project_scenario_name);

    /* Free the memory for the project scenario                 */
    op_prg_mem_free (project_scenario_name);

	FOUT;
	}

void			
ipnl_rte_map_invalid_label (char* acl_name)
	{
	static int		count = 0;
	
	/* This message will be called when an acl is called to be applied 	*/
	/* to a route update, however the label is found not to exist.		*/
	FIN (ipnl_rte_map_invalid_label (char* acl_name));
	
	if (count < 5)
		{
		op_prg_log_entry_write (
			ip_config_warning_loghndl,
			"WARNING(S):\n"
			" The Route Map with\n"
			" the label <%s> \n"
		    " has not been configured. \n"
		    "\n"
		    "ACTION(S):\n"
		    " An undefined Route Map \n"
			" that is applied to a route  \n"
			" will always Deny the route.\n"
			" \n"
			"SUGGESTION: \n"
			" Make sure that <%s> has been \n"
			" configured properly. \n"
			" Route Maps are configured  \n"
			" under the IP Routing \n"
			" Parameters attribute. \n"
			" NOTE: This log will only be written \n"
			" a maximum of 5 times \n"
		    "\n",
			 acl_name, acl_name);
		
		count++;
		}
	FOUT;
	}

void 
ipnl_cfgwarn_next_hop_name_for_broadcast_intf (const char* intf_name)
	{
	FIN (ipnl_cfgerr_next_hop_name_for_broadcast_intf (intf_name));
	
    op_prg_log_entry_write (
        ip_config_warning_loghndl,
        "WARNING(s):\n"
		" Detected a static routing table entry or	\n"
		" a Policy route map entry with interface	\n"
		" name <%s> specified for next hop.			\n"
		"\n"	
		" Next Hop attribute can be set to interface\n"
		" name for point-to-point interfaces only.	\n" 			
		"\n"
		" This interface has been determined to be	\n"
		" either a broadcast or non-broadcast multiple\n"
		" access interface.\n"
		"\n"	
		"ACTION(s):\n"
		" This route entry will be ignored.			\n",
		intf_name);
	
	FOUT;
	}

void 
ipnl_cfgwarn_next_hop_name_for_no_ip_addr_intf (const char* intf_name)
	{
	FIN (ipnl_cfgwarn_next_hop_name_for_no_ip_addr_intf (intf_name));
	
    op_prg_log_entry_write (
        ip_config_warning_loghndl,
        "WARNING(s):\n"
		" Detected a static routing table entry with\n"
		" interface name <%s> specified for next hop.\n"
		"\n"	
		" This interface has been determined to be set\n"
		" to No IP Address. An interface set to No IP\n"
		" address cannot be specified as the next hop.\n"
		"\n"	
		"ACTION(s):\n"
		" This static route entry will be ignored.\n",
		intf_name);
	
	FOUT;
	}

void
ipnl_rte_map_invalid_match_info_log_write (Objid match_objid,int match_property, int match_condition, char* match_string)
	{
	char		map_name [512];
	char		term_name [512];
	Objid		map_entry_objid, map_config_objid;
	Objid		map_table_objid;
	
	/* This message reports an error in configuring a route map with a match  	*/
	/* property, match condition, and match value combination that is 			*/
	/* invalid.																	*/
	FIN (ipnl_rte_map_invalid_match_info_log_write (Objid term_objid, int match_condition));
	
	/* Get the name of the route map the error occured in 	*/
	/* and also the name of the term within the route map	*/
	map_entry_objid 	= op_topo_parent (match_objid);
	map_config_objid 	= op_topo_parent (map_entry_objid);
	map_table_objid		= op_topo_parent (map_config_objid);
	
	op_ima_obj_attr_get (map_table_objid, "Map Label", map_name);
	op_ima_obj_attr_get (map_entry_objid, "Term", term_name);
	
	op_prg_log_entry_write (
		ip_config_error_loghndl,
		"Policy Error:\n"
		" A match clause in term, '%s' of route map '%s'\n"
		" cannot be read due to the invalid configuration.\n\n"
		" Match Property 	= '%s' 					\n"
		" Match Condition 	= '%s' 					\n"
		" Match Value		= '%s'					\n\n"	
		" This is not a valid combination.\n"			
		" \n"
		"ACTION(S):\n"
		" This match clause will be omitted from \n"
	    " the term of the route map.\n"
		" \n",
		term_name, map_name, match_prop_array [match_property], match_cond_array [match_condition], match_string);
		
	
	FOUT;
	}


void
ip_nl_rte_map_invalid_set_log_write (const char* prot_str, int set_attr, int set_oper)
	{
	static PrgT_String_Hash_Table*	ip_set_clause_hash_table_ptr = OPC_NIL;
	char 							hash_table_str [512];
	int*							hash_table_entry = OPC_NIL;
	void* 							dummy;
	
	/**	Generates a notification log message to inform the		**/
	/**	user that inavlid set clause has been configured in 	**/
	/** Route Maps												**/
	FIN (ip_nl_rte_map_invalid_set_log_write (int set_attr, int set_oper));

	/* Create the string for the hash table						*/
	sprintf (hash_table_str, "%s %s %s", prot_str, set_attr_array [set_attr], set_oper_array [set_oper]);
	
	/* If Hash table does not exist Create a hash table to		*/
	/* contain string of protocol set attr and set operation	*/
	/* else check if an entry exists for the supplied string	*/
	if (ip_set_clause_hash_table_ptr == OPC_NIL)
		ip_set_clause_hash_table_ptr = prg_string_hash_table_create (50, 50);		
	else
		hash_table_entry = (int *) prg_string_hash_table_item_get (ip_set_clause_hash_table_ptr, hash_table_str);
	
	if (hash_table_entry == OPC_NIL)
		{
		op_prg_log_entry_write (ip_config_warning_loghndl,
			"WARNING:\n"
			"An invalid set clause has been configured for\n"
			"the Route Map being applied to routes into 	\n"
			"%s on this node.\n"
			"\n"
			"POSSIBLE CAUSE:\n"
			"1. The set clause combination for:\n"
			"   Set Attribute = %s\n"
			"   Set Operation = %s\n"
			"   is not valid\n"	
			"\n"
			"ACTION:\n"
			"1. The set clause will be ignored.\n"
			"\n"	
			"SUGGESTIONS:\n"
			"1. Make sure that the the specified set operation is\n"
			"   valid for the set attribute chosen.\n\n"
			"2. Make sure this attribute can be altered for the route.\n" 	
			"\n", prot_str, set_attr_array [set_attr], set_oper_array [set_oper]);
	
		/* Feed it in the hash table, with some address,		*/
		/* we dont care what address until its non nil.			*/
		prg_string_hash_table_item_insert (ip_set_clause_hash_table_ptr, hash_table_str, &set_attr, &dummy);
		}
		
	FOUT;
	}

void
ip_nl_rte_map_invalid_match_log_write (const char* prot_str, int match_property, int match_condition)
	{
	static PrgT_String_Hash_Table*	ip_match_clause_hash_table_ptr = OPC_NIL;
	char 							hash_table_str [512];
	int*							hash_table_entry = OPC_NIL;
	void* 							dummy;
	
	/**	Generates a notification log message to inform the		**/
	/**	user that inavlid match clause has been configured in 	**/
	/** Route Maps												**/
	FIN (ip_nl_rte_map_invalid_match_log_write (char* prot_str, int match_property, int match_condition));

	/* Create the string for the hash table						*/
	sprintf (hash_table_str, "%s %s %s", prot_str, match_prop_array [match_property], match_cond_array [match_condition]);
	
	/* If Hash table does not exist Create a hash table to		*/
	/* contain string of protocol match prop and match condtion	*/
	/* else check if an entry exists for the supplied string	*/
	if (ip_match_clause_hash_table_ptr == OPC_NIL)
		ip_match_clause_hash_table_ptr = prg_string_hash_table_create (50, 50);		
	else
		hash_table_entry = (int *) prg_string_hash_table_item_get (ip_match_clause_hash_table_ptr, hash_table_str);
	
	if (hash_table_entry == OPC_NIL)
		{
		op_prg_log_entry_write (ip_config_warning_loghndl,
			"WARNING:\n"
			"An invalid match clause has been configured for\n"
			"the Route Map being applied to routes into 	\n"
			"%s on this node.\n"
			"\n"
			"POSSIBLE CAUSE:\n"
			"1. The match clause combination for:\n"
			"   Match Property  = %s\n"
			"   Match Condition = %s\n"
			"   is not valid\n"	
			"\n"
			"ACTION:\n"
			"1. The match clause will be ignored.\n"
			"\n"	
			"SUGGESTIONS:\n"
			"1. Make sure that the the specified match property is\n"
			"   valid for the match condition chosen.\n\n"
			"\n", prot_str, match_prop_array [match_property], match_cond_array [match_condition]);
	
		/* Feed it in the hash table, with some address,		*/
		/* we dont care what address until its non nil.			*/
		prg_string_hash_table_item_insert (ip_match_clause_hash_table_ptr, hash_table_str, &match_property, &dummy);
		}
		
	FOUT;
	}

void
ip_nl_dsr_not_enabled_log_write (void)
	{
	static Boolean		log_written = OPC_FALSE;
	
	/** Writes a log message to indicate that	**/
	/** DSR is not configured on a node that	**/
	/** received a DSR packet					**/
	FIN (ip_nl_dsr_not_enabled_log_write (void));
	
	if (log_written == OPC_FALSE)
		{
		op_prg_log_entry_write (ip_config_error_loghndl,
			"ERROR(S):\n"
				"Dropping the DSR packet received\n"
				"\n"
				"CAUSE(S):\n"
				"A DSR packet has been received by this 	\n"
				"node. However, DSR is not running on this	\n"
				"node\n"
				"\n"
				"SUGGESTION(S):\n"
				"Enable DSR on this node\n\n"
				"NOTE : This message will not be repeated	\n"
				"\n");
		
		/* Set the flag so that this log	*/
		/* is written only once.			*/
		log_written = OPC_TRUE;
		}
		
	FOUT;
	}

void
ip_nl_tunnel_routing_loop_src_log_write (const char* intf_name)
	{
	/** Write the log for a routing loop for the tunnel.	**/
	
	static Boolean log_written = OPC_FALSE;
	
	FIN (ip_nl_tunnel_routing_loop_src_log_write (intf_name));
	
	if (!log_written)
		{
		op_prg_log_entry_write (ip_prot_error_loghndl,
			"ERROR:\n"
				" Dropping tunnel packet.\n"
				"\n"
				"CAUSE(S):\n"
				" A packet going out on the tunnel %s 		\n"
				" is being dropped since it was previously	\n"
				" sent out on a tunnel out of this node.	\n"
				" This indicates the presence of a routing	\n"
				" loop in the network.						\n"
				"\n"
				"SUGGESTION(S): \n"
				" 1. Ensure that static route specification(s)\n"
				"	in the network do not result in routing	\n"
				"	loops.\n\n"
				"Note: This message will not be repeated\n"	, 
				intf_name);
	
		log_written = OPC_TRUE;
		}
	
	FOUT;
	}			
					

void
ip_nl_tunnel_routing_loop_dest_log_write (const char* intf_name)
	{
	/** Write the log for a routing loop for the tunnel.	**/
	
	static Boolean log_written = OPC_FALSE;
	
	FIN (ip_nl_tunnel_routing_loop_dest_log_write (intf_name));
	
	if (!log_written)
		{
		op_prg_log_entry_write (ip_prot_error_loghndl,
			"ERROR:\n"
				" Dropping tunneled packet.\n"
				"\n"
				"CAUSE(S):\n"
				" A packet coming in on the tunnel %s 		\n"
				" is being dropped since the destination of	\n"
				" the payload packet is the source of the	\n"
				" tunnel on which the packet has arrived.	\n"
				" This indicates the presence of a routing	\n"
				" loop in the network.						\n"
				"\n"
				"SUGGESTION(S): \n"
				" 1. Ensure that static route specification(s)\n"
				"    in the network do not result in routing	\n"
				"    loops.\n\n"
				"Note: This message will not be repeated\n"	, 
				intf_name);
	
		log_written = OPC_TRUE;
		}
	
	FOUT;
	}			
					
	
void
ip_nl_tunnel_gre_sequence_log_write (const char* intf_name)
	{
	/** Log message for out of sequence datagram	**/
	/** received on a GRE tunnel.					**/
	
	static Boolean	log_written = OPC_FALSE;
	
	FIN (ip_nl_gre_sequence_log_write (intf_name));
	
	if (!log_written)
		{
		op_prg_log_entry_write (ip_prot_warning_loghndl,
			"WARNING:\n"
				" Dropping out-of-sequence packet on GRE tunnel.\n"
				"\n"
				"CAUSE(S):\n"
				" Interface %s on this node is a GRE tunnel	\n"
				" interface that has been configured to drop	\n"
				" out-of-sequence datagrams. One such datagram \n"
				" has been received and is being dropped.		\n"	
				"\n"
				"SUGGESTION(S):	\n"	
				" 1. This may happen if IP data traffic is	\n"
				"	 being load-balanced across multiple paths.	\n"
				"\n\n"
				"Note: This message will not be repeated.\n",
				intf_name);
		
		log_written = OPC_TRUE;
		}
	FOUT;
	}
	
	
void
ip_nl_tunnel_passenger_proto_log_write (const char* intf_name, const char* proto_name)
	{
	
	/** Log for indicating that a passenger protocol is not **/
	/** supported on a tunnel interface.		 			**/
	
	static Boolean log_written = OPC_FALSE;
	
	FIN (ip_nl_tunnel_passenger_proto_log_write (intf_name, proto_name));
	
	if (!log_written)
		{
		op_prg_log_entry_write (ip_config_error_loghndl,
			"ERROR: \n"
				" Dropping packet of unsupported Passenger Protocol type.\n"
				"\n"
				"CAUSE(S): \n"
				" Tunnel interface %s on this node is not configured	\n"	
				" to encapsulate packets of protocol type %s.		\n"
				" But this interface has received a packet of this type.\n"
				" The packet is being dropped.\n"
				"\n"
				"SUGGESTION(S):\n"
				" Ensure that the Passenger Protocol(s) attribute under\n"
				" Tunnel Information on the Tunnel Interface has been  \n"					
				" set correctly for all tunnels.	\n"
				"\n\n"
				"Note: This message will not be repeated.\n",
				intf_name, proto_name);
		
		log_written = OPC_TRUE;
		}
	FOUT;
	}
		
void
ip_nl_tunnel_mtu_log_write (const char* intf_name)
	{
	
	/** Log for indicating that the MTU size on the 	**/
	/** tunnel interface has become too small after		**/
	/** accounting for tunnel overhead.					**/
	
	FIN (ip_nl_tunnel_mtu_log_write (intf_name));

	op_prg_log_entry_write (ip_prot_warning_loghndl,
		"WARNING:\n"
			" Changing MTU size on a tunnel.\n"
			"\n"
			"CAUSE(S):\n"
			" Tunnel interface %s has a very small configured 	\n"
			" MTU size. This size is not sufficient for carrying \n"
			" tunneled packets. This MTU size is being reset to	\n"
			" the minimum value of 1 byte of payload (in addition\n"
			" to inner packet's IP header).\n\n"
			"SUGGESTION(S):\n"
			" Please configure the MTU size on all tunnel interfaces	\n"
			" appropriately. Outer IP header needs 20 bytes. GRE		\n"
			" tunnels without checksumming enabled need 4 bytes. If	\n"
			" checksumming is enabled, an additional 4 bytes are needed.\n"	
			"\n"	
			"Note: This message will not be repeated.\n",
			intf_name);
		
	FOUT;
	}
	
void	
ip_nl_tunnel_modes_mismatch_log_write (const char* intf_name, const char* proto_name)
	{
	/** Log for indicating that tunnel modes on peer tunnels are 	**/
	/** not the same.												**/		
	
	static Boolean log_written = OPC_FALSE;
	
	FIN (ip_nl_tunnel_modes_mismatch_log_write (intf_name, protocol));
	
	if (!log_written)
		{
		op_prg_log_entry_write (ip_config_error_loghndl,
			"ERROR: \n"
				" Dropping packet due to mismatch in tunnel modes.\n"
				"\n"
				"CAUSE(S): \n"
				" Tunnel interface %s on this node has received a packet	\n"
				" of unexpected protocol type %s. The packet is therefore	\n"	
				" being dropped. \n"	
				"\n"
				"SUGGESTION(S):\n"
				" Please ensure that the Tunnel Mode attribute under\n"
				" Tunnel Information on the Tunnel Interface is the \n"
				" same for both tunnels that make up a pair (A->B and B->A).\n"	
				"\n"
				"Note: This message will not be repeated.\n",
				intf_name, proto_name);
		
		log_written = OPC_TRUE;
		}
	FOUT;
	}

void	
ip_nl_tunnel_creation_error_log_write (const char* attr_name, const char* attr_value)
	{
	/** Log for indicating that tunnel modes on peer tunnels are 	**/
	/** not the same.												**/		
	
	FIN (ip_nl_tunnel_modes_mismatch_log_write (intf_name, protocol));
	
	op_prg_log_entry_write (ip_config_error_loghndl,
		"WARNING:\n"
		" Tunnel not being created due to wrong configuration.\n"
		"\n"	
		"CAUSE(S):\n"	
		" Tunnel interface on this node is not being created \n"
		" because the attribute \"%s\" has been set to \"%s\",\n"
		" which is invalid.\n"
		"\n"
		"SUGGESTION(S):\n"
		" Please check the tunnel configuration under \n"
		" IP Routing Parameters -> Tunnel Interfaces.\n"
		" The following attributes must NOT be left to default:\n"
		"	- Address\n"
		"	- Tunnel Information -> Tunnel Source\n"
		"	- Tunnel Information -> Tunnel Destination\n",	
		attr_name, attr_value);				

	FOUT;
	}			
				
void
ip_nl_tunnel_to_dest_not_found_log_write (const char* dest_addr_str)
	{
	/** Log indicating that a matching outgoing tunnel has	**/
	/** not been found for an incoming tunnel.				**/

	static Boolean log_written = OPC_FALSE;
	
	FIN (ip_nl_tunnel_to_dest_not_found_log_write (dest_addr_str));
	
	if (!log_written)
		{
		op_prg_log_entry_write (ip_prot_warning_loghndl,
			"WARNING:\n"
			" Outgoing tunnel not found to destination %s, \n"
			" incoming packet will be dropped.\n"	
			"\n"
			"CAUSE(S):\n"
			" This node has received a packet on a tunnel with source address\n"
			" %s. But a corresponding peer tunnel to that address \n"
			" has not been configured on this node, or is not active at \n"
			" this time. Such an asymmetric configuration is allowed only \n"
			" for IPv6 automatic or 6to4 tunnels. But this packet has arrived\n"
			" on a GRE/IP-IP/IPv6 Manual tunnel. This packet will therefore \n"	
			" be dropped. \n"	
			"\n"
			"SUGGESTION(S):\n"
			" (1) Ensure that all tunnel interfaces originating from a node \n"
			" 	  have corresponding peer tunnels originating from the \n"
			"     destinations and terminating on that node. \n"
			" (2) Ensure that the source and destination IP addresses of \n"
			"     peer tunnels are an exact match. \n"
			"\n"
			"Note: This message will not be repeated for other tunnels.",
			dest_addr_str, dest_addr_str);
		
		log_written = OPC_TRUE;
	
		}
	
	FOUT;
	}

void
ip_nl_tunnel_mode_ipsec_not_supported_log_write (Objid iface_description_objid)
	{
	char tunnel_name [256];
	
	/** Write a log message informing the user that IPsec is	**/
	/** not supported in DES, and tunnel mode will be reset		**/
	/** to GRE.													**/
	FIN (ip_nl_tunnel_mode_ipsec_not_supported_log_write (tunnel_name));
	
	op_ima_obj_attr_get (iface_description_objid, "Name", tunnel_name);
	
	op_prg_log_entry_write (ip_config_error_loghndl,
		"WARNING: \n"
		" Tunnel mode IPsec not supported in DES.\n"
		"\n"
		"CAUSE:\n"
		" Tunnel interface (%s) on this node has the attribute\n"
		" Tunnel Information -> Tunnel Mode set to IPsec.\n"
		" This mode is currently not supported in Discrete\n"
		" Event Simulations. \n"
		"\n"
		"EFFECT: \n"
		" The tunnel mode will be reset to GRE.\n",
		tunnel_name);
	
	FOUT;
	}

void
ipnl_cmn_rte_optimal_hash_size_values_log (int value_used, int recommended_value)
	{
	/** Write a log message informing the user about the optimal	**/
	/** values for the hash table size in the IP common route table	**/

	FIN (ipnl_cmn_rte_optimal_hash_size_values_log (min_hash_size,
		max_hash_size, avg_hash_size));

	/* Write the log message.										*/
	op_prg_log_entry_write (ip_result_loghndl,
		"SUGGESTION(s):\n"
		"You might be able to improve the performance of this simulation\n"
		"by configuring the 'IP Source Dest Pairs' environment attribute\n"
		"as described below. Note that the value of this attribute will\n"
		"not affect the results of the simulation.\n"
		"\n"
		"The IP forwarding mechanism can be tuned to maintain peak\n"
		"performance while simulating large IP networks. The trade off is\n"
		"that higher values of this attribute will require more memory.\n"
		"The optimal value can be calculated as the maximum number of\n"
		"unique IP source destination pairs that will pass through any\n"
		"IP routing node in the network.\n"
		"\n"
		"The first value given below is the value used for this\n"
		"simulation. It was either configured explicitly through the\n"
		"environment attribute or estimated before the simulation based\n"
		"on various parameters such as the number of nodes and demands.\n"
		"The recommended value given is a more accurate estimate computed\n"
		"after the simulation.\n"
		"\n"
		"Estimated/Configured value: %d\n"
		"Recommended value: %d\n"
		"\n"
		"ACTION(s):\n"
		"1. If the estimated value and optimal values are close or if\n"
		"   performace is not a critical issue for this simulation,\n"
		"   this message may be ignored.\n"
		"2. If the above values are significantly different from each\n"
		"   other and simulation performance is important, set the value\n"
		"   of the environment attribute `IP Source Dest Pairs' through an\n"
		"   environment (.ef) file. Please refer the product documentation\n"
		"   for more information on environment files and how to use them.\n"
		"3. This attribute does not have to be set to the optimal value\n"
		"   suggested above. Setting this attribute to a higher value might\n"
		"   increase simulation performance with the trade off that memory\n"
		"   usage will also increase. Similarly, a lower value may be used\n"
		"   to decrease memory usage by sacrificing performance.\n"
	    "4. To disable the printing of this log message set the boolean\n"
		"   environment attribute 'IP Source Dest Pairs Log' to 'disabled'\n",
	value_used, recommended_value);

	FOUT;
	}

void
ipnl_dupl_intf_name_error (Objid first_intf_name_objid, const char* intf_name)
	{
	char		attr_name [128];
	char		interface_type [128];
	Objid		parent_objid;
	Objid		top_level_attr_objid;
	char		top_level_attr_name [128];
	
	FIN  (ipnl_dupl_intf_name_error (intf_name_objid, intf_name));
	
	parent_objid = op_topo_parent (first_intf_name_objid);
	
	op_ima_obj_attr_get (parent_objid, "name", &attr_name);
	
	if (strcmp (attr_name, "Interface Information") == 0)
		strcpy (interface_type, "physical interface");
	else if (strcmp (attr_name, "Subinterface Information") == 0)
		strcpy (interface_type, "subinterface");
	else if (strcmp (attr_name, "Loopback Interfaces") == 0)
		strcpy (interface_type, "loopback interface");
	else
		strcpy (interface_type, "tunnel interface");

	/* Get the top level attribute name.				*/
	top_level_attr_objid = oms_tan_top_level_attribute_objid_get (parent_objid);

	if (OPC_OBJID_INVALID != top_level_attr_objid)
		{
		op_ima_obj_attr_get (top_level_attr_objid, "name", top_level_attr_name);
		}
	else
		{
		/* We were not able to determine the top level	*/
		/* attribute.									*/
		strcpy (top_level_attr_name, "Unknown");
		}

	op_prg_log_entry_write (ip_config_error_loghndl, 
		"WARNING:\n"
		" IP process detected that the %s\n"
		" name \"%s\" occurs more than once\n"
		" under the \"%s\" attribute.\n"
		"\n"
		"SUGGESTION:\n"
		" 1. Make sure that interface names are unique\n"
		"    within each node. This must be true across all\n"
		"    physical, loopback and tunnel interfaces,\n"
		"    as well as subinterfaces.\n"
		" 2. Change the interface name of the above interface.\n"
		"    Interface names are configured using\n"
		"    \"IP Routing Parameters\" attribute.\n",
		interface_type, intf_name, top_level_attr_name);
	
	FOUT;
	}
