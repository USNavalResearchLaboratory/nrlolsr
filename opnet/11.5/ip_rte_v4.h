/* ip_rte_v4.h */
/* Definitions file for IP routing procedures. */

/****************************************/
/* 	     Copyright (c) 1987-2005    	*/
/*		by OPNET Technologies, Inc.		*/
/*		(A Delaware Corporation)		*/
/*	7255 Woodmont Av., Suite 250  		*/
/*     Bethesda, MD 20814, U.S.A.       */
/*			All Rights Reserved.		*/
/****************************************/

#ifndef _IP_RTE_H_INCL_
#define _IP_RTE_H_INCL_

#include <opnet.h>
#include <nato.h>
#include <ip_addr_v4.h>
#include "oms_data_def.h"
#include "ip_igmp_support.h"
#include <ip_dgram_sup.h>					/* Access IpT_Dgram_Fields */
	
#ifndef HDR_IP_QOS_SUPPORT_H
#  include "ip_qos_support.h"
#endif

#ifndef _MIPV6_DEFS_H_INCL_
#	include "mipv6_defs.h"
#endif



#if defined (__cplusplus)
extern "C" {
#endif

/* Constant that stores the maximum length of the name of	*/
/* an interface or a subinterface							*/
#define IPC_MAX_INTF_NAME_LEN			31

/* Contants related to subinterfaces						*/
#define IPC_SAME_AS_PARENT_STR		"Same as Parent"
#define IPC_SUBIF_MCAST_DISABLED		 0
#define IPC_SUBIF_MCAST_ENABLED			 1
#define IPC_MCAST_SAME_AS_PARENT		-1
#define IPC_MTU_SAME_AS_PARENT			-3
#define IPC_BANDWIDTH_SAME_AS_PARENT	-1
#define IPC_SUBINTF_PHYS_INTF			-1

/* Recommended minimum MTU for an IPv6 interface.			*/
/* RFC 2460 Sec. 5.											*/
#define IPV6C_MIN_MTU					1500

/* Macro representing a MAC layer broadcast address.		*/
#define IPC_PHYS_ADDR_BROADCAST			-1

/* Macro representing an invalid MAC Address.				*/
#define IPC_PHYS_ADDR_INVALID			-2

/* Value of ouput and input streams for logical interfaces	*/
#define IPC_PORT_NUM_INVALID			-1

/* Value of the addr_index field for logical interfaces.	*/
#define IPC_ADDR_INDEX_IVNALID			-1

/* Value corresponding to the symbol map Use link bandwidth	*/
/* of the Bandwidth attribute under Metric Information.		*/
#define IPC_BW_USE_LINK_BW	-1
#define IPC_BW_AUTO_CALC	-2

/* Value corresponding to the symbol map Auto Calculate		*/
/* for the Interface Speed attribute.						*/
#define IPC_INTF_SPEED_AUTO_CALCULATE	-1.0

/* Generic Routing Encapsulation header size.				*/
#define IPC_TUNNEL_GRE_BASE_HDR_SIZE_BITS		32
#define IPC_TUNNEL_GRE_HDR_OPTIONS_SIZE_BITS	32

/* Tunnel related constants	*/
#define IPC_TUNNEL_TOS_INHERITED				-1		
#define	IPC_TUNNEL_TTL_INHERITED				-1
#define IPC_TUNNEL_TOS_DEFAULT					0
#define IPC_TUNNEL_TTL_DEFAULT					255

#define IPC_TUNNEL_PASSENGER_PROTO_IPV4_MASK	0x01
#define IPC_TUNNEL_PASSENGER_PROTO_IPV6_MASK	0x02

#define IPC_INTF_FLAG_MANET_ENABLED				(0x01 << 0)	
#define IPC_INTF_FLAG_IGMP_ENABLED				(0x01 << 1)
#define IPC_INTF_FLAG_MCAST_ENABLED				(0x01 << 2)
#define IPC_INTF_FLAG_RSVP_ENABLED				(0x01 << 3)
#define IPC_INTF_FLAG_MIP_ENABLED				(0x01 << 4)	
#define IPC_INTF_FLAG_MSFC_ALT					(0x01 << 5)	
#define IPC_INTF_FLAG_MSFC_ALT_HOST_LB			(0x01 << 6)		

#define IP_TUNNEL_PASSENGER_PROTOCOL_IPV6_IS_ENABLED(_tunnel_info_ptr_) \
	((Boolean) (_tunnel_info_ptr_->passenger_proto_flags & IPC_TUNNEL_PASSENGER_PROTO_IPV6_MASK))
#define IP_TUNNEL_PASSENGER_PROTOCOL_IPV4_IS_ENABLED(_tunnel_info_ptr_) \
	((Boolean) (_tunnel_info_ptr_->passenger_proto_flags & IPC_TUNNEL_PASSENGER_PROTO_IPV4_MASK))
#define IP_TUNNEL_PASSENGER_PROTOCOL_ENABLE_IPV6(_tunnel_info_ptr_) \
	(_tunnel_info_ptr_->passenger_proto_flags |= IPC_TUNNEL_PASSENGER_PROTO_IPV6_MASK)
#define IP_TUNNEL_PASSENGER_PROTOCOL_ENABLE_IPV4(_tunnel_info_ptr_) \
	(_tunnel_info_ptr_->passenger_proto_flags |= IPC_TUNNEL_PASSENGER_PROTO_IPV4_MASK)

/* The size of PPP header. This is the total overhead in bits on PPP links.	*/
#define IPC_PPP_HEADER_SIZE_BITS			56

typedef enum IpT_Intf_Lower_Layer_Type
	{
	IpC_Intf_Lower_Layer_Invalid,
	IpC_Intf_Lower_Layer_LAN,
	IpC_Intf_Lower_Layer_FR,
	IpC_Intf_Lower_Layer_ATM,
	IpC_Intf_Lower_Layer_PPP
	}	IpT_Intf_Lower_Layer_Type;

/* Enumerated data type to identify the type IP interface.	*/
/* This is required due to the fact that we send an ICI		*/
/* with a packet to the lower layer, which is case of 		*/
/* "dumb" interfaces like "slip" is not required.			*/
typedef enum IpT_Interface_Type
	{
	IpC_Intf_Type_Unspec,
	IpC_Intf_Type_Dumb,
	IpC_Intf_Type_Smart
	} IpT_Interface_Type;

typedef enum IpT_Interface_Status
	{
	IpC_Intf_Status_Active,
	IpC_Intf_Status_Shutdown,
	IpC_Intf_Status_Loopback,
	IpC_Intf_Status_Tunnel,
	IpC_Intf_Status_Unconnected,
	IpC_Intf_Status_Group
	} IpT_Interface_Status;

/* Enumerated type specifying the source of the packet		*/
/* arriving to the IP routing process model.				*/
typedef enum 
	{
	IpC_Pk_Instrm_Child = -1	/* Packet is from child process. */
	} IpT_Pk_Instrm_Type;

typedef enum
	{
	IpC_Policy_Action_Unknown,
	IpC_Policy_Action_Drop,
	IpC_Policy_Action_Reroute,
	IpC_Policy_Action_Alter_Tos,
	IpC_Policy_Action_Alter_Prec,
	IpC_Policy_Action_Alter_Dscp,
	IpC_Policy_Action_Traverse,
	IpC_Policy_Action_Destination_Reached
	} IpT_Policy_Action;

/* Parent-to-child shared memory used to transfer packets between	*/
/* IP and its child processes (ip_basetraf_src or ip_icmp.)  Both	*/
/* the elements of this shared data structures are filled by the	*/
/* child process just before invoking IP.							*/
typedef struct
	{
	int						child_process_id;		/* Process ID of the child process.		*/

	Packet*					child_pkptr;			/* Packet pointer that the child		*/
													/* process wants to transmit.			*/

	IpT_Mcast_Ptc_Info		ip_mcast_ptc_info;		/* This field is used for communication	*/
													/* between IGMP (child) processes and	*/
													/* IP (parent) process					*/

	int						intf_index;				/* The IPv6 Index of the interface on	*/
													/* which the packet was received. Needed*/
													/* for icmp6 process.					*/
	} IpT_Ptc_Memory;

/* Struct to hold the IP Policy Checker information							*/
typedef struct
	{
	/* The Policy Check Demand ID					*/
	Objid				demand_id;
	Boolean				record_details;
	Boolean				reachable;
	List*				ip_policy_action_lptr;
	} IpT_Policy_Check_Info;

/* Struct to hold the IP Policy Action information	*/
typedef struct
	{
	char*				node_name;
	IpT_Policy_Action	policy_action;
	char*				rte_map_or_filter_name;
	char*				iface_name;	
	} IpT_Policy_Action_Info;

/* Structure to hold the IP protocol-specific info */
/* in type OmsT_Basetraf_Conversation_Info         */
typedef struct
	{
	char*					demand_name;
	InetT_Address 			src_addr; 
	InetT_Address 			dest_addr;
	int 					bgutil_tos;
	OmsT_Tracer_RR_Option 	route_record_option;
	Boolean 				route_recorded; 

	/* Demand object attributes to support Policy Routing 	*/
	InetT_Address 			actual_src_addr; 
	InetT_Address 			actual_dest_addr;
	int 					src_port;
	int 					dest_port;
	int 					protocol;
	IpT_Policy_Check_Info*	policy_check_info_ptr;
	} IpT_Conversation_Info;


/* This field will be added to a tracer packet to store		*/
/* IP specific information, like Src, dest address,			*/
/* port info, and protocol etc.This information will be		*/
/* used while using policy routing on Bgutil packets		*/			
struct IpT_Tracer_Pkt_IP_Info
	{
	InetT_Address 						actual_src_addr; 
	InetT_Address 						actual_dest_addr;
	int 								src_port;
	int 								dest_port;
	int 								protocol;
	IpT_Policy_Check_Info*				ip_policy_check_info_ptr;
	char*								demand_name;
	int									copy_counter; 	/* To keep track of copies that are pointing to orig structure.	*/
	struct IpT_Tracer_Pkt_IP_Info*		orig_struct_ptr;	
	};

typedef struct IpT_Tracer_Pkt_IP_Info	IpT_Tracer_Pkt_IP_Info;	

/* The structure below is needed as a return value */
/* from a unified parsing function which reads tos */
/* protocol, dest and src addresses, dest and src  */
/* port numbers from an IP dgram encapsulating a   */
/* TCP segment, a UDP segment or a bgutil_tracer.  */
typedef struct
	{
	int					packet_tos; 
	int					protocol; 
	InetT_Address		source_address; 
	InetT_Address		dest_address; 
	int					source_port; 
	int					dest_port; 
	Packet*				orig_pkptr;
	} IpT_Pkt_Socket_Info; 

/* Structure to hold the metric components of an IP interface */
typedef struct
	{
	int					    reliability;		
	int					    load;				
	int					    bandwidth;			/* in kbps */
	double					delay;				/* in units of 10 usec */
	} IpT_Intf_User_Metrics;

/* Enumerated type describing types of dynamic routing available.				*/
/* Default indicates the value will be chosen as specified on the IP interface.	*/

/* LP 9-18-05 - added OLSR_NRL */

typedef enum
	{
	IpC_Rte_Default = -99,
	IpC_Rte_Custom = -2,
	IpC_Rte_None = -1,
	IpC_Rte_Rip = 0,
	IpC_Rte_Igrp,
	IpC_Rte_Ospf,
	IpC_Rte_Bgp,
	IpC_Rte_Eigrp,
	IpC_Rte_Isis,
	IpC_Rte_Dsr,
	IpC_Rte_Tora,
	IpC_Rte_Aodv,
	IpC_Rte_Olsr,
	IpC_Rte_OLSR_NRL,   
	IpC_Rte_Ripng,
	IpC_Rte_Static
	} IpT_Rte_Protocol;

/* end LP */

/* Structure to hold an (IP destination addr, VC name) pair      */
/* for the layer 2 mapping of a multipoint interface. A multi-   */
/* point interface connects to several VCs, each for a different */
/* IP destination address. */
typedef struct
	{
	InetT_Address	ip_dest_addr;
	char* 			vc_name; 
	} IpT_Dest_To_VC_Mapping; 

/* Structure that stores the information like PVCs connected to	*/
/* a subinterface, VLAN/ELAN(s) to which the subinterface		*/
/* belongs etc.													*/
typedef struct
	{
	/* An array of (IP destination addr, ATM VC name) pairs for    */
	/* the ATM Layer 2 Mapping, together with the array dimension. */
	IpT_Dest_To_VC_Mapping* 	atm_pvc_set; 
	int 						num_atm_pvcs;
	
	/* An array of (IP destination addr, FR VC name) pairs for    */
	/* the FR Layer 2 Mapping, together with the array dimension. */
	IpT_Dest_To_VC_Mapping*		fr_pvc_set;
	int							num_fr_pvcs; 
	
	int							vlan_identifier;
	short						num_elan_names;
	char**						elan_names;
	} IpT_Layer2_Mappings;

/* Enumerates the types of lower layer mappings stored in the	*/
/* above structure.												*/
typedef enum
	{
	IpC_Layer2_Mapping_ATM_PVC,
	IpC_Layer2_Mapping_FR_PVC,
	IpC_Layer2_Mapping_VLAN_Identifier,
	IpC_Layer2_Mapping_ELAN_Name
	} IpT_Layer2_Mapping;

/* Enumerates the types of ICIs, which can be received in the	*/
typedef enum IpT_Rte_App_Ici_Type
	{
	IpC_Rte_Mcast_Ici = 0,
	IpC_Rte_Rsvp_Ici  = 1,
	IpC_Rte_Vpn_Ici	  = 2
	} IpT_Rte_App_Ici_Type;

typedef enum IpT_Interface_Mode
	{
	IpC_Interface_Mode_None,
	IpC_Interface_Mode_IPv4_Only,
	IpC_Interface_Mode_IPv4_IPv6,
	IpC_Interface_Mode_IPv6_Only
	} IpT_Interface_Mode;

typedef enum IpT_Tunnel_Mode
	{
	IpC_Tunnel_Mode_IPv6_Manual,
	IpC_Tunnel_Mode_IPv6_Auto,
	IpC_Tunnel_Mode_IPv6_6to4,
	IpC_Tunnel_Mode_GRE,
	IpC_Tunnel_Mode_IPIP,
	IpC_Tunnel_Mode_IPsec,
	IpC_Tunnel_Mode_Unspecified
	} IpT_Tunnel_Mode;

typedef enum IpT_Addr_Status
	{
	IPC_ADDR_STATUS_DUPLICATE = 0,
	IPC_ADDR_STATUS_UNIQUE
	}IpT_Addr_Status;

/* ..and corresponding bit flags.			*/
#define	IPC_RTE_PROTO_RIP		(1<<0)
#define	IPC_RTE_PROTO_IGRP		(1<<1)
#define	IPC_RTE_PROTO_OSPF		(1<<2)
#define	IPC_RTE_PROTO_BGP		(1<<3)
#define IPC_RTE_PROTO_EIGRP     (1<<4)
#define IPC_RTE_PROTO_ISIS		(1<<5)
#define IPC_RTE_PROTO_RIPNG		(1<<6)
#define	IPC_RTE_PROTO_STATIC	(1<<7)

/* Flags indicating the selection of the simulation */
/* attribute "IP Routing Table Export/Import"		*/ 
#define IP_RTE_TABLE_EXPORT_IMPORT_NOT_USED		0
#define IP_RTE_TABLE_EXPORT          			1
#define IP_RTE_TABLE_IMPORT						2
#define IP_RTE_TABLE_NON_DET					-1

/* Macro for interrupt code send by IP to routing processes		*/
#define IP_IMPORT_TABLE							1

/* Data structure to hold a secondary address and mask.		*/
typedef struct IpT_Secondary_Address
	{
	IpT_Address_Range		ip_addr_range;
	InetT_Address_Range		inet_addr_range;
	} IpT_Secondary_Address;

/* Data structure to hold all the secondary addresses of	*/
/* an interface.											*/
typedef struct IpT_Sec_Addr_Table
	{
	int						num_sec_addresses;
	IpT_Secondary_Address*	sec_addr_array;
	} IpT_Sec_Addr_Table;

/* Data structure to hold MPLS information for a particular interface						*/
typedef struct
	{
	Boolean 			iface_mpls_status;	/* Boolean to hold the MPLS status on this iface*/
	
	int					supported_resource_class;
											/* Resource Classes supported by this interface	*/
											/* These RCs will be used while calculating		*/
   											/* CSPF rtes for MPLS LSPs.						*/	

	double				te_cost;			/* TE cost specified under MPLS->Iface Info. 	*/

	} IpT_Iface_Mpls_Info;

/* Data structure to hold RSVP information for a particular interface						*/
typedef struct
	{
	Boolean 			rsvp_status;		/* Boolean to hold the RSVP status on this iface*/
	
	double	       		max_reservable_bandwidth_percent;
											/* Maximum Reservable bandwidth %age on iface	*/

	double	       		max_reservable_bandwidth_per_flow_percent;
											/* Maximum Reservable bandwidth %age for each 	*/
											/* individual flow on the interface				*/

	} IpT_Iface_Rsvp_Info;

/* Mobile IPv6 information stored per interface.	*/
typedef struct Mipv6T_Interface_Info
	{
	Mipv6T_Node_Type	mipv6_iface_type;
	OpT_uInt16 			ha_preference;
	OpT_uInt16			ha_lifetime;
	OpT_uInt16			max_num_mn;
	} Mipv6T_Interface_Info;

/* Structure to store the IPv6 related information of an interface.							*/
typedef struct Ipv6T_Interface_Info
	{
	unsigned int					intf_id;			/* Globally unique interface ID.			*/
	int								num_addresses;		/* Number of IPv6 addresses (incl. the link	*/
														/* local address).							*/

	InetT_Address_Range				*ipv6_addr_array;	/* Array of IP address ranges.				*/
														/* The first element of the array will be	*/
														/* will be the link local address. 			*/

	union												/* Router advertisement related information	*/
		{												/* On host nodes, ra_host_info_ptr will be	*/
		struct Ipv6T_Ra_Host_Info*	ra_host_info_ptr;	/* set. On Router advertisement enabled		*/
		struct Ipv6T_Ra_Gtwy_Info*	ra_gtwy_info_ptr;	/* router interfaces, ra_gtwy_info_ptr will	*/
		} ra_info;										/* be set.									*/

	struct Ipv6T_Nd_Info*			nd_info_ptr;		/* Neighbor Discovery related information.	*/

	Mipv6T_Interface_Info	*mipv6_info_ptr;	/* MIPv6 related information.				*/
	} Ipv6T_Interface_Info;


/* Structure to store information specific to GRE tunnels.									*/
typedef struct IpT_Tunnel_GRE_Params
	{
	Boolean						sequence_dgrams; 	/* Should we drop out-of-sequence packets	*/
	
	int							max_seq_number;	 	/* Current max sequence number seen on an	*/
													/* an incoming datagram						*/
	} IpT_Tunnel_GRE_Params;

typedef struct IpT_Tunnel_GRE_Hdr_Fields
	{
	int							ver;				/* Version number of GRE.				*/
	
	int							protocol_type;		/* What is the encapsulated protocol?	*/
	
	Boolean						checksum_present;	/* Are the checksum and reserved1		*/
													/* fields present in the packet?		*/
	
	} IpT_Tunnel_GRE_Hdr_Fields;
	
/* Structure to hold tunnel address to physical address mapping. */
typedef struct IpT_Tunnel_Address_Map
	{
	InetT_Address				tunnel_addr;		/* Logical end point of the tunnel. */
	InetT_Address				tunnel_phy_addr;	/* Physical address mapped to the above address. */
	} IpT_Tunnel_Address_Map;

/* Structure to store information specific to Tunnel interfaces.							*/
typedef struct IpT_Tunnel_Info
	{
	IpT_Tunnel_Mode				mode;				/* Type of tunnel.						*/

	struct IpT_Interface_Info*	source_intf_ptr;	/* Source Interface of the tunnel		*/
	
	InetT_Address				src_addr;			/* The source address as specified in	*/
													/* the tunnel information.				*/		
	
	int							dest_count;			/* Number of destinations in the array  */
	IpT_Tunnel_Address_Map*		dest_addr_array;	/* Destinations of the tunnel	(pt2mpt)*/

	InetT_Address				dest_addr;			/* Destination of the tunnel (pt2pt)	*/

	OmsT_Dist_Handle			encapsulation_delay;

	OmsT_Dist_Handle			decapsulation_delay;
	
	int							ttl;				/* TTL value to be used for outer packet	*/
	
	int							tos;				/* TOS value to be used for outer packet	*/		
	
	short						passenger_proto_flags;	/* A bit-field being used to record		*/
														/* which passenger protocols are 		*/
														/* enabled on the tunnel.				*/		

	OpT_Packet_Size				hdr_size_bits;		/* Some tunnels (GRE) may have a header.	*/
	
	OmsT_Dim_Stat_Handle		traffic_rcvd_bps_lsh;
	OmsT_Dim_Stat_Handle		traffic_rcvd_pps_lsh;
	OmsT_Dim_Stat_Handle		traffic_sent_bps_lsh;
	OmsT_Dim_Stat_Handle		traffic_sent_pps_lsh;
	OmsT_Dim_Stat_Handle		traffic_dropped_bps_lsh;
	OmsT_Dim_Stat_Handle		traffic_dropped_pps_lsh;
	OmsT_Dim_Stat_Handle		delay_sec_lsh;
	OmsT_Dim_Stat_Handle		delay_jitter_sec_lsh;
	
	OmsT_Stat_Data*				delay_stat_ptr; /* OMS data structure used to compute deviation.	*/	

	OmsT_Bgutil_Routed_State* 	bgutil_sent_state_ptr; /* Bgutil structures used to record	*/
	OmsT_Bgutil_Routed_State*	bgutil_rcvd_state_ptr; /* traffic sent and received stats	*/  
	double						last_sent_update_time; /* for background traffic.			*/
	double						last_rcvd_update_time; /*									*/
	
	IpT_Tunnel_GRE_Params*		gre_params_ptr;		/* GRE specific parameters of tunnel		*/
	} IpT_Tunnel_Info;

/* Data structure to store the interface from which an unnumbered interface must get its	*/
/* address. During parsing, the interface will be stored by name. Once all interfaces have	*/
/* been read in the interface name is resolved to an interface address.						*/
typedef union IpT_Unnumbered_Info
	{
	char*			interface_name;
	IpT_Address		interface_addr;
	} IpT_Unnumbered_Info;

/* Advance declaration for structure containing Aggregation related information.			*/
struct IpT_Group_Intf_Info;

/* Data Structure containing elements whose value will be the same for the physical			*/
/* interface and any subinterfaces it might have. e.g. connected link_objid. 				*/
typedef struct
	{
	IpT_Interface_Type	intf_type;		/* See enum explaination above.			*/
	
	short				ip_addr_index;	/* Index in IP interface information	*/
										/* specification (i_th row in the		*/
										/* compound attribute specification.)	*/

	short				port_num;		/* Output stream index reprsenting this iface.	*/

	short				in_port_num;	/* Input stream index reprsenting this iface.	*/

	short				slot_index;		/* Slot number to which a particular	*/
										/* interface belongs.					*/

	Objid				connected_link_objid;	/* Object identifier of the link	*/
												/* connected to this interface.		*/

	double				link_bandwidth;		/* Interface data rate (in bits/sec).	*/

	IpT_Interface_Status	intf_status;	/* Specifies whether this interface is Active, 		*/
											/* Shutdown, Loopback Address, or an unconnected 	*/
											/* interface. Enumerated values above.		 	 	*/

	short				link_status;		/* Whether or not the connectied link is active.	*/

	short				num_subinterfaces;	/* Number of subinterfaces on this physical interface	*/

	struct IpT_Interface_Info** subintf_pptr;/* Array of pointers to the subinterfaces on this	*/
											/* physical interface. If no subinterfaces are 		*/
											/* defined, this element wil be set to OPC_NIL		*/

	int					lower_layer_addr;	/* Lower layer address of this physical interface	*/
											/* This address will be same for all the ifaces		*/
   											/* including subifaces ubder this phyiscal iface	*/	
	
	OpT_Int8			lower_layer_type;	/* An enum that indicates the lower layer type.	*/

	struct IpT_Group_Intf_Info* group_info_ptr; /* Aggregation related information.				*/

	} IpT_Phys_Interface_Info;

/* Data structure describing an IP interface or subinterface*/
typedef struct IpT_Interface_Info
	{
	IpT_Address_Range*	addr_range_ptr;	/* Range of addresses covered by this	*/
										/* single IP interface.					*/

	InetT_Address_Range	inet_addr_range;/* The address and subnet mask in the	*/
										/* InetT format.						*/

	IpT_Address			network_address;/* IP Network to which this iface belongs*/

	Ipv6T_Interface_Info*	ipv6_info_ptr;	/* IPv6 information. For IPv4 only	*/
											/* interfaces, it will be NIL		*/

	IpT_Tunnel_Info*	tunnel_info_ptr;/* Used to store tunnel information for	*/
										/* tunnel interfaces.					*/

	IpT_Sec_Addr_Table	*sec_addr_tbl_ptr;
										/* Range of secondary addresses			*/
	
	IpT_Unnumbered_Info	*unnumbered_info;	/* The source interface of an		*/
											/* unnumbered interface.			*/

	char*				full_name;		/* Full Name given to IP interface by 	*/
										/* the user. For subinterfaces, this	*/
										/* would be of the form: 				*/
										/* <Physical Iface Name>.<Subiface Name>*/

	int					mtu;			/* Maximum amount of data that can be	*/
										/* transmitted in one IP datagram.		*/

	List*				routing_protocols_lptr;	/* Routing protocol(s), if any 	*/
									    /* run on this interface.				*/

	double				load_bits;		/* Outgoing load in bits/sec (ie, total	*/
										/* bits/total time) for this interface.	*/

	double				load_bps;		/* Outgoing load in bits/sec (ie, total	*/
										/* bits/total time) for this interface.	*/

	double				avail_bw;		/* BW available for reservation by RSVP	*/
										/* or CR-LDP							*/

	double				delay;			/* Value of delay that'll be incurred	*/
										/* on traveling through this interface	*/
	   									/* Usually this is just set as a static */
										/* value. But it can also be actively	*/
										/* computed								*/

	double				reliability;	/* Fraction of packets that arrive		*/
										/* undamaged.							*/

	IpT_Compression_Info* comp_info;    /* Information about the data           */
										/* compression scheme used at this      */
										/* interface. DS is defined in          */
										/* oms_data_def_ds_defs.h               */

	OpT_uInt8			flags;			/* multicast_enabled, rsvp_enabled,		*/
										/* manet_enabled, igmp_enabled,			*/
										/* mip_enabled, msfc_alt_intf			*/

	Prohandle			igmp_rte_iface_ph;	/* Process handle of the IGMP Router*/
   										/* Interface child process, which		*/
   										/* handles IGMP message	received on		*/
									    /* this IP interface. This field is		*/
										/* set only if multicasting is enabled	*/
									    /* on this interface					*/

	/* The oms_bgutil package uses this state variable to keep track of the	*/
	/* background utilization traffic flowing through this interface.		*/
	struct OmsT_Bgutil_Routed_State*	load_bgutil_routed_state_ptr;

	/* We use this variable to keep track of how much we need to fill in	*/
	/* the load_bits variable with background utilization traffic.			*/
	double				last_load_update_time;

	IpT_Queuing_Scheme	queuing_scheme;		/* Specify the queuing scheme for the interface: 	*/
											/* None, FIFO, WFQ. PQ, CQ							*/

	Prohandle			output_iface_prohandle;	/* Prohandle for the child process ip_output_iface	*/
												/* in charge of queuing scheme, RED, CAR.			*/


	IpT_Iface_Rsvp_Info* rsvp_info_ptr;		/* Stores all the RSVP info like status,		*/
										    /* max reservable BW and max per flow			*/
										    /* reservable BW								*/

	short				intf_index;			/* Index of this interface in the interface		*/
											/* array maintained by IP.						*/
	short				subintf_addr_index; /* Row number of this subinterface in the		*/
											/* Subinterface Information compound attribute	*/
											/* For a physical interface, this element will	*/
											/* be set to IPC_SUBINTF_PHYS_INTF (-1). Thus	*/
											/* the value of this element can be used to 	*/
											/* determine whether this structure represents	*/
   											/* a physical interface or a subinterface 		*/

	IpT_Layer2_Mappings layer2_mappings;	/* A structure containing information such as	*/
											/* PVCs, VLANs, ELANs etc. Refer definition of	*/
											/* struct for more details.						*/

	IpT_Intf_User_Metrics*	user_metrics;	/* User supplied metrics for the interface 		*/

	/* We use this for mapping flow in index to flow out index for bgutil flows */
	List*				flow_id_map_list_ptr; 
	
	IpT_Phys_Interface_Info* phys_intf_info_ptr;/* Pointer to a structure that contains 	*/
											/* attributes whose values are the same for the	*/
											/* physical interface and all the subinterfaces	*/

	IpT_Iface_Mpls_Info*	mpls_info_ptr; 	/* Pointer to hold MPLS info for this iface		*/

	struct IpT_Acl_Filter_Info*	filter_info_ptr;
											/* Stores the info about Packet Filters			*/
											/* configured on the interface, both in			*/
   											/* In and Out direction.						*/ 

	char*				policy_routing_name; /* Name of the Policy routing, usually 	*/
											/* a Route Map name, that will be used for 		*/
											/* all the incoming traffic on this interface	*/
	
	Prohandle			mip_phndl;		/* The handle to the mobile IP process on this  */
											/* interface if the above flag is true			*/
	
	List*				notif_proc_lptr;	/* List of processes (IpT_Te_Notif_Info) objects	*/
											/* that have registered for SIG_CHANGE notification	*/
											/* events for this interface (used for TE)			*/	
	} IpT_Interface_Info;

/* Data structure to store all the interfaces of a router,	*/
/* physical interfaces as well as subinterfaces.			*/
typedef struct IpT_Interface_Table
	{
	IpT_Interface_Info**	intf_info_ptr_array;	/* Array of pointers to IpT_Interface_Info	*/
													/* structures.								*/
	/* The entries in the array will be ordered as follows. The IPv4 only interfaces come first	*/
	/* Then come the IPv4/IPv6 interfaces. IPv6 only interfaces will be at the end.				*/

	unsigned short			total_interfaces;		/* Total number of elements in the above 	*/
													/* array (including IPv4 only, IPv4/IPv6 and*/
													/* IPv6 only interfaces).					*/

	unsigned short			num_ipv4_interfaces;	/* Number of IPv4 only and IPv4/IPv6 interfaces	*/

	unsigned short			num_ipv6_interfaces;	/* Number of IPv4/IPv6 and IPv6 only interfaces	*/

	IpT_Interface_Info**	first_ipv6_intf_ptr;	/* The intf_info_ptr_array offset by the number	*/
													/* of IPv4 only interfaces.						*/
	} IpT_Interface_Table;
	

typedef struct
	{
	List*	ip_iface_table_ptr;
	} IpT_Info;

#define	IPC_FAST_ADDR_INVALID	-1	/* Representation of an invalid fast address. */

/* Globals					*/
extern Boolean					ip_nato_tables_created;
extern NatoT_Table_Handle		ip_networks_table_handle;
extern NatoT_Table_Handle		ip_table_handle;

/* Procedure Declarations */
void				ip_rtab_local_addr_register (InetT_Address* ip_addr_ptr,
						struct IpT_Rte_Module_Data* iprmd_ptr);
Objid 				ip_rtab_index_to_node_objid_convert (int addr_index);
int					ip_rtab_num_addrs_registered (void);
int					ip_rtab_num_networks_registered (void);
int					ip_dyn_rte_protocol_obtain (char* rte_protocol_label_ptr);
Boolean 			ip_basetraf_protocol_parse(void** protocol_info_ptr, 
	char* sname, char* dname, char* stat_annotate_str, Objid bgutil_specs_objid, 
	Objid demand_objid, Objid dest_objid, Boolean is_src_to_dest_traffic, Boolean is_lsp_traffic);
void				ip_basetraf_conv_info_free (IpT_Conversation_Info* ip_conv_info_ptr);
DLLEXPORT Compcode	ip_support_ip_pkt_socket_info_extract (Packet* pkptr, IpT_Pkt_Socket_Info* pkt_ip_info_ptr); 
DLLEXPORT void		ip_support_ip_pkt_socket_info_apply (Packet* pkptr, IpT_Pkt_Socket_Info* pkt_ip_info_ptr, Boolean apply_outer_and_inner, Boolean apply_source, Boolean apply_dest);
DLLEXPORT void		ip_support_application_type_set (Packet* pkptr, IpT_Dgram_Fields* pk_fd_ptr, int src_port, int dest_port, Boolean apply_source, Boolean apply_dest);

int							inet_rtab_unique_addr_convert (InetT_Address addr, IpT_Addr_Status* addr_status_ptr);
#define	ip_rtab_unique_addr_convert(_ipv4_addr,_addr_status_ptr)	(inet_rtab_unique_addr_convert (inet_address_from_ipv4_address_create (_ipv4_addr),_addr_status_ptr))
#define inet_rtab_addr_convert(_inet_addr)							(inet_rtab_unique_addr_convert (_inet_addr,OPC_NIL))
#define	ip_rtab_addr_convert(_ipv4_addr)							(inet_rtab_unique_addr_convert (inet_address_from_ipv4_address_create (_ipv4_addr),OPC_NIL))

InetT_Address 				inet_rtab_index_to_addr_convert (int addr_index);
#define	ip_rtab_index_to_addr_convert(_index)	(inet_ipv4_address_get (inet_rtab_index_to_addr_convert (_index)))
Boolean						inet_rtab_addr_exists (InetT_Address addr);
#define	ip_rtab_addr_exists(_ipv4_addr)			(inet_rtab_addr_exists (inet_address_from_ipv4_address_create (_ipv4_addr)))
int							inet_rtab_network_convert (InetT_Address addr);
#define ip_rtab_network_convert(_ipv4_addr)		(inet_rtab_network_convert (inet_address_from_ipv4_address_create (_ipv4_addr)))
void						ip_rtab_intf_lower_layer_address_register (IpT_Interface_Info* intf_ptr,
								int lower_layer_address, int lower_layer_addr_type);
#if defined (__cplusplus)
} /* end of 'extern "C" {' */
#endif

#endif /* for _IP_RTE_H_INCL_ */
