/****************************************/
/*      Copyright (c) 1987-2006		*/
/*		by OPNET Technologies, Inc.		*/
/*       (A Delaware Corporation)      	*/
/*    7255 Woodmont Av., Suite 250     	*/
/*     Bethesda, MD 20814, U.S.A.       */
/*       All Rights Reserved.          	*/
/****************************************/

#ifndef _IP_HIGHER_LAYER_PROTO_REG_SUP_H_INCL_
#define _IP_HIGHER_LAYER_PROTO_REG_SUP_H_INCL_

/** Include directives.					**/
#include <opnet.h>


#if defined (__cplusplus)
extern "C" {
#endif

/* The protocols used in an IP packet	*/
/* stored as integers.					*/
typedef enum IpT_Protocol_Type
	{
	/* Background traffic tracer packets can */
	/* be encapsulated in ip_dgram packets.	 */ 
	IpC_Protocol_Basetraf				= -2,
	IpC_Protocol_Unspec					= -1,
	IpC_Protocol_Icmp					= 1,
	IpC_Protocol_Igmp					= 2,
	IpC_Protocol_Ip 					= 4,
	IpC_Protocol_Tcp					= 6,
	IpC_Protocol_Udp					= 17,
	IpC_Protocol_IPv6					= 41,
	IpC_Protocol_Rsvp					= 46,
	IpC_Protocol_GRE					= 47,
	IpC_Procotol_Routing_Ext_Hdr 		= 43,
	IpC_Protocol_ESP					= 50, /* HAIPE-IPsec Support */
	IpC_Protocol_Icmpv6					= 58,
	IpC_Protocol_Mipv6_Proto_None 		= 59,	
	IpC_Procotol_Destination_Ext_Hdr	= 60,
	IpC_Protocol_Ospf					= 89,
	IpC_Protocol_Igrp					= 9,
	IpC_Protocol_Pim					= 103,
	IpC_Protocol_Isis					= 124,
	IpC_Protocol_Eigrp					= 88,
	IpC_Protocol_Dsr					= 200,
	IpC_Protocol_Aodv					= 201,
	IpC_Protocol_Ip_GTP					= 253,
	IpC_Protocol_Ip_L2TP				= 115,
	IpC_Procotol_Mobility_Ext_Hdr  		= 135,	
	IpC_Protocol_Tora					= 254,
	IpC_Protocol_Ip_Mip					= 300
	} IpT_Protocol_Type;

/* Data structure describing a higher layer protocol.	*/
typedef struct
	{
	char*				higher_layer_protocol_label_ptr;
	int					higher_layer_protocol_id;	
	Boolean				inet_address_supported;
	} IpT_Higher_Layer_Protocol_Id_Table_Entry;

/* Macro representing the initial value of higher layer	*/
/* custom protocol id.									*/
#define IPC_INITIAL_HIGHER_LAYER_CUST_PROTO_ID	500

/*	Function Prototypes					*/
void					ip_higher_layer_proto_tbl_entry_add (const char* higher_layer_protocol_label_ptr,
							int* higher_layer_protocol_id_ptr, Boolean inet_address_supported);
const char*				ip_higher_layer_proto_name_find (int protocol_id);
int						ip_higher_layer_proto_id_find (const char* protocol_label_ptr,
							Boolean* inet_addr_supported_ptr);

#define		Ip_Higher_Layer_Protocol_Register(_protocol_label,_protocol_id_ptr)		\
				ip_higher_layer_proto_tbl_entry_add (_protocol_label,_protocol_id_ptr, OPC_FALSE)
#define		Inet_Higher_Layer_Protocol_Register(_protocol_label,_protocol_id_ptr)		\
				ip_higher_layer_proto_tbl_entry_add (_protocol_label,_protocol_id_ptr, OPC_TRUE)

#define		ip_proto_is_icmp_v4_or_v6(proto)	(((proto) == IpC_Protocol_Icmp) || ((proto) == IpC_Protocol_Icmpv6))				
				
#if defined (__cplusplus)
} /* end of 'extern "C" {' */
#endif

#endif /* for _IP_HIGHER_LAYER_PROTO_REG_SUP_H_INCL_ */

