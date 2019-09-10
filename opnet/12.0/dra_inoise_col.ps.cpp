/* dra_inoise.ps.cpp */                                                       
/* Default interference noise model for radio link Transceiver Pipeline */

/****************************************/
/*		  Copyright (c) 1993-2006		*/
/*		by OPNET Technologies, Inc.		*/
/*		(A Delaware Corporation)		*/
/*	7255 Woodmont Av., Suite 250  		*/
/*     Bethesda, MD 20814, U.S.A.       */
/*			All Rights Reserved.		*/
/****************************************/

/****************************************/
/*    Modified by JPH 11/29/2006        */
/*     Animate packet collisions.       */
/****************************************/


#include "opnet.h"
#include "animInfo.h"


#if defined (__cplusplus)
extern "C"
#endif
void
dra_inoise_col_mt (OP_SIM_CONTEXT_ARG_OPT_COMMA Packet * pkptr_prev, Packet * pkptr_arriv)
	{
	Objid		rx_ch_objid;
	int			arriv_match, prev_match;
	double		prev_rcvd_power, arriv_rcvd_power;
	int 		i;

	/** Evaluate a collision due to arrival of 'pkptr_arriv'	**/
	/** where 'pkptr_prev' is the packet that is currently		**/
	/** being received.											**/
	FIN_MT (dra_inoise_col (pkptr_prev, pkptr_arriv));

	/* If the previous packet ends just as the new one begins, this is not	*/
	/* a collision (just a near miss, or perhaps back-to-back packets).		*/ 
	if (op_td_get_dbl (pkptr_prev, OPC_TDA_RA_END_RX) != op_sim_time ())
		{
		/* Increment the number of collisions in previous packet. */
		op_td_increment_int (pkptr_prev, OPC_TDA_RA_NUM_COLLS, 1);

		/* Increment number of collisions in arriving packet. */
		op_td_increment_int (pkptr_arriv, OPC_TDA_RA_NUM_COLLS, 1);

		/* Determine if previous packet is valid or noise. */
		prev_match = op_td_get_int (pkptr_prev, OPC_TDA_RA_MATCH_STATUS);

		/* Determine if arriving packet is valid or noise. */
		arriv_match = op_td_get_int (pkptr_arriv, OPC_TDA_RA_MATCH_STATUS);
		
		/* If the arriving packet is valid, calculate		*/
		/* interference of previous packet on arriving one.	*/
		if (arriv_match == OPC_TDA_RA_MATCH_VALID)
			{
			prev_rcvd_power   = op_td_get_dbl (pkptr_prev, OPC_TDA_RA_RCVD_POWER);
			op_td_increment_dbl (pkptr_arriv, OPC_TDA_RA_NOISE_ACCUM, prev_rcvd_power);
			}

		/* And vice-versa. */
		if (prev_match == OPC_TDA_RA_MATCH_VALID)
			{
			arriv_rcvd_power = op_td_get_dbl (pkptr_arriv, OPC_TDA_RA_RCVD_POWER);
			op_td_increment_dbl (pkptr_prev, OPC_TDA_RA_NOISE_ACCUM, arriv_rcvd_power);
			}
		
		/* Collision animation */
		if (animFlag && !no_coll_anim)
			{
			rx_ch_objid = op_td_get_int (pkptr_arriv, OPC_TDA_RA_RX_CH_OBJID);
			for (i=0; i<MAX_NUM_NODES; i++)
				{
				if (op_topo_parent(op_topo_parent(op_topo_parent(rx_ch_objid))) == olsrNode[i]->objid)
					{
					olsrNode[i]->col_increment();
					if (olsrNode[i]->col_did > -1)
						{
						op_anim_igp_drawing_erase (olsr_vid, olsrNode[i]->col_did, OPC_ANIM_ERASE_MODE_XOR);
						}
					if (op_ev_valid (olsrNode[i]->col_timeout_ev))
						{
						op_ev_cancel (olsrNode[i]->col_timeout_ev);
						}
					char col_str[8];
					sprintf(col_str,"%d",olsrNode[i]->col_get());
					olsrNode[i]->col_did = op_anim_igp_text_draw (olsr_vid, 
						OPC_ANIM_RETAIN | OPC_ANIM_PIXOP_XOR | OPC_ANIM_COLOR_BLUE |
						OPC_ANIM_ALIGNH_CENTER | OPC_ANIM_ALIGNV_CENTER,
						olsrNode[i]->vx, olsrNode[i]->vy-30, col_str);
					olsrNode[i]->col_timeout_ev = op_intrpt_schedule_remote (op_sim_time () + COL_DISPLAY_TIME,
						COL_ANIM_TO, olsrNode[i]->olsr_objid);
					break;
					}
				}
			}
		}

	FOUT
	}                
