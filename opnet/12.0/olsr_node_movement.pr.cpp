/* Process model C++ form file: olsr_node_movement.pr.cpp */
/* Portions of this file copyright 1992-2006 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char olsr_node_movement_pr_cpp [] = "MIL_3_Tfile_Hdr_ 120A 30A op_runsim 7 464DAC9A 464DAC9A 1 wn12jh Jim@Hauser 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 10de 3                                                                                                                                                                                                                                                                                                                                                                                                      ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include	<string.h>
#include	<stdio.h>
#include 	<stdlib.h>

// #define OP_DEBUG2 1 /* LP 4-12-04 - added to test.  Should be removed later */


/* Global variables declaration. */

int			Movement_Read_Flag = OPC_FALSE;
int 		MAX_NUM_NODE = 40;
List *		Movement_data[40];


/* State Transition */
#define MOVE_EVENT				(op_intrpt_type () == OPC_INTRPT_SELF)

struct Movement_coord {
	
		double lat;
		double longitude;
		double altitude;
		double move_time;
	};
	
/* Functions */
	void read_movement_file(void);
	void schedule_moving_events(void);
	void move_my_node(int);

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
class olsr_node_movement_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		olsr_node_movement_state (void);

		/* Destructor contains Termination Block */
		~olsr_node_movement_state (void);

		/* State Variables */
		int	                    		NODE_ID                                         ;
		Objid	                  		own_module_objid                                ;
		Objid	                  		own_node_objid                                  ;
		double	                 		start_time                                      ;

		/* FSM code */
		void olsr_node_movement (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_olsr_node_movement_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype olsr_node_movement_state::obtype = (VosT_Obtype)OPC_NIL;

#define NODE_ID                 		op_sv_ptr->NODE_ID
#define own_module_objid        		op_sv_ptr->own_module_objid
#define own_node_objid          		op_sv_ptr->own_node_objid
#define start_time              		op_sv_ptr->start_time

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	olsr_node_movement_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((olsr_node_movement_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

void read_movement_file(void)
	
{
	List* 	fieldlist;
	List* 	movement_data_ptr;
	// LP 7-19-04 - replaced to test for Solaris
	// char 	*movement_data_file = "10nodes_a";
	char 	movement_data_file[256] = "10nodes_a";
	// end lp
	Movement_coord * coord_;
	int line_nbr, node_id;
	double time_in_seconds;
	
	FIN(read_movement_file());

	start_time = 0.0;
	op_ima_sim_attr_get_str("OLSR_move_file", 256, (char *) movement_data_file);
	movement_data_ptr = op_prg_gdf_read ( (const char *) movement_data_file );
	
	for ( line_nbr = 0; line_nbr < op_prg_list_size ( movement_data_ptr ); line_nbr++ )
		{
		coord_ = (Movement_coord *) op_prg_mem_alloc (sizeof (Movement_coord));
		fieldlist = op_prg_str_decomp ( (const char *) op_prg_list_access ( movement_data_ptr, line_nbr ), " " );

		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 0 ) ,"Src" ) == 0 )
		 	node_id = atoi ( (const char *)op_prg_list_access ( fieldlist, 1 ) );
		if (node_id == 100)
			node_id = 10;
		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 4 ), "Long" ) == 0 )
			{
			coord_->longitude = atof ((const char *)op_prg_list_access ( fieldlist, 5));			
			}
		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 6 ), "Lat" ) == 0 )
			{
			coord_->lat = atof ((const char *)op_prg_list_access ( fieldlist, 7));
			}
		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 8 ), "TxTime" ) == 0 )			
			{
			List * time_field_list;
			time_field_list = op_prg_str_decomp ( (const char *) op_prg_list_access (fieldlist, 9), ":");
			int t_hr = atoi (	(const char *)op_prg_list_access ( time_field_list, 0));								 
			int t_min = atoi (	(const char *)op_prg_list_access ( time_field_list, 1));								 
			int t_sec = atoi (	(const char *)op_prg_list_access ( time_field_list, 2));	
			time_in_seconds = (double) ((t_hr * 3600) + (t_min * 60) + t_sec);
			if (line_nbr == 0) // first line of the file - consider this is the start of simulation
				{
				start_time = time_in_seconds;
				}
			coord_->move_time = time_in_seconds - start_time;
#ifdef OP_DEBUG2
			printf(" Node %d - time = %d:%d:%d - time_in_sec = %lf, move_time = %lf\n", 
				node_id, t_hr, t_min, t_sec, time_in_seconds, coord_->move_time);
#endif
			} /* end if TxTime */
		
		op_prg_list_insert (Movement_data[node_id], coord_, OPC_LISTPOS_TAIL);
		op_prg_list_free ( fieldlist ); 
		op_prg_mem_free ( fieldlist );
		}
	op_prg_list_free ( movement_data_ptr ); 
	op_prg_mem_free ( movement_data_ptr );

#ifdef OP_DEBUG2

	for (i = 1; i <= 10; i++)
		{
		list_size = op_prg_list_size (Movement_data[i]);
		printf("Node %d\n", i);
		for (j = 0; j < list_size; j ++)
			{
			coord_ = (Movement_coord *) op_prg_list_access (Movement_data[i], j);
			printf("\t\tlong = %lf, lat = %lf , move_time = %lf\n", coord_->longitude, coord_->lat, coord_->move_time);
			}
		printf("\n\n");
		}
#endif
	FOUT;
}

void schedule_moving_events(void)
	{
	int i, list_size;
	Movement_coord * coord_, * coord_prev;
	
	FIN(schedule_moving_events());

	list_size = op_prg_list_size(Movement_data[NODE_ID]);
	for (i = 0; i < list_size; i++)
		{
		coord_ = (Movement_coord *) op_prg_list_access (Movement_data[NODE_ID], i);
		if (i > 0)
			{
			coord_prev = (Movement_coord *) op_prg_list_access (Movement_data[NODE_ID], (i-1));
			if ((coord_prev->longitude == coord_->longitude) && (coord_prev->lat == coord_->lat))
				{
#ifdef OP_DEBUG2
				printf("Node_%d - i = %d, time = %lf.  Same coord as that of time %lf - lat = %lf, long = %lf\n",
					NODE_ID, i, coord_->move_time, coord_prev->move_time, coord_->lat, coord_->longitude);
#endif
				continue;
				}
			} /* end if i > 0 */
		
#ifdef OP_DEBUG2
		printf("Node %d - schedule event for time = %lf, code = %d\n", NODE_ID, coord_->move_time, i);
#endif
		op_intrpt_schedule_self (coord_->move_time, i); 	

		} /* end for i */
	FOUT;
	}

void move_my_node(int list_index)
	{
	Movement_coord * coord_;
	
	FIN(move_my_node(list_index));

	coord_ = (Movement_coord *) op_prg_list_access (Movement_data[NODE_ID], list_index);
	
#ifdef OP_DEBUG2
	printf("Node %d - set coordinate to lat = %lf, long = %lf, alt = 0, current_time = %lf\n",
		NODE_ID, coord_->lat, coord_->longitude, op_sim_time());
#endif
	op_ima_obj_attr_set_dbl (own_node_objid, "x position", coord_->longitude);
	op_ima_obj_attr_set_dbl (own_node_objid, "y position", coord_->lat);
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
#undef NODE_ID
#undef own_module_objid
#undef own_node_objid
#undef start_time

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_olsr_node_movement_init (int * init_block_ptr);
	VosT_Address _op_olsr_node_movement_alloc (VosT_Obtype, int);
	void olsr_node_movement (OP_SIM_CONTEXT_ARG_OPT)
		{
		((olsr_node_movement_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->olsr_node_movement (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_olsr_node_movement_svar (void *, const char *, void **);

	void _op_olsr_node_movement_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((olsr_node_movement_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_olsr_node_movement_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_olsr_node_movement_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (olsr_node_movement_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


	VosT_Obtype Vos_Define_Object_Prstate (const char * _op_name, size_t _op_size);
	VosT_Address Vos_Alloc_Object (VosT_Obtype _op_ob_hndl);
	VosT_Fun_Status Vos_Poolmem_Dealloc (VosT_Address _op_ob_ptr);
} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
olsr_node_movement_state::olsr_node_movement (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (olsr_node_movement_state::olsr_node_movement ());
	try
		{
		/* Temporary Variables */
		int		i, list_index;
		
		/* End of Temporary Variables */


		FSM_ENTER ("olsr_node_movement")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_FORCED_NOLABEL (0, "init", "olsr_node_movement [init enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_node_movement [init enter execs]", state0_enter_exec)
				{
				own_module_objid = op_id_self();
				
				    // Obtain the surrounding node's objid.
				own_node_objid = op_topo_parent(own_module_objid);
				
				if (op_ima_sim_attr_exists("OLSR_move_file"))
					{
					// Obtain user_id
					op_ima_obj_attr_get (own_node_objid, "user id", &NODE_ID);
				
				
					/* Open the "OLM" file once. Decompose each line */ 
					/* in fields and load parameters of interest. */ 
				
					if ( Movement_Read_Flag == OPC_FALSE )
						{
						Movement_Read_Flag = OPC_TRUE;
						for (i = 0; i < MAX_NUM_NODE; i++)
							{
							Movement_data[i] = op_prg_list_create();
							}
						read_movement_file();
						}
				
					schedule_moving_events();
					}
				else
					printf("No OLSR_move_file exists.  Node mover will not be used.");
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** state (init) exit executives **/
			FSM_STATE_EXIT_FORCED (0, "init", "olsr_node_movement [init exit execs]")


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "init", "idle", "olsr_node_movement [init -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "idle", state1_enter_exec, "olsr_node_movement [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"olsr_node_movement")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "idle", "olsr_node_movement [idle exit execs]")


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("olsr_node_movement [idle trans conditions]", state1_trans_conds)
			FSM_INIT_COND (MOVE_EVENT)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 2, state2_enter_exec, ;, "MOVE_EVENT", "", "idle", "move", "olsr_node_movement [idle -> move : MOVE_EVENT / ]")
				FSM_CASE_TRANSIT (1, 1, state1_enter_exec, ;, "default", "", "idle", "idle", "olsr_node_movement [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (move) enter executives **/
			FSM_STATE_ENTER_FORCED (2, "move", state2_enter_exec, "olsr_node_movement [move enter execs]")
				FSM_PROFILE_SECTION_IN ("olsr_node_movement [move enter execs]", state2_enter_exec)
				{
				list_index = op_intrpt_code();
#ifdef OP_DEBUG2
				printf("Node %d - Move_event - index code = %d\n", NODE_ID, list_index);
#endif
				move_my_node(list_index);
				
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** state (move) exit executives **/
			FSM_STATE_EXIT_FORCED (2, "move", "olsr_node_movement [move exit execs]")


			/** state (move) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "move", "idle", "olsr_node_movement [move -> idle : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"olsr_node_movement")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (olsr_node_movement)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
olsr_node_movement_state::_op_olsr_node_movement_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
olsr_node_movement_state::operator delete (void* ptr)
	{
	FIN (olsr_node_movement_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

olsr_node_movement_state::~olsr_node_movement_state (void)
	{

	FIN (olsr_node_movement_state::~olsr_node_movement_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
olsr_node_movement_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (olsr_node_movement_state::operator new ());

	new_ptr = Vos_Alloc_Object (olsr_node_movement_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

olsr_node_movement_state::olsr_node_movement_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "olsr_node_movement [init enter execs]";
#endif
	}

VosT_Obtype
_op_olsr_node_movement_init (int * init_block_ptr)
	{
	FIN_MT (_op_olsr_node_movement_init (init_block_ptr))

	olsr_node_movement_state::obtype = Vos_Define_Object_Prstate ("proc state vars (olsr_node_movement)",
		sizeof (olsr_node_movement_state));
	*init_block_ptr = 0;

	FRET (olsr_node_movement_state::obtype)
	}

VosT_Address
_op_olsr_node_movement_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	olsr_node_movement_state * ptr;
	FIN_MT (_op_olsr_node_movement_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new olsr_node_movement_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new olsr_node_movement_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_olsr_node_movement_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	olsr_node_movement_state		*prs_ptr;

	FIN_MT (_op_olsr_node_movement_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (olsr_node_movement_state *)gen_ptr;

	if (strcmp ("NODE_ID" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->NODE_ID);
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
	if (strcmp ("start_time" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->start_time);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

