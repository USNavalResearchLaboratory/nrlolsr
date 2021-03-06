MIL_3_Tfile_Hdr_ 120A 107A opnet 9 406C407D 44FE329A 60 apocalypse Jim@Hauser 0 0 none none 0 0 none 6CCDBBCA 22F4 0 0 0 0 0 0 fec 0                                                                                                                                                                                                                                                                                                                                                                                            ��g�      @   D   �  [  �  �   �   �   �   �   �   �   �  �          olm   �������   ����       ����      ����      ����              	   begsim intrpt             ����      doc file            	nd_module      endsim intrpt             ����      failure intrpts            disabled      intrpt interval         ԲI�%��}����      priority              ����      recovery intrpts            disabled      subqueue                     count    ���   
   ����   
      list   	���   
          
      super priority             ����             priority      priority����    ����           ����      �������        �����                        int	\NODE_ID;       Objid	\own_module_objid;       Objid	\own_node_objid;       double	\start_time;          int		i, list_index;          #include	<string.h>   #include	<stdio.h>   #include 	<stdlib.h>       Q// #define OP_DEBUG2 1 /* LP 4-12-04 - added to test.  Should be removed later */           #/* Global variables declaration. */       %int			Movement_Read_Flag = OPC_FALSE;   int 		MAX_NUM_NODE = 40;   List *		Movement_data[40];           /* State Transition */   <#define MOVE_EVENT				(op_intrpt_type () == OPC_INTRPT_SELF)       struct Movement_coord {   	   		double lat;   		double longitude;   		double altitude;   		double move_time;   	};   	   /* Functions */   	void read_movement_file(void);   #	void schedule_moving_events(void);   	void move_my_node(int);   �   void read_movement_file(void)   	   {   	List* 	fieldlist;   	List* 	movement_data_ptr;   -	// LP 7-19-04 - replaced to test for Solaris   ,	// char 	*movement_data_file = "10nodes_a";   -	char 	movement_data_file[256] = "10nodes_a";   
	// end lp   	Movement_coord * coord_;   	int line_nbr, node_id;   	double time_in_seconds;   	   	FIN(read_movement_file());       	start_time = 0.0;   M	op_ima_sim_attr_get_str("OLSR_move_file", 256, (char *) movement_data_file);   K	movement_data_ptr = op_prg_gdf_read ( (const char *) movement_data_file );   	   T	for ( line_nbr = 0; line_nbr < op_prg_list_size ( movement_data_ptr ); line_nbr++ )   		{   I		coord_ = (Movement_coord *) op_prg_mem_alloc (sizeof (Movement_coord));   k		fieldlist = op_prg_str_decomp ( (const char *) op_prg_list_access ( movement_data_ptr, line_nbr ), " " );       R		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 0 ) ,"Src" ) == 0 )   I		 	node_id = atoi ( (const char *)op_prg_list_access ( fieldlist, 1 ) );   		if (node_id == 100)   			node_id = 10;   S		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 4 ), "Long" ) == 0 )   			{   R			coord_->longitude = atof ((const char *)op_prg_list_access ( fieldlist, 5));			   			}   R		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 6 ), "Lat" ) == 0 )   			{   I			coord_->lat = atof ((const char *)op_prg_list_access ( fieldlist, 7));   			}   X		if ( strcmp ( (const char *) op_prg_list_access ( fieldlist, 8 ), "TxTime" ) == 0 )			   			{   			List * time_field_list;   `			time_field_list = op_prg_str_decomp ( (const char *) op_prg_list_access (fieldlist, 9), ":");   V			int t_hr = atoi (	(const char *)op_prg_list_access ( time_field_list, 0));								    W			int t_min = atoi (	(const char *)op_prg_list_access ( time_field_list, 1));								    O			int t_sec = atoi (	(const char *)op_prg_list_access ( time_field_list, 2));	   E			time_in_seconds = (double) ((t_hr * 3600) + (t_min * 60) + t_sec);   Z			if (line_nbr == 0) // first line of the file - consider this is the start of simulation   				{   !				start_time = time_in_seconds;   				}   4			coord_->move_time = time_in_seconds - start_time;   #ifdef OP_DEBUG2   O			printf(" Node %d - time = %d:%d:%d - time_in_sec = %lf, move_time = %lf\n",    E				node_id, t_hr, t_min, t_sec, time_in_seconds, coord_->move_time);   #endif   			} /* end if TxTime */   		   H		op_prg_list_insert (Movement_data[node_id], coord_, OPC_LISTPOS_TAIL);   "		op_prg_list_free ( fieldlist );     		op_prg_mem_free ( fieldlist );   		}   )	op_prg_list_free ( movement_data_ptr );    '	op_prg_mem_free ( movement_data_ptr );       #ifdef OP_DEBUG2       	for (i = 1; i <= 10; i++)   		{   2		list_size = op_prg_list_size (Movement_data[i]);   		printf("Node %d\n", i);   "		for (j = 0; j < list_size; j ++)   			{   H			coord_ = (Movement_coord *) op_prg_list_access (Movement_data[i], j);   n			printf("\t\tlong = %lf, lat = %lf , move_time = %lf\n", coord_->longitude, coord_->lat, coord_->move_time);   			}   		printf("\n\n");   		}   #endif   	FOUT;   }       !void schedule_moving_events(void)   	{   	int i, list_size;   '	Movement_coord * coord_, * coord_prev;   	   	FIN(schedule_moving_events());       6	list_size = op_prg_list_size(Movement_data[NODE_ID]);    	for (i = 0; i < list_size; i++)   		{   M		coord_ = (Movement_coord *) op_prg_list_access (Movement_data[NODE_ID], i);   		if (i > 0)   			{   V			coord_prev = (Movement_coord *) op_prg_list_access (Movement_data[NODE_ID], (i-1));   X			if ((coord_prev->longitude == coord_->longitude) && (coord_prev->lat == coord_->lat))   				{   #ifdef OP_DEBUG2   e				printf("Node_%d - i = %d, time = %lf.  Same coord as that of time %lf - lat = %lf, long = %lf\n",   [					NODE_ID, i, coord_->move_time, coord_prev->move_time, coord_->lat, coord_->longitude);   #endif   				continue;   				}   			} /* end if i > 0 */   		   #ifdef OP_DEBUG2   `		printf("Node %d - schedule event for time = %lf, code = %d\n", NODE_ID, coord_->move_time, i);   #endif   3		op_intrpt_schedule_self (coord_->move_time, i); 	       		} /* end for i */   	FOUT;   	}       !void move_my_node(int list_index)   	{   	Movement_coord * coord_;   	   	FIN(move_my_node(list_index));       U	coord_ = (Movement_coord *) op_prg_list_access (Movement_data[NODE_ID], list_index);   	   #ifdef OP_DEBUG2   [	printf("Node %d - set coordinate to lat = %lf, long = %lf, alt = 0, current_time = %lf\n",   :		NODE_ID, coord_->lat, coord_->longitude, op_sim_time());   #endif   K	op_ima_obj_attr_set_dbl (own_node_objid, "x position", coord_->longitude);   E	op_ima_obj_attr_set_dbl (own_node_objid, "y position", coord_->lat);   	FOUT;   	}                                      �  J          
   init   
       J       own_module_objid = op_id_self();       +    // Obtain the surrounding node's objid.   2own_node_objid = op_topo_parent(own_module_objid);       -if (op_ima_sim_attr_exists("OLSR_move_file"))   	{   	// Obtain user_id   ;	op_ima_obj_attr_get (own_node_objid, "user id", &NODE_ID);           5	/* Open the "OLM" file once. Decompose each line */    2	/* in fields and load parameters of interest. */        '	if ( Movement_Read_Flag == OPC_FALSE )   		{    		Movement_Read_Flag = OPC_TRUE;   $		for (i = 0; i < MAX_NUM_NODE; i++)   			{   +			Movement_data[i] = op_prg_list_create();   			}   		read_movement_file();   		}       	schedule_moving_events();   	}   else   C	printf("No OLSR_move_file exists.  Node mover will not be used.");   J       
       
       
   ����   
          pr_state      
  J  J          
   idle   
       
       
       
       
       
    ����   
          pr_state        J   �          
   move   
       
      list_index = op_intrpt_code();   #ifdef OP_DEBUG2   Hprintf("Node %d - Move_event - index code = %d\n", NODE_ID, list_index);   #endif   move_my_node(list_index);       
                     
   ����   
          pr_state                  
   �  H      �  H  .  H          
   tr_0   
       
����   
       
����   
       
    ����   
       
   ����   
       
   
          pr_transition         
   
  H  �     8  _    �  D  �  ~  �  \  _          
       
       
   default   
       
����   
       
    ����   
       
   ����   
       
   
          pr_transition         
        �     @  7  ?   �          
   tr_17   
       
   
MOVE_EVENT   
       ����          
    ����   
          ����                       pr_transition            
  R   �     P   �  S  4          
   tr_18   
       ����          ����          
    ����   
          ����                       pr_transition                   outstat   d    ����   normal   linear        ԲI�%��}                            