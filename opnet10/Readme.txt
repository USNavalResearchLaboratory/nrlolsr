DEVELOPMENT ENVIRONMENT

1/ The Opnet codes were developed under the following environment:
- Window 2000
- Opnet 10.0.A PL 2 (Model Library:  10.0 (24-Oct-2003))
- MS Visual C++ 6.0

2/ The Opnet compiling flags and binding flags shall be set as shown in the env_db10_sample file 
that is stored in the nrlolsr/opnet directory.

3/  The following Opnet provided files were modified and are stored in the nrlolsr/opnet directory.  
The user's environment shall check this directory for these files rather than the Opnet standar directory.  
	Ip_dispatch.pr.m
	Ip_rte_v4.h
	Ip_rte_support.h
	Ip_higher_layer_proto_reg_sup.h
	Ip_cmn_rte_table.h & .c
	ip_notif_log_support.ex.c

OTHER REQUIRED FILES

1/  The OLSR Opnet model requires other files on the pf.itd.nrl.navy.mil as followed:
- All files in the olsr/nrlolsr/common directory
- All files in the protolib directory


WHAT TO DO AFTER DOWNLOADING 

1/  Opnet only reconizes external files that are ended with .ex.cpp or .ex.c.  Thus, user will need to convert 
the file names of all "cpp" files in the nrlolsr/common directory to have ".ex.cpp" extension.  For example, 
change nrlolsr.cpp to nrlolsr.ex.cpp

2/  Change the following files in the Protolib directory to have ".ex.cpp" extension:
     ProtoAddress.cpp
     ProtoDebug.cpp
     ProtoRouteMgr.cpp
     ProtoRouteTable.cpp
     ProtoSimAgent.cpp
     ProtoSimSocket.cpp
     ProtoTimer.cpp
     ProtoTree.cpp

   This step and step 1 can be done automatically for Window machines by executing the "generate_ex_file.bat"
file included in this directory.

3/    Set up the compiling and binding flags as shown in the env_db10_sample.
     Make sure that your working Opnet directory is searched first for included files.
4/  Follow the NODE SET-UP instruction below to set up the nodes in your network.

NODE SET-UP:

1/  Set Node name and user_id.  The user_id will be used to as the Node_id to identify
    the nodes in the network.
2/  Select a trajectory file if required
3/  IP Router Parameters/Interface Information
     Users need to set the following parameters for the required interface
            - IP address 
            - Subnet mask
            - Set Routing protocol of the main interface to OLSR_NRL
            - MTU
            - Interface Speed
4/  Flow-id for UDP traffic.
The UDP traffic is generated in module "udp-gen".  This module can support upto 20 different flows 
which is a Opnet-limit on the number of flows that it can keep track for data analysis purpose. 
User need to set the following parameter for the UDP traffic  that this node will generate:
            - data rate
            - destination IP address and port
            - distribution type for packet generation rate (constant, Poisson, etc.)
            - flow id
            - packet size
            - when to start generating packet.


MOVEMENT FILE

For the movement of the nodes, you can specify the trajectory files for each node using
standard Opnet procedures.  The olsr_protolib model can also read a movement file via 
the "OLSR_move_file" simulation attribute.  The code was developed to read a text file 
that was generated from a ns-2 program.

1/  File format

The file should has a suffix of ".gdf" and should be in the main OLSR directory; 
i.e., where OPNET write its models to.

Each line of the file contain the latitude and longitude data for a particular node at a particular time.    
Each line consists of 10 fields, and the field separators are either ">", "/", or "|".  The line format 
is as followed.  The text in the double quote should be spelled as is.

	Field 0:  "Src"
	Field 1:  node id. (this should be the same as the user_id mentioned in the NODE SET-UP section above)
      Field 2:  "Ad-hoc Mac"
 	Field 3:  Mac address of this node
	Field 4:  "Long"
	Field 5:  longitude coordinate (in degree only)
	Field 6:  "Lat"
	Field 7:  latitude coordinate (in degree only)
	Field 8:  "TxTime"
	Field 9:  GMT time when the long / lat data should take place.

The code will ignore data in Field 2 and Field 3.   The code will take the timing information in line # 1 
as start time of simulation.  All sequence data changes will be  based on the time of the first line.  

2/  Sample files:

Src>100/Ad-hoc Mac>00:02:2D:74:55:99 |Long>-77.026699 |Lat>38.826755 |TxTime>18:14:24
Src>100/Ad-hoc Mac>00:02:2D:74:55:99 |Long>-77.026699 |Lat>38.826755 |TxTime>18:14:25
Src>1/Ad-hoc Mac>00:02:2D:3F:EF:60 |Long>-77.022599 |Lat>38.827486 |TxTime>18:14:26
Src>100/Ad-hoc Mac>00:02:2D:74:55:99 |Long>-77.026699 |Lat>38.826755 |TxTime>18:14:26
Src>1/Ad-hoc Mac>00:02:2D:3F:EF:60 |Long>-77.022599 |Lat>38.827486 |TxTime>18:14:27
Src>100/Ad-hoc Mac>00:02:2D:74:55:99 |Long>-77.026699 |Lat>38.826755 |TxTime>18:14:27
Src>2/Ad-hoc Mac>00:02:2D:3F:EF:7E |Long>-77.023940 |Lat>38.824077 |TxTime>18:14:27
Src>1/Ad-hoc Mac>00:02:2D:3F:EF:60 |Long>-77.022599 |Lat>38.827486 |TxTime>18:14:28
Src>100/Ad-hoc Mac>00:02:2D:74:55:99 |Long>-77.026699 |Lat>38.826755 |TxTime>18:14:28
Src>2/Ad-hoc Mac>00:02:2D:3F:EF:7E |Long>-77.023940 |Lat>38.824077 |TxTime>18:14:28
Src>1/Ad-hoc Mac>00:02:2D:3F:EF:60 |Long>-77.022599 |Lat>38.827486 |TxTime>18:14:29

In this sample file, the first line specifies position data for node 100 at time of 18:14:24 GMT.  
The second line specifies position data for node 100 at time of 18:14:25 GMT.  The third line 
specifies position data for node 1 at time of 18:14:26 GMT.  

The program will read those data as the first line specifies position data for node 10 at 
the beginning of the simulation.  One second later, Node 10 changes its position to the one 
specified in line 2.  Two seconds after the start of simulation, node 1 changed to the location 
specified in line 3.; etc.


NRLOLSR COMMAND LINES

The Opnet model support most command-line parameters supported by the nrlolsr real code.
However, the name of the parameters are changed a bit so that they can be distinguished with other
command line parameters within the Opnet environment.  The following are names of nrlolsr command line 
parameters in Opnet environment

            OLSR Interface name  (not supported.  This can be done by editing node's IP attribute)
            OLSR Log File Name  (followed by file name)
            OLSR Debug Level    (followed by 0 - 10)
            OLSR Set OLSR All Links mode  (toggle ON/OFF)
            OLSR h	(toggle ON/OFF)
            OLSR v   (toggle ON/OFF)
            OLSR Willingness  (followed by willingness level)
            OLSR HNA Auto  (toggle ON/OFF)
            OLSR HNA Off  (toggle ON/OFF)
            OLSR HNA File  (followed by hna_file name)
            OLSR Setting Broadcast Address :  followed by
                     OLSR Broadcast Address   (followed by broacast address)
                     OLSR Broadcast Subnet Mask (followed by subnet mask)
            OLSR hello_intvl
            OLSR hello_jitter
            OLSR hello_timeout_factor
            OLSR tc_intvl
            OLSR tc_jitter
            OLSR tc_timeout_factor
            OLSR IPv6 mode (followed by either 0 or 1)
            OLSR HNA_intvl
            OLSR HNA_jitter
            OLSR HNA_timeout_factor
            OLSR Hys Up
            OLSR Hys Down
            OLSR Hys Alpha
            OLSR Hys ON
            OLSR QOS
            OLSR_move_file  (followed by movement file name)
