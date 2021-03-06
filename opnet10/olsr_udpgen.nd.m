MIL_3_Tfile_Hdr_ 100A 94E opnet 6 402D380E 40895953 18 condor pham 0 0 none none 0 0 none 88BFAC36 9D25 0 0 0 0 0 0 90b 2                                                                                                                                                                                                                                                                                                                                                                                                       Ф═gЅ      8   Ќ   п  *  .  й  ђ  ,р  A_  Ag  ЎТ  ЎЖ      node   IP   UDP   RIP   TCP   hidden   TCP   workstation   OSPF   WLAN   RSVP   
wlan_wkstn   
wlan_wkstn           Wireless LAN Workstation    ~   General Node Functions:       -----------------------       )The wlan_wkstn_adv node model represents    !a workstation with client-server    %applications running over TCP/IP and    %UDP/IP. The workstation supports one    (underlying Wlan connection at 1 Mbps, 2    Mbps, 5.5 Mbps, and 11 Mbps.                )This workstation requires a fixed amount    !of time to route each packet, as    'determined by the "IP Forwarding Rate"    *attribute of the node. Packets are routed    *on a first-come-first-serve basis and may    (encounter queuing at the lower protocol    &layers, depending on the transmission    "rates of the corresponding output    interfaces.               
Protocols:       
----------       $RIP, UDP, IP, TCP, IEEE 802.11, OSPF               Interconnections:       -----------------       Either of the following:       1) 1 WLAN connection at 1 Mbps,       2) 1 WLAN connection at 2 Mbps,       !3) 1 WLAN connection at 5.5 Mbps,        4) 1 WLAN connection at 11 Mbps                Attributes:       -----------       "Client Custom Application, Client    $Database Application, Client Email,    *Client Ftp, Client Remote Login, Client X    $Windows, Client Video Conferencing,    %Client Start Time:  These attributes    allow for the specification of    &application traffic generation in the    node.               *Transport Address:  This attribute allows    (for the specification of the address of    	the node.               )"IP Forwarding Rate": specifies the rate    *(in packets/second) at which the node can    "perform a routing decision for an    'arriving packet and transfer it to the    appropriate output interface.               )"IP Gateway Function": specifies whether    *the local IP node is acting as a gateway.    )Workstations should not act as gateways,    (as they only have one network interface.               *"RIP Process Mode": specifies whether the    (RIP process is silent or active. Silent    &RIP processes do not send any routing    (updates but simply receive updates. All    )RIP processes in a workstation should be    silent RIP processes.               ("TCP Connection Information": specifies    )whether diagnostic information about TCP    #connections from this node will be    'displayed at the end of the simulation.               '"TCP Maximum Segment Size": determines    'the size of segments sent by TCP. This    'value should be set to largest segment    %size that the underlying network can    carry unfragmented.               )"TCP Receive Buffer Capacity": specifies    $the size of the buffer used to hold    (received data before it is forwarded to    the application.               <<Summary>>       General Function: workstation       *Supported Protocols: UDP, IP, IEEE802.11,    RIP, TCP, OSPF       Port Interface Description:       '  1 WLAN connection at 1,2,5.5,11 Mbps              ARP Parameters      arp.ARP Parameters                                                        count                                                                           list   	          	                                                               CPU Background Utilization      CPU.background utilization                                                        count                                                                           list   	          	                                                               CPU Resource Parameters      CPU.Resource Parameters                                                        count                                                                           list   	          	                                                                CPU: Modeling Method      CPU.Compatibility Mode                                                                                     IGMP Host Parameters      $ip.ip_igmp_host.IGMP Host Attributes                                                        count                                                                           list   	          	                                                               IGMP Router Parameters      *ip.ip_igmp_rte_intf.IGMP Router Attributes                                                        count                                                                           list   	          	                                                               IP Gateway Function      
ip.gateway                                                                                    IP Host Parameters      ip.ip host parameters                                                        count                                                                           list   	          	                                                               IP Processing Information      ip.ip processing information                                                        count                                                                           list   	          	                                                               IP Slot Information      ip.ip slot information                                                        count                                                                           list   	          	                                                               TCP Parameters      tcp.TCP Parameters                                                        count                                                                           list   	          	                                                               ARP Parameters         
      Default   
   CPU Background Utilization         
      None   
   CPU Resource Parameters         
      Single Processor   
   CPU: Modeling Method          
       
Simple CPU   
   IGMP Host Parameters         
      Default   
   IGMP Router Parameters         
      Default   
   IP Gateway Function         
      Enabled   
   IP Host Parameters         
            count          
          
      list   	      
            Interface Information         
            count          
          
      list   	      
            MTU          
       WLAN   
      QoS Information         
      None   
   
   
      Static Routing Table         
      None   
   
   
   IP Processing Information         
      Default   
   IP Slot Information         
      NOT USED   
   TCP Parameters         
      Default   
   
TIM source         
   ip   
   altitude         
               
   altitude modeling            relative to subnet-platform      	condition         
          
   financial cost            0.00      ip.ip router parameters                     count          
          
      list   	      
            Interface Information         
            count          
          
      list   	      
            QoS Information         
      None   
   
   
      Loopback Interfaces         
            count          
          
      list   	      
            Name         
   Loopback   
   
   
      Static Routing Table         
      None   
   
      ip.mpls_mgr.MPLS Parameters                     count          
          
      list   	      
          
      olsr.TOS                        olsr.connection class                        phase         
               
   priority          
           
              >   џ          
   udp   
       
   rip_udp_v3_mdp   
       
   	processor   
                    џ   ╚          
   ip_encap   
       
   ip_encap_v4   
       
   	processor   
                    џ  $          
   arp   
       
   	ip_arp_v4   
       
   	processor   
                    џ   џ          
   tcp   
       
   tcp_manager_v3   
       
   	processor   
                    џ  R          
   wireless_lan_mac   
       
   wlan_mac   
          	processor                   Wireless LAN Parameters         	      Default   	       ж   џ   Ш          
   ip   
       
   ip_dispatch   
          	processor                   #manet_mgr.Ad-Hoc Routing Parameters         
            count          
          
      list   	      
            DSR Parameters         
      Default   
      TORA/IMEP Parameters         
      Default   
   
   
         Ш   џ          
   CPU   
       
   
server_mgr   
          	processor                   Compatibility Mode          	       
Simple CPU   	      Resource Parameters         	      Single Processor   	      background utilization         	      None   	   	  ;   >  ђ          
   wlan_port_rx_0_0   
       
            count          
          
      list   	      .            	data rate         .A.ёђ           .      packet formats         
   wlan_control,wlan_mac   
      	bandwidth         .@Н|            .      min frequency         .@б┬            .      processing gain         	н▓IГ%ћ├}       	   .   
          bpsk          	?­             	                             
   NONE   
       
   
wlan_power   
          dra_bkgnoise             
dra_inoise             dra_snr          
   wlan_ber   
       
   
wlan_error   
       
   wlan_ecc   
          ra_rx                       nd_radio_receiver         reception end time         
           0.0   
          sec                                                               0.0                        !THIS ATTRIBUTE SHOULD NOT BE SET    TO ANY VALUE EXCEPT 0.0. This    "attribute is used by the pipeline     stages to determine whether the    receiver is busy or not. The    value of the attribute will be    updated by the pipeline stages    dynamically during the    simulation. The value will    "indicate when the receiver became    idle or when it is expected to    become idle.         D   Ш  ђ          
   wlan_port_tx_0_0   
       
            count          
          
      list   	      
            	data rate         
A.ёђ           
      packet formats         
   wlan_control,wlan_mac   
      	bandwidth         
@Н|            
      min frequency         
@б┬            
      power         
?PbMмыЕЧ       
   
   
          bpsk          
   wlan_rxgroup   
       
   
wlan_txdel   
       
   NONE   
       
   wlan_chanmatch   
       
   NONE   
       
   wlan_propdel   
          ra_tx                       nd_radio_transmitter         F   >   >          
   olsr   
       
   olsr_protolib   
          	processor                   begsim intrpt         
          
      G   l   >          
   udp_gen   
       
   	udp_gen_1   
          	processor                                     љ   ╔   9   ╔   9   а   
       
   	strm_15_2   
       
   src stream [2]   
       
   dest stream [0]   
       
          
       
               
       
   0       
                                        nd_packet_stream                       ?   д   ?   к   Ї   к   
       
   	strm_16_2   
       
   src stream [0]   
       
   dest stream [2]   
       
          
       
               
       
          
                                        nd_packet_stream                ж      д   л   ╗   л   ╗   ы   д   ы   
       
   strm_8   
       
   src stream [0]   
       
   dest stream [0]   
       
          
       
               
       
          
                                        nd_packet_stream             ж         Ї   Ы   y   Ы   y   л   Ї   л   
       
   strm_9   
       
   src stream [0]   
       
   dest stream [0]   
       
          
       
               
       
   0       
                                        nd_packet_stream             ж         д   щ   ║   щ   ║  #   д  #          
   port_0   
       
   src stream [1]   
       
   dest stream [0]   
       
          
       
               
       
          
                                        nd_packet_stream         ip addr index          
           
                                                                               	            д   А   ║   А   ║   ┴   д   ┴   
       
   	strm_4104   
       
   src stream [0]   
       
   dest stream [1]   
       
          
       
               
       
          
                                        nd_packet_stream          
            Ї   ┴   z   ┴   z   а   Ї   а   
       
   	strm_4105   
       
   src stream [1]   
       
   dest stream [0]   
       
          
       
               
       
   0       
                                        nd_packet_stream                ж      Ї  #   {  #   {   §   Ї   §          
   	in_port_0   
       
   src stream [1]   
       
   dest stream [1]   
       
          
                             
   0       
                                        nd_packet_stream         ip addr index          
           
                                                                                           Ї  G   z  G   z  +   Ї  +   
          	strm_4109          
   src stream [4]   
       
   dest stream [4]   
       
          
                             
   0       
                                        nd_packet_stream                      д  ,   И  ,   И  G   д  G   
          	strm_4110          
   src stream [4]   
       
   dest stream [4]   
       
          
                             
          
                                        nd_packet_stream               D      д  Z   ь  Z   ь  s   
       
   tx   
       
   src stream [0]   
       
   dest stream [0]   
       
          
                                                                               nd_packet_stream            ;         D  s   D  X   Ї  X   
       
   rx   
       
   src stream [0]   
       
   dest stream [0]   
       
          
                             
   0       
                                        nd_packet_stream           D         ж  І   Ю  ^          
   txstat   
          channel [0]          
   radio transmitter.busy   
       
   
instat [1]   
       
          
                             
           
       
          
       
           
       
           
       
н▓IГ%ћ├}       
       
н▓IГ%ћ├}       
       
           
                                        nd_statistic_wire           ;         J  І   Ў  ^          
   rxstat   
          channel [0]          
   radio receiver.received power   
          
instat [0]          
          
                             
           
       
           
       
           
       
           
       
               
       
=4АмW1└ў       
       
           
                                        nd_statistic_wire          (      F      8   ј   8   E   
          	strm_4111             1             0                                                 
@Ы       
                                        nd_packet_stream          )  F          >   H   >   ј   
          	strm_4112             0             1                                                                                                   nd_packet_stream          *      G      H   Ј   c   Ј   c   E   
          	strm_4113             2             0                                                 
@Ы       
                                        nd_packet_stream          +  G          i   I   i   Њ   I   Њ   
          	strm_4114             0             2                                                                                                   nd_packet_stream     H   .   Џ   +ip.Broadcast Traffic Received (packets/sec)   (Broadcast Traffic Received (packets/sec)           IP   bucket/default total/sum_time   linear   IP   'ip.Broadcast Traffic Sent (packets/sec)   $Broadcast Traffic Sent (packets/sec)           IP   bucket/default total/sum_time   linear   IP   +ip.Multicast Traffic Received (packets/sec)   (Multicast Traffic Received (packets/sec)           IP   bucket/default total/sum_time   linear   IP   'ip.Multicast Traffic Sent (packets/sec)   $Multicast Traffic Sent (packets/sec)           IP   bucket/default total/sum_time   linear   IP    ip.Traffic Dropped (packets/sec)   Traffic Dropped (packets/sec)           IP   bucket/default total/sum_time   linear   IP   !ip.Traffic Received (packets/sec)   Traffic Received (packets/sec)           IP   bucket/default total/sum_time   linear   IP   ip.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           IP   bucket/default total/sum_time   linear   IP   ip.Processing Delay (sec)   Processing Delay (sec)           IP    bucket/default total/sample mean   linear   IP   "ip.Ping Replies Received (packets)   Ping Replies Received (packets)           IP   bucket/default total/count   square-wave   IP   ip.Ping Requests Sent (packets)   Ping Requests Sent (packets)           IP   bucket/default total/count   square-wave   IP   ip.Ping Response Time (sec)   Ping Response Time (sec)           IP    bucket/default total/sample mean   discrete   IP   %ip.Background Traffic Delay --> (sec)   "Background Traffic Delay --> (sec)           IP   normal   linear   IP   %ip.Background Traffic Delay <-- (sec)   "Background Traffic Delay <-- (sec)           IP   normal   linear   IP    wireless_lan_mac.Load (bits/sec)   Load (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   &wireless_lan_mac.Throughput (bits/sec)   Throughput (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   )wireless_lan_mac.Media Access Delay (sec)   Media Access Delay (sec)           Wireless Lan    bucket/default total/sample mean   linear   Wireless Lan   wireless_lan_mac.Delay (sec)   Delay (sec)           Wireless Lan    bucket/default total/sample mean   linear   Wireless Lan   &ip.Forwarding Memory Free Size (bytes)   #Forwarding Memory Free Size (bytes)           IP Processor   !bucket/default total/time average   linear   IP Processor   ip.Forwarding Memory Overflows   Forwarding Memory Overflows           IP Processor   sample/default total   linear   IP Processor   'ip.Forwarding Memory Queue Size (bytes)   $Forwarding Memory Queue Size (bytes)           IP Processor   !bucket/default total/time average   linear   IP Processor   0ip.Forwarding Memory Queue Size (incoming bytes)   -Forwarding Memory Queue Size (incoming bytes)           IP Processor   !bucket/default total/time average   linear   IP Processor   2ip.Forwarding Memory Queue Size (incoming packets)   /Forwarding Memory Queue Size (incoming packets)           IP Processor   !bucket/default total/time average   linear   IP Processor   )ip.Forwarding Memory Queue Size (packets)   &Forwarding Memory Queue Size (packets)           IP Processor   !bucket/default total/time average   linear   IP Processor   "ip.Forwarding Memory Queuing Delay   Forwarding Memory Queuing Delay           IP Processor    bucket/default total/sample mean   discrete   IP Processor    udp.Traffic Received (Bytes/Sec)   Traffic Received (Bytes/Sec)           UDP   bucket/default total/sum_time   linear   UDP   "udp.Traffic Received (Packets/Sec)   Traffic Received (Packets/Sec)           UDP   bucket/default total/sum_time   linear   UDP   udp.Traffic Sent (Bytes/Sec)   Traffic Sent (Bytes/Sec)           UDP   bucket/default total/sum_time   linear   UDP   udp.Traffic Sent (Packets/Sec)   Traffic Sent (Packets/Sec)           UDP   bucket/default total/sum_time   linear   UDP   CPU.CPU Elapsed Time   CPU Elapsed Time           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.CPU Job Queue Length   CPU Job Queue Length           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.CPU Total Utilization (%)   CPU Total Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.CPU Utilization (%)   CPU Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.CPU Wait Time   CPU Wait Time           Server Jobs   bucket/default total/sum_time   linear   Server Jobs    CPU.Prioritized Job Queue Length   Prioritized Job Queue Length           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Completion Time   Completion Time           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job CPU Segment Size   Job CPU Segment Size           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job CPU Service Time   Job CPU Service Time           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Disk Operations   Job Disk Operations           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Disk Reads   Job Disk Reads           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Disk Writes   Job Disk Writes           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Memory Size   Job Memory Size           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Paging Hard Faults   Job Paging Hard Faults           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Paging Soft Faults   Job Paging Soft Faults           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Job Resident Set Size   Job Resident Set Size           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Jobs Active   Jobs Active           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Jobs Completed   Jobs Completed           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Jobs Created   Jobs Created           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Completion Time   Total Completion Time           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Jobs Completed   Total Jobs Completed           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Jobs Created   Total Jobs Created           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Memory Size   Total Memory Size           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Resident Set Size   Total Resident Set Size           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Completion Time   Disk Completion Time           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Interface Bus Requests   Disk Interface Bus Requests           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   "CPU.Disk Interface Bus Utilization   Disk Interface Bus Utilization           Server Jobs   !bucket/default total/time average   linear   Server Jobs   #CPU.Disk Interface Max Bus Requests   Disk Interface Max Bus Requests           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Max Queue Length   Disk Max Queue Length           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Operations Per Second   Disk Operations Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Queue Length   Disk Queue Length           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Reads Per Second   Disk Reads Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   $CPU.Disk Total Operations Per Second    Disk Total Operations Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Total Reads Per Second   Disk Total Reads Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs    CPU.Disk Total Writes Per Second   Disk Total Writes Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Utilization   Disk Utilization           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.Disk Writes Per Second   Disk Writes Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Utilization (%)   Utilization (%)           CPU   !bucket/default total/time average   linear   resource    ip.Queuing Delay Deviation (sec)   Queue Delay Variation (sec)           IP Interface   sample/default total/   linear   IP Interface   &ip.Background Traffic Flow Delay (sec)   #Background Traffic Flow Delay (sec)           IP    bucket/default total/sample mean   linear   IP   olsr.End-to-End Delay (seconds)   End-to-End Delay (seconds)           OLSR    bucket/default total/sample mean   linear   OLSR   olsr.Traffic Received (bits)   Traffic Received (bits)           OLSR   bucket/default total/sum   linear   OLSR    olsr.Traffic Received (bits/sec)   Traffic Received (bits/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   olsr.Traffic Received (packets)   Traffic Received (packets)           OLSR   bucket/default total/sum   linear   OLSR   #olsr.Traffic Received (packets/sec)   Traffic Received (packets/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   olsr.Traffic Sent (bits)   Traffic Sent (bits)           OLSR   bucket/default total/sum   linear   OLSR   olsr.Traffic Sent (bits/sec)   Traffic Sent (bits/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   olsr.Traffic Sent (packets)   Traffic Sent (packets)           OLSR   bucket/default total/sum   linear   OLSR   olsr.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   *ip.CAR Incoming Traffic Dropped (bits/sec)   'CAR Incoming Traffic Dropped (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   -ip.CAR Incoming Traffic Dropped (packets/sec)   *CAR Incoming Traffic Dropped (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   *ip.CAR Outgoing Traffic Dropped (bits/sec)   'CAR Outgoing Traffic Dropped (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   -ip.CAR Outgoing Traffic Dropped (packets/sec)   *CAR Outgoing Traffic Dropped (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Dropped (bits/sec)   Traffic Dropped (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Received (bits/sec)   Traffic Received (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Sent (bits/sec)   Traffic Sent (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   0wireless_lan_mac.Dropped Data Packets (bits/sec)   Dropped Data Packets (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   )wireless_lan_mac.Hld Queue Size (packets)   Hld Queue Size (packets)           Wireless Lan   !bucket/default total/time average   linear   Wireless Lan   ip.Queuing Delay   Queuing Delay           IP Interface    bucket/default total/sample mean   linear   IP Interface   "udp_gen.End-to-End Delay (seconds)   End-to-End Delay (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 0 (seconds)   !End-to-End Delay flow 0 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 12 (seconds)   "End-to-End Delay flow 12 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   #udp_gen.Traffic Received (bits/sec)   Traffic Received (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 0 (bits/sec)   "Traffic Received flow 0 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 12 (bits/sec)   #Traffic Received flow 12 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   udp_gen.Traffic Sent (bits/sec)   Traffic Sent (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   )udp_gen.End-to-End Delay flow 1 (seconds)   !End-to-End Delay flow 1 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 10 (seconds)   "End-to-End Delay flow 10 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 11 (seconds)   "End-to-End Delay flow 11 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 13 (seconds)   "End-to-End Delay flow 13 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 14 (seconds)   "End-to-End Delay flow 14 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 15 (seconds)   "End-to-End Delay flow 15 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 16 (seconds)   "End-to-End Delay flow 16 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 17 (seconds)   "End-to-End Delay flow 17 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 18 (seconds)   "End-to-End Delay flow 18 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   *udp_gen.End-to-End Delay flow 19 (seconds)   "End-to-End Delay flow 19 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 2 (seconds)   !End-to-End Delay flow 2 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 3 (seconds)   !End-to-End Delay flow 3 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 4 (seconds)   !End-to-End Delay flow 4 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 5 (seconds)   !End-to-End Delay flow 5 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 6 (seconds)   !End-to-End Delay flow 6 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 7 (seconds)   !End-to-End Delay flow 7 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 8 (seconds)   !End-to-End Delay flow 8 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   )udp_gen.End-to-End Delay flow 9 (seconds)   !End-to-End Delay flow 9 (seconds)           UDP_GEN   bucket/1 secs/sample mean   sample-hold   UDP_GEN   (udp_gen.Traffic Received (5s) (bits/sec)    Traffic Received (5s) (bits/sec)           UDP_GEN   bucket/5 secs/sum_time   square-wave   UDP_GEN   udp_gen.Traffic Received (bits)   Traffic Received (bits)           UDP_GEN   bucket/1 secs/sum   sample-hold   UDP_GEN   "udp_gen.Traffic Received (packets)   Traffic Received (packets)           UDP_GEN   bucket/1 secs/sum   sample-hold   UDP_GEN   &udp_gen.Traffic Received (packets/sec)   Traffic Received (packets/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 1 (bits/sec)   "Traffic Received flow 1 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 10 (bits/sec)   #Traffic Received flow 10 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 11 (bits/sec)   #Traffic Received flow 11 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 13 (bits/sec)   #Traffic Received flow 13 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 14 (bits/sec)   #Traffic Received flow 14 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 15 (bits/sec)   #Traffic Received flow 15 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 16 (bits/sec)   #Traffic Received flow 16 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 17 (bits/sec)   #Traffic Received flow 17 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 18 (bits/sec)   #Traffic Received flow 18 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   +udp_gen.Traffic Received flow 19 (bits/sec)   #Traffic Received flow 19 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 2 (bits/sec)   "Traffic Received flow 2 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 3 (bits/sec)   "Traffic Received flow 3 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 4 (bits/sec)   "Traffic Received flow 4 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 5 (bits/sec)   "Traffic Received flow 5 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 6 (bits/sec)   "Traffic Received flow 6 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 7 (bits/sec)   "Traffic Received flow 7 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 8 (bits/sec)   "Traffic Received flow 8 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   *udp_gen.Traffic Received flow 9 (bits/sec)   "Traffic Received flow 9 (bits/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   udp_gen.Traffic Sent (bits)   Traffic Sent (bits)           UDP_GEN   bucket/1 secs/sum   sample-hold   UDP_GEN   udp_gen.Traffic Sent (packets)   Traffic Sent (packets)           UDP_GEN   bucket/1 secs/sum   sample-hold   UDP_GEN   "udp_gen.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           UDP_GEN   bucket/1 secs/sum_time   square-wave   UDP_GEN   ip.Buffer Usage (bytes)   Buffer Usage (bytes)           IP Interface   !bucket/default total/time average   linear   IP Interface   ip.Buffer Usage (packets)   Buffer Usage (packets)           IP Interface   !bucket/default total/time average   linear   IP Interface    ip.Traffic Dropped (packets/sec)   Traffic Dropped (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   !ip.Traffic Received (packets/sec)   Traffic Received (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   &wireless_lan_mac.Backoff Slots (slots)   Backoff Slots (slots)           Wireless Lan   bucket/default total/sum   linear   Wireless Lan   *wireless_lan_mac.Channel Reservation (sec)   Channel Reservation (sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   0wireless_lan_mac.Control Traffic Rcvd (bits/sec)   Control Traffic Rcvd (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   3wireless_lan_mac.Control Traffic Rcvd (packets/sec)   "Control Traffic Rcvd (packets/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   0wireless_lan_mac.Control Traffic Sent (bits/sec)   Control Traffic Sent (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   3wireless_lan_mac.Control Traffic Sent (packets/sec)   "Control Traffic Sent (packets/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   -wireless_lan_mac.Data Traffic Rcvd (bits/sec)   Data Traffic Rcvd (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   0wireless_lan_mac.Data Traffic Rcvd (packets/sec)   Data Traffic Rcvd (packets/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   -wireless_lan_mac.Data Traffic Sent (bits/sec)   Data Traffic Sent (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   0wireless_lan_mac.Data Traffic Sent (packets/sec)   Data Traffic Sent (packets/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   3wireless_lan_mac.Dropped Data Packets (packets/sec)   "Dropped Data Packets (packets/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   wireless_lan_mac.Load (packets)   Load (packets)           Wireless Lan   bucket/default total/sum   linear   Wireless Lan   2wireless_lan_mac.Retransmission Attempts (packets)   !Retransmission Attempts (packets)           Wireless Lan   bucket/default total/sum   linear   Wireless Lan          machine type       workstation                 interface type       
IEEE802.11      6IP Host Parameters.Interface Information [<n>].Address      
IP Address   :IP Host Parameters.Interface Information [<n>].Subnet Mask      IP Subnet Mask       wlan_port_tx_<n>_0   wlan_port_rx_<n>_0           