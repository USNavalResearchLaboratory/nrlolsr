# Copyright (c) 1997 Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#      This product includes software developed by the Computer Systems
#      Engineering Group at Lawrence Berkeley Laboratory.
# 4. Neither the name of the University nor of the Laboratory may be used
#    to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# simple-wireless.tcl
# A simple example for wireless simulation

# ======================================================================
# Define options
# ======================================================================
set val(chan)           Channel/WirelessChannel    ;# channel type
set val(prop)           Propagation/TwoRayGround   ;# radio-propagation model
set val(netif)          Phy/WirelessPhy            ;# network interface type
set val(mac)            Mac/802_11                 ;# MAC type
set val(ifq)            Queue/DropTail/PriQueue    ;# interface queue type
set val(ll)             LL                         ;# link layer type
set val(ant)            Antenna/OmniAntenna        ;# antenna model
set val(ifqlen)         50                         ;# max packet in ifq
set val(nn)             12                         ;# number of mobilenodes
set val(rp)             ProtolibManetKernel         ;# routing protocol
set val(x)	900
set val(y)	700

set state flag
foreach arg $argv {
	switch -- $state {
		flag {
		switch -- $arg {
			manet	{set state manet}
			help	{Usage}
			default	{error "unknown flag $arg"}
		}
		}
		
		manet	{set state flag; set val(rp) $arg}
		
	}
	
}

puts "this is a mobile network test program"
# =====================================================================
# Main Program
# ======================================================================

#
# Initialize Global Variables
#

 set ns_		[new Simulator]
 set tracefd     [open basicmhop.tr w]
 $ns_ trace-all $tracefd


# 
  set namtrace [open basicmhop.nam w]
 $ns_ namtrace-all-wireless $namtrace $val(x) $val(y)

$ns_ color 0 red
$ns_ color 1 blue

# # Set up color mapping for MDPv2 packet types
#  $ns_ color 41 yellow
#  $ns_ color 42 blue
#  $ns_ color 43 darkgreen
#  $ns_ color 44 purple
#  $ns_ color 45 orange
#  $ns_ color 46 red
#  $ns_ color 47 black


# set up topography object
set topo       [new Topography]

$topo load_flatgrid $val(x) $val(y)

#
# Create God
#
create-god $val(nn)

#
#  Create the specified number of mobilenodes [$val(nn)] and "attach" them
#  to the channel. 
#  Here two nodes are created : node(0) and node(1)

# configure node
set chan_1_ [new $val(chan)]

        $ns_ node-config -adhocRouting $val(rp) \
			 -llType $val(ll) \
			 -macType $val(mac) \
			 -ifqType $val(ifq) \
			 -ifqLen $val(ifqlen) \
			 -antType $val(ant) \
			 -propType $val(prop) \
			 -phyType $val(netif) \
			 -channel $chan_1_ \
			 -topoInstance $topo \
			 -agentTrace ON \
			 -routerTrace ON \
			 -macTrace OFF \
			 -movementTrace ON			

	for {set i 0} {$i < $val(nn) } {incr i} {
	        set node_($i) [$ns_ node]	
		$node_($i) random-motion 1
				;# enable random motion
	}
	for {set i 0} {$i < $val(nn) } {incr i} {
		$ns_ initial_node_pos $node_($i) 25		;# disable random motion
	}
if {$val(rp) == "ProtolibManetKernel"} {
    for {set i 0} {$i < $val(nn) } {incr i} {
	set p($i) [new Agent/NrlolsrAgent]
	$ns_ attach-agent $node_($i) $p($i)
	$ns_ at 0.0 "$p($i) startup -tcj .75 -hj .5 -tci 2.5 -hi .5 -d 8 -l /tmp/olsr.log"
	[$node_($i) set ragent_] attach-manet $p($i)
	$p($i) attach-protolibManetKernel [$node_($i) set ragent_]
    }
}

# Circle #1

# Make circle radius = radius
# numnodes = numnodes
# velocity = velocity
# totaltime 
# numsteps

set totaltime 90.0
set runtime $totaltime

$ns_ at 0.0 

#Make a 4 nodes in a line
set nextx 150.0
set nexty 250.0
 $node_(0) set X_ $nextx
 $node_(0) set Y_ $nexty
 $ns_ at 0.0 "$node_(0) setdest $nextx $nexty 0.0"
set nextx 150.0
set nexty 350.0
 $node_(1) set X_ $nextx
 $node_(1) set Y_ $nexty
 $ns_ at 0.0 "$node_(1) setdest $nextx $nexty 0.0"
set nextx 150.0
set nexty 450.0
 $node_(2) set X_ $nextx
 $node_(2) set Y_ $nexty
 $ns_ at 0.0 "$node_(2) setdest $nextx $nexty 0.0"
set nextx 350.0
set nexty 250.0
 $node_(3) set X_ $nextx
 $node_(3) set Y_ $nexty
 $ns_ at 0.0 "$node_(3) setdest $nextx $nexty 0.0"
set nextx 350.0
set nexty 350.0
 $node_(4) set X_ $nextx
 $node_(4) set Y_ $nexty
 $ns_ at 0.0 "$node_(4) setdest $nextx $nexty 0.0"
set nextx 350.0
set nexty 450.0
 $node_(5) set X_ $nextx
 $node_(5) set Y_ $nexty
 $ns_ at 0.0 "$node_(5) setdest $nextx $nexty 0.0"
set nextx 550.0
set nexty 250.0
 $node_(6) set X_ $nextx
 $node_(6) set Y_ $nexty
 $ns_ at 0.0 "$node_(6) setdest $nextx $nexty 0.0"
 set nextx 550.0
set nexty 350.0
 $node_(7) set X_ $nextx
 $node_(7) set Y_ $nexty
 $ns_ at 0.0 "$node_(7) setdest $nextx $nexty 0.0"
 set nextx 550.0
set nexty 450.0
 $node_(8) set X_ $nextx
 $node_(8) set Y_ $nexty
 $ns_ at 0.0 "$node_(8) setdest $nextx $nexty 0.0"
set nextx 750.0
set nexty 250.0
 $node_(9) set X_ $nextx
 $node_(9) set Y_ $nexty
 $ns_ at 0.0 "$node_(9) setdest $nextx $nexty 0.0"
 set nextx 750.0
set nexty 350.0
 $node_(10) set X_ $nextx
 $node_(10) set Y_ $nexty
 $ns_ at 0.0 "$node_(10) setdest $nextx $nexty 0.0"
 set nextx 750.0
set nexty 450.0
 $node_(11) set X_ $nextx
 $node_(11) set Y_ $nexty
 $ns_ at 0.0 "$node_(11) setdest $nextx $nexty 0.0"
 
# Take away an MPR
set nextx 1.0
set nexty 1.0
$ns_ at 10.0 "$node_(4) set X_ $nextx"
$ns_ at 10.0 "$node_(4) set Y_ $nexty"
$ns_ at 10.0 "$node_(4) setdest $nextx $nexty 0.0"
# bring back the MPR
set nextx 350.0
set nexty 350.0
$ns_ at 30.0 "$node_(4) set X_ $nextx"
$ns_ at 30.0 "$node_(4) set Y_ $nexty"
$ns_ at 30.0 "$node_(4) setdest $nextx $nexty 0.0"
# take away more
set nextx 1.0
set nexty 1.0
$ns_ at 40.0 "$node_(7) set X_ $nextx"
$ns_ at 40.0 "$node_(7) set Y_ $nexty"
$ns_ at 40.0 "$node_(7) setdest $nextx $nexty 0.0"
$ns_ at 50.0 "$node_(4) set X_ $nextx"
$ns_ at 50.0 "$node_(4) set Y_ $nexty"
$ns_ at 50.0 "$node_(4) setdest $nextx $nexty 0.0"
# Back  MPR
set nextx 1.0
set nexty 1.0
$ns_ at 60.0 "$node_(6) set X_ $nextx"
$ns_ at 60.0 "$node_(6) set Y_ $nexty"
$ns_ at 60.0 "$node_(6) setdest $nextx $nexty 0.0"


# SEtup CBR agents

proc ranstart { first last } {
	global agentstart
	set interval [expr $last - $first]
	set maxrval [expr pow(2,31)]
	set intrval [expr $interval/$maxrval]
	set agentstart [expr ([ns-random] * $intrval) + $first]
}

ns-random 0 # seed the thing heuristically
set agentstart 5.0
for {set i 0} {$i < [expr $val(nn)] } {incr i} {
        set udp($i) [new Agent/UDP]
        $ns_ attach-agent $node_($i) $udp($i)
 	set cbr($i) [new Application/Traffic/CBR]
	$cbr($i) attach-agent $udp($i)
 	$cbr($i) set packetSize_ 1000
 	$cbr($i) set interval_ 0.05
	$cbr($i) set random_ 1
#        $cbr($i) set port_ 5798
#	$cbr($i) set class_ 2	
# 	set null($i) [new Agent/LossMonitor]
#   	$ns_ attach-agent $node_(0) $null($i)
#     	$ns_ connect $udp($i) $null($i)
	ranstart 2.0 5.0
# 	puts $agentstart
	$ns_ at $agentstart "$cbr($i) start"
	}

# Not sure why record function doesn't work with variables specified in naming
# This is a hack

	set null1 [new Agent/LossMonitor]
  	$ns_ attach-agent $node_(0) $null1
    	$ns_ connect $udp(9) $null1
	set null2 [new Agent/LossMonitor]
  	$ns_ attach-agent $node_(1) $null2
    	$ns_ connect $udp(10) $null2
 	set null3 [new Agent/LossMonitor]
   	$ns_ attach-agent $node_(2) $null3
     	$ns_ connect $udp(11) $null3
	$cbr(11) set class_ 1
# 	set null4 [new Agent/LossMonitor]
#   	$ns_ attach-agent $node_(0) $null4
#     	$ns_ connect $udp(3) $null4



# Setup MDP traffic flow between nodes
# # 
# #Option defaults
# set unicastNacks "off"
# # Server side agent (Node 0)
#     set mdp_server(0) [new Agent/MDP]
#     $ns_ attach-agent $node_(1) $mdp_server(0)
#     $mdp_server(0) ttl 32
#     $mdp_server(0) txRate 400000
#     $mdp_server(0) segmentSize 1000
#     $mdp_server(0) blockSize 20
#     $mdp_server(0) numParity 20
#     $mdp_server(0) autoParity 0
#     $mdp_server(0) numRepeats -1
#     $mdp_server(0) congestionControl off
# #    $mdp_server(0) sendLoss 10.0
#     #$mdp_server(0) recvLoss 10.0
#     $mdp_server(0) initialGrtt 0.01
# 
# # Create $numClient MDP client agents
# #for {set i 2} {$i < $maxNode} {incr i} {
# # Client side agent (Node k)
#     set mdp_client(0) [new Agent/MDP]
#     $ns_ attach-agent $node_(0) $mdp_client(0)
#     #$mdp_client($i) recvLoss 10.0
#     $mdp_client(0) rxBufferSize 1000000
#     $mdp_client(0) unicastNacks $unicastNacks
# #}
# 
# # Global MDPv2 settings (These can be set via any MDP Agent)
# $mdp_server(0) backoffWindow 0.001
# $mdp_server(0) groupSize 1
# $mdp_server(0) debugLevel 2
# $mdp_server(0) useUdp
# $mdp_server(0) messageTrace on
# $mdp_server(0) logFile mdpLog.txt
# 
# #
# $ns_ at 2.0 "$mdp_server(0) baseObject 1"
# $ns_ at 2.0 "$mdp_server(0) start server [$mdp_client(0) addr] [$mdp_client(0) port]"
# $ns_ at 2.0 "$mdp_server(0) send 65535"
# 
# # Start MDP clients
# 
# $ns_ at 2.0 "$mdp_client(0) start client [$mdp_server(0) addr] [$mdp_server(0) port]"


#Tell nodes when the simulation ends
#
for {set i 1 } {$i < $val(nn) } {incr i} {
     	 
#         $ns_ at $runtime  set bw2 [$null3 set bytes_]
#         $ns_ at $runtime  set bw3 [$null4 set bytes_]
    $ns_ at $runtime "$node_($i) reset";
}
$ns_ at $runtime "stop"
$ns_ at $runtime "puts \"NS EXITING...\" ; $ns_ halt"

proc stop {} {
#    global ns_ nametrace tracefd runtime
    global ns_ null1 null2 null3 namtrace tracefd runtime
    set bw0 [$null1 set bytes_]
    set bw1 [$null2 set bytes_]
    set bw2 [$null3 set bytes_]
    puts "Cbr agent0 received [expr $bw0/$runtime*8/1000] Kbps"
    puts "Cbr agent1 received [expr $bw1/$runtime*8/1000] Kbps"
    puts "Cbr agent2 received [expr $bw2/$runtime*8/1000] Kbps"
    $ns_ flush-trace
 
    close $tracefd
   close $namtrace
    exit 0
}

#Begin command line parsing

proc Usage {} {
    puts {pent: Usage> ns pent.tcl [manet <DSR,AODV,TORA,OLSR> }
    puts {PARAMETERS NEED NOT BE SPECIFIED... DEFAULTS WILL BE USED}
    exit
}        

	
puts "Starting Simulation..."

$ns_ run



