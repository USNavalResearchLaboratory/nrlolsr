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
# A simple example for wireless smf simulation using nrlolsr/protolib

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
set val(nn)             3                          ;# number of mobilenodes
set val(rp)             ProtolibMK                 ;# routing protocol
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
 set tracefd     [open simplesmf.tr w]
 $ns_ trace-all $tracefd

# Use new trace format
 $ns_ use-newtrace

# 
  set namtrace [open simplesmf.nam w]
 $ns_ namtrace-all-wireless $namtrace $val(x) $val(y)

$ns_ color 0 red
$ns_ color 1 blue

# set up topography object
set topo       [new Topography]

$topo load_flatgrid $val(x) $val(y)

#
# Create God
#
create-god $val(nn)

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
if {$val(rp) == "ProtolibMK"} {
    for {set i 0} {$i < $val(nn) } {incr i} {
	set p($i) [new Agent/NrlolsrAgent]
	$ns_ attach-agent $node_($i) $p($i)
	$ns_ at 0.0 "$p($i) startup -tcj 0 -hj 0 -tci 4.2 -hi 1.0 -l /dev/null"
	[$node_($i) set ragent_] attach-manet $p($i)
	$p($i) attach-protolibmk [$node_($i) set ragent_]

#flooding command is turns on flooding of all broadcast packets
#based upon port settings.  off is the default option.
#"off", "simple", "ns-mpr" (non source specific), and "s-mpr" (source specific) 
#are valid options.  See mcastForward in nrlolsrAgent to see what they do
	$p($i) -flooding s-mpr
    }
}

set totaltime 5.0
set runtime $totaltime

$ns_ at 0.0 

#Make 3 nodes in a line
set nextx 150.0
set nexty 250.0
 $node_(0) set X_ $nextx
 $node_(0) set Y_ $nexty
 $ns_ at 0.0 "$node_(0) setdest $nextx $nexty 0.0"
set nextx 150.0
set nexty 400.0
 $node_(1) set X_ $nextx
 $node_(1) set Y_ $nexty
 $ns_ at 0.0 "$node_(1) setdest $nextx $nexty 0.0"
set nextx 150.0
set nexty 550.0
 $node_(2) set X_ $nextx
 $node_(2) set Y_ $nexty
 $ns_ at 0.0 "$node_(2) setdest $nextx $nexty 0.0"
# SEtup CBR agents

proc ranstart { first last } {
	global agentstart
	set interval [expr $last - $first]
	set maxrval [expr pow(2,31)]
	set intrval [expr $interval/$maxrval]
	set agentstart [expr ([ns-random] * $intrval) + $first]
}

ns-random 0 # seed the thing heuristically

set udp(0) [new Agent/UDP]
$udp(0) set dst_addr_ -1
$udp(0) set dst_port_ 699
$ns_ attach-agent $node_(0) $udp(0)

set null2 [new Agent/LossMonitor]
$node_(2) attach $null2 699


#send one "multicast" packet to be forwarded

$ns_ at 4.5 "$udp(0) send 1000"

#Tell nodes when the simulation ends
#
for {set i 1 } {$i < $val(nn) } {incr i} {
    $ns_ at $runtime "$node_($i) reset";
}
$ns_ at $runtime "stop"
$ns_ at $runtime "puts \"NS EXITING...\" ; $ns_ halt"

proc stop {} {
#    global ns_ nametrace tracefd runtime
    global ns_ null2 namtrace tracefd runtime
    set bw2 [$null2 set bytes_]
#    puts "Cbr agent0 received [expr $bw2/$runtime*8/1000] Kbps"
    puts "Cbr agent0 received [expr $bw2] bytes over [expr $runtime] for an average rate of [expr $bw2/$runtime*8/1000] Kbps"
    $ns_ flush-trace
    close $tracefd
    close $namtrace
    exit 0
}

#Begin command line parsing

proc Usage {} {
    puts {PARAMETERS NEED NOT BE SPECIFIED... DEFAULTS WILL BE USED}
    exit
}        

	
puts "Starting Simulation..."

$ns_ run



