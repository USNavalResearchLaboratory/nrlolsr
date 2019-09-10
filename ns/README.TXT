(NOTE: if you are trying to install nrlolsr on an ns build prior to 2.33 please follow the install install instructions contained in the README.OLD.TXT file.)

1. Download protolib and follow the ns install instructions.  The protolib 
   install instructions include information on how to install nrlolsr. They
   are located in the protolib/src/sim/ns/ns<ver> directory.

2. Run the sample tcl file basicmhop.tcl located in the ns-2.33/nrlolsr/ns 
    "ns basicmhop.tcl"  the output should be some invalid options then...

	ns-2.26 (this may be different have checked in a while)
	Cbr agent0 received 28.197333333333333 Kbps
	Cbr agent1 received 61.925333333333334 Kbps
	Cbr agent2 received 67.637333333333331 Kbps
	
	ns-2.33
	Cbr agent0 received 30.133333333333333 Kbps
	Cbr agent1 received 69.155555555555566 Kbps
	Cbr agent2 received 64.355555555555554 Kbps

        ns-2.34
        Cbr agent0 received 31.199999999999999 Kbps
        Cbr agent1 received 69.333333333333329 Kbps
        Cbr agent2 received 64.444444444444443 Kbps

3. Additional tcl file setup is required for your existing simulations please 
   follow the basicmhop.tcl for hints on how to set up an nrlolsr node in your 
   existing simulation tcl files.

4. Psuedo multicast has also been added.  Check out the simpleworking.tcl
    file to see how to set up and run a psuedo multicast simulation in a MANET 
    with "nrlolsr".  Its not real multicast because it uses the broadcast address 
    and port numbers instead of multicast addresses.

