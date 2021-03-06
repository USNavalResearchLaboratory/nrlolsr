Install instructions for building and running nrlolsr in ns-2.33:

1. Download nrlolsr source code by following either a or b steps.

	a. Using cvs: 

		1) make current directory /ns-allinone-2.27/ns-2.33/ 
		   or which ever ns-2 code directory you want to install nrlolsr in.

		2) Log into cvs anonymously using 
"cvs -d :pserver:anonymous@olsr.pf.itd.nrl.navy.mil:/cvsroot/olsr login"

		3) type 
"cvs -d :pserver:anonymous@olsr.pf.itd.nrl.navy.mil:/cvsroot/olsr co nrlolsr"

		4) type 
"cvs -d :pserver:anonymous@protolib.pf.itd.nrl.navy.mil:/cvsroot/protolib co protolib"

		5) type "cd nrlolsr"

		6) create symoblic link named protolib pointing to ../protolib
			"ln -s ../protolib protolib"

	b. Using available tarball:

		1) make current directory /ns-allinone-2.27/ns-2.33/

		2) download nrlolsrdv(version).tgz into /ns-allinone-2.27/ns-2.33

		3) type "tar -xvzf nrlolsrd(version).tgz"

		4) create symbolic link protolib which points to nrlolsr/protolib
			"ln -s nrlolsr/protolib protolib"
	
	NOTE: actual protolib source code is located in different 
	      locations depending on method of downloading.

2. Modify Makefile.in to include new source. If you have modifided or added code 
   to ns you must add changes manually to perserve your existing code.	

	a. Copy Makefile.in(ns version) from /ns(ns-version)/nrlolsr/ns/ directory to /ns(ns-version)/Makefile.in.
	
	b. Manually modify Makefile.in by comparing your modified Makefile.in
	   with /ns-2.33/nrlolsr/ns/Makefile.in(ns version) and adding lines which are not 
	   currently in your Makefile.in

3. Build new Makefile by running ./configure in your ns-2.33 directory.
   DO NOT TRY TO COMPILE YET!

4. Change your ns-2.33/common/packet.h file to include info on ProtolibManetKernel:

    a) add:
   
    "#define HDR_ProtolibManetKernel(p) (hdr_ProtolibManetKernel::access(p))"
    
       near the top of the file with the other similar #defines.
       
    b)  Before the end of the statics for packet_t, change the 
        current PT_NTYPE line to 
    
        "static const packet_t PT_MANET=61;"

         and change the last entry to
       
         "PT_NTYPE = 62; // This MUST be the LAST one"

    c) add "name_[PT_MANET]= "manet";" in the p_info() section

5. Change your ns-2.33/trace/cmu-trace.h file adding ProtolibManetKernel hooks
   add "void format_manet(Packet *p, int offset);" at the bottom with
   	the other "format_xxx" functions.

6. Change your ns-2.33/trace/cmu-trace.cc file adding ProtolibManetKernel hooks:

   a) add "#include <nrlolsr/ns/protolibManetKernel.h>" at the end of the #includes
   
   b) add empty function:
      "void CMUTrace::format_ProtolibManetKernel(Packet *p, int offset) {return;}"
   
   c) add to the switch(ch->ptype()) (default one) statement:

   "case PT_MANET:
		format_ProtolibManetKernel(p, offset);
		break;"

7. Change your ns-2.33/tcl/lib/ns-lib.tcl file:

   a) add to the "switch -exact $routingAgent" statement:
   
   "ProtolibManetKernel {
		set ragent [$self create-protolibmanetkernel-agent $node]
  	}"
    
   b) add along with other Simulator create functions:

   "Simulator instproc create-protolibmanetkernel-agent {node} {
		# create a dummie wireless agent
		# it will foward packets up to protolib manet
		# and just act as a wedge into ns
		# used by protolib wireless manets
		set ragent [new Agent/ProtolibManetKernel [$node node-addr]]
		$node set ragent_ $ragent
		return $ragent
   	}"

8. Last edit! Change ns-2.33/queue/priqueue.cc file, add 
   
   "case PT_MANET:"
   
   to the switch statment in the if(Prefer_Routing_Protocols) conditional (at top)

9. Now we can compile the code by typing "make" in your ns directory

10. Run the sample tcl file basicmhop.tcl located in the ns-2.33/nrlolsr/ns 
    "ns basicmhop.tcl"  the output should be some invalid options then...

	ns-2.26 (this may be different have checked in a while)
	Cbr agent0 received 28.197333333333333 Kbps
	Cbr agent1 received 61.925333333333334 Kbps
	Cbr agent2 received 67.637333333333331 Kbps
	
	ns-2.33
	Cbr agent0 received 17.861333333333333 Kbps
	Cbr agent1 received 82.325333333333333 Kbps
	Cbr agent2 received 73.802666666666667 Kbps

11. Additional tcl file setup is required for your existing simulations please 
    follow the basicmhop.tcl for hints on how to set up an nrlolsr node in your 
    existing simulation tcl files.

12. Psuedo multicast has also been added.  Check out the simpleworking.tcl
    file to see how to set up and run a psuedo multicast simulation in a MANET 
    with "nrlolsr".  Its not real multicast because it uses the broadcast address 
    and port numbers instead of multicast addresses.

