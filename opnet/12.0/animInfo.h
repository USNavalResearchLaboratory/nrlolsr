#ifndef _ANIMINFO_
#define _ANIMINFO_

#include <protoAddress.h>

#ifndef MAX_NUM_NODES
#define MAX_NUM_NODES 100
#endif

#define TX_DISPLAY_TIME 1.0
#define RX_DISPLAY_TIME 1.0
#define TTL_DISPLAY_TIME 1.0
#define COL_DISPLAY_TIME 1.0
#define MAX_MGEN_PORTS	32
#define RX_ANIM_TO 		381
#define TX_ANIM_TO 		382
#define TTL_ANIM_TO 	383
#define COL_ANIM_TO 	384

struct OlsrNode
{
  Objid objid;			// node objid
  Objid olsr_objid;		// olsr processor module objid
  Andid col_did;		// drawing id for collisions at this node
  int col_cnt;
  int col_exception_cnt;	// .NET 2003 dra_inoise_col exception counter
  Evhandle col_timeout_ev;
  ProtoAddress ipv4_addr;
  double lat;
  double lon;
  double alt;
  double x;
  double y;
  double z;
  int vx;
  int vy;
  int vz;
  char name[32];
  OlsrNode();
  void col_increment(){col_cnt++;}  // increment col_cnt by 1
  void col_reset(){col_cnt=0;}		// reset col_cnt to 0
  int col_get(){return col_cnt;}	
};

extern int animFlag;
extern int sdtFlag;
extern int no_coll_anim;
extern Anvid olsr_vid;
extern OlsrNode* olsrNode[MAX_NUM_NODES];
/* packet animation */
extern int mgen_tcp_port[MAX_MGEN_PORTS];
extern int mgen_udp_port[MAX_MGEN_PORTS];
extern int mgen_tcp_port_cnt;
extern int mgen_udp_port_cnt;

#endif  // _ANIMINFO_
