#ifndef _OLSR_PKT_TYPES
#define _OLSR_PKT_TYPES

#include "protokit.h"
#include <stdlib.h>
#include <stdio.h>

#define INVALID            -1
//link types
#define UNSPEC_LINK        0x00
#define ASYM_LINK          0x01
#define SYM_LINK           0x02
#define LOST_LINK          0x03
//neighbor types
#define NOT_NEIGH          0x00
#define SYM_NEIGH          0x01
#define MPR_NEIGH          0x02
//version 4 link types which are combinations of version 8 types.  is version 8 compliant.
#define SYM_LINKv4         0x06 
#define ASYM_LINKv4        0x01
#define MPR_LINKv4         0x0a
#define LOST_LINKv4        0x03
#define PENDING_LINK       0x05 //not really valid

#define NRLOLSR_HELLO      0x01
#define NRLOLSR_TC_MESSAGE 0x02
#define NRLOLSR_HNA_MESSAGE 0x4

#define NRLOLSR_TC_MESSAGE_EXTRA 0xF1

#define WILL_NEVER         0x00
#define WILL_LOW           0x01
#define WILL_DEFAULT       0x03
#define WILL_HIGH          0x06
#define WILL_ALWAYS        0x07

#define TIME_CONSTANT      .0625 //C value as described in v8 olsr spec 
struct ListNode
{
  ListNode *next, *prev;
  char* object;
  int size;
};

class List_
{
 public:
  //  static int ccounter, dcounter, counter;
  ListNode *head, *tail, *peekptr;
  ~List_(){destroy();}//fprintf(stdout,"%d is count %d is ccount %d is dcount %d is combined number\n",--counter,ccounter,++dcounter,ccounter-dcounter);}
  List_(){head=NULL;tail=NULL;peekptr=NULL;}//;fprintf(stdout,"d is count %d is ccount %d is dcount %d is combinednumber \n",++counter,++ccounter,dcounter,ccounter-dcounter);}
  bool IsEmpty() {if(head) return 0; return 1;}
  //List(List &); //copy constructor;
  bool append(char* object,int size);
  bool destroy();
  int pack(char* buffer,int maxSize);  //returns size that is used;
  char* peekNext(int* sizeptr); //sets pointer to next object (no copy is made)
  void peekInit(){peekptr=NULL;}
};

class LinkMessage
{
 public:
  LinkMessage(){linkCode=0;reserved=0;size=4;}
  ~LinkMessage(){}//neighbors.destroy();}
  UINT8 linkCode;
  UINT8 reserved;
  UINT16 size;
  List_ neighbors;
  List_ degrees; //degrees of neighbors reserved is set to 1 if this list is used.
  bool addNeighbor(ProtoAddress *newNeighbor);
  bool addNeighborExtra(ProtoAddress *newNeighbor, unsigned long degree);//used for sending 2 hop degree information to do ECDS for manet OSPF extentions
  int pack(char* buffer,int maxSize); //returns size that is used;
  int unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode); //returns size that was used, buffer can extend past one LinkMessage
};

class HelloMessage 
{
 public:
  HelloMessage(){reserved1=0;htime=0;willingness=WILL_DEFAULT;size=4;}
  ~HelloMessage(){}//messages.destroy();}
  UINT16 size;  //variable not placed in packet
  UINT16 reserved1;
  UINT8 htime;
  UINT8 willingness;

  List_ messages;
  //  bool addInterface(ProtoAddress *newInterface);
  bool addLinkMessage(LinkMessage *newMessage);
  int pack(char* buffer,int maxSize);
  int unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode); //returns size that was used
};

class TCMessage
{
 public:
  TCMessage(){reserved=0;mssn=0;size=4;}
  ~TCMessage(){}//mprselectors.destroy();}
  UINT16 mssn;
  UINT16 reserved;
  UINT16 size; //not packed in packet;
  List_ mprselectors;
  bool addMprSelector(ProtoAddress *newMprSelector);
  int pack(char* buffer, int maxSize);
  int unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode);
};

class TCMessageExtra
{
 public:
  TCMessageExtra(){reserved=0;mssn=0;size=4;}
  ~TCMessageExtra(){}//mprselectors.destroy();}
  UINT16 mssn;
  UINT16 reserved;
  UINT16 size; //not packed in packet;
  List_ mprselectors;
  List_ minmax;
  List_ spf;
  bool addMprSelector(ProtoAddress *newMprSelector,UINT8 minmax, UINT8 spf);
  int pack(char* buffer, int maxSize);
  int unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode);
};

class HNAMessage
{
 public:
  HNAMessage(){size=0;}
  ~HNAMessage(){}//networkaddress.destroy();
  UINT16 size;
  List_ networksandmasks;
  bool addNetwork(ProtoAddress *newNetwork,ProtoAddress *newMask);
  int pack(char* buffer, int maxSize);
  int unpack(char*buffer,int maxSize, ProtoAddress::Type ipvMode);
};

class OlsrMessage
{
 public:
  OlsrMessage(){type=0;Vtime=0;size=8;ttl=0;hopc=0;D_seq_num=0;message=NULL;} //size does not account for size of O_addr use SetO_addr function
  ~OlsrMessage(){free(message);}
  UINT8 type;
  UINT8 Vtime;
  UINT16 size; 
  ProtoAddress O_addr;
  UINT8 ttl;
  UINT8 hopc;
  UINT16 D_seq_num;
  //HelloMessage hello;  
  //TCMessage tc;
  char *message;
  bool SetO_addr(const ProtoAddress &theO_addr);
  bool setTCMessage(TCMessage* thetc); 
  bool setTCMessageExtra(TCMessageExtra* thetc);
  bool setHelloMessage(HelloMessage* theHello); 
  bool setHNAMessage(HNAMessage* thehna);
  
  int pack(char* buffer, int maxSize);
  int unpack(char* buffer, int maxSize, ProtoAddress::Type ipvMode); //returns size that was used
};

class OlsrPacket
{
 public:
  OlsrPacket(){size=4;seqno=0;}
  ~OlsrPacket(){}//messages.destroy();}
  UINT16 size;
  UINT16 seqno;
  List_ messages;
  bool addOlsrMessage(OlsrMessage *newMessage);
  int pack(char* buffer,int maxSize);
  int unpack(char* buffer, int maxSize, ProtoAddress::Type ipvMode); //returns size that was used
  void clear();
};

#endif // _OLSR_PKT_TYPES

#ifndef _MAC_CONTROL_MSG
#define _MAC_CONTROL_MSG

class MacControlMsg
{
    public:
        MacControlMsg();
    
        enum {MAX_SIZE = 8192};
    
        enum AddrType
        {
            ADDR_INVALID  = 0,
            ADDR_ETHERNET = 1, 
            ADDR_IPV4     = 2,
            ADDR_IPV6     = 3,
	    ADDR_LOCAL    = 4
	};
            
        UINT8 GetVersion() 
            {return msg_buffer[VERSION_OFFSET];}
        
        UINT16 GetLength()
            {return (ntohs(*((UINT16*)(msg_buffer+LENGTH_OFFSET))));}       
        
        AddrType GetAddressType() 
            {return (AddrType)msg_buffer[ADDRTYPE_OFFSET];} 
        
        UINT8 GetAddressLength();
        
        const char* GetAddress() 
            {return (msg_buffer+ADDR_OFFSET);}
        
        char* AccessBuffer() {return msg_buffer;}
        bool InitFromBuffer(UINT16 msgLength)
        {
            bool result = msgLength <= MAX_SIZE;
            msg_length = result ? msgLength : 0;
            return result;
        }
        
        class Param
        {
            public:
                Param(); 
            
                enum Type
                {
                    METRICS_INVALID         = 0,
                    METRICS_SPF_COST        = 1,
                    METRICS_MINMAX_COST     = 2,
                    METRICS_PROMISC_COUNT   = 3,
                    METRICS_NBR_QUALITY     = 4  
                };
                    
                enum NbrQuality
                {
                    NBR_INVALID = 0,
                    NBR_GOOD    = 1,
                    NBR_BAD     = 2,
                    NBR_UNKNOWN = 3  
                };
            
                Type GetType() 
                {
                    UINT16 temp16;
                    memcpy(&temp16, buffer+TYPE_OFFSET, sizeof(UINT16));
                    return ((Type)ntohs(temp16));   
                }    
                
                UINT16 GetLength()
                {
                    UINT16 temp16;
                    memcpy(&temp16, buffer+LENGTH_OFFSET, sizeof(UINT16));
                    return (ntohs(temp16));   
                }
                
                const char* GetContent() {return buffer+CONTENT_OFFSET;}
                
                int GetValue();
                
                void AttachBuffer(const char* theBuffer) {buffer = theBuffer;}   
                const char* GetBuffer() {return buffer;}   
                    
            private:
                enum
                {
                    TYPE_OFFSET     = 0,
                    LENGTH_OFFSET   = TYPE_OFFSET + 2,
                    CONTENT_OFFSET  = LENGTH_OFFSET + 2
                };
                const char* buffer;
        };  // end class MacControlMsg::Param
        
        UINT32 GetNumParams() 
        {
            UINT32 temp32;
            memcpy(&temp32, msg_buffer+ADDR_OFFSET+GetAddressLength(), sizeof(UINT32));
            return (ntohl(temp32));
        }
        bool GetNextParam(Param& param)
        {
            const char* currentBuffer = param.GetBuffer();
            UINT16 nextOffset = 
                currentBuffer ? (currentBuffer - msg_buffer + 4 + param.GetLength()) :
                                (ADDR_OFFSET+GetAddressLength()+4);    
            bool result = nextOffset < msg_length;
            param.AttachBuffer(result ? (msg_buffer+nextOffset) : NULL);
            return result;        
        }
                       
    private:
        enum
        {
            VERSION_OFFSET  = 0,
            ADDRTYPE_OFFSET = VERSION_OFFSET + 1,
            LENGTH_OFFSET   = ADDRTYPE_OFFSET + 1,
            ADDR_OFFSET     = LENGTH_OFFSET + 2
        };   
            
        char    msg_buffer[MAX_SIZE];
        UINT16  msg_length;       
};  // end class MacControlMsg

#endif // _MAC_CCONTROL_MSG
