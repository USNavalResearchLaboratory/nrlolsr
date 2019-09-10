#include "olsr_packet_types.h"

//OlsrPacket stuff
//int books=0;
bool
OlsrPacket::addOlsrMessage(OlsrMessage *newMessage){
  size+=newMessage->size;
  
  char* rawMessage = new char[newMessage->size];
  //void* rawMessage=malloc(newMessage->size);
  
  if(!rawMessage){
    fprintf(stderr,"malloc returned null pointer in OlsrPacket::addOlsrMessage\n");
    return 0;
  }
  newMessage->pack((char*)rawMessage,newMessage->size);
  int returnvalue = messages.append(rawMessage,newMessage->size);
  
  delete[] rawMessage;
  //free(rawMessage);
  
  if(returnvalue > 0)
	return true;
  return false;
}
int 
OlsrPacket::pack(char* buffer,int maxSize){
  int sizeused=4;
  ((UINT16*)buffer)[0]=htons(size);
  ((UINT16*)buffer)[1]=htons(seqno);
  sizeused += messages.pack(&buffer[4],maxSize-sizeused);
  if(sizeused<4){
    fprintf(stderr,"OlsrPacket::pack error packing olsr messages,%d is my maxSize, %d is my sizeused\n",maxSize,sizeused);
    return -1;
  }
  return sizeused;
}
int 
OlsrPacket::unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode){
  int sizeused = 4;
  size=ntohs(((UINT16*)buffer)[0]);
  seqno=ntohs(((UINT16*)buffer)[1]);
  if(size>maxSize){
    fprintf(stderr,"OlsrPacket::unpack packet size %d is greater than maxSize %d!\n",size,maxSize);
  }
  OlsrMessage newmessage;
  sizeused+=newmessage.unpack(&buffer[4],size-4,ipvMode);
  addOlsrMessage(&newmessage);
  if(sizeused>maxSize){
    fprintf(stderr,"OlsrPacket::unpack sizeused %d is greater than maxSize %d!\n",sizeused,maxSize);
  }
  DMSG(10,"added first olsr message\n");
  size=ntohs(((UINT16*)buffer)[0]);//needed to reset the size value as addolsrmessage adds to the size variable
  //new code
  //while(sizeused<maxSize){
  while(sizeused<size){ //changed line to allow for padding in olsr messages 
    DMSG(10,"trying to add second message to packet in unpack sizeused=%d size=%d maxsize=%d\n",sizeused,size,maxSize);
    sizeused+=newmessage.unpack(&buffer[sizeused],size-sizeused,ipvMode);
    DMSG(10,"after unpack sizeused=%d size=%d maxsize=%d testvalue=%d\n",sizeused,size,maxSize,ntohs(((UINT16*)buffer)[0]));
    addOlsrMessage(&newmessage);
    //we need to correct size value as addOlsrMessage adds the size of the message to the size variable 
    size=ntohs(((UINT16*)buffer)[0]);
    DMSG(10,"after add message sizeused=%d size=%d maxsize=%d testvalue=%d\n",sizeused,size,maxSize,ntohs(((UINT16*)buffer)[0]));
    if(sizeused>maxSize){
      fprintf(stderr,"OlsrPacket::unpack sizeused %d is greater than maxSize %d!\n",sizeused,maxSize);
    }
    DMSG(10,"added olsr message to packet in unpack success sizeused=%d size=%d maxsize=%d testvalue=%d\n",sizeused,size,maxSize,ntohs(((UINT16*)buffer)[0]));
  }
  //end new code
  if(sizeused!=size){
    fprintf(stderr,"OlsrPacket::unpack sizeused %d is not equal to packet size value %d! \n",sizeused,size);
  }
  
  return size;
}
void 
OlsrPacket::clear(){
  messages.destroy();
  size=4;
  seqno=0;
}

//OlsrMessage stuff
bool
OlsrMessage::setHelloMessage(HelloMessage* theHello){
  size+=theHello->size;
  //hello=theHello;
  if(message){ 
    fprintf(stderr,"message has value while in OlsrMessage::setHelloMessage double check pointers\n");
    return 0;
  }

  //message = (char*)malloc(theHello->size);
  message = new char[theHello->size];

  if(!message){ 
    fprintf(stderr,"malloc returned NULL in Olsrmessage::setHelloMessage\n"); 
    return 0;
  }
  theHello->pack(message,theHello->size);
  return 1;
}

bool
OlsrMessage::setTCMessage(TCMessage* thetc){
  size+=thetc->size;
  if(message){ 
    fprintf(stderr,"message has value while in OlsrMessage::setTCMessage double check pointers\n");
    return 0;
  }

  //message = (char*)malloc(thetc->size);
  message = new char[thetc->size];

  if(!message){ 
    fprintf(stderr,"malloc returned NULL in Olsrmessage::setTCMessage\n"); 
    return 0;
  }
  thetc->pack(message,thetc->size);
  return 1;
}

bool
OlsrMessage::setTCMessageExtra(TCMessageExtra* thetc){
  //have to do a little bit of messing with size because sometimes not a multipule of 4
  int packsize= thetc->size;
  if(thetc->size % 4 !=0){
    packsize+=2;
  }
  size+=packsize;//thetc->size;
   if(message){ 
    fprintf(stderr,"message has value while in OlsrMessage::setTCMessage double check pointers\n");
    return 0;
  }

   //message = (char*)malloc(thetc->size);
   //message = (char*)malloc(packsize);
   message = new char[packsize];

  if(!message){ 
    fprintf(stderr,"malloc returned NULL in Olsrmessage::setTCMessage\n"); 
    return 0;
  }
  memset(message,0,packsize);
  thetc->pack(message,thetc->size);
  return 1;
}

bool
OlsrMessage::setHNAMessage(HNAMessage* thehna){
  size+=thehna->size;
  if(message){
    fprintf(stderr,"message has value while in OlsrMessage::setHNAMessage double check pointers\n");
    return 0;
  }

  //message = (char*)malloc(thehna->size);
  message = new char[thehna->size];

  if(!message){
    fprintf(stderr,"malloc returned NULL in Olsrmessage::setHNAMessage\n");
    return 0;
  }
  thehna->pack(message,thehna->size);
  return 1;
}
bool
OlsrMessage::SetO_addr(const ProtoAddress &theO_addr){
  /*  if(O_addr.IsValid()){
    if(O_addr.Type()==IPv4){
      size-=4;
    } else if(O_addr.Type()==IPv6){
      size-=16;
    }
    }*/
  O_addr = theO_addr;
  if(O_addr.GetType()==ProtoAddress::IPv4){
    size+=4;
  } else if(O_addr.GetType()==ProtoAddress::IPv6){
    size+=16;
  } else if(O_addr.GetType()==ProtoAddress::SIM){
    if(O_addr.GetLength() > 4) {
      fprintf(stderr,"Error::OlsrMessage::SetO_addr simulation address is longer than 4 bytes\n");
    } else {
      size+=4;
    }
  }
  return true;
}
int
OlsrMessage::pack(char* buffer, int maxSize){
  if(O_addr.GetType()==ProtoAddress::IPv4){
    ((UINT8*)buffer)[0]=type;
    ((UINT8*)buffer)[1]=Vtime;
    ((UINT16*)buffer)[1]=htons(size);
    ((UINT32*)buffer)[1]=htonl(O_addr.IPv4GetAddress());
    ((UINT8*)buffer)[8]=ttl;
    ((UINT8*)buffer)[9]=hopc;
    ((UINT16*)buffer)[5]=htons(D_seq_num);
    memcpy(buffer+12,message,size-12);
  } else if(O_addr.GetType() == ProtoAddress::IPv6){ // v6
    ((UINT8*)buffer)[0]=type;
    ((UINT8*)buffer)[1]=Vtime;
    ((UINT16*)buffer)[1]=htons(size);
    memcpy((void*)(buffer+4),(void*)O_addr.GetRawHostAddress(),16); //copy over ipv6 address
    //    ((UINT32*)buffer)[1]=htonl(O_addr.IPv4GetAddress());
    ((UINT8*)buffer)[20]=ttl;
    ((UINT8*)buffer)[21]=hopc;
    ((UINT16*)buffer)[11]=htons(D_seq_num);
    memcpy(buffer+24,message,size-24);
  } else if(O_addr.GetType() == ProtoAddress::SIM){
    ((UINT8*)buffer)[0]=type;
    ((UINT8*)buffer)[1]=Vtime;
    ((UINT16*)buffer)[1]=htons(size);
	memset((void*)(buffer+4),0,16);
    if(O_addr.GetLength()<=4) { //we are in business
      memcpy((void*)(buffer+4),(void*)O_addr.GetRawHostAddress(),O_addr.GetLength()); //copy over up to 4 byte sim addr
    } else {
      fprintf(stderr, "OlsrMessage::pack Sim address size %d will not fit in 4 bytes\n",O_addr.GetLength());
      return 0;
    }
    ((UINT8*)buffer)[8]=ttl;
    ((UINT8*)buffer)[9]=hopc;
    ((UINT16*)buffer)[5]=htons(D_seq_num);
    memcpy(buffer+12,message,size-12);
  }
  return size;
}
int
OlsrMessage::unpack(char* buffer, int maxSize, ProtoAddress::Type ipvMode){
  if(ipvMode == ProtoAddress::IPv4){ 
    type=(UINT8)buffer[0];
    Vtime=(UINT8)buffer[1];
    size=ntohs(((UINT16*)buffer)[1]);
    O_addr.SetRawHostAddress(ProtoAddress::IPv4,buffer+4,4);
 
    ttl=(UINT8)buffer[8];
    hopc=(UINT8)buffer[9];
    D_seq_num=ntohs(((UINT16*)buffer)[5]);
 
    //fprintf(stdout,"%d type,%d Vtime,%d size,%s o_addr,%d ttl,%d hopc, %d seqnum\n",type,Vtime,size,O_addr.GetHostString(),ttl,hopc,D_seq_num);

    //message = (char*)malloc(size-12);
    message = new char[size-12];

    if(message){
      memcpy(message,buffer+12,size-12);
    } else {
      fprintf(stderr,"OlsrMessage::unpack malloc returned NULL!\n");
      return 0;
    }
    //  if(sizeused>maxSize){
    //  fprintf(stderr,"OlsrMessage::unpack:: sizeused %d is greater than the maxSize %d allowed!\n",sizeused,maxSize);
    // }
    //if(sizeused!=size){
    //  fprintf(stderr,"OlsrMessage::unpack:: sizeused %d is different than what packet size %d value is!\n",sizeused,size); 
    //}
  } else if(ipvMode == ProtoAddress::IPv6) { //v6
    type=(UINT8)buffer[0];
    Vtime=(UINT8)buffer[1];
    size=ntohs(((UINT16*)buffer)[1]);
    O_addr.SetRawHostAddress(ProtoAddress::IPv6,buffer+4,16);
    
    ttl=(UINT8)buffer[20];
    hopc=(UINT8)buffer[21];
    D_seq_num=ntohs(((UINT16*)buffer)[11]);
    //fprintf(stdout,"OlsrMessage::unpack:: %d type,%d Vtime,%d size,%s o_addr,%d ttl,%d hopc, %d seqnum\n",type,Vtime,size,O_addr.GetHostString(),ttl,hopc,D_seq_num);

    //message = (char*)malloc(size-24);
    message = new char[size-24];

    memcpy(message,buffer+24,size-24);
  } else if(ipvMode == ProtoAddress::SIM) { //Simulation
    type=(UINT8)buffer[0];
    Vtime=(UINT8)buffer[1];
    size=ntohs(((UINT16*)buffer)[1]);
    O_addr.SetRawHostAddress(ProtoAddress::SIM,buffer+4,4);

    ttl=(UINT8)buffer[8];
    hopc=(UINT8)buffer[9];
    D_seq_num=ntohs(((UINT16*)buffer)[5]);
 
    DMSG(9,"%d type,%d Vtime,%d size,%s o_addr,%d ttl,%d hopc, %d seqnum\n",type,Vtime,size,O_addr.GetHostString(),ttl,hopc,D_seq_num);


    //message = (char*)malloc(size-12);
    message = new char[size-12];

    if(message){
      memcpy(message,buffer+12,size-12);
    } else {
      fprintf(stderr,"OlsrMessage::unpack malloc returned NULL!\n");
      return 0;
    }
  }
  DMSG(7,"returning from olsrmessage unpack size=%d\n",size);
  return size;
}
//end OlsrMessage class

//HNA message stuff
bool 
HNAMessage::addNetwork(ProtoAddress *newNetwork,ProtoAddress *newMask){
  if(newNetwork->GetType() == ProtoAddress::IPv4) {
    UINT32 ipv4addr = newNetwork->IPv4GetAddress();
    UINT32 ipv4mask = newMask->IPv4GetAddress();
    ipv4addr=htonl(ipv4addr);
    ipv4mask=htonl(ipv4mask);
    size+=sizeof(newNetwork->IPv4GetAddress());
    bool returnvalue = networksandmasks.append((char*)&ipv4addr,sizeof(newNetwork->IPv4GetAddress()));
    if(returnvalue){
      size+=sizeof(newMask->IPv4GetAddress());
      return networksandmasks.append((char*)&ipv4mask,sizeof(newNetwork->IPv4GetAddress()));
    } else {
      fprintf(stderr,"Error: HNAMessage::addNetwork::IPV4 problem with adding network\n");
      return false;
    } 
  } else if(newNetwork->GetType() == ProtoAddress::IPv6){ // ipv6
    size+=16;
    bool returnvalue = networksandmasks.append((char*)newNetwork->GetRawHostAddress(),16);
    if(returnvalue){
      size+=16;
      return networksandmasks.append((char*)newMask->GetRawHostAddress(),16);
    } else {
      fprintf(stderr,"Error: HNAMessage::addNetwork::IPV6 problem with adding network\n");
      return false;
    }
  } else if(newNetwork->GetType() == ProtoAddress::SIM){ // simulation address
    if(newNetwork->GetLength() > 4 || newMask->GetLength() > 4){ //must fit into ipv4 address space
      fprintf(stderr,"Error: HNAMessage::addNetwork simulation address too large to fit new code needed\n");
      return false;
    }
    //putting it into uint32 to buffer space correctly
    UINT32 ipv4addr=0,ipv4mask=0;
    memcpy(&ipv4addr,newNetwork->GetRawHostAddress(),newNetwork->GetLength());
    memcpy(&ipv4mask,newMask->GetRawHostAddress(),newMask->GetLength());
    size+=4;
    bool returnvalue = networksandmasks.append((char*)&ipv4addr,4);
    if(returnvalue){
      size+=4;
      return networksandmasks.append((char*)&ipv4mask,4);
    } else {
      fprintf(stderr,"Error: HNAMessage::addNetwork::SIM problem with adding network\n");
      return false;
    } 
  }  
  return false;
}

int 
HNAMessage::pack(char* buffer, int maxSize){
  int sizeused = networksandmasks.pack(buffer,maxSize); 
  if(sizeused!=size){
    fprintf(stderr,"sanity check on sizeused %d vs size %d in HNAMessage::pack failed\n",sizeused,size);
  }
  return size;
}
int 
HNAMessage::unpack(char*buffer,int maxSize, ProtoAddress::Type ipvMode){
  if(ipvMode == ProtoAddress::IPv4) {
    UINT32 networkAddr,maskAddr;
    ProtoAddress newNetwork, newMask;
    size = maxSize;
    for(int i=1;i<maxSize/4;i+=2){
      newNetwork.SetRawHostAddress(ProtoAddress::IPv4,buffer+(i-1)*4,4); //this for loop can be cleaned up but why fix it if its not broken
      newMask.SetRawHostAddress(ProtoAddress::IPv4,buffer+(i)*4,4); 
      networkAddr=ntohl(newNetwork.IPv4GetAddress());
      maskAddr=ntohl(newMask.IPv4GetAddress());
      newNetwork.SetRawHostAddress(ProtoAddress::IPv4,(char*)&networkAddr,4);
      newMask.SetRawHostAddress(ProtoAddress::IPv4,(char*)&maskAddr,4);
      addNetwork(&newNetwork,&newMask);
    }
  } else if(ipvMode == ProtoAddress::IPv6){ // ipv6
    ProtoAddress newNetwork, newMask;
    size = maxSize;
    for(int i=0;i<maxSize;i+=32){
      newNetwork.SetRawHostAddress(ProtoAddress::IPv6,buffer+i,16);
      newMask.SetRawHostAddress(ProtoAddress::IPv6,buffer+i+16,16);
      addNetwork(&newNetwork,&newMask);
    }
  } else if(ipvMode == ProtoAddress::SIM){ // Sim
    ProtoAddress newNetwork, newMask;
    size = maxSize;
    for(int i=0;i<maxSize;i+=8){ //step by 2 addresses at a time
      newNetwork.SetRawHostAddress(ProtoAddress::SIM,buffer+i,4);//setting network
      newMask.SetRawHostAddress(ProtoAddress::SIM,buffer+i+4,4);//setting netmask
      addNetwork(&newNetwork,&newMask);
    }
  }
  return maxSize;
}

//end HNAMessage class

bool
TCMessageExtra::addMprSelector(ProtoAddress *newMprSelector, UINT8 newMinmax, UINT8 newSpf){
 // fprintf(stderr,"adding %s to tc message\n",newMprSelector->HostAddressString());
  bool returnvalue;
  returnvalue = minmax.append((char*)&newMinmax,1);
  returnvalue &= spf.append((char*)&newSpf,1);
  if(newMprSelector->GetType() == ProtoAddress::IPv4) {
    UINT32 ipv4addr = newMprSelector->IPv4GetAddress();
    ipv4addr=htonl(ipv4addr);
    size+=sizeof(newMprSelector->IPv4GetAddress())+2;
    returnvalue &= mprselectors.append((char*)&ipv4addr,sizeof(newMprSelector->IPv4GetAddress()));
    return returnvalue;
  } else if(newMprSelector->GetType() == ProtoAddress::IPv6) { //ipv6
    size+=18;
    returnvalue &= mprselectors.append((char*)(newMprSelector->GetRawHostAddress()),16);
  } else if(newMprSelector->GetType() == ProtoAddress::SIM) { //sim
    if(newMprSelector->GetLength() > 4) { //has to be less than or = 4 bytes
      fprintf(stderr,"TCMessage::addMprSelector: Error simulation address is greater than 4 bytes long not supported at this time!\n");
      return false;
    }
    size+=6;
    UINT32 ipv4addr=0; //using uint32 to fill in extra space
    memcpy(&ipv4addr,newMprSelector->GetRawHostAddress(),newMprSelector->GetLength());
    returnvalue &= mprselectors.append((char*)&ipv4addr,4);
  } else {
    returnvalue=false;
  }
  return returnvalue;
}
 
int 
TCMessageExtra::pack(char* buffer, int maxSize){
  int sizeused=4;
  ((UINT16*)buffer)[0]=htons(mssn);
  ((UINT16*)buffer)[1]=htons(reserved);
  sizeused+=mprselectors.pack(&buffer[sizeused],maxSize-sizeused);
  sizeused+=minmax.pack(&buffer[sizeused],maxSize-sizeused);
  sizeused+=spf.pack(&buffer[sizeused],maxSize-sizeused);
  if(sizeused<4){
    fprintf(stderr,"TCMessage::pack error packing mprselectors %d is my maxSize, %d is my sizeused\n",maxSize,4);
    return -1;
  }
  
  return sizeused;
}

int
TCMessageExtra::unpack(char* buffer, int maxSize, ProtoAddress::Type ipvMode){
  mssn=ntohs(((UINT16*)buffer)[0]);
  reserved=ntohs(((UINT16*)buffer)[1]);
  size=maxSize;
  ProtoAddress mprselector;
  int number_of_links=(maxSize-4)/6; //rounding down will be correct behavior
  UINT8 t_spf=0;
  UINT8 t_minmax=0;
  if(ipvMode == ProtoAddress::IPv4) {
    for(int i=0;i<number_of_links;i++){
      mprselector.SetRawHostAddress(ProtoAddress::IPv4,buffer+4+i*4,4);
      t_minmax = *(UINT8*)(buffer+number_of_links*4+4+i);
      t_spf = *(UINT8*)(buffer+number_of_links*5+4+i);
      addMprSelector(&mprselector,t_minmax,t_spf);
    }    
   //  tmaxSize=(maxSize-4)*2/3+4;//2/3s of buffer is for addresses 1/3 for info
//     for(int i=1;i<tmaxSize/4;i++){
//       mprselector.SetRawHostAddress(ProtoAddress::IPv4,buffer+i*4,4); //this for loop can be cleaned up but why fix it if its not broken
//       mprAddr=mprselector.IPv4GetAddress();
//       mprAddr=ntohl(mprAddr);
//       mprselector.SetRawHostAddress(ProtoAddress::IPv4,(char*)&mprAddr,4);
//       t_minmax = *(UINT8*)(buffer+(i-1)+tmaxSize);
//       t_spf = *(UINT8*)(buffer+(i-1)*2+tmaxSize);
//       addMprSelector(&mprselector,t_minmax,t_spf);
//     }
  } else if(ipvMode == ProtoAddress::IPv6){ //ipv6
    number_of_links=(maxSize-4)/18; //rounding down will be correct behavior
    for(int i=0;i<number_of_links;i++){
      mprselector.SetRawHostAddress(ProtoAddress::IPv6,buffer+4+i*16,16);
      t_minmax = *(UINT8*)(buffer+number_of_links*16+4+i);
      t_spf = *(UINT8*)(buffer+number_of_links*17+4+i);
      addMprSelector(&mprselector,t_minmax,t_spf);
    }
      //tmaxSize=(maxSize-4)*7/8+4; //7/8s of buffer is for address 1/8 is for info
      //for(int i=4;i<tmaxSize;i+=16){
      // mprselector.SetRawHostAddress(ProtoAddress::IPv6,buffer+i,16); 
      //t_minmax = *(UINT8*)(buffer+(i-4)/16+tmaxSize);
      //t_spf = *(UINT8*)(buffer+(i-4)/8+tmaxSize);
      //addMprSelector(&mprselector,t_minmax,t_spf);
      //}    
  } else if(ipvMode == ProtoAddress::SIM){ //sim
    for(int i=0;i<number_of_links;i++){
      mprselector.SetRawHostAddress(ProtoAddress::SIM,buffer+(1+i)*4,4);
      t_minmax = *(UINT8*)(buffer+4+number_of_links*4+i);
      t_spf = *(UINT8*)(buffer+4+number_of_links*5+i);
      addMprSelector(&mprselector,t_minmax,t_spf);
    }
  }
  return maxSize;
} 


//TC message stuff
bool 
TCMessage::addMprSelector(ProtoAddress *newMprSelector){
  // fprintf(stderr,"adding %s to tc message\n",newMprSelector->HostAddressString());
  if(newMprSelector->GetType() == ProtoAddress::IPv4) {
    UINT32 ipv4addr = newMprSelector->IPv4GetAddress();
    ipv4addr=htonl(ipv4addr);
    size+=sizeof(newMprSelector->IPv4GetAddress());
    return mprselectors.append((char*)&ipv4addr,sizeof(newMprSelector->IPv4GetAddress()));
  } else if(newMprSelector->GetType() == ProtoAddress::IPv6) { //ipv6
    size+=16;
    return mprselectors.append((char*)(newMprSelector->GetRawHostAddress()),16);
  } else if(newMprSelector->GetType() == ProtoAddress::SIM) { //sim
    if(newMprSelector->GetLength() > 4) { //has to be less than or = 4 bytes
      fprintf(stderr,"TCMessage::addMprSelector: Error simulation address is greater than 4 bytes long not supported at this time!\n");
      return false;
    }
    size+=4;
    UINT32 ipv4addr=0; //using uint32 to fill in extra space
    memcpy(&ipv4addr,newMprSelector->GetRawHostAddress(),newMprSelector->GetLength());
    return mprselectors.append((char*)&ipv4addr,4);
  }
  return false;
}

int 
TCMessage::pack(char* buffer, int maxSize){
  int sizeused=4;
  ((UINT16*)buffer)[0]=htons(mssn);
  ((UINT16*)buffer)[1]=htons(reserved);
  sizeused+=mprselectors.pack(&buffer[sizeused],maxSize-sizeused);
  if(sizeused<4){
    fprintf(stderr,"TCMessage::pack error packing mprselectors %d is my maxSize, %d is my sizeused\n",maxSize,4);
    return -1;
  }
  return sizeused;
}

int
TCMessage::unpack(char* buffer, int maxSize, ProtoAddress::Type ipvMode){
  mssn=ntohs(((UINT16*)buffer)[0]);
  reserved=ntohs(((UINT16*)buffer)[1]);
  size=maxSize;
  ProtoAddress mprselector;
  if(ipvMode == ProtoAddress::IPv4) {
    UINT32 mprAddr;
    for(int i=1;i<maxSize/4;i++){
      mprselector.SetRawHostAddress(ProtoAddress::IPv4,buffer+i*4,4); //this for loop can be cleaned up but why fix it if its not broken
      mprAddr=mprselector.IPv4GetAddress();
      mprAddr=ntohl(mprAddr);
      mprselector.SetRawHostAddress(ProtoAddress::IPv4,(char*)&mprAddr,4);
      addMprSelector(&mprselector);
    }
  } else if(ipvMode == ProtoAddress::IPv6){ //ipv6
    for(int i=4;i<maxSize;i+=16){
      mprselector.SetRawHostAddress(ProtoAddress::IPv6,buffer+i,16); 
      addMprSelector(&mprselector);
    }    
  } else if(ipvMode == ProtoAddress::SIM){ //sim
    for(int i=4;i<maxSize;i+=4){
      mprselector.SetRawHostAddress(ProtoAddress::SIM,buffer+i,4);
      addMprSelector(&mprselector);
    }
  }
  return maxSize;
} 

//helloMessage stuff
//bool
//HelloMessage::addInterface(NetworkAddress *newAddress){
//  UINT32 ipv4addr = newAddress->IPv4GetAddress();
//  ipv4addr=htonl(ipv4addr);
//  size+=sizeof(newAddress->IPv4GetAddress());
//  interfaceCount++;
//  return interfaces.append((void*)&ipv4addr,sizeof(newAddress->IPv4GetAddress()));
//}
bool
HelloMessage::addLinkMessage(LinkMessage *newMessage){
  size+=newMessage->size;

  //void* rawMessage=malloc(newMessage->size);
  char* rawMessage = new char[newMessage->size];

  if(!rawMessage){
    fprintf(stderr,"malloc returned null pointer in HelloMessage::addLinkmessage\n");
    return 0;
  }
  //char rawMessage[1024];
  int sizeused = newMessage->pack((char*)rawMessage,newMessage->size);
  if(sizeused<0){
    fprintf(stderr,"HelloMessage::addLinkMessage error packing newmessage, %d is newMessage size\n",newMessage->size);
    DMSG(8,"HelloMessage::addLinkMessage error packing newmessage, %d is newMessage size\n",newMessage->size);
    return false;
  }
  int returnvalue = messages.append((char*)rawMessage,newMessage->size);
 
  //free(rawMessage);
  delete[] rawMessage;

  if(returnvalue!=0)
	return true;
  return false;
}


int
HelloMessage::pack(char* buffer,int maxSize){
  int sizeused=4;
  ((UINT16*)buffer)[0]=htons(reserved1);
  ((UINT8*)buffer)[2]=htime;
  ((UINT8*)buffer)[3]=willingness;
  //  sizeused+=interfaces.pack(&buffer[sizeused],maxSize-sizeused);
  //if(sizeused<4){
  //  fprintf(stderr,"HelloMessage::pack error packing interfaces, %d is my maxSize, %d is my willingness\n",maxSize,willingness);
  //  return -1;
  //}
  int messagepacksize=messages.pack(&buffer[sizeused],maxSize-sizeused);
  if(messagepacksize<0){
    fprintf(stderr,"HelloMessage::pack error packing link messages, %d is my maxSize, %d is my sizeused, %d is my willingness\n",maxSize,sizeused,willingness);
    return -1;
  }
  sizeused+=messagepacksize;
  return sizeused;
}
int
HelloMessage::unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode){
  //interfaces.destroy();
  //messages.destroy();
  reserved1=ntohs(((UINT16*)buffer)[0]);
  htime=(UINT8)buffer[2];
  willingness=(UINT8)buffer[3];
  //  int loopsize = (int)interfaceCount;
  //fprintf(stdout,"HelloMessage::unpack %d reserved1, %d htime, %d willingness\n",reserved1,htime,willingness);
  int totalsizeused=4;//(1+loopsize)*4;
  //NetworkAddress newinterface;
  //for(int i=1;i<=loopsize;i++){
  //  newinterface.SetRawHostAddress(IPv4,buffer+i*4,4);
  //  addInterface(&newinterface);
  //}
  //interfaceCount=(UINT8)buffer[3]; //have to set this back cause adding interfaces incriments the count;
  int sizeused=0,maxloop=0;
  for(int i=4;i<maxSize;i+=sizeused){
    LinkMessage newmessage;
    maxloop++;
    sizeused = newmessage.unpack(&(buffer[i]),maxSize-i,ipvMode);
    //DMSG(8,"HelloMessage unpacked linkmessage of size %d \n",sizeused);
    //    sizeused = newmessage.unpack((char*)&(((UINT32*)buffer[i])),maxSize-i*4);
    totalsizeused+=sizeused;
    addLinkMessage(&newmessage);
    if(maxloop>500) {
      fprintf(stderr,"HelloMessage::unpack may have infinate loop, breaking\n");break;
    }
  }
  if(totalsizeused!=maxSize){
    fprintf(stderr,"HelloMessage::unpack:: maxSize %d should be set equal to what totalsizeuesed %d ends up being and it isn't!\n",maxSize,totalsizeused);
  }
  return totalsizeused;
}
//end HelloMessage class

//LinkMessage stuff
bool
LinkMessage::addNeighbor(ProtoAddress *newAddress){
  if(newAddress->GetType() == ProtoAddress::IPv4) {
    UINT32 ipv4addr = newAddress->IPv4GetAddress();
    ipv4addr=htonl(ipv4addr);
    size+=sizeof(newAddress->IPv4GetAddress()); // important to keep current size up to date;
    //fprintf(stderr,"%d is size of ipv4hostaddr which is what I am adding |",sizeof(newAddress->IPv4GetAddress()));
    return neighbors.append((char*)&ipv4addr,4);  
  } else if(newAddress->GetType() == ProtoAddress::IPv6){ //ipv6
    size+=16;
    return neighbors.append((char*)(newAddress->GetRawHostAddress()),16);
  } else if(newAddress->GetType() == ProtoAddress::SIM){ //sim
    if(newAddress->GetLength()>4){ //can not currently be greater than 4 bytes long
      fprintf(stderr,"Linkmessage::addNeighbor: Error because simulation address is longer than 4 bytes long, not supported at this time!\n");
      return false;
    }
    size+=4;
    UINT32 ipv4addr=0; //using uint32 to buffer space
    memcpy(&ipv4addr,newAddress->GetRawHostAddress(),newAddress->GetLength());
    return neighbors.append((char*)&ipv4addr,4);
  }
  return false;
}

bool
LinkMessage::addNeighborExtra(ProtoAddress *newAddress,unsigned long degree){
  bool returnvalue = false;
  reserved = 1; //this link message contains extra information.
  if(newAddress->GetType() == ProtoAddress::IPv4) {
    UINT32 ipv4addr = newAddress->IPv4GetAddress();
    ipv4addr=htonl(ipv4addr);
    size+=sizeof(newAddress->IPv4GetAddress())+4; // important to keep current size up to date;
    //fprintf(stderr,"%d is size of ipv4hostaddr which is what I am adding |",sizeof(newAddress->IPv4GetAddress()));
    returnvalue = neighbors.append((char*)&ipv4addr,4);  
    returnvalue &= degrees.append((char*)&degree,4);
  } else if(newAddress->GetType() == ProtoAddress::IPv6){ //ipv6
    size+=16;
    size+=4;
    returnvalue = neighbors.append((char*)(newAddress->GetRawHostAddress()),16);
    returnvalue &= degrees.append((char*)&degree,4);
  } else if(newAddress->GetType() == ProtoAddress::SIM){ //sim
    if(newAddress->GetLength()>4){ //can not currently be greater than 4 bytes long
      fprintf(stderr,"Linkmessage::addNeighbor: Error because simulation address is longer than 4 bytes long, not supported at this time!\n");
      return false;
    }
    size+=4;
    size+=4;
    UINT32 ipv4addr=0; //using uint32 to buffer space
    memcpy(&ipv4addr,newAddress->GetRawHostAddress(),newAddress->GetLength());
    returnvalue = neighbors.append((char*)&ipv4addr,4);
    returnvalue &= degrees.append((char*)&degree,4);
  }
  return returnvalue;
}
int
LinkMessage::pack(char* buffer,int maxSize){
  int sizeused=4;
  memset(buffer,0,maxSize);
  ((UINT8*)buffer)[0]=linkCode;
  ((UINT8*)buffer)[1]=reserved;
  if(size>4){
    sizeused += neighbors.pack(&buffer[sizeused],maxSize-sizeused);
    if(reserved == 1){
      sizeused += degrees.pack(&buffer[sizeused],maxSize-sizeused);
    }
    if(sizeused<4){
      fprintf(stderr,"LinkMessage::pack error packing neighbors %d is my maxSize,%d was my size value\n",maxSize,size);
      DMSG(8,"LinkMessage::pack error packing neighbors %d is my maxSize,%d was my size value\n",maxSize,size);
      return -1;
    }
  }
  ((UINT16*)buffer)[1]=htons((UINT16)sizeused);
  //(UINT16)buffer[2]=sizeused;
  return sizeused;
}
int 
LinkMessage::unpack(char* buffer,int maxSize, ProtoAddress::Type ipvMode){
  linkCode=(UINT8)buffer[0];
  reserved=(UINT8)buffer[1];
  size=ntohs(((UINT16*)buffer)[1]);
  //fprintf(stdout,"LinkMessage::unpack %d linkCode,%d reserved,%d size\n",linkCode,reserved,size);
  if(size>maxSize){
    fprintf(stderr,"Linkmessage::unpack:: insufficent room for unpacking! size=%d maxSize=%d\n",size,maxSize);
    return 0;
  }
  //  neighbors.destroy();
  ProtoAddress newaddress;
  if(reserved ==0){
    if(ipvMode == ProtoAddress::IPv4) {
      for(int i=1;i<(size/4);i++){ //loop for getting addresses
	newaddress.SetRawHostAddress(ProtoAddress::IPv4,buffer+i*4,4);
	addNeighbor(&newaddress);
	size-=4;//addNeighbor changes the size this is to correct it
      }
    } else if(ipvMode == ProtoAddress::IPv6){ //ipv6 
      for(int i=4;i<size;i+=16){ //loop for getting addresses
	newaddress.SetRawHostAddress(ProtoAddress::IPv6,buffer+i,16);
	addNeighbor(&newaddress);
	size-=16;//addNeighbor changes the size this is to correct it
      }
    } else if(ipvMode == ProtoAddress::SIM){ //sim
      for(int i=1;i<(size/4);i++){ //loop for getting addresses
	newaddress.SetRawHostAddress(ProtoAddress::SIM,buffer+i*4,4);
	addNeighbor(&newaddress);
	size-=4;//addNeighbor changes the size this is to correct it
      }
      //    for(int i=4;i<size;i+=4){ //loop for getting addresses
      //  newaddress.SetRawHostAddress(ProtoAddress::SIM,buffer+i,4);
      //  addNeighbor(&newaddress);
      //  size-=4;//addNeighbor changes the size this is to correct that change
      //}
    }
  } else { //reserved ==1 link message contains extra information
    unsigned long degree;
    int numberofaddrs = 0; 
    if(ipvMode == ProtoAddress::IPv4) {
      numberofaddrs = (size/4-1)/2;
      for(int i=1;i<=numberofaddrs;i++){ //loop for getting addresses
	newaddress.SetRawHostAddress(ProtoAddress::IPv4,buffer+i*4,4);
	degree = *(unsigned long*)(buffer+(i+numberofaddrs)*4);
	addNeighborExtra(&newaddress,degree);
	size-=8;//addNeighbor changes the size this is to correct it
      }
    } else if(ipvMode == ProtoAddress::IPv6){ //ipv6 
      numberofaddrs = (size-4)/20;
      for(int i=0;i<numberofaddrs;i++){ //loop for getting addresses
	newaddress.SetRawHostAddress(ProtoAddress::IPv6,buffer+4+(i*16),16);
	degree = *(unsigned long*)(buffer+4+(numberofaddrs*16)+(i*4));
	addNeighborExtra(&newaddress,degree);
	size-=20;//addNeighbor changes the size this is to correct it
      }
    } else if(ipvMode == ProtoAddress::SIM){ //sim
      numberofaddrs = (size/4-1)/2;
      for(int i=1;i<=numberofaddrs;i++){ //loop for getting addresses
	newaddress.SetRawHostAddress(ProtoAddress::SIM,buffer+i*4,4);
	degree = *(unsigned long*)(buffer+(i+numberofaddrs)*4);
	addNeighborExtra(&newaddress,degree);
	size-=8;//addNeighbor changes the size this is to correct it
      }
    }
  }
  if(size!=ntohs(((UINT16*)buffer)[1])) { //I don't see what I was trying to check here??? doesn't seem right at all!?
    fprintf(stderr,"LinkMessage::unpack size value somehow ended up different than size value in header!!!!!!!!!!\n");
  }
  //  size=((UINT16*)buffer)[1]; // have to reset the size cause adding addresses messed with the value
  return size;
}
//end LinkMessage class

//List class stuff
//List::List(List &listToCopy){
//  fprintf(stdout,"repeating here\n");
//  head=NULL;tail=NULL;
//  void* object=NULL;
//  int objectsize=0;
//  listToCopy.peekInit();
//  while((object = listToCopy.peekNext(&objectsize))){
//    append(object,objectsize);
//  }
//}
  
bool
List_::append(char* object, int size){
  //set up new list node 
  ListNode* newListNodePtr =new ListNode;
  //fprintf(stdout,"|books %d| ",++books);
  newListNodePtr->size=size;
  
  //newListNodePtr->object=malloc(size);
  newListNodePtr->object = (char*) new char[size];

  //  fprintf(stdout,"|malloced %d bytes books %d| ",size,++books);
  if(!newListNodePtr->object){
    fprintf(stderr,"malloc returned null pointer in list::append\n");
    return 0;
  }
  memcpy(newListNodePtr->object,object,size);
  //add new object to list
  if((newListNodePtr->prev=tail))
    tail->next=newListNodePtr;
  else
    head=newListNodePtr;
  newListNodePtr->next=NULL;
  tail=newListNodePtr;
  return true;
}
bool
List_::destroy(){
  //  fprintf(stderr,"in list destroy\n");
  ListNode* listNodePtr=head;
  while((head=listNodePtr)){
    listNodePtr=head->next;
    
    //free(head->object);
    delete[] head->object;
    
    //fprintf(stdout,"books %d ",--books);
    
    //free(head);
    delete head;
    
    //fprintf(stdout,"books %d ",--books);
  }
  head=NULL;
  tail=NULL;
  peekptr=NULL;
  return true;
}
int
List_::pack(char* buffer,int maxSize){
  memset(buffer,0,maxSize);
  ListNode* currentPtr=head;
  int localSize=0;
  while(currentPtr!=NULL){
    localSize+=currentPtr->size;
    if(localSize<=maxSize){
      memcpy((buffer+localSize-currentPtr->size),currentPtr->object,currentPtr->size);
    }   
    else{
      DMSG(8,"List::pack:: buffer size insufficent for packing list maxsize=%d localsize=%d\n",maxSize,localSize);
      fprintf(stderr,"List::pack:: buffer size insufficent for packing list maxsize=%d localsize=%d\n",maxSize,localSize);
      return -1; 
    }
    currentPtr=currentPtr->next;
  }
  return localSize;
}
char*
List_::peekNext(int *sizeptr){
  if(peekptr)
    peekptr=peekptr->next;
  else 
    peekptr=head;
  if(peekptr){
    *sizeptr = peekptr->size;
    return peekptr->object;
  }else{
    return NULL;
    *sizeptr = 0;
  }
}

MacControlMsg::MacControlMsg()
{
    msg_buffer[VERSION_OFFSET]= 0;
    msg_buffer[ADDRTYPE_OFFSET] = ADDR_INVALID;
    *((UINT16*)(msg_buffer+LENGTH_OFFSET)) = 0;
}

UINT8 MacControlMsg::GetAddressLength()
{
    switch (GetAddressType())
    {
        case 1:
            return 6;
        case 2:
            return 4;
        case 3:
            return 16;
        case 4:
	  return 0;
        default:
            DMSG(0, "MacControlMsg::GetAddressLength(): invalid addr type\n");
    }
    return 0;
}  // end MacControlMsg::GetAddressLength()

MacControlMsg::Param::Param()
 : buffer(NULL)
{
}

int MacControlMsg::Param::GetValue()
{
    switch (GetLength())
    {
        case 1:
        {
            UINT8* ptr = (UINT8*)GetContent();
            return ((int)(*ptr));
        }
        case 2:
        {
            UINT16 temp16;
            memcpy(&temp16, GetContent(), sizeof(UINT16));
            return (ntohs(temp16));
        }
        case 4:
        {
            UINT32 temp32;
            memcpy(&temp32, GetContent(), sizeof(UINT32));
            return (ntohl(temp32));
        }
        default:
            DMSG(0, "MacControlMsg::Param::GetValue() unsupported param length\n");
            return 0;
    }
}  // end MacControlMsg::Param::GetValue()

