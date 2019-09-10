cd ..\common
rename *.ex.cpp *.ex.old
copy *.cpp *.ex.cpp
cd ..\..\protolib\common
rename *.ex.cpp *.ex.old
copy protoAddress.cpp protoAddress.ex.cpp
copy protoDebug.cpp protoDebug.ex.cpp
copy protoRouteMgr.cpp protoRouteMgr.ex.cpp
copy protoRouteTable.cpp protoRouteTable.ex.cpp
copy protoSimAgent.cpp protoSimAgent.ex.cpp
copy protoSimSocket.cpp protoSimSocket.ex.cpp
copy protoTimer.cpp protoTimer.ex.cpp
copy protoTree.cpp protoTree.ex.cpp
cd ..\opnet
copy *.cpp *.ex.cpp
cd ..
