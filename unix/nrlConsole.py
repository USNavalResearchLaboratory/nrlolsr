#!/usr/bin/env python
import sys
import protokit

if len(sys.argv) <= 2:
  print "Usage: %s <consoleRPipeName> (n | r | g | i)" % sys.argv[0]
  sys.exit(1)

send_pipe = protokit.Pipe("MESSAGE")
send_pipe.Connect(sys.argv[1])

recv_pipe = protokit.Pipe("MESSAGE")

if sys.argv[2] is 'n':
  message = "-sendConsoleNeighbors"
elif sys.argv[2] is 'r':
  message = "-sendConsoleRoutes"
elif sys.argv[2] is 'i':
  message = "-sendConsoleRouterID"
elif sys.argv[2] is 'g':
  message = "-sendConsoleGraphML"
else: 
  print "Second arg '%s' isn't 'n','r','g' or 'i'" % sys.argv[2]
  sys.exit(1)

recv_pipe.Listen(sys.argv[1]+"console")

send_pipe.Send("-nrlConsole " + sys.argv[1]+"console")
recv_pipe.Recv(100000)

send_pipe.Send(message)
print recv_pipe.Recv(100000)
